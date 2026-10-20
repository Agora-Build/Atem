//! r9 admission end to end in process: the engine with the real device
//! list on a temp profile, the real session host over a `FileJournal`, and
//! clients that are `atem_client::connect` (the shared core) driven over
//! the channel envelope, several at once on one link.
use super::envelope::{self, Event, Transport};
use super::*;
use crate::session_protocol::fake_runtime::FakeRuntime;
use crate::session_protocol::file_journal::FileJournal;
use crate::session_protocol::host::HostConfig;
use crate::session_protocol::membership::r9log::{self, TestLog, secret};
use crate::session_protocol::membership::{HostPin, store};
use atem_client::connect::{AwaitWelcome, Connecting, Connector, Event as CEvent, Identity};
use atem_client::membership::Membership;
use serde_json::json;

pub(super) const HOST: &str = "host-r9";
pub(super) const ACCOUNT: &str = "acct-r9";
pub(super) const SID: &str = "ses-aaaaaaaaaaaa";
pub(super) const SID_B: &str = "ses-bbbbbbbbbbbb";
const PGEN: &str = "22222222-2222-4222-8222-222222222222";
const PGEN_B: &str = "33333333-3333-4333-8333-333333333333";
pub(super) const WALL0: u64 = 1_793_264_000_000;

/// A client's side of one channel.
pub(super) enum Client {
    Connecting(Connecting),
    Welcoming(AwaitWelcome),
    Attached(Box<atem_client::connect::Attached>, Vec<CEvent>),
    /// Refused (the error code, and the detail) or closed by Atem.
    Refused(String, Option<String>),
    /// Atem's clear error frame before the channel opened.
    Clear(String),
}

/// The runtime's r9 side, one link, and the clients on it.
pub(super) struct Rig {
    pub dir: tempfile::TempDir,
    pub pairing: crate::paths::PairingPaths,
    pub journal: std::path::PathBuf,
    pub log: TestLog,
    pub rt: FakeRuntime<FileJournal>,
    pub m: Option<MembershipHost>,
    pub failed: Option<String>,
    pub key: HostKey,
    pub engine: R9Host,
    pub now: Now,
    pub clients: BTreeMap<String, Client>,
    /// Atem's envelopes that weren't a client's frame (closes).
    pub closes: Vec<(String, Option<String>)>,
    /// The link takes nothing (output builds up in the engine).
    pub stalled: bool,
    pub link_gen: u64,
}

pub(super) fn now_at(wall: u64, mono: u64) -> Now {
    Now {
        mono,
        host: HostNow {
            wall_ms: wall,
            mono_ms: mono,
            boot_id: "boot-1".into(),
        },
    }
}

impl Rig {
    /// An account (the Mac genesis), this host added at trust generation 1,
    /// a phone (control), a bot (prompt and view on `SID` only, an hour
    /// left), pinned; two sessions.
    pub fn new() -> Rig {
        Self::with(|_| {})
    }

    pub fn with(more: impl FnOnce(&mut TestLog)) -> Rig {
        let dir = tempfile::tempdir().unwrap();
        let profile = crate::paths::ProfilePaths::in_dir(dir.path());
        let journal = dir.path().join("runtime").join("journal");
        store::private_dir(&journal).unwrap();
        let host_seed = secret("host seed");
        let mut log = TestLog::genesis(ACCOUNT, &secret("astation"));
        log.add_host(HOST, 1, &host_seed);
        log.add_native("dev-phone", &["control", "view"]);
        log.add_service(
            "svc-bot",
            &[HOST],
            Some(&[SID]),
            &["prompt", "view"],
            r9log::host_now().wall_ms + 3_600_000,
        );
        more(&mut log);
        let pin = HostPin {
            host_id: HOST.into(),
            host_trust_gen: 1,
        };
        MembershipHost::pin(&profile.pairing, &journal, &pin, &log.log, &host_seed).unwrap();
        let setup = json!({
            "host": {"account_id": ACCOUNT, "atem_device_id": HOST, "host_trust_gen": 1,
                     "runtime_gen": "11111111-1111-4111-8111-111111111111", "runtime_epoch": 1},
            "sessions": [{"session_id": SID, "process_gen": PGEN, "chat": true},
                         {"session_id": SID_B, "process_gen": PGEN_B, "chat": true}],
            "clients": [],
        });
        let file_journal = FileJournal::open(&journal).unwrap();
        let mut rt = FakeRuntime::from_json_with(setup, HostConfig::default(), file_journal);
        rt.host.set_refuse_r8(true);
        let now = now_at(r9log::host_now().wall_ms, 1_000);
        rt.set_now(now.mono);
        let mut fences = HostFences::new(&mut rt.host);
        let opened = MembershipHost::open(&profile.pairing, &journal, 1, &now.host, &mut fences)
            .unwrap()
            .map(|(m, _)| m);
        Rig {
            dir,
            pairing: profile.pairing,
            journal,
            log,
            rt,
            m: opened,
            failed: None,
            key: HostKey::new(&host_seed),
            engine: R9Host::new(Limits::default(), None),
            now,
            clients: BTreeMap::new(),
            closes: Vec::new(),
            stalled: false,
            link_gen: 0,
        }
    }

    /// Runs `f` on the engine with this rig's parts, then performs the
    /// effects (r9 attachments' messages back to the engine).
    pub fn run<T>(
        &mut self,
        f: impl FnOnce(&mut R9Host, &mut Parts<'_, FileJournal>) -> (T, Vec<Effect>),
    ) -> T {
        let list = match (&mut self.m, &self.failed) {
            (_, Some(why)) => DeviceList::Failed(why),
            (Some(m), None) => DeviceList::Open { m, key: &self.key },
            (None, None) => DeviceList::None,
        };
        let mut parts = Parts {
            host: &mut self.rt.host,
            list,
            now: self.now.clone(),
            projects: &NoProjects,
        };
        let (out, effects) = f(&mut self.engine, &mut parts);
        self.rt.apply(effects);
        self.route();
        self.engine.end_pass();
        out
    }

    /// The session host's messages and closes for r9 attachments.
    fn route(&mut self) {
        loop {
            let foreign = std::mem::take(&mut self.rt.foreign);
            if foreign.is_empty() {
                break;
            }
            for effect in foreign {
                match effect {
                    Effect::Send {
                        attachment,
                        message,
                    } => self.engine.deliver(
                        &attachment,
                        &message,
                        &NoProjects,
                        HOST,
                        self.now.host.mono_ms,
                    ),
                    Effect::Close { attachment } => self
                        .engine
                        .close_attachment(&attachment, self.now.host.mono_ms),
                    _ => {}
                }
            }
        }
    }

    pub fn link_up(&mut self) {
        self.link_gen += 1;
        let link = self.link_gen;
        self.run(|e, p| ((), e.link_up(link, p)));
    }

    pub fn link_down(&mut self) {
        self.run(|e, p| ((), e.link_down(p)));
        self.clients.clear();
    }

    pub fn envelope_in(&mut self, text: &str) {
        let text = text.to_string();
        self.run(|e, p| ((), e.on_envelope(&text, p)));
        self.pump();
    }

    pub fn advance(&mut self, ms: u64) {
        self.now.mono += ms;
        self.now.host.mono_ms += ms;
        self.now.host.wall_ms += ms;
        self.rt.set_now(self.now.mono);
        self.route();
        self.run(|e, p| ((), e.tick(p)));
        self.pump();
    }

    /// Delivers what Atem sent to the clients.
    pub fn pump(&mut self) {
        if self.stalled {
            return;
        }
        let mut sent = Vec::new();
        self.engine.flush(&mut |text| {
            sent.push(text);
            true
        });
        for text in sent {
            match envelope::parse(&text).expect("Atem sends valid envelopes") {
                Event::Frame { channel, frame } => self.to_client(&channel, &frame),
                Event::Close { channel, reason } => {
                    if let Some(Client::Attached(..)) = self.clients.get(&channel) {
                        self.clients.insert(
                            channel.clone(),
                            Client::Refused("closed".into(), reason.clone()),
                        );
                    }
                    self.closes.push((channel, reason));
                }
                Event::Open { .. } => panic!("Atem never opens"),
            }
        }
    }

    fn to_client(&mut self, handle: &str, frame: &[u8]) {
        let Some(client) = self.clients.remove(handle) else {
            return;
        };
        let mono = self.now.host.mono_ms;
        let next = match client {
            Client::Connecting(c) => {
                if let Ok(Frame::Error { code }) = chwire::parse_frame(frame) {
                    Client::Clear(code)
                } else {
                    let identity = self.identity_of(handle);
                    match c.on_accept(frame, &self.log.log, &self.log.keys, &identity, mono) {
                        Ok((await_welcome, finish)) => {
                            self.clients
                                .insert(handle.to_string(), Client::Welcoming(await_welcome));
                            self.send_frame(handle, &finish);
                            return;
                        }
                        Err(e) => Client::Refused(format!("{e:?}"), None),
                    }
                }
            }
            Client::Welcoming(w) => {
                if let Ok(Frame::Error { code }) = chwire::parse_frame(frame) {
                    Client::Clear(code)
                } else {
                    match w.on_frame(frame, &self.log.log, mono) {
                        Ok(attached) => Client::Attached(Box::new(attached), Vec::new()),
                        Err(atem_client::connect::ConnectError::Refused { error, .. }) => {
                            Client::Refused(error.code.clone(), error.detail.clone())
                        }
                        Err(e) => Client::Refused(format!("{e:?}"), None),
                    }
                }
            }
            Client::Attached(mut a, mut events) => match a.on_frame(frame, mono) {
                Ok(new) => {
                    events.extend(new);
                    Client::Attached(a, events)
                }
                Err(e) => Client::Refused(format!("{e:?}"), None),
            },
            other => other,
        };
        self.clients.insert(handle.to_string(), next);
    }

    fn identity_of(&self, handle: &str) -> Identity {
        IDS.with(|ids| ids.borrow().get(handle).cloned().expect("an identity"))
    }

    fn send_frame(&mut self, handle: &str, frame: &[u8]) {
        let text = envelope::frame(handle, frame);
        self.run(|e, p| ((), e.on_envelope(&text, p)));
        self.pump();
    }

    /// Opens `handle` and runs a full handshake for `identity`.
    pub fn connect(&mut self, handle: &str, identity: Identity) {
        self.connect_with(handle, identity, None);
    }

    /// As [`Rig::connect`], with `log` as the client's verified log.
    pub fn connect_with(&mut self, handle: &str, identity: Identity, log: Option<&Membership>) {
        IDS.with(|ids| ids.borrow_mut().insert(handle.to_string(), identity));
        self.envelope_in(&envelope::open(handle, Transport::Relay));
        let log = log.unwrap_or(&self.log.log).clone();
        let (connecting, init) = Connector::new(HOST)
            .start(&log, self.now.host.mono_ms)
            .unwrap();
        self.clients
            .insert(handle.to_string(), Client::Connecting(connecting));
        self.send_frame(handle, &init);
    }

    pub fn attached(&mut self, handle: &str) -> &mut atem_client::connect::Attached {
        match self.clients.get_mut(handle) {
            Some(Client::Attached(a, _)) => a,
            Some(Client::Refused(c, d)) => panic!("{handle} refused: {c} {d:?}"),
            Some(Client::Clear(c)) => panic!("{handle} got clear {c}"),
            _ => panic!("{handle} not attached"),
        }
    }

    pub fn refused(&self, handle: &str) -> (String, Option<String>) {
        match self.clients.get(handle) {
            Some(Client::Refused(c, d)) => (c.clone(), d.clone()),
            Some(Client::Clear(c)) => (c.clone(), None),
            _ => panic!("{handle} not refused"),
        }
    }

    /// The events `handle` received since the last call.
    pub fn events(&mut self, handle: &str) -> Vec<CEvent> {
        match self.clients.get_mut(handle) {
            Some(Client::Attached(_, events)) => std::mem::take(events),
            _ => Vec::new(),
        }
    }

    /// `handle` sends `message` (a session-family JSON value).
    pub fn send(&mut self, handle: &str, message: &Value) {
        let mono = self.now.host.mono_ms;
        let frame = self.attached(handle).send(message, mono).unwrap();
        self.send_frame(handle, &frame);
    }

    pub fn list(&mut self, handle: &str) -> Vec<String> {
        let mono = self.now.host.mono_ms;
        let (_, frame) = self.attached(handle).list(mono).unwrap();
        self.send_frame(handle, &frame);
        self.events(handle)
            .into_iter()
            .find_map(|e| match e {
                CEvent::Session(m) => match m.op {
                    R8Op::Sessions { sessions, .. } => {
                        Some(sessions.into_iter().map(|d| d.session_id).collect())
                    }
                    _ => None,
                },
                _ => None,
            })
            .expect("a sessions reply")
    }

    /// The last error `handle` got (`code`, `detail`).
    pub fn last_error(events: &[CEvent]) -> Option<(String, Option<String>)> {
        events.iter().rev().find_map(|e| match e {
            CEvent::Error(e) | CEvent::Fenced(e) => Some((e.code.clone(), e.detail.clone())),
            CEvent::Family(f) => f
                .data
                .as_ref()
                .filter(|d| d["op"] == "error")
                .map(|d| (d["code"].as_str().unwrap_or_default().to_string(), None)),
            _ => None,
        })
    }

    pub fn binding(&mut self, handle: &str, sid: &str) -> Value {
        // The client learns targets from the registry.
        self.list(handle);
        let mono = self.now.host.mono_ms;
        serde_json::to_value(self.attached(handle).binding(sid, mono).unwrap()).unwrap()
    }
}

thread_local! {
    static IDS: std::cell::RefCell<BTreeMap<String, Identity>> = Default::default();
}

pub(super) fn phone() -> Identity {
    Identity::native("dev-phone", r9log::auth("dev-phone"))
}

pub(super) fn bot() -> Identity {
    Identity::service("svc-bot", r9log::auth("svc-bot"))
}

fn welcome(rig: &mut Rig, handle: &str) -> Welcome {
    rig.attached(handle).welcome().clone()
}

// ── Admission ──

/// A phone (native, P-256), a bot (service, scoped, expiring) and a
/// browser (a phone-issued grant) are each admitted on their own channel
/// of one link, at once, with the welcome §R9.8 names.
#[test]
fn a_phone_a_bot_and_a_browser_are_admitted_on_one_link() {
    let mut rig = Rig::new();
    rig.link_up();
    rig.connect("ch-phone", phone());
    let w = welcome(&mut rig, "ch-phone");
    assert_eq!(w.principal, "member:dev-phone");
    assert_eq!(w.client_kind, ClientKind::Native);
    assert_eq!(w.permissions, vec![Permission::Control, Permission::View]);
    assert!(w.scope.is_none());
    assert_eq!(w.head, rig.log.log.head());
    assert!(w.pending_recovery.is_empty());
    assert_eq!(w.revision, 9);
    assert!(w.features.iter().any(|f| f == "membership.carry"));
    assert_eq!(w.atem_device_id, HOST);
    assert!(w.authorization_ms_left <= 86_400_000 && w.authorization_ms_left > 86_000_000);
    rig.advance(1000);
    rig.connect("ch-bot", bot());
    let w = welcome(&mut rig, "ch-bot");
    assert_eq!(w.principal, "service:svc-bot");
    assert_eq!(w.client_kind, ClientKind::Service);
    let scope = w.scope.clone().unwrap();
    assert_eq!(scope.sessions, Some(vec![SID.to_string()]));
    assert!(
        w.authorization_ms_left <= 3_600_000,
        "{}",
        w.authorization_ms_left
    );
    rig.advance(1000);
    let wall = rig.now.host.wall_ms;
    let grant_id = "aaaaaaaa-1111-4111-8111-000000000001";
    let (grant, key) = rig.log.grant(
        "dev-phone",
        grant_id,
        HOST,
        1,
        Some(SID),
        &["view"],
        wall,
        wall + 600_000,
    );
    rig.connect("ch-browser", Identity::browser(grant, key).unwrap());
    let w = welcome(&mut rig, "ch-browser");
    assert_eq!(w.principal, format!("browser:{grant_id}"));
    assert_eq!(w.client_kind, ClientKind::Browser);
    assert_eq!(w.permissions, vec![Permission::View]);
    assert!(w.authorization_ms_left <= 600_000);
    // Three channels, three attachments, distinct channel ids.
    assert_eq!(rig.engine.status().attachments, 3);
    assert_eq!(rig.rt.host.welcomed_attachments(), 3);
    let ids: HashSet<String> = ["ch-phone", "ch-bot", "ch-browser"]
        .iter()
        .map(|h| rig.attached(h).channel_id().to_string())
        .collect();
    assert_eq!(ids.len(), 3);
    // Each sees what its scope covers.
    assert_eq!(
        rig.list("ch-phone"),
        vec![SID.to_string(), SID_B.to_string()]
    );
    assert_eq!(rig.list("ch-bot"), vec![SID.to_string()]);
    assert_eq!(rig.list("ch-browser"), vec![SID.to_string()]);
}

/// Out of scope and nonexistent are both `unknown_session`; an op outside
/// the ops is `forbidden`.
#[test]
fn scope_and_ops_are_checked_on_every_request() {
    let mut rig = Rig::new();
    rig.link_up();
    rig.connect("ch-bot", bot());
    let b = rig.binding("ch-bot", SID);
    let mut other = b.clone();
    other["target"]["session_id"] = json!(SID_B);
    let mut missing = b.clone();
    missing["target"]["session_id"] = json!("ses-zzzzzzzzzzzz");
    for binding in [other, missing] {
        rig.send(
            "ch-bot",
            &json!({"type": "agentChat", "data": {"v": 1, "op": "open",
                "conversationId": "cccccccc-0000-4000-8000-000000000001",
                "agentId": binding["target"]["session_id"], "binding": binding}}),
        );
        let events = rig.events("ch-bot");
        assert_eq!(
            Rig::last_error(&events).map(|e| e.0),
            Some("unknown_session".into()),
            "{events:?}"
        );
    }
    // Terminal input is outside the bot's ops (prompt, view).
    rig.send(
        "ch-bot",
        &json!({"type": "terminal", "data": {"v": 1, "op": "input", "terminal_id": SID,
            "generation": PGEN, "stream_id": "dddddddd-0000-4000-8000-000000000001",
            "sequence": 0, "bytes": "eA==", "binding": b}}),
    );
    let events = rig.events("ch-bot");
    assert_eq!(
        Rig::last_error(&events).map(|e| e.0),
        Some("forbidden".into())
    );
    // A second hello inside the channel is not a request.
    rig.send(
        "ch-bot",
        &json!({"type": "session", "data": {"v": 1, "op": "hello",
            "id": "aaaaaaaa-0000-4000-8000-000000000009", "revision": 8}}),
    );
    let events = rig.events("ch-bot");
    assert_eq!(
        Rig::last_error(&events).map(|e| e.0),
        Some("invalid_request".into())
    );
    // In scope, it may prompt with a Send acquire.
    let b = rig.binding("ch-bot", SID);
    rig.send(
        "ch-bot",
        &json!({"type": "session", "data": {"v": 1, "op": "submit",
            "id": "aaaaaaaa-0000-4000-8000-000000000010", "binding": b,
            "kind": "prompt", "request_id": "bbbbbbbb-0000-4000-8000-000000000010",
            "acquire": true, "payload": {"text": "status?"}}}),
    );
    let events = rig.events("ch-bot");
    assert!(
        events.iter().any(|e| matches!(e, CEvent::Session(m) if matches!(&m.op, R8Op::Receipt(r) if r.lease.is_some()))),
        "{events:?}"
    );
}

/// Each principal kind is refused when expired, out of scope, or with a
/// tampered proof; a non-member and a revoked grant are refused too.
#[test]
fn expired_out_of_scope_and_tampered_principals_are_refused() {
    let wall = r9log::host_now().wall_ms;
    let mut rig = Rig::with(|log| {
        log.add_service("svc-old", &[HOST], None, &["view"], wall + 1_000);
        log.add_service(
            "svc-elsewhere",
            &["host-other"],
            None,
            &["view"],
            wall + 3_600_000,
        );
    });
    rig.link_up();
    rig.advance(2_000);
    rig.connect("c1", Identity::service("svc-old", r9log::auth("svc-old")));
    assert_eq!(
        rig.refused("c1"),
        ("unauthorized".into(), Some("expired".into()))
    );
    rig.advance(1_000);
    rig.connect(
        "c2",
        Identity::service("svc-elsewhere", r9log::auth("svc-elsewhere")),
    );
    assert_eq!(
        rig.refused("c2"),
        ("unauthorized".into(), Some("out of scope".into()))
    );
    rig.advance(1_000);
    // A native proof signed with another key.
    rig.connect("c3", Identity::native("dev-phone", r9log::auth("svc-bot")));
    assert_eq!(rig.refused("c3").0, "handshake_failed");
    rig.advance(1_000);
    // A device that isn't a member.
    rig.log
        .keys
        .insert_p256(r9log::auth("dev-evil"), &secret("dev-evil"))
        .unwrap();
    rig.connect("c4", Identity::native("dev-evil", r9log::auth("dev-evil")));
    assert_eq!(
        rig.refused("c4"),
        ("unauthorized".into(), Some("not a member".into()))
    );
    rig.advance(1_000);
    // A grant that expired, and one whose body was changed after signing.
    let now = rig.now.host.wall_ms;
    let (grant, key) = rig.log.grant(
        "dev-phone",
        "aaaaaaaa-1111-4111-8111-000000000002",
        HOST,
        1,
        None,
        &["view"],
        now - 3_000_000,
        now - 1,
    );
    rig.connect("c5", Identity::browser(grant, key).unwrap());
    assert_eq!(
        rig.refused("c5"),
        ("unauthorized".into(), Some("expired".into()))
    );
    rig.advance(1_000);
    let now = rig.now.host.wall_ms;
    let (grant, key) = rig.log.grant(
        "dev-phone",
        "aaaaaaaa-1111-4111-8111-000000000003",
        HOST,
        1,
        None,
        &["view"],
        now,
        now + 600_000,
    );
    let mut tampered = grant.to_json();
    tampered["body"]["ops"] = json!(["prompt", "view"]);
    let tampered = atem_client::SignedObject::parse(tampered.to_string().as_bytes()).unwrap();
    rig.connect("c6", Identity::browser(tampered, key).unwrap());
    let (code, detail) = rig.refused("c6");
    assert!(
        code == "handshake_failed" || detail.as_deref() == Some("invalid grant"),
        "{code} {detail:?}"
    );
    // Nothing was admitted.
    assert_eq!(rig.rt.host.welcomed_attachments(), 0);
}

/// A removal carried on an open channel fences the removed bot's live
/// attachment at once (its error, then its channel closes); the carrier
/// gets `membership_head`; other channels stay.
#[test]
fn a_carried_removal_fences_a_live_attachment() {
    let mut rig = Rig::new();
    rig.link_up();
    rig.connect("ch-phone", phone());
    rig.advance(1000);
    rig.connect("ch-bot", bot());
    rig.advance(1000);
    rig.connect(
        "ch-mac",
        Identity::native(r9log::MAC, r9log::auth(r9log::MAC)),
    );
    let removal = rig.log.remove("svc-bot");
    let mono = rig.now.host.mono_ms;
    let entry = atem_client::SignedObject::parse(removal.to_string().as_bytes()).unwrap();
    let (_, frame) = rig
        .attached("ch-phone")
        .send_membership(&[entry], mono)
        .unwrap();
    rig.send_frame("ch-phone", &frame);
    let events = rig.events("ch-phone");
    assert!(
        events.iter().any(|e| matches!(e, CEvent::MembershipHead { re: Some(_), head, .. } if *head == rig.log.log.head())),
        "{events:?}"
    );
    assert_eq!(
        rig.refused("ch-bot"),
        ("closed".into(), Some("closed".into()))
    );
    assert!(
        rig.closes
            .iter()
            .any(|(h, r)| h == "ch-bot" && r.as_deref() == Some("closed"))
    );
    // The Mac heard the head move.
    let events = rig.events("ch-mac");
    assert!(
        events
            .iter()
            .any(|e| matches!(e, CEvent::MembershipHead { re: None, .. })),
        "{events:?}"
    );
    assert_eq!(rig.engine.status().attachments, 2);
    assert_eq!(rig.rt.host.control_gen("service:svc-bot"), 2);
    // The bot can't come back.
    rig.advance(1000);
    rig.connect("ch-bot-2", bot());
    assert_eq!(
        rig.refused("ch-bot-2"),
        ("unauthorized".into(), Some("removed".into()))
    );
}

/// The removal arrives in a new client's hello instead (carry before
/// admission): the bot's live channel is fenced before the carrier is
/// judged.
#[test]
fn a_removal_carried_in_a_hello_fences_before_admission() {
    let mut rig = Rig::new();
    rig.link_up();
    rig.connect("ch-bot", bot());
    let host_log = rig.log.log.clone();
    rig.log.remove("svc-bot");
    rig.advance(1000);
    let client_log = rig.log.log.clone();
    rig.connect_with("ch-phone", phone(), Some(&client_log));
    let w = welcome(&mut rig, "ch-phone");
    assert_eq!(w.head, client_log.head());
    assert_ne!(host_log.head(), client_log.head());
    let events = rig.events("ch-bot");
    let _ = events;
    assert_eq!(rig.refused("ch-bot").0, "closed");
    assert_eq!(rig.m.as_ref().unwrap().head(), client_log.head());
}

/// An r8 `hello` is refused once a device list exists (no compatibility).
#[test]
fn an_r8_hello_is_refused_once_a_list_exists() {
    let mut rig = Rig::new();
    let attach = Attach {
        client: "astation-1".into(),
        principal: "astation:acct-r9:astation-1".into(),
        attachment_gen: "44444444-4444-4444-8444-444444444444".into(),
        permissions: vec![r8::Permission::View, r8::Permission::Control],
        client_kind: r8::ClientKind::Native,
        authorization_ms: 86_400_000,
    };
    let fx = rig.rt.host.connect(attach).unwrap();
    rig.rt.apply(fx);
    let hello = json!({"type": "session", "data": {"v": 1, "op": "hello",
        "id": "aaaaaaaa-0000-4000-8000-000000000001", "revision": 8}});
    let fx = rig.rt.host.receive(
        "44444444-4444-4444-8444-444444444444",
        hello.to_string().as_bytes(),
        rig.now.mono,
    );
    let sent: Vec<Value> = fx
        .iter()
        .filter_map(|e| match e {
            Effect::Send { message, .. } => Some(r8::to_value(message)),
            _ => None,
        })
        .collect();
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0]["data"]["code"], "unsupported_version");
    assert_eq!(sent[0]["data"]["revision"], 9);
    assert_eq!(rig.rt.host.welcomed_attachments(), 0);
}

// ── Refused device lists ──

/// No device list: `stale_target` (nothing of this host is pinned); a list
/// that failed to open: `busy`; both clear, before any key work.
#[test]
fn no_list_or_a_failed_one_refuses_r9() {
    let mut rig = Rig::new();
    rig.link_up();
    let m = rig.m.take();
    rig.connect("c1", phone());
    assert_eq!(rig.refused("c1").0, "stale_target");
    rig.m = m;
    rig.failed = Some("membership.json is damaged".into());
    rig.advance(1000);
    rig.connect("c2", phone());
    assert_eq!(rig.refused("c2").0, "busy");
    assert!(
        rig.closes
            .iter()
            .any(|(h, r)| h == "c2" && r.as_deref() == Some("busy"))
    );
}

/// A held host refuses everyone but a managing device at its head
/// (`busy` "device list not reconciled"); a frozen one refuses at `init`
/// (`account_frozen`, clear).
#[test]
fn held_and_frozen_lists_refuse_r9() {
    let mut rig = Rig::new();
    // A recorded fault: the next start is held.
    std::fs::write(
        &rig.pairing.fault,
        br#"{"v":1,"runtime_epoch":1,"file":"membership.json","at":1}"#,
    )
    .unwrap();
    let mut fences = HostFences::new(&mut rig.rt.host);
    let (m, _) = MembershipHost::open(&rig.pairing, &rig.journal, 2, &rig.now.host, &mut fences)
        .unwrap()
        .unwrap();
    assert!(m.held().is_some());
    rig.m = Some(m);
    rig.link_up();
    rig.connect("c1", phone());
    assert_eq!(
        rig.refused("c1"),
        ("busy".into(), Some("device list not reconciled".into()))
    );
    // The Mac (a manager at the host's head) reconciles.
    rig.advance(1000);
    rig.connect("c2", Identity::native(r9log::MAC, r9log::auth(r9log::MAC)));
    rig.attached("c2");
    assert!(rig.m.as_ref().unwrap().held().is_none());
    // A conflicting entry by a current manager freezes the host.
    let conflict = rig.log.conflicting_add("dev-x");
    rig.advance(1000);
    let mono = rig.now.host.mono_ms;
    let entry = atem_client::SignedObject::parse(conflict.to_string().as_bytes()).unwrap();
    let (_, frame) = rig.attached("c2").send_membership(&[entry], mono).unwrap();
    rig.send_frame("c2", &frame);
    assert!(rig.m.as_ref().unwrap().is_frozen());
    rig.advance(1000);
    rig.connect("c3", phone());
    assert_eq!(rig.refused("c3").0, "account_frozen");
}

/// A pending recovery shows in every welcome (and its subject is refused
/// `recovery_pending` until the wait ends).
#[test]
fn a_pending_recovery_is_shown_in_the_welcome() {
    let mut rig = Rig::new();
    let entry = rig.log.recovery_add("dev-newmac");
    rig.link_up();
    rig.connect("c1", phone());
    let mono = rig.now.host.mono_ms;
    let entry = atem_client::SignedObject::parse(entry.to_string().as_bytes()).unwrap();
    let (_, frame) = rig.attached("c1").send_membership(&[entry], mono).unwrap();
    rig.send_frame("c1", &frame);
    let events = rig.events("c1");
    assert!(
        events.iter().any(|e| matches!(e, CEvent::MembershipHead { pending_recovery, .. } if pending_recovery.len() == 1)),
        "{events:?}"
    );
    rig.advance(1000);
    rig.connect("c2", phone());
    let w = welcome(&mut rig, "c2");
    assert_eq!(w.pending_recovery.len(), 1);
    assert_eq!(w.pending_recovery[0].subject, "dev-newmac");
    assert!(w.pending_recovery[0].effective_at >= rig.now.host.wall_ms + 86_000_000);
    rig.advance(1000);
    rig.connect(
        "c3",
        Identity::native("dev-newmac", r9log::auth("dev-newmac")),
    );
    assert_eq!(rig.refused("c3").0, "recovery_pending");
}

// ── Fences per attachment and per principal ──

/// One principal with two attachments: closing one channel leaves the
/// other; a principal fence (expiry) closes both.
#[test]
fn attachments_are_fenced_alone_and_a_principal_together() {
    let mut rig = Rig::new();
    rig.link_up();
    rig.connect("bot-1", bot());
    rig.advance(1000);
    rig.connect("bot-2", bot());
    rig.advance(1000);
    rig.connect("phone", phone());
    rig.envelope_in(&envelope::close("bot-1", Some("client_gone")));
    assert_eq!(rig.engine.status().attachments, 2);
    assert_eq!(rig.list("bot-2"), vec![SID.to_string()]);
    // The bot's expiry passes: both of its attachments (one left) go, the
    // phone stays.
    rig.advance(3_600_000);
    assert_eq!(rig.refused("bot-2").0, "closed");
    assert_eq!(rig.engine.status().attachments, 1);
    assert!(rig.rt.host.control_gen("service:svc-bot") >= 2);
    assert_eq!(rig.list("phone").len(), 2);
}

/// `revoke_grant` from the issuer: the browser is fenced ("grant revoked")
/// and can't come back with that grant.
#[test]
fn a_revoked_grant_fences_its_browser() {
    let mut rig = Rig::new();
    rig.link_up();
    rig.connect("phone", phone());
    rig.advance(1000);
    let wall = rig.now.host.wall_ms;
    let grant_id = "aaaaaaaa-1111-4111-8111-000000000009";
    let (grant, key) = rig.log.grant(
        "dev-phone",
        grant_id,
        HOST,
        1,
        None,
        &["view"],
        wall,
        wall + 600_000,
    );
    rig.connect(
        "browser",
        Identity::browser(grant.clone(), key.clone()).unwrap(),
    );
    rig.attached("browser");
    let mono = rig.now.host.mono_ms;
    let (_, frame) = rig.attached("phone").revoke_grant(grant_id, mono).unwrap();
    rig.send_frame("phone", &frame);
    let events = rig.events("phone");
    assert!(
        events
            .iter()
            .any(|e| matches!(e, CEvent::GrantRevoked { .. })),
        "{events:?}"
    );
    assert_eq!(rig.refused("browser").0, "closed");
    rig.advance(1000);
    rig.connect("browser-2", Identity::browser(grant, key).unwrap());
    assert_eq!(
        rig.refused("browser-2"),
        ("unauthorized".into(), Some("grant revoked".into()))
    );
}

// ── The envelope ──

/// Unknown handles get one close; a duplicate open is ignored; the
/// router's close is never answered; one init a second per link.
#[test]
fn the_envelope_lifecycle_rules_hold() {
    let mut rig = Rig::new();
    rig.link_up();
    rig.connect("ch-1", phone());
    let ghost = envelope::frame(
        "ghost",
        br#"{"ch":"atem-ch1","op":"rec","ct":"AAAAAAAAAAAAAAAAAAAAAA"}"#,
    );
    rig.envelope_in(&ghost);
    rig.envelope_in(&ghost);
    let ghosts: Vec<_> = rig.closes.iter().filter(|(h, _)| h == "ghost").collect();
    assert_eq!(ghosts.len(), 1);
    assert_eq!(ghosts[0].1.as_deref(), Some("unknown_channel"));
    rig.envelope_in(&envelope::close("ghost", Some("unknown_channel")));
    rig.envelope_in(&envelope::open("ch-1", Transport::Direct));
    assert_eq!(
        rig.closes.len(),
        1,
        "nothing answers a close or a duplicate open"
    );
    assert_eq!(rig.list("ch-1").len(), 2, "the live channel is untouched");
    // A second init within the second: busy, that channel only.
    rig.advance(1000);
    rig.connect("ch-2", phone());
    rig.connect("ch-3", phone());
    assert_eq!(rig.refused("ch-3").0, "busy");
    assert!(
        rig.closes
            .iter()
            .any(|(h, r)| h == "ch-3" && r.as_deref() == Some("busy"))
    );
    rig.attached("ch-2");
    // A failed record closes only its channel.
    let mono = rig.now.host.mono_ms;
    let (_, mut frame) = rig.attached("ch-2").list(mono).unwrap();
    let n = frame.len();
    frame[n - 4] ^= 1;
    rig.send_frame("ch-2", &frame);
    assert!(rig.closes.iter().any(|(h, _)| h == "ch-2"));
    assert_eq!(rig.list("ch-1").len(), 2);
    // Link loss closes everything; an old handle is unknown afterwards.
    rig.link_down();
    assert_eq!(rig.engine.status().attachments, 0);
    assert_eq!(rig.rt.host.welcomed_attachments(), 0);
    rig.link_up();
    rig.closes.clear();
    rig.envelope_in(&envelope::frame(
        "ch-1",
        br#"{"ch":"atem-ch1","op":"rec","ct":"AAAAAAAAAAAAAAAAAAAAAA"}"#,
    ));
    assert_eq!(
        rig.closes,
        vec![("ch-1".to_string(), Some("unknown_channel".into()))]
    );
}

/// A channel whose queued output passes its bound is closed (`busy`)
/// explicitly; another channel keeps working.
#[test]
fn a_channel_that_falls_behind_is_closed_alone() {
    let mut rig = Rig::new();
    rig.engine = R9Host::new(
        Limits {
            queued_bytes: 8 * 1024,
            ..Limits::default()
        },
        None,
    );
    rig.link_up();
    rig.connect("slow", phone());
    rig.advance(1000);
    rig.connect("fast", phone());
    rig.stalled = true;
    for _ in 0..40 {
        let mono = rig.now.host.mono_ms;
        let (_, frame) = rig.attached("slow").list(mono).unwrap();
        let text = envelope::frame("slow", &frame);
        rig.run(|e, p| ((), e.on_envelope(&text, p)));
    }
    rig.stalled = false;
    rig.pump();
    assert!(
        rig.closes
            .iter()
            .any(|(h, r)| h == "slow" && r.as_deref() == Some("busy"))
    );
    rig.advance(10);
    assert_eq!(rig.list("fast").len(), 2);
    assert_eq!(rig.engine.status().attachments, 1);
}

/// `approval_seen`: `seen` for a pending approval of the exact session and
/// process, `stale_target` otherwise; services need the `approval` op.
#[test]
fn approval_seen_is_answered_on_the_host_side() {
    let mut rig = Rig::new();
    rig.link_up();
    rig.connect("phone", phone());
    let info = crate::session_protocol::host::ApprovalInfo {
        tool: "Bash".into(),
        summary: "ls".into(),
        always_rules: Vec::new(),
    };
    let (opened, fx) = rig.rt.host.open_approval(SID, PGEN, info, rig.now.mono);
    rig.rt.apply(fx);
    rig.route();
    let approval = opened.unwrap();
    rig.pump();
    rig.events("phone");
    let b = rig.binding("phone", SID);
    let seen = |rig: &mut Rig, b: &Value| {
        rig.send(
            "phone",
            &json!({"type": "session", "data": {"v": 1, "op": "approval_seen",
                "id": uuid::Uuid::new_v4().to_string(), "binding": b, "approval_id": approval}}),
        );
        rig.events("phone")
    };
    let events = seen(&mut rig, &b);
    assert!(
        events.iter().any(|e| matches!(e, CEvent::Seen { .. })),
        "{events:?}"
    );
    let events = seen(&mut rig, &b);
    assert!(
        events.iter().any(|e| matches!(e, CEvent::Seen { .. })),
        "a repeat is seen too"
    );
    let mut other = b.clone();
    other["target"]["process_gen"] = json!(PGEN_B);
    let events = seen(&mut rig, &other);
    assert_eq!(
        Rig::last_error(&events).map(|e| e.0),
        Some("stale_target".into())
    );
    // The bot (no `approval` op) is forbidden.
    rig.advance(1000);
    rig.connect("bot", bot());
    let b = rig.binding("bot", SID);
    rig.send(
        "bot",
        &json!({"type": "session", "data": {"v": 1, "op": "approval_seen",
            "id": "aaaaaaaa-0000-4000-8000-000000000077", "binding": b, "approval_id": approval}}),
    );
    let events = rig.events("bot");
    assert_eq!(
        Rig::last_error(&events).map(|e| e.0),
        Some("forbidden".into())
    );
}
