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
pub(super) const PGEN: &str = "22222222-2222-4222-8222-222222222222";
pub(super) const PGEN_B: &str = "33333333-3333-4333-8333-333333333333";
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
    pub host_id: String,
    /// The runtime's project scopes (none: `NoProjects`, a rig that needs
    /// no cred agent).
    pub projects: Option<crate::runtime::project_scope::ProjectScopes>,
    /// What Atem sent the relay (§R9.9), in order, not taken yet.
    pub relay: std::collections::VecDeque<Value>,
    /// The relay takes nothing (its messages are lost).
    pub relay_down: bool,
}

/// The hook's wait the rig's approvals get (Claude's, 600 s).
pub(super) const WAIT_MS: u64 = 600_000;

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
        let sessions = json!([{"session_id": SID, "process_gen": PGEN, "chat": true},
                              {"session_id": SID_B, "process_gen": PGEN_B, "chat": true}]);
        Self::with_sessions(more, sessions)
    }

    /// [`Rig::with`] running `sessions` (`[{session_id, process_gen,
    /// chat}]`) instead of the two.
    pub fn with_sessions(more: impl FnOnce(&mut TestLog), sessions: Value) -> Rig {
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
        drop(profile);
        Self::build(dir, log, HOST, 1, host_seed, sessions)
    }

    /// A rig whose device list is `log`, pinned for `host_id` at
    /// `host_trust_gen` with `host_seed`, and these sessions.
    pub fn build(
        dir: tempfile::TempDir,
        log: TestLog,
        host_id: &str,
        host_trust_gen: u64,
        host_seed: [u8; 32],
        sessions: Value,
    ) -> Rig {
        let profile = crate::paths::ProfilePaths::in_dir(dir.path());
        let journal = dir.path().join("runtime").join("journal");
        store::private_dir(&journal).unwrap();
        let pin = HostPin {
            host_id: host_id.into(),
            host_trust_gen,
        };
        MembershipHost::pin(&profile.pairing, &journal, &pin, &log.log, &host_seed).unwrap();
        let setup = json!({
            "host": {"account_id": log.account, "atem_device_id": host_id,
                     "host_trust_gen": host_trust_gen,
                     "runtime_gen": "11111111-1111-4111-8111-111111111111", "runtime_epoch": 1},
            "sessions": sessions,
            "clients": [],
        });
        let file_journal = FileJournal::open(&journal).unwrap();
        let now = now_at(r9log::host_now().wall_ms, 1_000);
        let mut rt = FakeRuntime::from_json_with(setup, HostConfig::default(), file_journal);
        rt.host.set_refuse_r8(true);
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
            host_id: host_id.to_string(),
            projects: None,
            relay: Default::default(),
            relay_down: false,
        }
    }

    /// Runs `f` on the engine with this rig's parts, then performs the
    /// effects (r9 attachments' messages back to the engine).
    pub fn run<T>(
        &mut self,
        f: impl FnOnce(&mut R9Host, &mut Parts<'_, FileJournal>) -> (T, Vec<Effect>),
    ) -> T {
        let (out, effects) = self.with_parts(f);
        self.rt.apply(effects);
        self.route();
        self.engine.end_pass();
        out
    }

    /// Runs `f` on the engine with this rig's parts (nothing else).
    pub fn with_parts<T>(
        &mut self,
        f: impl FnOnce(&mut R9Host, &mut Parts<'_, FileJournal>) -> T,
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
            projects: match &self.projects {
                Some(p) => p,
                None => &NoProjects,
            },
        };
        f(&mut self.engine, &mut parts)
    }

    /// The session host's messages and closes for r9 attachments.
    pub fn route(&mut self) {
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
                        match &self.projects {
                            Some(p) => p as &dyn ProjectScope,
                            None => &NoProjects,
                        },
                        &self.host_id,
                        self.now.host.mono_ms,
                    ),
                    Effect::Close { attachment } => self
                        .engine
                        .close_attachment(&attachment, self.now.host.mono_ms),
                    // §R9.9, as the runtime's bridge does.
                    Effect::PushApproval { request } => {
                        self.with_parts(|e, p| e.approval_opened(&request, WAIT_MS, p))
                    }
                    Effect::PushResolved {
                        approval_id,
                        reason,
                    } => self.with_parts(|e, p| e.approval_resolved(&approval_id, reason, p)),
                    _ => {}
                }
            }
        }
    }

    /// What Atem sent the relay since the last call (the link takes it
    /// unless `relay_down`).
    pub fn relay_out(&mut self) -> Vec<Value> {
        self.pump();
        std::mem::take(&mut self.relay).into_iter().collect()
    }

    /// The relay acknowledges.
    pub fn relay_in(&mut self, message: &Value) {
        let text = message.to_string();
        self.engine.relay_message(&text);
        self.pump();
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
        // As the runtime's pass: channels closed on Atem's side (overflow)
        // leave the session host.
        self.run(|e, p| ((), e.reap(p)));
        let mut relay = Vec::new();
        let down = self.relay_down;
        self.engine.flush_relay(&mut |text| {
            if !down {
                relay.push(serde_json::from_str::<Value>(&text).unwrap());
            }
            true
        });
        self.relay.extend(relay);
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
                Event::Frame { channel, frame } => self.deliver_to_client(&channel, &frame),
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

    fn deliver_to_client(&mut self, handle: &str, frame: &[u8]) {
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

    pub fn send_frame_raw(&mut self, handle: &str, frame: &[u8]) {
        self.send_frame(handle, frame);
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
        self.connect_full(handle, identity, log, Transport::Relay);
    }

    /// As [`Rig::connect`], opened with `transport`.
    pub fn connect_via(&mut self, handle: &str, identity: Identity, transport: Transport) {
        self.connect_full(handle, identity, None, transport);
    }

    fn connect_full(
        &mut self,
        handle: &str,
        identity: Identity,
        log: Option<&Membership>,
        transport: Transport,
    ) {
        IDS.with(|ids| ids.borrow_mut().insert(handle.to_string(), identity));
        self.envelope_in(&envelope::open(handle, transport));
        let log = log.unwrap_or(&self.log.log).clone();
        let (connecting, init) = Connector::new(&self.host_id)
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

/// A held host and a `finish` naming a manager at the host's head whose
/// `sig_c` is forged (another key): `handshake_failed`, and the host stays
/// held with `membership.fault` on disk (reconciliation only after the
/// proof is verified, §R9.3 "Held", §R9.7 step 6). The real manager then
/// reconciles.
#[test]
fn a_forged_finish_never_lifts_a_hold() {
    let mut rig = Rig::new();
    std::fs::write(
        &rig.pairing.fault,
        br#"{"v":1,"runtime_epoch":1,"file":"membership.json","at":1}"#,
    )
    .unwrap();
    let mut fences = HostFences::new(&mut rig.rt.host);
    let (m, _) = MembershipHost::open(&rig.pairing, &rig.journal, 2, &rig.now.host, &mut fences)
        .unwrap()
        .unwrap();
    rig.m = Some(m);
    rig.link_up();
    // The Mac's device id (public in the log), a proof under another key.
    rig.connect(
        "forged",
        Identity::native(r9log::MAC, r9log::auth("svc-bot")),
    );
    assert_eq!(rig.refused("forged").0, "handshake_failed");
    assert!(rig.m.as_ref().unwrap().held().is_some());
    assert!(rig.pairing.fault.exists());
    // Still held for everyone else.
    rig.advance(1000);
    rig.connect("c1", phone());
    assert_eq!(
        rig.refused("c1"),
        ("busy".into(), Some("device list not reconciled".into()))
    );
    assert!(rig.pairing.fault.exists());
    // The manager's own proof reconciles.
    rig.advance(1000);
    rig.connect("mac", Identity::native(r9log::MAC, r9log::auth(r9log::MAC)));
    rig.attached("mac");
    assert!(rig.m.as_ref().unwrap().held().is_none());
    assert!(!rig.pairing.fault.exists());
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
    let (opened, fx) =
        rig.rt
            .host
            .open_approval_at(SID, PGEN, info, rig.now.mono, rig.now.host.wall_ms);
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

// ── Review round 1 ──

/// A flood of refused opens (over the channel bounds, the link stalled)
/// never grows the close queue past its rate and cap; the rest is dropped
/// and counted (§R9.7a "Bounds").
#[test]
fn a_flood_of_refused_opens_cant_grow_the_close_queue() {
    let mut rig = Rig::new();
    rig.engine = R9Host::new(
        Limits {
            open_channels: 2,
            global_closes: 40,
            ..Limits::default()
        },
        None,
    );
    rig.link_up();
    rig.stalled = true;
    for second in 0..10 {
        for i in 0..500 {
            rig.envelope_in(&envelope::open(
                &format!("f-{second}-{i}"),
                Transport::Relay,
            ));
        }
        let queued = rig.engine.queued_closes();
        assert!(
            queued <= (second + 1) * 16 + 2 && queued <= 40,
            "{queued} closes queued after {second} s"
        );
        rig.advance(1000);
    }
    assert_eq!(rig.engine.queued_closes(), 40, "capped");
    // Unknown handles beyond the remembered ones are dropped, never answered.
    let mut rig = Rig::new();
    rig.engine = R9Host::new(
        Limits {
            unknown_handles: 3,
            ..Limits::default()
        },
        None,
    );
    rig.link_up();
    for i in 0..10 {
        rig.envelope_in(&envelope::frame(
            &format!("ghost-{i}"),
            br#"{"ch":"atem-ch1","op":"rec","ct":"AAAAAAAAAAAAAAAAAAAAAA"}"#,
        ));
    }
    assert_eq!(rig.closes.len(), 3);
}

/// An inner frame over the bound closes its channel `too_large`, before
/// any key work; a frame at the bound is the channel's to judge.
#[test]
fn an_oversize_inner_frame_is_too_large() {
    let mut rig = Rig::new();
    rig.link_up();
    rig.connect("big", phone());
    let ct = atem_client::encoding::b64u(&vec![0u8; (1 << 20) + 17]);
    let frame = json!({"ch": "atem-ch1", "op": "rec", "ct": ct}).to_string();
    assert_eq!(frame.len(), 1_398_160, "a ct one character over");
    rig.send_frame_raw("big", frame.as_bytes());
    assert!(
        rig.closes
            .iter()
            .any(|(h, r)| h == "big" && r.as_deref() == Some("too_large"))
    );
    assert_eq!(rig.engine.status().attachments, 0);
}

/// Restarting the channels on a live socket (a re-pin, an unpair, a
/// re-authentication) gives each live handle a close{closed}.
#[test]
fn a_restart_closes_every_live_handle() {
    let mut rig = Rig::new();
    rig.link_up();
    rig.connect("a", phone());
    rig.advance(1000);
    rig.connect("b", bot());
    rig.envelope_in(&envelope::open("c", Transport::Relay));
    // A close already queued outside a channel (an unknown handle) stays.
    rig.stalled = true;
    rig.envelope_in(&envelope::frame(
        "ghost",
        br#"{"ch":"atem-ch1","op":"rec","ct":"AAAAAAAAAAAAAAAAAAAAAA"}"#,
    ));
    rig.closes.clear();
    let link = rig.link_gen;
    rig.run(|e, p| {
        let mut fx = e.restart(p);
        fx.extend(e.link_up(link, p));
        ((), fx)
    });
    rig.stalled = false;
    rig.pump();
    let mut handles: Vec<String> = rig
        .closes
        .iter()
        .map(|(h, r)| {
            let want = if h == "ghost" {
                "unknown_channel"
            } else {
                "closed"
            };
            assert_eq!(r.as_deref(), Some(want), "{h}");
            h.clone()
        })
        .collect();
    handles.sort();
    assert_eq!(handles, ["a", "b", "c", "ghost"]);
    assert_eq!(rig.rt.host.welcomed_attachments(), 0);
}

/// N9: a new link generation on a live socket hands the old generation's
/// closes to the socket first; what a backed-up writer doesn't take is
/// dropped and counted, never sent on the new generation (a handle is
/// scoped to its generation).
#[test]
fn closes_never_cross_a_link_generation() {
    let mut rig = Rig::new();
    rig.link_up();
    rig.connect("a", phone());
    rig.advance(1000);
    rig.connect("b", bot());
    rig.stalled = true;
    rig.envelope_in(&envelope::frame(
        "ghost",
        br#"{"ch":"atem-ch1","op":"rec","ct":"AAAAAAAAAAAAAAAAAAAAAA"}"#,
    ));
    rig.closes.clear();
    // The writer takes one envelope, then is backed up.
    let mut sent = Vec::new();
    rig.run(|e, p| {
        let fx = e.end_generation(p, &mut |text| {
            if sent.is_empty() {
                sent.push(text);
                true
            } else {
                false
            }
        });
        ((), fx)
    });
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert!(sent[0].contains("ghost") && sent[0].contains("unknown_channel"));
    assert_eq!(rig.engine.queued_closes(), 0, "the rest was dropped");
    assert_eq!(rig.rt.host.welcomed_attachments(), 0);
    // The new generation: a client reuses handle "a"; nothing of the old
    // one reaches it.
    rig.stalled = false;
    rig.link_up();
    rig.connect("a", phone());
    rig.pump();
    assert!(
        rig.closes.iter().all(|(h, _)| h != "a" && h != "b"),
        "{:?}",
        rig.closes
    );
    assert!(!rig.list("a").is_empty());
    // An idle writer takes every close before the new generation.
    rig.closes.clear();
    let mut all = Vec::new();
    rig.run(|e, p| {
        let fx = e.end_generation(p, &mut |text| {
            all.push(text);
            true
        });
        ((), fx)
    });
    assert_eq!(all.len(), 1);
    assert!(all[0].contains("\"a\"") && all[0].contains("closed"));
}

/// `approval_closed` reaches a scoped service only for an approval of a
/// session in its scope (and only with the `approval` op).
#[test]
fn approval_closed_is_scope_checked() {
    let wall = r9log::host_now().wall_ms;
    let mut rig = Rig::with(|log| {
        log.add_service(
            "svc-ap",
            &[HOST],
            Some(&[SID]),
            &["approval", "view"],
            wall + 3_600_000,
        );
    });
    rig.link_up();
    rig.connect("ap", Identity::service("svc-ap", r9log::auth("svc-ap")));
    rig.list("ap");
    let info = || crate::session_protocol::host::ApprovalInfo {
        tool: "Bash".into(),
        summary: "ls".into(),
        always_rules: Vec::new(),
    };
    let mut ids = Vec::new();
    for (sid, pgen) in [(SID, PGEN), (SID_B, PGEN_B)] {
        let (opened, fx) =
            rig.rt
                .host
                .open_approval_at(sid, pgen, info(), rig.now.mono, rig.now.host.wall_ms);
        rig.rt.apply(fx);
        ids.push(opened.unwrap());
    }
    for id in &ids {
        let fx = rig
            .rt
            .host
            .close_approval(id, r8::ApprovalCloseReason::Released);
        rig.rt.apply(fx);
    }
    rig.run(|_, _| ((), Vec::new()));
    rig.pump();
    let closed: Vec<String> = rig
        .events("ap")
        .into_iter()
        .filter_map(|e| match e {
            CEvent::Session(m) => match m.op {
                R8Op::ApprovalClosed { approval_id, .. } => Some(approval_id),
                _ => None,
            },
            _ => None,
        })
        .collect();
    assert_eq!(closed, vec![ids[0].clone()], "only its own session's");
}

/// Astation's overload case: the 16 handshake slots are full, output is
/// blocked, and opens and frames for unknown handles keep coming for
/// minutes. The closes queued outside a channel stay within 16 a second
/// and 1024 in all; the rest is dropped and counted.
#[test]
fn opens_and_unknown_frames_flooding_with_output_blocked_stay_bounded() {
    let mut rig = Rig::new();
    rig.link_up();
    for i in 0..16 {
        rig.envelope_in(&envelope::open(&format!("pending-{i}"), Transport::Relay));
    }
    rig.stalled = true;
    let ghost = br#"{"ch":"atem-ch1","op":"rec","ct":"AAAAAAAAAAAAAAAAAAAAAA"}"#;
    for second in 0..120u64 {
        for i in 0..50 {
            rig.envelope_in(&envelope::open(
                &format!("x-{second}-{i}"),
                Transport::Relay,
            ));
            rig.envelope_in(&envelope::frame(&format!("u-{second}-{i}"), ghost));
        }
        let queued = rig.engine.queued_closes();
        assert!(
            queued <= 1024 && queued as u64 <= (second + 1) * 16,
            "{queued} after {second} s"
        );
        // Keep the handshakes pending (their 10 s step not reached).
        rig.now.mono += 1000;
        rig.now.host.mono_ms += 1000;
        rig.now.host.wall_ms += 1000;
    }
    assert_eq!(rig.engine.queued_closes(), 1024);
}

/// Astation's review of 66ea556: repeated restarts on a live socket with
/// output blocked never grow the queue past a fixed ceiling. A restart's
/// `close{closed}` holds its channel's slot until the link takes it, so
/// opens are refused while 64 are pending; when the link takes again the
/// refusals queued first go first, then every restarted handle's close,
/// once each, in restart order.
#[test]
fn repeated_restarts_with_output_blocked_keep_a_fixed_ceiling() {
    let mut rig = Rig::new();
    rig.link_up();
    let link = rig.link_gen;
    rig.stalled = true;
    let ghost = br#"{"ch":"atem-ch1","op":"rec","ct":"AAAAAAAAAAAAAAAAAAAAAA"}"#;
    // The refusal queue full (1024 at 16 a second).
    for second in 0..64u64 {
        for i in 0..16 {
            rig.envelope_in(&envelope::frame(&format!("u-{second}-{i}"), ghost));
        }
        rig.now.mono += 1000;
        rig.now.host.mono_ms += 1000;
        rig.now.host.wall_ms += 1000;
    }
    assert_eq!(rig.engine.queued_closes(), 1024);
    let widest = envelope::close(&"x".repeat(64), Some("unknown_channel")).len();
    let mut restarted: Vec<String> = Vec::new();
    for cycle in 0..12 {
        for i in 0..16 {
            rig.envelope_in(&envelope::open(&format!("c{cycle}-{i}"), Transport::Relay));
        }
        let live: Vec<String> = (0..16)
            .map(|i| format!("c{cycle}-{i}"))
            .filter(|h| rig.engine.chans.contains_key(h))
            .collect();
        restarted.extend(live);
        rig.run(|e, p| {
            let mut fx = e.restart(p);
            fx.extend(e.link_up(link, p));
            ((), fx)
        });
        let queued = rig.engine.queued_closes();
        assert!(queued <= 1024 + 64, "cycle {cycle}: {queued} queued");
        assert!(rig.engine.pending_lifecycle_closes() <= 64);
        assert!(rig.engine.queued_close_bytes() <= (1024 + 64) * widest);
    }
    assert_eq!(
        restarted.len(),
        64,
        "four cycles fill the slots, then opens wait"
    );
    assert_eq!(rig.engine.queued_closes(), 1024 + 64);
    rig.closes.clear();
    rig.stalled = false;
    rig.pump();
    let (refusals, lifecycle) = rig.closes.split_at(1024);
    assert!(
        refusals
            .iter()
            .all(|(h, r)| h.starts_with("u-") && r.as_deref() == Some("unknown_channel"))
    );
    let closed: Vec<String> = lifecycle
        .iter()
        .map(|(h, r)| {
            assert_eq!(r.as_deref(), Some("closed"), "{h}");
            h.clone()
        })
        .collect();
    let mut want = restarted.clone();
    want.sort_by_key(|h| {
        let (c, i) = h[1..].split_once('-').unwrap();
        (c.parse::<u32>().unwrap(), i.parse::<u32>().unwrap())
    });
    let mut got = closed.clone();
    got.sort_by_key(|h| {
        let (c, i) = h[1..].split_once('-').unwrap();
        (c.parse::<u32>().unwrap(), i.parse::<u32>().unwrap())
    });
    assert_eq!(got, want, "every restarted handle closed once");
    // In restart order: a cycle's closes before the next cycle's.
    let cycles: Vec<u32> = closed
        .iter()
        .map(|h| h[1..].split_once('-').unwrap().0.parse().unwrap())
        .collect();
    assert!(cycles.windows(2).all(|w| w[0] <= w[1]), "{cycles:?}");
    assert_eq!(rig.engine.pending_lifecycle_closes(), 0);
    // The slots are free again.
    rig.connect("p", phone());
    assert!(!rig.list("p").is_empty());
}

/// One `unknown_channel` per handle per link generation, then drop: the
/// 1025th handle gets nothing, and the first, replayed in a later rate
/// window, gets nothing either.
#[test]
fn unknown_handles_get_one_close_each_and_the_1025th_none() {
    let mut rig = Rig::new();
    rig.link_up();
    let ghost = br#"{"ch":"atem-ch1","op":"rec","ct":"AAAAAAAAAAAAAAAAAAAAAA"}"#;
    for i in 0..1025 {
        if i % 16 == 0 {
            rig.advance(1000);
        }
        rig.envelope_in(&envelope::frame(&format!("ghost-{i}"), ghost));
    }
    let unknown = |rig: &Rig| {
        rig.closes
            .iter()
            .filter(|(_, r)| r.as_deref() == Some("unknown_channel"))
            .count()
    };
    assert_eq!(unknown(&rig), 1024);
    assert!(!rig.closes.iter().any(|(h, _)| h == "ghost-1024"));
    rig.advance(5000);
    rig.envelope_in(&envelope::frame("ghost-0", ghost));
    rig.envelope_in(&envelope::frame("ghost-1024", ghost));
    assert_eq!(unknown(&rig), 1024, "no second close, no eviction");
}

/// Fair service with output backed up: a channel with a long queue
/// doesn't hold another's records back; each round gives every channel
/// one message, starting after the one the link last refused.
#[test]
fn a_backed_up_link_serves_the_channels_in_turn() {
    let mut rig = Rig::new();
    rig.link_up();
    rig.connect("a-busy", phone());
    rig.advance(1000);
    rig.connect("b-quiet", phone());
    rig.stalled = true;
    for _ in 0..20 {
        let mono = rig.now.host.mono_ms;
        let (_, frame) = rig.attached("a-busy").list(mono).unwrap();
        let text = envelope::frame("a-busy", &frame);
        rig.run(|e, p| ((), e.on_envelope(&text, p)));
    }
    let mono = rig.now.host.mono_ms;
    let (_, frame) = rig.attached("b-quiet").list(mono).unwrap();
    let text = envelope::frame("b-quiet", &frame);
    rig.run(|e, p| ((), e.on_envelope(&text, p)));
    // The link takes three messages: the quiet channel's reply is among
    // them, not behind the busy one's twenty.
    let mut taken = Vec::new();
    let mut budget = 3;
    rig.engine.flush(&mut |t| {
        if budget == 0 {
            return false;
        }
        budget -= 1;
        taken.push(t);
        true
    });
    let channels: Vec<String> = taken
        .iter()
        .map(|t| envelope::parse(t).unwrap().channel().to_string())
        .collect();
    assert!(channels.contains(&"b-quiet".to_string()), "{channels:?}");
}

/// N1: the outside-channel rate is one window on one clock, whatever the
/// session clock says: refused opens and unknown frames alternating in
/// one second queue at most 16.
#[test]
fn the_refusal_rate_uses_one_clock() {
    let mut rig = Rig::new();
    rig.engine = R9Host::new(
        Limits {
            open_channels: 1,
            ..Limits::default()
        },
        None,
    );
    rig.link_up();
    rig.envelope_in(&envelope::open("held", Transport::Relay));
    rig.stalled = true;
    // The session clock far from the host clock (different origins).
    rig.now.mono = 7;
    rig.now.host.mono_ms = 9_000_000_000;
    let ghost = br#"{"ch":"atem-ch1","op":"rec","ct":"AAAAAAAAAAAAAAAAAAAAAA"}"#;
    for i in 0..50 {
        rig.envelope_in(&envelope::open(&format!("o-{i}"), Transport::Relay));
        rig.envelope_in(&envelope::frame(&format!("u-{i}"), ghost));
    }
    assert_eq!(rig.engine.queued_closes(), 16);
}

/// N2: with more backed-up channels than the link takes per pass, every
/// channel gets about an equal share (the round resumes at the channel the
/// link refused).
#[test]
fn backed_up_channels_share_the_link_equally() {
    for (channels, per_pass) in [(2usize, 1usize), (3, 2)] {
        let mut rig = Rig::new();
        rig.link_up();
        let names: Vec<String> = (0..channels).map(|i| format!("ch-{i}")).collect();
        for name in &names {
            rig.connect(name, phone());
            rig.advance(1000);
        }
        rig.stalled = true;
        for name in &names {
            for _ in 0..30 {
                let mono = rig.now.host.mono_ms;
                let (_, frame) = rig.attached(name).list(mono).unwrap();
                let text = envelope::frame(name, &frame);
                rig.run(|e, p| ((), e.on_envelope(&text, p)));
            }
        }
        let mut served: BTreeMap<String, usize> = BTreeMap::new();
        for _ in 0..(9 * channels / per_pass) {
            let mut budget = per_pass;
            rig.engine.flush(&mut |t| {
                if budget == 0 {
                    return false;
                }
                budget -= 1;
                *served
                    .entry(envelope::parse(&t).unwrap().channel().to_string())
                    .or_default() += 1;
                true
            });
        }
        let counts: Vec<usize> = names
            .iter()
            .map(|n| served.get(n).copied().unwrap_or(0))
            .collect();
        let (min, max) = (counts.iter().min().unwrap(), counts.iter().max().unwrap());
        assert!(
            max - min <= 1,
            "{channels} channels at {per_pass} a pass: {counts:?}"
        );
    }
}

/// R9.10 with the PTY-write fence: a native phone holds the lease, its
/// terminal input waits at the writer, and the Mac carries the phone's
/// removal: the phone's attachment is fenced at once ("removed", then
/// Atem's close), the Mac hears the lease revoked, and the queued bytes are
/// dropped at the write boundary, never written.
#[test]
fn a_removed_phones_queued_terminal_input_is_dropped_at_the_write_boundary() {
    use crate::session_protocol::fixtures::{HostEvent, HostUnderTest};
    let mut rig = Rig::new();
    rig.link_up();
    rig.connect("ch-phone", phone());
    rig.advance(1000);
    rig.connect(
        "ch-mac",
        Identity::native(r9log::MAC, r9log::auth(r9log::MAC)),
    );
    rig.list("ch-mac");
    let read = rig.binding("ch-phone", SID);
    rig.send(
        "ch-phone",
        &json!({"type": "session", "data": {"v": 1, "op": "acquire",
            "id": "aaaaaaaa-0000-4000-8000-0000000000c1", "binding": read, "takeover": false}}),
    );
    assert_eq!(rig.rt.host.lease_epoch(SID), Some(1));
    rig.send(
        "ch-phone",
        &json!({"type": "terminal", "data": {"v": 1, "op": "subscribe", "terminal_id": SID,
            "generation": PGEN, "binding": read}}),
    );
    let stream = rig
        .events("ch-phone")
        .into_iter()
        .find_map(|e| match e {
            CEvent::Family(f) => f
                .data
                .filter(|d| d["op"] == "attached")
                .map(|d| d["stream_id"].clone()),
            _ => None,
        })
        .expect("subscribed");
    let now = rig.rt.now();
    rig.rt.event(&HostEvent::HoldPtyWrites, now).unwrap();
    let mut lease = read.clone();
    lease["lease_epoch"] = json!(1);
    rig.send(
        "ch-phone",
        &json!({"type": "terminal", "data": {"v": 1, "op": "input", "terminal_id": SID,
            "generation": PGEN, "stream_id": stream, "sequence": 0, "bytes": "eA==",
            "binding": lease}}),
    );
    rig.events("ch-mac");
    // The Mac carries the phone's removal.
    let removal = rig.log.remove("dev-phone");
    let mono = rig.now.host.mono_ms;
    let entry = atem_client::SignedObject::parse(removal.to_string().as_bytes()).unwrap();
    let (_, frame) = rig
        .attached("ch-mac")
        .send_membership(&[entry], mono)
        .unwrap();
    rig.send_frame("ch-mac", &frame);
    assert_eq!(
        rig.refused("ch-phone"),
        ("closed".into(), Some("closed".into()))
    );
    let events = rig.events("ch-mac");
    assert!(
        events.iter().any(|e| matches!(e, CEvent::Session(m)
            if matches!(&m.op, R8Op::LeaseChanged { reason, .. }
                if format!("{reason:?}").to_lowercase().contains("revoked")))),
        "{events:?}"
    );
    let now = rig.rt.now();
    rig.rt.event(&HostEvent::FlushPtyWrites, now).unwrap();
    assert_eq!(rig.rt.counter("pty_writes_dropped").unwrap(), json!(1));
    assert_eq!(rig.rt.counter("pty_writes_remote").unwrap(), json!(0));
    assert_eq!(rig.rt.host.lease_holder(SID), None);
    assert_eq!(rig.rt.host.control_gen("member:dev-phone"), 2);
}

/// §R9.6 project scopes on the real path (`ProjectScopes` asking a cred
/// agent through `Crypt`, here a table agent): a project-scoped bot sees
/// nothing while the agent is locked (pending, out of scope), and once an
/// unlock makes the hashes known it gets `session_changed` for its
/// project's session only; its `list` then shows exactly that session.
#[test]
fn a_project_scoped_bot_sees_its_projects_sessions_only_after_an_unlock() {
    use crate::runtime::project_scope::{CredAgentHasher, ProjectScopes, TableAgent};
    let wall = r9log::host_now().wall_ms;
    let mine = "h1.0a0b0c0d.1111111111111111111111111111111111111111111111111111111111111111";
    let mut rig = Rig::with(|log| {
        log.add_service_projects(
            "svc-proj",
            &[HOST],
            Some(&[mine]),
            None,
            &["prompt", "view"],
            wall + 3_600_000,
        );
    });
    let agent = TableAgent::new(false);
    {
        let mut t = agent.table.lock().unwrap();
        t.insert(
            ("github.com/agora/mine".into(), "0a0b0c0d".into()),
            mine.into(),
        );
        t.insert(
            ("github.com/agora/other".into(), "0a0b0c0d".into()),
            "h1.0a0b0c0d.2222222222222222222222222222222222222222222222222222222222222222".into(),
        );
    }
    let mut scopes = ProjectScopes::new(std::sync::Arc::new(CredAgentHasher {
        agent: agent.clone(),
        astation_id: "astation-1".into(),
    }));
    scopes.session(SID, Some("github.com/agora/mine".into()));
    scopes.session(SID_B, Some("github.com/agora/other".into()));
    rig.projects = Some(scopes);
    let settle = |rig: &mut Rig| -> Vec<String> {
        let kids = rig.engine.scope_project_kids();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        loop {
            let fresh = rig
                .projects
                .as_mut()
                .unwrap()
                .pass(&kids, std::time::Instant::now());
            if !fresh.is_empty() {
                return fresh;
            }
            if std::time::Instant::now() > deadline {
                return Vec::new();
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    };
    rig.link_up();
    rig.connect(
        "ch-proj",
        Identity::service("svc-proj", r9log::auth("svc-proj")),
    );
    assert_eq!(rig.engine.scope_project_kids().len(), 1);
    // Locked: nothing is in scope.
    assert!(settle(&mut rig).is_empty());
    assert!(*agent.requests.lock().unwrap() >= 1, "the agent was asked");
    assert!(rig.list("ch-proj").is_empty());
    // Unlocked: the hashes come, the descriptors go out again.
    *agent.unlocked.lock().unwrap() = true;
    let mut fresh = Vec::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while fresh.is_empty() && std::time::Instant::now() < deadline {
        // The retry after a locked answer is RETRY later.
        let kids = rig.engine.scope_project_kids();
        fresh = rig.projects.as_mut().unwrap().pass(
            &kids,
            std::time::Instant::now() + crate::runtime::project_scope::RETRY,
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    fresh.sort();
    assert_eq!(fresh, vec![SID.to_string(), SID_B.to_string()]);
    for sid in fresh {
        rig.rt.host.registry_resend(&sid);
        let effects = rig.rt.host.take_effects();
        rig.run(|_, _| ((), effects));
    }
    rig.pump();
    let changed: Vec<String> = rig
        .events("ch-proj")
        .into_iter()
        .filter_map(|e| match e {
            CEvent::Session(m) => match m.op {
                R8Op::SessionChanged { descriptor, .. } => Some(descriptor.session_id),
                _ => None,
            },
            _ => None,
        })
        .collect();
    assert_eq!(changed, vec![SID.to_string()], "only its project's session");
    assert_eq!(rig.list("ch-proj"), vec![SID.to_string()]);
}

/// §R9.6 "fenced when the issuer is removed or loses `control`", with the
/// change carried in a new client's `hello` (§R9.3: the main route a
/// removal reaches a host): the browser the phone issued holds the lease
/// with terminal input queued at the writer; the Mac connects carrying
/// `change`; the browser is fenced at once (its channel closes, its lease
/// is revoked, its queued bytes are dropped at the write boundary), and it
/// can't come back. (Its raised control state is then pruned at the Mac's
/// own control write: nothing of it is left to order, see
/// `SessionHost::prune_principals`.)
fn a_carried_issuer_change_fences_its_browser(change: impl FnOnce(&mut TestLog)) {
    use crate::session_protocol::fixtures::{HostEvent, HostUnderTest};
    let mut rig = Rig::new();
    rig.link_up();
    let wall = rig.now.host.wall_ms;
    let grant_id = "aaaaaaaa-1111-4111-8111-0000000000c2";
    let (grant, key) = rig.log.grant(
        "dev-phone",
        grant_id,
        HOST,
        1,
        Some(SID),
        &["view", "terminal", "prompt"],
        wall,
        wall + 600_000,
    );
    rig.connect(
        "browser",
        Identity::browser(grant.clone(), key.clone()).unwrap(),
    );
    let read = rig.binding("browser", SID);
    rig.send(
        "browser",
        &json!({"type": "session", "data": {"v": 1, "op": "acquire",
            "id": "aaaaaaaa-0000-4000-8000-0000000000c3", "binding": read, "takeover": false}}),
    );
    assert_eq!(rig.rt.host.lease_epoch(SID), Some(1));
    rig.send(
        "browser",
        &json!({"type": "terminal", "data": {"v": 1, "op": "subscribe", "terminal_id": SID,
            "generation": PGEN, "binding": read}}),
    );
    let stream = rig
        .events("browser")
        .into_iter()
        .find_map(|e| match e {
            CEvent::Family(f) => f
                .data
                .filter(|d| d["op"] == "attached")
                .map(|d| d["stream_id"].clone()),
            _ => None,
        })
        .expect("subscribed");
    let now = rig.rt.now();
    rig.rt.event(&HostEvent::HoldPtyWrites, now).unwrap();
    let mut lease = read.clone();
    lease["lease_epoch"] = json!(1);
    rig.send(
        "browser",
        &json!({"type": "terminal", "data": {"v": 1, "op": "input", "terminal_id": SID,
            "generation": PGEN, "stream_id": stream, "sequence": 0, "bytes": "eA==",
            "binding": lease}}),
    );
    // The Mac connects with the change in its hello.
    change(&mut rig.log);
    let client_log = rig.log.log.clone();
    rig.advance(1000);
    rig.connect_with(
        "mac",
        Identity::native(r9log::MAC, r9log::auth(r9log::MAC)),
        Some(&client_log),
    );
    rig.attached("mac");
    assert_eq!(rig.m.as_ref().unwrap().head(), client_log.head());
    assert_eq!(rig.refused("browser").0, "closed");
    assert_eq!(rig.rt.host.lease_holder(SID), None);
    let now = rig.rt.now();
    rig.rt.event(&HostEvent::FlushPtyWrites, now).unwrap();
    assert_eq!(rig.rt.counter("pty_writes_dropped").unwrap(), json!(1));
    assert_eq!(rig.rt.counter("pty_writes_remote").unwrap(), json!(0));
    // The grant can't come back.
    rig.advance(1000);
    rig.connect("browser-2", Identity::browser(grant, key).unwrap());
    assert_eq!(rig.refused("browser-2").0, "unauthorized");
}

#[test]
fn an_issuers_removal_carried_in_a_hello_fences_its_browser() {
    a_carried_issuer_change_fences_its_browser(|log| {
        log.remove("dev-phone");
    });
}

#[test]
fn an_issuers_demotion_carried_in_a_hello_fences_its_browser() {
    a_carried_issuer_change_fences_its_browser(|log| {
        log.set_native_roles("dev-phone", &["view"]);
    });
}

/// A damaged `revoked_grants` file fails closed: a revocation it held
/// can't be told from none, so every browser grant is refused (`busy`)
/// until any grant it could name has expired (grant lifetime + issue
/// slack after the start); members are unaffected; after that window
/// browsers are admitted again.
#[test]
fn a_damaged_revoked_grants_file_refuses_browsers_until_any_grant_expired() {
    let mut rig = Rig::new();
    std::fs::write(rig.journal.join(REVOKED_GRANTS_FILE), b"{not json").unwrap();
    rig.engine = R9Host::new(Limits::default(), Some(&rig.journal));
    rig.link_up();
    let grant = |rig: &mut Rig, n: u32| {
        let wall = rig.now.host.wall_ms;
        rig.log.grant(
            "dev-phone",
            &format!("aaaaaaaa-1111-4111-8111-0000000000{n:02}"),
            HOST,
            1,
            None,
            &["view"],
            wall,
            wall + 600_000,
        )
    };
    let (g, k) = grant(&mut rig, 1);
    rig.connect("b1", Identity::browser(g, k).unwrap());
    assert_eq!(rig.refused("b1").0, "busy");
    rig.advance(1000);
    rig.connect("ph", phone());
    rig.attached("ph");
    rig.advance(GRANT_MAX_LIFETIME_MS + GRANT_ISSUED_AHEAD_MS - 60_000);
    let (g, k) = grant(&mut rig, 2);
    rig.connect("b2", Identity::browser(g, k).unwrap());
    assert_eq!(rig.refused("b2").0, "busy");
    rig.advance(61_000);
    let (g, k) = grant(&mut rig, 3);
    rig.connect("b3", Identity::browser(g, k).unwrap());
    rig.attached("b3");
}

/// The revoked grants journal full (256 junk ids): a real revocation is
/// still in effect for the live browser (fenced at once, fail closed),
/// though answered `busy` "revoked grants journal full".
#[test]
fn a_full_revoked_grants_journal_still_fences_the_live_browser() {
    let mut rig = Rig::new();
    rig.link_up();
    rig.connect("phone", phone());
    rig.advance(1000);
    let wall = rig.now.host.wall_ms;
    let grant_id = "aaaaaaaa-1111-4111-8111-0000000000f1";
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
    rig.connect("browser", Identity::browser(grant, key).unwrap());
    rig.attached("browser");
    for n in 0..256u32 {
        let junk = format!("eeeeeeee-0000-4000-8000-{n:012}");
        let mono = rig.now.host.mono_ms;
        let (_, frame) = rig.attached("phone").revoke_grant(&junk, mono).unwrap();
        rig.send_frame("phone", &frame);
    }
    rig.events("phone");
    let mono = rig.now.host.mono_ms;
    let (_, frame) = rig.attached("phone").revoke_grant(grant_id, mono).unwrap();
    rig.send_frame("phone", &frame);
    let events = rig.events("phone");
    assert_eq!(
        Rig::last_error(&events),
        Some(("busy".into(), Some("revoked grants journal full".into())))
    );
    assert_eq!(rig.refused("browser").0, "closed");
}

/// runtime.log lines the router's input drives (refused envelopes,
/// duplicate opens, unmatched acknowledgments) are rate-limited like
/// refusal lines: a flood writes at most 20 a window plus one summary.
#[test]
fn router_driven_log_lines_are_rate_limited() {
    let mut rig = Rig::new();
    rig.link_up();
    rig.connect("ph", phone());
    let before = rig.engine.input_lines_written();
    for _ in 0..500 {
        rig.envelope_in("{\"not\":\"an envelope\"}");
        rig.envelope_in(&envelope::open("ph", Transport::Relay));
        rig.relay_in(&json!({"type": "relay", "op": "push_ack", "acks": []}));
    }
    assert!(
        rig.engine.input_lines_written() - before <= 20,
        "{}",
        rig.engine.input_lines_written() - before
    );
    rig.advance(10_000);
    rig.envelope_in("{\"not\":\"an envelope\"}");
    // The next window: the summary and the line.
    assert!(rig.engine.input_lines_written() - before <= 22);
}

/// The `membership` op judges the record's own bytes strictly, as the
/// `hello` route does: an entry with a duplicate key (a garbage `sig`
/// before the real one) is `invalid_request`, never re-serialized into a
/// valid entry (last key wins) and applied.
#[test]
fn a_membership_op_with_a_duplicate_key_is_refused() {
    let mut rig = Rig::new();
    rig.link_up();
    rig.connect("ph", phone());
    let removal = rig.log.remove("svc-bot").to_string();
    assert!(removal.contains("\"sig\":"));
    let dup = removal.replacen("\"sig\":", "\"sig\":\"AAAA\",\"sig\":", 1);
    let plain = format!(
        r#"{{"type":"session","data":{{"v":1,"op":"membership","id":"aaaaaaaa-0000-4000-8000-0000000000d1","entries":[{dup}]}}}}"#
    );
    let head = rig.m.as_ref().unwrap().head();
    let (att, authority) = match &rig.engine.chans["ph"].phase {
        Phase::Open(a) => (a.attachment.clone(), a.authority.clone()),
        _ => panic!("open"),
    };
    rig.run(|e, p| ((), e.on_record(&att, &authority, plain.as_bytes(), p)));
    rig.pump();
    let events = rig.events("ph");
    assert_eq!(
        Rig::last_error(&events).map(|e| e.0),
        Some("invalid_request".into()),
        "{events:?}"
    );
    assert_eq!(rig.m.as_ref().unwrap().head(), head);
}
