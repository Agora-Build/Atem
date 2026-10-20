//! The host runner of every host-side r9 scenario
//! (`designs/protocol/fixtures/r9-*.json`, `side: "host"`) but the channel
//! envelope's (`r9::fixtures_tests`): the real device-list store on a temp
//! profile (real files and fsyncs, the store's injected faults), the real
//! r9 admission engine (`R9Host`) with the real session host over a
//! `FileJournal` (`fake_runtime`: the r8 harness's fake PTY and
//! dispatcher), and clients that speak `atem-ch1` through the channel
//! envelope: every `connect` is a full handshake with the client's key from
//! `r9-vectors-keys` and a `hello` carrying exactly the fixture's entries,
//! every message a record on the client's channel, every reply what the
//! host sealed (the `welcome`, errors, events, fences).
//!
//! The handshake fixtures (`r9-handshake-*`) are run live: their exact
//! bytes are the crate runner's (`channel_fixtures`, on the vectors); here
//! the host's side of each step (tampered init, finish and hello, a replayed
//! finish and record, the host's own record sent back) is made on a live
//! handshake and the host's effects are checked.
//!
//! Items that are another task's (sealed push to the relay: Task 8) or
//! another runner's (keys, client side) are listed pending with their
//! owner; an unknown step or assert key fails the run.
use super::store::{DlFile, Injected, Step};
use super::tests::{Rig, Vectors, clock, fixtures_dir, pinned, vectors};
use super::*;
use crate::session_protocol::fake_runtime::FakeRuntime;
use crate::session_protocol::file_journal::FileJournal;
use crate::session_protocol::fixtures::{HostEvent, HostUnderTest};
use crate::session_protocol::host::HostConfig;
use crate::session_protocol::r9::envelope::{self, Event as EnvEvent, Transport};
use crate::session_protocol::r9::{
    DeviceList as R9List, HostKey, Limits, Now as R9Now, Parts as R9Parts, ProjectScope, R9Host,
};
use crate::session_protocol::wire::Permission;
use atem_client::channel::wire::{self as chwire, Frame};
use atem_client::channel::{Channel, Initiator, Principal};
use atem_client::encoding::b64u;
use atem_client::membership::PairingRefusal;
use atem_client::{KeyId, SignedObject, SoftwareKeys};
use base64::Engine as _;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

const T8: &str = "Task 8 (sealed push: push_hint/push_seen to the relay, the relay's acks)";
const CRATE: &str = "atem-client runners (keys, the client side, exact vector bytes)";
const CHAIN_ONLY: &str = "the fixture's note: this host is outside the vectors (chain handling only; no atem-ch1 client can reach a host missing from its log)";
const AUTH_MS: u64 = 24 * 60 * 60 * 1000;

/// What the fixture's sessions recorded as their launch project (the
/// service `projects` scope, §R9.6).
struct Projects(BTreeMap<String, String>);

impl ProjectScope for Projects {
    fn matches(&self, session_id: &str, entry: &str) -> Option<bool> {
        self.0.get(session_id).map(|p| p == entry)
    }
}

/// A client's channel on one host.
struct Chan {
    handle: String,
    channel: Option<Channel>,
    /// Its `welcome.attachment_gen`, once welcomed.
    attachment: Option<String>,
    /// Frames before the channel opened (handshake replies).
    raw: VecDeque<Vec<u8>>,
    /// Atem closed it (with this reason).
    closed: Option<Option<String>>,
    /// The `finish` frame sent (a replay sends it again elsewhere).
    finish: Option<Vec<u8>>,
    /// The records Atem sent on it, as received (sent back by a replay).
    received: Vec<Vec<u8>>,
    /// The records this client sent, as sent.
    sent: Vec<Vec<u8>>,
    /// The client subscribed to the registry on this channel (`list`).
    listed: bool,
}

struct HostRt {
    rig: Rig,
    rt: FakeRuntime<FileJournal>,
    m: Option<MembershipHost>,
    now: HostNow,
    epoch: u64,
    engine: R9Host,
    key: HostKey,
    link: u64,
    host_id: String,
    projects: Projects,
    /// Client → its newest channel.
    chans: BTreeMap<String, Chan>,
    handles: u64,
    /// The r8 attachment of the link itself (`plain_frame`).
    link_attached: bool,
    /// Clients admitted on the device list only (a host outside the
    /// vectors: no channel can reach it).
    chain_only: BTreeSet<String>,
}

impl HostRt {
    /// Runs `f` on the engine with this host's parts, then performs its
    /// effects (r9 attachments' messages back to the engine).
    fn call<T>(
        &mut self,
        f: impl FnOnce(&mut R9Host, &mut R9Parts<'_, FileJournal>) -> (T, Vec<Effect>),
    ) -> T {
        let mono = self.rt.now();
        let list = match &mut self.m {
            Some(m) => R9List::Open { m, key: &self.key },
            None => R9List::None,
        };
        let mut parts = R9Parts {
            host: &mut self.rt.host,
            list,
            now: R9Now {
                mono,
                host: self.now.clone(),
            },
            projects: &self.projects,
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
                        &self.projects,
                        &self.host_id,
                        self.now.mono_ms,
                    ),
                    Effect::Close { attachment } => {
                        self.engine.close_attachment(&attachment, self.now.mono_ms)
                    }
                    _ => {}
                }
            }
        }
    }

    fn envelope_in(&mut self, text: &str) {
        let text = text.to_string();
        self.call(|e, p| ((), e.on_envelope(&text, p)));
    }

    fn client_of_handle(&self, handle: &str) -> Option<String> {
        self.chans
            .iter()
            .find(|(_, c)| c.handle == handle)
            .map(|(n, _)| n.clone())
    }

    /// What Atem sent: records of open channels decoded for the inbox,
    /// handshake frames kept for the connect, closes noted.
    fn pump(&mut self) -> Vec<(String, Value)> {
        self.route();
        self.call(|e, p| ((), e.reap(p)));
        let mut sent = Vec::new();
        self.engine.flush(&mut |text| {
            sent.push(text);
            true
        });
        let mono = self.now.mono_ms;
        let mut out = Vec::new();
        for text in sent {
            match envelope::parse(&text).expect("Atem sends valid envelopes") {
                EnvEvent::Frame { channel, frame } => {
                    let Some(client) = self.client_of_handle(&channel) else {
                        continue;
                    };
                    let chan = self.chans.get_mut(&client).unwrap();
                    chan.received.push(frame.clone());
                    match (&mut chan.channel, &chan.attachment) {
                        (Some(ch), Some(_)) => match ch.open(&frame, mono) {
                            Ok(plain) => out.push((client, record_value(&plain))),
                            Err(_) => chan.closed = Some(Some("unreadable".into())),
                        },
                        _ => chan.raw.push_back(frame),
                    }
                }
                EnvEvent::Close { channel, reason } => {
                    if let Some(client) = self.client_of_handle(&channel) {
                        // Records before it are still read (a refusal is
                        // the last record, then the close).
                        self.chans.get_mut(&client).unwrap().closed = Some(reason);
                    }
                }
                EnvEvent::Open { .. } => panic!("Atem never opens"),
            }
        }
        out
    }

    fn send_frame(&mut self, client: &str, frame: &[u8]) {
        let handle = self.chans[client].handle.clone();
        self.envelope_in(&envelope::frame(&handle, frame));
    }

    /// The clients with a live (welcomed, not closed) channel.
    fn attached(&self) -> BTreeSet<String> {
        self.chans
            .iter()
            .filter(|(_, c)| c.attachment.is_some() && c.closed.is_none())
            .map(|(n, _)| n.clone())
            .collect()
    }

    fn client_of_attachment(&self, att: &str) -> Option<String> {
        self.chans
            .iter()
            .find(|(_, c)| c.attachment.as_deref() == Some(att))
            .map(|(n, _)| n.clone())
    }
}

/// The fence error a principal admitted on the device list only hears
/// (the engine's, §R9.8).
fn chain_fence_reply(reason: FenceReason) -> Value {
    match reason {
        FenceReason::Removed => json!({"op": "error", "code": "unauthorized", "detail": "removed"}),
        FenceReason::Frozen => json!({"op": "error", "code": "account_frozen"}),
        FenceReason::NotRecorded => {
            json!({"op": "error", "code": "busy", "detail": DETAIL_NOT_RECORDED})
        }
        FenceReason::Revoked => {
            json!({"op": "error", "code": "unauthorized", "detail": "roles changed"})
        }
        FenceReason::HostRemoved => {
            json!({"op": "error", "code": "unauthorized", "detail": "host removed"})
        }
    }
}

/// A record's plaintext as the inbox holds it: its `data`, with its
/// envelope type under `__type`.
fn record_value(plain: &[u8]) -> Value {
    let v: Value = serde_json::from_slice(plain).unwrap_or(Value::Null);
    let mut data = v.get("data").cloned().unwrap_or(Value::Null);
    if let Some(o) = data.as_object_mut() {
        o.insert("__type".into(), v["type"].clone());
    }
    data
}

#[derive(Clone)]
struct ClientSpec {
    principal: String,
    key: String,
}

struct Runner {
    name: String,
    v: &'static Vectors,
    keys: SoftwareKeys,
    hosts: BTreeMap<String, HostRt>,
    current: String,
    clients: BTreeMap<String, ClientSpec>,
    /// Messages each client got and hasn't had taken by an `expect`.
    inbox: BTreeMap<String, Vec<Value>>,
    /// Messages each client got since the last step.
    fresh: BTreeMap<String, usize>,
    passed: usize,
    pending: Vec<(String, &'static str)>,
    crash: Option<(String, u64)>,
    gens: u64,
    captures: BTreeMap<String, Value>,
    sessions: Vec<String>,
    /// Ids of the harness's own requests: their replies are invisible.
    harness_ids: BTreeSet<String>,
}

fn device_of(principal: &str) -> &str {
    principal.split_once(':').unwrap().1
}

fn labels(v: &Value) -> Vec<String> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|l| l.as_str().unwrap().to_owned())
        .collect()
}

/// `a.b` paths in a JSON object (`x.#` is an array's length).
fn get_path(v: &Value, path: &str) -> Option<Value> {
    if let Some(found) = v.get(path) {
        return Some(found.clone());
    }
    let mut at = v;
    for part in path.split('.') {
        if part == "#" {
            return at.as_array().map(|a| json!(a.len()));
        }
        at = match part.parse::<usize>() {
            Ok(i) => at.get(i)?,
            Err(_) => at.get(part)?,
        };
    }
    Some(at.clone())
}

fn load(name: &str) -> Value {
    serde_json::from_slice(&std::fs::read(fixtures_dir().join(format!("{name}.json"))).unwrap())
        .unwrap()
}

/// Every client key of `r9-vectors-keys` as `<name>/auth`.
fn key_book() -> SoftwareKeys {
    let keys = load("r9-vectors-keys")["keys"].clone();
    let mut book = SoftwareKeys::new();
    for (name, entry) in keys.as_object().unwrap() {
        let key = match entry.get("auth") {
            Some(auth) => auth,
            None if entry.get("alg").is_some() && entry.get("secret_hex").is_some() => entry,
            None => continue,
        };
        let secret = Hash32::from_hex(key["secret_hex"].as_str().unwrap())
            .unwrap()
            .0;
        let id = KeyId::new(format!("{name}/auth"));
        match key["alg"].as_str() {
            Some("p256") => book.insert_p256(id, &secret).unwrap(),
            _ => book.insert_ed25519(id, &secret),
        }
    }
    book
}

/// `${vector:<file>:<path>}`: a value of a vectors file.
fn vector_value(reference: &str) -> Value {
    let (file, path) = reference.split_once(':').unwrap();
    get_path(&load(file), path).unwrap_or_else(|| panic!("no {reference}"))
}

impl Runner {
    fn host(&mut self) -> &mut HostRt {
        let name = self.current.clone();
        self.hosts.get_mut(&name).unwrap()
    }

    fn pass(&mut self) {
        self.passed += 1;
    }

    fn later(&mut self, what: impl Into<String>, owner: &'static str) {
        self.pending.push((what.into(), owner));
    }

    fn uuid(&mut self) -> String {
        self.gens += 1;
        format!("abcdef00-0000-4000-8000-{:012}", self.gens)
    }

    fn name_of(&self, principal: &str) -> Option<String> {
        self.clients
            .iter()
            .find(|(_, c)| c.principal == principal)
            .map(|(n, _)| n.clone())
    }

    /// Strings with `${hash:L}`, `${vector:f:p}` and captures replaced.
    fn resolve(&self, value: &Value) -> Value {
        match value {
            Value::String(s) => {
                if let Some(label) = s.strip_prefix("${hash:").and_then(|t| t.strip_suffix('}')) {
                    return json!(self.v.hash(label).to_hex());
                }
                if let Some(r) = s
                    .strip_prefix("${vector:")
                    .and_then(|t| t.strip_suffix('}'))
                {
                    return vector_value(r);
                }
                if let Some(name) = s.strip_prefix("${").and_then(|t| t.strip_suffix('}'))
                    && let Some(v) = self.captures.get(name)
                {
                    return v.clone();
                }
                value.clone()
            }
            Value::Array(items) => Value::Array(items.iter().map(|i| self.resolve(i)).collect()),
            Value::Object(map) => Value::Object(
                map.iter()
                    .map(|(k, x)| (k.clone(), self.resolve(x)))
                    .collect(),
            ),
            other => other.clone(),
        }
    }

    fn setup(&mut self, file: &Value) {
        let setup = &file["setup"];
        let pinned_labels = labels(&setup["pinned"]);
        for client in setup["clients"].as_array().unwrap() {
            self.clients.insert(
                client["name"].as_str().unwrap().to_owned(),
                ClientSpec {
                    principal: client["principal"].as_str().unwrap().to_owned(),
                    key: client["key"].as_str().unwrap_or_default().to_owned(),
                },
            );
        }
        let hold_dispatch = file["steps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s.get("hold_dispatch").is_some());
        let mut specs = Vec::new();
        if let Some(host) = setup.get("host") {
            specs.push((String::new(), host.clone()));
        }
        if let Some(hosts) = setup.get("hosts") {
            for host in hosts.as_array().unwrap() {
                specs.push((host["name"].as_str().unwrap().to_owned(), host.clone()));
            }
            self.current = specs[0].0.clone();
        }
        let sessions: Vec<Value> = setup
            .get("sessions")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        self.sessions = sessions
            .iter()
            .map(|s| s["session_id"].as_str().unwrap().to_owned())
            .collect();
        let projects: BTreeMap<String, String> = sessions
            .iter()
            .filter_map(|s| {
                Some((
                    s["session_id"].as_str()?.to_owned(),
                    s.get("project")?.as_str()?.to_owned(),
                ))
            })
            .collect();
        for (name, spec) in specs {
            let now = clock(spec["wall_clock_ms"].as_u64().unwrap(), 1_000, "boot-1");
            let rig = Rig::new();
            let refs: Vec<&str> = pinned_labels.iter().map(String::as_str).collect();
            let m = pinned(&refs, &now);
            let host_id = spec["host_id"].as_str().unwrap().to_owned();
            let pin = HostPin {
                host_id: host_id.clone(),
                host_trust_gen: spec["host_trust_gen"].as_u64().unwrap(),
            };
            let seed = super::tests::host_a_seed();
            MembershipHost::pin(&rig.pairing, &rig.journal, &pin, &m, &seed).unwrap();
            let r8_sessions: Vec<Value> = sessions
                .iter()
                .map(|s| {
                    json!({"session_id": s["session_id"], "process_gen": s["process_gen"],
                           "chat": s["chat"]})
                })
                .collect();
            let r8 = json!({
                "host": {"account_id": spec["account_id"], "atem_device_id": spec["atem_device_id"],
                         "host_trust_gen": spec["host_trust_gen"], "runtime_gen": spec["runtime_gen"],
                         "runtime_epoch": spec["runtime_epoch"]},
                "sessions": r8_sessions,
                "clients": [],
            });
            let journal = FileJournal::open(&rig.journal).unwrap();
            let mut rt = FakeRuntime::from_json_with(r8, HostConfig::default(), journal);
            rt.host.hold_dispatch(hold_dispatch);
            rt.host.set_refuse_r8(true);
            let epoch = spec["runtime_epoch"].as_u64().unwrap();
            let mut fences = HostFences::new(&mut rt.host);
            let (m, fenced) =
                MembershipHost::open(&rig.pairing, &rig.journal, epoch, &now, &mut fences)
                    .unwrap()
                    .unwrap();
            assert!(fenced.is_empty());
            let effects = fences.effects;
            rt.apply(effects);
            let mut host = HostRt {
                rig,
                rt,
                m: Some(m),
                now,
                epoch,
                engine: R9Host::new(Limits::default(), None),
                key: HostKey::new(&seed),
                link: 1,
                host_id,
                projects: Projects(projects.clone()),
                chans: BTreeMap::new(),
                handles: 0,
                link_attached: false,
                chain_only: BTreeSet::new(),
            };
            host.call(|e, p| ((), e.link_up(1, p)));
            self.hosts.insert(name, host);
        }
        let connected: Vec<String> = setup.get("connected").map(labels).unwrap_or_default();
        let leases: BTreeMap<String, u64> = setup
            .get("holds_lease")
            .and_then(Value::as_object)
            .map(|o| {
                o.iter()
                    .map(|(k, v)| (k.clone(), v.as_u64().unwrap()))
                    .collect()
            })
            .unwrap_or_default();
        let names: Vec<String> = self.clients.keys().cloned().collect();
        for c in &names {
            if connected.contains(c) || leases.contains_key(c) {
                let grant = setup["clients"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|x| x["name"] == c.as_str())
                    .and_then(|x| x.get("grant"))
                    .and_then(Value::as_str)
                    .map(|g| json!(format!("${{vector:{g}}}")));
                let mut step = json!({"connect": c, "carry": []});
                if let Some(g) = grant {
                    step["grant"] = g;
                }
                self.connect(&step);
                assert!(
                    self.host().attached().contains(c),
                    "{}: setup {c} wasn't welcomed: {:?}",
                    self.name,
                    self.inbox.get(c)
                );
                self.subscribe(c);
            }
        }
        for (c, epoch) in &leases {
            let sid = self.sessions[0].clone();
            let binding = self.binding(c, &sid, false);
            let id = self.uuid();
            let json = json!({"type": "session", "data": {"v": 1, "op": "acquire", "id": id,
                "binding": binding, "takeover": false}});
            self.send_json(c, &json);
            let host = self.host();
            assert_eq!(
                host.rt.host.lease_epoch(&sid),
                Some(*epoch),
                "setup holds_lease {c}"
            );
        }
        self.inbox.clear();
        self.fresh.clear();
        if !self.sessions.is_empty() || !leases.is_empty() || !connected.is_empty() {
            self.pass();
        }
    }

    /// Moves what every host sent its clients into their inboxes.
    fn drain(&mut self) {
        let names: Vec<String> = self.hosts.keys().cloned().collect();
        for name in names {
            let out = self.hosts.get_mut(&name).unwrap().pump();
            for (client, value) in out {
                self.deliver(&client, value);
            }
        }
    }

    fn deliver(&mut self, client: &str, fields: Value) {
        if fields
            .get("re")
            .and_then(Value::as_str)
            .is_some_and(|re| self.harness_ids.contains(re))
        {
            return;
        }
        *self.fresh.entry(client.to_owned()).or_default() += 1;
        self.inbox
            .entry(client.to_owned())
            .or_default()
            .push(fields);
    }

    fn principal(&self, client: &str, grant: Option<&SignedObject>) -> Principal {
        let p = &self.clients[client].principal;
        match p.split_once(':').unwrap() {
            ("member", d) => Principal::Native {
                device_id: d.into(),
            },
            ("service", d) => Principal::Service {
                device_id: d.into(),
            },
            ("browser", _) => {
                Principal::browser(grant.expect("a browser connects with its grant")).unwrap()
            }
            other => panic!("principal {other:?}"),
        }
    }

    /// A full `atem-ch1` handshake through the envelope, then a `hello`
    /// carrying exactly the step's entries. `tamper` (handshake fixtures)
    /// spoils one part on the wire.
    fn connect(&mut self, step: &Value) {
        let client = step["connect"]
            .as_str()
            .or_else(|| step["reconnect"].as_str())
            .or_else(|| step["handshake"].as_str())
            .unwrap()
            .to_owned();
        if let Some(host) = step.get("host") {
            self.current = host.as_str().unwrap().to_owned();
        }
        let transport = match step.get("transport").and_then(Value::as_str) {
            Some("direct") => Transport::Direct,
            _ => Transport::Relay,
        };
        let tamper = step.get("tamper").cloned().unwrap_or(Value::Null);
        let carry = step.get("carry").map(labels).unwrap_or_default();
        let more = step.get("more").and_then(Value::as_bool).unwrap_or(false);
        let grant_json = step.get("grant").map(|g| self.resolve(g));
        let grant = grant_json.as_ref().map(|g| {
            SignedObject::from_strict(
                &StrictValue::parse(g.to_string().as_bytes(), usize::MAX).unwrap(),
            )
            .unwrap()
        });
        let principal = self.principal(&client, grant.as_ref());
        let key = KeyId::new(format!("{}/auth", self.clients[&client].key));
        let v = self.v;
        let host = self.host();
        let host_id = host.host_id.clone();
        if host
            .m
            .as_ref()
            .is_some_and(|m| m.membership().host(&host_id).is_none())
        {
            return self.connect_chain_only(&client, step);
        }
        let host = self.host();
        // A client that reconnects leaves its old channel (the router
        // closes it).
        if let Some(old) = host.chans.get(&client)
            && old.closed.is_none()
        {
            let close = envelope::close(&old.handle, None);
            host.envelope_in(&close);
        }
        host.handles += 1;
        let handle = format!("{client}-{}", host.handles);
        host.chans.insert(
            client.clone(),
            Chan {
                handle: handle.clone(),
                channel: None,
                attachment: None,
                raw: VecDeque::new(),
                closed: None,
                finish: None,
                received: Vec::new(),
                sent: Vec::new(),
                listed: false,
            },
        );
        host.engine.reset_init_limiter();
        host.envelope_in(&envelope::open(&handle, transport));
        let mono = host.now.mono_ms;
        let log = host.m.as_ref().expect("paired").membership().clone();
        let (await_accept, mut init) =
            Initiator::start(&log, &host.host_id, mono).expect("the host is in the log");
        if let Some(e) = tamper.get("init.e").and_then(Value::as_str) {
            let mut frame: Value = serde_json::from_slice(&init).unwrap();
            frame["e"] = json!(e);
            init = frame.to_string().into_bytes();
        }
        host.send_frame(&client, &init);
        let out = host.pump();
        let accept = host.chans.get_mut(&client).unwrap().raw.pop_front();
        let Some(accept) = accept else {
            panic!("{}: {client}: no reply to init", self.name);
        };
        let at_init = |code: &str| json!({"op": "channel_error", "code": code, "at": "init"});
        if let Ok(Frame::Error { code }) = chwire::parse_frame(&accept) {
            for (c, value) in out {
                self.deliver(&c, value);
            }
            self.deliver(&client, at_init(&code));
            self.pass();
            return;
        }
        let accepted = await_accept
            .on_frame(&accept, &log, mono)
            .unwrap_or_else(|e| panic!("{}: {client}: accept refused: {e:?}", self.name));
        let signed = accepted
            .sign(principal.clone(), &self.keys, &key)
            .unwrap_or_else(|e| panic!("{}: {client}: signing: {e:?}", self.name));
        // The client's own head: the fixture's, else its last carried
        // entry's, else the host's (it verified what it carries).
        let head = match step.get("client_head").and_then(Value::as_str) {
            Some(label) => v.head(label),
            None => match carry.last() {
                Some(label) => v.head(label),
                None => log.head(),
            },
        };
        let mut membership = json!({"head": head.to_json(),
            "entries": carry.iter().map(|l| v.wire(l).clone()).collect::<Vec<_>>()});
        if more {
            membership["more"] = json!(true);
        }
        let mut data = json!({"v": 1, "op": "hello", "id": self.uuid(), "revision": 9,
            "proof": {"principal": principal.to_json(), "sig": b64u(signed.sig_c())},
            "membership": membership});
        if let Some(g) = &grant_json {
            data["grant"] = g.clone();
        }
        if let Some(over) = step.get("hello").and_then(Value::as_object) {
            for (k, x) in over {
                data[k] = x.clone();
            }
        }
        if let Some(p) = tamper.get("hello.proof.principal") {
            data["proof"]["principal"] = p.clone();
        }
        let hello = atem_client::canonical::jcs(&json!({"type": "session", "data": data}))
            .unwrap()
            .into_bytes();
        let host = self.host();
        let (channel, mut finish) = signed.finish(&hello, mono).unwrap();
        if tamper.get("finish.ct").is_some() {
            let mut frame: Value = serde_json::from_slice(&finish).unwrap();
            let ct = frame["ct"].as_str().unwrap().to_string();
            let flipped = if ct.starts_with('A') { "B" } else { "A" };
            frame["ct"] = json!(format!("{flipped}{}", &ct[1..]));
            finish = frame.to_string().into_bytes();
        }
        {
            let chan = host.chans.get_mut(&client).unwrap();
            chan.channel = Some(channel);
            chan.finish = Some(finish.clone());
        }
        host.send_frame(&client, &finish);
        let mut out = host.pump();
        let chan = host.chans.get_mut(&client).unwrap();
        let first = chan.raw.pop_front();
        let mut mine = Vec::new();
        match first {
            None => mine.push(
                json!({"op": "channel_error", "code": "closed", "at": "finish",
                       "reason": chan.closed.clone()}),
            ),
            Some(frame) => match chwire::parse_frame(&frame) {
                Ok(Frame::Error { code }) => {
                    mine.push(json!({"op": "channel_error", "code": code, "at": "finish"}))
                }
                _ => {
                    let ch = chan.channel.as_mut().unwrap();
                    match ch.open(&frame, mono) {
                        Ok(plain) => {
                            let value = record_value(&plain);
                            if value["op"] == "welcome" {
                                chan.attachment =
                                    value["attachment_gen"].as_str().map(str::to_owned);
                            }
                            mine.push(value);
                            // Records queued behind the welcome.
                            while let Some(more) = chan.raw.pop_front() {
                                if let Ok(plain) = chan.channel.as_mut().unwrap().open(&more, mono)
                                {
                                    mine.push(record_value(&plain));
                                }
                            }
                        }
                        // An encrypted refusal the client can't read (a
                        // hello naming another principal than it signed).
                        Err(_) => mine.push(
                            json!({"op": "channel_error", "code": "handshake_failed", "at": "finish"}),
                        ),
                    }
                }
            },
        }
        out.extend(mine.into_iter().map(|m| (client.clone(), m)));
        for (c, value) in out {
            self.deliver(&c, value);
        }
        if self.crashed_now() {
            return;
        }
        self.drain();
        self.pass();
    }

    /// A host outside the vectors (the fixture's note): the carriage and the
    /// sender are judged by the device list, as the engine does, with no
    /// channel; the welcome's wire fields are listed pending.
    fn connect_chain_only(&mut self, client: &str, step: &Value) {
        let principal = self.clients[client].principal.clone();
        let carry = step.get("carry").map(labels).unwrap_or_default();
        let carried: Vec<StrictValue> = carry.iter().map(|l| self.v.strict(l)).collect();
        let client_head = step
            .get("client_head")
            .and_then(Value::as_str)
            .map(|l| self.v.head(l));
        let more = step.get("more").and_then(Value::as_bool).unwrap_or(false);
        let host = self.host();
        if !matches!(host.m.as_ref().unwrap().init(), Init::Accept) {
            let code = match host.m.as_ref().unwrap().init() {
                Init::Frozen => "account_frozen",
                _ => "busy",
            };
            self.deliver(
                client,
                json!({"op": "channel_error", "code": code, "at": "init"}),
            );
            self.pass();
            return;
        }
        let result = (!carried.is_empty()).then(|| {
            let mut fences = HostFences::new(&mut host.rt.host);
            let m = host.m.as_mut().unwrap();
            let r = m.apply_carriage(&carried, &host.now, &mut fences);
            let effects = fences.effects;
            host.rt.apply(effects);
            r
        });
        let fences = result
            .as_ref()
            .map(|r| r.fences.clone())
            .unwrap_or_default();
        for fence in &fences {
            let Some(name) = self.name_of(&fence.principal) else {
                continue;
            };
            if self.host().chain_only.remove(&name) {
                self.deliver(&name, chain_fence_reply(fence.reason));
            }
        }
        let host = self.host();
        let now = host.now.clone();
        let m = host.m.as_mut().unwrap();
        let reported = client_head.or(Some(m.head()));
        let verdict = m.hello(device_of(&principal), reported, result.as_ref(), more, &now);
        let reply = match &verdict {
            Hello::Admit(Admission::Member { head, .. }) => {
                host.chain_only.insert(client.to_owned());
                self.later("welcome client_kind, permissions, revision", CHAIN_ONLY);
                json!({"op": "welcome", "principal": principal, "head": head.to_json(),
                       "__chain_only": true})
            }
            Hello::Admit(Admission::Frozen) | Hello::Frozen => {
                json!({"op": "error", "code": "account_frozen"})
            }
            Hello::Admit(other) => {
                let e = atem_client::principal::admission_error(other, None).expect("a refusal");
                serde_json::from_slice::<Value>(&e.to_bytes()).unwrap()["data"].clone()
            }
            Hello::NotReconciled => {
                json!({"op": "error", "code": "busy", "detail": DETAIL_NOT_RECONCILED})
            }
            Hello::NotRecorded => {
                json!({"op": "error", "code": "busy", "detail": DETAIL_NOT_RECORDED})
            }
        };
        self.deliver(client, reply);
        self.pass();
    }

    /// A crash armed by `crash_after_membership_commit` happened in the
    /// step just run: the runtime restarts (nothing it sent after counts).
    fn crashed_now(&mut self) -> bool {
        let fired =
            self.crash.is_some() && self.host().m.as_ref().is_some_and(|m| !m.crash_armed());
        if fired {
            let (gen_, epoch) = self.crash.take().unwrap();
            self.restart(&gen_, epoch, false, None);
            self.pass();
        }
        fired
    }

    /// `client` sends `json` as a record on its channel.
    fn send_json(&mut self, client: &str, json: &Value) {
        let bytes = serde_json::to_vec(json).unwrap();
        let host = self.host();
        let mono = host.now.mono_ms;
        let chan = host
            .chans
            .get_mut(client)
            .unwrap_or_else(|| panic!("{client} has no channel"));
        let frame = chan
            .channel
            .as_mut()
            .unwrap()
            .seal(&bytes, mono)
            .unwrap_or_else(|e| panic!("{client}: can't send: {e:?}"));
        chan.sent.push(frame.clone());
        host.send_frame(client, &frame);
        if self.crashed_now() {
            return;
        }
        self.drain();
    }

    fn send_membership(&mut self, step: &Value) {
        let client = step["send_membership"].as_str().unwrap().to_owned();
        let entries: Vec<Value> = labels(&step["entries"])
            .iter()
            .map(|l| self.v.wire(l).clone())
            .collect();
        let id = self.uuid();
        let json = json!({"type": "session", "data": {"v": 1, "op": "membership", "id": id,
            "entries": entries}});
        self.send_json(&client, &json);
        self.pass();
    }

    fn expect(&mut self, client: &str, want: &Value, kind: Option<&str>, capture: Option<&Value>) {
        let want = self.resolve(want);
        self.drain();
        let op = want.get("op").and_then(Value::as_str);
        let inbox = self.inbox.entry(client.to_owned()).or_default();
        let found = inbox.iter().position(|m| {
            kind.is_none_or(|t| m["__type"] == t)
                && op.is_none_or(|op| m.get("op").and_then(Value::as_str) == Some(op))
                && ["code", "detail", "reason", "state", "re"].iter().all(|k| {
                    want.get(*k)
                        .is_none_or(|w| get_path(m, k).as_ref() == Some(w))
                })
        });
        let Some(i) = found else {
            panic!(
                "{}: {client} got no {want} (inbox {:?})",
                self.name, self.inbox[client]
            );
        };
        let got = self.inbox.get_mut(client).unwrap().remove(i);
        for (key, value) in want.as_object().unwrap() {
            match get_path(&got, key) {
                Some(g) => assert_eq!(&g, value, "{}: {client} {key} in {got}", self.name),
                // Listed pending at the connect (CHAIN_ONLY).
                None if got.get("__chain_only").is_some()
                    && ["revision", "client_kind", "permissions"].contains(&key.as_str()) => {}
                None => panic!("{}: {client}: {key} not produced in {got}", self.name),
            }
        }
        if let Some(capture) = capture {
            for (name, path) in capture.as_object().unwrap() {
                let path = path.as_str().unwrap();
                let value = get_path(&got, path)
                    .unwrap_or_else(|| panic!("{}: capture {path} in {got}", self.name));
                self.captures.insert(name.clone(), value);
            }
        }
        self.pass();
    }

    fn restart(&mut self, runtime_gen: &str, epoch: u64, orderly: bool, disk: Option<&str>) {
        let host = self.host();
        let mut m = host.m.take().expect("paired");
        if let Some(mode) = disk {
            match mode {
                "as_written" | "rename_kept" => {}
                "rename_lost" | "write_lost" => {
                    if let Some(lost) = m.store().unsynced_rename().cloned() {
                        match lost.before {
                            Some(bytes) => std::fs::write(&lost.path, bytes).unwrap(),
                            None => std::fs::remove_file(&lost.path).unwrap(),
                        }
                    }
                }
                other => panic!("disk {other}"),
            }
        }
        if orderly {
            m.close(&host.now);
        }
        drop(m);
        let event = if orderly {
            HostEvent::RestartRuntime {
                runtime_gen: runtime_gen.into(),
                runtime_epoch: epoch,
            }
        } else {
            HostEvent::CrashRuntime {
                runtime_gen: runtime_gen.into(),
                runtime_epoch: epoch,
            }
        };
        let now_ms = host.rt.now();
        host.rt.event(&event, now_ms).unwrap();
        host.rt.foreign.clear();
        host.epoch = epoch;
        let mut fences = HostFences::new(&mut host.rt.host);
        let (m, _) = host
            .rig
            .open(epoch, &host.now, &mut fences)
            .unwrap_or_else(|e| panic!("restart: {e}"));
        let effects = fences.effects;
        host.rt.apply(effects);
        host.rt.foreign.clear();
        host.m = Some(m);
        // A new runtime: a new engine on a new link; every channel ended.
        host.engine = R9Host::new(Limits::default(), None);
        host.chans.clear();
        host.link += 1;
        host.link_attached = false;
        let link = host.link;
        host.call(|e, p| ((), e.link_up(link, p)));
        self.inbox.clear();
    }

    fn advance(&mut self, ms: u64, wall_only: bool) {
        for host in self.hosts.values_mut() {
            host.now.wall_ms += ms;
            if !wall_only {
                host.now.mono_ms += ms;
                let to = host.rt.now() + ms;
                host.rt.advance(to);
            }
            let mut fences = HostFences::new(&mut host.rt.host);
            if let Some(m) = host.m.as_mut() {
                let changes = m.advance(&host.now, &mut fences);
                let effects = fences.effects;
                host.rt.apply(effects);
                host.route();
                if !changes.is_empty() {
                    host.call(|e, p| {
                        e.announce(p);
                        ((), Vec::new())
                    });
                }
            }
            host.call(|e, p| ((), e.tick(p)));
        }
        self.drain();
    }

    /// The client subscribes to the registry (`list`), as a client does
    /// before it names a session: its reply is the harness's.
    fn subscribe(&mut self, client: &str) {
        if self.host().chans[client].listed || self.host().chans[client].attachment.is_none() {
            return;
        }
        let id = self.uuid();
        self.harness_ids.insert(id.clone());
        let json = json!({"type": "session", "data": {"v": 1, "op": "list", "id": id}});
        self.send_json(client, &json);
        self.host().chans.get_mut(client).unwrap().listed = true;
    }

    fn binding(&mut self, client: &str, sid: &str, lease: bool) -> Value {
        self.subscribe(client);
        let host = self.host();
        let target = serde_json::to_value(host.rt.target(sid)).unwrap();
        let attachment = host.chans[client].attachment.clone();
        let mut b = json!({"target": target, "attachment_gen": attachment});
        if lease {
            b["lease_epoch"] = json!(host.rt.host.lease_epoch(sid).unwrap());
        }
        b
    }

    fn substitute(&mut self, v: &mut Value) {
        match v {
            Value::String(s) => {
                for (prefix, lease) in [("${lease_binding:", true), ("${binding:", false)] {
                    if let Some(rest) = s.strip_prefix(prefix).and_then(|r| r.strip_suffix('}')) {
                        let (client, sid) = rest.split_once(':').unwrap();
                        let (client, sid) = (client.to_owned(), sid.to_owned());
                        *v = self.binding(&client, &sid, lease);
                        return;
                    }
                }
                *v = self.resolve(v);
            }
            Value::Array(items) => items.iter_mut().for_each(|i| self.substitute(i)),
            Value::Object(map) => map.values_mut().for_each(|i| self.substitute(i)),
            _ => {}
        }
    }

    fn assert(&mut self, assert: &Value) {
        if let Some(name) = assert.get("host") {
            self.current = name.as_str().unwrap().to_owned();
        }
        let assert = self.resolve(assert);
        let v = self.v;
        let name = self.name.clone();
        let sid = self.sessions.first().cloned();
        let mut later: Vec<(String, &'static str)> = Vec::new();
        let host = self.host();
        let paired = host.m.as_ref();
        let rt = &host.rt;
        for (key, want) in assert.as_object().unwrap() {
            let m = || paired.expect("a device list");
            let ok = |got: Value| assert_eq!(&got, want, "{name}: assert {key}");
            match key.as_str() {
                "host" => {}
                "head" => assert_eq!(m().head(), v.head(want.as_str().unwrap()), "{name}: head"),
                "membership_applied" => assert_eq!(
                    m().applied().head,
                    v.head(want.as_str().unwrap()),
                    "{name}: applied"
                ),
                "frozen" => ok(json!(m().is_frozen())),
                "frozen_durable" => ok(json!(m().frozen_durable())),
                "membership_halted" => {
                    ok(json!(m().faulted().is_some() && rt.host.journal_halted()))
                }
                "membership_held" => ok(json!(m().held().is_some())),
                "membership_unclean" => match want {
                    Value::Null => assert_eq!(m().unclean(), None, "{name}: unclean"),
                    l => assert_eq!(m().unclean(), Some(v.head(l.as_str().unwrap()))),
                },
                "carriage_record" => ok(json!(m().carriage_record_present())),
                "fault_record" => ok(json!(m().fault_record_present())),
                "control_gen" => {
                    for (p, n) in want.as_object().unwrap() {
                        assert_eq!(json!(rt.host.control_gen(p)), *n, "{name}: control_gen {p}");
                    }
                }
                "attachments" | "pty_writes" | "pty_writes_local" | "pty_writes_remote"
                | "pty_writes_dropped" | "dispatches" | "approvals_pending" => {
                    ok(rt.counter(key).unwrap())
                }
                "approval_decisions" => {
                    let got = rt.counter(key).unwrap();
                    match want.as_array() {
                        Some(_) => ok(got),
                        None => panic!("{name}: approval_decisions"),
                    }
                }
                "approval_decisions.#" => ok(json!(
                    rt.counter("approval_decisions")
                        .unwrap()
                        .as_array()
                        .map_or(0, Vec::len)
                )),
                "lease_holder" => {
                    let sid = sid.as_deref().expect("a session");
                    let got = match rt.host.lease_holder(sid) {
                        Some(att) => json!(host.client_of_attachment(att).expect("a client")),
                        None => Value::Null,
                    };
                    ok(got)
                }
                "receipts_visible" => {
                    for (c, n) in want.as_object().unwrap() {
                        let att = host.chans[c].attachment.clone().unwrap();
                        assert_eq!(
                            json!(rt.host.receipts_visible(&att)),
                            *n,
                            "{name}: receipts_visible {c}"
                        );
                    }
                }
                "receipts" => {
                    for (rid, r) in want.as_object().unwrap() {
                        let receipt = rt
                            .host
                            .receipt(rid)
                            .unwrap_or_else(|| panic!("{name}: no {rid}"));
                        let got = serde_json::to_value(&receipt).unwrap();
                        assert_eq!(got["state"], r["state"], "{name}: {rid}");
                        assert_eq!(got["detail"], r["detail"], "{name}: {rid}");
                    }
                }
                "evidence_count" => ok(json!(m().membership().evidence().count)),
                "evidence_reason" => ok(json!(
                    m().membership()
                        .evidence()
                        .recent
                        .last()
                        .unwrap()
                        .reason
                        .as_str()
                )),
                "frozen_genesis" => {
                    let got: Vec<Value> = frozen_genesis(&host.rig.pairing)
                        .iter()
                        .map(|h| json!(h.to_hex()))
                        .collect();
                    assert_eq!(Value::Array(got), *want, "{name}: frozen_genesis");
                }
                "members" => ok(json!(m().membership().members())),
                "pending" => {
                    for (label, state) in want.as_object().unwrap() {
                        let record = m().membership().record(&v.hash(label)).unwrap();
                        assert_eq!(json!(record.state().as_str()), *state, "{name}: {label}");
                    }
                }
                "stored_sig" => {
                    let label = want.as_str().unwrap();
                    let seq = v.head(label).seq;
                    let stored = m().membership().entry(seq).unwrap().object().to_json();
                    assert_eq!(stored["sig"], v.wire(label)["sig"], "{name}: stored_sig");
                }
                "channel_id" => {
                    // The vector's channel id is the crate's (exact bytes);
                    // here: the live channel's id, as its welcome named it.
                    let chan = host.chans.values().last().expect("a channel");
                    let id = chan.channel.as_ref().unwrap().channel_id().to_string();
                    assert_eq!(id.len(), 32, "{name}: channel_id");
                    later.push(("channel_id: the vector's exact value".into(), CRATE));
                }
                "recovery_key" | "k_backup" | "carried_ever" => later.push((key.clone(), CRATE)),
                other => panic!("{name}: unknown assert key {other}"),
            }
        }
        self.pass();
        for (k, owner) in later {
            self.later(format!("assert {k}"), owner);
        }
    }

    fn host_event(&mut self, event: HostEvent) {
        let host = self.host();
        let now = host.rt.now();
        host.rt.event(&event, now).unwrap();
        host.route();
        self.drain();
        self.pass();
    }

    fn step(&mut self, step: &Value) {
        self.fresh.clear();
        let object = step.as_object().unwrap();
        let kinds = [
            "connect",
            "reconnect",
            "handshake",
            "client_handshake",
            "send_membership",
            "expect",
            "expect_channel_error",
            "expect_channel_or_session_error",
            "expect_none",
            "expect_record",
            "expect_closed",
            "expect_plain",
            "plain_frame",
            "send_record",
            "replay",
            "advance_ms",
            "set_wall_clock",
            "assert",
            "expect_local_status",
            "restart_runtime",
            "crash_runtime",
            "fail_next_membership_write",
            "crash_after_membership_commit",
            "send",
            "hold_dispatch",
            "hold_pty_writes",
            "flush_pty_writes",
            "local_input",
            "unpair",
            "pair",
            "open_approval",
            "close_approval",
            "approval_applied",
            "turn_complete",
            "expect_relay",
            "expect_relay_none",
            "relay_ack",
            "relay_lost",
            "expect_client_refusal",
        ];
        let kind = kinds
            .into_iter()
            .find(|k| object.contains_key(*k))
            .unwrap_or_else(|| panic!("{}: unknown step {step}", self.name));
        match kind {
            "connect" | "reconnect" | "handshake" => self.connect(step),
            "client_handshake" | "expect_client_refusal" => {
                self.later(format!("{kind}: the client's side"), CRATE)
            }
            "send_membership" => self.send_membership(step),
            "expect" => {
                let client = step["expect"].as_str().unwrap().to_owned();
                let kind = step.get("type").and_then(Value::as_str);
                self.expect(&client, &step["match"], kind, step.get("capture"));
            }
            "expect_channel_error" => {
                let client = step["expect_channel_error"].as_str().unwrap().to_owned();
                let want = json!({"op": "channel_error", "code": step["code"], "at": step["at"]});
                self.expect(&client, &want, None, None);
            }
            "expect_channel_or_session_error" => {
                let client = step["expect_channel_or_session_error"]
                    .as_str()
                    .unwrap()
                    .to_owned();
                self.drain();
                let code = step["code"].clone();
                let inbox = self.inbox.entry(client.clone()).or_default();
                let at = inbox
                    .iter()
                    .position(|m| {
                        (m["op"] == "error" || m["op"] == "channel_error")
                            && m["code"] == code
                            && step.get("detail").is_none_or(|d| m["detail"] == *d)
                    })
                    .unwrap_or_else(|| panic!("{}: {client}: no {step} in {inbox:?}", self.name));
                inbox.remove(at);
                self.pass();
            }
            "expect_none" => {
                let client = step["expect_none"].as_str().unwrap().to_owned();
                let ms = step["for_ms"].as_u64().unwrap_or(0);
                if ms > 0 {
                    self.advance(ms, false);
                }
                self.drain();
                let got = self.fresh.get(&client).copied().unwrap_or(0);
                assert_eq!(
                    got,
                    0,
                    "{}: {client} got {:?}",
                    self.name,
                    self.inbox.get(&client)
                );
                self.pass();
            }
            "expect_record" => {
                // The host's first record (h2c 0): the live welcome.
                let client = step["expect_record"].as_str().unwrap().to_owned();
                self.drain();
                let welcome = self
                    .inbox
                    .get_mut(&client)
                    .and_then(|i| {
                        let at = i.iter().position(|m| m["op"] == "welcome")?;
                        Some(i.remove(at))
                    })
                    .unwrap_or_else(|| panic!("{}: {client}: no welcome", self.name));
                self.check_welcome(&client, &welcome);
                self.pass();
                self.later("expect_record: the vector's exact record bytes", CRATE);
            }
            "send_record" => self.send_record(step),
            "expect_closed" => {
                let client = step["expect_closed"].as_str().unwrap().to_owned();
                self.drain();
                let host = self.host();
                let chan = &host.chans[&client];
                assert!(chan.closed.is_some(), "{}: {client} not closed", self.name);
                assert_eq!(
                    self.fresh.get(&client).copied().unwrap_or(0),
                    0,
                    "{}: {client}: a reply before the close",
                    self.name
                );
                self.pass();
            }
            "replay" => self.replay(step),
            "plain_frame" => {
                let host = self.host();
                if !host.link_attached {
                    host.rt.connect_only(
                        "link",
                        "abcdef00-0000-4000-8000-0000000000ff",
                        vec![Permission::View, Permission::Control],
                        AUTH_MS,
                    );
                    host.link_attached = true;
                }
                host.rt.send("link", &step["json"]);
                self.pass();
            }
            "expect_plain" => {
                let want = step["match"].clone();
                let host = self.host();
                let got: Vec<Value> = host
                    .rt
                    .take("link")
                    .into_iter()
                    .map(|m| m["data"].clone())
                    .collect();
                let found = got.iter().any(|m| {
                    want.as_object()
                        .unwrap()
                        .iter()
                        .all(|(k, w)| get_path(m, k).as_ref() == Some(w))
                });
                assert!(found, "{}: expect_plain {want} in {got:?}", self.name);
                self.pass();
            }
            "advance_ms" => {
                self.advance(step["advance_ms"].as_u64().unwrap(), false);
                self.pass();
            }
            "set_wall_clock" => {
                let wall = step["set_wall_clock"].as_u64().unwrap();
                let now = self.host().now.wall_ms;
                assert!(wall >= now, "the fixtures only move it forward");
                self.advance(wall - now, true);
                self.pass();
            }
            "assert" => self.assert(&step["assert"]),
            "expect_local_status" => self.local_status(step),
            "restart_runtime" | "crash_runtime" => {
                let spec = &step[kind];
                self.restart(
                    spec["runtime_gen"].as_str().unwrap(),
                    spec["runtime_epoch"].as_u64().unwrap(),
                    kind == "restart_runtime",
                    step.get("disk").and_then(Value::as_str),
                );
                self.pass();
            }
            "fail_next_membership_write" => {
                let spec = &step[kind];
                let injected = match spec {
                    Value::Bool(true) => Injected {
                        file: DlFile::State,
                        step: Step::TempWrite,
                    },
                    spec => {
                        let at = spec["at"].as_str().unwrap();
                        match spec.get("file").and_then(Value::as_str) {
                            Some(file) => Injected {
                                file: DlFile::parse(file).unwrap(),
                                step: Step::parse(at).unwrap(),
                            },
                            None => Injected::parse(at).unwrap(),
                        }
                    }
                };
                self.host().m.as_mut().unwrap().store_mut().inject(injected);
                self.pass();
            }
            "crash_after_membership_commit" => {
                let spec = &step[kind];
                self.crash = Some((
                    spec["runtime_gen"].as_str().unwrap().to_owned(),
                    spec["runtime_epoch"].as_u64().unwrap(),
                ));
                self.host().m.as_mut().unwrap().crash_after_commit();
                self.pass();
            }
            "send" => {
                let client = step["send"].as_str().unwrap().to_owned();
                let mut json = step["json"].clone();
                self.substitute(&mut json);
                if json["type"] == "terminal" && json["data"]["op"] == "input" {
                    // Input needs the client's stream: the harness
                    // subscribes first and uses the stream the host opened
                    // (r8 terminal-v1), when the client may subscribe.
                    let sid = json["data"]["terminal_id"].as_str().unwrap().to_owned();
                    let read = self.binding(&client, &sid, false);
                    let subscribe = json!({"type": "terminal", "data": {"v": 1, "op": "subscribe",
                        "terminal_id": sid, "generation": json["data"]["generation"], "binding": read}});
                    self.send_json(&client, &subscribe);
                    let inbox = self.inbox.entry(client.clone()).or_default();
                    if let Some(at) = inbox
                        .iter()
                        .position(|m| m["__type"] == "terminal" && m["op"] == "attached")
                    {
                        let attached = inbox.remove(at);
                        json["data"]["stream_id"] = attached["stream_id"].clone();
                    }
                }
                if json["type"] == "session" && json["data"]["op"] == "list" {
                    self.host().chans.get_mut(&client).unwrap().listed = true;
                }
                self.send_json(&client, &json);
                self.pass();
            }
            "hold_dispatch" => {
                // Set from the start (the runner's pre-scan): the work
                // accepted before this step stays queued too.
                self.pass();
            }
            "hold_pty_writes" | "flush_pty_writes" => {
                let event = if kind == "hold_pty_writes" {
                    HostEvent::HoldPtyWrites
                } else {
                    HostEvent::FlushPtyWrites
                };
                self.host_event(event);
            }
            "local_input" => {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(step["bytes"].as_str().unwrap())
                    .unwrap();
                let event = HostEvent::LocalInput {
                    session_id: step["local_input"].as_str().unwrap().to_owned(),
                    bytes,
                };
                self.host_event(event);
            }
            "open_approval" => {
                let event = HostEvent::OpenApproval {
                    session_id: step["open_approval"].as_str().unwrap().to_owned(),
                    tool: step["tool"].as_str().unwrap().to_owned(),
                    summary: step["summary"].as_str().unwrap().to_owned(),
                    always_rules: Vec::new(),
                    turn_id: None,
                };
                self.host_event(event);
            }
            "close_approval" => {
                let id = self.resolve(&step["close_approval"]);
                let event = HostEvent::CloseApproval {
                    approval_id: id.as_str().unwrap().to_owned(),
                    reason: serde_json::from_value(step["reason"].clone()).unwrap(),
                };
                self.host_event(event);
            }
            "approval_applied" => {
                let id = self.resolve(&step["approval_applied"]);
                let event = HostEvent::ApprovalApplied {
                    approval_id: id.as_str().unwrap().to_owned(),
                    ok: step["ok"].as_bool().unwrap(),
                };
                self.host_event(event);
            }
            "turn_complete" => {
                let event = HostEvent::TurnComplete {
                    session_id: step["turn_complete"].as_str().unwrap().to_owned(),
                    turn_id: step["turn_id"].as_str().unwrap().to_owned(),
                };
                self.host_event(event);
            }
            "expect_relay" | "expect_relay_none" | "relay_ack" | "relay_lost" => {
                self.later(format!("{kind}: {}", step[kind]), T8)
            }
            "unpair" => {
                let host = self.host();
                host.m = None;
                forget_on_unpair(&host.rig.pairing).unwrap();
                assert!(!host.rig.pairing.membership.exists());
                self.pass();
            }
            "pair" => {
                let host = self.host();
                let pin = labels(&step["pair"]["log"]);
                let refs: Vec<&str> = pin.iter().map(String::as_str).collect();
                let m = pinned(&refs, &host.now);
                let refused = m
                    .check_pairing(
                        "host-a",
                        1,
                        &m.host("host-a").unwrap().host_key,
                        &m.member("dev-mac").unwrap().member.auth_key,
                        &frozen_genesis(&host.rig.pairing),
                    )
                    .unwrap_err();
                assert_eq!(step["result"], "refused");
                assert_eq!(refused, PairingRefusal::FrozenGenesis);
                assert_eq!(json!(refused.as_str()), step["detail"]);
                self.pass();
            }
            other => panic!("{}: unhandled step {other}", self.name),
        }
    }

    /// The welcome on the wire: r9 revision, kind, permissions and the
    /// principal the client proved; its head after the carriage.
    fn check_welcome(&self, client: &str, welcome: &Value) {
        let principal = &self.clients[client].principal;
        assert_eq!(welcome["revision"], 9, "{}: {welcome}", self.name);
        assert_eq!(welcome["principal"], principal.as_str());
        let kind = match principal.split_once(':').unwrap().0 {
            "member" => "native",
            other => other,
        };
        assert_eq!(welcome["client_kind"], kind);
        assert!(welcome["features"].as_array().unwrap().len() >= 14);
        assert!(
            welcome["channel_id"]
                .as_str()
                .is_some_and(|c| c.len() == 32)
        );
        assert!(welcome.get("pending_recovery").is_some());
    }

    /// `send_record` of the handshake fixtures, live: a `list` on the
    /// client's channel (the vector's records are lists), the same record
    /// again (`as_counter`: a replay), or the host's own record sent back
    /// (`ct_from: "h2c"`).
    fn send_record(&mut self, step: &Value) {
        let client = step["send_record"].as_str().unwrap().to_owned();
        if step.get("ct_from").and_then(Value::as_str) == Some("h2c") {
            let host = self.host();
            let frame = host.chans[&client].received[0].clone();
            host.send_frame(&client, &frame);
            self.drain();
        } else if step.get("as_counter").is_some() {
            let host = self.host();
            let frame = host.chans[&client].sent.last().unwrap().clone();
            host.send_frame(&client, &frame);
            self.drain();
        } else {
            let id = self.uuid();
            let json = json!({"type": "session", "data": {"v": 1, "op": "list", "id": id}});
            self.send_json(&client, &json);
            self.later("send_record: the vector's exact record bytes", CRATE);
        }
        self.pass();
    }

    /// `replay{finish_of: previous, into_new_channel}`: the previous
    /// channel's `finish` sent again in a new channel after its own `init`
    /// and `accept` (the transcript differs).
    fn replay(&mut self, step: &Value) {
        let client = self.clients.keys().next().cloned().expect("a client");
        assert_eq!(step["replay"]["finish_of"], "previous");
        let host = self.host();
        let old = host.chans[&client].finish.clone().expect("a finish");
        host.handles += 1;
        let handle = format!("{client}-{}", host.handles);
        let mut chan = host.chans.remove(&client).unwrap();
        chan.handle = handle.clone();
        chan.raw.clear();
        chan.closed = None;
        let previous = chan.channel.take();
        host.chans.insert(client.clone(), chan);
        host.engine.reset_init_limiter();
        host.envelope_in(&envelope::open(&handle, Transport::Relay));
        let mono = host.now.mono_ms;
        let log = host.m.as_ref().unwrap().membership().clone();
        let (_, init) = Initiator::start(&log, &host.host_id, mono).unwrap();
        host.send_frame(&client, &init);
        host.pump();
        let accept = host.chans.get_mut(&client).unwrap().raw.pop_front();
        assert!(accept.is_some(), "{}: no accept", self.name);
        host.send_frame(&client, &old);
        host.pump();
        let chan = host.chans.get_mut(&client).unwrap();
        let reply = chan.raw.pop_front();
        let code = match reply.as_deref().map(chwire::parse_frame) {
            Some(Ok(Frame::Error { code })) => code,
            other => panic!("replayed finish: {other:?}"),
        };
        // The first channel goes on (its records are the next steps').
        chan.channel = previous;
        chan.handle = format!("{client}-{}", host.handles - 1);
        chan.closed = None;
        self.deliver(
            &client,
            json!({"op": "channel_error", "code": code, "at": "finish"}),
        );
        self.pass();
        self.later("replay: the vector's fixed e_h/n_h", CRATE);
    }

    /// `expect_local_status{recovery_pending}`: the runtime's status for
    /// `atem status` (the `Device list:` line) and the status row's label.
    fn local_status(&mut self, step: &Value) {
        let want = step["expect_local_status"]["recovery_pending"]
            .as_bool()
            .unwrap();
        let host = self.host();
        let clients = host.engine.status().attachments;
        let status = crate::runtime::host_bridge::device_list_status_of(
            host.m.as_ref(),
            None,
            clients,
            &host.now,
        )
        .expect("a device list");
        let look = crate::runtime::client::Look::Running {
            welcome: crate::runtime::client::Welcome {
                protocol: 1,
                build: String::new(),
                pid: 0,
                astation: true,
                host_error: None,
                worker_protocol: None,
                device_list: None,
            },
            status: Some(crate::runtime::protocol::RuntimeStatus {
                device_list: Some(status.clone()),
                ..Default::default()
            }),
        };
        let line = crate::status::device_list_line(&look, |ms| format!("@{ms}"))
            .unwrap()
            .value;
        assert_eq!(
            line.contains("; recovery pending: "),
            want,
            "{}: atem status: {line}",
            self.name
        );
        assert_eq!(
            status.label.as_deref() == Some("Recovery pending"),
            want,
            "{}: the status row's label {:?}",
            self.name,
            status.label
        );
        assert_eq!(status.pending_recovery.is_empty(), !want);
        self.pass();
    }
}

fn scenario_names() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(fixtures_dir())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.starts_with("r9-") && n.ends_with(".json") && !n.starts_with("r9-envelope-"))
        .map(|n| n.trim_end_matches(".json").to_owned())
        .collect();
    names.sort();
    // `ATEM_R9_FIXTURE=<name>` runs one.
    if let Ok(only) = std::env::var("ATEM_R9_FIXTURE") {
        names.retain(|n| *n == only);
    }
    names
}

fn run(name: &str) -> Option<(usize, Vec<(String, &'static str)>)> {
    let bytes = std::fs::read(fixtures_dir().join(format!("{name}.json"))).unwrap();
    let file: Value = serde_json::from_slice(&bytes).unwrap();
    if file["side"] != "host" || file["kind"] != "scenario" {
        return None;
    }
    let mut runner = Runner {
        name: name.to_owned(),
        v: vectors(),
        keys: key_book(),
        hosts: BTreeMap::new(),
        current: String::new(),
        clients: BTreeMap::new(),
        inbox: BTreeMap::new(),
        fresh: BTreeMap::new(),
        passed: 0,
        pending: Vec::new(),
        crash: None,
        gens: 0,
        captures: BTreeMap::new(),
        sessions: Vec::new(),
        harness_ids: BTreeSet::new(),
    };
    let (_tmp, _scope) = crate::test_profile::temp();
    runner.setup(&file);
    for step in file["steps"].as_array().unwrap() {
        runner.step(step);
    }
    Some((runner.passed, runner.pending))
}

/// Every host-side r9 scenario (but the envelope's) through the real
/// engine, store and session host. Run with `-- --nocapture` for the
/// counts and the pending list.
#[test]
fn r9_host_scenarios_on_the_real_engine_and_store() {
    let mut total = 0;
    let mut by_owner: BTreeMap<&str, usize> = BTreeMap::new();
    let mut ran = 0;
    for name in scenario_names() {
        let Some((passed, pending)) = run(&name) else {
            continue;
        };
        ran += 1;
        total += passed;
        eprintln!("{name}: {passed} checked, {} pending", pending.len());
        for (what, owner) in &pending {
            eprintln!("  PENDING {what}: {owner}");
            *by_owner.entry(owner).or_default() += 1;
        }
    }
    eprintln!("{ran} scenarios: {total} checked, pending {by_owner:?}");
    if std::env::var("ATEM_R9_FIXTURE").is_err() {
        assert!(ran >= 44, "the host scenarios ran ({ran})");
    }
}

/// Nothing a host scenario asserts is left to Task 7: what stays pending
/// is sealed push (Task 8) or the client side and exact vector bytes (the
/// crate's runners).
#[test]
fn no_host_scenario_item_is_left_to_task_7() {
    for name in scenario_names() {
        let Some((passed, pending)) = run(&name) else {
            continue;
        };
        assert!(passed > 0, "{name}");
        assert!(
            pending
                .iter()
                .all(|(_, owner)| *owner == T8 || *owner == CRATE || *owner == CHAIN_ONLY),
            "{name}: {pending:?}"
        );
    }
}
