//! Runs the r9 membership scenarios (`designs/protocol/fixtures/r9-chain-*`,
//! `r9-recovery-*` and `r9-service-expiry-over-90-days-is-invalid`;
//! `schema.md` "r9 fixtures") against the crate's verifier, publisher,
//! backup writer and restore.
//!
//! Every step and every expected field is either checked or listed as
//! pending with the task that brings it (the handshake, the host's durable
//! state and fault injection, the rest of admission and the fences, the
//! real runtime). An unknown step or field fails the run, so nothing is
//! skipped silently. `-- --nocapture` prints the counts and the pending
//! list.
mod support;

use std::collections::BTreeMap;

use atem_client::KeyId;
use atem_client::SignedObject;
use atem_client::backup::{BackupKey, KBackupEnvelope};
use atem_client::backup_writer::{BackupError, BackupJob, BackupWriter, Discarded, PutReply, Step};
use atem_client::canonical::StrictValue;
use atem_client::channel::HostAccept;
use atem_client::channel::responder::HostContext;
use atem_client::channel::{
    Channel, ChannelError, ClientProof, Initiator, Keyed, Principal, Responder,
};
use atem_client::encoding::{Hash32, b64u, b64u_decode};
use atem_client::membership::publish::{AppendReply, Published, Publisher};
use atem_client::membership::{Admission, Conflict, Member, MemberKind, Membership, Role, Stop};
use atem_client::restore::{Enrollment, Freshness, RestoreError, RestoreFlow, UserNotice};
use serde_json::{Map, Value, json};
use support::*;
use zeroize::Zeroizing;

const T6: &str = "host runner (src/session_protocol/membership/fixtures_tests.rs: the real r9 admission engine, device-list store and session host)";
const T7: &str = "host runner (src/session_protocol/membership/fixtures_tests.rs: the real r9 admission engine, device-list store and session host)";

/// Display clock of the backup writers: the fixtures' `k_backup` entries
/// are signed at 1793264100000 + seq (KB7, KB8).
const KB_SIGNED_AT: u64 = 1_793_264_100_000;

fn scenario_files() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(fixtures_dir())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| {
            (n.starts_with("r9-chain-")
                || n.starts_with("r9-recovery-")
                || n == "r9-service-expiry-over-90-days-is-invalid.json")
                && n.ends_with(".json")
        })
        .map(|n| n.trim_end_matches(".json").to_owned())
        .collect();
    names.sort();
    names
}

/// What one fixture checked and what it left to later tasks.
struct Report {
    name: String,
    passed: usize,
    pending: Vec<(String, &'static str)>,
}

impl Report {
    fn pass(&mut self) {
        self.passed += 1;
    }

    fn pending(&mut self, what: impl Into<String>, owner: &'static str) {
        self.pending.push((what.into(), owner));
    }
}

/// Replaces `${hash:L}` and `${vector:file:path}` in expected values.
fn resolve(value: &Value, v: &Vectors, named: &BTreeMap<String, SignedObject>) -> Value {
    match value {
        Value::String(text) => {
            if let Some(label) = text
                .strip_prefix("${hash:")
                .and_then(|t| t.strip_suffix('}'))
            {
                let hash = named
                    .get(label.trim_start_matches('@'))
                    .map(|o| o.entry_hash().unwrap())
                    .unwrap_or_else(|| v.hash(label));
                return Value::String(hash.to_hex());
            }
            if let Some(rest) = text
                .strip_prefix("${vector:")
                .and_then(|t| t.strip_suffix('}'))
            {
                let (file, path) = rest.split_once(':').unwrap();
                let mut node = load(file);
                for part in path.split('.') {
                    node = match part.parse::<usize>() {
                        Ok(i) => node[i].clone(),
                        Err(_) => node[part].clone(),
                    };
                }
                return node;
            }
            value.clone()
        }
        Value::Array(items) => Value::Array(items.iter().map(|i| resolve(i, v, named)).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, x)| (k.clone(), resolve(x, v, named)))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn labels(value: &Value) -> Vec<String> {
    value
        .as_array()
        .unwrap_or_else(|| panic!("not a list: {value}"))
        .iter()
        .map(|l| l.as_str().unwrap().to_owned())
        .collect()
}

fn device_of(principal: &str) -> String {
    principal
        .split_once(':')
        .map(|(_, id)| id.to_owned())
        .unwrap()
}

fn pending_json(m: &Membership, clock: &Clock) -> Value {
    Value::Array(
        m.pending_recovery(&clock.now)
            .into_iter()
            .map(|p| {
                json!({"entry_hash": p.entry_hash.to_hex(), "seq": p.seq, "action": p.action,
                       "subject": p.subject, "effective_at": p.effective_at})
            })
            .collect(),
    )
}

// ------------------------------------------------------------------- host

/// The membership side of what a client got back.
enum Reply {
    /// The reply to a `hello` (after its carriage): its fields.
    Hello(Value),
    /// The reply to an open channel's `membership` op.
    Membership(Map<String, Value>),
    /// `init` refused in the clear (frozen).
    ChannelFrozen,
}

struct Host {
    m: Membership,
    clock: Clock,
}

struct HostSide<'a> {
    v: &'a Vectors,
    book: &'a Book,
    report: Report,
    hosts: BTreeMap<String, Host>,
    current: String,
    clients: BTreeMap<String, String>,
    /// Each client's key (a `r9-vectors-keys` name).
    client_keys: BTreeMap<String, String>,
    replies: BTreeMap<String, Reply>,
    carried: Vec<Hash32>,
    faulted: bool,
    frozen_genesis: Vec<Hash32>,
    named: BTreeMap<String, SignedObject>,
    // Relay-side state.
    relay: Option<FakeRelay>,
    devices: BTreeMap<String, (Membership, Publisher, Vec<Hash32>)>,
}

fn principal_of(principal: &str) -> Principal {
    let (kind, id) = principal.split_once(':').unwrap();
    match kind {
        "member" => Principal::Native {
            device_id: id.into(),
        },
        "service" => Principal::Service {
            device_id: id.into(),
        },
        other => panic!("principal kind {other}"),
    }
}

/// A full `atem-ch1` handshake of a client (its key from the book) with a
/// host whose committed log is `host`, the client's `hello` carrying
/// `carry`. The client's verified log is the host's (the fixtures carry
/// the entries explicitly). Returns what the host decrypted, or its clear
/// refusal.
struct Shake {
    keyed: Keyed,
    client: Channel,
    entries: Vec<StrictValue>,
    bytes: usize,
}

fn channel_handshake(
    book: &Book,
    host: &Membership,
    principal: &Principal,
    key: &str,
    carry: &[StrictValue],
) -> Result<Shake, ChannelError> {
    let host_key = KeyId::new("host-a/host_key");
    let ctx = HostContext {
        log: host,
        host_id: "host-a",
        host_trust_gen: 1,
        provider: &book.provider,
        key: &host_key,
    };
    let (initiator, init) = Initiator::start(host, "host-a", 0).unwrap();
    let (await_finish, accept) = Responder::on_init(&ctx, &init, 0).map_err(|r| r.error)?;
    let signed = initiator
        .on_frame(&accept, host, 0)
        .unwrap()
        .sign(principal.clone(), &book.provider, &book.auth(key))
        .unwrap();
    let head = host.head();
    let hello = json!({"type": "session", "data": {"v": 1, "op": "hello", "revision": 9,
        "id": "aaaaaaaa-0000-4000-8000-0000000000aa",
        "proof": {"principal": principal.to_json(), "sig": b64u(signed.sig_c())},
        "membership": {"head": {"seq": head.seq, "hash": head.hash.to_hex()},
                       "entries": carry.iter().map(|e| e.value().clone()).collect::<Vec<_>>()}}});
    let (client, finish) = signed.finish(hello.to_string().as_bytes(), 0).unwrap();
    let opened = await_finish.on_finish(&finish, 0).unwrap();
    let received = StrictValue::parse(opened.hello(), usize::MAX).unwrap();
    let data = received.get("data").unwrap();
    let proof = data.get("proof").unwrap();
    let entries = data.get("membership").unwrap().get("entries").unwrap();
    let proof = ClientProof {
        principal: Principal::from_json(proof.get("principal").unwrap().value(), None).unwrap(),
        sig_c: b64u_decode(proof.get("sig").unwrap().value().as_str().unwrap()).unwrap(),
    };
    Ok(Shake {
        keyed: opened.key(&proof),
        client,
        bytes: entries.value().to_string().len(),
        entries: entries.items().unwrap(),
    })
}

impl Shake {
    /// After the carriage: a member is admitted with its `auth_key` (sig_c
    /// must verify); anyone else gets the encrypted first-record refusal.
    /// Either way the client opens the host's first record.
    fn complete(self, admission: &Admission) {
        let Shake {
            keyed, mut client, ..
        } = self;
        let first = match admission {
            Admission::Member { state, .. } => {
                let mut host = keyed
                    .admit(&state.member.auth_key, u64::MAX)
                    .expect("sig_c verifies");
                assert_eq!(host.channel_id(), client.channel_id());
                host.seal(br#"{"type":"session","data":{"v":1,"op":"welcome"}}"#, 0)
                    .unwrap()
            }
            _ => keyed
                .refuse(br#"{"type":"session","data":{"v":1,"op":"error"}}"#, 0)
                .unwrap(),
        };
        client.open(&first, 0).unwrap();
    }
}

fn admission_fields(adm: &Admission, m: &Membership, clock: &Clock) -> Value {
    match adm {
        Admission::Frozen => json!({"op": "error", "code": "account_frozen"}),
        Admission::Invalid {
            head,
            index,
            reason,
            need_before,
        } => {
            let mut fields = json!({"op": "error", "code": "membership_invalid",
                "head.seq": head.seq, "head.hash": head.hash.to_hex(),
                "index": index, "detail": reason.code()});
            if let Some(seq) = need_before {
                fields["need_before"] = json!(seq);
            }
            fields
        }
        Admission::Incomplete { head } => json!({"op": "error", "code": "membership_incomplete",
            "head.seq": head.seq, "head.hash": head.hash.to_hex()}),
        Admission::RecoveryPending {
            entry_hash,
            effective_at,
        } => json!({"op": "error", "code": "recovery_pending",
            "entry_hash": entry_hash.to_hex(), "effective_at": effective_at}),
        Admission::Unauthorized(detail) => {
            json!({"op": "error", "code": "unauthorized", "detail": detail})
        }
        Admission::Member { head, state } => {
            let kind = match state.member.kind {
                MemberKind::Native { .. } => "member",
                MemberKind::Service { .. } => "service",
            };
            json!({"op": "welcome", "principal": format!("{kind}:{}", state.member.device_id),
                "head.seq": head.seq, "head.hash": head.hash.to_hex(),
                "pending_recovery": pending_json(m, clock)})
        }
    }
}

impl<'a> HostSide<'a> {
    fn new(name: &str, v: &'a Vectors, book: &'a Book) -> Self {
        HostSide {
            v,
            book,
            report: Report {
                name: name.to_owned(),
                passed: 0,
                pending: Vec::new(),
            },
            hosts: BTreeMap::new(),
            current: String::new(),
            clients: BTreeMap::new(),
            client_keys: BTreeMap::new(),
            replies: BTreeMap::new(),
            carried: Vec::new(),
            faulted: false,
            frozen_genesis: Vec::new(),
            named: BTreeMap::new(),
            relay: None,
            devices: BTreeMap::new(),
        }
    }

    fn pinned(&self, labels: &[String], clock: &Clock) -> Membership {
        let refs: Vec<&str> = labels.iter().map(String::as_str).collect();
        let verified =
            Membership::verify_chain(ACCOUNT, &genesis_hash(), &self.v.entries(&refs), &clock.now)
                .unwrap();
        assert!(verified.deferred.is_none());
        verified.membership
    }

    fn host(&mut self) -> &mut Host {
        let name = self.current.clone();
        self.hosts
            .get_mut(&name)
            .unwrap_or_else(|| panic!("no host {name:?}"))
    }

    fn setup(&mut self, setup: &Value) {
        let pinned = labels(&setup["pinned"]);
        let mut add_host = |name: &str, host: &Value| {
            let clock = Clock::at(host["wall_clock_ms"].as_u64().unwrap());
            let m = self.pinned(&pinned, &clock);
            self.hosts.insert(name.to_owned(), Host { m, clock });
        };
        if let Some(host) = setup.get("host") {
            add_host("", host);
        }
        if let Some(hosts) = setup.get("hosts") {
            for host in hosts.as_array().unwrap() {
                add_host(host["name"].as_str().unwrap(), host);
            }
            self.current = hosts[0]["name"].as_str().unwrap().to_owned();
        }
        for client in setup["clients"].as_array().unwrap() {
            self.clients.insert(
                client["name"].as_str().unwrap().to_owned(),
                client["principal"].as_str().unwrap().to_owned(),
            );
            self.client_keys.insert(
                client["name"].as_str().unwrap().to_owned(),
                client["key"].as_str().unwrap().to_owned(),
            );
        }
        for key in ["connected", "holds_lease"] {
            if setup.get(key).is_some() {
                self.report
                    .pending(format!("setup {key}: attachments and leases"), T7);
            }
        }
        if setup.get("sessions").is_some() {
            self.report.pending("setup sessions", T7);
        }
        if let Some(head) = setup.get("relay_head") {
            let head = head.as_str().unwrap();
            let end = pinned.iter().position(|l| l == head).unwrap();
            let objects = pinned[..=end].iter().map(|l| self.v.object(l)).collect();
            self.relay = Some(FakeRelay::with_log(objects));
            let clock = self.hosts[""].clock.clone();
            for principal in self.clients.values() {
                let m = self.pinned(&pinned[..=end], &clock);
                self.devices
                    .insert(device_of(principal), (m, Publisher::new(), Vec::new()));
            }
        }
    }

    /// The carried entries as a client sends them (some don't parse).
    /// The carried entries as a client sends them (some don't parse), and
    /// their size on the wire.
    fn carry(&mut self, labels: &[String]) -> (Vec<StrictValue>, usize) {
        self.carried.extend(labels.iter().map(|l| self.v.hash(l)));
        let bytes =
            atem_client::channel::carriage::carried_bytes(labels.iter().map(|l| self.v.wire(l)));
        (
            labels.iter().map(|l| strict(self.v.wire(l))).collect(),
            bytes,
        )
    }

    fn step(&mut self, step: &Value) {
        let object = step.as_object().unwrap();
        let kind = [
            "connect",
            "send_membership",
            "expect",
            "expect_channel_error",
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
            "reconnect",
            "expect_channel_or_session_error",
            "unpair",
            "pair",
            "relay_append",
            "assert_client",
            "host_connect",
        ]
        .into_iter()
        .find(|k| object.contains_key(*k))
        .unwrap_or_else(|| panic!("{}: unknown step {step}", self.report.name));
        if self.faulted {
            self.report
                .pending(format!("{kind} after an injected fault or crash"), T6);
            return;
        }
        match kind {
            "connect" => self.connect(step),
            "send_membership" => self.send_membership(step),
            "expect" => self.expect(step),
            "expect_channel_error" => {
                let client = step["expect_channel_error"].as_str().unwrap();
                match (step["code"].as_str().unwrap(), self.replies.remove(client)) {
                    ("account_frozen", Some(Reply::ChannelFrozen)) => {
                        assert_eq!(step["at"], "init");
                        self.report.pass();
                    }
                    ("busy", _) => self.report.pending("init refused busy (halted)", T6),
                    (code, _) => panic!("{}: expected channel error {code}", self.report.name),
                }
            }
            "advance_ms" => {
                let ms = step["advance_ms"].as_u64().unwrap();
                for host in self.hosts.values_mut() {
                    host.clock.advance(ms);
                    let now = host.clock.now.clone();
                    host.m.advance(&now);
                }
                self.report.pass();
            }
            "set_wall_clock" => {
                let wall = step["set_wall_clock"].as_u64().unwrap();
                for host in self.hosts.values_mut() {
                    host.clock.set_wall(wall);
                    let now = host.clock.now.clone();
                    host.m.advance(&now);
                }
                self.report.pass();
            }
            "assert" => self.assert(&step["assert"]),
            "expect_local_status" => {
                let want = step["expect_local_status"]["recovery_pending"]
                    .as_bool()
                    .unwrap();
                let host = self.host();
                let now = host.clock.now.clone();
                assert_eq!(!host.m.pending_recovery(&now).is_empty(), want);
                self.report.pass();
                self.report.pending(
                    "expect_local_status: the status row and atem status text",
                    T7,
                );
            }
            "restart_runtime" | "crash_runtime" => {
                if step.get("disk").is_some() || kind == "crash_runtime" {
                    self.faulted = true;
                    self.report.pending(format!("{kind} with disk state"), T6);
                } else {
                    // An orderly restart: every host's log goes through its
                    // durable form (`membership.json`) and back. The host's
                    // files, fsyncs and faults are checked by its own runner
                    // (`src/session_protocol/membership`).
                    for host in self.hosts.values_mut() {
                        let stored = host.m.to_stored();
                        let back = Membership::from_stored(
                            host.m.account_id(),
                            &host.m.genesis_hash(),
                            &stored,
                        )
                        .unwrap_or_else(|e| panic!("stored log refused: {e}"));
                        assert_eq!(back, host.m, "the stored log reads back unchanged");
                        host.m = back;
                    }
                    self.report.pass();
                    self.replies.clear();
                }
            }
            "fail_next_membership_write" | "crash_after_membership_commit" => {
                self.faulted = true;
                self.report.pending(kind, T6);
            }
            "unpair" => {
                let genesis = self.host().m.genesis_hash();
                if self.host().m.frozen().is_some() {
                    self.frozen_genesis.push(genesis);
                }
                self.report
                    .pending("unpair (pairing/frozen_genesis kept, files deleted)", T6);
            }
            "pair" => {
                let pin = labels(&step["pair"]["log"]);
                let clock = self.host().clock.clone();
                let m = self.pinned(&pin, &clock);
                let refusal = m
                    .check_pairing(
                        "host-a",
                        1,
                        &self.book.public("host-a/host_key"),
                        &self.book.public("dev-mac/auth"),
                        &self.frozen_genesis,
                    )
                    .unwrap_err();
                assert_eq!(step["result"], "refused");
                assert_eq!(refusal.as_str(), step["detail"].as_str().unwrap());
                self.report.pass();
            }
            "relay_append" => self.relay_append(step),
            "assert_client" => self.assert_relay_client(&step["assert_client"]),
            "host_connect" => {
                let spec = &step["host_connect"];
                let clock = self.hosts[""].clock.clone();
                let mut m = self.pinned(&labels(&spec["host_pinned"]), &clock);
                let (carry, _) = self.carry(&labels(&spec["carry"]));
                let client = spec["client"].as_str().unwrap();
                let principal = principal_of(&self.clients[client]);
                let shake =
                    channel_handshake(self.book, &m, &principal, &self.client_keys[client], &carry)
                        .unwrap();
                let eval = m.evaluate(&shake.entries, &clock.now);
                let admission =
                    eval.admission(&device_of(&self.clients[client]), false, &clock.now);
                m = eval.next;
                shake.complete(&admission);
                self.hosts.insert("relay-host".into(), Host { m, clock });
                self.current = "relay-host".into();
                self.report.pass();
            }
            other => self.report.pending(other.to_owned(), T7),
        }
    }

    fn connect(&mut self, step: &Value) {
        let client = step["connect"].as_str().unwrap().to_owned();
        if let Some(host) = step.get("host") {
            self.current = host.as_str().unwrap().to_owned();
        }
        let principal = self.clients[&client].clone();
        let device = device_of(&principal);
        let (carry, bytes) = self.carry(&labels(&step["carry"]));
        let more = step.get("more").and_then(Value::as_bool).unwrap_or(false);
        for key in ["hello", "grant"] {
            if step.get(key).is_some() {
                self.report.pending(format!("connect {key}"), T7);
            }
        }
        let key = self.client_keys[&client].clone();
        let book = self.book;
        let host = self.host();
        // The atem-ch1 handshake (host B of a two-host fixture answers with
        // host-a's test key: "handshake keys come from the harness"); the
        // host evaluates the entries that came out of the decrypted hello.
        let shake = match channel_handshake(book, &host.m, &principal_of(&principal), &key, &carry)
        {
            Ok(shake) => shake,
            Err(error) => {
                assert_eq!(error, ChannelError::AccountFrozen);
                assert!(host.m.frozen().is_some());
                self.replies.insert(client, Reply::ChannelFrozen);
                self.report.pass();
                return;
            }
        };
        assert_eq!(
            shake.entries, carry,
            "carried through the channel unchanged"
        );
        // What arrived is the entries array, measured as the planner and
        // the host measure it (`carried_bytes`).
        assert_eq!(shake.bytes, bytes);
        let now = host.clock.now.clone();
        let eval = host.m.evaluate(&shake.entries, &now);
        let admission = eval.admission(&device, more, &now);
        host.m = eval.next;
        shake.complete(&admission);
        self.report.pass();
        let host = self.host();
        let fields = admission_fields(&admission, &host.m, &host.clock);
        self.replies.insert(client, Reply::Hello(fields));
    }

    fn send_membership(&mut self, step: &Value) {
        let client = step["send_membership"].as_str().unwrap().to_owned();
        let (carry, _) = self.carry(&labels(&step["entries"]));
        let host = self.host();
        let now = host.clock.now.clone();
        let eval = host.m.evaluate(&carry, &now);
        let stop = eval.stop.clone();
        let admission = eval.admission("", false, &now);
        host.m = eval.next;
        let fields = match (&stop, admission) {
            (Some(Stop::Invalid { .. } | Stop::NeedBefore { .. }), adm)
            | (
                Some(
                    Stop::Frozen
                    | Stop::Conflict {
                        outcome: Conflict::Freeze,
                        ..
                    },
                ),
                adm,
            ) => admission_fields(&adm, &host.m, &host.clock),
            _ => {
                let head = host.m.head();
                json!({"op": "membership_head", "head.seq": head.seq,
                       "head.hash": head.hash.to_hex(),
                       "pending_recovery": pending_json(&host.m, &host.clock)})
            }
        };
        self.replies.insert(
            client,
            Reply::Membership(fields.as_object().unwrap().clone()),
        );
    }

    fn expect(&mut self, step: &Value) {
        let client = step["expect"].as_str().unwrap();
        let want = resolve(&step["match"], self.v, &self.named);
        let fields = match self.replies.remove(client) {
            Some(Reply::Hello(fields)) => fields.as_object().unwrap().clone(),
            Some(Reply::Membership(fields)) => fields,
            Some(Reply::ChannelFrozen) => {
                panic!("{}: {client} got a channel error", self.report.name)
            }
            None => {
                self.report.pending(
                    format!("expect {client} {}: an event to an attachment", want["op"]),
                    T7,
                );
                return;
            }
        };
        let mut later = Vec::new();
        for (key, value) in want.as_object().unwrap() {
            match fields.get(key) {
                Some(got) => assert_eq!(
                    got, value,
                    "{}: expect {client} {key} (got {fields:?})",
                    self.report.name
                ),
                None if ["revision", "client_kind", "permissions"].contains(&key.as_str()) => {
                    later.push(key.clone())
                }
                None => panic!(
                    "{}: expect {client}: field {key} not produced ({fields:?})",
                    self.report.name
                ),
            }
        }
        self.report.pass();
        if !later.is_empty() {
            self.report
                .pending(format!("welcome {}", later.join(", ")), T7);
        }
    }

    fn assert(&mut self, assert: &Value) {
        if let Some(host) = assert.get("host") {
            self.current = host.as_str().unwrap().to_owned();
        }
        let v = self.v;
        let book = self.book;
        let name = self.report.name.clone();
        let carried = self.carried.clone();
        let mut later = Vec::new();
        let host = self.host();
        let m = &host.m;
        for (key, want) in assert.as_object().unwrap() {
            match key.as_str() {
                "host" => {}
                "head" => assert_eq!(m.head(), v.head(want.as_str().unwrap()), "{name}: head"),
                "frozen" => assert_eq!(m.frozen().is_some(), want.as_bool().unwrap(), "{name}"),
                "evidence_count" => {
                    assert_eq!(m.evidence().count, want.as_u64().unwrap(), "{name}")
                }
                "evidence_reason" => assert_eq!(
                    m.evidence().recent.last().unwrap().reason.as_str(),
                    want.as_str().unwrap()
                ),
                "stored_sig" => {
                    let label = want.as_str().unwrap();
                    let seq = v.head(label).seq;
                    let sig = b64u_decode(v.wire(label)["sig"].as_str().unwrap()).unwrap();
                    assert_eq!(m.entry(seq).unwrap().object().sig(), sig.as_slice());
                }
                "pending" => {
                    for (label, state) in want.as_object().unwrap() {
                        let record = m
                            .record(&v.hash(label))
                            .unwrap_or_else(|| panic!("{name}: no record for {label}"));
                        assert_eq!(
                            record.state().as_str(),
                            state.as_str().unwrap(),
                            "{name}: {label}"
                        );
                    }
                }
                "members" => assert_eq!(
                    m.members(),
                    labels(want).iter().map(String::as_str).collect::<Vec<_>>(),
                    "{name}: members"
                ),
                "recovery_key" => assert_eq!(
                    *m.recovery_key(),
                    book.public(&format!("{}/sign", want.as_str().unwrap())),
                    "{name}: recovery key"
                ),
                "k_backup" => {
                    let record = m.k_backup().unwrap();
                    assert_eq!(record.blob_version, want["blob_version"].as_u64().unwrap());
                    assert_eq!(
                        record.backup_hash.to_hex(),
                        resolve(&want["backup_hash"], v, &BTreeMap::new())
                            .as_str()
                            .unwrap()
                    );
                }
                "carried_ever" => {
                    for (label, ever) in want.as_object().unwrap() {
                        assert_eq!(carried.contains(&v.hash(label)), ever.as_bool().unwrap());
                    }
                }
                "membership_applied" | "control_gen" | "attachments" | "lease_holder"
                | "pty_writes" | "pty_writes_local" | "pty_writes_remote"
                | "pty_writes_dropped" | "dispatches" | "receipts" => later.push((key.clone(), T7)),
                "membership_halted" | "membership_held" | "membership_unclean"
                | "carriage_record" | "fault_record" | "frozen_durable" | "frozen_genesis" => {
                    later.push((key.clone(), T6))
                }
                other => panic!("{name}: unknown assert key {other}"),
            }
        }
        self.report.pass();
        for (key, owner) in later {
            self.report.pending(format!("assert {key}"), owner);
        }
    }

    fn relay_append(&mut self, step: &Value) {
        let spec = &step["relay_append"];
        let by = spec["by"].as_str().unwrap().to_owned();
        let label = spec["entry"].as_str().unwrap();
        let expected = self.v.head(spec["expected"].as_str().unwrap());
        let retry = spec.get("retry").and_then(Value::as_bool).unwrap_or(false);
        let relay = self.relay.as_mut().unwrap();
        let clock = self.hosts[""].clock.clone();
        if retry {
            // An uncertain outcome: the same stored bytes, or the same body
            // re-signed (E7_retry): never a conflict.
            let answer = relay.append(&self.v.object(label), expected);
            assert_eq!(answer.status() as u64, step["status"].as_u64().unwrap());
            if let Some(stored) = step["reply"].get("stored") {
                let atem_client_relay_stored = match &answer {
                    RelayAppend::Ok(o) => o.entry_hash().unwrap(),
                    _ => unreachable!(),
                };
                assert_eq!(
                    atem_client_relay_stored,
                    self.v.hash(stored.as_str().unwrap())
                );
            }
            self.report.pass();
            return;
        }
        let (log, publisher, discarded) = self.devices.get_mut(&by).unwrap();
        let body = self.v.wire(label)["body"].clone();
        publisher.prepare(log, body).unwrap();
        let signed = publisher
            .sign(&self.book.provider, &self.book.auth(&by), None)
            .unwrap()
            .clone();
        assert_eq!(signed.hash(), self.v.hash(label));
        let answer = relay.append(signed.object(), expected);
        assert_eq!(answer.status() as u64, step["status"].as_u64().unwrap());
        if let RelayAppend::Conflict { head, entries, .. } = &answer {
            let reply = &step["reply"];
            assert_eq!(*head, self.v.head(reply["head"].as_str().unwrap()));
            let want: Vec<Hash32> = labels(&reply["entries"])
                .iter()
                .map(|l| self.v.hash(l))
                .collect();
            let got: Vec<Hash32> = entries.iter().map(|e| e.entry_hash().unwrap()).collect();
            assert_eq!(got, want);
        }
        match publisher.reply(answer.reply(), log, &clock.now).unwrap() {
            Published::Committed(head) => assert_eq!(head.hash, self.v.hash(label)),
            Published::LostRace { discarded: d, .. } => {
                discarded.push(d.signed.unwrap().hash());
            }
            other => panic!("{other:?}"),
        }
        self.report.pass();
    }

    fn assert_relay_client(&mut self, spec: &Value) {
        let client = spec["client"].as_str().unwrap();
        let device = device_of(&self.clients[client]);
        let (log, _, discarded) = &self.devices[&device];
        let want: Vec<Hash32> = labels(&spec["discarded"])
            .iter()
            .map(|l| self.v.hash(l))
            .collect();
        assert_eq!(*discarded, want);
        assert_eq!(log.head(), self.v.head(spec["log_head"].as_str().unwrap()));
        self.report.pass();
    }
}

// ----------------------------------------------------------------- client

struct Writer {
    by: String,
    log: Membership,
    writer: Option<BackupWriter>,
    step: Option<Step>,
    saved: Option<(BackupWriter, Membership)>,
    uploads: BTreeMap<u64, String>,
}

struct ClientSide<'a> {
    v: &'a Vectors,
    book: &'a Book,
    report: Report,
    clients: BTreeMap<String, String>,
    writers: BTreeMap<String, Writer>,
    named_bytes: BTreeMap<String, String>,
    named: BTreeMap<String, SignedObject>,
    keys: BTreeMap<String, [u8; 32]>,
    clock: Clock,
    /// The last restore: the kids it stored, or why it stopped (`None`:
    /// the kit itself was refused).
    last_restore: Option<Result<Vec<String>, Option<RestoreError>>>,
    /// The restore client machine of the last `restore` step.
    last_flow: Option<RestoreFlow>,
}

impl<'a> ClientSide<'a> {
    fn new(name: &str, v: &'a Vectors, book: &'a Book) -> Self {
        // K by kid: the book's K-gen-3, and kit 1's backup's keys.
        let mut keys = BTreeMap::new();
        let kit1 = book.kit("recovery");
        let recovery = load("r9-vectors-recovery");
        for path in ["k_backup", "k_backup_rotated"] {
            let env = KBackupEnvelope::from_strict(&strict(&recovery[path]["wire"])).unwrap();
            for key in env.open_with_kit(&kit1).unwrap() {
                keys.insert(key.kid.clone(), *key.k);
            }
        }
        ClientSide {
            v,
            book,
            report: Report {
                name: name.to_owned(),
                passed: 0,
                pending: Vec::new(),
            },
            clients: BTreeMap::new(),
            writers: BTreeMap::new(),
            named_bytes: BTreeMap::new(),
            named: BTreeMap::new(),
            keys,
            clock: Clock::at(1_793_264_200_000),
            last_restore: None,
            last_flow: None,
        }
    }

    fn setup(&mut self, setup: &Value) {
        for client in setup["clients"].as_array().into_iter().flatten() {
            self.clients.insert(
                client["name"].as_str().unwrap().to_owned(),
                device_of(client["principal"].as_str().unwrap()),
            );
        }
        assert_eq!(setup["account_id"], ACCOUNT);
        assert_eq!(
            resolve(&setup["genesis_hash"], self.v, &self.named),
            Value::String(genesis_hash().to_hex())
        );
        if let Some(hosts) = setup.get("hosts") {
            // The restoring device reaches these hosts (their heads are the
            // steps' `host_heads`).
            assert!(hosts.is_array());
        }
        if let Some(log) = setup.get("client_log") {
            let refs = labels(log);
            let refs: Vec<&str> = refs.iter().map(String::as_str).collect();
            for (name, device) in self.clients.clone() {
                let m = Membership::verify_chain(
                    ACCOUNT,
                    &genesis_hash(),
                    &self.v.entries(&refs),
                    &self.clock.now,
                )
                .unwrap()
                .membership;
                self.writers.insert(
                    name,
                    Writer {
                        by: device,
                        log: m,
                        writer: None,
                        step: None,
                        saved: None,
                        uploads: BTreeMap::new(),
                    },
                );
            }
        }
        if setup.get("relay_occupied").is_some() {
            // The relay's answers are the fixture's `relay_reply` steps.
            self.report.pass();
        }
    }

    fn entry_ref(&self, label: &str) -> SignedObject {
        match label.strip_prefix('@') {
            Some(name) => self.named[name].clone(),
            None => self.v.object(label),
        }
    }

    /// Seals as the caller of `Step::Seal` would: with the vectors' `ikmE`
    /// when a vector envelope has these parameters (so its bytes are
    /// reproduced), else with a fresh ephemeral.
    fn seal(&self, log: &Membership, version: u64, job: &BackupJob) -> KBackupEnvelope {
        let keys: Vec<BackupKey> = job
            .kids
            .iter()
            .map(|kid| BackupKey {
                kid: kid.clone(),
                k: Zeroizing::new(self.keys[kid]),
            })
            .collect();
        let recovery = load("r9-vectors-recovery");
        for vector in [&recovery["k_backup"], &recovery["k_backup_rotated"]] {
            let env = KBackupEnvelope::from_strict(&strict(&vector["wire"])).unwrap();
            if env.blob_version == version && env.kids == job.kids && env.recovery_key == job.kit {
                let ikm = unhex32(vector["ikmE_hex"].as_str().unwrap());
                return KBackupEnvelope::seal_with_ikm(
                    log.account_id(),
                    log.genesis_hash(),
                    version,
                    &job.kit,
                    &keys,
                    &ikm,
                )
                .unwrap();
            }
        }
        KBackupEnvelope::seal(
            log.account_id(),
            log.genesis_hash(),
            version,
            &job.kit,
            &keys,
        )
        .unwrap()
    }

    /// Runs a writer's steps that need no relay answer (sealing; signing
    /// the stored body).
    fn drive(&mut self, name: &str) {
        let book = self.book;
        loop {
            let w = &self.writers[name];
            if let Some(Step::Sign { body }) = w.step.clone() {
                let w = self.writers.get_mut(name).unwrap();
                // The writer (with this body) is stored before the key signs.
                let writer = w.writer.as_mut().unwrap();
                assert_eq!(writer.prepared().unwrap().body, body);
                w.step = Some(writer.sign(&book.provider, &book.auth(&w.by)));
                continue;
            }
            let Some(Step::Seal { blob_version }) = w.step.clone() else {
                return;
            };
            let job = w.writer.as_ref().unwrap().job().clone();
            let envelope = self.seal(&w.log, blob_version, &job);
            let w = self.writers.get_mut(name).unwrap();
            let signed_at = KB_SIGNED_AT + w.log.head().seq + 1;
            let step = w
                .writer
                .as_mut()
                .unwrap()
                .sealed(&w.log, envelope, signed_at);
            w.step = Some(step);
        }
    }

    fn step(&mut self, step: &Value) {
        let object = step.as_object().unwrap();
        let kind = [
            "client_backup",
            "expect_backup_put",
            "expect_backup_put_none",
            "relay_reply",
            "expect_log_append",
            "client_crash",
            "client_restart",
            "assert_client",
            "restore",
        ]
        .into_iter()
        .find(|k| object.contains_key(*k))
        .unwrap_or_else(|| panic!("{}: unknown step {step}", self.report.name));
        match kind {
            "client_backup" => {
                let spec = &step["client_backup"];
                let name = spec["by"].as_str().unwrap().to_owned();
                let kit = self
                    .book
                    .public(&format!("{}/sign", spec["kit"].as_str().unwrap()));
                let w = self.writers.get_mut(&name).unwrap();
                let job = BackupJob {
                    kids: labels(&spec["kids"]),
                    kit,
                    signer: w.by.clone(),
                };
                let (writer, step) = BackupWriter::start(&w.log, job);
                w.writer = Some(writer);
                w.step = Some(step);
                self.drive(&name);
                self.report.pass();
            }
            "expect_backup_put" => {
                let spec = &step["expect_backup_put"];
                let name = spec["by"].as_str().unwrap();
                let Some(Step::Put {
                    blob_version,
                    bytes,
                }) = self.writers[name].step.clone()
                else {
                    panic!(
                        "{}: {name} isn't uploading: {:?}",
                        self.report.name, self.writers[name].step
                    )
                };
                assert_eq!(blob_version, spec["blob_version"].as_u64().unwrap());
                if let Some(want) = spec.get("bytes") {
                    let want = resolve(want, self.v, &self.named);
                    let want = KBackupEnvelope::from_strict(&strict(&want)).unwrap().jcs();
                    assert_eq!(bytes, want, "byte-exact envelope");
                }
                if let Some(same) = spec.get("same_bytes_as") {
                    assert_eq!(bytes, self.named_bytes[same.as_str().unwrap()]);
                }
                if let Some(label) = step.get("name") {
                    self.named_bytes
                        .insert(label.as_str().unwrap().to_owned(), bytes.clone());
                }
                if let Some(label) = step.get("name").and_then(Value::as_str) {
                    self.writers
                        .get_mut(name)
                        .unwrap()
                        .uploads
                        .insert(blob_version, label.to_owned());
                }
                self.report.pass();
            }
            "expect_backup_put_none" => {
                let name = step["expect_backup_put_none"]["by"].as_str().unwrap();
                assert!(!matches!(self.writers[name].step, Some(Step::Put { .. })));
                self.report.pass();
            }
            "relay_reply" => self.relay_reply(&step["relay_reply"]),
            "expect_log_append" => {
                let spec = &step["expect_log_append"];
                let name = spec["by"].as_str().unwrap();
                let Some(Step::Append { entry, expected }) = self.writers[name].step.clone() else {
                    panic!("{}: {name} isn't appending", self.report.name)
                };
                let body = entry.body();
                assert_eq!(body["action"], spec["action"]);
                assert_eq!(body["k_backup"]["blob_version"], spec["blob_version"]);
                assert_eq!(body["seq"], spec["seq"]);
                let want_expected = self.entry_ref(spec["expected"].as_str().unwrap());
                assert_eq!(expected, head_of(&want_expected));
                if let Some(of) = spec.get("backup_hash_of") {
                    let bytes = &self.named_bytes[of.as_str().unwrap()];
                    let env = KBackupEnvelope::parse(bytes.as_bytes()).unwrap();
                    assert_eq!(
                        body["k_backup"]["backup_hash"].as_str().unwrap(),
                        env.backup_hash().to_hex()
                    );
                }
                if let Some(label) = spec.get("entry") {
                    let want = self.v.object(label.as_str().unwrap());
                    assert_eq!(entry.jcs(), want.jcs(), "the body equals {label}");
                    assert_eq!(entry.entry_hash().unwrap(), want.entry_hash().unwrap());
                }
                if let Some(label) = step.get("name") {
                    self.named
                        .insert(label.as_str().unwrap().to_owned(), entry.clone());
                }
                self.report.pass();
            }
            "client_crash" => {
                let name = step["client_crash"].as_str().unwrap();
                let w = self.writers.get_mut(name).unwrap();
                // Everything the writer holds is its durable state.
                w.saved = Some((w.writer.take().unwrap(), w.log.clone()));
                w.step = None;
                self.report.pass();
            }
            "client_restart" => {
                let name = step["client_restart"].as_str().unwrap();
                let w = self.writers.get_mut(name).unwrap();
                let (mut writer, log) = w.saved.take().unwrap();
                w.step = Some(writer.restart());
                w.writer = Some(writer);
                w.log = log;
                self.drive(name);
                self.report.pass();
            }
            "assert_client" => self.assert_client(&step["assert_client"]),
            "restore" => self.restore(step),
            _ => unreachable!(),
        }
    }

    fn relay_reply(&mut self, spec: &Value) {
        let name = spec["by"].as_str().unwrap().to_owned();
        let status = spec["status"].as_u64().unwrap();
        let entries: Vec<SignedObject> = spec
            .get("entries")
            .map(|e| labels(e).iter().map(|l| self.entry_ref(l)).collect())
            .unwrap_or_default();
        if let Some(head) = spec.get("head") {
            let head = self.entry_ref(head.as_str().unwrap());
            assert_eq!(head_of(&head), head_of(entries.last().unwrap()));
        }
        let reply_head = spec
            .get("head")
            .map(|h| head_of(&self.entry_ref(h.as_str().unwrap())))
            .or_else(|| entries.last().map(head_of));
        let now = self.clock.now.clone();
        let w = self.writers.get_mut(&name).unwrap();
        let writer = w.writer.as_mut().unwrap();
        let step = match w.step.clone() {
            Some(Step::Put { .. }) => writer.put_reply(
                &w.log,
                if status == 200 {
                    PutReply::Stored
                } else {
                    PutReply::Occupied {
                        max_occupied: spec["max_occupied"].as_u64().unwrap(),
                    }
                },
            ),
            Some(Step::Append { .. }) => {
                let reply = if status == 200 {
                    AppendReply::Stored
                } else {
                    AppendReply::Conflict {
                        head: reply_head.unwrap(),
                        entries: entries.clone(),
                        more: false,
                    }
                };
                let next_seq = entries
                    .last()
                    .map_or(w.log.head().seq + 1, |e| seq_of(e) + 1);
                writer.append_reply(&mut w.log, reply, &now, KB_SIGNED_AT + next_seq)
            }
            other => panic!("{}: a relay reply while {other:?}", self.report.name),
        };
        w.step = Some(step);
        self.drive(&name);
        self.report.pass();
    }

    fn assert_client(&mut self, spec: &Value) {
        if let Some(name) = spec.get("by").and_then(Value::as_str) {
            let w = &self.writers[name];
            let writer = w.writer.as_ref().unwrap();
            for (key, want) in spec.as_object().unwrap() {
                match key.as_str() {
                    "by" => {}
                    "discarded" => {
                        let got: Vec<String> = writer
                            .discarded()
                            .iter()
                            .map(|d| match d {
                                Discarded::Envelope { blob_version, .. } => {
                                    w.uploads[blob_version].clone()
                                }
                                Discarded::Entry { entry_hash } => self
                                    .v
                                    .label_of(entry_hash)
                                    .map(str::to_owned)
                                    .unwrap_or_else(|| entry_hash.to_hex()),
                            })
                            .collect();
                        assert_eq!(got, labels(want), "{}: discarded", self.report.name);
                    }
                    "k_backup_committed" => {
                        assert_eq!(BackupWriter::committed(&w.log), want.as_u64().unwrap())
                    }
                    "backup_done" => assert_eq!(
                        matches!(w.step, Some(Step::Done { .. })),
                        want.as_bool().unwrap()
                    ),
                    "backup_error" => {
                        assert_eq!(want, "relay_misbehaviour");
                        assert!(matches!(
                            w.step,
                            Some(Step::Failed(BackupError::RelayMisbehaviour { .. }))
                        ));
                    }
                    "may_use_k" => assert_eq!(
                        BackupWriter::may_use_k(&w.log, &writer.job().kids[0]),
                        want.as_bool().unwrap()
                    ),
                    "log_head_seq" => assert_eq!(w.log.head().seq, want.as_u64().unwrap()),
                    other => panic!("{}: unknown assert_client {other}", self.report.name),
                }
            }
        } else {
            let last = self.last_restore.as_ref().expect("a restore ran");
            for (key, want) in spec.as_object().unwrap() {
                match key.as_str() {
                    "k_stored" => assert_eq!(last.is_ok(), want.as_bool().unwrap()),
                    "log_head" => {
                        assert!(want.is_null());
                        assert!(last.is_err(), "no log stored as current");
                    }
                    "may_rotate_k" | "may_seal_backup" => {
                        let flow = self.last_flow.as_ref().expect("a restore flow ran");
                        let got = if key == "may_rotate_k" {
                            flow.may_rotate_k("dev-newmac")
                        } else {
                            flow.may_seal_backup("dev-newmac")
                        };
                        assert_eq!(got, want.as_bool().unwrap(), "{key}");
                        assert_eq!(flow.k_stored(), last.is_ok());
                    }
                    "user_notice" => {
                        assert_eq!(want, "waiting_for_host");
                        let flow = self.last_flow.as_ref().expect("a restore flow ran");
                        assert!(matches!(
                            flow.user_notice(),
                            Some(UserNotice::WaitingForHost { hosts }) if hosts == ["host-a"]
                        ));
                    }
                    "refetch" => assert_eq!(
                        matches!(last, Err(Some(e)) if e.refetch()),
                        want.as_bool().unwrap()
                    ),
                    other => panic!("{}: unknown assert_client {other}", self.report.name),
                }
            }
        }
        self.report.pass();
    }

    fn restore(&mut self, step: &Value) {
        let spec = &step["restore"];
        let kit_name = spec["kit"].as_str().unwrap();
        let entry = &self.book.keys[kit_name];
        let r = unhex32(entry["R_hex"].as_str().unwrap());
        let tag = hex16(entry["kit_tag_hex"].as_str().unwrap());
        let mut account = ACCOUNT.to_owned();
        let mut genesis = genesis_hash();
        if let Some(tamper) = step.get("tamper") {
            let tamper = resolve(tamper, self.v, &self.named);
            for (path, value) in tamper.as_object().unwrap() {
                match path.as_str() {
                    "kit.account_id" => account = value.as_str().unwrap().to_owned(),
                    "kit.genesis_hash" => {
                        genesis = Hash32::from_hex(value.as_str().unwrap()).unwrap()
                    }
                    other => panic!("unknown tamper {other}"),
                }
            }
        }
        let outcome = match RestoreFlow::read(&r, &account, genesis, &tag) {
            Err(e) => {
                assert_eq!(step["result"], "refused");
                assert_eq!(e.code(), step["detail"].as_str().unwrap());
                assert_eq!(step["published"], false);
                self.last_restore = Some(Err(None));
                self.last_flow = None;
                self.report.pass();
                return;
            }
            Ok(mut flow) => {
                let refs = labels(&spec["relay_log"]);
                let refs: Vec<&str> = refs.iter().map(String::as_str).collect();
                let blob = resolve(&spec["relay_blob"], self.v, &self.named);
                let blob = KBackupEnvelope::from_strict(&strict(&blob)).unwrap().jcs();
                // Each host answers the device's init with an accept signed
                // by the host key the served chain records for it (the real
                // host-a, or the substitute chain's own host).
                let served = self.v.entries(&refs);
                let host_key = |host: &str| {
                    let record = served
                        .iter()
                        .rev()
                        .find_map(|e| match &e.action {
                            atem_client::membership::Action::AddHost { host: h }
                                if h.host_id == host =>
                            {
                                Some(h.host_key.clone())
                            }
                            _ => None,
                        })
                        .unwrap();
                    ["host-a/host_key", "host-evil/host_key"]
                        .into_iter()
                        .find(|id| self.book.public(id) == record)
                        .map(atem_client::KeyId::new)
                        .unwrap()
                };
                let heads: Vec<HostAccept> = spec["host_heads"]
                    .as_object()
                    .unwrap()
                    .iter()
                    .map(|(host, label)| {
                        signed_accept(
                            &self.book.provider,
                            &host_key(host),
                            served[0].hash(),
                            host,
                            self.v.head(label.as_str().unwrap()),
                        )
                    })
                    .collect();
                let result = flow
                    .attempt(
                        &self.v.entries(&refs),
                        blob.as_bytes(),
                        &heads,
                        &self.clock.now,
                    )
                    .map(|r| r.keys.iter().map(|k| k.kid.clone()).collect::<Vec<_>>());
                (flow, result)
            }
        };
        let (mut flow, result) = outcome;
        match result {
            Err(error) => {
                let want = step["result"].as_str().unwrap();
                assert_eq!(
                    want,
                    if error.is_withheld() {
                        "withheld"
                    } else {
                        "refused"
                    },
                    "{}: {error:?}",
                    self.report.name
                );
                assert_eq!(
                    error.code(),
                    step["detail"].as_str().unwrap(),
                    "{}",
                    self.report.name
                );
                assert_eq!(step["published"], false);
                self.last_restore = Some(Err(Some(error)));
            }
            Ok(kids) => {
                assert_eq!(step["result"], "restored", "{}", self.report.name);
                assert_eq!(step["freshness"], "host_confirmed");
                assert_eq!(flow.freshness(), Some(Freshness::HostConfirmed));
                assert!(flow.k_stored());
                assert_eq!(kids, labels(&step["kids"]));
                // Publish: a recovery_add for the new device on the
                // confirmed head, valid on the restored log.
                let member = Member {
                    device_id: "dev-newmac".into(),
                    auth_key: self.book.public("dev-newmac/auth"),
                    kind: MemberKind::Native {
                        enc_key: self.book.public("dev-newmac/enc"),
                        roles: [Role::Control, Role::Manage, Role::View].into(),
                    },
                };
                let (entry, expected) = flow.enroll(member, self.clock.now.wall_ms).unwrap();
                assert_eq!(expected, flow.restored().unwrap().head);
                let published = resolve(&step["published"], self.v, &self.named);
                assert_eq!(published["action"], "recovery_add");
                assert_eq!(entry.seq, published["seq"].as_u64().unwrap());
                assert_eq!(
                    entry.prev_hash.to_hex(),
                    published["prev_hash"].as_str().unwrap()
                );
                assert_eq!(
                    flow.restored().unwrap().log.check_next(&entry),
                    atem_client::membership::Check::Valid
                );
                // The relay stores it: published, pending the 24 h wait; the
                // device holds nothing yet, so it rotates and seals nothing.
                assert!(matches!(
                    flow.append_reply(
                        atem_client::membership::publish::AppendReply::Stored,
                        &self.clock.now
                    ),
                    Ok(Enrollment::Published { .. })
                ));
                assert!(!flow.may_rotate_k("dev-newmac"));
                self.last_restore = Some(Ok(kids));
            }
        }
        self.last_flow = Some(flow);
        self.report.pass();
    }
}

fn run(name: &str, v: &Vectors, book: &Book) -> Report {
    let file = load(name);
    assert_eq!(file["name"], name, "named after its file");
    assert_eq!(file["requires"], "r9");
    assert_eq!(file["kind"], "scenario");
    if let Some(log) = file.get("log") {
        assert_eq!(log, "r9-vectors-membership-log");
    }
    let steps = file["steps"].as_array().unwrap();
    match file["side"].as_str().unwrap() {
        "host" | "relay" => {
            let mut side = HostSide::new(name, v, book);
            side.setup(&file["setup"]);
            for step in steps {
                side.step(step);
            }
            side.report
        }
        "client" => {
            let mut side = ClientSide::new(name, v, book);
            side.setup(&file["setup"]);
            for step in steps {
                side.step(step);
            }
            side.report
        }
        other => panic!("{name}: side {other}"),
    }
}

#[test]
fn membership_scenarios() {
    let v = Vectors::load();
    let book = Book::load();
    let names = scenario_files();
    assert_eq!(
        names.len(),
        40,
        "chain, recovery and service-expiry scenarios"
    );
    let mut total = (0, 0);
    let mut by_owner: BTreeMap<&str, usize> = BTreeMap::new();
    for name in &names {
        let report = run(name, &v, &book);
        eprintln!(
            "{name}: {} checked, {} pending",
            report.passed,
            report.pending.len()
        );
        for (what, owner) in &report.pending {
            eprintln!("  PENDING {what}: {owner}");
            *by_owner.entry(owner).or_default() += 1;
        }
        assert!(report.passed > 0 || !report.pending.is_empty(), "{name}");
        total.0 += report.passed;
        total.1 += report.pending.len();
    }
    eprintln!(
        "total: {} checked, {} pending {by_owner:?}",
        total.0, total.1
    );
}
