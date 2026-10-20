//! Host runner of the r9 membership scenarios (`designs/protocol/fixtures/
//! r9-chain-*`, `r9-recovery-*` host side, `r9-service-expiry-*`) against
//! the real device-list store on a temp profile (real files and fsyncs, the
//! store's injected faults) and the real session host over a `FileJournal`
//! (`fake_runtime`: the r8 harness's fake PTY and dispatcher), so the §H
//! fences, receipts, leases and the write boundary are the host's own.
//!
//! What this runner checks (Task 6): the carriage record, intent, commit,
//! freeze and fault files; fail-closed fences on every write step; restart
//! replay and held; reconciliation; the host clock across restarts; and the
//! membership side of every reply. The `atem-ch1` handshake and the wire
//! form of `welcome` (revision, client kind, permissions) and of events to
//! other attachments (`membership_head`) are Task 7's: a client "connects"
//! here by carrying its entries and being judged by
//! `MembershipHost::hello`; admitted, it gets an r8 attachment with its
//! principal. Those items are listed pending with their owner; an unknown
//! step or assert key fails the run.
use super::store::{DlFile, Injected, Step};
use super::tests::{Rig, Vectors, clock, fixtures_dir, pinned, vectors};
use super::*;
use crate::session_protocol::fake_runtime::FakeRuntime;
use crate::session_protocol::file_journal::FileJournal;
use crate::session_protocol::fixtures::{HostEvent, HostUnderTest};
use crate::session_protocol::host::HostConfig;
use crate::session_protocol::wire::Permission;
use atem_client::membership::{PairingRefusal, Stop};
use base64::Engine as _;
use std::collections::{BTreeMap, BTreeSet};

const T7: &str =
    "Task 7 (atem-ch1 handshake, welcome revision/client_kind/permissions, events to attachments)";
const CRATE: &str = "atem-client scenario runner (keys, relay and client side)";
const AUTH_MS: u64 = 24 * 60 * 60 * 1000;

struct HostRt {
    rig: Rig,
    rt: FakeRuntime<FileJournal>,
    m: Option<MembershipHost>,
    now: HostNow,
    epoch: u64,
    /// Clients with a live attachment.
    attached: BTreeSet<String>,
}

struct Runner {
    name: String,
    v: &'static Vectors,
    hosts: BTreeMap<String, HostRt>,
    current: String,
    /// Fixture client name → principal.
    clients: BTreeMap<String, String>,
    /// Messages each client got, in order (flattened fields).
    inbox: BTreeMap<String, Vec<Value>>,
    passed: usize,
    pending: Vec<(String, &'static str)>,
    crash: Option<(String, u64)>,
    gens: u64,
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

/// `a.b` paths in a JSON object.
fn get_path<'a>(v: &'a Value, path: &str) -> Option<&'a Value> {
    if let Some(found) = v.get(path) {
        return Some(found);
    }
    path.split('.').try_fold(v, |node, part| node.get(part))
}

fn resolve(v: &Vectors, value: &Value) -> Value {
    match value {
        Value::String(s) => match s.strip_prefix("${hash:").and_then(|t| t.strip_suffix('}')) {
            Some(label) => json!(v.hash(label).to_hex()),
            None => value.clone(),
        },
        Value::Array(items) => Value::Array(items.iter().map(|i| resolve(v, i)).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, x)| (k.clone(), resolve(v, x)))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn pending_json(m: &MembershipHost, now: &HostNow) -> Value {
    Value::Array(
        m.membership()
            .pending_recovery(now)
            .into_iter()
            .map(|p| {
                json!({"entry_hash": p.entry_hash.to_hex(), "seq": p.seq, "action": p.action,
                       "subject": p.subject, "effective_at": p.effective_at})
            })
            .collect(),
    )
}

/// The membership side of a reply (as the crate runner renders it).
fn admission_fields(adm: &Admission, m: &MembershipHost, now: &HostNow) -> Value {
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
            json!({"op": "welcome", "principal": principal_of(&state.member),
                "head.seq": head.seq, "head.hash": head.hash.to_hex(),
                "pending_recovery": pending_json(m, now)})
        }
    }
}

fn fence_reply(reason: FenceReason) -> Value {
    match reason {
        FenceReason::Removed => json!({"op": "error", "code": "unauthorized", "detail": "removed"}),
        FenceReason::Frozen => json!({"op": "error", "code": "account_frozen"}),
        FenceReason::NotRecorded => {
            json!({"op": "error", "code": "busy", "detail": DETAIL_NOT_RECORDED})
        }
        FenceReason::Revoked | FenceReason::HostRemoved => {
            json!({"op": "error", "code": "unauthorized", "detail": "control revoked"})
        }
    }
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
            .find(|(_, p)| p.as_str() == principal)
            .map(|(n, _)| n.clone())
    }

    fn setup(&mut self, file: &Value) {
        let setup = &file["setup"];
        let pinned_labels = labels(&setup["pinned"]);
        for client in setup["clients"].as_array().unwrap() {
            self.clients.insert(
                client["name"].as_str().unwrap().to_owned(),
                client["principal"].as_str().unwrap().to_owned(),
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
        for (name, spec) in specs {
            let now = clock(spec["wall_clock_ms"].as_u64().unwrap(), 1_000, "boot-1");
            let rig = Rig::new();
            let refs: Vec<&str> = pinned_labels.iter().map(String::as_str).collect();
            let m = pinned(&refs, &now);
            let pin = HostPin {
                host_id: spec["host_id"].as_str().unwrap().to_owned(),
                host_trust_gen: spec["host_trust_gen"].as_u64().unwrap(),
            };
            MembershipHost::pin(&rig.pairing, &rig.journal, &pin, &m).unwrap();
            let mut clients = Vec::new();
            let mut attached = BTreeSet::new();
            for (c, principal) in &self.clients {
                if !connected.contains(c) && !leases.contains_key(c) {
                    continue;
                }
                attached.insert(c.clone());
                clients.push(
                    json!({"name": principal, "attachment_gen": self.uuid_static(c),
                    "permissions": ["view", "control"], "client_kind": "native",
                    "holds_lease_epoch": leases.get(c)}),
                );
            }
            let sessions: Vec<Value> = setup
                .get("sessions")
                .and_then(Value::as_array)
                .map(|list| {
                    list.iter()
                        .map(|s| {
                            json!({"session_id": s["session_id"], "process_gen": s["process_gen"],
                                        "chat": s["chat"]})
                        })
                        .collect()
                })
                .unwrap_or_default();
            let r8 = json!({
                "host": {"account_id": spec["account_id"], "atem_device_id": spec["atem_device_id"],
                         "host_trust_gen": spec["host_trust_gen"], "runtime_gen": spec["runtime_gen"],
                         "runtime_epoch": spec["runtime_epoch"]},
                "sessions": sessions,
                "clients": clients,
            });
            let journal = FileJournal::open(&rig.journal).unwrap();
            let mut rt = FakeRuntime::from_json_with(r8, HostConfig::default(), journal);
            rt.host.hold_dispatch(hold_dispatch);
            let epoch = spec["runtime_epoch"].as_u64().unwrap();
            let mut fences = HostFences::new(&mut rt.host);
            let (m, fenced) =
                MembershipHost::open(&rig.pairing, &rig.journal, epoch, &now, &mut fences)
                    .unwrap()
                    .unwrap();
            assert!(fenced.is_empty());
            let effects = fences.effects;
            rt.apply(effects);
            self.hosts.insert(
                name,
                HostRt {
                    rig,
                    rt,
                    m: Some(m),
                    now,
                    epoch,
                    attached,
                },
            );
        }
        if setup.get("sessions").is_some() || !leases.is_empty() || !connected.is_empty() {
            self.pass();
        }
    }

    fn uuid_static(&self, client: &str) -> String {
        let n: u64 = client.bytes().map(u64::from).sum();
        format!("cccccccc-0000-4000-8000-{n:012}")
    }

    /// Moves what the session host sent each client to its inbox.
    fn drain(&mut self) {
        let clients = self.clients.clone();
        let current = self.current.clone();
        for (name, principal) in clients {
            let host = self.hosts.get_mut(&current).unwrap();
            for msg in host.rt.take(&principal) {
                let data = msg.get("data").cloned().unwrap_or(msg);
                self.inbox.entry(name.clone()).or_default().push(data);
            }
        }
    }

    fn deliver(&mut self, client: &str, fields: Value) {
        self.inbox
            .entry(client.to_owned())
            .or_default()
            .push(fields);
    }

    /// Fenced principals with a live attachment hear why.
    fn tell_fenced(&mut self, fences: &[Fence]) {
        for fence in fences {
            let Some(name) = self.name_of(&fence.principal) else {
                continue;
            };
            if self.host().attached.remove(&name) {
                self.deliver(&name, fence_reply(fence.reason));
            }
        }
    }

    fn carry_values(&self, labels: &[String]) -> Vec<StrictValue> {
        labels.iter().map(|l| self.v.strict(l)).collect()
    }

    /// The device list applies a carriage through the session host's fences.
    fn apply(&mut self, carried: &[StrictValue]) -> CarriageResult {
        let host = self.host();
        let mut fences = HostFences::new(&mut host.rt.host);
        let m = host.m.as_mut().expect("paired");
        let result = m.apply_carriage(carried, &host.now, &mut fences);
        let effects = fences.effects;
        host.rt.apply(effects);
        result
    }

    fn crashed(&mut self) {
        let (gen_, epoch) = self.crash.take().expect("a crash was armed");
        self.restart(&gen_, epoch, false, None);
        self.pass();
    }

    fn connect(&mut self, step: &Value) {
        let client = step["connect"]
            .as_str()
            .or_else(|| step["reconnect"].as_str())
            .unwrap()
            .to_owned();
        if let Some(host) = step.get("host") {
            self.current = host.as_str().unwrap().to_owned();
        }
        for key in ["hello", "grant", "transport"] {
            if step.get(key).is_some() {
                self.later(format!("connect {key}"), T7);
            }
        }
        let principal = self.clients[&client].clone();
        let carry = step.get("carry").map(labels).unwrap_or_default();
        let carried = self.carry_values(&carry);
        let more = step.get("more").and_then(Value::as_bool).unwrap_or(false);
        let client_head = step
            .get("client_head")
            .and_then(Value::as_str)
            .map(|l| self.v.head(l));
        // init (clear, before any key work).
        match self.host().m.as_ref().unwrap().init() {
            Init::Frozen => {
                self.deliver(
                    &client,
                    json!({"op": "channel_error", "code": "account_frozen", "at": "init"}),
                );
                self.pass();
                return;
            }
            Init::Busy => {
                self.deliver(
                    &client,
                    json!({"op": "channel_error", "code": "busy", "at": "init"}),
                );
                self.pass();
                return;
            }
            Init::Accept => {}
        }
        let result = (!carried.is_empty()).then(|| self.apply(&carried));
        if result
            .as_ref()
            .is_some_and(|r| r.carried == Carried::Crashed)
        {
            return self.crashed();
        }
        let fences = result
            .as_ref()
            .map(|r| r.fences.clone())
            .unwrap_or_default();
        self.tell_fenced(&fences);
        let host = self.host();
        let now = host.now.clone();
        let m = host.m.as_mut().unwrap();
        // The client reports the host's head unless the fixture says
        // otherwise (it verified what it carried).
        let reported = client_head.or(Some(m.head()));
        let verdict = m.hello(device_of(&principal), reported, result.as_ref(), more, &now);
        let reply = match &verdict {
            Hello::Admit(adm) => admission_fields(adm, m, &now),
            Hello::NotReconciled => {
                json!({"op": "error", "code": "busy", "detail": DETAIL_NOT_RECONCILED})
            }
            Hello::NotRecorded => {
                json!({"op": "error", "code": "busy", "detail": DETAIL_NOT_RECORDED})
            }
            Hello::Frozen => json!({"op": "error", "code": "account_frozen"}),
        };
        if let Hello::Admit(Admission::Member { .. }) = verdict {
            let (first, second) = (self.uuid(), self.uuid());
            let host = self.host();
            // An r8 attachment with the principal (Task 7's channel admits it).
            host.rt.connect_only(
                &principal,
                &first,
                vec![Permission::View, Permission::Control],
                AUTH_MS,
            );
            host.rt.attach(&principal, &second).unwrap();
            host.attached.insert(client.clone());
        }
        self.drain();
        self.deliver(&client, reply);
        self.pass();
    }

    fn send_membership(&mut self, step: &Value) {
        let client = step["send_membership"].as_str().unwrap().to_owned();
        let carried = self.carry_values(&labels(&step["entries"]));
        let result = self.apply(&carried);
        if result.carried == Carried::Crashed {
            return self.crashed();
        }
        self.tell_fenced(&result.fences.clone());
        let host = self.host();
        let now = host.now.clone();
        let m = host.m.as_ref().unwrap();
        let reply = match result.carried {
            Carried::NotRecorded | Carried::Refused => {
                json!({"op": "error", "code": "busy", "detail": DETAIL_NOT_RECORDED})
            }
            Carried::Frozen => json!({"op": "error", "code": "account_frozen"}),
            _ => match result.evaluation.as_ref().and_then(|e| e.stop.clone()) {
                Some(Stop::Invalid { .. } | Stop::NeedBefore { .. }) => {
                    let adm = result
                        .evaluation
                        .as_ref()
                        .unwrap()
                        .admission("", false, &now);
                    admission_fields(&adm, m, &now)
                }
                _ => {
                    let head = m.head();
                    json!({"op": "membership_head", "head.seq": head.seq,
                           "head.hash": head.hash.to_hex(), "pending_recovery": pending_json(m, &now)})
                }
            },
        };
        self.drain();
        self.deliver(&client, reply);
        self.pass();
    }

    fn expect(&mut self, client: &str, want: &Value) {
        let want = resolve(self.v, want);
        self.drain();
        let op = want["op"].as_str().unwrap();
        let inbox = self.inbox.entry(client.to_owned()).or_default();
        let found = inbox.iter().position(|m| {
            m.get("op").and_then(Value::as_str) == Some(op)
                && ["code", "detail", "reason", "state"]
                    .iter()
                    .all(|k| want.get(*k).is_none_or(|w| get_path(m, k) == Some(w)))
        });
        let Some(i) = found else {
            if op == "membership_head" || op == "error" && want["code"] == "membership_invalid" {
                self.later(
                    format!("expect {client} {op}: an event to an attachment"),
                    T7,
                );
                return;
            }
            panic!(
                "{}: {client} got no {want} (inbox {:?})",
                self.name, self.inbox[client]
            );
        };
        let got = self.inbox.get_mut(client).unwrap().remove(i);
        let mut later = Vec::new();
        for (key, value) in want.as_object().unwrap() {
            match get_path(&got, key) {
                Some(g) => assert_eq!(g, value, "{}: {client} {key} in {got}", self.name),
                None if ["revision", "client_kind", "permissions"].contains(&key.as_str()) => {
                    later.push(key.clone())
                }
                None => panic!("{}: {client}: {key} not produced in {got}", self.name),
            }
        }
        self.pass();
        if !later.is_empty() {
            self.later(format!("welcome {}", later.join(", ")), T7);
        }
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
        host.epoch = epoch;
        host.attached.clear();
        let mut fences = HostFences::new(&mut host.rt.host);
        let (m, _) = host
            .rig
            .open(epoch, &host.now, &mut fences)
            .unwrap_or_else(|e| panic!("restart: {e}"));
        let effects = fences.effects;
        host.rt.apply(effects);
        host.m = Some(m);
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
            let m = host.m.as_mut().unwrap();
            m.advance(&host.now, &mut fences);
            let effects = fences.effects;
            host.rt.apply(effects);
        }
    }

    fn binding(&mut self, client: &str, sid: &str, lease: bool) -> Value {
        let principal = self.clients[client].clone();
        let host = self.host();
        let target = serde_json::to_value(host.rt.target(sid)).unwrap();
        let mut b = json!({"target": target, "attachment_gen": host.rt.attachment(&principal)});
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
        let v = self.v;
        let name = self.name.clone();
        let clients = self.clients.clone();
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
                | "pty_writes_dropped" | "dispatches" => ok(rt.counter(key).unwrap()),
                "lease_holder" => {
                    let got = rt.counter("lease_holder").unwrap();
                    let got = match got.as_str() {
                        Some(p) => json!(clients.iter().find(|(_, x)| x.as_str() == p).unwrap().0),
                        None => Value::Null,
                    };
                    ok(got)
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
                    assert_eq!(
                        Value::Array(got),
                        resolve(v, want),
                        "{name}: frozen_genesis"
                    );
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
                "recovery_key" | "k_backup" | "carried_ever" | "channel_id" => {
                    later.push((key.clone(), CRATE))
                }
                other => panic!("{name}: unknown assert key {other}"),
            }
        }
        self.pass();
        for (k, owner) in later {
            self.later(format!("assert {k}"), owner);
        }
    }

    fn step(&mut self, step: &Value) {
        let object = step.as_object().unwrap();
        let kinds = [
            "connect",
            "reconnect",
            "send_membership",
            "expect",
            "expect_channel_error",
            "expect_channel_or_session_error",
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
            "expect_none",
            "open_approval",
        ];
        let kind = kinds
            .into_iter()
            .find(|k| object.contains_key(*k))
            .unwrap_or_else(|| panic!("{}: unknown step {step}", self.name));
        match kind {
            "connect" | "reconnect" => self.connect(step),
            "send_membership" => self.send_membership(step),
            "expect" => {
                let client = step["expect"].as_str().unwrap().to_owned();
                self.expect(&client, &step["match"]);
            }
            "expect_channel_error" => {
                let client = step["expect_channel_error"].as_str().unwrap().to_owned();
                let want = json!({"op": "channel_error", "code": step["code"], "at": step["at"]});
                self.expect(&client, &want);
            }
            "expect_channel_or_session_error" => {
                let client = step["expect_channel_or_session_error"]
                    .as_str()
                    .unwrap()
                    .to_owned();
                let mut want = json!({"op": "error", "code": step["code"]});
                if let Some(d) = step.get("detail") {
                    want["detail"] = d.clone();
                }
                self.expect(&client, &want);
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
            "expect_local_status" => {
                let want = step["expect_local_status"]["recovery_pending"]
                    .as_bool()
                    .unwrap();
                let host = self.host();
                let pending = !host
                    .m
                    .as_ref()
                    .unwrap()
                    .membership()
                    .pending_recovery(&host.now)
                    .is_empty();
                assert_eq!(pending, want, "{}: recovery pending", self.name);
                self.pass();
                self.later(
                    "expect_local_status: the status row and atem status text",
                    T7,
                );
            }
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
                let principal = self.clients[&client].clone();
                let mut json = step["json"].clone();
                self.substitute(&mut json);
                if json["type"] == "terminal" && json["data"]["op"] == "input" {
                    // Input needs the client's stream: the fixture names one,
                    // the harness subscribes first and uses the stream the
                    // host opened (r8 terminal-v1).
                    let sid = json["data"]["terminal_id"].as_str().unwrap().to_owned();
                    let read = self.binding(&client, &sid, false);
                    let subscribe = json!({"type": "terminal", "data": {"v": 1, "op": "subscribe",
                        "terminal_id": sid, "generation": json["data"]["generation"], "binding": read}});
                    let host = self.host();
                    host.rt.send(&principal, &subscribe);
                    let attached = host
                        .rt
                        .take(&principal)
                        .into_iter()
                        .find(|m| m["data"]["op"] == "attached")
                        .expect("subscribed");
                    json["data"]["stream_id"] = attached["data"]["stream_id"].clone();
                }
                self.host().rt.send(&principal, &json);
                self.drain();
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
                let host = self.host();
                let now = host.rt.now();
                host.rt.event(&event, now).unwrap();
                self.drain();
                self.pass();
            }
            "local_input" => {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(step["bytes"].as_str().unwrap())
                    .unwrap();
                let event = HostEvent::LocalInput {
                    session_id: step["local_input"].as_str().unwrap().to_owned(),
                    bytes,
                };
                let host = self.host();
                let now = host.rt.now();
                host.rt.event(&event, now).unwrap();
                self.drain();
                self.pass();
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
            other => self.later(other.to_owned(), T7),
        }
    }
}

fn scenario_names() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(fixtures_dir())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| {
            n.ends_with(".json")
                && (n.starts_with("r9-chain-")
                    || n.starts_with("r9-recovery-")
                    || n == "r9-service-expiry-over-90-days-is-invalid.json")
        })
        .map(|n| n.trim_end_matches(".json").to_owned())
        .collect();
    names.sort();
    names
}

fn run(name: &str) -> Option<(usize, Vec<(String, &'static str)>)> {
    let bytes = std::fs::read(fixtures_dir().join(format!("{name}.json"))).unwrap();
    let file: Value = serde_json::from_slice(&bytes).unwrap();
    if file["side"] != "host" {
        return None;
    }
    let mut runner = Runner {
        name: name.to_owned(),
        v: vectors(),
        hosts: BTreeMap::new(),
        current: String::new(),
        clients: BTreeMap::new(),
        inbox: BTreeMap::new(),
        passed: 0,
        pending: Vec::new(),
        crash: None,
        gens: 0,
    };
    let (_tmp, _scope) = crate::test_profile::temp();
    runner.setup(&file);
    for step in file["steps"].as_array().unwrap() {
        runner.step(step);
    }
    Some((runner.passed, runner.pending))
}

/// Every host-side r9 membership scenario against the real store. Run with
/// `-- --nocapture` for the counts and the pending list.
#[test]
fn r9_membership_scenarios_on_the_real_store() {
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
    assert!(ran >= 30, "the host scenarios ran");
}

/// The nine fault and crash scenarios have no pending membership item: only
/// Task 7's wire items remain.
#[test]
fn the_fault_and_crash_scenarios_leave_nothing_to_task_6() {
    for name in [
        "r9-chain-crash-after-a-recorded-fault-stays-held",
        "r9-chain-crash-between-commit-and-fences-replays-them",
        "r9-chain-freeze-write-fault-stays-frozen-in-memory",
        "r9-chain-lost-carriage-record-restart-stays-held",
        "r9-chain-lost-freeze-restart-replays-the-freeze",
        "r9-chain-lost-intent-restart-replays-and-stays-held",
        "r9-chain-membership-write-fault-fences-in-memory-and-halts",
        "r9-chain-uncertain-rename-is-reconciled-at-restart",
        "r9-chain-uncertain-rename-lost-is-replayed-then-held",
        "r9-chain-removal-on-an-open-channel-fences-at-once",
        "r9-chain-valid-suffix-applies-before-admission",
        "r9-chain-relay-cas-failure-freezes-both-hosts",
    ] {
        let (passed, pending) = run(name).unwrap();
        assert!(passed > 0, "{name}");
        assert!(
            pending.iter().all(|(_, owner)| *owner == T7),
            "{name}: {pending:?}"
        );
    }
}
