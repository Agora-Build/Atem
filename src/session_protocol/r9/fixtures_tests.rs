//! The channel envelope fixtures (`designs/protocol/fixtures/r9-envelope-*`,
//! §R9.7a) run against the r9 engine in process: the real device list
//! pinned to the vectors' log, the real session host over a `FileJournal`,
//! and clients that are the shared core, routed by handle on one link.
use super::envelope;
use super::tests::{Client, Rig};
use super::*;
use crate::session_protocol::membership::r9log::{TestLog, auth};
use atem_client::connect::{Event as CEvent, Identity};
use atem_client::encoding::Hash32;
use atem_client::membership::{Entry, Membership};
use serde_json::json;

fn fixtures_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("designs/protocol/fixtures")
}

fn load(name: &str) -> Value {
    serde_json::from_slice(&std::fs::read(fixtures_dir().join(format!("{name}.json"))).unwrap())
        .unwrap()
}

fn unhex32(text: &str) -> [u8; 32] {
    Hash32::from_hex(text).unwrap().0
}

/// The vectors' log (the `pinned` labels) with every client key, and
/// host-a's seed.
fn vector_log(pinned: &[Value]) -> (TestLog, [u8; 32]) {
    let keys_file = load("r9-vectors-keys");
    let keys = &keys_file["keys"];
    let mut book = SoftwareKeys::new();
    for (name, k) in keys.as_object().unwrap() {
        let Some(auth_key) = k.get("auth") else {
            continue;
        };
        let secret = unhex32(auth_key["secret_hex"].as_str().unwrap());
        match auth_key["alg"].as_str() {
            Some("p256") => book.insert_p256(auth(name), &secret).unwrap(),
            _ => book.insert_ed25519(auth(name), &secret),
        }
    }
    let log_file = load("r9-vectors-membership-log");
    let by_label = |label: &str| -> Value {
        for list in ["log", "others"] {
            for v in log_file[list].as_array().unwrap() {
                if v["label"] == label {
                    return v["entry"].clone();
                }
            }
        }
        panic!("no vector {label}")
    };
    let entries: Vec<Entry> = pinned
        .iter()
        .map(|l| {
            let wire = by_label(l.as_str().unwrap());
            Entry::from_strict(
                &StrictValue::parse(wire.to_string().as_bytes(), usize::MAX).unwrap(),
            )
            .unwrap()
        })
        .collect();
    let now = membership::r9log::host_now();
    let account = entries[0].account_id.clone();
    let genesis = entries[0].hash();
    let log = Membership::verify_chain(&account, &genesis, &entries, &now)
        .unwrap()
        .membership;
    let seed = unhex32(keys["host-a"]["host_key"]["secret_hex"].as_str().unwrap());
    (
        TestLog {
            keys: book,
            account,
            entries,
            log,
            now,
        },
        seed,
    )
}

fn identity(principal: &str) -> Identity {
    match principal.split_once(':') {
        Some(("member", d)) => Identity::native(d, auth(d)),
        Some(("service", d)) => Identity::service(d, auth(d)),
        _ => panic!("no identity for {principal}"),
    }
}

/// `actual` matches every dotted path of `expected` (`x.#` is a length).
fn matches(actual: &Value, expected: &Value) -> Result<(), String> {
    for (path, want) in expected.as_object().unwrap() {
        let mut at = actual;
        let mut got = None;
        for part in path.split('.') {
            if part == "#" {
                got = Some(json!(at.as_array().map_or(0, Vec::len)));
                break;
            }
            at = match part.parse::<usize>() {
                Ok(i) => at.get(i).unwrap_or(&Value::Null),
                Err(_) => at.get(part).unwrap_or(&Value::Null),
            };
        }
        let got = got.unwrap_or_else(|| at.clone());
        if &got != want {
            return Err(format!("{path}: {got} != {want} in {actual}"));
        }
    }
    Ok(())
}

struct Run {
    rig: Rig,
    principals: BTreeMap<String, String>,
    /// client → its current channel handle.
    handle: BTreeMap<String, String>,
    /// A client just connected: its next expectation is the welcome.
    welcome_due: HashSet<String>,
    closes_seen: usize,
    checked: usize,
}

impl Run {
    fn new(file: &Value) -> Run {
        let setup = &file["setup"];
        let (log, seed) = vector_log(setup["pinned"].as_array().unwrap());
        let host = &setup["host"];
        let dir = tempfile::tempdir().unwrap();
        let mut rig = Rig::build(
            dir,
            log,
            host["host_id"].as_str().unwrap(),
            host["host_trust_gen"].as_u64().unwrap(),
            seed,
            // The recorded launch project isn't part of the r8 setup (no
            // project is recorded in the runtime yet: `NoProjects`).
            json!(
                setup["sessions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|s| {
                        let mut s = s.clone();
                        s.as_object_mut().unwrap().remove("project");
                        s
                    })
                    .collect::<Vec<_>>()
            ),
        );
        rig.engine = R9Host::new(Limits::default(), None);
        let principals = setup["clients"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| {
                (
                    c["name"].as_str().unwrap().to_string(),
                    c["principal"].as_str().unwrap().to_string(),
                )
            })
            .collect();
        Run {
            rig,
            principals,
            handle: BTreeMap::new(),
            welcome_due: HashSet::new(),
            closes_seen: 0,
            checked: 0,
        }
    }

    fn h(&self, client: &str) -> String {
        self.handle[client].clone()
    }

    fn new_closes(&mut self) -> Vec<(String, Option<String>)> {
        let out = self.rig.closes[self.closes_seen..].to_vec();
        self.closes_seen = self.rig.closes.len();
        out
    }

    /// `${binding:c:sid}` in a message.
    fn substitute(&mut self, client: &str, value: &Value) -> Value {
        match value {
            Value::String(s) if s.starts_with("${binding:") => {
                let inner = s.trim_start_matches("${binding:").trim_end_matches('}');
                let (_, sid) = inner.split_once(':').unwrap();
                let h = self.h(client);
                self.rig.binding(&h, sid)
            }
            Value::Object(map) => Value::Object(
                map.iter()
                    .map(|(k, v)| (k.clone(), self.substitute(client, v)))
                    .collect(),
            ),
            other => other.clone(),
        }
    }

    fn step(&mut self, step: &Value) -> Result<(), String> {
        if step.get("link_up").is_some() {
            self.rig.link_up();
        } else if step.get("link_down").is_some() {
            self.rig.link_down();
        } else if let Some(c) = step.get("connect").and_then(Value::as_str) {
            let handle = step["channel"].as_str().unwrap().to_string();
            let transport = match step["transport"].as_str() {
                Some("direct") => envelope::Transport::Direct,
                _ => envelope::Transport::Relay,
            };
            let identity = identity(&self.principals[c]);
            self.rig.connect_via(&handle, identity, transport);
            self.handle.insert(c.to_string(), handle.clone());
            if let Some(code) = step.get("expect_init_refused").and_then(Value::as_str) {
                match self.rig.clients.get(&handle) {
                    Some(Client::Clear(got)) if got == code => {}
                    _ => return Err(format!("{c}: init not refused {code}")),
                }
            } else {
                self.welcome_due.insert(c.to_string());
            }
        } else if let Some(c) = step.get("expect").and_then(Value::as_str) {
            let h = self.h(c);
            let want = &step["match"];
            if self.welcome_due.remove(c) {
                let welcome = self.rig.attached(&h).welcome().to_json();
                let data = welcome.get("data").cloned().unwrap_or(welcome);
                return matches(&data, want);
            }
            let events = self.rig.events(&h);
            let datas: Vec<Value> = events
                .iter()
                .filter_map(|e| match e {
                    CEvent::Session(m) => Some(
                        atem_client::session::wire::to_value(
                            &atem_client::session::wire::Envelope::Session(m.clone()),
                        )["data"]
                            .clone(),
                    ),
                    _ => None,
                })
                .collect();
            if !datas.iter().any(|d| matches(d, want).is_ok()) {
                return Err(format!("{c}: nothing matches {want} in {datas:?}"));
            }
        } else if let Some(ms) = step.get("advance_ms").and_then(Value::as_u64) {
            self.rig.advance(ms);
        } else if let Some(a) = step.get("assert") {
            let status = self.rig.engine.status();
            if let Some(n) = a.get("channels").and_then(Value::as_u64)
                && status.channels as u64 != n
            {
                return Err(format!("channels {} != {n}", status.channels));
            }
            if let Some(n) = a.get("attachments").and_then(Value::as_u64)
                && (status.attachments as u64 != n
                    || self.rig.rt.host.welcomed_attachments() as u64 != n)
            {
                return Err(format!(
                    "attachments {} / {} != {n}",
                    status.attachments,
                    self.rig.rt.host.welcomed_attachments()
                ));
            }
            self.checked += 1;
        } else if let Some(h) = step.get("close_channel").and_then(Value::as_str) {
            let reason = step["reason"].as_str();
            self.rig.envelope_in(&envelope::close(h, reason));
        } else if let Some(e) = step.get("expect_no_envelope") {
            self.rig.pump();
            let closes = self.new_closes();
            let channel = e.get("channel").and_then(Value::as_str);
            if closes.iter().any(|(h, _)| channel.is_none_or(|c| c == h)) {
                return Err(format!("unexpected envelopes {closes:?}"));
            }
        } else if let Some(c) = step.get("send_record").and_then(Value::as_str) {
            let h = self.h(c);
            let mono = self.rig.now.host.mono_ms;
            let (_, mut frame) = self.rig.attached(&h).list(mono).unwrap();
            let n = frame.len();
            frame[n - 4] ^= 1;
            self.rig.send_frame_raw(&h, &frame);
        } else if let Some(e) = step.get("expect_envelope") {
            if step.get("after_unstall").is_some() {
                self.rig.stalled = false;
            }
            self.rig.pump();
            let want = &e["match"];
            let closes = self.new_closes();
            let found = closes.iter().any(|(h, r)| {
                matches(&json!({"event": "close", "channel": h, "reason": r}), want).is_ok()
            });
            if !found {
                return Err(format!("no envelope {want} in {closes:?}"));
            }
        } else if let Some(c) = step.get("send").and_then(Value::as_str) {
            let json = self.substitute(c, &step["json"]);
            let h = self.h(c);
            self.rig.send(&h, &json);
        } else if let Some(e) = step.get("envelope_in") {
            self.rig.envelope_in(&e.to_string());
        } else if let Some(c) = step.get("send_frame").and_then(Value::as_str) {
            let h = self.h(c);
            let n = step["frame_of_plaintext_bytes"].as_u64().unwrap() as usize;
            if step.get("unchecked").is_some() {
                // Past the sender's own bound: a record no sender makes.
                let ct = atem_client::encoding::b64u(&vec![7u8; n + 16]);
                let frame = json!({"ch": "atem-ch1", "op": "rec", "ct": ct}).to_string();
                self.rig.send_frame_raw(&h, frame.as_bytes());
            } else {
                let mut msg = json!({"type": "session", "data": {"v": 1, "op": "list",
                    "id": uuid::Uuid::new_v4().to_string(), "pad": ""}});
                let base = msg.to_string().len();
                msg["data"]["pad"] = json!("x".repeat(n - base));
                assert_eq!(msg.to_string().len(), n);
                let mono = self.rig.now.host.mono_ms;
                let frame = self.rig.attached(&h).send(&msg, mono).unwrap();
                if let Some(m) = step.get("expect_envelope_bytes").and_then(Value::as_u64) {
                    let outer = envelope::frame(&h, &frame);
                    if outer.len() as u64 != m {
                        return Err(format!("envelope {} != {m} bytes", outer.len()));
                    }
                }
                self.rig.send_frame_raw(&h, &frame);
                let events = self.rig.events(&h);
                if !events.iter().any(|e| matches!(e, CEvent::Session(_))) {
                    return Err(format!("no reply to the largest record: {events:?}"));
                }
            }
        } else if let Some(c) = step.get("expect_channel_open").and_then(Value::as_str) {
            let h = self.h(c);
            if !matches!(self.rig.clients.get(&h), Some(Client::Attached(..))) {
                return Err(format!("{c}'s channel closed"));
            }
        } else if let Some(e) = step.get("envelope_in_bytes") {
            let h = e["channel"].as_str().unwrap();
            let n = e["bytes"].as_u64().unwrap() as usize;
            let mut text = envelope::frame(
                h,
                br#"{"ch":"atem-ch1","op":"rec","ct":"AAAAAAAAAAAAAAAAAAAAAA"}"#,
            );
            let pad = n - text.len();
            text.insert_str(text.len() - 1, &" ".repeat(pad));
            assert_eq!(text.len(), n);
            self.rig.envelope_in(&text);
        } else if step.get("stall_link").is_some() {
            self.rig.stalled = true;
        } else if step.get("unstall_link").is_some() {
            self.rig.stalled = false;
            self.rig.pump();
        } else if let Some(c) = step.get("fill_queue").and_then(Value::as_str) {
            let h = self.h(c);
            let bytes = step["bytes"].as_u64().unwrap() as usize;
            let att = self
                .rig
                .engine
                .attachments()
                .into_iter()
                .find(|(_, p)| *p == self.principals[c])
                .map(|(a, _)| a)
                .unwrap();
            let mut sent = 0;
            while self.rig.engine.owns(&att)
                && self.rig.engine.backlog(&att) <= bytes
                && sent < 100_000
            {
                let mono = self.rig.now.host.mono_ms;
                let (_, frame) = self.rig.attached(&h).list(mono).unwrap();
                self.rig.send_frame_raw(&h, &frame);
                sent += 1;
            }
        } else {
            return Err(format!("unknown step {step}"));
        }
        Ok(())
    }
}

#[test]
fn the_envelope_fixtures_pass_on_the_engine() {
    let names = [
        "r9-envelope-several-channels",
        "r9-envelope-unknown-and-duplicate",
        "r9-envelope-link-loss",
        "r9-envelope-bounds",
    ];
    let mut total = 0;
    for name in names {
        let file = load(name);
        assert_eq!(file["name"], name);
        let mut run = Run::new(&file);
        for (i, step) in file["steps"].as_array().unwrap().iter().enumerate() {
            run.step(step)
                .unwrap_or_else(|e| panic!("{name} step {i} {step}: {e}"));
            total += 1;
        }
    }
    assert!(total > 50, "{total} steps");
}
