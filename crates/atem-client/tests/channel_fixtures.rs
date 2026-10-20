//! Runs the `atem-ch1` scenarios (`designs/protocol/fixtures/
//! r9-handshake-*` and the channel side of
//! `r9-hello-needs-revision-9-inside-the-channel`; `schema.md` "r9
//! fixtures") against the crate's initiator and responder, with the
//! vector's ephemerals (`r9-vectors-channel-handshake`) where a step drives
//! a handshake from it.
//!
//! Every step and expected field is checked or listed as pending with the
//! task that brings it (the hello's content, the welcome, attachments and
//! effects of the real host). An unknown step or field fails the run.
//! `-- --nocapture` prints the counts and the pending list.
mod support;

use std::collections::BTreeMap;

use atem_client::channel::record::Direction;
use atem_client::channel::responder::HostContext;
use atem_client::channel::transcript::{Schedule, th3, th4};
use atem_client::channel::wire::{self, Frame, Parsed};
use atem_client::channel::{
    Carriage, Channel, ChannelError, ClearCode, ClientProof, Failure, HeadRelation, HostAccept,
    Initiator, Principal, Responder,
};
use atem_client::encoding::{b64u, b64u_decode, hex};
use atem_client::membership::{Admission, Entry, Membership};
use atem_client::provider::sign;
use atem_client::{KeyId, SoftwareKeys};
use serde_json::{Value, json};
use support::*;

const T4: &str = "Task 4 (the r9 hello and welcome inside the channel: revision, proof, carriage)";
const T7: &str = "Task 7 (host admission and effects: welcome content, attachments, dispatches, PTY writes, session replies)";

const FILES: [&str; 5] = [
    "r9-handshake-success",
    "r9-handshake-tampered-transcript",
    "r9-handshake-replay",
    "r9-handshake-wrong-head",
    "r9-hello-needs-revision-9-inside-the-channel",
];

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn s<'a>(v: &'a Value, field: &str) -> &'a str {
    v[field]
        .as_str()
        .unwrap_or_else(|| panic!("{field} is not a string in {v}"))
}

/// `${vector:file:path}` and `${hash:L}`.
fn resolve(value: &Value, v: &Vectors) -> Value {
    match value {
        Value::String(text) => {
            if let Some(label) = text
                .strip_prefix("${hash:")
                .and_then(|t| t.strip_suffix('}'))
            {
                return Value::String(v.hash(label).to_hex());
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
        Value::Array(items) => Value::Array(items.iter().map(|i| resolve(i, v)).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, x)| (k.clone(), resolve(x, v)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Checks that `step` has only these keys (besides its kind).
fn keys(step: &Value, allowed: &[&str]) {
    for key in step.as_object().unwrap().keys() {
        assert!(
            allowed.contains(&key.as_str()),
            "unknown field {key} in {step}"
        );
    }
}

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

/// What the last handshake step left for the `expect_*` steps.
#[derive(Debug)]
enum Outcome {
    /// The host's clear refusal (`at` init or finish) and its reply.
    Clear {
        at: &'static str,
        error: ChannelError,
        reply: Option<Vec<u8>>,
    },
    /// The host's encrypted first-record refusal, opened with the keys the
    /// hello as sent gives: the session error's code.
    InChannel { code: String },
    /// The client refused; how many frames it sent after `accept`.
    ClientRefused {
        error: ChannelError,
        sent_after_accept: usize,
    },
    /// The client sent its `finish`; the carriage its hello carried.
    ClientSent { carriage: Carriage },
}

struct Fixture<'a> {
    v: &'a Vectors,
    book: &'a Book,
    vec: Value,
    report: Report,
    host_log: Membership,
    host_keys: SoftwareKeys,
    host_key_id: KeyId,
    /// The host's open channel per client (and the client's end).
    channels: BTreeMap<String, (Channel, Channel)>,
    last_finish: Option<Vec<u8>>,
    last_init: Option<Vec<u8>>,
    outcome: Option<Outcome>,
    clock: Clock,
}

impl<'a> Fixture<'a> {
    fn new(file: &Value, v: &'a Vectors, book: &'a Book) -> Self {
        let setup = &file["setup"];
        let host = &setup["host"];
        assert_eq!(host["host_id"], "host-a");
        assert_eq!(host["host_trust_gen"], 1);
        assert_eq!(host["account_id"], ACCOUNT);
        let clock = Clock::at(host["wall_clock_ms"].as_u64().unwrap());
        let pinned: Vec<String> = setup["pinned"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| l.as_str().unwrap().to_owned())
            .collect();
        let host_log = log_of(v, &pinned, &clock);
        let mut host_keys = SoftwareKeys::new();
        let secret = unhex32(s(&book.keys["host-a"]["host_key"], "secret_hex"));
        host_keys.insert_ed25519(KeyId::new("host"), &secret);
        let mut report = Report {
            name: file["name"].as_str().unwrap().to_owned(),
            passed: 0,
            pending: Vec::new(),
        };
        // Sessions (r8 setup) belong to the host harness.
        report.pending("setup sessions", T7);
        for client in setup["clients"].as_array().unwrap() {
            assert_eq!(client["principal"], "member:dev-phone");
            assert_eq!(client["key"], "dev-phone");
        }
        Fixture {
            v,
            book,
            vec: load("r9-vectors-channel-handshake"),
            report,
            host_log,
            host_keys,
            host_key_id: KeyId::new("host"),
            channels: BTreeMap::new(),
            last_finish: None,
            last_init: None,
            outcome: None,
            clock,
        }
    }

    fn ctx(&self) -> HostContext<'_> {
        HostContext {
            log: &self.host_log,
            host_id: "host-a",
            host_trust_gen: 1,
            provider: &self.host_keys,
            key: &self.host_key_id,
        }
    }

    fn input32(&self, field: &str) -> [u8; 32] {
        unhex32(s(&self.vec["inputs"], field))
    }

    fn principal() -> Principal {
        Principal::Native {
            device_id: "dev-phone".into(),
        }
    }

    /// `{"handshake": c, "vector": f, "tamper"?}` (host side): the client's
    /// messages from the vector (optionally one field changed), answered by
    /// the responder with the vector's host ephemeral.
    fn handshake(&mut self, step: &Value) {
        keys(step, &["handshake", "vector", "tamper"]);
        assert_eq!(step["vector"], "r9-vectors-channel-handshake");
        let client = s(step, "handshake").to_owned();
        let tamper = step.get("tamper").cloned().unwrap_or(json!({}));
        let tamper = resolve(&tamper, self.v);
        let tamper = tamper.as_object().unwrap();
        let log = self.host_log.clone();
        let (initiator, init) = Initiator::start_with(
            &log,
            "host-a",
            self.input32("e_c_secret_hex"),
            self.input32("n_c_hex"),
            0,
        )
        .unwrap();
        let mut init_value = wire::to_value(&init).unwrap();
        assert_eq!(init_value, self.vec["init"], "the vector's init");
        if let Some(e) = tamper.get("init.e") {
            init_value["e"] = e.clone();
        }
        let init = init_value.to_string().into_bytes();
        self.last_init = Some(init.clone());
        let answer = Responder::on_init_with(
            &self.ctx(),
            &init,
            self.input32("e_h_secret_hex"),
            self.input32("n_h_hex"),
            0,
        );
        let (host, accept) = match answer {
            Ok(ok) => ok,
            Err(refused) => {
                self.outcome = Some(Outcome::Clear {
                    at: "init",
                    error: refused.error,
                    reply: refused.reply,
                });
                return;
            }
        };
        assert_eq!(wire::to_value(&accept).unwrap(), self.vec["accept"]);
        let signed = initiator
            .on_frame(&accept, &log, 0)
            .unwrap()
            .sign(
                Self::principal(),
                &self.book.provider,
                &self.book.auth("dev-phone"),
            )
            .unwrap();
        let mut hello: Value = serde_json::from_str(s(&self.vec, "hello_jcs")).unwrap();
        if let Some(p) = tamper.get("hello.proof.principal") {
            hello["data"]["proof"]["principal"] = p.clone();
        }
        let hello = atem_client::canonical::jcs(&hello).unwrap().into_bytes();
        let (client_channel, mut finish) = signed.finish(&hello, 0).unwrap();
        if let Some(ct) = tamper.get("finish.ct") {
            finish = Frame::Finish {
                ct: unhex(ct.as_str().unwrap()),
            }
            .to_bytes();
        }
        for key in tamper.keys() {
            assert!(
                ["init.e", "hello.proof.principal", "finish.ct"].contains(&key.as_str()),
                "unknown tamper {key}"
            );
        }
        self.last_finish = Some(finish.clone());
        let opened = match host.on_finish(&finish, 0) {
            Ok(opened) => opened,
            Err(refused) => {
                self.outcome = Some(Outcome::Clear {
                    at: "finish",
                    error: refused.error,
                    reply: refused.reply,
                });
                return;
            }
        };
        // The proof as the hello carries it (its full parse is Task 4's).
        let sent: Value = serde_json::from_slice(opened.hello()).unwrap();
        let proof = ClientProof {
            principal: Principal::from_json(&sent["data"]["proof"]["principal"], None).unwrap(),
            sig_c: b64u_decode(s(&sent["data"]["proof"], "sig")).unwrap(),
        };
        let keyed = opened.key(&proof);
        // The principal against the committed head (the empty carriage).
        let device = match &proof.principal {
            Principal::Native { device_id } | Principal::Service { device_id } => device_id.clone(),
            Principal::Browser { .. } => unreachable!(),
        };
        let Admission::Member { state, .. } = self.host_log.admit(&device, &self.clock.now) else {
            panic!("{device} is a member at E6");
        };
        match keyed.admit(&state.member.auth_key) {
            Ok(host_channel) => {
                assert_eq!(host_channel.channel_id(), s(&self.vec, "channel_id"));
                self.channels.insert(client, (host_channel, client_channel));
                self.outcome = None;
            }
            Err(refusal) => {
                assert_eq!(
                    refusal.error(),
                    ChannelError::HandshakeFailed(Failure::BadClientSignature)
                );
                let error = json!({"type": "session", "data": {"v": 1, "op": "error",
                    "code": "handshake_failed"}});
                let reply = refusal.reply(error.to_string().as_bytes(), 0).unwrap();
                // The client that lied about its principal derived th4 from
                // its own th3: it can't read the refusal (closed, no reply).
                let mut client_channel = client_channel;
                assert_eq!(
                    client_channel.open(&reply, 0).err(),
                    Some(ChannelError::RecordRejected)
                );
                // Opened with the keys of the hello as sent, the host's
                // first record is the session error.
                let code = self.open_as_sent(&reply, &proof, &sent, &hello);
                self.outcome = Some(Outcome::InChannel { code });
            }
        }
    }

    /// Opens the host's first record with the keys the hello as sent gives
    /// (th3 from its principal), from the transcript functions.
    fn open_as_sent(
        &self,
        reply: &[u8],
        proof: &ClientProof,
        _sent: &Value,
        hello: &[u8],
    ) -> String {
        let th2 = atem_client::encoding::Hash32::from_hex(s(&self.vec, "th2_hex")).unwrap();
        let schedule = Schedule::new(th2, &unhex32(s(&self.vec, "ss_hex")));
        let sig_h = unhex(s(&self.vec, "sig_h_hex"));
        let th4 = th4(&th3(&th2, &sig_h, &proof.principal), &proof.sig_c, hello);
        let (_, k_h2c) = schedule.record_keys(&th4);
        let Frame::Rec { ct } = wire::parse_frame(reply).unwrap() else {
            panic!("the refusal is a record")
        };
        let plain = chacha_open(&k_h2c, &ct);
        let error: Value = serde_json::from_slice(&plain).unwrap();
        assert_eq!(error["data"]["op"], "error");
        error["data"]["code"].as_str().unwrap().to_owned()
    }

    /// `{"client_handshake": c, "vector"?, "tamper"?, "client_log"?,
    /// "accept_head"?, "init"?}` (client side): the client's initiator
    /// against the fixture's host.
    fn client_handshake(&mut self, step: &Value) {
        keys(
            step,
            &[
                "client_handshake",
                "vector",
                "tamper",
                "client_log",
                "accept_head",
                "init",
            ],
        );
        let tamper = resolve(&step.get("tamper").cloned().unwrap_or(json!({})), self.v);
        let client_log = match step.get("client_log") {
            Some(labels) => log_of(
                self.v,
                &labels
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|l| l.as_str().unwrap().to_owned())
                    .collect::<Vec<_>>(),
                &self.clock,
            ),
            None => self.host_log.clone(),
        };
        // The fixture's host is at `accept_head` (default: its pinned E6).
        let host_log = match step.get("accept_head") {
            Some(label) => {
                assert_eq!(self.v.head(label.as_str().unwrap()), self.host_log.head());
                self.host_log.clone()
            }
            None => self.host_log.clone(),
        };
        let (initiator, init) = if step.get("vector").is_some() {
            Initiator::start_with(
                &client_log,
                "host-a",
                self.input32("e_c_secret_hex"),
                self.input32("n_c_hex"),
                0,
            )
            .unwrap()
        } else {
            Initiator::start(&client_log, "host-a", 0).unwrap()
        };
        let mut init_value = wire::to_value(&init).unwrap();
        if let Some(overrides) = step.get("init") {
            for (k, x) in overrides.as_object().unwrap() {
                init_value[k] = x.clone();
            }
        }
        let init = init_value.to_string().into_bytes();
        let ctx = HostContext {
            log: &host_log,
            host_id: "host-a",
            host_trust_gen: 1,
            provider: &self.host_keys,
            key: &self.host_key_id,
        };
        let accept = match Responder::on_init(&ctx, &init, 0) {
            Ok((_, accept)) => accept,
            Err(refused) => {
                // The client receives the clear error: advisory.
                let reply = refused.reply.clone().unwrap();
                let got = initiator.on_frame(&reply, &client_log, 0).err().unwrap();
                assert_eq!(
                    got,
                    ChannelError::Advisory {
                        code: refused.error.code().to_owned()
                    }
                );
                self.outcome = Some(Outcome::Clear {
                    at: "init",
                    error: refused.error,
                    reply: refused.reply,
                });
                return;
            }
        };
        let mut accept_value = wire::to_value(&accept).unwrap();
        for (path, value) in tamper.as_object().unwrap() {
            match path.as_str() {
                "accept.head" => accept_value["head"] = value.clone(),
                "accept.sig_by" => {
                    // Re-signed over the same th2 by another key.
                    let signer = value.as_str().unwrap();
                    let entry = &self.book.keys[signer];
                    let mut other = SoftwareKeys::new();
                    other.insert_ed25519(KeyId::new("x"), &unhex32(s(entry, "secret_hex")));
                    let (Ok(Frame::Init(i)), Ok(Frame::Accept(a))) =
                        (wire::parse_frame(&init), wire::parse_frame(&accept))
                    else {
                        unreachable!()
                    };
                    let input = HostAccept::new(&i, &a).signing_input();
                    let sig = sign(&other, &KeyId::new("x"), &input).unwrap();
                    accept_value["sig"] = Value::String(b64u(&sig));
                }
                other => panic!("unknown tamper {other}"),
            }
        }
        let accept = accept_value.to_string().into_bytes();
        match initiator.on_frame(&accept, &client_log, 0) {
            Err(error) => {
                // A refused accept: the state is consumed, nothing more is
                // sent (the API returns no frame).
                self.outcome = Some(Outcome::ClientRefused {
                    error,
                    sent_after_accept: 0,
                });
            }
            Ok(accepted) => {
                let relation = accepted.relation();
                let carriage = Carriage::plan(&client_log, accepted.host_head().head(), None);
                match relation {
                    HeadRelation::HostAhead => assert_eq!(carriage.fetch_to, Some(host_log.head())),
                    HeadRelation::Diverged | HeadRelation::Same | HeadRelation::HostBehind => {}
                }
                let signed = accepted
                    .sign(
                        Self::principal(),
                        &self.book.provider,
                        &self.book.auth("dev-phone"),
                    )
                    .unwrap();
                let hello = json!({"type": "session", "data": {"v": 1, "op": "hello",
                    "revision": 9, "id": "aaaaaaaa-0000-4000-8000-000000000001",
                    "proof": {"principal": Self::principal().to_json(), "sig": b64u(signed.sig_c())},
                    "membership": {"head": {"seq": carriage.head.seq,
                                            "hash": carriage.head.hash.to_hex()},
                                   "entries": carriage.entries.iter().map(|o| o.to_json()).collect::<Vec<_>>()}}});
                let (_, finish) = signed.finish(hello.to_string().as_bytes(), 0).unwrap();
                assert!(matches!(
                    wire::parse_frame(&finish),
                    Ok(Frame::Finish { .. })
                ));
                self.outcome = Some(Outcome::ClientSent { carriage });
            }
        }
    }

    fn step(&mut self, raw: &Value) {
        let step = resolve(raw, self.v);
        let object = step.as_object().unwrap();
        let kind = [
            "handshake",
            "client_handshake",
            "expect_record",
            "send_record",
            "expect_channel_error",
            "expect_client_refusal",
            "expect_client_sent",
            "expect_closed",
            "replay",
            "assert",
            "expect",
            "connect",
            "plain_frame",
            "expect_plain",
        ]
        .into_iter()
        .find(|k| object.contains_key(*k))
        .unwrap_or_else(|| panic!("{}: unknown step {step}", self.report.name));
        match kind {
            "handshake" => {
                self.handshake(&step);
                self.report.pass();
            }
            "client_handshake" => {
                self.client_handshake(&step);
                self.report.pass();
            }
            "expect_record" => {
                keys(&step, &["expect_record", "dir", "counter", "vector_record"]);
                let client = s(&step, "expect_record");
                let record = &self.vec["records"][step["vector_record"].as_u64().unwrap() as usize];
                assert_eq!(step["dir"], record["dir"]);
                assert_eq!(step["counter"], record["counter"]);
                assert_eq!(step["dir"], "h2c");
                let (host, client_end) = self.channels.get_mut(client).unwrap();
                assert_eq!(host.counters().0, step["counter"].as_u64().unwrap());
                let frame = host.seal(s(record, "plain_jcs").as_bytes(), 0).unwrap();
                let Frame::Rec { ct } = wire::parse_frame(&frame).unwrap() else {
                    unreachable!()
                };
                assert_eq!(hex(&ct), s(record, "ct_hex"));
                assert_eq!(
                    &**client_end.open(&frame, 0).unwrap(),
                    s(record, "plain_jcs").as_bytes()
                );
                self.report.pass();
                self.report.pending(
                    "the real welcome's content (the vector's is abbreviated)",
                    T7,
                );
            }
            "send_record" => {
                keys(
                    &step,
                    &["send_record", "vector_record", "as_counter", "ct_from"],
                );
                let client = s(&step, "send_record").to_owned();
                let record = &self.vec["records"][step["vector_record"].as_u64().unwrap() as usize];
                let frame = Frame::Rec {
                    ct: unhex(s(record, "ct_hex")),
                }
                .to_bytes();
                if let Some(dir) = step.get("ct_from") {
                    assert_eq!(dir, &record["dir"]);
                }
                let (host, _) = self.channels.get_mut(&client).unwrap();
                let expected_counter = host.counters().1;
                if let Some(n) = step.get("as_counter") {
                    assert_eq!(n.as_u64().unwrap(), expected_counter);
                }
                let fits = record["dir"] == "c2h"
                    && record["counter"].as_u64().unwrap() == expected_counter;
                match host.open(&frame, 0) {
                    Ok(plain) => {
                        assert!(fits, "only the record at its counter and direction opens");
                        assert_eq!(&*plain, s(record, "plain_jcs").as_bytes());
                        self.report.pass();
                        self.report
                            .pending("the session reply to the record (sessions)", T7);
                    }
                    Err(error) => {
                        assert!(!fits);
                        assert_eq!(error, ChannelError::RecordRejected);
                        assert!(host.is_closed());
                        self.outcome = Some(Outcome::Clear {
                            at: "record",
                            error,
                            reply: None,
                        });
                        self.report.pass();
                    }
                }
            }
            "expect_closed" => {
                keys(&step, &["expect_closed", "reply"]);
                assert_eq!(step["reply"], false);
                let client = s(&step, "expect_closed").to_owned();
                match self.outcome.take() {
                    Some(Outcome::Clear {
                        at: "record",
                        reply: None,
                        ..
                    }) => {}
                    other => panic!(
                        "{}: expected a silent close, got {other:?}",
                        self.report.name
                    ),
                }
                assert!(self.channels.remove(&client).unwrap().0.is_closed());
                self.report.pass();
            }
            "expect_channel_error" => {
                keys(&step, &["expect_channel_error", "code", "at"]);
                let code = s(&step, "code");
                let at = s(&step, "at");
                match self.outcome.take() {
                    Some(Outcome::Clear {
                        at: got_at,
                        error,
                        reply,
                    }) => {
                        assert_eq!(got_at, at, "{}", self.report.name);
                        assert_eq!(error.code(), code);
                        assert_eq!(
                            reply,
                            Some(wire::clear_error(ClearCode::parse(code).unwrap()))
                        );
                    }
                    Some(Outcome::InChannel { code: got }) => {
                        assert_eq!(at, "finish");
                        assert_eq!(got, code);
                    }
                    other => panic!("{}: no channel error ({other:?})", self.report.name),
                }
                self.report.pass();
            }
            "expect_client_refusal" => {
                keys(
                    &step,
                    &["expect_client_refusal", "code", "sent_after_accept"],
                );
                match self.outcome.take() {
                    Some(Outcome::ClientRefused {
                        error,
                        sent_after_accept,
                    }) => {
                        assert_eq!(
                            error,
                            ChannelError::HandshakeFailed(Failure::BadHostSignature)
                        );
                        assert_eq!(error.code(), s(&step, "code"));
                        assert_eq!(
                            sent_after_accept as u64,
                            step["sent_after_accept"].as_u64().unwrap()
                        );
                    }
                    other => panic!("{}: no client refusal ({other:?})", self.report.name),
                }
                self.report.pass();
            }
            "expect_client_sent" => {
                let Some(Outcome::ClientSent { carriage }) = self.outcome.take() else {
                    panic!("{}: the client sent no finish", self.report.name)
                };
                assert_eq!(step["op"], "finish");
                for (key, want) in object {
                    match key.as_str() {
                        "expect_client_sent" | "op" => {}
                        "membership.entries.#" => {
                            assert_eq!(carriage.entries.len() as u64, want.as_u64().unwrap())
                        }
                        "membership.entries" => {
                            let want: Vec<_> = want
                                .as_array()
                                .unwrap()
                                .iter()
                                .map(|l| self.v.object(l.as_str().unwrap()))
                                .collect();
                            assert_eq!(carriage.entries, want);
                        }
                        other => panic!("unknown field {other}"),
                    }
                }
                self.report.pass();
                self.report
                    .pending("expect_client_sent: the hello carrying that carriage", T4);
            }
            "replay" => {
                keys(&step, &["replay"]);
                let replay = &step["replay"];
                assert_eq!(replay["finish_of"], "previous");
                // The fixture names the second channel's e_h and n_h, public
                // values only (no secret to answer with): the responder
                // answers with a fresh ephemeral, as a real host does; the
                // vector runner checks that channel's exact th2, sig_h and
                // k_finish.
                let e_h = unhex32(s(&replay["into_new_channel"], "e_h"));
                assert_ne!(e_h, self.input32("e_h_hex"));
                let init = self.last_init.clone().unwrap();
                let (host, accept) = Responder::on_init(&self.ctx(), &init, 0).unwrap();
                assert_ne!(wire::to_value(&accept).unwrap(), self.vec["accept"]);
                let refused = host
                    .on_finish(self.last_finish.as_ref().unwrap(), 0)
                    .err()
                    .unwrap();
                self.outcome = Some(Outcome::Clear {
                    at: "finish",
                    error: refused.error,
                    reply: refused.reply,
                });
                self.report.pass();
            }
            "assert" => {
                keys(&step, &["assert"]);
                for (key, want) in step["assert"].as_object().unwrap() {
                    match key.as_str() {
                        "head" => {
                            assert_eq!(self.host_log.head(), self.v.head(want.as_str().unwrap()));
                            self.report.pass();
                        }
                        "channel_id" => {
                            let open: Vec<&str> = self
                                .channels
                                .values()
                                .map(|(h, _)| h.channel_id())
                                .collect();
                            assert_eq!(open, vec![want.as_str().unwrap()]);
                            self.report.pass();
                        }
                        "attachments" | "pty_writes" | "dispatches" => {
                            self.report.pending(format!("assert {key}"), T7)
                        }
                        other => panic!("unknown assert {other}"),
                    }
                }
            }
            "connect" => self.connect(&step),
            "expect" => {
                keys(&step, &["expect", "match"]);
                let want = &step["match"];
                match self.outcome.take() {
                    // The channel carried the refusal (checked in `connect`);
                    // the refusal itself is the hello check.
                    Some(Outcome::InChannel { .. }) => self.report.pending(
                        format!("expect {want}: refusing the hello for its revision"),
                        T4,
                    ),
                    _ => self
                        .report
                        .pending(format!("expect {want}: a session reply in the channel"), T7),
                }
            }
            "plain_frame" => {
                keys(&step, &["plain_frame", "json"]);
                let bytes = step["json"].to_string().into_bytes();
                // Outside any channel: never a channel frame, never opened.
                assert!(matches!(wire::parse(&bytes), Ok(Parsed::Plain(_))));
                assert!(Responder::on_init(&self.ctx(), &bytes, 0).is_err());
                self.report.pass();
            }
            "expect_plain" => {
                self.report
                    .pending("expect_plain: the host's plain session error", T7);
            }
            _ => unreachable!(),
        }
    }

    /// `{"connect": c, "carry": [], "hello": {…}}`: a full handshake whose
    /// hello the host refuses; the refusal is the encrypted first record,
    /// which the client reads. Whether `revision: 8` is refused is the
    /// hello check (Task 4); the channel carries the host's answer.
    fn connect(&mut self, step: &Value) {
        keys(step, &["connect", "carry", "hello"]);
        assert_eq!(step["carry"], json!([]));
        let log = self.host_log.clone();
        let (initiator, init) = Initiator::start(&log, "host-a", 0).unwrap();
        let (host, accept) = Responder::on_init(&self.ctx(), &init, 0).unwrap();
        let accepted = initiator.on_frame(&accept, &log, 0).unwrap();
        let carriage = Carriage::plan(&log, accepted.host_head().head(), None);
        let signed = accepted
            .sign(
                Self::principal(),
                &self.book.provider,
                &self.book.auth("dev-phone"),
            )
            .unwrap();
        let mut hello = json!({"type": "session", "data": {"v": 1, "op": "hello",
            "id": "aaaaaaaa-0000-4000-8000-000000000008", "revision": 9,
            "proof": {"principal": Self::principal().to_json(), "sig": b64u(signed.sig_c())},
            "membership": {"head": {"seq": carriage.head.seq, "hash": carriage.head.hash.to_hex()},
                           "entries": []}}});
        for (k, x) in step["hello"].as_object().unwrap() {
            hello["data"][k] = x.clone();
        }
        let hello = hello.to_string().into_bytes();
        let (mut client, finish) = signed.finish(&hello, 0).unwrap();
        let opened = host.on_finish(&finish, 0).unwrap();
        let sent: Value = serde_json::from_slice(opened.hello()).unwrap();
        let keyed = opened.key(&ClientProof {
            principal: Self::principal(),
            sig_c: b64u_decode(s(&sent["data"]["proof"], "sig")).unwrap(),
        });
        assert_eq!(sent["data"]["revision"], 8);
        let error = json!({"type": "session", "data": {"v": 1, "op": "error",
            "code": "unsupported_version", "revision": 9}});
        let reply = keyed.refuse(error.to_string().as_bytes(), 0).unwrap();
        let plain = client.open(&reply, 0).unwrap();
        let got: Value = serde_json::from_slice(&plain).unwrap();
        self.outcome = Some(Outcome::InChannel {
            code: got["data"]["code"].as_str().unwrap().to_owned(),
        });
        self.report.pass();
    }
}

fn chacha_open(key: &[u8; 32], ct: &[u8]) -> Vec<u8> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    let aad = atem_client::channel::record::record_aad(Direction::H2c);
    chacha20poly1305::ChaCha20Poly1305::new(key.into())
        .decrypt(
            &atem_client::channel::record::record_nonce(0).into(),
            Payload { msg: ct, aad: &aad },
        )
        .unwrap()
}

fn log_of(v: &Vectors, labels: &[String], clock: &Clock) -> Membership {
    let refs: Vec<&str> = labels.iter().map(String::as_str).collect();
    let entries: Vec<Entry> = v.entries(&refs);
    Membership::verify_chain(ACCOUNT, &genesis_hash(), &entries, &clock.now)
        .unwrap()
        .membership
}

#[test]
fn channel_scenarios() {
    let v = Vectors::load();
    let book = Book::load();
    let mut total = (0, 0);
    for name in FILES {
        let file = load(name);
        assert_eq!(file["name"], name);
        assert_eq!(file["requires"], "r9");
        assert_eq!(file["kind"], "scenario");
        assert_eq!(file["log"], "r9-vectors-membership-log");
        let mut fixture = Fixture::new(&file, &v, &book);
        for step in file["steps"].as_array().unwrap() {
            fixture.step(step);
        }
        assert!(
            fixture.outcome.is_none(),
            "{name}: an outcome nobody checked"
        );
        let report = fixture.report;
        eprintln!(
            "{name}: {} checked, {} pending",
            report.passed,
            report.pending.len()
        );
        for (what, owner) in &report.pending {
            eprintln!("  PENDING {what}: {owner}");
        }
        assert!(report.passed > 0);
        total.0 += report.passed;
        total.1 += report.pending.len();
    }
    eprintln!("total: {} checked, {} pending", total.0, total.1);
}
