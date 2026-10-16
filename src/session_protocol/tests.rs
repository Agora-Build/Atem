//! Tests for atem-session v1 wire types, strict decoding and the canonical digest.
//! Fixtures are read from `designs/protocol/fixtures/` at test time.

use super::canonical::{self, Numbers, StrictError};
use super::wire::{self, Binding, BindingUse, Envelope, ErrorCode, Op};
use serde_json::{Value, json};
use std::path::PathBuf;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("designs/protocol/fixtures")
}

fn read_fixture(name: &str) -> Value {
    let bytes = std::fs::read(fixtures_dir().join(name)).expect("read fixture");
    canonical::parse_strict(&bytes, usize::MAX, Numbers::AllowFractions)
        .unwrap_or_else(|e| panic!("{name} is not strict JSON: {e:?}"))
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// ── digest vectors ────────────────────────────────────────────────────────

#[test]
fn digest_vectors_canonicalise_and_hash() {
    let file = read_fixture("digest-vectors.json");
    let vectors = file["vectors"].as_array().unwrap();
    assert!(vectors.len() >= 10);
    for v in vectors {
        let name = v["name"].as_str().unwrap();
        let canonical = canonical::jcs(&v["payload"]).unwrap();
        assert_eq!(canonical, v["canonical"].as_str().unwrap(), "{name}");
        let digest = canonical::payload_digest(&v["payload"]).unwrap();
        assert_eq!(digest, v["sha256"].as_str().unwrap(), "{name}");
        assert!(wire::is_digest(&digest));
        // Canonical form is a fixed point of parse + canonicalise.
        let reparsed = canonical::parse_payload(canonical.as_bytes()).unwrap();
        assert_eq!(canonical::jcs(&reparsed).unwrap(), canonical, "{name}");
    }
}

fn must_reject_inputs() -> Vec<(String, Vec<u8>)> {
    let file = read_fixture("digest-vectors.json");
    let rejects = file["must_reject"].as_array().unwrap();
    assert!(rejects.len() >= 9);
    rejects
        .iter()
        .map(|r| {
            let bytes = match (r.get("payload_json"), r.get("payload_hex")) {
                (Some(Value::String(s)), None) => s.as_bytes().to_vec(),
                (None, Some(Value::String(h))) => hex_decode(h),
                other => panic!("bad must_reject entry {other:?}"),
            };
            (r["name"].as_str().unwrap().to_string(), bytes)
        })
        .collect()
}

#[test]
fn digest_must_reject_inputs_are_refused() {
    for (name, bytes) in must_reject_inputs() {
        assert!(
            canonical::parse_payload(&bytes).is_err(),
            "{name} was accepted"
        );
    }
}

fn submit_with_payload(payload: &[u8]) -> Vec<u8> {
    let mut out = br#"{"type":"session","data":{"v":1,"op":"submit","id":"11111111-1111-4111-8111-000000000001","binding":{"target":{"account_id":"account-a","atem_device_id":"host-a","host_trust_gen":1,"session_id":"ses-aaaaaaaaaaaa","process_gen":"22222222-2222-4222-8222-222222222222"},"attachment_gen":"33333333-3333-4333-8333-333333333333","lease_epoch":1},"request_id":"44444444-4444-4444-8444-444444444447","kind":"approval","payload":"#.to_vec();
    out.extend_from_slice(payload);
    out.extend_from_slice(b"}}");
    out
}

#[test]
fn must_reject_payloads_are_refused_inside_a_submit() {
    // Sanity: a valid payload in the same frame decodes.
    assert!(wire::decode(&submit_with_payload(br#"{"text":"a"}"#)).is_ok());
    for (name, bytes) in must_reject_inputs() {
        let err = wire::decode(&submit_with_payload(&bytes))
            .err()
            .unwrap_or_else(|| panic!("{name} accepted in a submit"));
        assert_eq!(err.code, ErrorCode::UnsupportedVersion, "{name}");
    }
}

#[test]
fn jcs_rejects_values_outside_the_domain() {
    assert!(canonical::jcs(&json!({"n": 1.5})).is_err());
    assert!(canonical::jcs(&json!({"n": 1.0})).is_err());
    assert!(canonical::jcs(&json!({"n": 9007199254740992u64})).is_err());
    assert!(canonical::jcs(&json!({"n": -9007199254740992i64})).is_err());
    assert_eq!(canonical::jcs(&json!([0, -0, -5])).unwrap(), "[0,0,-5]");
    assert_eq!(
        canonical::jcs(&json!({"s": "\u{7f}\u{2028}é"})).unwrap(),
        "{\"s\":\"\u{7f}\u{2028}é\"}"
    );
}

// ── strict parser ─────────────────────────────────────────────────────────

#[test]
fn strict_parser_rules() {
    let p = |s: &str| canonical::parse_strict(s.as_bytes(), 1 << 20, Numbers::AllowFractions);
    let i = |s: &str| canonical::parse_strict(s.as_bytes(), 1 << 20, Numbers::IntegersOnly);
    assert_eq!(
        p(r#"{"a":[1,"x",null,true]}"#).unwrap(),
        json!({"a":[1,"x",null,true]})
    );
    assert_eq!(p(r#""\ud83d\ude00""#).unwrap(), json!("😀"));
    assert_eq!(p(" { } ").unwrap(), json!({}));
    assert_eq!(p("1.5").unwrap(), json!(1.5));
    assert_eq!(i("1.5"), Err(StrictError::NonInteger));
    assert_eq!(i("1e3"), Err(StrictError::NonInteger));
    assert_eq!(i("-0"), Ok(json!(0)));
    assert_eq!(p(r#"{"a":1,"a":1}"#), Err(StrictError::DuplicateKey));
    assert_eq!(
        p(r#"[{"b":{"c":1,"c":2}}]"#),
        Err(StrictError::DuplicateKey)
    );
    // Escaped spelling of the same key is still a duplicate.
    assert_eq!(p(r#"{"a":1,"\u0061":2}"#), Err(StrictError::DuplicateKey));
    assert_eq!(p("9007199254740992"), Err(StrictError::UnsafeInteger));
    assert_eq!(p("-9007199254740992"), Err(StrictError::UnsafeInteger));
    assert_eq!(
        p("123456789012345678901234567890"),
        Err(StrictError::UnsafeInteger)
    );
    assert_eq!(p(r#""\udc00""#), Err(StrictError::LoneSurrogate));
    assert_eq!(p(r#""\ud800\u0041""#), Err(StrictError::LoneSurrogate));
    assert_eq!(
        canonical::parse_strict(b"\"\xff\"", 100, Numbers::AllowFractions),
        Err(StrictError::InvalidUtf8)
    );
    assert_eq!(
        canonical::parse_strict(b"[1, 2]", 5, Numbers::AllowFractions),
        Err(StrictError::TooLarge)
    );
    for bad in [
        "",
        "{",
        "[1,]",
        "{\"a\" 1}",
        "01",
        "1.",
        ".5",
        "+1",
        "tru",
        "\"a\nb\"",
        "1 2",
        "{'a':1}",
        "\"\\x\"",
    ] {
        assert!(matches!(p(bad), Err(StrictError::Syntax(_))), "{bad:?}");
    }
    let deep = "[".repeat(10_000) + &"]".repeat(10_000);
    assert_eq!(p(&deep), Err(StrictError::TooDeep));
}

// ── fixtures: every wire message decodes and round-trips ─────────────────

/// Replaces harness placeholders (`${name}`) with a valid value.
fn substitute(v: &mut Value) {
    match v {
        Value::String(s) if s.contains("${") => *s = "stream-0001".to_string(),
        Value::Array(a) => a.iter_mut().for_each(substitute),
        Value::Object(m) => m.values_mut().for_each(substitute),
        _ => {}
    }
}

fn collect_messages(v: &Value, out: &mut Vec<Value>) {
    match v {
        Value::Object(m) => {
            if let Some(msg @ Value::Object(_)) = m.get("json") {
                out.push(msg.clone());
            }
            m.values().for_each(|c| collect_messages(c, out));
        }
        Value::Array(a) => a.iter().for_each(|c| collect_messages(c, out)),
        _ => {}
    }
}

fn round_trip(msg: &Value) -> Envelope {
    let bytes = serde_json::to_vec(msg).unwrap();
    let env = wire::decode(&bytes).unwrap_or_else(|e| panic!("decode failed: {e:?}\n{msg}"));
    let again = wire::encode(&env);
    let reparsed: Value = serde_json::from_slice(&again).unwrap();
    assert_eq!(&reparsed, msg, "round trip changed the message");
    // And the re-encoded form decodes again.
    wire::decode(&again).unwrap();
    env
}

#[test]
fn every_fixture_wire_message_decodes_and_round_trips() {
    let mut files: Vec<_> = std::fs::read_dir(fixtures_dir())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .filter(|p| p.file_name().unwrap() != "digest-vectors.json")
        .collect();
    files.sort();
    assert!(files.len() >= 7, "fixture files missing");
    let (mut total, mut session, mut bound) = (0, 0, 0);
    for path in files {
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let file = read_fixture(&name);
        let mut msgs = Vec::new();
        collect_messages(&file["steps"], &mut msgs);
        assert!(!msgs.is_empty(), "{name} has no wire messages");
        for mut msg in msgs {
            substitute(&mut msg);
            match round_trip(&msg) {
                Envelope::Session(_) => session += 1,
                Envelope::Family(f) => {
                    assert_ne!(msg["type"], "session");
                    if let Some(b) = &f.binding {
                        bound += 1;
                        b.validate(BindingUse::Read)
                            .or_else(|_| b.validate(BindingUse::Mutation))
                            .unwrap();
                    }
                }
            }
            total += 1;
        }
    }
    eprintln!("fixture wire messages: {total} ({session} session, {bound} legacy with binding)");
    assert!(total >= 55 && session >= 30, "{total} / {session}");
}

// ── every op round-trips ──────────────────────────────────────────────────

const ID: &str = "11111111-1111-4111-8111-000000000001";
const RE: &str = "11111111-1111-4111-8111-000000000002";
const PG: &str = "22222222-2222-4222-8222-222222222222";
const AG: &str = "33333333-3333-4333-8333-333333333333";

fn target() -> Value {
    json!({"account_id":"account-a","atem_device_id":"host-a","host_trust_gen":1,
           "session_id":"ses-aaaaaaaaaaaa","process_gen":PG})
}

fn binding(epoch: Option<u64>) -> Value {
    let mut b = json!({"target": target(), "attachment_gen": AG});
    if let Some(e) = epoch {
        b["lease_epoch"] = json!(e);
    }
    b
}

fn descriptor() -> Value {
    json!({"session_id":"ses-abcdefghijkl","process_gen":PG,"provider":"claude",
           "cwd_label":"Atem","state":"running","activity":"ready","activity_since":1760500000000u64,
           "controller":{"controller_session":RE,"lease_epoch":7},
           "capabilities":["terminal-v1","chat-v1"],"created_at":1760490000000u64})
}

fn session(op: &str, mut fields: Value) -> Value {
    let m = fields.as_object_mut().unwrap();
    m.insert("v".into(), json!(1));
    m.insert("op".into(), json!(op));
    m.insert("id".into(), json!(ID));
    json!({"type":"session","data":fields})
}

fn all_ops() -> Vec<Value> {
    let receipt = json!({"request_id":RE,"target":target(),"kind":"prompt","state":"completed",
                         "detail":"done","updated_at":1760500000000u64});
    vec![
        session("hello", json!({})),
        session("hello", json!({"resume":{"controller_session":RE}})),
        session(
            "challenge",
            json!({"re":RE,"nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}),
        ),
        session("resume_proof", json!({"re":RE,"proof":"c2ln"})),
        session(
            "welcome",
            json!({"re":RE,"account_id":"account-a","atem_device_id":"host-a",
            "host_trust_gen":1,"runtime_gen":PG,"controller_session":RE,"attachment_gen":AG,
            "client_kind":"native","permissions":["view","control","approve"],
            "authorization_ms_left":86400000,"server_time":1760500000000u64}),
        ),
        session("list", json!({})),
        session(
            "sessions",
            json!({"re":RE,"runtime_gen":PG,"runtime_epoch":7,"seq":1,"sessions":[descriptor()]}),
        ),
        session(
            "sessions",
            json!({"runtime_gen":PG,"runtime_epoch":7,"seq":0,"sessions":[]}),
        ),
        session(
            "session_changed",
            json!({"runtime_gen":PG,"runtime_epoch":7,"seq":2,"descriptor":descriptor()}),
        ),
        session("acquire", json!({"binding":binding(None),"takeover":true})),
        session("renew", json!({"binding":binding(Some(7))})),
        session("release", json!({"binding":binding(Some(7))})),
        session(
            "lease",
            json!({"re":RE,"binding":binding(Some(7)),"ms_left":15000}),
        ),
        session("lease_released", json!({"re":RE})),
        session(
            "lease_changed",
            json!({"session_id":"ses-aaaaaaaaaaaa","process_gen":PG,
            "controller":null,"lease_epoch":8,"reason":"local_input"}),
        ),
        session(
            "lease_changed",
            json!({"session_id":"ses-aaaaaaaaaaaa","process_gen":PG,
            "controller":{"controller_session":RE,"lease_epoch":9},"lease_epoch":9,"reason":"takeover"}),
        ),
        session(
            "submit",
            json!({"binding":binding(Some(7)),"request_id":RE,"kind":"prompt","payload":{"text":"run the tests"}}),
        ),
        session(
            "submit",
            json!({"binding":binding(Some(7)),"request_id":RE,"kind":"interrupt","payload":{}}),
        ),
        session(
            "submit",
            json!({"binding":binding(Some(7)),"request_id":RE,"kind":"stop","payload":{}}),
        ),
        session(
            "submit",
            json!({"binding":binding(Some(7)),"request_id":RE,"kind":"approval","payload":{"x":[1,{"y":null}]}}),
        ),
        session("receipt", {
            let mut r = receipt.clone();
            r["re"] = json!(RE);
            r
        }),
        session(
            "receipt_query",
            json!({"binding":binding(None),"request_ids":[RE, ID]}),
        ),
        session("receipts", json!({"re":RE,"receipts":[receipt]})),
        session("error", json!({"re":RE,"code":"stale_target"})),
        session(
            "error",
            json!({"re":RE,"code":"forbidden","detail":"approval answers are not supported in v1"}),
        ),
        // terminal-v1 / chat-v1 with data.binding (§2)
        json!({"type":"terminal","data":{"v":1,"op":"subscribe","terminal_id":"ses-aaaaaaaaaaaa","generation":PG,
            "binding":binding(None)}}),
        json!({"type":"terminal","data":{"v":1,"op":"input","terminal_id":"ses-aaaaaaaaaaaa","generation":PG,
            "stream_id":"s1","sequence":0,"bytes":"aGkN","binding":binding(Some(7))}}),
        json!({"type":"terminal","data":{"v":1,"op":"resize","terminal_id":"ses-aaaaaaaaaaaa","generation":PG,
            "stream_id":"s1","rows":40,"cols":120,"binding":binding(Some(7))}}),
        json!({"type":"terminal","data":{"v":1,"op":"stop","terminal_id":"ses-aaaaaaaaaaaa","generation":PG,
            "stream_id":"s1","binding":binding(Some(7))}}),
        json!({"type":"agentChat","data":{"v":1,"op":"open","conversationId":"c1","agentId":"ses-aaaaaaaaaaaa",
            "binding":binding(None)}}),
        json!({"type":"agentChat","data":{"v":1,"op":"submit","conversationId":"c1","agentId":"ses-aaaaaaaaaaaa",
            "generation":PG,"requestId":RE,"text":"run the tests","binding":binding(Some(7))}}),
        // legacy, unbound
        json!({"type":"terminal","data":{"v":1,"op":"input","terminal_id":"claude","generation":"g","stream_id":"s",
            "lease_id":"l","sequence":3,"bytes":"aGk="}}),
        json!({"type":"heartbeat","data":{"ts":1}}),
    ]
}

#[test]
fn every_op_decodes_and_round_trips() {
    for msg in all_ops() {
        round_trip(&msg);
    }
}

#[test]
fn decoded_values_are_typed() {
    let env = round_trip(&all_ops()[16]);
    let Envelope::Session(m) = env else { panic!() };
    assert_eq!(m.id, ID);
    let Op::Submit {
        binding,
        kind,
        payload,
        ..
    } = m.op
    else {
        panic!()
    };
    assert_eq!(binding.lease_epoch, Some(7));
    assert_eq!(binding.target.session_id, "ses-aaaaaaaaaaaa");
    assert_eq!(kind, wire::ReceiptKind::Prompt);
    assert_eq!(
        canonical::payload_digest(&payload).unwrap(),
        "51b365c654de71c69dac5afdc09dbbf06929ef6137ee7878f32937071d2923a8"
    );
}

#[test]
fn family_binding_ids_must_agree() {
    let check = |msg: Value| {
        let Envelope::Family(f) = wire::decode(&serde_json::to_vec(&msg).unwrap()).unwrap() else {
            panic!()
        };
        f.check_binding_ids()
    };
    let ok = json!({"type":"terminal","data":{"v":1,"op":"subscribe","terminal_id":"ses-aaaaaaaaaaaa",
        "generation":PG,"binding":binding(None)}});
    assert_eq!(check(ok), Ok(()));
    let wrong_id = json!({"type":"terminal","data":{"v":1,"op":"subscribe","terminal_id":"ses-bbbbbbbbbbbb",
        "generation":PG,"binding":binding(None)}});
    assert_eq!(check(wrong_id), Err(ErrorCode::StaleTarget));
    let wrong_gen = json!({"type":"agentChat","data":{"v":1,"op":"submit","conversationId":"c1",
        "agentId":"ses-aaaaaaaaaaaa","generation":AG,"requestId":RE,"text":"x","binding":binding(Some(7))}});
    assert_eq!(check(wrong_gen), Err(ErrorCode::StaleTarget));
    let unbound = json!({"type":"agentInput","data":{"agent_id":null,"kind":"text","text":"x"}});
    assert_eq!(check(unbound), Ok(()));
}

// ── negative cases per §1 row ─────────────────────────────────────────────

fn rejects(msg: &Value) -> wire::DecodeError {
    match wire::decode(&serde_json::to_vec(msg).unwrap()) {
        Ok(env) => panic!("accepted: {msg}\n{env:?}"),
        Err(e) => e,
    }
}

fn with(mut msg: Value, path: &str, value: Option<Value>) -> Value {
    let mut parts: Vec<&str> = path.split('.').collect();
    let last = parts.pop().unwrap();
    let mut cur = &mut msg["data"];
    for p in parts {
        cur = match p.parse::<usize>() {
            Ok(i) => &mut cur[i],
            Err(_) => &mut cur[p],
        };
    }
    match value {
        Some(v) => match last.parse::<usize>() {
            Ok(i) => cur[i] = v,
            Err(_) => cur[last] = v,
        },
        None => {
            cur.as_object_mut().unwrap().remove(last);
        }
    }
    msg
}

fn submit() -> Value {
    all_ops()[16].clone()
}

#[test]
fn envelope_and_version() {
    rejects(&json!({"data":{}}));
    rejects(&json!({"type":"session"}));
    rejects(&json!({"type":"session","data":[]}));
    rejects(&json!([]));
    let e = rejects(&with(submit(), "v", Some(json!(2))));
    assert_eq!(e.code, ErrorCode::UnsupportedVersion);
    assert_eq!(
        e.id.as_deref(),
        Some(ID),
        "the error can still answer the request"
    );
    rejects(&with(submit(), "v", Some(json!("1"))));
    rejects(&with(submit(), "v", None));
    rejects(&with(submit(), "op", Some(json!("frobnicate"))));
    rejects(&with(submit(), "id", None));
    rejects(&with(submit(), "re", Some(json!(null))));
    // Unknown fields are ignored.
    let extra = with(submit(), "future_field", Some(json!({"a":1.5})));
    assert!(wire::decode(&serde_json::to_vec(&extra).unwrap()).is_ok());
    let extra = with(submit(), "binding.target.future", Some(json!(true)));
    assert!(wire::decode(&serde_json::to_vec(&extra).unwrap()).is_ok());
}

#[test]
fn uuids_are_lowercase_canonical_v4() {
    for bad in [
        "11111111-1111-4111-8111-00000000000A",
        "11111111-1111-1111-8111-000000000001",
        "11111111-1111-4111-c111-000000000001",
        "11111111-1111-4111-8111-0000000000001",
        "111111111111-4111-8111-000000000001",
        "{11111111-1111-4111-8111-000000000001}",
        "",
    ] {
        assert!(!wire::is_uuid_v4(bad), "{bad}");
        rejects(&with(submit(), "id", Some(json!(bad))));
        rejects(&with(submit(), "request_id", Some(json!(bad))));
        rejects(&with(submit(), "binding.attachment_gen", Some(json!(bad))));
        rejects(&with(
            submit(),
            "binding.target.process_gen",
            Some(json!(bad)),
        ));
    }
    for good in [
        "11111111-1111-4111-8111-000000000001",
        "aaaaaaaa-aaaa-4aaa-baaa-aaaaaaaaaaaa",
    ] {
        assert!(wire::is_uuid_v4(good));
    }
}

#[test]
fn session_ids() {
    assert!(wire::is_session_id("ses-abcdefghijkl"));
    assert!(wire::is_session_id("ses-a2b3c4d5e6f7"));
    for bad in [
        "ses-ABCDEFGHIJKL",
        "ses-abcdefghijk",
        "ses-abcdefghijklm",
        "ses-abcdefghijk1",
        "ses-abcdefghijk8",
        "abc-abcdefghijkl",
        "claude",
    ] {
        assert!(!wire::is_session_id(bad), "{bad}");
        rejects(&with(
            submit(),
            "binding.target.session_id",
            Some(json!(bad)),
        ));
    }
    let mut d = descriptor();
    d["session_id"] = json!("ses-abc");
    rejects(&session(
        "session_changed",
        json!({"runtime_gen":PG,"runtime_epoch":7,"seq":2,"descriptor":d}),
    ));
}

#[test]
fn opaque_ids() {
    assert!(wire::is_opaque_id(&"a".repeat(128)));
    assert!(wire::is_opaque_id("A.b_c:d-9"));
    for bad in [
        String::new(),
        "a".repeat(129),
        "a b".into(),
        "a/b".into(),
        "é".into(),
    ] {
        assert!(!wire::is_opaque_id(&bad), "{bad}");
        rejects(&with(
            submit(),
            "binding.target.account_id",
            Some(json!(bad)),
        ));
        rejects(&with(
            submit(),
            "binding.target.atem_device_id",
            Some(json!(bad)),
        ));
    }
}

#[test]
fn counters_and_times() {
    let max = json!(9007199254740991u64);
    for path in ["binding.target.host_trust_gen", "binding.lease_epoch"] {
        assert!(
            wire::decode(&serde_json::to_vec(&with(submit(), path, Some(max.clone()))).unwrap())
                .is_ok()
        );
        for bad in [json!(-1), json!(1.5), json!("1"), json!(null)] {
            rejects(&with(submit(), path, Some(bad)));
        }
    }
    // Exponent / fraction spellings and unsafe integers are refused before typing.
    let raw = String::from_utf8(serde_json::to_vec(&submit()).unwrap()).unwrap();
    for (from, to) in [
        ("\"lease_epoch\":7", "\"lease_epoch\":7.0"),
        ("\"lease_epoch\":7", "\"lease_epoch\":7e0"),
        ("\"lease_epoch\":7", "\"lease_epoch\":9007199254740992"),
        (
            "\"host_trust_gen\":1",
            "\"host_trust_gen\":18446744073709551616",
        ),
    ] {
        assert!(raw.contains(from));
        assert!(
            wire::decode(raw.replace(from, to).as_bytes()).is_err(),
            "{to}"
        );
    }
    let changed = |path: &str, v: Value| {
        session(
            "session_changed",
            json!({"runtime_gen":PG,"runtime_epoch":7,"seq":2,"descriptor":descriptor()}),
        )
        .pipe(|m| with(m, path, Some(v)))
    };
    rejects(&changed("seq", json!(-1)));
    rejects(&changed("runtime_epoch", json!(1.5)));
    rejects(&changed("descriptor.activity_since", json!(1.5)));
    rejects(&changed("descriptor.created_at", json!(-5)));
    rejects(&changed("descriptor.controller.lease_epoch", json!("7")));
}

trait Pipe: Sized {
    fn pipe<T>(self, f: impl FnOnce(Self) -> T) -> T {
        f(self)
    }
}
impl Pipe for Value {}

#[test]
fn digests() {
    assert!(wire::is_digest(&"a".repeat(64)));
    assert!(!wire::is_digest(&"A".repeat(64)));
    assert!(!wire::is_digest(&"a".repeat(63)));
    assert!(!wire::is_digest(&"g".repeat(64)));
}

#[test]
fn bounds() {
    // Message size is checked before parsing.
    let mut big = serde_json::to_vec(&submit()).unwrap();
    big.extend(std::iter::repeat_n(b' ', wire::MAX_MESSAGE_BYTES));
    assert_eq!(
        wire::decode(&big).unwrap_err().code,
        ErrorCode::UnsupportedVersion
    );
    // Prompt text.
    let at = "a".repeat(wire::MAX_PROMPT_BYTES);
    assert!(
        wire::decode(
            &serde_json::to_vec(&with(submit(), "payload.text", Some(json!(at)))).unwrap()
        )
        .is_ok()
    );
    rejects(&with(
        submit(),
        "payload.text",
        Some(json!("a".repeat(wire::MAX_PROMPT_BYTES + 1))),
    ));
    // Canonical payload size (approval is the only kind with a free-form payload).
    let approval = |n: usize| {
        with(
            with(submit(), "kind", Some(json!("approval"))),
            "payload",
            Some(json!({"t": "a".repeat(n)})),
        )
    };
    assert!(
        wire::decode(&serde_json::to_vec(&approval(wire::MAX_PAYLOAD_BYTES - 8)).unwrap()).is_ok()
    );
    rejects(&approval(wire::MAX_PAYLOAD_BYTES - 7));
    // receipt_query.request_ids
    let ids: Vec<String> = (0..65)
        .map(|i| format!("11111111-1111-4111-8111-{i:012}"))
        .collect();
    let q = |n: usize| {
        session(
            "receipt_query",
            json!({"binding":binding(None),"request_ids":ids[..n].to_vec()}),
        )
    };
    assert!(wire::decode(&serde_json::to_vec(&q(64)).unwrap()).is_ok());
    rejects(&q(65));
    // detail
    let err = |n: usize| session("error", json!({"code":"busy","detail":"d".repeat(n)}));
    assert!(wire::decode(&serde_json::to_vec(&err(512)).unwrap()).is_ok());
    rejects(&err(513));
}

#[test]
fn payload_shapes_per_kind() {
    rejects(&with(submit(), "payload", Some(json!({}))));
    rejects(&with(submit(), "payload", Some(json!({"text": 1}))));
    rejects(&with(submit(), "payload", Some(json!("text"))));
    rejects(&with(
        submit(),
        "payload",
        Some(json!({"text":"a","more":1})),
    ));
    rejects(&with(submit(), "payload", None));
    let interrupt = with(submit(), "kind", Some(json!("interrupt")));
    rejects(&interrupt);
    rejects(&with(submit(), "kind", Some(json!("shell"))));
}

#[test]
fn duplicate_keys_anywhere_in_a_message() {
    let raw = String::from_utf8(serde_json::to_vec(&submit()).unwrap()).unwrap();
    for (from, to) in [
        ("\"op\":\"submit\"", "\"op\":\"submit\",\"op\":\"submit\""),
        ("\"lease_epoch\":7", "\"lease_epoch\":7,\"lease_epoch\":8"),
        (
            "\"host_trust_gen\":1",
            "\"host_trust_gen\":1,\"host_trust_gen\":1",
        ),
        (
            "\"text\":\"run the tests\"",
            "\"text\":\"run the tests\",\"text\":\"x\"",
        ),
        (
            "\"type\":\"session\"",
            "\"type\":\"session\",\"type\":\"session\"",
        ),
    ] {
        assert!(raw.contains(from), "{from}");
        assert!(
            wire::decode(raw.replace(from, to).as_bytes()).is_err(),
            "{to}"
        );
    }
    // Lone surrogates and invalid UTF-8 inside a message.
    let lone = raw.replace("run the tests", "run \\ud800 tests");
    assert!(wire::decode(lone.as_bytes()).is_err());
    let mut bytes = raw.into_bytes();
    let at = bytes.windows(3).position(|w| w == b"run").unwrap();
    bytes[at] = 0xff;
    assert!(wire::decode(&bytes).is_err());
}

#[test]
fn descriptors_need_every_field() {
    for field in [
        "session_id",
        "process_gen",
        "provider",
        "cwd_label",
        "state",
        "activity",
        "activity_since",
        "controller",
        "capabilities",
        "created_at",
    ] {
        let mut d = descriptor();
        d.as_object_mut().unwrap().remove(field);
        rejects(&session(
            "session_changed",
            json!({"runtime_gen":PG,"runtime_epoch":7,"seq":2,"descriptor":d.clone()}),
        ));
        rejects(&session(
            "sessions",
            json!({"runtime_gen":PG,"runtime_epoch":7,"seq":2,"sessions":[d]}),
        ));
    }
    let mut d = descriptor();
    d["state"] = json!("sleeping");
    rejects(&session(
        "session_changed",
        json!({"runtime_gen":PG,"runtime_epoch":7,"seq":2,"descriptor":d}),
    ));
    let mut d = descriptor();
    d["activity"] = json!("idle");
    rejects(&session(
        "session_changed",
        json!({"runtime_gen":PG,"runtime_epoch":7,"seq":2,"descriptor":d}),
    ));
    // lease_changed.controller is required too (null when nobody holds it).
    let lc = all_ops()[14].clone();
    rejects(&with(lc.clone(), "controller", None));
    rejects(&with(lc, "reason", Some(json!("bored"))));
}

#[test]
fn lease_epoch_presence_follows_mutation_rules() {
    let ops = all_ops();
    rejects(&with(ops[9].clone(), "binding.lease_epoch", Some(json!(1)))); // acquire
    rejects(&with(ops[10].clone(), "binding.lease_epoch", None)); // renew
    rejects(&with(ops[11].clone(), "binding.lease_epoch", None)); // release
    rejects(&with(ops[12].clone(), "binding.lease_epoch", None)); // lease
    rejects(&with(ops[16].clone(), "binding.lease_epoch", None)); // submit
    rejects(&with(
        ops[21].clone(),
        "binding.lease_epoch",
        Some(json!(1)),
    )); // receipt_query
    rejects(&with(ops[9].clone(), "takeover", None));
    // terminal-v1 / chat-v1 bound forms
    rejects(&with(
        ops[25].clone(),
        "binding.lease_epoch",
        Some(json!(1)),
    )); // subscribe
    rejects(&with(ops[26].clone(), "binding.lease_epoch", None)); // input
    rejects(&with(ops[27].clone(), "binding.lease_epoch", None)); // resize
    rejects(&with(ops[28].clone(), "binding.lease_epoch", None)); // stop
    rejects(&with(
        ops[29].clone(),
        "binding.lease_epoch",
        Some(json!(1)),
    )); // chat open
    rejects(&with(ops[30].clone(), "binding.lease_epoch", None)); // chat submit
    rejects(&with(
        ops[26].clone(),
        "binding.target.session_id",
        Some(json!("claude")),
    ));
    rejects(&with(ops[26].clone(), "binding", Some(json!("x"))));
    // A bound legacy op still needs its own fields.
    rejects(&with(ops[26].clone(), "terminal_id", None));
    rejects(&with(ops[30].clone(), "generation", None));
    // A foreign family's binding is shape-checked too.
    let foreign = json!({"type":"agentInput","data":{"kind":"text","text":"x","binding":{"target":target()}}});
    rejects(&foreign);
    // Unbound legacy messages keep their existing shapes.
    rejects(&with(ops[31].clone(), "sequence", Some(json!(-1))));
    rejects(&json!({"type":"terminal","data":{"v":1,"op":"warp"}}));
    rejects(
        &json!({"type":"agentChat","data":{"v":1,"op":"submit","conversationId":"c","agentId":"a"}}),
    );
}

#[test]
fn binding_validator() {
    let b: Binding = serde_json::from_value(binding(Some(7))).unwrap();
    assert!(b.validate(BindingUse::Mutation).is_ok());
    assert!(b.validate(BindingUse::Read).is_err());
    assert_eq!(b.check_family_ids("ses-aaaaaaaaaaaa", Some(PG)), Ok(()));
    assert_eq!(b.check_family_ids("ses-aaaaaaaaaaaa", None), Ok(()));
    assert_eq!(
        b.check_family_ids("ses-aaaaaaaaaaab", Some(PG)),
        Err(ErrorCode::StaleTarget)
    );
    assert_eq!(
        b.check_family_ids("ses-aaaaaaaaaaaa", Some(AG)),
        Err(ErrorCode::StaleTarget)
    );
}

#[test]
fn enums_and_codes() {
    rejects(&session("error", json!({"code":"teapot"})));
    rejects(&with(
        all_ops()[4].clone(),
        "client_kind",
        Some(json!("web")),
    ));
    rejects(&with(
        all_ops()[4].clone(),
        "permissions",
        Some(json!(["view", "root"])),
    ));
    rejects(&with(all_ops()[20].clone(), "state", Some(json!("done"))));
    rejects(&with(
        all_ops()[20].clone(),
        "detail",
        Some(json!("d".repeat(513))),
    ));
    rejects(&with(all_ops()[2].clone(), "nonce", Some(json!("short"))));
    rejects(&with(
        all_ops()[2].clone(),
        "nonce",
        Some(json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+")),
    ));
    rejects(&with(all_ops()[3].clone(), "proof", Some(json!(""))));
    rejects(&with(
        all_ops()[1].clone(),
        "resume.controller_session",
        Some(json!("x")),
    ));
    assert_eq!(
        serde_json::to_value(ErrorCode::RequestIdReused).unwrap(),
        json!("request_id_reused")
    );
}
