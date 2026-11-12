//! Control records through the bindings (delegated host work I.5.3 to
//! I.5.5, I.5.8): the Station builders' exports. Every record of
//! `designs/protocol/fixtures/r9-vectors-host-work-control.json` parses and
//! verifies as the vector says, the builders (a provider, or a signing
//! input and a signature) reproduce it, every sequence runs through
//! `ControlStateHandle` with the vector's per-effect results, standing and
//! state, the state persists (whole, or one part per principal) and loads
//! only for its own device list, and the signing purposes follow the
//! record's signer.
#![cfg(feature = "uniffi")]

#[path = "../../atem-client/tests/support/mod.rs"]
#[allow(unused_imports)]
mod support;

use std::sync::{Arc, Mutex};

use atem_client::KeyProvider as _;
use atem_client::provider::KeyId;
use atem_client_ffi::AtemError;
use atem_client_ffi::control::{
    ControlStateHandle, build_control_record, control_record_signing_input,
    control_record_with_signature, control_state_from_parts, parse_control_record,
    verify_control_record,
};
use atem_client_ffi::log::MembershipLog;
use atem_client_ffi::provider::{AppKeyProvider, ProviderError};
use atem_client_ffi::types::{
    ControlApplied, ControlCheckInfo, ControlEffectKind, ControlFeedPos, ControlHostAction,
    ControlRecordBody, ControlResultKind, ControlStanding, ControlStatePart, HostClock,
    PublicKeyData, SignRequest, SigningPurpose,
};
use serde_json::{Value, json};
use support::*;

const L: [&str; 6] = ["E1", "E2", "E3", "E4", "E5", "E6"];

fn now() -> HostClock {
    HostClock {
        wall_ms: 1_793_264_001_000,
        mono_ms: 1_000,
        boot_id: "boot-1".into(),
    }
}

fn control() -> Value {
    load("r9-vectors-host-work-control")
}

fn wires(v: &Vectors, labels: &[&str]) -> Vec<String> {
    labels.iter().map(|l| v.wire(l).to_string()).collect()
}

/// Log L, then a chain of membership-log labels.
fn log_after(v: &Vectors, chain: &[String]) -> Arc<MembershipLog> {
    let log = MembershipLog::verify(ACCOUNT.into(), genesis_hash().to_hex(), wires(v, &L), now())
        .unwrap();
    let chain: Vec<&str> = chain.iter().map(String::as_str).collect();
    assert_eq!(log.extend(wires(v, &chain), now()).unwrap().stop, None);
    log
}

fn chain_of(v: &Value) -> Vec<String> {
    v["chain"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l.as_str().unwrap().to_owned())
        .collect()
}

fn s(v: &Value) -> String {
    v.as_str().unwrap().to_owned()
}

/// The typed body of a record's body JSON (`None` for a field it can't
/// express: a field the body doesn't have).
fn body_of(body: &Value) -> Option<ControlRecordBody> {
    let o = body.as_object()?;
    let known = [
        "type",
        "v",
        "account_id",
        "genesis_hash",
        "origin",
        "feed_id",
        "principal",
        "principal_key",
        "signer",
        "action",
        "interrupt_running",
        "revoke_seq",
        "record_id",
        "issued_at",
        "about",
    ];
    if !o.keys().all(|k| known.contains(&k.as_str())) {
        return None;
    }
    let text = |k: &str| o.get(k).and_then(Value::as_str).map(str::to_owned);
    Some(ControlRecordBody {
        account_id: text("account_id")?,
        genesis_hash: text("genesis_hash")?,
        origin: text("origin"),
        feed_id: text("feed_id"),
        principal: text("principal")?,
        principal_key: text("principal_key"),
        signer: text("signer")?,
        action: text("action")?,
        interrupt_running: o.get("interrupt_running").and_then(Value::as_bool),
        revoke_seq: o.get("revoke_seq").and_then(Value::as_u64),
        record_id: text("record_id")?,
        issued_at: o["issued_at"].as_u64()?,
        integration_id: body["about"]
            .get("integration_id")
            .and_then(Value::as_str)
            .map(str::to_owned),
        by: body["about"]["by"].as_str()?.to_owned(),
    })
}

/// The test key a vector names: a member's `auth`, or a host's `host_key`.
fn key_id(signed_with: &str) -> String {
    if signed_with.starts_with("host-") {
        format!("{signed_with}/host_key")
    } else {
        format!("{signed_with}/auth")
    }
}

fn result_code(r: ControlResultKind) -> &'static str {
    match r {
        ControlResultKind::Applied => "applied",
        ControlResultKind::Duplicate => "duplicate",
        ControlResultKind::Pending => "pending",
        ControlResultKind::Refused => "refused",
    }
}

fn effect_code(e: ControlEffectKind) -> &'static str {
    match e {
        ControlEffectKind::Revocation => "revocation",
        ControlEffectKind::Interrupt => "interrupt",
        ControlEffectKind::Hold => "hold",
        ControlEffectKind::Release => "release",
        ControlEffectKind::Cover => "cover",
    }
}

/// A step's result as the vectors write it.
fn applied_json(a: &ControlApplied) -> Value {
    let actions: Vec<Value> = a
        .actions
        .iter()
        .map(|action| match action {
            ControlHostAction::Revoke { principal } => {
                json!({"type": "revoke", "principal": principal})
            }
            ControlHostAction::Hold { principal } => json!({"type": "hold", "principal": principal}),
            ControlHostAction::Release { principal } => {
                json!({"type": "release", "principal": principal})
            }
            ControlHostAction::Interrupt {
                principal,
                revocation,
            } => json!({"type": "interrupt", "principal": principal, "revocation": revocation}),
            ControlHostAction::Cover {
                principal,
                origin,
                feed_id,
            } => json!({"type": "cover", "principal": principal, "origin": origin, "feed_id": feed_id}),
        })
        .collect();
    let effects: Vec<Value> = a
        .effects
        .iter()
        .map(|e| json!({"effect": effect_code(e.effect), "result": result_code(e.result)}))
        .collect();
    json!({
        "result": result_code(a.result),
        "effects": effects,
        "actions": actions,
        "evidence": a.evidence,
    })
}

fn verdict_json(chain: &[String], check: &ControlCheckInfo) -> Value {
    match check {
        ControlCheckInfo::Valid {
            signer, key_seq, ..
        } => {
            let mut v = json!({"chain": chain, "verdict": "valid", "signer": signer});
            if let Some(seq) = key_seq {
                v["key_seq"] = (*seq).into();
            }
            v
        }
        ControlCheckInfo::Pending { reason } => {
            json!({"chain": chain, "verdict": "pending", "reason": reason})
        }
        ControlCheckInfo::Refused { reason } => {
            json!({"chain": chain, "verdict": "refused", "reason": reason})
        }
    }
}

fn code(e: AtemError) -> String {
    e.code()
}

/// Every record: its parse (or the parse's refusal), its typed body and
/// its verdict on each chain, with the list's head.
#[test]
fn every_record_parses_and_verifies_as_the_vectors_say() {
    let v = Vectors::load();
    let file = control();
    let mut checked = 0;
    for r in file["records"].as_array().unwrap() {
        let label = r["label"].as_str().unwrap();
        let json = r["record"].to_string();
        if let Some(want) = r.get("parse_error") {
            assert_eq!(
                code(parse_control_record(json.clone()).unwrap_err()),
                s(want),
                "{label}"
            );
            let log = log_after(&v, &[]);
            assert_eq!(
                code(verify_control_record(log, json).unwrap_err()),
                s(want),
                "{label}"
            );
            continue;
        }
        let body = parse_control_record(json.clone()).unwrap();
        assert_eq!(Some(body.clone()), body_of(&r["record"]["body"]), "{label}");
        for c in r["checks"].as_array().unwrap() {
            let chain = chain_of(c);
            let log = log_after(&v, &chain);
            let check = verify_control_record(log.clone(), json.clone()).unwrap();
            assert_eq!(verdict_json(&chain, &check), *c, "{label} on {chain:?}");
            if let ControlCheckInfo::Valid { head, .. } = check {
                assert_eq!(head, log.head(), "{label}");
            }
            checked += 1;
        }
    }
    assert!(checked >= 52, "{checked} verdicts");
    // Not a record at all.
    let log = log_after(&v, &[]);
    assert_eq!(
        code(verify_control_record(log, "{}".into()).unwrap_err()),
        "malformed"
    );
    let entry = v.wire("E2").to_string();
    assert_eq!(code(parse_control_record(entry).unwrap_err()), "wrong_type");
}

/// A provider that records every request and signs with the test book's
/// keys whatever the label (a Station's key store).
struct Recorder {
    book: Book,
    requests: Mutex<Vec<SignRequest>>,
}

impl Recorder {
    fn new() -> Arc<Self> {
        Arc::new(Recorder {
            book: Book::load(),
            requests: Mutex::new(Vec::new()),
        })
    }

    fn last(&self) -> SignRequest {
        self.requests.lock().unwrap().last().unwrap().clone()
    }
}

impl AppKeyProvider for Recorder {
    fn public_key(&self, key_id: String) -> Result<PublicKeyData, ProviderError> {
        let key = self
            .book
            .provider
            .public_key(&KeyId::new(key_id))
            .map_err(|_| ProviderError::UnknownKey)?;
        Ok((&key).into())
    }

    fn sign(&self, request: SignRequest) -> Result<Vec<u8>, ProviderError> {
        self.requests.lock().unwrap().push(request.clone());
        let fields =
            atem_client::encoding::dec(&request.input).map_err(|e| ProviderError::Failed {
                reason: e.to_string(),
            })?;
        assert_eq!(fields[0], b"atem-host-work-control-v1");
        let input =
            atem_client::SigningInput::new(atem_client::SignLabel::HostWorkControl, fields[1]);
        self.book
            .provider
            .sign(&KeyId::new(request.key_id), &input)
            .map_err(|e| ProviderError::Failed {
                reason: e.to_string(),
            })
    }

    fn x25519(&self, _: String, _: Vec<u8>) -> Result<Vec<u8>, ProviderError> {
        Err(ProviderError::UnknownKey)
    }

    fn hpke_open(
        &self,
        _: String,
        _: Vec<u8>,
        _: Vec<u8>,
        _: Vec<u8>,
        _: Vec<u8>,
    ) -> Result<Vec<u8>, ProviderError> {
        Err(ProviderError::UnknownKey)
    }
}

/// The builders reproduce every record byte for byte (deterministic
/// signatures: RFC 6979 P-256, Ed25519), through a provider and through
/// the signing input and a signature; a body the parse refuses is refused
/// with the same code and nothing is signed. The provider is asked under
/// the purpose the signer gives: the service key's own, no confirmation; a
/// native manager's, a fresh confirmation of the body.
#[test]
fn the_builders_reproduce_every_record() {
    let file = control();
    let recorder = Recorder::new();
    let provider: Arc<dyn AppKeyProvider> = recorder.clone();
    let mut built = 0;
    for r in file["records"].as_array().unwrap() {
        let label = r["label"].as_str().unwrap();
        let Some(body) = body_of(&r["record"]["body"]) else {
            assert_eq!(r["parse_error"], "unknown_field", "{label}");
            continue;
        };
        let signer = key_id(r["signed_with"].as_str().unwrap());
        if let Some(want) = r.get("parse_error") {
            let before = recorder.requests.lock().unwrap().len();
            let e = build_control_record(provider.clone(), signer, body.clone()).unwrap_err();
            assert_eq!(code(e), s(want), "{label}");
            assert_eq!(recorder.requests.lock().unwrap().len(), before, "{label}");
            assert_eq!(
                code(control_record_signing_input(body).unwrap_err()),
                s(want),
                "{label}"
            );
            continue;
        }
        let input = control_record_signing_input(body.clone()).unwrap();
        assert_eq!(hex(&input), s(&r["signing_input_hex"]), "{label}");
        let signer_key: PublicKeyData = (&recorder.book.public(&signer)).into();
        let sig = atem_client::encoding::b64u_decode(r["record"]["sig"].as_str().unwrap()).unwrap();
        let assembled = control_record_with_signature(body.clone(), signer_key.clone(), sig);
        if r["checks"][0]["reason"] == "bad_signature" {
            assert_eq!(code(assembled.unwrap_err()), "bad_signature", "{label}");
            continue;
        }
        let canonical = atem_client::canonical::jcs(&r["record"]).unwrap();
        assert_eq!(assembled.unwrap(), canonical, "{label}");
        let made = build_control_record(provider.clone(), signer.clone(), body.clone()).unwrap();
        assert_eq!(made, canonical, "{label}");
        let request = recorder.last();
        let own = r["record"]["body"]["signer"] == r["record"]["body"]["principal"]
            && body.principal.starts_with("service:");
        let purpose = if own {
            SigningPurpose::ServiceControl
        } else {
            SigningPurpose::ControlRecord
        };
        assert_eq!(request.purpose, purpose, "{label}");
        assert_eq!(request.fresh_confirmation, !own, "{label}");
        assert_eq!(request.body_json.as_deref(), r["jcs"].as_str(), "{label}");
        assert_eq!(request.label, "atem-host-work-control-v1");
        built += 1;
    }
    assert!(built >= 44, "{built} built");
    // A malformed field the builder takes: an unsafe integer, an X25519
    // signer, a hex that isn't one.
    let s1 = &file["records"][0];
    let mut body = body_of(&s1["record"]["body"]).unwrap();
    body.issued_at = u64::MAX;
    assert_eq!(
        code(control_record_signing_input(body).unwrap_err()),
        "not_canonical"
    );
    let mut body = body_of(&s1["record"]["body"]).unwrap();
    body.genesis_hash = "not hex".into();
    assert_eq!(
        code(control_record_signing_input(body.clone()).unwrap_err()),
        "malformed"
    );
    let body = body_of(&s1["record"]["body"]).unwrap();
    let x25519 = PublicKeyData {
        alg: atem_client_ffi::types::KeyAlg::X25519,
        raw: vec![9; 32],
    };
    assert_eq!(
        code(control_record_with_signature(body, x25519, vec![0; 64]).unwrap_err()),
        "wrong_alg"
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// What a principal has in force, as the vectors write it.
fn standing_json(standing: &ControlStanding) -> Value {
    let mut v = json!({"held": standing.held, "interrupted": standing.interrupted});
    if let Some(by) = &standing.revoked {
        v["revoked"] = by.as_str().into();
    }
    if let Some(c) = &standing.coverage {
        v["coverage"] = json!({"origin": c.origin, "feed_id": c.feed_id});
    }
    v
}

/// Every principal's part of `state`, as a host stores them.
fn parts_of(state: &ControlStateHandle) -> Vec<ControlStatePart> {
    state
        .principals()
        .into_iter()
        .map(|principal| ControlStatePart {
            part_json: state.part(principal.clone()).unwrap(),
            principal,
        })
        .collect()
}

/// Every sequence through the handle, from its `initial` state when it has
/// one: each step's results and the standing of its record's principal,
/// the parts it touched (exactly the parts that changed), the state as the
/// vector writes it, and the state reloaded whole and from its parts.
#[test]
fn the_sequences_through_the_state_handle() {
    let v = Vectors::load();
    let file = control();
    let records: std::collections::BTreeMap<String, (String, String)> = file["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            let principal = s(&r["record"]["body"]["principal"]);
            (s(&r["label"]), (r["record"].to_string(), principal))
        })
        .collect();
    let l = log_after(&v, &[]);
    for q in file["sequences"].as_array().unwrap() {
        let label = q["label"].as_str().unwrap();
        let mut state = match q.get("initial") {
            Some(initial) => {
                let text = atem_client::canonical::jcs(initial).unwrap();
                ControlStateHandle::from_json(l.clone(), text).unwrap()
            }
            None => ControlStateHandle::new(l.clone()),
        };
        for (i, step) in q["steps"].as_array().unwrap().iter().enumerate() {
            let pos = step.get("pos").map(|p| ControlFeedPos {
                origin: s(&p["origin"]),
                feed_id: s(&p["feed_id"]),
                feed_seq: p["feed_seq"].as_u64().unwrap(),
            });
            let (record, principal) = &records[step["record"].as_str().unwrap()];
            let before = state.to_json();
            let got = state
                .apply(
                    record.clone(),
                    log_after(&v, &chain_of(step)),
                    pos,
                    step["host_applied_seq"].as_u64().unwrap(),
                )
                .unwrap();
            assert_eq!(
                applied_json(&got.applied),
                step["expect"],
                "{label} step {}",
                i + 1
            );
            assert_eq!(
                standing_json(&got.next.standing(principal.clone())),
                step["standing"],
                "{label} step {}",
                i + 1
            );
            let changed = state.part(principal.clone()) != got.next.part(principal.clone());
            let touched: Vec<String> = changed.then(|| principal.clone()).into_iter().collect();
            assert_eq!(got.touched, touched, "{label} step {}", i + 1);
            // The handle applied on is unchanged; the next one goes on.
            assert_eq!(state.to_json(), before, "{label} step {}", i + 1);
            state = got.next;
        }
        let text = atem_client::canonical::jcs(&q["state"]).unwrap();
        assert_eq!(state.to_json(), text, "{label}");
        let back = ControlStateHandle::from_json(l.clone(), text.clone()).unwrap();
        assert_eq!(back.to_json(), text, "{label}");
        let parts = parts_of(&state);
        for part in &parts {
            let want = &q["state"]["principals"][&part.principal];
            assert_eq!(part.part_json, atem_client::canonical::jcs(want).unwrap());
        }
        let back = control_state_from_parts(l.clone(), parts).unwrap();
        assert_eq!(back.state.to_json(), text, "{label}: from its parts");
        assert!(back.foreign.is_empty(), "{label}");
    }
}

/// A state loads from its parts, one per principal in any order, exactly
/// as written and only for its own device list (each part names its
/// account and genesis: another list's parts, an earlier pairing's
/// leftovers, are skipped and reported, never loaded): a principal given
/// twice, a part that isn't strict JSON, out of its kind's form, whose
/// device list can't be read or not exactly as `part` writes it, or parts
/// larger in all than a whole state may be, are refused.
#[test]
fn the_state_loads_from_its_parts_only_as_written() {
    let v = Vectors::load();
    let file = control();
    let l = log_after(&v, &[]);
    // Q17 holds a service's part and a host principal's.
    let q = file["sequences"]
        .as_array()
        .unwrap()
        .iter()
        .find(|q| q["label"] == "Q17_record_ids_per_principal")
        .unwrap();
    let state =
        ControlStateHandle::from_json(l.clone(), atem_client::canonical::jcs(&q["state"]).unwrap())
            .unwrap();
    let parts = parts_of(&state);
    assert_eq!(
        parts
            .iter()
            .map(|p| p.principal.as_str())
            .collect::<Vec<_>>(),
        ["host:host-a", "service:svc-discord"]
    );
    let reversed: Vec<_> = parts.iter().rev().cloned().collect();
    assert_eq!(
        control_state_from_parts(l.clone(), reversed)
            .unwrap()
            .state
            .to_json(),
        state.to_json()
    );
    assert_eq!(
        control_state_from_parts(l.clone(), Vec::new())
            .unwrap()
            .state
            .to_json(),
        ControlStateHandle::new(l.clone()).to_json()
    );
    assert_eq!(state.part("service:svc-other".into()), None);
    let stored = |e: AtemError| match e {
        AtemError::Stored { code, .. } => code,
        other => panic!("{other:?}"),
    };
    let load = |parts: Vec<ControlStatePart>| {
        control_state_from_parts(l.clone(), parts)
            .map(|_| ())
            .map_err(stored)
    };
    let with = |principal: &str, part_json: &str| ControlStatePart {
        principal: principal.into(),
        part_json: part_json.into(),
    };
    let host = parts[0].part_json.clone();
    let svc = parts[1].part_json.clone();
    let cases: Vec<(Vec<ControlStatePart>, &str)> = vec![
        (vec![parts[1].clone(), parts[1].clone()], "stored_invalid"),
        (vec![with("service:svc-discord", "{")], "malformed"),
        (vec![with("service:svc-discord", &host)], "stored_invalid"),
        (vec![with("host:host-a", &svc)], "stored_invalid"),
        (vec![with("svc-discord", &svc)], "stored_invalid"),
        (vec![with("member:dev-mac", &host)], "stored_invalid"),
        (
            vec![with(
                "service:svc-discord",
                &svc.replace("\"held\":false", "\"held\":0"),
            )],
            "stored_invalid",
        ),
        (
            vec![with(
                "host:host-a",
                &" ".repeat(atem_client_ffi::control::MAX_CONTROL_STATE_JSON + 1),
            )],
            "too_large",
        ),
        // A part whose device list can't be read might be this list's.
        (
            vec![with(
                "host:host-a",
                &host.replace(&genesis_hash().to_hex(), "zz"),
            )],
            "stored_invalid",
        ),
    ];
    for (parts, want) in cases {
        assert_eq!(load(parts.clone()), Err(want.to_owned()), "{parts:?}");
    }
    // Parts of another account or genesis (an earlier pairing's leftovers)
    // are skipped and reported, beside this list's, whose stops load.
    let other_account = with(
        "service:svc-discord",
        &svc.replace("\"acct-test-1\"", "\"acct-other\""),
    );
    let other_genesis = with(
        "host:host-a",
        &host.replace(&genesis_hash().to_hex(), &"11".repeat(32)),
    );
    let loaded =
        control_state_from_parts(l.clone(), vec![parts[1].clone(), other_genesis]).unwrap();
    assert_eq!(loaded.foreign, ["host:host-a"]);
    assert_eq!(
        loaded.state.principals(),
        ["service:svc-discord"],
        "this list's part loaded"
    );
    assert_eq!(
        loaded.state.part("service:svc-discord".into()),
        Some(svc.clone())
    );
    let loaded = control_state_from_parts(l.clone(), vec![other_account]).unwrap();
    assert_eq!(loaded.foreign, ["service:svc-discord"]);
    assert_eq!(
        loaded.state.to_json(),
        ControlStateHandle::new(l.clone()).to_json()
    );
    // Re-paired (another genesis): the old list's parts load into nothing,
    // every key reported for deletion.
    let other = MembershipLog::verify(
        ACCOUNT.into(),
        v.hash("SUB1").to_hex(),
        wires(&v, &["SUB1", "SUB2", "SUB3"]),
        now(),
    )
    .unwrap();
    let loaded = control_state_from_parts(other.clone(), parts).unwrap();
    assert_eq!(loaded.foreign, ["host:host-a", "service:svc-discord"]);
    assert_eq!(
        loaded.state.to_json(),
        ControlStateHandle::new(other).to_json()
    );
}

/// A state loads only for its own device list, exactly as written; the
/// handle refuses an unsafe position and applies nothing for another list.
#[test]
fn the_state_loads_only_as_written_for_its_own_list() {
    let v = Vectors::load();
    let file = control();
    let l = log_after(&v, &[]);
    let q1 = &file["sequences"][0]["state"];
    let text = atem_client::canonical::jcs(q1).unwrap();
    let load = |text: String| ControlStateHandle::from_json(l.clone(), text).map(|_| ());
    let stored = |e: AtemError| match e {
        AtemError::Stored { code, .. } => code,
        other => panic!("{other:?}"),
    };
    assert_eq!(load(text.clone()), Ok(()));
    let edit = |f: &dyn Fn(&mut Value)| {
        let mut state = q1.clone();
        f(&mut state);
        atem_client::canonical::jcs(&state).unwrap()
    };
    let cases: [(String, &str); 10] = [
        ("[".into(), "malformed"),
        ("[]".into(), "malformed"),
        (
            edit(&|s| drop(s.as_object_mut().unwrap().remove("v"))),
            "malformed",
        ),
        // The format before parts per principal.
        (edit(&|s| s["v"] = 1.into()), "unsupported_version"),
        (edit(&|s| s["v"] = 3.into()), "unsupported_version"),
        (
            edit(&|s| s["account_id"] = "acct-other".into()),
            "account_mismatch",
        ),
        (
            edit(&|s| s["genesis_hash"] = "00".repeat(32).into()),
            "genesis_mismatch",
        ),
        // The state's own rules: an interrupt without its revocation.
        (
            edit(&|s| {
                s["principals"]["service:svc-discord"]
                    .as_object_mut()
                    .unwrap()
                    .remove("revoked_by");
            }),
            "stored_invalid",
        ),
        // Host seqs out of their strict order.
        (
            edit(&|s| {
                s["principals"]["host:host-a"] = json!({
                    "account_id": ACCOUNT, "genesis_hash": genesis_hash().to_hex(),
                    "interrupted": [7, 7],
                    "records": [["00000000-0000-4000-8000-000000000001", "11".repeat(32), 1]],
                })
            }),
            "stored_invalid",
        ),
        // More record ids than a principal keeps.
        (
            edit(&|s| {
                let ids: Vec<Value> = (0..=atem_client::control::MAX_RECORD_IDS)
                    .map(|n| {
                        json!([
                            format!("00000000-0000-4000-8000-{n:012x}"),
                            "11".repeat(32),
                            1
                        ])
                    })
                    .collect();
                s["principals"]["host:host-a"] = json!({
                    "account_id": ACCOUNT, "genesis_hash": genesis_hash().to_hex(), "records": ids,
                });
            }),
            "stored_invalid",
        ),
    ];
    for (text, want) in cases {
        assert_eq!(
            load(text.clone()).map_err(stored),
            Err(want.to_owned()),
            "{text}"
        );
    }
    let big = " ".repeat(atem_client_ffi::control::MAX_CONTROL_STATE_JSON + 1);
    assert_eq!(load(big).map_err(stored), Err("too_large".to_owned()));
    // Another device list: the substitute chain's genesis.
    let other = MembershipLog::verify(
        ACCOUNT.into(),
        v.hash("SUB1").to_hex(),
        wires(&v, &["SUB1", "SUB2", "SUB3"]),
        now(),
    )
    .unwrap();
    assert_eq!(
        ControlStateHandle::from_json(other.clone(), text)
            .map(|_| ())
            .map_err(stored),
        Err("genesis_mismatch".to_owned())
    );
    let s1 = file["records"][0]["record"].to_string();
    let state = ControlStateHandle::new(l.clone());
    let refused = state.apply(s1.clone(), other, None, 6).unwrap().applied;
    assert_eq!(refused.result, ControlResultKind::Refused);
    assert!(!refused.evidence && refused.actions.is_empty());
    // A position above 2^53 - 1 never enters the state.
    let station = &file["stations"]["A"];
    let unsafe_pos = ControlFeedPos {
        origin: s(&station["origin"]),
        feed_id: s(&station["feed_id"]),
        feed_seq: u64::MAX,
    };
    assert_eq!(
        code(state.apply(s1, l, Some(unsafe_pos), 6).unwrap_err()),
        "not_canonical"
    );
    assert_eq!(
        state.to_json(),
        ControlStateHandle::new(log_after(&v, &[])).to_json()
    );
}

/// A failed persistence transaction loses no effect (PR 3 review I4): the
/// handle `apply` was called on is unchanged until the caller adopts the
/// next state, so applying the same record again (after the caller's
/// transaction failed) gives the same results and actions; once the next
/// state is adopted, the record is a duplicate.
#[test]
fn a_failed_commit_loses_no_effect() {
    let v = Vectors::load();
    let file = control();
    let l = log_after(&v, &[]);
    let record = |label: &str| {
        file["records"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["label"] == label)
            .unwrap()["record"]
            .to_string()
    };
    let station = &file["stations"]["A"];
    let pos = |n| {
        Some(ControlFeedPos {
            origin: s(&station["origin"]),
            feed_id: s(&station["feed_id"]),
            feed_seq: n,
        })
    };
    let state = ControlStateHandle::new(l.clone());
    let before = state.to_json();
    let first = state
        .apply(record("S5_revoke_interrupt"), l.clone(), pos(1), 6)
        .unwrap();
    assert_eq!(first.applied.actions.len(), 2);
    // The caller's transaction failed: nothing was stored, and the state
    // it applies on next is the one it had.
    assert_eq!(state.to_json(), before);
    let again = state
        .apply(record("S5_revoke_interrupt"), l.clone(), pos(1), 6)
        .unwrap();
    assert_eq!(again.applied, first.applied);
    assert_eq!(again.next.to_json(), first.next.to_json());
    // Committed this time: the next state goes on from it.
    let state = again.next;
    let after = state
        .apply(record("S5_revoke_interrupt"), l, pos(1), 6)
        .unwrap();
    assert_eq!(after.applied.result, ControlResultKind::Duplicate);
    assert!(after.applied.actions.is_empty());
}
