//! A native manager's Station binding proof (`atem_client::station_binding`;
//! delegated host-work III.5 (b), Atem's answer on #120 comment 7207827118,
//! owner decision 2026-11-27: unbind needs the same proof) beyond the shared
//! vectors: each action signed and verified, every refusal at its place in
//! the verifier's and the builder's order, the challenge's grammar and the
//! per-action rules, the body compared with the stored challenge on its
//! `jcs`, a demoted or removed manager, an ancestor head, a frozen log, the
//! held body's signature and the label. The vectors
//! (`r9-vectors-station-binding`) run in `station_binding.rs`.
mod support;

use atem_client::canonical::jcs;
use atem_client::domain::{SignLabel, SigningInput};
use atem_client::encoding::{b64u, b64u_decode};
use atem_client::member_report::ReportRefusal;
use atem_client::membership::{
    Action, Head, HostRecord, Membership, Role, RolesChange, sign_entry,
};
use atem_client::provider::sign;
use atem_client::station_binding::{
    AuthClaims, BINDING_BUILD_ORDER, BINDING_VERIFY_ORDER, BindingAction, BindingRecord,
    ExpectedBinding, StationBindingChallenge, sign_station_binding, station_binding_request,
    verify_station_binding,
};
use atem_client::{KeyId, SignedObject, SoftwareKeys};
use serde_json::{Value, json};
use support::*;

const STATION: &str = "https://station-dev.agora.build";
const OTHER_STATION: &str = "https://station.agora.build";
const ISSUER: &str = "https://auth.dev.agora.build";
const OWNER_A: &str = "ab00000000000000000000000001";
const OWNER_B: &str = "ab00000000000000000000000002";
const PHONE: &str = "member:dev-phone";
/// The verifier's and the signer's clock: after log L's entries.
const NOW: u64 = 1_793_264_001_000;
const ISSUED: u64 = 1_793_264_000_000;
const EXPIRES: u64 = ISSUED + 30_000;
/// The token's `auth_time`, in seconds: ten minutes before the challenge.
const AUTH_TIME: u64 = ISSUED / 1000 - 600;

fn log_l(v: &Vectors) -> Membership {
    let entries = v.entries(&["E1", "E2", "E3", "E4", "E5", "E6"]);
    Membership::verify_chain(ACCOUNT, &v.hash("E1"), &entries, &Clock::at(NOW).now)
        .unwrap()
        .membership
}

/// The log after `log` with an entry `action` by dev-mac, signed at `at`.
fn after(book: &SoftwareKeys, log: &Membership, action: Action, at: u64) -> Membership {
    let body = log.draft("dev-mac", at, &action);
    let entry = sign_entry(book, &KeyId::new("dev-mac/auth"), body).unwrap();
    let eval = log.evaluate_objects(&[entry.object().clone()], &Clock::at(NOW).now);
    assert!(eval.changed(log), "the entry applies");
    eval.next
}

/// dev-phone's roles set to `roles` on `log`, by an entry signed a second
/// after `log`'s newest.
fn phone_roles(book: &SoftwareKeys, log: &Membership, roles: &[Role]) -> Membership {
    let at = log.entries().last().unwrap().signed_at + 1_000;
    after(
        book,
        log,
        Action::SetRoles {
            device_id: "dev-phone".into(),
            change: RolesChange::Native(roles.iter().copied().collect()),
        },
        at,
    )
}

/// A later head of `log`, every member unchanged: host-b added, by dev-mac.
fn later(book: &Book, log: &Membership) -> Membership {
    let at = log.entries().last().unwrap().signed_at + 1_000;
    after(
        &book.provider,
        log,
        Action::AddHost {
            host: HostRecord {
                host_id: "host-b".into(),
                host_trust_gen: 1,
                host_key: book.public("host-b/host_key"),
            },
        },
        at,
    )
}

fn claims(subject: &str) -> AuthClaims {
    AuthClaims {
        issuer: ISSUER.into(),
        subject: subject.into(),
        auth_time: AUTH_TIME,
    }
}

fn record(version: u64, owner: &str) -> BindingRecord {
    BindingRecord {
        binding_id: "bind-1".into(),
        version,
        owner: owner.into(),
    }
}

/// The challenge fields a Station mints for `action` at `log`'s head, as an
/// object (its nonce fixed).
fn fields(log: &Membership, action: &str, subject: &str, expected: Value) -> Value {
    json!({
        "type": "atem-station-binding", "v": 1, "action": action, "origin": STATION,
        "issuer": ISSUER, "subject": subject, "auth_time": AUTH_TIME,
        "account_id": log.account_id(), "genesis_hash": log.genesis_hash().to_hex(),
        "head": log.head().to_json(), "signer": PHONE, "expected_binding": expected,
        "nonce": b64u(&[7u8; 32]), "issued_at": ISSUED, "expires_at": EXPIRES,
    })
}

fn never_bound() -> Value {
    json!({"state": "never_bound"})
}

fn bound(owner: &str) -> Value {
    json!({"state": "bound", "binding_id": "bind-1", "version": 2, "owner": owner})
}

/// A bind of `log`'s account to OWNER_A, never bound before.
fn bind_fields(log: &Membership) -> Value {
    fields(log, "bind", OWNER_A, never_bound())
}

fn with(mut value: Value, path: &str, to: Value) -> Value {
    let mut at = &mut value;
    for part in path.split('.') {
        at = &mut at[part];
    }
    *at = to;
    value
}

fn challenge_of(fields: &Value) -> StationBindingChallenge {
    StationBindingChallenge::parse(fields.to_string().as_bytes())
        .unwrap_or_else(|e| panic!("{e}: {fields}"))
}

fn read(fields: &Value) -> Result<StationBindingChallenge, ReportRefusal> {
    StationBindingChallenge::parse(fields.to_string().as_bytes())
}

/// `{"body":<jcs(body)>,"sig":…}` signed by `key` under `label`, with no
/// check of the body.
fn signed_as(keys: &SoftwareKeys, key: &str, label: SignLabel, body: &Value) -> String {
    let text = jcs(body).unwrap();
    let sig = sign(
        keys,
        &KeyId::new(key),
        &SigningInput::new(label, text.as_bytes()),
    )
    .unwrap();
    format!(r#"{{"body":{text},"sig":"{}"}}"#, b64u(&sig))
}

fn signed(keys: &SoftwareKeys, key: &str, body: &Value) -> String {
    signed_as(keys, key, SignLabel::StationBinding, body)
}

fn verify(
    log: &Membership,
    proof: &str,
    expected: &StationBindingChallenge,
    now_ms: u64,
) -> Result<atem_client::station_binding::VerifiedStationBinding, ReportRefusal> {
    verify_station_binding(log, proof.as_bytes(), expected, now_ms)
}

fn code<T>(r: Result<T, ReportRefusal>) -> Result<(), &'static str> {
    r.map(|_| ()).map_err(|e| e.code())
}

#[test]
fn a_manager_signs_each_action_and_the_station_verifies_it() {
    let (v, book) = (Vectors::load(), Book::load());
    let keys = &book.provider;
    let log = log_l(&v);
    for (action, subject, expected) in [
        (BindingAction::Bind, OWNER_A, ExpectedBinding::NeverBound),
        (
            BindingAction::Bind,
            OWNER_B,
            ExpectedBinding::Unbound(record(3, OWNER_A)),
        ),
        (
            BindingAction::Bind,
            OWNER_A,
            ExpectedBinding::Unbound(record(3, OWNER_A)),
        ),
        (
            BindingAction::Bind,
            OWNER_B,
            ExpectedBinding::Released(record(4, OWNER_A)),
        ),
        (
            BindingAction::Transfer,
            OWNER_B,
            ExpectedBinding::Bound(record(1, OWNER_A)),
        ),
        (
            BindingAction::Unbind,
            OWNER_A,
            ExpectedBinding::Bound(record(2, OWNER_A)),
        ),
    ] {
        let challenge = StationBindingChallenge::new(
            action,
            "https://Station-Dev.agora.build/",
            &claims(subject),
            log.account_id(),
            log.genesis_hash(),
            log.head(),
            PHONE,
            expected.clone(),
            ISSUED,
            EXPIRES,
        )
        .unwrap();
        assert_eq!(challenge.origin(), STATION, "the origin normalized");
        let request =
            station_binding_request(&log, &challenge, PHONE, STATION, &claims(subject), NOW)
                .unwrap();
        assert_eq!(
            request.body_json(),
            challenge.jcs(),
            "the body is the challenge"
        );
        assert_eq!(
            request.signing_input(),
            SigningInput::new(SignLabel::StationBinding, challenge.jcs().as_bytes())
        );
        let proof = sign_station_binding(keys, &KeyId::new("dev-phone/auth"), &request).unwrap();
        let text = jcs(&proof.to_json()).unwrap();
        let verified = verify(&log, &text, &challenge, NOW).unwrap();
        assert_eq!(verified.action, action);
        assert_eq!(verified.signer, PHONE);
        assert_eq!(verified.head, log.head());
        assert!(verified.at_head);
        assert_eq!(verified.account_id, ACCOUNT);
        assert_eq!(verified.genesis_hash, log.genesis_hash());
        assert_eq!(verified.issuer, ISSUER);
        assert_eq!(verified.subject, subject);
        assert_eq!(verified.auth_time, AUTH_TIME);
        assert_eq!(verified.expected_binding, expected);
        assert_eq!(&verified.nonce, challenge.nonce());
        assert_eq!(verified.expires_at, EXPIRES);
    }
}

/// A head whose `seq` is beyond the safe integers is the head's own
/// malformed part, minted or read.
#[test]
fn a_head_beyond_the_safe_integers_is_malformed() {
    let v = Vectors::load();
    let log = log_l(&v);
    let head = Head {
        seq: atem_client::canonical::MAX_SAFE_INTEGER + 1,
        hash: log.head().hash,
    };
    assert_eq!(
        StationBindingChallenge::new(
            BindingAction::Bind,
            STATION,
            &claims(OWNER_A),
            log.account_id(),
            log.genesis_hash(),
            head,
            PHONE,
            ExpectedBinding::NeverBound,
            ISSUED,
            EXPIRES,
        ),
        Err(ReportRefusal::Malformed("head"))
    );
    let text = bind_fields(&log)
        .to_string()
        .replacen(r#""seq":6"#, r#""seq":9007199254740991"#, 1);
    assert!(StationBindingChallenge::parse(text.as_bytes()).is_ok());
}

/// Two challenges minted with the same terms differ in their nonce: 32
/// bytes from the operating system's CSPRNG.
#[test]
fn each_minted_challenge_has_a_fresh_nonce() {
    let v = Vectors::load();
    let log = log_l(&v);
    let mint = || {
        StationBindingChallenge::new(
            BindingAction::Bind,
            STATION,
            &claims(OWNER_A),
            log.account_id(),
            log.genesis_hash(),
            log.head(),
            PHONE,
            ExpectedBinding::NeverBound,
            ISSUED,
            EXPIRES,
        )
        .unwrap()
    };
    let (a, b) = (mint(), mint());
    assert_ne!(a.nonce(), b.nonce());
    assert_eq!(a.nonce().len(), 32);
    // What the Station stores reads back exactly.
    assert_eq!(
        StationBindingChallenge::parse(a.jcs().as_bytes()).unwrap(),
        a
    );
    // A term outside its grammar mints nothing.
    assert_eq!(
        code(StationBindingChallenge::new(
            BindingAction::Transfer,
            STATION,
            &claims(OWNER_A),
            log.account_id(),
            log.genesis_hash(),
            log.head(),
            PHONE,
            ExpectedBinding::Bound(record(1, OWNER_A)),
            ISSUED,
            EXPIRES,
        )),
        Err("malformed"),
        "a transfer to the current owner"
    );
}

/// The orders of Atem's answer (#120 comment 7207827118): Atem's proposal,
/// for Astation's agreement.
#[test]
fn the_orders_are_atems_proposal() {
    assert_eq!(
        BINDING_VERIFY_ORDER,
        [
            "malformed",
            "frozen",
            "wrong_account",
            "unknown_signer",
            "not_a_manager",
            "bad_signature",
            "stale_log",
            "fork",
            "challenge_mismatch",
            "expired",
        ]
    );
    assert_eq!(
        BINDING_BUILD_ORDER,
        [
            "malformed",
            "frozen",
            "wrong_account",
            "origin_mismatch",
            "signer_mismatch",
            "unknown_signer",
            "not_a_manager",
            "stale_log",
            "fork",
            "binding_mismatch",
            "expired",
        ]
    );
}

/// Each refusal of the verifier where the order puts it: a proof that fails
/// two checks gets the earlier code.
#[test]
fn every_verifier_refusal_at_its_place_in_the_order() {
    let (v, book) = (Vectors::load(), Book::load());
    let keys = &book.provider;
    let log = log_l(&v);
    let good = bind_fields(&log);
    let stored = challenge_of(&good);
    let text = signed(keys, "dev-phone/auth", &good);
    assert!(verify(&log, &text, &stored, NOW).is_ok());

    // malformed before frozen: the proof doesn't read, the list is frozen.
    let frozen = log
        .evaluate(&[strict(v.wire("C6_mac"))], &Clock::at(NOW).now)
        .next;
    assert!(frozen.frozen().is_some());
    let unreadable = text.replacen(r#""v":1"#, r#""v":2"#, 1);
    assert_eq!(
        code(verify(&frozen, &unreadable, &stored, NOW)),
        Err("malformed")
    );
    // frozen before wrong_account.
    let other_account = signed(
        keys,
        "dev-phone/auth",
        &with(good.clone(), "account_id", json!("acct-other")),
    );
    assert_eq!(code(verify(&frozen, &text, &stored, NOW)), Err("frozen"));
    assert_eq!(
        code(verify(&frozen, &other_account, &stored, NOW)),
        Err("frozen")
    );
    // wrong_account before unknown_signer: another account, by dev-evil.
    let evil_other = signed(
        keys,
        "dev-evil/auth",
        &with(
            with(good.clone(), "account_id", json!("acct-other")),
            "signer",
            json!("member:dev-evil"),
        ),
    );
    assert_eq!(
        code(verify(&log, &evil_other, &stored, NOW)),
        Err("wrong_account")
    );
    assert_eq!(
        code(verify(
            &log,
            &signed(
                keys,
                "dev-phone/auth",
                &with(good.clone(), "genesis_hash", json!(v.hash("SUB1").to_hex())),
            ),
            &stored,
            NOW
        )),
        Err("wrong_account")
    );
    // unknown_signer before bad_signature: dev-evil's body signed by
    // dev-phone.
    let evil = with(good.clone(), "signer", json!("member:dev-evil"));
    assert_eq!(
        code(verify(
            &log,
            &signed(keys, "dev-phone/auth", &evil),
            &stored,
            NOW
        )),
        Err("unknown_signer")
    );
    // not_a_manager before bad_signature: dev-phone demoted to [control,
    // view], its proof signed by dev-mac's key.
    let demoted = phone_roles(&book.provider, &log, &[Role::Control, Role::View]);
    assert_eq!(
        code(verify(&demoted, &text, &stored, NOW)),
        Err("not_a_manager")
    );
    assert_eq!(
        code(verify(
            &demoted,
            &signed(keys, "dev-mac/auth", &good),
            &stored,
            NOW
        )),
        Err("not_a_manager")
    );
    // bad_signature before stale_log: a head beyond the list, signed by
    // another key.
    let ahead = with(good.clone(), "head", later(&book, &log).head().to_json());
    assert_eq!(
        code(verify(
            &log,
            &signed(keys, "dev-mac/auth", &ahead),
            &stored,
            NOW
        )),
        Err("bad_signature")
    );
    assert_eq!(
        code(verify(
            &log,
            &signed(keys, "dev-phone/auth", &ahead),
            &stored,
            NOW
        )),
        Err("stale_log")
    );
    // fork, then challenge_mismatch, then expired.
    let fork = with(good.clone(), "head.hash", json!(v.hash("C6_ipad").to_hex()));
    assert_eq!(
        code(verify(
            &log,
            &signed(keys, "dev-phone/auth", &fork),
            &stored,
            NOW
        )),
        Err("fork")
    );
    let other_nonce = challenge_of(&with(good.clone(), "nonce", json!(b64u(&[8u8; 32]))));
    assert_eq!(
        code(verify(&log, &text, &other_nonce, EXPIRES)),
        Err("challenge_mismatch"),
        "challenge_mismatch before expired"
    );
    assert_eq!(code(verify(&log, &text, &stored, EXPIRES)), Err("expired"));
    assert_eq!(
        code(verify(&log, &text, &stored, EXPIRES + 1)),
        Err("expired")
    );
    assert!(verify(&log, &text, &stored, EXPIRES - 1).is_ok());
}

/// Each refusal of the builder where the order puts it.
#[test]
fn every_builder_refusal_at_its_place_in_the_order() {
    let (v, book) = (Vectors::load(), Book::load());
    let log = log_l(&v);
    let good = bind_fields(&log);
    let build =
        |log: &Membership, fields: &Value, signer: &str, station: &str, auth: &AuthClaims, now| {
            code(station_binding_request(
                log,
                &challenge_of(fields),
                signer,
                station,
                auth,
                now,
            ))
        };
    let a = claims(OWNER_A);
    assert_eq!(build(&log, &good, PHONE, STATION, &a, NOW), Ok(()));
    assert_eq!(
        build(
            &log,
            &good,
            PHONE,
            "https://STATION-dev.agora.build:443/",
            &a,
            NOW
        ),
        Ok(()),
        "the configured Station normalized"
    );
    // malformed: the builder's own inputs outside their grammar.
    let frozen = log
        .evaluate(&[strict(v.wire("C6_mac"))], &Clock::at(NOW).now)
        .next;
    for signer in ["service:svc-discord", "host:host-a", "dev-phone", "member:"] {
        assert_eq!(
            build(&frozen, &good, signer, STATION, &a, NOW),
            Err("malformed"),
            "{signer}"
        );
    }
    assert_eq!(
        build(
            &frozen,
            &good,
            PHONE,
            "ftp://station-dev.agora.build",
            &a,
            NOW
        ),
        Err("malformed")
    );
    for bad in [
        AuthClaims {
            issuer: String::new(),
            ..claims(OWNER_A)
        },
        AuthClaims {
            subject: "a b".into(),
            ..claims(OWNER_A)
        },
        AuthClaims {
            subject: "s".repeat(257),
            ..claims(OWNER_A)
        },
        AuthClaims {
            auth_time: 1 << 53,
            ..claims(OWNER_A)
        },
    ] {
        assert_eq!(
            build(&frozen, &good, PHONE, STATION, &bad, NOW),
            Err("malformed"),
            "{bad:?}"
        );
    }
    // frozen before wrong_account.
    let other = with(good.clone(), "account_id", json!("acct-other"));
    assert_eq!(
        build(&frozen, &other, PHONE, STATION, &a, NOW),
        Err("frozen")
    );
    // wrong_account before origin_mismatch.
    assert_eq!(
        build(&log, &other, PHONE, OTHER_STATION, &a, NOW),
        Err("wrong_account")
    );
    let other_genesis = with(good.clone(), "genesis_hash", json!(v.hash("SUB1").to_hex()));
    assert_eq!(
        build(&log, &other_genesis, PHONE, STATION, &a, NOW),
        Err("wrong_account")
    );
    // origin_mismatch before signer_mismatch.
    let mac = with(good.clone(), "signer", json!("member:dev-mac"));
    assert_eq!(
        build(&log, &mac, PHONE, OTHER_STATION, &a, NOW),
        Err("origin_mismatch")
    );
    assert_eq!(
        build(
            &log,
            &good,
            PHONE,
            "https://station-dev.agora.build:8443",
            &a,
            NOW
        ),
        Err("origin_mismatch")
    );
    // signer_mismatch before unknown_signer.
    assert_eq!(
        build(&log, &mac, "member:dev-ipad", STATION, &a, NOW),
        Err("signer_mismatch")
    );
    assert_eq!(
        build(&log, &mac, PHONE, STATION, &a, NOW),
        Err("signer_mismatch")
    );
    // unknown_signer: removed, never added, a service named as a member.
    for id in [
        "member:dev-ipad",
        "member:dev-evil",
        "member:svc-discord",
        "member:recovery",
    ] {
        let theirs = with(good.clone(), "signer", json!(id));
        assert_eq!(
            build(&log, &theirs, id, STATION, &a, NOW),
            Err("unknown_signer"),
            "{id}"
        );
    }
    // not_a_manager before stale_log, unknown_signer before stale_log:
    // the signer's standing is read before the challenge's head, so a
    // demoted or removed signer fails on its standing even when the Station
    // is ahead too.
    let demoted = phone_roles(&book.provider, &log, &[Role::View]);
    let ahead_of_l = with(good.clone(), "head", demoted.head().to_json());
    assert_eq!(
        build(&demoted, &good, PHONE, STATION, &a, NOW),
        Err("not_a_manager")
    );
    let beyond_demoted = with(
        good.clone(),
        "head",
        later(&book, &demoted).head().to_json(),
    );
    assert_eq!(
        build(&demoted, &beyond_demoted, PHONE, STATION, &a, NOW),
        Err("not_a_manager"),
        "demoted, and the Station ahead of it"
    );
    let ipad_ahead = with(
        with(good.clone(), "signer", json!("member:dev-ipad")),
        "head",
        later(&book, &log).head().to_json(),
    );
    assert_eq!(
        build(&log, &ipad_ahead, "member:dev-ipad", STATION, &a, NOW),
        Err("unknown_signer"),
        "removed, and the Station ahead of it"
    );
    assert_eq!(
        build(&log, &ahead_of_l, PHONE, STATION, &a, NOW),
        Err("stale_log"),
        "a Station ahead of the signer: fetch first"
    );
    let fork = with(good.clone(), "head.hash", json!(v.hash("C6_ipad").to_hex()));
    assert_eq!(build(&log, &fork, PHONE, STATION, &a, NOW), Err("fork"));
    // stale_log before binding_mismatch, binding_mismatch before expired.
    assert_eq!(
        build(&log, &ahead_of_l, PHONE, STATION, &claims(OWNER_B), NOW),
        Err("stale_log")
    );
    for other in [
        AuthClaims {
            issuer: "https://auth.agora.build".into(),
            ..claims(OWNER_A)
        },
        claims(OWNER_B),
        AuthClaims {
            auth_time: AUTH_TIME + 1,
            ..claims(OWNER_A)
        },
    ] {
        assert_eq!(
            build(&log, &good, PHONE, STATION, &other, EXPIRES),
            Err("binding_mismatch"),
            "{other:?}"
        );
    }
    assert_eq!(
        build(&log, &good, PHONE, STATION, &a, EXPIRES),
        Err("expired")
    );
    assert_eq!(build(&log, &good, PHONE, STATION, &a, EXPIRES - 1), Ok(()));
    // An ancestor head builds: the signer's list moved on since the
    // Station's.
    assert_eq!(
        build(&later(&book, &log), &good, PHONE, STATION, &a, NOW),
        Ok(())
    );
}

/// The challenge is exactly its fifteen fields, each in its grammar.
#[test]
fn a_challenge_is_exactly_its_fields() {
    let v = Vectors::load();
    let log = log_l(&v);
    let good = bind_fields(&log);
    let ok = read(&good).unwrap();
    assert_eq!(ok.to_json(), good);
    assert_eq!(ok.jcs(), jcs(&good).unwrap());
    assert_eq!(ok.action(), BindingAction::Bind);
    assert_eq!(ok.signer(), PHONE);
    assert_eq!(ok.head(), log.head());
    for field in good.as_object().unwrap().keys() {
        let mut missing = good.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert_eq!(code(read(&missing)), Err("malformed"), "missing {field}");
        assert_eq!(
            code(read(&with(good.clone(), field, Value::Null))),
            Err("malformed"),
            "{field} null"
        );
    }
    assert_eq!(
        code(read(&with(good.clone(), "note", json!("x")))),
        Err("malformed")
    );
    assert_eq!(
        code(read(&with(good.clone(), "head.note", json!(1)))),
        Err("malformed")
    );
    assert_eq!(
        code(read(&with(
            good.clone(),
            "expected_binding.binding_id",
            json!("bind-1")
        ))),
        Err("malformed"),
        "never_bound has the state alone"
    );
    let compact = good.to_string();
    for text in [
        compact.replacen('{', r#"{"subject":"ab1","#, 1),
        compact.replacen('{', r#"{"\u0073ubject":"ab1","#, 1),
        compact.replacen(r#""seq":"#, r#""seq":5,"seq":"#, 1),
        format!("[{compact}]"),
        compact.replacen(',', &format!("{},", " ".repeat(4096)), 1),
        compact.replacen(r#""v":1"#, r#""v":1.0"#, 1),
    ] {
        assert_eq!(
            code(StationBindingChallenge::parse(text.as_bytes())),
            Err("malformed"),
            "{text:.80}"
        );
    }
    let printable_256: String = (0..256).map(|i| (b'!' + (i % 94) as u8) as char).collect();
    let goods: Vec<(&str, Value)> = vec![
        ("issuer", json!(printable_256.clone())),
        ("subject", json!(printable_256)),
        ("subject", json!("\"\\")),
        ("auth_time", json!(0)),
        ("auth_time", json!(ISSUED / 1000)),
        ("account_id", json!("a".repeat(128))),
        ("account_id", json!("acct.test_1:x-y")),
        ("origin", json!("http://127.0.0.1:8080")),
        ("expires_at", json!(ISSUED + 1)),
        ("signer", json!(format!("member:{}", "d".repeat(128)))),
    ];
    for (field, value) in goods {
        assert!(
            read(&with(good.clone(), field, value.clone())).is_ok(),
            "{field} {value}"
        );
    }
    let bads: Vec<(&str, Value)> = vec![
        ("type", json!("atem-station-binding-2")),
        ("type", json!("atem-verifier-report")),
        ("v", json!(2)),
        ("v", json!("1")),
        ("action", json!("release")),
        ("action", json!("Bind")),
        ("origin", json!("https://Station-dev.agora.build")),
        ("origin", json!("https://station-dev.agora.build/")),
        ("origin", json!("https://station-dev.agora.build:443")),
        ("origin", json!("https://station-dev.agora.build/v1")),
        ("origin", json!("https://user@station-dev.agora.build")),
        ("origin", json!("http://station-dev.agora.build")),
        ("issuer", json!("")),
        ("issuer", json!("i".repeat(257))),
        ("issuer", json!("https://auth dev")),
        ("subject", json!("")),
        ("subject", json!("s".repeat(257))),
        ("subject", json!("ab 1")),
        ("subject", json!("abé")),
        ("subject", json!("ab\u{7f}")),
        ("subject", json!("ab\t1")),
        ("auth_time", json!(-1)),
        ("auth_time", json!("1793263400")),
        ("auth_time", json!(ISSUED / 1000 + 1)),
        ("account_id", json!("")),
        ("account_id", json!("a".repeat(129))),
        ("account_id", json!("acct test")),
        ("account_id", json!("acct/test")),
        ("account_id", json!("acct-tést")),
        (
            "genesis_hash",
            json!(log.genesis_hash().to_hex().to_uppercase()),
        ),
        ("genesis_hash", json!("ab".repeat(31))),
        ("head", json!({"seq": 0, "hash": log.head().hash.to_hex()})),
        ("head.hash", json!(log.head().hash.to_hex().to_uppercase())),
        ("signer", json!("service:svc-discord")),
        ("signer", json!("host:host-a")),
        ("signer", json!("browser:grant-1")),
        ("signer", json!("dev-phone")),
        ("signer", json!("member:")),
        ("signer", json!("member:dev phone")),
        ("nonce", json!(b64u(&[0u8; 31]))),
        ("nonce", json!(b64u(&[0u8; 33]))),
        ("nonce", json!(format!("{}=", b64u(&[7u8; 32])))),
        (
            "nonce",
            json!("BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHB+/"),
        ),
        ("issued_at", json!(-1)),
        ("expires_at", json!(ISSUED)),
        ("expires_at", json!(ISSUED - 1)),
        ("expires_at", json!(ISSUED + 30_001)),
        ("expected_binding", json!({})),
        ("expected_binding", json!({"state": "pending"})),
        ("expected_binding", json!({"state": "bound"})),
        ("expected_binding.state", json!("Never_bound")),
        ("expected_binding", json!("never_bound")),
    ];
    for (field, value) in bads {
        assert_eq!(
            code(read(&with(good.clone(), field, value.clone()))),
            Err("malformed"),
            "{field} {value}"
        );
    }
}

/// The record's fields when the expected binding names one: all four, each
/// in its grammar. `owner` is named in every state but `never_bound`
/// (Atem's proposal, for Astation's agreement).
#[test]
fn a_recorded_binding_names_its_id_version_and_owner() {
    let v = Vectors::load();
    let log = log_l(&v);
    for state in ["unbound", "released"] {
        let expected =
            json!({"state": state, "binding_id": "bind-1", "version": 3, "owner": OWNER_A});
        let good = fields(&log, "bind", OWNER_B, expected.clone());
        let read_back = read(&good).unwrap();
        assert_eq!(
            read_back.expected_binding().record().unwrap().owner,
            OWNER_A
        );
        assert_eq!(read_back.expected_binding().state(), state);
        let mut no_owner = expected.clone();
        no_owner.as_object_mut().unwrap().remove("owner");
        assert_eq!(
            code(read(&fields(&log, "bind", OWNER_B, no_owner))),
            Err("malformed"),
            "{state} without its owner"
        );
    }
    let base = bound(OWNER_A);
    for (field, value) in [
        ("binding_id", json!("")),
        ("binding_id", json!("b".repeat(129))),
        ("binding_id", json!("bind 1")),
        ("version", json!(0)),
        ("version", json!(-1)),
        ("version", json!("2")),
        ("owner", json!("")),
        ("owner", json!("o".repeat(257))),
        ("owner", json!("ab 1")),
        ("extra", json!(1)),
    ] {
        let expected = with(base.clone(), field, value.clone());
        assert_eq!(
            code(read(&fields(&log, "transfer", OWNER_B, expected))),
            Err("malformed"),
            "{field} {value}"
        );
    }
    for field in ["state", "binding_id", "version", "owner"] {
        let mut missing = base.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert_eq!(
            code(read(&fields(&log, "transfer", OWNER_B, missing))),
            Err("malformed"),
            "without {field}"
        );
    }
    let longest = with(
        with(base, "binding_id", json!("b".repeat(128))),
        "version",
        json!(atem_client::canonical::MAX_SAFE_INTEGER),
    );
    assert!(read(&fields(&log, "transfer", OWNER_B, longest)).is_ok());
}

/// The per-action rules: which state each action names, and the subject
/// against the owner.
#[test]
fn each_action_names_its_state_and_subject() {
    let v = Vectors::load();
    let log = log_l(&v);
    let recorded = |state: &str| json!({"state": state, "binding_id": "bind-1", "version": 2, "owner": OWNER_A});
    let cases = [
        ("bind", OWNER_A, never_bound(), true),
        ("bind", OWNER_A, recorded("unbound"), true),
        ("bind", OWNER_B, recorded("unbound"), true),
        ("bind", OWNER_A, recorded("released"), true),
        ("bind", OWNER_B, recorded("released"), true),
        ("bind", OWNER_B, recorded("bound"), false),
        ("bind", OWNER_A, recorded("bound"), false),
        ("transfer", OWNER_B, recorded("bound"), true),
        ("transfer", OWNER_A, recorded("bound"), false),
        ("transfer", OWNER_B, never_bound(), false),
        ("transfer", OWNER_B, recorded("unbound"), false),
        ("transfer", OWNER_B, recorded("released"), false),
        ("unbind", OWNER_A, recorded("bound"), true),
        ("unbind", OWNER_B, recorded("bound"), false),
        ("unbind", OWNER_A, never_bound(), false),
        ("unbind", OWNER_A, recorded("unbound"), false),
        ("unbind", OWNER_A, recorded("released"), false),
    ];
    for (action, subject, expected, reads) in cases {
        let got = read(&fields(&log, action, subject, expected.clone()));
        assert_eq!(got.is_ok(), reads, "{action} {subject} {expected}");
        if !reads {
            assert_eq!(code(got), Err("malformed"));
        }
    }
    // The owner compared byte for byte: a case change is another account.
    let upper = OWNER_A.to_uppercase();
    assert!(read(&fields(&log, "transfer", &upper, recorded("bound"))).is_ok());
    assert!(read(&fields(&log, "unbind", &upper, recorded("bound"))).is_err());
}

/// The body is compared with the stored challenge on its `jcs`: the stored
/// text's key order and spacing don't count, every field's value does.
#[test]
fn the_body_is_the_stored_challenge_compared_on_its_jcs() {
    let (v, book) = (Vectors::load(), Book::load());
    let keys = &book.provider;
    let log = log_l(&v);
    let good = fields(&log, "transfer", OWNER_B, bound(OWNER_A));
    let text = signed(keys, "dev-phone/auth", &good);
    // The stored challenge written another way reads the same.
    let spaced = serde_json::to_string_pretty(&good)
        .unwrap()
        .replace("\"type\"", "\"\\u0074ype\" ");
    let stored = StationBindingChallenge::parse(spaced.as_bytes()).unwrap();
    assert!(verify(&log, &text, &stored, NOW).is_ok());
    for (field, value) in [
        ("origin", json!(OTHER_STATION)),
        ("issuer", json!("https://auth.agora.build")),
        ("subject", json!("ab00000000000000000000000003")),
        ("auth_time", json!(AUTH_TIME - 1)),
        ("account_id", json!("acct-other")),
        ("genesis_hash", json!(v.hash("SUB1").to_hex())),
        ("head", v.head("E5").to_json()),
        ("signer", json!("member:dev-mac")),
        ("expected_binding.binding_id", json!("bind-2")),
        ("expected_binding.version", json!(3)),
        (
            "expected_binding.owner",
            json!("ab00000000000000000000000003"),
        ),
        ("nonce", json!(b64u(&[8u8; 32]))),
        ("issued_at", json!(ISSUED + 1)),
        ("expires_at", json!(EXPIRES - 1)),
    ] {
        let stored = challenge_of(&with(good.clone(), field, value.clone()));
        assert_eq!(
            code(verify(&log, &text, &stored, NOW)),
            Err("challenge_mismatch"),
            "{field}"
        );
    }
    // The action can't change alone (each names its own state and subject
    // rule): an unbind of the same record stored instead.
    let unbind = with(
        fields(&log, "unbind", OWNER_A, bound(OWNER_A)),
        "nonce",
        good["nonce"].clone(),
    );
    assert_eq!(
        code(verify(&log, &text, &challenge_of(&unbind), NOW)),
        Err("challenge_mismatch")
    );
    // A state change of a bind: unbound stored, released signed.
    let released = fields(
        &log,
        "bind",
        OWNER_B,
        json!({"state": "released", "binding_id": "bind-1", "version": 2, "owner": OWNER_A}),
    );
    let as_unbound = with(released.clone(), "expected_binding.state", json!("unbound"));
    assert_eq!(
        code(verify(
            &log,
            &signed(keys, "dev-phone/auth", &released),
            &challenge_of(&as_unbound),
            NOW
        )),
        Err("challenge_mismatch")
    );
}

/// A manager demoted after it signed: its proof no longer verifies, and
/// it builds none (manage at the head, never "ever held"). A removed one is
/// no member.
#[test]
fn a_demoted_or_removed_manager_neither_signs_nor_verifies() {
    let (v, book) = (Vectors::load(), Book::load());
    let keys = &book.provider;
    let log = log_l(&v);
    let good = bind_fields(&log);
    let stored = challenge_of(&good);
    let text = signed(keys, "dev-phone/auth", &good);
    let demoted = phone_roles(keys, &log, &[Role::Control, Role::View]);
    assert_eq!(
        code(verify(&demoted, &text, &stored, NOW)),
        Err("not_a_manager")
    );
    let at_demoted = with(good.clone(), "head", demoted.head().to_json());
    assert_eq!(
        code(station_binding_request(
            &demoted,
            &challenge_of(&at_demoted),
            PHONE,
            STATION,
            &claims(OWNER_A),
            NOW
        )),
        Err("not_a_manager")
    );
    // Promoted again: it verifies at the new head's ancestor.
    let again = phone_roles(keys, &demoted, &[Role::Control, Role::Manage, Role::View]);
    let verified = verify(&again, &text, &stored, NOW).unwrap();
    assert!(!verified.at_head);
    // dev-ipad, removed by E6, signs with its own key.
    let ipad = with(good, "signer", json!("member:dev-ipad"));
    assert_eq!(
        code(verify(
            &log,
            &signed(keys, "dev-ipad/auth", &ipad),
            &challenge_of(&ipad),
            NOW
        )),
        Err("unknown_signer")
    );
}

#[test]
fn an_ancestor_head_verifies_with_at_head_false() {
    let (v, book) = (Vectors::load(), Book::load());
    let keys = &book.provider;
    let log = log_l(&v);
    let good = bind_fields(&log);
    let text = signed(keys, "dev-phone/auth", &good);
    let verified = verify(&later(&book, &log), &text, &challenge_of(&good), NOW).unwrap();
    assert!(!verified.at_head);
    assert_eq!(verified.head, log.head());
    // An earlier head on the chain verifies too.
    let earlier = with(good, "head", v.head("E5").to_json());
    let verified = verify(
        &log,
        &signed(keys, "dev-phone/auth", &earlier),
        &challenge_of(&earlier),
        NOW,
    )
    .unwrap();
    assert_eq!(
        verified.head,
        Head {
            seq: 5,
            hash: v.hash("E5")
        }
    );
    assert!(!verified.at_head);
}

/// The held body takes only a signature over itself by its signer; the
/// proof is the held body with the signature (low S), byte for byte.
#[test]
fn a_held_body_takes_only_its_signers_signature_over_itself() {
    let (v, book) = (Vectors::load(), Book::load());
    let keys = &book.provider;
    let log = log_l(&v);
    let good = bind_fields(&log);
    let request = station_binding_request(
        &log,
        &challenge_of(&good),
        PHONE,
        STATION,
        &claims(OWNER_A),
        NOW,
    )
    .unwrap();
    assert_eq!(request.challenge().to_json(), good);
    assert_eq!(request.signer_key(), &book.public("dev-phone/auth"));
    let sig = sign(
        keys,
        &KeyId::new("dev-phone/auth"),
        &request.signing_input(),
    )
    .unwrap();
    let proof = request.finish(&sig).unwrap();
    assert_eq!(
        jcs(&proof.to_json()).unwrap(),
        format!(
            r#"{{"body":{},"sig":"{}"}}"#,
            request.body_json(),
            b64u(&sig)
        )
    );
    // Its high-S twin is normalized to the same proof.
    let high = high_s(&sig);
    assert_eq!(request.finish(&high).unwrap(), proof);
    // Another member's key, or a signature over another body, is refused.
    let by_mac = sign(keys, &KeyId::new("dev-mac/auth"), &request.signing_input()).unwrap();
    assert_eq!(code(request.finish(&by_mac)), Err("bad_signature"));
    let other = challenge_of(&with(good, "nonce", json!(b64u(&[9u8; 32]))));
    let other_input = station_binding_request(&log, &other, PHONE, STATION, &claims(OWNER_A), NOW)
        .unwrap()
        .signing_input();
    let over_other = sign(keys, &KeyId::new("dev-phone/auth"), &other_input).unwrap();
    assert_eq!(code(request.finish(&over_other)), Err("bad_signature"));
    assert_eq!(code(request.finish(&[0u8; 63])), Err("bad_signature"));
    // A key that isn't the signer's, behind the provider: bad_signature.
    assert_eq!(
        code(sign_station_binding(
            keys,
            &KeyId::new("dev-mac/auth"),
            &request
        )),
        Err("bad_signature")
    );
}

/// The verifier takes only a low-S P-256 signature.
#[test]
fn a_high_s_signature_is_refused() {
    let (v, book) = (Vectors::load(), Book::load());
    let log = log_l(&v);
    let good = bind_fields(&log);
    let text = signed(&book.provider, "dev-phone/auth", &good);
    let mut object: Value = serde_json::from_str(&text).unwrap();
    let sig = b64u_decode(object["sig"].as_str().unwrap()).unwrap();
    object["sig"] = json!(b64u(&high_s(&sig)));
    assert_eq!(
        code(verify(
            &log,
            &jcs(&object).unwrap(),
            &challenge_of(&good),
            NOW
        )),
        Err("bad_signature")
    );
}

/// No other label's signature verifies as a binding, and a binding body
/// relabelled as another kind doesn't read.
#[test]
fn a_label_collision_is_impossible() {
    let (v, book) = (Vectors::load(), Book::load());
    let keys = &book.provider;
    let log = log_l(&v);
    let good = bind_fields(&log);
    let stored = challenge_of(&good);
    for label in [
        SignLabel::MembershipEntry,
        SignLabel::RecoveryCosign,
        SignLabel::BrowserGrant,
        SignLabel::PushHint,
        SignLabel::Seen,
        SignLabel::ChannelHost,
        SignLabel::ChannelClient,
        SignLabel::HostRoute,
        SignLabel::HostRouteProxy,
        SignLabel::HostEncKey,
        SignLabel::HostWorkControl,
        SignLabel::Envelope,
        SignLabel::Result,
        SignLabel::VerifierReport,
        SignLabel::SignerReport,
    ] {
        assert_eq!(
            code(verify(
                &log,
                &signed_as(keys, "dev-phone/auth", label, &good),
                &stored,
                NOW
            )),
            Err("bad_signature"),
            "{label:?}"
        );
    }
    let relabelled = signed_as(
        keys,
        "dev-phone/auth",
        SignLabel::VerifierReport,
        &with(good, "type", json!("atem-verifier-report")),
    );
    assert_eq!(
        code(verify(&log, &relabelled, &stored, NOW)),
        Err("malformed")
    );
}

/// The proof's envelope: exactly `body` and `sig`, within 16 KiB.
#[test]
fn the_proof_is_exactly_body_and_sig() {
    let (v, book) = (Vectors::load(), Book::load());
    let log = log_l(&v);
    let good = bind_fields(&log);
    let stored = challenge_of(&good);
    let text = signed(&book.provider, "dev-phone/auth", &good);
    let object = SignedObject::parse(text.as_bytes()).unwrap();
    assert_eq!(object.label(), SignLabel::StationBinding);
    for bad in [
        text.replacen(r#"{"body":"#, r#"{"kit_sig":"AA","body":"#, 1),
        text.replacen(r#"{"body":"#, r#"{"note":"x","body":"#, 1),
        text.replacen(r#","sig":"#, r#","sig":"AA","sig":"#, 1),
        format!(r#"{{"body":{}}}"#, jcs(&good).unwrap()),
        text.replacen(
            r#","sig":"#,
            &format!("{},\"sig\":", " ".repeat(16 * 1024)),
            1,
        ),
        text.replacen(r#""sig":""#, r#""sig":"*"#, 1),
    ] {
        assert_eq!(
            code(verify(&log, &bad, &stored, NOW)),
            Err("malformed"),
            "{bad:.60}"
        );
    }
}

/// An Ed25519 manager's proof, at its head and at an ancestor.
#[test]
fn an_ed25519_manager_signs_too() {
    let (v, book) = (Vectors::load(), Book::load());
    let keys = &book.provider;
    let log = log_l(&v);
    let desk = Action::Add {
        member: atem_client::membership::Member {
            device_id: "dev-desk".into(),
            auth_key: book.public("dev-desk/auth"),
            kind: atem_client::membership::MemberKind::Native {
                enc_key: book.public("dev-desk/enc"),
                roles: [Role::Control, Role::Manage, Role::View]
                    .into_iter()
                    .collect(),
            },
        },
    };
    let with_desk = after(keys, &log, desk, 1_792_400_006_000);
    let body = with(
        with(bind_fields(&with_desk), "signer", json!("member:dev-desk")),
        "head",
        with_desk.head().to_json(),
    );
    let request = station_binding_request(
        &with_desk,
        &challenge_of(&body),
        "member:dev-desk",
        STATION,
        &claims(OWNER_A),
        NOW,
    )
    .unwrap();
    let proof = sign_station_binding(keys, &KeyId::new("dev-desk/auth"), &request).unwrap();
    let text = jcs(&proof.to_json()).unwrap();
    assert!(
        verify(&with_desk, &text, &challenge_of(&body), NOW)
            .unwrap()
            .at_head
    );
    assert!(
        !verify(&later(&book, &with_desk), &text, &challenge_of(&body), NOW)
            .unwrap()
            .at_head
    );
}

/// `s` replaced by `n − s` (the other valid P-256 signature).
fn high_s(sig: &[u8]) -> Vec<u8> {
    const N: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ];
    let mut out = sig[..32].to_vec();
    let s = &sig[32..];
    let mut borrow = 0i16;
    let mut tail = [0u8; 32];
    for i in (0..32).rev() {
        let d = N[i] as i16 - s[i] as i16 - borrow;
        borrow = i16::from(d < 0);
        tail[i] = d.rem_euclid(256) as u8;
    }
    out.extend_from_slice(&tail);
    out
}
