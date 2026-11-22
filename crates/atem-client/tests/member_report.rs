//! A member's signed verifier report (`atem_client::member_report`;
//! session-v1 R9.2 "How a verifier reports itself", agreed for
//! implementation on Astation #101) beyond the shared vectors: every
//! refusal at its place in the order, the builder's refusals, a frozen
//! log, a service signer (expired too), an ancestor head, the process
//! fixed within a process, the label, substitutions and the held body's
//! signature. The vectors (`r9-vectors-verifier-report`) run in
//! `verifier_report.rs`.
mod support;

use atem_client::canonical::jcs;
use atem_client::domain::{SignLabel, SigningInput};
use atem_client::encoding::{Hash32, b64u};
use atem_client::member_report::{
    MAX_LEASE_MS, ReportChallenge, ReportRefusal, SignerKind, VERIFY_ORDER, process_generation,
    sign_verifier_report, verifier_report_body, verify_verifier_report,
};
use atem_client::membership::{
    Action, Member, MemberKind, MemberStatus, Membership, Role, RolesChange, VerifierInventory,
    sign_entry,
};
use atem_client::provider::sign;
use atem_client::{Alg, KeyId, KeyProvider, SignedObject, SoftwareKeys};
use serde_json::{Value, json};
use support::*;

const STATION: &str = "https://station-dev.agora.build";
const SLOT: &str = "astation-ios";
const PHONE: &str = "member:dev-phone";
const SVC: &str = "service:svc-discord";
/// The reporter's clock: after log L's entries, before svc-discord expires.
const NOW: u64 = 1_793_264_001_000;
const ISSUED: u64 = 1_793_264_000_000;
/// svc-discord's `expires_at` (E5).
const SVC_EXPIRES: u64 = 1_794_992_004_000;

fn log_l(v: &Vectors, clock: &Clock) -> Membership {
    let entries = v.entries(&["E1", "E2", "E3", "E4", "E5", "E6"]);
    Membership::verify_chain(ACCOUNT, &v.hash("E1"), &entries, &clock.now)
        .unwrap()
        .membership
}

fn clock() -> Clock {
    Clock::at(NOW)
}

fn challenge(signer: &str, slot: &str, connection: u64) -> ReportChallenge {
    ReportChallenge::new(signer, slot, STATION, connection, ISSUED, ISSUED + 20_000).unwrap()
}

/// A challenge with exactly these fields (a fixed nonce), read as a minter
/// stores it.
fn challenge_of(fields: Value) -> ReportChallenge {
    ReportChallenge::parse(fields.to_string().as_bytes()).unwrap()
}

/// A report of `signer` at `log`'s head for `challenge`, signed with `key`.
fn report(
    book: &SoftwareKeys,
    key: &str,
    log: &Membership,
    signer: &str,
    challenge: &ReportChallenge,
) -> String {
    let body =
        verifier_report_body(log, challenge, signer, challenge.slot(), STATION, NOW).unwrap();
    sign_verifier_report(book, &KeyId::new(key), &body)
        .unwrap()
        .to_json()
        .to_string()
}

/// `body` as the JSON object a valid report carries, changed by `edit`,
/// then signed with `key`: a report the builder would never make.
fn resigned(book: &SoftwareKeys, key: &str, text: &str, edit: impl FnOnce(&mut Value)) -> String {
    let mut body: Value = serde_json::from_str::<Value>(text).unwrap()["body"].clone();
    edit(&mut body);
    SignedObject::sign(book, &KeyId::new(key), body)
        .unwrap()
        .to_json()
        .to_string()
}

/// The log after `log` with an entry `action` by dev-mac.
fn after(book: &SoftwareKeys, log: &Membership, action: Action, clock: &Clock) -> Membership {
    let body = log.draft("dev-mac", 1_792_400_006_000, &action);
    let entry = sign_entry(book, &KeyId::new("dev-mac/auth"), body).unwrap();
    let eval = log.evaluate_objects(&[entry.object().clone()], &clock.now);
    assert!(eval.changed(log), "the entry applies");
    eval.next
}

/// A native member `device_id` with a new key of `alg` in `book`.
fn native(book: &mut SoftwareKeys, device_id: &str, alg: Alg) -> Action {
    let auth = book
        .generate(KeyId::new(format!("{device_id}/auth")), alg)
        .unwrap();
    let enc = book
        .generate(KeyId::new(format!("{device_id}/enc")), Alg::X25519)
        .unwrap();
    Action::Add {
        member: Member {
            device_id: device_id.into(),
            auth_key: auth,
            kind: MemberKind::Native {
                enc_key: enc,
                roles: [Role::View].into_iter().collect(),
            },
        },
    }
}

/// Another host after L: a chain position for the ancestor cases.
fn host_b(book: &mut SoftwareKeys) -> Action {
    let key = book
        .generate(KeyId::new("host-b/host_key"), Alg::Ed25519)
        .unwrap();
    Action::AddHost {
        host: atem_client::membership::HostRecord {
            host_id: "host-b".into(),
            host_trust_gen: 1,
            host_key: key,
        },
    }
}

#[test]
fn a_native_report_round_trips_at_the_head() {
    let (v, book, clock) = (Vectors::load(), Book::load(), clock());
    let log = log_l(&v, &clock);
    let challenge = challenge(PHONE, SLOT, 3);
    let wire = challenge.to_json().to_string();
    assert_eq!(ReportChallenge::parse(wire.as_bytes()).unwrap(), challenge);
    let text = report(&book.provider, "dev-phone/auth", &log, PHONE, &challenge);
    let verified = verify_verifier_report(&log, text.as_bytes(), &challenge, NOW).unwrap();
    assert_eq!(verified.signer, PHONE);
    assert_eq!(verified.kind, SignerKind::Native);
    assert_eq!(verified.slot, SLOT);
    assert_eq!(verified.process, process_generation());
    assert_eq!(verified.connection, 3);
    assert_eq!(verified.head, log.head());
    assert!(verified.at_head);
    assert_eq!(verified.inventory, VerifierInventory::ours());
    assert_eq!(verified.expires_at, ISSUED + 20_000);
    // The body is exactly the agreed fields, signer and slot at the top.
    let body = &serde_json::from_str::<Value>(&text).unwrap()["body"];
    let mut fields: Vec<&str> = body
        .as_object()
        .unwrap()
        .keys()
        .map(|k| k.as_str())
        .collect();
    fields.sort_unstable();
    assert_eq!(
        fields,
        [
            "account_id",
            "challenge",
            "genesis_hash",
            "head",
            "process",
            "signer",
            "slot",
            "type",
            "v",
            "verifier"
        ]
    );
    assert_eq!(
        body["challenge"],
        json!({"origin": STATION, "connection": 3, "nonce": b64u(challenge.nonce()),
               "issued_at": ISSUED, "expires_at": ISSUED + 20_000})
    );
    // A fresh challenge never accepts this report.
    let next = self::challenge(PHONE, SLOT, 3);
    assert_ne!(next.nonce(), challenge.nonce());
    assert_eq!(
        verify_verifier_report(&log, text.as_bytes(), &next, NOW),
        Err(ReportRefusal::ChallengeMismatch)
    );
}

#[test]
fn an_ed25519_native_reports_too() {
    let (v, mut keys, clock) = (Vectors::load(), Book::load().provider, clock());
    let action = native(&mut keys, "dev-desk", Alg::Ed25519);
    let log = after(&keys, &log_l(&v, &clock), action, &clock);
    let challenge = challenge("member:dev-desk", SLOT, 1);
    let text = report(&keys, "dev-desk/auth", &log, "member:dev-desk", &challenge);
    let verified = verify_verifier_report(&log, text.as_bytes(), &challenge, NOW).unwrap();
    assert_eq!(verified.kind, SignerKind::Native);
    assert!(verified.at_head);
}

/// Each refusal comes at its place: a report that fails a check and every
/// check after it is refused with that check's code, in the agreed order.
#[test]
fn every_refusal_code_at_its_place_in_the_order() {
    let (v, book, clock) = (Vectors::load(), Book::load(), clock());
    let keys = &book.provider;
    let log = log_l(&v, &clock);
    let frozen = log.evaluate(&[strict(v.wire("C6_mac"))], &clock.now).next;
    assert!(frozen.frozen().is_some());
    assert_eq!(
        VERIFY_ORDER,
        [
            "malformed",
            "frozen",
            "wrong_account",
            "unknown_signer",
            "signer_expired",
            "bad_signature",
            "stale_log",
            "fork",
            "signer_mismatch",
            "slot_mismatch",
            "challenge_mismatch",
            "expired"
        ]
    );
    let expected = challenge(PHONE, SLOT, 3);
    let expires = expected.expires_at();
    let good = report(keys, "dev-phone/auth", &log, PHONE, &expected);
    // The later failures every case below also carries: a challenge
    // expired at the verifier's clock, whose nonce, slot and signer are
    // another's.
    let other = challenge_of(json!({"signer": "member:dev-mac", "slot": "astation-mac",
        "origin": STATION, "connection": 3, "nonce": b64u(&[9u8; 32]),
        "issued_at": ISSUED, "expires_at": expires}));
    let check = |log: &Membership, text: &str, expected: &ReportChallenge, now: u64| {
        verify_verifier_report(log, text.as_bytes(), expected, now).map_err(|r| r.code())
    };

    assert_eq!(
        check(&log, &good, &expected, expires - 1).map(|r| r.at_head),
        Ok(true)
    );
    assert_eq!(check(&log, &good, &expected, expires), Err("expired"));
    let mut wrong_nonce = expected.to_json();
    wrong_nonce["nonce"] = json!(b64u(&[9u8; 32]));
    assert_eq!(
        check(&log, &good, &challenge_of(wrong_nonce), expires),
        Err("challenge_mismatch")
    );
    let mut wrong_slot = other.to_json();
    wrong_slot["signer"] = json!(PHONE);
    assert_eq!(
        check(&log, &good, &challenge_of(wrong_slot), expires),
        Err("slot_mismatch")
    );
    assert_eq!(check(&log, &good, &other, expires), Err("signer_mismatch"));
    // On the chain but at another hash: E6's hash at seq 5.
    let fork = resigned(keys, "dev-phone/auth", &good, |b| {
        b["head"] = json!({"seq": 5, "hash": v.hash("E6").to_hex()})
    });
    assert_eq!(check(&log, &fork, &other, expires), Err("fork"));
    let stale = resigned(keys, "dev-phone/auth", &good, |b| {
        b["head"] = json!({"seq": 7, "hash": Hash32([7; 32]).to_hex()})
    });
    assert_eq!(check(&log, &stale, &other, expires), Err("stale_log"));
    // Tampered after signing (the slot), and at a head beyond the log's.
    let mut tampered: Value = serde_json::from_str(&stale).unwrap();
    tampered["body"]["slot"] = json!("astation-mac");
    let tampered = tampered.to_string();
    assert_eq!(
        check(&log, &tampered, &other, expires),
        Err("bad_signature")
    );
    // A service past its expiry, with a signature by another key.
    let svc_challenge = challenge(SVC, SLOT, 3);
    let svc = report(keys, "svc-discord/auth", &log, SVC, &svc_challenge);
    let svc_bad = resigned(keys, "dev-phone/auth", &svc, |b| {
        b["head"] = json!({"seq": 7, "hash": Hash32([7; 32]).to_hex()})
    });
    assert_eq!(
        check(&log, &svc_bad, &other, SVC_EXPIRES),
        Err("signer_expired")
    );
    assert_eq!(
        check(&log, &svc_bad, &other, SVC_EXPIRES - 1),
        Err("bad_signature")
    );
    // A member removed (dev-ipad, E6), with a service's key.
    let removed = resigned(keys, "svc-discord/auth", &svc, |b| {
        b["signer"] = json!("member:dev-ipad")
    });
    assert_eq!(
        check(&log, &removed, &other, SVC_EXPIRES),
        Err("unknown_signer")
    );
    let wrong_account = resigned(keys, "svc-discord/auth", &removed, |b| {
        b["account_id"] = json!("acct-other")
    });
    assert_eq!(
        check(&log, &wrong_account, &other, SVC_EXPIRES),
        Err("wrong_account")
    );
    assert_eq!(
        check(&frozen, &wrong_account, &other, SVC_EXPIRES),
        Err("frozen")
    );
    let mut malformed: Value = serde_json::from_str(&wrong_account).unwrap();
    malformed["body"]["note"] = json!("x");
    assert_eq!(
        check(&frozen, &malformed.to_string(), &other, SVC_EXPIRES),
        Err("malformed")
    );
}

#[test]
fn the_builder_refuses_another_station_signer_slot_or_an_expired_challenge() {
    let (v, clock) = (Vectors::load(), clock());
    let log = log_l(&v, &clock);
    let challenge = challenge(PHONE, SLOT, 3);
    let build = |station: &str, signer: &str, slot: &str, now: u64| {
        verifier_report_body(&log, &challenge, signer, slot, station, now).map(|_| ())
    };
    assert_eq!(build(STATION, PHONE, SLOT, NOW), Ok(()));
    // The configured Station, normalized, is the challenge's origin.
    assert_eq!(
        build("https://Station-Dev.agora.build/", PHONE, SLOT, NOW),
        Ok(())
    );
    assert_eq!(
        build("https://station.agora.build", PHONE, SLOT, NOW),
        Err(ReportRefusal::OriginMismatch)
    );
    assert_eq!(
        build("https://station-dev.agora.build:8443", PHONE, SLOT, NOW),
        Err(ReportRefusal::OriginMismatch)
    );
    assert!(matches!(
        build("ftp://station-dev.agora.build", PHONE, SLOT, NOW),
        Err(ReportRefusal::Malformed(_))
    ));
    assert_eq!(
        build(STATION, "member:dev-mac", SLOT, NOW),
        Err(ReportRefusal::SignerMismatch)
    );
    assert_eq!(
        build(STATION, PHONE, "astation-mac", NOW),
        Err(ReportRefusal::SlotMismatch)
    );
    assert_eq!(
        build(STATION, PHONE, SLOT, challenge.expires_at()),
        Err(ReportRefusal::Expired)
    );
    // Only a reporter that is itself a current member or service.
    for signer in ["dev-phone", "host:host-a", "member:", "service:dev phone"] {
        assert!(
            matches!(
                build(STATION, signer, SLOT, NOW),
                Err(ReportRefusal::Malformed(_))
            ),
            "{signer}"
        );
    }
    assert!(matches!(
        build(STATION, PHONE, "", NOW),
        Err(ReportRefusal::Malformed(_))
    ));
    for signer in [
        "member:dev-ipad",
        "member:svc-discord",
        "service:dev-phone",
        "member:dev-evil",
    ] {
        let challenge = self::challenge(signer, SLOT, 3);
        assert_eq!(
            verifier_report_body(&log, &challenge, signer, SLOT, STATION, NOW).map(|_| ()),
            Err(ReportRefusal::UnknownSigner),
            "{signer}"
        );
    }
}

#[test]
fn a_challenge_lease_is_at_most_30_seconds() {
    let new = |issued, expires| ReportChallenge::new(PHONE, SLOT, STATION, 1, issued, expires);
    assert!(new(ISSUED, ISSUED + MAX_LEASE_MS).is_ok());
    assert!(new(ISSUED, ISSUED + 1).is_ok());
    for (issued, expires) in [
        (ISSUED, ISSUED),
        (ISSUED, ISSUED - 1),
        (ISSUED, ISSUED + MAX_LEASE_MS + 1),
    ] {
        assert!(
            matches!(new(issued, expires), Err(ReportRefusal::Malformed(_))),
            "{issued} {expires}"
        );
    }
    for connection in [0, 1 << 53] {
        assert!(matches!(
            ReportChallenge::new(PHONE, SLOT, STATION, connection, ISSUED, ISSUED + 1),
            Err(ReportRefusal::Malformed(_))
        ));
    }
    // A challenge names a member or a service, never a host or a grant.
    for signer in [
        "host:host-a",
        "browser:g-1",
        "member:recovery x",
        "dev-phone",
    ] {
        assert!(matches!(
            ReportChallenge::new(signer, SLOT, STATION, 1, ISSUED, ISSUED + 1),
            Err(ReportRefusal::Malformed(_))
        ));
    }
    let slot = "s".repeat(128);
    assert!(ReportChallenge::new(PHONE, &slot, STATION, 1, ISSUED, ISSUED + 1).is_ok());
    let slot = "s".repeat(129);
    assert!(ReportChallenge::new(PHONE, &slot, STATION, 1, ISSUED, ISSUED + 1).is_err());
}

#[test]
fn a_challenge_is_exactly_its_fields() {
    let good = challenge(PHONE, SLOT, 3).to_json();
    assert!(ReportChallenge::parse(good.to_string().as_bytes()).is_ok());
    let edits: [(&str, Value); 12] = [
        ("extra", json!(1)),
        ("nonce", json!(b64u(&[1u8; 31]))),
        ("nonce", json!("not b64u!")),
        ("origin", json!("https://station-dev.agora.build/")),
        ("origin", json!("https://Station-dev.agora.build")),
        ("origin", json!("https://station-dev.agora.build:443")),
        ("origin", json!("https://user@station-dev.agora.build")),
        ("origin", json!("https://station-dev.agora.build/path")),
        ("connection", json!(0)),
        ("slot", json!("a b")),
        ("signer", json!("host:host-a")),
        ("expires_at", json!(ISSUED + MAX_LEASE_MS + 1)),
    ];
    for (field, value) in edits {
        let mut bad = good.clone();
        bad[field] = value.clone();
        assert!(
            matches!(
                ReportChallenge::parse(bad.to_string().as_bytes()),
                Err(ReportRefusal::Malformed(_))
            ),
            "{field}: {value}"
        );
    }
    let mut missing = good.clone();
    missing.as_object_mut().unwrap().remove("slot");
    assert!(ReportChallenge::parse(missing.to_string().as_bytes()).is_err());
    let mut null = good.clone();
    null["slot"] = Value::Null;
    assert!(ReportChallenge::parse(null.to_string().as_bytes()).is_err());
    let text = good.to_string();
    let dup = text.replacen("{", r#"{"slot":"astation-mac","#, 1);
    assert!(ReportChallenge::parse(dup.as_bytes()).is_err());
    let escaped = text.replacen("{", r#"{"\u0073lot":"astation-mac","#, 1);
    assert!(ReportChallenge::parse(escaped.as_bytes()).is_err());
}

#[test]
fn a_frozen_log_reports_nothing_and_verifies_nothing() {
    let (v, book, clock) = (Vectors::load(), Book::load(), clock());
    let log = log_l(&v, &clock);
    let challenge = challenge(PHONE, SLOT, 3);
    let text = report(&book.provider, "dev-phone/auth", &log, PHONE, &challenge);
    // C6_mac conflicts with E6 and is signed by a manager: a freeze.
    let frozen = log.evaluate(&[strict(v.wire("C6_mac"))], &clock.now).next;
    assert!(frozen.frozen().is_some());
    assert_eq!(
        verifier_report_body(&frozen, &challenge, PHONE, SLOT, STATION, NOW).map(|_| ()),
        Err(ReportRefusal::Frozen)
    );
    assert_eq!(
        verify_verifier_report(&frozen, text.as_bytes(), &challenge, NOW),
        Err(ReportRefusal::Frozen)
    );
}

#[test]
fn a_service_reports_with_its_own_key_until_it_expires() {
    let (v, book, clock) = (Vectors::load(), Book::load(), clock());
    let keys = &book.provider;
    let log = log_l(&v, &clock);
    let challenge = challenge(SVC, "discord-bot", 1);
    let text = report(keys, "svc-discord/auth", &log, SVC, &challenge);
    let verified = verify_verifier_report(&log, text.as_bytes(), &challenge, NOW).unwrap();
    assert_eq!(verified.kind, SignerKind::Service);
    assert_eq!(verified.signer, SVC);
    // Its own key only: a manager's key over its body is refused.
    let body = verifier_report_body(&log, &challenge, SVC, "discord-bot", STATION, NOW).unwrap();
    assert_eq!(
        sign_verifier_report(keys, &KeyId::new("dev-mac/auth"), &body),
        Err(ReportRefusal::BadSignature)
    );
    // Expired at its expires_at, for the builder and the verifier.
    let late =
        ReportChallenge::new(SVC, "discord-bot", STATION, 1, SVC_EXPIRES, SVC_EXPIRES + 1).unwrap();
    assert_eq!(
        verifier_report_body(&log, &late, SVC, "discord-bot", STATION, SVC_EXPIRES).map(|_| ()),
        Err(ReportRefusal::SignerExpired)
    );
    let early =
        verifier_report_body(&log, &late, SVC, "discord-bot", STATION, SVC_EXPIRES - 1).unwrap();
    let early = sign_verifier_report(keys, &KeyId::new("svc-discord/auth"), &early)
        .unwrap()
        .to_json()
        .to_string();
    assert_eq!(
        verify_verifier_report(&log, early.as_bytes(), &late, SVC_EXPIRES),
        Err(ReportRefusal::SignerExpired)
    );
    assert!(verify_verifier_report(&log, early.as_bytes(), &late, SVC_EXPIRES - 1).is_ok());
}

#[test]
fn an_ancestor_head_verifies_with_at_head_false() {
    let (v, mut keys, clock) = (Vectors::load(), Book::load().provider, clock());
    let log = log_l(&v, &clock);
    let challenge = challenge(PHONE, SLOT, 3);
    let text = report(&keys, "dev-phone/auth", &log, PHONE, &challenge);
    let action = host_b(&mut keys);
    let later = after(&keys, &log, action, &clock);
    assert_eq!(later.head().seq, 7);
    let verified = verify_verifier_report(&later, text.as_bytes(), &challenge, NOW).unwrap();
    assert!(!verified.at_head);
    assert_eq!(verified.head, log.head());
    // The later report is beyond the earlier log: stale there.
    let ahead = report(&keys, "dev-phone/auth", &later, PHONE, &challenge);
    assert_eq!(
        verify_verifier_report(&log, ahead.as_bytes(), &challenge, NOW),
        Err(ReportRefusal::StaleLog)
    );
}

/// A native member whose roles changed is still a current native member:
/// its report from before the change verifies at an ancestor, and a new one
/// at the head.
#[test]
fn a_native_whose_roles_changed_still_reports() {
    let (v, book, clock) = (Vectors::load(), Book::load(), clock());
    let keys = &book.provider;
    let log = log_l(&v, &clock);
    let challenge = challenge(PHONE, SLOT, 3);
    let before = report(keys, "dev-phone/auth", &log, PHONE, &challenge);
    let view_only = Action::SetRoles {
        device_id: "dev-phone".into(),
        change: RolesChange::Native([Role::View].into_iter().collect()),
    };
    let later = after(keys, &log, view_only, &clock);
    assert!(!later.member("dev-phone").unwrap().member.is_manager());
    let old = verify_verifier_report(&later, before.as_bytes(), &challenge, NOW).unwrap();
    assert_eq!((old.kind, old.at_head), (SignerKind::Native, false));
    let now = report(keys, "dev-phone/auth", &later, PHONE, &challenge);
    let new = verify_verifier_report(&later, now.as_bytes(), &challenge, NOW).unwrap();
    assert_eq!((new.kind, new.at_head), (SignerKind::Native, true));
}

/// The subject of a `recovery_add` still waiting is no current member: it
/// neither builds a report nor has one verified (`unknown_signer`).
#[test]
fn the_pending_subject_of_a_recovery_add_does_not_report() {
    let (v, book, clock) = (Vectors::load(), Book::load(), clock());
    let keys = &book.provider;
    let log = log_l(&v, &clock);
    // R7: the recovery key adds dev-newmac, pending for 24 h here.
    let pending = log.evaluate(&[strict(v.wire("R7"))], &clock.now).next;
    assert!(matches!(
        pending.member("dev-newmac").unwrap().status,
        MemberStatus::Pending { .. }
    ));
    let newmac = "member:dev-newmac";
    let challenge = challenge(newmac, SLOT, 3);
    assert_eq!(
        verifier_report_body(&pending, &challenge, newmac, SLOT, STATION, NOW).map(|_| ()),
        Err(ReportRefusal::UnknownSigner)
    );
    let phone = report(
        keys,
        "dev-phone/auth",
        &log,
        PHONE,
        &self::challenge(PHONE, SLOT, 3),
    );
    let text = resigned(keys, "dev-newmac/auth", &phone, |b| {
        b["signer"] = json!(newmac);
        b["head"] = pending.head().to_json();
    });
    assert_eq!(
        verify_verifier_report(&pending, text.as_bytes(), &challenge, NOW),
        Err(ReportRefusal::UnknownSigner)
    );
}

/// The verifier takes only a low-S P-256 signature (R9.1): the valid
/// report with `s` replaced by `n − s` is `bad_signature`.
#[test]
fn a_high_s_report_is_refused() {
    let (v, book, clock) = (Vectors::load(), Book::load(), clock());
    let log = log_l(&v, &clock);
    let challenge = challenge(PHONE, SLOT, 3);
    let text = report(&book.provider, "dev-phone/auth", &log, PHONE, &challenge);
    assert!(verify_verifier_report(&log, text.as_bytes(), &challenge, NOW).is_ok());
    let mut object: Value = serde_json::from_str(&text).unwrap();
    let sig = atem_client::encoding::b64u_decode(object["sig"].as_str().unwrap()).unwrap();
    object["sig"] = json!(b64u(&high_s(&sig)));
    assert_eq!(
        verify_verifier_report(&log, object.to_string().as_bytes(), &challenge, NOW),
        Err(ReportRefusal::BadSignature)
    );
}

#[test]
fn the_process_stays_fixed_within_a_process() {
    let (v, book, clock) = (Vectors::load(), Book::load(), clock());
    let log = log_l(&v, &clock);
    let first = process_generation();
    assert_eq!(process_generation(), first);
    assert_ne!(first, [0u8; 16]);
    let threads: Vec<[u8; 16]> = (0..4)
        .map(|_| std::thread::spawn(process_generation))
        .map(|t| t.join().unwrap())
        .collect();
    assert!(threads.iter().all(|p| *p == first));
    for connection in [1, 2] {
        let challenge = challenge(PHONE, SLOT, connection);
        let text = report(&book.provider, "dev-phone/auth", &log, PHONE, &challenge);
        let verified = verify_verifier_report(&log, text.as_bytes(), &challenge, NOW).unwrap();
        assert_eq!(verified.process, first);
    }
}

/// A report's signature is over its own label only: the same body signed
/// under any other label is `bad_signature`, and a body relabelled to
/// another kind is `malformed` (its type).
#[test]
fn a_label_collision_is_impossible() {
    let (v, book, clock) = (Vectors::load(), Book::load(), clock());
    let keys = &book.provider;
    let log = log_l(&v, &clock);
    let challenge = challenge(PHONE, SLOT, 3);
    let body = verifier_report_body(&log, &challenge, PHONE, SLOT, STATION, NOW).unwrap();
    assert_eq!(body.signing_input().label(), SignLabel::VerifierReport);
    for other in [
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
    ] {
        let input = SigningInput::new(other, body.jcs().as_bytes());
        let sig = sign(keys, &KeyId::new("dev-phone/auth"), &input).unwrap();
        let text = json!({"body": body.to_json(), "sig": b64u(&sig)}).to_string();
        assert_eq!(
            verify_verifier_report(&log, text.as_bytes(), &challenge, NOW),
            Err(ReportRefusal::BadSignature),
            "{other:?}"
        );
        assert_eq!(body.with_signature(&sig), Err(ReportRefusal::BadSignature));
    }
    let signed = sign_verifier_report(keys, &KeyId::new("dev-phone/auth"), &body).unwrap();
    let mut relabelled = signed.to_json();
    relabelled["body"]["type"] = json!("atem-host-route");
    assert!(matches!(
        verify_verifier_report(&log, relabelled.to_string().as_bytes(), &challenge, NOW),
        Err(ReportRefusal::Malformed(_))
    ));
}

/// A cryptographically valid report for another slot or member fails
/// against the expectation it doesn't answer.
#[test]
fn a_valid_report_for_another_slot_or_member_fails() {
    let (v, book, clock) = (Vectors::load(), Book::load(), clock());
    let keys = &book.provider;
    let log = log_l(&v, &clock);
    let fields = |signer: &str, slot: &str| {
        json!({"signer": signer, "slot": slot, "origin": STATION, "connection": 4,
               "nonce": b64u(&[3u8; 32]), "issued_at": ISSUED, "expires_at": ISSUED + 30_000})
    };
    let for_a = challenge_of(fields(PHONE, SLOT));
    let for_b = challenge_of(fields("member:dev-mac", SLOT));
    let by_b = report(keys, "dev-mac/auth", &log, "member:dev-mac", &for_b);
    assert!(verify_verifier_report(&log, by_b.as_bytes(), &for_b, NOW).is_ok());
    assert_eq!(
        verify_verifier_report(&log, by_b.as_bytes(), &for_a, NOW),
        Err(ReportRefusal::SignerMismatch)
    );
    let slot_x = challenge_of(fields(PHONE, "astation-mac"));
    let slot_y = challenge_of(fields(PHONE, SLOT));
    let for_x = report(keys, "dev-phone/auth", &log, PHONE, &slot_x);
    assert_eq!(
        verify_verifier_report(&log, for_x.as_bytes(), &slot_y, NOW),
        Err(ReportRefusal::SlotMismatch)
    );
}

/// The held body takes only a signature over itself by its signer: one
/// over another body (another slot) or by another member is refused, and
/// the report is the held body with the signature, byte for byte.
#[test]
fn a_held_body_takes_only_its_signers_signature_over_itself() {
    let (v, book, clock) = (Vectors::load(), Book::load(), clock());
    let keys = &book.provider;
    let log = log_l(&v, &clock);
    let challenge_a = challenge(PHONE, SLOT, 3);
    let mut fields_b = challenge_a.to_json();
    fields_b["slot"] = json!("astation-mac");
    let challenge_b = challenge_of(fields_b);
    let held = verifier_report_body(&log, &challenge_a, PHONE, SLOT, STATION, NOW).unwrap();
    let other =
        verifier_report_body(&log, &challenge_b, PHONE, "astation-mac", STATION, NOW).unwrap();
    let phone = KeyId::new("dev-phone/auth");
    let over_other = sign(keys, &phone, &other.signing_input()).unwrap();
    assert_eq!(
        held.with_signature(&over_other),
        Err(ReportRefusal::BadSignature)
    );
    let by_mac = sign(keys, &KeyId::new("dev-mac/auth"), &held.signing_input()).unwrap();
    assert_eq!(
        held.with_signature(&by_mac),
        Err(ReportRefusal::BadSignature)
    );
    assert_eq!(
        held.with_signature(&[0u8; 64]),
        Err(ReportRefusal::BadSignature)
    );
    assert_eq!(
        held.with_signature(&[1u8; 3]),
        Err(ReportRefusal::BadSignature)
    );
    let sig = sign(keys, &phone, &held.signing_input()).unwrap();
    let report = held.with_signature(&sig).unwrap();
    assert_eq!(report.jcs(), held.jcs());
    assert_eq!(
        jcs(&report.to_json()).unwrap(),
        format!(r#"{{"body":{},"sig":"{}"}}"#, held.jcs(), b64u(&sig))
    );
    assert!(
        verify_verifier_report(
            &log,
            jcs(&report.to_json()).unwrap().as_bytes(),
            &challenge_a,
            NOW
        )
        .is_ok()
    );
    // A high-S P-256 signature is normalized, as from WebCrypto.
    let high = high_s(&sig);
    assert_ne!(high, sig);
    assert_eq!(held.with_signature(&high).unwrap().sig(), &sig[..]);
    // The signer's key comes from the log, never from the provider.
    assert_eq!(held.signer_key(), &keys.public_key(&phone).unwrap());
    assert_eq!(held.head(), log.head());
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
