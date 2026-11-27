//! A native manager's signed report of its control-record signing journal
//! (`atem_client::member_report`'s signer report; host-work-v1 §11.1 "The
//! signer report", agreed with Astation, #114 comment 7089435073) beyond
//! the shared vectors: every refusal at its place in the order, the
//! builder's refusals and its strict reading of the journal's bodies, the
//! set hashes, each form of `records_mismatch`, the challenge's grammar, a
//! demoted manager and a native that never managed, an ancestor head, a
//! reinstalled journal, a frozen log, the held body's signature and the
//! label. The vectors (`r9-vectors-signer-report`) run in
//! `signer_report.rs`.
mod support;

use atem_client::canonical::jcs;
use atem_client::control::{
    ControlAbout, ControlAction, ControlBody, ControlFeed, ControlPrincipal, ControlSigner,
    build_control, principal_key_of,
};
use atem_client::domain::{SIGNER_REPORT_DRAFTS, SIGNER_REPORT_RECORDS, SignLabel, SigningInput};
use atem_client::encoding::{Hash32, b64u, enc};
use atem_client::member_report::{
    JournalView, MAX_GENERATION, OutOfPlan, PlanRecord, RecoveryPlan, ReportRefusal,
    SIGNER_VERIFY_ORDER, SignerReportChallenge, process_generation, sign_signer_report,
    signer_report_body, signer_report_plan_record, verify_signer_report,
};
use atem_client::membership::{
    Action, Member, MemberKind, Membership, Role, RolesChange, sign_entry,
};
use atem_client::provider::sign;
use atem_client::{Alg, KeyId, KeyProvider, SignedObject, SoftwareKeys};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use support::*;

const STATION: &str = "https://station-dev.agora.build";
const OTHER_STATION: &str = "https://station.agora.build";
const SLOT: &str = "astation-ios";
const PHONE: &str = "member:dev-phone";
const MAC: &str = "member:dev-mac";
/// The reporter's clock: after log L's entries.
const NOW: u64 = 1_793_264_001_000;
const ISSUED: u64 = 1_793_264_000_000;
const EXPIRES: u64 = ISSUED + 20_000;
const PLAN: &str = "5b7c9d1e-2f3a-4b5c-8d6e-7f8091a2b3c4";
const CANDIDATE: &str = "7a2d3c4b-5e6f-4071-9b8c-0d1e2f3a4b5c";
/// The old feed the stops name.
const FEED: &str = "6f1c2b3a-4d5e-4f60-8a7b-9c0d1e2f3a4b";
const INTEGRATION: &str = "i-01jc5zq9x8w7v6t5s4r3q2p1n0";
const JOURNAL_ID: [u8; 16] = *b"journal-id-0001!";

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

/// A native member `device_id` with `roles` and a new P-256 key in `book`.
fn native(book: &mut SoftwareKeys, device_id: &str, roles: &[Role]) -> Action {
    let auth = book
        .generate(KeyId::new(format!("{device_id}/auth")), Alg::P256)
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
                roles: roles.iter().copied().collect(),
            },
        },
    }
}

fn recovery() -> RecoveryPlan {
    RecoveryPlan::new(7, PLAN, CANDIDATE, Hash32([0x5a; 32]), Hash32([0xe7; 32])).unwrap()
}

fn challenge(signer: &str, slot: &str) -> SignerReportChallenge {
    SignerReportChallenge::new(signer, slot, STATION, 3, ISSUED, EXPIRES, recovery()).unwrap()
}

/// A challenge with exactly these fields, read as a minter stores it.
fn challenge_of(fields: Value) -> SignerReportChallenge {
    SignerReportChallenge::parse(fields.to_string().as_bytes()).unwrap()
}

fn record_id(n: u64) -> String {
    format!("00000000-0000-4000-8000-{n:012x}")
}

/// `signer`'s stop of svc-discord naming `origin`.
fn service_stop(
    book: &Book,
    signer: &str,
    action: ControlAction,
    origin: &str,
    n: u64,
) -> ControlBody {
    ControlBody {
        account_id: ACCOUNT.into(),
        genesis_hash: genesis_hash(),
        feed: Some(ControlFeed {
            origin: origin.into(),
            feed_id: FEED.into(),
        }),
        principal: ControlPrincipal::Service("svc-discord".into()),
        principal_key: Some(principal_key_of(&book.public("svc-discord/auth")).unwrap()),
        signer: ControlSigner::Member(signer.into()),
        action,
        record_id: record_id(n),
        issued_at: ISSUED - 60_000 + n,
        about: ControlAbout {
            integration_id: Some(INTEGRATION.into()),
            by: "owner".into(),
        },
    }
}

/// `signer`'s `interrupt_running` of the host sender host-a (no origin).
fn host_interrupt(signer: &str, n: u64) -> ControlBody {
    ControlBody {
        account_id: ACCOUNT.into(),
        genesis_hash: genesis_hash(),
        feed: None,
        principal: ControlPrincipal::Host("host-a".into()),
        principal_key: None,
        signer: ControlSigner::Member(signer.into()),
        action: ControlAction::InterruptRunning {
            revoke_seq: Some(7),
        },
        record_id: record_id(n),
        issued_at: ISSUED - 60_000 + n,
        about: ControlAbout {
            integration_id: None,
            by: "owner".into(),
        },
    }
}

const REVOKE: ControlAction = ControlAction::Revoke {
    interrupt_running: true,
};
const INTERRUPT: ControlAction = ControlAction::InterruptRunning { revoke_seq: None };

fn text(body: &ControlBody) -> String {
    jcs(&body.to_json()).unwrap()
}

/// `body` signed by `key`, as the journal saved it.
fn signed(book: &Book, key: &str, body: &ControlBody) -> String {
    build_control(&book.provider, &KeyId::new(key), body)
        .unwrap()
        .to_json()
        .to_string()
}

/// dev-phone's plan: two stops of svc-discord at this Station, a host
/// sender's interrupt, and a draft.
struct Plan {
    records: Vec<ControlBody>,
    drafts: Vec<ControlBody>,
}

fn plan(book: &Book) -> Plan {
    Plan {
        records: vec![
            service_stop(book, "dev-phone", REVOKE, STATION, 1),
            service_stop(book, "dev-phone", INTERRUPT, STATION, 2),
            host_interrupt("dev-phone", 3),
        ],
        drafts: vec![service_stop(
            book,
            "dev-phone",
            ControlAction::Revoke {
                interrupt_running: false,
            },
            STATION,
            4,
        )],
    }
}

fn journal_of(records: &[String], drafts: &[String]) -> JournalView {
    JournalView {
        id: JOURNAL_ID,
        since: 4,
        revision: 118,
        records: records.to_vec(),
        drafts: drafts.to_vec(),
    }
}

fn journal(plan: &Plan) -> JournalView {
    journal_of(
        &plan.records.iter().map(text).collect::<Vec<_>>(),
        &plan.drafts.iter().map(text).collect::<Vec<_>>(),
    )
}

/// The plan's records as dev-phone signed them.
fn exported(book: &Book, plan: &Plan) -> Vec<String> {
    plan.records
        .iter()
        .map(|b| signed(book, "dev-phone/auth", b))
        .collect()
}

/// A report of `signer` at `log`'s head for `challenge` and `journal`,
/// signed with `key`.
fn report(
    book: &Book,
    key: &str,
    log: &Membership,
    signer: &str,
    challenge: &SignerReportChallenge,
    journal: &JournalView,
) -> String {
    let body = signer_report_body(
        log,
        challenge,
        signer,
        challenge.slot(),
        STATION,
        journal,
        NOW,
    )
    .unwrap();
    sign_signer_report(&book.provider, &KeyId::new(key), &body)
        .unwrap()
        .to_json()
        .to_string()
}

/// The body of `text` changed by `edit`, then signed with `key`.
fn resigned(book: &SoftwareKeys, key: &str, text: &str, edit: impl FnOnce(&mut Value)) -> String {
    let mut body: Value = serde_json::from_str::<Value>(text).unwrap()["body"].clone();
    edit(&mut body);
    SignedObject::sign(book, &KeyId::new(key), body)
        .unwrap()
        .to_json()
        .to_string()
}

/// SHA-256(enc([label, d1…dn])) over each body's SHA-256(jcs(body)),
/// sorted by bytes, computed here on its own.
fn set_hash(label: &str, bodies: &[String]) -> Hash32 {
    let mut digests: Vec<[u8; 32]> = bodies
        .iter()
        .map(|b| {
            let value: Value = serde_json::from_str(b).unwrap();
            Sha256::digest(jcs(&value).unwrap().as_bytes()).into()
        })
        .collect();
    digests.sort();
    let mut fields: Vec<&[u8]> = vec![label.as_bytes()];
    fields.extend(digests.iter().map(|d| &d[..]));
    Hash32(Sha256::digest(enc(&fields)).into())
}

fn verify(
    log: &Membership,
    text: &str,
    expected: &SignerReportChallenge,
    exported: &[String],
    now: u64,
) -> Result<atem_client::member_report::VerifiedSignerReport, ReportRefusal> {
    verify_signer_report(log, text.as_bytes(), expected, exported, now)
}

#[test]
fn a_manager_reports_its_journal_at_the_head() {
    let (v, book) = (Vectors::load(), Book::load());
    let log = log_l(&v);
    let plan = plan(&book);
    let challenge = challenge(PHONE, SLOT);
    let wire = challenge.to_json().to_string();
    assert_eq!(
        SignerReportChallenge::parse(wire.as_bytes()).unwrap(),
        challenge
    );
    assert_eq!(challenge.recovery(), &recovery());
    assert_eq!(challenge.to_json()["recovery"]["generation"], json!("7"));
    let journal = journal(&plan);
    let text = report(&book, "dev-phone/auth", &log, PHONE, &challenge, &journal);
    let exported = exported(&book, &plan);
    let verified = verify(&log, &text, &challenge, &exported, NOW).unwrap();
    assert_eq!(verified.signer, PHONE);
    assert_eq!(verified.slot, SLOT);
    assert_eq!(verified.process, process_generation());
    assert_eq!(verified.connection, 3);
    assert_eq!(verified.head, log.head());
    assert!(verified.at_head);
    assert_eq!(verified.recovery, recovery());
    assert_eq!(verified.journal.id, JOURNAL_ID);
    assert_eq!(verified.journal.since, 4);
    assert_eq!(verified.journal.revision, 118);
    assert_eq!(verified.journal.records, 3);
    assert_eq!(verified.journal.drafts, 1);
    assert_eq!(
        verified.journal.records_hash,
        set_hash(SIGNER_REPORT_RECORDS, &journal.records)
    );
    assert_eq!(
        verified.journal.drafts_hash,
        set_hash(SIGNER_REPORT_DRAFTS, &journal.drafts)
    );
    let ids: Vec<&str> = verified.records.iter().map(|r| r.record_id()).collect();
    assert_eq!(ids, [record_id(1), record_id(2), record_id(3)]);
    // The body as signed: the challenge's echo, the recovery and the
    // journal's summary.
    let body: Value = serde_json::from_str::<Value>(&text).unwrap()["body"].clone();
    assert_eq!(body["type"], "atem-signer-report");
    assert_eq!(
        body["recovery"],
        json!({"generation": "7", "plan_id": PLAN, "candidate_feed_id": CANDIDATE,
               "source_hash": "5a".repeat(32), "evidence_hash": "e7".repeat(32)})
    );
    assert_eq!(
        body["journal"],
        json!({"id": b64u(&JOURNAL_ID), "since": 4, "revision": 118,
               "records": 3, "records_hash": set_hash(SIGNER_REPORT_RECORDS, &journal.records).to_hex(),
               "drafts": 1, "drafts_hash": set_hash(SIGNER_REPORT_DRAFTS, &journal.drafts).to_hex()})
    );
    assert_eq!(
        body.as_object().unwrap().keys().collect::<Vec<_>>(),
        [
            "account_id",
            "challenge",
            "genesis_hash",
            "head",
            "journal",
            "process",
            "recovery",
            "signer",
            "slot",
            "type",
            "v"
        ]
    );
    // Exported in any order: the same set.
    let mut reversed = exported.clone();
    reversed.reverse();
    assert!(verify(&log, &text, &challenge, &reversed, NOW).is_ok());
}

#[test]
fn every_refusal_code_at_its_place_in_the_order() {
    let (v, mut book) = (Vectors::load(), Book::load());
    // L plus a native that never held manage.
    let viewer = native(
        &mut book.provider,
        "dev-viewer",
        &[Role::Control, Role::View],
    );
    let log = after(&book.provider, &log_l(&v), viewer, 1_792_400_006_000);
    let frozen = log
        .evaluate(&[strict(v.wire("C6_mac"))], &Clock::at(NOW).now)
        .next;
    assert!(frozen.frozen().is_some());
    assert_eq!(
        SIGNER_VERIFY_ORDER,
        [
            "malformed",
            "frozen",
            "wrong_account",
            "unknown_signer",
            "not_a_manager",
            "bad_signature",
            "stale_log",
            "fork",
            "signer_mismatch",
            "slot_mismatch",
            "challenge_mismatch",
            "recovery_mismatch",
            "records_mismatch",
            "expired"
        ]
    );
    let keys = &book.provider;
    let plan = plan(&book);
    let expected = challenge(PHONE, SLOT);
    let good = report(
        &book,
        "dev-phone/auth",
        &log,
        PHONE,
        &expected,
        &journal(&plan),
    );
    let all = exported(&book, &plan);
    let missing = &all[..2];
    let check =
        |log: &Membership,
         text: &str,
         expected: &SignerReportChallenge,
         exported: &[String],
         now: u64| { verify(log, text, expected, exported, now).map_err(|r| r.code()) };
    assert_eq!(
        check(&log, &good, &expected, &all, EXPIRES - 1).map(|r| r.at_head),
        Ok(true)
    );
    assert_eq!(check(&log, &good, &expected, &all, EXPIRES), Err("expired"));
    assert_eq!(
        check(&log, &good, &expected, missing, EXPIRES),
        Err("records_mismatch")
    );
    let mut other_plan = expected.to_json();
    other_plan["recovery"]["plan_id"] = json!("9b7c9d1e-2f3a-4b5c-8d6e-7f8091a2b3c4");
    assert_eq!(
        check(
            &log,
            &good,
            &challenge_of(other_plan.clone()),
            missing,
            EXPIRES
        ),
        Err("recovery_mismatch")
    );
    let mut wrong_nonce = other_plan;
    wrong_nonce["nonce"] = json!(b64u(&[9u8; 32]));
    assert_eq!(
        check(
            &log,
            &good,
            &challenge_of(wrong_nonce.clone()),
            missing,
            EXPIRES
        ),
        Err("challenge_mismatch")
    );
    let mut wrong_slot = wrong_nonce;
    wrong_slot["slot"] = json!("astation-mac");
    assert_eq!(
        check(
            &log,
            &good,
            &challenge_of(wrong_slot.clone()),
            missing,
            EXPIRES
        ),
        Err("slot_mismatch")
    );
    let mut wrong_signer = wrong_slot;
    wrong_signer["signer"] = json!("member:dev-mac");
    let other = challenge_of(wrong_signer);
    assert_eq!(
        check(&log, &good, &other, missing, EXPIRES),
        Err("signer_mismatch")
    );
    // On the chain but at another hash: E6's hash at seq 5.
    let fork = resigned(keys, "dev-phone/auth", &good, |b| {
        b["head"] = json!({"seq": 5, "hash": v.hash("E6").to_hex()})
    });
    assert_eq!(check(&log, &fork, &other, missing, EXPIRES), Err("fork"));
    let stale = resigned(keys, "dev-phone/auth", &good, |b| {
        b["head"] = json!({"seq": 9, "hash": Hash32([7; 32]).to_hex()})
    });
    assert_eq!(
        check(&log, &stale, &other, missing, EXPIRES),
        Err("stale_log")
    );
    let mut tampered: Value = serde_json::from_str(&stale).unwrap();
    tampered["body"]["slot"] = json!("astation-mac");
    let tampered = tampered.to_string();
    assert_eq!(
        check(&log, &tampered, &other, missing, EXPIRES),
        Err("bad_signature")
    );
    // A current native that never held manage, signing with another key.
    let viewer = resigned(keys, "dev-phone/auth", &stale, |b| {
        b["signer"] = json!("member:dev-viewer")
    });
    assert_eq!(
        check(&log, &viewer, &other, missing, EXPIRES),
        Err("not_a_manager")
    );
    // A member removed (dev-ipad, E6), and a service.
    for signer in ["member:dev-ipad", "service:svc-discord"] {
        let unknown = resigned(keys, "dev-phone/auth", &viewer, |b| {
            b["signer"] = json!(signer)
        });
        assert_eq!(
            check(&log, &unknown, &other, missing, EXPIRES),
            Err("unknown_signer"),
            "{signer}"
        );
    }
    let unknown = resigned(keys, "dev-phone/auth", &viewer, |b| {
        b["signer"] = json!("member:dev-ipad")
    });
    let wrong_account = resigned(keys, "dev-phone/auth", &unknown, |b| {
        b["account_id"] = json!("acct-other")
    });
    assert_eq!(
        check(&log, &wrong_account, &other, missing, EXPIRES),
        Err("wrong_account")
    );
    assert_eq!(
        check(&frozen, &wrong_account, &other, missing, EXPIRES),
        Err("frozen")
    );
    let mut malformed: Value = serde_json::from_str(&wrong_account).unwrap();
    malformed["body"]["journal"]["note"] = json!("x");
    assert_eq!(
        check(&frozen, &malformed.to_string(), &other, missing, EXPIRES),
        Err("malformed")
    );
}

#[test]
fn the_builder_refuses_another_station_signer_slot_or_an_expired_challenge() {
    let (v, mut book) = (Vectors::load(), Book::load());
    let viewer = native(&mut book.provider, "dev-viewer", &[Role::View]);
    let log = after(&book.provider, &log_l(&v), viewer, 1_792_400_006_000);
    let journal = journal(&plan(&book));
    let challenge = challenge(PHONE, SLOT);
    let build =
        |challenge: &SignerReportChallenge, signer: &str, slot: &str, station: &str, now: u64| {
            signer_report_body(&log, challenge, signer, slot, station, &journal, now)
                .map(|_| ())
                .map_err(|r| r.code())
        };
    assert_eq!(build(&challenge, PHONE, SLOT, STATION, NOW), Ok(()));
    // The configured Station, normalized, is the challenge's origin.
    assert_eq!(
        build(
            &challenge,
            PHONE,
            SLOT,
            "https://Station-Dev.agora.build/",
            NOW
        ),
        Ok(())
    );
    assert_eq!(
        build(&challenge, PHONE, SLOT, OTHER_STATION, NOW),
        Err("origin_mismatch")
    );
    assert_eq!(
        build(
            &challenge,
            PHONE,
            SLOT,
            "ftp://station-dev.agora.build",
            NOW
        ),
        Err("malformed")
    );
    assert_eq!(
        build(&challenge, "member:dev-mac", SLOT, STATION, NOW),
        Err("signer_mismatch")
    );
    assert_eq!(
        build(&challenge, PHONE, "astation-mac", STATION, NOW),
        Err("slot_mismatch")
    );
    assert_eq!(build(&challenge, PHONE, "", STATION, NOW), Err("malformed"));
    // Only a native member reports its signing journal.
    for signer in ["service:svc-discord", "host:host-a", "dev-phone"] {
        assert_eq!(
            build(&challenge, signer, SLOT, STATION, NOW),
            Err("malformed"),
            "{signer}"
        );
    }
    // The challenge at its expires_at on the reporter's clock.
    assert_eq!(
        build(&challenge, PHONE, SLOT, STATION, EXPIRES),
        Err("expired")
    );
    // A removed member, and a native that never held manage.
    let removed = challenge_with_signer("member:dev-ipad");
    assert_eq!(
        build(&removed, "member:dev-ipad", SLOT, STATION, NOW),
        Err("unknown_signer")
    );
    let never = challenge_with_signer("member:dev-viewer");
    assert_eq!(
        build(&never, "member:dev-viewer", SLOT, STATION, NOW),
        Err("not_a_manager")
    );
    // A frozen log reports nothing.
    let frozen = log
        .evaluate(&[strict(v.wire("C6_mac"))], &Clock::at(NOW).now)
        .next;
    assert_eq!(
        signer_report_body(&frozen, &challenge, PHONE, SLOT, STATION, &journal, NOW)
            .map(|_| ())
            .map_err(|r| r.code()),
        Err("frozen")
    );
}

fn challenge_with_signer(signer: &str) -> SignerReportChallenge {
    let mut fields = challenge(PHONE, SLOT).to_json();
    fields["signer"] = json!(signer);
    challenge_of(fields)
}

/// Each journal body is read strictly as a control-record body this
/// member signs, of this account and genesis: a service's stop naming this
/// origin or a host sender's interrupt. Anything else is `malformed`, and
/// so is a body twice in one set.
#[test]
fn the_builder_reads_each_journal_body_strictly() {
    let (v, book) = (Vectors::load(), Book::load());
    let log = log_l(&v);
    let challenge = challenge(PHONE, SLOT);
    let good = service_stop(&book, "dev-phone", REVOKE, STATION, 1);
    let build = |records: &[String], drafts: &[String]| {
        signer_report_body(
            &log,
            &challenge,
            PHONE,
            SLOT,
            STATION,
            &journal_of(records, drafts),
            NOW,
        )
        .map(|b| b.journal().clone())
        .map_err(|r| r.code())
    };
    assert!(build(&[text(&good)], &[]).is_ok());
    let edit = |f: &dyn Fn(&mut ControlBody)| {
        let mut b = good.clone();
        f(&mut b);
        text(&b)
    };
    let json_edit = |f: &dyn Fn(&mut Value)| {
        let mut b = good.to_json();
        f(&mut b);
        b.to_string()
    };
    let refused = [
        (
            "another account",
            edit(&|b| b.account_id = "acct-other".into()),
        ),
        (
            "another genesis",
            edit(&|b| b.genesis_hash = Hash32([1; 32])),
        ),
        (
            "another member's",
            edit(&|b| b.signer = ControlSigner::Member("dev-mac".into())),
        ),
        (
            "the service's own key's",
            edit(&|b| b.signer = ControlSigner::Principal),
        ),
        (
            "another origin",
            edit(&|b| {
                b.feed = Some(ControlFeed {
                    origin: OTHER_STATION.into(),
                    feed_id: FEED.into(),
                })
            }),
        ),
        ("a cover", edit(&|b| b.action = ControlAction::Cover)),
        ("a hold", edit(&|b| b.action = ControlAction::Hold)),
        ("a release", edit(&|b| b.action = ControlAction::Release)),
        ("not JSON", "{".to_owned()),
        ("an array", format!("[{}]", text(&good))),
        ("a field beyond", json_edit(&|b| b["note"] = json!("x"))),
        ("a null", json_edit(&|b| b["about"]["by"] = Value::Null)),
        (
            "a duplicate key",
            text(&good).replacen(r#""v":1"#, r#""v":1,"v":1"#, 1),
        ),
        (
            "an escaped duplicate key",
            text(&good).replacen(r#""v":1"#, r#""v":1,"\u0076":1"#, 1),
        ),
        (
            "another type",
            json_edit(&|b| b["type"] = json!("atem-verifier-report")),
        ),
        ("v 2", json_edit(&|b| b["v"] = json!(2))),
        ("a signed object", signed(&book, "dev-phone/auth", &good)),
        (
            "a fraction",
            text(&good).replacen(r#""v":1"#, r#""v":1.5"#, 1),
        ),
    ];
    for (what, body) in &refused {
        assert_eq!(
            build(std::slice::from_ref(body), &[]),
            Err("malformed"),
            "a record: {what}"
        );
        assert_eq!(
            build(&[], std::slice::from_ref(body)),
            Err("malformed"),
            "a draft: {what}"
        );
    }
    // A body twice in one set, even written another way.
    let spaced = serde_json::to_string_pretty(&good.to_json()).unwrap();
    assert_eq!(build(&[text(&good), spaced.clone()], &[]), Err("malformed"));
    assert_eq!(build(&[], &[text(&good), text(&good)]), Err("malformed"));
    // A body written another way hashes as its jcs; the same body as a
    // record and as a draft is read (only one set at a time is a set).
    assert_eq!(build(&[spaced], &[]), build(&[text(&good)], &[]));
    assert!(build(&[text(&good)], &[text(&good)]).is_ok());
    // A host sender's interrupt names no origin; any other host form is
    // no record at all.
    assert!(build(&[text(&host_interrupt("dev-phone", 2))], &[]).is_ok());
    let mut host_revoke = host_interrupt("dev-phone", 2).to_json();
    host_revoke["action"] = json!("revoke");
    assert_eq!(build(&[host_revoke.to_string()], &[]), Err("malformed"));
    // The journal's own grammar.
    let bad_since = JournalView {
        since: 0,
        ..journal_of(&[], &[])
    };
    let bad_revision = JournalView {
        revision: 1 << 53,
        ..journal_of(&[], &[])
    };
    for journal in [bad_since, bad_revision] {
        assert_eq!(
            signer_report_body(&log, &challenge, PHONE, SLOT, STATION, &journal, NOW)
                .map(|_| ())
                .map_err(|r| r.code()),
            Err("malformed")
        );
    }
}

/// The plan predicate (`signer_report_plan_record`, Astation's ask on #114
/// comment 7093796254): whether a control-record body is one of the plan's
/// records for this member and origin, typed. In the plan: this member's
/// service `revoke` or `interrupt_running` naming the origin, or its
/// `host:` interrupt (no origin, so at any origin). Not in the plan, in the
/// order checked: another account, genesis, signer, then a service's stop
/// at another origin. Refused (`malformed`): this member's cover, hold or
/// release (reading (c), checked after the signer and before the origin),
/// a body that isn't a control record's, and a member or origin outside
/// its grammar.
#[test]
fn the_plan_predicate_judges_a_body_by_the_builders_rule() {
    let (v, book) = (Vectors::load(), Book::load());
    let log = log_l(&v);
    let good = service_stop(&book, "dev-phone", REVOKE, STATION, 1);
    let judge = |body: &str, member: &str, origin: &str| {
        signer_report_plan_record(&log, body, member, origin).map_err(|r| r.code())
    };
    let edit = |f: &dyn Fn(&mut ControlBody)| {
        let mut b = good.clone();
        f(&mut b);
        text(&b)
    };
    let out = |reason| Ok(PlanRecord::NotInPlan(reason));
    let in_plan = Ok(PlanRecord::InPlan);
    // In the plan.
    for (what, body) in [
        ("a revoke with interrupt_running", text(&good)),
        (
            "an interrupt_running",
            text(&service_stop(&book, "dev-phone", INTERRUPT, STATION, 2)),
        ),
        (
            "a revoke without interrupt_running",
            edit(&|b| {
                b.action = ControlAction::Revoke {
                    interrupt_running: false,
                }
            }),
        ),
        (
            "a host sender's interrupt",
            text(&host_interrupt("dev-phone", 3)),
        ),
        (
            "a body written another way",
            serde_json::to_string_pretty(&good.to_json()).unwrap(),
        ),
    ] {
        assert_eq!(judge(&body, PHONE, STATION), in_plan, "{what}");
    }
    // A host sender's interrupt names no origin: it is the plan's at any.
    assert_eq!(
        judge(&text(&host_interrupt("dev-phone", 3)), PHONE, OTHER_STATION),
        in_plan
    );
    // Not in the plan, each with why.
    assert_eq!(
        judge(
            &edit(&|b| b.account_id = "acct-other".into()),
            PHONE,
            STATION
        ),
        out(OutOfPlan::AnotherAccount)
    );
    assert_eq!(
        judge(&edit(&|b| b.genesis_hash = Hash32([1; 32])), PHONE, STATION),
        out(OutOfPlan::AnotherGenesis)
    );
    for (what, signer) in [
        ("another member's", ControlSigner::Member("dev-mac".into())),
        ("the service's own key's", ControlSigner::Principal),
    ] {
        let body = edit(&|b| b.signer = signer.clone());
        assert_eq!(
            judge(&body, PHONE, STATION),
            out(OutOfPlan::AnotherSigner),
            "{what}"
        );
    }
    assert_eq!(
        judge(&text(&good), "member:dev-mac", STATION),
        out(OutOfPlan::AnotherSigner),
        "asked for another member"
    );
    let elsewhere = edit(&|b| {
        b.feed = Some(ControlFeed {
            origin: OTHER_STATION.into(),
            feed_id: FEED.into(),
        })
    });
    assert_eq!(
        judge(&elsewhere, PHONE, STATION),
        out(OutOfPlan::AnotherOrigin)
    );
    assert_eq!(
        judge(&text(&good), PHONE, OTHER_STATION),
        out(OutOfPlan::AnotherOrigin),
        "asked for another origin"
    );
    // This member's cover, hold or release is refused, never skipped, at
    // any origin; another signer's, account's or genesis's is out first.
    for action in [
        ControlAction::Cover,
        ControlAction::Hold,
        ControlAction::Release,
    ] {
        let mine = edit(&|b| b.action = action);
        assert_eq!(judge(&mine, PHONE, STATION), Err("malformed"), "{action:?}");
        assert_eq!(
            judge(&mine, PHONE, OTHER_STATION),
            Err("malformed"),
            "{action:?}"
        );
        let theirs = edit(&|b| {
            b.action = action;
            b.signer = ControlSigner::Principal;
        });
        assert_eq!(
            judge(&theirs, PHONE, STATION),
            out(OutOfPlan::AnotherSigner)
        );
        let other_account = edit(&|b| {
            b.action = action;
            b.account_id = "acct-other".into();
        });
        assert_eq!(
            judge(&other_account, PHONE, STATION),
            out(OutOfPlan::AnotherAccount)
        );
    }
    // What isn't a control record's body.
    let mut host_revoke = host_interrupt("dev-phone", 2).to_json();
    host_revoke["action"] = json!("revoke");
    let json_edit = |f: &dyn Fn(&mut Value)| {
        let mut b = good.to_json();
        f(&mut b);
        b.to_string()
    };
    for (what, body) in [
        ("not JSON", "{".to_owned()),
        ("an array", format!("[{}]", text(&good))),
        ("a field beyond", json_edit(&|b| b["note"] = json!("x"))),
        ("a null", json_edit(&|b| b["about"]["by"] = Value::Null)),
        (
            "a duplicate key",
            text(&good).replacen(r#""v":1"#, r#""v":1,"v":1"#, 1),
        ),
        ("a signed object", signed(&book, "dev-phone/auth", &good)),
        ("a host principal's revoke", host_revoke.to_string()),
        (
            "over 16 KiB",
            format!("{}{}", " ".repeat(16 * 1024), text(&good)),
        ),
    ] {
        assert_eq!(judge(&body, PHONE, STATION), Err("malformed"), "{what}");
    }
    // The member and the origin in their grammar: `member:<id>`, the
    // origin exactly as normalize_relay writes it.
    for member in ["service:svc-discord", "host:host-a", "dev-phone", ""] {
        assert_eq!(
            judge(&text(&good), member, STATION),
            Err("malformed"),
            "{member}"
        );
    }
    for origin in [
        "https://Station-Dev.agora.build/",
        "ftp://station-dev.agora.build",
        "",
    ] {
        assert_eq!(
            judge(&text(&good), PHONE, origin),
            Err("malformed"),
            "{origin}"
        );
    }
    // Bodies only: neither the list's freeze nor the member's standing
    // changes an answer (the builder refuses those itself).
    let frozen = log
        .evaluate(&[strict(v.wire("C6_mac"))], &Clock::at(NOW).now)
        .next;
    assert!(frozen.frozen().is_some());
    assert_eq!(
        signer_report_plan_record(&frozen, &text(&good), PHONE, STATION),
        Ok(PlanRecord::InPlan)
    );
    let stranger = service_stop(&book, "dev-evil", REVOKE, STATION, 1);
    assert_eq!(judge(&text(&stranger), "member:dev-evil", STATION), in_plan);
}

/// The predicate is the builder's rule: a body the builder takes in a
/// journal set is exactly one the predicate puts in the plan, as a record
/// and as a draft, for every body the strict reading test refuses or
/// takes.
#[test]
fn the_plan_predicate_and_the_builder_agree_on_every_body() {
    let (v, book) = (Vectors::load(), Book::load());
    let log = log_l(&v);
    let good = service_stop(&book, "dev-phone", REVOKE, STATION, 1);
    let edit = |f: &dyn Fn(&mut ControlBody)| {
        let mut b = good.clone();
        f(&mut b);
        text(&b)
    };
    let mut bodies = vec![
        text(&good),
        text(&service_stop(&book, "dev-phone", INTERRUPT, STATION, 2)),
        text(&host_interrupt("dev-phone", 3)),
        text(&host_interrupt("dev-mac", 3)),
        edit(&|b| b.account_id = "acct-other".into()),
        edit(&|b| b.genesis_hash = Hash32([1; 32])),
        edit(&|b| b.signer = ControlSigner::Member("dev-mac".into())),
        edit(&|b| b.signer = ControlSigner::Principal),
        edit(&|b| {
            b.feed = Some(ControlFeed {
                origin: OTHER_STATION.into(),
                feed_id: FEED.into(),
            })
        }),
        "{".to_owned(),
        signed(&book, "dev-phone/auth", &good),
    ];
    for action in [
        ControlAction::Cover,
        ControlAction::Hold,
        ControlAction::Release,
    ] {
        bodies.push(edit(&|b| b.action = action));
    }
    for (challenge, station, member) in [
        (challenge(PHONE, SLOT), STATION, PHONE),
        (
            SignerReportChallenge::new(MAC, SLOT, OTHER_STATION, 3, ISSUED, EXPIRES, recovery())
                .unwrap(),
            OTHER_STATION,
            MAC,
        ),
    ] {
        for body in &bodies {
            let in_plan = signer_report_plan_record(&log, body, member, challenge.origin())
                == Ok(PlanRecord::InPlan);
            for (records, drafts) in [(vec![body.clone()], vec![]), (vec![], vec![body.clone()])] {
                let built = signer_report_body(
                    &log,
                    &challenge,
                    member,
                    SLOT,
                    station,
                    &journal_of(&records, &drafts),
                    NOW,
                );
                assert_eq!(built.is_ok(), in_plan, "{member} at {station}: {body}");
            }
        }
    }
}

/// `records_hash` and `drafts_hash` are SHA-256 over their own label and
/// the bodies' digests sorted by bytes: the journal's order changes
/// nothing, an empty set hashes its label alone, and the two sets never
/// share a hash.
#[test]
fn the_journal_hashes_are_over_sorted_body_digests() {
    let (v, book) = (Vectors::load(), Book::load());
    let log = log_l(&v);
    let challenge = challenge(PHONE, SLOT);
    let plan = plan(&book);
    let summary = |journal: &JournalView| {
        signer_report_body(&log, &challenge, PHONE, SLOT, STATION, journal, NOW)
            .unwrap()
            .journal()
            .clone()
    };
    let records: Vec<String> = plan.records.iter().map(text).collect();
    let mut shuffled = records.clone();
    shuffled.rotate_left(1);
    let one = summary(&journal_of(&records, &[]));
    let two = summary(&journal_of(&shuffled, &[]));
    assert_eq!(one, two);
    assert_eq!(one.records, 3);
    assert_eq!(one.records_hash, set_hash(SIGNER_REPORT_RECORDS, &records));
    let empty = summary(&journal_of(&[], &[]));
    assert_eq!((empty.records, empty.drafts), (0, 0));
    assert_eq!(
        empty.records_hash,
        Hash32(Sha256::digest(enc(&[SIGNER_REPORT_RECORDS.as_bytes()])).into())
    );
    assert_eq!(
        empty.drafts_hash,
        Hash32(Sha256::digest(enc(&[SIGNER_REPORT_DRAFTS.as_bytes()])).into())
    );
    let as_drafts = summary(&journal_of(&[], &records));
    assert_eq!(as_drafts.drafts, 3);
    assert_eq!(
        as_drafts.drafts_hash,
        set_hash(SIGNER_REPORT_DRAFTS, &records)
    );
    assert_ne!(as_drafts.drafts_hash, one.records_hash);
}

/// The exported set must be exactly the report's `records`: each a signed
/// control record of the plan by this member, verified under its key, once.
#[test]
fn records_mismatch_in_each_form() {
    let (v, book) = (Vectors::load(), Book::load());
    let log = log_l(&v);
    let plan = plan(&book);
    let expected = challenge(PHONE, SLOT);
    let text = report(
        &book,
        "dev-phone/auth",
        &log,
        PHONE,
        &expected,
        &journal(&plan),
    );
    let all = exported(&book, &plan);
    let check = |exported: &[String]| {
        verify(&log, &text, &expected, exported, NOW)
            .map(|_| ())
            .map_err(|r| r.code())
    };
    assert_eq!(check(&all), Ok(()));
    let with = |i: usize, record: String| {
        let mut out = all.clone();
        out[i] = record;
        out
    };
    let later = service_stop(&book, "dev-phone", INTERRUPT, STATION, 9);
    let mut extra = all.clone();
    extra.push(signed(&book, "dev-phone/auth", &later));
    let mut twice = all[..2].to_vec();
    twice.push(all[0].clone());
    // The same body signed twice is one body: still a duplicate.
    let resigned_r1 = {
        let mut object: Value = serde_json::from_str(&all[0]).unwrap();
        let sig = sign(
            &book.provider,
            &KeyId::new("dev-phone/auth"),
            &SigningInput::new(
                SignLabel::HostWorkControl,
                text_of(&object["body"]).as_bytes(),
            ),
        )
        .unwrap();
        object["sig"] = json!(b64u(&sig));
        object.to_string()
    };
    let mut twice_signed = all[..2].to_vec();
    twice_signed.push(resigned_r1);
    let mac_signed = service_stop(&book, "dev-mac", REVOKE, STATION, 1);
    let elsewhere = service_stop(&book, "dev-phone", REVOKE, OTHER_STATION, 1);
    let forged = {
        let mut object: Value = serde_json::from_str(&all[0]).unwrap();
        let sig = sign(
            &book.provider,
            &KeyId::new("dev-mac/auth"),
            &SigningInput::new(
                SignLabel::HostWorkControl,
                text_of(&object["body"]).as_bytes(),
            ),
        )
        .unwrap();
        object["sig"] = json!(b64u(&sig));
        object.to_string()
    };
    let high = {
        let mut object: Value = serde_json::from_str(&all[0]).unwrap();
        let sig = atem_client::encoding::b64u_decode(object["sig"].as_str().unwrap()).unwrap();
        object["sig"] = json!(b64u(&high_s(&sig)));
        object.to_string()
    };
    let unsigned = format!(r#"{{"body":{}}}"#, self::text(&plan.records[0]));
    let in_place = with(0, signed(&book, "dev-phone/auth", &later));
    let cases: Vec<(&str, Vec<String>, &str)> = vec![
        ("one missing", all[..2].to_vec(), "count"),
        ("none", Vec::new(), "count"),
        ("one extra, signed after the report", extra, "count"),
        (
            "one signed after the report, in place of one",
            in_place,
            "records_hash",
        ),
        ("a duplicate", twice, "duplicate"),
        ("the same body signed again", twice_signed, "duplicate"),
        (
            "a possibly signed body without a signature",
            with(0, unsigned),
            "not a control record",
        ),
        (
            "another member's record",
            with(0, signed(&book, "dev-mac/auth", &mac_signed)),
            "not a record of the plan",
        ),
        (
            "a record naming another origin",
            with(0, signed(&book, "dev-phone/auth", &elsewhere)),
            "not a record of the plan",
        ),
        ("a signature by another key", with(0, forged), "signature"),
        ("a high S", with(0, high), "signature"),
        ("not a record", with(0, "{}".into()), "not a control record"),
        (
            "its body alone",
            with(0, self::text(&plan.records[0])),
            "not a control record",
        ),
    ];
    for (what, exported, why) in &cases {
        assert_eq!(
            verify(&log, &text, &expected, exported, NOW).map(|_| ()),
            Err(ReportRefusal::RecordsMismatch(why)),
            "{what}"
        );
        assert_eq!(check(exported), Err("records_mismatch"), "{what}");
    }
}

/// The exported set's count is checked before any record is parsed or any
/// signature verified: a list of the wrong length is refused for its count
/// however many records it carries, and whatever they are.
#[test]
fn the_count_is_checked_before_any_signature() {
    let (v, book) = (Vectors::load(), Book::load());
    let log = log_l(&v);
    let plan = plan(&book);
    let expected = challenge(PHONE, SLOT);
    let text = report(
        &book,
        "dev-phone/auth",
        &log,
        PHONE,
        &expected,
        &journal(&plan),
    );
    for exported in [
        vec!["{}".to_owned(); 4],
        vec!["{}".to_owned(); 2],
        Vec::new(),
    ] {
        assert_eq!(
            verify(&log, &text, &expected, &exported, NOW).map(|_| ()),
            Err(ReportRefusal::RecordsMismatch("count")),
            "{} exported",
            exported.len()
        );
    }
    // The right count of records that aren't records is refused as such.
    assert_eq!(
        verify(&log, &text, &expected, &vec!["{}".to_owned(); 3], NOW).map(|_| ()),
        Err(ReportRefusal::RecordsMismatch("not a control record"))
    );
}

fn text_of(value: &Value) -> String {
    jcs(value).unwrap()
}

/// A body the journal holds as `signing` with no saved signature is in
/// `records`; it can't be exported as signed, so the report stays refused
/// (Astation's conservative rule: no permissive path).
#[test]
fn a_possibly_signed_body_keeps_the_report_refused() {
    let (v, book) = (Vectors::load(), Book::load());
    let log = log_l(&v);
    let plan = plan(&book);
    let mut records: Vec<String> = plan.records.iter().map(text).collect();
    let signing = service_stop(&book, "dev-phone", INTERRUPT, STATION, 8);
    records.push(text(&signing));
    let expected = challenge(PHONE, SLOT);
    let report = report(
        &book,
        "dev-phone/auth",
        &log,
        PHONE,
        &expected,
        &journal_of(&records, &[]),
    );
    let signed_ones = exported(&book, &plan);
    assert_eq!(
        verify(&log, &report, &expected, &signed_ones, NOW).map(|_| ()),
        Err(ReportRefusal::RecordsMismatch("count"))
    );
    // Once its signature is recovered and exported, the report verifies.
    let mut all = signed_ones;
    all.push(signed(&book, "dev-phone/auth", &signing));
    assert!(verify(&log, &report, &expected, &all, NOW).is_ok());
}

#[test]
fn a_challenge_is_exactly_its_fields() {
    let good = challenge(PHONE, SLOT).to_json();
    let compact = good.to_string();
    assert!(SignerReportChallenge::parse(compact.as_bytes()).is_ok());
    let edit = |f: &dyn Fn(&mut Value)| {
        let mut c = good.clone();
        f(&mut c);
        c.to_string()
    };
    let mut refused = vec![
        compact.replacen('{', r#"{"slot":"astation-mac","#, 1),
        compact.replacen('{', r#"{"\u0073lot":"astation-mac","#, 1),
        compact.replacen(r#""plan_id":"#, r#""plan_id":"x","plan_id":"#, 1),
        edit(&|c| c["note"] = json!("x")),
        edit(&|c| c["recovery"]["note"] = json!("x")),
        edit(&|c| c["slot"] = Value::Null),
        edit(&|c| c["recovery"] = Value::Null),
        edit(&|c| {
            c["recovery"]
                .as_object_mut()
                .unwrap()
                .remove("evidence_hash");
        }),
        edit(&|c| {
            c.as_object_mut().unwrap().remove("recovery");
        }),
        // Only a native member reports its journal.
        edit(&|c| c["signer"] = json!("service:svc-discord")),
        edit(&|c| c["signer"] = json!("host:host-a")),
        edit(&|c| c["expires_at"] = json!(ISSUED)),
        edit(&|c| c["expires_at"] = json!(ISSUED + 30_001)),
        edit(&|c| c["origin"] = json!("https://station-dev.agora.build/")),
        format!("[{compact}]"),
        compact.replacen(',', &format!("{},", " ".repeat(4096)), 1),
    ];
    for generation in [
        json!(7),
        json!(""),
        json!("0"),
        json!("07"),
        json!("+7"),
        json!(" 7"),
        json!("7 "),
        json!("-7"),
        json!("7.0"),
        json!("1e3"),
        json!("9223372036854775808"),
        json!("99999999999999999999"),
    ] {
        refused.push(edit(&|c| c["recovery"]["generation"] = generation.clone()));
    }
    for (field, value) in [
        ("plan_id", json!("5b7c9d1e-2f3a-1b5c-8d6e-7f8091a2b3c4")),
        ("plan_id", json!("5B7C9D1E-2F3A-4B5C-8D6E-7F8091A2B3C4")),
        ("plan_id", json!("5b7c9d1e2f3a4b5c8d6e7f8091a2b3c4")),
        ("candidate_feed_id", json!("not-a-uuid")),
        ("source_hash", json!("5A".repeat(32))),
        ("source_hash", json!("5a".repeat(31))),
        ("evidence_hash", json!(7)),
    ] {
        refused.push(edit(&|c| c["recovery"][field] = value.clone()));
    }
    for text in &refused {
        assert!(
            matches!(
                SignerReportChallenge::parse(text.as_bytes()),
                Err(ReportRefusal::Malformed(_))
            ),
            "{text}"
        );
    }
    // The largest generation, and a loopback Station.
    let max = edit(&|c| c["recovery"]["generation"] = json!(MAX_GENERATION.to_string()));
    let read = SignerReportChallenge::parse(max.as_bytes()).unwrap();
    assert_eq!(read.recovery().generation(), MAX_GENERATION);
    assert_eq!(MAX_GENERATION, (1 << 63) - 1);
    let loopback = edit(&|c| c["origin"] = json!("http://127.0.0.1:8080"));
    assert!(SignerReportChallenge::parse(loopback.as_bytes()).is_ok());
    // The constructors refuse what the reader refuses.
    assert!(RecoveryPlan::new(0, PLAN, CANDIDATE, Hash32([0; 32]), Hash32([0; 32])).is_err());
    assert!(
        RecoveryPlan::new(
            MAX_GENERATION + 1,
            PLAN,
            CANDIDATE,
            Hash32([0; 32]),
            Hash32([0; 32])
        )
        .is_err()
    );
    assert!(RecoveryPlan::new(1, "plan", CANDIDATE, Hash32([0; 32]), Hash32([0; 32])).is_err());
    assert!(
        SignerReportChallenge::new(
            "service:svc-discord",
            SLOT,
            STATION,
            3,
            ISSUED,
            EXPIRES,
            recovery()
        )
        .is_err()
    );
    assert!(
        SignerReportChallenge::new(PHONE, SLOT, STATION, 3, ISSUED, ISSUED + 30_001, recovery())
            .is_err()
    );
    // A fresh nonce each time; the Station normalized.
    let a = SignerReportChallenge::new(
        PHONE,
        SLOT,
        "https://Station-Dev.agora.build/",
        3,
        ISSUED,
        EXPIRES,
        recovery(),
    )
    .unwrap();
    let b = challenge(PHONE, SLOT);
    assert_eq!(a.origin(), STATION);
    assert_ne!(a.nonce(), b.nonce());
}

/// A manager demoted since still reports (it held `manage` at some `seq`
/// of the list: its stops before the demotion count); a current native
/// that never held `manage` is `not_a_manager`.
#[test]
fn a_demoted_manager_still_reports_and_a_native_that_never_managed_does_not() {
    let (v, mut book) = (Vectors::load(), Book::load());
    let l = log_l(&v);
    let demoted = after(
        &book.provider,
        &l,
        Action::SetRoles {
            device_id: "dev-phone".into(),
            change: RolesChange::Native([Role::View].into_iter().collect()),
        },
        1_792_400_006_000,
    );
    let plan = plan(&book);
    let challenge = challenge(PHONE, SLOT);
    let text = report(
        &book,
        "dev-phone/auth",
        &demoted,
        PHONE,
        &challenge,
        &journal(&plan),
    );
    let verified = verify(&demoted, &text, &challenge, &exported(&book, &plan), NOW).unwrap();
    assert!(verified.at_head);
    let viewer = native(
        &mut book.provider,
        "dev-viewer",
        &[Role::Control, Role::View],
    );
    let log = after(&book.provider, &l, viewer, 1_792_400_006_000);
    let never = challenge_with_signer("member:dev-viewer");
    let journal = journal_of(&[], &[]);
    assert_eq!(
        signer_report_body(
            &log,
            &never,
            "member:dev-viewer",
            SLOT,
            STATION,
            &journal,
            NOW
        )
        .map(|_| ()),
        Err(ReportRefusal::NotAManager)
    );
    let by_phone = report(&book, "dev-phone/auth", &log, PHONE, &challenge, &journal);
    let as_viewer = resigned(&book.provider, "dev-viewer/auth", &by_phone, |b| {
        b["signer"] = json!("member:dev-viewer")
    });
    assert_eq!(
        verify(&log, &as_viewer, &never, &[], NOW).map(|_| ()),
        Err(ReportRefusal::NotAManager)
    );
    // Given manage later, it held manage at some seq: it reports.
    let promoted = after(
        &book.provider,
        &log,
        Action::SetRoles {
            device_id: "dev-viewer".into(),
            change: RolesChange::Native([Role::Manage, Role::View].into_iter().collect()),
        },
        1_792_400_007_000,
    );
    let promoted_text = report(
        &book,
        "dev-viewer/auth",
        &promoted,
        "member:dev-viewer",
        &never,
        &journal,
    );
    assert!(verify(&promoted, &promoted_text, &never, &[], NOW).is_ok());
}

/// A manager added through a Recovery Kit (`recovery_add` of a native with
/// `manage`) is a manager once its recovery took effect (here approved by
/// dev-mac, r9-vectors-membership-log's R7 then A8): its report verifies.
/// While the recovery still waits it is no current member.
#[test]
fn a_manager_added_by_a_recovery_that_took_effect_reports() {
    let (v, book) = (Vectors::load(), Book::load());
    let now = Clock::at(NOW).now;
    let l = log_l(&v);
    let waiting = l.evaluate_objects(&[v.object("R7")], &now).next;
    let recovered = l
        .evaluate_objects(&[v.object("R7"), v.object("A8")], &now)
        .next;
    assert_eq!(recovered.head().seq, 8);
    let newmac = "member:dev-newmac";
    let challenge = challenge_with_signer(newmac);
    let stop = service_stop(&book, "dev-newmac", REVOKE, STATION, 1);
    let journal = journal_of(&[text(&stop)], &[]);
    let body =
        signer_report_body(&recovered, &challenge, newmac, SLOT, STATION, &journal, NOW).unwrap();
    let report = sign_signer_report(&book.provider, &KeyId::new("dev-newmac/auth"), &body)
        .unwrap()
        .to_json()
        .to_string();
    let exported = [signed(&book, "dev-newmac/auth", &stop)];
    let verified = verify(&recovered, &report, &challenge, &exported, NOW).unwrap();
    assert_eq!(verified.signer, newmac);
    assert!(verified.at_head);
    assert_eq!(verified.journal.records, 1);
    // Still waiting: no current member, at the builder and the verifier.
    assert_eq!(
        signer_report_body(&waiting, &challenge, newmac, SLOT, STATION, &journal, NOW).map(|_| ()),
        Err(ReportRefusal::UnknownSigner)
    );
    assert_eq!(
        verify(&waiting, &report, &challenge, &exported, NOW).map(|_| ()),
        Err(ReportRefusal::UnknownSigner)
    );
}

/// Services, hosts, `recovery`, grants and removed members never report.
#[test]
fn only_a_current_native_signs_a_signer_report() {
    let (v, book) = (Vectors::load(), Book::load());
    let log = log_l(&v);
    let challenge = challenge(PHONE, SLOT);
    let good = report(
        &book,
        "dev-phone/auth",
        &log,
        PHONE,
        &challenge,
        &journal_of(&[], &[]),
    );
    for (signer, key) in [
        ("service:svc-discord", "svc-discord/auth"),
        ("member:svc-discord", "svc-discord/auth"),
        ("host:host-a", "host-a/host_key"),
        ("browser:grant-1", "browser/auth"),
        ("member:recovery", "dev-phone/auth"),
        ("member:dev-ipad", "dev-ipad/auth"),
        ("member:dev-evil", "dev-evil/auth"),
    ] {
        let text = resigned(&book.provider, key, &good, |b| b["signer"] = json!(signer));
        assert_eq!(
            verify(&log, &text, &challenge, &[], NOW).map(|_| ()),
            Err(ReportRefusal::UnknownSigner),
            "{signer}"
        );
    }
}

#[test]
fn an_ancestor_head_verifies_with_at_head_false() {
    let (v, mut book) = (Vectors::load(), Book::load());
    let l = log_l(&v);
    let plan = plan(&book);
    let challenge = challenge(PHONE, SLOT);
    let text = report(
        &book,
        "dev-phone/auth",
        &l,
        PHONE,
        &challenge,
        &journal(&plan),
    );
    let viewer = native(&mut book.provider, "dev-viewer", &[Role::View]);
    let later = after(&book.provider, &l, viewer, 1_792_400_006_000);
    let verified = verify(&later, &text, &challenge, &exported(&book, &plan), NOW).unwrap();
    assert!(!verified.at_head);
    assert_eq!(verified.head, l.head());
}

/// A reinstalled journal (another `id`, a later `since`) is a valid report
/// for the primitive; comparing it with the earlier one is the Station's.
#[test]
fn a_reinstalled_journal_is_valid_for_the_primitive() {
    let (v, book) = (Vectors::load(), Book::load());
    let log = log_l(&v);
    let challenge = challenge(PHONE, SLOT);
    let reinstalled = JournalView {
        id: *b"journal-id-0002!",
        since: 6,
        revision: 0,
        records: Vec::new(),
        drafts: Vec::new(),
    };
    let text = report(
        &book,
        "dev-phone/auth",
        &log,
        PHONE,
        &challenge,
        &reinstalled,
    );
    let verified = verify(&log, &text, &challenge, &[], NOW).unwrap();
    assert_eq!(verified.journal.id, *b"journal-id-0002!");
    assert_eq!((verified.journal.since, verified.journal.revision), (6, 0));
    assert!(verified.records.is_empty());
}

#[test]
fn every_recovery_field_is_compared() {
    let (v, book) = (Vectors::load(), Book::load());
    let log = log_l(&v);
    let expected = challenge(PHONE, SLOT);
    let text = report(
        &book,
        "dev-phone/auth",
        &log,
        PHONE,
        &expected,
        &journal_of(&[], &[]),
    );
    assert!(verify(&log, &text, &expected, &[], NOW).is_ok());
    for (field, value) in [
        ("generation", json!("8")),
        ("plan_id", json!("9b7c9d1e-2f3a-4b5c-8d6e-7f8091a2b3c4")),
        (
            "candidate_feed_id",
            json!("9a2d3c4b-5e6f-4071-9b8c-0d1e2f3a4b5c"),
        ),
        ("source_hash", json!("5b".repeat(32))),
        ("evidence_hash", json!("e8".repeat(32))),
    ] {
        let mut other = expected.to_json();
        other["recovery"][field] = value;
        assert_eq!(
            verify(&log, &text, &challenge_of(other), &[], NOW).map(|_| ()),
            Err(ReportRefusal::RecoveryMismatch),
            "{field}"
        );
    }
}

#[test]
fn a_frozen_log_reports_nothing_and_verifies_nothing() {
    let (v, book) = (Vectors::load(), Book::load());
    let log = log_l(&v);
    let challenge = challenge(PHONE, SLOT);
    let journal = journal_of(&[], &[]);
    let text = report(&book, "dev-phone/auth", &log, PHONE, &challenge, &journal);
    let frozen = log
        .evaluate(&[strict(v.wire("C6_mac"))], &Clock::at(NOW).now)
        .next;
    assert!(frozen.frozen().is_some());
    assert_eq!(
        signer_report_body(&frozen, &challenge, PHONE, SLOT, STATION, &journal, NOW).map(|_| ()),
        Err(ReportRefusal::Frozen)
    );
    assert_eq!(
        verify(&frozen, &text, &challenge, &[], NOW).map(|_| ()),
        Err(ReportRefusal::Frozen)
    );
}

/// The held body takes only a signature over itself by its signer, and the
/// report is the held body with the signature, byte for byte.
#[test]
fn a_held_body_takes_only_its_signers_signature_over_itself() {
    let (v, book) = (Vectors::load(), Book::load());
    let keys = &book.provider;
    let log = log_l(&v);
    let challenge = challenge(PHONE, SLOT);
    let plan = plan(&book);
    let held =
        signer_report_body(&log, &challenge, PHONE, SLOT, STATION, &journal(&plan), NOW).unwrap();
    let other = signer_report_body(
        &log,
        &challenge,
        PHONE,
        SLOT,
        STATION,
        &journal_of(&[], &[]),
        NOW,
    )
    .unwrap();
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
    let sig = sign(keys, &phone, &held.signing_input()).unwrap();
    let report = held.with_signature(&sig).unwrap();
    assert_eq!(report.jcs(), held.jcs());
    assert_eq!(
        jcs(&report.to_json()).unwrap(),
        format!(r#"{{"body":{},"sig":"{}"}}"#, held.jcs(), b64u(&sig))
    );
    // A high-S P-256 signature is normalized.
    let high = high_s(&sig);
    assert_ne!(high, sig);
    assert_eq!(held.with_signature(&high).unwrap().sig(), &sig[..]);
    assert_eq!(held.signer_key(), &keys.public_key(&phone).unwrap());
    assert_eq!(held.head(), log.head());
    assert_eq!(held.process(), process_generation());
    assert_eq!(
        held.signing_input(),
        SigningInput::new(SignLabel::SignerReport, held.jcs().as_bytes())
    );
    // The report's own signature: a high S is refused.
    let mut object: Value = serde_json::from_str(&report.to_json().to_string()).unwrap();
    object["sig"] = json!(b64u(&high));
    assert_eq!(
        verify(
            &log,
            &object.to_string(),
            &challenge,
            &exported(&book, &plan),
            NOW
        )
        .map(|_| ()),
        Err(ReportRefusal::BadSignature)
    );
}

/// A signer report's signature is over its own label only, and a body
/// relabelled to another kind is `malformed`.
#[test]
fn a_label_collision_is_impossible() {
    let (v, book) = (Vectors::load(), Book::load());
    let keys = &book.provider;
    let log = log_l(&v);
    let challenge = challenge(PHONE, SLOT);
    let body = signer_report_body(
        &log,
        &challenge,
        PHONE,
        SLOT,
        STATION,
        &journal_of(&[], &[]),
        NOW,
    )
    .unwrap();
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
    ] {
        let sig = sign(
            keys,
            &KeyId::new("dev-phone/auth"),
            &SigningInput::new(label, body.jcs().as_bytes()),
        )
        .unwrap();
        let text = format!(r#"{{"body":{},"sig":"{}"}}"#, body.jcs(), b64u(&sig));
        assert_eq!(
            verify(&log, &text, &challenge, &[], NOW).map(|_| ()),
            Err(ReportRefusal::BadSignature),
            "{label:?}"
        );
    }
    let good = report(
        &book,
        "dev-phone/auth",
        &log,
        PHONE,
        &challenge,
        &journal_of(&[], &[]),
    );
    let relabelled = resigned(keys, "dev-phone/auth", &good, |b| {
        b["type"] = json!("atem-verifier-report")
    });
    assert!(matches!(
        verify(&log, &relabelled, &challenge, &[], NOW),
        Err(ReportRefusal::Malformed(_))
    ));
}

/// The report's `process` is the loaded core's, the verifier report's.
#[test]
fn the_process_is_the_loaded_cores() {
    let (v, book) = (Vectors::load(), Book::load());
    let log = log_l(&v);
    let challenge = challenge(PHONE, SLOT);
    let text = report(
        &book,
        "dev-phone/auth",
        &log,
        PHONE,
        &challenge,
        &journal_of(&[], &[]),
    );
    let verified = verify(&log, &text, &challenge, &[], NOW).unwrap();
    assert_eq!(verified.process, process_generation());
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
