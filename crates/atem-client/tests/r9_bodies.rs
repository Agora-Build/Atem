//! §R9.1 for the signed bodies Task 4 parses (grant, push hint, seen) and
//! the hello's shape: exact fields (an unknown field is refused even when
//! validly signed), keys pinned to their algorithm, and the hint/seen
//! identity rules, through the public API.
mod support;

use atem_client::membership::Membership;
use atem_client::principal::{Authority, BrowserGrant, Need, Op, Permission, Refusal};
use atem_client::push::{self, Hint, Identity, Refusal as PushRefusal, Seen, Verifier};
use atem_client::session::r9::{Hello, HelloRefusal};
use atem_client::{Error, KeyId, KeyProvider, SignedObject};
use serde_json::{Value, json};
use support::*;

fn log_l(v: &Vectors) -> Membership {
    let clock = Clock::at(1_793_264_000_000);
    Membership::verify_chain(
        ACCOUNT,
        &genesis_hash(),
        &v.entries(&["E1", "E2", "E3", "E4", "E5", "E6"]),
        &clock.now,
    )
    .unwrap()
    .membership
}

/// Re-signs `body` with `key` (so only the field rules can refuse it).
fn resign(book: &Book, key: &str, body: Value) -> SignedObject {
    SignedObject::sign(&book.provider, &KeyId::new(key), body).unwrap()
}

#[test]
fn a_grant_has_exactly_its_fields_and_a_p256_browser_key() {
    let v = Vectors::load();
    let book = Book::load();
    let log = log_l(&v);
    let grant = load("r9-vectors-browser-grant")["grant"]["body"].clone();
    let ok = resign(&book, "dev-phone/auth", grant.clone());
    let parsed = BrowserGrant::parse(ok).unwrap();
    assert!(Authority::of_grant(&parsed, &log, "host-a", 1, 1_793_264_001_000, &|_| false).is_ok());
    // An unknown field, top level or in the target, validly signed.
    let mut extra = grant.clone();
    extra["scope"] = json!("all");
    assert!(BrowserGrant::parse(resign(&book, "dev-phone/auth", extra)).is_err());
    let mut extra = grant.clone();
    extra["target"]["port"] = json!(8080);
    assert!(BrowserGrant::parse(resign(&book, "dev-phone/auth", extra)).is_err());
    // The browser key is pinned to P-256: an Ed25519 key is refused.
    let mut ed = grant.clone();
    ed["browser_key"] = book.public("svc-discord/auth").to_json();
    assert_eq!(
        BrowserGrant::parse(resign(&book, "dev-phone/auth", ed)).err(),
        Some(Error::WrongAlg)
    );
    // Ops: an unknown op or one without view is refused; absent is view.
    let mut bad = grant.clone();
    bad["ops"] = json!(["root", "view"]);
    assert!(BrowserGrant::parse(resign(&book, "dev-phone/auth", bad)).is_err());
    let mut no_view = grant.clone();
    no_view["ops"] = json!(["prompt"]);
    assert!(BrowserGrant::parse(resign(&book, "dev-phone/auth", no_view)).is_err());
    let mut absent = grant.clone();
    absent.as_object_mut().unwrap().remove("ops");
    let g = BrowserGrant::parse(resign(&book, "dev-phone/auth", absent)).unwrap();
    assert_eq!(g.ops, [Op::View].into());
    // A control grant gives control, never more than its issuer; a grant
    // signed by someone else than its issuer is invalid; an issuer removed
    // since is fenced; issued too far ahead is invalid.
    let mut control = grant.clone();
    control["ops"] = json!(["prompt", "view"]);
    let g = BrowserGrant::parse(resign(&book, "dev-phone/auth", control.clone())).unwrap();
    let a = Authority::of_grant(&g, &log, "host-a", 1, 1_793_264_001_000, &|_| false).unwrap();
    assert!(
        a.allows(Need::Op(Op::Prompt))
            && a.allows(Need::Lease)
            && !a.allows(Need::Op(Op::Terminal))
    );
    assert!(!a.allows(Need::RevokeGrant), "a browser never revokes");
    assert!(
        !a.allows(Need::ControlRecords),
        "a browser carries no control records"
    );
    assert!(!a.allows(Need::Alerts), "a browser is shown no alerts");
    assert!(
        !a.allows(Need::HostEncKey),
        "a browser never asks for the host's encryption key"
    );
    let g = BrowserGrant::parse(resign(&book, "dev-mac/auth", control.clone())).unwrap();
    assert_eq!(
        Authority::of_grant(&g, &log, "host-a", 1, 1_793_264_001_000, &|_| false),
        Err(Refusal::Unauthorized("invalid grant"))
    );
    let mut by_ipad = control.clone();
    by_ipad["issuer"] = json!("dev-ipad");
    let g = BrowserGrant::parse(resign(&book, "dev-ipad/auth", by_ipad)).unwrap();
    assert_eq!(
        Authority::of_grant(&g, &log, "host-a", 1, 1_793_264_001_000, &|_| false),
        Err(Refusal::Unauthorized("issuer fenced")),
        "E6 removed the iPad"
    );
    let g = BrowserGrant::parse(resign(&book, "dev-phone/auth", grant)).unwrap();
    assert_eq!(
        Authority::of_grant(&g, &log, "host-a", 1, g.issued_at - 300_001, &|_| false),
        Err(Refusal::Unauthorized("invalid grant"))
    );
    assert!(Authority::of_grant(&g, &log, "host-a", 1, g.issued_at - 300_000, &|_| false).is_ok());
}

#[test]
fn hints_and_seens_have_exactly_their_fields() {
    let v = Vectors::load();
    let book = Book::load();
    let log = log_l(&v);
    let file = load("r9-vectors-push-hint");
    let now = file["verifier_now"].as_u64().unwrap();
    let open = &file["open"][0];
    let sealed = |body: Value| {
        let mut wire = resign(&book, "host-a/host_key", body).to_json();
        wire["enc"] = open["enc"].clone();
        wire["ct"] = open["ct"].clone();
        SignedObject::parse(wire.to_string().as_bytes()).unwrap()
    };
    let ok = sealed(open["body"].clone());
    let h = Hint::verify(&ok, &log, now, Verifier::Client).unwrap();
    // The vector's own signature reproduces (RFC 8032), so the re-signed
    // object is the vector itself.
    assert_eq!(ok.to_json(), *open);
    for (path, value) in [
        ("extra", json!(1)),
        ("recipient.extra", json!(1)),
        ("recipient.enc_kid", json!("07B69E3EE18D1695")),
        ("host_trust_gen", json!(0)),
        ("state", json!("closed")),
    ] {
        let mut body = open["body"].clone();
        match path.split_once('.') {
            Some((a, b)) => body[a][b] = value,
            None => body[path] = value,
        }
        let r = Hint::verify(&sealed(body), &log, now, Verifier::Client);
        assert!(matches!(r, Err(PushRefusal::Malformed(_))), "{path}: {r:?}");
    }
    // Another trust generation than the host's newest add_host: binding.
    let mut body = open["body"].clone();
    body["host_trust_gen"] = json!(2);
    assert_eq!(
        Hint::verify(&sealed(body), &log, now, Verifier::Client),
        Err(PushRefusal::Binding)
    );
    // Signed by another key than host-a's (a member's): bad signature.
    let wrong = resign(&book, "dev-phone/auth", open["body"].clone());
    assert_eq!(
        Hint::verify(&wrong, &log, now, Verifier::Client),
        Err(PushRefusal::BadSignature)
    );
    // An open whose sealed part isn't the one sealed_hash names, or none.
    let mut swapped = ok.to_json();
    swapped["ct"] = file["open"][1]["ct"].clone();
    let swapped = SignedObject::parse(swapped.to_string().as_bytes()).unwrap();
    let swapped = Hint::verify(&swapped, &log, now, Verifier::Client).unwrap();
    assert_eq!(swapped.check_sealed(), Err(PushRefusal::BadSealed));
    assert!(
        swapped
            .open(&book.provider, &KeyId::new("dev-phone/enc"), "dev-phone")
            .is_err()
    );
    // Staleness and the client's skew, at their exact bounds.
    assert!(Hint::verify(&ok, &log, h.expires_at() + 299_999, Verifier::Client).is_ok());
    assert_eq!(
        Hint::verify(&ok, &log, h.expires_at() + 300_000, Verifier::Client),
        Err(PushRefusal::Stale)
    );
    assert!(Hint::verify(&ok, &log, h.created_at() - 300_000, Verifier::Client).is_ok());
    assert_eq!(
        Hint::verify(&ok, &log, h.created_at() - 300_001, Verifier::Client),
        Err(PushRefusal::Skew)
    );
    assert!(Hint::verify(&ok, &log, h.created_at() - 120_000, Verifier::Relay).is_ok());
    assert_eq!(
        Hint::verify(&ok, &log, h.created_at() - 120_001, Verifier::Relay),
        Err(PushRefusal::Skew)
    );

    // Seen: exact fields too, and its identity names the device.
    let seen = file["seen"].clone();
    let mut extra = seen["body"].clone();
    extra["state"] = json!("open");
    assert!(matches!(
        Seen::verify(&resign(&book, "host-a/host_key", extra), &log),
        Err(PushRefusal::Malformed(_))
    ));
    let s = Seen::verify(
        &SignedObject::parse(seen.to_string().as_bytes()).unwrap(),
        &log,
    )
    .unwrap();
    let id = s.identity();
    assert_eq!(Identity::from_ack(&id.to_ack()).unwrap(), id);
    assert_ne!(id, h.identity(), "a seen and a hint never match");
    // An ack entry with an unknown field acknowledges nothing.
    let mut ack = id.to_ack();
    ack["extra"] = json!(1);
    assert!(Identity::from_ack(&ack).is_err());
    assert!(
        push::parse_push_ack(&json!({"type": "relay", "op": "push_ack", "acks": [ack]})).is_empty()
    );
}

#[test]
fn the_hello_shape() {
    let v = Vectors::load();
    let head = log_l(&v).head().to_json();
    let proof = json!({"principal": {"kind": "native", "device_id": "dev-phone"}, "sig": "AAAA"});
    let hello = |data: Value| {
        let mut d = json!({"v": 1, "op": "hello", "id": "aaaaaaaa-0000-4000-8000-000000000001",
            "revision": 9, "proof": proof, "membership": {"head": head, "entries": []}});
        for (k, x) in data.as_object().unwrap() {
            if x.is_null() {
                d.as_object_mut().unwrap().remove(k);
            } else {
                d[k] = x.clone();
            }
        }
        json!({"type": "session", "data": d})
            .to_string()
            .into_bytes()
    };
    assert!(Hello::parse(&hello(json!({}))).unwrap().check().is_ok());
    // No readable proof: the clear handshake_failed (None).
    assert!(Hello::parse(&hello(json!({"proof": null}))).is_none());
    assert!(
        Hello::parse(&hello(
            json!({"proof": {"principal": {"kind": "native"}, "sig": "AAAA"}})
        ))
        .is_none()
    );
    assert!(Hello::parse(&hello(json!({"op": "list"}))).is_none());
    assert!(Hello::parse(b"not json").is_none());
    // A browser principal without its grant can't key the channel.
    assert!(
        Hello::parse(&hello(
            json!({"proof": {"principal": {"kind": "browser", "grant_id": "x"}, "sig": "AAAA"}})
        ))
        .is_none()
    );
    // Readable proof, refused in the channel.
    let check = |data: Value| Hello::parse(&hello(data)).unwrap().check().err();
    assert_eq!(
        check(json!({"revision": 8})),
        Some(HelloRefusal::UnsupportedVersion)
    );
    assert_eq!(
        check(json!({"revision": null})),
        Some(HelloRefusal::UnsupportedVersion)
    );
    assert_eq!(
        check(json!({"resume": {"controller_session": "x"}})),
        Some(HelloRefusal::UnsupportedVersion)
    );
    assert!(matches!(
        check(json!({"membership": null})),
        Some(HelloRefusal::InvalidRequest(_))
    ));
    assert!(matches!(
        check(json!({"membership": {"head": head, "entries": [], "extra": 1}})),
        Some(HelloRefusal::InvalidRequest(_))
    ));
    assert!(matches!(
        check(json!({"id": null})),
        Some(HelloRefusal::InvalidRequest(_))
    ));
    let e = HelloRefusal::UnsupportedVersion.to_error(Some("r"));
    assert_eq!(e.to_json()["data"]["revision"], 9);
}

/// The host's outbox: resends every 10 s and at a reconnect until acked;
/// an acknowledged resolved hint ends its approval's resends; nothing is
/// kept past `expires_at + 300 s`.
#[test]
fn the_outbox_resends_until_acknowledged() {
    let v = Vectors::load();
    let book = Book::load();
    let log = log_l(&v);
    let file = load("r9-vectors-push-hint");
    let now = file["verifier_now"].as_u64().unwrap();
    let hints: Vec<Hint> = file["open"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| {
            let o = SignedObject::parse(h.to_string().as_bytes()).unwrap();
            Hint::verify(&o, &log, now, Verifier::Client).unwrap()
        })
        .collect();
    let seen = Seen::verify(
        &SignedObject::parse(file["seen"].to_string().as_bytes()).unwrap(),
        &log,
    )
    .unwrap();
    let mut outbox = push::Outbox::new();
    let first = outbox.send_hints(&hints, 0);
    assert_eq!(first["hints"].as_array().unwrap().len(), 2);
    outbox.send_seen(&seen, hints[0].expires_at(), 0);
    assert!(outbox.tick(9_999).is_empty());
    let resent = outbox.tick(10_000);
    assert_eq!(resent.len(), 2, "one push_hint (both hints), one push_seen");
    assert_eq!(resent[0], first, "the same bytes");
    // One hint acked: the next resend carries the other only.
    outbox.on_ack(&[hints[0].identity()]);
    let resent = outbox.tick(20_000);
    assert_eq!(resent[0]["hints"].as_array().unwrap().len(), 1);
    // A reconnect resends everything left at once.
    assert_eq!(outbox.reconnect(21_000).len(), 2);
    // The resolved hint, acknowledged, ends the approval's resends.
    let resolved = Hint::verify(
        &SignedObject::parse(file["resolved"].to_string().as_bytes()).unwrap(),
        &log,
        now,
        Verifier::Client,
    )
    .unwrap();
    outbox.send_hints(std::slice::from_ref(&resolved), 22_000);
    outbox.on_ack(&[resolved.identity()]);
    assert!(outbox.is_empty());
    // Nothing outlives expires_at + 300 s (on the clock the host passes).
    let mut outbox = push::Outbox::new();
    outbox.send_seen(&seen, 1_000, 0);
    assert!(outbox.tick(301_000).is_empty());
    assert!(outbox.is_empty());
    let _ = book;
}

/// The reference relay: the skew bound applies at first receipt only (an
/// accepted hint resent late is idempotent), and every refusal it can
/// identify (the signature verified) names the identity, so the host can
/// be acknowledged and stop resending.
#[test]
fn the_relay_acks_late_resends_and_identified_refusals() {
    let v = Vectors::load();
    let log = log_l(&v);
    let file = load("r9-vectors-push-hint");
    let now = file["verifier_now"].as_u64().unwrap();
    let object = |v: &Value| SignedObject::parse(v.to_string().as_bytes()).unwrap();
    let open = object(&file["open"][0]);
    let mut ledger = push::RelayLedger::new();
    assert_eq!(
        ledger.receive_hint(&open, &log, now).0,
        push::Verdict::Accepted
    );
    // 200 s later (beyond ±120 s), the same bytes: idempotent, acked.
    let (verdict, id) = ledger.receive_hint(&open, &log, now + 200_000);
    assert_eq!(verdict, push::Verdict::Idempotent);
    assert!(id.is_some());
    // A first receipt outside the bound: skew, still identified.
    let other = object(&file["open"][1]);
    let (verdict, id) = ledger.receive_hint(&other, &log, now + 200_000);
    assert_eq!(verdict, push::Verdict::Refused(PushRefusal::Skew));
    assert_eq!(
        id,
        Some(
            Hint::verify(&other, &log, now, Verifier::Relay)
                .unwrap()
                .identity()
        )
    );
    // invalid_times is identified too; a bad signature is not.
    let (verdict, id) = ledger.receive_hint(&object(&file["invalid"][1]["hint"]), &log, now);
    assert_eq!(verdict, push::Verdict::Refused(PushRefusal::InvalidTimes));
    assert!(id.is_some());
    let mut tampered = file["open"][1].clone();
    tampered["body"]["created_at"] = json!(now - 1);
    let (verdict, id) = ledger.receive_hint(&object(&tampered), &log, now);
    assert_eq!(verdict, push::Verdict::Refused(PushRefusal::BadSignature));
    assert!(id.is_none());
}

/// What each request needs, and the one per-request check (§R9.6): the
/// session first (`unknown_session`), then the op (`forbidden`); any member
/// with control may revoke a grant, services included.
#[test]
fn one_authority_check_per_request() {
    use atem_client::principal::{Denied, SessionRef};
    let v = Vectors::load();
    let book = Book::load();
    let log = log_l(&v);
    let now = atem_client::membership::HostNow {
        wall_ms: 1_793_264_001_000,
        mono_ms: 0,
        boot_id: "b".into(),
    };
    let bot = Authority::resolve(
        &log,
        &atem_client::channel::Principal::Service {
            device_id: "svc-discord".into(),
        },
        None,
        "host-a",
        1,
        &now,
        &|_| false,
    )
    .unwrap();
    let need = |family: &str, data: Value| Need::of_request(family, &data).unwrap();
    assert_eq!(need("session", json!({"op": "acquire"})), Need::Lease);
    assert_eq!(
        need("session", json!({"op": "receipt_query"})),
        Need::Op(Op::View)
    );
    assert_eq!(
        need("session", json!({"op": "submit", "kind": "approval"})),
        Need::Op(Op::Approval)
    );
    assert_eq!(need("session", json!({"op": "approval_seen"})), Need::Seen);
    assert_eq!(
        need("session", json!({"op": "control_records"})),
        Need::ControlRecords
    );
    assert_eq!(
        need("session", json!({"op": "message_publish"})),
        Need::Op(Op::Message)
    );
    assert_eq!(
        need("session", json!({"op": "message_query"})),
        Need::Op(Op::Message)
    );
    // A reply is read with the authority that queried its task.
    assert_eq!(
        need("session", json!({"op": "reply_query"})),
        need("session", json!({"op": "work_query"}))
    );
    assert_eq!(
        need("session", json!({"op": "reply_query"})),
        Need::Op(Op::Notify)
    );
    // The delegated ops are directed-work requests: the channel checks
    // `notify` before decoding them (the host then checks `interrupt` for
    // `work_interrupt`), and a native member needs `control`.
    for op in ["work_interrupt", "work_resolve"] {
        assert_eq!(
            need("session", json!({ "op": op })),
            need("session", json!({"op": "work_cancel"})),
            "{op}"
        );
        assert_eq!(need("session", json!({ "op": op })), Need::Op(Op::Notify));
    }
    assert!(Op::Notify.is_control());
    assert!(!Op::Message.is_control());
    assert_eq!(
        need("terminal", json!({"op": "input"})),
        Need::Op(Op::Terminal)
    );
    assert_eq!(
        need("agentChat", json!({"op": "submit", "text": "x"})),
        Need::Op(Op::Prompt)
    );
    // Fails closed: anything the map doesn't name is refused, never
    // skipped (ops the r8 decoder accepts from a client, like `hello`,
    // host messages, unknown kinds and families).
    for (family, data) in [
        ("session", json!({"op": "hello"})),
        ("session", json!({"op": "welcome"})),
        ("session", json!({"op": "submit", "kind": "reboot"})),
        ("session", json!({"op": "submit"})),
        ("session", json!({})),
        ("terminal", json!({"op": "frame"})),
        ("agentChat", json!({"op": "opened"})),
        ("voiceCommand", json!({"op": "start"})),
    ] {
        assert_eq!(
            Need::of_request(family, &data),
            Err(Denied::InvalidRequest),
            "{family} {data}"
        );
    }
    assert_eq!(Denied::InvalidRequest.code(), "invalid_request");
    assert_eq!(
        Need::session_of(&json!({"binding": {"target": {"session_id": "ses-aaaaaaaaaaaa"}}})),
        Some("ses-aaaaaaaaaaaa")
    );
    let abab = |e: &str| {
        Some(e.ends_with("abababababababababababababababababababababababababababababababab"))
    };
    let other = |_: &str| Some(false);
    let mine = SessionRef {
        host_id: "host-a",
        session_id: "ses-aaaaaaaaaaaa",
        project_matches: &abab,
    };
    let theirs = SessionRef {
        host_id: "host-a",
        session_id: "ses-bbbbbbbbbbbb",
        project_matches: &other,
    };
    assert_eq!(bot.authorize(Need::Lease, Some(Some(&mine))), Ok(()));
    assert_eq!(
        bot.authorize(Need::Lease, Some(Some(&theirs))),
        Err(Denied::UnknownSession)
    );
    assert_eq!(
        bot.authorize(Need::Op(Op::Terminal), Some(Some(&theirs))),
        Err(Denied::UnknownSession)
    );
    assert_eq!(
        bot.authorize(Need::Op(Op::Terminal), Some(Some(&mine))),
        Err(Denied::Forbidden)
    );
    assert_eq!(
        bot.authorize(Need::Op(Op::View), Some(None)),
        Err(Denied::UnknownSession)
    );
    assert_eq!(
        bot.authorize(Need::Seen, Some(Some(&mine))),
        Err(Denied::Forbidden),
        "no approval op"
    );
    assert_eq!(
        bot.authorize(Need::RevokeGrant, None),
        Ok(()),
        "a member with control"
    );
    // Control records are for native members only (the records' own
    // signatures carry the authority; the carrier's is only to carry).
    assert_eq!(
        bot.authorize(Need::ControlRecords, None),
        Err(Denied::Forbidden),
        "a service is no native"
    );
    let phone = Authority::resolve(
        &log,
        &atem_client::channel::Principal::Native {
            device_id: "dev-phone".into(),
        },
        None,
        "host-a",
        1,
        &now,
        &|_| false,
    )
    .unwrap();
    assert_eq!(phone.authorize(Need::ControlRecords, None), Ok(()));

    // `alert_list` (design I.4.6) answers native members with `control`, the
    // members that get approval hints: a service never does, whatever its
    // ops (this one holds control), nor a native member without `control`.
    assert_eq!(
        need("session", json!({"op": "alert_list"})),
        Need::Alerts,
        "its own need, not directed work's"
    );
    assert_eq!(
        bot.authorize(Need::Alerts, None),
        Err(Denied::Forbidden),
        "a service, though it holds control"
    );
    assert_eq!(phone.authorize(Need::Alerts, None), Ok(()));
    let mut viewer = phone.clone();
    viewer.permissions = [Permission::View].into();
    assert_eq!(
        viewer.authorize(Need::Alerts, None),
        Err(Denied::Forbidden),
        "a native member without control"
    );

    // `host_enc_key_get` (design II.4.1) is a native member's: the channel
    // admits no service or browser; whether the native holds `manage` at the
    // head is the host's question when it handles the request (as for the
    // host policy), so a native without `control` passes here too.
    assert_eq!(
        need("session", json!({"op": "host_enc_key_get"})),
        Need::HostEncKey
    );
    assert_eq!(
        bot.authorize(Need::HostEncKey, None),
        Err(Denied::Forbidden),
        "a service is no native"
    );
    assert_eq!(phone.authorize(Need::HostEncKey, None), Ok(()));
    assert_eq!(viewer.authorize(Need::HostEncKey, None), Ok(()));
    let _ = book;
}

// ---------------------------------------------- the outcome_unknown hint
//
// `atem-push-hint` of kind `outcome_unknown` (delegated host-work design
// I.4.6, host-work-v1 §11.3, session-v1 R9.9): the host signs one per
// recipient, the task, session, sender and reason sealed to its `enc_key`;
// the relay and clients verify it as strictly as an open approval hint.

const ALERT_ID: &str = "aaaaaaaa-0000-4000-8000-0000000000a1";
const ALERT_TASK: &str = "bbbbbbbb-0000-4000-8000-0000000000b1";
/// The vectors' verifier clock (the first open hint's `created_at`).
const ALERT_NOW: u64 = 1_793_264_005_000;

fn alert_plain() -> push::AlertPlain {
    push::AlertPlain {
        task_id: ALERT_TASK.into(),
        session_id: "ses-aaaaaaaaaaaa".into(),
        sender: "service:svc-discord".into(),
        reason: "agent exited".into(),
    }
}

fn alert_hint(book: &Book, log: &Membership, device: &str) -> SignedObject {
    let key = push::AlertKey::new(log, "host-a", 1, ALERT_ID);
    push::alert_hint(
        &book.provider,
        &KeyId::new("host-a/host_key"),
        &key,
        ALERT_NOW,
        ALERT_NOW + 600_000,
        device,
        &book.public(&format!("{device}/enc")),
        &alert_plain(),
    )
    .unwrap()
}

#[test]
fn outcome_unknown_hint_seal_open() {
    let v = Vectors::load();
    let book = Book::load();
    let log = log_l(&v);
    let object = alert_hint(&book, &log, "dev-phone");

    // The body: the kind, the alert's identity and the recipient; the task,
    // session, sender and reason are only in the sealed part.
    let body = object.body();
    assert_eq!(body["type"], "atem-push-hint");
    assert_eq!(body["v"], 1);
    assert_eq!(body["kind"], "outcome_unknown");
    assert_eq!(body["alert_id"], ALERT_ID);
    assert_eq!(body["host_id"], "host-a");
    assert_eq!(body["host_trust_gen"], 1);
    assert_eq!(body["recipient"]["device_id"], "dev-phone");
    assert!(body.get("state").is_none(), "no approval state");
    for secret in ["task_id", "session_id", "sender", "reason", "approval_id"] {
        assert!(body.get(secret).is_none(), "{secret} is not in the clear");
    }
    assert!(
        !object.jcs().contains(ALERT_TASK) && !object.jcs().contains("agent exited"),
        "nothing of the sealed facts in the body"
    );
    assert!(object.jcs().len() <= 4096);
    assert_eq!(object.label(), atem_client::domain::SignLabel::PushHint);

    // Verified by a client and by the relay; opened by its device only.
    for verifier in [Verifier::Client, Verifier::Relay] {
        let hint = push::AlertHint::verify(&object, &log, ALERT_NOW, verifier).unwrap();
        hint.check_sealed().unwrap();
        assert_eq!(hint.key().alert_id, ALERT_ID);
        assert_eq!(hint.created_at(), ALERT_NOW);
        assert_eq!(hint.expires_at(), ALERT_NOW + 600_000);
        assert_eq!(hint.device_id(), "dev-phone");
        let opened = hint
            .open(&book.provider, &KeyId::new("dev-phone/enc"), "dev-phone")
            .unwrap();
        assert_eq!(opened, alert_plain());
        // Another device, another enc_key: refused before opening.
        assert!(
            hint.open(&book.provider, &KeyId::new("dev-phone/enc"), "dev-mac")
                .is_err()
        );
        assert!(
            hint.open(&book.provider, &KeyId::new("dev-mac/enc"), "dev-phone")
                .is_err()
        );
        assert!(
            hint.open(&book.provider, &KeyId::new("dev-mac/enc"), "dev-mac")
                .is_err()
        );
    }
    // The sealed plaintext is exactly the canonical four fields.
    let sealed = object.sealed().unwrap();
    let kid = atem_client::keys::enc_kid(&book.public("dev-phone/enc")).unwrap();
    let info = push::alert_seal_info(
        &push::AlertKey::new(&log, "host-a", 1, ALERT_ID),
        ALERT_NOW,
        ALERT_NOW + 600_000,
        "dev-phone",
        &kid,
    )
    .unwrap();
    let plain = book
        .provider
        .hpke_open(
            &KeyId::new("dev-phone/enc"),
            &sealed.enc,
            &sealed.ct,
            &info,
            b"",
        )
        .unwrap();
    assert_eq!(
        std::str::from_utf8(&plain).unwrap(),
        format!(
            r#"{{"reason":"agent exited","sender":"service:svc-discord","session_id":"ses-aaaaaaaaaaaa","task_id":"{ALERT_TASK}"}}"#
        )
    );
    // The seal info starts with the push seal label and names the kind, so
    // an approval hint's seal never opens as an alert's (12 fields there,
    // 11 here, and the kind is a field).
    let fields = atem_client::encoding::dec(&info).unwrap();
    assert_eq!(fields[0], atem_client::domain::PUSH_SEAL.as_bytes());
    assert_eq!(fields.len(), 11);
    assert_eq!(fields[5], b"outcome_unknown");
    assert_eq!(fields[6], ALERT_ID.as_bytes());

    // The seal is bound to the body's fields: a re-signed body with another
    // time or alert id verifies as a hint and refuses to open.
    for (field, value) in [
        ("created_at", json!(ALERT_NOW + 1)),
        ("expires_at", json!(ALERT_NOW + 600_001)),
        ("alert_id", json!("aaaaaaaa-0000-4000-8000-0000000000a2")),
    ] {
        let mut body = object.body().clone();
        body[field] = value;
        let mut wire = resign(&book, "host-a/host_key", body).to_json();
        wire["enc"] = object.to_json()["enc"].clone();
        wire["ct"] = object.to_json()["ct"].clone();
        let moved = SignedObject::parse(wire.to_string().as_bytes()).unwrap();
        let hint = push::AlertHint::verify(&moved, &log, ALERT_NOW, Verifier::Client).unwrap();
        assert!(
            hint.open(&book.provider, &KeyId::new("dev-phone/enc"), "dev-phone")
                .is_err(),
            "{field}"
        );
    }

    // Neither verifier takes the other's kind: an approval hint isn't an
    // alert hint and an alert hint isn't an approval hint, however each is
    // signed.
    let file = load("r9-vectors-push-hint");
    let approval = SignedObject::parse(file["open"][0].to_string().as_bytes()).unwrap();
    assert!(matches!(
        push::AlertHint::verify(&approval, &log, ALERT_NOW, Verifier::Client),
        Err(PushRefusal::Malformed(_))
    ));
    assert!(matches!(
        Hint::verify(&object, &log, ALERT_NOW, Verifier::Client),
        Err(PushRefusal::Malformed(_))
    ));

    // The builder refuses what a reader would: bounds on every sealed field.
    let key = push::AlertKey::new(&log, "host-a", 1, ALERT_ID);
    let build = |plain: push::AlertPlain| {
        push::alert_hint(
            &book.provider,
            &KeyId::new("host-a/host_key"),
            &key,
            ALERT_NOW,
            ALERT_NOW + 600_000,
            "dev-phone",
            &book.public("dev-phone/enc"),
            &plain,
        )
    };
    let edit = |f: &dyn Fn(&mut push::AlertPlain)| {
        let mut plain = alert_plain();
        f(&mut plain);
        build(plain)
    };
    assert!(edit(&|p| p.reason = "x".repeat(256)).is_ok());
    assert!(edit(&|p| p.reason = "x".repeat(257)).is_err());
    assert!(edit(&|p| p.reason.clear()).is_err());
    assert!(edit(&|p| p.reason = "a\nb".into()).is_err());
    assert!(edit(&|p| p.reason = "a\u{202E}b".into()).is_err(), "no Cf");
    assert!(edit(&|p| p.reason = "   ".into()).is_err(), "not blank");
    assert!(
        edit(&|p| p.reason = "\u{00A0}\u{3000}".into()).is_err(),
        "not blank in Unicode white space either"
    );
    assert!(edit(&|p| p.sender = "phone".into()).is_err());
    // Only a delegated sender's UUID v4 task raises an alert:
    // `local` and browser grants keep v1, and a local selector's UUID v5
    // task is never one.
    assert!(edit(&|p| p.sender = "local".into()).is_err());
    assert!(edit(&|p| p.sender = "browser:grant-1".into()).is_err());
    assert!(edit(&|p| p.sender = "host:host-b".into()).is_ok());
    assert!(edit(&|p| p.session_id = "ses-A".into()).is_err());
    assert!(edit(&|p| p.task_id = "x".into()).is_err());
    assert!(
        edit(&|p| p.task_id = "6ba7b810-9dad-51d1-80b4-00c04fd430c8".into()).is_err(),
        "a local selector's UUID v5 task"
    );
    // One hint per native member with control, as for an approval.
    let all = push::alert_hints(
        &book.provider,
        &KeyId::new("host-a/host_key"),
        &log,
        &key,
        ALERT_NOW,
        ALERT_NOW + 600_000,
        &alert_plain(),
    )
    .unwrap();
    let devices: Vec<String> = all
        .iter()
        .map(|o| {
            push::AlertHint::verify(o, &log, ALERT_NOW, Verifier::Client)
                .unwrap()
                .device_id()
                .to_owned()
        })
        .collect();
    let expected: Vec<String> = push::recipients(&log).into_iter().map(|(d, _)| d).collect();
    assert_eq!(devices, expected);
    assert!(devices.len() >= 2);
    let _ = (v, book);
}

#[test]
fn relay_ledger_accepts_new_kind_strictly() {
    let v = Vectors::load();
    let book = Book::load();
    let log = log_l(&v);
    let phone = alert_hint(&book, &log, "dev-phone");
    let mac = alert_hint(&book, &log, "dev-mac");
    let mut ledger = push::RelayLedger::new();

    // Accepted, with the identity its ack names; the same bytes are
    // idempotent whenever they arrive again.
    let (verdict, identity) = ledger.receive_hint(&phone, &log, ALERT_NOW);
    assert_eq!(verdict, push::Verdict::Accepted);
    let identity = identity.unwrap();
    assert!(matches!(&identity, Identity::Alert { device_id, .. } if device_id == "dev-phone"));
    assert_eq!(Identity::from_ack(&identity.to_ack()).unwrap(), identity);
    assert_eq!(identity.to_ack()["kind"], "outcome_unknown");
    let (verdict, again) = ledger.receive_hint(&phone, &log, ALERT_NOW + 200_000);
    assert_eq!(verdict, push::Verdict::Idempotent);
    assert_eq!(again, Some(identity.clone()));
    // Another device's hint for the alert is its own identity.
    let (verdict, other) = ledger.receive_hint(&mac, &log, ALERT_NOW);
    assert_eq!(verdict, push::Verdict::Accepted);
    assert_ne!(other, Some(identity.clone()));
    // The same identity with other bytes (another seal): the first stays,
    // and it is acknowledged like any identified refusal.
    let key = push::AlertKey::new(&log, "host-a", 1, ALERT_ID);
    let rebuilt = push::alert_hint(
        &book.provider,
        &KeyId::new("host-a/host_key"),
        &key,
        ALERT_NOW,
        ALERT_NOW + 600_000,
        "dev-phone",
        &book.public("dev-phone/enc"),
        &alert_plain(),
    )
    .unwrap();
    assert_ne!(rebuilt, phone, "a fresh ephemeral");
    let (verdict, id) = ledger.receive_hint(&rebuilt, &log, ALERT_NOW);
    assert_eq!(verdict, push::Verdict::Refused(PushRefusal::Duplicate));
    assert_eq!(id, Some(identity.clone()));

    // Every malformed shape is refused, none identified (the signature is
    // over fields the verifier can't trust yet), and nothing is stored.
    let signed = |edit: &dyn Fn(&mut Value)| {
        let mut body = phone.body().clone();
        edit(&mut body);
        let mut wire = resign(&book, "host-a/host_key", body).to_json();
        wire["enc"] = phone.to_json()["enc"].clone();
        wire["ct"] = phone.to_json()["ct"].clone();
        SignedObject::parse(wire.to_string().as_bytes()).unwrap()
    };
    let mut fresh = push::RelayLedger::new();
    let malformed = |fresh: &mut push::RelayLedger, name: &str, object: SignedObject| {
        let (verdict, id) = fresh.receive_hint(&object, &log, ALERT_NOW);
        assert!(
            matches!(verdict, push::Verdict::Refused(PushRefusal::Malformed(_))),
            "{name}: {verdict:?}"
        );
        assert!(id.is_none(), "{name}");
    };
    malformed(
        &mut fresh,
        "an extra field",
        signed(&|b| b["extra"] = json!(1)),
    );
    malformed(
        &mut fresh,
        "a task id in the clear",
        signed(&|b| b["task_id"] = json!(ALERT_TASK)),
    );
    malformed(
        &mut fresh,
        "a state",
        signed(&|b| b["state"] = json!("open")),
    );
    malformed(
        &mut fresh,
        "another kind",
        signed(&|b| b["kind"] = json!("expired")),
    );
    malformed(
        &mut fresh,
        "an approval's identity",
        signed(&|b| b["approval_id"] = json!(ALERT_ID)),
    );
    malformed(
        &mut fresh,
        "no kind",
        signed(&|b| {
            b.as_object_mut().unwrap().remove("kind");
        }),
    );
    malformed(
        &mut fresh,
        "no alert id",
        signed(&|b| {
            b.as_object_mut().unwrap().remove("alert_id");
        }),
    );
    malformed(
        &mut fresh,
        "an empty alert id",
        signed(&|b| b["alert_id"] = json!("")),
    );
    malformed(
        &mut fresh,
        "a recipient field",
        signed(&|b| b["recipient"]["extra"] = json!(1)),
    );
    malformed(
        &mut fresh,
        "an upper-case enc_kid",
        signed(&|b| b["recipient"]["enc_kid"] = json!("07B69E3EE18D1695")),
    );
    malformed(
        &mut fresh,
        "a number for the hash",
        signed(&|b| b["sealed_hash"] = json!(5)),
    );
    malformed(
        &mut fresh,
        "a zero generation",
        signed(&|b| b["host_trust_gen"] = json!(0)),
    );
    // An approval-shaped hint is not an alert, nor an alert an approval.
    let file = load("r9-vectors-push-hint");
    let approval = SignedObject::parse(file["open"][0].to_string().as_bytes()).unwrap();
    assert!(
        matches!(
            fresh.receive_hint(&approval, &log, ALERT_NOW).0,
            push::Verdict::Accepted
        ),
        "an approval hint still goes the approval way"
    );
    // The rest of §R9.9's order: signature, binding, times, skew, sealed.
    let (verdict, id) = fresh.receive_hint(
        &resign(&book, "dev-phone/auth", phone.body().clone()),
        &log,
        ALERT_NOW,
    );
    assert_eq!(verdict, push::Verdict::Refused(PushRefusal::BadSignature));
    assert!(id.is_none());
    let (verdict, id) = fresh.receive_hint(
        &signed(&|b| b["host_trust_gen"] = json!(2)),
        &log,
        ALERT_NOW,
    );
    assert_eq!(verdict, push::Verdict::Refused(PushRefusal::Binding));
    assert!(id.is_some(), "signed by the host: identified");
    for (name, edit, refusal) in [
        (
            "expires before it begins",
            (&|b: &mut Value| b["expires_at"] = json!(ALERT_NOW)) as &dyn Fn(&mut Value),
            PushRefusal::InvalidTimes,
        ),
        (
            "a window over 15 minutes",
            &|b: &mut Value| b["expires_at"] = json!(ALERT_NOW + 900_001),
            PushRefusal::InvalidTimes,
        ),
        (
            "a first receipt over 120 s from the clock",
            &|b: &mut Value| {
                b["created_at"] = json!(ALERT_NOW - 120_001);
                b["expires_at"] = json!(ALERT_NOW + 100_000);
            },
            PushRefusal::Skew,
        ),
    ] {
        let (verdict, id) = fresh.receive_hint(&signed(&edit), &log, ALERT_NOW);
        assert_eq!(verdict, push::Verdict::Refused(refusal), "{name}");
        assert!(id.is_some(), "{name}: identified");
    }
    // Stale: a client stops showing it 300 s after `expires_at` (at the
    // relay the skew bound comes first, so a stale first receipt is `skew`).
    let stale = signed(&|b| {
        b["created_at"] = json!(ALERT_NOW - 1_000_000);
        b["expires_at"] = json!(ALERT_NOW - 400_000);
    });
    assert_eq!(
        push::AlertHint::verify(&stale, &log, ALERT_NOW, Verifier::Client).err(),
        Some(PushRefusal::Stale)
    );
    assert_eq!(
        fresh.receive_hint(&stale, &log, ALERT_NOW).0,
        push::Verdict::Refused(PushRefusal::Skew)
    );
    // An alert hint without its sealed part, or with another one's.
    let bare = SignedObject::parse(
        &serde_json::to_vec(&json!({"body": phone.body(), "sig": phone.to_json()["sig"]})).unwrap(),
    )
    .unwrap();
    let (verdict, id) = fresh.receive_hint(&bare, &log, ALERT_NOW);
    assert_eq!(verdict, push::Verdict::Refused(PushRefusal::BadSealed));
    assert!(id.is_some());
    let mut swapped = phone.to_json();
    swapped["ct"] = mac.to_json()["ct"].clone();
    let swapped = SignedObject::parse(swapped.to_string().as_bytes()).unwrap();
    assert_eq!(
        fresh.receive_hint(&swapped, &log, ALERT_NOW).0,
        push::Verdict::Refused(PushRefusal::BadSealed)
    );

    // What the relay sends: once per recipient, at once, before the guard.
    let desktop = |_: &str| push::RecipientInfo {
        class: push::DeviceClass::Desktop,
        connected: false,
        immediate_mobile: false,
    };
    let pushes = ledger.due(ALERT_NOW, &desktop);
    let mut sent: Vec<(String, &str, String)> = pushes
        .iter()
        .map(|p| (p.device_id.clone(), p.kind, p.collapse_id.clone()))
        .collect();
    sent.sort();
    assert_eq!(
        sent,
        [
            ("dev-mac".to_owned(), "desktop_os", ALERT_ID.to_owned()),
            ("dev-phone".to_owned(), "desktop_os", ALERT_ID.to_owned()),
        ]
    );
    assert!(ledger.due(ALERT_NOW + 1, &desktop).is_empty(), "sent once");
    // The approval schedule, from the signed created_at, with nothing to
    // cancel it: a mobile device that hasn't opted in to immediate pushes
    // gets its push 60 s in, one that has gets it at once.
    let mobile = |_: &str| push::RecipientInfo {
        class: push::DeviceClass::Mobile,
        connected: false,
        immediate_mobile: false,
    };
    let mut other = push::RelayLedger::new();
    assert_eq!(
        other.receive_hint(&phone, &log, ALERT_NOW).0,
        push::Verdict::Accepted
    );
    assert_eq!(
        other.next_wake(ALERT_NOW, &mobile),
        Some(ALERT_NOW + 60_000)
    );
    assert!(other.due(ALERT_NOW + 59_999, &mobile).is_empty());
    let pushes = other.due(ALERT_NOW + 60_000, &mobile);
    assert_eq!(pushes.len(), 1);
    assert_eq!(pushes[0].kind, "mobile");
    assert_eq!(pushes[0].collapse_id, ALERT_ID);
    assert!(other.due(ALERT_NOW + 70_000, &mobile).is_empty(), "once");
    let immediate = |_: &str| push::RecipientInfo {
        immediate_mobile: true,
        ..mobile("")
    };
    let mut now_ledger = push::RelayLedger::new();
    now_ledger.receive_hint(&phone, &log, ALERT_NOW);
    assert_eq!(now_ledger.due(ALERT_NOW, &immediate).len(), 1);
    // Never at or after the guard (expires_at − 15 s): the stage due at 60 s
    // is still sent late, before it, and never on it.
    let mut late = push::RelayLedger::new();
    late.receive_hint(&phone, &log, ALERT_NOW);
    assert!(late.due(ALERT_NOW + 600_000 - 15_000, &mobile).is_empty());
    assert_eq!(late.next_wake(ALERT_NOW, &mobile), Some(ALERT_NOW + 60_000));
    assert_eq!(late.due(ALERT_NOW + 600_000 - 15_001, &mobile).len(), 1);
    assert_eq!(late.next_wake(ALERT_NOW, &mobile), None);
    // The ack names the alert; a client's book dedups by it.
    let mut client = push::HintBook::new();
    let verified =
        |o: &SignedObject| push::AlertHint::verify(o, &log, ALERT_NOW, Verifier::Client).unwrap();
    assert_eq!(
        client.offer_alert(verified(&phone)),
        Ok(push::Accepted::Accepted)
    );
    assert_eq!(
        client.offer_alert(verified(&phone)),
        Ok(push::Accepted::Idempotent)
    );
    assert_eq!(
        client.offer_alert(verified(&rebuilt)),
        Err(PushRefusal::Duplicate)
    );
    assert_eq!(
        client.offer_alert(verified(&mac)),
        Ok(push::Accepted::Accepted)
    );
    // The host keeps and resends it until acknowledged, like an approval's.
    let mut outbox = push::Outbox::new();
    let first = outbox.send_alert_hints(&[verified(&phone), verified(&mac)], 0);
    assert_eq!(first["op"], "push_hint");
    assert_eq!(first["hints"].as_array().unwrap().len(), 2);
    assert!(outbox.tick(9_999).is_empty());
    assert_eq!(outbox.tick(10_000), vec![first.clone()], "the same bytes");
    outbox.on_ack(&[identity]);
    assert_eq!(outbox.tick(20_000)[0]["hints"].as_array().unwrap().len(), 1);
    let _ = book;
}
