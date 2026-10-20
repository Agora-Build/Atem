//! §R9.1 for the signed bodies Task 4 parses (grant, push hint, seen) and
//! the hello's shape: exact fields (an unknown field is refused even when
//! validly signed), keys pinned to their algorithm, and the hint/seen
//! identity rules, through the public API.
mod support;

use atem_client::membership::Membership;
use atem_client::principal::{Authority, BrowserGrant, Need, Op, Refusal};
use atem_client::push::{self, Hint, Identity, Refusal as PushRefusal, Seen, Verifier};
use atem_client::session::r9::{Hello, HelloRefusal};
use atem_client::{Error, KeyId, SignedObject};
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
    assert!(Hint::verify(&ok, &log, h.expires_at + 299_999, Verifier::Client).is_ok());
    assert_eq!(
        Hint::verify(&ok, &log, h.expires_at + 300_000, Verifier::Client),
        Err(PushRefusal::Stale)
    );
    assert!(Hint::verify(&ok, &log, h.created_at - 300_000, Verifier::Client).is_ok());
    assert_eq!(
        Hint::verify(&ok, &log, h.created_at - 300_001, Verifier::Client),
        Err(PushRefusal::Skew)
    );
    assert!(Hint::verify(&ok, &log, h.created_at - 120_000, Verifier::Relay).is_ok());
    assert_eq!(
        Hint::verify(&ok, &log, h.created_at - 120_001, Verifier::Relay),
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
    outbox.send_seen(&seen, hints[0].expires_at, 0);
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
