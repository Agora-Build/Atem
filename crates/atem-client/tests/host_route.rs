//! The host route proof (§R9.7b) beyond the shared vectors: a fresh
//! challenge round trip, the challenge's own refusals, a frozen verifier,
//! the builder's bounds. Every proof refusal has a vector
//! (`r9-vectors-host-route`, run by `vectors.rs`).
mod support;

use atem_client::encoding::b64u;
use atem_client::host_route::{
    HostChallenge, HostRouteBody, HostRouteRefusal, MAX_ID_BYTES, RouteKind, host_route_message,
    sign_host_route, sign_host_route_as, verify_host_route, verify_host_route_as,
    verify_host_route_message, verify_host_route_message_as,
};
use atem_client::membership::Membership;
use atem_client::{KeyId, SignedObject};
use serde_json::json;
use support::*;

const ATEM_ID: &str = "hosta-0000000-1a2b3c4d";

fn log_l(v: &Vectors, clock: &Clock) -> Membership {
    let entries = v.entries(&["E1", "E2", "E3", "E4", "E5", "E6"]);
    Membership::verify_chain(ACCOUNT, &v.hash("E1"), &entries, &clock.now)
        .unwrap()
        .membership
}

fn host_a() -> KeyId {
    KeyId::new("host-a/host_key")
}

#[test]
fn a_fresh_challenge_round_trips_through_the_relay_message() {
    let (v, book, clock) = (Vectors::load(), Book::load(), Clock::at(1_793_264_000_000));
    let log = log_l(&v, &clock);
    let challenge = HostChallenge::new("astation-test-1");
    let wire = challenge.to_json().to_string();
    let read = HostChallenge::parse(wire.as_bytes()).unwrap();
    assert_eq!(read, challenge);
    let body = HostRouteBody::at(&log, "host-a", ATEM_ID, &read);
    let proof = sign_host_route(&book.provider, &host_a(), &body).unwrap();
    let message = host_route_message(&proof).to_string();
    let route = verify_host_route_message(
        &log,
        message.as_bytes(),
        &challenge.nonce,
        "astation-test-1",
        ATEM_ID,
    )
    .unwrap();
    assert_eq!(route.host_id, "host-a");
    assert_eq!(route.head, log.head());
    // A second challenge never accepts the first one's proof.
    let next = HostChallenge::new("astation-test-1");
    assert_ne!(next.nonce, challenge.nonce);
    assert_eq!(
        verify_host_route_message(
            &log,
            message.as_bytes(),
            &next.nonce,
            "astation-test-1",
            ATEM_ID
        ),
        Err(HostRouteRefusal::NonceMismatch)
    );
    // The proof alone verifies the same.
    let proof_json = proof.to_json().to_string();
    assert_eq!(
        verify_host_route(
            &log,
            proof_json.as_bytes(),
            &challenge.nonce,
            "astation-test-1",
            ATEM_ID
        ),
        Ok(route)
    );
}

#[test]
fn a_challenge_is_exactly_its_fields() {
    let nonce = b64u(&[7u8; 32]);
    let ok = json!({"type": "relay", "op": "host_challenge", "v": 1, "nonce": nonce, "room": "r"});
    assert!(HostChallenge::parse(ok.to_string().as_bytes()).is_ok());
    let long_room = "r".repeat(MAX_ID_BYTES + 1);
    let short_nonce = b64u(&[7u8; 31]);
    let bad = [
        json!({"type": "relay", "op": "host_challenge", "v": 1, "nonce": nonce, "room": "r", "x": 1}),
        json!({"type": "relay", "op": "host_challenge", "v": 1, "nonce": nonce}),
        json!({"type": "relay", "op": "host_challenge", "v": 2, "nonce": nonce, "room": "r"}),
        json!({"type": "relay", "op": "host_route", "v": 1, "nonce": nonce, "room": "r"}),
        json!({"type": "session", "op": "host_challenge", "v": 1, "nonce": nonce, "room": "r"}),
        json!({"type": "relay", "op": "host_challenge", "v": 1, "nonce": short_nonce, "room": "r"}),
        json!({"type": "relay", "op": "host_challenge", "v": 1, "nonce": "not b64u!", "room": "r"}),
        json!({"type": "relay", "op": "host_challenge", "v": 1, "nonce": nonce, "room": ""}),
        json!({"type": "relay", "op": "host_challenge", "v": 1, "nonce": nonce, "room": long_room}),
        json!({"type": "relay", "op": "host_challenge", "v": 1, "nonce": nonce, "room": 5}),
    ];
    for message in bad {
        assert!(
            matches!(
                HostChallenge::parse(message.to_string().as_bytes()),
                Err(HostRouteRefusal::Malformed(_))
            ),
            "{message}"
        );
    }
    let dup = format!(
        r#"{{"type":"relay","op":"host_challenge","v":1,"nonce":"{nonce}","room":"r","room":"s"}}"#
    );
    assert!(HostChallenge::parse(dup.as_bytes()).is_err());
    let huge = format!(
        r#"{{"type":"relay","op":"host_challenge","v":1,"nonce":"{nonce}","room":"{}"}}"#,
        "r".repeat(20_000)
    );
    assert_eq!(
        HostChallenge::parse(huge.as_bytes()),
        Err(HostRouteRefusal::Malformed("too large"))
    );
}

#[test]
fn a_frozen_verifier_restores_no_route() {
    let (v, book, clock) = (Vectors::load(), Book::load(), Clock::at(1_793_264_000_000));
    let log = log_l(&v, &clock);
    let challenge = HostChallenge::new("astation-test-1");
    let proof = sign_host_route(
        &book.provider,
        &host_a(),
        &HostRouteBody::at(&log, "host-a", ATEM_ID, &challenge),
    )
    .unwrap();
    // C6_mac conflicts with E6 and is signed by a manager: a freeze.
    let frozen = log.evaluate(&[strict(v.wire("C6_mac"))], &clock.now).next;
    assert!(frozen.frozen().is_some());
    let message = host_route_message(&proof).to_string();
    assert_eq!(
        verify_host_route_message(
            &frozen,
            message.as_bytes(),
            &challenge.nonce,
            "astation-test-1",
            ATEM_ID
        ),
        Err(HostRouteRefusal::Frozen)
    );
}

#[test]
fn the_builder_refuses_ids_outside_their_bounds_and_signs_nothing_else() {
    let (v, book, clock) = (Vectors::load(), Book::load(), Clock::at(1_793_264_000_000));
    let log = log_l(&v, &clock);
    let challenge = HostChallenge::new("astation-test-1");
    for atem_id in [String::new(), "a".repeat(MAX_ID_BYTES + 1)] {
        let body = HostRouteBody::at(&log, "host-a", &atem_id, &challenge);
        assert!(sign_host_route(&book.provider, &host_a(), &body).is_err());
    }
    // Another signed type in a host_route message is refused as such.
    let seen_like = SignedObject::sign(
        &book.provider,
        &host_a(),
        json!({"type": "atem-seen", "v": 1, "x": "y"}),
    )
    .unwrap();
    let message = host_route_message(&seen_like).to_string();
    assert_eq!(
        verify_host_route_message(
            &log,
            message.as_bytes(),
            &challenge.nonce,
            "astation-test-1",
            ATEM_ID
        ),
        Err(HostRouteRefusal::Malformed("type"))
    );
}

#[test]
fn every_refusal_code_is_a_reply_code_and_replies_round_trip() {
    use atem_client::host_route::{HostRoute, REFUSAL_CODES, RelayReply};
    let all = [
        HostRouteRefusal::Malformed("x"),
        HostRouteRefusal::Frozen,
        HostRouteRefusal::WrongAccount,
        HostRouteRefusal::UnknownHost,
        HostRouteRefusal::BadSignature,
        HostRouteRefusal::StaleLog,
        HostRouteRefusal::Fork,
        HostRouteRefusal::NonceMismatch,
        HostRouteRefusal::RoomMismatch,
        HostRouteRefusal::AtemIdMismatch,
    ];
    assert_eq!(all.each_ref().map(|r| r.code()), REFUSAL_CODES);
    for refusal in &all {
        let reply = RelayReply::refused(refusal);
        let text = reply.to_json().to_string();
        assert_eq!(RelayReply::parse(text.as_bytes()), Some(Ok(reply)));
    }
    let (v, clock) = (Vectors::load(), Clock::at(1_793_264_000_000));
    let log = log_l(&v, &clock);
    let ok = RelayReply::ok(&HostRoute {
        host_id: "host-a".into(),
        head: log.head(),
    });
    let text = ok.to_json().to_string();
    assert_eq!(RelayReply::parse(text.as_bytes()), Some(Ok(ok)));
    // Other relay messages are none of these.
    assert_eq!(
        RelayReply::parse(br#"{"type":"relay","op":"push_ack","acks":[]}"#),
        None
    );
}

/// The proxy kind (the delegated host-work design I.5.8 through Astation's
/// `:8080`; agreed with Astation 2026-11-16, #174) is domain separated from the
/// relay's: its own body `type` (`atem-host-route-proxy`) and signing label
/// (`atem-host-route-proxy-v1`) over the same fields. A proof a host gives
/// on a local link verifies only as a proxy proof: the relay's verifier
/// refuses it, so it never routes a relay connection as that host; a relay
/// proof is refused by the proxy verifier; and a body relabelled to the
/// other kind keeps no valid signature.
#[test]
fn a_proxy_proof_is_its_own_kind_and_never_a_relay_route() {
    use atem_client::SignLabel;
    let (v, book, clock) = (Vectors::load(), Book::load(), Clock::at(1_793_264_000_000));
    let log = log_l(&v, &clock);
    let challenge = HostChallenge::new("astation-test-1");
    let body = HostRouteBody::at(&log, "host-a", ATEM_ID, &challenge);
    let proxy = sign_host_route_as(RouteKind::Proxy, &book.provider, &host_a(), &body).unwrap();
    let relay = sign_host_route(&book.provider, &host_a(), &body).unwrap();
    assert_eq!(proxy.label(), SignLabel::HostRouteProxy);
    assert_eq!(proxy.body()["type"], "atem-host-route-proxy");
    assert_eq!(relay.label(), SignLabel::HostRoute);
    assert_eq!(
        sign_host_route_as(RouteKind::Relay, &book.provider, &host_a(), &body).unwrap(),
        relay,
        "the relay kind is sign_host_route's"
    );
    let verify = |kind, proof: &SignedObject| {
        let message = host_route_message(proof).to_string();
        let whole = verify_host_route_message_as(
            kind,
            &log,
            message.as_bytes(),
            &challenge.nonce,
            "astation-test-1",
            ATEM_ID,
        );
        let alone = verify_host_route_as(
            kind,
            &log,
            proof.to_json().to_string().as_bytes(),
            &challenge.nonce,
            "astation-test-1",
            ATEM_ID,
        );
        assert_eq!(whole, alone);
        whole
    };
    let route = verify(RouteKind::Proxy, &proxy).unwrap();
    assert_eq!((route.host_id.as_str(), route.head), ("host-a", log.head()));
    assert_eq!(
        verify(RouteKind::Relay, &relay).map(|r| r.head),
        Ok(log.head())
    );
    // Across the kinds: refused, by the relay's own verifier too.
    assert_eq!(
        verify(RouteKind::Relay, &proxy),
        Err(HostRouteRefusal::Malformed("type"))
    );
    let message = host_route_message(&proxy).to_string();
    assert_eq!(
        verify_host_route_message(
            &log,
            message.as_bytes(),
            &challenge.nonce,
            "astation-test-1",
            ATEM_ID
        ),
        Err(HostRouteRefusal::Malformed("type")),
        "a local link's proof routes no relay connection"
    );
    assert_eq!(
        verify(RouteKind::Proxy, &relay),
        Err(HostRouteRefusal::Malformed("type"))
    );
    // Relabelled to the other kind, a signature is no longer valid.
    let relabel = |proof: &SignedObject, to: &str| {
        let mut wire = proof.to_json();
        wire["body"]["type"] = json!(to);
        SignedObject::parse(wire.to_string().as_bytes()).unwrap()
    };
    assert_eq!(
        verify(RouteKind::Relay, &relabel(&proxy, "atem-host-route")),
        Err(HostRouteRefusal::BadSignature)
    );
    assert_eq!(
        verify(RouteKind::Proxy, &relabel(&relay, "atem-host-route-proxy")),
        Err(HostRouteRefusal::BadSignature)
    );
}

/// `service_suspended` (the delegated host-work design III.5; its `text`
/// and the disclosure order are Atem's proposal, #120 7207832274, agreed
/// with Astation, #120 7212501350 and 7213560895): a Station's refusal of
/// a proof that verified, not a
/// verifier code. It carries a required `text` (1 to 256 bytes of UTF-8,
/// no Cc, Cf, Zl or Zp), and a verifier code carries none.
#[test]
fn a_service_suspended_refusal_carries_its_text_and_is_no_verifier_code() {
    use atem_client::host_route::{
        MAX_SERVICE_TEXT_BYTES, REFUSAL_CODES, RelayReply, SERVICE_SUSPENDED,
        STATION_REFUSAL_CODES, service_text_ok,
    };
    let text = "service suspended: account disabled at Agora.Build";
    let reply = RelayReply::suspended(text).unwrap();
    assert_eq!(
        reply,
        RelayReply::Suspended {
            text: text.to_owned()
        }
    );
    assert_eq!(
        reply.to_json(),
        json!({"type": "relay", "op": "host_route_refused", "v": 1,
               "code": "service_suspended", "text": text})
    );
    let wire = reply.to_json().to_string();
    assert_eq!(RelayReply::parse(wire.as_bytes()), Some(Ok(reply)));
    // A Station's code, never the verifier's.
    assert_eq!(STATION_REFUSAL_CODES, [SERVICE_SUSPENDED]);
    assert!(!REFUSAL_CODES.contains(&SERVICE_SUSPENDED));

    // The text's grammar: bytes, not characters.
    assert_eq!(MAX_SERVICE_TEXT_BYTES, 256);
    assert!(service_text_ok("x"));
    assert!(service_text_ok(&"a".repeat(256)));
    assert!(!service_text_ok(&"a".repeat(257)));
    assert!(service_text_ok(&"é".repeat(128)));
    assert!(!service_text_ok(&format!("{}a", "é".repeat(128))));
    assert!(service_text_ok("服务已暂停: 账户已停用"));
    for bad in [
        "",
        "a\u{1b}[31mred",
        "a\u{0}b",
        "line\nbreak",
        "a\tb",
        "a\u{7f}b",
        "a\u{85}b",
        "a\u{202e}b",
        "a\u{200b}b",
        "\u{feff}a",
        "a\u{2028}b",
        "a\u{2029}b",
    ] {
        assert!(!service_text_ok(bad), "{bad:?}");
        assert!(RelayReply::suspended(bad).is_err(), "{bad:?}");
    }

    // Read strictly: per code, exactly its fields.
    let refused =
        |fields: &str| format!(r#"{{"type":"relay","op":"host_route_refused","v":1,{fields}}}"#);
    for bad in [
        refused(r#""code":"service_suspended""#),
        refused(r#""code":"service_suspended","text":"""#),
        refused(&format!(
            r#""code":"service_suspended","text":"{}""#,
            "a".repeat(257)
        )),
        refused(r#""code":"service_suspended","text":"a\u001bb""#),
        refused(&format!(
            r#""code":"service_suspended","text":"a{}b""#,
            '\u{202e}'
        )),
        refused(&format!(
            r#""code":"service_suspended","text":"a{}b""#,
            '\u{2028}'
        )),
        refused(r#""code":"service_suspended","text":7"#),
        refused(r#""code":"stale_log","text":"service suspended""#),
        refused(r#""code":"service_suspended","text":"t","extra":1"#),
        refused(r#""code":"service_suspended","text":"t","text":"u""#),
    ] {
        let parsed = RelayReply::parse(bad.as_bytes());
        assert!(
            matches!(parsed, Some(Err(ref e)) if e.code() == "malformed"),
            "{bad}: {parsed:?}"
        );
    }
}
