//! The host route proof (§R9.7b) beyond the shared vectors: a fresh
//! challenge round trip, the challenge's own refusals, a frozen verifier,
//! the builder's bounds. Every proof refusal has a vector
//! (`r9-vectors-host-route`, run by `vectors.rs`).
mod support;

use atem_client::encoding::b64u;
use atem_client::host_route::{
    HostChallenge, HostRouteBody, HostRouteRefusal, MAX_ID_BYTES, host_route_message,
    sign_host_route, verify_host_route, verify_host_route_message,
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
