//! The deferred handshake (`Connecting::on_accept_unsigned` →
//! `PendingSignature::finish`): signing as an effect for a signer that
//! answers later (WebCrypto's promise, an owner-auth prompt). The browser
//! of the bindings' end-to-end test uses it over a real socket
//! (`atem-client-ffi/tests/e2e_bindings.rs`); this checks its rules
//! against the test host, frames passed in memory.
mod support;

use atem_client::channel::ChannelError;
use atem_client::connect::{ConnectError, Connector, Identity};
use atem_client::domain::SignLabel;
use atem_client::membership::Membership;
use atem_client::{KeyId, KeyProvider};
use support::host::{HostConn, HostCore, HostSession};
use support::*;

const WALL: u64 = 1_793_264_001_000;

fn world() -> (Vectors, Book, Clock, HostCore) {
    let v = Vectors::load();
    let book = Book::load();
    let clock = Clock::at(WALL);
    let log = Membership::verify_chain(
        ACCOUNT,
        &genesis_hash(),
        &v.entries(&["E1", "E2", "E3", "E4", "E5", "E6"]),
        &clock.now,
    )
    .unwrap()
    .membership;
    let seed = unhex32(
        book.keys["host-a"]["host_key"]["secret_hex"]
            .as_str()
            .unwrap(),
    );
    let sessions = vec![HostSession {
        session_id: "ses-aaaaaaaaaaaa".into(),
        process_gen: "22222222-2222-4222-8222-222222222222".into(),
        project: "h1.b982533d.abababababababababababababababababababababababababababababababab"
            .into(),
    }];
    let core = HostCore::new(log, clock.now.clone(), &seed, sessions);
    (v, book, clock, core)
}

/// Exactly the input `on_accept` signs; a signature made outside the crate
/// (here: by the same key, high S on purpose) is normalized, verified and
/// gives the same welcome.
#[test]
fn a_signature_made_later_finishes_the_handshake() {
    let (_, book, clock, mut core) = world();
    let log = core.log.clone();
    let identity = Identity::native("dev-phone", book.auth("dev-phone"));
    let mut conn = HostConn::new(&mut core);
    let now = clock.now.mono_ms;

    let (connecting, init) = Connector::new("host-a").start(&log, now).unwrap();
    let accept = conn.on_frame(&mut core, &init).frames.remove(0);
    let pending = connecting
        .on_accept_unsigned(&accept, &log, &identity, now)
        .unwrap();
    assert_eq!(pending.signing_input().label(), SignLabel::ChannelClient);
    assert_eq!(pending.key(), &book.auth("dev-phone"));
    assert!(
        pending.carriage().entries.is_empty(),
        "same head: nothing carried"
    );

    // The platform signs later; give it a high-S signature (n − s).
    let sig = book
        .provider
        .sign(pending.key(), pending.signing_input())
        .unwrap();
    let public = book.public("dev-phone/auth");
    let input = pending.signing_input();
    let high = if public.verify(input, &sig) == Err(atem_client::Error::HighS) {
        sig
    } else {
        high_s(&sig)
    };
    assert_eq!(
        public.verify(input, &high),
        Err(atem_client::Error::HighS),
        "a high-S signature"
    );
    let (await_welcome, finish) = pending.finish(&public, &high, now).unwrap();
    let first = conn.on_frame(&mut core, &finish).frames.remove(0);
    let attached = await_welcome.on_frame(&first, &log, now).unwrap();
    assert_eq!(attached.welcome().principal, "member:dev-phone");
    assert_eq!(attached.welcome().revision, 9);
}

/// A signature by another key (or garbage) is refused locally: nothing is
/// sent, the error is `signing_failed`.
#[test]
fn a_signature_by_another_key_is_refused_before_anything_is_sent() {
    let (_, book, clock, mut core) = world();
    let log = core.log.clone();
    let identity = Identity::native("dev-phone", book.auth("dev-phone"));
    let now = clock.now.mono_ms;
    for (signer, sig_len) in [("dev-mac", 64), ("dev-phone", 63)] {
        let (connecting, init) = Connector::new("host-a").start(&log, now).unwrap();
        let mut conn2 = HostConn::new(&mut core);
        let accept = conn2.on_frame(&mut core, &init).frames.remove(0);
        let pending = connecting
            .on_accept_unsigned(&accept, &log, &identity, now)
            .unwrap();
        let mut sig = book
            .provider
            .sign(
                &KeyId::new(format!("{signer}/auth")),
                pending.signing_input(),
            )
            .unwrap();
        sig.truncate(sig_len);
        let result = pending.finish(&book.public("dev-phone/auth"), &sig, now);
        let Err(ConnectError::Channel(error @ ChannelError::Signing(_))) = result else {
            panic!("expected a local signing failure, got {result:?}");
        };
        assert_eq!(error.code(), "signing_failed");
    }
}

/// `n − s` of a P-256 `r‖s` (a high-S twin of a low-S signature).
fn high_s(sig: &[u8]) -> Vec<u8> {
    const N: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ];
    let mut out = sig[..32].to_vec();
    let s = &sig[32..];
    let mut borrow = 0i16;
    let mut twin = [0u8; 32];
    for i in (0..32).rev() {
        let d = N[i] as i16 - s[i] as i16 - borrow;
        borrow = i16::from(d < 0);
        twin[i] = (d + if d < 0 { 256 } else { 0 }) as u8;
    }
    out.extend_from_slice(&twin);
    out
}
