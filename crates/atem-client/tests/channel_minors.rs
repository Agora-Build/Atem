//! The Task 3 review's Minor items, through the public API: the deep
//! divergence the client can't carry, the required channel deadline at
//! admission, the local signing failure, and the crate's own hello builder.
//! (Minor 2, one carriage byte measure, is in `review_regressions.rs`.)
mod support;

use atem_client::channel::carriage::CarryError;
use atem_client::channel::responder::HostContext;
use atem_client::channel::{
    Carriage, ChannelError, HeadRelation, Initiator, Limit, NATIVE_LIFETIME_MS, Principal,
    Responder,
};
use atem_client::domain::SigningInput;
use atem_client::membership::{HostNow, Membership};
use atem_client::session::r9::Hello;
use atem_client::{Error, KeyId, KeyProvider, PublicKey, SignedObject};
use support::*;
use zeroize::Zeroizing;

fn now() -> HostNow {
    HostNow {
        wall_ms: 1_793_264_000_000,
        mono_ms: 0,
        boot_id: "b".into(),
    }
}

fn log_l(v: &Vectors) -> Membership {
    let entries = v.entries(&["E1", "E2", "E3", "E4", "E5", "E6"]);
    Membership::verify_chain(ACCOUNT, &genesis_hash(), &entries, &now())
        .unwrap()
        .membership
}

/// Minor 1: after `need_before`, the widest window; when even that starts at
/// or after `need_before`, `DivergenceTooDeep` instead of the same window.
#[test]
fn a_divergence_deeper_than_the_widest_window_is_reported() {
    let v = Vectors::load();
    let log = log_l(&v);
    let other = v.head("C6_ipad");
    assert_eq!(HeadRelation::of(&log, other), HeadRelation::Diverged);
    let first = Carriage::plan(&log, other, None).unwrap();
    assert_eq!(first.entries, vec![v.object("E6")]);
    let widest = Carriage::plan(&log, other, Some(6)).unwrap();
    assert_eq!(widest.entries.len(), 6, "E1–E6: up to 64 ending at 6");
    assert_eq!(widest.entries[0], v.object("E1"));
    assert_eq!(
        Carriage::plan(&log, other, Some(1)),
        Err(CarryError::DivergenceTooDeep {
            need_before: 1,
            earliest: 1
        })
    );
    // A need_before inside the widest window is answered with it.
    assert!(Carriage::plan(&log, other, Some(2)).is_ok());
}

/// A provider that refuses to sign (a cancelled owner confirmation).
struct Refusing(PublicKey);

impl KeyProvider for Refusing {
    fn public_key(&self, _: &KeyId) -> atem_client::Result<PublicKey> {
        Ok(self.0.clone())
    }
    fn sign(&self, _: &KeyId, _: &SigningInput) -> atem_client::Result<Vec<u8>> {
        Err(Error::Provider("the user cancelled".into()))
    }
    fn x25519(&self, _: &KeyId, _: &[u8; 32]) -> atem_client::Result<Zeroizing<[u8; 32]>> {
        Err(Error::UnknownKey)
    }
    fn hpke_open(
        &self,
        _: &KeyId,
        _: &[u8],
        _: &[u8],
        _: &[u8],
        _: &[u8],
    ) -> atem_client::Result<Zeroizing<Vec<u8>>> {
        Err(Error::UnknownKey)
    }
}

/// Minors 3, 4 and 5 over one handshake each.
#[test]
fn admission_deadline_signing_failure_and_the_hello_builder() {
    let v = Vectors::load();
    let book = Book::load();
    let log = log_l(&v);
    let host_key = KeyId::new("host-a/host_key");
    let ctx = HostContext {
        log: &log,
        host_id: "host-a",
        host_trust_gen: 1,
        provider: &book.provider,
        key: &host_key,
    };

    // Minor 4: a cancelled confirmation is a local failure, not a bad sig_c.
    let (client, init) = Initiator::start(&log, "host-a", 0).unwrap();
    let (_host, accept) = Responder::on_init(&ctx, &init, 0).unwrap();
    let accepted = client.on_frame(&accept, &log, 0).unwrap();
    let refusing = Refusing(book.public("dev-phone/auth"));
    let err = accepted
        .sign(
            Principal::Native {
                device_id: "dev-phone".into(),
            },
            &refusing,
            &KeyId::new("x"),
        )
        .unwrap_err();
    assert!(matches!(err, ChannelError::Signing(Error::Provider(_))));
    assert_eq!(err.code(), "signing_failed");

    // Minors 3 and 5: the bot's hello is built by the crate (the proof is
    // the sig_c of this handshake), and the host must give the channel a
    // deadline: the service's expiry, before the 24 h.
    let bot = Principal::Service {
        device_id: "svc-discord".into(),
    };
    let (client, init) = Initiator::start(&log, "host-a", 0).unwrap();
    let (host, accept) = Responder::on_init(&ctx, &init, 0).unwrap();
    let accepted = client.on_frame(&accept, &log, 0).unwrap();
    let carriage = Carriage::plan(&log, accepted.host_head().head(), None).unwrap();
    let signed = accepted
        .sign(bot.clone(), &book.provider, &book.auth("svc-discord"))
        .unwrap();
    let sig_c = signed.sig_c().to_vec();
    let grant = SignedObject::parse(
        load("r9-vectors-browser-grant")["grant"]
            .to_string()
            .as_bytes(),
    )
    .unwrap();
    let (mut client_channel, finish) = signed
        .finish_hello("aaaaaaaa-0000-4000-8000-000000000001", &carriage, None, 1)
        .unwrap();
    let opened = host.on_finish(&finish, 1).unwrap();
    let hello = Hello::parse(opened.hello()).unwrap();
    assert_eq!(hello.proof.principal, bot);
    assert_eq!(hello.proof.sig_c, sig_c);
    assert_eq!(hello.revision, Some(9));
    let membership = hello.check().unwrap();
    assert_eq!(membership.head, log.head());
    assert!(membership.entries.is_empty());
    let deadline = 5_000;
    let mut host_channel = opened
        .key(&hello.proof)
        .admit(&book.public("svc-discord/auth"), deadline)
        .unwrap();
    assert_eq!(host_channel.deadline_ms(), deadline);
    let frame = host_channel.seal(b"{}", 4_999).unwrap();
    client_channel.open(&frame, 4_999).unwrap();
    assert_eq!(
        host_channel.seal(b"{}", deadline),
        Err(ChannelError::Limit(Limit::Lifetime))
    );
    // A browser grant beside a native principal is refused locally; a
    // deadline beyond 24 h never lengthens the channel.
    let (client, init) = Initiator::start(&log, "host-a", 0).unwrap();
    let (_unused, accept) = Responder::on_init(&ctx, &init, 0).unwrap();
    let signed = client
        .on_frame(&accept, &log, 0)
        .unwrap()
        .sign(
            Principal::Native {
                device_id: "dev-phone".into(),
            },
            &book.provider,
            &book.auth("dev-phone"),
        )
        .unwrap();
    assert_eq!(
        signed
            .finish_hello(
                "aaaaaaaa-0000-4000-8000-000000000002",
                &carriage,
                Some(&grant),
                1
            )
            .err(),
        Some(ChannelError::InvalidHello(
            "the grant is not the principal's"
        ))
    );
    let (client, init) = Initiator::start(&log, "host-a", 0).unwrap();
    let (host, accept) = Responder::on_init(&ctx, &init, 0).unwrap();
    let signed = client
        .on_frame(&accept, &log, 0)
        .unwrap()
        .sign(
            Principal::Native {
                device_id: "dev-phone".into(),
            },
            &book.provider,
            &book.auth("dev-phone"),
        )
        .unwrap();
    let (_, finish) = signed
        .finish_hello("aaaaaaaa-0000-4000-8000-000000000003", &carriage, None, 1)
        .unwrap();
    let opened = host.on_finish(&finish, 1).unwrap();
    let hello = Hello::parse(opened.hello()).unwrap();
    let channel = opened
        .key(&hello.proof)
        .admit(&book.public("dev-phone/auth"), u64::MAX)
        .unwrap();
    assert_eq!(channel.deadline_ms(), 1 + NATIVE_LIFETIME_MS);
}
