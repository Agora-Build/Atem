//! Signing round trips through the `KeyProvider` path, and every way to
//! misuse a domain label, a pinned `alg` or an array rule is refused. Public
//! API only.
use atem_client::backup::{BackupKey, KBackupEnvelope};
use atem_client::canonical::StrictValue;
use atem_client::domain::{SignLabel, SigningInput};
use atem_client::encoding::b64u;
use atem_client::kit::RecoveryKit;
use atem_client::provider::sign;
use atem_client::{Alg, Error, Hash32, KeyId, KeyProvider, PublicKey, SignedObject, SoftwareKeys};
use serde_json::{Value, json};
use zeroize::Zeroizing;

/// A strictly parsed copy of `value` (what a host or client gets from the wire).
fn strict(value: &Value) -> StrictValue {
    StrictValue::parse(value.to_string().as_bytes(), usize::MAX).unwrap()
}

const LABELS: [SignLabel; 7] = [
    SignLabel::MembershipEntry,
    SignLabel::RecoveryCosign,
    SignLabel::BrowserGrant,
    SignLabel::PushHint,
    SignLabel::Seen,
    SignLabel::ChannelHost,
    SignLabel::ChannelClient,
];

fn provider() -> SoftwareKeys {
    let mut keys = SoftwareKeys::new();
    keys.generate(KeyId::new("phone"), Alg::P256).unwrap();
    keys.generate(KeyId::new("host"), Alg::Ed25519).unwrap();
    keys.generate(KeyId::new("kit"), Alg::Ed25519).unwrap();
    keys.generate(KeyId::new("enc"), Alg::X25519).unwrap();
    keys
}

fn entry_body(keys: &SoftwareKeys, roles: Value) -> Value {
    json!({
        "type": "atem-membership-entry", "v": 1, "account_id": "acct-1",
        "genesis_hash": "ab".repeat(32), "seq": 3, "prev_hash": "cd".repeat(32),
        "action": "add", "signer": "dev-mac", "signed_at": 1_792_400_002_000u64,
        "member": {
            "device_id": "dev-phone", "kind": "native",
            "auth_key": keys.public_key(&KeyId::new("phone")).unwrap().to_json(),
            "enc_key": keys.public_key(&KeyId::new("enc")).unwrap().to_json(),
            "roles": roles,
        }
    })
}

#[test]
fn a_signature_verifies_only_under_its_own_label() {
    let keys = provider();
    for id in ["phone", "host"] {
        let key = keys.public_key(&KeyId::new(id)).unwrap();
        for signed_as in LABELS {
            let sig = sign(
                &keys,
                &KeyId::new(id),
                &SigningInput::new(signed_as, b"payload"),
            )
            .unwrap();
            for checked_as in LABELS {
                let result = key.verify(&SigningInput::new(checked_as, b"payload"), &sig);
                if signed_as == checked_as {
                    result.unwrap();
                } else {
                    assert_eq!(
                        result,
                        Err(Error::BadSignature),
                        "{id}: {signed_as:?} as {checked_as:?}"
                    );
                }
            }
            // And never as the bare payload.
            assert_eq!(key.verify_raw(b"payload", &sig), Err(Error::BadSignature));
        }
    }
}

#[test]
fn an_entry_signature_is_not_a_kit_signature_and_back() {
    let keys = provider();
    let body = json!({
        "type": "atem-membership-entry", "v": 1, "account_id": "acct-1",
        "genesis_hash": "ab".repeat(32), "seq": 7, "prev_hash": "cd".repeat(32),
        "action": "set_recovery_key", "signer": "dev-phone", "signed_at": 1u64,
        "kit": "current",
        "recovery_key": keys.public_key(&KeyId::new("host")).unwrap().to_json(),
    });
    let mut object = SignedObject::sign(&keys, &KeyId::new("kit"), body).unwrap();
    // `kit_sig` is required with kit: "current" before the object can go out.
    let missing = SignedObject::from_strict(&strict(&object.to_json()));
    assert_eq!(missing, Err(Error::KitSigMissing));
    object.cosign(&keys, &KeyId::new("kit")).unwrap();
    let wire = SignedObject::from_strict(&strict(&object.to_json())).unwrap();
    let kit = keys.public_key(&KeyId::new("kit")).unwrap();
    wire.verify(&kit).unwrap();
    wire.verify_kit_sig(&kit).unwrap();
    // The same key signed both, over the same body: swapping them fails.
    let mut swapped = wire.to_json();
    let (sig, kit_sig) = (swapped["sig"].clone(), swapped["kit_sig"].clone());
    swapped["sig"] = kit_sig;
    swapped["kit_sig"] = sig;
    let swapped = SignedObject::from_strict(&strict(&swapped)).unwrap();
    assert_eq!(swapped.verify(&kit), Err(Error::BadSignature));
    assert_eq!(swapped.verify_kit_sig(&kit), Err(Error::BadSignature));
}

#[test]
fn the_pinned_alg_is_never_swapped() {
    let keys = provider();
    let input = SigningInput::new(SignLabel::Seen, b"{}");
    let p256 = keys.public_key(&KeyId::new("phone")).unwrap();
    let ed = keys.public_key(&KeyId::new("host")).unwrap();
    let x = keys.public_key(&KeyId::new("enc")).unwrap();
    let ed_sig = sign(&keys, &KeyId::new("host"), &input).unwrap();
    let p_sig = sign(&keys, &KeyId::new("phone"), &input).unwrap();
    // A signature of one algorithm never verifies under the other.
    // (Ed25519 bytes read as r‖s may also have a high S: refused either way.)
    assert!(matches!(
        p256.verify(&input, &ed_sig),
        Err(Error::BadSignature | Error::HighS)
    ));
    assert_eq!(ed.verify(&input, &p_sig), Err(Error::BadSignature));
    // An X25519 key neither signs nor verifies.
    assert_eq!(x.verify(&input, &ed_sig), Err(Error::WrongAlg));
    assert_eq!(
        sign(&keys, &KeyId::new("enc"), &input),
        Err(Error::WrongAlg)
    );
    // Key bytes relabelled with another alg are refused when parsed.
    let relabelled = json!({"alg": "ed25519", "pub": b64u(p256.as_bytes())});
    assert_eq!(PublicKey::from_json(&relabelled), Err(Error::BadKey));
    let as_p256 = json!({"alg": "p256", "pub": b64u(ed.as_bytes())});
    assert_eq!(PublicKey::from_json(&as_p256), Err(Error::BadKey));
    // A field pinned to one alg refuses another valid key.
    assert_eq!(
        PublicKey::from_json_as(&p256.to_json(), Alg::Ed25519),
        Err(Error::WrongAlg)
    );
    assert_eq!(
        PublicKey::from_json_as(&ed.to_json(), Alg::X25519),
        Err(Error::WrongAlg)
    );
    // A recovery key must be Ed25519 for a kit signature.
    let mut obj = SignedObject::sign(
        &keys,
        &KeyId::new("phone"),
        json!({
            "type": "atem-membership-entry", "v": 1, "action": "set_recovery_key", "kit": "current"
        }),
    )
    .unwrap();
    assert_eq!(
        obj.cosign(&keys, &KeyId::new("phone")),
        Err(Error::WrongAlg)
    );
    obj.cosign(&keys, &KeyId::new("kit")).unwrap();
    assert_eq!(obj.verify_kit_sig(&p256), Err(Error::WrongAlg));
}

#[test]
fn a_high_s_twin_is_refused() {
    // n − s gives a second valid ECDSA signature; only low S is accepted.
    let keys = provider();
    let input = SigningInput::new(SignLabel::MembershipEntry, b"{}");
    let key = keys.public_key(&KeyId::new("phone")).unwrap();
    let sig = sign(&keys, &KeyId::new("phone"), &input).unwrap();
    const N: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ];
    let mut high = sig.clone();
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let d = N[i] as i16 - sig[32 + i] as i16 - borrow;
        high[32 + i] = d.rem_euclid(256) as u8;
        borrow = i16::from(d < 0);
    }
    key.verify(&input, &sig).unwrap();
    assert_eq!(key.verify(&input, &high), Err(Error::HighS));
}

#[test]
fn sets_must_be_sorted_and_unique_when_signed_and_when_parsed() {
    let keys = provider();
    let signer = KeyId::new("phone");
    let good = SignedObject::sign(
        &keys,
        &signer,
        entry_body(&keys, json!(["control", "view"])),
    )
    .unwrap();
    for bad in [
        json!(["view", "control"]),
        json!(["view", "view"]),
        json!(["view", 1]),
    ] {
        // The signer refuses to sign it...
        assert_eq!(
            SignedObject::sign(&keys, &signer, entry_body(&keys, bad.clone())),
            Err(Error::ArrayNotCanonical),
            "{bad}"
        );
        // ...and a verifier refuses it even with a valid signature over it.
        let mut wire = good.to_json();
        wire["body"]["member"]["roles"] = bad.clone();
        assert_eq!(
            SignedObject::from_strict(&strict(&wire)),
            Err(Error::ArrayNotCanonical),
            "{bad}"
        );
    }
    // Every set field, in entries and grants.
    let grant = |ops: Value| json!({"type": "atem-browser-grant", "v": 1, "ops": ops});
    assert!(SignedObject::sign(&keys, &signer, grant(json!(["prompt", "view"]))).is_ok());
    assert_eq!(
        SignedObject::sign(&keys, &signer, grant(json!(["view", "prompt"]))),
        Err(Error::ArrayNotCanonical)
    );
    for field in ["hosts", "projects", "sessions", "ops"] {
        let mut body = entry_body(&keys, json!(["service"]));
        body["member"]["scope"] = json!({ field: ["b", "a"] });
        assert_eq!(
            SignedObject::sign(&keys, &signer, body),
            Err(Error::ArrayNotCanonical),
            "{field}"
        );
    }
    // A push hint or a seen has no array at all.
    let seen = json!({"type": "atem-seen", "v": 1, "ids": ["a"]});
    assert_eq!(
        SignedObject::sign(&keys, &signer, seen),
        Err(Error::ArrayNotCanonical)
    );
}

#[test]
fn a_sequence_keeps_its_order_and_a_reordered_one_is_another_object() {
    let keys = provider();
    let kit = RecoveryKit::make(&[9u8; 32], "acct-1", Hash32([1u8; 32]));
    let body = |kids: Value| {
        json!({
            "type": "atem-membership-entry", "v": 1, "action": "k_backup",
            "k_backup": {"blob_version": 4, "kids": kids,
                         "recovery_key": kit.recovery_key().to_json(), "backup_hash": "00".repeat(32)}
        })
    };
    let signer = KeyId::new("phone");
    let key = keys.public_key(&signer).unwrap();
    // Current first, never sorted: the unsorted order is accepted as is.
    let entry = SignedObject::sign(&keys, &signer, body(json!(["b98", "1f2"]))).unwrap();
    entry.verify(&key).unwrap();
    // Reordered: still well-formed, but another body, so the signature and
    // the entry hash no longer match.
    let mut reordered = entry.to_json();
    reordered["body"]["k_backup"]["kids"] = json!(["1f2", "b98"]);
    let reordered = SignedObject::from_strict(&strict(&reordered)).unwrap();
    assert_eq!(reordered.verify(&key), Err(Error::BadSignature));
    assert_ne!(reordered.entry_hash(), entry.entry_hash());
    // A duplicate kid is refused outright.
    assert_eq!(
        SignedObject::sign(&keys, &signer, body(json!(["b98", "b98"]))),
        Err(Error::ArrayNotCanonical)
    );

    // The envelope binds the same sequence: reordering its kids breaks it.
    let k = |kid: &str, b: u8| BackupKey {
        kid: kid.into(),
        k: Zeroizing::new([b; 32]),
    };
    let env = KBackupEnvelope::seal(
        "acct-1",
        kit.genesis_hash(),
        4,
        &kit.recovery_key(),
        &[k("b98", 1), k("1f2", 2)],
    )
    .unwrap();
    assert_eq!(env.kids, ["b98", "1f2"]);
    let mut wire = env.to_json();
    wire["kids"] = json!(["1f2", "b98"]);
    let reordered = KBackupEnvelope::from_strict(&strict(&wire)).unwrap();
    assert_ne!(reordered.backup_hash(), env.backup_hash());
    assert_eq!(
        reordered.open_with_kit(&kit).unwrap_err(),
        Error::BackupInvalid
    );
    wire["kids"] = json!(["b98", "b98"]);
    assert_eq!(
        KBackupEnvelope::from_strict(&strict(&wire)),
        Err(Error::BackupInvalid)
    );
}

#[test]
fn a_body_type_signs_only_under_its_label() {
    let keys = provider();
    let key = keys.public_key(&KeyId::new("host")).unwrap();
    let hint = SignedObject::sign(
        &keys,
        &KeyId::new("host"),
        json!({"type": "atem-push-hint", "v": 1, "state": "resolved"}),
    )
    .unwrap();
    assert_eq!(hint.label(), SignLabel::PushHint);
    hint.verify(&key).unwrap();
    // The same signature presented on a seen with the same other fields fails.
    let mut as_seen = hint.to_json();
    as_seen["body"]["type"] = json!("atem-seen");
    let as_seen = SignedObject::from_strict(&strict(&as_seen)).unwrap();
    assert_eq!(as_seen.label(), SignLabel::Seen);
    assert_eq!(as_seen.verify(&key), Err(Error::BadSignature));
    // An unknown type has no label and can't be signed or parsed.
    let other = json!({"type": "atem-other", "v": 1});
    assert_eq!(
        SignedObject::sign(&keys, &KeyId::new("host"), other),
        Err(Error::UnknownType)
    );
}
