//! End to end through the public API only, the way the devices use it:
//! a phone signs an entry and sends its bytes, the host verifies them with
//! the key it pinned from the chain; a manager seals a K backup to the kit
//! the log names, a restorer holding the kit opens it; the host signs a
//! `seen`, the phone verifies it with the host key from its log.
use atem_client::backup::{BackupKey, KBackupEnvelope};
use atem_client::kit::{RecoveryKit, kit_x25519_public};
use atem_client::{Alg, Error, Hash32, KeyId, KeyProvider, PublicKey, SignedObject, SoftwareKeys};
use serde_json::json;
use zeroize::Zeroizing;

#[test]
fn a_phone_signs_an_entry_and_the_host_verifies_it() {
    // The phone's platform keys (a Secure Enclave in production).
    let mut phone = SoftwareKeys::new();
    let auth = phone.generate(KeyId::new("auth"), Alg::P256).unwrap();
    let enc_key = phone.generate(KeyId::new("enc"), Alg::X25519).unwrap();

    // What the host pinned for dev-phone: the `member` object of its entry.
    let pinned_member = json!({
        "device_id": "dev-phone", "kind": "native",
        "auth_key": auth.to_json(), "enc_key": enc_key.to_json(),
        "roles": ["control", "manage", "view"],
    });

    // The phone adds a service, as an `add` entry.
    let mut bot = SoftwareKeys::new();
    let bot_key = bot.generate(KeyId::new("bot"), Alg::Ed25519).unwrap();
    let body = json!({
        "type": "atem-membership-entry", "v": 1, "account_id": "acct-1",
        "genesis_hash": "93".repeat(32), "seq": 5, "prev_hash": "f5".repeat(32),
        "action": "add", "signer": "dev-phone", "signed_at": 1_792_400_004_000u64,
        "member": {
            "device_id": "svc-discord", "kind": "service", "auth_key": bot_key.to_json(),
            "roles": ["service"], "expires_at": 1_794_992_004_000u64,
            "scope": {"hosts": ["host-a"], "ops": ["interrupt", "prompt", "view"]},
        }
    });
    let signed = SignedObject::sign(&phone, &KeyId::new("auth"), body).unwrap();
    let wire = serde_json::to_vec(&signed.to_json()).unwrap();

    // The host: strict parse of the bytes, the signer's key from its pin
    // (never from the object), verify, hash.
    let received = SignedObject::parse(&wire).unwrap();
    let signer_key = PublicKey::from_json(&pinned_member["auth_key"]).unwrap();
    assert_eq!(received.body()["signer"], pinned_member["device_id"]);
    received.verify(&signer_key).unwrap();
    assert_eq!(received.entry_hash(), signed.entry_hash());
    assert_eq!(received.entry_hash().unwrap().to_hex().len(), 64);

    // A relay that edits any byte of the body breaks the signature or the parse.
    let text = String::from_utf8(wire).unwrap();
    for (from, to) in [
        ("\"seq\":5", "\"seq\":6"),
        ("\"prompt\"", "\"stop\""),
        ("svc-discord", "svc-discorx"),
    ] {
        let tampered = text.replacen(from, to, 1);
        assert_ne!(tampered, text);
        let result = SignedObject::parse(tampered.as_bytes()).and_then(|o| o.verify(&signer_key));
        assert!(result.is_err(), "{from} → {to}");
    }
    // Another member's key never verifies it.
    let mut other = SoftwareKeys::new();
    let other_key = other.generate(KeyId::new("mac"), Alg::P256).unwrap();
    assert_eq!(received.verify(&other_key), Err(Error::BadSignature));
}

#[test]
fn a_manager_seals_k_to_the_kit_and_a_restorer_opens_it() {
    // Astation made the kit at account setup; the log records its key.
    let r = [0x5au8; 32];
    let kit = RecoveryKit::make(&r, "acct-1", Hash32([0x93u8; 32]));
    let logged_recovery_key =
        PublicKey::from_json_as(&kit.recovery_key().to_json(), Alg::Ed25519).unwrap();

    // A manager (no R) seals the retained keys to that key.
    let keys = [
        BackupKey {
            kid: "7a3c9e10".into(),
            k: Zeroizing::new([3u8; 32]),
        },
        BackupKey {
            kid: "b982533d".into(),
            k: Zeroizing::new([2u8; 32]),
        },
    ];
    let envelope = KBackupEnvelope::seal(
        "acct-1",
        Hash32([0x93u8; 32]),
        4,
        &logged_recovery_key,
        &keys,
    )
    .unwrap();
    let uploaded = envelope.jcs();
    let recorded_hash = envelope.backup_hash();

    // The restorer reads the kit back (tag checked), fetches the envelope,
    // checks it against the hash the log recorded, and opens it.
    let restored_kit =
        RecoveryKit::read(&r, "acct-1", Hash32([0x93u8; 32]), &kit.kit_tag()).unwrap();
    restored_kit
        .check_genesis(&Hash32([0x93u8; 32]), "acct-1")
        .unwrap();
    let fetched = KBackupEnvelope::parse(uploaded.as_bytes()).unwrap();
    assert_eq!(fetched.backup_hash(), recorded_hash);
    let opened = fetched.open_with_kit(&restored_kit).unwrap();
    assert_eq!(opened.len(), 2);
    assert_eq!(opened[0].kid, "7a3c9e10", "current key first");
    assert_eq!(*opened[0].k, [3u8; 32]);

    // A platform holding only the kit's X25519 key opens it the same way.
    let mut vault = SoftwareKeys::new();
    vault.insert_x25519(KeyId::new("kit"), &restored_kit.x25519_secret());
    assert_eq!(
        vault.public_key(&KeyId::new("kit")).unwrap().as_bytes(),
        kit_x25519_public(&logged_recovery_key).unwrap()
    );
    assert_eq!(
        fetched.open(&vault, &KeyId::new("kit")).unwrap()[1].kid,
        "b982533d"
    );

    // A mistyped kit is refused before anything is fetched.
    let mut tag = kit.kit_tag();
    tag[0] ^= 0x80;
    assert!(matches!(
        RecoveryKit::read(&r, "acct-1", Hash32([0x93u8; 32]), &tag),
        Err(Error::KitTagMismatch)
    ));
}

#[test]
fn the_host_signs_a_seen_and_the_phone_verifies_it() {
    let mut host = SoftwareKeys::new();
    let host_key = host
        .generate(KeyId::new("host_channel_key"), Alg::Ed25519)
        .unwrap();
    // The phone knows the host key from the log's add_host entry.
    let add_host_key = PublicKey::from_json_as(&host_key.to_json(), Alg::Ed25519).unwrap();

    let seen = SignedObject::sign(
        &host,
        &KeyId::new("host_channel_key"),
        json!({
            "type": "atem-seen", "v": 1, "account_id": "acct-1", "genesis_hash": "93".repeat(32),
            "host_id": "host-a", "host_trust_gen": 1, "session_id": "ses-aaaaaaaaaaaa",
            "process_gen": "22222222-2222-4222-8222-222222222222",
            "approval_id": "8c3e9d6b-1f40-4b52-8dae-4f5a6b7c8d9e", "device_id": "dev-phone",
            "created_at": 1_793_264_005_000u64, "seen_at": 1_793_264_025_000u64,
        }),
    )
    .unwrap();
    let bytes = serde_json::to_vec(&seen.to_json()).unwrap();
    let received = SignedObject::parse(&bytes).unwrap();
    received.verify(&add_host_key).unwrap();
    assert_eq!(received.body()["seen_at"], 1_793_264_025_000u64);
}
