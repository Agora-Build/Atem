//! Known-answer vectors for everything Astation must reproduce byte for byte.
//! The same inputs and outputs are listed in designs/e2e-encryption.md
//! "Test vectors". Inputs are constants; outputs were computed once and
//! hard-coded, so any change to an encoding, label or hash breaks this test.
use base64::{Engine, engine::general_purpose::STANDARD};
use p256::ecdsa::SigningKey;

use crate::memory::crypto::EncryptionMode;
use crate::memory::device_keys::DeviceKeys;
use crate::memory::encoding::enc;
use crate::memory::grant::hpke_open;
use crate::memory::grant::{GrantWire, open_grant};
use crate::memory::statements::{
    AccountState, DeviceVerified, GrantStatement, SignedWire, StorageAbandon, StorageAck,
    StorageConfirm, StorageRotate, UnlockGrant, UnlockRequest, sealed_hash, storage_key_info,
    unlock_info, unlock_request_hash, verify_device,
};
use crate::memory::storage_key::{UnlockGrantWire, check_unlock_grant, device_keys_aad};
use crate::memory::trust::{AstationTrust, TrustStore};
use crate::memory::verification::{
    AstationKeys, Reveal, commitment_for, safety_code, transcript_for,
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

const ACCOUNT: &str = "acct-1";
const DEVICE_ID: &str = "dev-1";
const KID: &str = "0123abcd";

fn device_keys() -> DeviceKeys {
    DeviceKeys::from_secrets([0x11; 32], [0x22; 32], [0x33; 32])
}

fn astation_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[0x55; 32].into()).unwrap()
}

fn reveal() -> Reveal {
    let keys = device_keys();
    Reveal {
        device_pub: keys.device_pub(),
        device_sign_pub: keys.device_sign_pub(),
        unlock_auth_pub: keys.unlock_auth_pub(),
        nonce_a: [0x44; 32],
    }
}

fn astation() -> AstationKeys {
    let enc_pub = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([0x66; 32]));
    let recovery = ed25519_dalek::SigningKey::from_bytes(&[0x77; 32]);
    AstationKeys {
        sign_pub: astation_signing_key()
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec(),
        enc_pub: enc_pub.to_bytes(),
        recovery_sign_pub: recovery.verifying_key().to_bytes(),
        nonce_s: [0x88; 32],
    }
}

fn account_state() -> AccountState {
    AccountState {
        account: ACCOUNT.into(),
        sign_gen: 1,
        mode: EncryptionMode::On,
        kid: Some(KID.into()),
        epoch: 2,
    }
}

fn device_verified() -> DeviceVerified {
    let reveal = reveal();
    DeviceVerified {
        account: ACCOUNT.into(),
        sign_gen: 1,
        device_id: DEVICE_ID.into(),
        device_pub: reveal.device_pub,
        device_sign_pub: reveal.device_sign_pub,
        unlock_auth_pub: reveal.unlock_auth_pub,
        transcript: transcript_for(
            &commitment_for(&reveal),
            &reveal.nonce_a,
            &astation().nonce_s,
        ),
        epoch: 1,
    }
}

fn grant_statement(sealed: [u8; 32]) -> GrantStatement {
    GrantStatement {
        account: ACCOUNT.into(),
        sign_gen: 1,
        kind: "K".into(),
        device_id: DEVICE_ID.into(),
        device_pub: reveal().device_pub,
        kid: KID.into(),
        scope_hmac: String::new(),
        sealed_hash: sealed,
    }
}

/// p256 signs deterministically (RFC 6979), so these are fixed too.
fn sign(statement: &[u8]) -> SignedWire {
    use p256::ecdsa::{Signature, signature::Signer};
    let signature: Signature = astation_signing_key().sign(statement);
    let signature = signature.normalize_s().unwrap_or(signature);
    SignedWire {
        statement: STANDARD.encode(statement),
        signature: STANDARD.encode(signature.to_bytes()),
    }
}

const DEVICE_PUB: &str = "7b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13";
const DEVICE_SIGN_PUB: &str = "a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0";
const UNLOCK_AUTH_PUB: &str = "17cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce";
const SIGN_PUB: &str = "0457e977f6db7e33c3fe7acf2842ed987009caf56d458682fca447b7d3d762ab34c5ab3770ba573bdff5414065640ffb5b346dfa84dec4db4d68e5f59cc471c2ec";
const ENC_PUB: &str = "219e4d800da968d2a5fcb009c784f4746c7138edb9ee4844b739e830b05cf424";
const RECOVERY_SIGN_PUB: &str = "c853ad0f0cd2b619aea92ceec4fd56a24d6499d584ce79257e45cfd8139b60a7";
const ENC_SAMPLE: &str = "000000046174656d00000000000000020102";
const COMMITMENT: &str = "24763549320fde4498bc72c2cf8b6bb6deb3df3911e611a762d912d0c5a8be05";
const SAFETY_CODE: &str = "MN3H-A74N-FJE4";
const TRANSCRIPT: &str = "101b660209618c9130060c9cb737e9647b8ec0ab826684009427bd9cbabcec5f";
const ACCOUNT_STATE: &str = "000000156174656d2d6163636f756e742d73746174652d763100000006616363742d31000000080000000000000001000000026f6e000000083031323361626364000000080000000000000002";
const DEVICE_VERIFIED: &str = "000000176174656d2d6465766963652d76657269666965642d763100000006616363742d31000000080000000000000001000000056465762d31000000207b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f1300000020a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f00000002017cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce00000020101b660209618c9130060c9cb737e9647b8ec0ab826684009427bd9cbabcec5f000000080000000000000001";
const DEVICE_VERIFIED_SIGNATURE: &str = "fff634a2bd4621e42ec788123d0222e3bbda96705baf2ac0d210fcd76e0b05d930d0781c1d133ae5b99a0aeaad5546c4e5c53502a1557c2cc295594be900bf9f";
const GRANT_INFO: &str = "000000126174656d2d6772616e742d696e666f2d763100000006616363742d31000000014b000000056465762d31000000207b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f1300000008303132336162636400000000";
const ENCAPPED_KEY: &str = "b5aad53eeb4319e1d910ec0440f849d19e0a3aa9fe3bcb91342bd80e48835755";
const CIPHERTEXT: &str = "c3f37d28128d3516989f0a41d3c087f40ef8b17cbaa114ab928e4f5ae764136eba6d809254b08bd347694a94c6510500";
const SEALED_HASH: &str = "5373b5bb2fa7696625db127b4a17bcd30e87ce858fee861f85ddcf7c41dcfc7c";
const GRANT_STATEMENT: &str = "0000000d6174656d2d6772616e742d763100000006616363742d31000000080000000000000001000000014b000000056465762d31000000207b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f1300000008303132336162636400000000000000205373b5bb2fa7696625db127b4a17bcd30e87ce858fee861f85ddcf7c41dcfc7c";
const GRANT_SIGNATURE: &str = "01848754ec7cdc93c706a49cd176b683575115a9f838c3f23a092710703b90ae02f746331708f148a01b2e774472bf48851f8ad1f5ee33e430cd5925e48fc0e6";
/// The granted `K`.
const K: [u8; 32] = [0x99; 32];

#[test]
fn fixed_inputs_give_the_listed_public_keys() {
    let reveal = reveal();
    let astation = astation();
    assert_eq!(hex(&reveal.device_pub), DEVICE_PUB);
    assert_eq!(hex(&reveal.device_sign_pub), DEVICE_SIGN_PUB);
    assert_eq!(hex(&reveal.unlock_auth_pub), UNLOCK_AUTH_PUB);
    assert_eq!(hex(&astation.sign_pub), SIGN_PUB);
    assert_eq!(hex(&astation.enc_pub), ENC_PUB);
    assert_eq!(hex(&astation.recovery_sign_pub), RECOVERY_SIGN_PUB);
    let wire = AstationKeys::from_wire(
        &STANDARD.encode(unhex(SIGN_PUB)),
        &STANDARD.encode(unhex(ENC_PUB)),
        &STANDARD.encode(unhex(RECOVERY_SIGN_PUB)),
        &STANDARD.encode([0x88; 32]),
    )
    .unwrap();
    assert_eq!(wire, astation);
}

#[test]
fn encoding_and_ceremony_vectors() {
    let reveal = reveal();
    let astation = astation();
    assert_eq!(hex(&enc(&[b"atem", b"", &[1, 2]])), ENC_SAMPLE);
    let commitment = commitment_for(&reveal);
    assert_eq!(hex(&commitment), COMMITMENT);
    assert_eq!(safety_code(&reveal, &astation), SAFETY_CODE);
    assert_eq!(
        hex(&transcript_for(
            &commitment,
            &reveal.nonce_a,
            &astation.nonce_s
        )),
        TRANSCRIPT
    );
}

#[test]
fn statement_vectors() {
    assert_eq!(hex(&account_state().encode()), ACCOUNT_STATE);
    assert_eq!(hex(&device_verified().encode()), DEVICE_VERIFIED);
    assert_eq!(hex(&grant_statement([0; 32]).info()), GRANT_INFO);
    assert_eq!(
        hex(&sealed_hash(&unhex(ENCAPPED_KEY), &unhex(CIPHERTEXT))),
        SEALED_HASH
    );
    let sealed: [u8; 32] = unhex(SEALED_HASH).try_into().unwrap();
    assert_eq!(hex(&grant_statement(sealed).encode()), GRANT_STATEMENT);
    // RFC 6979 signatures are deterministic; Astation's CryptoKit ones are
    // not, so Swift checks that atem's vectors verify rather than match.
    assert_eq!(
        hex(&STANDARD
            .decode(sign(&unhex(DEVICE_VERIFIED)).signature)
            .unwrap()),
        DEVICE_VERIFIED_SIGNATURE
    );
    assert_eq!(
        hex(&STANDARD
            .decode(sign(&unhex(GRANT_STATEMENT)).signature)
            .unwrap()),
        GRANT_SIGNATURE
    );
}

#[test]
fn seeded_seal_reproduces_the_fixed_grant() {
    use hpke::{
        Deserializable, OpModeS, Serializable, aead::ChaCha20Poly1305, kdf::HkdfSha256,
        kem::X25519HkdfSha256,
    };
    use rand::SeedableRng;
    let recipient =
        <X25519HkdfSha256 as hpke::Kem>::PublicKey::from_bytes(&unhex(DEVICE_PUB)).unwrap();
    let mut rng = rand::rngs::StdRng::seed_from_u64(7);
    let (encapped, ciphertext) =
        hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256, _>(
            &OpModeS::Base,
            &recipient,
            &unhex(GRANT_INFO),
            &K,
            b"",
            &mut rng,
        )
        .unwrap();
    assert_eq!(hex(&encapped.to_bytes()), ENCAPPED_KEY);
    assert_eq!(hex(&ciphertext), CIPHERTEXT);
}

/// The pins atem holds after verifying with the fixed Astation.
fn verified_trust() -> AstationTrust {
    let mut trust = TrustStore::default();
    trust.set_pending(
        "astation-1",
        DEVICE_ID,
        &device_keys(),
        &astation(),
        SAFETY_CODE,
        &unhex(TRANSCRIPT).try_into().unwrap(),
    );
    let certificate = SignedWire {
        statement: STANDARD.encode(unhex(DEVICE_VERIFIED)),
        signature: STANDARD.encode(unhex(DEVICE_VERIFIED_SIGNATURE)),
    };
    trust.confirm("astation-1", &certificate).unwrap();
    trust.verified("astation-1").unwrap().clone()
}

#[test]
fn atem_opens_the_fixed_grant() {
    let keys = device_keys();
    let grant = GrantWire {
        signed: SignedWire {
            statement: STANDARD.encode(unhex(GRANT_STATEMENT)),
            signature: STANDARD.encode(unhex(GRANT_SIGNATURE)),
        },
        encapped_key: STANDARD.encode(unhex(ENCAPPED_KEY)),
        ciphertext: STANDARD.encode(unhex(CIPHERTEXT)),
    };
    let opened = open_grant(&verified_trust(), &keys, &grant).unwrap();
    assert_eq!((opened.kid.as_str(), *opened.key), (KID, K));
}

// Build step 2a. Extra inputs: X25519 secret `E` = 32 × aa, unlock nonce =
// 32 × bb, boot_id "boot-1", ticket "", time 1760000000, old storage_kid
// "0a1b2c3d", new storage_kid "4e5f6a7b", unlock-grant sealed_hash = 32 × cc,
// rotation sealed_hash = 32 × dd, storage key = 32 × ee.
const OLD_STORAGE_KID: &str = "0a1b2c3d";
const NEW_STORAGE_KID: &str = "4e5f6a7b";
const E_SECRET: [u8; 32] = [0xaa; 32];
const STORAGE_KEY: [u8; 32] = [0xee; 32];
const E_PUB: &str = "14ca9e4d387bccf35746e0407daaacc6b28a4f8445ef5a5158894db983e24070";
const UNLOCK_REQUEST: &str = "000000166174656d2d756e6c6f636b2d726571756573742d763100000006616363742d31000000056465762d3100000006626f6f742d31000000000000002014ca9e4d387bccf35746e0407daaacc6b28a4f8445ef5a5158894db983e2407000000020bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb000000080000000068e77800000000083061316232633364";
const UNLOCK_REQUEST_HASH: &str =
    "1301ff47099849bf273dbf5b62df77365f305991efd763d2621b35670db65b9d";
const UNLOCK_REQUEST_SIGNATURE: &str = "e82afd604b8697c54433e33fc7f2f1cf168ad248e0c620edb2c2e470d7908a2cf71362934c8c33f2c9449f27f52d4de6076ad7e2fa16fa87c274192ca3b58008";
const UNLOCK_INFO: &str = "000000136174656d2d756e6c6f636b2d696e666f2d763100000006616363742d31000000056465762d31000000083061316232633364000000201301ff47099849bf273dbf5b62df77365f305991efd763d2621b35670db65b9d";
const UNLOCK_GRANT: &str = "000000146174656d2d756e6c6f636b2d6772616e742d763100000006616363742d31000000080000000000000001000000056465762d31000000083061316232633364000000201301ff47099849bf273dbf5b62df77365f305991efd763d2621b35670db65b9d00000020cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const DEVICE_KEYS_AAD: &str =
    "000000136174656d2d6465766963652d6b6579732d7631000000056465762d31000000083061316232633364";
const STORAGE_KEY_INFO: &str = "000000186174656d2d73746f726167652d6b65792d696e666f2d763100000006616363742d31000000056465762d31000000083465356636613762";
const STORAGE_ROTATE: &str = "000000166174656d2d73746f726167652d726f746174652d763100000006616363742d31000000056465762d3100000008306131623263336400000008346535663661376200000020dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const STORAGE_ROTATE_SIGNATURE: &str = "2041a1670126328aa40f7bb9cf4d35146cd45cc447ecef1c904c5b970876242a7c37f59dc117a5486e8e37d0b39b958f00806c0cf00d9c52e4d3fd90818e4408";
const FIRST_STORAGE_ROTATE: &str = "000000166174656d2d73746f726167652d726f746174652d763100000006616363742d31000000056465762d310000000000000008306131623263336400000020dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const STORAGE_ACK: &str = "000000136174656d2d73746f726167652d61636b2d763100000006616363742d31000000080000000000000001000000056465762d31000000083465356636613762";
const STORAGE_CONFIRM: &str = "000000176174656d2d73746f726167652d636f6e6669726d2d763100000006616363742d31000000056465762d31000000083465356636613762";
const STORAGE_CONFIRM_SIGNATURE: &str = "6a7c7961862d5ef7d3028b3d6c511434f5a5e8e4fd1f0541de1ca3a6db9aca2b32d5f3aec90aa750948a46faa61078dee3339490cd873e58e5639ec36167db0d";
const STORAGE_ABANDON: &str = "000000176174656d2d73746f726167652d6162616e646f6e2d763100000006616363742d31000000056465762d31000000083465356636613762";
const STORAGE_ABANDON_SIGNATURE: &str = "4cecaeeda1ba12cce89797ca065ee9c04b050407c05c06e784501b01034a3e0df4f00fac0d35591ec710fc3c316a395c66bd70630f6cd7ba2f72a78e97e15b01";
// The storage key released to `E_PUB` (seeded seal, StdRng seed 8).
const UNLOCK_ENCAPPED_KEY: &str =
    "8e5c2c633c06326dfba94d9a717724ca1542bd07e800b99e1f12dd9efb95c341";
const UNLOCK_CIPHERTEXT: &str = "4eccc2f528b4d5cf884cd9049545cb96d804ddca7c2e943fe101ced564bff96d8a7150a4fdfa3fad8b11d9697da64109";
const UNLOCK_SEALED_HASH: &str = "5222490f82b684dbfb043d64c9d213e4e4c38b048d083744f78437455a165be5";
const SEALED_UNLOCK_GRANT: &str = "000000146174656d2d756e6c6f636b2d6772616e742d763100000006616363742d31000000080000000000000001000000056465762d31000000083061316232633364000000201301ff47099849bf273dbf5b62df77365f305991efd763d2621b35670db65b9d000000205222490f82b684dbfb043d64c9d213e4e4c38b048d083744f78437455a165be5";
const SEALED_UNLOCK_GRANT_SIGNATURE: &str = "ac2e60b3834f1f0907a8eb22a04f5b15b86f5388d16e074b1fd694e2c646088f74ac5f849c1c9ad9c20647164d8e0f8b9efb730058ec9d42c78e54306a58746d";
// The new storage key sealed to Astation's encryption key (StdRng seed 9).
const ROTATE_ENCAPPED_KEY: &str =
    "3fe8a9052458c90d03badd8cbe52b2a0b38f8a0212023ed63013d457aad1e67f";
const ROTATE_CIPHERTEXT: &str = "2c6ab9033b8dbbdae43bd691a2f590455984416dc70989de638b99a78821d2d78523ffbc9827815e0fe00f4b2a9ad4e8";
const ROTATE_SEALED_HASH: &str = "db1a3c8e614277746e1e437077664041860372fbfbf80a0cb7ee930f98608e17";
const SEALED_STORAGE_ROTATE: &str = "000000166174656d2d73746f726167652d726f746174652d763100000006616363742d31000000056465762d3100000008306131623263336400000008346535663661376200000020db1a3c8e614277746e1e437077664041860372fbfbf80a0cb7ee930f98608e17";
const SEALED_STORAGE_ROTATE_SIGNATURE: &str = "35d7a8f51c36b1d70bc699360556c47293c47100fd3c3fd96e84fd128557ab505d26834de38235b194ddef76883b2cfc5b882b7e4e3b0b7872f7d5e2c998d800";

fn signature_hex(signed: &SignedWire) -> String {
    hex(&STANDARD.decode(&signed.signature).unwrap())
}

fn unlock_request() -> UnlockRequest {
    UnlockRequest {
        account: ACCOUNT.into(),
        device_id: DEVICE_ID.into(),
        boot_id: "boot-1".into(),
        ticket: String::new(),
        e_pub: x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(E_SECRET))
            .to_bytes(),
        nonce: [0xbb; 32],
        time: 1_760_000_000,
        storage_kid: OLD_STORAGE_KID.into(),
    }
}

fn unlock_grant(sealed_hash: [u8; 32]) -> UnlockGrant {
    UnlockGrant {
        account: ACCOUNT.into(),
        sign_gen: 1,
        device_id: DEVICE_ID.into(),
        storage_kid: OLD_STORAGE_KID.into(),
        request_hash: unhex(UNLOCK_REQUEST_HASH).try_into().unwrap(),
        sealed_hash,
    }
}

fn rotate(old: &str, new: &str, sealed_hash: [u8; 32]) -> StorageRotate {
    StorageRotate {
        account: ACCOUNT.into(),
        device_id: DEVICE_ID.into(),
        old_storage_kid: old.into(),
        new_storage_kid: new.into(),
        sealed_hash,
    }
}

/// A base-mode seal of `STORAGE_KEY` from a seeded RNG, so the output is fixed.
fn seeded_seal(recipient: &[u8], info: &[u8], seed: u64) -> (Vec<u8>, Vec<u8>) {
    use hpke::{
        Deserializable, OpModeS, Serializable, aead::ChaCha20Poly1305, kdf::HkdfSha256,
        kem::X25519HkdfSha256,
    };
    use rand::SeedableRng;
    let recipient = <X25519HkdfSha256 as hpke::Kem>::PublicKey::from_bytes(recipient).unwrap();
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    let (encapped, ciphertext) =
        hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256, _>(
            &OpModeS::Base,
            &recipient,
            info,
            &STORAGE_KEY,
            b"",
            &mut rng,
        )
        .unwrap();
    (encapped.to_bytes().to_vec(), ciphertext)
}

#[test]
fn unlock_vectors() {
    let request = unlock_request();
    assert_eq!(hex(&request.e_pub), E_PUB);
    let request = request.encode();
    assert_eq!(hex(&request), UNLOCK_REQUEST);
    let request_hash = unlock_request_hash(&request);
    assert_eq!(hex(&request_hash), UNLOCK_REQUEST_HASH);
    // Ed25519 is deterministic, so the unlock-auth signature is fixed too.
    let signed = device_keys().unlock_auth_key().sign_statement(&request);
    assert_eq!(signature_hex(&signed), UNLOCK_REQUEST_SIGNATURE);
    verify_device(&unhex(UNLOCK_AUTH_PUB).try_into().unwrap(), &signed).unwrap();
    assert_eq!(
        hex(&unlock_info(
            ACCOUNT,
            DEVICE_ID,
            OLD_STORAGE_KID,
            &request_hash
        )),
        UNLOCK_INFO
    );
    assert_eq!(hex(&unlock_grant([0xcc; 32]).encode()), UNLOCK_GRANT);
}

#[test]
fn storage_key_vectors() {
    assert_eq!(
        hex(&device_keys_aad(DEVICE_ID, OLD_STORAGE_KID)),
        DEVICE_KEYS_AAD
    );
    assert_eq!(
        hex(&storage_key_info(ACCOUNT, DEVICE_ID, NEW_STORAGE_KID)),
        STORAGE_KEY_INFO
    );
    let rotation = rotate(OLD_STORAGE_KID, NEW_STORAGE_KID, [0xdd; 32]).encode();
    assert_eq!(hex(&rotation), STORAGE_ROTATE);
    assert_eq!(
        signature_hex(&device_keys().sign_statement(&rotation)),
        STORAGE_ROTATE_SIGNATURE
    );
    assert_eq!(
        hex(&rotate("", OLD_STORAGE_KID, [0xdd; 32]).encode()),
        FIRST_STORAGE_ROTATE
    );
    let ack = StorageAck {
        account: ACCOUNT.into(),
        sign_gen: 1,
        device_id: DEVICE_ID.into(),
        storage_kid: NEW_STORAGE_KID.into(),
    };
    assert_eq!(hex(&ack.encode()), STORAGE_ACK);
    let confirm = StorageConfirm {
        account: ACCOUNT.into(),
        device_id: DEVICE_ID.into(),
        storage_kid: NEW_STORAGE_KID.into(),
    }
    .encode();
    assert_eq!(hex(&confirm), STORAGE_CONFIRM);
    assert_eq!(
        signature_hex(&device_keys().sign_statement(&confirm)),
        STORAGE_CONFIRM_SIGNATURE
    );
    let abandon = StorageAbandon {
        account: ACCOUNT.into(),
        device_id: DEVICE_ID.into(),
        storage_kid: NEW_STORAGE_KID.into(),
    }
    .encode();
    assert_eq!(hex(&abandon), STORAGE_ABANDON);
    assert_eq!(
        signature_hex(&device_keys().sign_statement(&abandon)),
        STORAGE_ABANDON_SIGNATURE
    );
}

#[test]
fn seeded_seals_reproduce_the_fixed_storage_key_seals() {
    let (encapped, ciphertext) = seeded_seal(&unhex(E_PUB), &unhex(UNLOCK_INFO), 8);
    assert_eq!(
        (hex(&encapped), hex(&ciphertext)),
        (UNLOCK_ENCAPPED_KEY.into(), UNLOCK_CIPHERTEXT.into())
    );
    assert_eq!(
        hex(&sealed_hash(&encapped, &ciphertext)),
        UNLOCK_SEALED_HASH
    );
    let (encapped, ciphertext) = seeded_seal(&unhex(ENC_PUB), &unhex(STORAGE_KEY_INFO), 9);
    assert_eq!(
        (hex(&encapped), hex(&ciphertext)),
        (ROTATE_ENCAPPED_KEY.into(), ROTATE_CIPHERTEXT.into())
    );
    assert_eq!(
        hex(&sealed_hash(&encapped, &ciphertext)),
        ROTATE_SEALED_HASH
    );
}

#[test]
fn atem_opens_the_fixed_unlock_grant() {
    let sealed: [u8; 32] = unhex(UNLOCK_SEALED_HASH).try_into().unwrap();
    let statement = unlock_grant(sealed).encode();
    assert_eq!(hex(&statement), SEALED_UNLOCK_GRANT);
    let signed = sign(&statement);
    assert_eq!(signature_hex(&signed), SEALED_UNLOCK_GRANT_SIGNATURE);
    let wire = UnlockGrantWire {
        grant: SignedWire {
            statement: STANDARD.encode(unhex(SEALED_UNLOCK_GRANT)),
            signature: STANDARD.encode(unhex(SEALED_UNLOCK_GRANT_SIGNATURE)),
        },
        encapped_key: STANDARD.encode(unhex(UNLOCK_ENCAPPED_KEY)),
        ciphertext: STANDARD.encode(unhex(UNLOCK_CIPHERTEXT)),
    };
    // The key agent's checks and open, with the fixed single-use key.
    let checked = check_unlock_grant(&verified_trust(), &unhex(UNLOCK_REQUEST), &wire).unwrap();
    assert_eq!(checked.grant.storage_kid, OLD_STORAGE_KID);
    let info = unlock_info(
        ACCOUNT,
        DEVICE_ID,
        &checked.grant.storage_kid,
        &checked.request_hash,
    );
    let key = hpke_open(&E_SECRET, &checked.encapped, &checked.ciphertext, &info).unwrap();
    assert_eq!(key.as_slice(), STORAGE_KEY);
}

#[test]
fn astation_opens_the_fixed_storage_rotate() {
    let sealed: [u8; 32] = unhex(ROTATE_SEALED_HASH).try_into().unwrap();
    let statement = rotate(OLD_STORAGE_KID, NEW_STORAGE_KID, sealed).encode();
    assert_eq!(hex(&statement), SEALED_STORAGE_ROTATE);
    let signed = device_keys().sign_statement(&statement);
    assert_eq!(signature_hex(&signed), SEALED_STORAGE_ROTATE_SIGNATURE);
    // Astation's side: the device signature verifies and the seal opens with
    // its encryption key (secret 32 × 66).
    verify_device(&unhex(DEVICE_SIGN_PUB).try_into().unwrap(), &signed).unwrap();
    let key = hpke_open(
        &[0x66; 32],
        &unhex(ROTATE_ENCAPPED_KEY),
        &unhex(ROTATE_CIPHERTEXT),
        &unhex(STORAGE_KEY_INFO),
    )
    .unwrap();
    assert_eq!(key.as_slice(), STORAGE_KEY);
}
