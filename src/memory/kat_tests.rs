//! Known-answer vectors for everything Astation must reproduce byte for byte.
//! The same inputs and outputs are listed in designs/e2e-encryption.md
//! "Test vectors". Inputs are constants; outputs were computed once and
//! hard-coded, so any change to an encoding, label or hash breaks this test.
use base64::{Engine, engine::general_purpose::STANDARD};
use p256::ecdsa::SigningKey;

use crate::memory::crypto::EncryptionMode;
use crate::memory::device_keys::DeviceKeys;
use crate::memory::encoding::enc;
use crate::memory::grant::{GrantWire, open_grant};
use crate::memory::statements::{
    AccountState, DeviceVerified, GrantStatement, SignedWire, sealed_hash,
};
use crate::memory::trust::TrustStore;
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

#[test]
fn atem_opens_the_fixed_grant() {
    let keys = device_keys();
    let astation = astation();
    let mut trust = TrustStore::default();
    trust.set_pending(
        "astation-1",
        DEVICE_ID,
        &keys,
        &astation,
        SAFETY_CODE,
        &unhex(TRANSCRIPT).try_into().unwrap(),
    );
    let certificate = SignedWire {
        statement: STANDARD.encode(unhex(DEVICE_VERIFIED)),
        signature: STANDARD.encode(unhex(DEVICE_VERIFIED_SIGNATURE)),
    };
    trust.confirm("astation-1", &certificate).unwrap();
    let grant = GrantWire {
        signed: SignedWire {
            statement: STANDARD.encode(unhex(GRANT_STATEMENT)),
            signature: STANDARD.encode(unhex(GRANT_SIGNATURE)),
        },
        encapped_key: STANDARD.encode(unhex(ENCAPPED_KEY)),
        ciphertext: STANDARD.encode(unhex(CIPHERTEXT)),
    };
    let opened = open_grant(trust.verified("astation-1").unwrap(), &keys, &grant).unwrap();
    assert_eq!((opened.kid.as_str(), *opened.key), (KID, K));
}
