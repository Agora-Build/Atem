//! The bindings' durable state survives a restart mid-flight (§R9.5
//! "Writing a backup" step 2, §R9.4 rules 1, 4 and 5): the K-backup writer
//! and the publisher resume at the same step and sign the same body (no
//! sibling); a second write for the same device is refused while one is
//! prepared; the restore's enrollment resumes and finishes; tampered saved
//! state is refused. Each test uses its own devices: the per-device claim
//! is process-wide and the tests run in parallel.
// The provider-taking calls are the UniFFI layer's (default feature).
#![cfg(feature = "uniffi")]

#[path = "../../atem-client/tests/support/mod.rs"]
#[allow(unused_imports)]
mod support;

use std::sync::Arc;

use atem_client::KeyProvider as _;
use atem_client::provider::KeyId;
use atem_client_ffi::AtemError;
use atem_client_ffi::kit::{RestoreSession, seal_k_backup};
use atem_client_ffi::log::MembershipLog;
use atem_client_ffi::provider::{AppKeyProvider, ProviderError};
use atem_client_ffi::publish::{EntryPublisher, KBackupWriter};
use atem_client_ffi::types::{
    AccountKey, BackupStep, EnrollmentOutcome, HostAcceptPair, HostClock, PublicKeyData,
    SignRequest,
};
use support::*;

const WALL: u64 = 1_793_264_001_000;

fn clock() -> HostClock {
    HostClock {
        wall_ms: WALL,
        mono_ms: 1_000,
        boot_id: "boot-1".into(),
    }
}

fn json(v: &Vectors, labels: &[&str]) -> Vec<String> {
    labels
        .iter()
        .map(|l| v.object(l).to_json().to_string())
        .collect()
}

const L: [&str; 6] = ["E1", "E2", "E3", "E4", "E5", "E6"];

struct BookKeys(Book);

fn failed(e: impl std::fmt::Display) -> ProviderError {
    ProviderError::Failed {
        reason: e.to_string(),
    }
}

impl AppKeyProvider for BookKeys {
    fn public_key(&self, key_id: String) -> Result<PublicKeyData, ProviderError> {
        let k = self
            .0
            .provider
            .public_key(&KeyId::new(key_id))
            .map_err(failed)?;
        Ok((&k).into())
    }
    fn sign(&self, request: SignRequest) -> Result<Vec<u8>, ProviderError> {
        let fields = atem_client::encoding::dec(&request.input).map_err(failed)?;
        assert_eq!(fields[0], b"atem-membership-entry-v1");
        let input =
            atem_client::SigningInput::new(atem_client::SignLabel::MembershipEntry, fields[1]);
        self.0
            .provider
            .sign(&KeyId::new(request.key_id), &input)
            .map_err(failed)
    }
    fn x25519(&self, _: String, _: Vec<u8>) -> Result<Vec<u8>, ProviderError> {
        Err(ProviderError::UnknownKey)
    }
    fn hpke_open(
        &self,
        _: String,
        _: Vec<u8>,
        _: Vec<u8>,
        _: Vec<u8>,
        _: Vec<u8>,
    ) -> Result<Vec<u8>, ProviderError> {
        Err(ProviderError::UnknownKey)
    }
}

fn code(e: AtemError) -> String {
    e.code()
}

#[test]
fn a_k_backup_resumes_mid_flight_and_signs_the_same_body() {
    let v = Vectors::load();
    let book = Book::load();
    let kit = book.kit("recovery");
    let keys: Arc<dyn AppKeyProvider> = Arc::new(BookKeys(Book::load()));
    let log = MembershipLog::verify(
        ACCOUNT.into(),
        genesis_hash().to_hex(),
        json(&v, &L),
        clock(),
    )
    .unwrap();
    let kit_pub: PublicKeyData = (&kit.recovery_key()).into();
    let writer = KBackupWriter::start(
        log.clone(),
        vec!["b982533d".into()],
        kit_pub.clone(),
        "dev-mac".into(),
    )
    .unwrap();
    let saved_seal = writer.prepared_json().expect("the allocation is durable");
    let envelope = seal_k_backup(
        ACCOUNT.into(),
        genesis_hash().to_hex(),
        1,
        kit_pub.clone(),
        vec![AccountKey {
            kid: "b982533d".into(),
            k: vec![7u8; 32],
        }],
    )
    .unwrap();
    let BackupStep::Sign { body_json } = writer.sealed(log.clone(), envelope, WALL).unwrap() else {
        panic!("sign next");
    };
    // The app persists before signing.
    let saved = writer.prepared_json().unwrap();

    // While this body is prepared, the device starts nothing else.
    let other = KBackupWriter::start(
        log.clone(),
        vec!["b982533d".into()],
        kit_pub.clone(),
        "dev-mac".into(),
    )
    .unwrap();
    let envelope2 = seal_k_backup(
        ACCOUNT.into(),
        genesis_hash().to_hex(),
        1,
        kit_pub.clone(),
        vec![AccountKey {
            kid: "b982533d".into(),
            k: vec![7u8; 32],
        }],
    )
    .unwrap();
    assert_eq!(
        code(other.sealed(log.clone(), envelope2, WALL + 1).unwrap_err()),
        "outstanding"
    );
    let body = log
        .draft_entry(
            "dev-mac".into(),
            WALL,
            r#"{"action":"remove","device_id":"svc-discord"}"#.into(),
        )
        .unwrap();
    assert_eq!(
        code(
            EntryPublisher::new()
                .prepare(log.clone(), body)
                .unwrap_err()
        ),
        "outstanding"
    );
    assert_eq!(
        code(KBackupWriter::resume(saved.clone()).err().unwrap()),
        "outstanding"
    );

    // The app crashes before the signature (the writer is gone).
    drop(writer);
    drop(other);
    let resumed = KBackupWriter::resume(saved.clone()).unwrap();
    assert_eq!(
        resumed.step(),
        BackupStep::Sign {
            body_json: body_json.clone()
        },
        "the same body"
    );
    let BackupStep::Put { bytes, .. } = resumed.sign(keys.clone(), "dev-mac/auth".into()).unwrap()
    else {
        panic!("put next");
    };
    let after_sign = resumed.prepared_json().unwrap();
    let signed_hash = |state: &str| {
        let v: serde_json::Value = serde_json::from_str(state).unwrap();
        atem_client::SignedObject::parse(v["writer"]["prepared"]["signed"].to_string().as_bytes())
            .unwrap()
            .entry_hash()
            .unwrap()
    };
    let hash = signed_hash(&after_sign);

    // A second crash before the upload's answer: the same bytes and entry.
    drop(resumed);
    let resumed = KBackupWriter::resume(after_sign.clone()).unwrap();
    assert_eq!(
        resumed.restart().unwrap(),
        BackupStep::Put {
            blob_version: 1,
            bytes: bytes.clone()
        }
    );
    let BackupStep::Append { request } = resumed.put_reply(log.clone(), None).unwrap() else {
        panic!("append next");
    };
    assert_eq!(
        request.entry_hash,
        hash.to_hex(),
        "no sibling: the signed entry is resent"
    );
    let before_append = resumed.prepared_json().unwrap();
    drop(resumed);
    let resumed = KBackupWriter::resume(before_append).unwrap();
    // §R9.5 step 6: the upload is resent first, then the same entry.
    assert_eq!(
        resumed.step(),
        BackupStep::Put {
            blob_version: 1,
            bytes: bytes.clone()
        }
    );
    assert_eq!(
        resumed.put_reply(log.clone(), None).unwrap(),
        BackupStep::Append { request }
    );
    assert_eq!(
        resumed.append_stored(log.clone(), clock(), WALL).unwrap(),
        BackupStep::Done { committed: 1 }
    );
    assert_eq!(resumed.prepared_json(), None, "nothing in flight");
    assert_eq!(log.k_backup().unwrap().blob_version, 1);
    // The allocation-only state resumes too.
    drop(resumed);
    assert!(matches!(
        KBackupWriter::resume(saved_seal).unwrap().step(),
        BackupStep::Seal { blob_version: 1 }
    ));
}

#[test]
fn a_publisher_resumes_and_tampered_state_is_refused() {
    let v = Vectors::load();
    let keys: Arc<dyn AppKeyProvider> = Arc::new(BookKeys(Book::load()));
    let log = MembershipLog::verify(
        ACCOUNT.into(),
        genesis_hash().to_hex(),
        json(&v, &L),
        clock(),
    )
    .unwrap();
    let body = log
        .draft_entry(
            "dev-phone".into(),
            WALL,
            r#"{"action":"remove","device_id":"svc-discord"}"#.into(),
        )
        .unwrap();
    let p = EntryPublisher::new();
    p.prepare(log.clone(), body.clone()).unwrap();
    let saved = p.prepared_json().unwrap();
    drop(p);
    let resumed = EntryPublisher::resume(saved.clone()).unwrap();
    let request = resumed
        .sign(keys.clone(), "dev-phone/auth".into(), None)
        .unwrap();
    let signed = resumed.prepared_json().unwrap();
    drop(resumed);
    // A crash after signing: the same entry is resent, not re-signed.
    let resumed = EntryPublisher::resume(signed.clone()).unwrap();
    assert_eq!(resumed.outstanding().unwrap(), request);
    drop(resumed);
    // Tampered state: a body the signed entry isn't, or one the verifier's
    // schema refuses.
    let mut tampered: serde_json::Value = serde_json::from_str(&signed).unwrap();
    tampered["body"]["device_id"] = serde_json::json!("dev-ipad");
    assert!(EntryPublisher::resume(tampered.to_string()).is_err());
    let mut bad: serde_json::Value = serde_json::from_str(&saved).unwrap();
    bad["body"]["action"] = serde_json::json!("unknown");
    assert_eq!(
        code(EntryPublisher::resume(bad.to_string()).err().unwrap()),
        "membership_invalid"
    );
    // Values outside the canonical domain are typed errors, not panics.
    assert_eq!(
        code(
            log.draft_entry(
                "dev-phone".into(),
                1 << 53,
                r#"{"action":"remove","device_id":"x"}"#.into()
            )
            .unwrap_err()
        ),
        "not_canonical"
    );
}

#[test]
fn a_restore_enrollment_resumes_after_a_restart() {
    let v = Vectors::load();
    let rec = load("r9-vectors-recovery");
    let hs = load("r9-vectors-channel-handshake");
    let r = hex(&rec["R_hex"]);
    let tag = hex(&rec["kit"]["kit_tag_hex"]);
    let mut entries = json(&v, &L);
    entries.extend(json(&v, &["KB7"]));
    let accept = vec![HostAcceptPair {
        init_json: hs["init"].to_string(),
        accept_json: hs["accept"].to_string(),
    }];
    let member = v.vector("R7")["entry"]["body"]["member"].to_string();
    let session = RestoreSession::read(
        r.clone(),
        ACCOUNT.into(),
        genesis_hash().to_hex(),
        tag.clone(),
    )
    .unwrap();
    session
        .attempt(
            entries.clone(),
            rec["k_backup"]["wire"].to_string(),
            accept.clone(),
            clock(),
        )
        .unwrap();
    let request = session.enroll(member.clone(), WALL).unwrap();
    let saved = session.prepared_json().unwrap();
    drop(session);

    let resumed =
        RestoreSession::resume(r, ACCOUNT.into(), genesis_hash().to_hex(), tag, saved).unwrap();
    assert_eq!(
        resumed.outstanding().unwrap(),
        request,
        "the same recovery_add"
    );
    resumed
        .attempt(
            entries,
            rec["k_backup"]["wire"].to_string(),
            accept,
            clock(),
        )
        .unwrap();
    assert_eq!(
        code(resumed.enroll(member, WALL + 1).unwrap_err()),
        "outstanding",
        "no second body while one is outstanding"
    );
    let EnrollmentOutcome::Published { head } = resumed.append_stored(clock()).unwrap() else {
        panic!("published");
    };
    assert_eq!(head.hash, request.entry_hash);
    assert_eq!(resumed.prepared_json(), None);
}

fn hex(v: &serde_json::Value) -> Vec<u8> {
    let s = v.as_str().unwrap();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// The device's claim holds for a writer resumed before any body was
/// prepared (the review's probe): start → save → drop → resume → sealed,
/// then a publisher for the same device is refused.
#[test]
fn a_writer_resumed_at_seal_claims_the_device_once_sealed() {
    let v = Vectors::load();
    let book = Book::load();
    let kit = book.kit("recovery");
    let kit_pub: PublicKeyData = (&kit.recovery_key()).into();
    let log = MembershipLog::verify(
        ACCOUNT.into(),
        genesis_hash().to_hex(),
        json(&v, &L),
        clock(),
    )
    .unwrap();
    let writer = KBackupWriter::start(
        log.clone(),
        vec!["1f2e3d4c".into()],
        kit_pub.clone(),
        "dev-ipad".into(),
    )
    .unwrap();
    let saved = writer.prepared_json().unwrap();
    let saved_value: serde_json::Value = serde_json::from_str(&saved).unwrap();
    assert_eq!(saved_value["account_id"], ACCOUNT);
    drop(writer);
    let resumed = KBackupWriter::resume(saved).unwrap();
    let envelope = seal_k_backup(
        ACCOUNT.into(),
        genesis_hash().to_hex(),
        1,
        kit_pub,
        vec![AccountKey {
            kid: "1f2e3d4c".into(),
            k: vec![9u8; 32],
        }],
    )
    .unwrap();
    assert!(matches!(
        resumed.sealed(log.clone(), envelope, WALL).unwrap(),
        BackupStep::Sign { .. }
    ));
    // dev-ipad is removed at E6, but the claim is about the device's one
    // outstanding body, whatever the verifier later says of it.
    let body = serde_json::json!({
        "type": "atem-membership-entry", "v": 1, "account_id": ACCOUNT,
        "genesis_hash": genesis_hash().to_hex(), "seq": 7,
        "prev_hash": log.head().hash, "action": "remove", "device_id": "svc-discord",
        "signer": "dev-ipad", "signed_at": WALL,
    });
    assert_eq!(
        code(
            EntryPublisher::new()
                .prepare(log.clone(), body.to_string())
                .unwrap_err()
        ),
        "outstanding"
    );
    drop(resumed);
    assert!(EntryPublisher::new().prepare(log, body.to_string()).is_ok());
}

/// Saved state whose parts don't belong together is refused on resume.
#[test]
fn resumed_state_must_hold_together() {
    let v = Vectors::load();
    let rec = load("r9-vectors-recovery");
    let hs = load("r9-vectors-channel-handshake");
    let r = hex(&rec["R_hex"]);
    let tag = hex(&rec["kit"]["kit_tag_hex"]);
    let log = MembershipLog::verify(
        ACCOUNT.into(),
        genesis_hash().to_hex(),
        json(&v, &L),
        clock(),
    )
    .unwrap();
    // A restore resumed with a body that isn't the kit's recovery_add.
    let body = log
        .draft_entry(
            "dev-evil".into(),
            WALL,
            r#"{"action":"remove","device_id":"svc-discord"}"#.into(),
        )
        .unwrap();
    let p = EntryPublisher::new();
    p.prepare(log.clone(), body).unwrap();
    let not_recovery = p.prepared_json().unwrap();
    drop(p);
    assert!(
        RestoreSession::resume(
            r.clone(),
            ACCOUNT.into(),
            genesis_hash().to_hex(),
            tag.clone(),
            not_recovery
        )
        .is_err()
    );
    // A writer state of another account than its envelope's.
    let kit = Book::load().kit("recovery");
    let kit_pub: PublicKeyData = (&kit.recovery_key()).into();
    let w = KBackupWriter::start(
        log.clone(),
        vec!["b982533d".into()],
        kit_pub.clone(),
        "dev-other".into(),
    )
    .unwrap();
    let envelope = seal_k_backup(
        ACCOUNT.into(),
        genesis_hash().to_hex(),
        1,
        kit_pub,
        vec![AccountKey {
            kid: "b982533d".into(),
            k: vec![7u8; 32],
        }],
    )
    .unwrap();
    w.sealed(log.clone(), envelope, WALL).unwrap();
    let mut saved: serde_json::Value = serde_json::from_str(&w.prepared_json().unwrap()).unwrap();
    drop(w);
    saved["account_id"] = serde_json::json!("acct-other");
    assert!(KBackupWriter::resume(saved.to_string()).is_err());
    let mut wrong_signer = saved.clone();
    wrong_signer["account_id"] = serde_json::json!(ACCOUNT);
    wrong_signer["writer"]["job"]["signer"] = serde_json::json!("dev-evil");
    assert!(KBackupWriter::resume(wrong_signer.to_string()).is_err());
    let _ = hs;
}
