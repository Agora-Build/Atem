//! A K-backup writer and an enrollment survive a restart in their durable
//! form (§R9.5 "Writing a backup" step 2, §R9.4 rules 1 and 4): the resumed
//! writer stands at the same step and signs the same body, never a sibling.
mod support;

use atem_client::backup::{BackupKey, KBackupEnvelope};
use atem_client::backup_writer::{BackupJob, BackupWriter, PutReply, Step};
use atem_client::membership::Membership;
use atem_client::membership::publish::{AppendReply, Prepared};
use support::*;
use zeroize::Zeroizing;

fn log_l(v: &Vectors, clock: &Clock) -> Membership {
    Membership::verify_chain(
        ACCOUNT,
        &genesis_hash(),
        &v.entries(&["E1", "E2", "E3", "E4", "E5", "E6"]),
        &clock.now,
    )
    .unwrap()
    .membership
}

fn keys() -> Vec<BackupKey> {
    vec![BackupKey {
        kid: "b982533d".into(),
        k: Zeroizing::new([7u8; 32]),
    }]
}

fn roundtrip(writer: &BackupWriter) -> (BackupWriter, Step) {
    let saved = writer.to_json().expect("in flight");
    // Through bytes, as an app stores it.
    let text = saved.to_string();
    BackupWriter::from_json(&serde_json::from_str(&text).unwrap()).unwrap()
}

#[test]
fn a_restarted_writer_signs_the_same_body_and_resends_the_same_bytes() {
    let v = Vectors::load();
    let book = Book::load();
    let clock = Clock::at(1_793_264_001_000);
    let mut log = log_l(&v, &clock);
    let kit = book.kit("recovery");
    let job = BackupJob {
        kids: vec!["b982533d".into()],
        kit: kit.recovery_key(),
        signer: "dev-mac".into(),
    };
    let (mut writer, step) = BackupWriter::start(&log, job);
    assert_eq!(step, Step::Seal { blob_version: 1 });
    let (resumed, again) = roundtrip(&writer);
    assert_eq!(again, step, "allocation survives");
    drop(resumed);

    let envelope =
        KBackupEnvelope::seal(ACCOUNT, genesis_hash(), 1, &kit.recovery_key(), &keys()).unwrap();
    let Step::Sign { body } = writer.sealed(&log, envelope.clone(), 1_792_400_009_000) else {
        panic!("sign next");
    };
    // Crash after storing the body, before (or while) signing.
    let (mut resumed, step) = roundtrip(&writer);
    assert_eq!(step, Step::Sign { body: body.clone() }, "the same body");
    let a = writer.sign(&book.provider, &book.auth("dev-mac"));
    let b = resumed.sign(&book.provider, &book.auth("dev-mac"));
    let (Step::Put { bytes: ba, .. }, Step::Put { bytes: bb, .. }) = (&a, &b) else {
        panic!("put next: {a:?} {b:?}");
    };
    assert_eq!(ba, bb, "the same envelope bytes");
    assert_eq!(
        writer.prepared().unwrap().signed.as_ref().unwrap().hash(),
        resumed.prepared().unwrap().signed.as_ref().unwrap().hash(),
        "the same entry_hash: no sibling"
    );

    // Crash after the upload's 200, before the append's answer.
    let step = resumed.put_reply(&log, PutReply::Stored);
    let Step::Append { entry, expected } = step else {
        panic!("append next");
    };
    let (mut again, step) = roundtrip(&resumed);
    // §R9.5 step 6: the upload first (the same bytes), then the same entry.
    assert_eq!(
        step,
        Step::Put {
            blob_version: 1,
            bytes: bb.clone()
        },
        "the upload is resent first"
    );
    assert_eq!(
        again.put_reply(&log, PutReply::Stored),
        Step::Append {
            entry: entry.clone(),
            expected
        },
        "the same signed entry is resent"
    );
    assert_eq!(
        again.append_reply(&mut log, AppendReply::Stored, &clock.now, 1),
        Step::Done { committed: 1 }
    );
    assert!(again.to_json().is_none(), "nothing in flight once done");
}

#[test]
fn damaged_or_inconsistent_writer_state_is_refused() {
    let v = Vectors::load();
    let book = Book::load();
    let clock = Clock::at(1_793_264_001_000);
    let log = log_l(&v, &clock);
    let kit = book.kit("recovery");
    let job = BackupJob {
        kids: vec!["b982533d".into()],
        kit: kit.recovery_key(),
        signer: "dev-mac".into(),
    };
    let (mut writer, _) = BackupWriter::start(&log, job);
    let envelope =
        KBackupEnvelope::seal(ACCOUNT, genesis_hash(), 1, &kit.recovery_key(), &keys()).unwrap();
    writer.sealed(&log, envelope, 1);
    writer.sign(&book.provider, &book.auth("dev-mac"));
    let saved = writer.to_json().unwrap();
    let mut no_envelope = saved.clone();
    no_envelope["envelope"] = serde_json::Value::Null;
    assert!(BackupWriter::from_json(&no_envelope).is_err());
    let mut other_body = saved.clone();
    other_body["prepared"]["body"]["signed_at"] = serde_json::json!(2);
    assert!(
        BackupWriter::from_json(&other_body).is_err(),
        "signed entry != body"
    );
    // Parts that don't belong together are refused.
    let mut other_signer = saved.clone();
    other_signer["job"]["signer"] = serde_json::json!("dev-phone");
    assert!(
        BackupWriter::from_json(&other_signer).is_err(),
        "signer != job's"
    );
    let mut other_version = saved.clone();
    other_version["envelope"]["blob_version"] = serde_json::json!(2);
    assert!(
        BackupWriter::from_json(&other_version).is_err(),
        "body names another envelope"
    );
    let mut unsigned_upload = saved.clone();
    unsigned_upload["prepared"]["signed"] = serde_json::Value::Null;
    assert_eq!(unsigned_upload["phase"]["name"], "upload");
    assert!(
        BackupWriter::from_json(&unsigned_upload).is_err(),
        "an upload needs its entry"
    );
    let mut extra = saved.clone();
    extra["x"] = serde_json::json!(1);
    assert!(BackupWriter::from_json(&extra).is_err());
    // A prepared entry round-trips on its own too.
    let prepared = writer.prepared().unwrap().clone();
    assert_eq!(Prepared::from_json(&prepared.to_json()).unwrap(), prepared);
}
