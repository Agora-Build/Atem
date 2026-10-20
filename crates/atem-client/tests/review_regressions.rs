//! Regression tests for the Task 2 review (fix round 1), through the public
//! API: each builds a log with its own software keys and kits and drives the
//! verifier, publisher, backup writer or restore the way a host or a device
//! does.
mod support;

use atem_client::backup::{BackupKey, KBackupEnvelope};
use atem_client::backup_writer::{BackupError, BackupJob, BackupWriter, Step};
use atem_client::encoding::Hash32;
use atem_client::kit::RecoveryKit;
use atem_client::membership::publish::{AppendReply, Published, Publisher};
use atem_client::membership::{
    Action, Admission, Conflict, Entry, EvidenceReason, Head, HostNow, HostRecord, Invalid,
    KBackupRecord, KitMode, Member, MemberKind, Membership, RECOVERY_SIGNER, RECOVERY_WAIT_MS,
    Role, Stop, draft_on, sign_entry, sign_entry_cosigned,
};
use atem_client::restore::{HostHead, restore};
use atem_client::{Alg, KeyId, SignedObject, SoftwareKeys};
use support::{FakeRelay, strict};
use zeroize::Zeroizing;

const ACCOUNT: &str = "acct-review";
const ALL: [Role; 3] = [Role::Control, Role::Manage, Role::View];

fn now(wall_ms: u64) -> HostNow {
    HostNow {
        wall_ms,
        mono_ms: wall_ms,
        boot_id: "b".into(),
    }
}

fn auth() -> KeyId {
    KeyId::new("auth")
}

/// A device with its own P-256 auth key and X25519 enc key.
fn device(id: &str, roles: &[Role]) -> (SoftwareKeys, Member) {
    let mut keys = SoftwareKeys::new();
    let auth_key = keys.generate(auth(), Alg::P256).unwrap();
    let enc_key = keys.generate(KeyId::new("enc"), Alg::X25519).unwrap();
    let member = Member {
        device_id: id.into(),
        auth_key,
        kind: MemberKind::Native {
            enc_key,
            roles: roles.iter().copied().collect(),
        },
    };
    (keys, member)
}

fn kit(seed: u8) -> RecoveryKit {
    RecoveryKit::make(&[seed; 32], ACCOUNT, Hash32([0; 32]))
}

/// A log on one verifier: the Mac's genesis naming `kit`.
fn genesis(kit: &RecoveryKit) -> (Membership, SoftwareKeys) {
    let (keys, member) = device("dev-mac", &ALL);
    let body = draft_on(
        ACCOUNT,
        &Hash32([0; 32]),
        1,
        &Hash32([0; 32]),
        "dev-mac",
        0,
        &Action::Genesis {
            member,
            recovery_key: kit.recovery_key(),
        },
    );
    let entry = sign_entry(&keys, &auth(), body).unwrap();
    let m = Membership::from_genesis(ACCOUNT, &entry.hash(), entry).unwrap();
    (m, keys)
}

/// Signs `action` as `signer` on `m`'s head and applies it.
fn apply(
    m: &mut Membership,
    signer: &str,
    keys: &dyn atem_client::KeyProvider,
    key: &KeyId,
    action: Action,
    at: u64,
) -> Entry {
    let body = m.draft(signer, at, &action);
    let entry = sign_entry(keys, key, body).unwrap();
    let eval = m.evaluate_objects(&[entry.object().clone()], &now(at));
    assert_eq!(eval.stop, None, "{action:?}");
    *m = eval.next;
    entry
}

fn conflict_of(m: &Membership, entry: &Entry, at: u64) -> Option<Stop> {
    m.evaluate_objects(&[entry.object().clone()], &now(at)).stop
}

/// Critical 1: after the host applied a veto of a pending `recovery_add`, an
/// entry at the veto's seq naming the subject as `signer` freezes only if
/// the subject really signed it.
#[test]
fn a_forged_subject_entry_after_a_veto_does_not_freeze() {
    let kit1 = kit(1);
    let (mut host, mac_keys) = genesis(&kit1);
    let (phone_keys, phone) = device("dev-phone", &ALL);
    apply(
        &mut host,
        "dev-mac",
        &mac_keys,
        &auth(),
        Action::Add { member: phone },
        1,
    );
    let (newmac_keys, newmac) = device("dev-newmac", &ALL);
    let recovery = apply(
        &mut host,
        RECOVERY_SIGNER,
        &kit1,
        &RecoveryKit::sign_id(),
        Action::RecoveryAdd { member: newmac },
        2,
    );
    let before_veto = host.clone();
    apply(
        &mut host,
        "dev-phone",
        &phone_keys,
        &auth(),
        Action::RecoveryVeto {
            target: recovery.hash(),
        },
        3,
    );
    // The same body, at the veto's seq, chaining from the recovery_add.
    let body = before_veto.draft(
        "dev-newmac",
        4,
        &Action::Remove {
            device_id: "dev-phone".into(),
        },
    );

    // (a) Signed by an unrelated key: not the subject's entry. Invalid
    // against C[..s-1], so ignored; no freeze.
    let (stranger_keys, _) = device("dev-x", &ALL);
    let forged = sign_entry(&stranger_keys, &auth(), body.clone()).unwrap();
    assert_eq!(
        conflict_of(&host, &forged, 5),
        Some(Stop::Conflict {
            index: 0,
            outcome: Conflict::Ignored(EvidenceReason::Invalid)
        })
    );
    let eval = host.evaluate_objects(&[forged.object().clone()], &now(5));
    assert!(eval.next.frozen().is_none());
    assert!(matches!(
        eval.admission("dev-phone", false, &now(5)),
        Admission::Member { .. }
    ));

    // (b) Genuinely signed by the subject: the relay ordered the subject's
    // entry ahead of a veto this host applied in time. Freeze.
    let genuine = sign_entry(&newmac_keys, &auth(), body).unwrap();
    assert_eq!(
        conflict_of(&host, &genuine, 5),
        Some(Stop::Conflict {
            index: 0,
            outcome: Conflict::Freeze
        })
    );
}

/// Important 2: a conflict signed by the recovery key freezes even when that
/// key was replaced later (it was the recovery key at that position; the
/// recovery key is never "removed", §R9.4 row 6, §R9.5).
#[test]
fn a_conflict_by_a_since_replaced_recovery_key_freezes() {
    let (kit1, kit2) = (kit(1), kit(2));
    let (mut host, mac_keys) = genesis(&kit1);
    let (phone_keys, phone) = device("dev-phone", &ALL);
    apply(
        &mut host,
        "dev-mac",
        &mac_keys,
        &auth(),
        Action::Add { member: phone },
        1,
    );
    let before = host.clone();
    let (_, ipad) = device("dev-ipad", &ALL);
    apply(
        &mut host,
        "dev-phone",
        &phone_keys,
        &auth(),
        Action::Add { member: ipad },
        2,
    );
    // The kit is replaced with the current kit's co-signature.
    let body = host.draft(
        "dev-phone",
        3,
        &Action::SetRecoveryKey {
            recovery_key: kit2.recovery_key(),
            kit: KitMode::Current,
        },
    );
    let replace =
        sign_entry_cosigned(&phone_keys, &auth(), &kit1, &RecoveryKit::sign_id(), body).unwrap();
    let eval = host.evaluate_objects(&[replace.object().clone()], &now(3));
    assert_eq!(eval.stop, None);
    host = eval.next;
    assert_eq!(*host.recovery_key(), kit2.recovery_key());
    // A recovery_add by the old kit at seq 3, chaining from seq 2.
    let (_, thief) = device("dev-thief", &ALL);
    let body = before.draft(RECOVERY_SIGNER, 4, &Action::RecoveryAdd { member: thief });
    let theirs = sign_entry(&kit1, &RecoveryKit::sign_id(), body).unwrap();
    assert_eq!(
        conflict_of(&host, &theirs, 5),
        Some(Stop::Conflict {
            index: 0,
            outcome: Conflict::Freeze
        })
    );
}

fn object_list(m: &Membership, after: u64) -> Vec<SignedObject> {
    m.entries()[after as usize..]
        .iter()
        .map(|e| e.object().clone())
        .collect()
}

/// Minor 3: a `409` that doesn't move the client's verified log to the
/// reported head never becomes `LostRace` (no rebuild loop on an unchanged
/// head); a window that doesn't chain is a divergence; a window beyond a
/// pending entry waits; an own entry the client can't apply yet is still
/// committed on `200`.
#[test]
fn the_publisher_never_rebuilds_on_an_unchanged_head() {
    let kit1 = kit(1);
    let (mut relay_log, mac_keys) = genesis(&kit1);
    let (phone_keys, phone) = device("dev-phone", &ALL);
    apply(
        &mut relay_log,
        "dev-mac",
        &mac_keys,
        &auth(),
        Action::Add { member: phone },
        1,
    );
    let client = relay_log.clone();
    let (_, tv) = device("dev-tv", &[Role::View]);
    let won = apply(
        &mut relay_log,
        "dev-mac",
        &mac_keys,
        &auth(),
        Action::Add { member: tv },
        2,
    );
    let add = |m: &Membership, id: &str| {
        let (_, member) = device(id, &[Role::View]);
        m.draft("dev-phone", 3, &Action::Add { member })
    };
    let prepared = |client: &Membership| {
        let mut p = Publisher::new();
        p.prepare(client, add(client, "dev-watch")).unwrap();
        p.sign(&phone_keys, &auth(), None).unwrap();
        p
    };

    // An empty 409 claiming a newer head: inconsistent, not a lost race.
    let mut p = prepared(&client);
    let mut log = client.clone();
    let reply = AppendReply::Conflict {
        head: relay_log.head(),
        entries: vec![],
        more: false,
    };
    assert!(matches!(
        p.reply(reply, &mut log, &now(4)).unwrap(),
        Published::RelayInconsistent { .. }
    ));
    assert_eq!(log.head(), client.head());

    // The honest 409: the winner, and the head it reaches.
    let mut p = prepared(&client);
    let mut log = client.clone();
    let reply = AppendReply::Conflict {
        head: relay_log.head(),
        entries: vec![won.object().clone()],
        more: false,
    };
    assert!(matches!(
        p.reply(reply, &mut log, &now(4)).unwrap(),
        Published::LostRace { .. }
    ));
    assert_eq!(log.head(), relay_log.head());

    // A window whose entry at a seq we hold doesn't chain from ours: two
    // histories.
    let mut other = client.clone();
    let (_, x) = device("dev-x", &[Role::View]);
    apply(
        &mut other,
        "dev-mac",
        &mac_keys,
        &auth(),
        Action::Add { member: x },
        2,
    );
    let (_, y) = device("dev-y", &[Role::View]);
    let y_entry = apply(
        &mut other,
        "dev-mac",
        &mac_keys,
        &auth(),
        Action::Add { member: y },
        2,
    );
    let mut ahead = client.clone();
    let eval = ahead.evaluate_objects(&[won.object().clone()], &now(4));
    ahead = eval.next;
    let (_, v) = device("dev-v", &[Role::View]);
    apply(
        &mut ahead,
        "dev-mac",
        &mac_keys,
        &auth(),
        Action::Add { member: v },
        3,
    );
    let mut p = prepared(&ahead);
    let mut log = ahead.clone();
    let reply = AppendReply::Conflict {
        head: other.head(),
        entries: vec![y_entry.object().clone()],
        more: false,
    };
    assert!(matches!(
        p.reply(reply, &mut log, &now(4)).unwrap(),
        Published::Diverged { .. }
    ));

    // A window beyond an entry pending on this device's clock: wait.
    let mut pending_log = relay_log.clone();
    let (newmac_keys, newmac) = device("dev-newmac", &ALL);
    let recovery = apply(
        &mut pending_log,
        RECOVERY_SIGNER,
        &kit1,
        &RecoveryKit::sign_id(),
        Action::RecoveryAdd { member: newmac },
        5,
    );
    let mut client = pending_log.clone();
    let by_subject = {
        let (_, z) = device("dev-z", &[Role::View]);
        let body = pending_log.draft("dev-newmac", 6, &Action::Add { member: z });
        sign_entry(&newmac_keys, &auth(), body).unwrap()
    };
    let mut p = Publisher::new();
    p.prepare(&client, add(&client, "dev-watch")).unwrap();
    p.sign(&phone_keys, &auth(), None).unwrap();
    let reply = AppendReply::Conflict {
        head: Head {
            seq: by_subject.seq,
            hash: by_subject.hash(),
        },
        entries: vec![by_subject.object().clone()],
        more: false,
    };
    assert!(matches!(
        p.reply(reply, &mut client, &now(7)).unwrap(),
        Published::Waiting { on, .. } if on == recovery.hash()
    ));
    assert_eq!(
        client.head(),
        pending_log.head(),
        "nothing applied beyond the pending entry"
    );

    // The subject's own entry, stored by the relay, is committed even though
    // its own log defers it (not "diverged").
    let mut p = Publisher::new();
    let mut subject_log = pending_log.clone();
    let (_, w) = device("dev-w", &[Role::View]);
    p.prepare(
        &subject_log,
        subject_log.draft("dev-newmac", 8, &Action::Add { member: w }),
    )
    .unwrap();
    p.sign(&newmac_keys, &auth(), None).unwrap();
    assert!(matches!(
        p.reply(AppendReply::Stored, &mut subject_log, &now(8)).unwrap(),
        Published::StoredPending { on, .. } if on == recovery.hash()
    ));
}

/// Minor 3 (fake relay): a `409` holds at most 64 entries / 256 KiB, and
/// says `more`.
#[test]
fn the_fake_relay_bounds_its_replies() {
    let kit1 = kit(1);
    let (mut m, mac_keys) = genesis(&kit1);
    for i in 0..70 {
        let (_, member) = device(&format!("dev-{i}"), &[Role::View]);
        apply(
            &mut m,
            "dev-mac",
            &mac_keys,
            &auth(),
            Action::Add { member },
            i,
        );
    }
    let relay = FakeRelay::with_log(object_list(&m, 0));
    let (page, more) = relay.after_page(1);
    assert_eq!(page.len(), 64);
    assert!(more);
    let (rest, more) = relay.after_page(65);
    assert_eq!(rest.len(), 6);
    assert!(!more);
}

/// Minor 4: a restore reading a log with a past recovery that took effect
/// by its wait, followed by entries its subject signed, restores fully once
/// a host-signed head covers them (no `log_behind_host`).
#[test]
fn a_restore_reads_through_a_past_recovery() {
    let kit1 = kit(1);
    let (mut log, mac_keys) = genesis(&kit1);
    let genesis_hash = log.genesis_hash();
    let kit1 = RecoveryKit::make(&[1; 32], ACCOUNT, genesis_hash);
    let mut host_keys = SoftwareKeys::new();
    let host_key = host_keys.generate(KeyId::new("h"), Alg::Ed25519).unwrap();
    apply(
        &mut log,
        "dev-mac",
        &mac_keys,
        &auth(),
        Action::AddHost {
            host: HostRecord {
                host_id: "host-a".into(),
                host_trust_gen: 1,
                host_key,
            },
        },
        1,
    );
    let (newmac_keys, newmac) = device("dev-newmac", &ALL);
    apply(
        &mut log,
        RECOVERY_SIGNER,
        &kit1,
        &RecoveryKit::sign_id(),
        Action::RecoveryAdd { member: newmac },
        2,
    );
    // The wait ended on the host; the recovered Mac then backs up K.
    log.advance(&now(2 + RECOVERY_WAIT_MS));
    let keys = vec![BackupKey {
        kid: "k1".into(),
        k: Zeroizing::new([7; 32]),
    }];
    let env = KBackupEnvelope::seal(ACCOUNT, genesis_hash, 1, &kit1.recovery_key(), &keys).unwrap();
    apply(
        &mut log,
        "dev-newmac",
        &newmac_keys,
        &auth(),
        Action::KBackup(KBackupRecord {
            blob_version: 1,
            kids: vec!["k1".into()],
            recovery_key: kit1.recovery_key(),
            backup_hash: env.backup_hash(),
        }),
        3 + RECOVERY_WAIT_MS,
    );
    let entries: Vec<Entry> = log.entries().to_vec();
    let head = HostHead {
        host_id: "host-a".into(),
        head: log.head(),
    };
    let fresh = now(10 + RECOVERY_WAIT_MS);
    // A fresh verifier alone stops at the subject's entry.
    let alone = Membership::verify_chain(ACCOUNT, &genesis_hash, &entries, &fresh).unwrap();
    assert!(alone.deferred.is_some());
    // With the host-signed head the restore reads through it.
    let restored = restore(&kit1, &entries, env.jcs().as_bytes(), &[head], &fresh).unwrap();
    assert_eq!(restored.head, log.head());
    assert_eq!(*restored.keys[0].k, [7; 32]);
    // A head before the subject's entry confirms nothing beyond it.
    let early = HostHead {
        host_id: "host-a".into(),
        head: Head {
            seq: 3,
            hash: entries[2].hash(),
        },
    };
    assert_eq!(
        restore(&kit1, &entries, env.jcs().as_bytes(), &[early], &fresh)
            .err()
            .unwrap()
            .code(),
        "no_backup"
    );
}

/// Minor 5: `recovery_pending` is answered for a device added only by the
/// verified, deferred entry; an unverified add after it proves nothing.
#[test]
fn only_the_verified_deferred_entry_can_make_a_device_pending() {
    let kit1 = kit(1);
    let (mut host, _mac_keys) = genesis(&kit1);
    let (newmac_keys, newmac) = device("dev-newmac", &ALL);
    let recovery = apply(
        &mut host,
        RECOVERY_SIGNER,
        &kit1,
        &RecoveryKit::sign_id(),
        Action::RecoveryAdd { member: newmac },
        1,
    );
    let (_, tv) = device("dev-tv", &[Role::View]);
    let body = host.draft("dev-newmac", 2, &Action::Add { member: tv });
    let deferred = sign_entry(&newmac_keys, &auth(), body).unwrap();
    // An entry after it, chaining from it, signed by someone else.
    let (stranger_keys, stranger) = device("dev-stranger", &[Role::View]);
    let body = draft_on(
        ACCOUNT,
        &host.genesis_hash(),
        deferred.seq + 1,
        &deferred.hash(),
        "dev-newmac",
        3,
        &Action::Add { member: stranger },
    );
    let forged = sign_entry(&stranger_keys, &auth(), body).unwrap();
    let carriage = [deferred.object().clone(), forged.object().clone()];
    let eval = host.evaluate_objects(&carriage, &now(4));
    assert_eq!(
        eval.stop,
        Some(Stop::Deferred {
            index: 0,
            on: recovery.hash()
        })
    );
    assert!(matches!(
        eval.admission("dev-tv", false, &now(4)),
        Admission::RecoveryPending { entry_hash, .. } if entry_hash == recovery.hash()
    ));
    assert_eq!(
        eval.admission("dev-stranger", false, &now(4)),
        Admission::Unauthorized("not a member")
    );
}

/// Minor 6: the writer hands out the drafted body to store before the key
/// signs it; a restart in between signs the same body again.
#[test]
fn the_backup_writer_stores_the_body_before_signing() {
    let kit1 = kit(1);
    let (log, mac_keys) = genesis(&kit1);
    let kit1 = RecoveryKit::make(&[1; 32], ACCOUNT, log.genesis_hash());
    let keys = vec![BackupKey {
        kid: "k1".into(),
        k: Zeroizing::new([7; 32]),
    }];
    let job = BackupJob {
        kids: vec!["k1".into()],
        kit: kit1.recovery_key(),
        signer: "dev-mac".into(),
    };
    let (mut writer, step) = BackupWriter::start(&log, job);
    assert_eq!(step, Step::Seal { blob_version: 1 });
    let env =
        KBackupEnvelope::seal(ACCOUNT, log.genesis_hash(), 1, &kit1.recovery_key(), &keys).unwrap();
    let Step::Sign { body } = writer.sealed(&log, env, 9) else {
        panic!()
    };
    assert!(
        writer.prepared().unwrap().signed.is_none(),
        "not signed yet"
    );
    // The writer is stored here; the device restarts before signing.
    let mut stored = writer.clone();
    assert_eq!(stored.restart(), Step::Sign { body: body.clone() });
    let Step::Put { blob_version, .. } = stored.sign(&mac_keys, &auth()) else {
        panic!()
    };
    assert_eq!(blob_version, 1);
    let signed = stored.prepared().unwrap().signed.clone().unwrap();
    assert_eq!(signed.object().body(), &body);
    // Signing before the body was handed out isn't possible.
    let (mut fresh, _) = BackupWriter::start(
        &log,
        BackupJob {
            kids: vec!["k1".into()],
            kit: kit1.recovery_key(),
            signer: "dev-mac".into(),
        },
    );
    assert_eq!(
        fresh.sign(&mac_keys, &auth()),
        Step::Failed(BackupError::UnexpectedReply)
    );
}

/// Minor 7: the 256 KiB carriage bound is on the bytes received.
#[test]
fn the_carriage_bound_is_on_the_received_bytes() {
    let kit1 = kit(1);
    let (host, mac_keys) = genesis(&kit1);
    let (_, phone) = device("dev-phone", &ALL);
    let body = host.draft("dev-mac", 1, &Action::Add { member: phone });
    let entry = sign_entry(&mac_keys, &auth(), body).unwrap();
    let wire = entry.object().to_json();
    let carried = [strict(&wire)];
    // The same entry, received padded past 256 KiB (whitespace): refused,
    // nothing applied.
    let eval = host.evaluate(&carried, 256 * 1024 + 1, &now(2));
    assert_eq!(
        eval.stop,
        Some(Stop::Invalid {
            index: 1,
            reason: Invalid::CarriageTooLarge
        })
    );
    assert_eq!(eval.next.head(), host.head());
    let eval = host.evaluate(&carried, wire.to_string().len(), &now(2));
    assert_eq!(eval.stop, None);
    assert_eq!(eval.appended, 1);
}
