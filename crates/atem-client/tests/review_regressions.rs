//! Regression tests for the Task 2 review (fix round 1), through the public
//! API: each builds a log with its own software keys and kits and drives the
//! verifier, publisher, backup writer or restore the way a host or a device
//! does.
mod support;

use atem_client::backup::{BackupKey, KBackupEnvelope};
use atem_client::backup_writer::{BackupError, BackupJob, BackupWriter, PutReply, Step};
use atem_client::channel::{HeadError, HostAccept};
use atem_client::encoding::Hash32;
use atem_client::kit::RecoveryKit;
use atem_client::membership::publish::{AppendReply, Published, Publisher};
use atem_client::membership::{
    Action, Admission, Conflict, Entry, EvidenceReason, Head, HostNow, HostRecord, Invalid,
    KBackupRecord, KitMode, Member, MemberKind, Membership, RECOVERY_SIGNER, RECOVERY_WAIT_MS,
    Role, Stop, draft_on, sign_entry, sign_entry_cosigned,
};
use atem_client::restore::restore;
use atem_client::{Alg, KeyId, SignedObject, SoftwareKeys};
use support::{FakeRelay, signed_accept, strict};
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
    // Its signature was never checked: not signed conflicting history, so
    // refetch an earlier window rather than stop signing (m-2).
    assert!(matches!(
        p.reply(reply, &mut log, &now(4)).unwrap(),
        Published::RelayInconsistent { .. }
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
    let h = KeyId::new("h");
    let head = signed_accept(&host_keys, &h, genesis_hash, "host-a", log.head());
    let fresh = now(10 + RECOVERY_WAIT_MS);
    // A fresh verifier alone stops at the subject's entry.
    let alone = Membership::verify_chain(ACCOUNT, &genesis_hash, &entries, &fresh).unwrap();
    assert!(alone.deferred.is_some());
    // With the host-signed head the restore reads through it.
    let restored = restore(
        &kit1,
        &entries,
        env.jcs().as_bytes(),
        std::slice::from_ref(&head),
        &fresh,
    )
    .unwrap();
    assert_eq!(restored.head, log.head());
    assert_eq!(*restored.keys[0].k, [7; 32]);
    // Its log holds a `host_confirmed` decision: a client's snapshot of it
    // reloads (Atem #93 fix round 1), a host's reader refuses it.
    let stored = restored.log.to_stored();
    let record = &stored["recovery"][0];
    assert_eq!(record["reason"], "host_confirmed");
    let reloaded = Membership::from_stored_client(ACCOUNT, &genesis_hash, &stored).unwrap();
    assert_eq!(reloaded, restored.log);
    assert_eq!(reloaded.to_stored(), stored);
    assert_eq!(
        Membership::from_stored(ACCOUNT, &genesis_hash, &stored)
            .unwrap_err()
            .0,
        "recovery reason"
    );
    // A head before the subject's entry confirms nothing beyond it, and
    // the restore doesn't go on with the verified prefix (its newest
    // k_backup may be older than the log's): it waits (Task 2 review
    // carried requirement, applied in Task 4).
    let early = signed_accept(
        &host_keys,
        &h,
        genesis_hash,
        "host-a",
        Head {
            seq: 3,
            hash: entries[2].hash(),
        },
    );
    assert_eq!(
        restore(&kit1, &entries, env.jcs().as_bytes(), &[early], &fresh)
            .err()
            .unwrap()
            .code(),
        "no_host_reachable"
    );

    // M-1: restore is fail-closed on host heads. A head whose sig_h doesn't
    // verify with the chain's key for that host, or that names another log,
    // proves nothing: the restore waits (withheld) instead of reading through.
    let blob = env.jcs();
    let mut other_keys = SoftwareKeys::new();
    other_keys.generate(h.clone(), Alg::Ed25519).unwrap();
    let wrong_key = signed_accept(&other_keys, &h, genesis_hash, "host-a", log.head());
    let mut forged = head.clone();
    forged.sig[0] ^= 1;
    let other_log = signed_accept(&host_keys, &h, Hash32([9; 32]), "host-a", log.head());
    let mut other_gen = head.clone();
    other_gen.host_trust_gen = 2;
    other_gen.sig =
        atem_client::provider::sign(&host_keys, &h, &other_gen.signing_input()).unwrap();
    let prefix = Membership::verify_chain(ACCOUNT, &genesis_hash, &entries, &fresh)
        .unwrap()
        .membership;
    assert_eq!(wrong_key.verify(&prefix), Err(HeadError::BadSignature));
    assert_eq!(forged.verify(&prefix), Err(HeadError::BadSignature));
    assert_eq!(other_log.verify(&prefix), Err(HeadError::OtherGenesis));
    assert_eq!(other_gen.verify(&prefix), Err(HeadError::UnknownHost));
    assert_eq!(head.verify(&prefix).unwrap().head(), log.head());
    for bad in [wrong_key, forged, other_log, other_gen] {
        let refused = restore(&kit1, &entries, blob.as_bytes(), &[bad], &fresh)
            .err()
            .unwrap();
        assert!(refused.is_withheld(), "{refused:?}");
    }
    // The pair also round-trips through its wire messages.
    let init = serde_json::json!({"ch": "atem-ch1", "op": "init",
        "e": atem_client::encoding::b64u(&head.e_c), "n": atem_client::encoding::b64u(&head.n_c),
        "genesis_hash": genesis_hash.to_hex(), "host_id": "host-a", "host_trust_gen": 1});
    let accept = serde_json::json!({"ch": "atem-ch1", "op": "accept",
        "e": atem_client::encoding::b64u(&head.e_h), "n": atem_client::encoding::b64u(&head.n_h),
        "head": {"seq": log.head().seq, "hash": log.head().hash.to_hex()},
        "sig": atem_client::encoding::b64u(&head.sig)});
    assert_eq!(
        HostAccept::from_messages(&strict(&init), &strict(&accept)).unwrap(),
        head
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

/// Task 3 review Minor 2: one measure of carriage bytes. The client's
/// planner fills a suffix up to 256 KiB of `carried_bytes`, exactly what the
/// crate's hello puts on the wire, and the host's `evaluate` bounds the same
/// measure: the planned carriage is accepted, one more entry is refused.
#[test]
fn the_planner_and_the_host_measure_carriage_bytes_the_same_way() {
    use atem_client::channel::carriage::{Carriage, MAX_CARRIED_BYTES, carried_bytes};
    use atem_client::membership::Scope;
    let kit1 = kit(1);
    let (mut client, mac_keys) = genesis(&kit1);
    let host = client.clone();
    // Large entries (~4 KiB each: a service scope listing many projects),
    // so the byte bound binds before the 64-entry one.
    let projects: Vec<String> = (0..45).map(|i| format!("h1.b982533d.{:064x}", i)).collect();
    for i in 0..70u64 {
        let mut svc_keys = SoftwareKeys::new();
        let auth_key = svc_keys.generate(auth(), Alg::Ed25519).unwrap();
        let member = Member {
            device_id: format!("svc-{i:03}"),
            auth_key,
            kind: MemberKind::Service {
                scope: Scope {
                    hosts: vec!["host-a".into()],
                    projects: Some(projects.clone()),
                    sessions: None,
                    ops: vec!["view".into()],
                },
                expires_at: 1 + i + 1000,
            },
        };
        apply(
            &mut client,
            "dev-mac",
            &mac_keys,
            &auth(),
            Action::Add { member },
            1 + i,
        );
    }
    let carriage = Carriage::plan(&client, host.head(), None).unwrap();
    assert!(carriage.more, "the suffix is longer than one carriage");
    assert!(carriage.entries.len() < 64, "the byte bound binds first");
    let wire: Vec<_> = carriage.entries.iter().map(SignedObject::to_json).collect();
    let bytes = carried_bytes(&wire);
    assert_eq!(bytes, carriage.bytes());
    assert!(bytes <= MAX_CARRIED_BYTES);
    // The next entry would cross the bound.
    let next = client
        .entry(host.head().seq + carriage.entries.len() as u64 + 1)
        .unwrap()
        .object()
        .to_json();
    assert!(bytes + next.to_string().len() + 1 > MAX_CARRIED_BYTES);
    // What the hello sends is exactly that array.
    let hello = atem_client::session::r9::hello_bytes(
        "aaaaaaaa-0000-4000-8000-000000000001",
        &atem_client::channel::Principal::Native {
            device_id: "dev-mac".into(),
        },
        &[0u8; 64],
        &carriage,
        None,
    );
    let text = String::from_utf8(hello).unwrap();
    assert!(text.contains(&serde_json::Value::Array(wire.clone()).to_string()));
    // The host accepts the planned carriage and refuses one entry more.
    let carried: Vec<_> = wire.iter().map(strict).collect();
    let eval = host.evaluate(&carried, &now(100));
    assert_eq!(eval.stop, None);
    assert_eq!(eval.appended, carriage.entries.len());
    let mut over = carried.clone();
    over.push(strict(&next));
    assert_eq!(
        host.evaluate(&over, &now(100)).stop,
        Some(Stop::Invalid {
            index: carriage.entries.len(),
            reason: Invalid::CarriageTooLarge
        })
    );
}

/// The exact boundary of the host's measure: an `entries` array of exactly
/// 262 144 bytes passes the byte bound (and is judged on its contents), one
/// byte more is `carriage_too_large`.
#[test]
fn the_carriage_byte_bound_is_exact() {
    use atem_client::channel::carriage::{MAX_CARRIED_BYTES, carried_bytes};
    let kit1 = kit(1);
    let (host, _) = genesis(&kit1);
    // Two objects: `[` + a + `,` + b + `]`.
    let make = |total: usize| {
        let a = serde_json::json!({ "pad": "x".repeat(100_000) });
        let fixed = 1 + a.to_string().len() + 1 + 1 + r#"{"pad":""}"#.len();
        let b = serde_json::json!({ "pad": "y".repeat(total - fixed) });
        vec![a, b]
    };
    let at = make(MAX_CARRIED_BYTES);
    assert_eq!(carried_bytes(&at), MAX_CARRIED_BYTES);
    let stop = host
        .evaluate(&at.iter().map(strict).collect::<Vec<_>>(), &now(1))
        .stop;
    assert!(!matches!(
        stop,
        Some(Stop::Invalid {
            reason: Invalid::CarriageTooLarge,
            ..
        })
    ));
    let over = make(MAX_CARRIED_BYTES + 1);
    assert_eq!(carried_bytes(&over), MAX_CARRIED_BYTES + 1);
    assert_eq!(
        host.evaluate(&over.iter().map(strict).collect::<Vec<_>>(), &now(1))
            .stop,
        Some(Stop::Invalid {
            index: 1,
            reason: Invalid::CarriageTooLarge
        })
    );
}

/// I-1: a since-removed manager's stolen key signing a conflict aimed at the
/// vetoed subject is ignored (row 5), not a freeze through row 2; a current
/// manager's conflicting entry at the same seq still freezes (row 6).
#[test]
fn a_removed_managers_conflict_on_the_subject_is_ignored() {
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
    let (laptop_keys, laptop) = device("dev-laptop", &ALL);
    apply(
        &mut host,
        "dev-mac",
        &mac_keys,
        &auth(),
        Action::Add { member: laptop },
        2,
    );
    let (_, newmac) = device("dev-newmac", &ALL);
    let recovery = apply(
        &mut host,
        RECOVERY_SIGNER,
        &kit1,
        &RecoveryKit::sign_id(),
        Action::RecoveryAdd { member: newmac },
        3,
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
        4,
    );
    apply(
        &mut host,
        "dev-mac",
        &mac_keys,
        &auth(),
        Action::Remove {
            device_id: "dev-laptop".into(),
        },
        5,
    );
    let remove_newmac = Action::Remove {
        device_id: "dev-newmac".into(),
    };
    // The laptop (removed after the veto) at the veto's seq: ignored.
    let body = before_veto.draft("dev-laptop", 6, &remove_newmac);
    let stolen = sign_entry(&laptop_keys, &auth(), body).unwrap();
    assert_eq!(
        conflict_of(&host, &stolen, 7),
        Some(Stop::Conflict {
            index: 0,
            outcome: Conflict::Ignored(EvidenceReason::SignerRemoved)
        })
    );
    assert!(
        host.evaluate_objects(&[stolen.object().clone()], &now(7))
            .next
            .frozen()
            .is_none()
    );
    // The Mac, still a manager at the head: rows 4–6 apply, and row 6
    // freezes.
    let body = before_veto.draft("dev-mac", 6, &remove_newmac);
    let current = sign_entry(&mac_keys, &auth(), body).unwrap();
    assert_eq!(
        conflict_of(&host, &current, 7),
        Some(Stop::Conflict {
            index: 0,
            outcome: Conflict::Freeze
        })
    );
}

/// m-1: the byte bound can't be lifted by a wrong count (the entries' own
/// encoding counts too), and `index` names the entry that crosses it.
#[test]
fn a_wrong_byte_count_cannot_lift_the_bound() {
    let kit1 = kit(1);
    let (host, mac_keys) = genesis(&kit1);
    // Objects whose encoding crosses 256 KiB with the second one: the bound
    // runs before parsing and names the crossing entry.
    let big = "x".repeat(200 * 1024);
    let junk: Vec<_> = (0..3)
        .map(|_| strict(&serde_json::json!({ "pad": big })))
        .collect();
    assert_eq!(
        host.evaluate(&junk, &now(1)).stop,
        Some(Stop::Invalid {
            index: 1,
            reason: Invalid::CarriageTooLarge
        })
    );
    // One such object is under the bound: the shape check runs (and refuses
    // it as malformed, at its own index), not the byte bound.
    assert!(!matches!(
        host.evaluate(&junk[..1], &now(1)).stop,
        Some(Stop::Invalid {
            reason: Invalid::CarriageTooLarge,
            ..
        })
    ));
    // 65 entries: the 65th (index 64) is named.
    let mut many = Vec::new();
    let mut scratch = host.clone();
    for i in 0..65 {
        let (_, member) = device(&format!("dev-m{i}"), &[Role::View]);
        let entry = apply(
            &mut scratch,
            "dev-mac",
            &mac_keys,
            &auth(),
            Action::Add { member },
            i,
        );
        many.push(strict(&entry.object().to_json()));
    }
    let eval = host.evaluate(&many, &now(1));
    assert_eq!(
        eval.stop,
        Some(Stop::Invalid {
            index: 64,
            reason: Invalid::CarriageTooLarge
        })
    );
}

/// m-3: a fetched page that says more follow but doesn't move the log stops
/// the writer as relay-inconsistent instead of fetching forever.
#[test]
fn a_fetch_without_progress_stops_the_writer() {
    let kit1 = kit(1);
    let (mut log, mac_keys) = genesis(&kit1);
    let (phone_keys, phone) = device("dev-phone", &ALL);
    apply(
        &mut log,
        "dev-mac",
        &mac_keys,
        &auth(),
        Action::Add { member: phone },
        1,
    );
    let kit1 = RecoveryKit::make(&[1; 32], ACCOUNT, log.genesis_hash());
    let mut relay = FakeRelay::with_log(object_list(&log, 0));
    let keys = vec![BackupKey {
        kid: "k1".into(),
        k: Zeroizing::new([7; 32]),
    }];
    let (mut writer, step) = BackupWriter::start(
        &log,
        BackupJob {
            kids: vec!["k1".into()],
            kit: kit1.recovery_key(),
            signer: "dev-mac".into(),
        },
    );
    assert_eq!(step, Step::Seal { blob_version: 1 });
    let env =
        KBackupEnvelope::seal(ACCOUNT, log.genesis_hash(), 1, &kit1.recovery_key(), &keys).unwrap();
    assert!(matches!(writer.sealed(&log, env, 1), Step::Sign { .. }));
    let Step::Put { .. } = writer.sign(&mac_keys, &auth()) else {
        panic!()
    };
    let Step::Append { entry, expected } = writer.put_reply(&log, PutReply::Stored) else {
        panic!()
    };
    // The phone wins the seq; the relay's 409 says more follow.
    let mut phone_log = log.clone();
    let (_, tv) = device("dev-tv", &[Role::View]);
    let won = apply(
        &mut phone_log,
        "dev-phone",
        &phone_keys,
        &auth(),
        Action::Add { member: tv },
        2,
    );
    relay.log.push(won.object().clone());
    let reply = AppendReply::Conflict {
        head: phone_log.head(),
        entries: vec![won.object().clone()],
        more: true,
    };
    let _ = (entry, expected);
    let Step::Fetch { after } = writer.append_reply(&mut log, reply, &now(3), 3) else {
        panic!()
    };
    assert_eq!(after, phone_log.head().seq);
    // The next page is empty yet claims more: no progress.
    assert_eq!(
        writer.fetched(&mut log, &[], true, &now(4), 4),
        Step::Failed(BackupError::RelayInconsistent)
    );
}

/// I-2: a host removed (or re-keyed) beyond the deferral point can't confirm
/// the head a restore reads through (§R9.7 step 1): every head is checked
/// again against the extended chain.
#[test]
fn restore_head_from_host_removed_beyond_deferral() {
    let kit0 = kit(1);
    let (mut log, mac_keys) = genesis(&kit0);
    let gh = log.genesis_hash();
    let kit1 = RecoveryKit::make(&[1; 32], ACCOUNT, gh);
    let mut hk = SoftwareKeys::new();
    let h = KeyId::new("h");
    let host_key = hk.generate(h.clone(), Alg::Ed25519).unwrap();
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
    let (nk, newmac) = device("dev-newmac", &ALL);
    apply(
        &mut log,
        RECOVERY_SIGNER,
        &kit1,
        &RecoveryKit::sign_id(),
        Action::RecoveryAdd { member: newmac },
        2,
    );
    log.advance(&now(2 + RECOVERY_WAIT_MS));
    let keys = vec![BackupKey {
        kid: "k1".into(),
        k: Zeroizing::new([7; 32]),
    }];
    let env = KBackupEnvelope::seal(ACCOUNT, gh, 1, &kit1.recovery_key(), &keys).unwrap();
    apply(
        &mut log,
        "dev-newmac",
        &nk,
        &auth(),
        Action::KBackup(KBackupRecord {
            blob_version: 1,
            kids: vec!["k1".into()],
            recovery_key: kit1.recovery_key(),
            backup_hash: env.backup_hash(),
        }),
        3 + RECOVERY_WAIT_MS,
    );
    let before_removal = log.clone();
    apply(
        &mut log,
        "dev-newmac",
        &nk,
        &auth(),
        Action::RemoveHost {
            host_id: "host-a".into(),
        },
        4 + RECOVERY_WAIT_MS,
    );
    let entries = log.entries().to_vec();
    let tip = signed_accept(&hk, &h, gh, "host-a", log.head());
    assert_eq!(tip.verify(&log), Err(HeadError::UnknownHost));
    let fresh = now(10 + RECOVERY_WAIT_MS);
    let refused = restore(
        &kit1,
        &entries,
        env.jcs().as_bytes(),
        std::slice::from_ref(&tip),
        &fresh,
    )
    .err()
    .expect("never Ok on a removed host's head");
    assert!(refused.is_withheld(), "{refused:?}");
    // A lower head of the same host, before its removal, is still no
    // confirmation: the extended chain removes the host.
    let earlier = signed_accept(&hk, &h, gh, "host-a", before_removal.head());
    let refused = restore(
        &kit1,
        &entries,
        env.jcs().as_bytes(),
        &[tip, earlier],
        &fresh,
    )
    .err()
    .unwrap();
    assert!(refused.is_withheld(), "{refused:?}");
}

/// m-a: a deferred signer is judged by where it stands at our head. A
/// `kit: "lost"` key K2 pending at seq-1 and current at our head freezes; one
/// vetoed since is ignored (signer_not_in_effect). The same for a recovered
/// subject: active now freezes; cancelled now is ignored.
#[test]
fn a_deferred_signer_is_judged_at_our_head() {
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
    let lost = apply(
        &mut host,
        "dev-mac",
        &mac_keys,
        &auth(),
        Action::SetRecoveryKey {
            recovery_key: kit2.recovery_key(),
            kit: KitMode::Lost,
        },
        2,
    );
    let before = host.clone();
    let (_, x) = device("dev-x", &[Role::View]);
    apply(
        &mut host,
        "dev-mac",
        &mac_keys,
        &auth(),
        Action::Add { member: x },
        3,
    );
    let (_, z) = device("dev-z", &ALL);
    let body = before.draft(RECOVERY_SIGNER, 4, &Action::RecoveryAdd { member: z });
    let by_k2 = sign_entry(&kit2, &RecoveryKit::sign_id(), body).unwrap();
    // K2 vetoed: not in effect at our head.
    let mut vetoed = host.clone();
    apply(
        &mut vetoed,
        "dev-phone",
        &phone_keys,
        &auth(),
        Action::RecoveryVeto {
            target: lost.hash(),
        },
        4,
    );
    assert_eq!(
        conflict_of(&vetoed, &by_k2, 5),
        Some(Stop::Conflict {
            index: 0,
            outcome: Conflict::Ignored(EvidenceReason::SignerNotInEffect)
        })
    );
    // K2 in effect (its wait ended): freeze.
    let mut active = host.clone();
    active.advance(&now(2 + RECOVERY_WAIT_MS + 5));
    assert_eq!(*active.recovery_key(), kit2.recovery_key());
    assert_eq!(
        conflict_of(&active, &by_k2, 3 + RECOVERY_WAIT_MS + 10),
        Some(Stop::Conflict {
            index: 0,
            outcome: Conflict::Freeze
        })
    );

    // A recovered subject signing at a seq that isn't a veto.
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
    let r = apply(
        &mut host,
        RECOVERY_SIGNER,
        &kit1,
        &RecoveryKit::sign_id(),
        Action::RecoveryAdd { member: newmac },
        2,
    );
    let before = host.clone();
    let (_, x) = device("dev-x", &[Role::View]);
    apply(
        &mut host,
        "dev-mac",
        &mac_keys,
        &auth(),
        Action::Add { member: x },
        3,
    );
    let body = before.draft(
        "dev-newmac",
        4,
        &Action::Remove {
            device_id: "dev-phone".into(),
        },
    );
    let by_subject = sign_entry(&newmac_keys, &auth(), body).unwrap();
    // Cancelled since: ignored, with its own evidence label (m-c).
    let mut cancelled = host.clone();
    apply(
        &mut cancelled,
        "dev-phone",
        &phone_keys,
        &auth(),
        Action::RecoveryVeto { target: r.hash() },
        4,
    );
    let eval = cancelled.evaluate_objects(&[by_subject.object().clone()], &now(5));
    assert_eq!(
        eval.stop,
        Some(Stop::Conflict {
            index: 0,
            outcome: Conflict::Ignored(EvidenceReason::SignerNotInEffect)
        })
    );
    assert_eq!(
        eval.next.evidence().recent.last().unwrap().reason.as_str(),
        "signer_not_in_effect"
    );
    // Active since: a manager at our head, freeze.
    let mut active = host.clone();
    active.advance(&now(2 + RECOVERY_WAIT_MS + 5));
    assert_eq!(
        conflict_of(&active, &by_subject, 3 + RECOVERY_WAIT_MS + 10),
        Some(Stop::Conflict {
            index: 0,
            outcome: Conflict::Freeze
        })
    );
}
