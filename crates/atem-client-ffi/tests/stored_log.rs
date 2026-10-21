//! The log's durable snapshot (`MembershipLog::stored_json` /
//! `from_stored`, Atem #93): an app restart resumes the exact state. Wait
//! clocks continue (same boot from first sight, another boot from the time
//! already waited), a wall clock set back neither ends nor restarts a wait,
//! decisions stay at their chain positions, a freeze survives; anything
//! that isn't the export, or is of another account or genesis, is refused;
//! publishers, writers and restores take a restored log as before. Each
//! test that publishes uses its own device (the per-device claim is
//! process-wide and the tests run in parallel).
#![cfg(feature = "uniffi")]

#[path = "../../atem-client/tests/support/mod.rs"]
#[allow(unused_imports)]
mod support;

use std::sync::Arc;

use atem_client::KeyProvider as _;
use atem_client::backup::{BackupKey, KBackupEnvelope};
use atem_client::channel::wire::{Accept, Frame, Init};
use atem_client::encoding::Hash32;
use atem_client::kit::RecoveryKit;
use atem_client::membership::{
    Action, HostNow, HostRecord, KBackupRecord, Member, MemberKind, Membership, RECOVERY_SIGNER,
    RECOVERY_WAIT_MS, Role, draft_on, sign_entry,
};
use atem_client::provider::KeyId;
use atem_client::{Alg, SoftwareKeys};
use atem_client_ffi::AtemError;
use atem_client_ffi::kit::RestoreSession;
use atem_client_ffi::log::{MAX_STORED_JSON, MembershipLog};
use atem_client_ffi::provider::{AppKeyProvider, ProviderError};
use atem_client_ffi::publish::{EntryPublisher, KBackupWriter};
use atem_client_ffi::types::{
    BackupStep, CarriageStop, HostAcceptPair, HostClock, MemberStatusKind, MembershipEffect,
    PublicKeyData, PublishOutcome, SignRequest,
};
use serde_json::{Value, json};
use support::*;

const WALL: u64 = 1_793_264_001_000;
const HOUR: u64 = 3_600_000;
const DAY: u64 = 24 * HOUR;

fn at(wall_ms: u64, mono_ms: u64, boot: &str) -> HostClock {
    HostClock {
        wall_ms,
        mono_ms,
        boot_id: boot.into(),
    }
}

/// First sight: wall `WALL`, monotonic 1 000 on boot-1; `later(ms)` moves
/// both together.
fn t0() -> HostClock {
    at(WALL, 1_000, "boot-1")
}

fn later(ms: u64) -> HostClock {
    at(WALL + ms, 1_000 + ms, "boot-1")
}

fn json_of(v: &Vectors, labels: &[&str]) -> Vec<String> {
    labels
        .iter()
        .map(|l| v.object(l).to_json().to_string())
        .collect()
}

const L: [&str; 6] = ["E1", "E2", "E3", "E4", "E5", "E6"];

fn base(v: &Vectors) -> Arc<MembershipLog> {
    MembershipLog::verify(
        ACCOUNT.into(),
        genesis_hash().to_hex(),
        json_of(v, &L),
        t0(),
    )
    .unwrap()
}

fn extend(log: &MembershipLog, v: &Vectors, labels: &[&str], now: HostClock) {
    let r = log.extend(json_of(v, labels), now).unwrap();
    assert_eq!(r.stop, None, "{labels:?}");
}

fn restore(stored: &str, now: HostClock) -> Result<Arc<MembershipLog>, AtemError> {
    MembershipLog::from_stored(
        ACCOUNT.into(),
        genesis_hash().to_hex(),
        stored.to_owned(),
        now,
    )
}

fn code(e: AtemError) -> String {
    e.code()
}

fn stored_code(e: AtemError) -> String {
    match e {
        AtemError::Stored { code, .. } => code,
        other => panic!("expected a Stored error, got {other:?}"),
    }
}

fn effective_at(log: &MembershipLog, now: HostClock) -> Vec<u64> {
    log.pending_recovery(now)
        .unwrap()
        .into_iter()
        .map(|p| p.effective_at)
        .collect()
}

fn activated(effects: &[MembershipEffect]) -> Vec<String> {
    effects
        .iter()
        .filter_map(|e| match e {
            MembershipEffect::RecoveryActive { reason, .. } => Some(reason.clone()),
            _ => None,
        })
        .collect()
}

fn stored_value(log: &MembershipLog) -> Value {
    serde_json::from_str(&log.stored_json().unwrap()).unwrap()
}

#[test]
fn a_partly_elapsed_wait_continues_across_a_same_boot_restart() {
    let v = Vectors::load();
    let log = base(&v);
    extend(&log, &v, &["R7"], t0());
    assert_eq!(log.advance(later(10 * HOUR)).unwrap(), vec![]);
    let saved = log.stored_json().unwrap();
    // The app restarts 2 h later on the same boot (the snapshot is 2 h old).
    let restored = restore(&saved, later(12 * HOUR)).unwrap();
    assert_eq!(
        effective_at(&restored, later(12 * HOUR)),
        vec![WALL + DAY],
        "the same deadline: from first sight"
    );
    assert_eq!(
        effective_at(&restored, later(12 * HOUR)),
        effective_at(&log, later(12 * HOUR)),
        "as without the restart"
    );
    assert_eq!(restored.advance(later(DAY - 1)).unwrap(), vec![]);
    assert_eq!(
        activated(&restored.advance(later(DAY)).unwrap()),
        vec!["wait_ended"]
    );
    assert_eq!(
        activated(&log.advance(later(DAY)).unwrap()),
        vec!["wait_ended"]
    );
    assert_eq!(restored.stored_json().unwrap(), log.stored_json().unwrap());

    // A snapshot taken at first sight (nothing waited persisted) restored
    // on the same boot still counts from first sight.
    let fresh = base(&v);
    extend(&fresh, &v, &["R7"], t0());
    let restored = restore(&fresh.stored_json().unwrap(), later(20 * HOUR)).unwrap();
    assert_eq!(effective_at(&restored, later(20 * HOUR)), vec![WALL + DAY]);
    assert_eq!(
        activated(&restored.advance(later(DAY)).unwrap()),
        vec!["wait_ended"]
    );
}

#[test]
fn a_reboot_carries_the_time_already_waited() {
    let v = Vectors::load();
    let log = base(&v);
    extend(&log, &v, &["R7"], t0());
    log.advance(later(10 * HOUR)).unwrap(); // 10 h waited, persisted below
    let saved = log.stored_json().unwrap();
    // The machine was off for 20 h; the new boot's clock is young.
    let boot = |since: u64| at(WALL + 30 * HOUR + since, 500 + since, "boot-2");
    let restored = restore(&saved, boot(0)).unwrap();
    assert_eq!(
        effective_at(&restored, boot(0)),
        vec![WALL + 30 * HOUR + 14 * HOUR],
        "14 h left on the monotonic side"
    );
    assert_eq!(restored.advance(boot(14 * HOUR - 1)).unwrap(), vec![]);
    assert_eq!(
        activated(&restored.advance(boot(14 * HOUR)).unwrap()),
        vec!["wait_ended"]
    );

    // Restored again later in the new boot (from a snapshot taken right
    // after the reboot): the re-anchored wait goes on, nothing restarts.
    let restored = restore(&saved, boot(0)).unwrap();
    let resaved = restored.stored_json().unwrap();
    let again = restore(&resaved, boot(6 * HOUR)).unwrap();
    assert_eq!(effective_at(&again, boot(6 * HOUR)), vec![WALL + 44 * HOUR]);
    // And a second reboot before anything was persisted again only keeps
    // the 10 h: time that wasn't persisted never counts.
    let third = restore(&resaved, at(WALL + 50 * HOUR, 200, "boot-3")).unwrap();
    assert_eq!(
        effective_at(&third, at(WALL + 50 * HOUR, 200, "boot-3")),
        vec![WALL + 50 * HOUR + 14 * HOUR]
    );
}

#[test]
fn a_wall_clock_set_back_after_restore_neither_ends_nor_restarts_a_wait() {
    let v = Vectors::load();
    let log = base(&v);
    extend(&log, &v, &["R7"], t0());
    log.advance(later(HOUR)).unwrap();
    let saved = log.stored_json().unwrap();
    // Restored with the wall clock five days behind (same boot).
    let back = |ms: u64| at(WALL - 5 * DAY + ms, 1_000 + ms, "boot-1");
    let restored = restore(&saved, back(2 * HOUR)).unwrap();
    // The monotonic side is over, the wall side isn't: no early end.
    assert_eq!(restored.advance(back(DAY)).unwrap(), vec![]);
    assert_eq!(
        effective_at(&restored, back(DAY)),
        vec![WALL + DAY],
        "first sight is kept: not restarted from the new wall time"
    );
    // Once the wall clock reaches first sight + 24 h it ends.
    let fixed = at(WALL + DAY, 1_000 + 3 * DAY, "boot-1");
    assert_eq!(
        activated(&restored.advance(fixed).unwrap()),
        vec!["wait_ended"]
    );

    // A wall clock jumped forward alone ends nothing either.
    let restored = restore(&saved, later(2 * HOUR)).unwrap();
    assert_eq!(
        restored
            .advance(at(WALL + 10 * DAY, 1_000 + 2 * HOUR, "boot-1"))
            .unwrap(),
        vec![]
    );
}

#[test]
fn a_wait_ended_decision_keeps_its_chain_position() {
    let v = Vectors::load();
    let log = base(&v);
    extend(&log, &v, &["R7"], t0());
    assert_eq!(
        activated(&log.advance(later(DAY)).unwrap()),
        vec!["wait_ended"]
    );
    let saved = stored_value(&log);
    assert_eq!(saved["recovery"][0]["reason"], json!("wait_ended"));
    assert_eq!(saved["recovery"][0]["decided_at_seq"], json!(7));

    // Restored, N8 (signed by R7's subject, valid only once R7 is in
    // effect) still applies.
    let restored = restore(&saved.to_string(), later(DAY + HOUR)).unwrap();
    assert_eq!(
        restored.member("dev-newmac".into()).unwrap().status,
        MemberStatusKind::Active
    );
    extend(&restored, &v, &["N8"], later(DAY + HOUR));
    assert_eq!(restored.head().seq, 8);

    // And a snapshot that holds N8 replays it with the decision at seq 7.
    let after = restored.stored_json().unwrap();
    let again = restore(&after, later(DAY + 2 * HOUR)).unwrap();
    assert_eq!(again.head(), restored.head());
    assert_eq!(again.stored_json().unwrap(), after);
    // Without the decision the chain doesn't verify: N8 depends on it.
    let mut undecided: Value = serde_json::from_str(&after).unwrap();
    let record = undecided["recovery"][0].as_object_mut().unwrap();
    for k in ["decided_at_wall", "decided_at_seq", "order", "reason"] {
        record.remove(k);
    }
    record.insert("state".into(), json!("pending"));
    assert_eq!(
        stored_code(restore(&undecided.to_string(), later(DAY)).err().unwrap()),
        "stored_invalid"
    );
}

#[test]
fn pending_approved_and_vetoed_records_survive() {
    let v = Vectors::load();
    let cases: [(&[&str], &str, Option<&str>); 5] = [
        (&["R7"], "dev-newmac", None),
        (&["R7", "A8"], "dev-newmac", Some("approved")),
        (&["R7", "V8"], "dev-newmac", Some("vetoed")),
        (&["K7_lost"], "dev-phone", None),
        (&["K7_lost", "V8_k"], "dev-phone", Some("vetoed")),
    ];
    for (labels, subject, reason) in cases {
        let log = base(&v);
        extend(&log, &v, labels, later(HOUR));
        let saved = log.stored_json().unwrap();
        // The same reading the snapshot was taken at: nothing moves.
        let restored = restore(&saved, later(HOUR)).unwrap();
        assert_eq!(restored.stored_json().unwrap(), saved, "{labels:?}");
        assert_eq!(restored.head(), log.head());
        assert_eq!(restored.members(), log.members());
        assert_eq!(restored.recovery_key(), log.recovery_key());
        let record = &stored_value(&restored)["recovery"][0];
        match reason {
            None => {
                let pending = restored.pending_recovery(later(2 * HOUR)).unwrap();
                assert_eq!(pending.len(), 1, "{labels:?}");
                assert_eq!(pending[0].subject, subject);
                assert_eq!(pending[0].effective_at, WALL + HOUR + DAY);
                assert_eq!(record["state"], json!("pending"));
            }
            Some(reason) => {
                assert!(
                    restored
                        .pending_recovery(later(2 * HOUR))
                        .unwrap()
                        .is_empty()
                );
                assert_eq!(record["reason"], json!(reason), "{labels:?}");
            }
        }
    }
    // A pending key replacement ends its wait after restore and replaces
    // the recovery key, as without the restart.
    let log = base(&v);
    extend(&log, &v, &["K7_lost"], t0());
    let kit1 = log.recovery_key();
    let restored = restore(&log.stored_json().unwrap(), later(HOUR)).unwrap();
    let effects = restored.advance(later(DAY)).unwrap();
    assert!(effects.contains(&MembershipEffect::RecoveryKeyReplaced));
    assert_ne!(restored.recovery_key(), kit1);
    let again = restore(&restored.stored_json().unwrap(), later(DAY + 1)).unwrap();
    assert_eq!(again.recovery_key(), restored.recovery_key());
}

#[test]
fn a_frozen_log_stays_frozen() {
    let v = Vectors::load();
    let log = base(&v);
    let r = log.extend(json_of(&v, &["C6_mac"]), t0()).unwrap();
    assert!(r.stop.is_some());
    let frozen = log.frozen().expect("frozen");
    let restored = restore(&log.stored_json().unwrap(), later(HOUR)).unwrap();
    assert_eq!(restored.frozen(), Some(frozen));
    let r = restored.extend(json_of(&v, &["E7"]), later(HOUR)).unwrap();
    assert_eq!(r.stop, Some(CarriageStop::Frozen), "nothing applies");
    // A pending wait in a frozen log never ends.
    let log = base(&v);
    extend(&log, &v, &["R7"], t0());
    log.extend(json_of(&v, &["C6_mac"]), t0()).unwrap();
    assert!(log.frozen().is_some());
    let restored = restore(&log.stored_json().unwrap(), later(HOUR)).unwrap();
    assert!(restored.frozen().is_some());
    assert_eq!(restored.advance(later(2 * DAY)).unwrap(), vec![]);
    assert_eq!(restored.pending_recovery(later(2 * DAY)).unwrap().len(), 1);
}

#[test]
fn a_snapshot_that_isnt_the_export_is_refused() {
    let v = Vectors::load();
    let log = base(&v);
    extend(&log, &v, &["R7"], t0());
    log.advance(later(HOUR)).unwrap();
    let saved = log.stored_json().unwrap();
    let value: Value = serde_json::from_str(&saved).unwrap();
    let refused = |text: String, want: &str, why: &str| {
        let e = restore(&text, later(2 * HOUR)).err();
        assert_eq!(
            e.map(stored_code).as_deref(),
            Some(want),
            "{why} was not refused as {want}"
        );
    };
    let changed = |change: &dyn Fn(&mut Value)| {
        let mut s = value.clone();
        change(&mut s);
        s.to_string()
    };

    refused(
        saved[..saved.len() / 2].to_owned(),
        "malformed",
        "truncated",
    );
    refused(String::new(), "malformed", "empty");
    refused("[]".into(), "malformed", "not an object");
    refused(
        format!("{}{}", saved, " ".repeat(MAX_STORED_JSON)),
        "too_large",
        "oversize",
    );
    refused(
        saved.replacen("{", r#"{"account_id":"x","#, 1),
        "malformed",
        "a duplicate key",
    );
    // An altered byte in a stored entry (a signature).
    refused(
        changed(&|s| {
            let sig = s["entries"][3]["sig"].as_str().unwrap().to_owned();
            let mut c: Vec<char> = sig.chars().collect();
            c[5] = if c[5] == 'A' { 'B' } else { 'A' };
            s["entries"][3]["sig"] = json!(c.into_iter().collect::<String>());
        }),
        "stored_invalid",
        "an altered signature",
    );
    refused(
        changed(&|s| s["entries"][2]["body"]["signed_at"] = json!(1)),
        "stored_invalid",
        "an altered entry body",
    );
    refused(
        changed(&|s| {
            s["recovery"].as_array_mut().unwrap().clear();
        }),
        "stored_invalid",
        "a removed record",
    );
    refused(
        changed(&|s| s["recovery"][0]["state"] = json!("active")),
        "stored_invalid",
        "a decision without its fields",
    );
    refused(
        changed(&|s| s["head"]["seq"] = json!(6)),
        "stored_invalid",
        "another head",
    );
    refused(
        changed(&|s| {
            s.as_object_mut().unwrap().remove("frozen");
            s["frozen_at"] = json!(1);
        }),
        "stored_invalid",
        "an unknown top-level field",
    );
    refused(
        changed(&|s| s["recovery"][0]["note"] = json!("x")),
        "stored_invalid",
        "an unknown record field",
    );
    refused(
        changed(&|s| s["host"] = json!({"host_id": "host-a", "host_trust_gen": 1})),
        "stored_invalid",
        "the host's own fields",
    );
    refused(
        changed(&|s| s["evidence"]["recent"] = json!([{"x": 1}])),
        "stored_invalid",
        "a malformed evidence record",
    );
    // The export itself is accepted, whitespace aside.
    assert!(restore(&saved, later(2 * HOUR)).is_ok());
    assert!(
        restore(
            &serde_json::to_string_pretty(&value).unwrap(),
            later(2 * HOUR)
        )
        .is_ok()
    );
}

#[test]
fn another_account_or_genesis_is_refused() {
    let v = Vectors::load();
    let log = base(&v);
    extend(&log, &v, &["R7"], t0());
    let saved = log.stored_json().unwrap();
    let with = |account: &str, genesis: String, text: &str| {
        MembershipLog::from_stored(account.into(), genesis, text.into(), t0())
    };
    let g = genesis_hash().to_hex();
    let other_genesis = v.hash("SUB1").to_hex();
    assert_eq!(
        stored_code(with("acct-other", g.clone(), &saved).err().unwrap()),
        "account_mismatch"
    );
    assert_eq!(
        stored_code(with(ACCOUNT, other_genesis.clone(), &saved).err().unwrap()),
        "genesis_mismatch"
    );
    // The snapshot's own fields never stand in for the anchors.
    let mut renamed: Value = serde_json::from_str(&saved).unwrap();
    renamed["account_id"] = json!("acct-other");
    assert_eq!(
        stored_code(
            with(ACCOUNT, g.clone(), &renamed.to_string())
                .err()
                .unwrap()
        ),
        "account_mismatch"
    );
    assert_eq!(
        stored_code(
            with("acct-other", g.clone(), &renamed.to_string())
                .err()
                .unwrap()
        ),
        "stored_invalid",
        "the entries name the real account"
    );
    let mut regenesis: Value = serde_json::from_str(&saved).unwrap();
    regenesis["genesis_hash"] = json!(other_genesis);
    assert_eq!(
        stored_code(
            with(ACCOUNT, g.clone(), &regenesis.to_string())
                .err()
                .unwrap()
        ),
        "genesis_mismatch"
    );
    assert_eq!(
        stored_code(
            with(ACCOUNT, other_genesis, &regenesis.to_string())
                .err()
                .unwrap()
        ),
        "stored_invalid",
        "the genesis entry isn't that anchor"
    );
    // A malformed anchor is the caller's input error.
    assert_eq!(
        code(with(ACCOUNT, "zz".into(), &saved).err().unwrap()),
        "malformed"
    );
}

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

#[test]
fn a_restored_log_drives_a_resumed_publisher() {
    let v = Vectors::load();
    let keys: Arc<dyn AppKeyProvider> = Arc::new(BookKeys(Book::load()));
    let log = base(&v);
    let body = log
        .draft_entry(
            "dev-phone".into(),
            WALL,
            r#"{"action":"remove","device_id":"svc-discord"}"#.into(),
        )
        .unwrap();
    let p = EntryPublisher::new();
    p.prepare(log.clone(), body).unwrap();
    let request = p.sign(keys, "dev-phone/auth".into(), None).unwrap();
    // The app persisted both, then crashed.
    let prepared = p.prepared_json().unwrap();
    let saved = log.stored_json().unwrap();
    drop(p);
    drop(log);

    let log = restore(&saved, later(HOUR)).unwrap();
    let p = EntryPublisher::resume(prepared).unwrap();
    assert_eq!(p.outstanding().unwrap(), request, "the same entry");
    let PublishOutcome::Committed { head } = p.reply_stored(log.clone(), later(HOUR)).unwrap()
    else {
        panic!("committed");
    };
    assert_eq!(head.hash, request.entry_hash);
    assert_eq!(log.head(), head);
    assert_eq!(p.prepared_json(), None);
    // The new state is what the app commits next.
    let next = restore(&log.stored_json().unwrap(), later(HOUR)).unwrap();
    assert_eq!(next.head(), head);
}

#[test]
fn a_restored_log_drives_a_k_backup_writer() {
    let v = Vectors::load();
    let book = Book::load();
    let kit_pub: PublicKeyData = (&book.kit("recovery").recovery_key()).into();
    let log = restore(&base(&v).stored_json().unwrap(), t0()).unwrap();
    let writer = KBackupWriter::start(
        log.clone(),
        vec!["b982533d".into()],
        kit_pub,
        "dev-mac".into(),
    )
    .unwrap();
    assert!(matches!(
        writer.step(),
        BackupStep::Seal { blob_version: 1 }
    ));
}

#[test]
fn a_restore_sessions_log_round_trips() {
    let v = Vectors::load();
    let rec = load("r9-vectors-recovery");
    let hs = load("r9-vectors-channel-handshake");
    let hex = |v: &Value| {
        let text = v.as_str().unwrap();
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect::<Vec<u8>>()
    };
    let mut entries = json_of(&v, &L);
    entries.extend(json_of(&v, &["KB7"]));
    let session = RestoreSession::read(
        hex(&rec["R_hex"]),
        ACCOUNT.into(),
        genesis_hash().to_hex(),
        hex(&rec["kit"]["kit_tag_hex"]),
    )
    .unwrap();
    session
        .attempt(
            entries,
            rec["k_backup"]["wire"].to_string(),
            vec![HostAcceptPair {
                init_json: hs["init"].to_string(),
                accept_json: hs["accept"].to_string(),
            }],
            t0(),
        )
        .unwrap();
    let log = session.log().expect("the restore's verified log");
    let restored = restore(&log.stored_json().unwrap(), t0()).unwrap();
    assert_eq!(restored.head(), log.head());
    assert_eq!(restored.k_backup(), log.k_backup());
    assert_eq!(restored.stored_json().unwrap(), log.stored_json().unwrap());
}

/// A device with its own P-256 auth key and X25519 enc key.
fn device(id: &str, roles: &[Role]) -> (SoftwareKeys, Member) {
    let mut keys = SoftwareKeys::new();
    let auth_key = keys.generate(KeyId::new("auth"), Alg::P256).unwrap();
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

fn clock_at(wall_ms: u64) -> HostNow {
    HostNow {
        wall_ms,
        mono_ms: wall_ms,
        boot_id: "b".into(),
    }
}

/// Signs `action` as `signer` on `m`'s head and applies it.
fn apply(
    m: &mut Membership,
    signer: &str,
    keys: &dyn atem_client::KeyProvider,
    key: &KeyId,
    action: Action,
    at: u64,
) {
    let body = m.draft(signer, at, &action);
    let entry = sign_entry(keys, key, body).unwrap();
    let eval = m.evaluate_objects(&[entry.object().clone()], &clock_at(at));
    assert_eq!(eval.stop, None, "{action:?}");
    *m = eval.next;
}

/// Fix round 1 (H-1): a kit restore that reads through a past recovery (a
/// host-signed head shows it took effect) records `host_confirmed`; its
/// log's snapshot reloads with the same head, members and pending state.
#[test]
fn a_restore_read_through_log_reloads() {
    const ALL: [Role; 3] = [Role::Control, Role::Manage, Role::View];
    let r = [1u8; 32];
    let (mac_keys, mac) = device("dev-mac", &ALL);
    let recovery_key = RecoveryKit::make(&r, ACCOUNT, Hash32([0; 32])).recovery_key();
    let body = draft_on(
        ACCOUNT,
        &Hash32([0; 32]),
        1,
        &Hash32([0; 32]),
        "dev-mac",
        0,
        &Action::Genesis {
            member: mac,
            recovery_key,
        },
    );
    let genesis = sign_entry(&mac_keys, &KeyId::new("auth"), body).unwrap();
    let genesis_hash = genesis.hash();
    let mut log = Membership::from_genesis(ACCOUNT, &genesis_hash, genesis).unwrap();
    let kit = RecoveryKit::make(&r, ACCOUNT, genesis_hash);
    let mut host_keys = SoftwareKeys::new();
    let host_key = host_keys.generate(KeyId::new("h"), Alg::Ed25519).unwrap();
    apply(
        &mut log,
        "dev-mac",
        &mac_keys,
        &KeyId::new("auth"),
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
        &kit,
        &RecoveryKit::sign_id(),
        Action::RecoveryAdd { member: newmac },
        2,
    );
    log.advance(&clock_at(2 + RECOVERY_WAIT_MS));
    let keys = vec![BackupKey {
        kid: "k1".into(),
        k: zeroize::Zeroizing::new([7; 32]),
    }];
    let env = KBackupEnvelope::seal(ACCOUNT, genesis_hash, 1, &kit.recovery_key(), &keys).unwrap();
    apply(
        &mut log,
        "dev-newmac",
        &newmac_keys,
        &KeyId::new("auth"),
        Action::KBackup(KBackupRecord {
            blob_version: 1,
            kids: vec!["k1".into()],
            recovery_key: kit.recovery_key(),
            backup_hash: env.backup_hash(),
        }),
        3 + RECOVERY_WAIT_MS,
    );
    let accept = signed_accept(
        &host_keys,
        &KeyId::new("h"),
        genesis_hash,
        "host-a",
        log.head(),
    );
    let init = Frame::Init(Init {
        e: accept.e_c,
        n: accept.n_c,
        genesis_hash,
        host_id: accept.host_id.clone(),
        host_trust_gen: accept.host_trust_gen,
    });
    let reply = Frame::Accept(Accept {
        e: accept.e_h,
        n: accept.n_h,
        head: accept.head,
        sig: accept.sig.clone(),
    });
    let entries: Vec<String> = log
        .entries()
        .iter()
        .map(|e| e.object().to_json().to_string())
        .collect();
    let now = at(10 + RECOVERY_WAIT_MS, 10 + RECOVERY_WAIT_MS, "b");
    let session = RestoreSession::read(
        r.to_vec(),
        ACCOUNT.into(),
        genesis_hash.to_hex(),
        kit.kit_tag().to_vec(),
    )
    .unwrap();
    session
        .attempt(
            entries,
            env.jcs(),
            vec![HostAcceptPair {
                init_json: String::from_utf8(init.to_bytes()).unwrap(),
                accept_json: String::from_utf8(reply.to_bytes()).unwrap(),
            }],
            now.clone(),
        )
        .unwrap();
    let restored = session.log().expect("the restore's verified log");
    let saved = restored.stored_json().unwrap();
    let value: Value = serde_json::from_str(&saved).unwrap();
    assert_eq!(value["recovery"][0]["reason"], json!("host_confirmed"));
    let reloaded = MembershipLog::from_stored(
        ACCOUNT.into(),
        genesis_hash.to_hex(),
        saved.clone(),
        now.clone(),
    )
    .unwrap();
    assert_eq!(reloaded.head(), restored.head());
    assert_eq!(reloaded.members(), restored.members());
    assert_eq!(
        reloaded.pending_recovery(now.clone()).unwrap(),
        restored.pending_recovery(now.clone()).unwrap()
    );
    assert_eq!(reloaded.k_backup(), restored.k_backup());
    assert_eq!(reloaded.stored_json().unwrap(), saved);
    // The host's reader still refuses the restore-only reason.
    let mut host_form = value.clone();
    host_form.as_object_mut().unwrap().remove("v");
    assert_eq!(
        Membership::from_stored(ACCOUNT, &genesis_hash, &host_form)
            .unwrap_err()
            .0,
        "recovery reason"
    );
}

/// Fix round 1 (M-1): the snapshot carries its version; a newer or missing
/// one is refused.
#[test]
fn a_snapshot_names_its_version() {
    let v = Vectors::load();
    let log = base(&v);
    let saved = log.stored_json().unwrap();
    let mut value: Value = serde_json::from_str(&saved).unwrap();
    assert_eq!(value["v"], json!(1));
    value["v"] = json!(2);
    assert_eq!(
        stored_code(restore(&value.to_string(), t0()).err().unwrap()),
        "unsupported_version"
    );
    value["v"] = json!("1");
    assert_eq!(
        stored_code(restore(&value.to_string(), t0()).err().unwrap()),
        "unsupported_version"
    );
    value.as_object_mut().unwrap().remove("v");
    assert_eq!(
        stored_code(restore(&value.to_string(), t0()).err().unwrap()),
        "malformed"
    );
}

/// Fix round 1 (L-2): a clock reading above 2^53 − 1 (nanoseconds by
/// mistake) is refused at the boundary, so the log stays exportable.
#[test]
fn a_clock_beyond_the_json_domain_is_refused() {
    let v = Vectors::load();
    let log = base(&v);
    let saved = log.stored_json().unwrap();
    let max = (1u64 << 53) - 1;
    for bad in [at(max + 1, 1, "boot-1"), at(WALL, max + 1, "boot-1")] {
        assert_eq!(code(log.advance(bad.clone()).unwrap_err()), "malformed");
        assert_eq!(
            code(log.pending_recovery(bad.clone()).unwrap_err()),
            "malformed"
        );
        assert_eq!(
            code(log.extend(json_of(&v, &["E7"]), bad.clone()).unwrap_err()),
            "malformed"
        );
        assert_eq!(
            code(restore(&saved, bad.clone()).err().unwrap()),
            "malformed"
        );
        assert!(
            MembershipLog::verify(
                ACCOUNT.into(),
                genesis_hash().to_hex(),
                json_of(&v, &L),
                bad
            )
            .is_err()
        );
    }
    assert_eq!(log.head().seq, 6, "nothing applied");
    assert!(log.advance(at(max, max, "boot-1")).is_ok());
    assert!(log.stored_json().is_ok());
}
