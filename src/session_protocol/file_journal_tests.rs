use super::*;
use crate::session_protocol::journal::{MemJournal, Replayed, Stored};
use serde_json::json;
use std::collections::BTreeMap;

const S1: &str = "ses-aaaaaaaaaaaa";
const S2: &str = "ses-bbbbbbbbbbbb";
const SECRET: &str = "prompt-text-that-must-be-dropped";

fn target(sid: &str) -> Target {
    Target {
        account_id: "account-a".into(),
        atem_device_id: "host-a".into(),
        host_trust_gen: 1,
        session_id: sid.into(),
        process_gen: "22222222-2222-4222-8222-222222222222".into(),
    }
}

fn accepted(id: &str, sid: &str, text: &str) -> Record {
    Record::Accepted {
        request_id: id.into(),
        target: target(sid),
        kind: ReceiptKind::Prompt,
        payload_digest: "0".repeat(64),
        payload: json!({ "text": text }),
        updated_at: 1,
        principal: "astation:account-a:a1".into(),
        control_gen: 1,
    }
}

fn to(id: &str, state: ReceiptState, at: u64) -> Record {
    Record::Transition {
        request_id: id.into(),
        state,
        detail: Some(format!("d{at}")),
        updated_at: at,
    }
}

fn floor(sid: &str, reserved: u64) -> Record {
    Record::LeaseEpochs {
        session_id: sid.into(),
        reserved,
    }
}

fn evicted(id: &str) -> Record {
    Record::Evicted {
        request_id: id.into(),
    }
}

/// A mixed history over two sessions: every state, payload drops, an
/// eviction and lease floors.
fn history() -> Vec<Record> {
    use ReceiptState::*;
    vec![
        floor(S1, 64),
        accepted("a", S1, SECRET),
        accepted("b", S2, "b text"),
        to("a", Executing, 2),
        accepted("c", S1, "still accepted"),
        to("b", Rejected, 3),
        to("a", Completed, 4),
        accepted("d", S2, "d text"),
        to("d", Executing, 5),
        to("d", OutcomeUnknown, 6),
        accepted("e", S1, "e text"),
        to("e", Executing, 7),
        floor(S2, 64),
        floor(S1, 128),
        evicted("b"),
        accepted("f", S2, "f text"),
    ]
}

/// The replayed state with admission order replaced by its rank, so journals
/// that number records differently (compaction) compare equal.
fn state(records: Vec<Record>) -> (BTreeMap<String, Stored>, Vec<(String, u64)>) {
    let Replayed {
        receipts,
        lease_epochs,
        ..
    } = journal::replay(records).unwrap();
    let mut by_order: Vec<Stored> = receipts.into_values().collect();
    by_order.sort_by_key(|s| s.order);
    let receipts = by_order
        .into_iter()
        .enumerate()
        .map(|(i, mut s)| {
            s.order = i as u64;
            (s.request_id.clone(), s)
        })
        .collect();
    let mut floors: Vec<(String, u64)> = lease_epochs.into_iter().collect();
    floors.sort();
    (receipts, floors)
}

fn mem_state(records: &[Record]) -> (BTreeMap<String, Stored>, Vec<(String, u64)>) {
    let mut mem = MemJournal::default();
    for r in records {
        mem.append(r.clone()).unwrap();
    }
    state(mem.load().unwrap())
}

/// The journal's state dir inside a test temp dir (which may not be 0700).
fn sd(dir: &tempfile::TempDir) -> PathBuf {
    dir.path().join("state")
}

fn open(dir: &Path) -> FileJournal {
    FileJournal::open(dir).unwrap()
}

fn log(dir: &Path, sid: &str) -> PathBuf {
    dir.join("receipts").join(format!("{sid}.log"))
}

fn text(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_default()
}

fn mode(path: &Path) -> u32 {
    fs::symlink_metadata(path).unwrap().mode() & 0o777
}

#[test]
fn crc32_matches_the_ieee_check_value() {
    assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    assert_eq!(crc32(b""), 0);
}

#[test]
fn reload_equals_the_in_memory_state() {
    let dir = tempfile::tempdir().unwrap();
    let records = history();
    let expected = mem_state(&records);
    let mut j = open(&sd(&dir));
    for r in &records {
        j.append(r.clone()).unwrap();
    }
    assert_eq!(state(j.load().unwrap()), expected);
    drop(j);
    let mut j = open(&sd(&dir));
    assert_eq!(state(j.load().unwrap()), expected);
    // Compacted, then reopened: still the same state, and appends go on.
    j.compact_all().unwrap();
    assert_eq!(state(j.load().unwrap()), expected);
    drop(j);
    let mut j = open(&sd(&dir));
    assert_eq!(state(j.load().unwrap()), expected);
    let more = [
        to("c", ReceiptState::Executing, 8),
        to("e", ReceiptState::Completed, 9),
    ];
    let mut all = records.clone();
    for r in more {
        j.append(r.clone()).unwrap();
        all.push(r);
    }
    drop(j);
    assert_eq!(state(open(&sd(&dir)).load().unwrap()), mem_state(&all));
}

#[test]
fn load_keeps_the_append_order_across_sessions() {
    let dir = tempfile::tempdir().unwrap();
    let mut j = open(&sd(&dir));
    for (id, sid) in [("x", S2), ("y", S1), ("z", S2)] {
        j.append(accepted(id, sid, "t")).unwrap();
    }
    let ids: Vec<String> = j
        .load()
        .unwrap()
        .into_iter()
        .map(|r| match r {
            Record::Accepted { request_id, .. } => request_id,
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(ids, ["x", "y", "z"]);
}

#[test]
fn a_torn_last_record_is_truncated_and_earlier_ones_kept() {
    let dir = tempfile::tempdir().unwrap();
    let mut j = open(&sd(&dir));
    let records = &history()[..4];
    for r in records {
        j.append(r.clone()).unwrap();
    }
    drop(j);
    let path = log(&sd(&dir), S1);
    let good = fs::metadata(&path).unwrap().len();
    let line = encode(99, to("a", ReceiptState::Completed, 9)).unwrap();
    let mut f = OpenOptions::new().append(true).open(&path).unwrap();
    f.write_all(&line[..line.len() - 3]).unwrap();
    drop(f);

    let mut j = open(&sd(&dir));
    assert_eq!(fs::metadata(&path).unwrap().len(), good);
    assert_eq!(state(j.load().unwrap()), mem_state(records));
    // The journal goes on after the cut.
    j.append(to("a", ReceiptState::Completed, 9)).unwrap();
    drop(j);
    let mut all = records.to_vec();
    all.push(to("a", ReceiptState::Completed, 9));
    assert_eq!(state(open(&sd(&dir)).load().unwrap()), mem_state(&all));
}

#[test]
fn a_corrupted_middle_record_truncates_the_log_there() {
    let dir = tempfile::tempdir().unwrap();
    drop(open(&sd(&dir)));
    let records = [
        accepted("a", S1, "one"),
        accepted("c", S1, "two"),
        to("a", ReceiptState::Executing, 2),
        to("c", ReceiptState::Rejected, 3),
    ];
    let path = log(&sd(&dir), S1);
    let mut bytes = Vec::new();
    for (seq, r) in records.iter().enumerate() {
        bytes.extend(encode(seq as u64 + 1, r.clone()).unwrap());
    }
    let first_end = bytes.iter().position(|&b| b == b'\n').unwrap() + 1;
    // Flip one byte inside the second record's JSON (checksum mismatch).
    let at = first_end + 30;
    bytes[at] ^= 0x01;
    fs::write(&path, &bytes).unwrap();

    let j = open(&sd(&dir));
    assert_eq!(fs::metadata(&path).unwrap().len(), first_end as u64);
    assert_eq!(state(j.load().unwrap()), mem_state(&records[..1]));
}

#[test]
fn a_record_naming_another_session_or_going_back_in_seq_is_not_trusted() {
    let dir = tempfile::tempdir().unwrap();
    drop(open(&sd(&dir)));
    let path = log(&sd(&dir), S1);
    let mut bytes = encode(5, accepted("a", S1, "t")).unwrap();
    let good = bytes.len() as u64;
    bytes.extend(encode(6, accepted("b", S2, "t")).unwrap());
    bytes.extend(encode(7, accepted("c", S1, "t")).unwrap());
    fs::write(&path, &bytes).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    drop(open(&sd(&dir)));
    assert_eq!(fs::metadata(&path).unwrap().len(), good);

    let mut bytes = encode(5, accepted("a", S1, "t")).unwrap();
    bytes.extend(encode(4, to("a", ReceiptState::Executing, 2)).unwrap());
    fs::write(&path, &bytes).unwrap();
    drop(open(&sd(&dir)));
    assert_eq!(fs::metadata(&path).unwrap().len(), good);
}

#[test]
fn a_failed_fsync_or_write_stops_every_later_append() {
    for fault in [Fault::Fsync, Fault::Write] {
        let dir = tempfile::tempdir().unwrap();
        let mut j = open(&sd(&dir));
        j.append(accepted("a", S1, "t")).unwrap();
        let path = log(&sd(&dir), S1);
        let len = fs::metadata(&path).unwrap().len();
        j.inject(fault);
        assert!(j.append(to("a", ReceiptState::Executing, 2)).is_err());
        assert!(j.failed().is_some());
        // No admission afterwards, in any session.
        assert!(j.append(to("a", ReceiptState::Rejected, 3)).is_err());
        assert!(j.append(accepted("b", S2, "t")).is_err());
        assert!(j.append(floor(S2, 64)).is_err());
        // The failed record was cut back off.
        assert_eq!(fs::metadata(&path).unwrap().len(), len, "{fault:?}");
        drop(j);
        // A restart reloads and appends again.
        let mut j = open(&sd(&dir));
        assert!(j.failed().is_none());
        assert_eq!(
            state(j.load().unwrap()),
            mem_state(&[accepted("a", S1, "t")])
        );
        j.append(to("a", ReceiptState::Rejected, 3)).unwrap();
    }
}

#[test]
fn caller_errors_do_not_fail_the_journal() {
    let dir = tempfile::tempdir().unwrap();
    let mut j = open(&sd(&dir));
    assert!(j.append(to("nope", ReceiptState::Executing, 2)).is_err());
    assert!(j.append(evicted("nope")).is_err());
    assert!(j.append(accepted("a", "../escape", "t")).is_err());
    j.append(accepted("a", S1, "t")).unwrap();
    assert!(j.append(accepted("a", S1, "t")).is_err());
    assert!(j.failed().is_none());
    j.append(to("a", ReceiptState::Executing, 2)).unwrap();
}

#[test]
fn a_log_with_nothing_live_is_removed_by_compaction() {
    let dir = tempfile::tempdir().unwrap();
    let mut j = open(&sd(&dir));
    j.append(accepted("a", S2, "t")).unwrap();
    j.append(to("a", ReceiptState::Rejected, 2)).unwrap();
    j.append(evicted("a")).unwrap();
    j.compact_all().unwrap();
    assert!(!log(&sd(&dir), S2).exists());
    // The request id is free again, and its session log comes back.
    j.append(accepted("a", S2, "t")).unwrap();
    drop(j);
    assert_eq!(
        state(open(&sd(&dir)).load().unwrap()),
        mem_state(&[accepted("a", S2, "t")])
    );
}

#[test]
fn a_large_log_is_compacted_on_append() {
    let dir = tempfile::tempdir().unwrap();
    let mut j = open(&sd(&dir)).with_compact_threshold(4096);
    let mut all = Vec::new();
    for n in 0..200 {
        let id = format!("r{n}");
        for r in [
            accepted(&id, S1, &"x".repeat(200)),
            to(&id, ReceiptState::Rejected, n),
            evicted(&id),
        ] {
            j.append(r.clone()).unwrap();
            all.push(r);
        }
    }
    j.append(floor(S1, 64)).unwrap();
    all.push(floor(S1, 64));
    let len = fs::metadata(log(&sd(&dir), S1)).map_or(0, |m| m.len());
    assert!(len <= 4096 + 1024, "log stays bounded: {len}");
    drop(j);
    assert_eq!(state(open(&sd(&dir)).load().unwrap()), mem_state(&all));
}

#[test]
fn lease_floors_never_decrease_across_reloads_and_compaction() {
    let dir = tempfile::tempdir().unwrap();
    let mut j = open(&sd(&dir));
    for reserved in [64, 192, 128] {
        j.append(floor(S1, reserved)).unwrap();
    }
    drop(j);
    let mut j = open(&sd(&dir));
    let floors = |j: &FileJournal| state(j.load().unwrap()).1;
    assert_eq!(floors(&j), vec![(S1.to_string(), 192)]);
    j.compact_all().unwrap();
    j.append(floor(S1, 64)).unwrap();
    drop(j);
    let mut j = open(&sd(&dir));
    assert_eq!(floors(&j), vec![(S1.to_string(), 192)]);
    j.compact_all().unwrap();
    drop(j);
    assert_eq!(floors(&open(&sd(&dir))), vec![(S1.to_string(), 192)]);
}

#[test]
fn files_are_private_and_symlinks_refused() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("state");
    let mut j = open(&state_dir);
    j.append(accepted("a", S1, "t")).unwrap();
    j.compact_all().unwrap();
    j.append(to("a", ReceiptState::Executing, 2)).unwrap();
    assert_eq!(mode(&state_dir), 0o700);
    assert_eq!(mode(&state_dir.join("receipts")), 0o700);
    assert_eq!(mode(&log(&state_dir, S1)), 0o600);
    assert_eq!(mode(&state_dir.join("journal.lock")), 0o600);
    drop(j);

    // A symlinked state dir, an open one, or a symlinked log is refused.
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&state_dir, &link).unwrap();
    assert!(FileJournal::open(&link).is_err());
    let open_dir = dir.path().join("open");
    fs::create_dir(&open_dir).unwrap();
    fs::set_permissions(&open_dir, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(FileJournal::open(&open_dir).is_err());
    let victim = dir.path().join("victim");
    fs::write(&victim, b"").unwrap();
    std::os::unix::fs::symlink(&victim, log(&state_dir, S2)).unwrap();
    assert!(FileJournal::open(&state_dir).is_err());
}

#[test]
fn one_journal_per_state_dir() {
    let dir = tempfile::tempdir().unwrap();
    let j = open(&sd(&dir));
    assert!(FileJournal::open(&sd(&dir)).is_err());
    drop(j);
    open(&sd(&dir));
}

#[test]
fn compaction_drops_payloads_and_evicted_receipts_and_keeps_finals_and_floors() {
    let dir = tempfile::tempdir().unwrap();
    let mut j = open(&sd(&dir));
    let records = history();
    for r in &records {
        j.append(r.clone()).unwrap();
    }
    j.compact_all().unwrap();
    let s1 = text(&log(&sd(&dir), S1));
    let s2 = text(&log(&sd(&dir), S2));
    // `a` left accepted: payload gone, digest and final state kept.
    assert!(!s1.contains(SECRET));
    assert!(s1.contains("\"completed\""));
    // `c` is still accepted: its payload stays for a dispatch after a crash.
    assert!(s1.contains("still accepted"));
    // Floors live in their own file, the highest per session.
    assert!(!s1.contains("lease_epochs") && !s2.contains("lease_epochs"));
    let floors = text(&sd(&dir).join("floors"));
    assert!(floors.contains(&format!("\"{S1}\":128")), "{floors}");
    assert!(floors.contains(&format!("\"{S2}\":64")), "{floors}");
    // `b` was evicted: gone with its records.
    assert!(!s2.contains("\"b\""));
    assert!(!s2.contains("evicted"));
    assert!(s2.contains("\"outcome_unknown\""));
    assert_eq!(state(j.load().unwrap()), mem_state(&records));
}

#[test]
fn a_finished_prompt_leaves_no_text_on_disk() {
    let dir = tempfile::tempdir().unwrap();
    let mut j = open(&sd(&dir));
    j.append(accepted("a", S1, SECRET)).unwrap();
    j.append(accepted("c", S1, "still accepted")).unwrap();
    assert!(text(&log(&sd(&dir), S1)).contains(SECRET));
    // The transition out of `accepted` takes the text off the disk at once.
    j.append(to("a", ReceiptState::Executing, 2)).unwrap();
    let s1 = text(&log(&sd(&dir), S1));
    assert!(!s1.contains(SECRET), "{s1}");
    assert!(s1.contains("still accepted"));
    // Rejected straight from `accepted`, and evicted: same.
    j.append(accepted("d", S2, SECRET)).unwrap();
    j.append(to("d", ReceiptState::Rejected, 3)).unwrap();
    assert!(!text(&log(&sd(&dir), S2)).contains(SECRET));
    drop(j);

    // A log left with a finished prompt's text (a crash before the rewrite)
    // is rewritten when the journal opens.
    let path = log(&sd(&dir), S2);
    let mut bytes = encode(50, accepted("e", S2, SECRET)).unwrap();
    bytes.extend(encode(51, to("e", ReceiptState::Rejected, 4)).unwrap());
    fs::write(&path, &bytes).unwrap();
    let j = open(&sd(&dir));
    assert!(!text(&path).contains(SECRET));
    assert_eq!(
        j.load()
            .unwrap()
            .iter()
            .filter(|r| matches!(r, Record::Accepted { request_id, .. } if request_id == "e"))
            .count(),
        1
    );
}

#[test]
fn a_session_with_every_receipt_evicted_leaves_no_log_and_no_handle() {
    let dir = tempfile::tempdir().unwrap();
    let mut j = open(&sd(&dir));
    j.append(floor(S2, 64)).unwrap();
    j.append(accepted("a", S2, "t")).unwrap();
    j.append(accepted("b", S1, "t")).unwrap();
    assert_eq!(j.open_handles(), 2);
    j.append(to("a", ReceiptState::Rejected, 2)).unwrap();
    j.append(evicted("a")).unwrap();
    assert!(!log(&sd(&dir), S2).exists());
    assert_eq!(j.open_handles(), 1);
    drop(j);
    let j = open(&sd(&dir));
    assert!(!log(&sd(&dir), S2).exists());
    assert_eq!(state(j.load().unwrap()).1, vec![(S2.to_string(), 64)]);
}

#[test]
fn compaction_backs_off_as_the_live_state_grows() {
    let dir = tempfile::tempdir().unwrap();
    let mut j = open(&sd(&dir)).with_compact_threshold(1024);
    // Live receipts without payload text: every compaction keeps them all.
    for n in 0..400 {
        j.append(Record::Accepted {
            request_id: format!("i{n}"),
            target: target(S1),
            kind: ReceiptKind::Interrupt,
            payload_digest: "0".repeat(64),
            payload: json!({}),
            updated_at: n,
            principal: "p1".into(),
            control_gen: 1,
        })
        .unwrap();
    }
    assert!(j.compactions() <= 12, "{} compactions", j.compactions());
}

#[test]
fn an_invalid_transition_truncates_instead_of_failing_the_load() {
    let dir = tempfile::tempdir().unwrap();
    drop(open(&sd(&dir)));
    let path = log(&sd(&dir), S1);
    let mut bytes = encode(5, accepted("a", S1, "t")).unwrap();
    let good = bytes.len() as u64;
    bytes.extend(encode(6, to("a", ReceiptState::Completed, 2)).unwrap());
    bytes.extend(encode(7, to("a", ReceiptState::Executing, 3)).unwrap());
    fs::write(&path, &bytes).unwrap();
    let j = open(&sd(&dir));
    assert_eq!(fs::metadata(&path).unwrap().len(), good);
    assert_eq!(
        state(j.load().unwrap()),
        mem_state(&[accepted("a", S1, "t")])
    );
}

#[test]
fn a_failed_undo_is_retried_on_refused_appends_and_on_drop() {
    for retry_on_drop in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let mut j = open(&sd(&dir));
        j.append(accepted("a", S1, "t")).unwrap();
        let path = log(&sd(&dir), S1);
        let len = fs::metadata(&path).unwrap().len();
        j.inject(Fault::FsyncAndUndo);
        assert!(j.append(accepted("b", S1, "t")).is_err());
        assert!(fs::metadata(&path).unwrap().len() > len, "undo failed");
        if retry_on_drop {
            drop(j);
        } else {
            assert!(j.append(accepted("c", S1, "t")).is_err());
            assert_eq!(fs::metadata(&path).unwrap().len(), len);
            drop(j);
        }
        assert_eq!(fs::metadata(&path).unwrap().len(), len);
        let j = open(&sd(&dir));
        assert_eq!(
            state(j.load().unwrap()),
            mem_state(&[accepted("a", S1, "t")])
        );
    }
}

#[test]
fn a_crash_during_compaction_leaves_a_valid_log() {
    for fault in [Fault::CrashBeforeRename, Fault::CrashAfterRename] {
        let dir = tempfile::tempdir().unwrap();
        let records = [
            accepted("a", S1, SECRET),
            accepted("c", S1, "still accepted"),
            to("a", ReceiptState::Executing, 2),
        ];
        let mut j = open(&sd(&dir));
        j.append(records[0].clone()).unwrap();
        j.append(records[1].clone()).unwrap();
        j.inject(fault);
        // The record is durable; the rewrite after it "crashed".
        j.append(records[2].clone()).unwrap();
        assert!(j.failed().is_some(), "{fault:?}");
        assert!(j.append(floor(S1, 192)).is_err());
        drop(j);
        let tmp = sd(&dir).join("receipts").join(format!("{S1}{TMP_SUFFIX}"));
        assert_eq!(tmp.exists(), fault == Fault::CrashBeforeRename, "{fault:?}");
        assert_eq!(
            text(&log(&sd(&dir), S1)).contains(SECRET),
            fault == Fault::CrashBeforeRename
        );
        let j = open(&sd(&dir));
        assert!(!tmp.exists(), "leftover temp removed on open");
        assert!(
            !text(&log(&sd(&dir), S1)).contains(SECRET),
            "rewritten on open"
        );
        assert_eq!(state(j.load().unwrap()), mem_state(&records), "{fault:?}");
    }
}
