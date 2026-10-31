//! The durable form of a host's log (§R9.3 `membership.json`): it reads
//! back as the same state, and anything that doesn't match the entries is
//! refused rather than guessed.
mod support;

use atem_client::membership::Membership;
use serde_json::{Value, json};
use support::*;

fn pinned(v: &Vectors, labels: &[&str], clock: &Clock) -> Membership {
    let entries: Vec<_> = labels.iter().map(|l| v.entry(l)).collect();
    Membership::verify_chain(ACCOUNT, &v.hash("E1"), &entries, &clock.now)
        .unwrap()
        .membership
}

fn carry(m: &Membership, v: &Vectors, labels: &[&str], clock: &Clock) -> Membership {
    let carried: Vec<_> = labels.iter().map(|l| strict(v.wire(l))).collect();
    m.evaluate(&carried, &clock.now).next
}

fn back(m: &Membership, stored: &Value) -> Result<Membership, String> {
    Membership::from_stored(m.account_id(), &m.genesis_hash(), stored).map_err(|e| e.0)
}

#[test]
fn a_stored_log_reads_back_unchanged() {
    let v = Vectors::load();
    let mut clock = Clock::at(1_793_264_000_000);
    let base = pinned(&v, &["E1", "E2", "E3", "E4", "E5", "E6"], &clock);
    // Evidence (an ignored conflict), a pending recovery, then its approval.
    let ignored = carry(&base, &v, &["C6_ipad"], &clock);
    assert_eq!(ignored.evidence().count, 1);
    let pending = carry(&ignored, &v, &["R7"], &clock);
    assert_eq!(pending.records().len(), 1);
    clock.advance(60_000);
    let mut checkpointed = pending.clone();
    checkpointed.checkpoint(&clock.now);
    let approved = carry(&checkpointed, &v, &["A8"], &clock);
    let frozen = carry(&base, &v, &["C6_mac"], &clock);
    assert!(frozen.frozen().is_some());
    for m in [&base, &ignored, &pending, &checkpointed, &approved, &frozen] {
        let stored = m.to_stored();
        assert_eq!(&back(m, &stored).unwrap(), m);
        // Through bytes, as the file is.
        let text = serde_json::to_string(&stored).unwrap();
        let reread: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(&back(m, &reread).unwrap(), m);
    }
}

#[test]
fn a_stored_log_that_doesnt_match_its_entries_is_refused() {
    let v = Vectors::load();
    let clock = Clock::at(1_793_264_000_000);
    let base = pinned(&v, &["E1", "E2", "E3", "E4", "E5", "E6"], &clock);
    let m = carry(&base, &v, &["R7"], &clock);
    let stored = m.to_stored();
    let refused = |change: &dyn Fn(&mut Value), why: &str| {
        let mut s = stored.clone();
        change(&mut s);
        assert!(back(&m, &s).is_err(), "{why} was accepted");
    };
    refused(
        &|s| s["head"]["seq"] = json!(6),
        "a head behind the entries",
    );
    refused(
        &|s| {
            s["entries"].as_array_mut().unwrap().pop();
        },
        "a missing entry",
    );
    refused(
        &|s| {
            let sig = s["entries"][3]["sig"].as_str().unwrap().to_owned();
            let mut bytes: Vec<char> = sig.chars().collect();
            bytes[5] = if bytes[5] == 'A' { 'B' } else { 'A' };
            s["entries"][3]["sig"] = json!(bytes.into_iter().collect::<String>());
        },
        "a bad signature",
    );
    refused(
        &|s| s["recovery"][0]["state"] = json!("active"),
        "a decision without its fields",
    );
    refused(
        &|s| {
            s["recovery"].as_array_mut().unwrap().clear();
        },
        "a pending entry without its record",
    );
    refused(
        &|s| {
            let extra = s["recovery"][0].clone();
            s["recovery"].as_array_mut().unwrap().push(extra);
        },
        "a second record",
    );
    refused(
        &|s| s["recovery_key"] = s["entries"][1]["body"]["member"]["auth_key"].clone(),
        "another recovery key",
    );
    refused(
        &|s| s["account_id"] = json!("acct-other"),
        "another account",
    );
    // A stored entry the chain before it doesn't support (E6 removes the
    // iPad, which then signs X7_ipad): the replay refuses it.
    refused(
        &|s| {
            let entries = s["entries"].as_array_mut().unwrap();
            entries.truncate(6);
            entries.push(v.wire("X7_ipad").clone());
            s["recovery"] = json!([]);
            s["head"] = json!({"seq": 7, "hash": v.hash("X7_ipad").to_hex()});
        },
        "an entry its signer couldn't sign",
    );
}
