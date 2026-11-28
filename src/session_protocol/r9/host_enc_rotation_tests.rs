//! The routine rotation of the host's encryption key on the host (agreed
//! with Astation on 2026-11-23, #120 comment 7089435308; `host_enc`): the
//! pending key a manager's `host_enc_key_new` gets, its stamp before the
//! device list commits the entry that sets it, its promotion, the previous
//! key's 24 h window on the delegated clock (`D`) and its retirement, the
//! record of retired key ids, and the receiver's view, which follows the
//! committed list only. Each crash point is a test: the files a crash
//! leaves, read again as a restart reads them.
use super::HostKey;
use super::host_enc::{self, RETAIN_MS};
use crate::paths::PairingPaths;
use crate::session_protocol::membership::r9log::{MAC, TestLog, secret};
use crate::session_protocol::membership::store::{DlFile, Injected, Step, Store};
use crate::session_protocol::membership::{HostPin, MembershipHost, journal_of};
use atem_client::encoding::{b64u_decode, hex};
use atem_client::membership::{Membership, sign_host_enc_key, verify_host_enc_sig};
use atem_client::{Alg, KeyProvider, PublicKey};
use serde_json::{Value, json};

const ACCOUNT: &str = "acct-rot";
const HOST: &str = "host-rot";
const SEED: &str = "rot host";
/// The delegated clock's `D` when the rotation's entry applies.
const D0: u64 = 1_800_000_000_000;
const HOUR: u64 = 3_600_000;
const REQUEST: &str = "aaaaaaaa-0000-4000-8000-00000000f001";

/// A pinned host whose list set the key it made at the pin (its current
/// key), with the keys a manager signs with.
struct Rot {
    _dir: tempfile::TempDir,
    pairing: PairingPaths,
    log: TestLog,
    host_key: HostKey,
}

fn rot() -> Rot {
    let mut r = unset_rot();
    let current = pub_of(&r, "current");
    set(&mut r, &current, false);
    r
}

/// A pinned host holding the key it made at the pin, no entry having set
/// it yet (its first key, or a key the list hasn't caught up with).
fn unset_rot() -> Rot {
    let dir = tempfile::tempdir().unwrap();
    let pairing = crate::profile::Sources::in_dir(dir.path()).paths.pairing;
    let mut log = TestLog::genesis(ACCOUNT, &secret("rot astation"));
    log.add_host(HOST, 1, &secret(SEED));
    let pin = HostPin {
        host_id: HOST.into(),
        host_trust_gen: 1,
    };
    MembershipHost::pin(
        &pairing,
        &journal_of(&pairing),
        &pin,
        &log.log,
        &secret(SEED),
    )
    .unwrap();
    assert_eq!(
        host_enc::ensure(&pairing, &journal_of(&pairing), 1).len(),
        1
    );
    Rot {
        _dir: dir,
        pairing,
        log,
        host_key: HostKey::new(&secret(SEED)),
    }
}

fn dl_store(r: &Rot) -> Store {
    Store::new(&r.pairing, &journal_of(&r.pairing))
}

fn file(r: &Rot) -> Value {
    serde_json::from_slice(&std::fs::read(&r.pairing.host_enc_key).unwrap()).unwrap()
}

fn record(r: &Rot) -> Value {
    serde_json::from_slice(&std::fs::read(&r.pairing.host_enc_generated).unwrap()).unwrap()
}

/// The public half (32 bytes) the key file holds in `slot`.
fn pub_of(r: &Rot, slot: &str) -> [u8; 32] {
    let f = file(r);
    b64u_decode(
        f[slot]["pub"]
            .as_str()
            .unwrap_or_else(|| panic!("{slot}: {f}")),
    )
    .unwrap()
    .try_into()
    .unwrap()
}

fn kid(public: &[u8; 32]) -> String {
    atem_client::keys::enc_kid(&PublicKey::new(Alg::X25519, public).unwrap()).unwrap()
}

/// A manager's `host_enc_key` entry setting `public` (the host's `enc_sig`
/// over it), signed into the list.
fn set(r: &mut Rot, public: &[u8; 32], retire_previous: bool) {
    let sig = sign_host_enc_key(
        &r.host_key.keys,
        &r.host_key.id,
        ACCOUNT,
        &r.log.genesis_hash(),
        HOST,
        1,
        public,
    )
    .unwrap();
    let action = atem_client::membership::host_enc_key(
        HOST,
        1,
        &PublicKey::new(Alg::X25519, public).unwrap(),
        &sig,
        retire_previous,
        1,
    )
    .unwrap();
    r.log.append(MAC, action);
}

/// `host_enc_key_new`'s durable part, under a fresh `request_id`: the key
/// handed out, its public half.
fn new_key(r: &Rot) -> Result<([u8; 32], Vec<String>), String> {
    new_key_as(r, &uuid::Uuid::new_v4().to_string())
}

/// `host_enc_key_new` under `request_id`.
fn new_key_as(r: &Rot, request_id: &str) -> Result<([u8; 32], Vec<String>), String> {
    let mut store = dl_store(r);
    host_enc::new_pending(
        &mut store,
        &r.pairing,
        &r.log.log,
        &r.host_key,
        HOST,
        1,
        request_id,
    )
    .map(|(key, sig, lines)| {
        // The host vouches for it at its generation.
        verify_host_enc_sig(
            &r.log.log.host(HOST).unwrap().host_key,
            ACCOUNT,
            &r.log.genesis_hash(),
            HOST,
            1,
            key.enc_pub(),
            &sig,
        )
        .unwrap();
        (*key.enc_pub(), lines)
    })
}

/// The list committing a rotation to `pending` (`retire_previous` as
/// given), the stamp written before it at `d` (none: the stamp never ran,
/// as when a crash came before the hook or `D` couldn't be read).
fn commit_rotation(r: &mut Rot, pending: &[u8; 32], retire_previous: bool, d: Option<u64>) {
    let prev = r.log.log.clone();
    set(r, pending, retire_previous);
    if let Some(d) = d {
        stamp(r, &prev, d);
    }
}

/// The delegated clock's mark these tests run under (no repair, lowering
/// or fresh start since a stamp).
const MARK: u64 = 7;
/// The boot these tests run on, as its mark (`host_clock::boot_mark`).
const BOOT: u64 = 0xb007;
/// The boot-time counter when the rotation's entry applies (at `D0`).
const B0: u64 = 5_000_000;

/// `D` = `d`, the clock's mark unchanged, on the same boot, the boot-time
/// counter keeping pace with `D` from `D0` (a true clock).
fn at(d: u64) -> host_enc::DNow {
    at_boot(d, BOOT, (B0 + d).saturating_sub(D0))
}

/// `D` = `d`, the clock's mark unchanged, the boot-time counter reading
/// `ms` on the boot `boot`.
fn at_boot(d: u64, boot: u64, ms: u64) -> host_enc::DNow {
    host_enc::DNow {
        d_ms: d,
        clock: MARK,
        boot: Some(host_enc::BootAt { boot, ms }),
    }
}

fn stamp(r: &Rot, prev: &Membership, d: u64) -> Vec<String> {
    let mut store = dl_store(r);
    host_enc::stamp_application_locked(&mut store, prev, &r.log.log, HOST, 1, Some(at(d)))
}

fn reconcile(r: &Rot, d: Option<u64>) -> Result<host_enc::Reconciled, String> {
    host_enc::reconcile(&r.pairing, HOST, 1, &r.log.log, d.map(at))
}

/// The receiver's view at `d`: the accepted kids (hex) and the generated
/// ones, each checked against the provider.
fn view(r: &Rot, d: u64) -> (Vec<String>, Vec<String>) {
    let got = host_enc::recipient_at(&r.pairing, HOST.into(), 1, &r.log.log, Some(at(d))).unwrap();
    for (id, k) in &got.recipient.keys {
        let public = got.provider.public_key(id).unwrap();
        assert_eq!(atem_client::keys::enc_kid_bytes(&public).unwrap(), *k);
    }
    (
        got.recipient.keys.iter().map(|(_, k)| hex(k)).collect(),
        got.recipient.generated.iter().map(|k| hex(k)).collect(),
    )
}

/// The receiver's accepted kids (hex) at `now`.
fn accepted_at(r: &Rot, now: host_enc::DNow) -> Vec<String> {
    let got = host_enc::recipient_at(&r.pairing, HOST.into(), 1, &r.log.log, Some(now)).unwrap();
    got.recipient.keys.iter().map(|(_, k)| hex(k)).collect()
}

fn retired(r: &Rot) -> Vec<String> {
    record(r)["retired"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k.as_str().unwrap().to_owned())
        .collect()
}

/// A manager's request makes a pending key: its id durably in the record
/// first (v2, with the retired ids), then the key file (v2) with the
/// current key and the pending one; `host_enc_key_get` still hands out the
/// current key, a pure read.
#[test]
fn a_new_key_is_recorded_then_kept_pending() {
    let r = rot();
    let current = pub_of(&r, "current");
    let (pending, lines) = new_key_as(&r, REQUEST).unwrap();
    assert_ne!(pending, current);
    assert!(
        lines.iter().any(|l| l.contains(&kid(&pending))),
        "{lines:?}"
    );
    assert_eq!(
        record(&r),
        json!({"v": 2, "host_trust_gen": 1, "kids": [kid(&current), kid(&pending)], "retired": [],
            "requests": [{"request_id": REQUEST, "kid": kid(&pending),
                "pub": atem_client::encoding::b64u(&pending)}]})
    );
    let f = file(&r);
    assert_eq!(f["v"], 2);
    assert_eq!(
        f.as_object().unwrap().keys().collect::<Vec<_>>(),
        ["current", "host_trust_gen", "pending", "v"]
    );
    assert_eq!(pub_of(&r, "pending"), pending);
    assert!(f["pending"].get("applied").is_none());
    let mut store = dl_store(&r);
    let (got, _, _) =
        host_enc::hand_out(&mut store, &r.pairing, &r.log.log, &r.host_key, HOST, 1).unwrap();
    assert_eq!(*got.enc_pub(), current, "the get hands out the current key");
}

/// One pending key per generation: a second request (another manager, or
/// a retry after a lost answer) gets the same key; the key file isn't
/// written again, only the record of the requests answered.
#[test]
fn one_pending_key_per_generation() {
    let r = rot();
    let (first, _) = new_key(&r).unwrap();
    let before = (file(&r), record(&r)["kids"].clone());
    let (second, _) = new_key(&r).unwrap();
    assert_eq!(second, first);
    assert_eq!((file(&r), record(&r)["kids"].clone()), before);
    assert_eq!(record(&r)["requests"].as_array().unwrap().len(), 2);
}

/// The draw never offers a key this host made in the generation (its
/// record) nor one the committed list set since its `add_host`: such a
/// draw is thrown away and drawn again.
#[test]
fn a_new_key_is_never_one_made_or_set_before() {
    let mut r = rot();
    // A key the list set and then rotated away (no longer held), and the
    // current key: both drawn first, both refused.
    let (rotated, _) = new_key(&r).unwrap();
    commit_rotation(&mut r, &rotated, true, Some(D0));
    reconcile(&r, Some(D0)).unwrap();
    let old_secret = secret("rot old drawn");
    let old_pub = x25519_pub(&old_secret);
    set(&mut r, &old_pub, false);
    let made = secret("rot drawn fresh");
    host_enc::DRAWS.with(|d| {
        d.borrow_mut()
            .extend([secret_of_current(&r), old_secret, made])
    });
    let (drawn, _) = new_key(&r).unwrap();
    assert_eq!(drawn, x25519_pub(&made));
    assert!(host_enc::DRAWS.with(|d| d.borrow().is_empty()));
}

fn x25519_pub(secret: &[u8; 32]) -> [u8; 32] {
    *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*secret)).as_bytes()
}

fn secret_of_current(r: &Rot) -> [u8; 32] {
    b64u_decode(file(r)["current"]["secret"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

/// Crash point: after the kid record, before `pending` (here a failed key
/// file write, as the crash leaves it): `busy`, nothing handed out; the id
/// stays recorded (a key made, never handed out, so no mail names it) and
/// the next request makes another key.
#[test]
fn a_crash_after_the_record_before_pending_hands_out_nothing() {
    let r = rot();
    for step in [Step::TempWrite, Step::TempFsync, Step::Rename] {
        let mut store = dl_store(&r);
        store.inject(Injected {
            file: DlFile::HostEncKey,
            step,
        });
        assert!(
            host_enc::new_pending(
                &mut store,
                &r.pairing,
                &r.log.log,
                &r.host_key,
                HOST,
                1,
                &uuid::Uuid::new_v4().to_string()
            )
            .is_err(),
            "{step:?}"
        );
        assert!(file(&r).get("pending").is_none(), "{step:?}");
    }
    assert_eq!(
        record(&r)["kids"].as_array().unwrap().len(),
        4,
        "1 + 3 made"
    );
    // A record that can't be written: nothing is written at all.
    let before = file(&r);
    let mut store = dl_store(&r);
    store.inject(Injected {
        file: DlFile::HostEncGenerated,
        step: Step::TempWrite,
    });
    assert!(
        host_enc::new_pending(
            &mut store,
            &r.pairing,
            &r.log.log,
            &r.host_key,
            HOST,
            1,
            &uuid::Uuid::new_v4().to_string()
        )
        .is_err()
    );
    assert_eq!(file(&r), before);
    let (pending, _) = new_key(&r).unwrap();
    assert_eq!(pub_of(&r, "pending"), pending);
    assert_eq!(record(&r)["kids"].as_array().unwrap().len(), 5);
}

/// Crash point: after `pending`, before the answer: the files hold the
/// key, so a retry after the restart (a lost answer) gets that same key.
#[test]
fn a_crash_after_pending_before_the_answer_gets_the_same_key_again() {
    let r = rot();
    let mut store = dl_store(&r);
    let made = host_enc::new_pending(
        &mut store,
        &r.pairing,
        &r.log.log,
        &r.host_key,
        HOST,
        1,
        &uuid::Uuid::new_v4().to_string(),
    )
    .unwrap();
    let made = *made.0.enc_pub();
    drop(store);
    let (again, _) = new_key(&r).unwrap();
    assert_eq!(again, made);
}

/// A pending key is no accepted key: the receiver accepts the list's
/// current key only, and the pending one is among the keys made (mail
/// naming it waits for the list beyond its head).
#[test]
fn the_pending_key_is_no_accepted_key() {
    let r = rot();
    let current = pub_of(&r, "current");
    let (pending, _) = new_key(&r).unwrap();
    let (keys, generated) = view(&r, D0);
    assert_eq!(keys, [kid(&current)]);
    assert_eq!(generated, [kid(&current), kid(&pending)]);
}

/// A key the list never set is no accepted key either, current in the
/// file or not (committed-list authority).
#[test]
fn a_key_the_list_never_set_is_not_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let pairing = crate::profile::Sources::in_dir(dir.path()).paths.pairing;
    let mut log = TestLog::genesis(ACCOUNT, &secret("rot astation"));
    log.add_host(HOST, 1, &secret(SEED));
    MembershipHost::pin(
        &pairing,
        &journal_of(&pairing),
        &HostPin {
            host_id: HOST.into(),
            host_trust_gen: 1,
        },
        &log.log,
        &secret(SEED),
    )
    .unwrap();
    host_enc::ensure(&pairing, &journal_of(&pairing), 1);
    let got = host_enc::recipient_at(&pairing, HOST.into(), 1, &log.log, Some(at(D0))).unwrap();
    assert!(got.recipient.keys.is_empty());
    assert_eq!(got.recipient.generated.len(), 1, "made, so its mail waits");
}

/// The rotation's entry commits (its stamp written first at `D0`): the
/// pending key becomes current, the old one previous; both open mail
/// until `D0` + 24 h on the delegated clock, then the old secret is erased
/// (its id retired first) and only the new key opens mail.
#[test]
fn a_routine_rotation_keeps_the_previous_key_for_24_hours_from_its_application() {
    let mut r = rot();
    let old = pub_of(&r, "current");
    let (new, _) = new_key(&r).unwrap();
    commit_rotation(&mut r, &new, false, Some(D0));
    assert_eq!(file(&r)["applied"]["d_ms"], D0, "stamped before the commit");
    // Before the promotion runs, the receiver promotes first.
    let (keys, _) = view(&r, D0 + HOUR);
    assert_eq!(keys, [kid(&new), kid(&old)]);
    let f = file(&r);
    assert_eq!(pub_of(&r, "current"), new);
    assert_eq!(pub_of(&r, "previous"), old);
    assert!(f.get("pending").is_none());
    assert_eq!(f["previous"]["applied_d_ms"], D0);
    assert_eq!(f["previous"]["replaced_at_seq"], r.log.log.head().seq);
    assert_eq!(view(&r, D0 + RETAIN_MS - 1).0, [kid(&new), kid(&old)]);
    // At the deadline: erased, retired, never accepted again.
    let done = reconcile(&r, Some(D0 + RETAIN_MS)).unwrap();
    assert!(done.changed);
    assert!(file(&r).get("previous").is_none());
    assert_eq!(retired(&r), [kid(&old)]);
    let (keys, generated) = view(&r, D0 + RETAIN_MS);
    assert_eq!(keys, [kid(&new)]);
    assert!(
        !generated.contains(&kid(&old)),
        "retired: refused, never waits"
    );
}

/// Crash point: after the list committed the entry, before the promotion
/// (the stamp written, the key file still pending). Whenever the restart
/// comes, the deadline is the stamp's `D0` + 24 h: never restarted, never
/// lengthened.
#[test]
fn a_crash_after_the_list_commit_neither_restarts_nor_lengthens_the_window() {
    for (restart_at, kept) in [(D0 + 2 * HOUR, true), (D0 + 30 * HOUR, false)] {
        let mut r = rot();
        let old = pub_of(&r, "current");
        let (new, _) = new_key(&r).unwrap();
        commit_rotation(&mut r, &new, false, Some(D0));
        reconcile(&r, Some(restart_at)).unwrap();
        assert_eq!(pub_of(&r, "current"), new);
        let (keys, _) = view(&r, restart_at);
        if kept {
            assert_eq!(keys, [kid(&new), kid(&old)]);
            assert_eq!(
                file(&r)["previous"]["applied_d_ms"],
                D0,
                "not the restart's"
            );
            assert_eq!(view(&r, D0 + RETAIN_MS).0, [kid(&new)]);
        } else {
            assert_eq!(keys, [kid(&new)]);
            assert!(file(&r).get("previous").is_none());
            assert_eq!(retired(&r), [kid(&old)]);
        }
    }
}

/// No application time to rely on (no stamp: the crash came before the
/// hook, or `D` couldn't be read then; or a stamp naming another entry):
/// the promotion fails closed, the previous key retired at once, never a
/// fresh 24 h.
#[test]
fn without_its_application_time_the_previous_key_is_retired_at_once() {
    for stamped in [false, true] {
        let mut r = rot();
        let old = pub_of(&r, "current");
        let (new, _) = new_key(&r).unwrap();
        set(&mut r, &new, false);
        if stamped {
            // A stamp naming another entry at that seq (one that never
            // committed): no evidence for this one.
            let mut f = file(&r);
            f["applied"] = json!({
                "seq": r.log.log.head().seq,
                "hash": "00".repeat(32),
                "d_ms": D0,
                "clock": MARK,
            });
            std::fs::write(&r.pairing.host_enc_key, f.to_string()).unwrap();
        }
        let done = reconcile(&r, Some(D0)).unwrap();
        assert!(
            done.lines.iter().any(|l| l.contains("retired at once")),
            "{:?}",
            done.lines
        );
        assert_eq!(pub_of(&r, "current"), new);
        assert!(file(&r).get("previous").is_none());
        assert_eq!(retired(&r), [kid(&old)]);
        assert_eq!(view(&r, D0).0, [kid(&new)]);
    }
}

/// `retire_previous` (a suspected compromise): the old secret is erased
/// when the entry is applied; mail to it is refused from then.
#[test]
fn retire_previous_erases_the_old_key_when_applied() {
    let mut r = rot();
    let old = pub_of(&r, "current");
    let (new, _) = new_key(&r).unwrap();
    commit_rotation(&mut r, &new, true, Some(D0));
    let (keys, generated) = view(&r, D0);
    assert_eq!(keys, [kid(&new)]);
    assert!(!generated.contains(&kid(&old)));
    assert!(file(&r).get("previous").is_none());
    assert_eq!(retired(&r), [kid(&old)]);
}

/// An early second rotation: its commit erases the older previous key
/// still in its window (one previous key only), which becomes retired.
#[test]
fn an_early_second_rotation_erases_the_older_previous_key() {
    let mut r = rot();
    let k1 = pub_of(&r, "current");
    let (k2, _) = new_key(&r).unwrap();
    commit_rotation(&mut r, &k2, false, Some(D0));
    assert_eq!(view(&r, D0 + HOUR).0, [kid(&k2), kid(&k1)]);
    let (k3, _) = new_key(&r).unwrap();
    commit_rotation(&mut r, &k3, false, Some(D0 + 2 * HOUR));
    assert_eq!(view(&r, D0 + 2 * HOUR).0, [kid(&k3), kid(&k2)]);
    assert_eq!(retired(&r), [kid(&k1)]);
    assert_eq!(pub_of(&r, "previous"), k2);
    assert_eq!(file(&r)["previous"]["applied_d_ms"], D0 + 2 * HOUR);
}

/// `D` below the application time (the delegated clock lowered past it):
/// the window can't be established, so the previous key is retired.
#[test]
fn a_clock_below_the_application_fails_closed() {
    let mut r = rot();
    let old = pub_of(&r, "current");
    let (new, _) = new_key(&r).unwrap();
    commit_rotation(&mut r, &new, false, Some(D0));
    assert_eq!(view(&r, D0).0, [kid(&new), kid(&old)]);
    assert_eq!(view(&r, D0 - 1).0, [kid(&new)]);
    assert_eq!(retired(&r), [kid(&old)]);
}

/// Crash point: mid-retirement, the id retired but the key file not yet
/// rewritten (its write failed, as a crash leaves it): the secret the file
/// still holds is never accepted, and the next reconcile erases it. A key
/// file rolled back afterwards brings no retired key back.
#[test]
fn a_retirement_cut_short_completes_and_no_retired_key_comes_back() {
    let mut r = rot();
    let old = pub_of(&r, "current");
    let (new, _) = new_key(&r).unwrap();
    commit_rotation(&mut r, &new, false, Some(D0));
    view(&r, D0);
    let promoted = std::fs::read(&r.pairing.host_enc_key).unwrap();
    // The deadline's erasure, its key file write failing.
    let mut store = dl_store(&r);
    store.inject(Injected {
        file: DlFile::HostEncKey,
        step: Step::Rename,
    });
    assert!(
        host_enc::reconcile_with(&mut store, HOST, 1, &r.log.log, Some(at(D0 + RETAIN_MS)))
            .is_err()
    );
    assert_eq!(retired(&r), [kid(&old)]);
    assert_eq!(pub_of(&r, "previous"), old, "still in the file");
    // Even inside the window's numbers, a retired id is never accepted.
    let mut store = dl_store(&r);
    store.inject(Injected {
        file: DlFile::HostEncKey,
        step: Step::Rename,
    });
    let held = host_enc::recipient_with(&mut store, HOST.into(), 1, &r.log.log, Some(at(D0 + 1)));
    assert!(held.is_err(), "nothing decided while it can't be erased");
    reconcile(&r, Some(D0 + 1)).unwrap();
    assert!(file(&r).get("previous").is_none());
    assert_eq!(view(&r, D0 + 1).0, [kid(&new)]);
    // A rollback of the key file to the promoted state.
    std::fs::write(&r.pairing.host_enc_key, &promoted).unwrap();
    assert_eq!(view(&r, D0 + 1).0, [kid(&new)]);
    assert!(file(&r).get("previous").is_none(), "erased again");
}

/// The host's generation replaced (a newer `add_host`) or the host removed:
/// the pending key and the previous one go with it, and the current one
/// too (no key of a voided generation is ever accepted).
#[test]
fn a_generation_change_or_removal_retires_the_pending_key() {
    for removed in [false, true] {
        let mut r = rot();
        let current = pub_of(&r, "current");
        let (pending, _) = new_key(&r).unwrap();
        if removed {
            r.log.append(
                MAC,
                atem_client::membership::entry::Action::RemoveHost {
                    host_id: HOST.into(),
                },
            );
        } else {
            r.log.add_host(HOST, 2, &secret("rot host 2"));
        }
        let done = reconcile(&r, Some(D0)).unwrap();
        assert!(done.changed);
        let f = file(&r);
        for slot in ["current", "pending", "previous"] {
            assert!(f.get(slot).is_none(), "{removed}: {slot}: {f}");
        }
        let mut gone = vec![kid(&current), kid(&pending)];
        gone.sort();
        let mut got = retired(&r);
        got.sort();
        assert_eq!(got, gone);
    }
}

/// A list behind the host's own generation (its new `add_host` not
/// applied yet) changes nothing: no key of the newer generation is set
/// there, and none is erased.
#[test]
fn a_list_behind_the_hosts_generation_changes_nothing() {
    let r = rot();
    let (_, _) = new_key(&r).unwrap();
    let before = (file(&r), record(&r));
    // This host at generation 2, its list still at 1.
    let done = host_enc::reconcile(&r.pairing, HOST, 2, &r.log.log, Some(at(D0)));
    assert!(done.is_ok_and(|d| !d.changed));
    assert_eq!((file(&r), record(&r)), before);
}

/// A request while the pending key's entry is committed but not yet
/// promoted is `busy`: the key is no longer pending, and no other is made
/// over it.
#[test]
fn a_new_request_before_the_promotion_is_busy() {
    let mut r = rot();
    let (new, _) = new_key(&r).unwrap();
    commit_rotation(&mut r, &new, false, Some(D0));
    assert!(new_key(&r).is_err());
    assert_eq!(pub_of(&r, "pending"), new);
    reconcile(&r, Some(D0)).unwrap();
    let (next, _) = new_key(&r).unwrap();
    assert_ne!(next, new);
}

/// After the promotion `host_enc_key_get` hands out the new current key.
#[test]
fn the_get_hands_out_the_promoted_key() {
    let mut r = rot();
    let (new, _) = new_key(&r).unwrap();
    commit_rotation(&mut r, &new, false, Some(D0));
    reconcile(&r, Some(D0)).unwrap();
    let mut store = dl_store(&r);
    let (got, _, _) =
        host_enc::hand_out(&mut store, &r.pairing, &r.log.log, &r.host_key, HOST, 1).unwrap();
    assert_eq!(*got.enc_pub(), new);
}

/// The stamp is written once: a later commit naming the same entry (a
/// replay) keeps the earlier time, so nothing lengthens the window.
#[test]
fn the_stamp_is_kept_at_its_first_time() {
    let mut r = rot();
    let (new, _) = new_key(&r).unwrap();
    let prev = r.log.log.clone();
    set(&mut r, &new, false);
    stamp(&r, &prev, D0);
    stamp(&r, &prev, D0 + 5 * HOUR);
    assert_eq!(file(&r)["applied"]["d_ms"], D0);
    assert_eq!(file(&r)["applied"]["seq"], r.log.log.head().seq);
    // No stamp for an entry that sets no pending key of this host.
    let before = file(&r);
    let prev = r.log.log.clone();
    r.log.add_native("dev-ipad", &["view"]);
    stamp(&r, &prev, D0 + 6 * HOUR);
    assert_eq!(file(&r), before);
}

/// `atem status`'s `Host key:` text: the current key's id, a pending one,
/// and the previous one with its deadline: the earlier of its 24 h on the
/// delegated clock and its 24 h of the boot-time counter (placed on the
/// wall clock of the status's own reading), and that a reboot ends it
/// (after one, or with the counter below its stamp, it is retired at the
/// next check). The reading is taken only for a previous key whose stamp
/// has its boot (review L3: a status with no key file, or no previous key,
/// reads no clock); with none, only the end on `D` is shown, as such.
#[test]
fn the_status_names_the_keys() {
    use host_enc::BootAt;
    let unread = || -> Option<(BootAt, u64)> { panic!("no clock is read for this status") };
    let mut r = rot();
    let current = pub_of(&r, "current");
    let at_hour = Some((
        BootAt {
            boot: BOOT,
            ms: B0 + HOUR,
        },
        D0 + HOUR,
    ));
    assert_eq!(
        host_enc::status_text(&r.pairing, unread).unwrap(),
        format!("enc_kid {} (current)", kid(&current))
    );
    let (new, _) = new_key(&r).unwrap();
    assert_eq!(
        host_enc::status_text(&r.pairing, unread).unwrap(),
        format!("enc_kid {} (current); {} pending", kid(&current), kid(&new))
    );
    commit_rotation(&mut r, &new, false, Some(D0));
    reconcile(&r, Some(D0)).unwrap();
    let status = |now: Option<(BootAt, u64)>| host_enc::status_text(&r.pairing, || now).unwrap();
    let head = format!(
        "enc_kid {} (current); {} previous",
        kid(&new),
        kid(&current)
    );
    let window = "(24 h on the delegated clock or of the boot-time counter, whichever ends first), or until a reboot";
    // The counter keeping pace with the wall clock: both end at D0 + 24 h.
    assert_eq!(
        status(at_hour),
        format!("{head} until 2027-01-16T08:00:00Z {window}")
    );
    // The wall clock 500 ppm slow, 12 h on: the counter's end comes 21.6 s
    // earlier.
    let slow = Some((
        BootAt {
            boot: BOOT,
            ms: B0 + 12 * HOUR,
        },
        D0 + 12 * HOUR - 21_600,
    ));
    assert_eq!(
        status(slow),
        format!("{head} until 2027-01-16T07:59:38Z {window}")
    );
    // The wall clock ahead: the end on `D` comes first.
    let fast = Some((
        BootAt {
            boot: BOOT,
            ms: B0 + HOUR,
        },
        D0 + 5 * HOUR,
    ));
    assert_eq!(
        status(fast),
        format!("{head} until 2027-01-16T08:00:00Z {window}")
    );
    // Another boot: it goes at the next check.
    let rebooted = Some((
        BootAt {
            boot: BOOT + 1,
            ms: 60_000,
        },
        D0 + HOUR,
    ));
    assert_eq!(
        status(rebooted),
        format!("{head}, retired at the next check (the host rebooted since its application)")
    );
    // The counter below the stamp's on its boot: it goes at the next check.
    let below = Some((
        BootAt {
            boot: BOOT,
            ms: B0 - 1,
        },
        D0 + HOUR,
    ));
    assert_eq!(
        status(below),
        format!(
            "{head}, retired at the next check (the boot-time counter reads below its application)"
        )
    );
    // No reading (none, or a boot the OS can't name): the end on `D` only.
    assert_eq!(
        status(None),
        format!(
            "{head} until 2027-01-16T08:00:00Z on the delegated clock at the latest (the boot-time counter isn't read here), or until a reboot"
        )
    );
    // No key file: nothing, and no clock read.
    std::fs::remove_file(&r.pairing.host_enc_key).unwrap();
    assert_eq!(host_enc::status_text(&r.pairing, unread), None);
}

/// A record that can't be read (or is lost) doesn't stall the receiver: it
/// is rebuilt from the keys held, with a line, and the view goes on.
#[test]
fn a_damaged_record_is_rebuilt_from_the_keys_held() {
    let r = rot();
    let current = pub_of(&r, "current");
    let (pending, _) = new_key(&r).unwrap();
    std::fs::write(&r.pairing.host_enc_generated, b"not json").unwrap();
    let done = reconcile(&r, Some(D0)).unwrap();
    assert!(
        done.lines
            .iter()
            .any(|l| l.contains("rebuilt from the keys held")),
        "{:?}",
        done.lines
    );
    assert_eq!(
        record(&r),
        json!({"v": 2, "host_trust_gen": 1, "kids": [kid(&current), kid(&pending)], "retired": [],
            "requests": []})
    );
    assert_eq!(
        view(&r, D0),
        (vec![kid(&current)], vec![kid(&current), kid(&pending)])
    );
}

// ── Fix round 1: the key state follows the list entry by entry (R61), a
// retry's same key (R62), a clock repair after the stamp (R63) ──

/// Writes a second key no entry set into the key file's `pending` slot
/// beside an unset current key, as a key file from before rule R61's
/// "answer the unset current key" holds it: its id recorded first.
fn put_unset_pending(r: &Rot, secret_seed: &str) -> [u8; 32] {
    let secret = secret(secret_seed);
    let public = x25519_pub(&secret);
    let mut rec = record(r);
    rec["kids"]
        .as_array_mut()
        .unwrap()
        .push(json!(kid(&public)));
    std::fs::write(&r.pairing.host_enc_generated, rec.to_string()).unwrap();
    let mut f = file(r);
    f["pending"] = json!({"secret": atem_client::encoding::b64u(&secret),
        "pub": atem_client::encoding::b64u(&public)});
    std::fs::write(&r.pairing.host_enc_key, f.to_string()).unwrap();
    public
}

/// R61 rule 2: while the host's current key is one no entry has set, a
/// manager's `host_enc_key_new` gets that key (a stale `host_enc_key_get`
/// answer can only ever name the key the host will promote); none is
/// minted beside it. Once the list sets it, a new request makes the next.
#[test]
fn a_new_request_while_the_current_key_is_unset_gets_that_key() {
    let mut r = unset_rot();
    let k1 = pub_of(&r, "current");
    // Manager A: the get. Manager B: a new key, under its own request.
    let mut store = dl_store(&r);
    let (got, _, _) =
        host_enc::hand_out(&mut store, &r.pairing, &r.log.log, &r.host_key, HOST, 1).unwrap();
    assert_eq!(*got.enc_pub(), k1);
    let (b, _) = new_key_as(&r, REQUEST).unwrap();
    assert_eq!(b, k1, "the unset current key, not a second one");
    assert!(file(&r).get("pending").is_none());
    // B's entry lands first; A's draft of the same key is then reused.
    let prev = r.log.log.clone();
    set(&mut r, &k1, false);
    assert!(
        stamp(&r, &prev, D0).is_empty(),
        "no previous key: no window"
    );
    assert!(
        r.log
            .log
            .host_enc_key_set_before(HOST, &PublicKey::new(Alg::X25519, &k1).unwrap())
    );
    assert_eq!(view(&r, D0).0, [kid(&k1)]);
    // The next request, the current key set, makes a new pending key.
    let (k2, _) = new_key(&r).unwrap();
    assert_ne!(k2, k1);
    assert_eq!(pub_of(&r, "pending"), k2);
}

/// R61 (review H1, the exact scenario): A got K1 by `host_enc_key_get`
/// while no entry set it; B rotated to K2 (a pending key beside the unset
/// K1, as a key file from before rule 2 holds them); B's entry sets K2,
/// then A's stale entry sets K1. The host follows the list entry by entry:
/// K1 is kept unaccepted (never erased) while no entry sets it, K2 is
/// current; A's entry makes K1 current and K2 the previous key, stamped,
/// opening mail for its 24 h. The host never ends with no key.
#[test]
fn a_stale_managers_entry_keeps_the_host_following_the_list() {
    let mut r = unset_rot();
    let k1 = pub_of(&r, "current");
    let k2 = put_unset_pending(&r, "rot b's pending key");
    commit_rotation(&mut r, &k2, false, Some(D0));
    let (keys, generated) = view(&r, D0);
    assert_eq!(keys, [kid(&k2)], "the list's current key only");
    assert!(
        generated.contains(&kid(&k1)),
        "K1 kept: it may still be set"
    );
    assert_eq!(pub_of(&r, "current"), k2);
    assert_eq!(pub_of(&r, "pending"), k1, "kept unaccepted, never erased");
    assert!(retired(&r).is_empty());
    // A's stale entry sets K1 (every verifier takes it: never set before).
    commit_rotation(&mut r, &k1, false, Some(D0 + HOUR));
    let (keys, _) = view(&r, D0 + HOUR);
    assert_eq!(keys, [kid(&k1), kid(&k2)], "K1 current, K2 for its window");
    assert_eq!(file(&r)["previous"]["applied_d_ms"], D0 + HOUR);
    assert_eq!(view(&r, D0 + HOUR + RETAIN_MS).0, [kid(&k1)]);
    assert_eq!(retired(&r), [kid(&k2)]);
    // The get hands out the list's current key.
    let mut store = dl_store(&r);
    let (got, _, _) =
        host_enc::hand_out(&mut store, &r.pairing, &r.log.log, &r.host_key, HOST, 1).unwrap();
    assert_eq!(*got.enc_pub(), k1);
}

/// R61, the alternative order: B asks for a new key while K1 is unset and
/// gets K1; A's entry sets K1; B, asking again under a new request, gets
/// a fresh K2, whose entry makes K1 the previous key.
#[test]
fn the_alternative_order_rotates_from_the_key_set_first() {
    let mut r = unset_rot();
    let k1 = pub_of(&r, "current");
    let (b, _) = new_key(&r).unwrap();
    assert_eq!(b, k1);
    let prev = r.log.log.clone();
    set(&mut r, &k1, false);
    stamp(&r, &prev, D0);
    let (k2, _) = new_key(&r).unwrap();
    assert_ne!(k2, k1);
    commit_rotation(&mut r, &k2, false, Some(D0 + HOUR));
    assert_eq!(view(&r, D0 + HOUR).0, [kid(&k2), kid(&k1)]);
    assert_eq!(file(&r)["previous"]["applied_d_ms"], D0 + HOUR);
}

/// R62 (review M1): a retry under the same `request_id` gets the same key,
/// before the promotion, after it, and after a later rotation retired the
/// key (its id and public half are in the bounded record); a new
/// `request_id` gets a fresh key once the old one is set.
#[test]
fn a_retry_gets_the_same_key_before_and_after_the_promotion() {
    let mut r = rot();
    let (k2, _) = new_key_as(&r, REQUEST).unwrap();
    assert_eq!(new_key_as(&r, REQUEST).unwrap().0, k2, "before");
    commit_rotation(&mut r, &k2, false, Some(D0));
    reconcile(&r, Some(D0)).unwrap();
    assert_eq!(pub_of(&r, "current"), k2);
    assert_eq!(
        new_key_as(&r, REQUEST).unwrap().0,
        k2,
        "after the promotion"
    );
    let (k3, _) = new_key(&r).unwrap();
    assert_ne!(k3, k2);
    commit_rotation(&mut r, &k3, true, Some(D0 + HOUR));
    reconcile(&r, Some(D0 + HOUR)).unwrap();
    assert!(retired(&r).contains(&kid(&k2)));
    assert_eq!(
        new_key_as(&r, REQUEST).unwrap().0,
        k2,
        "after its retirement"
    );
    // At most 64 requests are remembered: the oldest go first.
    for _ in 0..70 {
        new_key(&r).unwrap();
    }
    assert_eq!(record(&r)["requests"].as_array().unwrap().len(), 64);
}

/// R62: a request whose recorded key the host never wrote (its key file
/// write failed after the record) is answered as a new request, never with
/// a key the host doesn't hold.
#[test]
fn a_retry_never_gets_a_key_the_host_lost() {
    let r = rot();
    let mut store = dl_store(&r);
    store.inject(Injected {
        file: DlFile::HostEncKey,
        step: Step::TempWrite,
    });
    assert!(
        host_enc::new_pending(
            &mut store,
            &r.pairing,
            &r.log.log,
            &r.host_key,
            HOST,
            1,
            REQUEST
        )
        .is_err()
    );
    let lost = record(&r)["requests"][0]["kid"]
        .as_str()
        .unwrap()
        .to_owned();
    let (got, _) = new_key_as(&r, REQUEST).unwrap();
    assert_ne!(kid(&got), lost);
    assert_eq!(pub_of(&r, "pending"), got);
}

/// R63 (review M2) and re-review N1: the delegated clock's mark changed
/// after a previous key's stamp (a repair, a lowering, or a fresh start)
/// retires that key at once (its window could otherwise run longer than
/// 24 h of real time); the mark unchanged since the stamp keeps it.
#[test]
fn a_clock_repair_after_the_stamp_retires_the_previous_key() {
    let mut r = rot();
    let old = pub_of(&r, "current");
    let (new, _) = new_key(&r).unwrap();
    let prev = r.log.log.clone();
    set(&mut r, &new, false);
    let mut store = dl_store(&r);
    let before = Some(host_enc::DNow {
        clock: 11,
        ..at(D0)
    });
    host_enc::stamp_application_locked(&mut store, &prev, &r.log.log, HOST, 1, before);
    let view_at = |r: &Rot, d: u64, clock: u64| {
        let now = host_enc::DNow { clock, ..at(d) };
        let got =
            host_enc::recipient_at(&r.pairing, HOST.into(), 1, &r.log.log, Some(now)).unwrap();
        got.recipient
            .keys
            .iter()
            .map(|(_, k)| hex(k))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        view_at(&r, D0 + HOUR, 11),
        [kid(&new), kid(&old)],
        "the change before the stamp, unchanged"
    );
    let done = host_enc::reconcile(
        &r.pairing,
        HOST,
        1,
        &r.log.log,
        Some(host_enc::DNow {
            clock: 12,
            ..at(D0 + 2 * HOUR)
        }),
    )
    .unwrap();
    assert!(
        done.lines
            .iter()
            .any(|l| l.contains("repaired, lowered or started afresh")),
        "{:?}",
        done.lines
    );
    assert_eq!(retired(&r), [kid(&old)]);
    assert_eq!(view_at(&r, D0 + 2 * HOUR, 12), [kid(&new)]);
}

/// Astation's review of the rotation (#120 comment 7208696433): the
/// window is at most 24 h of the host's boot-time counter. `D` follows a
/// slow wall clock down at up to 500 ppm (§11.6), which the clock's mark
/// doesn't count, so on `D` alone the previous key would still open mail up
/// to 43 s after 24 h of the counter. On the boot its stamp was taken on,
/// 24 h of the counter since the stamp retires it first: accepted 1 ms
/// before, refused at 24 h of it, while `D` still reads short of the
/// stamp's `D` + 24 h. The stamp keeps the boot and the counter, and the
/// previous key takes them.
#[test]
fn a_slow_clock_retires_the_previous_key_at_24_hours_elapsed() {
    use crate::runtime::host_clock::state::RHO_PPM;
    let mut r = rot();
    let old = pub_of(&r, "current");
    let (new, _) = new_key(&r).unwrap();
    commit_rotation(&mut r, &new, false, Some(D0));
    let f = file(&r);
    assert_eq!(
        (&f["applied"]["boot"], &f["applied"]["boot_ms"]),
        (&json!(BOOT), &json!(B0))
    );
    // `D` 500 ppm behind the boot-time counter.
    let slow = |elapsed: u64| {
        at_boot(
            D0 + elapsed - elapsed * RHO_PPM / 1_000_000,
            BOOT,
            B0 + elapsed,
        )
    };
    let before = slow(RETAIN_MS - 1);
    assert_eq!(accepted_at(&r, before), [kid(&new), kid(&old)]);
    let f = file(&r);
    assert_eq!(
        (&f["previous"]["boot"], &f["previous"]["applied_boot_ms"]),
        (&json!(BOOT), &json!(B0))
    );
    let ceiling = slow(RETAIN_MS);
    assert!(
        ceiling.d_ms + 43_000 < D0 + RETAIN_MS,
        "D short of its deadline: {}",
        ceiling.d_ms
    );
    let done = host_enc::reconcile(&r.pairing, HOST, 1, &r.log.log, Some(ceiling)).unwrap();
    assert!(
        done.lines.iter().any(|l| l.contains("24 h elapsed")),
        "{:?}",
        done.lines
    );
    assert!(file(&r).get("previous").is_none());
    assert_eq!(retired(&r), [kid(&old)]);
    assert_eq!(accepted_at(&r, ceiling), [kid(&new)]);
}

/// A reboot inside the window retires the previous key at once, with its
/// reason: elapsed time across a reboot can't be established, so it fails
/// closed (as a crash before the stamp does), however little `D` and the
/// new boot's counter moved.
#[test]
fn a_reboot_inside_the_window_retires_the_previous_key_at_once() {
    let mut r = rot();
    let old = pub_of(&r, "current");
    let (new, _) = new_key(&r).unwrap();
    commit_rotation(&mut r, &new, false, Some(D0));
    assert_eq!(view(&r, D0 + HOUR).0, [kid(&new), kid(&old)]);
    let rebooted = at_boot(D0 + 2 * HOUR, BOOT + 1, 60_000);
    let done = host_enc::reconcile(&r.pairing, HOST, 1, &r.log.log, Some(rebooted)).unwrap();
    assert!(
        done.lines.iter().any(|l| l.contains("rebooted")),
        "{:?}",
        done.lines
    );
    assert!(file(&r).get("previous").is_none());
    assert_eq!(retired(&r), [kid(&old)]);
    assert_eq!(accepted_at(&r, rebooted), [kid(&new)]);
}

/// `D` running fast (a wall clock ahead of the boot-time counter, which
/// `D` follows up at once): the window still ends at the stamp's `D` +
/// 24 h, today's rule kept, though only 20 h passed on the counter.
#[test]
fn a_fast_clock_still_retires_the_previous_key_at_its_deadline_on_d() {
    let mut r = rot();
    let old = pub_of(&r, "current");
    let (new, _) = new_key(&r).unwrap();
    commit_rotation(&mut r, &new, false, Some(D0));
    // `D` 20 % ahead of the counter.
    let fast = |d: u64| at_boot(D0 + d, BOOT, B0 + d * 5 / 6);
    assert_eq!(accepted_at(&r, fast(RETAIN_MS - 1)), [kid(&new), kid(&old)]);
    let deadline = fast(RETAIN_MS);
    assert_eq!(deadline.boot.unwrap().ms, B0 + 20 * HOUR);
    let done = host_enc::reconcile(&r.pairing, HOST, 1, &r.log.log, Some(deadline)).unwrap();
    assert!(
        done.lines
            .iter()
            .any(|l| l.contains("window on the delegated clock ended")),
        "{:?}",
        done.lines
    );
    assert!(file(&r).get("previous").is_none());
    assert_eq!(accepted_at(&r, deadline), [kid(&new)]);
}

/// A stamp or a previous key read without its boot (a file this format
/// never writes): no elapsed time can be established from it, so the
/// previous key is retired at once.
#[test]
fn a_stamp_without_its_boot_retires_the_previous_key_at_once() {
    for slot in ["applied", "previous"] {
        let mut r = rot();
        let old = pub_of(&r, "current");
        let (new, _) = new_key(&r).unwrap();
        commit_rotation(&mut r, &new, false, Some(D0));
        if slot == "previous" {
            assert_eq!(view(&r, D0).0, [kid(&new), kid(&old)]);
        }
        let mut f = file(&r);
        let (boot, ms) = if slot == "applied" {
            ("boot", "boot_ms")
        } else {
            ("boot", "applied_boot_ms")
        };
        let entry = f[slot].as_object_mut().unwrap();
        assert!(
            entry.remove(boot).is_some() && entry.remove(ms).is_some(),
            "{slot}"
        );
        std::fs::write(&r.pairing.host_enc_key, f.to_string()).unwrap();
        let done = reconcile(&r, Some(D0 + HOUR)).unwrap();
        assert!(
            done.lines.iter().any(|l| l.contains("boot isn't recorded")),
            "{slot}: {:?}",
            done.lines
        );
        assert!(file(&r).get("previous").is_none(), "{slot}");
        assert_eq!(retired(&r), [kid(&old)], "{slot}");
        assert_eq!(view(&r, D0 + HOUR).0, [kid(&new)], "{slot}");
    }
}
