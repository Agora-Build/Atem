//! Unit tests of the device list's durable state on real files (a temp
//! profile), with the r9 vectors' log; and the helpers the fixture runner
//! and the end-to-end tests share.
use super::store::{DlFile, Injected, Step};
use super::*;
use crate::paths::ProfilePaths;
use std::collections::BTreeMap;
use std::path::PathBuf;

// ── Shared helpers ──

pub(super) const WALL0: u64 = 1_793_264_000_000;

/// The r9 membership-log vectors by label.
pub(super) struct Vectors {
    by_label: BTreeMap<String, Value>,
}

pub(super) fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("designs/protocol/fixtures")
}

pub(super) fn vectors() -> &'static Vectors {
    static V: std::sync::OnceLock<Vectors> = std::sync::OnceLock::new();
    V.get_or_init(|| {
        let bytes = std::fs::read(fixtures_dir().join("r9-vectors-membership-log.json")).unwrap();
        let file: Value = serde_json::from_slice(&bytes).unwrap();
        let mut by_label = BTreeMap::new();
        for list in ["log", "others"] {
            for v in file[list].as_array().unwrap() {
                by_label.insert(v["label"].as_str().unwrap().to_owned(), v.clone());
            }
        }
        Vectors { by_label }
    })
}

impl Vectors {
    fn vector(&self, label: &str) -> &Value {
        self.by_label
            .get(label)
            .unwrap_or_else(|| panic!("no vector {label}"))
    }

    pub fn wire(&self, label: &str) -> &Value {
        &self.vector(label)["entry"]
    }

    pub fn strict(&self, label: &str) -> StrictValue {
        StrictValue::parse(self.wire(label).to_string().as_bytes(), usize::MAX).unwrap()
    }

    pub fn carry(&self, labels: &[&str]) -> Vec<StrictValue> {
        labels.iter().map(|l| self.strict(l)).collect()
    }

    pub fn entry(&self, label: &str) -> atem_client::membership::Entry {
        atem_client::membership::Entry::from_strict(&self.strict(label)).unwrap()
    }

    pub fn hash(&self, label: &str) -> Hash32 {
        Hash32::from_hex(self.vector(label)["entry_hash"].as_str().unwrap()).unwrap()
    }

    pub fn head(&self, label: &str) -> Head {
        Head {
            seq: self.wire(label)["body"]["seq"].as_u64().unwrap(),
            hash: self.hash(label),
        }
    }
}

pub(super) fn clock(wall_ms: u64, mono_ms: u64, boot: &str) -> HostNow {
    HostNow {
        wall_ms,
        mono_ms,
        boot_id: boot.into(),
    }
}

pub(super) fn pinned(labels: &[&str], now: &HostNow) -> Membership {
    let v = vectors();
    let entries: Vec<_> = labels.iter().map(|l| v.entry(l)).collect();
    Membership::verify_chain("acct-test-1", &v.hash("E1"), &entries, now)
        .unwrap()
        .membership
}

/// host-a's `host_channel_key` seed (`r9-vectors-keys`).
pub(super) fn host_a_seed() -> [u8; 32] {
    let bytes = std::fs::read(fixtures_dir().join("r9-vectors-keys.json")).unwrap();
    let file: Value = serde_json::from_slice(&bytes).unwrap();
    let hex = file["keys"]["host-a"]["host_key"]["secret_hex"]
        .as_str()
        .unwrap();
    Hash32::from_hex(hex).unwrap().0
}

pub(super) fn pin_a() -> HostPin {
    HostPin {
        host_id: "host-a".into(),
        host_trust_gen: 1,
    }
}

/// A temp profile: `pairing/` and the runtime journal directory.
pub(super) struct Rig {
    pub dir: tempfile::TempDir,
    pub pairing: PairingPaths,
    pub journal: PathBuf,
}

impl Rig {
    pub fn new() -> Rig {
        let dir = tempfile::tempdir().unwrap();
        let profile = ProfilePaths::in_dir(dir.path());
        let journal = dir.path().join("runtime").join("journal");
        store::private_dir(&journal).unwrap();
        Rig {
            pairing: profile.pairing,
            journal,
            dir,
        }
    }

    pub fn pin(&self, labels: &[&str]) {
        let m = pinned(labels, &clock(WALL0, 1_000, "boot-1"));
        MembershipHost::pin(&self.pairing, &self.journal, &pin_a(), &m, &host_a_seed()).unwrap();
    }

    pub fn open(
        &self,
        epoch: u64,
        now: &HostNow,
        fences: &mut dyn Fences,
    ) -> Result<(MembershipHost, Vec<Fence>), String> {
        MembershipHost::open(&self.pairing, &self.journal, epoch, now, fences)
            .map(|o| o.expect("a device list"))
    }

    pub fn exists(&self, file: DlFile) -> bool {
        Store::new(&self.pairing, &self.journal).present(file)
    }

    pub fn read(&self, file: DlFile) -> Option<Value> {
        let bytes = Store::new(&self.pairing, &self.journal)
            .read(file)
            .unwrap()?;
        Some(serde_json::from_slice(&bytes).unwrap())
    }

    /// The head `membership.json` holds on disk.
    pub fn disk_head(&self) -> Head {
        Head::from_json(&self.read(DlFile::State).unwrap()["head"]).unwrap()
    }
}

/// Records what the device list asked of the session host.
#[derive(Default, Debug)]
pub(super) struct RecFences {
    pub remote: Vec<String>,
    pub fenced: Vec<(String, u64)>,
    pub faults: Vec<Vec<String>>,
}

impl Fences for RecFences {
    fn fence(&mut self, principal: &str, seq: u64) {
        self.fenced.push((principal.to_owned(), seq));
    }
    fn fault(&mut self, principals: Option<&[String]>) {
        self.faults
            .push(principals.map_or_else(|| self.remote.clone(), |p| p.to_vec()));
    }
    fn remote_principals(&self) -> Vec<String> {
        self.remote.clone()
    }
}

fn remote() -> RecFences {
    RecFences {
        remote: vec![
            "member:dev-mac".into(),
            "member:dev-phone".into(),
            "service:svc-discord".into(),
        ],
        ..Default::default()
    }
}

const SVC: &str = "service:svc-discord";
const LOG6: [&str; 6] = ["E1", "E2", "E3", "E4", "E5", "E6"];

fn t0() -> HostNow {
    clock(WALL0, 1_000, "boot-1")
}

fn opened(rig: &Rig, epoch: u64) -> (MembershipHost, RecFences) {
    let mut f = remote();
    let (host, fenced) = rig.open(epoch, &t0(), &mut f).unwrap();
    assert!(fenced.is_empty(), "nothing to replay: {fenced:?}");
    (host, f)
}

// ── Tests ──

#[test]
fn a_pinned_list_opens_at_its_head_with_nothing_to_replay() {
    let rig = Rig::new();
    rig.pin(&LOG6);
    let (host, f) = opened(&rig, 1);
    let v = vectors();
    assert_eq!(host.head(), v.head("E6"));
    assert_eq!(host.applied().head, v.head("E6"));
    assert!(host.held().is_none() && host.faulted().is_none() && !host.is_frozen());
    assert!(f.fenced.is_empty());
    assert_eq!(host.init(), Init::Accept);
    // Files are private.
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(&rig.pairing.membership)
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn a_committed_removal_writes_in_order_and_fences_by_its_seq() {
    let rig = Rig::new();
    rig.pin(&LOG6);
    let (mut host, mut f) = opened(&rig, 1);
    let v = vectors();
    let result = host.apply_carriage(&v.carry(&["E7"]), &t0(), &mut f);
    assert_eq!(result.carried, Carried::Committed);
    assert!(result.announce);
    assert_eq!(f.fenced, vec![(SVC.to_owned(), 7)]);
    assert_eq!(result.fences[0].reason, FenceReason::Removed);
    assert_eq!(host.head(), v.head("E7"));
    assert_eq!(rig.disk_head(), v.head("E7"));
    assert_eq!(host.applied().head, v.head("E7"));
    assert!(!rig.exists(DlFile::Carriage) && !rig.exists(DlFile::Intent));
    // The same entry again writes nothing and fences nothing.
    let again = host.apply_carriage(&v.carry(&["E7"]), &t0(), &mut f);
    assert_eq!(again.carried, Carried::Unchanged);
    assert_eq!(f.fenced.len(), 1);
}

/// Each step of the commit fails once: in-memory fences of the removed
/// principal, the journal halts, the fault is recorded, the record stays;
/// the restart replays the record and is held.
#[test]
fn a_failed_commit_step_fails_closed_and_the_restart_replays_it() {
    let v = vectors();
    for (file, step) in [
        (DlFile::Intent, Step::TempWrite),
        (DlFile::Intent, Step::TempFsync),
        (DlFile::Intent, Step::Rename),
        (DlFile::Intent, Step::DirectoryFsync),
        (DlFile::State, Step::TempWrite),
        (DlFile::State, Step::TempFsync),
        (DlFile::State, Step::Rename),
        (DlFile::State, Step::DirectoryFsync),
    ] {
        let what = format!("{file:?} {step:?}");
        let rig = Rig::new();
        rig.pin(&LOG6);
        let (mut host, mut f) = opened(&rig, 1);
        host.store_mut().inject(Injected { file, step });
        let result = host.apply_carriage(&v.carry(&["E7"]), &t0(), &mut f);
        assert_eq!(result.carried, Carried::NotRecorded, "{what}");
        assert_eq!(f.faults, vec![vec![SVC.to_owned()]], "{what}");
        assert!(f.fenced.is_empty(), "{what}: no durable fence");
        assert!(!result.fences[0].durable);
        assert_eq!(host.head(), v.head("E6"), "{what}: not committed in memory");
        assert!(host.faulted().is_some());
        assert_eq!(host.init(), Init::Busy);
        assert!(rig.exists(DlFile::Fault), "{what}: the fault is recorded");
        assert!(rig.exists(DlFile::Carriage), "{what}: the record stays");
        // The rename that happened before a failed directory fsync is there.
        let on_disk = if (file, step) == (DlFile::State, Step::DirectoryFsync) {
            "E7"
        } else {
            "E6"
        };
        assert_eq!(rig.disk_head(), v.head(on_disk), "{what}");
        // Later carriages are refused unread.
        let later = host.apply_carriage(&v.carry(&["E7"]), &t0(), &mut f);
        assert_eq!(later.carried, Carried::Refused);
        drop(host);

        let mut f2 = remote();
        let (host, fenced) = rig.open(2, &t0(), &mut f2).unwrap();
        assert_eq!(host.head(), v.head("E7"), "{what}: replayed");
        assert_eq!(host.applied().head, v.head("E7"));
        assert_eq!(f2.fenced, vec![(SVC.to_owned(), 7)], "{what}");
        assert_eq!(fenced.len(), 1);
        assert_eq!(host.held(), Some(&Held::Fault), "{what}");
        assert!(!rig.exists(DlFile::Carriage) && !rig.exists(DlFile::Intent));
        assert!(rig.exists(DlFile::Fault));
    }
}

/// The carriage record itself can't be written: nothing is evaluated, every
/// remote principal is fenced in memory, the restart is held and not frozen.
#[test]
fn a_carriage_record_that_cant_be_written_is_refused_unread() {
    let v = vectors();
    for step in [
        Step::TempWrite,
        Step::TempFsync,
        Step::Rename,
        Step::DirectoryFsync,
    ] {
        let rig = Rig::new();
        rig.pin(&LOG6);
        let (mut host, mut f) = opened(&rig, 1);
        host.store_mut().inject(Injected {
            file: DlFile::Carriage,
            step,
        });
        let result = host.apply_carriage(&v.carry(&["C6_mac"]), &t0(), &mut f);
        assert_eq!(result.carried, Carried::NotRecorded);
        assert!(result.evaluation.is_none(), "never evaluated");
        assert_eq!(f.faults, vec![f.remote.clone()], "every remote principal");
        assert!(
            result
                .fences
                .iter()
                .all(|x| x.reason == FenceReason::NotRecorded)
        );
        assert!(!host.is_frozen());
        assert_eq!(host.membership().evidence().count, 0);
        drop(host);
        if step != Step::DirectoryFsync {
            assert!(!rig.exists(DlFile::Carriage));
        } else {
            // A visible rename of a failed directory fsync is lost by
            // the "machine" here: the test removes it (write_lost).
            std::fs::remove_file(&rig.pairing.carriage).unwrap();
        }
        let mut f2 = remote();
        let (host, _) = rig.open(2, &t0(), &mut f2).unwrap();
        assert!(!host.is_frozen(), "it never learnt of the conflict");
        assert_eq!(host.held(), Some(&Held::Fault));
        assert_eq!(host.head(), v.head("E6"));
    }
}

/// §R9.3 step 0: the record holds a carriage within the carriage bounds.
/// One past them (65 entries) is refused `carriage_too_large` before
/// anything is written: no carriage record, no fault (here a write would
/// fail and fault the host).
#[test]
fn a_carriage_past_its_bounds_is_refused_before_the_record() {
    let v = vectors();
    let rig = Rig::new();
    rig.pin(&LOG6);
    let (mut host, mut f) = opened(&rig, 1);
    host.store_mut().inject(Injected {
        file: DlFile::Carriage,
        step: Step::TempWrite,
    });
    let carried: Vec<StrictValue> = (0..65).map(|_| v.strict("C6_mac")).collect();
    let result = host.apply_carriage(&carried, &t0(), &mut f);
    assert_eq!(result.carried, Carried::Unchanged);
    assert!(matches!(
        result.evaluation.as_ref().and_then(|e| e.stop.clone()),
        Some(atem_client::membership::Stop::Invalid {
            index: 64,
            reason: atem_client::membership::Invalid::CarriageTooLarge
        })
    ));
    assert!(host.faulted().is_none());
    assert!(f.faults.is_empty());
    assert!(!rig.exists(DlFile::Carriage));
    assert_eq!(host.head(), v.head("E6"));
}

#[test]
fn a_freeze_is_durable_first_and_survives_restarts() {
    let rig = Rig::new();
    rig.pin(&LOG6);
    let (mut host, mut f) = opened(&rig, 1);
    let v = vectors();
    let result = host.apply_carriage(&v.carry(&["C6_mac"]), &t0(), &mut f);
    assert_eq!(result.carried, Carried::Frozen);
    assert!(host.is_frozen() && host.frozen_durable());
    assert_eq!(f.fenced.len(), 3, "every remote principal, durably");
    assert!(f.fenced.iter().all(|(_, seq)| *seq == 0));
    assert!(rig.read(DlFile::State).unwrap().get("frozen").is_some());
    assert!(host.applied().frozen);
    assert_eq!(host.init(), Init::Frozen);
    assert_eq!(
        host.hello("dev-phone", Some(v.head("E6")), None, false, &t0()),
        Hello::Frozen
    );
    // Frozen applies nothing more.
    let more = host.apply_carriage(&v.carry(&["E7"]), &t0(), &mut f);
    assert_eq!(more.carried, Carried::Frozen);
    drop(host);
    let mut f2 = remote();
    let (host, _) = rig.open(2, &t0(), &mut f2).unwrap();
    assert!(host.is_frozen());
    assert!(f2.fenced.is_empty(), "the freeze's fences were applied");
    assert!(host.held().is_none(), "no fault recorded");
}

#[test]
fn a_failed_freeze_write_freezes_in_memory_and_the_record_freezes_again() {
    let v = vectors();
    for step in [
        Step::TempWrite,
        Step::TempFsync,
        Step::Rename,
        Step::DirectoryFsync,
    ] {
        let rig = Rig::new();
        rig.pin(&LOG6);
        let (mut host, mut f) = opened(&rig, 1);
        host.store_mut().inject(Injected {
            file: DlFile::Freeze,
            step,
        });
        let result = host.apply_carriage(&v.carry(&["C6_mac"]), &t0(), &mut f);
        assert_eq!(result.carried, Carried::Frozen, "{step:?}");
        assert!(host.is_frozen(), "frozen in memory at once");
        assert_eq!(f.faults, vec![f.remote.clone()]);
        assert!(
            result
                .fences
                .iter()
                .all(|x| x.reason == FenceReason::Frozen)
        );
        assert!(host.faulted().is_some());
        assert_eq!(host.init(), Init::Frozen, "frozen before busy");
        assert!(rig.exists(DlFile::Carriage));
        let renamed = step == Step::DirectoryFsync;
        assert_eq!(host.frozen_durable(), renamed);
        drop(host);
        let mut f2 = remote();
        let (host, _) = rig.open(2, &t0(), &mut f2).unwrap();
        assert!(host.is_frozen() && host.frozen_durable(), "{step:?}");
        assert_eq!(host.head(), v.head("E6"));
        assert!(!rig.exists(DlFile::Carriage));
        assert!(rig.exists(DlFile::Fault));
        assert_eq!(f2.fenced.len(), 3, "the freeze's fences, durably now");
    }
}

#[test]
fn a_freeze_file_in_any_state_freezes_at_start() {
    let rig = Rig::new();
    rig.pin(&LOG6);
    std::fs::write(&rig.pairing.freeze, b"{not json").unwrap();
    let mut f = remote();
    let (host, _) = rig.open(1, &t0(), &mut f).unwrap();
    assert!(host.is_frozen());
    assert_eq!(f.fenced.len(), 3, "every remote principal fenced");
    // A leftover temp file of a freeze write counts too.
    let rig = Rig::new();
    rig.pin(&LOG6);
    let mut tmp = rig.pairing.freeze.clone().into_os_string();
    tmp.push(".tmp");
    std::fs::write(&tmp, b"").unwrap();
    let (host, _) = rig.open(1, &t0(), &mut remote()).unwrap();
    assert!(host.is_frozen());
}

#[test]
fn an_unreadable_carriage_record_holds_the_host() {
    let rig = Rig::new();
    rig.pin(&LOG6);
    std::fs::write(&rig.pairing.carriage, b"\x00garbage").unwrap();
    let (host, _) = rig.open(1, &t0(), &mut remote()).unwrap();
    assert_eq!(host.held(), Some(&Held::CarriageUnreadable));
    assert!(
        rig.exists(DlFile::Fault),
        "recorded, so a restart stays held"
    );
    assert!(!rig.exists(DlFile::Carriage));
    drop(host);
    let (host, _) = rig.open(2, &t0(), &mut remote()).unwrap();
    assert_eq!(host.held(), Some(&Held::Fault));
}

#[test]
fn an_intent_left_beyond_the_head_holds_until_it_is_reached() {
    let v = vectors();
    let rig = Rig::new();
    rig.pin(&LOG6);
    std::fs::write(
        &rig.pairing.intent,
        v.head("E7").to_json().to_string().as_bytes(),
    )
    .unwrap();
    let mut f = remote();
    let (mut host, _) = rig.open(1, &t0(), &mut f).unwrap();
    assert_eq!(host.held(), Some(&Held::Unclean(v.head("E7"))));
    assert_eq!(host.unclean(), Some(v.head("E7")));
    // A manager at the host's head can't reconcile while it is unsatisfied.
    assert_eq!(
        host.hello("dev-phone", Some(v.head("E6")), None, false, &t0()),
        Hello::NotReconciled
    );
    // The carriage of E7 reaches it; then the manager reconciles.
    let result = host.apply_carriage(&v.carry(&["E7"]), &t0(), &mut f);
    assert_eq!(result.carried, Carried::Committed);
    assert_eq!(host.held(), Some(&Held::Fault));
    assert!(matches!(
        host.hello("dev-phone", Some(v.head("E7")), Some(&result), false, &t0()),
        Hello::Admit(Admission::Member { .. })
    ));
    assert!(host.held().is_none() && !rig.exists(DlFile::Fault));
}

#[test]
fn an_intent_naming_another_entry_never_reconciles() {
    let v = vectors();
    let rig = Rig::new();
    rig.pin(&LOG6);
    // An intent for another entry at seq 6 (the conflicting C6_ipad).
    std::fs::write(
        &rig.pairing.intent,
        v.head("C6_ipad").to_json().to_string().as_bytes(),
    )
    .unwrap();
    let (mut host, _) = rig.open(1, &t0(), &mut remote()).unwrap();
    assert!(matches!(host.held(), Some(Held::IntentMismatch(_))));
    assert_eq!(
        host.hello("dev-phone", Some(v.head("E6")), None, false, &t0()),
        Hello::NotReconciled
    );
    drop(host);
    // The mismatch is kept in the fault record across restarts.
    let (host, _) = rig.open(2, &t0(), &mut remote()).unwrap();
    assert!(matches!(host.held(), Some(Held::IntentMismatch(_))));
}

#[test]
fn only_a_managing_native_device_at_the_hosts_head_reconciles() {
    let v = vectors();
    let rig = Rig::new();
    rig.pin(&LOG6);
    let (mut host, mut f) = opened(&rig, 1);
    host.store_mut().inject(Injected {
        file: DlFile::State,
        step: Step::TempFsync,
    });
    host.apply_carriage(&v.carry(&["E7"]), &t0(), &mut f);
    drop(host);
    let (mut host, _) = rig.open(2, &t0(), &mut remote()).unwrap();
    let e7 = Some(v.head("E7"));
    // A service, a removed device, an unknown one: never.
    for device in ["svc-discord", "dev-ipad", "dev-stranger"] {
        assert_eq!(
            host.hello(device, e7, None, false, &t0()),
            Hello::NotReconciled
        );
    }
    // A manager behind the host's head, or announcing more: not yet.
    assert_eq!(
        host.hello("dev-phone", Some(v.head("E6")), None, false, &t0()),
        Hello::NotReconciled
    );
    assert_eq!(
        host.hello("dev-phone", e7, None, true, &t0()),
        Hello::NotReconciled
    );
    // A carriage with an invalid entry isn't clean.
    let mut f = remote();
    let dirty = host.apply_carriage(&v.carry(&["X8_badsig"]), &t0(), &mut f);
    assert!(!dirty.clean());
    assert_eq!(
        host.hello("dev-phone", e7, Some(&dirty), false, &t0()),
        Hello::NotReconciled
    );
    assert!(host.held().is_some());
    // The manager at the head: admitted, the fault record removed.
    assert!(matches!(
        host.hello("dev-phone", e7, None, false, &t0()),
        Hello::Admit(Admission::Member { .. })
    ));
    assert!(host.held().is_none());
    assert!(!rig.exists(DlFile::Fault));
    assert_eq!(
        host.hello("svc-discord", e7, None, false, &t0()),
        Hello::Admit(Admission::Unauthorized("removed"))
    );
    drop(host);
    let (host, _) = rig.open(3, &t0(), &mut remote()).unwrap();
    assert!(host.held().is_none(), "reconciled for good");
}

#[test]
fn a_crash_between_commit_and_fences_replays_them_and_resumes() {
    let v = vectors();
    let rig = Rig::new();
    rig.pin(&LOG6);
    let (mut host, mut f) = opened(&rig, 1);
    host.crash_after_commit();
    let result = host.apply_carriage(&v.carry(&["E7"]), &t0(), &mut f);
    assert_eq!(result.carried, Carried::Crashed);
    assert!(f.fenced.is_empty(), "died before the fences");
    assert_eq!(rig.disk_head(), v.head("E7"));
    assert!(rig.exists(DlFile::Intent) && rig.exists(DlFile::Carriage));
    drop(host);
    let mut f2 = remote();
    let (host, _) = rig.open(2, &t0(), &mut f2).unwrap();
    assert_eq!(f2.fenced, vec![(SVC.to_owned(), 7)]);
    assert_eq!(host.applied().head, v.head("E7"));
    assert!(host.held().is_none(), "a plain crash records no fault");
    assert!(!rig.exists(DlFile::Intent) && !rig.exists(DlFile::Carriage));
}

#[test]
fn an_applied_head_the_list_doesnt_hold_disables_remote_sessions() {
    let v = vectors();
    let rig = Rig::new();
    rig.pin(&["E1", "E2", "E3", "E4", "E5"]);
    std::fs::write(
        rig.journal.join("membership_applied"),
        v.head("E6").to_json().to_string(),
    )
    .unwrap();
    assert!(rig.open(1, &t0(), &mut remote()).is_err());
    // A damaged list is never reset silently.
    let rig = Rig::new();
    rig.pin(&LOG6);
    std::fs::write(&rig.pairing.membership, b"{}").unwrap();
    assert!(rig.open(1, &t0(), &mut remote()).is_err());
    // Records without a list.
    let rig = Rig::new();
    store::private_dir(rig.pairing.dir()).unwrap();
    std::fs::write(&rig.pairing.carriage, b"{}").unwrap();
    assert!(MembershipHost::open(&rig.pairing, &rig.journal, 1, &t0(), &mut remote()).is_err());
    // No list at all: not an r9 host.
    let rig = Rig::new();
    assert!(
        MembershipHost::open(&rig.pairing, &rig.journal, 1, &t0(), &mut remote())
            .unwrap()
            .is_none()
    );
}

/// A client's restored log may hold the restore-only `host_confirmed`
/// decision (Atem #93); a host's `membership.json` never does, so its
/// reader still refuses one.
#[test]
fn a_host_confirmed_decision_in_the_hosts_list_is_refused() {
    let decided = |reason: &str| {
        let rig = Rig::new();
        let mut labels = LOG6.to_vec();
        labels.push("R7");
        rig.pin(&labels);
        let mut state = rig.read(DlFile::State).unwrap();
        let record = state["recovery"][0].as_object_mut().unwrap();
        record.insert("state".into(), json!("active"));
        record.insert("reason".into(), json!(reason));
        record.insert("decided_at_seq".into(), json!(7));
        record.insert("decided_at_wall".into(), json!(WALL0));
        record.insert("order".into(), json!(1));
        state["decision_order"] = json!(1);
        std::fs::write(&rig.pairing.membership, state.to_string()).unwrap();
        rig.open(1, &t0(), &mut remote()).map(|_| ())
    };
    decided("wait_ended").expect("the same record as a host decides it");
    assert!(decided("host_confirmed").is_err());
}

#[test]
fn a_missing_applied_record_replays_every_fence_once() {
    let rig = Rig::new();
    rig.pin(&["E1", "E2", "E3", "E4", "E5", "E6", "E7"]);
    std::fs::remove_file(rig.journal.join("membership_applied")).unwrap();
    let mut f = remote();
    let (host, _) = rig.open(1, &t0(), &mut f).unwrap();
    // E6 removes the iPad, E7 the service.
    assert_eq!(
        f.fenced,
        vec![("member:dev-ipad".to_owned(), 6), (SVC.to_owned(), 7)]
    );
    assert_eq!(host.applied().head, vectors().head("E7"));
}

#[test]
fn ignored_history_is_persisted_at_most_once_a_minute() {
    let v = vectors();
    let rig = Rig::new();
    rig.pin(&LOG6);
    let (mut host, mut f) = opened(&rig, 1);
    let first = host.apply_carriage(&v.carry(&["C6_ipad"]), &t0(), &mut f);
    assert_eq!(first.carried, Carried::Committed);
    let on_disk = |rig: &Rig| rig.read(DlFile::State).unwrap()["evidence"]["count"].clone();
    assert_eq!(on_disk(&rig), json!(1));
    let second = host.apply_carriage(
        &v.carry(&["C6_ipad"]),
        &clock(WALL0 + 1, 2_000, "boot-1"),
        &mut f,
    );
    assert_eq!(second.carried, Carried::Committed);
    assert_eq!(host.membership().evidence().count, 2, "counted in memory");
    assert_eq!(on_disk(&rig), json!(1), "not written again within a minute");
    assert!(!rig.exists(DlFile::Carriage));
    // The next checkpoint writes it.
    host.advance(&clock(WALL0 + 61_000, 62_000, "boot-1"), &mut f);
    assert_eq!(on_disk(&rig), json!(2));
}

#[test]
fn a_pending_recovery_waits_on_the_host_clock_across_restarts_and_reboots() {
    let v = vectors();
    let rig = Rig::new();
    rig.pin(&LOG6);
    let (mut host, mut f) = opened(&rig, 1);
    let result = host.apply_carriage(&v.carry(&["R7"]), &t0(), &mut f);
    assert_eq!(result.carried, Carried::Committed);
    assert!(result.announce, "a pending entry started");
    assert_eq!(host.membership().pending_recovery(&t0()).len(), 1);
    // 10 h of host time, checkpointed by the pass.
    let ten_h = 10 * 3_600_000;
    host.advance(&clock(WALL0 + ten_h, 1_000 + ten_h, "boot-1"), &mut f);
    host.close(&clock(WALL0 + ten_h, 1_000 + ten_h, "boot-1"));
    drop(host);
    let stored = rig.read(DlFile::State).unwrap();
    assert_eq!(stored["recovery"][0]["mono_waited_ms"], json!(ten_h));
    assert_eq!(stored["checkpoint"]["runtime_epoch"], json!(1));

    // A reboot: the machine was off for 20 h (wall moved), the monotonic
    // clock restarted. Only the persisted 10 h count.
    let boot2 = |extra: u64| clock(WALL0 + 30 * 3_600_000 + extra, 5_000 + extra, "boot-2");
    let (mut host, _) = rig.open(2, &boot2(0), &mut f).unwrap();
    assert_eq!(host.previous_checkpoint(), Some(1));
    host.advance(&boot2(13 * 3_600_000), &mut f);
    assert_eq!(
        host.membership().record(&v.hash("R7")).unwrap().state(),
        RecoveryState::Pending,
        "23 h of host time"
    );
    // A runtime restart within the boot keeps counting from the anchor.
    host.close(&boot2(13 * 3_600_000));
    drop(host);
    let (mut host, _) = rig.open(3, &boot2(13 * 3_600_000 + 1), &mut f).unwrap();
    let changes = host.advance(&boot2(14 * 3_600_000 + 1), &mut f);
    assert!(
        changes
            .iter()
            .any(|c| matches!(c, Change::RecoveryActive { .. })),
        "24 h of host time"
    );
    // Written before any effect.
    let stored = rig.read(DlFile::State).unwrap();
    assert_eq!(stored["recovery"][0]["state"], json!("active"));
}

#[test]
fn a_failed_recovery_write_fails_closed() {
    let v = vectors();
    let rig = Rig::new();
    rig.pin(&LOG6);
    let (mut host, mut f) = opened(&rig, 1);
    host.apply_carriage(&v.carry(&["R7"]), &t0(), &mut f);
    host.store_mut().inject(Injected {
        file: DlFile::State,
        step: Step::Rename,
    });
    let day = clock(WALL0 + 86_400_001, 1_000 + 86_400_001, "boot-1");
    let changes = host.advance(&day, &mut f);
    assert!(changes.is_empty());
    assert_eq!(
        host.membership().record(&v.hash("R7")).unwrap().state(),
        RecoveryState::Pending,
        "not in effect: never written"
    );
    assert!(host.faulted().is_some() && rig.exists(DlFile::Fault));
    assert_eq!(f.faults.len(), 1);
}

#[test]
fn unpair_keeps_a_frozen_genesis_and_removes_the_list() {
    let v = vectors();
    let rig = Rig::new();
    rig.pin(&LOG6);
    let (mut host, mut f) = opened(&rig, 1);
    host.apply_carriage(&v.carry(&["C6_mac"]), &t0(), &mut f);
    drop(host);
    std::fs::write(&rig.pairing.host_channel_key, b"seed").unwrap();
    forget_on_unpair(&rig.pairing).unwrap();
    for file in [
        DlFile::State,
        DlFile::Carriage,
        DlFile::Intent,
        DlFile::Freeze,
        DlFile::Fault,
    ] {
        assert!(!rig.exists(file), "{file:?}");
    }
    assert!(!rig.pairing.host_channel_key.exists());
    assert_eq!(frozen_genesis(&rig.pairing).unwrap(), vec![v.hash("E1")]);
    // The pairing check refuses it.
    let m = pinned(&LOG6, &t0());
    assert!(
        m.check_pairing(
            "host-a",
            1,
            &m.host("host-a").unwrap().host_key,
            &m.member("dev-mac").unwrap().member.auth_key,
            &frozen_genesis(&rig.pairing).unwrap(),
        )
        .is_err()
    );
    // Bounded at 16, oldest first out; an unfrozen list adds nothing.
    let list: Vec<String> = (0..16u8).map(|i| Hash32([i; 32]).to_hex()).collect();
    for path in [
        &rig.pairing.frozen_genesis,
        &super::frozen_genesis_mirror(&rig.pairing),
    ] {
        std::fs::write(path, json!({"v": 1, "genesis": list}).to_string()).unwrap();
    }
    rig.pin(&LOG6);
    forget_on_unpair(&rig.pairing).unwrap();
    assert_eq!(frozen_genesis(&rig.pairing).unwrap().len(), 16);
    rig.pin(&LOG6);
    std::fs::write(&rig.pairing.freeze, b"x").unwrap();
    forget_on_unpair(&rig.pairing).unwrap();
    let kept = frozen_genesis(&rig.pairing).unwrap();
    assert_eq!(kept.len(), 16);
    assert_eq!(kept.last(), Some(&v.hash("E1")));
    assert_eq!(kept[0], Hash32([1; 32]), "the oldest went");
}

#[test]
fn the_fault_record_counts_even_when_it_cant_be_read() {
    let rig = Rig::new();
    rig.pin(&LOG6);
    std::fs::write(&rig.pairing.fault, b"\xff").unwrap();
    let (host, _) = rig.open(1, &t0(), &mut remote()).unwrap();
    assert_eq!(host.held(), Some(&Held::Fault));
}

#[test]
fn a_fault_record_that_cant_be_written_still_halts() {
    let v = vectors();
    let rig = Rig::new();
    rig.pin(&LOG6);
    let (mut host, mut f) = opened(&rig, 1);
    host.store_mut().inject(Injected {
        file: DlFile::State,
        step: Step::TempWrite,
    });
    // The fault record's rename fails too, and its mirror's: a directory
    // is in their way.
    let mirror = Store::new(&rig.pairing, &rig.journal).path(DlFile::FaultMirror);
    std::fs::create_dir(&rig.pairing.fault).unwrap();
    std::fs::create_dir(&mirror).unwrap();
    let result = host.apply_carriage(&v.carry(&["E7"]), &t0(), &mut f);
    assert_eq!(result.carried, Carried::NotRecorded);
    assert!(host.faulted().is_some(), "halted all the same");
    assert_eq!(f.faults, vec![vec![SVC.to_owned()]]);
    drop(host);
    // The restart relies on the carriage record alone.
    std::fs::remove_dir(&rig.pairing.fault).unwrap();
    std::fs::remove_dir(&mirror).unwrap();
    let mut f2 = remote();
    let (host, _) = rig.open(2, &t0(), &mut f2).unwrap();
    assert_eq!(host.head(), v.head("E7"));
    assert_eq!(f2.fenced, vec![(SVC.to_owned(), 7)]);
    assert!(host.held().is_none());
}

#[test]
fn an_unpaired_list_is_never_written_again() {
    let v = vectors();
    let rig = Rig::new();
    rig.pin(&LOG6);
    let (mut host, mut f) = opened(&rig, 1);
    host.apply_carriage(&v.carry(&["R7"]), &t0(), &mut f);
    forget_on_unpair(&rig.pairing).unwrap();
    let later = clock(WALL0 + 120_000, 121_000, "boot-1");
    assert!(host.advance(&later, &mut f).is_empty());
    assert!(host.unpaired());
    assert_eq!(
        host.apply_carriage(&v.carry(&["E7"]), &later, &mut f)
            .carried,
        Carried::Unpaired
    );
    assert!(!host.close(&later));
    for file in [DlFile::State, DlFile::Carriage, DlFile::Intent] {
        assert!(!rig.exists(file), "{file:?} came back");
    }
}

/// Important 1: the carriage record can't be read and the fault record
/// can't be written either: the record stays, so the host is held at this
/// start and the next ones; a reconciling manager removes both.
#[test]
fn an_unreadable_record_whose_fault_cant_be_recorded_holds_across_restarts() {
    use std::os::unix::fs::PermissionsExt;
    let v = vectors();
    let rig = Rig::new();
    rig.pin(&LOG6);
    std::fs::write(&rig.pairing.carriage, b"\x00garbage").unwrap();
    let dir = rig.pairing.dir().to_path_buf();
    let mode = |m| std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(m)).unwrap();
    // Nothing can be created in pairing/: the fault record's write fails.
    mode(0o500);
    for epoch in [1, 2] {
        let (host, _) = rig.open(epoch, &t0(), &mut remote()).unwrap();
        assert_eq!(
            host.held(),
            Some(&Held::CarriageUnreadable),
            "start {epoch}"
        );
        assert!(!rig.exists(DlFile::Fault));
        assert!(
            rig.exists(DlFile::Carriage),
            "kept: it alone holds the host"
        );
    }
    mode(0o700);
    // Writable again: the third start records the fault, then removes the
    // record; a reconciling manager ends the hold.
    let (mut host, _) = rig.open(3, &t0(), &mut remote()).unwrap();
    assert!(host.held().is_some());
    assert!(rig.exists(DlFile::Fault) && !rig.exists(DlFile::Carriage));
    assert!(matches!(
        host.hello("dev-phone", Some(v.head("E6")), None, false, &t0()),
        Hello::Admit(Admission::Member { .. })
    ));
    drop(host);
    let (host, _) = rig.open(4, &t0(), &mut remote()).unwrap();
    assert!(host.held().is_none());
}

/// Minor 1: a satisfied intent or committed carriage record that can't be
/// removed is a harmless leftover: no fault, no hold; the next start
/// removes it.
#[test]
fn a_leftover_that_cant_be_removed_is_harmless() {
    let v = vectors();
    for file in [DlFile::Intent, DlFile::Carriage] {
        let rig = Rig::new();
        rig.pin(&LOG6);
        let (mut host, mut f) = opened(&rig, 1);
        host.store_mut().inject(Injected {
            file,
            step: Step::Remove,
        });
        let result = host.apply_carriage(&v.carry(&["E7"]), &t0(), &mut f);
        assert_eq!(result.carried, Carried::Committed, "{file:?}");
        assert!(host.faulted().is_none(), "{file:?}");
        assert!(f.faults.is_empty(), "{file:?}");
        assert!(!rig.exists(DlFile::Fault), "{file:?}");
        // The unsynced unlink "came back".
        let leftover = match file {
            DlFile::Intent => v.head("E7").to_json().to_string(),
            _ => json!({"v": 1, "runtime_epoch": 1, "base": v.head("E6").to_json(),
                        "entries": [v.wire("E7")]})
            .to_string(),
        };
        std::fs::write(Store::new(&rig.pairing, &rig.journal).path(file), leftover).unwrap();
        drop(host);
        let mut f2 = remote();
        let (host, _) = rig.open(2, &t0(), &mut f2).unwrap();
        assert!(host.held().is_none(), "{file:?}");
        assert!(!rig.exists(file), "{file:?}: removed at the next start");
        assert_eq!(host.head(), v.head("E7"));
    }
}

/// Minor 4: unpair, then a new pin of the same files: the old host (still
/// running) can't overwrite the new list.
#[test]
fn an_old_host_never_overwrites_a_new_pin() {
    let v = vectors();
    let rig = Rig::new();
    rig.pin(&LOG6);
    let (mut host, mut f) = opened(&rig, 1);
    host.apply_carriage(&v.carry(&["R7"]), &t0(), &mut f);
    forget_on_unpair(&rig.pairing).unwrap();
    // A new pairing pins the list again, in a newer trust generation.
    let m = pinned(&["E1", "E2", "E3", "E4", "E5"], &t0());
    let new_pin = HostPin {
        host_id: "host-a".into(),
        host_trust_gen: 2,
    };
    MembershipHost::pin(&rig.pairing, &rig.journal, &new_pin, &m, &host_a_seed()).unwrap();
    let before = std::fs::read(&rig.pairing.membership).unwrap();
    let later = clock(WALL0 + 120_000, 121_000, "boot-1");
    host.advance(&later, &mut f);
    assert!(host.unpaired());
    assert_eq!(
        host.apply_carriage(&v.carry(&["E6"]), &later, &mut f)
            .carried,
        Carried::Unpaired
    );
    assert!(!host.close(&later));
    assert_eq!(std::fs::read(&rig.pairing.membership).unwrap(), before);
    assert!(!rig.exists(DlFile::Carriage));
}

/// Minor 8: `trust_gen.lock` can't be taken: the pass fails closed (no
/// write without the lock), the clean checkpoint is skipped.
#[test]
fn no_write_without_the_lock() {
    let v = vectors();
    let rig = Rig::new();
    rig.pin(&LOG6);
    let (mut host, mut f) = opened(&rig, 1);
    host.apply_carriage(&v.carry(&["R7"]), &t0(), &mut f);
    let before = std::fs::read(&rig.pairing.membership).unwrap();
    // A symlink where the lock is: refused (O_NOFOLLOW).
    let lock = rig.pairing.dir().join("trust_gen.lock");
    let _ = std::fs::remove_file(&lock);
    std::os::unix::fs::symlink("/nonexistent", &lock).unwrap();
    let later = clock(WALL0 + 120_000, 121_000, "boot-1");
    assert!(!host.close(&later));
    assert_eq!(std::fs::read(&rig.pairing.membership).unwrap(), before);
    host.advance(&later, &mut f);
    assert!(host.faulted().is_some(), "the checkpoint failed closed");
    assert_eq!(f.faults.len(), 1);
    assert_eq!(std::fs::read(&rig.pairing.membership).unwrap(), before);
}

/// Minor 10: a group- or world-readable pairing directory is refused, as
/// for the journal.
#[test]
fn a_device_list_dir_that_isnt_0700_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let rig = Rig::new();
    rig.pin(&LOG6);
    std::fs::set_permissions(rig.pairing.dir(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(rig.open(1, &t0(), &mut remote()).is_err());
    assert!(store::private_dir(rig.pairing.dir()).is_err());
}

/// Minor 9: a `remove_host` of this host in a batch fences everyone else,
/// at its own entry; the other entries' fences keep their reasons and seqs.
#[test]
fn a_host_removal_in_a_batch_keeps_the_other_fences() {
    let v = vectors();
    let rig = Rig::new();
    rig.pin(&LOG6);
    let (host, _) = opened(&rig, 1);
    let eval = Evaluation {
        next: pinned(&LOG6, &t0()),
        carried: Vec::new(),
        appended: 2,
        effects: vec![
            Change::Appended(v.head("E6")),
            Change::MemberRemoved {
                device_id: "dev-ipad".into(),
            },
            Change::Appended(Head {
                seq: 7,
                hash: Hash32([7; 32]),
            }),
            Change::HostRemoved {
                host_id: "host-a".into(),
            },
        ],
        stop: None,
    };
    let fences = host.planned_fences(&eval).fences(&host, &remote(), true);
    assert_eq!(fences[0].principal, "member:dev-ipad");
    assert_eq!(fences[0].reason, FenceReason::Removed);
    assert_eq!(fences[0].seq, 6);
    assert!(
        fences[1..]
            .iter()
            .all(|f| f.reason == FenceReason::HostRemoved && f.seq == 7)
    );
    assert!(
        fences[1..]
            .iter()
            .any(|f| f.principal == "service:svc-discord")
    );
    assert_eq!(
        fences
            .iter()
            .filter(|f| f.principal == "member:dev-ipad")
            .count(),
        1,
        "each principal once"
    );
}

/// Re-review P1: held on an unreadable record whose fault record couldn't
/// be written; with `pairing/` writable again a carriage first records the
/// fault, then may replace the record: the restart stays held. While the
/// fault record still can't be written, the carriage is refused and the
/// record kept.
#[test]
fn a_carriage_never_clears_a_hold_held_by_its_record_alone() {
    use std::os::unix::fs::PermissionsExt;
    let v = vectors();
    for writable in [false, true] {
        let rig = Rig::new();
        rig.pin(&LOG6);
        std::fs::write(&rig.pairing.carriage, b"\x00garbage").unwrap();
        // Neither the fault record nor its mirror (in the journal's
        // directory) can be written.
        let dirs = [rig.pairing.dir().to_path_buf(), rig.journal.clone()];
        let mode = |m| {
            for dir in &dirs {
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(m)).unwrap();
            }
        };
        mode(0o500);
        let (mut host, _) = rig.open(1, &t0(), &mut remote()).unwrap();
        assert_eq!(host.held(), Some(&Held::CarriageUnreadable));
        if writable {
            mode(0o700);
        }
        let mut f = remote();
        let r = host.apply_carriage(&v.carry(&["E7"]), &t0(), &mut f);
        if writable {
            assert_eq!(r.carried, Carried::Committed);
            assert!(rig.exists(DlFile::Fault), "recorded before the record went");
        } else {
            assert_eq!(r.carried, Carried::NotRecorded, "fail closed");
            assert_eq!(
                std::fs::read(&rig.pairing.carriage).unwrap(),
                b"\x00garbage",
                "the evidence is untouched"
            );
        }
        assert!(host.held().is_some());
        drop(host);
        mode(0o700);
        let (host, _) = rig.open(2, &t0(), &mut remote()).unwrap();
        assert!(host.held().is_some(), "writable {writable}: still held");
    }
}

/// Re-review P1b: the same with an intent beyond the head (seq 9).
#[test]
fn a_carriage_never_clears_a_hold_held_by_its_intent_alone() {
    use std::os::unix::fs::PermissionsExt;
    let v = vectors();
    let far = Head {
        seq: 9,
        hash: Hash32([9; 32]),
    };
    for writable in [false, true] {
        let rig = Rig::new();
        rig.pin(&LOG6);
        let intent = Store::new(&rig.pairing, &rig.journal).path(DlFile::Intent);
        std::fs::write(&intent, far.to_json().to_string()).unwrap();
        // Neither the fault record nor its mirror (in the journal's
        // directory) can be written.
        let dirs = [rig.pairing.dir().to_path_buf(), rig.journal.clone()];
        let mode = |m| {
            for dir in &dirs {
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(m)).unwrap();
            }
        };
        mode(0o500);
        let (mut host, _) = rig.open(1, &t0(), &mut remote()).unwrap();
        assert_eq!(host.held(), Some(&Held::Unclean(far)));
        assert!(rig.exists(DlFile::Intent) && !rig.exists(DlFile::Fault));
        if writable {
            mode(0o700);
        }
        let mut f = remote();
        let r = host.apply_carriage(&v.carry(&["E7"]), &t0(), &mut f);
        if writable {
            assert_eq!(r.carried, Carried::Committed);
            let fault = rig.read(DlFile::Fault).unwrap();
            assert_eq!(
                Head::from_json(&fault["intent"]),
                Some(far),
                "the intent kept"
            );
        } else {
            assert_eq!(r.carried, Carried::NotRecorded);
            assert_eq!(
                std::fs::read_to_string(&intent).unwrap(),
                far.to_json().to_string()
            );
        }
        drop(host);
        mode(0o700);
        let (host, _) = rig.open(2, &t0(), &mut remote()).unwrap();
        assert_eq!(
            host.held(),
            Some(&Held::Unclean(far)),
            "writable {writable}"
        );
    }
}

/// Re-review P3 / New Important 2: an r9 leftover without `membership.json`
/// opens as a failure, never as "no device list".
#[test]
fn a_leftover_without_the_list_fails_closed() {
    for file in [
        DlFile::Carriage,
        DlFile::Intent,
        DlFile::Freeze,
        DlFile::Fault,
        DlFile::HostChannelKey,
        DlFile::Applied,
    ] {
        let rig = Rig::new();
        rig.pin(&LOG6);
        let store = Store::new(&rig.pairing, &rig.journal);
        std::fs::write(store.path(file), b"x").unwrap();
        std::fs::remove_file(&rig.pairing.membership).unwrap();
        let opened = MembershipHost::open(&rig.pairing, &rig.journal, 2, &t0(), &mut remote());
        let error = opened
            .err()
            .unwrap_or_else(|| panic!("{file:?}: not a failure"));
        assert!(error.contains("atem unpair"), "{error}");
    }
}

/// Re-review Minor 1: the 0700 error says how to fix it.
#[test]
fn the_private_dir_error_says_how_to_fix_it() {
    use std::os::unix::fs::PermissionsExt;
    let rig = Rig::new();
    rig.pin(&LOG6);
    std::fs::set_permissions(rig.pairing.dir(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let error = rig.open(1, &t0(), &mut remote()).unwrap_err();
    assert!(error.contains("chmod 700"), "{error}");
}

/// Re-review Minor 2: an old host's reconciliation never clears a newer
/// pin's fault record.
#[test]
fn an_old_host_never_clears_a_newer_pins_fault() {
    let v = vectors();
    let rig = Rig::new();
    rig.pin(&LOG6);
    std::fs::write(&rig.pairing.fault, b"{}").unwrap();
    let (mut host, _) = rig.open(1, &t0(), &mut remote()).unwrap();
    assert_eq!(host.held(), Some(&Held::Fault));
    let m = pinned(&LOG6, &t0());
    let new_pin = HostPin {
        host_id: "host-a".into(),
        host_trust_gen: 2,
    };
    MembershipHost::pin(&rig.pairing, &rig.journal, &new_pin, &m, &host_a_seed()).unwrap();
    std::fs::write(&rig.pairing.fault, b"{}").unwrap();
    assert_eq!(
        host.hello("dev-phone", Some(v.head("E6")), None, false, &t0()),
        Hello::NotReconciled
    );
    assert!(rig.exists(DlFile::Fault), "the newer pin's fault stays");
}

// ── Task 6 carry-overs (Task 7a) ──

/// `atem unpair` of a list that never had `membership_applied` writes the
/// unpairing marker first; when the list's own unlink then fails, the
/// unpair aborts with the host paired as it was and the marker taken back,
/// so the next start opens the list normally.
#[test]
fn an_aborted_unpair_takes_its_marker_back() {
    let rig = Rig::new();
    let src = crate::profile::Sources::in_dir(rig.dir.path());
    crate::pairing::tests::bound_profile(rig.dir.path(), "astation-a");
    rig.pin(&["E1", "E2"]);
    std::fs::remove_file(rig.journal.join("membership_applied")).unwrap();
    FORGET_FAULT.with(|f| {
        f.set(Some(Injected {
            file: DlFile::State,
            step: Step::Rename,
        }))
    });
    let err = crate::pairing::unpair(&src).unwrap_err();
    assert!(
        err.to_string().contains("could not remove the device list"),
        "{err}"
    );
    assert!(
        crate::records::PairingRecord::load(&rig.pairing)
            .unwrap()
            .is_some(),
        "still paired"
    );
    assert!(rig.pairing.membership.exists(), "the list is kept");
    assert!(!rig.exists(DlFile::Applied), "the marker was taken back");
    let (host, _) = rig
        .open(2, &clock(WALL0, 2_000, "boot-1"), &mut RecFences::default())
        .expect("opens as it was");
    assert_eq!(host.head(), vectors().head("E2"));
}

/// A marker that couldn't be taken back is read as no record (every fence
/// replayed); any other damaged record names the fix.
#[test]
fn an_unpairing_marker_beside_the_list_reads_as_no_record() {
    let rig = Rig::new();
    rig.pin(&["E1", "E2"]);
    std::fs::write(
        rig.journal.join("membership_applied"),
        br#"{"unpairing":true}"#,
    )
    .unwrap();
    let (host, _) = rig
        .open(2, &clock(WALL0, 2_000, "boot-1"), &mut RecFences::default())
        .expect("opens");
    assert_eq!(host.applied().head, vectors().head("E2"), "rewritten");
    std::fs::write(rig.journal.join("membership_applied"), b"{\"x\":1}").unwrap();
    let err = rig
        .open(3, &clock(WALL0, 3_000, "boot-1"), &mut RecFences::default())
        .unwrap_err();
    assert!(
        err.contains("is damaged; re-pair this host (atem unpair, then atem pair)"),
        "{err}"
    );
}

/// `host_channel_key` is written without a `serde_json::Value` in between
/// (every copy of the seed is wiped) and keeps its JSON shape.
#[test]
fn the_host_channel_key_keeps_its_shape() {
    let seed = [7u8; 32];
    let bytes = host_key_bytes(&seed);
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    let public = ed25519_dalek::SigningKey::from_bytes(&seed)
        .verifying_key()
        .to_bytes();
    assert_eq!(
        v,
        json!({"v": 1, "seed": atem_client::encoding::b64u(&seed),
               "pub": atem_client::encoding::b64u(&public)})
    );
}

/// Re-review N3: the unpair of a frozen list never replaces an unreadable
/// `frozen_genesis` (it may hold a genesis the write would forget): it
/// stops before anything changed, the host still paired with its list.
#[test]
fn an_unpair_never_replaces_an_unreadable_frozen_genesis() {
    let v = vectors();
    let rig = Rig::new();
    rig.pin(&LOG6);
    let (mut host, mut f) = opened(&rig, 1);
    host.apply_carriage(&v.carry(&["C6_mac"]), &t0(), &mut f);
    drop(host);
    std::fs::write(&rig.pairing.frozen_genesis, b"{not json").unwrap();
    let e = forget_on_unpair(&rig.pairing).unwrap_err();
    assert!(!e.begun, "{e:?}");
    assert!(rig.exists(DlFile::State), "still paired with its list");
    assert_eq!(
        std::fs::read(&rig.pairing.frozen_genesis).unwrap(),
        b"{not json"
    );
    assert!(frozen_genesis(&rig.pairing).is_err());
}

/// Re-review N3: an observed write fault holds the host; losing either
/// `membership.fault` or its mirror never lifts the hold (the other one
/// holds it at the restart). Only a managing device's reconciliation
/// removes both.
#[test]
fn losing_one_fault_record_never_lifts_the_hold() {
    let v = vectors();
    for lost in [DlFile::Fault, DlFile::FaultMirror] {
        let rig = Rig::new();
        rig.pin(&LOG6);
        let (mut host, mut f) = opened(&rig, 1);
        host.store_mut().inject(Injected {
            file: DlFile::State,
            step: Step::TempFsync,
        });
        host.apply_carriage(&v.carry(&["E7"]), &t0(), &mut f);
        drop(host);
        assert!(rig.exists(DlFile::Fault) && rig.exists(DlFile::FaultMirror));
        // The restart (which replays the carriage) is held.
        let (host, _) = rig.open(2, &t0(), &mut remote()).unwrap();
        assert_eq!(host.held(), Some(&Held::Fault), "{lost:?}");
        drop(host);
        let path = Store::new(&rig.pairing, &rig.journal).path(lost);
        std::fs::remove_file(&path).unwrap();
        let (mut host, _) = rig.open(3, &t0(), &mut remote()).unwrap();
        assert_eq!(host.held(), Some(&Held::Fault), "{lost:?} lost: still held");
        assert_eq!(
            host.hello("svc-discord", Some(v.head("E7")), None, false, &t0()),
            Hello::NotReconciled
        );
        // The manager at the head reconciles: both go.
        assert!(matches!(
            host.hello("dev-phone", Some(v.head("E7")), None, false, &t0()),
            Hello::Admit(Admission::Member { .. })
        ));
        assert!(!rig.exists(DlFile::Fault) && !rig.exists(DlFile::FaultMirror));
        drop(host);
        let (host, _) = rig.open(4, &t0(), &mut remote()).unwrap();
        assert!(host.held().is_none(), "{lost:?}: reconciled for good");
    }
}

/// Re-review F1: a pinned host always has its revoked grants' files (the
/// pin seeds them), and the list vouches for a wall-time floor.
#[test]
fn the_pin_seeds_the_revoked_grants_and_vouches_for_a_floor() {
    let rig = Rig::new();
    assert_eq!(super::pin_wall_floor(&rig.pairing), None, "no list: fresh");
    rig.pin(&LOG6);
    assert!(rig.journal.join("revoked_quarantine").exists());
    assert!(rig.journal.join("revoked_grants").exists());
    assert!(super::pin_wall_floor(&rig.pairing).unwrap() > 0);
}

// ── Capacity (D23) ──

use atem_client::membership::Capacity;

const ENTRIES_NEARLY: &str =
    "entries nearly full: renewals use one entry each; a full list needs re-pairing";
const MEMBERS_NEARLY: &str = "members nearly full: remove expired or unused services so a place stays free for a Recovery Kit";
const MEMBERS_FULL: &str = "members full: no device can be added and a Recovery Kit can't recover the account; remove expired or unused services";

#[test]
fn the_status_names_the_lists_use_of_its_limits_and_warns_from_90_percent() {
    assert_eq!(
        capacity_text(&Capacity::of(6, 3, 1)),
        "6/1024 entries, 3/256 members, 1/64 hosts"
    );
    assert_eq!(
        capacity_text(&Capacity::of(922, 3, 1)),
        format!("922/1024 entries, 3/256 members, 1/64 hosts; {ENTRIES_NEARLY}")
    );
    assert_eq!(
        capacity_text(&Capacity::of(40, 231, 1)),
        format!("40/1024 entries, 231/256 members, 1/64 hosts; {MEMBERS_NEARLY}")
    );
    assert_eq!(
        capacity_text(&Capacity::of(1024, 3, 1)),
        "1024/1024 entries, 3/256 members, 1/64 hosts; entries full: no device can be added, renewed or removed and a Recovery Kit can't recover the account; a full list needs re-pairing"
    );
    // Every limit at nearly full or full has its own warning, in order.
    assert_eq!(
        capacity_text(&Capacity::of(950, 256, 58)),
        format!(
            "950/1024 entries, 256/256 members, 58/64 hosts; {ENTRIES_NEARLY}; {MEMBERS_FULL}; hosts nearly full: remove hosts no longer used"
        )
    );
    assert!(
        capacity_text(&Capacity::of(10, 3, 64))
            .ends_with("64/64 hosts; hosts full: remove a host before adding one")
    );
    assert_eq!(
        capacity_text(&Capacity::of(10, 3, 57)),
        "10/1024 entries, 3/256 members, 57/64 hosts"
    );
}

#[test]
fn runtime_log_gets_one_line_naming_the_limits_that_cross() {
    let line = |b: (u64, u64, u64), a: (u64, u64, u64)| {
        capacity_crossing(&Capacity::of(b.0, b.1, b.2), &Capacity::of(a.0, a.1, a.2))
    };
    assert_eq!(line((900, 3, 1), (921, 3, 1)), None);
    assert_eq!(
        line((921, 3, 1), (922, 3, 1)).as_deref(),
        Some(
            format!(
                "entries nearly full: 922/1024 entries, 3/256 members, 1/64 hosts; {ENTRIES_NEARLY}"
            )
            .as_str()
        )
    );
    // Not again on every commit while nearly full, nor when it empties.
    assert_eq!(line((922, 3, 1), (960, 3, 1)), None);
    assert_eq!(line((960, 231, 1), (961, 230, 1)), None);
    assert!(
        line((1023, 3, 1), (1024, 3, 1))
            .unwrap()
            .starts_with("entries full: ")
    );
    // Only the limit that crossed is named, whatever else is full.
    assert!(
        line((950, 256, 57), (951, 256, 58))
            .unwrap()
            .starts_with("hosts nearly full: 951/1024 entries")
    );
    assert!(
        line((950, 230, 1), (951, 231, 1))
            .unwrap()
            .starts_with("members nearly full: ")
    );
    assert!(
        line((10, 230, 57), (11, 231, 58))
            .unwrap()
            .starts_with("members nearly full, hosts nearly full: ")
    );
}

#[test]
fn a_list_opened_nearly_full_is_logged_once_at_the_open() {
    assert_eq!(capacity_at_open(&Capacity::of(6, 3, 1)), None);
    assert_eq!(
        capacity_at_open(&Capacity::of(40, 256, 1)).as_deref(),
        Some(
            format!("opened with members full: 40/1024 entries, 256/256 members, 1/64 hosts; {MEMBERS_FULL}")
                .as_str()
        )
    );
}

#[test]
fn the_runtime_status_line_carries_the_capacity() {
    let rig = Rig::new();
    rig.pin(&LOG6);
    let (host, _) = opened(&rig, 1);
    let status =
        crate::runtime::host_bridge::device_list_status_of(Some(&host), None, 1, &t0()).unwrap();
    // L: six entries; the mac, the phone and the service (the iPad was
    // removed: its id stays used, its place is free).
    assert_eq!(
        status.text,
        "pinned at seq 6 (1 remote client); 6/1024 entries, 3/256 members, 1/64 hosts"
    );
}
