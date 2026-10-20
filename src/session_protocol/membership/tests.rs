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

    pub fn label_of(&self, hash: &Hash32) -> Option<String> {
        self.by_label
            .iter()
            .find(|(_, v)| v["entry_hash"].as_str() == Some(&hash.to_hex()))
            .map(|(l, _)| l.clone())
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
        MembershipHost::pin(&self.pairing, &self.journal, &pin_a(), &m).unwrap();
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
    pub halts: usize,
}

impl Fences for RecFences {
    fn fence(&mut self, principal: &str, seq: u64) {
        self.fenced.push((principal.to_owned(), seq));
    }
    fn fault(&mut self, principals: Option<&[String]>) {
        self.faults
            .push(principals.map_or_else(|| self.remote.clone(), |p| p.to_vec()));
    }
    fn halt(&mut self) {
        self.halts += 1;
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
    assert_eq!(frozen_genesis(&rig.pairing), vec![v.hash("E1")]);
    // The pairing check refuses it.
    let m = pinned(&LOG6, &t0());
    assert!(
        m.check_pairing(
            "host-a",
            1,
            &m.host("host-a").unwrap().host_key,
            &m.member("dev-mac").unwrap().member.auth_key,
            &frozen_genesis(&rig.pairing),
        )
        .is_err()
    );
    // Bounded at 16, oldest first out; an unfrozen list adds nothing.
    let list: Vec<String> = (0..16u8).map(|i| Hash32([i; 32]).to_hex()).collect();
    std::fs::write(
        &rig.pairing.frozen_genesis,
        json!({"v": 1, "genesis": list}).to_string(),
    )
    .unwrap();
    rig.pin(&LOG6);
    forget_on_unpair(&rig.pairing).unwrap();
    assert_eq!(frozen_genesis(&rig.pairing).len(), 16);
    rig.pin(&LOG6);
    std::fs::write(&rig.pairing.freeze, b"x").unwrap();
    forget_on_unpair(&rig.pairing).unwrap();
    let kept = frozen_genesis(&rig.pairing);
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
    // The fault record's rename fails too: a directory is in its way.
    std::fs::create_dir(&rig.pairing.fault).unwrap();
    let result = host.apply_carriage(&v.carry(&["E7"]), &t0(), &mut f);
    assert_eq!(result.carried, Carried::NotRecorded);
    assert!(host.faulted().is_some(), "halted all the same");
    assert_eq!(f.faults, vec![vec![SVC.to_owned()]]);
    drop(host);
    // The restart relies on the carriage record alone.
    std::fs::remove_dir(&rig.pairing.fault).unwrap();
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
