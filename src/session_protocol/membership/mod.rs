//! The host's durable r9 membership state (§R9.3–§R9.5): the verified
//! device list this host pinned at pairing, how carried suffixes become
//! durable before they are judged, freezes, the recorded write fault that
//! holds the host until a managing device reconciles it, the pending
//! recoveries on the host clock, and the replay at start.
//!
//! [`MembershipHost`] owns the files (`store`) and the in-memory log (the
//! `atem_client` verifier). It never touches attachments itself: every fence
//! goes through [`Fences`], which the runtime implements over its
//! `SessionHost` (r8 §H: the `control_revoked` fence with a raised
//! `control_gen`, attachments fenced, leases revoked, queued work rejected;
//! on a fault the same in memory, then the journal halts).
//!
//! **A carriage** ([`MembershipHost::apply_carriage`], one step of the
//! broker pass) that holds anything not stored already is written as the
//! carriage record first; only then is it evaluated. A commit writes the
//! intent (when the head moves), then `membership.json`, then the fences,
//! then `membership_applied`, then removes the intent and the record. A
//! freeze writes `membership.freeze`, then `membership.json`, then fences
//! every remote principal. Any failed write, fsync, rename or directory
//! fsync fails closed in the same step: the principals the uncommitted
//! change would fence (every remote principal when that can't be told: a
//! freeze, a carriage record that couldn't be written) are fenced in
//! memory, a freeze takes effect in memory, the journal halts, the fault is
//! recorded (`membership.fault`) and every later carriage of the run is
//! refused unread. Nothing is retried in the run. A failed
//! `membership_applied` write, or `trust_gen.lock` that can't be taken, is
//! such a fault too. A satisfied intent or committed carriage record that
//! can't be removed is a harmless leftover (§R9.3): no fault, no hold; the
//! next start removes it.
//!
//! **Fences are stricter than §R9.3's wording on purpose:** every r9 fence
//! (removal, `set_roles` of roles, scope or expiry, `remove_host` of this
//! host, a freeze) closes all of the principal's attachments, view ones
//! included, not only those with `control`; the client is re-admitted under
//! its new standing. "Every remote principal" is the session host's known
//! principals plus every member of the log.
//!
//! A host writes only while `membership.json` still names the pin it
//! opened (account, genesis, host and trust generation): after `atem
//! unpair` (which removes the list first, under `trust_gen.lock`) or a new
//! pin, the old host never writes again. A list that exists but can't be
//! opened is [`DeviceList::Failed`], distinct from no list: r9 admission is
//! refused on it (Task 7); r8 is unaffected.
//!
//! **At start** ([`MembershipHost::open`], before any remote admission and
//! before the session host resolves recovered work): `membership.json` and
//! its directory are fsynced; a freeze file in any state freezes; a
//! readable carriage record is replayed exactly as when it arrived (an
//! unreadable one holds the host); fences after `membership_applied` are
//! replayed (idempotent: the fence names the entry's `seq`); an intent left
//! beyond the head holds the host. A fault record holds it until a
//! [`MembershipHost::hello`] from a `native` manager whose carriage was clean
//! and whose verified head is the host's (reconciliation removes the
//! record). A crash with no recorded fault resumes normally.
//!
//! **Recovery waits** run on the host clock ([`host_now`]: wall time,
//! `CLOCK_MONOTONIC` and the boot id); [`MembershipHost::advance`] (the
//! 100 ms pass) ends them, writing `membership.json` before any effect, and
//! persists the time waited at least once a minute; [`MembershipHost::close`]
//! at an orderly stop writes it with the clean checkpoint naming the run's
//! `runtime_epoch`.
pub mod pairing;
pub mod store;

#[cfg(test)]
mod e2e_tests;
#[cfg(test)]
mod fixtures_tests;
#[cfg(test)]
mod pairing_tests;
/// The test account's device list builder, shared with the binary tests.
#[cfg(test)]
#[path = "../../../tests/support/r9log.rs"]
pub(crate) mod r9log;
#[cfg(test)]
mod tests;

use super::host::{Effect, SessionHost};
use super::journal::Journal;
use crate::paths::PairingPaths;
use atem_client::canonical::StrictValue;
use atem_client::encoding::Hash32;
use atem_client::membership::entry::{Action, Member, MemberKind, Role};
use atem_client::membership::stored::{freeze_to_json, parse_freeze};
use atem_client::membership::{
    Admission, Effect as Change, Evaluation, Head, HostNow, Membership, RecoveryState,
};
use serde_json::{Map, Value, json};
use std::path::Path;
use store::{DlFile, Store, WriteError};

/// `busy` detail when a carriage couldn't be made durable (§R9.3).
pub const DETAIL_NOT_RECORDED: &str = "device list not recorded";
/// `busy` detail while the host is held (§R9.3).
pub const DETAIL_NOT_RECONCILED: &str = "device list not reconciled";
/// Evidence is persisted at most this often (§R9.3 bounds).
const EVIDENCE_PERSIST_MS: u64 = 60_000;
/// The time waited is persisted at least this often (§R9.5).
const CHECKPOINT_MS: u64 = 60_000;
/// r9 files that exist only with a device list (§R9.3): one of them
/// without `membership.json` is a damaged or half-removed list.
const LEFTOVERS: [DlFile; 6] = [
    DlFile::Carriage,
    DlFile::Intent,
    DlFile::Freeze,
    DlFile::Fault,
    DlFile::HostChannelKey,
    DlFile::Applied,
];
/// `membership_applied` while `atem unpair` removes a list that never had
/// one (so a half-done removal still opens as failed, never as none).
const UNPAIRING_MARKER: &[u8] = br#"{"unpairing":true}"#;
/// `frozen_genesis` keeps at most this many hashes.
const MAX_FROZEN_GENESIS: usize = 16;

/// The host clock of §R9.5: wall time, `CLOCK_MONOTONIC` and the boot it
/// belongs to (the debug hook `ATEM_TEST_HOST_CLOCK` replaces all three).
pub fn host_now() -> HostNow {
    if let Some((wall_ms, mono_ms, boot_id)) = crate::runtime::test_hooks::host_clock() {
        return HostNow {
            wall_ms,
            mono_ms,
            boot_id,
        };
    }
    let wall_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid timespec for the call to fill.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    let mono_ms = ts.tv_sec as u64 * 1000 + ts.tv_nsec as u64 / 1_000_000;
    HostNow {
        wall_ms,
        mono_ms,
        boot_id: boot_id(),
    }
}

/// This boot's id. Unknown (unreadable) → a fresh id per process, so only
/// the persisted time waited carries over (the wait only gets longer).
fn boot_id() -> String {
    static ID: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    ID.get_or_init(|| {
        #[cfg(target_os = "linux")]
        if let Ok(id) = std::fs::read_to_string("/proc/sys/kernel/random/boot_id") {
            return id.trim().to_string();
        }
        // macOS: `kern.boottime` can shift when the wall clock is stepped;
        // that reads as a reboot, which only lengthens a wait (safe).
        #[cfg(target_os = "macos")]
        {
            let mut tv = libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            };
            let mut size = std::mem::size_of::<libc::timeval>();
            let name = c"kern.boottime";
            // SAFETY: `tv` and `size` describe a valid buffer for the value.
            let rc = unsafe {
                libc::sysctlbyname(
                    name.as_ptr(),
                    (&mut tv as *mut libc::timeval).cast(),
                    &mut size,
                    std::ptr::null_mut(),
                    0,
                )
            };
            if rc == 0 {
                return format!("boot-{}.{}", tv.tv_sec, tv.tv_usec);
            }
        }
        format!("unknown-{}", uuid::Uuid::new_v4())
    })
    .clone()
}

/// The host this device list names (`membership.json`'s `host`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPin {
    pub host_id: String,
    pub host_trust_gen: u64,
}

/// Why a principal was fenced (Task 7 turns these into the client's error).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FenceReason {
    /// A removal (`unauthorized` "removed").
    Removed,
    /// `set_roles` (roles, scope, expiry): re-admitted under the new standing.
    Revoked,
    /// `remove_host` of this host.
    HostRemoved,
    /// A freeze (`account_frozen`).
    Frozen,
    /// A device-list write failed before Atem could tell what it changed
    /// (`busy` "device list not recorded").
    NotRecorded,
}

/// A fence of one principal (`member:<id>`, `service:<id>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fence {
    pub principal: String,
    pub reason: FenceReason,
    /// The membership entry that fenced it (0: a freeze or a fault).
    pub seq: u64,
    /// Durable (`control_revoked` written) or in memory only (a fault).
    pub durable: bool,
}

/// The session host's side of the fences (r8 §H).
pub trait Fences {
    /// The durable §H fence of `principal` by entry `seq` (0: no entry):
    /// idempotent per entry.
    fn fence(&mut self, principal: &str, seq: u64);
    /// A device-list fault: `principals` (every remote one with `None`)
    /// fenced in memory, then the journal halts.
    fn fault(&mut self, principals: Option<&[String]>);
    /// A journal write of the step failed (`membership_applied`): the journal
    /// halts (r8 §I).
    fn halt(&mut self);
    /// Every remote principal the host knows.
    fn remote_principals(&self) -> Vec<String>;
}

/// [`Fences`] over a `SessionHost`, collecting its effects for the runtime.
pub struct HostFences<'a, J: Journal> {
    pub host: &'a mut SessionHost<J>,
    pub effects: Vec<Effect>,
}

impl<'a, J: Journal> HostFences<'a, J> {
    pub fn new(host: &'a mut SessionHost<J>) -> Self {
        Self {
            host,
            effects: Vec::new(),
        }
    }
}

impl<J: Journal> Fences for HostFences<'_, J> {
    fn fence(&mut self, principal: &str, seq: u64) {
        let fx = self.host.fence_principal(principal, seq);
        self.effects.extend(fx);
    }

    fn fault(&mut self, principals: Option<&[String]>) {
        let fx = self.host.membership_fault(principals);
        self.effects.extend(fx);
    }

    fn halt(&mut self) {
        let fx = self.host.membership_fault(Some(&[]));
        self.effects.extend(fx);
    }

    fn remote_principals(&self) -> Vec<String> {
        self.host.remote_principals()
    }
}

/// What a carriage did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Carried {
    /// Nothing to write (the same entries, an invalid or deferred tail with
    /// nothing before it, a window that needs an earlier start).
    Unchanged,
    /// Committed: entries, decisions, evidence or a replaced veto.
    Committed,
    /// The host is frozen (now or before): `account_frozen`.
    Frozen,
    /// A write failed: `busy` "device list not recorded"; fenced in memory,
    /// the journal halted.
    NotRecorded,
    /// Refused unread: a fault earlier in this run.
    Refused,
    /// The device list was removed (`atem unpair`) while the runtime ran:
    /// nothing is written again.
    Unpaired,
    /// Tests: the runtime "died" right after `membership.json` was durable.
    Crashed,
}

/// The result of [`MembershipHost::apply_carriage`].
#[derive(Debug)]
pub struct CarriageResult {
    pub carried: Carried,
    /// The evaluation (its `next` is the committed log), when one ran.
    pub evaluation: Option<Evaluation>,
    /// Principals fenced by this carriage, in order.
    pub fences: Vec<Fence>,
    /// The head moved, or a pending entry started or ended: every attachment
    /// gets `membership_head` (Task 7).
    pub announce: bool,
}

impl CarriageResult {
    fn plain(carried: Carried) -> Self {
        CarriageResult {
            carried,
            evaluation: None,
            fences: Vec::new(),
            announce: false,
        }
    }

    /// No conflicting, invalid or deferred entry (reconciliation, §R9.3).
    pub fn clean(&self) -> bool {
        matches!(self.carried, Carried::Unchanged | Carried::Committed)
            && self.evaluation.as_ref().is_none_or(|e| e.stop.is_none())
    }
}

/// The answer to a `hello` after its carriage (§R9.3 step 5, "Held").
/// Returned once per `hello`, never stored: its size doesn't matter.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub enum Hello {
    /// The membership side of admission (Task 7 adds scope, expiry, keys).
    Admit(Admission),
    /// `busy` "device list not reconciled".
    NotReconciled,
    /// `busy` "device list not recorded" (a fault in this run).
    NotRecorded,
    /// `account_frozen`.
    Frozen,
}

/// An `init` before any key work (§R9.3, §R9.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Init {
    Accept,
    /// `account_frozen`.
    Frozen,
    /// `busy`: a device-list fault halted this run.
    Busy,
}

/// The runtime's device list as opened at start (§R9.3 "Crash recovery").
#[derive(Debug, Clone, Copy)]
pub enum DeviceList<'a> {
    /// No device list: this host isn't paired for r9.
    None,
    Open(&'a MembershipHost),
    /// It exists but couldn't be opened (damaged, unsynced, an applied head
    /// it doesn't hold): r9 admission must be refused (Task 7); r8 is
    /// unaffected.
    Failed(&'a str),
}

/// `membership_applied`: the head whose fences are durable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Applied {
    pub head: Head,
    /// The freeze's fences are durable too.
    pub frozen: bool,
}

/// Why the host is held.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Held {
    /// A fault record (in any state).
    Fault,
    /// The carriage record couldn't be read at start.
    CarriageUnreadable,
    /// An intent left beyond the head (`membership_unclean`).
    Unclean(Head),
    /// An intent whose `seq` holds another entry: only re-pairing ends it.
    IntentMismatch(Head),
}

pub struct MembershipHost {
    store: Store,
    m: Membership,
    pin: HostPin,
    runtime_epoch: u64,
    /// A freeze file exists but couldn't be read: frozen, without evidence.
    frozen_unreadable: bool,
    /// A device-list write failed in this run (why).
    faulted: Option<String>,
    held: Option<Held>,
    applied: Applied,
    evidence_dirty: bool,
    evidence_written_at: Option<u64>,
    checkpoint_at: u64,
    /// The previous run's clean checkpoint epoch, as read at start.
    previous_checkpoint: Option<u64>,
    /// `membership.json` disappeared (`atem unpair`): this host stops.
    unpaired: bool,
    #[cfg(test)]
    crash_after_commit: bool,
}

impl std::fmt::Debug for MembershipHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MembershipHost")
            .field("head", &self.m.head())
            .field("faulted", &self.faulted)
            .field("held", &self.held)
            .finish_non_exhaustive()
    }
}

/// The principal a member speaks for (§R9.6).
pub fn principal_of(member: &Member) -> String {
    match member.kind {
        MemberKind::Native { .. } => format!("member:{}", member.device_id),
        MemberKind::Service { .. } => format!("service:{}", member.device_id),
    }
}

fn head_json(head: &Head) -> Value {
    head.to_json()
}

fn parse_json(bytes: &[u8]) -> Option<Value> {
    serde_json::from_slice(bytes).ok()
}

fn log(line: &str) {
    eprintln!("atem runtime: device list: {line}");
}

/// What a failed step makes uncertain: which principals it would fence.
struct Scope {
    /// These principals, each with its own reason and entry.
    list: Vec<Fence>,
    /// And every other remote principal, with this reason and entry (a
    /// `remove_host` of this host, a freeze, a carriage nobody evaluated).
    all: Option<(FenceReason, u64)>,
}

impl Scope {
    fn none() -> Scope {
        Scope {
            list: Vec::new(),
            all: None,
        }
    }

    fn all(reason: FenceReason) -> Scope {
        Scope {
            list: Vec::new(),
            all: Some((reason, 0)),
        }
    }

    /// The fences, in order: the listed ones, then everyone else.
    fn fences(self, host: &MembershipHost, fences: &dyn Fences, durable: bool) -> Vec<Fence> {
        let mut out: Vec<Fence> = self
            .list
            .into_iter()
            .map(|f| Fence { durable, ..f })
            .collect();
        if let Some((reason, seq)) = self.all {
            for principal in host.all_remote(fences) {
                if !out.iter().any(|f| f.principal == principal) {
                    out.push(Fence {
                        principal,
                        reason,
                        seq,
                        durable,
                    });
                }
            }
        }
        out
    }
}

impl MembershipHost {
    // ── Pairing and start ──

    /// Writes a pinned, verified log (pairing, R9.2), its
    /// `host_channel_key` and `membership_applied` at its head, under
    /// `trust_gen.lock`. Replaces any earlier device list: every r9 file
    /// left from an earlier one goes first (a stale carriage record, fault,
    /// freeze, key or applied head never survives a new pin).
    pub fn pin(
        pairing: &PairingPaths,
        journal_dir: &Path,
        pin: &HostPin,
        m: &Membership,
        host_seed: &[u8; 32],
    ) -> Result<(), String> {
        let store = Store::new(pairing, journal_dir);
        let _lock = store.lock().map_err(|e| e.to_string())?;
        Self::pin_locked(pairing, journal_dir, pin, m, host_seed)
    }

    /// [`MembershipHost::pin`] for a caller already holding
    /// `trust_gen.lock` (the pairing ceremony's apply).
    pub fn pin_locked(
        pairing: &PairingPaths,
        journal_dir: &Path,
        pin: &HostPin,
        m: &Membership,
        host_seed: &[u8; 32],
    ) -> Result<(), String> {
        let mut store = Store::new(pairing, journal_dir);
        #[cfg(test)]
        if let Some(injected) = PIN_FAULT.with(|f| f.take()) {
            store.inject(injected);
        }
        // `membership.json` first: a pin interrupted after it fails closed
        // (a leftover without the list) until the next pin or unpair.
        store.remove(DlFile::State).map_err(|e| e.to_string())?;
        for file in LEFTOVERS {
            store.remove(file).map_err(|e| e.to_string())?;
        }
        store
            .replace(DlFile::HostChannelKey, &host_key_bytes(host_seed))
            .map_err(|e| e.to_string())?;
        let applied = Applied {
            head: m.head(),
            frozen: m.frozen().is_some(),
        };
        store
            .replace(DlFile::Applied, &applied_bytes(&applied))
            .map_err(|e| e.to_string())?;
        // The list last: until it is there, whatever was written is a
        // leftover that fails closed.
        store
            .replace(DlFile::State, &state_bytes(m, pin, None))
            .map_err(|e| e.to_string())
    }

    /// Opens the device list at a runtime start (§R9.3 "Crash recovery"),
    /// before any remote admission and before the session host resolves its
    /// recovered work. `None` when this host has no device list (not paired
    /// for r9). An `Err` disables remote sessions (`welcome.host_error`):
    /// nothing is reset silently.
    pub fn open(
        pairing: &PairingPaths,
        journal_dir: &Path,
        runtime_epoch: u64,
        now: &HostNow,
        fences: &mut dyn Fences,
    ) -> Result<Option<(MembershipHost, Vec<Fence>)>, String> {
        let store = Store::new(pairing, journal_dir);
        let state_path = store.path(DlFile::State);
        if !store::present(&state_path) {
            // Any r9 leftover without the list (an `atem unpair` that
            // stopped midway, a damaged profile) fails closed: never "not
            // an r9 host" on a host that was one.
            let leftovers: Vec<&str> = LEFTOVERS
                .into_iter()
                .filter(|f| store.present(*f))
                .map(DlFile::name)
                .collect();
            if !leftovers.is_empty() {
                return Err(format!(
                    "the device list is missing but {} is there; run atem unpair, then atem pair",
                    leftovers.join(", ")
                ));
            }
            return Ok(None);
        }
        let _lock = store.lock().map_err(|e| e.to_string())?;
        store
            .sync_at_start()
            .map_err(|e| format!("cannot sync {}: {e}", state_path.display()))?;
        let damaged = || {
            format!(
                "{} is damaged; re-pair this host (atem unpair, then atem pair)",
                state_path.display()
            )
        };
        let bytes = store
            .read(DlFile::State)
            .map_err(|e| format!("cannot read {}: {e}", state_path.display()))?
            .ok_or_else(damaged)?;
        let value = parse_json(&bytes).ok_or_else(damaged)?;
        let (m, pin, previous_checkpoint) = parse_state(&value).ok_or_else(damaged)?;
        let applied = match store.read(DlFile::Applied) {
            // An `atem unpair` that stopped before the list's removal began
            // and couldn't take its marker back: as if no record (every
            // fence is replayed, idempotently).
            Ok(Some(bytes)) if bytes == UNPAIRING_MARKER => None,
            Ok(Some(bytes)) => Some(parse_applied(&bytes).ok_or_else(|| {
                format!(
                    "{} is damaged; re-pair this host (atem unpair, then atem pair)",
                    store.path(DlFile::Applied).display()
                )
            })?),
            Ok(None) => None,
            Err(e) => return Err(format!("cannot read membership_applied: {e}")),
        };
        if let Some(a) = &applied {
            let ours = m.entry(a.head.seq).map(|e| e.hash());
            if a.head.seq > m.head().seq || ours != Some(a.head.hash) {
                return Err(format!(
                    "{} names a head the device list doesn't hold",
                    store.path(DlFile::Applied).display()
                ));
            }
        }
        let fault_present = store.present(DlFile::Fault);
        let fault_intent = store
            .read(DlFile::Fault)
            .ok()
            .flatten()
            .and_then(|b| parse_json(&b))
            .and_then(|v| v.get("intent").and_then(Head::from_json));
        let mut host = MembershipHost {
            store,
            m,
            pin,
            runtime_epoch,
            frozen_unreadable: false,
            faulted: None,
            held: None,
            // No record: replay every entry's fences (idempotent).
            applied: applied.unwrap_or(Applied {
                head: Head {
                    seq: 0,
                    hash: Hash32([0; 32]),
                },
                frozen: false,
            }),
            evidence_dirty: false,
            evidence_written_at: None,
            checkpoint_at: now.mono_ms,
            previous_checkpoint,
            unpaired: false,
            #[cfg(test)]
            crash_after_commit: false,
        };
        // The first clock reading of this run: time before it isn't counted.
        host.m.checkpoint(now);

        // 1. A freeze file in any state.
        if host.store.present(DlFile::Freeze) && host.m.frozen().is_none() {
            let freeze = host
                .store
                .read(DlFile::Freeze)
                .ok()
                .flatten()
                .and_then(|b| parse_json(&b))
                .and_then(|v| parse_freeze(&v).ok());
            let restored = freeze.is_some_and(|freeze| host.m.restore_freeze(freeze).is_ok());
            if !restored {
                host.frozen_unreadable = true;
            }
        }

        let mut fenced = Vec::new();
        // 2. The carriage record, replayed as when it arrived.
        if host.store.present(DlFile::Carriage) {
            let record = host
                .store
                .read(DlFile::Carriage)
                .ok()
                .flatten()
                .and_then(|b| parse_json(&b))
                .and_then(|v| parse_carriage(&v));
            match record {
                Some(entries) => {
                    if !host.is_frozen() {
                        let result = host.commit_carriage(&entries, now, fences, true);
                        fenced.extend(result.fences);
                    } else {
                        host.remove_leftover(DlFile::Carriage);
                    }
                }
                None => {
                    log("the carriage record can't be read; held until a manager reconciles");
                    host.held = Some(Held::CarriageUnreadable);
                    host.record_fault(DlFile::Carriage, None, now);
                    // Removed only once the fault record holds the host;
                    // else the record itself holds it at the next start.
                    if host.store.present(DlFile::Fault) {
                        let _ = host.store.remove(DlFile::Carriage);
                    }
                }
            }
        }
        // The freeze's own `membership.json` write, if it was lost.
        if host.m.frozen().is_some() && !host.state_says_frozen() && host.faulted.is_none() {
            host.write_state(now, fences, &mut fenced);
        }

        // 3. Fences after `membership_applied`.
        if host.faulted.is_none() {
            host.replay_fences(now, fences, &mut fenced);
        }

        // 4. Held: a fault record, an unreadable record, an intent left over.
        if host.store.present(DlFile::Intent) {
            let intent = host
                .store
                .read(DlFile::Intent)
                .ok()
                .flatten()
                .and_then(|b| parse_json(&b))
                .and_then(|v| Head::from_json(&v));
            match intent {
                Some(intent) if host.m.entry(intent.seq).map(|e| e.hash()) == Some(intent.hash) => {
                    // Reached: harmless.
                    let _ = host.store.remove(DlFile::Intent);
                }
                intent => {
                    let intent = intent.unwrap_or(Head {
                        seq: u64::MAX,
                        hash: Hash32([0; 32]),
                    });
                    log("an intent is left beyond the head; held until a manager reconciles");
                    host.record_fault(DlFile::Intent, Some(intent), now);
                    if host.store.present(DlFile::Fault) {
                        let _ = host.store.remove(DlFile::Intent);
                    }
                    host.held = Some(host.intent_hold(intent));
                }
            }
        }
        if host.held.is_none() && (fault_present || host.store.present(DlFile::Fault)) {
            host.held = Some(match fault_intent {
                Some(intent) => host.intent_hold(intent),
                None => Held::Fault,
            });
        }
        if let Some(held) = &host.held {
            log(&format!(
                "held ({held:?}): remote access waits for a managing device"
            ));
        }
        Ok(Some((host, fenced)))
    }

    /// An intent not satisfied by the head: beyond it, or another entry at
    /// its `seq`.
    fn intent_hold(&self, intent: Head) -> Held {
        match self.m.entry(intent.seq) {
            Some(e) if e.hash() == intent.hash => Held::Fault,
            Some(_) => Held::IntentMismatch(intent),
            None => Held::Unclean(intent),
        }
    }

    fn state_says_frozen(&self) -> bool {
        self.store
            .read(DlFile::State)
            .ok()
            .flatten()
            .and_then(|b| parse_json(&b))
            .is_some_and(|v| v.get("frozen").is_some())
    }

    // ── Queries ──

    pub fn membership(&self) -> &Membership {
        &self.m
    }

    pub fn head(&self) -> Head {
        self.m.head()
    }

    pub fn pin_of(&self) -> &HostPin {
        &self.pin
    }

    /// Frozen: durably, in memory after a failed freeze write, or by a
    /// freeze file that couldn't be read.
    pub fn is_frozen(&self) -> bool {
        self.m.frozen().is_some() || self.frozen_unreadable
    }

    /// The freeze file is on disk (in any state).
    pub fn frozen_durable(&self) -> bool {
        self.store.present(DlFile::Freeze)
    }

    /// A device-list write failed in this run: remote admission, dispatch
    /// and remote input are stopped (the journal halted) until the restart.
    pub fn faulted(&self) -> Option<&str> {
        self.faulted.as_deref()
    }

    /// No remote admission until a manager reconciles (§R9.3).
    pub fn held(&self) -> Option<&Held> {
        self.held.as_ref()
    }

    /// An intent beyond the head (`membership_unclean`).
    pub fn unclean(&self) -> Option<Head> {
        match &self.held {
            Some(Held::Unclean(head) | Held::IntentMismatch(head)) => Some(*head),
            _ => None,
        }
    }

    pub fn applied(&self) -> Applied {
        self.applied
    }

    pub fn carriage_record_present(&self) -> bool {
        self.store.present(DlFile::Carriage)
    }

    pub fn fault_record_present(&self) -> bool {
        self.store.present(DlFile::Fault)
    }

    /// The previous run's clean checkpoint named this `runtime_epoch`.
    pub fn previous_checkpoint(&self) -> Option<u64> {
        self.previous_checkpoint
    }

    /// `atem unpair` removed the device list while this runtime ran: the
    /// runtime drops this host (nothing is written again).
    pub fn unpaired(&self) -> bool {
        self.unpaired
    }

    /// Whether the device list is still there; once it is gone (`atem
    /// unpair`, which removes it under `trust_gen.lock`) this host never
    /// writes again, so an unpaired list isn't brought back. Callers that
    /// write hold the lock.
    fn still_paired(&mut self) -> bool {
        if !self.unpaired && !store::present(&self.store.path(DlFile::State)) {
            log("the device list was removed (atem unpair); remote membership stops");
            self.unpaired = true;
        }
        !self.unpaired
    }

    /// Before a write: `trust_gen.lock`, then the pinned identity checked
    /// against `membership.json` (account, genesis, host and its trust
    /// generation, as this host opened them). `Ok(None)`: the list was
    /// removed or replaced by another pin (`atem unpair`, `atem pair`)
    /// while this runtime ran, so this host never writes again. `Err`: the
    /// lock couldn't be taken (a write fault of `file`).
    fn lock_for_write(
        &mut self,
        file: DlFile,
    ) -> Result<Option<crate::memory::trust::TrustLock>, WriteError> {
        let lock = self.store.lock().map_err(|e| WriteError {
            file,
            step: store::Step::TempWrite,
            message: format!("cannot take trust_gen.lock: {e}"),
        })?;
        if !self.unpaired && !self.same_pin() {
            log("the device list was removed or re-pinned; this host no longer writes it");
            self.unpaired = true;
        }
        Ok((!self.unpaired).then_some(lock))
    }

    /// While held, the evidence that holds the host (a kept carriage record
    /// or intent) may be overwritten or removed only once the fault record
    /// is durable: it is written again here if it is missing. Still
    /// missing: a fault of the carriage (refused unread, fail closed), and
    /// nothing of the evidence is touched.
    fn hold_is_durable(&mut self, now: &HostNow) -> Result<(), WriteError> {
        let Some(held) = self.held.clone() else {
            return Ok(());
        };
        if self.store.present(DlFile::Fault) {
            return Ok(());
        }
        let (file, intent) = match held {
            Held::Unclean(intent) | Held::IntentMismatch(intent) => (DlFile::Intent, Some(intent)),
            Held::CarriageUnreadable => (DlFile::Carriage, None),
            Held::Fault => (DlFile::Fault, None),
        };
        self.record_fault(file, intent, now);
        if self.store.present(DlFile::Fault) {
            Ok(())
        } else {
            Err(WriteError {
                file: DlFile::Fault,
                step: store::Step::TempWrite,
                message: "the hold's fault record can't be written; the carriage is refused".into(),
            })
        }
    }

    /// `membership.json` still names this host's pin.
    fn same_pin(&self) -> bool {
        #[derive(serde::Deserialize)]
        struct Pin {
            account_id: String,
            genesis_hash: String,
            host: HostField,
        }
        #[derive(serde::Deserialize)]
        struct HostField {
            host_id: String,
            host_trust_gen: u64,
        }
        let Ok(Some(bytes)) = self.store.read(DlFile::State) else {
            return false;
        };
        let Ok(pin) = serde_json::from_slice::<Pin>(&bytes) else {
            return false;
        };
        pin.account_id == self.m.account_id()
            && pin.genesis_hash == self.m.genesis_hash().to_hex()
            && pin.host.host_id == self.pin.host_id
            && pin.host.host_trust_gen == self.pin.host_trust_gen
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    pub fn store_mut(&mut self) -> &mut Store {
        &mut self.store
    }

    /// The runtime is killed (tests: `Carried::Crashed`) right after the next
    /// durable `membership.json`, before its fences.
    #[cfg(test)]
    pub fn crash_after_commit(&mut self) {
        self.crash_after_commit = true;
    }

    /// `init` (§R9.3, §R9.4): frozen first, then a fault of this run.
    pub fn init(&self) -> Init {
        if self.is_frozen() {
            Init::Frozen
        } else if self.faulted.is_some() {
            Init::Busy
        } else {
            Init::Accept
        }
    }

    // ── Carriage ──

    /// Applies a carried suffix or window (§R9.3 "Applying a carriage",
    /// "Writing the device list"), from any route or the host's own relay
    /// fetch: one step of the broker pass, before the carrier's admission.
    pub fn apply_carriage(
        &mut self,
        carried: &[StrictValue],
        now: &HostNow,
        fences: &mut dyn Fences,
    ) -> CarriageResult {
        if !self.still_paired() {
            return CarriageResult::plain(Carried::Unpaired);
        }
        if self.is_frozen() {
            return CarriageResult::plain(Carried::Frozen);
        }
        if self.faulted.is_some() {
            return CarriageResult::plain(Carried::Refused);
        }
        // Waits that ended are applied (and written) first, as the 100 ms
        // pass would.
        let mut early = Vec::new();
        let advanced = self.advance(now, fences);
        if self.faulted.is_some() {
            return CarriageResult::plain(Carried::Refused);
        }
        if !self.holds_anything_new(carried) {
            let eval = self.m.evaluate(carried, now);
            let mut result = CarriageResult::plain(Carried::Unchanged);
            result.announce = !advanced.is_empty();
            result.evaluation = Some(eval);
            return result;
        }
        let record = carriage_bytes(self.runtime_epoch, &self.m.head(), carried);
        let written = match self.lock_for_write(DlFile::Carriage) {
            Ok(None) => return CarriageResult::plain(Carried::Unpaired),
            Ok(Some(lock)) => self
                .hold_is_durable(now)
                .and_then(|()| self.store.replace(DlFile::Carriage, &record))
                .map(|()| lock),
            Err(e) => Err(e),
        };
        let _lock = match written {
            Ok(lock) => lock,
            Err(e) => {
                // Never evaluated: every remote principal, refused unread.
                log(&format!("cannot record a carriage: {e}"));
                self.fail(
                    e,
                    Scope::all(FenceReason::NotRecorded),
                    now,
                    fences,
                    &mut early,
                );
                let mut result = CarriageResult::plain(Carried::NotRecorded);
                result.fences = early;
                return result;
            }
        };
        let mut result = self.commit_carriage(carried, now, fences, false);
        result.announce |= !advanced.is_empty();
        result
    }

    /// Anything the log doesn't store already: an entry beyond the head, a
    /// different one at a stored `seq`, or one that doesn't parse.
    fn holds_anything_new(&self, carried: &[StrictValue]) -> bool {
        carried.iter().any(
            |value| match atem_client::membership::Entry::from_strict(value) {
                Ok(entry) => self
                    .m
                    .entry(entry.seq)
                    .is_none_or(|e| e.hash() != entry.hash()),
                Err(_) => true,
            },
        )
    }

    /// Evaluates a durably recorded carriage and commits it (steps 1–4 of
    /// "Writing the device list"); `replay` at start.
    fn commit_carriage(
        &mut self,
        carried: &[StrictValue],
        now: &HostNow,
        fences: &mut dyn Fences,
        replay: bool,
    ) -> CarriageResult {
        let mut fenced = Vec::new();
        let eval = self.m.evaluate(carried, now);
        let froze = eval.next.frozen().is_some() && self.m.frozen().is_none();
        if froze {
            return self.commit_freeze(eval, now, fences, replay);
        }
        if !eval.changed(&self.m) {
            self.remove_leftover(DlFile::Carriage);
            return CarriageResult {
                carried: Carried::Unchanged,
                evaluation: Some(eval),
                fences: fenced,
                announce: false,
            };
        }
        let head_moves = eval.next.head() != self.m.head();
        let evidence_only = !head_moves
            && eval
                .effects
                .iter()
                .all(|e| matches!(e, Change::Evidence(_)));
        if evidence_only
            && !replay
            && self
                .evidence_written_at
                .is_some_and(|at| now.mono_ms.saturating_sub(at) < EVIDENCE_PERSIST_MS)
        {
            // Counted in memory (and runtime.log) until the next write.
            log("ignored conflicting history (evidence counted in memory)");
            self.m = eval.next.clone();
            self.evidence_dirty = true;
            self.remove_leftover(DlFile::Carriage);
            return CarriageResult {
                carried: Carried::Committed,
                evaluation: Some(eval),
                fences: fenced,
                announce: false,
            };
        }
        let planned = self.planned_fences(&eval);
        if head_moves
            && let Err(e) = self.store.replace(
                DlFile::Intent,
                &head_json(&eval.next.head()).to_string().into_bytes(),
            )
        {
            log(&format!("cannot record the intent: {e}"));
            self.fail(e, planned, now, fences, &mut fenced);
            return CarriageResult {
                carried: Carried::NotRecorded,
                evaluation: None,
                fences: fenced,
                announce: false,
            };
        }
        if let Err(e) = self
            .store
            .replace(DlFile::State, &state_bytes(&eval.next, &self.pin, None))
        {
            log(&format!("cannot write the device list: {e}"));
            self.fail(e, planned, now, fences, &mut fenced);
            return CarriageResult {
                carried: Carried::NotRecorded,
                evaluation: None,
                fences: fenced,
                announce: false,
            };
        }
        if evidence_only {
            self.evidence_written_at = Some(now.mono_ms);
        }
        self.evidence_dirty = false;
        self.m = eval.next.clone();
        if self.crash_now() {
            return CarriageResult {
                carried: Carried::Crashed,
                evaluation: Some(eval),
                fences: fenced,
                announce: false,
            };
        }
        // Fences, then `membership_applied`.
        for f in planned.fences(self, fences, true) {
            fences.fence(&f.principal, f.seq);
            fenced.push(f);
        }
        self.write_applied(now, fences, &mut fenced);
        if head_moves {
            self.satisfy_intent();
            self.remove_leftover(DlFile::Intent);
        }
        self.remove_leftover(DlFile::Carriage);
        let announce = head_moves
            || eval.effects.iter().any(|e| {
                matches!(
                    e,
                    Change::RecoveryPending { .. }
                        | Change::RecoveryActive { .. }
                        | Change::RecoveryCancelled { .. }
                )
            });
        CarriageResult {
            carried: Carried::Committed,
            evaluation: Some(eval),
            fences: fenced,
            announce,
        }
    }

    /// A conflict froze the log: the freeze file, then `membership.json`,
    /// then every remote principal fenced (§R9.4).
    fn commit_freeze(
        &mut self,
        eval: Evaluation,
        now: &HostNow,
        fences: &mut dyn Fences,
        replay: bool,
    ) -> CarriageResult {
        let mut fenced = Vec::new();
        let freeze = eval.next.frozen().expect("frozen").clone();
        log(&format!(
            "conflicting signed history at seq {}: remote access is paused; re-pair this host from a device you trust (atem unpair, then atem pair)",
            freeze.seq
        ));
        let mut file = Map::new();
        file.insert("v".into(), json!(1));
        if let Value::Object(fields) = freeze_to_json(&freeze) {
            file.extend(fields);
        }
        let written = self
            .store
            .replace(DlFile::Freeze, Value::Object(file).to_string().as_bytes())
            .and_then(|()| {
                self.store
                    .replace(DlFile::State, &state_bytes(&eval.next, &self.pin, None))
            });
        // In memory at once, whatever the disk says.
        self.m = eval.next.clone();
        if let Err(e) = written {
            log(&format!("cannot record the freeze: {e}"));
            self.fail(e, Scope::all(FenceReason::Frozen), now, fences, &mut fenced);
            return CarriageResult {
                carried: Carried::Frozen,
                evaluation: Some(eval),
                fences: fenced,
                announce: false,
            };
        }
        if self.crash_now() {
            return CarriageResult {
                carried: Carried::Crashed,
                evaluation: Some(eval),
                fences: fenced,
                announce: false,
            };
        }
        self.fence_all_frozen(now, fences, &mut fenced);
        let _ = replay;
        self.remove_leftover(DlFile::Carriage);
        CarriageResult {
            carried: Carried::Frozen,
            evaluation: Some(eval),
            fences: fenced,
            announce: false,
        }
    }

    /// Every remote principal (§R9.3): the ones the session host knows
    /// (attachments, leases, queued work, `control`) and every member of
    /// the log.
    fn all_remote(&self, fences: &dyn Fences) -> Vec<String> {
        let mut all: std::collections::BTreeSet<String> =
            fences.remote_principals().into_iter().collect();
        for device in self.m.members() {
            if let Some(state) = self.m.member(device) {
                all.insert(principal_of(&state.member));
            }
        }
        all.into_iter().collect()
    }

    fn fence_all_frozen(
        &mut self,
        now: &HostNow,
        fences: &mut dyn Fences,
        fenced: &mut Vec<Fence>,
    ) {
        for p in self.all_remote(fences) {
            fences.fence(&p, 0);
            fenced.push(Fence {
                principal: p,
                reason: FenceReason::Frozen,
                seq: 0,
                durable: true,
            });
        }
        self.applied.frozen = true;
        self.write_applied(now, fences, fenced);
    }

    #[cfg(test)]
    fn crash_now(&mut self) -> bool {
        std::mem::take(&mut self.crash_after_commit)
    }

    #[cfg(not(test))]
    fn crash_now(&mut self) -> bool {
        if crate::runtime::test_hooks::crash_after_membership_commit() {
            log("test hook: killed after the commit, before its fences");
            // SAFETY: signals this process; nothing after it runs.
            unsafe { libc::kill(libc::getpid(), libc::SIGKILL) };
        }
        false
    }

    /// The fences a committed evaluation brings, in `seq` order.
    fn planned_fences(&self, eval: &Evaluation) -> Scope {
        let mut list = Vec::new();
        let mut all = None;
        let mut seq = 0;
        for effect in &eval.effects {
            let (device, reason) = match effect {
                Change::Appended(head) => {
                    seq = head.seq;
                    continue;
                }
                Change::MemberRemoved { device_id } => (device_id, FenceReason::Removed),
                Change::RolesChanged { device_id } => (device_id, FenceReason::Revoked),
                Change::HostRemoved { host_id } if *host_id == self.pin.host_id => {
                    // Everyone else, at this entry; the other entries'
                    // fences keep their own reasons and seqs.
                    all.get_or_insert((FenceReason::HostRemoved, seq));
                    continue;
                }
                _ => continue,
            };
            if let Some(state) = eval.next.member(device) {
                list.push(Fence {
                    principal: principal_of(&state.member),
                    reason,
                    seq,
                    durable: true,
                });
            }
        }
        Scope { list, all }
    }

    /// The fences of the stored entries after `membership_applied` (and of a
    /// freeze not yet applied), replayed at start; then the record.
    fn replay_fences(&mut self, now: &HostNow, fences: &mut dyn Fences, fenced: &mut Vec<Fence>) {
        let head = self.m.head();
        let from = self.applied.head.seq + 1;
        let mut all = None;
        for seq in from..=head.seq {
            let Some(entry) = self.m.entry(seq) else {
                continue;
            };
            let (device, reason) = match &entry.action {
                Action::Remove { device_id } => (device_id.clone(), FenceReason::Removed),
                Action::SetRoles { device_id, .. } => (device_id.clone(), FenceReason::Revoked),
                Action::RemoveHost { host_id } if *host_id == self.pin.host_id => {
                    all = Some(seq);
                    continue;
                }
                _ => continue,
            };
            if let Some(state) = self.m.member(&device) {
                let principal = principal_of(&state.member);
                fences.fence(&principal, seq);
                fenced.push(Fence {
                    principal,
                    reason,
                    seq,
                    durable: true,
                });
            }
        }
        if let Some(seq) = all {
            for p in self.all_remote(fences) {
                fences.fence(&p, seq);
                fenced.push(Fence {
                    principal: p,
                    reason: FenceReason::HostRemoved,
                    seq,
                    durable: true,
                });
            }
        }
        let freeze_pending = self.is_frozen() && !self.applied.frozen;
        if freeze_pending {
            self.fence_all_frozen(now, fences, fenced);
        } else if self.applied.head != head {
            self.write_applied(now, fences, fenced);
        }
    }

    fn write_applied(&mut self, now: &HostNow, fences: &mut dyn Fences, fenced: &mut Vec<Fence>) {
        let applied = Applied {
            head: self.m.head(),
            frozen: self.applied.frozen || self.is_frozen(),
        };
        match self
            .store
            .replace(DlFile::Applied, &applied_bytes(&applied))
        {
            Ok(()) => self.applied = applied,
            Err(e) => {
                // A write fault like any other: fail closed (the journal
                // halts, the run is faulted, the fault is recorded); the
                // restart replays the fences after the old record. The
                // fences themselves were written (or are in memory).
                log(&format!("cannot record the applied head: {e}"));
                self.fail(e, Scope::none(), now, fences, fenced);
            }
        }
    }

    /// A head that reached a recorded intent satisfies it; another entry at
    /// its `seq` holds the host for good (re-pairing).
    fn satisfy_intent(&mut self) {
        let Some(Held::Unclean(intent)) = self.held.clone() else {
            return;
        };
        match self.m.entry(intent.seq) {
            Some(e) if e.hash() == intent.hash => self.held = Some(Held::Fault),
            Some(_) => self.held = Some(Held::IntentMismatch(intent)),
            None => {}
        }
    }

    /// Removes a satisfied intent or a carriage record whose content is
    /// committed. A failed removal leaves a harmless leftover (§R9.3: its
    /// entries are at or below the stored head and equal to it): no fault,
    /// no hold; the next start removes it.
    fn remove_leftover(&mut self, file: DlFile) {
        if let Err(e) = self.store.remove(file) {
            log(&format!(
                "cannot remove {} ({e}); harmless, removed at the next start",
                file.name()
            ));
        }
    }

    /// Writes `membership.json` as it stands (a freeze's lost second write).
    fn write_state(&mut self, now: &HostNow, fences: &mut dyn Fences, fenced: &mut Vec<Fence>) {
        if let Err(e) = self
            .store
            .replace(DlFile::State, &state_bytes(&self.m, &self.pin, None))
        {
            log(&format!("cannot write the device list: {e}"));
            let scope = if self.is_frozen() {
                Scope::all(FenceReason::Frozen)
            } else {
                Scope::none()
            };
            self.fail(e, scope, now, fences, fenced);
        }
    }

    /// Fails closed (§R9.3 "A failed write"): in-memory fences, the journal
    /// halts, the fault is recorded, later carriages are refused unread.
    fn fail(
        &mut self,
        error: WriteError,
        scope: Scope,
        now: &HostNow,
        fences: &mut dyn Fences,
        fenced: &mut Vec<Fence>,
    ) {
        let list = scope.fences(self, fences, false);
        let principals: Vec<String> = list.iter().map(|f| f.principal.clone()).collect();
        fences.fault(Some(&principals));
        fenced.extend(list);
        self.faulted = Some(error.to_string());
        log(&format!(
            "write failed ({error}); remote admission, dispatch and remote input stop until Atem restarts"
        ));
        self.record_fault(error.file, None, now);
    }

    /// `membership.fault` (user option 2): its failure is logged; the
    /// restart then relies on the carriage record alone.
    ///
    /// It doesn't take `trust_gen.lock` itself: its callers hold it, except
    /// after a failed lock (`fail` from `lock_for_write`), where a fault
    /// record written without it is harmless: at worst a stray record after
    /// an unpair, which makes the next start fail closed (a leftover) and
    /// which `pin` removes.
    fn record_fault(&mut self, file: DlFile, intent: Option<Head>, now: &HostNow) {
        let mut record = json!({"v": 1, "runtime_epoch": self.runtime_epoch,
                                "file": file.name(), "at": now.wall_ms});
        if let Some(intent) = intent {
            record["intent"] = intent.to_json();
        }
        if let Err(e) = self
            .store
            .replace(DlFile::Fault, record.to_string().as_bytes())
        {
            log(&format!("cannot record the fault either: {e}"));
        }
    }

    // ── Admission ──

    /// The membership side of a `hello` after its carriage (§R9.3 step 5,
    /// "Held"): `client_head` is the head the client verified and reported,
    /// `more` the carriage's flag. While held, only a reconciling `hello`
    /// is admitted: a `native` member holding `manage` at the committed
    /// head, with a clean carriage and no `more`, whose head is the host's,
    /// with no intent unsatisfied; it removes the fault record.
    pub fn hello(
        &mut self,
        device_id: &str,
        client_head: Option<Head>,
        carriage: Option<&CarriageResult>,
        more: bool,
        now: &HostNow,
    ) -> Hello {
        if self.is_frozen() {
            return Hello::Frozen;
        }
        if self.faulted.is_some() {
            return Hello::NotRecorded;
        }
        let admission = match carriage.and_then(|c| c.evaluation.as_ref()) {
            Some(eval) => eval.admission(device_id, more, now),
            None => self.m.admit(device_id, now),
        };
        if matches!(admission, Admission::Frozen) {
            return Hello::Frozen;
        }
        let Some(held) = self.held.clone() else {
            return Hello::Admit(admission);
        };
        let manager = matches!(&admission, Admission::Member { state, .. }
            if matches!(&state.member.kind, MemberKind::Native { roles, .. } if roles.contains(&Role::Manage)));
        let clean = carriage.is_none_or(CarriageResult::clean) && !more;
        let satisfied = matches!(held, Held::Fault | Held::CarriageUnreadable);
        if !(manager && clean && satisfied && client_head == Some(self.m.head())) {
            return Hello::NotReconciled;
        }
        // Under `trust_gen.lock`, and only while the list is still this
        // host's pin (an old host never clears a newer pin's fault).
        let _lock = match self.lock_for_write(DlFile::Fault) {
            Ok(Some(lock)) => lock,
            Ok(None) | Err(_) => return Hello::NotReconciled,
        };
        // An unreadable carriage record left because its fault record
        // couldn't be written goes too (the manager confirmed the head).
        if held == Held::CarriageUnreadable
            && let Err(e) = self.store.remove(DlFile::Carriage)
        {
            log(&format!(
                "cannot remove the carriage record: {e}; still held"
            ));
            return Hello::NotReconciled;
        }
        if let Err(e) = self.store.remove(DlFile::Fault) {
            log(&format!("cannot remove the fault record: {e}; still held"));
            return Hello::NotReconciled;
        }
        log(&format!(
            "reconciled by {device_id} at seq {}; remote admission resumes",
            self.m.head().seq
        ));
        self.held = None;
        Hello::Admit(admission)
    }

    // ── Time ──

    /// The 100 ms pass (§R9.5): ends waits whose time is up on the host
    /// clock, writing `membership.json` before any effect; persists the
    /// time waited (and evidence counted in memory) at least once a minute.
    /// Returns the changes (Task 7 announces them).
    pub fn advance(&mut self, now: &HostNow, fences: &mut dyn Fences) -> Vec<Change> {
        if self.faulted.is_some() || self.is_frozen() || !self.still_paired() {
            return Vec::new();
        }
        let mut fenced = Vec::new();
        let due = self
            .m
            .records()
            .iter()
            .any(|r| r.state() == RecoveryState::Pending && r.clock.elapsed(now));
        if due {
            let _lock = match self.lock_for_write(DlFile::State) {
                Ok(Some(lock)) => lock,
                Ok(None) => return Vec::new(),
                Err(e) => {
                    self.fail(e, Scope::none(), now, fences, &mut fenced);
                    return Vec::new();
                }
            };
            let mut next = self.m.clone();
            let changes = next.advance(now);
            if let Err(e) = self
                .store
                .replace(DlFile::State, &state_bytes(&next, &self.pin, None))
            {
                log(&format!("cannot record a recovery decision: {e}"));
                self.fail(e, Scope::none(), now, fences, &mut fenced);
                return Vec::new();
            }
            self.m = next;
            self.checkpoint_at = now.mono_ms;
            self.evidence_dirty = false;
            return changes;
        }
        let pending = self
            .m
            .records()
            .iter()
            .any(|r| r.state() == RecoveryState::Pending);
        if (pending || self.evidence_dirty)
            && now.mono_ms.saturating_sub(self.checkpoint_at) >= CHECKPOINT_MS
        {
            self.m.checkpoint(now);
            self.checkpoint_at = now.mono_ms;
            let _lock = match self.lock_for_write(DlFile::State) {
                Ok(Some(lock)) => lock,
                Ok(None) => return Vec::new(),
                Err(e) => {
                    self.fail(e, Scope::none(), now, fences, &mut fenced);
                    return Vec::new();
                }
            };
            if let Err(e) = self
                .store
                .replace(DlFile::State, &state_bytes(&self.m, &self.pin, None))
            {
                log(&format!("cannot record the time waited: {e}"));
                self.fail(e, Scope::none(), now, fences, &mut fenced);
            } else {
                self.evidence_dirty = false;
            }
        }
        Vec::new()
    }

    /// An orderly stop: the time waited and the clean checkpoint naming
    /// this run's `runtime_epoch` (not after a fault: the restart relies on
    /// the records).
    pub fn close(&mut self, now: &HostNow) -> bool {
        if self.faulted.is_some() {
            return false;
        }
        self.m.checkpoint(now);
        // No lock, no write: without a clean checkpoint the next start
        // relies on the last persisted time (the wait only gets longer).
        let _lock = match self.lock_for_write(DlFile::State) {
            Ok(Some(lock)) => lock,
            Ok(None) => return false,
            Err(e) => {
                log(&format!("no clean checkpoint: {e}"));
                return false;
            }
        };
        let checkpoint = json!({"runtime_epoch": self.runtime_epoch, "at_wall": now.wall_ms});
        match self.store.replace(
            DlFile::State,
            &state_bytes(&self.m, &self.pin, Some(checkpoint)),
        ) {
            Ok(()) => true,
            Err(e) => {
                log(&format!("cannot write the clean checkpoint: {e}"));
                false
            }
        }
    }
}

// ── File formats ──

fn state_bytes(m: &Membership, pin: &HostPin, checkpoint: Option<Value>) -> Vec<u8> {
    let mut object = Map::new();
    object.insert("v".into(), json!(1));
    object.insert(
        "host".into(),
        json!({"host_id": pin.host_id, "host_trust_gen": pin.host_trust_gen}),
    );
    if let Value::Object(fields) = m.to_stored() {
        object.extend(fields);
    }
    if let Some(checkpoint) = checkpoint {
        object.insert("checkpoint".into(), checkpoint);
    }
    Value::Object(object).to_string().into_bytes()
}

fn parse_state(value: &Value) -> Option<(Membership, HostPin, Option<u64>)> {
    if value.get("v")?.as_u64()? != 1 {
        return None;
    }
    let host = value.get("host")?;
    let pin = HostPin {
        host_id: host.get("host_id")?.as_str()?.to_string(),
        host_trust_gen: host.get("host_trust_gen")?.as_u64()?,
    };
    let account = value.get("account_id")?.as_str()?;
    let genesis = Hash32::from_hex(value.get("genesis_hash")?.as_str()?).ok()?;
    let m = match Membership::from_stored(account, &genesis, value) {
        Ok(m) => m,
        Err(e) => {
            log(&format!("membership.json refused: {e}"));
            return None;
        }
    };
    let checkpoint = value
        .get("checkpoint")
        .and_then(|c| c.get("runtime_epoch"))
        .and_then(Value::as_u64);
    Some((m, pin, checkpoint))
}

fn carriage_bytes(runtime_epoch: u64, base: &Head, carried: &[StrictValue]) -> Vec<u8> {
    json!({"v": 1, "runtime_epoch": runtime_epoch, "base": base.to_json(),
           "entries": carried.iter().map(|v| v.value().clone()).collect::<Vec<_>>()})
    .to_string()
    .into_bytes()
}

/// The carried objects of a record, strict again (they were strict when
/// they arrived).
fn parse_carriage(value: &Value) -> Option<Vec<StrictValue>> {
    if value.get("v")?.as_u64()? != 1 {
        return None;
    }
    Head::from_json(value.get("base")?)?;
    value
        .get("entries")?
        .as_array()?
        .iter()
        .map(|v| StrictValue::parse(v.to_string().as_bytes(), usize::MAX).ok())
        .collect()
}

fn applied_bytes(applied: &Applied) -> Vec<u8> {
    let mut v = applied.head.to_json();
    if applied.frozen {
        v["frozen"] = json!(true);
    }
    v.to_string().into_bytes()
}

fn parse_applied(bytes: &[u8]) -> Option<Applied> {
    let mut v = parse_json(bytes)?;
    let frozen = match v.as_object_mut()?.remove("frozen") {
        Some(f) => f.as_bool()?,
        None => false,
    };
    Some(Applied {
        head: Head::from_json(&v)?,
        frozen,
    })
}

// ── Unpair and pairing ──

/// The genesis hashes this host was frozen on (`frozen_genesis`).
pub fn frozen_genesis(pairing: &PairingPaths) -> Vec<Hash32> {
    store::read_private(&pairing.frozen_genesis)
        .ok()
        .flatten()
        .and_then(|b| parse_json(&b))
        .and_then(|v| {
            v.get("genesis")?
                .as_array()?
                .iter()
                .map(|h| Hash32::from_hex(h.as_str()?).ok())
                .collect()
        })
        .unwrap_or_default()
}

/// Why `forget_on_unpair` failed, and whether the removal had begun.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForgetError {
    pub message: String,
    /// `membership.json` is (or may be) gone already: the unpair must go on
    /// (the leftovers are inert: `open` fails closed on them and `pin`
    /// removes them), never leave a paired host without its list.
    pub begun: bool,
}

impl std::fmt::Display for ForgetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

#[cfg(test)]
thread_local! {
    /// Tests: the next `pin` step that fails.
    pub(crate) static PIN_FAULT: std::cell::Cell<Option<store::Injected>> =
        const { std::cell::Cell::new(None) };
}

/// `host_channel_key` (§R9.3): the Ed25519 seed and its public key,
/// base64url (§R9.1). Plain 0600 like `unlock_auth_key`: it only proves
/// the host to clients, so it works while the cred agent is locked.
fn host_key_bytes(seed: &[u8; 32]) -> Vec<u8> {
    let public = ed25519_dalek::SigningKey::from_bytes(seed)
        .verifying_key()
        .to_bytes();
    json!({"v": 1, "seed": atem_client::encoding::b64u(seed),
           "pub": atem_client::encoding::b64u(&public)})
    .to_string()
    .into_bytes()
}

/// The pinned host's `host_channel_key` seed, checked against the newest
/// `add_host` key of `host_id` in the device list. A missing, unreadable or
/// other key is an error (the device list then fails to open).
pub fn host_channel_seed(
    pairing: &PairingPaths,
    m: &Membership,
    host_id: &str,
) -> Result<zeroize::Zeroizing<[u8; 32]>, String> {
    let path = &pairing.host_channel_key;
    let bytes = store::read_private(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?
        .ok_or_else(|| {
            format!(
                "{} is missing; re-pair this host (atem unpair, then atem pair)",
                path.display()
            )
        })?;
    let bytes = zeroize::Zeroizing::new(bytes);
    let damaged = || {
        format!(
            "{} is damaged; re-pair this host (atem unpair, then atem pair)",
            path.display()
        )
    };
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| damaged())?;
    let seed = value
        .get("seed")
        .and_then(Value::as_str)
        .and_then(|t| atem_client::encoding::b64u_decode(t).ok())
        .map(zeroize::Zeroizing::new)
        .ok_or_else(damaged)?;
    let seed: zeroize::Zeroizing<[u8; 32]> =
        zeroize::Zeroizing::new(seed.as_slice().try_into().map_err(|_| damaged())?);
    let public = ed25519_dalek::SigningKey::from_bytes(&seed)
        .verifying_key()
        .to_bytes();
    let pinned = m.host(host_id).map(|h| h.host_key.as_bytes().to_vec());
    if pinned.as_deref() != Some(&public[..]) {
        return Err(format!(
            "{} isn't the key the device list names for {host_id}; re-pair this host (atem unpair, then atem pair)",
            path.display()
        ));
    }
    Ok(seed)
}

#[cfg(test)]
thread_local! {
    /// Tests: the next `forget_on_unpair` step that fails.
    pub(crate) static FORGET_FAULT: std::cell::Cell<Option<store::Injected>> =
        const { std::cell::Cell::new(None) };
}

/// `atem unpair` (§R9.3): a frozen list's genesis goes on
/// `frozen_genesis` (≤ 16, oldest dropped), then `membership.json` is
/// removed first, then every other r9 file (the carriage record, intent,
/// freeze and fault records, the host channel key, the journal's
/// `membership_applied`). `frozen_genesis` stays. Until `membership.json`
/// is gone nothing changed (an error leaves the host paired as it was);
/// after that, any file left makes the next start fail closed.
pub fn forget_on_unpair(pairing: &PairingPaths) -> Result<(), ForgetError> {
    let state = store::read_private(&pairing.membership)
        .ok()
        .flatten()
        .and_then(|b| parse_json(&b));
    let frozen = store::present(&pairing.freeze)
        || state.as_ref().is_some_and(|v| v.get("frozen").is_some());
    let mut store = Store::new(pairing, &journal_of(pairing));
    #[cfg(test)]
    if let Some(injected) = FORGET_FAULT.with(|f| f.get())
        && injected.file != DlFile::Applied
    {
        FORGET_FAULT.with(|f| f.set(None));
        store.inject(injected);
    }
    let not_begun = |e: WriteError| ForgetError {
        message: e.to_string(),
        begun: false,
    };
    if frozen
        && let Some(genesis) = state
            .as_ref()
            .and_then(|v| Hash32::from_hex(v.get("genesis_hash")?.as_str()?).ok())
    {
        let mut list = frozen_genesis(pairing);
        if !list.contains(&genesis) {
            list.push(genesis);
        }
        while list.len() > MAX_FROZEN_GENESIS {
            list.remove(0);
        }
        let file = json!({"v": 1, "genesis": list.iter().map(Hash32::to_hex).collect::<Vec<_>>()});
        store
            .replace(DlFile::FrozenGenesis, file.to_string().as_bytes())
            .map_err(not_begun)?;
    }
    // `membership_applied` is the last leftover: it stays until
    // `forget_leftovers`, after the unpair committed the next trust
    // generation, so a failure in between still opens as `Failed`. A list
    // without one (never applied) gets one now.
    let marker = store::present(&pairing.membership) && !store.present(DlFile::Applied);
    if marker {
        store
            .replace(DlFile::Applied, UNPAIRING_MARKER)
            .map_err(not_begun)?;
    }
    if let Err(e) = store.remove(DlFile::State) {
        // A failed unlink changed nothing; a failed directory fsync after
        // it may have.
        let begun = e.step == store::Step::Remove || !store::present(&pairing.membership);
        if !begun && marker {
            // Aborted: the host stays paired as it was, so the marker goes
            // (`open` would ignore it anyway).
            if let Err(e) = store.remove(DlFile::Applied) {
                log(&format!("cannot remove the unpairing marker: {e}"));
            }
        }
        return Err(ForgetError {
            begun,
            message: e.to_string(),
        });
    }
    for file in LEFTOVERS {
        if file == DlFile::Applied {
            continue;
        }
        store.remove(file).map_err(|e| ForgetError {
            message: e.to_string(),
            begun: true,
        })?;
    }
    Ok(())
}

/// After `atem unpair` committed the next trust generation (or on an
/// unpaired profile with leftovers): removes every r9 leftover, the last
/// one (`membership_applied`) included.
pub fn forget_leftovers(pairing: &PairingPaths) -> Result<(), String> {
    let mut store = Store::new(pairing, &journal_of(pairing));
    #[cfg(test)]
    if let Some(injected) = FORGET_FAULT.with(|f| f.take()) {
        store.inject(injected);
    }
    for file in LEFTOVERS {
        store.remove(file).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// The account and host `membership.json` pins, read without verifying
/// the log (the runtime's session host takes this identity; `open`
/// verifies everything). `None` without a readable list.
pub fn peek_pin(pairing: &PairingPaths) -> Option<(String, HostPin)> {
    #[derive(serde::Deserialize)]
    struct Pin {
        account_id: String,
        host: HostField,
    }
    #[derive(serde::Deserialize)]
    struct HostField {
        host_id: String,
        host_trust_gen: u64,
    }
    let bytes = store::read_private(&pairing.membership).ok()??;
    let pin: Pin = serde_json::from_slice(&bytes).ok()?;
    Some((
        pin.account_id,
        HostPin {
            host_id: pin.host.host_id,
            host_trust_gen: pin.host.host_trust_gen,
        },
    ))
}

/// What identifies the device-list files on disk now (inode, size, mtime
/// of `membership.json` and `host_channel_key`): a change means a pin, an
/// unpair or a write happened since.
pub fn list_stamp(pairing: &PairingPaths) -> Vec<Option<(u64, u64, i64, i64)>> {
    use std::os::unix::fs::MetadataExt;
    [&pairing.membership, &pairing.host_channel_key]
        .into_iter()
        .map(|p| {
            std::fs::symlink_metadata(p)
                .ok()
                .map(|m| (m.ino(), m.len(), m.mtime(), m.mtime_nsec()))
        })
        .collect()
}

/// Whether the profile holds a device list or any r9 leftover.
pub fn has_device_list_files(pairing: &PairingPaths) -> bool {
    let store = Store::new(pairing, &journal_of(pairing));
    store::present(&pairing.membership) || LEFTOVERS.into_iter().any(|f| store.present(f))
}

/// The journal directory of the runtime this profile's `atem runtime`
/// uses (`<config>/runtime/journal`).
fn journal_of(pairing: &PairingPaths) -> std::path::PathBuf {
    pairing
        .dir()
        .parent()
        .map(|config| crate::runtime::state_dir(config).join("journal"))
        .unwrap_or_else(|| pairing.dir().to_path_buf())
}
