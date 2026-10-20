//! The membership log (§R9.2–§R9.5): verification of entries against a
//! chain, carriage of suffixes (§R9.3 "Applying a carriage"), the conflict
//! rule and freeze (§R9.4), and the recovery state machine with its 24 h
//! wait on the verifier's own clock (§R9.5).
//!
//! Everything here is pure: [`Membership`] is the verified chain plus what
//! follows from it on one verifier (a host or a device): who is a member in
//! effect, the current recovery key, the pending recovery entries with their
//! waits, evidence of refused history and a freeze. The host makes it
//! durable (Task 6) and turns its [`Effect`]s into fences (Task 7); a client
//! keeps its own copy.
//!
//! [`Membership::evaluate`] runs one carriage against a scratch copy and
//! returns the proposed next state; the caller commits it (after its durable
//! write) or drops it. [`Membership::advance`] ends waits whose time is up.
//!
//! **Stored recovery fields** (for the host's `membership.json`, §R9.3; Task
//! 6 persists them). §R9.3 sketches one `recovery[]` record per pending-type
//! entry as `{entry_hash, seq, state, first_seen_wall, boot_id,
//! mono_at_first_seen_ns, mono_waited_ms, decided_at_wall?, reason?}`.
//! [`RecoveryRecord`] maps to it as follows:
//!
//! - `entry_hash`, `seq`: the same.
//! - `state`: [`RecoveryRecord::state`] (`pending` without a decision).
//! - `clock.first_seen_wall`, `clock.boot_id`, `clock.mono_waited_ms`: the
//!   same.
//! - `clock.mono_anchor_ms` replaces `mono_at_first_seen_ns`: milliseconds
//!   (ns since boot exceeds 2^53, the I-JSON integer limit, after about 104
//!   days of uptime), and signed: within one boot it is the monotonic reading
//!   at first sight (identical meaning); after a reboot it is re-based to
//!   `mono_now − mono_waited_ms` at the first reading of the new boot, so the
//!   wait continues from the persisted time.
//! - `decision.at_wall` is `decided_at_wall`, `decision.reason` is `reason`
//!   ([`RecoveryReason::as_str`]).
//! - Additions: `decision.at_seq` (`decided_at_seq`: the head `seq` at
//!   which the decision took effect) and `decision.order` (the order of
//!   decisions on this host). Judging a conflict "against `C[..seq-1]`"
//!   (§R9.4) replays the chain with them; where a wait-ended decision took
//!   effect isn't derivable from the chain itself.
//!
//! Time between a boot and the host's first clock reading in it (its first
//! `checkpoint` or `advance`, which it should take at start) isn't counted:
//! the wait can only get longer, never shorter.
use std::collections::BTreeMap;

use crate::canonical::StrictValue;
use crate::encoding::Hash32;
use crate::error::Error;
use crate::keys::PublicKey;
use crate::signed::SignedObject;

pub mod draft;
pub mod entry;
pub mod publish;
pub mod wait;

pub use draft::{draft_on, sign_entry, sign_entry_cosigned};
pub use entry::{
    Action, Entry, HostRecord, KBackupRecord, KitMode, Member, MemberKind, RECOVERY_SIGNER, Role,
    RolesChange, Scope,
};
pub use wait::{HostNow, RECOVERY_WAIT_MS, WaitClock};

/// Log limits (§R9.2).
pub const MAX_ENTRIES: u64 = 1024;
pub const MAX_MEMBERS: usize = 256;
pub const MAX_HOSTS: usize = 64;
/// Carriage bounds (§R9.3): at most 64 entries and 256 KiB per carriage.
pub const MAX_CARRIAGE_ENTRIES: usize = 64;
pub const MAX_CARRIAGE_BYTES: usize = 256 * 1024;
/// `evidence` keeps a count and the 32 most recent records (§R9.3).
pub const MAX_EVIDENCE: usize = 32;

/// Why an entry is invalid. `code()` is the `membership_invalid` detail
/// (§R9.11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Invalid {
    /// Not strict JSON, a missing or mistyped field; the text names it.
    Malformed(&'static str),
    /// A field the action doesn't have (§R9.1).
    UnknownField,
    /// A key with an algorithm other than its field's pin.
    WrongAlg,
    /// A key that isn't a valid (or is a weak) point.
    BadKey,
    ArrayNotCanonical,
    KitSigMissing,
    KitSigUnexpected,
    TooLarge,
    /// Another account.
    WrongAccount,
    /// Another log (`genesis_hash`), or a genesis that isn't the pinned one.
    GenesisMismatch,
    /// A `genesis` that breaks its rules, or one after seq 1.
    BadGenesis,
    /// Not `head + 1`.
    WrongSeq,
    /// `prev_hash` isn't the hash of the entry before it.
    WrongPrevHash,
    /// Entries out of order or with a gap.
    Gap,
    BadSignature,
    /// The signer isn't a native member holding `manage`, in effect here.
    SignerNotManager,
    /// Signed by (or co-signed with) a replaced recovery key.
    RecoveryKeyRetired,
    /// The recovery key signing anything but `recovery_add`, or a
    /// `recovery_add` not signed by it.
    RecoverySignerAction,
    /// A `device_id` used before in this log (ids are never reused).
    DeviceIdReused,
    /// `remove` or `set_roles` of a device that isn't a current member.
    NotAMember,
    /// The change would leave no native manager.
    LastManager,
    /// Roles outside the kind rules (§R9.2).
    BadRoles,
    /// A service `expires_at` more than 90 days after `signed_at`.
    ServiceExpiry,
    BadScope,
    /// `remove_host` of a host that isn't current.
    NotAHost,
    /// `add_host` whose `host_trust_gen` isn't above every earlier one.
    HostTrustGenNotIncreasing,
    /// A `set_recovery_key` naming a key used before in this log.
    RecoveryKeyReused,
    /// A decision whose `target` isn't a pending-type entry of the chain.
    NotARecoveryEntry,
    /// An approval by the target's own signer.
    SelfApproval,
    BlobVersionNotIncreasing,
    /// A `k_backup` naming a kit that is neither current nor pending.
    KBackupKitNotCurrent,
    /// The log (or its member or host list) is full.
    LogFull,
    /// More than 64 entries or 256 KiB in one carriage.
    CarriageTooLarge,
}

impl Invalid {
    pub fn code(&self) -> &'static str {
        match self {
            Invalid::Malformed(_) => "malformed",
            Invalid::UnknownField => "unknown_field",
            Invalid::WrongAlg => "wrong_alg",
            Invalid::BadKey => "bad_key",
            Invalid::ArrayNotCanonical => "array_not_canonical",
            Invalid::KitSigMissing => "kit_sig_missing",
            Invalid::KitSigUnexpected => "kit_sig_unexpected",
            Invalid::TooLarge => "too_large",
            Invalid::WrongAccount => "wrong_account",
            Invalid::GenesisMismatch => "genesis_mismatch",
            Invalid::BadGenesis => "bad_genesis",
            Invalid::WrongSeq => "wrong_seq",
            Invalid::WrongPrevHash => "wrong_prev_hash",
            Invalid::Gap => "gap",
            Invalid::BadSignature => "bad_signature",
            Invalid::SignerNotManager => "signer_not_manager",
            Invalid::RecoveryKeyRetired => "recovery_key_retired",
            Invalid::RecoverySignerAction => "recovery_signer_action",
            Invalid::DeviceIdReused => "device_id_reused",
            Invalid::NotAMember => "not_a_member",
            Invalid::LastManager => "last_manager",
            Invalid::BadRoles => "bad_roles",
            Invalid::ServiceExpiry => "service_expiry",
            Invalid::BadScope => "bad_scope",
            Invalid::NotAHost => "not_a_host",
            Invalid::HostTrustGenNotIncreasing => "host_trust_gen_not_increasing",
            Invalid::RecoveryKeyReused => "recovery_key_reused",
            Invalid::NotARecoveryEntry => "not_a_recovery_entry",
            Invalid::SelfApproval => "self_approval",
            Invalid::BlobVersionNotIncreasing => "blob_version_not_increasing",
            Invalid::KBackupKitNotCurrent => "k_backup_kit_not_current",
            Invalid::LogFull => "log_full",
            Invalid::CarriageTooLarge => "carriage_too_large",
        }
    }
}

impl std::fmt::Display for Invalid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Invalid::Malformed(what) => write!(f, "malformed: {what}"),
            other => f.write_str(other.code()),
        }
    }
}

impl std::error::Error for Invalid {}

impl From<Error> for Invalid {
    fn from(e: Error) -> Self {
        match e {
            Error::ArrayNotCanonical => Invalid::ArrayNotCanonical,
            Error::KitSigMissing => Invalid::KitSigMissing,
            Error::KitSigUnexpected => Invalid::KitSigUnexpected,
            Error::TooLarge => Invalid::TooLarge,
            Error::WrongAlg => Invalid::WrongAlg,
            Error::BadKey | Error::WeakKey => Invalid::BadKey,
            Error::BadSignature | Error::HighS => Invalid::BadSignature,
            Error::UnknownType => Invalid::Malformed("type"),
            Error::NullValue => Invalid::Malformed("null"),
            Error::Strict(_) | Error::Canonical(_) => Invalid::Malformed("not strict JSON"),
            Error::Malformed(what) => Invalid::Malformed(what),
            _ => Invalid::Malformed("entry"),
        }
    }
}

/// A chain position: `seq` and its `entry_hash`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Head {
    pub seq: u64,
    pub hash: Hash32,
}

/// A member's standing on this verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberStatus {
    /// In effect.
    Active,
    /// The subject of a `recovery_add` still pending here: holds nothing.
    Pending { entry_hash: Hash32 },
    /// Its `recovery_add` was cancelled: never a member.
    Cancelled,
    /// Removed (ids are never reused).
    Removed,
}

/// A member and its standing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberState {
    pub member: Member,
    pub status: MemberStatus,
}

/// A recovery entry's state (§R9.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryState {
    Pending,
    Active,
    Cancelled,
}

impl RecoveryState {
    pub fn as_str(self) -> &'static str {
        match self {
            RecoveryState::Pending => "pending",
            RecoveryState::Active => "active",
            RecoveryState::Cancelled => "cancelled",
        }
    }
}

/// Why a pending entry left `pending`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryReason {
    Approved,
    WaitEnded,
    Vetoed,
    /// The recovery key that signed it was replaced (§R9.5).
    KitReplaced,
    /// A verified host-signed head beyond an entry that depends on it shows
    /// it took effect on that host (a restore reading a past recovery;
    /// `Membership::verify_chain_confirmed`).
    HostConfirmed,
}

impl RecoveryReason {
    pub fn as_str(self) -> &'static str {
        match self {
            RecoveryReason::Approved => "approved",
            RecoveryReason::WaitEnded => "wait_ended",
            RecoveryReason::Vetoed => "vetoed",
            RecoveryReason::KitReplaced => "kit_replaced",
            RecoveryReason::HostConfirmed => "host_confirmed",
        }
    }
}

/// How and when a pending entry was decided on this verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub state: RecoveryState,
    pub reason: RecoveryReason,
    /// The head `seq` when it happened (the decision entry's own `seq`, or
    /// the head when the wait ended): the chain position it takes effect at.
    pub at_seq: u64,
    /// Order of decisions on this verifier (several can share a position).
    pub order: u64,
    /// Host wall time (display).
    pub at_wall: u64,
}

/// One pending-type entry (`recovery_add`, `kit: "lost"`
/// `set_recovery_key`) on this verifier: `membership.json`'s `recovery[]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryRecord {
    pub entry_hash: Hash32,
    pub seq: u64,
    pub clock: WaitClock,
    pub decision: Option<Decision>,
}

impl RecoveryRecord {
    pub fn state(&self) -> RecoveryState {
        self.decision
            .as_ref()
            .map_or(RecoveryState::Pending, |d| d.state)
    }
}

/// A pending entry as `welcome.pending_recovery` lists it (§R9.5, R9.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingSummary {
    pub entry_hash: Hash32,
    pub seq: u64,
    pub action: &'static str,
    /// The member for `recovery_add`, the requesting manager for
    /// `set_recovery_key`.
    pub subject: String,
    /// On this verifier's clock.
    pub effective_at: u64,
}

/// Why a conflicting entry was ignored (§R9.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceReason {
    DuplicateVeto,
    LateDecision,
    Invalid,
    SignerRemoved,
    /// Validly signed by a device that holds nothing at our head (a
    /// recovery subject still pending or cancelled here).
    SignerNotInEffect,
}

impl EvidenceReason {
    pub fn as_str(self) -> &'static str {
        match self {
            EvidenceReason::DuplicateVeto => "duplicate_veto",
            EvidenceReason::LateDecision => "late_decision",
            EvidenceReason::Invalid => "invalid",
            EvidenceReason::SignerRemoved => "signer_removed",
            EvidenceReason::SignerNotInEffect => "signer_not_in_effect",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceRecord {
    pub seq: u64,
    pub entry_hash: Hash32,
    pub signer: String,
    pub reason: EvidenceReason,
    pub at: u64,
}

/// Refused history: a count and the most recent records (bounded).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Evidence {
    pub count: u64,
    pub recent: Vec<EvidenceRecord>,
}

impl Evidence {
    fn push(&mut self, record: EvidenceRecord) {
        self.count += 1;
        if self.recent.len() == MAX_EVIDENCE {
            self.recent.remove(0);
        }
        self.recent.push(record);
    }
}

/// A freeze (§R9.4): both entries, final until re-pairing.
#[derive(Debug, Clone, PartialEq)]
pub struct Freeze {
    pub seq: u64,
    pub ours: SignedObject,
    pub theirs: SignedObject,
    pub at: u64,
}

/// What a committed state change means for the host (Task 7 turns these into
/// fences, `membership_head` events and local status).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// An entry was appended.
    Appended(Head),
    MemberAdded {
        device_id: String,
    },
    /// Fence every attachment of the principal (§R9.3 step 4).
    MemberRemoved {
        device_id: String,
    },
    /// Always a revocation (§R9.3): fence the principal.
    RolesChanged {
        device_id: String,
    },
    HostKeyChanged {
        host_id: String,
    },
    HostRemoved {
        host_id: String,
    },
    RecoveryPending {
        entry_hash: Hash32,
    },
    RecoveryActive {
        entry_hash: Hash32,
        reason: RecoveryReason,
    },
    RecoveryCancelled {
        entry_hash: Hash32,
        reason: RecoveryReason,
    },
    RecoveryKeyReplaced,
    KBackupRecorded {
        blob_version: u64,
    },
    /// Atem's veto at the head was replaced by an equivalent one (§R9.4 row 1).
    VetoReplaced(Head),
    Evidence(EvidenceReason),
    Frozen,
}

/// The result of checking one entry against a chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Check {
    Valid,
    /// Its only problem is that it depends on this entry, still pending
    /// here (§R9.2, R9.5).
    Deferred(Hash32),
    Invalid(Invalid),
}

#[derive(Debug, Clone, PartialEq)]
struct HostState {
    record: HostRecord,
    removed: bool,
}

/// What follows from a chain prefix: members, hosts, keys, the newest K
/// backup. Pure function of the entries and the recorded decisions.
#[derive(Debug, Clone, PartialEq)]
struct Derived {
    members: BTreeMap<String, MemberState>,
    hosts: BTreeMap<String, HostState>,
    recovery_key: PublicKey,
    retired: Vec<PublicKey>,
    used_keys: Vec<PublicKey>,
    /// `kit: "lost"` replacements still pending: (entry hash, new key).
    pending_keys: Vec<(Hash32, PublicKey)>,
    k_backup: Option<KBackupRecord>,
}

impl Derived {
    fn new(genesis: &Entry) -> Self {
        let Action::Genesis {
            member,
            recovery_key,
        } = &genesis.action
        else {
            unreachable!("checked by the caller")
        };
        let mut members = BTreeMap::new();
        members.insert(
            member.device_id.clone(),
            MemberState {
                member: member.clone(),
                status: MemberStatus::Active,
            },
        );
        Derived {
            members,
            hosts: BTreeMap::new(),
            recovery_key: recovery_key.clone(),
            retired: Vec::new(),
            used_keys: vec![recovery_key.clone()],
            pending_keys: Vec::new(),
            k_backup: None,
        }
    }

    /// The entry's own effect (decisions are applied by `resolve`).
    fn apply(&mut self, entry: &Entry) {
        match &entry.action {
            Action::Genesis { .. } => {}
            Action::Add { member } => {
                self.members.insert(
                    member.device_id.clone(),
                    MemberState {
                        member: member.clone(),
                        status: MemberStatus::Active,
                    },
                );
            }
            Action::RecoveryAdd { member } => {
                self.members.insert(
                    member.device_id.clone(),
                    MemberState {
                        member: member.clone(),
                        status: MemberStatus::Pending {
                            entry_hash: entry.hash(),
                        },
                    },
                );
            }
            Action::Remove { device_id } => {
                if let Some(state) = self.members.get_mut(device_id) {
                    state.status = MemberStatus::Removed;
                }
            }
            Action::SetRoles { device_id, change } => {
                if let Some(state) = self.members.get_mut(device_id) {
                    match (&mut state.member.kind, change) {
                        (MemberKind::Native { roles, .. }, RolesChange::Native(new)) => {
                            *roles = new.clone();
                        }
                        (
                            MemberKind::Service { scope, expires_at },
                            RolesChange::Service {
                                scope: new_scope,
                                expires_at: new_expiry,
                            },
                        ) => {
                            *scope = new_scope.clone();
                            *expires_at = *new_expiry;
                        }
                        _ => unreachable!("kind checked before applying"),
                    }
                }
            }
            Action::AddHost { host } => {
                self.hosts.insert(
                    host.host_id.clone(),
                    HostState {
                        record: host.clone(),
                        removed: false,
                    },
                );
            }
            Action::RemoveHost { host_id } => {
                if let Some(host) = self.hosts.get_mut(host_id) {
                    host.removed = true;
                }
            }
            Action::SetRecoveryKey { recovery_key, kit } => {
                self.used_keys.push(recovery_key.clone());
                match kit {
                    KitMode::Current => self.replace_key(recovery_key.clone()),
                    KitMode::Lost => self.pending_keys.push((entry.hash(), recovery_key.clone())),
                }
            }
            Action::RecoveryApprove { .. } | Action::RecoveryVeto { .. } => {}
            Action::KBackup(record) => self.k_backup = Some(record.clone()),
        }
    }

    fn replace_key(&mut self, new: PublicKey) {
        let old = std::mem::replace(&mut self.recovery_key, new);
        self.retired.push(old);
    }

    /// A pending entry's decision.
    fn resolve(&mut self, entry: &Entry, state: RecoveryState) {
        match &entry.action {
            Action::RecoveryAdd { member } => {
                if let Some(m) = self.members.get_mut(&member.device_id) {
                    m.status = match state {
                        RecoveryState::Active => MemberStatus::Active,
                        RecoveryState::Cancelled => MemberStatus::Cancelled,
                        RecoveryState::Pending => m.status,
                    };
                }
            }
            Action::SetRecoveryKey { recovery_key, .. } => {
                self.pending_keys.retain(|(hash, _)| *hash != entry.hash());
                if state == RecoveryState::Active {
                    self.replace_key(recovery_key.clone());
                }
            }
            _ => {}
        }
    }

    fn native_managers_except(&self, device_id: &str) -> usize {
        self.members
            .iter()
            .filter(|(id, m)| {
                id.as_str() != device_id
                    && m.status == MemberStatus::Active
                    && m.member.is_manager()
            })
            .count()
    }

    fn current_member_count(&self) -> usize {
        self.members
            .values()
            .filter(|m| {
                matches!(
                    m.status,
                    MemberStatus::Active | MemberStatus::Pending { .. }
                )
            })
            .count()
    }

    fn current_hosts(&self) -> usize {
        self.hosts.values().filter(|h| !h.removed).count()
    }
}

/// A verified membership log on one verifier.
#[derive(Debug, Clone, PartialEq)]
pub struct Membership {
    account_id: String,
    genesis_hash: Hash32,
    entries: Vec<Entry>,
    records: Vec<RecoveryRecord>,
    decision_order: u64,
    evidence: Evidence,
    frozen: Option<Freeze>,
    derived: Derived,
}

/// A chain that failed verification: the index of the first bad entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainError {
    pub index: usize,
    pub reason: Invalid,
}

impl std::fmt::Display for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "entry {}: {}", self.index, self.reason)
    }
}

impl std::error::Error for ChainError {}

/// The result of verifying a whole chain.
#[derive(Debug, Clone, PartialEq)]
pub struct Verified {
    pub membership: Membership,
    /// The first entry that depends on one still pending on this verifier
    /// (its index and the pending entry); the chain stops before it.
    pub deferred: Option<(usize, Hash32)>,
}

impl Membership {
    /// Verifies a whole chain from its genesis (pairing, a device's
    /// enrollment, a restore). `genesis_hash` is the pin (the ceremony's
    /// `verifyKeys`, a device's own record, or the Recovery Kit). Pending
    /// entries start their wait at `now` (this verifier's first sight).
    pub fn verify_chain(
        account_id: &str,
        genesis_hash: &Hash32,
        entries: &[Entry],
        now: &HostNow,
    ) -> Result<Verified, ChainError> {
        Self::verify_chain_confirmed(account_id, genesis_hash, entries, None, now)
    }

    /// `verify_chain`, given a head a host signed (verified by the caller
    /// with that host's key): an entry at or below it whose only problem is
    /// that it depends on a pending entry shows the pending entry took effect
    /// on that host (a host applies such entries only then), so it is
    /// activated (`HostConfirmed`) instead of stopping there. Restore-only
    /// (an Atem interpretation, see `restore`): a host never verifies this
    /// way, so it never records that reason. Only applied when the chain
    /// holds `confirmed` itself.
    pub(crate) fn verify_chain_confirmed(
        account_id: &str,
        genesis_hash: &Hash32,
        entries: &[Entry],
        confirmed: Option<Head>,
        now: &HostNow,
    ) -> Result<Verified, ChainError> {
        let confirmed = confirmed.filter(|head| {
            usize::try_from(head.seq)
                .ok()
                .and_then(|seq| entries.get(seq.checked_sub(1)?))
                .is_some_and(|e| e.seq == head.seq && e.hash() == head.hash)
        });
        let at = |index: usize| move |reason: Invalid| ChainError { index, reason };
        let genesis = entries.first().ok_or(ChainError {
            index: 0,
            reason: Invalid::Malformed("no genesis"),
        })?;
        let mut membership =
            Membership::from_genesis(account_id, genesis_hash, genesis.clone()).map_err(at(0))?;
        for (index, entry) in entries.iter().enumerate().skip(1) {
            loop {
                match membership.check_next(entry) {
                    Check::Valid => {
                        membership.append(entry.clone(), now, &mut Vec::new());
                        break;
                    }
                    Check::Deferred(on) => {
                        let covered = confirmed.is_some_and(|head| entry.seq <= head.seq);
                        let pending = membership.records.iter().position(|r| {
                            r.entry_hash == on && r.state() == RecoveryState::Pending
                        });
                        match (covered, pending) {
                            (true, Some(record)) => {
                                let head = membership.head().seq;
                                membership.decide(
                                    record,
                                    RecoveryState::Active,
                                    RecoveryReason::HostConfirmed,
                                    head,
                                    now,
                                    &mut Vec::new(),
                                );
                            }
                            _ => {
                                return Ok(Verified {
                                    membership,
                                    deferred: Some((index, on)),
                                });
                            }
                        }
                    }
                    Check::Invalid(reason) => return Err(at(index)(reason)),
                }
            }
        }
        Ok(Verified {
            membership,
            deferred: None,
        })
    }

    /// A log of one entry: the pinned genesis, self-signed by its member.
    pub fn from_genesis(
        account_id: &str,
        genesis_hash: &Hash32,
        genesis: Entry,
    ) -> Result<Membership, Invalid> {
        let Action::Genesis { member, .. } = &genesis.action else {
            return Err(Invalid::BadGenesis);
        };
        if genesis.hash() != *genesis_hash {
            return Err(Invalid::GenesisMismatch);
        }
        if genesis.account_id != account_id {
            return Err(Invalid::WrongAccount);
        }
        genesis.object().verify(&member.auth_key)?;
        let derived = Derived::new(&genesis);
        Ok(Membership {
            account_id: account_id.to_owned(),
            genesis_hash: *genesis_hash,
            entries: vec![genesis],
            records: Vec::new(),
            decision_order: 0,
            evidence: Evidence::default(),
            frozen: None,
            derived,
        })
    }

    // ------------------------------------------------------------ queries

    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    pub fn genesis_hash(&self) -> Hash32 {
        self.genesis_hash
    }

    pub fn head(&self) -> Head {
        let last = self.entries.last().expect("a log has its genesis");
        Head {
            seq: last.seq,
            hash: last.hash(),
        }
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// The stored entry at `seq` (1-based).
    pub fn entry(&self, seq: u64) -> Option<&Entry> {
        let index = usize::try_from(seq.checked_sub(1)?).ok()?;
        self.entries.get(index)
    }

    pub fn entry_by_hash(&self, hash: &Hash32) -> Option<&Entry> {
        self.entries.iter().find(|e| e.hash() == *hash)
    }

    pub fn member(&self, device_id: &str) -> Option<&MemberState> {
        self.derived.members.get(device_id)
    }

    /// Members in effect here, by id.
    pub fn members(&self) -> Vec<&str> {
        self.derived
            .members
            .iter()
            .filter(|(_, m)| m.status == MemberStatus::Active)
            .map(|(id, _)| id.as_str())
            .collect()
    }

    /// A current host's newest key (`add_host`).
    pub fn host(&self, host_id: &str) -> Option<&HostRecord> {
        self.derived
            .hosts
            .get(host_id)
            .filter(|h| !h.removed)
            .map(|h| &h.record)
    }

    /// The current recovery key (genesis, or the newest replacement in
    /// effect here).
    pub fn recovery_key(&self) -> &PublicKey {
        &self.derived.recovery_key
    }

    pub fn retired_recovery_keys(&self) -> &[PublicKey] {
        &self.derived.retired
    }

    /// Keys of `kit: "lost"` replacements still pending here.
    pub fn pending_recovery_keys(&self) -> impl Iterator<Item = &PublicKey> {
        self.derived.pending_keys.iter().map(|(_, key)| key)
    }

    /// The newest `k_backup` record (the restore's version floor).
    pub fn k_backup(&self) -> Option<&KBackupRecord> {
        self.derived.k_backup.as_ref()
    }

    pub fn records(&self) -> &[RecoveryRecord] {
        &self.records
    }

    pub fn record(&self, entry_hash: &Hash32) -> Option<&RecoveryRecord> {
        self.records.iter().find(|r| r.entry_hash == *entry_hash)
    }

    pub fn evidence(&self) -> &Evidence {
        &self.evidence
    }

    pub fn frozen(&self) -> Option<&Freeze> {
        self.frozen.as_ref()
    }

    /// The pending entries with their `effective_at` on this clock.
    pub fn pending_recovery(&self, now: &HostNow) -> Vec<PendingSummary> {
        self.records
            .iter()
            .filter(|r| r.state() == RecoveryState::Pending)
            .map(|r| {
                let entry = self.entry(r.seq).expect("a record names a stored entry");
                PendingSummary {
                    entry_hash: r.entry_hash,
                    seq: r.seq,
                    action: entry.action.name(),
                    subject: match &entry.action {
                        Action::RecoveryAdd { member } => member.device_id.clone(),
                        _ => entry.signer.clone(),
                    },
                    effective_at: r.clock.effective_at(now),
                }
            })
            .collect()
    }

    // ------------------------------------------------------- verification

    /// Checks `entry` as the next one after the head (§R9.2 "Verifying entry
    /// n"), on this verifier's current standing.
    pub fn check_next(&self, entry: &Entry) -> Check {
        self.check_against(&self.derived, &self.entries, entry)
    }

    fn check_against(&self, d: &Derived, chain: &[Entry], entry: &Entry) -> Check {
        match self.check_inner(d, chain, entry) {
            Ok(None) => Check::Valid,
            Ok(Some(on)) => Check::Deferred(on),
            Err(reason) => Check::Invalid(reason),
        }
    }

    fn check_inner(
        &self,
        d: &Derived,
        chain: &[Entry],
        entry: &Entry,
    ) -> Result<Option<Hash32>, Invalid> {
        if entry.account_id != self.account_id {
            return Err(Invalid::WrongAccount);
        }
        if entry.genesis_hash != Some(self.genesis_hash) {
            return Err(Invalid::GenesisMismatch);
        }
        let head = chain.last().expect("a chain has its genesis");
        if entry.seq != head.seq + 1 {
            return Err(Invalid::WrongSeq);
        }
        if entry.seq > MAX_ENTRIES {
            return Err(Invalid::LogFull);
        }
        if entry.prev_hash != head.hash() {
            return Err(Invalid::WrongPrevHash);
        }
        let object = entry.object();
        let mut deferred = None;

        // The signer (§R9.2): the current recovery key for `recovery_add`,
        // else a native manager in effect here, each under its pinned alg.
        if entry.signer == RECOVERY_SIGNER {
            deferred = recovery_signature(d, |key| object.verify(key))?;
        } else {
            let Some(signer) = d.members.get(&entry.signer) else {
                return Err(Invalid::SignerNotManager);
            };
            if !signer.member.is_manager() {
                return Err(Invalid::SignerNotManager);
            }
            match signer.status {
                MemberStatus::Active => {}
                MemberStatus::Pending { entry_hash } => deferred = Some(entry_hash),
                MemberStatus::Cancelled | MemberStatus::Removed => {
                    return Err(Invalid::SignerNotManager);
                }
            }
            object.verify(&signer.member.auth_key)?;
        }
        if let Action::SetRecoveryKey {
            kit: KitMode::Current,
            ..
        } = entry.action
        {
            if object.kit_sig().is_none() {
                return Err(Invalid::KitSigMissing);
            }
            if let Some(on) = recovery_signature(d, |key| object.verify_kit_sig(key))? {
                deferred.get_or_insert(on);
            }
        }

        // The action's rules.
        match &entry.action {
            Action::Genesis { .. } => return Err(Invalid::BadGenesis),
            Action::Add { member } | Action::RecoveryAdd { member } => {
                if d.members.contains_key(&member.device_id) {
                    return Err(Invalid::DeviceIdReused);
                }
                if d.current_member_count() >= MAX_MEMBERS {
                    return Err(Invalid::LogFull);
                }
            }
            Action::Remove { device_id } => {
                let target = current_target(d, device_id, &mut deferred)?;
                if target.member.is_manager() && d.native_managers_except(device_id) == 0 {
                    return Err(Invalid::LastManager);
                }
            }
            Action::SetRoles { device_id, change } => {
                let target = current_target(d, device_id, &mut deferred)?;
                let still_manager = match (&target.member.kind, change) {
                    (MemberKind::Native { .. }, RolesChange::Native(roles)) => {
                        roles.contains(&Role::Manage)
                    }
                    (MemberKind::Service { .. }, RolesChange::Service { .. }) => false,
                    _ => return Err(Invalid::BadRoles),
                };
                if target.member.is_manager()
                    && !still_manager
                    && d.native_managers_except(device_id) == 0
                {
                    return Err(Invalid::LastManager);
                }
            }
            Action::AddHost { host } => {
                let earlier = d.hosts.get(&host.host_id);
                if earlier.is_some_and(|h| h.record.host_trust_gen >= host.host_trust_gen) {
                    return Err(Invalid::HostTrustGenNotIncreasing);
                }
                let is_new = earlier.is_none_or(|h| h.removed);
                if is_new && d.current_hosts() >= MAX_HOSTS {
                    return Err(Invalid::LogFull);
                }
            }
            Action::RemoveHost { host_id } => {
                if d.hosts.get(host_id).is_none_or(|h| h.removed) {
                    return Err(Invalid::NotAHost);
                }
            }
            Action::SetRecoveryKey { recovery_key, .. } => {
                if d.used_keys.contains(recovery_key) {
                    return Err(Invalid::RecoveryKeyReused);
                }
            }
            Action::RecoveryApprove { target } | Action::RecoveryVeto { target } => {
                let Some(target_entry) = chain
                    .iter()
                    .find(|e| e.hash() == *target && e.action.is_pending_type())
                else {
                    return Err(Invalid::NotARecoveryEntry);
                };
                if matches!(entry.action, Action::RecoveryApprove { .. })
                    && target_entry.signer == entry.signer
                {
                    return Err(Invalid::SelfApproval);
                }
            }
            Action::KBackup(record) => {
                if d.k_backup
                    .as_ref()
                    .is_some_and(|newest| record.blob_version <= newest.blob_version)
                {
                    return Err(Invalid::BlobVersionNotIncreasing);
                }
                let named = record.recovery_key == d.recovery_key
                    || d.pending_keys
                        .iter()
                        .any(|(_, k)| *k == record.recovery_key);
                if !named {
                    return Err(Invalid::KBackupKitNotCurrent);
                }
            }
        }
        Ok(deferred)
    }

    /// The standing derived from the first `len` entries, with the decisions
    /// this verifier recorded up to that position (for judging a conflict
    /// against `C[..seq-1]`, §R9.4).
    fn derived_at(&self, len: usize) -> Derived {
        let mut d = Derived::new(&self.entries[0]);
        for entry in &self.entries[..len] {
            d.apply(entry);
            self.apply_decisions_at(&mut d, entry.seq);
        }
        d
    }

    fn apply_decisions_at(&self, d: &mut Derived, seq: u64) {
        let mut decided: Vec<(&Decision, &RecoveryRecord)> = self
            .records
            .iter()
            .filter_map(|r| r.decision.as_ref().map(|dec| (dec, r)))
            .filter(|(dec, _)| dec.at_seq == seq)
            .collect();
        decided.sort_by_key(|(dec, _)| dec.order);
        for (decision, record) in decided {
            let entry = self
                .entry(record.seq)
                .expect("a record names a stored entry");
            d.resolve(entry, decision.state);
        }
    }

    // -------------------------------------------------------- transitions

    /// Appends a checked entry: its effect, a pending record (its wait starts
    /// now), and a decision it makes.
    fn append(&mut self, entry: Entry, now: &HostNow, effects: &mut Vec<Effect>) {
        self.derived.apply(&entry);
        let head = Head {
            seq: entry.seq,
            hash: entry.hash(),
        };
        effects.push(Effect::Appended(head));
        match &entry.action {
            Action::Add { member } => effects.push(Effect::MemberAdded {
                device_id: member.device_id.clone(),
            }),
            Action::Remove { device_id } => effects.push(Effect::MemberRemoved {
                device_id: device_id.clone(),
            }),
            Action::SetRoles { device_id, .. } => effects.push(Effect::RolesChanged {
                device_id: device_id.clone(),
            }),
            Action::AddHost { host } => effects.push(Effect::HostKeyChanged {
                host_id: host.host_id.clone(),
            }),
            Action::RemoveHost { host_id } => effects.push(Effect::HostRemoved {
                host_id: host_id.clone(),
            }),
            Action::KBackup(record) => effects.push(Effect::KBackupRecorded {
                blob_version: record.blob_version,
            }),
            _ => {}
        }
        let pending = entry.action.is_pending_type();
        let decision = match &entry.action {
            Action::RecoveryApprove { target } => Some((*target, RecoveryState::Active)),
            Action::RecoveryVeto { target } => Some((*target, RecoveryState::Cancelled)),
            _ => None,
        };
        let replaced_now = matches!(
            entry.action,
            Action::SetRecoveryKey {
                kit: KitMode::Current,
                ..
            }
        );
        self.entries.push(entry);
        if pending {
            self.records.push(RecoveryRecord {
                entry_hash: head.hash,
                seq: head.seq,
                clock: WaitClock::start(now),
                decision: None,
            });
            effects.push(Effect::RecoveryPending {
                entry_hash: head.hash,
            });
        }
        if replaced_now {
            effects.push(Effect::RecoveryKeyReplaced);
            self.cancel_for_kit_replacement(head.seq, now, effects);
        }
        if let Some((target, state)) = decision {
            // A decision acts only while its target is pending here; after
            // that it is a valid entry with no effect (§R9.5).
            if let Some(index) = self
                .records
                .iter()
                .position(|r| r.entry_hash == target && r.state() == RecoveryState::Pending)
            {
                let reason = if state == RecoveryState::Active {
                    RecoveryReason::Approved
                } else {
                    RecoveryReason::Vetoed
                };
                self.decide(index, state, reason, head.seq, now, effects);
            }
        }
    }

    /// Records a decision and applies it; a kit replacement taking effect
    /// cancels every pending `recovery_add` (signed by the replaced key).
    fn decide(
        &mut self,
        index: usize,
        state: RecoveryState,
        reason: RecoveryReason,
        at_seq: u64,
        now: &HostNow,
        effects: &mut Vec<Effect>,
    ) {
        self.decision_order += 1;
        let record = &mut self.records[index];
        record.clock.observe(now);
        record.decision = Some(Decision {
            state,
            reason,
            at_seq,
            order: self.decision_order,
            at_wall: now.wall_ms,
        });
        let (entry_hash, seq) = (record.entry_hash, record.seq);
        let entry = self
            .entry(seq)
            .expect("a record names a stored entry")
            .clone();
        self.derived.resolve(&entry, state);
        effects.push(match state {
            RecoveryState::Active => Effect::RecoveryActive { entry_hash, reason },
            _ => Effect::RecoveryCancelled { entry_hash, reason },
        });
        if state == RecoveryState::Active && matches!(entry.action, Action::SetRecoveryKey { .. }) {
            effects.push(Effect::RecoveryKeyReplaced);
            self.cancel_for_kit_replacement(at_seq, now, effects);
        }
    }

    fn cancel_for_kit_replacement(
        &mut self,
        at_seq: u64,
        now: &HostNow,
        effects: &mut Vec<Effect>,
    ) {
        while let Some(index) = self.records.iter().position(|r| {
            r.state() == RecoveryState::Pending
                && matches!(
                    self.entry(r.seq).map(|e| &e.action),
                    Some(Action::RecoveryAdd { .. })
                )
        }) {
            self.decide(
                index,
                RecoveryState::Cancelled,
                RecoveryReason::KitReplaced,
                at_seq,
                now,
                effects,
            );
        }
    }

    /// Ends every wait whose time is up on `now` (the host's 100 ms pass),
    /// in `seq` order, and records the time waited. A frozen verifier
    /// applies nothing.
    pub fn advance(&mut self, now: &HostNow) -> Vec<Effect> {
        let mut effects = Vec::new();
        if self.frozen.is_some() {
            return effects;
        }
        let head = self.head().seq;
        let mut index = 0;
        while index < self.records.len() {
            let record = &self.records[index];
            if record.state() == RecoveryState::Pending && record.clock.elapsed(now) {
                self.decide(
                    index,
                    RecoveryState::Active,
                    RecoveryReason::WaitEnded,
                    head,
                    now,
                    &mut effects,
                );
            }
            index += 1;
        }
        self.checkpoint(now);
        effects
    }

    /// Records the time waited by every pending entry (persist at least once
    /// a minute and at shutdown).
    pub fn checkpoint(&mut self, now: &HostNow) {
        for record in &mut self.records {
            if record.decision.is_none() {
                record.clock.observe(now);
            }
        }
    }

    // ----------------------------------------------------------- carriage

    /// Evaluates a carriage (§R9.3 "Applying a carriage", §R9.4) against a
    /// scratch copy. Nothing in `self` changes: commit `next` once it is
    /// durable. `received_bytes` is the size of the carried `entries` as they
    /// arrived on the wire (or of the whole message carrying them): the
    /// 256 KiB bound is on what was received, not on a re-encoding.
    pub fn evaluate(
        &self,
        carried: &[StrictValue],
        received_bytes: usize,
        now: &HostNow,
    ) -> Evaluation {
        let parsed = carried.iter().map(Entry::from_strict).collect::<Vec<_>>();
        let sizes = carried
            .iter()
            .map(|v| v.value().to_string().len())
            .collect::<Vec<_>>();
        self.evaluate_parsed(parsed, &sizes, received_bytes, now)
    }

    /// `evaluate` of signed objects already parsed (a client applying a
    /// relay reply it bounded itself); the bound is checked on their wire
    /// encoding.
    pub fn evaluate_objects(&self, carried: &[SignedObject], now: &HostNow) -> Evaluation {
        let sizes = carried
            .iter()
            .map(|o| o.to_json().to_string().len())
            .collect::<Vec<_>>();
        let parsed = carried.iter().cloned().map(Entry::parse).collect();
        self.evaluate_parsed(parsed, &sizes, 0, now)
    }

    fn evaluate_parsed(
        &self,
        parsed: Vec<Result<Entry, Invalid>>,
        sizes: &[usize],
        received_bytes: usize,
        now: &HostNow,
    ) -> Evaluation {
        let mut eval = Evaluation {
            next: self.clone(),
            carried: Vec::new(),
            appended: 0,
            effects: Vec::new(),
            stop: None,
        };
        if self.frozen.is_some() {
            eval.stop = Some(Stop::Frozen);
            return eval;
        }
        // 1. Shape: bounds, every body parses, contiguous ascending seq.
        // The byte bound is on the larger of the count the caller measured
        // on the wire and the entries' own encoding, so a wrong count can't
        // lift it. `index` names the entry that crosses the bound (the 65th,
        // or the one whose bytes cross 256 KiB; the last one when only the
        // received count does).
        let mut total = 0;
        let crossing = sizes.iter().position(|size| {
            total += size;
            total > MAX_CARRIAGE_BYTES
        });
        let too_large = if parsed.len() > MAX_CARRIAGE_ENTRIES {
            Some(MAX_CARRIAGE_ENTRIES)
        } else if let Some(index) = crossing {
            Some(index)
        } else if received_bytes > MAX_CARRIAGE_BYTES {
            Some(parsed.len().saturating_sub(1))
        } else {
            None
        };
        if let Some(index) = too_large {
            eval.stop = Some(Stop::Invalid {
                index,
                reason: Invalid::CarriageTooLarge,
            });
            return eval;
        }
        for (index, entry) in parsed.into_iter().enumerate() {
            let checked = entry.and_then(|entry| {
                if eval
                    .carried
                    .last()
                    .is_some_and(|prev: &Entry| entry.seq != prev.seq + 1)
                {
                    Err(Invalid::Gap)
                } else {
                    Ok(entry)
                }
            });
            match checked {
                Ok(entry) => eval.carried.push(entry),
                Err(reason) => {
                    eval.carried.clear();
                    eval.stop = Some(Stop::Invalid { index, reason });
                    return eval;
                }
            }
        }

        // Time first: a wait that ended is applied before the carriage.
        eval.effects = eval.next.advance(now);

        // 2. Each entry in order against the scratch chain.
        let window_start = eval.carried.first().map(|e| e.seq);
        for (index, entry) in eval.carried.clone().into_iter().enumerate() {
            let head = eval.next.head();
            if entry.seq <= head.seq {
                let ours = eval.next.entry(entry.seq).expect("seq ≤ head");
                if ours.hash() == entry.hash() {
                    continue; // the same entry; the stored signature stays
                }
                if entry.seq == 1 {
                    eval.stop = Some(Stop::Invalid {
                        index,
                        reason: Invalid::GenesisMismatch,
                    });
                    return eval;
                }
                let before = eval.next.entry(entry.seq - 1).expect("seq ≥ 2").hash();
                if entry.prev_hash != before {
                    eval.stop = Some(Stop::NeedBefore {
                        index,
                        seq: window_start.unwrap_or(entry.seq),
                    });
                    return eval;
                }
                let outcome = eval.next.conflict(&entry, now, &mut eval.effects);
                eval.stop = Some(Stop::Conflict { index, outcome });
                return eval;
            }
            if entry.seq > head.seq + 1 {
                eval.stop = Some(Stop::Invalid {
                    index,
                    reason: Invalid::Gap,
                });
                return eval;
            }
            match eval.next.check_next(&entry) {
                Check::Valid => {
                    eval.next.append(entry, now, &mut eval.effects);
                    eval.appended += 1;
                }
                Check::Deferred(on) => {
                    eval.stop = Some(Stop::Deferred { index, on });
                    return eval;
                }
                Check::Invalid(reason) => {
                    eval.stop = Some(Stop::Invalid { index, reason });
                    return eval;
                }
            }
        }
        eval
    }

    /// §R9.4: `theirs` differs from our entry at its `seq` and chains from
    /// our entry before it. Only this first divergent entry is judged.
    fn conflict(&mut self, theirs: &Entry, now: &HostNow, effects: &mut Vec<Effect>) -> Conflict {
        let seq = theirs.seq;
        let ours = self.entry(seq).expect("seq ≤ head").clone();
        let prefix_len = (seq - 1) as usize;
        let prefix = self.derived_at(prefix_len);
        let against_prefix = self.check_against(&prefix, &self.entries[..prefix_len], theirs);
        let target_of = |entry: &Entry| match entry.action {
            Action::RecoveryApprove { target } | Action::RecoveryVeto { target } => Some(target),
            _ => None,
        };
        let is_veto = |entry: &Entry| matches!(entry.action, Action::RecoveryVeto { .. });

        // Row 1: two vetoes of one target.
        if is_veto(theirs)
            && is_veto(&ours)
            && target_of(theirs) == target_of(&ours)
            && against_prefix == Check::Valid
        {
            if seq == self.head().seq {
                let head = Head {
                    seq,
                    hash: theirs.hash(),
                };
                *self.entries.last_mut().expect("a log has entries") = theirs.clone();
                effects.push(Effect::VetoReplaced(head));
                return Conflict::ReplacedVeto;
            }
            return self.ignore(theirs, EvidenceReason::DuplicateVeto, now, effects);
        }
        // Row 2: our veto acted while its target was pending here, and theirs
        // is the target subject's own entry (or verifies only with its key).
        if let Some(target) = target_of(&ours).filter(|_| is_veto(&ours))
            && let Some(record) = self.record(&target)
            && record
                .decision
                .as_ref()
                .is_some_and(|d| d.reason == RecoveryReason::Vetoed && d.at_seq == seq)
            && self.signed_by_subject(theirs, &target)
        {
            return self.freeze(seq, &ours, theirs, now, effects);
        }
        // Row 3: a decision of a target already in effect here, against our
        // entry signed by that target's subject.
        if let Some(target) = target_of(theirs)
            && self
                .record(&target)
                .is_some_and(|r| r.state() == RecoveryState::Active)
            && self.signed_by_subject(&ours, &target)
        {
            return self.ignore(theirs, EvidenceReason::LateDecision, now, effects);
        }
        // Row 4: invalid against C[..seq-1]. An entry that is only deferred
        // there (validly signed; it waits on an entry pending at that
        // position) is not invalid (§R9.2); rows 5 and 6 judge its signer.
        //
        // Deferred signers are judged by where they stand at our head, the
        // same way for both kinds: a key that was pending at seq-1 and is in
        // effect at our head freezes (a recovered subject now active, or a
        // `kit: "lost"` key K2 now the current recovery key); otherwise the
        // entry is ignored (the key was vetoed, cancelled or replaced).
        if matches!(against_prefix, Check::Invalid(_)) {
            return self.ignore(theirs, EvidenceReason::Invalid, now, effects);
        }
        // Row 5: the signer was removed or lost `manage` in C[seq..head]. The
        // recovery key is never "removed": a conflict it signed (it was the
        // recovery key at that position) freezes, even if it was replaced
        // since (§R9.4 row 6, §R9.5).
        if self.signer_removed_since(theirs, seq) {
            return self.ignore(theirs, EvidenceReason::SignerRemoved, now, effects);
        }
        // Row 6: signed by the recovery key, or by a manager in effect at our
        // head.
        if theirs.signer == RECOVERY_SIGNER {
            let current_at_head = match against_prefix {
                Check::Deferred(on) => matches!(
                    self.entry_by_hash(&on).map(|e| &e.action),
                    Some(Action::SetRecoveryKey { recovery_key, .. })
                        if recovery_key == self.recovery_key()
                ),
                _ => true,
            };
            if current_at_head {
                return self.freeze(seq, &ours, theirs, now, effects);
            }
            return self.ignore(theirs, EvidenceReason::SignerNotInEffect, now, effects);
        }
        let manager_at_head = self
            .member(&theirs.signer)
            .is_some_and(|m| m.status == MemberStatus::Active && m.member.is_manager());
        if manager_at_head {
            return self.freeze(seq, &ours, theirs, now, effects);
        }
        self.ignore(theirs, EvidenceReason::SignerNotInEffect, now, effects)
    }

    /// `entry` is signed by the subject of the pending-type entry `target`:
    /// the recovered device itself (its `signer` and a signature that
    /// verifies with its `auth_key`; the `signer` string alone proves
    /// nothing), or (for a `kit: "lost"` replacement) the new kit's key,
    /// alone or as `kit_sig`.
    fn signed_by_subject(&self, entry: &Entry, target: &Hash32) -> bool {
        let Some(target_entry) = self.entry_by_hash(target) else {
            return false;
        };
        match &target_entry.action {
            Action::RecoveryAdd { member } => {
                entry.signer == member.device_id && entry.object().verify(&member.auth_key).is_ok()
            }
            Action::SetRecoveryKey { recovery_key, .. } => {
                (entry.signer == RECOVERY_SIGNER && entry.object().verify(recovery_key).is_ok())
                    || entry.object().verify_kit_sig(recovery_key).is_ok()
            }
            _ => false,
        }
    }

    fn signer_removed_since(&self, theirs: &Entry, seq: u64) -> bool {
        if theirs.signer == RECOVERY_SIGNER {
            return false;
        }
        let later = &self.entries[(seq - 1) as usize..];
        later.iter().any(|e| match &e.action {
            Action::Remove { device_id } => *device_id == theirs.signer,
            Action::SetRoles { device_id, change } => {
                *device_id == theirs.signer
                    && !matches!(change, RolesChange::Native(roles) if roles.contains(&Role::Manage))
            }
            _ => false,
        })
    }

    fn ignore(
        &mut self,
        theirs: &Entry,
        reason: EvidenceReason,
        now: &HostNow,
        effects: &mut Vec<Effect>,
    ) -> Conflict {
        self.evidence.push(EvidenceRecord {
            seq: theirs.seq,
            entry_hash: theirs.hash(),
            signer: theirs.signer.clone(),
            reason,
            at: now.wall_ms,
        });
        effects.push(Effect::Evidence(reason));
        Conflict::Ignored(reason)
    }

    fn freeze(
        &mut self,
        seq: u64,
        ours: &Entry,
        theirs: &Entry,
        now: &HostNow,
        effects: &mut Vec<Effect>,
    ) -> Conflict {
        self.frozen = Some(Freeze {
            seq,
            ours: ours.object().clone(),
            theirs: theirs.object().clone(),
            at: now.wall_ms,
        });
        effects.push(Effect::Frozen);
        Conflict::Freeze
    }

    // ------------------------------------------------------------ pairing

    /// The pairing checks of §R9.2 "Pairing" on a verified chain: its
    /// genesis isn't frozen here, and the newest `add_host` of `host_id`
    /// names this host's key and trust generation and is signed by the
    /// verified Astation (`astation_sign_pub`).
    pub fn check_pairing(
        &self,
        host_id: &str,
        host_trust_gen: u64,
        host_key: &PublicKey,
        astation_sign_pub: &PublicKey,
        frozen_genesis: &[Hash32],
    ) -> Result<(), PairingRefusal> {
        if frozen_genesis.contains(&self.genesis_hash) {
            return Err(PairingRefusal::FrozenGenesis);
        }
        let newest = self
            .entries
            .iter()
            .rev()
            .find(|e| matches!(&e.action, Action::AddHost { host } if host.host_id == host_id))
            .ok_or(PairingRefusal::HostNotAdded)?;
        let Action::AddHost { host } = &newest.action else {
            unreachable!()
        };
        if host.host_trust_gen != host_trust_gen || host.host_key != *host_key {
            return Err(PairingRefusal::HostKeyMismatch);
        }
        if self.host(host_id).is_none() {
            return Err(PairingRefusal::HostNotAdded);
        }
        let signer = self
            .member(&newest.signer)
            .ok_or(PairingRefusal::NotSignedByAstation)?;
        if signer.member.auth_key != *astation_sign_pub {
            return Err(PairingRefusal::NotSignedByAstation);
        }
        Ok(())
    }
}

/// The checks shared by both recovery-key signatures (`sig` of a
/// `recovery_add`, `kit_sig`): the current key, else a pending
/// replacement's key (deferred), else a replaced key (retired).
fn recovery_signature(
    d: &Derived,
    verify: impl Fn(&PublicKey) -> crate::error::Result<()>,
) -> Result<Option<Hash32>, Invalid> {
    if verify(&d.recovery_key).is_ok() {
        return Ok(None);
    }
    if let Some((hash, _)) = d.pending_keys.iter().find(|(_, key)| verify(key).is_ok()) {
        return Ok(Some(*hash));
    }
    if d.retired.iter().any(|key| verify(key).is_ok()) {
        return Err(Invalid::RecoveryKeyRetired);
    }
    Err(Invalid::BadSignature)
}

/// The target of `remove`/`set_roles`: a current member, or the subject of a
/// pending `recovery_add` (the entry then waits for it).
fn current_target<'a>(
    d: &'a Derived,
    device_id: &str,
    deferred: &mut Option<Hash32>,
) -> Result<&'a MemberState, Invalid> {
    let target = d.members.get(device_id).ok_or(Invalid::NotAMember)?;
    match target.status {
        MemberStatus::Active => Ok(target),
        MemberStatus::Pending { entry_hash } => {
            deferred.get_or_insert(entry_hash);
            Ok(target)
        }
        MemberStatus::Cancelled | MemberStatus::Removed => Err(Invalid::NotAMember),
    }
}

/// Why a pairing can't pin a log (§R9.2 "Pairing").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingRefusal {
    /// The log's genesis is on `pairing/frozen_genesis`: re-pairing must
    /// start a new list.
    FrozenGenesis,
    HostNotAdded,
    HostKeyMismatch,
    NotSignedByAstation,
}

impl PairingRefusal {
    pub fn as_str(self) -> &'static str {
        match self {
            PairingRefusal::FrozenGenesis => "frozen genesis",
            PairingRefusal::HostNotAdded => "host not in the device list",
            PairingRefusal::HostKeyMismatch => "host key or trust generation differs",
            PairingRefusal::NotSignedByAstation => "add_host not signed by the verified Astation",
        }
    }
}

/// How a conflict was settled (§R9.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Conflict {
    Freeze,
    Ignored(EvidenceReason),
    /// Row 1 with our veto at the head: replaced by theirs in one write.
    ReplacedVeto,
}

/// Where a carriage stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stop {
    /// The verifier is frozen: nothing was evaluated.
    Frozen,
    /// `membership_invalid{index}` (the valid prefix before it applies).
    Invalid {
        index: usize,
        reason: Invalid,
    },
    /// The divergence is before the window: `need_before: seq`.
    NeedBefore {
        index: usize,
        seq: u64,
    },
    /// Depends on a pending entry: stopped without an error.
    Deferred {
        index: usize,
        on: Hash32,
    },
    Conflict {
        index: usize,
        outcome: Conflict,
    },
}

/// The outcome of a carriage: the proposed next state and why it stopped.
#[derive(Debug, Clone)]
pub struct Evaluation {
    /// The scratch state: the valid prefix appended, waits ended, evidence,
    /// a replaced veto or a freeze. Commit it once it is durable.
    pub next: Membership,
    /// The carried entries, parsed (empty when the shape was refused).
    pub carried: Vec<Entry>,
    /// How many entries were appended.
    pub appended: usize,
    pub effects: Vec<Effect>,
    pub stop: Option<Stop>,
}

/// What a carrier gets (§R9.3 step 5), from the membership side. The host
/// adds the rest of admission (expiry, scope, revision; R9.6, R9.8).
#[derive(Debug, Clone, PartialEq)]
pub enum Admission {
    /// `account_frozen`.
    Frozen,
    /// `membership_invalid{head, index, detail, need_before?}`.
    Invalid {
        head: Head,
        index: usize,
        reason: Invalid,
        need_before: Option<u64>,
    },
    /// `membership_incomplete{head}`.
    Incomplete { head: Head },
    /// `recovery_pending{entry_hash, effective_at}`.
    RecoveryPending {
        entry_hash: Hash32,
        effective_at: u64,
    },
    /// `unauthorized` with this detail (`removed`, `not a member`).
    Unauthorized(&'static str),
    /// A member in effect at the committed head.
    Member { head: Head, state: MemberState },
}

impl Evaluation {
    /// Something to write: entries, a replaced veto, decisions, evidence or a
    /// freeze.
    pub fn changed(&self, before: &Membership) -> bool {
        self.next != *before
    }

    /// The membership side of the reply to the carrier `device_id` (§R9.3
    /// step 5), once `next` is committed. `more`: the carriage said more
    /// entries follow.
    pub fn admission(&self, device_id: &str, more: bool, now: &HostNow) -> Admission {
        let next = &self.next;
        let head = next.head();
        match &self.stop {
            Some(Stop::Frozen) => return Admission::Frozen,
            Some(Stop::Conflict {
                outcome: Conflict::Freeze,
                ..
            }) => return Admission::Frozen,
            Some(Stop::Invalid { index, reason }) => {
                return Admission::Invalid {
                    head,
                    index: *index,
                    reason: reason.clone(),
                    need_before: None,
                };
            }
            Some(Stop::NeedBefore { index, seq }) => {
                return Admission::Invalid {
                    head,
                    index: *index,
                    reason: Invalid::WrongPrevHash,
                    need_before: Some(*seq),
                };
            }
            _ => {}
        }
        if next.frozen.is_some() {
            return Admission::Frozen;
        }
        if more && next.member(device_id).is_none() {
            return Admission::Incomplete { head };
        }
        // Added only by the entry deferred behind a pending one. That entry
        // was verified up to its deferral (signature included); the ones
        // after it weren't, so they prove nothing.
        if let Some(Stop::Deferred { index, on }) = &self.stop
            && next.member(device_id).is_none()
            && matches!(&self.carried[*index].action,
                Action::Add { member } | Action::RecoveryAdd { member }
                    if member.device_id == device_id)
        {
            return next.pending_admission(on, now);
        }
        next.admit(device_id, now)
    }
}

impl Membership {
    /// The membership side of admitting `device_id` at the committed head
    /// (no carriage).
    pub fn admit(&self, device_id: &str, now: &HostNow) -> Admission {
        if self.frozen.is_some() {
            return Admission::Frozen;
        }
        match self.member(device_id) {
            None => Admission::Unauthorized("not a member"),
            Some(state) => match state.status {
                MemberStatus::Active => Admission::Member {
                    head: self.head(),
                    state: state.clone(),
                },
                MemberStatus::Pending { entry_hash } => self.pending_admission(&entry_hash, now),
                MemberStatus::Removed => Admission::Unauthorized("removed"),
                MemberStatus::Cancelled => Admission::Unauthorized("not a member"),
            },
        }
    }

    fn pending_admission(&self, entry_hash: &Hash32, now: &HostNow) -> Admission {
        let effective_at = self
            .record(entry_hash)
            .map_or(now.wall_ms, |r| r.clock.effective_at(now));
        Admission::RecoveryPending {
            entry_hash: *entry_hash,
            effective_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kit::RecoveryKit;
    use crate::provider::KeyProvider;

    /// A device whose Ed25519 auth key is held by a `RecoveryKit` (any
    /// provider will do here).
    fn device(seed: u8) -> RecoveryKit {
        RecoveryKit::make(&[seed; 32], "acct", Hash32([0; 32]))
    }

    fn member(id: &str, keys: &RecoveryKit, roles: &[Role]) -> Member {
        Member {
            device_id: id.into(),
            auth_key: keys.recovery_key(),
            kind: MemberKind::Native {
                enc_key: keys.public_key(&RecoveryKit::x25519_id()).unwrap(),
                roles: roles.iter().copied().collect(),
            },
        }
    }

    const ALL: [Role; 3] = [Role::Control, Role::Manage, Role::View];

    fn now(wall: u64) -> HostNow {
        HostNow {
            wall_ms: wall,
            mono_ms: wall,
            boot_id: "b".into(),
        }
    }

    /// The standing replayed from the entries and the recorded decisions is
    /// the one built incrementally (conflicts are judged on replays).
    fn assert_replay(m: &Membership) {
        assert_eq!(m.derived_at(m.entries.len()), m.derived);
    }

    fn append(
        m: &mut Membership,
        signer: &str,
        keys: &RecoveryKit,
        action: Action,
        at: u64,
    ) -> Hash32 {
        let body = m.draft(signer, at, &action);
        let entry = sign_entry(keys, &RecoveryKit::sign_id(), body).unwrap();
        let hash = entry.hash();
        let eval = m.evaluate_objects(&[entry.object().clone()], &now(at));
        assert_eq!(eval.stop, None, "{action:?}");
        *m = eval.next;
        assert_replay(m);
        hash
    }

    #[test]
    fn a_replayed_prefix_matches_the_incremental_state() {
        let (mac, phone, ipad, newmac) = (device(1), device(2), device(3), device(4));
        let (kit1, kit2) = (device(10), device(11));
        let genesis_body = draft::draft_on(
            "acct",
            &Hash32([0; 32]),
            1,
            &Hash32([0; 32]),
            "mac",
            0,
            &Action::Genesis {
                member: member("mac", &mac, &ALL),
                recovery_key: kit1.recovery_key(),
            },
        );
        let genesis = sign_entry(&mac, &RecoveryKit::sign_id(), genesis_body).unwrap();
        let mut m = Membership::from_genesis("acct", &genesis.hash(), genesis).unwrap();
        assert_replay(&m);
        append(
            &mut m,
            "mac",
            &mac,
            Action::Add {
                member: member("phone", &phone, &ALL),
            },
            1,
        );
        append(
            &mut m,
            "mac",
            &mac,
            Action::Add {
                member: member("ipad", &ipad, &ALL),
            },
            2,
        );
        append(
            &mut m,
            "phone",
            &phone,
            Action::SetRoles {
                device_id: "ipad".into(),
                change: RolesChange::Native([Role::View].into()),
            },
            3,
        );
        let r = append(
            &mut m,
            RECOVERY_SIGNER,
            &kit1,
            Action::RecoveryAdd {
                member: member("newmac", &newmac, &ALL),
            },
            4,
        );
        append(
            &mut m,
            "mac",
            &mac,
            Action::RecoveryApprove { target: r },
            5,
        );
        assert_eq!(m.record(&r).unwrap().state(), RecoveryState::Active);
        append(
            &mut m,
            "newmac",
            &newmac,
            Action::Remove {
                device_id: "ipad".into(),
            },
            6,
        );
        // A kit-lost replacement, then the old kit's enrollment while it
        // waits, then the wait ends for both (one cancels the other).
        let lost = append(
            &mut m,
            "phone",
            &phone,
            Action::SetRecoveryKey {
                recovery_key: kit2.recovery_key(),
                kit: KitMode::Lost,
            },
            7,
        );
        let late = append(
            &mut m,
            RECOVERY_SIGNER,
            &kit1,
            Action::RecoveryAdd {
                member: member("thief", &device(5), &ALL),
            },
            RECOVERY_WAIT_MS / 2,
        );
        m.advance(&now(RECOVERY_WAIT_MS + 8));
        assert_replay(&m);
        assert_eq!(m.record(&lost).unwrap().state(), RecoveryState::Active);
        assert_eq!(m.record(&late).unwrap().state(), RecoveryState::Cancelled);
        assert_eq!(*m.recovery_key(), kit2.recovery_key());
        // Every prefix replays to a state a later entry can be judged on.
        for len in 1..=m.entries.len() {
            let d = m.derived_at(len);
            assert!(d.members.contains_key("mac"));
        }
        assert_eq!(m.derived_at(5).recovery_key, kit1.recovery_key());
        assert_eq!(
            m.derived_at(5).members["newmac"].status,
            MemberStatus::Pending { entry_hash: r }
        );
    }

    #[test]
    fn the_last_manager_can_neither_be_removed_nor_demoted() {
        let mac = device(1);
        let body = draft::draft_on(
            "acct",
            &Hash32([0; 32]),
            1,
            &Hash32([0; 32]),
            "mac",
            0,
            &Action::Genesis {
                member: member("mac", &mac, &ALL),
                recovery_key: device(9).recovery_key(),
            },
        );
        let genesis = sign_entry(&mac, &RecoveryKit::sign_id(), body).unwrap();
        let m = Membership::from_genesis("acct", &genesis.hash(), genesis).unwrap();
        for action in [
            Action::Remove {
                device_id: "mac".into(),
            },
            Action::SetRoles {
                device_id: "mac".into(),
                change: RolesChange::Native([Role::Control, Role::View].into()),
            },
        ] {
            let body = m.draft("mac", 1, &action);
            let entry = sign_entry(&mac, &RecoveryKit::sign_id(), body).unwrap();
            assert_eq!(m.check_next(&entry), Check::Invalid(Invalid::LastManager));
        }
    }
}
