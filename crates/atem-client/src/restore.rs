//! The Recovery Kit restore (§R9.5 "Restore", user decision of 2026-10-19
//! "no recovery on a stale head"), as a pure check over what the device
//! fetched: the relay's log and envelope, and the heads hosts signed.
//!
//! 1. Read the kit: `RecoveryKit::read` (a tag mismatch is
//!    `kit_tag_mismatch`; nothing is fetched).
//! 2. Anchor: the log's entry 1 is a genesis whose `entry_hash` and
//!    `account_id` are the kit's (`genesis_mismatch`), and the chain
//!    verifies from it.
//! 3. Confirm the head: at least one host-signed head. The caller passes
//!    each host's `init`/`accept` pair ([`HostAccept`]); `restore` checks
//!    `sig_h` over `th2` (§R9.7) with that host's newest key in the chain
//!    prefix it has verified, the `init`'s `genesis_hash` (the kit's anchor,
//!    which binds the account) and `host_trust_gen`. A pair that doesn't
//!    verify proves nothing and is left out. None left → `withheld` (wait,
//!    never fall back). The log must reach every verified head with the same
//!    hash (`log_behind_host`). [`HostHead`] can only be made this way.
//! 4. The kit's recovery key is the current one (`kit_not_current`).
//! 5. The newest `k_backup` naming this kit; the envelope's `backup_hash`
//!    matches it (`backup_hash_mismatch`) and it opens with the kit
//!    (`backup_invalid`).
//! 6. Then (the caller) store `K`, sign and publish the `recovery_add` on
//!    the confirmed head: [`Restored::recovery_add`].
//!
//! **Reading through a past recovery (an Atem interpretation, noted on
//! #80).** A fresh verifier starts every pending entry's wait now, so a log
//! with a recovery that took effect long ago, followed by entries its
//! subject signed, would stop at the first of them. When a verified host
//! head lies beyond such an entry, `restore` reads through it: a host
//! applies an entry that depends on a pending recovery only once the
//! recovery took effect there, so the dependency is marked active with the
//! reason `host_confirmed`. This is restore-only: hosts never verify with a
//! confirmed head, so a host never records that reason.
use crate::backup::{BackupKey, KBackupEnvelope};
use crate::channel::{HostAccept, HostHead};
use crate::kit::RecoveryKit;
use crate::membership::{
    Action, Entry, Head, HostNow, Invalid, Member, Membership, RECOVERY_SIGNER, sign_entry,
};

/// Why a restore stopped. `code()` is the fixture `detail`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreError {
    GenesisMismatch,
    /// The relay's chain doesn't verify.
    ChainInvalid {
        index: usize,
        reason: Invalid,
    },
    /// No host of the chain answered: wait and retry; never an unconfirmed
    /// head. `hosts` are the chain's hosts to tell the user about.
    Withheld {
        hosts: Vec<String>,
    },
    /// A host signed a head the relay's log doesn't reach: refetch or try
    /// another route.
    LogBehindHost,
    /// The kit was replaced.
    KitNotCurrent,
    /// No `k_backup` names this kit.
    NoBackup,
    /// The envelope isn't the one the newest `k_backup` names.
    BackupHashMismatch,
    /// The envelope doesn't open with the kit (or isn't for this account).
    BackupInvalid,
}

impl RestoreError {
    pub fn code(&self) -> &'static str {
        match self {
            RestoreError::GenesisMismatch => "genesis_mismatch",
            RestoreError::ChainInvalid { .. } => "membership_invalid",
            RestoreError::Withheld { .. } => "no_host_reachable",
            RestoreError::LogBehindHost => "log_behind_host",
            RestoreError::KitNotCurrent => "kit_not_current",
            RestoreError::NoBackup => "no_backup",
            RestoreError::BackupHashMismatch => "backup_hash_mismatch",
            RestoreError::BackupInvalid => "backup_invalid",
        }
    }

    /// The restore waits (no host reachable) rather than failing.
    pub fn is_withheld(&self) -> bool {
        matches!(self, RestoreError::Withheld { .. })
    }

    /// Fetching the log again (or by another route) may help.
    pub fn refetch(&self) -> bool {
        matches!(self, RestoreError::LogBehindHost)
    }
}

/// A restore that passed steps 1–5.
pub struct Restored {
    /// The anchored, verified log (on the restoring device's clock).
    pub log: Membership,
    /// The confirmed head (the log's head, reaching every host head).
    pub head: Head,
    /// The `K` set, current first.
    pub keys: Vec<BackupKey>,
}

impl Restored {
    /// Step 6: the `recovery_add` for `member` on the confirmed head, signed
    /// by the kit (prepare it durably before publishing, §R9.4).
    pub fn recovery_add(
        &self,
        kit: &RecoveryKit,
        member: Member,
        signed_at: u64,
    ) -> Result<Entry, Invalid> {
        let body = self
            .log
            .draft(RECOVERY_SIGNER, signed_at, &Action::RecoveryAdd { member });
        sign_entry(kit, &RecoveryKit::sign_id(), body)
    }
}

/// Steps 2–5 for a kit already read (step 1).
pub fn restore(
    kit: &RecoveryKit,
    relay_log: &[Entry],
    relay_blob: &[u8],
    host_accepts: &[HostAccept],
    now: &HostNow,
) -> Result<Restored, RestoreError> {
    // 2. Anchor and verify.
    let genesis = relay_log.first().ok_or(RestoreError::GenesisMismatch)?;
    kit.check_genesis(&genesis.hash(), &genesis.account_id)
        .map_err(|_| RestoreError::GenesisMismatch)?;
    let chain_error = |e: crate::membership::ChainError| match e.reason {
        Invalid::GenesisMismatch => RestoreError::GenesisMismatch,
        reason => RestoreError::ChainInvalid {
            index: e.index,
            reason,
        },
    };
    let verify = |confirmed: Option<Head>| {
        Membership::verify_chain_confirmed(
            kit.account_id(),
            &kit.genesis_hash(),
            relay_log,
            confirmed,
            now,
        )
        .map_err(chain_error)
    };
    let mut verified = verify(None)?;

    // 3. Host-signed heads, each verified with its host's key from the
    // chain prefix verified so far (a forged or foreign one proves nothing).
    let verify_heads = |log: &Membership| -> Vec<HostHead> {
        host_accepts
            .iter()
            .filter_map(|accept| accept.verify(log).ok())
            .collect()
    };
    let mut confirmed = verify_heads(&verified.membership);
    // A chain that stops at an entry depending on a recovery still pending on
    // this (fresh) verifier: a verified host head beyond it shows that the
    // recovery took effect there, so verify again up to that head. The
    // longer chain may remove or re-key that host (§R9.7 step 1: current, at
    // its newest generation, in the verified log), so every head is checked
    // again against it; if the head read through no longer verifies, the
    // next highest is tried, and with none left the restore waits.
    if verified.deferred.is_some() {
        let mut candidates = confirmed.clone();
        loop {
            let Some(highest) = candidates.iter().max_by_key(|h| h.head().seq).cloned() else {
                confirmed = Vec::new();
                break;
            };
            let extended = verify(Some(highest.head()))?;
            let survivors = verify_heads(&extended.membership);
            if survivors.contains(&highest) {
                verified = extended;
                confirmed = survivors;
                break;
            }
            candidates.retain(|h| *h != highest);
        }
    }
    let log = verified.membership;
    let confirmed: Vec<&HostHead> = confirmed.iter().collect();
    if confirmed.is_empty() {
        let hosts: Vec<String> = log
            .entries()
            .iter()
            .filter_map(|e| match &e.action {
                Action::AddHost { host } if log.host(&host.host_id).is_some() => {
                    Some(host.host_id.clone())
                }
                _ => None,
            })
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        return Err(RestoreError::Withheld { hosts });
    }
    for host in &confirmed {
        if !host.reached_by(&log) {
            return Err(RestoreError::LogBehindHost);
        }
    }

    // 4. The kit is the current one.
    if *log.recovery_key() != kit.recovery_key() {
        return Err(RestoreError::KitNotCurrent);
    }

    // 5. The newest k_backup naming this kit, and its envelope.
    let record = log
        .entries()
        .iter()
        .rev()
        .find_map(|e| match &e.action {
            Action::KBackup(record) if record.recovery_key == kit.recovery_key() => Some(record),
            _ => None,
        })
        .ok_or(RestoreError::NoBackup)?;
    let envelope = KBackupEnvelope::parse(relay_blob).map_err(|_| RestoreError::BackupInvalid)?;
    if envelope.backup_hash() != record.backup_hash {
        return Err(RestoreError::BackupHashMismatch);
    }
    let bound = envelope.account_id == kit.account_id()
        && envelope.genesis_hash == kit.genesis_hash()
        && envelope.blob_version == record.blob_version
        && envelope.kids == record.kids;
    if !bound {
        return Err(RestoreError::BackupInvalid);
    }
    let keys = envelope
        .open_with_kit(kit)
        .map_err(|_| RestoreError::BackupInvalid)?;
    let head = log.head();
    Ok(Restored { log, head, keys })
}
