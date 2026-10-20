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
use serde_json::Value;

use crate::backup::{BackupKey, KBackupEnvelope};
use crate::canonical::StrictValue;
use crate::domain::{self, SignLabel, SigningInput};
use crate::encoding::{Hash32, b64u_decode, b64u_decode_array, u64_field};
use crate::kit::RecoveryKit;
use crate::membership::{
    Action, Entry, Head, HostNow, Invalid, Member, Membership, RECOVERY_SIGNER, sign_entry,
};

/// One host's answer to an `init` (§R9.7 messages 1 and 2): what the client
/// sent and what the host signed. Verified by [`HostAccept::verify`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostAccept {
    /// `init`: the client's ephemeral and nonce, and the target it named.
    pub e_c: [u8; 32],
    pub n_c: [u8; 32],
    pub genesis_hash: Hash32,
    pub host_id: String,
    pub host_trust_gen: u64,
    /// `accept`: the host's ephemeral and nonce, its head and `sig_h`.
    pub e_h: [u8; 32],
    pub n_h: [u8; 32],
    pub head: Head,
    pub sig: Vec<u8>,
}

/// Why a host's `accept` doesn't confirm a head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeadError {
    /// Not the `init`/`accept` shape of §R9.7.
    Malformed,
    /// The `init` named another log (another account or genesis).
    OtherGenesis,
    /// No current host by that id in the verified chain, or not its newest
    /// trust generation.
    UnknownHost,
    /// `sig_h` doesn't verify with that host's key.
    BadSignature,
}

/// A head a host signed, verified: only [`HostAccept::verify`] makes one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostHead {
    host_id: String,
    head: Head,
}

impl HostHead {
    pub fn host_id(&self) -> &str {
        &self.host_id
    }

    pub fn head(&self) -> Head {
        self.head
    }
}

fn field<'a>(v: &'a Value, name: &str) -> Result<&'a str, HeadError> {
    v.get(name)
        .and_then(Value::as_str)
        .ok_or(HeadError::Malformed)
}

impl HostAccept {
    /// From the two wire messages, parsed strictly.
    pub fn from_messages(init: &StrictValue, accept: &StrictValue) -> Result<Self, HeadError> {
        let (init, accept) = (init.value(), accept.value());
        let op = |v: &Value, op: &str| {
            v.get("ch").and_then(Value::as_str) == Some("atem-ch1")
                && v.get("op").and_then(Value::as_str) == Some(op)
        };
        if !op(init, "init") || !op(accept, "accept") {
            return Err(HeadError::Malformed);
        }
        let b32 = |v: &Value, name: &str| {
            b64u_decode_array::<32>(field(v, name)?).map_err(|_| HeadError::Malformed)
        };
        let head = accept.get("head").ok_or(HeadError::Malformed)?;
        Ok(HostAccept {
            e_c: b32(init, "e")?,
            n_c: b32(init, "n")?,
            genesis_hash: Hash32::from_hex(field(init, "genesis_hash")?)
                .map_err(|_| HeadError::Malformed)?,
            host_id: field(init, "host_id")?.to_owned(),
            host_trust_gen: init
                .get("host_trust_gen")
                .and_then(Value::as_u64)
                .ok_or(HeadError::Malformed)?,
            e_h: b32(accept, "e")?,
            n_h: b32(accept, "n")?,
            head: Head {
                seq: head
                    .get("seq")
                    .and_then(Value::as_u64)
                    .ok_or(HeadError::Malformed)?,
                hash: Hash32::from_hex(field(head, "hash")?).map_err(|_| HeadError::Malformed)?,
            },
            sig: b64u_decode(field(accept, "sig")?).map_err(|_| HeadError::Malformed)?,
        })
    }

    /// `th2 = H(enc(["atem-ch1-th2", e_c, n_c, genesis_hash, host_id,
    /// u64(host_trust_gen), e_h, n_h, u64(head.seq), head.hash]))`.
    pub fn th2(&self) -> Hash32 {
        Hash32::of_enc(&[
            domain::CH1_TH2.as_bytes(),
            &self.e_c,
            &self.n_c,
            self.genesis_hash.as_bytes(),
            self.host_id.as_bytes(),
            &u64_field(self.host_trust_gen),
            &self.e_h,
            &self.n_h,
            &u64_field(self.head.seq),
            self.head.hash.as_bytes(),
        ])
    }

    /// `enc(["atem-ch1-host-sig-v1", th2])`: what the host signs.
    pub fn signing_input(&self) -> SigningInput {
        SigningInput::new(SignLabel::ChannelHost, self.th2().as_bytes())
    }

    /// Checks `sig_h` with the host key `log` records for `host_id` at
    /// `host_trust_gen` (its newest `add_host`), and that the `init` named
    /// `log`'s genesis.
    pub fn verify(&self, log: &Membership) -> Result<HostHead, HeadError> {
        if self.genesis_hash != log.genesis_hash() {
            return Err(HeadError::OtherGenesis);
        }
        let host = log.host(&self.host_id).ok_or(HeadError::UnknownHost)?;
        if host.host_trust_gen != self.host_trust_gen {
            return Err(HeadError::UnknownHost);
        }
        host.host_key
            .verify(&self.signing_input(), &self.sig)
            .map_err(|_| HeadError::BadSignature)?;
        Ok(HostHead {
            host_id: self.host_id.clone(),
            head: self.head,
        })
    }
}

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
            let Some(highest) = candidates.iter().max_by_key(|h| h.head.seq).cloned() else {
                confirmed = Vec::new();
                break;
            };
            let extended = verify(Some(highest.head))?;
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
        let reaches = log
            .entry(host.head.seq)
            .is_some_and(|e| e.hash() == host.head.hash);
        if !reaches {
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
