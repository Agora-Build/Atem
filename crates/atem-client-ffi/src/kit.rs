//! The Recovery Kit (§R9.5), K-backup envelopes and the restore flow. `R`
//! (the kit's secret) is typed or scanned by the user, so it does pass
//! through Rust: it is wiped when the handle drops.
use std::sync::{Arc, Mutex, MutexGuard};

use atem_client::backup::{BackupKey, KBackupEnvelope};
use atem_client::channel::HostAccept;
use atem_client::kit::{RecoveryKit, kit_x25519_public};
use atem_client::membership::HostNow;
use atem_client::membership::publish::AppendReply;
use atem_client::restore::{Enrollment, RestoreFlow};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::encoding::{hash_of, safe_int};
use crate::error::{AtemError, Result};
use crate::log::{MembershipLog, entries_of};
use crate::publish::{append_request, conflict_reply, prepared_from_json, prepared_json};
use crate::types::{
    AccountKey, AppendRequest, EnrollmentOutcome, HostAcceptPair, HostClock, KBackupInfo, LogHead,
    PublicKeyData, RestoredInfo,
};

fn r32(r: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let r: [u8; 32] = r
        .try_into()
        .map_err(|_| AtemError::malformed("R is 32 bytes"))?;
    Ok(Zeroizing::new(r))
}

fn tag16(tag: &[u8]) -> Result<[u8; 16]> {
    tag.try_into()
        .map_err(|_| AtemError::malformed("a kit tag is 16 bytes"))
}

/// A Recovery Kit (account setup, a replacement, or read back for a
/// restore).
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct RecoveryKitHandle {
    kit: Mutex<RecoveryKit>,
    r: Zeroizing<[u8; 32]>,
}

impl RecoveryKitHandle {
    pub(crate) fn kit(&self) -> MutexGuard<'_, RecoveryKit> {
        self.kit.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A copy of the kit for one signing, so no lock of this handle is held
    /// while it is used.
    pub(crate) fn fresh(&self) -> RecoveryKit {
        let kit = self.kit();
        RecoveryKit::make(&self.r, kit.account_id(), kit.genesis_hash())
    }

    fn wrap(r: Zeroizing<[u8; 32]>, kit: RecoveryKit) -> Arc<Self> {
        Arc::new(RecoveryKitHandle {
            kit: Mutex::new(kit),
            r,
        })
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl RecoveryKitHandle {
    /// A new kit with a fresh random `R`, bound to the account's genesis.
    /// Print `secret_r()` and `kit_tag()` for the user; put
    /// `recovery_key()` in the genesis or a `set_recovery_key`.
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn generate(account_id: String, genesis_hash: String) -> Result<Arc<Self>> {
        let mut r = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut *r);
        let kit = RecoveryKit::make(&r, &account_id, hash_of(&genesis_hash)?);
        Ok(Self::wrap(r, kit))
    }

    /// The kit for a known `R` (no tag check: a kit being made).
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn make(r: Vec<u8>, account_id: String, genesis_hash: String) -> Result<Arc<Self>> {
        let r = r32(&Zeroizing::new(r))?;
        let kit = RecoveryKit::make(&r, &account_id, hash_of(&genesis_hash)?);
        Ok(Self::wrap(r, kit))
    }

    /// A kit as typed or scanned: refused `kit_tag_mismatch` when the tag
    /// doesn't match ("damaged or mistyped").
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn read(
        r: Vec<u8>,
        account_id: String,
        genesis_hash: String,
        kit_tag: Vec<u8>,
    ) -> Result<Arc<Self>> {
        let r = r32(&Zeroizing::new(r))?;
        let kit = RecoveryKit::read(&r, &account_id, hash_of(&genesis_hash)?, &tag16(&kit_tag)?)?;
        Ok(Self::wrap(r, kit))
    }

    /// `R`, for printing the kit (secret).
    pub fn secret_r(&self) -> Vec<u8> {
        self.r.to_vec()
    }

    pub fn kit_tag(&self) -> Vec<u8> {
        self.kit().kit_tag().to_vec()
    }

    pub fn account_id(&self) -> String {
        self.kit().account_id().into()
    }

    pub fn genesis_hash(&self) -> String {
        self.kit().genesis_hash().to_hex()
    }

    /// The recovery key (Ed25519) the log names.
    pub fn recovery_key(&self) -> PublicKeyData {
        (&self.kit().recovery_key()).into()
    }

    /// The kit's X25519 public key (K backups are sealed to it).
    pub fn x25519_public(&self) -> Result<Vec<u8>> {
        Ok(kit_x25519_public(&self.kit().recovery_key())?.to_vec())
    }
}

fn envelope_info(envelope: &KBackupEnvelope) -> KBackupInfo {
    KBackupInfo {
        blob_version: envelope.blob_version,
        kids: envelope.kids.clone(),
        recovery_key: (&envelope.recovery_key).into(),
        backup_hash: envelope.backup_hash().to_hex(),
    }
}

fn account_keys(keys: Vec<BackupKey>) -> Vec<AccountKey> {
    keys.into_iter()
        .map(|k| AccountKey {
            kid: k.kid.clone(),
            k: k.k.to_vec(),
        })
        .collect()
}

/// Parses an `atem-k-backup-v2` envelope strictly.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn parse_k_backup(envelope_json: String) -> Result<KBackupInfo> {
    Ok(envelope_info(&KBackupEnvelope::parse(
        envelope_json.as_bytes(),
    )?))
}

/// Opens an envelope with the kit (a restore holds `R`). Secret output.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn open_k_backup(
    envelope_json: String,
    kit: Arc<RecoveryKitHandle>,
) -> Result<Vec<AccountKey>> {
    let envelope = KBackupEnvelope::parse(envelope_json.as_bytes())?;
    Ok(account_keys(envelope.open_with_kit(&kit.kit())?))
}

/// Seals `keys` (current first) to the kit named by `recovery_key` at
/// `blob_version` (the writer's `Seal` step). Returns the envelope's
/// canonical JSON.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn seal_k_backup(
    account_id: String,
    genesis_hash: String,
    blob_version: u64,
    recovery_key: PublicKeyData,
    keys: Vec<AccountKey>,
) -> Result<String> {
    let keys = keys
        .into_iter()
        .map(|AccountKey { kid, k }| {
            let k = Zeroizing::new(k);
            let bytes: [u8; 32] = k
                .as_slice()
                .try_into()
                .map_err(|_| AtemError::malformed("a K is 32 bytes"))?;
            Ok(BackupKey {
                kid,
                k: Zeroizing::new(bytes),
            })
        })
        .collect::<Result<Vec<BackupKey>>>()?;
    let envelope = KBackupEnvelope::seal(
        &account_id,
        hash_of(&genesis_hash)?,
        safe_int(blob_version, "blob_version")?,
        &recovery_key.to_key()?,
        &keys,
    )?;
    Ok(envelope.jcs())
}

/// A host's signed head for the restore.
fn host_accepts(pairs: &[HostAcceptPair]) -> Result<Vec<HostAccept>> {
    pairs
        .iter()
        .map(|p| {
            let init = atem_client::canonical::StrictValue::parse(p.init_json.as_bytes(), 1 << 16)
                .map_err(atem_client::Error::from)?;
            let accept =
                atem_client::canonical::StrictValue::parse(p.accept_json.as_bytes(), 1 << 16)
                    .map_err(atem_client::Error::from)?;
            HostAccept::from_messages(&init, &accept)
                .map_err(|e| AtemError::malformed(&format!("host accept: {e:?}")))
        })
        .collect()
}

fn host_accept(init_json: &str, accept_json: &str) -> Result<HostAccept> {
    host_accepts(&[HostAcceptPair {
        init_json: init_json.into(),
        accept_json: accept_json.into(),
    }])
    .map(|mut v| v.remove(0))
}

/// `th2` of a host's `init`/`accept` pair (hex).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn host_accept_th2(init_json: String, accept_json: String) -> Result<String> {
    Ok(host_accept(&init_json, &accept_json)?.th2().to_hex())
}

/// A host-signed head: `sig_h` over `th2` with the host key `log` records
/// for the `init`'s host and trust generation, and the `init`'s genesis is
/// the log's. Returns the head the host signed (never adopt it: fetch and
/// verify up to it).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn verify_host_accept(
    init_json: String,
    accept_json: String,
    log: Arc<MembershipLog>,
) -> Result<LogHead> {
    let head = host_accept(&init_json, &accept_json)?
        .verify(&log.lock())
        .map_err(|e| AtemError::Channel {
            code: "handshake_failed".into(),
            detail: format!("host head: {e:?}"),
        })?;
    Ok(head.head().into())
}

/// The Recovery Kit restore (§R9.5 "Restore", no recovery on a stale
/// head). Order of calls:
///
/// 1. `read(R, account, genesis, tag)` (nothing fetched on a mismatch);
/// 2. fetch the relay's log and newest envelope, reach at least one host
///    (`init`/`accept`: its signed head), `attempt(…)`. `no_host_reachable`
///    waits: show `user_notice()` and retry; `log_behind_host`: refetch.
///    Nothing is stored on a refusal;
/// 3. on success store the returned keys, then `enroll(member, now)`,
///    **persist `prepared_json()`**, send the `AppendRequest`, feed the
///    relay's answer to `append_stored`/`append_conflict`.
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct RestoreSession {
    inner: Mutex<RestoreFlow>,
}

impl RestoreSession {
    fn lock(&self) -> MutexGuard<'_, RestoreFlow> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl RestoreSession {
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn read(
        r: Vec<u8>,
        account_id: String,
        genesis_hash: String,
        kit_tag: Vec<u8>,
    ) -> Result<Arc<Self>> {
        let r = r32(&Zeroizing::new(r))?;
        let flow = RestoreFlow::read(&r, &account_id, hash_of(&genesis_hash)?, &tag16(&kit_tag)?)?;
        Ok(Arc::new(RestoreSession {
            inner: Mutex::new(flow),
        }))
    }

    /// After a restart with an enrollment in flight: the kit read again and
    /// the persisted `prepared_json()` (trusted local storage; read
    /// strictly and checked again). Run `attempt` again with a new fetch,
    /// then resend `outstanding()` and feed the relay's answer to
    /// `append_stored` / `append_conflict`; `enroll` refuses a new body while
    /// this one is outstanding.
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn resume(
        r: Vec<u8>,
        account_id: String,
        genesis_hash: String,
        kit_tag: Vec<u8>,
        prepared_json: String,
    ) -> Result<Arc<Self>> {
        let r = r32(&Zeroizing::new(r))?;
        let kit = RecoveryKit::read(&r, &account_id, hash_of(&genesis_hash)?, &tag16(&kit_tag)?)?;
        let prepared = prepared_from_json(&prepared_json)?;
        // The kit's own `recovery_add` on this account's chain.
        let body = &prepared.body;
        if body["action"] != "recovery_add"
            || body["signer"] != atem_client::membership::RECOVERY_SIGNER
            || body["account_id"].as_str() != Some(kit.account_id())
            || body["genesis_hash"].as_str() != Some(kit.genesis_hash().to_hex().as_str())
        {
            return Err(AtemError::malformed(
                "the prepared entry is not this kit's recovery_add",
            ));
        }
        Ok(Arc::new(RestoreSession {
            inner: Mutex::new(RestoreFlow::resume(kit, prepared)),
        }))
    }

    /// The signed `recovery_add` to send (and resend after an uncertain
    /// outcome). Returned at once, also right after `resume`; resend it
    /// only after `attempt` confirmed the log again (an early resend gains
    /// nothing: the relay's compare-and-set on `expected` refuses a moved
    /// head).
    pub fn outstanding(&self) -> Option<AppendRequest> {
        self.lock()
            .outstanding()
            .map(|(entry, head)| append_request(entry, head))
    }

    /// Steps 2–5 over what was fetched. Secret output (`keys`).
    pub fn attempt(
        &self,
        relay_entries: Vec<String>,
        envelope_json: String,
        host_accepts_: Vec<HostAcceptPair>,
        now: HostClock,
    ) -> Result<RestoredInfo> {
        let entries = entries_of(&relay_entries)?;
        let accepts = host_accepts(&host_accepts_)?;
        let now: HostNow = (&now).into();
        let mut flow = self.lock();
        let restored = flow.attempt(&entries, envelope_json.as_bytes(), &accepts, &now)?;
        Ok(RestoredInfo {
            head: restored.head.into(),
            keys: restored
                .keys
                .iter()
                .map(|k| AccountKey {
                    kid: k.kid.clone(),
                    k: k.k.to_vec(),
                })
                .collect(),
        })
    }

    /// The restored, host-confirmed log (after a successful `attempt`).
    pub fn log(&self) -> Option<Arc<MembershipLog>> {
        self.lock()
            .restored()
            .map(|r| MembershipLog::wrap(r.log.clone()))
    }

    pub fn k_stored(&self) -> bool {
        self.lock().k_stored()
    }

    /// Never while withheld or refused, nor until the recovery took effect.
    pub fn may_rotate_k(&self, device_id: String) -> bool {
        self.lock().may_rotate_k(&device_id)
    }

    pub fn may_seal_backup(&self, device_id: String) -> bool {
        self.lock().may_seal_backup(&device_id)
    }

    /// The hosts to tell the user about while waiting ("Recovery needs to
    /// reach one of your Atem hosts …"); none when not waiting.
    pub fn waiting_for_hosts(&self) -> Option<Vec<String>> {
        self.lock().user_notice().map(|n| match n {
            atem_client::restore::UserNotice::WaitingForHost { hosts } => hosts,
        })
    }

    pub fn refetch(&self) -> bool {
        self.lock().refetch()
    }

    pub fn last_error_code(&self) -> Option<String> {
        self.lock().last_error().map(|e| e.code().to_owned())
    }

    /// Step 6: prepares and signs (with the kit) the `recovery_add` for
    /// `member_json` on the confirmed head. Persist `prepared_json()`, then
    /// send the request.
    pub fn enroll(&self, member_json: String, signed_at: u64) -> Result<AppendRequest> {
        let log = self.log().ok_or_else(|| AtemError::state("not restored"))?;
        let member = log.parse_member(&member_json)?;
        let signed_at = safe_int(signed_at, "signed_at")?;
        let (entry, head) = self.lock().enroll(member, signed_at)?;
        Ok(append_request(&entry, head))
    }

    pub fn prepared_json(&self) -> Option<String> {
        self.lock().prepared().map(prepared_json)
    }

    pub fn append_stored(&self, now: HostClock) -> Result<EnrollmentOutcome> {
        let outcome = self
            .lock()
            .append_reply(AppendReply::Stored, &(&now).into())?;
        Ok(enrollment(outcome))
    }

    pub fn append_conflict(
        &self,
        head: LogHead,
        entries: Vec<String>,
        more: bool,
        now: HostClock,
    ) -> Result<EnrollmentOutcome> {
        let reply = conflict_reply(head, &entries, more)?;
        let outcome = self.lock().append_reply(reply, &(&now).into())?;
        Ok(enrollment(outcome))
    }
}

fn enrollment(e: Enrollment) -> EnrollmentOutcome {
    match e {
        Enrollment::Published { head } => EnrollmentOutcome::Published { head: head.into() },
        Enrollment::Rebuild => EnrollmentOutcome::Rebuild,
        Enrollment::Stopped(p) => EnrollmentOutcome::Stopped {
            detail: format!("{p:?}"),
        },
    }
}
