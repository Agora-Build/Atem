//! Publishing entries with the relay's compare-and-swap (§R9.4 client rules
//! 1–5) and writing K backups (§R9.5), sans-I/O: the app sends the
//! requests, feeds the relay's answers back and persists the durable state
//! (`prepared_json`) in trusted local storage after every call.
//!
//! No binding lock is held while the app's provider signs: the state is
//! copied under the lock, signed without it, and put back only if nothing
//! moved meanwhile (else `AtemError::State`).
//!
//! One outstanding append per device (rule 5): within the process, a second
//! publisher or writer for the same account and signer is refused
//! (`Publish{code: outstanding}`) while one holds a prepared body. Across a
//! restart the app must `resume` its persisted state instead of starting a
//! new write.
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, MutexGuard};

use atem_client::backup::KBackupEnvelope;
use atem_client::backup_writer::{BackupError, BackupJob, BackupWriter, PutReply, Step};
use atem_client::membership::publish::{AppendReply, Prepared, Published, Publisher};
use atem_client::membership::{Entry, HostNow};
use atem_client::provider::{KeyId, KeyProvider};

use crate::encoding::{canonical_lossy, safe_int, strict};
use crate::error::{AtemError, Result};
use crate::kit::RecoveryKitHandle;
use crate::log::{MembershipLog, object_json, objects_of, structural_entry};
use crate::types::{AppendRequest, BackupStep, HostClock, LogHead, PublicKeyData, PublishOutcome};

// ----------------------------------------------- one append per device

static IN_FLIGHT: Mutex<BTreeSet<(String, String)>> = Mutex::new(BTreeSet::new());

/// A device's claim on its one outstanding append, released on drop.
#[derive(Debug)]
struct Claim((String, String));

impl Claim {
    fn take(account_id: &str, signer: &str) -> Result<Claim> {
        let key = (account_id.to_owned(), signer.to_owned());
        let mut set = IN_FLIGHT.lock().unwrap_or_else(|e| e.into_inner());
        if !set.insert(key.clone()) {
            return Err(AtemError::Publish {
                code: "outstanding".into(),
                detail: format!("{signer} already has an append in flight in this process"),
            });
        }
        Ok(Claim(key))
    }
}

impl Drop for Claim {
    fn drop(&mut self) {
        IN_FLIGHT
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.0);
    }
}

fn body_owner(body: &serde_json::Value) -> Result<(String, String)> {
    match (body["account_id"].as_str(), body["signer"].as_str()) {
        (Some(a), Some(s)) => Ok((a.to_owned(), s.to_owned())),
        _ => Err(AtemError::malformed("a body names its account and signer")),
    }
}

/// Keeps the claim in step with whether a body is prepared.
fn sync_claim(claim: &mut Option<Claim>, prepared: Option<&Prepared>) -> Result<()> {
    match prepared {
        Some(p) if claim.is_none() => {
            let (account, signer) = body_owner(&p.body)?;
            *claim = Some(Claim::take(&account, &signer)?);
        }
        None => *claim = None,
        _ => {}
    }
    Ok(())
}

fn moved() -> AtemError {
    AtemError::state("the object changed while the provider was signing")
}

// ------------------------------------------------------------ helpers

pub(crate) fn append_request(
    entry: &Entry,
    expected: atem_client::membership::Head,
) -> AppendRequest {
    AppendRequest {
        entry_json: object_json(entry.object()),
        entry_hash: entry.hash().to_hex(),
        expected: expected.into(),
    }
}

pub(crate) fn prepared_json(prepared: &Prepared) -> String {
    canonical_lossy(&prepared.to_json())
}

/// Reads a persisted `prepared_json()`: exact fields, a signed entry that is
/// the stored body, and the body checked again with the verifier's schema.
pub(crate) fn prepared_from_json(json: &str) -> Result<Prepared> {
    let prepared =
        Prepared::from_json(&strict(json)?).map_err(|r| AtemError::membership(&r, None))?;
    structural_entry(&prepared.body)?;
    Ok(prepared)
}

pub(crate) fn conflict_reply(head: LogHead, entries: &[String], more: bool) -> Result<AppendReply> {
    Ok(AppendReply::Conflict {
        head: head.to_head()?,
        entries: objects_of(entries)?,
        more,
    })
}

pub(crate) fn outcome(published: Published) -> PublishOutcome {
    match published {
        Published::Committed(head) => PublishOutcome::Committed { head: head.into() },
        Published::StoredPending { head, on } => PublishOutcome::StoredPending {
            head: head.into(),
            on: on.to_hex(),
        },
        Published::LostRace { head, .. } => PublishOutcome::LostRace { head: head.into() },
        Published::FetchMore { after, .. } => PublishOutcome::FetchMore { after },
        Published::Diverged { .. } => PublishOutcome::Diverged,
        Published::Waiting { on, .. } => PublishOutcome::Waiting { on: on.to_hex() },
        Published::RelayInconsistent { head, .. } => {
            PublishOutcome::RelayInconsistent { head: head.into() }
        }
        Published::RelayInvalid { index, reason, .. } => PublishOutcome::RelayInvalid {
            index: index as u64,
            code: reason.code().into(),
        },
    }
}

// ----------------------------------------------------- EntryPublisher

struct PublisherState {
    publisher: Publisher,
    claim: Option<Claim>,
}

/// One device's appends (at most one in flight). Order of calls:
///
/// 1. `prepare(log, body)`, then **persist `prepared_json()`** (rule 1:
///    the body is stored before the key signs it);
/// 2. `sign(provider, key)` (a fresh owner confirmation of that body),
///    then persist `prepared_json()` again;
/// 3. send the `AppendRequest`; on an uncertain outcome resend the same
///    request (`outstanding()`);
/// 4. `reply_stored(log)` / `reply_conflict(log, …)`; persist
///    `prepared_json()` (now none).
///
/// After a restart: `resume(saved)`, then `outstanding()` (resend) or
/// `sign` again (a lost signature is re-made over the same body).
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct EntryPublisher {
    inner: Mutex<PublisherState>,
}

impl EntryPublisher {
    fn lock(&self) -> MutexGuard<'_, PublisherState> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(crate) fn sign_with(
        &self,
        provider: &dyn KeyProvider,
        key_id: &str,
        cosign_kit: Option<&RecoveryKitHandle>,
    ) -> Result<AppendRequest> {
        // Copy under the lock, sign without it, put back if unchanged.
        let before = self.lock().publisher.clone();
        let mut work = before.clone();
        let key = KeyId::new(key_id);
        match cosign_kit.map(RecoveryKitHandle::fresh) {
            Some(kit) => {
                work.sign(
                    provider,
                    &key,
                    Some((&kit, &atem_client::kit::RecoveryKit::sign_id())),
                )?;
            }
            None => {
                work.sign(provider, &key, None)?;
            }
        }
        let mut state = self.lock();
        if state.publisher != before {
            return Err(moved());
        }
        let (entry, expected) = work.outstanding().expect("just signed");
        let request = append_request(entry, expected);
        state.publisher = work;
        Ok(request)
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl EntryPublisher {
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn new() -> Arc<Self> {
        Arc::new(EntryPublisher {
            inner: Mutex::new(PublisherState {
                publisher: Publisher::new(),
                claim: None,
            }),
        })
    }

    /// Resumes from the persisted `prepared_json()` (trusted local storage;
    /// read strictly and checked again with the verifier's schema).
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn resume(prepared_json: String) -> Result<Arc<Self>> {
        let prepared = prepared_from_json(&prepared_json)?;
        let mut claim = None;
        sync_claim(&mut claim, Some(&prepared))?;
        Ok(Arc::new(EntryPublisher {
            inner: Mutex::new(PublisherState {
                publisher: Publisher::resume(Some(prepared)),
                claim,
            }),
        }))
    }

    /// Rule 1: stores `body_json` (from `MembershipLog::draft_entry`),
    /// which must chain from `log`'s head.
    pub fn prepare(&self, log: Arc<MembershipLog>, body_json: String) -> Result<()> {
        let body = strict(&body_json)?;
        structural_entry(&body)?;
        let head_log = log.lock().clone();
        let mut state = self.lock();
        let mut work = state.publisher.clone();
        work.prepare(&head_log, body)?;
        sync_claim(&mut state.claim, work.prepared())?;
        state.publisher = work;
        Ok(())
    }

    /// The durable state to persist after every call (none when idle).
    pub fn prepared_json(&self) -> Option<String> {
        self.lock().publisher.prepared().map(prepared_json)
    }

    /// What to send (and resend after an uncertain outcome).
    pub fn outstanding(&self) -> Option<AppendRequest> {
        self.lock()
            .publisher
            .outstanding()
            .map(|(entry, expected)| append_request(entry, expected))
    }

    /// The relay answered `200`.
    pub fn reply_stored(&self, log: Arc<MembershipLog>, now: HostClock) -> Result<PublishOutcome> {
        let now: HostNow = (&now).into();
        let mut state = self.lock();
        let published = state
            .publisher
            .reply(AppendReply::Stored, &mut log.lock(), &now)?;
        let _ = sync_claim(&mut state.claim, None);
        Ok(outcome(published))
    }

    /// The relay answered `409 {head, entries, more}`.
    pub fn reply_conflict(
        &self,
        log: Arc<MembershipLog>,
        head: LogHead,
        entries: Vec<String>,
        more: bool,
        now: HostClock,
    ) -> Result<PublishOutcome> {
        let reply = conflict_reply(head, &entries, more)?;
        let now: HostNow = (&now).into();
        let mut state = self.lock();
        let published = state.publisher.reply(reply, &mut log.lock(), &now)?;
        let _ = sync_claim(&mut state.claim, None);
        Ok(outcome(published))
    }
}

#[cfg(feature = "uniffi")]
#[uniffi::export]
impl EntryPublisher {
    /// Rule 1's second half: the signer's key signs the stored body (purpose
    /// from the body's action). `cosign_kit`: the current kit for a
    /// `set_recovery_key` with `kit: "current"`. No binding lock is held
    /// while the provider signs.
    pub fn sign(
        &self,
        provider: Arc<dyn crate::provider::AppKeyProvider>,
        key_id: String,
        cosign_kit: Option<Arc<RecoveryKitHandle>>,
    ) -> Result<AppendRequest> {
        self.sign_with(
            &crate::provider::Platform(provider),
            &key_id,
            cosign_kit.as_deref(),
        )
    }
}

// ------------------------------------------------------- KBackupWriter

fn step_info(step: Step) -> BackupStep {
    match step {
        Step::Seal { blob_version } => BackupStep::Seal { blob_version },
        Step::Sign { body } => BackupStep::Sign {
            body_json: canonical_lossy(&body),
        },
        Step::Put {
            blob_version,
            bytes,
        } => BackupStep::Put {
            blob_version,
            bytes,
        },
        Step::Append { entry, expected } => BackupStep::Append {
            request: AppendRequest {
                entry_json: object_json(&entry),
                entry_hash: entry.entry_hash().map(|h| h.to_hex()).unwrap_or_default(),
                expected: expected.into(),
            },
        },
        Step::Fetch { after } => BackupStep::Fetch { after },
        Step::Done { committed } => BackupStep::Done { committed },
        Step::Failed(error) => {
            let code = match &error {
                BackupError::RelayMisbehaviour { .. } => "relay_misbehaviour",
                BackupError::WrongEnvelope => "wrong_envelope",
                BackupError::RelayInvalid => "relay_invalid",
                BackupError::Diverged => "diverged",
                BackupError::Sign(_) => "sign",
                BackupError::Waiting { .. } => "waiting",
                BackupError::RelayInconsistent => "relay_inconsistent",
                BackupError::UnexpectedReply => "unexpected_reply",
            };
            BackupStep::Failed {
                code: code.into(),
                detail: format!("{error:?}"),
            }
        }
    }
}

struct WriterState {
    writer: BackupWriter,
    step: Step,
    account_id: String,
    claim: Option<Claim>,
}

impl WriterState {
    /// Applies a call's result: the step, and the claim on the device's one
    /// append (held while a body is prepared).
    fn apply(&mut self, writer: BackupWriter, step: Step) -> Result<BackupStep> {
        // In flight: a prepared body and a phase that isn't Done or Failed.
        let in_flight = writer.prepared().is_some() && writer.to_json().is_some();
        if in_flight && self.claim.is_none() {
            self.claim = Some(Claim::take(&self.account_id, &writer.job().signer)?);
        } else if !in_flight {
            self.claim = None;
        }
        self.writer = writer;
        self.step = step.clone();
        Ok(step_info(step))
    }
}

/// A K backup (§R9.5 "Writing a backup"): allocate a version, seal (the app
/// holds `K`: `seal_k_backup`), sign the `k_backup` entry, upload
/// put-if-absent, append with the CAS, and the `409` paths of both. Each
/// call returns the next [`BackupStep`].
///
/// Durability (step 2, rules 1 and 4): **persist `prepared_json()` after
/// every call, before performing the returned step** (it holds the job, the
/// envelope and its version, the uploaded versions, the prepared entry).
/// After a restart, `KBackupWriter::resume(saved)` stands at the same step
/// and signs the same body again, never a sibling; don't `start` a new
/// backup while a saved one exists.
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct KBackupWriter {
    inner: Mutex<WriterState>,
}

impl KBackupWriter {
    fn lock(&self) -> MutexGuard<'_, WriterState> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Runs `f` on a copy of the writer and applies the result.
    fn update(&self, f: impl FnOnce(&mut BackupWriter) -> Step) -> Result<BackupStep> {
        let mut state = self.lock();
        let mut work = state.writer.clone();
        let step = f(&mut work);
        state.apply(work, step)
    }

    pub(crate) fn sign_with(&self, provider: &dyn KeyProvider, key_id: &str) -> Result<BackupStep> {
        let before = self.lock().writer.clone();
        let mut work = before.clone();
        let step = work.sign(provider, &KeyId::new(key_id));
        let mut state = self.lock();
        if state.writer != before {
            return Err(moved());
        }
        state.apply(work, step)
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl KBackupWriter {
    /// Backs up `kids` (current first) to the kit `kit_recovery_key`, as the
    /// manager `signer`.
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn start(
        log: Arc<MembershipLog>,
        kids: Vec<String>,
        kit_recovery_key: PublicKeyData,
        signer: String,
    ) -> Result<Arc<Self>> {
        let job = BackupJob {
            kids,
            kit: kit_recovery_key.to_key()?,
            signer,
        };
        let log = log.lock();
        let account_id = log.account_id().to_owned();
        let (writer, step) = BackupWriter::start(&log, job);
        Ok(Arc::new(KBackupWriter {
            inner: Mutex::new(WriterState {
                writer,
                step,
                account_id,
                claim: None,
            }),
        }))
    }

    /// A writer resumed from its persisted `prepared_json()` (trusted local
    /// storage; read strictly, the prepared body checked again): it stands
    /// at the step it was at (`step()`).
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn resume(saved_json: String) -> Result<Arc<Self>> {
        let value = strict(&saved_json)?;
        let (writer, step) =
            BackupWriter::from_json(&value).map_err(|r| AtemError::membership(&r, None))?;
        let account_id = match writer.prepared() {
            Some(p) => {
                structural_entry(&p.body)?;
                body_owner(&p.body)?.0
            }
            None => writer
                .envelope()
                .map(|e| e.account_id.clone())
                .unwrap_or_default(),
        };
        let mut state = WriterState {
            writer: writer.clone(),
            step: step.clone(),
            account_id,
            claim: None,
        };
        state.apply(writer, step)?;
        Ok(Arc::new(KBackupWriter {
            inner: Mutex::new(state),
        }))
    }

    /// The durable state to persist after every call (none once nothing is
    /// in flight: `Done`, `Failed`).
    pub fn prepared_json(&self) -> Option<String> {
        self.lock().writer.to_json().map(|v| canonical_lossy(&v))
    }

    /// The current step (what to do now).
    pub fn step(&self) -> BackupStep {
        step_info(self.lock().step.clone())
    }

    /// The app sealed the asked version (`seal_k_backup`): stores it and
    /// drafts the entry. Next: `Sign`.
    pub fn sealed(
        &self,
        log: Arc<MembershipLog>,
        envelope_json: String,
        signed_at: u64,
    ) -> Result<BackupStep> {
        let signed_at = safe_int(signed_at, "signed_at")?;
        let envelope = KBackupEnvelope::parse(envelope_json.as_bytes())?;
        let log = log.lock().clone();
        self.update(|w| w.sealed(&log, envelope, signed_at))
    }

    /// The upload's answer: `200` (`max_occupied` none) or `409
    /// {max_occupied}`.
    pub fn put_reply(
        &self,
        log: Arc<MembershipLog>,
        max_occupied: Option<u64>,
    ) -> Result<BackupStep> {
        let reply = match max_occupied {
            None => PutReply::Stored,
            Some(max_occupied) => PutReply::Occupied { max_occupied },
        };
        let log = log.lock().clone();
        self.update(|w| w.put_reply(&log, reply))
    }

    /// The append's answer: `200`.
    pub fn append_stored(
        &self,
        log: Arc<MembershipLog>,
        now: HostClock,
        signed_at: u64,
    ) -> Result<BackupStep> {
        let signed_at = safe_int(signed_at, "signed_at")?;
        let now: HostNow = (&now).into();
        let mut state = self.lock();
        let mut work = state.writer.clone();
        let step = work.append_reply(&mut log.lock(), AppendReply::Stored, &now, signed_at);
        state.apply(work, step)
    }

    /// The append's answer: `409 {head, entries, more}`.
    pub fn append_conflict(
        &self,
        log: Arc<MembershipLog>,
        head: LogHead,
        entries: Vec<String>,
        more: bool,
        now: HostClock,
        signed_at: u64,
    ) -> Result<BackupStep> {
        let signed_at = safe_int(signed_at, "signed_at")?;
        let reply = conflict_reply(head, &entries, more)?;
        let now: HostNow = (&now).into();
        let mut state = self.lock();
        let mut work = state.writer.clone();
        let step = work.append_reply(&mut log.lock(), reply, &now, signed_at);
        state.apply(work, step)
    }

    /// The entries fetched after a `Fetch` step.
    pub fn fetched(
        &self,
        log: Arc<MembershipLog>,
        entries: Vec<String>,
        more: bool,
        now: HostClock,
        signed_at: u64,
    ) -> Result<BackupStep> {
        let signed_at = safe_int(signed_at, "signed_at")?;
        let objects = objects_of(&entries)?;
        let now: HostNow = (&now).into();
        let mut state = self.lock();
        let mut work = state.writer.clone();
        let step = work.fetched(&mut log.lock(), &objects, more, &now, signed_at);
        state.apply(work, step)
    }

    /// After an uncertain outcome: resend the upload, then the entry.
    pub fn restart(&self) -> Result<BackupStep> {
        self.update(|w| w.restart())
    }
}

#[cfg(feature = "uniffi")]
#[uniffi::export]
impl KBackupWriter {
    /// The manager's key signs the stored `k_backup` body (purpose
    /// `KeyBackup`). No binding lock is held while the provider signs.
    pub fn sign(
        &self,
        provider: Arc<dyn crate::provider::AppKeyProvider>,
        key_id: String,
    ) -> Result<BackupStep> {
        self.sign_with(&crate::provider::Platform(provider), &key_id)
    }
}
