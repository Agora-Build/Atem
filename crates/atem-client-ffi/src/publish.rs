//! Publishing entries with the relay's compare-and-swap (§R9.4 client rules
//! 1–5) and writing K backups (§R9.5), sans-I/O: the app sends the
//! requests, feeds the relay's answers back and persists the durable state
//! where the doc says so.
use std::sync::{Arc, Mutex, MutexGuard};

use atem_client::backup::KBackupEnvelope;
use atem_client::backup_writer::{BackupError, BackupJob, BackupWriter, PutReply, Step};
use atem_client::membership::publish::{AppendReply, Prepared, Published, Publisher};
use atem_client::membership::{Entry, HostNow};
use atem_client::provider::{KeyId, KeyProvider};

use crate::encoding::{canonical, strict};
use crate::error::{AtemError, Result};
use crate::kit::RecoveryKitHandle;
use crate::log::{MembershipLog, object_json, objects_of};
use crate::types::{AppendRequest, BackupStep, HostClock, LogHead, PublicKeyData, PublishOutcome};

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
    canonical(&serde_json::json!({
        "body": prepared.body,
        "expected": prepared.expected.to_json(),
        "signed": prepared.signed.as_ref().map(|e| e.object().to_json()),
    }))
}

pub(crate) fn prepared_from_json(json: &str) -> Result<Prepared> {
    let value = strict(json)?;
    let o = value
        .as_object()
        .filter(|o| o.len() == 3)
        .ok_or(AtemError::malformed("prepared state"))?;
    let expected = atem_client::membership::Head::from_json(&o["expected"])
        .ok_or(AtemError::malformed("prepared expected head"))?;
    let signed = match &o["signed"] {
        serde_json::Value::Null => None,
        v => Some(
            Entry::parse_bytes(canonical(v).as_bytes())
                .map_err(|r| AtemError::membership(&r, None))?,
        ),
    };
    if let Some(entry) = &signed
        && *entry.object().body() != o["body"]
    {
        return Err(AtemError::malformed(
            "the signed entry is not the prepared body",
        ));
    }
    Ok(Prepared {
        body: o["body"].clone(),
        expected,
        signed,
    })
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
    inner: Mutex<Publisher>,
}

impl EntryPublisher {
    fn lock(&self) -> MutexGuard<'_, Publisher> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(crate) fn sign_with(
        &self,
        provider: &dyn KeyProvider,
        key_id: &str,
        cosign_kit: Option<&RecoveryKitHandle>,
    ) -> Result<AppendRequest> {
        let mut publisher = self.lock();
        match cosign_kit {
            Some(kit) => {
                let kit = kit.kit();
                publisher.sign(
                    provider,
                    &KeyId::new(key_id),
                    Some((&*kit, &atem_client::kit::RecoveryKit::sign_id())),
                )?;
            }
            None => {
                publisher.sign(provider, &KeyId::new(key_id), None)?;
            }
        }
        let (entry, expected) = publisher.outstanding().expect("just signed");
        Ok(append_request(entry, expected))
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl EntryPublisher {
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn new() -> Arc<Self> {
        Arc::new(EntryPublisher {
            inner: Mutex::new(Publisher::new()),
        })
    }

    /// Resumes from the persisted `prepared_json()`.
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn resume(prepared_json: String) -> Result<Arc<Self>> {
        Ok(Arc::new(EntryPublisher {
            inner: Mutex::new(Publisher::resume(Some(prepared_from_json(&prepared_json)?))),
        }))
    }

    /// Rule 1: stores `body_json` (from `MembershipLog::draft_entry`),
    /// which must chain from `log`'s head.
    pub fn prepare(&self, log: Arc<MembershipLog>, body_json: String) -> Result<()> {
        let body = strict(&body_json)?;
        crate::log::structural_entry(&body)?;
        Ok(self.lock().prepare(&log.lock(), body)?)
    }

    /// The durable state to persist after every call (none when idle).
    pub fn prepared_json(&self) -> Option<String> {
        self.lock().prepared().map(prepared_json)
    }

    /// What to send (and resend after an uncertain outcome).
    pub fn outstanding(&self) -> Option<AppendRequest> {
        self.lock()
            .outstanding()
            .map(|(entry, expected)| append_request(entry, expected))
    }

    /// The relay answered `200`.
    pub fn reply_stored(&self, log: Arc<MembershipLog>, now: HostClock) -> Result<PublishOutcome> {
        let now: HostNow = (&now).into();
        let published = self
            .lock()
            .reply(AppendReply::Stored, &mut log.lock(), &now)?;
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
        let published = self.lock().reply(reply, &mut log.lock(), &now)?;
        Ok(outcome(published))
    }
}

#[cfg(feature = "uniffi")]
#[uniffi::export]
impl EntryPublisher {
    /// Rule 1's second half: the signer's key signs the stored body (purpose
    /// from the body's action). `cosign_kit`: the current kit for a
    /// `set_recovery_key` with `kit: "current"`.
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

fn step_info(step: Step) -> BackupStep {
    match step {
        Step::Seal { blob_version } => BackupStep::Seal { blob_version },
        Step::Sign { body } => BackupStep::Sign {
            body_json: canonical(&body),
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

/// A K backup (§R9.5 "Writing a backup"): allocate a version, seal (the app
/// holds `K`: `seal_k_backup`), sign the `k_backup` entry, upload
/// put-if-absent, append with the CAS, and the `409` paths of both. Each
/// call returns the next [`BackupStep`].
///
/// Durability: the writer lives in memory. After a restart, fetch and
/// extend the log, then `start` again: a committed backup ends at `Done`;
/// an upload this writer made but never committed is occupied at the relay
/// and the new allocation moves above it after one `409` (decision recorded
/// in the bindings doc).
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct KBackupWriter {
    inner: Mutex<(BackupWriter, Step)>,
}

impl KBackupWriter {
    fn lock(&self) -> MutexGuard<'_, (BackupWriter, Step)> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn set(&self, guard: &mut (BackupWriter, Step), step: Step) -> BackupStep {
        guard.1 = step.clone();
        step_info(step)
    }

    pub(crate) fn sign_with(&self, provider: &dyn KeyProvider, key_id: &str) -> BackupStep {
        let mut g = self.lock();
        let step = g.0.sign(provider, &KeyId::new(key_id));
        self.set(&mut g, step)
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
        let (writer, step) = BackupWriter::start(&log.lock(), job);
        Ok(Arc::new(KBackupWriter {
            inner: Mutex::new((writer, step)),
        }))
    }

    /// The current step (what to do now).
    pub fn step(&self) -> BackupStep {
        step_info(self.lock().1.clone())
    }

    /// The app sealed the asked version (`seal_k_backup`): stores it and
    /// drafts the entry. Next: `Sign`.
    pub fn sealed(
        &self,
        log: Arc<MembershipLog>,
        envelope_json: String,
        signed_at: u64,
    ) -> Result<BackupStep> {
        let envelope = KBackupEnvelope::parse(envelope_json.as_bytes())?;
        let mut g = self.lock();
        let step = g.0.sealed(&log.lock(), envelope, signed_at);
        Ok(self.set(&mut g, step))
    }

    /// The upload's answer: `200` (`max_occupied` none) or `409
    /// {max_occupied}`.
    pub fn put_reply(&self, log: Arc<MembershipLog>, max_occupied: Option<u64>) -> BackupStep {
        let reply = match max_occupied {
            None => PutReply::Stored,
            Some(max_occupied) => PutReply::Occupied { max_occupied },
        };
        let mut g = self.lock();
        let step = g.0.put_reply(&log.lock(), reply);
        self.set(&mut g, step)
    }

    /// The append's answer: `200`.
    pub fn append_stored(
        &self,
        log: Arc<MembershipLog>,
        now: HostClock,
        signed_at: u64,
    ) -> BackupStep {
        let mut g = self.lock();
        let step = g.0.append_reply(
            &mut log.lock(),
            AppendReply::Stored,
            &(&now).into(),
            signed_at,
        );
        self.set(&mut g, step)
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
        let reply = conflict_reply(head, &entries, more)?;
        let mut g = self.lock();
        let step =
            g.0.append_reply(&mut log.lock(), reply, &(&now).into(), signed_at);
        Ok(self.set(&mut g, step))
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
        let objects = objects_of(&entries)?;
        let mut g = self.lock();
        let step =
            g.0.fetched(&mut log.lock(), &objects, more, &(&now).into(), signed_at);
        Ok(self.set(&mut g, step))
    }

    /// After an uncertain outcome: resend the upload, then the entry.
    pub fn restart(&self) -> BackupStep {
        let mut g = self.lock();
        let step = g.0.restart();
        self.set(&mut g, step)
    }
}

#[cfg(feature = "uniffi")]
#[uniffi::export]
impl KBackupWriter {
    /// The manager's key signs the stored `k_backup` body (purpose
    /// `KeyBackup`).
    pub fn sign(
        &self,
        provider: Arc<dyn crate::provider::AppKeyProvider>,
        key_id: String,
    ) -> BackupStep {
        self.sign_with(&crate::provider::Platform(provider), &key_id)
    }
}
