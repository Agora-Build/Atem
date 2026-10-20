//! Writing a K backup (§R9.5 "Writing a backup"), sans-I/O: allocate a
//! version, seal, upload (put-if-absent), publish the `k_backup` entry with
//! the log's CAS, and the `409` paths of both.
//!
//! The caller performs each [`Step`] and feeds the answer back; the writer
//! never sees `K` (the caller seals: the cred agent or Astation holds it)
//! and holds nothing that a restart loses: [`BackupWriter`] is the durable
//! state (store it after every call).
//!
//! - **Allocate:** `blob_version` = 1 + the highest of the newest committed
//!   version in the verified log, every version this writer uploaded and
//!   hasn't committed or discarded, and the `max_occupied` of the last
//!   `409` for this log. So each `409` moves the next attempt strictly
//!   higher; a `max_occupied` more than 1024 above the newest committed
//!   version is relay misbehaviour (stop and report).
//! - A version is **committed** only once a `k_backup` entry in the log
//!   names it; anything else the relay holds is occupied but uncommitted
//!   and never trusted.
use std::collections::BTreeSet;

use serde_json::Value;

use crate::backup::KBackupEnvelope;
use crate::encoding::Hash32;
use crate::keys::PublicKey;
use crate::membership::publish::{AppendReply, Prepared, Published, Publisher};
use crate::membership::{
    Action, Conflict, Head, HostNow, Invalid, KBackupRecord, Membership, Stop,
};
use crate::provider::{KeyId, KeyProvider};
use crate::signed::SignedObject;

/// A `max_occupied` more than this above the newest committed version is
/// relay misbehaviour.
pub const MAX_VERSION_SKIP: u64 = 1024;

/// What to back up: the `K` sequence (current kid first) for a kit, by a
/// manager.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupJob {
    pub kids: Vec<String>,
    /// The kit's recovery key (current or pending).
    pub kit: PublicKey,
    /// The manager's device id (the entry's `signer`).
    pub signer: String,
}

/// The relay's answer to an envelope upload (put-if-absent).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutReply {
    /// `200`: stored, or the same bytes were already there.
    Stored,
    /// `409 {max_occupied}`: other bytes hold that version.
    Occupied { max_occupied: u64 },
}

/// The next thing the caller does.
#[derive(Debug, Clone, PartialEq)]
pub enum Step {
    /// Seal the job's keys to its kit at this version
    /// (`KBackupEnvelope::seal`) and pass it to [`BackupWriter::sealed`].
    Seal { blob_version: u64 },
    /// Store the writer (it now holds this exact body: §R9.4 rule 1), then
    /// have the manager's key sign it with [`BackupWriter::sign`].
    Sign { body: Value },
    /// Upload these envelope bytes (put-if-absent at this version).
    Put { blob_version: u64, bytes: String },
    /// Append this entry with the log CAS (`expected` = the head it chains
    /// from).
    Append { entry: SignedObject, expected: Head },
    /// The `409` said `more`: fetch `…/entries?after=<after>` and pass them to
    /// [`BackupWriter::fetched`].
    Fetch { after: u64 },
    /// The log's newest committed backup covers the job.
    Done { committed: u64 },
    /// Stopped; nothing more is sent.
    Failed(BackupError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackupError {
    /// A `409` reported `max_occupied` more than 1024 above the newest
    /// committed version.
    RelayMisbehaviour { max_occupied: u64, committed: u64 },
    /// The envelope handed to `sealed` isn't the one asked for.
    WrongEnvelope,
    /// The relay returned entries that don't verify, or showed two histories.
    RelayInvalid,
    /// The relay showed conflicting signed history: stop signing.
    Diverged,
    /// Signing the entry failed.
    Sign(Invalid),
    /// The relay's log goes beyond an entry still pending on this device's
    /// clock: wait for it, then start again.
    Waiting { on: Hash32 },
    /// The relay's `409` didn't move the verified log to the head it
    /// reported: try again later.
    RelayInconsistent,
    /// An answer that doesn't fit the current step.
    UnexpectedReply,
}

/// What was discarded durably: an envelope, and an entry that was sent and
/// can never be named (a `k_backup` naming a version ≥ ours won the CAS).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Discarded {
    Envelope {
        blob_version: u64,
        backup_hash: Hash32,
    },
    Entry {
        entry_hash: Hash32,
    },
}

#[derive(Debug, Clone, PartialEq)]
enum Phase {
    Seal {
        blob_version: u64,
    },
    /// The body is stored; next the signature, then the upload (a new
    /// envelope) or the append (an entry rebuilt on a new head).
    Sign {
        then_upload: bool,
    },
    Upload,
    Publish,
    Fetch {
        after: u64,
        lost: Option<Hash32>,
    },
    Done {
        committed: u64,
    },
    Failed(BackupError),
}

/// The writer's durable state.
#[derive(Debug, Clone, PartialEq)]
pub struct BackupWriter {
    job: BackupJob,
    phase: Phase,
    envelope: Option<KBackupEnvelope>,
    /// Versions uploaded and not yet committed or discarded.
    uploaded: BTreeSet<u64>,
    last_max_occupied: Option<u64>,
    publisher: Publisher,
    discarded: Vec<Discarded>,
}

impl BackupWriter {
    /// Starts a backup on the writer's verified log: the first allocation.
    pub fn start(log: &Membership, job: BackupJob) -> (BackupWriter, Step) {
        let mut writer = BackupWriter {
            job,
            phase: Phase::Done { committed: 0 },
            envelope: None,
            uploaded: BTreeSet::new(),
            last_max_occupied: None,
            publisher: Publisher::new(),
            discarded: Vec::new(),
        };
        let step = writer.allocate(log);
        (writer, step)
    }

    pub fn job(&self) -> &BackupJob {
        &self.job
    }

    /// Everything discarded so far, in order.
    pub fn discarded(&self) -> &[Discarded] {
        &self.discarded
    }

    pub fn envelope(&self) -> Option<&KBackupEnvelope> {
        self.envelope.as_ref()
    }

    /// The version of the newest committed backup in `log` (0: none).
    pub fn committed(log: &Membership) -> u64 {
        log.k_backup().map_or(0, |r| r.blob_version)
    }

    /// The log's newest committed backup covers this `K` sequence and the
    /// current kit: nothing more to write.
    pub fn covers(log: &Membership, kids: &[String]) -> bool {
        log.k_backup()
            .is_some_and(|r| r.kids == kids && r.recovery_key == *log.recovery_key())
    }

    /// The new `K`'s current kid may be used: a committed `k_backup` in the
    /// log names it first (§R9.5 step 4, "before first use").
    pub fn may_use_k(log: &Membership, kid: &str) -> bool {
        log.k_backup()
            .is_some_and(|r| r.kids.first().map(String::as_str) == Some(kid))
    }

    /// After a restart (§R9.5 step 6): resend the stored bytes in order, the
    /// upload (idempotent) and then the entry (CAS). A `409` on the resent
    /// upload means the relay collected the envelope and another writer took
    /// the version: allocation goes on above it.
    pub fn restart(&mut self) -> Step {
        // A body stored without its signature is signed again (same body,
        // same entry_hash); that is `Phase::Sign`, resumed as is.
        if self.phase == Phase::Publish && self.envelope.is_some() {
            self.phase = Phase::Upload;
        }
        self.resume()
    }

    /// The current step (to send again, e.g. after a timeout).
    pub fn resume(&self) -> Step {
        match &self.phase {
            Phase::Seal { blob_version } => Step::Seal {
                blob_version: *blob_version,
            },
            Phase::Sign { .. } => match self.publisher.prepared() {
                Some(prepared) => Step::Sign {
                    body: prepared.body.clone(),
                },
                None => Step::Failed(BackupError::UnexpectedReply),
            },
            Phase::Upload => {
                let envelope = self.envelope.as_ref().expect("uploading an envelope");
                Step::Put {
                    blob_version: envelope.blob_version,
                    bytes: envelope.jcs(),
                }
            }
            Phase::Publish => match self.publisher.outstanding() {
                Some((entry, expected)) => Step::Append {
                    entry: entry.object().clone(),
                    expected,
                },
                None => Step::Failed(BackupError::UnexpectedReply),
            },
            Phase::Fetch { after, .. } => Step::Fetch { after: *after },
            Phase::Done { committed } => Step::Done {
                committed: *committed,
            },
            Phase::Failed(error) => Step::Failed(error.clone()),
        }
    }

    fn allocate(&mut self, log: &Membership) -> Step {
        let committed = Self::committed(log);
        if let Some(max) = self.last_max_occupied
            && max > committed.saturating_add(MAX_VERSION_SKIP)
        {
            return self.fail(BackupError::RelayMisbehaviour {
                max_occupied: max,
                committed,
            });
        }
        let highest = [
            committed,
            self.uploaded.iter().next_back().copied().unwrap_or(0),
            self.last_max_occupied.unwrap_or(0),
        ]
        .into_iter()
        .max()
        .unwrap_or(0);
        let blob_version = highest + 1;
        self.phase = Phase::Seal { blob_version };
        Step::Seal { blob_version }
    }

    fn fail(&mut self, error: BackupError) -> Step {
        self.phase = Phase::Failed(error.clone());
        Step::Failed(error)
    }

    fn done(&mut self, log: &Membership) -> Step {
        let committed = Self::committed(log);
        self.phase = Phase::Done { committed };
        Step::Done { committed }
    }

    /// The caller sealed the asked version (step 2): the envelope and the
    /// prepared entry are stored, then the entry is signed. Next: upload.
    pub fn sealed(&mut self, log: &Membership, envelope: KBackupEnvelope, signed_at: u64) -> Step {
        let Phase::Seal { blob_version } = self.phase else {
            return Step::Failed(BackupError::UnexpectedReply);
        };
        let fits = envelope.blob_version == blob_version
            && envelope.kids == self.job.kids
            && envelope.recovery_key == self.job.kit
            && envelope.account_id == log.account_id()
            && envelope.genesis_hash == log.genesis_hash();
        if !fits {
            return Step::Failed(BackupError::WrongEnvelope);
        }
        if let Err(error) = self.draft_entry(log, &envelope, signed_at) {
            return self.fail(error);
        }
        self.envelope = Some(envelope);
        self.phase = Phase::Sign { then_upload: true };
        self.resume()
    }

    /// Signs the stored body with the manager's key (§R9.4 rule 1: after the
    /// body was stored). Next: the upload, or the append of a rebuilt entry.
    pub fn sign(&mut self, provider: &dyn KeyProvider, key: &KeyId) -> Step {
        let Phase::Sign { then_upload } = self.phase else {
            return Step::Failed(BackupError::UnexpectedReply);
        };
        if let Err(e) = self.publisher.sign(provider, key, None) {
            return self.fail(match e {
                crate::membership::publish::PublishError::Sign(invalid) => {
                    BackupError::Sign(invalid)
                }
                _ => BackupError::UnexpectedReply,
            });
        }
        self.phase = if then_upload {
            Phase::Upload
        } else {
            Phase::Publish
        };
        self.resume()
    }

    fn draft_entry(
        &mut self,
        log: &Membership,
        envelope: &KBackupEnvelope,
        signed_at: u64,
    ) -> Result<(), BackupError> {
        let action = Action::KBackup(KBackupRecord {
            blob_version: envelope.blob_version,
            kids: envelope.kids.clone(),
            recovery_key: envelope.recovery_key.clone(),
            backup_hash: envelope.backup_hash(),
        });
        let body = log.draft(&self.job.signer, signed_at, &action);
        self.publisher = Publisher::new();
        self.publisher
            .prepare(log, body)
            .map_err(|_| BackupError::UnexpectedReply)?;
        Ok(())
    }

    fn discard_envelope(&mut self) {
        if let Some(envelope) = self.envelope.take() {
            self.uploaded.remove(&envelope.blob_version);
            self.discarded.push(Discarded::Envelope {
                blob_version: envelope.blob_version,
                backup_hash: envelope.backup_hash(),
            });
        }
        self.publisher = Publisher::new();
    }

    /// The relay's answer to the upload (step 3).
    pub fn put_reply(&mut self, log: &Membership, reply: PutReply) -> Step {
        if self.phase != Phase::Upload {
            return Step::Failed(BackupError::UnexpectedReply);
        }
        match reply {
            PutReply::Stored => {
                let version = self.envelope.as_ref().expect("uploading").blob_version;
                self.uploaded.insert(version);
                self.phase = Phase::Publish;
                self.resume()
            }
            PutReply::Occupied { max_occupied } => {
                self.discard_envelope();
                self.last_max_occupied =
                    Some(self.last_max_occupied.unwrap_or(0).max(max_occupied));
                if Self::covers(log, &self.job.kids) && self.job.kit == *log.recovery_key() {
                    return self.done(log);
                }
                self.allocate(log)
            }
        }
    }

    /// The relay's answer to the CAS append (steps 4 and 5). `log` is the
    /// writer's verified log: a `409`'s entries are verified into it.
    /// `signed_at` is used if the entry must be rebuilt on a new head.
    pub fn append_reply(
        &mut self,
        log: &mut Membership,
        reply: AppendReply,
        now: &HostNow,
        signed_at: u64,
    ) -> Step {
        if self.phase != Phase::Publish {
            return Step::Failed(BackupError::UnexpectedReply);
        }
        let sent = self.publisher.outstanding().map(|(e, _)| e.hash());
        let ours = self.envelope.as_ref().expect("publishing").blob_version;
        match self.publisher.reply(reply, log, now) {
            Ok(Published::Committed(_)) => {
                self.uploaded.remove(&ours);
                self.envelope = None;
                self.done(log)
            }
            Ok(Published::StoredPending { .. }) => {
                // Committed at the relay; our log applies it once the entry it
                // depends on takes effect here.
                self.uploaded.remove(&ours);
                self.envelope = None;
                self.phase = Phase::Done { committed: ours };
                Step::Done { committed: ours }
            }
            Ok(Published::LostRace { .. }) => self.after_loss(log, sent, signed_at),
            Ok(Published::Waiting { on, .. }) => self.fail(BackupError::Waiting { on }),
            Ok(Published::RelayInconsistent { .. }) => self.fail(BackupError::RelayInconsistent),
            Ok(Published::FetchMore { after, .. }) => {
                self.phase = Phase::Fetch { after, lost: sent };
                self.resume()
            }
            Ok(Published::Diverged { .. }) => self.fail(BackupError::Diverged),
            Ok(Published::RelayInvalid { .. }) => self.fail(BackupError::RelayInvalid),
            Err(_) => Step::Failed(BackupError::UnexpectedReply),
        }
    }

    /// The rest of a `409`'s entries (`…/entries?after=`), verified into
    /// `log` before anything is rebuilt.
    pub fn fetched(
        &mut self,
        log: &mut Membership,
        entries: &[SignedObject],
        more: bool,
        now: &HostNow,
        signed_at: u64,
    ) -> Step {
        let Phase::Fetch { lost, .. } = self.phase else {
            return Step::Failed(BackupError::UnexpectedReply);
        };
        let eval = log.evaluate_objects(entries, now);
        let stop = eval.stop.clone();
        *log = eval.next;
        match stop {
            Some(Stop::Invalid { .. }) => return self.fail(BackupError::RelayInvalid),
            Some(Stop::Frozen)
            | Some(Stop::NeedBefore { .. })
            | Some(Stop::Conflict {
                outcome: Conflict::Freeze,
                ..
            }) => return self.fail(BackupError::Diverged),
            Some(Stop::Deferred { on, .. }) => return self.fail(BackupError::Waiting { on }),
            Some(Stop::Conflict {
                outcome: Conflict::Ignored(_),
                ..
            }) => return self.fail(BackupError::RelayInconsistent),
            _ => {}
        }
        if more {
            self.phase = Phase::Fetch {
                after: log.head().seq,
                lost,
            };
            return self.resume();
        }
        self.after_loss(log, lost, signed_at)
    }

    /// Step 5 after the log moved under our entry.
    fn after_loss(&mut self, log: &Membership, sent: Option<Hash32>, signed_at: u64) -> Step {
        let ours = self.envelope.as_ref().expect("publishing").blob_version;
        if Self::committed(log) >= ours {
            // A `k_backup` naming a version ≥ ours won: ours can never be
            // named. Discard both.
            self.discard_envelope();
            if let Some(entry_hash) = sent {
                self.discarded.push(Discarded::Entry { entry_hash });
            }
            if Self::covers(log, &self.job.kids) {
                return self.done(log);
            }
            return self.allocate(log);
        }
        // An unrelated entry won the seq: keep the uploaded envelope (its
        // bytes don't depend on the head) and rebuild only the entry, if the
        // kit it names is still current or pending.
        let kit_named = *log.recovery_key() == self.job.kit
            || log.pending_recovery_keys().any(|k| *k == self.job.kit);
        if !kit_named {
            self.discard_envelope();
            self.job.kit = log.recovery_key().clone();
            return self.allocate(log);
        }
        let envelope = self.envelope.clone().expect("publishing");
        match self.draft_entry(log, &envelope, signed_at) {
            Ok(()) => {
                self.phase = Phase::Sign { then_upload: false };
                self.resume()
            }
            Err(error) => self.fail(error),
        }
    }

    /// The prepared entry (durable).
    pub fn prepared(&self) -> Option<&Prepared> {
        self.publisher.prepared()
    }
}
