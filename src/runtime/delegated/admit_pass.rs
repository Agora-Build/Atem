//! (`impl HostBridge`) Admission of host senders' mail on the receiving
//! host (the delegated host-work design II.4.2 step 7, II.4.4, II.6, II.7;
//! host-work-v1 §11.5, "On the receiving host"), with the debug-only hook's
//! `host.senders` on. Each pass while hosting runs, gate open or not (the
//! gate's mailbox part waits for the inbox, so admission never waits for
//! it): every inbox row the mailbox committed becomes a decision in its
//! own `BEGIN IMMEDIATE` transaction of the host-work store, with the row's
//! removal and the status owed to its sender enqueued in the put engine
//! (`outbox::enqueue`, until stored). Nothing reaches an agent, and
//! nothing is put, before that commits. Its store is [`admit`].
//!
//! - **A request**: deduplicated against this host's own permanent records
//!   (a message record, a recorded whole refusal: never only the mailbox's
//!   claims); the sender's standing checked again on the committed list
//!   (`signed_at_head` at or after its current generation and epoch); then
//!   step 7: each recipient for this host's triple, with the sender's
//!   permit (`host_sender_permits`) in place of a channel scope, `select`
//!   expanded once with stage 1's `resolve` over the agents of routes that
//!   consent to it; the limits; the message record, its tasks (each with
//!   its admission record, `Admission::for_host`) and its early stops.
//! - **A `cancel` or `complete`** (II.7): applied to the sender's own task
//!   admitted at its current generation and epoch, else not reached; one
//!   whose task isn't here yet is kept as an early stop (ruling R38).
//! - **Status objects** (II.4.4): the message's current status, sealed to
//!   the sender's current `host_enc_key` with this host's
//!   `host_channel_key`, signed at the committed head; a refused
//!   authenticated object's status (`report`); and, each pass, the statuses
//!   owed for a host sender's task whose state changed ([`admit`]'s
//!   trigger). A sender with no current key, or no longer a current host,
//!   gets none: the record keeps the state for the owner.
use super::*;
use crate::runtime::delegated::admit::{self, InboxRow};
use crate::runtime::delegated::attempts::{AttemptEnd, SessionAnswer, attempt_end};
use crate::runtime::delegated::effects::Followup;
use crate::runtime::delegated::host_senders::{
    HostOp, HostSender, host_sender_permits, host_standing, host_task_covered,
};
use crate::runtime::delegated::outbox::{self, Policy};
use crate::runtime::delegated::start::{CANCELLED_BEFORE_SUBMISSION, Event};
use crate::runtime::host_work::MessageRecord;
use crate::session_protocol::r9::HostKey;
use atem_client::host_mail::{EnvelopePlain, HostRef, MailFields, ResultPlain};
use atem_client::host_principal::{host_principal, host_principal_key, parse_host_principal};
use atem_client::membership::{Membership, ProjectOp};
use atem_client::session::messages::{
    Delivery, Destination, Message, MessageReceipt, Recipient, RecipientReceipt,
};
use atem_client::session::select::Selector;
use rusqlite::Transaction;
use std::collections::BTreeSet;
use std::sync::atomic::AtomicU64;

/// Tries of a row, or a report, that can't be decided before it is settled
/// (review M2).
pub(super) const MAX_ADMIT_FAILURES: u32 = 8;
/// Inbox rows decided per pass, at most (the inbox holds 128).
const ROWS_PER_PASS: usize = 128;
/// Statuses sealed per pass, at most (the rest next pass).
const STATUSES_PER_PASS: usize = 64;

static UNADMITTED: AtomicU64 = AtomicU64::new(0);
static UNSEALED: AtomicU64 = AtomicU64::new(0);

/// What signs and seals this host's status objects (design II.4.4): its
/// committed device list, itself as a current host at its own trust
/// generation, its `host_channel_key`, its account and the delegated
/// clock's `D`.
struct Signing {
    list: Arc<Membership>,
    key: Arc<HostKey>,
    me: HostRef,
    account: String,
    now_d: u64,
    /// A forward jump's anchor is pending: `D` may still come back down,
    /// so nothing is judged expired on it (review M1).
    anchored: bool,
}

impl Signing {
    /// `plain` sealed to host `to` (its current key, at its current trust
    /// generation), signed at the committed head, alive 24 h: its exact
    /// bytes and where they go. None when `to` can't receive one now (no
    /// longer a current host, or no key), or the seal failed (a line).
    fn seal(&self, to: &str, plain: &ResultPlain) -> Option<(Vec<u8>, HostRef)> {
        let host = self.list.host(to)?;
        let key = self.list.host_enc_key(to)?;
        let target = HostRef {
            host_id: to.to_owned(),
            host_trust_gen: host.host_trust_gen,
        };
        let fields = MailFields {
            account_id: self.account.clone(),
            genesis_hash: self.list.genesis_hash(),
            sender: self.me.clone(),
            recipient: target.clone(),
            enc_kid: atem_client::encoding::hex(&key.current.kid),
            id: uuid::Uuid::new_v4().to_string(),
            created_at: self.now_d,
            expires_at: self.now_d.saturating_add(hw::MAX_LIFETIME_MS),
            signed_at_head: self.list.head(),
        };
        match self.key.seal_result(&fields, plain, &key.current.key) {
            Ok(object) => Some((object.to_json().to_string().into_bytes(), target)),
            Err(error) => {
                super::delegated_mail_pass::log_limited(&UNSEALED, || {
                    format!("atem runtime: a status to host {to} couldn't be sealed ({error})")
                });
                None
            }
        }
    }

    /// The current status of `record` (a host sender's message) to its
    /// sender, enqueued in `tx` (the one before it superseded), or none
    /// owed when the sender can't receive one (no key, no longer a current
    /// host, or another key than the one the message came under).
    fn status(
        &self,
        tx: &Transaction,
        store: &Store,
        record: &MessageRecord,
    ) -> anyhow::Result<()> {
        let message_id = &record.message.message_id;
        let plain = ResultPlain::Status {
            message_id: message_id.clone(),
            recipients: admit::receipts(store, record)?,
        };
        // Only to the sender at the key it was admitted under (review L4,
        // design II.2.1): re-verified since, its old outbox is gone, so
        // the new generation gets none.
        let sealed = parse_host_principal(&record.message.sender)
            .filter(|sender| {
                self.list.host(sender).is_some_and(|h| {
                    record.sender_key == json!(host_principal_key(&h.host_key).to_hex())
                })
            })
            .and_then(|sender| self.seal(sender, &plain));
        match sealed {
            Some((bytes, to)) => {
                let n = outbox::enqueue(tx, &bytes, &to, Policy::UntilStored)?;
                admit::sent(tx, message_id, n)
            }
            None => admit::clear(tx, message_id),
        }
    }

    /// `{"kind":"status","object_id","refused":code}` to `sender`,
    /// enqueued in `tx` (none when it can't receive one).
    fn refusal(
        &self,
        tx: &Transaction,
        sender: &str,
        object_id: &str,
        code: &str,
    ) -> anyhow::Result<()> {
        let plain = ResultPlain::Refusal {
            object_id: object_id.to_owned(),
            refused: code.to_owned(),
        };
        if let Some((bytes, to)) = self.seal(sender, &plain) {
            outbox::enqueue(tx, &bytes, &to, Policy::UntilStored)?;
        }
        Ok(())
    }
}

/// A report or an inbox row admission failed to decide (review M2).
enum Failed {
    Row(InboxRow, String),
    Report {
        evidence: String,
        sender: String,
        object_id: String,
    },
}

impl Failed {
    /// Its key in the failures' count.
    fn key(&self) -> String {
        match self {
            Failed::Row(row, _) => format!("row:{}", row.n),
            Failed::Report { evidence, .. } => format!("report:{evidence}"),
        }
    }
}

/// The ops of every project in effect that lists both `sender` and this
/// host (`me`): a host sender's account permission toward it (design
/// II.2.3), whatever the route.
fn shared_ops(list: &Membership, me: &str, sender: &str) -> BTreeSet<ProjectOp> {
    if sender == me {
        return BTreeSet::new();
    }
    list.host_projects(sender)
        .into_iter()
        .filter(|name| list.project_hosts(name).contains(&me))
        .filter_map(|name| list.project(name))
        .flat_map(|project| project.ops.iter().copied())
        .collect()
}

/// `sender`'s authorization generation and membership epoch now, when it
/// may send on `list` an object it signed at `signed_seq` (design II.3.1,
/// check 3 again at admission): a current host, authorized at a generation
/// and in a membership epoch at or before that head. A revoke and a
/// readmit, or a removal and a re-add, since the object opened refuse it.
fn may_send(list: &Membership, sender: &str, signed_seq: u64) -> Option<(u64, u64)> {
    host_standing(list, sender, None)
        .ok()
        .filter(|(generation, epoch)| signed_seq >= *generation && signed_seq >= *epoch)
}

impl HostBridge {
    /// The signing of this host's status objects now, when it may sign
    /// (§11.5's sender rule: its committed list shows it a current host at
    /// its own trust generation), with its key and `D`.
    fn signing(&self) -> Option<Signing> {
        let list = self.send_list()?;
        let now_d = self.start_view().now_d_ms?;
        let key = self.host_key.clone()?;
        let host = self.work_host();
        if list
            .host(&host.atem_device_id)
            .is_none_or(|h| h.host_trust_gen != host.host_trust_gen)
        {
            return None;
        }
        Some(Signing {
            list,
            key,
            me: HostRef {
                host_id: host.atem_device_id,
                host_trust_gen: host.host_trust_gen,
            },
            account: host.account_id,
            now_d,
            anchored: self
                .work
                .clock
                .as_ref()
                .is_some_and(crate::runtime::host_clock::HostClock::anchored),
        })
    }

    /// Each pass while hosting runs, with `host.senders` on (and the
    /// store this identity's, its tables made): the refusals to report,
    /// then every inbox row decided (the module docs). The gate's mailbox
    /// part follows the inbox as it now stands. Debug builds: held while a
    /// test says (`<pty faults>/hold_admission`).
    pub(super) fn admit_mail(&mut self, cx: &mut Cx) {
        if !self.senders_on() || crate::runtime::test_hooks::admission_held() {
            return;
        }
        let Some(signing) = self.signing() else {
            return;
        };
        let (mut decided, failed, followups) = match self.admit_with(&signing, cx.sessions) {
            Ok(done) => done,
            Err(error) => {
                super::delegated_mail_pass::log_limited(&UNADMITTED, || {
                    format!(
                        "atem runtime: host senders' mail not admitted ({error:#}); tried again"
                    )
                });
                return;
            }
        };
        // Review M2: one that failed is tried again on the next passes; one
        // still failing after `MAX_ADMIT_FAILURES` tries is settled, so it
        // never holds the gate for good. A count goes once its row or
        // report no longer fails.
        let mut counts = std::mem::take(&mut self.work.admit_failures);
        for failure in failed {
            let key = failure.key();
            let tries = counts.remove(&key).unwrap_or(0) + 1;
            if tries < MAX_ADMIT_FAILURES {
                self.work.admit_failures.insert(key, tries);
            } else if self.settle_failure(&signing, &failure, tries) {
                decided = true;
            } else {
                self.work.admit_failures.insert(key, tries);
            }
        }
        // The gate's mailbox part as the inbox now stands, before anything
        // of this pass is dispatched.
        if decided {
            self.mail_observe();
            self.publish_mail_gate();
        }
        // A cancel's withdrawal of an attempt waiting `accepted` (ruling
        // R46), after the commit that decided it, as a revoke's.
        if !followups.is_empty() {
            self.work.followups.extend(followups);
            self.effects_pass(cx);
        }
    }

    /// Every report and inbox row decided, each on its own: whether a row
    /// was taken, and what failed (each logged; review M2: one failing
    /// skips none of the others).
    fn admit_with(
        &self,
        signing: &Signing,
        sessions: &BTreeMap<SessionId, BrokerSession>,
    ) -> anyhow::Result<(bool, Vec<Failed>, Vec<Followup>)> {
        let Some(store) = self.outbox_store() else {
            return Ok((false, Vec::new(), Vec::new()));
        };
        let mut followups = Vec::new();
        let mut failed = Vec::new();
        // II.4.4: an authenticated object refused at check 5 or 6 is
        // reported to its sender, `invalid_request`, its mark cleared in
        // the transaction that enqueues the status.
        for (evidence, sender, object_id) in admit::reports(&store.db, ROWS_PER_PASS)? {
            let reported = (|| -> anyhow::Result<()> {
                let tx = store.immediate()?;
                signing.refusal(&tx, &sender, &object_id, "invalid_request")?;
                admit::reported(&tx, &evidence)?;
                tx.commit()?;
                Ok(())
            })();
            if let Err(error) = reported {
                super::delegated_mail_pass::log_limited(&UNADMITTED, || {
                    format!(
                        "atem runtime: host sender {sender}'s refused object {object_id} not reported ({error:#}); tried again"
                    )
                });
                failed.push(Failed::Report {
                    evidence,
                    sender,
                    object_id,
                });
            }
        }
        let mut decided = false;
        for row in admit::inbox(&store.db, ROWS_PER_PASS)? {
            // A row that can't be decided now stays, holding the gate (fail
            // closed) until it is settled; the rows after it are decided all
            // the same.
            match self.admit_row(store, signing, &row, sessions) {
                Ok((taken, after)) => {
                    decided |= taken;
                    followups.extend(after);
                }
                Err(error) => {
                    super::delegated_mail_pass::log_limited(&UNADMITTED, || {
                        format!(
                            "atem runtime: host sender {}'s mailbox object {} not admitted ({error:#}); tried again",
                            row.sender_host, row.object_id
                        )
                    });
                    failed.push(Failed::Row(row, format!("{error:#}")));
                }
            }
        }
        Ok((decided, failed, followups))
    }

    /// A row that failed `tries` times settled, as an unreadable task
    /// record is (review M2): refused `busy` to its sender by its own
    /// object id (a request's refusal recorded, as any whole refusal),
    /// removed, one runtime.log line; a report's mark cleared. Whether it
    /// was.
    fn settle_failure(&self, signing: &Signing, failure: &Failed, tries: u32) -> bool {
        let Some(store) = self.outbox_store() else {
            return false;
        };
        let settled = (|| -> anyhow::Result<()> {
            let tx = store.immediate()?;
            match failure {
                Failed::Row(row, _) => {
                    if let Some(EnvelopePlain::Request { message }) = &row.plain {
                        admit::refuse(
                            &tx,
                            &row.sender_host,
                            &message.message_id,
                            &message.digest(),
                            "busy",
                            signing.now_d,
                            message.expires_at,
                        )?;
                    }
                    signing.refusal(&tx, &row.sender_host, &row.object_id, "busy")?;
                    admit::take_row(&tx, row.n)?;
                }
                Failed::Report { evidence, .. } => admit::reported(&tx, evidence)?,
            }
            tx.commit()?;
            Ok(())
        })();
        match (&settled, failure) {
            (Ok(()), Failed::Row(row, error)) => eprintln!(
                "atem runtime: host sender {}'s mailbox object {} couldn't be admitted after {tries} tries ({error}); refused busy",
                row.sender_host, row.object_id
            ),
            (
                Ok(()),
                Failed::Report {
                    sender, object_id, ..
                },
            ) => eprintln!(
                "atem runtime: host sender {sender}'s refused object {object_id} couldn't be reported after {tries} tries; dropped"
            ),
            (Err(error), _) => super::delegated_mail_pass::log_limited(&UNADMITTED, || {
                format!("atem runtime: a host sender's mailbox object not settled ({error:#})")
            }),
        }
        settled.is_ok()
    }

    /// One inbox row decided in its own transaction, removed with its
    /// decision (a stop waiting for room stays, held): whether the inbox
    /// changed (a row taken, or newly held).
    fn admit_row(
        &self,
        store: &Store,
        signing: &Signing,
        row: &InboxRow,
        sessions: &BTreeMap<SessionId, BrokerSession>,
    ) -> anyhow::Result<(bool, Vec<Followup>)> {
        let tx = store.immediate()?;
        let mut followups = Vec::new();
        let decided = match &row.plain {
            Some(EnvelopePlain::Request { message }) => {
                self.admit_request(&tx, store, signing, row, message, sessions)?;
                true
            }
            Some(EnvelopePlain::Cancel { task_id }) => {
                self.admit_stop(&tx, store, signing, row, task_id, None, &mut followups)?
            }
            Some(EnvelopePlain::Complete { task_id, result }) => self.admit_stop(
                &tx,
                store,
                signing,
                row,
                task_id,
                Some(result),
                &mut followups,
            )?,
            // Its bytes no longer read (a stricter reader than the one that
            // wrote it): refused and reported (review L2).
            None => {
                admit::refuse_unreadable(&tx, row, signing.now_d)?;
                true
            }
        };
        if !decided {
            // A stop waiting for room among its sender's early stops: held,
            // holding only that sender's task starts (ruling R47).
            if row.held {
                return Ok((false, Vec::new()));
            }
            admit::hold_row(&tx, row.n)?;
            tx.commit()?;
            return Ok((true, Vec::new()));
        }
        admit::take_row(&tx, row.n)?;
        tx.commit()?;
        // Debug builds: the runtime is killed here, a request's admission
        // and its status committed, nothing put yet.
        #[cfg(not(test))]
        if matches!(row.plain, Some(EnvelopePlain::Request { .. })) {
            crate::runtime::test_hooks::crash_point(
                "crash_after_admission_commit",
                "after a host sender's request was admitted, before its status was put",
            );
        }
        Ok((true, followups))
    }

    /// The statuses owed (a host sender's task changed state: [`admit`]'s
    /// trigger), each sealed with its message's current state and enqueued,
    /// the mark cleared, in one transaction; at most
    /// [`STATUSES_PER_PASS`] a pass. With `host.senders` on, while hosting
    /// runs or is paused (a device-list entry's effects change tasks then
    /// too). Kept owed while this host can't sign.
    pub(super) fn mail_statuses(&mut self) {
        if !self.senders_on() || crate::runtime::test_hooks::admission_held() {
            return;
        }
        let Some(signing) = self.signing() else {
            return;
        };
        let Some(store) = self.outbox_store() else {
            return;
        };
        let owed = match admit::owed(&store.db, STATUSES_PER_PASS) {
            Ok(owed) => owed,
            Err(error) => {
                super::delegated_mail_pass::log_limited(&UNSEALED, || {
                    format!("atem runtime: host senders' statuses not read ({error:#})")
                });
                return;
            }
        };
        for message_id in owed {
            let sealed = (|| -> anyhow::Result<()> {
                let tx = store.immediate()?;
                match store.message(&message_id)? {
                    Some(record) => signing.status(&tx, store, &record)?,
                    None => admit::clear(&tx, &message_id)?,
                }
                tx.commit()?;
                Ok(())
            })();
            // One that can't be built (a task record that doesn't read)
            // is dropped, never blocking the others: the record keeps the
            // state for the owner.
            if let Err(error) = sealed {
                super::delegated_mail_pass::log_limited(&UNSEALED, || {
                    format!(
                        "atem runtime: message {message_id}'s status not sent to its host sender ({error:#})"
                    )
                });
                let dropped = store.immediate().and_then(|tx| {
                    admit::clear(&tx, &message_id)?;
                    Ok(tx.commit()?)
                });
                if dropped.is_err() {
                    return;
                }
            }
        }
    }

    /// A host sender's request (design II.4.2 step 7, "Duplicates"; the
    /// module docs), decided in `tx`: its message record and tasks, or a
    /// refusal, and the status to its sender.
    fn admit_request(
        &self,
        tx: &Transaction,
        store: &Store,
        signing: &Signing,
        row: &InboxRow,
        message: &Message,
        sessions: &BTreeMap<SessionId, BrokerSession>,
    ) -> anyhow::Result<()> {
        let sender = row.sender_host.as_str();
        let principal = host_principal(sender);
        let id = &message.message_id;
        let digest = message.digest();
        // A refusal of the whole request, recorded for good when `record`
        // (a resend is answered the same), reported to its sender.
        let refuse = |code: &str, record: bool| -> anyhow::Result<()> {
            if record {
                admit::refuse(
                    tx,
                    sender,
                    id,
                    &digest,
                    code,
                    signing.now_d,
                    message.expires_at,
                )?;
            }
            signing.refusal(tx, sender, id, code)
        };
        // Duplicates: this host's own permanent records. The same content
        // again is its current status; other content, or an id another
        // principal used here, `request_id_reused` (host-work v1's rule).
        if let Some(old) = store.message(id)? {
            if old.message.sender != principal || old.receipt.digest != digest {
                return refuse("request_id_reused", false);
            }
            return signing.status(tx, store, &old);
        }
        let local: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM outbox WHERE message_id=?1)",
            [id],
            |r| r.get(0),
        )?;
        if local {
            return refuse("request_id_reused", false);
        }
        if let Some((recorded, code)) = admit::refusal(tx, sender, id)? {
            return if recorded == digest {
                refuse(&code, false)
            } else {
                refuse("request_id_reused", false)
            };
        }
        // Expired before admission took it (a long pause, an outage; review
        // L6): no task past its deadline. Not judged under a clock anchor.
        if message.expires_at <= signing.now_d && !signing.anchored {
            return refuse("busy", true);
        }
        let list = &signing.list;
        // The sender's standing now, against the head it signed at.
        let Some(standing) = may_send(list, sender, row.signed_seq) else {
            return refuse("forbidden", true);
        };
        // A host sender's Message, without attachments (checked when it
        // opened; here as the last line).
        if !message.valid_from_host(sender) {
            return refuse("invalid_request", true);
        }
        let host = self.work_host();
        let mine: Vec<&Recipient> = message
            .recipients
            .iter()
            .filter(|r| r.host == host)
            .collect();
        // None for this host's triple (another host, or this one at an
        // older trust generation).
        if mine.is_empty() {
            return refuse("stale_target", true);
        }
        let mut tasks = Vec::new();
        let recipients: Vec<RecipientReceipt> = mine
            .into_iter()
            .map(|r| RecipientReceipt {
                recipient_id: r.recipient_id.clone(),
                delivery: self.deliver(list, message, &digest, r, sender, sessions, &mut tasks),
            })
            .collect();
        // A task that could never be dispatched refuses the message (its
        // text and context are every task's).
        if tasks
            .iter()
            .any(|t| crate::runtime::collab::task_problem(&t.task, &host).is_some())
        {
            return refuse("invalid_request", true);
        }
        for task in &tasks {
            if store.work(&task.task.task_id)?.is_some() {
                return refuse("request_id_reused", true);
            }
        }
        // The limits (II.9), as a channel member's publish meets them.
        if (!tasks.is_empty() && store.over_capacity(&principal)?) || !room(tx, &tasks)? {
            return refuse("busy", true);
        }
        if let Err(error) = crate::runtime::collab::count_received(
            tx,
            &self.work.config.collab,
            &message.workflow_id,
            message.created_at,
        ) {
            if error.to_string().starts_with("limit:") {
                return refuse("busy", true);
            }
            return Err(error);
        }
        // Early stops of its tasks (ruling R38): a cancel cancels it now;
        // a complete finds it queued, not reached.
        for task in &mut tasks {
            for kind in admit::take_stops(tx, sender, &task.task.task_id, standing)? {
                if kind == "cancel" {
                    task.status.state = WorkState::Cancelled;
                    task.status.detail = CANCELLED_BEFORE_SUBMISSION.into();
                }
            }
        }
        let key = list
            .host(sender)
            .map(|h| host_principal_key(&h.host_key).to_hex())
            .unwrap_or_default();
        let record = MessageRecord {
            sender_key: json!(key),
            message: message.clone(),
            receipt: MessageReceipt {
                message_id: id.clone(),
                digest,
                sender: principal,
                recipients,
            },
        };
        tx.execute(
            "INSERT INTO messages(id,record) VALUES(?1,?2)",
            rusqlite::params![id, serde_json::to_string(&record)?],
        )?;
        for task in &tasks {
            let state = serde_json::to_value(task.status.state)?;
            tx.execute(
                "INSERT INTO work(id,record,state) VALUES(?1,?2,?3)",
                rusqlite::params![
                    task.task.task_id,
                    serde_json::to_string(task)?,
                    state.as_str().unwrap_or_default()
                ],
            )?;
        }
        signing.status(tx, store, &record)
    }

    /// One recipient of a host sender's request for this host (step 7),
    /// with the sender's permit in place of a channel scope: a notice
    /// `stored`, an agent task `work`, a `select` expanded once
    /// (`resolved` or `no_match`), else `refused{forbidden}`. Its tasks go
    /// to `tasks`.
    #[allow(clippy::too_many_arguments)]
    fn deliver(
        &self,
        list: &Membership,
        message: &Message,
        digest: &str,
        r: &Recipient,
        sender: &str,
        sessions: &BTreeMap<SessionId, BrokerSession>,
        tasks: &mut Vec<WorkRecord>,
    ) -> Delivery {
        let forbidden = || Delivery::Refused {
            code: "forbidden".into(),
        };
        let me = self.work_host().atem_device_id;
        let at = |route_id: &str, revision: u64| {
            self.work
                .config
                .route(route_id)
                .filter(|route| route.revision == revision)
        };
        let permits = |route: &crate::runtime::host_work::Route, op: HostOp| {
            let sender = HostSender {
                host_id: sender,
                admitted: None,
            };
            host_sender_permits(list, &me, &sender, route, op).is_ok()
        };
        match &r.destination {
            // A host notice: the account's `message` op (II.2.3).
            Destination::Host => {
                if shared_ops(list, &me, sender).contains(&ProjectOp::Message) {
                    Delivery::Stored {}
                } else {
                    forbidden()
                }
            }
            Destination::Project {
                route_id,
                route_revision,
            } => match at(route_id, *route_revision) {
                Some(route) if permits(route, HostOp::Notice) => Delivery::Stored {},
                _ => forbidden(),
            },
            Destination::Agent {
                route_id,
                route_revision,
                target,
            } => {
                let task = message.task(r);
                let record = task.and_then(|task| {
                    self.host_task(
                        list,
                        message,
                        digest,
                        sender,
                        route_id,
                        *route_revision,
                        task,
                    )
                });
                match record {
                    Some(record) if self.host_target_ok(&record, target, sessions) => {
                        let delivery = Delivery::Work {
                            work: (&record.status).into(),
                        };
                        tasks.push(record);
                        delivery
                    }
                    _ => forbidden(),
                }
            }
            Destination::Select {
                selectors, budget, ..
            } => {
                // No project it shares with this host grants a task's ops.
                let ops = shared_ops(list, &me, sender);
                if !HostOp::Task.needs().iter().all(|op| ops.contains(op)) {
                    return forbidden();
                }
                let Ok(selectors) = selectors
                    .iter()
                    .map(|s| s.parse::<Selector>())
                    .collect::<Result<Vec<_>, _>>()
                else {
                    return forbidden();
                };
                // The agents of routes that consent to the sender and whose
                // grant covers a task (II.6, "The receiver decides"): no
                // sending session to leave out.
                let candidates: Vec<crate::runtime::collab::Candidate> = self
                    .work
                    .config
                    .routes
                    .iter()
                    .filter(|route| permits(route, HostOp::Task))
                    .flat_map(|route| self.route_candidates(route, sessions))
                    .collect();
                let resolved = crate::runtime::collab::resolve(
                    &me,
                    &candidates,
                    &selectors,
                    *budget,
                    "",
                    &message.message_id,
                    &r.recipient_id,
                );
                let host = self.work_host();
                let mut progress = Vec::new();
                for t in resolved {
                    let task = hw::WorkTask {
                        task_id: t.task_id,
                        workflow_id: message.workflow_id.clone(),
                        target: wire::Target {
                            account_id: host.account_id.clone(),
                            atem_device_id: host.atem_device_id.clone(),
                            host_trust_gen: host.host_trust_gen,
                            session_id: t.session_id,
                            process_gen: t.process_gen,
                        },
                        expires_at: message.expires_at,
                        prompt: message.text.clone(),
                        context: message.context.clone(),
                        attachments: Vec::new(),
                    };
                    if let Some(record) = self.host_task(
                        list,
                        message,
                        digest,
                        sender,
                        &t.route_id,
                        t.route_revision,
                        task,
                    ) {
                        progress.push((&record.status).into());
                        tasks.push(record);
                    }
                }
                if progress.is_empty() {
                    Delivery::NoMatch {}
                } else {
                    Delivery::Resolved { tasks: progress }
                }
            }
        }
    }

    /// The agents of `route` a selector may match: its profile's live
    /// sessions, with this host's labels, the route's and their own tags
    /// (stage 1's candidates, `collab_candidates`).
    fn route_candidates(
        &self,
        route: &crate::runtime::host_work::Route,
        sessions: &BTreeMap<SessionId, BrokerSession>,
    ) -> Vec<crate::runtime::collab::Candidate> {
        let Some(profile) = self.work.config.profile(&route.profile_id) else {
            return Vec::new();
        };
        sessions
            .values()
            .filter(|s| {
                s.is_live()
                    && s.cwd == profile.cwd
                    && s.provider == profile.provider
                    && self.projects.key_of(s.id.as_str()) == Some(profile.project.as_str())
            })
            .map(|session| crate::runtime::collab::Candidate {
                route_id: route.id.clone(),
                route_revision: route.revision,
                session_id: session.id.to_string(),
                process_gen: session.process_gen.clone(),
                started_ms: session.created_at_ms,
                labels: self
                    .work
                    .config
                    .instance
                    .labels
                    .iter()
                    .chain(&route.labels)
                    .chain(session.self_tags())
                    .filter_map(|s| s.parse().ok())
                    .collect(),
            })
            .collect()
    }

    /// The task `task` of a host sender's message through `route_id` at
    /// `revision` (design I.4.1): queued, its admission record frozen from
    /// the sender's permit; none when the route doesn't take it.
    #[allow(clippy::too_many_arguments)]
    fn host_task(
        &self,
        list: &Membership,
        message: &Message,
        digest: &str,
        sender: &str,
        route_id: &str,
        revision: u64,
        task: hw::WorkTask,
    ) -> Option<WorkRecord> {
        let route = self
            .work
            .config
            .route(route_id)
            .filter(|route| route.revision == revision)?;
        let profile = self.work.config.profile(&route.profile_id)?;
        let me = self.work_host().atem_device_id;
        let permit = host_sender_permits(
            list,
            &me,
            &HostSender {
                host_id: sender,
                admitted: None,
            },
            route,
            HostOp::Task,
        )
        .ok()?;
        let admission = Admission::for_host(list, sender, &permit, route_id, revision)?;
        let principal = host_principal(sender);
        Some(WorkRecord {
            control_gen: self.host.control_gen(&principal),
            principal,
            attachment_owner: String::new(),
            route_id: route_id.to_owned(),
            route_revision: revision,
            profile_id: profile.id.clone(),
            profile_revision: profile.revision,
            project: profile.project.clone(),
            digest: hw::digest(&serde_json::to_vec(&(digest, &task.task_id)).ok()?),
            status: WorkStatus {
                task_id: task.task_id.clone(),
                receipt_id: uuid::Uuid::new_v4().to_string(),
                state: WorkState::Queued,
                detail: "waiting for a ready agent".into(),
                result: None,
                resolved: None,
            },
            task,
            turn_id: None,
            authorization_expires_at: None,
            message: Some(MessageFrame {
                message_id: message.message_id.clone(),
                mark: None,
            }),
            delegated: Some(admission),
            deadline_passed: false,
        })
    }

    /// Whether an agent recipient's `target` is a session of `record`'s
    /// profile on this host (a channel member's check, `work_allowed`'s:
    /// its process generation, directory, provider and launch project).
    fn host_target_ok(
        &self,
        record: &WorkRecord,
        target: &wire::Target,
        sessions: &BTreeMap<SessionId, BrokerSession>,
    ) -> bool {
        let Some(profile) = self.work.config.profile(&record.profile_id) else {
            return false;
        };
        self.work_host().contains(target)
            && SessionId::parse(&target.session_id)
                .and_then(|id| sessions.get(&id))
                .is_some_and(|s| {
                    s.process_gen == target.process_gen
                        && s.cwd == profile.cwd
                        && s.provider == profile.provider
                        && self.projects.key_of(s.id.as_str()) == Some(profile.project.as_str())
                })
    }

    /// A host sender's `cancel` or `complete` (`result`) of `task_id`
    /// (design II.7), decided in `tx`; false when it waits in the inbox
    /// (its sender's early stops full, ruling R38).
    ///
    /// - Its own task, admitted at its current generation and epoch, from
    ///   a sender that may send now: a cancel finds it `queued` or
    ///   `blocked` (no live attempt) and cancels it (`cancelled before
    ///   submission`); a complete finds it `awaiting_result` with the
    ///   project still covering a task and completes it with the result
    ///   snapshot. Otherwise it isn't reached, and is refused by its own
    ///   object id (ruling R48): `busy` for the task's state, `forbidden`
    ///   when the sender has no authority over it now. Either way the
    ///   message's current status goes to the sender.
    /// - No such task yet: an early stop until its expiry (dropped once
    ///   expired, or when its sender may not send now).
    /// - Another sender's task: nothing, and no status.
    #[allow(clippy::too_many_arguments)]
    fn admit_stop(
        &self,
        tx: &Transaction,
        store: &Store,
        signing: &Signing,
        row: &InboxRow,
        task_id: &str,
        result: Option<&hw::ContextSnapshot>,
        followups: &mut Vec<Followup>,
    ) -> anyhow::Result<bool> {
        let sender = row.sender_host.as_str();
        let list = &signing.list;
        let standing = may_send(list, sender, row.signed_seq);
        let sends = standing.is_some();
        let Some(mut task) = store.work(task_id)? else {
            let Some(standing) = standing else {
                return Ok(true);
            };
            if row.expires_at <= signing.now_d && !signing.anchored {
                return Ok(true);
            }
            let kind = if result.is_some() {
                "complete"
            } else {
                "cancel"
            };
            return admit::keep_stop(tx, row, task_id, kind, standing);
        };
        if task.principal != host_principal(sender) {
            return Ok(true);
        }
        let me = self.work_host().atem_device_id;
        let current = task
            .delegated
            .as_ref()
            .and_then(|adm| adm.host_admitted())
            .filter(|(host_id, admitted)| {
                sends
                    && host_standing(list, host_id, Some((admitted.generation, admitted.epoch)))
                        .is_ok()
            });
        // What isn't reached is answered by its own id too (ruling R48), so
        // the sending host stops resending it: `busy` when the task's state
        // doesn't allow it, `forbidden` when the sender has no authority
        // over the task now.
        let unreached = match current {
            None => Some("forbidden"),
            Some((host_id, admitted)) => match result {
                None => match store.live_attempt(task_id)? {
                    // Ruling R46: an attempt that hasn't started (waiting
                    // `accepted`, or never admitted) is withdrawn after the
                    // commit, as a revoke withdraws it; the task settles
                    // `cancelled` from that.
                    Some(attempt) if !self.attempt_started(&attempt.attempt_id, task_id) => {
                        followups.push(Followup::Withdraw {
                            task_id: task_id.to_owned(),
                            attempt_id: attempt.attempt_id,
                            then: Event::Cancelled,
                        });
                        None
                    }
                    Some(_) => Some("busy"),
                    None if matches!(task.status.state, WorkState::Queued | WorkState::Blocked) => {
                        task.status.state = WorkState::Cancelled;
                        task.status.detail = CANCELLED_BEFORE_SUBMISSION.into();
                        store.save_work(&task)?;
                        None
                    }
                    None => Some("busy"),
                },
                Some(result) if task.status.state == WorkState::AwaitingResult => {
                    if host_task_covered(list, &me, host_id, admitted, HostOp::Task).is_ok() {
                        task.status.state = WorkState::Completed;
                        task.status.result = Some(result.clone());
                        task.status.detail = crate::runtime::host_work::RESULT_PUBLISHED.into();
                        store.save_work(&task)?;
                        None
                    } else {
                        Some("forbidden")
                    }
                }
                Some(_) => Some("busy"),
            },
        };
        let record = match &task.message {
            Some(frame) => store.message(&frame.message_id)?,
            None => None,
        };
        if let Some(record) = record {
            signing.status(tx, store, &record)?;
        }
        if let Some(code) = unreached {
            signing.refusal(tx, sender, &row.object_id, code)?;
        }
        Ok(true)
    }
}

impl HostBridge {
    /// Whether attempt `attempt_id` of `task_id` started: its receipt
    /// `executing` or past it (design I.6.4).
    fn attempt_started(&self, attempt_id: &str, task_id: &str) -> bool {
        self.host
            .attempt_receipt(attempt_id, task_id)
            .is_some_and(|rc| {
                attempt_end(
                    SessionAnswer::Receipt(rc.state, rc.detail.as_deref()),
                    false,
                ) == Some(AttemptEnd::Started)
            })
    }
}

/// Whether the store has room for a message with `tasks` (host work's
/// bounds, as `accept_message` checks them): open messages and tasks
/// within `MAX_RECORDS`, unfinished tasks within `MAX_QUEUED`.
fn room(tx: &Transaction, tasks: &[WorkRecord]) -> anyhow::Result<bool> {
    use crate::runtime::host_work::{MAX_QUEUED, MAX_RECORDS, open_records};
    let queued = tasks.iter().filter(|t| !t.status.state.terminal()).count();
    let unfinished: usize = tx.query_row(
        "SELECT count(*) FROM work WHERE state IN ('queued','blocked','submitting','submitted')",
        [],
        |r| r.get(0),
    )?;
    Ok(open_records(tx, "messages")? < MAX_RECORDS
        && open_records(tx, "work")? + tasks.len() <= MAX_RECORDS
        && unfinished + queued <= MAX_QUEUED)
}
