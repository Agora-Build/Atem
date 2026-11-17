//! (`impl HostBridge`) The sending host's results back (the delegated
//! host-work design II.4.4; host-work-v1 §11.5, "On the sending host"),
//! with the debug-only hook's `host.senders` on; its store is
//! [`results_back`].
//!
//! - **The drain** ([`HostBridge::results_drain`]): every status and result
//!   the mailbox kept (`mailbox_results`) is judged with the shared core's
//!   `accept_result_among` against this host's rows to its sender, before
//!   anything reads it; then, in one `BEGIN IMMEDIATE` transaction, its
//!   effect and its removal from the mailbox's results. A status moves its
//!   row and records the resolution, a refusal refuses its row, a result
//!   records its reply (kept as data when its sender is revoked or
//!   removed). What answers no row is dropped with a runtime.log line,
//!   except a result that may answer a task whose status hasn't come yet:
//!   it waits for it, as do one signed beyond this host's list and one a
//!   local fault left undecided. Run on the pass after the mailbox kept an
//!   object, and once a minute for those that wait.
//! - **The delivery** ([`HostBridge::remote_deliveries`]): a reply `due` is
//!   delivered once, as data, into the session that sent the message, by
//!   stage 1's result delivery (a local task carrying it, its prompt framed
//!   as another host's result), only while its return grant is live (the
//!   session runs on its route, which takes results, the message unexpired,
//!   the task not ended) and its sender is still a host this one takes
//!   work from (`authorized`, not removed, a current project listing both).
//!   Otherwise it is kept as data, with why. A delivery queued but not
//!   started is looked at again each pass: one whose grant or sender no
//!   longer qualifies is cancelled and its reply kept.
use super::*;
use crate::runtime::collab::results::{self, EarlyEnd};
use crate::runtime::delegated::results_back::{self, Candidate, Delivering};
use atem_client::host_mail::receive::reason::{
    DOES_NOT_ANSWER_OUTBOX_ROW, NOT_DELIVERED_SENDER_REMOVED, NOT_DELIVERED_SENDER_REVOKED,
};
use atem_client::host_mail::{
    MailBody, ResultPlain, ResultVerdict, accept_result_among, parse_object,
};
use atem_client::host_principal::host_principal;
use atem_client::membership::{HostSenderState, Membership};
use std::sync::atomic::AtomicU64;

/// Kept results judged per drain, at most (the mailbox keeps 256).
const RESULTS_PER_DRAIN: usize = 256;
/// Replies looked at for delivery per pass, at most.
const DELIVERIES_PER_PASS: usize = 64;
/// Results that wait (their status, a list advance) are judged again at
/// most this often.
const RESULTS_AGAIN_EVERY: Duration = Duration::from_secs(60);

static DROPPED: AtomicU64 = AtomicU64::new(0);
static UNAPPLIED: AtomicU64 = AtomicU64::new(0);

/// What a reply's delivery check found.
enum Check {
    /// Delivered now, on the origin's route.
    Go(
        Box<crate::runtime::collab::results::Origin>,
        Box<OriginRoute>,
    ),
    /// Not now, maybe later (no list read yet, the queue full, a session's
    /// project not read yet).
    Wait,
    /// Never: kept as data, with why.
    Keep(&'static str),
}

use crate::runtime::collab::results::OriginRoute;

/// Why a reply from `host_id` isn't delivered while `list` says so
/// (design II.4.4): revoked (first, when it is removed too), removed, or no
/// current project lists both it and this host (`me`).
fn not_delivered(list: &Membership, me: &str, host_id: &str) -> Option<&'static str> {
    match list.host_sender_state(host_id) {
        Some(HostSenderState::Revoked { .. }) => return Some(NOT_DELIVERED_SENDER_REVOKED),
        None => return Some(NOT_DELIVERED_SENDER_REMOVED),
        Some(HostSenderState::Authorized { .. }) => {}
    }
    if list.host(host_id).is_none() {
        return Some(NOT_DELIVERED_SENDER_REMOVED);
    }
    let shared = list
        .host_projects(host_id)
        .into_iter()
        .any(|name| list.project_hosts(name).contains(&me));
    (!shared).then_some(results_back::NOT_GRANTED)
}

impl HostBridge {
    /// The results pass, each scheduling pass while hosting runs (with
    /// `host.senders` on and the store's tables made): the drain when due,
    /// then the deliveries.
    pub(super) fn results_pass(&mut self, sessions: &BTreeMap<SessionId, BrokerSession>) {
        if !self.senders_on() || self.work.mail_prepared.as_ref() != Some(&self.work_host()) {
            return;
        }
        let due = std::mem::take(&mut self.work.results_due)
            || self
                .work
                .results_drained_at
                .is_none_or(|at| at.elapsed() >= RESULTS_AGAIN_EVERY);
        if due {
            self.results_drain();
        }
        self.remote_deliveries(sessions);
    }

    /// Every result the mailbox kept judged and applied (the module docs).
    pub(super) fn results_drain(&mut self) {
        // Debug builds: held while a test says (`<pty faults>/hold_results`).
        if !self.senders_on() || crate::runtime::test_hooks::results_held() {
            return;
        }
        // Nothing can be judged now (the store isn't this identity's, the
        // list doesn't serve, no `D`): tried again on the next pass (the
        // receiver, which reads this host's key, only once the store is).
        if self.mail_store().is_none() {
            self.work.results_due = true;
            return;
        }
        let Some((list, receiver, now_d)) = self.mail_receiver() else {
            self.work.results_due = true;
            return;
        };
        let Some((store, _)) = self.mail_store() else {
            return;
        };
        let kept = match results_back::kept(&store.db, RESULTS_PER_DRAIN) {
            Ok(kept) => kept,
            Err(error) => {
                super::delegated_mail_pass::log_limited(&UNAPPLIED, || {
                    format!("atem runtime: host senders' results not read ({error:#})")
                });
                return;
            }
        };
        let mut applied_status = false;
        let mut waiting = false;
        for (hash, bytes) in kept {
            let judged = (|| -> anyhow::Result<Judged> {
                let Ok(object) = parse_object(&bytes) else {
                    return Ok(Judged::Drop("its bytes don't read"));
                };
                let Ok((_, body)) = MailBody::from_object(&object) else {
                    return Ok(Judged::Drop("its bytes don't read"));
                };
                let since = now_d.saturating_sub(results_back::CANDIDATES_SINCE_MS);
                let candidates = results_back::candidates(&store.db, &body.sender, since)?;
                if candidates.is_empty() {
                    return Ok(Judged::Drop(DOES_NOT_ANSWER_OUTBOX_ROW));
                }
                let rows: Vec<_> = candidates.iter().map(|c| c.expected.clone()).collect();
                let (verdict, answered) = accept_result_among(
                    &object,
                    &list.membership,
                    &receiver.recipient,
                    &rows,
                    &receiver.provider,
                    now_d,
                );
                Ok(match (verdict, answered) {
                    (ResultVerdict::Accepted { plain, .. }, Some(i)) => Judged::Apply {
                        candidate: candidates[i].clone(),
                        plain,
                        kept: None,
                        at: body.created_at,
                    },
                    (ResultVerdict::NotDelivered { plain, reason, .. }, Some(i)) => Judged::Apply {
                        candidate: candidates[i].clone(),
                        plain,
                        kept: Some(reason),
                        at: body.created_at,
                    },
                    (ResultVerdict::Pending { .. } | ResultVerdict::Unavailable { .. }, _) => {
                        Judged::Wait
                    }
                    // A result for a task whose status hasn't come yet
                    // (statuses and results arrive in any order).
                    (ResultVerdict::RefusedAuthenticated { reason, .. }, _)
                        if reason == DOES_NOT_ANSWER_OUTBOX_ROW
                            && candidates.iter().any(|c| !c.resolved) =>
                    {
                        Judged::Wait
                    }
                    (ResultVerdict::Refused { reason, .. }, _)
                    | (ResultVerdict::RefusedAuthenticated { reason, .. }, _) => {
                        Judged::Drop(reason)
                    }
                    (_, None) => Judged::Drop(DOES_NOT_ANSWER_OUTBOX_ROW),
                })
            })();
            let applied = match judged {
                Ok(Judged::Wait) => {
                    waiting = true;
                    continue;
                }
                Ok(Judged::Drop(reason)) => {
                    super::delegated_mail_pass::log_limited(&DROPPED, || {
                        format!("atem runtime: a host's result refused ({reason}); dropped")
                    });
                    store.immediate().and_then(|tx| {
                        results_back::judged(&tx, &hash)?;
                        Ok(tx.commit()?)
                    })
                }
                Ok(Judged::Apply {
                    candidate,
                    plain,
                    kept,
                    at,
                }) => store.immediate().and_then(|tx| {
                    applied_status |= apply(&tx, &candidate, &plain, kept, at)?;
                    results_back::judged(&tx, &hash)?;
                    Ok(tx.commit()?)
                }),
                Err(error) => Err(error),
            };
            if let Err(error) = applied {
                waiting = true;
                super::delegated_mail_pass::log_limited(&UNAPPLIED, || {
                    format!("atem runtime: a host's result not applied ({error:#}); tried again")
                });
            }
        }
        // A status recorded a resolution a waiting result may answer: the
        // next pass judges it again.
        self.work.results_due = applied_status && waiting;
        self.work.results_drained_at = Some(Instant::now());
        self.mail_observe();
    }

    /// The replies due delivered or kept, and the deliveries queued but not
    /// started looked at again (the module docs). Wall time, as stage 1's
    /// return grants.
    pub(super) fn remote_deliveries(&mut self, sessions: &BTreeMap<SessionId, BrokerSession>) {
        if !self.senders_on() || self.work.mail_prepared.as_ref() != Some(&self.work_host()) {
            return;
        }
        let Some(store) = self.work.store.as_ref() else {
            return;
        };
        let now = host_now().wall_ms;
        let (due, queued) = match (
            results_back::due(&store.db, DELIVERIES_PER_PASS),
            results_back::queued(&store.db),
        ) {
            (Ok(due), Ok(queued)) => (due, queued),
            (Err(error), _) | (_, Err(error)) => {
                super::delegated_mail_pass::log_limited(&UNAPPLIED, || {
                    format!("atem runtime: host senders' replies not read ({error:#})")
                });
                return;
            }
        };
        for d in due {
            let check = self.remote_delivery_check(&d, sessions, now, true);
            if let Err(error) = self.remote_deliver(&d, check) {
                super::delegated_mail_pass::log_limited(&UNAPPLIED, || {
                    format!("atem runtime: a host's reply not delivered ({error:#}); tried again")
                });
            }
        }
        for d in queued {
            let Check::Keep(why) = self.remote_delivery_check(&d, sessions, now, false) else {
                continue;
            };
            let undelivered = (|| -> anyhow::Result<()> {
                let store = self.work.store.as_ref().unwrap();
                let tx = store.immediate()?;
                if let Some(mut task) = d
                    .work_id
                    .as_deref()
                    .map(|id| store.work(id))
                    .transpose()?
                    .flatten()
                    && matches!(task.status.state, WorkState::Queued | WorkState::Blocked)
                {
                    task.status.state = WorkState::Cancelled;
                    task.status.detail = format!("not delivered: {why}");
                    store.save_work(&task)?;
                }
                results_back::keep(&tx, &d, why)?;
                Ok(tx.commit()?)
            })();
            if let Err(error) = undelivered {
                super::delegated_mail_pass::log_limited(&UNAPPLIED, || {
                    format!("atem runtime: a host's reply delivery not ended ({error:#})")
                });
            }
        }
    }

    /// Whether `d`'s reply may be delivered now (`due`: also its expiry and
    /// its task's state; a queued delivery expires and ends by itself).
    fn remote_delivery_check(
        &self,
        d: &Delivering,
        sessions: &BTreeMap<SessionId, BrokerSession>,
        now: u64,
        due: bool,
    ) -> Check {
        let Some(list) = self.send_list() else {
            return Check::Wait;
        };
        let me = self.work_host().atem_device_id;
        if let Some(why) = not_delivered(&list, &me, &d.host_id) {
            return Check::Keep(why);
        }
        let origin = self.work.store.as_ref().and_then(|store| {
            store
                .db
                .query_row(
                    "SELECT record FROM origins WHERE message_id=?1",
                    [&d.message_id],
                    |r| r.get::<_, String>(0),
                )
                .ok()
                .and_then(|o| serde_json::from_str::<results::Origin>(&o).ok())
        });
        let Some(origin) = origin else {
            return Check::Keep(collab_bridge::SENDER_GONE);
        };
        if due && now >= d.expires_at {
            return Check::Keep(results_back::GRANT_EXPIRED);
        }
        if due
            && matches!(
                d.state.as_str(),
                "cancelled" | "expired" | "failed" | "completed"
            )
        {
            return Check::Keep(results_back::TASK_ENDED);
        }
        if origin.route.is_some() && self.project_unread.contains_key(&origin.target.session_id) {
            return Check::Wait;
        }
        if !self.collab_origin_live(&origin, sessions) {
            return Check::Keep(match self.collab_origin_end(&origin, sessions) {
                Some(EarlyEnd::SenderRouteChanged) => collab_bridge::SENDER_ROUTE_CHANGED,
                _ => collab_bridge::SENDER_GONE,
            });
        }
        let Some(route) = origin.route.clone().filter(|r| r.results) else {
            return Check::Keep(results_back::NO_RESULTS);
        };
        Check::Go(Box::new(origin), Box::new(route))
    }

    /// `d`'s reply delivered as `check` says: a local task carrying it into
    /// the origin session (stage 1's result delivery), or kept; one that
    /// can't be carried is kept with why (`result could not be delivered:
    /// …`); a full queue only delays it.
    fn remote_deliver(&self, d: &Delivering, check: Check) -> anyhow::Result<()> {
        let store = self.work.store.as_ref().unwrap();
        let (origin, route) = match check {
            Check::Wait => return Ok(()),
            Check::Keep(why) => {
                let tx = store.immediate()?;
                results_back::keep(&tx, d, why)?;
                return Ok(tx.commit()?);
            }
            Check::Go(origin, route) => (origin, route),
        };
        let Some(reply) = d.reply.as_ref() else {
            return Ok(());
        };
        let task = hw::WorkTask {
            task_id: results::delivery_id(&d.task_id),
            workflow_id: d.workflow_id.clone(),
            target: origin.target.clone(),
            expires_at: d.expires_at,
            prompt: reply.text.clone(),
            context: reply.context.clone(),
            attachments: vec![],
        };
        if let Some(problem) = crate::runtime::collab::task_problem(&task, &self.work_host()) {
            let tx = store.immediate()?;
            results_back::keep(&tx, d, &format!("{}{problem}", results::UNDELIVERED))?;
            return Ok(tx.commit()?);
        }
        if !store.has_room()? {
            return Ok(());
        }
        let tx = store.immediate()?;
        let work_id = task.task_id.clone();
        store.enqueue(&WorkRecord {
            delegated: None,
            deadline_passed: false,
            cancel_id: None,
            principal: "local".into(),
            attachment_owner: Sender::Local.owner(),
            control_gen: origin.control_gen,
            route_id: route.id.clone(),
            route_revision: route.revision,
            profile_id: route.profile_id.clone(),
            profile_revision: route.profile_revision,
            project: route.project.clone(),
            digest: hw::digest(&serde_json::to_vec(&(&reply.result_id, &reply.digest))?),
            status: WorkStatus {
                task_id: work_id.clone(),
                receipt_id: uuid::Uuid::new_v4().to_string(),
                state: WorkState::Queued,
                detail: format!(
                    "a reply from {}; waiting for the originating agent",
                    host_principal(&d.host_id)
                ),
                result: None,
                resolved: None,
            },
            task,
            turn_id: None,
            authorization_expires_at: None,
            message: None,
        })?;
        results_back::delivered(&tx, d, &work_id)?;
        Ok(tx.commit()?)
    }
}

/// What the drain decided about one kept result.
// Short-lived: one per kept result, acted on at once.
#[allow(clippy::large_enum_variant)]
enum Judged {
    /// Applied: `plain` from `candidate`'s host, made at `at`; `kept`: a
    /// revoked or removed sender's, never delivered (why).
    Apply {
        candidate: Candidate,
        plain: ResultPlain,
        kept: Option<&'static str>,
        at: u64,
    },
    /// Left for a later drain.
    Wait,
    /// Dropped (why), never applied.
    Drop(&'static str),
}

/// `plain` applied in `tx` (the module docs). Whether it was a status that
/// applied.
fn apply(
    tx: &rusqlite::Transaction,
    c: &Candidate,
    plain: &ResultPlain,
    kept: Option<&'static str>,
    at: u64,
) -> anyhow::Result<bool> {
    match plain {
        ResultPlain::Status { recipients, .. } => results_back::apply_status(tx, c, recipients, at),
        ResultPlain::Refusal { object_id, refused } => {
            results_back::apply_refusal(tx, c, object_id, refused)?;
            Ok(false)
        }
        ResultPlain::Result { task_id, reply } => {
            results_back::record_reply(tx, c, task_id, reply, kept, at)?;
            Ok(false)
        }
    }
}
