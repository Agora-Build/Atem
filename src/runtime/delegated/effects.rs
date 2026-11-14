//! What a control record does to the delegated tasks the host holds (the
//! delegated host-work design I.5.5 to I.5.7, I.5.9; host-work-v1 §11.1
//! "Application and per-effect results", §11.6): the actions a record's
//! application gives (`Applied::actions`, a re-verified pending record's
//! too), carried out by [`act`] in the record's own transaction (the feed
//! store's `FeedTx`, with the touched parts and the scan cursor), so the
//! record's effects, its intents and the cursor commit together; what can
//! only be done once that transaction committed, the bridge does after the
//! commit ([`Followup`]).
//!
//! - **Revoke** (I.5.5 step 2). Every unstarted task of the principal
//!   (`queued`, `blocked`, held ones included) is `cancelled`, `sender
//!   revoked`. A task whose attempt is live (it may wait `accepted`, or
//!   have reached `executing` a moment ago) isn't settled here: its
//!   withdrawal is asked ([`Followup::Withdraw`], I.5.6), and the task
//!   settles from the withdrawal's result in a following transaction:
//!   cancelled when the attempt never ran, running when it reached
//!   `executing`. So a task never shows `cancelled` while its turn runs
//!   (VII.A test 21). A started task goes on. The principal is fenced
//!   through session-v1's §H where it has attachments ([`Followup::Fence`]),
//!   and its later requests are refused, by the bridge, from the committed
//!   standings.
//! - **Interrupt** (step 3, I.5.7). A durable interrupt intent (reason
//!   `revoke`, the revocation) for each task of the principal whose turn
//!   may run: in its turn (`submitting`, `submitted`, its attempt started),
//!   or with a live attempt, which may have reached `executing` (one still
//!   `accepted` is withdrawn by the intent, and its task cancelled). A task
//!   awaiting its result has no turn left, and one of unknown outcome has
//!   none the host can tie to it (session-v1 R9.14 item 6): neither gets an
//!   intent (Atem's choice: such an intent would be done at once, with no
//!   Esc, as PR 8's reading has it; writing none saves the rows). One per
//!   attempt and revocation: a record that adds nothing writes nothing.
//!   The intents are carried out at once after the commit
//!   ([`Followup::Intents`]), and each scheduling pass until done.
//! - **Hold** (step 4). Unstarted tasks are `blocked`, `paused`; a live
//!   attempt's withdrawal is asked, not counted toward the attempt limit
//!   (I.6.4), and its task paused from it. A hold doesn't hold the session
//!   (§11.6, "Waiting doesn't hold the session").
//! - **Release** (step 4). Tasks `blocked`, `paused` are `queued` again,
//!   and get an attempt through the start check before their deadline (one
//!   past it expires there).
//! - **Cover** (step 5) starts delegated execution for the principal's
//!   future tasks (`classify` reads the feed store's coverage); tasks it
//!   already has keep the rules they were admitted under, so nothing here.
//!
//! A host principal's actions (an interrupt for its `revoke_seq`) find no
//! task: host senders aren't served in step 4 (`host.senders`).
use crate::runtime::delegated::attempts::Attempt;
use crate::runtime::delegated::details;
use crate::runtime::delegated::intents::IntentReason;
use crate::runtime::delegated::start::{Event, WAITING_FOR_A_READY_AGENT};
use crate::runtime::host_work::{Store, WorkRecord};
use anyhow::Result;
use atem_client::control::HostAction;
use atem_client::session::host_work::WorkState;
use rusqlite::Transaction;

/// What a record's effects ask of the bridge once their transaction
/// committed (none of it is in the record's transaction: the session host
/// isn't the store).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Followup {
    /// Task `task_id`'s live attempt `attempt_id` is withdrawn in the session
    /// host (I.5.6), and the task settles from the withdrawal in a following
    /// transaction: `then`'s state ([`Event::outcome`]: `cancelled` for a
    /// revoke, `blocked`, `paused` for a hold, its withdrawal not counted)
    /// when the attempt never ran; running when it reached `executing`.
    Withdraw {
        task_id: String,
        attempt_id: String,
        then: Event,
    },
    /// `principal` was revoked: session-v1's §H fence where it has
    /// attachments (its `control_gen` raised, its attachments fenced).
    Fence { principal: String },
    /// Interrupt intents were written for `principal`'s tasks for
    /// `revocation` (I.5.7): carried out at once.
    Intents {
        principal: String,
        revocation: String,
    },
}

/// Carries out `actions` (one record's, in its order) on the delegated
/// tasks `store` holds, in `tx`, the record's own transaction (the feed
/// store's `FeedTx`): the tasks' states and the intents are written there;
/// what must wait for its commit is returned ([`Followup`]). An error fails
/// the transaction: nothing of the record applies, and it is applied again
/// to the state kept.
///
/// (Task 35's sketch returned the followups alone; a write in the record's
/// transaction can fail, so it returns a `Result`.)
pub fn act(store: &Store, tx: &Transaction, actions: &[HostAction]) -> Result<Vec<Followup>> {
    let mut out = Vec::new();
    // Each principal's tasks read once per record (a record's actions are
    // its own principal's), and changed in place as its actions go (review
    // m4).
    let mut read: Vec<(String, Vec<Task>)> = Vec::new();
    for action in actions {
        let principal = match action {
            HostAction::Revoke(p) | HostAction::Hold(p) | HostAction::Release(p) => p,
            HostAction::Interrupt { principal, .. } => principal,
            HostAction::Cover { .. } => continue,
        };
        let i = match read.iter().position(|(p, _)| p == principal) {
            Some(i) => i,
            None => {
                read.push((principal.clone(), tasks_of(store, principal)?));
                read.len() - 1
            }
        };
        let tasks = &mut read[i].1;
        match action {
            HostAction::Revoke(_) => {
                stop(store, tx, tasks, Event::Revoked, &mut out)?;
                out.push(Followup::Fence {
                    principal: principal.clone(),
                });
            }
            HostAction::Hold(_) => stop(store, tx, tasks, Event::Held, &mut out)?,
            HostAction::Release(_) => release(store, tasks)?,
            HostAction::Interrupt { revocation, .. } => {
                interrupt(store, tx, principal, tasks, revocation, &mut out)?
            }
            HostAction::Cover { .. } => {}
        }
    }
    Ok(out)
}

/// A delegated task a record acts on, with its live attempt.
type Task = (WorkRecord, Option<Attempt>);

/// `principal`'s delegated tasks that wait or run (`queued`, `blocked`,
/// `submitting`, `submitted`), oldest first, each with its live attempt:
/// one read, the principal filtered in SQL (`Store::delegated_active_of`).
fn tasks_of(store: &Store, principal: &str) -> Result<Vec<Task>> {
    let mut out = Vec::new();
    for r in store.delegated_active_of(principal)? {
        let live = store.live_attempt(&r.task.task_id)?;
        out.push((r, live));
    }
    Ok(out)
}

/// A revoke or a hold (`event`) of the principal whose tasks are `tasks`:
/// its unstarted tasks take the event's state now; a task with a live
/// attempt gets its withdrawal asked; a started one goes on. A hold's
/// cause is written with the attempt in `tx` (`Store::hold_withdrawal`), so
/// the attempt's withdrawal isn't counted whoever makes it, the recovery
/// after a crash included (review m5).
fn stop(
    store: &Store,
    tx: &Transaction,
    tasks: &mut [Task],
    event: Event,
    out: &mut Vec<Followup>,
) -> Result<()> {
    let (state, detail) = event.outcome();
    for (r, live) in tasks.iter_mut() {
        if let Some(attempt) = live {
            if event == Event::Held {
                store.hold_withdrawal(tx, &r.task.task_id, &attempt.attempt_id)?;
            }
            out.push(Followup::Withdraw {
                task_id: r.task.task_id.clone(),
                attempt_id: attempt.attempt_id.clone(),
                then: event,
            });
            continue;
        }
        if !matches!(r.status.state, WorkState::Queued | WorkState::Blocked)
            || (r.status.state, r.status.detail.as_str()) == (state, detail)
        {
            continue;
        }
        r.status.state = state;
        r.status.detail = detail.into();
        store.save_work(r)?;
    }
    Ok(())
}

/// A release of the principal whose tasks are `tasks`: its tasks paused
/// (and not live) wait for an attempt again.
fn release(store: &Store, tasks: &mut [Task]) -> Result<()> {
    for (r, live) in tasks.iter_mut() {
        if live.is_some()
            || r.status.state != WorkState::Blocked
            || r.status.detail != details::PAUSED
        {
            continue;
        }
        r.status.state = WorkState::Queued;
        r.status.detail = WAITING_FOR_A_READY_AGENT.into();
        store.save_work(r)?;
    }
    Ok(())
}

/// The interrupt for `principal`'s revocation `revocation`: an intent for
/// each of its tasks (`tasks`) whose turn may run (its live attempt, or the
/// attempt it started).
fn interrupt(
    store: &Store,
    tx: &Transaction,
    principal: &str,
    tasks: &[Task],
    revocation: &str,
    out: &mut Vec<Followup>,
) -> Result<()> {
    let reason = IntentReason::Revoke {
        revocation: revocation.to_string(),
    };
    let mut written = false;
    for (r, live) in tasks {
        let attempt = match (live, r.status.state) {
            (Some(attempt), _) => attempt.attempt_id.clone(),
            // Its attempt started (the current one, `receipt_id`).
            (None, WorkState::Submitting | WorkState::Submitted) => r.status.receipt_id.clone(),
            _ => continue,
        };
        written |= store.write_intent(tx, &r.task.task_id, &attempt, reason.clone())?;
    }
    if written {
        out.push(Followup::Intents {
            principal: principal.to_string(),
            revocation: revocation.to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::delegated::{Admission, DelegatedSender};
    use crate::session_protocol::wire::Target;
    use atem_client::session::host_work::{self as hw, HostTarget, WorkStatus, WorkTask};
    use std::cell::RefCell;

    thread_local! {
        /// The statements this thread ran on a traced store.
        static TRACED: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    }

    fn traced(sql: &str) {
        TRACED.with(|t| t.borrow_mut().push(sql.to_string()));
    }

    fn uuid() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    /// `principal`'s delegated task, `queued`: its id.
    fn task_of(store: &Store, principal: &str) -> String {
        let task_id = uuid();
        let device_id = principal.split_once(':').unwrap().1.to_string();
        let r = WorkRecord {
            principal: principal.into(),
            attachment_owner: String::new(),
            control_gen: 1,
            route_id: "r".into(),
            route_revision: 1,
            profile_id: "p".into(),
            profile_revision: 1,
            project: "local:project".into(),
            digest: hw::digest(task_id.as_bytes()),
            task: WorkTask {
                task_id: task_id.clone(),
                workflow_id: uuid(),
                target: Target {
                    account_id: "acct".into(),
                    atem_device_id: "host".into(),
                    host_trust_gen: 1,
                    session_id: "ses-aaaaaaaaaaaa".into(),
                    process_gen: uuid(),
                },
                expires_at: u64::MAX / 2,
                prompt: "do it".into(),
                context: vec![],
                attachments: vec![],
            },
            status: WorkStatus {
                task_id: task_id.clone(),
                receipt_id: uuid(),
                state: WorkState::Queued,
                detail: WAITING_FOR_A_READY_AGENT.into(),
                result: None,
                resolved: None,
            },
            turn_id: None,
            authorization_expires_at: None,
            message: None,
            deadline_passed: false,
            delegated: Some(Admission {
                principal: principal.into(),
                principal_key: "ab".repeat(32),
                sender: DelegatedSender::Service {
                    device_id,
                    feed: crate::runtime::delegated::FeedRef {
                        origin: "https://station-dev.agora.build".into(),
                        feed_id: "feed-1".into(),
                    },
                },
                feed: None,
                route_id: "r".into(),
                route_revision: 1,
                ops_at_admission: vec!["notify".into(), "prompt".into()],
                scope_at_admission: serde_json::Value::Null,
                grant_expires_at: None,
                device_list_seq: 3,
                projects_matched: vec![],
            }),
        };
        store.enqueue(&r).unwrap();
        task_id
    }

    /// Review m4: a record's actions read the delegated tasks they act on
    /// once, and only its principal's (filtered in SQL, not parsed and
    /// dropped): one read of the work table for a revoke with its
    /// interrupt, naming the principal; another principal's task is left
    /// as it was.
    #[test]
    fn a_records_actions_read_their_principals_tasks_once() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(dir.path()).unwrap();
        store
            .bind(&HostTarget {
                account_id: "acct".into(),
                atem_device_id: "host".into(),
                host_trust_gen: 1,
            })
            .unwrap();
        let mine = task_of(&store, "service:svc-bot");
        let other = task_of(&store, "service:svc-other");
        store.db.trace(Some(traced));
        TRACED.with(|t| t.borrow_mut().clear());
        let actions = [
            HostAction::Revoke("service:svc-bot".into()),
            HostAction::Interrupt {
                principal: "service:svc-bot".into(),
                revocation: "rec-1".into(),
            },
        ];
        let tx = store.immediate().unwrap();
        let followups = act(&store, &tx, &actions).unwrap();
        tx.commit().unwrap();
        let reads: Vec<String> = TRACED.with(|t| {
            t.borrow()
                .iter()
                .filter(|sql| sql.contains("FROM work WHERE"))
                .cloned()
                .collect()
        });
        assert_eq!(reads.len(), 1, "{reads:?}");
        assert!(reads[0].contains("service:svc-bot"), "{}", reads[0]);
        assert_eq!(
            followups,
            [Followup::Fence {
                principal: "service:svc-bot".into()
            }]
        );
        let state = |id: &str| store.work(id).unwrap().unwrap().status.state;
        assert_eq!(state(&mine), WorkState::Cancelled);
        assert_eq!(state(&other), WorkState::Queued);
    }
}
