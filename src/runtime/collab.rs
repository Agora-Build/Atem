//! Local collaboration: immutable resolution, durable outbox and loop limits.

#[path = "collab_results.rs"]
pub mod results;

use super::host_work::{Collab, Store};
use anyhow::{Result, bail};
use atem_client::session::{
    host_work::{HostTarget, WorkTask},
    messages::Message,
    select::{AgentLabels, Label, MAX_AGENTS, Selector},
    wire::MAX_PROMPT_BYTES,
};
use rusqlite::{OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SendRequest {
    pub to: Vec<String>,
    pub text: String,
    #[serde(default)]
    pub memory: Vec<String>,
    #[serde(default)]
    pub vault: Vec<String>,
    #[serde(default)]
    pub launch: bool,
    pub expires_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplyRequest {
    pub task_id: Option<String>,
    pub text: String,
    #[serde(default)]
    pub memory: Vec<String>,
    #[serde(default)]
    pub vault: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub route_id: String,
    pub route_revision: u64,
    pub session_id: String,
    pub process_gen: String,
    pub started_ms: u64,
    pub labels: BTreeSet<Label>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryRow {
    pub atem_id: String,
    pub route_id: String,
    pub labels: Vec<String>,
    pub session_id: Option<String>,
    pub local_consent: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedTask {
    pub task_id: String,
    pub route_id: String,
    pub route_revision: u64,
    pub session_id: String,
    pub process_gen: String,
    pub launch_request_id: Option<String>,
}

pub fn resolve(
    atem_id: &str,
    candidates: &[Candidate],
    selectors: &[Selector],
    budget: u32,
    from_session: &str,
    message_id: &str,
    recipient_id: &str,
) -> Vec<ResolvedTask> {
    let mut ordered: Vec<_> = candidates.iter().collect();
    ordered.sort_by(|a, b| {
        (&a.route_id, a.started_ms, &a.session_id).cmp(&(&b.route_id, b.started_ms, &b.session_id))
    });
    let mut seen = BTreeSet::new();
    ordered
        .into_iter()
        .filter(|a| {
            a.session_id != from_session
                && selectors.iter().any(|s| {
                    s.matches(&AgentLabels {
                        atem_id,
                        route_id: &a.route_id,
                        labels: &a.labels,
                    })
                })
                && seen.insert(a.session_id.clone())
        })
        .take(budget.min(MAX_AGENTS) as usize)
        .map(|a| ResolvedTask {
            task_id: uuid::Uuid::new_v5(
                &uuid::Uuid::NAMESPACE_OID,
                &serde_json::to_vec(&(message_id, recipient_id, &a.session_id)).unwrap(),
            )
            .to_string(),
            route_id: a.route_id.clone(),
            route_revision: a.route_revision,
            session_id: a.session_id.clone(),
            process_gen: a.process_gen.clone(),
            launch_request_id: None,
        })
        .collect()
}

/// An hour row's window: the rolling hour after its message.
const HOUR_MS: u64 = 3_600_000;

/// A workflow's row lasts two days from the latest message it counted: no
/// message lives longer than a day, and a turn one of them started may
/// outlast it. After that, nothing can send under the workflow any more.
const WORKFLOW_WINDOW_MS: u64 = 2 * atem_client::session::host_work::MAX_LIFETIME_MS;

/// Counts `amount` messages in the row of `key` whose window starts at
/// `window`.
fn count(
    tx: &Transaction<'_>,
    key: &str,
    window: u64,
    amount: u32,
    limit: u32,
    detail: &str,
) -> Result<()> {
    let previous: u32 = tx
        .query_row(
            "SELECT count FROM counters WHERE key=?1 AND window_start_ms=?2",
            params![key, window],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or(0);
    if previous.checked_add(amount).is_none_or(|n| n > limit) {
        bail!("limit: {limit} {detail}");
    }
    tx.execute(
        "INSERT INTO counters(key,window_start_ms,count) VALUES(?1,?2,?3)
        ON CONFLICT(key,window_start_ms) DO UPDATE SET count=excluded.count",
        params![key, window, previous + amount],
    )?;
    Ok(())
}

/// Counts `amount` messages of a workflow (`key`): one row for the whole
/// workflow, whose window starts at the latest message it counted (`now`;
/// never moved back by a message accepted late).
fn count_workflow(
    tx: &Transaction<'_>,
    key: &str,
    now: u64,
    amount: u32,
    limit: u32,
) -> Result<()> {
    let (previous, since): (u32, u64) = tx.query_row(
        "SELECT coalesce(sum(count),0),coalesce(max(window_start_ms),0) FROM counters WHERE key=?1",
        [key],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if previous.checked_add(amount).is_none_or(|n| n > limit) {
        bail!("limit: {limit} messages per workflow");
    }
    tx.execute("DELETE FROM counters WHERE key=?1", [key])?;
    tx.execute(
        "INSERT INTO counters(key,window_start_ms,count) VALUES(?1,?2,?3)",
        params![key, since.max(now), previous + amount],
    )?;
    Ok(())
}

pub(super) fn count_send(
    tx: &Transaction<'_>,
    config: &Collab,
    from: &str,
    workflow: &str,
    now: u64,
) -> Result<()> {
    prune_counters(tx, now)?;
    // Rolling hourly windows avoid a double burst at a clock-hour boundary.
    let total: u32 = tx.query_row(
        "SELECT coalesce(sum(count),0) FROM counters WHERE key=?1 AND window_start_ms>?2",
        params![format!("hour:{from}"), now.saturating_sub(HOUR_MS)],
        |r| r.get(0),
    )?;
    if total >= config.per_hour {
        bail!("limit: {} messages per hour", config.per_hour);
    }
    count_workflow(tx, &format!("send:{workflow}"), now, 1, config.per_workflow)?;
    count(
        tx,
        &format!("hour:{from}"),
        now,
        1,
        config.per_hour,
        "messages per hour",
    )
}

/// A message counts once toward what a workflow may receive, however many
/// agents it reaches. Results are not messages here and count against nothing.
pub(super) fn count_received(
    tx: &Transaction<'_>,
    config: &Collab,
    workflow: &str,
    now: u64,
) -> Result<()> {
    count_workflow(
        tx,
        &format!("receive:{workflow}"),
        now,
        1,
        config.per_workflow,
    )
}

/// Removes the counter rows whose window has passed (spec section 6): an
/// hour row an hour after its message, a workflow's row two days after its
/// latest message. Deletes nothing (and writes nothing) when none has.
pub(super) fn prune_counters(db: &rusqlite::Connection, now: u64) -> Result<()> {
    db.execute(
        "DELETE FROM counters WHERE window_start_ms <=
        CASE WHEN key LIKE 'hour:%' THEN ?1 ELSE ?2 END",
        params![
            now.saturating_sub(HOUR_MS),
            now.saturating_sub(WORKFLOW_WINDOW_MS)
        ],
    )?;
    Ok(())
}

/// Would one more message fit the sender's limits? Nothing is recorded: the
/// counting transaction is dropped, which rolls it back. A send with context
/// is counted only when it is accepted, after publication, so the ones still
/// `publishing` count here for the sender and for the workflow: a loop of
/// them is refused at send, not left to queue up and publish.
pub(super) fn check_send(
    store: &Store,
    config: &Collab,
    from: &str,
    workflow: &str,
    now: u64,
) -> Result<()> {
    let tx = store.db.unchecked_transaction()?;
    let in_flight = |field: &str, value: &str| -> Result<u32> {
        Ok(tx.query_row(
            &format!(
                "SELECT count(*) FROM outbox WHERE state='publishing'
                AND json_extract(envelope,'$.kind') IS NULL
                AND json_extract(envelope,'$.{field}')=?1"
            ),
            [value],
            |r| r.get(0),
        )?)
    };
    let (sender, flow) = (
        in_flight("from_session", from)?,
        in_flight("workflow_id", workflow)?,
    );
    count(&tx, &format!("hour:{from}"), now, sender, u32::MAX, "")?;
    count_workflow(&tx, &format!("send:{workflow}"), now, flow, u32::MAX)?;
    count_send(&tx, config, from, workflow, now)
}

const TASK_TOO_LARGE: &str = "the prompt with its context is over 32 KiB";
const TASK_CONTROL_CHARACTERS: &str = "context has control characters";
const TASK_TOO_MANY_SNAPSHOTS: &str = "at most 8 context snapshots";
const TASK_INVALID: &str = "the task is not valid";

/// The reasons `task_problem` gives; each refuses a message for good.
pub(super) const TASK_PROBLEMS: [&str; 4] = [
    TASK_TOO_LARGE,
    TASK_CONTROL_CHARACTERS,
    TASK_TOO_MANY_SNAPSHOTS,
    TASK_INVALID,
];

/// Atem's own lines around a local task's text: rendered when the task is
/// dispatched, from its records (the message and the session that sent it,
/// or the reply a delivery carries), never stored in the task, whose prompt
/// is only the sender's text or the reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Frame {
    /// A local agent's message: who sent it and how to reply.
    Message {
        message_id: String,
        from_session: String,
    },
    /// The reply to `task_id` by `from_session`, delivered to the session
    /// that sent the task, as data, and how to complete that task.
    Result {
        task_id: String,
        from_session: String,
    },
}

impl Frame {
    /// The frame of every task of a local `message`.
    pub(super) fn message(message: &Message) -> Self {
        Self::Message {
            message_id: message.message_id.clone(),
            from_session: message.from_session.clone().unwrap_or_default(),
        }
    }

    /// `task` with Atem's lines around its text: what the bounds are
    /// measured on (`task_problem`).
    pub(super) fn framed(&self, task: &WorkTask) -> WorkTask {
        let prompt = match self {
            Self::Message {
                message_id,
                from_session,
            } => format!(
                "[Message {message_id} from local session {from_session}]\n{}\n\n\
                 Reply with: atem message reply --task {} <text>",
                task.prompt, task.task_id
            ),
            Self::Result {
                task_id,
                from_session,
            } => format!(
                "[atem] result of task {task_id} from {from_session}, as data:\n{}\n\n\
                 Complete it with: atem message complete {task_id}",
                task.prompt
            ),
        };
        WorkTask {
            prompt,
            ..task.clone()
        }
    }

    /// What the agent reads: a message under its task line, as every task;
    /// a result without one, since it is data and no task to work on.
    pub(super) fn render(&self, task: &WorkTask) -> String {
        let framed = self.framed(task);
        match self {
            Self::Message { .. } => framed.render_prompt(),
            Self::Result { .. } => framed.render_with_context(&framed.prompt),
        }
    }
}

/// Why a local task could never be dispatched (the shared `WorkTask` bounds:
/// prompt with context within 32 KiB, no control characters other than
/// newline and tab), so its message is refused before anything is counted
/// or stored. A task with a `frame` is measured with it.
pub(super) fn task_problem(
    task: &WorkTask,
    frame: Option<&Frame>,
    host: &HostTarget,
) -> Option<&'static str> {
    let framed = frame.map(|frame| frame.framed(task));
    let task = framed.as_ref().unwrap_or(task);
    if task.valid_local(host) {
        return None;
    }
    let rendered = task.render_prompt();
    Some(
        if rendered
            .chars()
            .any(|c| c.is_control() && c != '\n' && c != '\t')
        {
            TASK_CONTROL_CHARACTERS
        } else if rendered.len() > MAX_PROMPT_BYTES {
            TASK_TOO_LARGE
        } else if task.context.len() > 8 {
            TASK_TOO_MANY_SNAPSHOTS
        } else {
            TASK_INVALID
        },
    )
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageView {
    pub message_id: String,
    pub workflow_id: String,
    pub delivery: String,
    pub detail: String,
    pub tasks: Vec<TaskView>,
}

/// A task's reply: its one result row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResultView {
    pub result_id: String,
    pub state: results::ReplyState,
    pub detail: String,
    pub text: String,
    /// The context it carries once published.
    pub context: Vec<atem_client::session::messages::ContextReference>,
    /// Its text is no longer kept (a day after its task settled past its
    /// deadline); its context references still are.
    #[serde(default)]
    pub dropped: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskView {
    pub task_id: String,
    pub receipt_id: String,
    pub session_id: String,
    pub route_id: String,
    pub state: atem_client::session::host_work::WorkState,
    pub detail: String,
    pub result: Option<ResultView>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct Publication {
    pub atem_id: String,
    pub origin: results::Origin,
    /// The sender's `--launch`, kept until the message is accepted.
    pub launch: bool,
    pub context: Vec<super::collab_context::ContextSpec>,
}

impl Publication {
    /// Drops the text of the memories it was to publish
    /// (`Store::drop_payloads`, a send never accepted).
    pub(super) fn drop_payload(&mut self) {
        for spec in &mut self.context {
            spec.drop_payload();
        }
    }
}

pub(super) fn reserve_context(
    store: &Store,
    config: &Collab,
    message: &Message,
    publication: &Publication,
) -> Result<()> {
    if let Some((envelope, record)) = store.db.query_row("SELECT o.envelope,p.record FROM outbox o JOIN publications p USING(message_id) WHERE o.message_id=?1",
        [&message.message_id], |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?))).optional()? {
        let previous: Message = serde_json::from_str(&envelope)?;
        let previous_publication: Publication = serde_json::from_str(&record)?;
        if previous.text != message.text || previous.reply_to != message.reply_to || previous.from_session != message.from_session
            || previous.workflow_id != message.workflow_id || previous_publication.origin.target != publication.origin.target
            || serde_json::to_value(previous_publication.context)? != serde_json::to_value(&publication.context)? {
            bail!("request_id_reused");
        }
        return Ok(());
    }
    // A request is counted when it is accepted, and may still turn out to be
    // refused then; checking now only tells the sender early.
    check_send(
        store,
        config,
        message.from_session.as_deref().unwrap(),
        &message.workflow_id,
        message.created_at,
    )?;
    let tx = store.db.unchecked_transaction()?;
    if super::host_work::open_records(&tx, "outbox")? >= super::host_work::MAX_RECORDS {
        bail!("outbox capacity reached");
    }
    tx.execute(
        "INSERT INTO outbox(message_id,envelope,state,detail,next_try_ms,created_ms)
        VALUES(?1,?2,'publishing','waiting for verified context publication',0,?3)",
        params![
            message.message_id,
            serde_json::to_string(message)?,
            message.created_at
        ],
    )?;
    tx.execute(
        "INSERT INTO publications(message_id,record) VALUES(?1,?2)",
        params![message.message_id, serde_json::to_string(publication)?],
    )?;
    tx.commit()?;
    Ok(())
}

pub(super) fn context_due(store: &Store, now: u64) -> Result<Vec<(Message, Publication, u32)>> {
    let mut q = store.db.prepare(
        "SELECT o.envelope,p.record,p.attempts FROM outbox o
        CROSS JOIN publications p ON p.message_id=o.message_id
        WHERE o.state='publishing' AND o.next_try_ms<=?1 ORDER BY o.created_ms LIMIT 16",
    )?;
    q.query_map([now], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, u32>(2)?,
        ))
    })?
    .map(|r| {
        let (m, p, n) = r?;
        Ok((serde_json::from_str(&m)?, serde_json::from_str(&p)?, n))
    })
    .collect()
}

pub(super) fn publication_state(
    store: &Store,
    id: &str,
    state: &str,
    detail: &str,
    retry: u64,
) -> Result<()> {
    store.db.execute(
        "UPDATE outbox SET state=?2,detail=?3,next_try_ms=?4 WHERE message_id=?1",
        params![id, state, detail, retry],
    )?;
    Ok(())
}

pub(super) fn persist(
    tx: &Transaction<'_>,
    message: &Message,
    resolution: &[ResolvedTask],
) -> Result<()> {
    tx.execute(
        "INSERT INTO outbox(message_id,envelope,state,detail,next_try_ms,created_ms)
        VALUES(?1,?2,'accepted',?3,0,?4)
        ON CONFLICT(message_id) DO UPDATE SET envelope=excluded.envelope,state='accepted',detail=excluded.detail,next_try_ms=0",
        params![
            message.message_id,
            serde_json::to_string(message)?,
            if resolution.is_empty() {
                "no_match"
            } else {
                "delivered to local queue"
            },
            message.created_at
        ],
    )?;
    tx.execute(
        "DELETE FROM publications WHERE message_id=?1",
        [&message.message_id],
    )?;
    for r in resolution {
        tx.execute("INSERT INTO resolutions(message_id,recipient_id,task_id,route_id,session_id,process_gen,launch_request_id,record)
            VALUES(?1,?2,?3,?4,?5,?6,?7,?8)", params![message.message_id, message.recipients[0].recipient_id,
            r.task_id, r.route_id, r.session_id, r.process_gen, r.launch_request_id, serde_json::to_string(r)?])?;
    }
    Ok(())
}

/// The reservation that made `session_id` a launched session: the task's
/// resolution carrying the launch request id, if a local message started it.
pub(super) fn launched_by(store: &Store, session_id: &str) -> Result<Option<ResolvedTask>> {
    store
        .db
        .query_row(
            "SELECT record FROM resolutions WHERE session_id=?1 AND launch_request_id IS NOT NULL
            LIMIT 1",
            [session_id],
            |r| r.get::<_, String>(0),
        )
        .optional()?
        .map(|record| Ok(serde_json::from_str(&record)?))
        .transpose()
}

/// The session that sent the local message of task `task_id`, if any.
pub(super) fn sender_of(store: &Store, task_id: &str) -> Result<Option<String>> {
    Ok(store
        .db
        .query_row(
            "SELECT json_extract(o.envelope,'$.from_session') FROM resolutions r
            JOIN outbox o USING(message_id) WHERE r.task_id=?1",
            [task_id],
            |r| r.get::<_, Option<String>>(0),
        )
        .optional()?
        .flatten())
}

/// The frame of local task `task_id` (`Frame::Message`): its message and
/// the session that sent it. None for a task no local send made.
pub(super) fn message_frame(store: &Store, task_id: &str) -> Result<Option<Frame>> {
    Ok(store
        .db
        .query_row(
            "SELECT r.message_id,json_extract(o.envelope,'$.from_session') FROM resolutions r
            JOIN outbox o USING(message_id) WHERE r.task_id=?1",
            [task_id],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?)),
        )
        .optional()?
        .and_then(|(message_id, from_session)| {
            Some(Frame::Message {
                message_id,
                from_session: from_session?,
            })
        }))
}

/// `views`' messages: message `?1` by its primary key, or the 32 newest
/// (`outbox_created`); with a scope `?2`, only those the session sent or
/// with a task sent to it. `+r.session_id` keeps that check on
/// `resolution_message`, one probe per message: through
/// `resolution_session` it would read all of the session's resolutions for
/// every message.
const STATUS_BY_ID: &str = "SELECT message_id,envelope,state,detail FROM outbox o
    WHERE message_id=?1 AND (?2 IS NULL OR json_extract(envelope,'$.from_session')=?2
        OR EXISTS(SELECT 1 FROM resolutions r
            WHERE r.message_id=o.message_id AND +r.session_id=?2))";
const STATUS_LATEST: &str = "SELECT message_id,envelope,state,detail FROM outbox o
    WHERE (?2 IS NULL OR json_extract(envelope,'$.from_session')=?2
        OR EXISTS(SELECT 1 FROM resolutions r
            WHERE r.message_id=o.message_id AND +r.session_id=?2))
    ORDER BY created_ms DESC,rowid DESC LIMIT 32";

/// The latest 32 messages (or message `id`), bounded to 1 MiB. With a
/// `scope` (the calling session): the messages it sent, with all their
/// tasks, and the messages with a task sent to it, with that task only.
pub(super) fn views(
    store: &Store,
    id: Option<&str>,
    scope: Option<&str>,
) -> Result<Vec<MessageView>> {
    let mut query = store.db.prepare(if id.is_some() {
        STATUS_BY_ID
    } else {
        STATUS_LATEST
    })?;
    let rows = query.query_map(params![id, scope], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
        ))
    })?;
    let views = rows
        .map(|row| {
            let (message_id, envelope, delivery, detail) = row?;
            let message: Message = serde_json::from_str(&envelope)?;
            // Another session's message: only the task sent to `scope`.
            let only = scope.filter(|s| message.from_session.as_deref() != Some(*s));
            let mut q = store.db.prepare(
                "SELECT task_id FROM resolutions WHERE message_id=?1
                AND (?2 IS NULL OR session_id=?2) ORDER BY rowid",
            )?;
            let tasks = q
                .query_map(params![&message_id, only], |r| r.get::<_, String>(0))?
                .map(|id| {
                    let r = store
                        .work(&id?)?
                        .ok_or_else(|| anyhow::anyhow!("missing resolved task"))?;
                    let result = results::load(&store.db, &r.task.task_id)?.map(|row| ResultView {
                        context: row
                            .reply
                            .context
                            .iter()
                            .map(|c| atem_client::session::messages::ContextReference {
                                kind: c.kind,
                                id: c.id.clone(),
                                version: c.version,
                                digest: c.digest.clone(),
                            })
                            .collect(),
                        result_id: row.result_id,
                        state: row.state,
                        detail: row.detail,
                        text: row.reply.text,
                        dropped: row.reply.dropped,
                    });
                    Ok(TaskView {
                        task_id: r.status.task_id,
                        receipt_id: r.status.receipt_id,
                        session_id: r.task.target.session_id,
                        route_id: r.route_id,
                        state: r.status.state,
                        detail: r.status.detail,
                        result,
                    })
                })
                .collect::<Result<_>>()?;
            Ok(MessageView {
                message_id,
                workflow_id: message.workflow_id,
                delivery,
                detail,
                tasks,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let mut bounded = Vec::new();
    let mut size = 0;
    for view in views {
        size += serde_json::to_vec(&view)?.len();
        if size > 1024 * 1024 {
            break;
        }
        bounded.push(view);
    }
    Ok(bounded)
}

pub(super) fn save_tags(
    state: &std::path::Path,
    session: &super::broker::BrokerSession,
) -> Result<()> {
    super::worker::write_atomic(
        &state.join(format!("collab-tags-{}.json", session.id)),
        &serde_json::to_vec(&(&session.process_gen, session.self_tags()))?,
    )?;
    Ok(())
}

/// A removed session's tags go with it.
pub(super) fn remove_tags(state: &std::path::Path, session_id: &str) {
    let _ = std::fs::remove_file(state.join(format!("collab-tags-{session_id}.json")));
}

pub(super) fn restore_tags(state: &std::path::Path, session: &mut super::broker::BrokerSession) {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let Ok(file) = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(state.join(format!("collab-tags-{}.json", session.id)))
    else {
        return;
    };
    let mut bytes = Vec::new();
    if file.take(4097).read_to_end(&mut bytes).is_err() || bytes.len() > 4096 {
        return;
    }
    let Ok((generation, tags)) = serde_json::from_slice::<(String, BTreeSet<String>)>(&bytes)
    else {
        return;
    };
    if generation != session.process_gen
        || tags.len() > 16
        || tags
            .iter()
            .any(|t| super::host_work::label_problem(t, false).is_some())
    {
        return;
    }
    for tag in tags {
        let _ = session.add_tag(tag);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use atem_client::session::{
        host_work::{ContextKind, ContextSnapshot, HostTarget, WorkTask},
        wire,
    };

    #[test]
    fn resolution_is_ordered_budgeted_and_stable() {
        let labels: BTreeSet<Label> = ["tag:a".parse().unwrap()].into_iter().collect();
        let agents: Vec<_> = (0..40)
            .rev()
            .map(|n| Candidate {
                route_id: "a".into(),
                route_revision: 1,
                session_id: format!("session-{n}"),
                process_gen: "process".into(),
                started_ms: n,
                labels: labels.clone(),
            })
            .collect();
        let selectors = vec!["tag:a".parse().unwrap(), "atem:host/a".parse().unwrap()];
        let message = uuid::Uuid::new_v4().to_string();
        let recipient = uuid::Uuid::new_v4().to_string();
        let tasks = resolve(
            "host",
            &agents,
            &selectors,
            32,
            "session-0",
            &message,
            &recipient,
        );
        assert_eq!(tasks.len(), 32);
        assert_eq!(tasks[0].session_id, "session-1");
        assert_eq!(
            tasks,
            resolve(
                "host",
                &agents,
                &selectors,
                32,
                "session-0",
                &message,
                &recipient
            )
        );
        assert_eq!(
            tasks
                .iter()
                .map(|t| &t.session_id)
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            32
        );
        assert!(
            uuid::Uuid::parse_str(&tasks[0].task_id)
                .unwrap()
                .get_version_num()
                == 5
        );
    }

    #[test]
    fn limits_survive_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let config = super::super::host_work::Collab {
            per_hour: 2,
            ..Default::default()
        };
        let store = Store::open(dir.path()).unwrap();
        for flow in ["one", "two"] {
            let tx = store.db.unchecked_transaction().unwrap();
            count_send(&tx, &config, "session", flow, 1_000).unwrap();
            tx.commit().unwrap();
        }
        drop(store);
        let store = Store::open(dir.path()).unwrap();
        let tx = store.db.unchecked_transaction().unwrap();
        assert_eq!(
            count_send(&tx, &config, "session", "three", 1_001)
                .unwrap_err()
                .to_string(),
            "limit: 2 messages per hour"
        );
    }

    fn counted(store: &Store, key: &str) -> u32 {
        store
            .db
            .query_row(
                "SELECT coalesce(sum(count),0) FROM counters WHERE key=?1",
                [key],
                |r| r.get(0),
            )
            .unwrap()
    }

    /// What accepting one message does to the counters, however many agents
    /// it reaches (`HostBridge::collab_accept`).
    fn accept_one(store: &Store, config: &Collab, from: &str) -> Result<()> {
        let tx = store.db.unchecked_transaction()?;
        count_send(&tx, config, from, "flow", 1_000)?;
        count_received(&tx, config, "flow", 1_000)?;
        Ok(tx.commit()?)
    }

    #[test]
    fn the_workflow_limit_counts_messages_once_each_way() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let config = Collab::default();
        assert_eq!(config.per_workflow, 8);
        for n in 0..8 {
            accept_one(&store, &config, &format!("session-{n}")).unwrap();
        }
        assert_eq!(counted(&store, "send:flow"), 8);
        assert_eq!(counted(&store, "receive:flow"), 8);
        assert_eq!(
            accept_one(&store, &config, "session-9")
                .unwrap_err()
                .to_string(),
            "limit: 8 messages per workflow"
        );
        // The refused ninth message changed nothing.
        assert_eq!(counted(&store, "send:flow"), 8);
        assert_eq!(counted(&store, "receive:flow"), 8);
        assert_eq!(counted(&store, "hour:session-9"), 0);
    }

    #[test]
    fn the_receive_limit_also_speaks_of_messages() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let config = Collab {
            per_workflow: 2,
            ..Default::default()
        };
        for _ in 0..2 {
            let tx = store.db.unchecked_transaction().unwrap();
            count_received(&tx, &config, "flow", 1_000).unwrap();
            tx.commit().unwrap();
        }
        let tx = store.db.unchecked_transaction().unwrap();
        assert_eq!(
            count_received(&tx, &config, "flow", 1_000)
                .unwrap_err()
                .to_string(),
            "limit: 2 messages per workflow"
        );
    }

    #[test]
    fn checking_a_send_records_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let config = Collab {
            per_workflow: 1,
            ..Default::default()
        };
        for _ in 0..3 {
            check_send(&store, &config, "session", "flow", 1_000).unwrap();
        }
        assert_eq!(counted(&store, "send:flow"), 0);
        assert_eq!(counted(&store, "hour:session"), 0);
        accept_one(&store, &config, "session").unwrap();
        assert!(check_send(&store, &config, "session", "flow", 1_000).is_err());
    }

    /// Sends with context count when they are accepted, after publication;
    /// until then the ones still publishing bound the sender and the workflow.
    #[test]
    fn checking_a_send_counts_context_sends_still_publishing() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let config = Collab {
            per_hour: 3,
            per_workflow: 3,
            ..Default::default()
        };
        let row = |id: &str, from: &str, workflow: &str, state: &str, kind: Option<&str>| {
            let mut envelope = serde_json::json!({"workflow_id": workflow, "from_session": from});
            if let Some(kind) = kind {
                envelope["kind"] = kind.into();
            }
            store
                .db
                .execute(
                    "INSERT INTO outbox(message_id,envelope,state,detail,next_try_ms,created_ms)
                    VALUES(?1,?2,?3,'',0,0)",
                    params![id, envelope.to_string(), state],
                )
                .unwrap();
        };
        row("m1", "session", "flow-a", "publishing", None);
        row("m2", "session", "flow-b", "publishing", None);
        row("m3", "other", "flow-a", "publishing", None);
        // A result, a refused row and an accepted one (the counters hold it)
        // are not in flight.
        row("m4", "session", "flow-a", "publishing", Some("result"));
        row("m5", "session", "flow-a", "refused", None);
        row("m6", "session", "flow-a", "accepted", None);
        check_send(&store, &config, "session", "flow-c", 1_000).unwrap();
        check_send(&store, &config, "session", "flow-a", 1_000).unwrap();
        check_send(&store, &config, "other", "flow-a", 1_000).unwrap();
        row("m7", "session", "flow-c", "publishing", None);
        assert_eq!(
            check_send(&store, &config, "session", "flow-z", 1_000)
                .unwrap_err()
                .to_string(),
            "limit: 3 messages per hour"
        );
        row("m8", "another", "flow-a", "publishing", None);
        assert_eq!(
            check_send(&store, &config, "other", "flow-a", 1_000)
                .unwrap_err()
                .to_string(),
            "limit: 3 messages per workflow"
        );
        // Nothing was recorded by checking.
        assert_eq!(counted(&store, "send:flow-a"), 0);
        assert_eq!(counted(&store, "hour:session"), 0);
    }

    fn local_task(prompt: &str, context: Vec<ContextSnapshot>) -> WorkTask {
        WorkTask {
            task_id: "6ba7b810-9dad-51d1-80b4-00c04fd430c8".into(),
            workflow_id: uuid::Uuid::new_v4().to_string(),
            target: wire::Target {
                account_id: "account".into(),
                atem_device_id: "host".into(),
                host_trust_gen: 1,
                session_id: "ses-aaaaaaaaaaaa".into(),
                process_gen: uuid::Uuid::new_v4().to_string(),
            },
            expires_at: 1,
            prompt: prompt.into(),
            context,
            attachments: vec![],
        }
    }

    fn snapshot(text: &str) -> ContextSnapshot {
        ContextSnapshot {
            kind: ContextKind::Vault,
            id: "v-context:1".into(),
            version: 1,
            digest: atem_client::session::host_work::digest(text.as_bytes()),
            text: text.into(),
        }
    }

    /// Atem's lines around a local task's text and a delivered reply come
    /// from their frame, rendered as they were once stored in the prompt (a
    /// result without the task line); the prompt keeps only the text, and
    /// the bounds are measured with the frame.
    #[test]
    fn frames_render_the_lines_atem_wrote_before() {
        let mut task = local_task("Review the API contract", vec![snapshot("The contract.")]);
        let (id, workflow) = (task.task_id.clone(), task.workflow_id.clone());
        let block = format!(
            "\n\n[Context Vault:v-context:1 version 1 sha256 {}]\nThe contract.",
            atem_client::session::host_work::digest(b"The contract.")
        );
        let message = Frame::Message {
            message_id: "11111111-1111-4111-8111-111111111111".into(),
            from_session: "ses-bbbbbbbbbbbb".into(),
        };
        assert_eq!(
            message.render(&task),
            format!(
                "[Atem task {id} / workflow {workflow}]\n\
                 [Message 11111111-1111-4111-8111-111111111111 from local session \
                 ses-bbbbbbbbbbbb]\nReview the API contract\n\n\
                 Reply with: atem message reply --task {id} <text>{block}"
            )
        );
        let result = Frame::Result {
            task_id: "22222222-2222-4222-8222-222222222222".into(),
            from_session: "ses-cccccccccccc".into(),
        };
        assert_eq!(
            result.render(&task),
            format!(
                "[atem] result of task 22222222-2222-4222-8222-222222222222 from \
                 ses-cccccccccccc, as data:\nReview the API contract\n\n\
                 Complete it with: atem message complete \
                 22222222-2222-4222-8222-222222222222{block}"
            )
        );
        assert_eq!(task.prompt, "Review the API contract");
        // A task that fits bare but not framed can never be dispatched.
        let host = HostTarget {
            account_id: "account".into(),
            atem_device_id: "host".into(),
            host_trust_gen: 1,
        };
        task.context = vec![snapshot("")];
        let room = MAX_PROMPT_BYTES - task.render_prompt().len();
        task.context = vec![snapshot(&"x".repeat(room))];
        assert_eq!(task.render_prompt().len(), MAX_PROMPT_BYTES);
        assert_eq!(task_problem(&task, None, &host), None);
        for frame in [&message, &result] {
            assert_eq!(
                task_problem(&task, Some(frame), &host),
                Some("the prompt with its context is over 32 KiB")
            );
        }
    }

    #[test]
    fn a_task_that_could_never_dispatch_names_its_problem() {
        let host = HostTarget {
            account_id: "account".into(),
            atem_device_id: "host".into(),
            host_trust_gen: 1,
        };
        assert_eq!(task_problem(&local_task("work", vec![]), None, &host), None);
        assert_eq!(
            task_problem(
                &local_task("work", vec![snapshot("fine\n\tlines")]),
                None,
                &host
            ),
            None
        );
        assert_eq!(
            task_problem(
                &local_task("work", vec![snapshot(&"x".repeat(40_000))]),
                None,
                &host
            ),
            Some("the prompt with its context is over 32 KiB")
        );
        assert_eq!(
            task_problem(
                &local_task("work", vec![snapshot("escape \u{1b}[2J")]),
                None,
                &host
            ),
            Some("context has control characters")
        );
        let many = (0..9).map(|_| snapshot("same")).collect();
        assert_eq!(
            task_problem(&local_task("work", many), None, &host),
            Some("at most 8 context snapshots")
        );
        let mut elsewhere = host.clone();
        elsewhere.atem_device_id = "other".into();
        assert_eq!(
            task_problem(&local_task("work", vec![]), None, &elsewhere),
            Some("the task is not valid")
        );
        for problem in [
            "the prompt with its context is over 32 KiB",
            "context has control characters",
            "at most 8 context snapshots",
            "the task is not valid",
        ] {
            assert!(TASK_PROBLEMS.contains(&problem), "{problem}");
        }
    }

    fn rows(store: &Store) -> Vec<(String, u64, u32)> {
        let mut q = store
            .db
            .prepare("SELECT key,window_start_ms,count FROM counters ORDER BY key")
            .unwrap();
        q.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
    }

    /// An hour row's window is its hour; a workflow's row lasts while the
    /// workflow may still send (its latest message lives a day at most, and
    /// a turn it started may outlast it): two days from that message.
    #[test]
    fn counter_rows_of_passed_windows_are_pruned() {
        const HOUR: u64 = 3_600_000;
        const DAY: u64 = 24 * HOUR;
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let config = Collab {
            per_workflow: 2,
            ..Default::default()
        };
        let t = 10 * DAY;
        accept_at(&store, &config, "session", "flow", t);
        assert_eq!(
            rows(&store),
            vec![
                ("hour:session".into(), t, 1),
                ("receive:flow".into(), t, 1),
                ("send:flow".into(), t, 1),
            ]
        );
        // The hour passed: its row goes; the workflow still counts.
        prune_counters(&store.db, t + HOUR).unwrap();
        assert_eq!(counted(&store, "hour:session"), 0);
        assert_eq!(counted(&store, "send:flow"), 1);
        // A later message of the workflow moves its window: still one row.
        accept_at(&store, &config, "other", "flow", t + DAY);
        assert_eq!(counted(&store, "send:flow"), 2);
        assert_eq!(counted(&store, "receive:flow"), 2);
        let tx = store.db.unchecked_transaction().unwrap();
        assert_eq!(
            count_send(&tx, &config, "third", "flow", t + DAY + 1)
                .unwrap_err()
                .to_string(),
            "limit: 2 messages per workflow"
        );
        drop(tx);
        // Two days after the first message, the second's window remains.
        prune_counters(&store.db, t + 2 * DAY).unwrap();
        assert_eq!(counted(&store, "send:flow"), 2);
        assert_eq!(counted(&store, "receive:flow"), 2);
        // Two days after the latest: the workflow can't send any more.
        prune_counters(&store.db, t + 3 * DAY).unwrap();
        assert!(rows(&store).is_empty(), "{:?}", rows(&store));
        // Counting prunes too.
        accept_at(&store, &config, "session", "flow-b", t + 3 * DAY);
        accept_at(&store, &config, "session", "flow-c", t + 6 * DAY);
        assert_eq!(counted(&store, "send:flow-b"), 0);
        assert_eq!(counted(&store, "hour:session"), 1);
    }

    fn accept_at(store: &Store, config: &Collab, from: &str, flow: &str, now: u64) {
        let tx = store.db.unchecked_transaction().unwrap();
        count_send(&tx, config, from, flow, now).unwrap();
        count_received(&tx, config, flow, now).unwrap();
        tx.commit().unwrap();
    }

    #[test]
    fn a_workflow_counts_sends_from_its_tasks() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        for n in 0..8 {
            let tx = store.db.unchecked_transaction().unwrap();
            count_send(
                &tx,
                &Default::default(),
                &format!("session-{n}"),
                "workflow",
                1_000,
            )
            .unwrap();
            tx.commit().unwrap();
        }
        let tx = store.db.unchecked_transaction().unwrap();
        assert_eq!(
            count_send(&tx, &Default::default(), "another", "workflow", 1_000)
                .unwrap_err()
                .to_string(),
            "limit: 8 messages per workflow"
        );
    }
}
