//! Local collaboration: immutable resolution, durable outbox and loop limits.

#[path = "collab_results.rs"]
pub mod results;

use super::host_work::{Collab, Store};
use anyhow::{Result, bail};
use atem_client::session::{
    host_work::{HostTarget, WorkTask},
    messages::{Message, MessageKind},
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

pub(super) fn count_send(
    tx: &Transaction<'_>,
    config: &Collab,
    from: &str,
    workflow: &str,
    now: u64,
) -> Result<()> {
    // Rolling hourly windows avoid a double burst at a clock-hour boundary.
    tx.execute(
        "DELETE FROM counters WHERE key LIKE 'hour:%' AND window_start_ms<=?1",
        [now.saturating_sub(3_600_000)],
    )?;
    let total: u32 = tx.query_row(
        "SELECT coalesce(sum(count),0) FROM counters WHERE key=?1 AND window_start_ms>?2",
        params![format!("hour:{from}"), now.saturating_sub(3_600_000)],
        |r| r.get(0),
    )?;
    if total >= config.per_hour {
        bail!("limit: {} messages per hour", config.per_hour);
    }
    count(
        tx,
        &format!("send:{workflow}"),
        0,
        1,
        config.per_workflow,
        "messages per workflow",
    )?;
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
pub(super) fn count_received(tx: &Transaction<'_>, config: &Collab, workflow: &str) -> Result<()> {
    count(
        tx,
        &format!("receive:{workflow}"),
        0,
        1,
        config.per_workflow,
        "messages per workflow",
    )
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
    count(&tx, &format!("send:{workflow}"), 0, flow, u32::MAX, "")?;
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

/// Why a local task could never be dispatched (the shared `WorkTask` bounds:
/// prompt with context within 32 KiB, no control characters other than
/// newline and tab), so its message is refused before anything is counted
/// or stored.
pub(super) fn task_problem(task: &WorkTask, host: &HostTarget) -> Option<&'static str> {
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResultView {
    pub text: String,
    pub context: Vec<atem_client::session::messages::ContextReference>,
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
    pub turn_id: Option<String>,
    pub context: Vec<super::collab_context::ContextSpec>,
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
            || previous_publication.turn_id != publication.turn_id || serde_json::to_value(previous_publication.context)? != serde_json::to_value(&publication.context)? {
            bail!("request_id_reused");
        }
        return Ok(());
    }
    // A request is counted when it is accepted, and may still turn out to be
    // refused then; checking now only tells the sender early. Results count
    // against nothing.
    if message.kind == MessageKind::Request {
        check_send(
            store,
            config,
            message.from_session.as_deref().unwrap(),
            &message.workflow_id,
            message.created_at,
        )?;
    }
    let tx = store.db.unchecked_transaction()?;
    let count: usize = tx.query_row("SELECT count(*) FROM outbox", [], |r| r.get(0))?;
    if count >= super::host_work::MAX_RECORDS {
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
        "SELECT o.envelope,p.record,p.attempts FROM publications p JOIN outbox o USING(message_id)
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

pub(super) fn views(store: &Store, id: Option<&str>) -> Result<Vec<MessageView>> {
    let mut query = store.db.prepare("SELECT message_id,envelope,state,detail FROM outbox WHERE (?1 IS NULL OR message_id=?1) ORDER BY created_ms DESC,rowid DESC LIMIT 32")?;
    let rows = query.query_map([id], |row| {
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
            let mut q = store
                .db
                .prepare("SELECT task_id FROM resolutions WHERE message_id=?1 ORDER BY rowid")?;
            let tasks = q
                .query_map([&message_id], |r| r.get::<_, String>(0))?
                .map(|id| {
                    let r = store
                        .work(&id?)?
                        .ok_or_else(|| anyhow::anyhow!("missing resolved task"))?;
                    let result =
                        results::accepted(store, &r.task.task_id)?.map(|result| ResultView {
                            text: result.text,
                            context: result
                                .context
                                .iter()
                                .map(|c| atem_client::session::messages::ContextReference {
                                    kind: c.kind,
                                    id: c.id.clone(),
                                    version: c.version,
                                    digest: c.digest.clone(),
                                })
                                .collect(),
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
        count_received(&tx, config, "flow")?;
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
            count_received(&tx, &config, "flow").unwrap();
            tx.commit().unwrap();
        }
        let tx = store.db.unchecked_transaction().unwrap();
        assert_eq!(
            count_received(&tx, &config, "flow")
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

    #[test]
    fn a_task_that_could_never_dispatch_names_its_problem() {
        let host = HostTarget {
            account_id: "account".into(),
            atem_device_id: "host".into(),
            host_trust_gen: 1,
        };
        assert_eq!(task_problem(&local_task("work", vec![]), &host), None);
        assert_eq!(
            task_problem(&local_task("work", vec![snapshot("fine\n\tlines")]), &host),
            None
        );
        assert_eq!(
            task_problem(
                &local_task("work", vec![snapshot(&"x".repeat(40_000))]),
                &host
            ),
            Some("the prompt with its context is over 32 KiB")
        );
        assert_eq!(
            task_problem(
                &local_task("work", vec![snapshot("escape \u{1b}[2J")]),
                &host
            ),
            Some("context has control characters")
        );
        let many = (0..9).map(|_| snapshot("same")).collect();
        assert_eq!(
            task_problem(&local_task("work", many), &host),
            Some("at most 8 context snapshots")
        );
        let mut elsewhere = host.clone();
        elsewhere.atem_device_id = "other".into();
        assert_eq!(
            task_problem(&local_task("work", vec![]), &elsewhere),
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
