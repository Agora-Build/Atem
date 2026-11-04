//! Local collaboration: immutable resolution, durable outbox and loop limits.

#[path = "collab_results.rs"]
pub mod results;

use super::host_work::{Collab, Store};
use anyhow::{Result, bail};
use atem_client::session::{
    messages::Message,
    select::{AgentLabels, Label, MAX_AGENTS, Selector},
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

pub(super) fn count_received(
    tx: &Transaction<'_>,
    config: &Collab,
    workflow: &str,
    tasks: usize,
) -> Result<()> {
    count(
        tx,
        &format!("receive:{workflow}"),
        0,
        tasks as u32,
        config.per_workflow,
        "tasks per workflow",
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
    let tx = store.db.unchecked_transaction()?;
    let count: usize = tx.query_row("SELECT count(*) FROM outbox", [], |r| r.get(0))?;
    if count >= super::host_work::MAX_RECORDS {
        bail!("outbox capacity reached");
    }
    count_send(
        &tx,
        config,
        message.from_session.as_deref().unwrap(),
        &message.workflow_id,
        message.created_at,
    )?;
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
