//! Replies to tasks, one durable result row per task for every sender, and
//! the narrow return grants that deliver them to local senders.
//!
//! A row is committed when `atem message reply` is answered, bound to the
//! task, session, process and turn it answers. Its state is `publishing`
//! (its context is still being published), `submitted` (published, or with
//! nothing to publish) or `refused` (its publication was refused; a
//! corrected reply replaces it). A reply never completes its task.

use super::*;
use crate::runtime::collab_context::ContextSpec;
use atem_client::session::{
    host_work::{ContextKind, ContextSnapshot, ResultReply, WorkState},
    wire::Target,
};
use rusqlite::Connection;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OriginRoute {
    pub id: String,
    pub revision: u64,
    pub profile_id: String,
    pub profile_revision: u64,
    pub project: String,
    pub results: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Origin {
    pub target: Target,
    pub control_gen: u64,
    pub route: Option<OriginRoute>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReturnGrant {
    pub task_id: String,
    pub message_id: String,
    pub workflow_id: String,
    pub origin: Origin,
    pub recipient: Target,
    pub expires_at: u64,
}

impl ReturnGrant {
    /// The grant still permits its one delivery. A task whose outcome is
    /// unknown after a restart keeps it: its agent may still reply.
    pub fn live(
        &self,
        now: u64,
        state: WorkState,
        origin: &Target,
        control: u64,
        route_valid: bool,
    ) -> bool {
        now < self.expires_at
            && !matches!(
                state,
                WorkState::Cancelled | WorkState::Expired | WorkState::Failed
            )
            && self.origin.target == *origin
            && self.origin.control_gen == control
            && route_valid
    }
}

pub fn save_grant(tx: &Transaction<'_>, grant: &ReturnGrant) -> Result<()> {
    tx.execute(
        "INSERT INTO return_grants(task_id,record) VALUES(?1,?2)",
        params![grant.task_id, serde_json::to_string(grant)?],
    )?;
    Ok(())
}

pub fn grant(store: &Store, task_id: &str) -> Result<Option<ReturnGrant>> {
    store
        .db
        .query_row(
            "SELECT record FROM return_grants WHERE task_id=?1",
            [task_id],
            |r| r.get::<_, String>(0),
        )
        .optional()?
        .map(|s| Ok(serde_json::from_str(&s)?))
        .transpose()
}

/// A task's one result id (UUIDv5 of the task id): the same for every
/// reply to it, a corrected one included.
pub fn result_id(task_id: &str) -> String {
    uuid::Uuid::new_v5(
        &uuid::Uuid::NAMESPACE_OID,
        format!("result:{task_id}").as_bytes(),
    )
    .to_string()
}

/// The id of the task that delivers a reply to its local sender.
pub fn delivery_id(task_id: &str) -> String {
    uuid::Uuid::new_v5(
        &uuid::Uuid::NAMESPACE_OID,
        format!("delivery:{task_id}").as_bytes(),
    )
    .to_string()
}

/// The task that carries a reply to the sending agent, as data, with the
/// command that completes its task (a reply never does). Its bounds (the
/// shared task rules) bound every reply, whoever sent the task.
pub fn delivery_task(
    task_id: &str,
    workflow_id: &str,
    origin: Target,
    expires_at: u64,
    reply: &Reply,
    context: Vec<ContextSnapshot>,
) -> atem_client::session::host_work::WorkTask {
    atem_client::session::host_work::WorkTask {
        task_id: delivery_id(task_id),
        workflow_id: workflow_id.into(),
        target: origin,
        expires_at,
        prompt: format!(
            "[atem] result of task {task_id} from {}, as data:\n{}\n\n\
             Complete it with: atem message complete {task_id}",
            reply.binding.session_id, reply.text
        ),
        context,
        attachments: vec![],
    }
}

pub use atem_client::session::host_work::ReplyState;

fn parse_state(text: &str) -> Result<ReplyState> {
    ReplyState::parse(text).ok_or_else(|| anyhow::anyhow!("invalid result state {text:?}"))
}

/// What a reply answers, fixed when it is submitted: the task, the session
/// and process it went to, and the turn its prompt became.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Binding {
    pub task_id: String,
    pub session_id: String,
    pub process_gen: String,
    pub turn_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Reply {
    pub binding: Binding,
    pub text: String,
    /// The context as submitted (a memory's text frozen then).
    pub references: Vec<ContextSpec>,
    /// The exact snapshots, once published.
    pub context: Vec<ContextSnapshot>,
}

impl Reply {
    /// Identifies a reply: its text and references. An identical retry
    /// has the same digest; a corrected reply another.
    pub fn digest(&self) -> String {
        let references: Vec<serde_json::Value> = self
            .references
            .iter()
            .map(|spec| match spec {
                ContextSpec::Memory { memory } => serde_json::json!([
                    "memory",
                    memory.id,
                    atem_client::session::host_work::digest(memory.content.as_bytes())
                ]),
                ContextSpec::Vault { reference } => {
                    serde_json::json!(["vault", reference.id, reference.entry, reference.version])
                }
            })
            .collect();
        atem_client::session::host_work::digest(
            &serde_json::to_vec(&(&self.text, references)).expect("serializable reply"),
        )
    }
}

#[derive(Clone, Debug)]
pub struct ResultRow {
    pub result_id: String,
    pub state: ReplyState,
    pub detail: String,
    pub digest: String,
    /// When the reply was committed (`atem message reply` answered).
    pub created_ms: u64,
    /// When it became `submitted`.
    pub submitted_at: Option<u64>,
    pub reply: Reply,
    /// The task delivering it to its local sender, once queued.
    pub work_id: Option<String>,
}

pub const PUBLISHING: &str = "publishing its context";

/// A reply refused because its task expired before its context was
/// published: an expired task takes no new reply.
pub const EXPIRED: &str = "expired before context publication";

/// The detail of a submitted reply its return grant could not carry to its
/// sender (the reason follows); the only detail a submitted reply has.
pub const UNDELIVERED: &str = "result could not be delivered: ";

impl ResultRow {
    /// A new reply: `submitted` at once, unless it has context to publish.
    pub fn new(reply: Reply, now: u64) -> Self {
        let publishing = !reply.references.is_empty();
        Self {
            result_id: result_id(&reply.binding.task_id),
            state: if publishing {
                ReplyState::Publishing
            } else {
                ReplyState::Submitted
            },
            detail: if publishing {
                PUBLISHING.into()
            } else {
                String::new()
            },
            digest: reply.digest(),
            created_ms: now,
            submitted_at: (!publishing).then_some(now),
            reply,
            work_id: None,
        }
    }

    pub fn task_id(&self) -> &str {
        &self.reply.binding.task_id
    }

    /// The reply as a task's result.
    pub fn snapshot(&self) -> ContextSnapshot {
        let text = serde_json::to_string(&serde_json::json!({
            "result_id": self.result_id,
            "binding": self.reply.binding,
            "text": self.reply.text,
            "context": self.reply.context,
        }))
        .expect("serializable result");
        ContextSnapshot {
            kind: ContextKind::Result,
            id: format!("result:{}", self.result_id),
            version: 1,
            digest: atem_client::session::host_work::digest(text.as_bytes()),
            text,
        }
    }

    /// The reply as its sender reads it with `reply_query`. A reply that
    /// isn't submitted has no context yet (or none at all, if refused).
    pub fn wire(&self) -> ResultReply {
        ResultReply {
            result_id: self.result_id.clone(),
            state: self.state,
            digest: self.digest.clone(),
            text: self.reply.text.clone(),
            context: if self.state == ReplyState::Submitted {
                self.reply.context.clone()
            } else {
                Vec::new()
            },
            submitted_at: self
                .submitted_at
                .filter(|_| self.state == ReplyState::Submitted),
        }
    }

    /// What the replied task's detail says about its reply.
    pub fn task_detail(&self) -> String {
        match self.state {
            ReplyState::Publishing => "reply received; publishing its context".into(),
            ReplyState::Submitted if self.detail.starts_with(UNDELIVERED) => self.detail.clone(),
            ReplyState::Submitted => "reply submitted".into(),
            ReplyState::Refused if self.detail == EXPIRED => {
                format!("reply refused ({})", self.detail)
            }
            ReplyState::Refused => format!(
                "reply refused ({}); a corrected reply replaces it",
                self.detail
            ),
        }
    }
}

/// The outcome of submitting a reply.
#[derive(Debug)]
pub enum Submission {
    /// Committed as the task's reply (new, or replacing a refused one).
    Stored(ResultRow),
    /// The same reply was already recorded: that row, in whatever state.
    Recorded(ResultRow),
}

const COLUMNS: &str = "result_id,state,detail,digest,created_ms,submitted_at,record,work_id";

/// A row as stored, before its state and record are parsed.
struct Stored {
    result_id: String,
    state: String,
    detail: String,
    digest: String,
    created_ms: u64,
    submitted_at: Option<u64>,
    record: String,
    work_id: Option<String>,
}

fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Stored> {
    Ok(Stored {
        result_id: r.get(0)?,
        state: r.get(1)?,
        detail: r.get(2)?,
        digest: r.get(3)?,
        created_ms: r.get(4)?,
        submitted_at: r.get(5)?,
        record: r.get(6)?,
        work_id: r.get(7)?,
    })
}

fn parse(stored: Stored) -> Result<ResultRow> {
    Ok(ResultRow {
        result_id: stored.result_id,
        state: parse_state(&stored.state)?,
        detail: stored.detail,
        digest: stored.digest,
        created_ms: stored.created_ms,
        submitted_at: stored.submitted_at,
        reply: serde_json::from_str(&stored.record)?,
        work_id: stored.work_id,
    })
}

/// The reply to `task_id`, if one was submitted.
pub fn load(db: &Connection, task_id: &str) -> Result<Option<ResultRow>> {
    db.query_row(
        &format!("SELECT {COLUMNS} FROM results WHERE task_id=?1"),
        [task_id],
        row,
    )
    .optional()?
    .map(parse)
    .transpose()
}

/// The reply a task delivers to its local sender.
pub fn delivered_by(db: &Connection, work_id: &str) -> Result<Option<ResultRow>> {
    db.query_row(
        &format!("SELECT {COLUMNS} FROM results WHERE work_id=?1"),
        [work_id],
        row,
    )
    .optional()?
    .map(parse)
    .transpose()
}

/// Replies whose context is due for a publication attempt, oldest first,
/// with their attempts so far; without replies to local tasks unless
/// `local` (those wait out a local pause).
pub fn publishing_due(db: &Connection, now: u64, local: bool) -> Result<Vec<(ResultRow, u32)>> {
    let columns = COLUMNS
        .split(',')
        .map(|c| format!("r.{c}"))
        .collect::<Vec<_>>()
        .join(",");
    let mut q = db.prepare(&format!(
        "SELECT {columns},r.attempts FROM results r JOIN work w ON w.id=r.task_id
        WHERE r.state='publishing' AND r.next_try_ms<=?1
        AND (?2 OR json_extract(w.record,'$.principal')!='local')
        ORDER BY r.created_ms LIMIT 16"
    ))?;
    q.query_map(params![now, local], |r| Ok((row(r)?, r.get::<_, u32>(8)?)))?
        .map(|r| {
            let (row, attempts) = r?;
            Ok((parse(row)?, attempts))
        })
        .collect()
}

/// The result ids of every reply still publishing.
pub fn publishing(db: &Connection) -> Result<Vec<String>> {
    let mut q = db.prepare("SELECT result_id FROM results WHERE state='publishing'")?;
    q.query_map([], |r| r.get(0))?.map(|r| Ok(r?)).collect()
}

/// Commits `reply` as its task's one reply: an identical one returns the
/// row recorded (in any state); another is refused while the recorded one
/// is publishing or submitted, and replaces it once it was refused.
pub fn submit(tx: &Transaction<'_>, reply: &ResultRow) -> Result<Submission> {
    if let Some(old) = load(tx, reply.task_id())? {
        if old.digest == reply.digest {
            return Ok(Submission::Recorded(old));
        }
        if old.state != ReplyState::Refused {
            bail!("request_id_reused");
        }
    }
    tx.execute(
        "INSERT INTO results(task_id,result_id,state,detail,digest,created_ms,submitted_at,record,next_try_ms,attempts,work_id)
        VALUES(?1,?2,?3,?4,?5,?6,?7,?8,0,0,NULL)
        ON CONFLICT(task_id) DO UPDATE SET state=excluded.state,detail=excluded.detail,
            digest=excluded.digest,created_ms=excluded.created_ms,submitted_at=excluded.submitted_at,
            record=excluded.record,next_try_ms=0,attempts=0,work_id=NULL",
        params![
            reply.task_id(),
            reply.result_id,
            reply.state.as_str(),
            reply.detail,
            reply.digest,
            reply.created_ms,
            reply.submitted_at,
            serde_json::to_string(&reply.reply)?
        ],
    )?;
    Ok(Submission::Stored(reply.clone()))
}

/// Its context was published and read back: the reply is submitted. A
/// reply no longer publishing (refused or replaced meanwhile) is left as it
/// is, and returned as it is.
pub fn published(
    db: &Connection,
    task_id: &str,
    context: Vec<ContextSnapshot>,
    now: u64,
) -> Result<ResultRow> {
    let mut row = load(db, task_id)?.ok_or_else(|| anyhow::anyhow!("missing reply"))?;
    row.reply.context = context;
    row.state = ReplyState::Submitted;
    row.detail = String::new();
    row.submitted_at = Some(now);
    let changed = db.execute(
        "UPDATE results SET state='submitted',detail='',submitted_at=?2,record=?3
        WHERE task_id=?1 AND state='publishing'",
        params![task_id, now, serde_json::to_string(&row.reply)?],
    )?;
    if changed == 0 {
        return load(db, task_id)?.ok_or_else(|| anyhow::anyhow!("missing reply"));
    }
    Ok(row)
}

/// Its publication was refused for good: a corrected reply may replace it.
pub fn refuse(db: &Connection, task_id: &str, detail: &str) -> Result<()> {
    db.execute(
        "UPDATE results SET state='refused',detail=?2 WHERE task_id=?1 AND state='publishing'",
        params![task_id, detail],
    )?;
    Ok(())
}

/// The publication failed for now: tried again at `next_try_ms`.
pub fn retry(db: &Connection, task_id: &str, detail: &str, next_try_ms: u64) -> Result<()> {
    db.execute(
        "UPDATE results SET detail=?2,next_try_ms=?3,attempts=attempts+1
        WHERE task_id=?1 AND state='publishing'",
        params![task_id, detail, next_try_ms],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        (dir, store)
    }

    fn reply(text: &str, references: Vec<ContextSpec>) -> Reply {
        Reply {
            binding: Binding {
                task_id: uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_OID, b"task").to_string(),
                session_id: "ses-bbbbbbbbbbbb".into(),
                process_gen: "6ba7b810-9dad-41d1-80b4-00c04fd430c8".into(),
                turn_id: "turn-1".into(),
            },
            text: text.into(),
            references,
            context: vec![],
        }
    }

    fn vault(version: u32) -> ContextSpec {
        ContextSpec::Vault {
            reference: crate::runtime::collab_context::VaultRef::parse(&format!(
                "v-result:1@{version}"
            ))
            .unwrap(),
        }
    }

    fn submit_now(store: &Store, row: &ResultRow) -> Result<Submission> {
        let tx = store.db.unchecked_transaction()?;
        let outcome = submit(&tx, row)?;
        tx.commit()?;
        Ok(outcome)
    }

    #[test]
    fn one_row_per_task_and_an_identical_retry_returns_it_in_any_state() {
        let (_dir, store) = store();
        let first = ResultRow::new(reply("done", vec![]), 100);
        let task = first.task_id().to_string();
        assert_eq!(first.result_id, result_id(&task));
        let id = uuid::Uuid::parse_str(&first.result_id).unwrap();
        assert_eq!(id.get_version_num(), 5);
        assert_ne!(first.result_id, delivery_id(&task));
        assert_eq!(first.state, ReplyState::Submitted);
        assert!(matches!(
            submit_now(&store, &first).unwrap(),
            Submission::Stored(_)
        ));
        // The same reply again, later: the row recorded first.
        let again = ResultRow::new(reply("done", vec![]), 200);
        let Submission::Recorded(recorded) = submit_now(&store, &again).unwrap() else {
            panic!("an identical retry is the recorded reply");
        };
        assert_eq!(recorded.created_ms, 100);
        assert_eq!(recorded.submitted_at, Some(100));
        // Refused too: the recorded refusal, not a new publication.
        let (_dir, store) = self::store();
        let held = ResultRow::new(reply("with context", vec![vault(1)]), 100);
        assert_eq!(held.state, ReplyState::Publishing);
        submit_now(&store, &held).unwrap();
        refuse(&store.db, held.task_id(), "context changed").unwrap();
        let Submission::Recorded(recorded) = submit_now(&store, &held).unwrap() else {
            panic!("an identical retry is the recorded reply");
        };
        assert_eq!(recorded.state, ReplyState::Refused);
        assert_eq!(recorded.detail, "context changed");
    }

    #[test]
    fn a_different_reply_is_refused_unless_the_recorded_one_was_refused() {
        let (_dir, store) = store();
        let publishing = ResultRow::new(reply("first", vec![vault(1)]), 100);
        submit_now(&store, &publishing).unwrap();
        for other in [
            ResultRow::new(reply("second", vec![]), 110),
            ResultRow::new(reply("first", vec![vault(2)]), 110),
        ] {
            assert_eq!(
                submit_now(&store, &other).unwrap_err().to_string(),
                "request_id_reused"
            );
        }
        let row = published(&store.db, publishing.task_id(), vec![], 120).unwrap();
        assert_eq!(row.state, ReplyState::Submitted);
        assert_eq!(
            load(&store.db, publishing.task_id())
                .unwrap()
                .unwrap()
                .submitted_at,
            Some(120)
        );
        assert_eq!(
            submit_now(&store, &ResultRow::new(reply("second", vec![]), 130))
                .unwrap_err()
                .to_string(),
            "request_id_reused"
        );

        // A refused publication: a corrected reply takes its place, under
        // the same result id.
        let (_dir, store) = self::store();
        let refused = ResultRow::new(reply("too big", vec![vault(1)]), 100);
        submit_now(&store, &refused).unwrap();
        refuse(&store.db, refused.task_id(), "over 32 KiB").unwrap();
        let corrected = ResultRow::new(reply("smaller", vec![]), 140);
        let Submission::Stored(stored) = submit_now(&store, &corrected).unwrap() else {
            panic!("a corrected reply replaces a refused one");
        };
        assert_eq!(stored.result_id, refused.result_id);
        let row = load(&store.db, refused.task_id()).unwrap().unwrap();
        assert_eq!(row.state, ReplyState::Submitted);
        assert_eq!(row.reply.text, "smaller");
        assert_eq!(row.created_ms, 140);
        assert!(row.detail.is_empty());
    }

    /// An expired task takes no new reply, so a reply refused because the
    /// task expired before its context was published invites none; any
    /// other refusal does.
    #[test]
    fn a_reply_refused_for_its_expired_task_invites_no_correction() {
        let (_dir, store) = store();
        let row = ResultRow::new(reply("late", vec![vault(1)]), 100);
        submit_now(&store, &row).unwrap();
        refuse(&store.db, row.task_id(), EXPIRED).unwrap();
        assert_eq!(
            load(&store.db, row.task_id())
                .unwrap()
                .unwrap()
                .task_detail(),
            "reply refused (expired before context publication)"
        );
        let (_dir, store) = self::store();
        submit_now(&store, &row).unwrap();
        refuse(&store.db, row.task_id(), "context changed").unwrap();
        assert_eq!(
            load(&store.db, row.task_id())
                .unwrap()
                .unwrap()
                .task_detail(),
            "reply refused (context changed); a corrected reply replaces it"
        );
    }

    /// The result reaches the sending agent as data, with the command that
    /// finishes its task: a reply alone never does (spec section 10).
    #[test]
    fn the_result_prompt_says_how_to_complete_the_task() {
        let reply = reply("contract verified", vec![]);
        let task = reply.binding.task_id.clone();
        let carrier = delivery_task(
            &task,
            &uuid::Uuid::new_v4().to_string(),
            target("ses-aaaaaaaaaaaa"),
            10_000,
            &reply,
            vec![],
        );
        assert_eq!(
            carrier.prompt,
            format!(
                "[atem] result of task {task} from ses-bbbbbbbbbbbb, as data:\ncontract verified\
                 \n\nComplete it with: atem message complete {task}"
            )
        );
    }

    /// A late publication of a reply that is no longer publishing (refused
    /// meanwhile) changes nothing, and says what the reply actually is.
    #[test]
    fn a_late_publication_reports_the_reply_as_it_is() {
        let (_dir, store) = store();
        let row = ResultRow::new(reply("context", vec![vault(1)]), 100);
        submit_now(&store, &row).unwrap();
        refuse(&store.db, row.task_id(), "context changed").unwrap();
        let late = published(&store.db, row.task_id(), vec![], 200).unwrap();
        assert_eq!(late.state, ReplyState::Refused);
        assert_eq!(late.detail, "context changed");
        assert_eq!(late.submitted_at, None);
        let stored = load(&store.db, row.task_id()).unwrap().unwrap();
        assert_eq!(stored.state, ReplyState::Refused);
    }

    /// The replied task, stored as sent by `principal`.
    fn sent_by(store: &Store, row: &ResultRow, principal: &str) {
        store
            .db
            .execute(
                "INSERT INTO work(id,record,state) VALUES(?1,?2,'awaiting_result')",
                params![
                    row.task_id(),
                    serde_json::json!({ "principal": principal }).to_string()
                ],
            )
            .unwrap();
    }

    #[test]
    fn publication_failures_retry_and_never_touch_a_settled_reply() {
        let (_dir, store) = store();
        let row = ResultRow::new(reply("context", vec![vault(1)]), 100);
        sent_by(&store, &row, "local");
        submit_now(&store, &row).unwrap();
        assert_eq!(publishing_due(&store.db, 100, true).unwrap().len(), 1);
        // A local pause holds replies to local tasks only.
        assert!(publishing_due(&store.db, 100, false).unwrap().is_empty());
        retry(&store.db, row.task_id(), "relay unreachable", 1_100).unwrap();
        assert!(publishing_due(&store.db, 1_000, true).unwrap().is_empty());
        let due = publishing_due(&store.db, 1_100, true).unwrap();
        assert_eq!(
            (due[0].0.detail.as_str(), due[0].1),
            ("relay unreachable", 1)
        );
        assert_eq!(publishing(&store.db).unwrap(), vec![row.result_id.clone()]);
        published(&store.db, row.task_id(), vec![], 1_200).unwrap();
        // Settled: a late failure changes nothing.
        refuse(&store.db, row.task_id(), "late").unwrap();
        retry(&store.db, row.task_id(), "late", 9_999).unwrap();
        let settled = load(&store.db, row.task_id()).unwrap().unwrap();
        assert_eq!(settled.state, ReplyState::Submitted);
        assert!(publishing(&store.db).unwrap().is_empty());

        // A remote sender's task: due during a local pause too.
        let (_dir, store) = self::store();
        let remote = ResultRow::new(reply("context", vec![vault(1)]), 100);
        sent_by(&store, &remote, "service:svc-work");
        submit_now(&store, &remote).unwrap();
        assert_eq!(publishing_due(&store.db, 100, false).unwrap().len(), 1);
    }

    #[test]
    fn a_grant_ends_with_cancel_expiry_process_end_and_control_change() {
        let g = grant();
        assert!(g.live(
            100,
            WorkState::AwaitingResult,
            &g.origin.target,
            g.origin.control_gen,
            true
        ));
        // A restart in the task's turn leaves its outcome unknown: the
        // grant stays, so the agent's reply still reaches its sender.
        assert!(g.live(
            100,
            WorkState::OutcomeUnknown,
            &g.origin.target,
            g.origin.control_gen,
            true
        ));
        for state in [WorkState::Cancelled, WorkState::Expired, WorkState::Failed] {
            assert!(!g.live(100, state, &g.origin.target, g.origin.control_gen, true));
        }
        assert!(!g.live(
            g.expires_at,
            WorkState::AwaitingResult,
            &g.origin.target,
            g.origin.control_gen,
            true
        ));
        let mut another = g.origin.target.clone();
        another.process_gen = uuid::Uuid::new_v4().to_string();
        assert!(!g.live(
            100,
            WorkState::AwaitingResult,
            &another,
            g.origin.control_gen,
            true
        ));
        assert!(!g.live(
            100,
            WorkState::AwaitingResult,
            &g.origin.target,
            g.origin.control_gen + 1,
            true
        ));
        assert!(!g.live(
            100,
            WorkState::AwaitingResult,
            &g.origin.target,
            g.origin.control_gen,
            false
        ));
    }

    fn grant() -> ReturnGrant {
        let origin = Origin {
            target: target("ses-aaaaaaaaaaaa"),
            control_gen: 1,
            route: None,
        };
        ReturnGrant {
            task_id: uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_OID, b"task").to_string(),
            message_id: uuid::Uuid::new_v4().to_string(),
            workflow_id: uuid::Uuid::new_v4().to_string(),
            origin,
            recipient: target("ses-bbbbbbbbbbbb"),
            expires_at: 10_000,
        }
    }
    fn target(session: &str) -> Target {
        Target {
            account_id: "account".into(),
            atem_device_id: "host".into(),
            host_trust_gen: 1,
            session_id: session.into(),
            process_gen: uuid::Uuid::new_v4().to_string(),
        }
    }
}
