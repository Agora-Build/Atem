//! Same-runtime collaboration, using the host's ordinary receipt scheduler.
use super::*;
use crate::runtime::collab::results::{
    self, Binding, Origin, OriginRoute, Reply, ReplyState, ResultRow, ReturnGrant, Submission,
};
use crate::runtime::collab::{self, Candidate, DirectoryRow, MessageView, SendRequest};
use crate::runtime::collab_context::{self, ContextSpec, VaultRef};
use crate::runtime::host_work::MessageRecord;
use anyhow::{Result, anyhow, bail};
use atem_client::session::messages::{
    Delivery, Destination, Message, MessageKind, MessageReceipt, Recipient, RecipientReceipt,
};
use atem_client::session::select::{AgentLabels, MAX_AGENTS, Selector, selectors_problem};

/// A submitted task's detail once the runtime saw its prompt accepted and
/// stored the turn it became.
pub(super) const IN_TURN: &str = "in the agent's turn";

/// A local task whose return grant ended early: its sender can never take
/// its reply or complete it.
const SENDER_GONE: &str = "sender gone";

/// How often counter rows whose window passed are pruned (besides at each
/// counted send).
const PRUNE_EVERY: Duration = Duration::from_secs(60);

/// A reply's text fits the task that carries it to its sender.
const MAX_REPLY_TEXT: usize = atem_client::session::host_work::MAX_REPLY_TEXT_BYTES;

/// What a task's reply does to it: a submitted reply proves its prompt
/// arrived (an unknown outcome becomes awaiting its result), and the detail
/// says how the reply stands. A reply never completes its task.
pub(super) fn apply_reply(task: &mut WorkRecord, reply: &ResultRow) {
    if reply.state == ReplyState::Submitted && task.status.state == WorkState::OutcomeUnknown {
        task.status.state = WorkState::AwaitingResult;
    }
    if matches!(
        task.status.state,
        WorkState::Submitted | WorkState::AwaitingResult | WorkState::OutcomeUnknown
    ) {
        task.status.detail = reply.task_detail();
    }
}

/// A task state as `atem message status` names it.
fn state_name(state: WorkState) -> String {
    serde_json::to_value(state)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

/// A context publication that failed for good (never retried).
fn publication_refused(detail: &str) -> bool {
    matches!(
        detail,
        "context changed"
            | "invalid context snapshot"
            | "context profile changed"
            | "invalid message content"
            | "context publication refused"
            | "request_id_reused"
    ) || collab::TASK_PROBLEMS.contains(&detail)
        || detail.starts_with("ambiguous vault reference")
        || detail.starts_with("limit:")
}

impl HostBridge {
    fn collab_origin(
        &self,
        session: &BrokerSession,
        sessions: &BTreeMap<SessionId, BrokerSession>,
    ) -> Origin {
        let mut candidates = self.collab_candidates(sessions);
        candidates.retain(|c| c.session_id == session.id.as_str());
        candidates.sort_by_key(|c| {
            (
                !self.work.config.route(&c.route_id).unwrap().results,
                c.route_id.clone(),
            )
        });
        let route = candidates.first().map(|c| {
            let r = self.work.config.route(&c.route_id).unwrap();
            let p = self.work.config.profile(&r.profile_id).unwrap();
            OriginRoute {
                id: r.id.clone(),
                revision: r.revision,
                profile_id: p.id.clone(),
                profile_revision: p.revision,
                project: p.project.clone(),
                results: r.results,
            }
        });
        let host = self.work_host();
        Origin {
            target: wire::Target {
                account_id: host.account_id,
                atem_device_id: host.atem_device_id,
                host_trust_gen: host.host_trust_gen,
                session_id: session.id.to_string(),
                process_gen: session.process_gen.clone(),
            },
            control_gen: self.host.control_gen("local"),
            route,
        }
    }

    pub(super) fn collab_origin_live(
        &self,
        origin: &Origin,
        sessions: &BTreeMap<SessionId, BrokerSession>,
    ) -> bool {
        let Some(session) =
            SessionId::parse(&origin.target.session_id).and_then(|s| sessions.get(&s))
        else {
            return false;
        };
        if !session.is_live()
            || session.process_gen != origin.target.process_gen
            || self.host.control_gen("local") != origin.control_gen
            || !self.work_host().contains(&origin.target)
        {
            return false;
        }
        origin.route.as_ref().is_none_or(|approved| {
            self.work.config.route(&approved.id).is_some_and(|r| {
                r.revision == approved.revision
                    && r.profile_id == approved.profile_id
                    && r.results == approved.results
                    && r.principals.iter().any(|p| p == "local")
            }) && self
                .work
                .config
                .profile(&approved.profile_id)
                .is_some_and(|p| {
                    p.revision == approved.profile_revision
                        && p.project == approved.project
                        && p.cwd == session.cwd
                        && p.provider == session.provider
                        && self.projects.key_of(session.id.as_str()) == Some(p.project.as_str())
                })
        })
    }

    /// The provider turn `task`'s prompt became (spec section 10): stored
    /// with the task once known; before that, from its receipt's result, or
    /// from the target session's chat while that turn runs or in its
    /// history. Never the session's turn of the moment.
    pub(super) fn collab_task_turn(
        &self,
        task: &WorkRecord,
        sessions: &BTreeMap<SessionId, BrokerSession>,
    ) -> Option<String> {
        if let Some(turn) = &task.turn_id {
            return Some(turn.clone());
        }
        let receipt = task.status.receipt_id.as_str();
        if let Some(turn) = self
            .host
            .receipt(receipt)
            .and_then(|r| r.result)
            .map(|r| r.turn_id)
        {
            return Some(turn);
        }
        let session = SessionId::parse(&task.task.target.session_id)
            .and_then(|s| sessions.get(&s))
            .filter(|s| s.process_gen == task.task.target.process_gen)?;
        if session.chat.current_request_id() == Some(receipt) {
            return session.chat.current_turn_id().map(str::to_string);
        }
        session
            .chat
            .retained()
            .find(|m| m.request_id.as_deref() == Some(receipt))
            .map(|m| m.turn_id.clone())
    }

    /// `atem message reply`: the calling session's reply to a task sent to
    /// it, by any sender, while the task is in its turn, awaits its result
    /// or its outcome is unknown (spec section 10). The reply is committed,
    /// bound to the task, session, process and the task's own turn, before
    /// this returns; its context is published, and it is delivered to a
    /// local sender, later and only outside a pause. A pause refuses new
    /// sends, never a reply.
    pub fn collab_reply(
        &mut self,
        from: &SessionId,
        request: collab::ReplyRequest,
        sessions: &BTreeMap<SessionId, BrokerSession>,
    ) -> Result<ResultRow> {
        self.collab_store_ready()?;
        let session = sessions
            .get(from)
            .filter(|s| s.is_live())
            .ok_or_else(|| anyhow!("the calling session ended"))?;
        // Malformed references are refused before anything is stored. A
        // reply's vault reference names its entry: an ambiguous one could
        // only be found out once the reply was stored.
        if let Some(bare) = request
            .vault
            .iter()
            .find(|v| VaultRef::parse(v).is_ok_and(|r| r.entry.is_none()))
        {
            bail!("ambiguous vault reference {bare}: a reply names the entry, ID:ENTRY@VERSION");
        }
        let references = collab_context::capture(&self.work.dir, &request.memory, &request.vault)?;
        if request.text.trim().is_empty() && references.is_empty() {
            bail!("a reply needs text");
        }
        if request.text.len() > MAX_REPLY_TEXT {
            bail!("a reply's text is at most 16 KiB");
        }
        if request
            .text
            .chars()
            .any(|c| c.is_control() && c != '\n' && c != '\t')
        {
            bail!("the reply has control characters");
        }
        let mut reply = Reply {
            binding: Binding {
                task_id: String::new(),
                session_id: from.to_string(),
                process_gen: session.process_gen.clone(),
                turn_id: String::new(),
            },
            text: request.text,
            references,
            context: vec![],
        };
        let digest = reply.digest();
        let store = self.work.store.as_ref().unwrap();
        let mut task = match &request.task_id {
            Some(id) => store
                .work(id)?
                .ok_or_else(|| anyhow!("no task {id} in this runtime"))?,
            None => self.collab_reply_task(from, session, &digest)?,
        };
        let id = task.task.task_id.clone();
        if task.task.target.session_id != from.as_str()
            || task.task.target.process_gen != session.process_gen
        {
            bail!("mismatch: task {id} was not sent to this session");
        }
        if results::delivered_by(&store.db, &id)?.is_some() {
            bail!("task {id} delivers a result as data; it takes no reply");
        }
        // An identical retry returns the reply recorded, whatever happened
        // to the task since.
        if let Some(old) = results::load(&store.db, &id)?
            && old.digest == digest
        {
            return Ok(old);
        }
        if !matches!(
            task.status.state,
            WorkState::Submitted | WorkState::AwaitingResult | WorkState::OutcomeUnknown
        ) {
            let why = match task.status.state {
                WorkState::Failed | WorkState::Expired | WorkState::Cancelled => {
                    format!(" ({})", task.status.detail)
                }
                _ => String::new(),
            };
            bail!(
                "task {id} is {}{why}; a reply needs it in its turn or awaiting its result",
                state_name(task.status.state)
            );
        }
        let now = host_now().wall_ms;
        if now >= task.task.expires_at {
            bail!("task {id} expired");
        }
        let Some(turn) = self.collab_task_turn(&task, sessions) else {
            if task.status.state == WorkState::Submitted {
                bail!("the turn of task {id} is not known yet; retry in a moment");
            }
            bail!("the runtime never saw task {id}'s prompt accepted; no turn binds a reply");
        };
        reply.binding.task_id = id.clone();
        reply.binding.turn_id = turn.clone();
        // What is known now (a memory's text) must fit the task that would
        // carry the reply; a vault entry is checked once it is read.
        let known = reply
            .references
            .iter()
            .filter_map(ContextSpec::known_snapshot)
            .collect();
        if let Some(problem) = self.collab_reply_problem(&task, &reply, known) {
            bail!("{problem}");
        }
        let row = ResultRow::new(reply, now);
        let tx = store.db.unchecked_transaction()?;
        let row = match results::submit(&tx, &row)? {
            Submission::Recorded(row) => row,
            Submission::Stored(row) => {
                task.turn_id = Some(turn);
                apply_reply(&mut task, &row);
                store.save_work(&task)?;
                row
            }
        };
        tx.commit()?;
        Ok(row)
    }

    /// The one task of the calling session a reply without `--task` is for:
    /// in its turn or awaiting its result, with no reply yet (or a refused
    /// one). With none, an identical retry finds the task it answered.
    fn collab_reply_task(
        &self,
        from: &SessionId,
        session: &BrokerSession,
        digest: &str,
    ) -> Result<WorkRecord> {
        let store = self.work.store.as_ref().unwrap();
        let (mut open, mut identical) = (Vec::new(), Vec::new());
        for task in store.tasks()? {
            if task.task.target.session_id != from.as_str()
                || task.task.target.process_gen != session.process_gen
                || results::delivered_by(&store.db, &task.task.task_id)?.is_some()
            {
                continue;
            }
            let reply = results::load(&store.db, &task.task.task_id)?;
            if reply.as_ref().is_some_and(|r| r.digest == digest) {
                identical.push(task);
            } else if matches!(
                task.status.state,
                WorkState::Submitted | WorkState::AwaitingResult | WorkState::OutcomeUnknown
            ) && reply.is_none_or(|r| r.state == ReplyState::Refused)
            {
                open.push(task);
            }
        }
        match (open.len(), identical.len()) {
            (1, _) => Ok(open.remove(0)),
            (0, 1) => Ok(identical.remove(0)),
            (0, 0) => {
                bail!("no task of this session is in its turn or awaits a reply; use --task <id>")
            }
            (n, _) => bail!("{n} tasks of this session await a reply; use --task <id>"),
        }
    }

    /// Why the task carrying `reply` (with `context`) to its sender could
    /// never be dispatched: the same bounds for every sender. A task with no
    /// local sender is measured against its own target.
    fn collab_reply_problem(
        &self,
        task: &WorkRecord,
        reply: &Reply,
        context: Vec<atem_client::session::host_work::ContextSnapshot>,
    ) -> Option<&'static str> {
        let store = self.work.store.as_ref()?;
        let (target, workflow) = match results::grant(store, &task.task.task_id) {
            Ok(Some(grant)) => (grant.origin.target, grant.workflow_id),
            _ => (task.task.target.clone(), task.task.workflow_id.clone()),
        };
        let carrier = results::delivery_task(
            &task.task.task_id,
            &workflow,
            target,
            task.task.expires_at,
            reply,
            context,
        );
        collab::task_problem(&carrier, &self.work_host())
    }

    /// Publishes the context of replies (spec section 8) against the binding
    /// stored with each, whatever its session does meanwhile. A reply to a
    /// local task waits while local collaboration is paused; one to a remote
    /// sender's task only while hosting is (`work_pass` doesn't run then).
    pub(super) fn collab_reply_pass(&mut self) -> Result<()> {
        let local_waits = !self.collab_paused().is_empty() || !self.local_authorized();
        let now = host_now().wall_ms;
        let due =
            results::publishing_due(&self.work.store.as_ref().unwrap().db, now, !local_waits)?;
        for (row, attempts) in due {
            let store = self.work.store.as_ref().unwrap();
            let task_id = row.task_id().to_string();
            let Some(task) = store.work(&task_id)? else {
                continue;
            };
            if now >= task.task.expires_at {
                self.work.context_jobs.remove(&row.result_id);
                self.collab_reply_refused(&task_id, results::EXPIRED)?;
                continue;
            }
            let Some(job) = self.work.context_jobs.get_mut(&row.result_id) else {
                if self.work.context_jobs.len() < 2 {
                    self.collab_publish_job(row.result_id.clone(), row.reply.references.clone());
                }
                continue;
            };
            let result = match job.try_recv() {
                Ok(r) => r,
                Err(tokio::sync::oneshot::error::TryRecvError::Empty) => continue,
                Err(_) => Err(anyhow!("relay unreachable")),
            };
            self.work.context_jobs.remove(&row.result_id);
            let result = result.and_then(|snapshots| {
                match self.collab_reply_problem(&task, &row.reply, snapshots.clone()) {
                    Some(problem) => Err(anyhow!("{problem}")),
                    None => Ok(snapshots),
                }
            });
            match result {
                Ok(snapshots) => {
                    let store = self.work.store.as_ref().unwrap();
                    let tx = store.db.unchecked_transaction()?;
                    let row = results::published(&tx, &task_id, snapshots, now)?;
                    if let Some(mut task) = store.work(&task_id)? {
                        apply_reply(&mut task, &row);
                        store.save_work(&task)?;
                    }
                    tx.commit()?;
                }
                Err(error) if publication_refused(&error.to_string()) => {
                    self.collab_reply_refused(&task_id, &error.to_string())?;
                }
                Err(_) => {
                    let delay = 1_000u64
                        .saturating_mul(1u64 << attempts.min(9))
                        .min(300_000);
                    results::retry(
                        &self.work.store.as_ref().unwrap().db,
                        &task_id,
                        "relay unreachable; publication will retry",
                        now.saturating_add(delay),
                    )?;
                }
            }
        }
        Ok(())
    }

    /// A reply's publication was refused for good; its task says so, and a
    /// corrected reply may replace it while the task has not expired.
    fn collab_reply_refused(&self, task_id: &str, detail: &str) -> Result<()> {
        let store = self.work.store.as_ref().unwrap();
        let tx = store.db.unchecked_transaction()?;
        results::refuse(&tx, task_id, detail)?;
        if let (Some(mut task), Some(row)) = (store.work(task_id)?, results::load(&tx, task_id)?) {
            apply_reply(&mut task, &row);
            store.save_work(&task)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Publishes `specs` in the background (at most two at a time); the
    /// pass collects the snapshots under `key`.
    fn collab_publish_job(&mut self, key: String, specs: Vec<ContextSpec>) {
        let publisher = crate::runtime::collab_context::RelayPublisher::new(
            self.work.dir.clone(),
            self.work_host(),
        );
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.work.context_jobs.insert(key, rx);
        tokio::spawn(async move {
            let result = tokio::time::timeout(
                Duration::from_secs(10),
                crate::runtime::collab_context::publish(&publisher, &specs),
            )
            .await
            .unwrap_or_else(|_| Err(anyhow!("relay unreachable")));
            let _ = tx.send(result);
        });
    }

    /// The one delivery a return grant permits: the submitted reply, queued
    /// as data into the originating session (spec section 10). Deliveries
    /// count against no limit; a full queue only delays one.
    fn collab_deliver(
        &self,
        grant: &ReturnGrant,
        route: &OriginRoute,
        row: &ResultRow,
    ) -> Result<()> {
        let store = self.work.store.as_ref().unwrap();
        let task = results::delivery_task(
            &grant.task_id,
            &grant.workflow_id,
            grant.origin.target.clone(),
            grant.expires_at,
            &row.reply,
            row.reply.context.clone(),
        );
        let tx = store.db.unchecked_transaction()?;
        // Checked when the reply was submitted and published; never queued
        // if it could not be dispatched.
        if collab::task_problem(&task, &self.work_host()).is_none() {
            if !store.has_room()? {
                return Ok(());
            }
            store.enqueue(&WorkRecord {
                principal: "local".into(),
                attachment_owner: Sender::Local.owner(),
                control_gen: grant.origin.control_gen,
                route_id: route.id.clone(),
                route_revision: route.revision,
                profile_id: route.profile_id.clone(),
                profile_revision: route.profile_revision,
                project: route.project.clone(),
                digest: hw::digest(&serde_json::to_vec(&(&row.result_id, &row.digest))?),
                status: WorkStatus {
                    task_id: task.task_id.clone(),
                    receipt_id: uuid::Uuid::new_v4().to_string(),
                    state: WorkState::Queued,
                    detail: "reply submitted; waiting for the originating agent".into(),
                    result: None,
                },
                task,
                turn_id: None,
            })?;
            tx.execute(
                "UPDATE results SET work_id=?2 WHERE task_id=?1",
                rusqlite::params![grant.task_id, results::delivery_id(&grant.task_id)],
            )?;
        }
        tx.execute(
            "UPDATE return_grants SET state='consumed' WHERE task_id=?1 AND state='open'",
            [&grant.task_id],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// The reply a delivery task carries, with the grant it was queued under.
    pub(super) fn collab_result_delivery(
        &self,
        record: &WorkRecord,
    ) -> Result<Option<(ReturnGrant, ResultRow)>> {
        let Some(store) = self.work.store.as_ref() else {
            return Ok(None);
        };
        let Some(row) = results::delivered_by(&store.db, &record.task.task_id)? else {
            return Ok(None);
        };
        let grant =
            results::grant(store, row.task_id())?.ok_or_else(|| anyhow!("missing return grant"))?;
        Ok(Some((grant, row)))
    }

    /// The reply to `task_id`, if any.
    pub(super) fn collab_reply_of(&self, task_id: &str) -> Option<ResultRow> {
        let store = self.work.store.as_ref()?;
        results::load(&store.db, task_id).ok().flatten()
    }

    /// `atem message complete`: a local task is completed by its sender,
    /// with its submitted reply as the result, if any (spec section 10).
    /// Inside a session only the task's sending session may; from outside
    /// any session, the owner. A remote sender completes its tasks with
    /// `work_complete`.
    pub fn collab_complete(
        &mut self,
        caller: Option<&SessionId>,
        task_id: &str,
        sessions: &BTreeMap<SessionId, BrokerSession>,
    ) -> Result<()> {
        self.collab_store_ready()?;
        let store = self.work.store.as_ref().unwrap();
        let mut task = store
            .work(task_id)?
            .ok_or_else(|| anyhow!("no task {task_id} in this runtime"))?;
        if task.principal != "local" {
            bail!(
                "task {task_id} was sent by {}; its sender completes it with work_complete",
                task.principal
            );
        }
        let grant = results::grant(store, task_id)?
            .ok_or_else(|| anyhow!("task {task_id} delivers a result; it completes by itself"))?;
        if let Some(caller) = caller
            && (grant.origin.target.session_id != caller.as_str()
                || sessions
                    .get(caller)
                    .is_none_or(|s| s.process_gen != grant.origin.target.process_gen))
        {
            bail!("only the task's sending session completes it");
        }
        if task.status.state == WorkState::Completed {
            return Ok(());
        }
        if !matches!(
            task.status.state,
            WorkState::AwaitingResult | WorkState::OutcomeUnknown
        ) {
            bail!(
                "task {task_id} is {}; only a task awaiting its result can be completed",
                state_name(task.status.state)
            );
        }
        let reply = results::load(&store.db, task_id)?;
        if reply
            .as_ref()
            .is_some_and(|r| r.state == ReplyState::Publishing)
        {
            bail!(
                "the reply to task {task_id} is still publishing its context; complete it once it is submitted"
            );
        }
        let reply = reply.filter(|r| r.state == ReplyState::Submitted);
        task.status.state = WorkState::Completed;
        task.status.result = reply.as_ref().map(ResultRow::snapshot);
        task.status.detail = if reply.is_some() {
            "completed by its sender with the reply"
        } else {
            "completed by its sender without a reply"
        }
        .into();
        let tx = store.db.unchecked_transaction()?;
        store.save_work(&task)?;
        // Completed: no delivery is queued, or prompted, from now on.
        tx.execute(
            "UPDATE return_grants SET state='ended' WHERE task_id=?1 AND state IN ('open','consumed')",
            [task_id],
        )?;
        let delivery = reply
            .as_ref()
            .and_then(|r| r.work_id.as_deref())
            .map(|id| store.work(id))
            .transpose()?
            .flatten();
        if let Some(mut delivery) = delivery
            && matches!(
                delivery.status.state,
                WorkState::Queued | WorkState::Blocked
            )
        {
            delivery.status.state = WorkState::Cancelled;
            delivery.status.detail = "not delivered: its task was completed by its sender".into();
            store.save_work(&delivery)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Each return grant still open or consumed (spec section 10). One that
    /// is no longer live ends: when it ended early (its sender's process
    /// ended, the sender's authority or the route changed) its task fails
    /// ("sender gone") instead of waiting, with a delivery still queued for
    /// it; one that ran out ends with its task, which expires at its deadline
    /// (`Store::expire_awaiting`). An open, live grant permits the one
    /// delivery of a submitted reply (where the origin route opts in), or a
    /// report on a silent turn. A grant is written only when its state
    /// changes. Runs only outside a pause.
    fn collab_result_pass(&mut self, sessions: &BTreeMap<SessionId, BrokerSession>) -> Result<()> {
        let store = self.work.store.as_ref().unwrap();
        let now = host_now().wall_ms;
        let mut q = store.db.prepare(
            "SELECT w.record,g.record,g.state,g.awaiting_since_ms FROM return_grants g
            JOIN work w ON w.id=g.task_id WHERE g.state IN ('open','consumed')",
        )?;
        let pending = q
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Option<u64>>(3)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        for (task, grant, state, since) in pending {
            let mut task: WorkRecord = serde_json::from_str(&task)?;
            let grant: ReturnGrant = serde_json::from_str(&grant)?;
            // A broker that just started reads each session's launch record
            // (its project) on its first passes: until the sender's is read,
            // its route can't be checked, which is no change.
            if grant.origin.route.is_some()
                && self
                    .project_unread
                    .contains_key(&grant.origin.target.session_id)
            {
                continue;
            }
            let store = self.work.store.as_ref().unwrap();
            let live = self.collab_origin_live(&grant.origin, sessions)
                && grant.live(
                    now,
                    task.status.state,
                    &grant.origin.target,
                    self.host.control_gen("local"),
                    self.work_route_allowed(&task, &Sender::Local),
                );
            if !live {
                let tx = store.db.unchecked_transaction()?;
                tx.execute(
                    "UPDATE return_grants SET state='ended'
                    WHERE task_id=?1 AND state IN ('open','consumed')",
                    [&grant.task_id],
                )?;
                if now < grant.expires_at {
                    self.collab_sender_gone(&mut task)?;
                }
                tx.commit()?;
                continue;
            }
            if state != "open" {
                continue;
            }
            let reply = results::load(&store.db, &grant.task_id)?;
            if let Some(row) = &reply
                && row.state == ReplyState::Submitted
                && row.work_id.is_none()
            {
                if let Some(route) = grant.origin.route.as_ref().filter(|r| r.results) {
                    self.collab_deliver(&grant, route, row)?;
                }
                continue;
            }
            if reply.is_some_and(|r| r.state != ReplyState::Refused) {
                continue;
            }
            let since = match since {
                Some(since) => since,
                None if self
                    .host
                    .receipt(&task.status.receipt_id)
                    .is_some_and(|r| r.result.is_some()) =>
                {
                    store.db.execute(
                        "UPDATE return_grants SET awaiting_since_ms=?2 WHERE task_id=?1",
                        rusqlite::params![grant.task_id, now],
                    )?;
                    now
                }
                None => continue,
            };
            if task.status.state == WorkState::AwaitingResult
                && now >= since.saturating_add(self.work.config.collab.result_timeout_ms())
                && !task.status.detail.starts_with("turn ended without a reply")
            {
                task.status.detail = "turn ended without a reply".into();
                if self.work.config.route(&task.route_id).is_some_and(|r| {
                    r.auto_report == crate::runtime::host_work::AutoReport::FinalMessage
                }) && let Some(session) =
                    SessionId::parse(&task.task.target.session_id).and_then(|s| sessions.get(&s))
                {
                    let text = session
                        .chat
                        .retained()
                        .filter(|m| {
                            m.role == crate::chat::session::Role::Assistant
                                && Some(m.turn_id.as_str()) == task.turn_id.as_deref()
                        })
                        .filter_map(|m| {
                            let text = m
                                .parts
                                .iter()
                                .filter_map(|p| {
                                    if let crate::chat::adapter::Part::Text { markdown, .. } = p {
                                        Some(markdown.as_str())
                                    } else {
                                        None
                                    }
                                })
                                .collect::<Vec<_>>()
                                .join("\n");
                            (!text.is_empty()).then_some(text)
                        })
                        .last();
                    if let Some(text) = text {
                        task.status.detail.push_str(": ");
                        task.status.detail.extend(
                            text.chars()
                                .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
                                .take(200),
                        );
                    }
                }
                store.save_work(&task)?;
            }
        }
        Ok(())
    }

    /// The sender of `task` is gone for good: the task, and a delivery of
    /// its reply still waiting to be prompted, fail instead of waiting for
    /// it (spec section 10, "Ending early"). Settled ones stay as they are.
    fn collab_sender_gone(&self, task: &mut WorkRecord) -> Result<()> {
        let store = self.work.store.as_ref().unwrap();
        if !task.status.state.terminal() || task.status.state == WorkState::OutcomeUnknown {
            task.status.state = WorkState::Failed;
            task.status.detail = SENDER_GONE.into();
            store.save_work(task)?;
        }
        let delivery = results::load(&store.db, &task.task.task_id)?
            .and_then(|row| row.work_id)
            .map(|id| store.work(&id))
            .transpose()?
            .flatten();
        if let Some(mut delivery) = delivery
            && matches!(
                delivery.status.state,
                WorkState::Queued | WorkState::Blocked
            )
        {
            delivery.status.state = WorkState::Failed;
            delivery.status.detail = SENDER_GONE.into();
            store.save_work(&delivery)?;
        }
        Ok(())
    }

    /// What pauses local collaboration, in the owner's words: `runtime.toml`
    /// not loading, hosting switched off, the receipt database failed. A
    /// pause only waits (spec section 9): queued local tasks, replies and
    /// their deliveries wait, nothing is fenced, and everything resumes once
    /// these are gone. Empty exactly when the pause is over (`local_healthy`
    /// adds the authority checks). `[collab] send = false` is no pause: the
    /// owner's setting refuses new sends only (`collab_unavailable`).
    pub(super) fn collab_paused(&self) -> Vec<String> {
        if let Some(problem) = &self.work.config_problem {
            return vec![format!(
                "runtime.toml is not valid ({problem}); fix it, then see `atem runtime check`"
            )];
        }
        let mut paused = Vec::new();
        if !self.work.config.enabled {
            paused.push("set `enabled = true` in runtime.toml".to_string());
        }
        if self.work.error {
            paused.push("agent hosting records are unavailable; run `atem runtime restart`".into());
        }
        paused
    }

    /// What keeps a new send from going out, in the owner's words: the
    /// pauses (`collab_paused`), sending switched off, the pairing and the
    /// device list.
    fn collab_unavailable(&self) -> Vec<String> {
        let mut missing = self.collab_paused();
        if self.work.config_problem.is_some() {
            return missing;
        }
        if !self.work.config.collab.send {
            missing.push("set `[collab] send = true` in runtime.toml".to_string());
        }
        missing.extend(self.collab_unauthorized());
        missing
    }

    /// What `local` lacks of a verified host's authority, in the owner's
    /// words: the pairing, the device list, the session journal.
    fn collab_unauthorized(&self) -> Vec<String> {
        let mut missing = Vec::new();
        if self.host.context().account_id == UNPAIRED {
            missing.push("pair and verify this device with Astation (`atem pair`)".into());
        } else if let Some(error) = &self.membership_error {
            missing.push(format!("the device list is unusable ({error})"));
        } else if let Some(m) = &self.membership {
            if m.is_frozen() {
                missing
                    .push("the device list is frozen; a managing device must reconcile it".into());
            } else if m.faulted().is_some() || m.held().is_some() {
                missing.push(
                    "the device list is held after a fault; a managing device must reconcile it (see `atem status`)"
                        .into(),
                );
            }
        }
        if self.host.journal_halted() {
            missing.push("the session journal halted; run `atem runtime restart`".into());
        }
        missing
    }

    /// The task store as a reply or a completion needs it: under the host's
    /// current authority and readable. A pause doesn't matter here.
    fn collab_store_ready(&mut self) -> Result<()> {
        self.work_config();
        let mut missing = self.collab_unauthorized();
        if self.work.error {
            missing
                .push("agent hosting records are unavailable; run `atem runtime restart`".into());
        }
        if !missing.is_empty() || !self.local_authorized() {
            bail!(
                "collaboration unavailable: {}",
                if missing.is_empty() {
                    "see `atem status`".to_string()
                } else {
                    missing.join("; ")
                }
            );
        }
        if self.work.store.is_none() || !self.work_store_ready(&self.work_host()) {
            bail!("collaboration receipt store unavailable");
        }
        Ok(())
    }

    fn collab_ready(&mut self) -> Result<()> {
        self.work_config();
        let missing = self.collab_unavailable();
        if !missing.is_empty() || !self.local_healthy() {
            bail!(
                "collaboration unavailable: {}",
                if missing.is_empty() {
                    "see `atem runtime check` and `atem status`".to_string()
                } else {
                    missing.join("; ")
                }
            );
        }
        if !self.work_store_ready(&self.work_host()) {
            bail!("collaboration receipt store unavailable");
        }
        Ok(())
    }

    /// Why a task made from this message could never be dispatched. The
    /// target is a placeholder: only the content decides.
    fn collab_content_problem(&self, message: &Message) -> Option<&'static str> {
        let host = self.work_host();
        let target = wire::Target {
            account_id: host.account_id.clone(),
            atem_device_id: host.atem_device_id.clone(),
            host_trust_gen: host.host_trust_gen,
            session_id: SessionId::new().to_string(),
            process_gen: uuid::Uuid::new_v4().to_string(),
        };
        let task = local_task(message, &uuid::Uuid::new_v4().to_string(), target);
        collab::task_problem(&task, &host)
    }

    pub(super) fn collab_candidates(
        &self,
        sessions: &BTreeMap<SessionId, BrokerSession>,
    ) -> Vec<Candidate> {
        let mut candidates = Vec::new();
        for route in &self.work.config.routes {
            if !route.principals.iter().any(|p| p == "local") {
                continue;
            }
            let Some(profile) = self.work.config.profile(&route.profile_id) else {
                continue;
            };
            for session in sessions.values().filter(|s| {
                s.is_live()
                    && s.cwd == profile.cwd
                    && s.provider == profile.provider
                    && self.projects.key_of(s.id.as_str()) == Some(profile.project.as_str())
            }) {
                let labels = self
                    .work
                    .config
                    .instance
                    .labels
                    .iter()
                    .chain(&route.labels)
                    .chain(session.self_tags())
                    .filter_map(|s| s.parse().ok())
                    .collect();
                candidates.push(Candidate {
                    route_id: route.id.clone(),
                    route_revision: route.revision,
                    session_id: session.id.to_string(),
                    process_gen: session.process_gen.clone(),
                    started_ms: session.created_at_ms,
                    labels,
                });
            }
        }
        candidates
    }

    pub fn collab_directory(
        &mut self,
        atem_id: &str,
        selector: Option<&str>,
        sessions: &BTreeMap<SessionId, BrokerSession>,
    ) -> Result<Vec<DirectoryRow>> {
        self.work_config();
        let selector: Option<Selector> = selector
            .map(str::parse)
            .transpose()
            .map_err(|e| anyhow!("{e}"))?;
        let atem_id = atem_id.to_string();
        let mut rows = Vec::new();
        for route in &self.work.config.routes {
            let profile = self
                .work
                .config
                .profile(&route.profile_id)
                .ok_or_else(|| anyhow!("missing route profile"))?;
            let matched: Vec<_> = sessions
                .values()
                .filter(|s| {
                    s.is_live()
                        && s.cwd == profile.cwd
                        && s.provider == profile.provider
                        && self.projects.key_of(s.id.as_str()) == Some(profile.project.as_str())
                })
                .collect();
            for session in matched
                .iter()
                .map(Some)
                .chain(matched.is_empty().then_some(None))
            {
                let labels = self
                    .work
                    .config
                    .instance
                    .labels
                    .iter()
                    .chain(&route.labels)
                    .chain(session.into_iter().flat_map(|s| s.self_tags()))
                    .filter_map(|s| s.parse().ok())
                    .collect();
                if selector.as_ref().is_some_and(|s| {
                    !s.matches(&AgentLabels {
                        atem_id: &atem_id,
                        route_id: &route.id,
                        labels: &labels,
                    })
                }) {
                    continue;
                }
                rows.push(DirectoryRow {
                    atem_id: atem_id.clone(),
                    route_id: route.id.clone(),
                    labels: labels.iter().map(|s| s.as_str().into()).collect(),
                    session_id: session.map(|s| s.id.to_string()),
                    local_consent: route.principals.iter().any(|p| p == "local"),
                });
            }
        }
        rows.sort_by(|a, b| (&a.route_id, &a.session_id).cmp(&(&b.route_id, &b.session_id)));
        Ok(rows)
    }

    fn collab_workflow(&self, from: &BrokerSession) -> Result<String> {
        let turn = from.chat.current_turn_id();
        for task in self.work.store.as_ref().unwrap().tasks()? {
            if task.task.target.session_id != from.id.as_str()
                || task.task.target.process_gen != from.process_gen
            {
                continue;
            }
            let bound = from.chat.current_request_id() == Some(task.status.receipt_id.as_str())
                || turn.is_some_and(|turn| {
                    task.turn_id.as_deref() == Some(turn)
                        || self
                            .host
                            .receipt(&task.status.receipt_id)
                            .and_then(|r| r.result)
                            .is_some_and(|r| r.turn_id == turn)
                });
            // The child may call us before the worker's prompt hook has
            // reached the broker. Its durable dispatch already owns this
            // session's queue slot; never let that race start a new loop.
            let starting = matches!(
                task.status.state,
                WorkState::Submitting | WorkState::Submitted
            ) && self
                .host
                .receipt(&task.status.receipt_id)
                .is_some_and(|r| r.result.is_none());
            if bound || starting {
                return Ok(task.task.workflow_id);
            }
        }
        Ok(uuid::Uuid::new_v4().to_string())
    }

    pub fn collab_send(
        &mut self,
        atem_id: &str,
        from: &SessionId,
        request: SendRequest,
        sessions: &BTreeMap<SessionId, BrokerSession>,
    ) -> Result<String> {
        self.collab_ready()?;
        if let Some(problem) = selectors_problem(&request.to, MAX_AGENTS) {
            bail!("{problem}");
        }
        if !(1_000..=hw::MAX_LIFETIME_MS).contains(&request.expires_ms) {
            bail!("expiry must be between 1s and 24h");
        }
        let specs = crate::runtime::collab_context::capture(
            &self.work.dir,
            &request.memory,
            &request.vault,
        )?;
        if request.launch
            && !request.to.iter().any(|s| {
                s.parse::<Selector>().is_ok_and(|s| {
                    matches!(s,
            Selector::Instance { atem_id: id, route_id: Some(_) } if id == atem_id)
                })
            })
        {
            bail!(
                "use --launch with atem:<atem_id>/<route_id>; the route must allow launch = on_message"
            );
        }
        let origin = sessions
            .get(from)
            .filter(|s| s.is_live())
            .ok_or_else(|| anyhow!("originating session ended"))?;
        let source = self.collab_origin(origin, sessions);
        let now = host_now().wall_ms;
        let message = Message {
            message_id: uuid::Uuid::new_v4().to_string(),
            workflow_id: self.collab_workflow(origin)?,
            sender: "local".into(),
            kind: MessageKind::Request,
            reply_to: None,
            from_session: Some(from.to_string()),
            created_at: now,
            expires_at: now.saturating_add(request.expires_ms),
            recipients: vec![Recipient {
                recipient_id: uuid::Uuid::new_v4().to_string(),
                host: self.work_host(),
                destination: Destination::Select {
                    selectors: request.to.clone(),
                    budget: MAX_AGENTS,
                },
            }],
            text: request.text,
            context: vec![],
            mark: None,
        };
        let mut probe = message.clone();
        if probe.text.trim().is_empty() && !specs.is_empty() {
            probe.text = "pending context".into();
        }
        if !probe.valid_local() {
            bail!("invalid message content");
        }
        // What is known now (a memory's text) must already fit a task; a
        // vault entry is checked once it is read back.
        probe.context = specs
            .iter()
            .filter_map(ContextSpec::known_snapshot)
            .collect();
        if let Some(problem) = self.collab_content_problem(&probe) {
            bail!("{problem}");
        }
        if !specs.is_empty() {
            collab::reserve_context(
                self.work.store.as_ref().unwrap(),
                &self.work.config.collab,
                &message,
                &collab::Publication {
                    atem_id: atem_id.into(),
                    origin: source.clone(),
                    context: specs,
                },
            )?;
        } else {
            self.collab_accept(atem_id, &message, &source, sessions)?;
        }
        Ok(message.message_id)
    }

    pub(super) fn collab_accept(
        &mut self,
        atem_id: &str,
        message: &Message,
        origin: &Origin,
        sessions: &BTreeMap<SessionId, BrokerSession>,
    ) -> Result<()> {
        // Replies are result rows (`collab_reply`), never messages.
        if message.kind != MessageKind::Request {
            bail!("invalid message content");
        }
        if let Some(old) = self
            .work
            .store
            .as_ref()
            .unwrap()
            .message(&message.message_id)?
        {
            if old.message != *message {
                bail!("request_id_reused");
            }
            return Ok(());
        }
        if !message.valid_local() {
            bail!("invalid message content");
        }
        // Every task of a message has this prompt and context, so one that
        // could never dispatch refuses the message before it is counted.
        if let Some(problem) = self.collab_content_problem(message) {
            bail!("{problem}");
        }
        let from = message.from_session.as_deref().unwrap();
        let plan = self.collab_resolve(atem_id, message, sessions)?;
        let resolved = &plan.tasks;
        let mut work = Vec::new();
        for r in resolved {
            let route = self.work.config.route(&r.route_id).unwrap();
            let profile = self.work.config.profile(&route.profile_id).unwrap();
            let target = wire::Target {
                account_id: self.work_host().account_id.clone(),
                atem_device_id: self.work_host().atem_device_id.clone(),
                host_trust_gen: self.work_host().host_trust_gen,
                session_id: r.session_id.clone(),
                process_gen: r.process_gen.clone(),
            };
            let task = local_task(message, &r.task_id, target);
            let record = WorkRecord {
                principal: "local".into(),
                attachment_owner: Sender::Local.owner(),
                control_gen: self.host.control_gen("local"),
                route_id: route.id.clone(),
                route_revision: route.revision,
                profile_id: profile.id.clone(),
                profile_revision: profile.revision,
                project: profile.project.clone(),
                digest: hw::digest(&serde_json::to_vec(&(&message, &r.task_id))?),
                task,
                status: WorkStatus {
                    task_id: r.task_id.clone(),
                    receipt_id: uuid::Uuid::new_v4().to_string(),
                    state: WorkState::Queued,
                    detail: "waiting for a ready agent".into(),
                    result: None,
                },
                turn_id: None,
            };
            if !(self.work_allowed(&record, &Sender::Local, sessions)
                || r.launch_request_id.is_some()
                    && self.work_route_allowed(&record, &Sender::Local))
            {
                bail!("route {} no longer permits local work", route.id);
            }
            work.push(record);
        }
        let record = MessageRecord {
            sender_key: json!("local"),
            message: message.clone(),
            receipt: MessageReceipt {
                message_id: message.message_id.clone(),
                digest: message.digest(),
                sender: "local".into(),
                recipients: work
                    .iter()
                    .map(|r| RecipientReceipt {
                        recipient_id: r.task.task_id.clone(),
                        delivery: Delivery::Work {
                            work: (&r.status).into(),
                        },
                    })
                    .collect(),
            },
        };
        self.work
            .store
            .as_ref()
            .unwrap()
            .accept_message_with(&record, &work, |tx| {
                // One message, once under `send:` and once under `receive:`,
                // however many agents it reaches.
                collab::count_send(
                    tx,
                    &self.work.config.collab,
                    from,
                    &message.workflow_id,
                    message.created_at,
                )?;
                collab::count_received(
                    tx,
                    &self.work.config.collab,
                    &message.workflow_id,
                    message.created_at,
                )?;
                tx.execute(
                    "INSERT INTO origins(message_id,record) VALUES(?1,?2)",
                    rusqlite::params![message.message_id, serde_json::to_string(origin)?],
                )?;
                for task in &work {
                    results::save_grant(
                        tx,
                        &ReturnGrant {
                            task_id: task.task.task_id.clone(),
                            message_id: message.message_id.clone(),
                            workflow_id: message.workflow_id.clone(),
                            origin: origin.clone(),
                            recipient: task.task.target.clone(),
                            expires_at: message.expires_at,
                        },
                    )?;
                }
                self.collab_reserve_launches(tx, &plan)?;
                collab::persist(tx, message, resolved)
            })?;
        self.collab_start_launches(plan, message.expires_at);
        Ok(())
    }

    pub(super) fn collab_pass(&mut self, cx: &mut Cx) -> Result<()> {
        if !self.local_healthy() {
            return Ok(());
        }
        let local = self.local_attachment().to_string();
        let idle: Vec<_> = cx
            .sessions
            .values()
            .filter(|s| {
                self.host.lease_holder(s.id.as_str()) == Some(local.as_str())
                    && !self.prompts.values().any(|id| id == s.id.as_str())
            })
            .map(|s| s.id.to_string())
            .collect();
        for sid in idle {
            let host = self.work_host();
            let target = self.host.descriptor_of(&sid).map(|d| wire::Target {
                account_id: host.account_id,
                atem_device_id: host.atem_device_id,
                host_trust_gen: host.host_trust_gen,
                session_id: d.session_id,
                process_gen: d.process_gen,
            });
            if let Some(target) = target
                && let Some((binding, _)) = self.host.binding_for_work(&local, &target)
            {
                // A finished local prompt gives up its lease before the next
                // FIFO task. Other controllers keep their leases unchanged.
                let effects = self.host.receive(
                    &local,
                    json!({"type":"session","data":{"v":1,"op":"release",
                    "id":uuid::Uuid::new_v4().to_string(),"binding":binding}})
                    .to_string()
                    .as_bytes(),
                    self.clock.now(),
                );
                self.exec(effects, cx);
            }
        }
        self.collab_result_pass(cx.sessions)?;
        let now = host_now().wall_ms;
        let store = self.work.store.as_ref().unwrap();
        if Instant::now() >= self.work.pruned {
            self.work.pruned = Instant::now() + PRUNE_EVERY;
            collab::prune_counters(&store.db, now)?;
        }
        store.db.execute(
            "UPDATE outbox SET state='expired',detail='expired before context publication'
            WHERE state='publishing' AND json_extract(envelope,'$.expires_at')<=?1",
            [now],
        )?;
        // Jobs of sends and of replies still publishing are kept.
        let mut active: HashSet<String> = store
            .db
            .prepare("SELECT message_id FROM outbox WHERE state='publishing'")?
            .query_map([], |r| r.get(0))?
            .collect::<std::result::Result<_, _>>()?;
        active.extend(results::publishing(&store.db)?);
        self.work.context_jobs.retain(|id, _| active.contains(id));
        let pending = collab::context_due(store, now)?;
        for (mut message, publication, attempts) in pending {
            let id = message.message_id.clone();
            let store = self.work.store.as_ref().unwrap();
            let origin_live = self.collab_origin_live(&publication.origin, cx.sessions);
            if !origin_live {
                self.work.context_jobs.remove(&id);
                collab::publication_state(store, &id, "refused", "originating session ended", 0)?;
                continue;
            }
            if let Some(job) = self.work.context_jobs.get_mut(&id) {
                let result = match job.try_recv() {
                    Ok(r) => r,
                    Err(tokio::sync::oneshot::error::TryRecvError::Empty) => continue,
                    Err(_) => Err(anyhow!("relay unreachable")),
                };
                self.work.context_jobs.remove(&id);
                let result = result.and_then(|snapshots| {
                    message.context = snapshots;
                    self.collab_accept(
                        &publication.atem_id,
                        &message,
                        &publication.origin,
                        cx.sessions,
                    )
                });
                if let Err(error) = result {
                    let detail = error.to_string();
                    let store = self.work.store.as_ref().unwrap();
                    if publication_refused(&detail) {
                        collab::publication_state(store, &id, "refused", &detail, 0)?;
                    } else {
                        let delay = 1_000u64
                            .saturating_mul(1u64 << attempts.min(9))
                            .min(300_000);
                        store.db.execute(
                            "UPDATE publications SET attempts=attempts+1 WHERE message_id=?1",
                            [&id],
                        )?;
                        collab::publication_state(
                            store,
                            &id,
                            "publishing",
                            "relay unreachable; publication will retry",
                            now.saturating_add(delay),
                        )?;
                    }
                }
            } else if self.work.context_jobs.len() < 2 {
                self.collab_publish_job(id, publication.context);
            }
        }
        Ok(())
    }

    /// `atem message status`: inside a session (`caller`), the messages it
    /// sent and the tasks sent to it; from outside any session, everything
    /// (spec section 10, "Who sees what").
    pub fn collab_status(
        &mut self,
        caller: Option<&SessionId>,
        id: Option<&str>,
    ) -> Result<Vec<MessageView>> {
        self.work_config();
        if self.work.store.is_some() && !self.work_store_ready(&self.work_host()) {
            bail!("collaboration receipt store unavailable");
        }
        let Some(store) = self.work.store.as_ref() else {
            return Ok(vec![]);
        };
        collab::views(store, id, caller.map(SessionId::as_str))
    }

    /// `atem message cancel`: inside a session (`caller`), a task of a
    /// message it sent; from outside any session, any local task.
    pub fn collab_cancel(&mut self, caller: Option<&SessionId>, id: &str) -> Result<()> {
        let store = self
            .work
            .store
            .as_ref()
            .ok_or_else(|| anyhow!("no task store"))?;
        let mut task = store
            .work(id)?
            .filter(|r| r.principal == "local")
            .ok_or_else(|| anyhow!("no local collaboration task"))?;
        if let Some(caller) = caller
            && collab::sender_of(store, id)?.as_deref() != Some(caller.as_str())
        {
            bail!(
                "task {id} is not one of this session's messages; only the session that sent it (or the owner, outside any session) cancels it"
            );
        }
        if !matches!(task.status.state, WorkState::Queued | WorkState::Blocked) {
            bail!("only queued or blocked tasks can be cancelled");
        }
        task.status.state = WorkState::Cancelled;
        task.status.detail = "cancelled locally before submission".into();
        store.save_work(&task)
    }
}

/// The task one recipient of a local request gets: the sender's text and
/// context, and how to answer.
fn local_task(message: &Message, task_id: &str, target: wire::Target) -> hw::WorkTask {
    let from = message.from_session.as_deref().unwrap_or_default();
    hw::WorkTask {
        task_id: task_id.into(),
        workflow_id: message.workflow_id.clone(),
        target,
        expires_at: message.expires_at,
        prompt: format!(
            "[Message {} from local session {}]\n{}\n\nReply with: atem message reply --task {} <text>",
            message.message_id, from, message.text, task_id
        ),
        context: message.context.clone(),
        attachments: vec![],
    }
}
