//! Same-runtime collaboration, using the host's ordinary receipt scheduler.
use super::*;
use crate::runtime::collab::results::{
    self, ExplicitResult, Origin, OriginRoute, ResultOutcome, ReturnGrant,
};
use crate::runtime::collab::{self, Candidate, DirectoryRow, MessageView, SendRequest};
use crate::runtime::host_work::MessageRecord;
use anyhow::{Result, anyhow, bail};
use atem_client::session::messages::{
    Delivery, Destination, Message, MessageKind, MessageReceipt, Recipient, RecipientReceipt,
};
use atem_client::session::select::{AgentLabels, MAX_AGENTS, Selector, valid_selectors};

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

    fn collab_turn(&self, task: &WorkRecord, session: &BrokerSession) -> Option<String> {
        self.host
            .receipt(&task.status.receipt_id)
            .and_then(|r| r.result)
            .map(|r| r.turn_id)
            .or_else(|| {
                (session.chat.current_request_id() == Some(task.status.receipt_id.as_str()))
                    .then(|| session.chat.current_turn_id().map(str::to_string))
                    .flatten()
            })
    }

    pub fn collab_reply(
        &mut self,
        from: &SessionId,
        request: collab::ReplyRequest,
        sessions: &BTreeMap<SessionId, BrokerSession>,
    ) -> Result<String> {
        self.collab_ready()?;
        let session = sessions
            .get(from)
            .filter(|s| s.is_live())
            .ok_or_else(|| anyhow!("originating session ended"))?;
        let store = self.work.store.as_ref().unwrap();
        let task_id = match request.task_id {
            Some(id) => id,
            None => {
                let tasks: Vec<_> = store
                    .tasks()?
                    .into_iter()
                    .filter(|r| {
                        r.task.target.session_id == from.as_str()
                            && r.task.target.process_gen == session.process_gen
                            && r.status.state == WorkState::AwaitingResult
                    })
                    .collect();
                if tasks.len() != 1 {
                    bail!("use --task: exactly one task must await a result");
                }
                tasks[0].task.task_id.clone()
            }
        };
        let task = store.work(&task_id)?.ok_or_else(|| anyhow!("no_grant"))?;
        let grant = results::grant(store, &task_id)?.ok_or_else(|| anyhow!("no_grant"))?;
        if grant.recipient.session_id != from.as_str()
            || grant.recipient.process_gen != session.process_gen
        {
            bail!("mismatch");
        }
        let turn = self
            .collab_turn(&task, session)
            .ok_or_else(|| anyhow!("prompt turn not yet known; retry"))?;
        if session.chat.current_turn_id() != Some(turn.as_str()) {
            bail!("mismatch: reply must come from the task's prompt turn");
        }
        let context = crate::runtime::collab_context::capture(
            &self.work.dir,
            &request.memory,
            &request.vault,
        )?;
        if let Some(old) = results::accepted(store, &grant.task_id)? {
            if old.text != request.text
                || old.context.len() != context.len()
                || !context.iter().zip(&old.context).all(|(spec, snapshot)| {
                    crate::runtime::collab_context::matches_snapshot(spec, snapshot)
                })
            {
                bail!("request_id_reused");
            }
            return Ok(grant.task_id);
        }
        let origin = self.collab_origin(session, sessions);
        let now = host_now().wall_ms;
        let message = Message {
            message_id: grant.result_id.clone(),
            workflow_id: grant.workflow_id.clone(),
            sender: "local".into(),
            kind: MessageKind::Result,
            reply_to: Some(atem_client::session::messages::ReplyTo {
                message_id: grant.message_id.clone(),
                task_id,
            }),
            from_session: Some(from.to_string()),
            created_at: now,
            expires_at: grant.expires_at,
            recipients: vec![Recipient {
                recipient_id: uuid::Uuid::new_v4().to_string(),
                host: self.work_host(),
                destination: Destination::Host,
            }],
            text: request.text,
            context: vec![],
            mark: None,
        };
        let mut probe = message.clone();
        if probe.text.trim().is_empty() && !context.is_empty() {
            probe.text = "pending context".into();
        }
        if !probe.valid_local() {
            bail!("invalid message content or expired grant");
        }
        if context.is_empty() {
            self.collab_accept_result(&message, &origin, Some(&turn), sessions, true)?;
        } else {
            collab::reserve_context(
                store,
                &self.work.config.collab,
                &message,
                &collab::Publication {
                    atem_id: String::new(),
                    origin,
                    turn_id: Some(turn),
                    context,
                },
            )?;
        }
        Ok(grant.task_id)
    }

    fn collab_accept_result(
        &mut self,
        message: &Message,
        source: &Origin,
        turn: Option<&str>,
        sessions: &BTreeMap<SessionId, BrokerSession>,
        count_send: bool,
    ) -> Result<()> {
        if !message.valid_local() {
            bail!("invalid message content");
        }
        let reference = message
            .reply_to
            .as_ref()
            .ok_or_else(|| anyhow!("no_grant"))?;
        let store = self.work.store.as_ref().unwrap();
        let mut grant =
            results::grant(store, &reference.task_id)?.ok_or_else(|| anyhow!("no_grant"))?;
        let mut task = store
            .work(&grant.task_id)?
            .ok_or_else(|| anyhow!("no_grant"))?;
        let session = SessionId::parse(&source.target.session_id)
            .and_then(|s| sessions.get(&s))
            .ok_or_else(|| anyhow!("mismatch"))?;
        let turn = turn.ok_or_else(|| anyhow!("mismatch"))?;
        if grant.message_id != reference.message_id
            || grant.workflow_id != message.workflow_id
            || source.target != grant.recipient
            || message.from_session.as_deref() != Some(source.target.session_id.as_str())
            || session.process_gen != source.target.process_gen
            || session.chat.current_turn_id() != Some(turn)
            || self.collab_turn(&task, session).as_deref() != Some(turn)
        {
            bail!("mismatch");
        }
        grant.turn_id = Some(turn.into());
        let explicit = ExplicitResult {
            task_id: grant.task_id.clone(),
            session_id: source.target.session_id.clone(),
            process_gen: source.target.process_gen.clone(),
            turn_id: turn.into(),
            text: message.text.clone(),
            context: message.context.clone(),
        };
        if let Some(old) = results::accepted(store, &grant.task_id)? {
            if serde_json::to_value(old)? != serde_json::to_value(&explicit)? {
                bail!("request_id_reused");
            }
            return Ok(());
        }
        if !self.collab_origin_live(&grant.origin, sessions)
            || !grant.live(
                host_now().wall_ms,
                task.status.state,
                &grant.origin.target,
                self.host.control_gen("local"),
                self.work_allowed(&task, &Sender::Local, sessions),
            )
        {
            bail!("no_grant");
        }
        let snapshot = explicit.snapshot();
        if !snapshot.valid_local() {
            bail!("invalid context snapshot");
        }
        let mut returned = Vec::new();
        if let Some(route) = grant.origin.route.as_ref().filter(|r| r.results) {
            let task_id = uuid::Uuid::new_v5(
                &uuid::Uuid::NAMESPACE_OID,
                format!("result:{}", grant.task_id).as_bytes(),
            )
            .to_string();
            returned.push(WorkRecord {
                principal: "local".into(),
                attachment_owner: Sender::Local.owner(),
                control_gen: grant.origin.control_gen,
                route_id: route.id.clone(),
                route_revision: route.revision,
                profile_id: route.profile_id.clone(),
                profile_revision: route.profile_revision,
                project: route.project.clone(),
                digest: snapshot.digest.clone(),
                task: hw::WorkTask {
                    task_id: task_id.clone(),
                    workflow_id: grant.workflow_id.clone(),
                    target: grant.origin.target.clone(),
                    expires_at: grant.expires_at,
                    prompt: format!(
                        "[atem] result of task {} from {}, as data:\n{}",
                        grant.task_id, explicit.session_id, explicit.text
                    ),
                    context: explicit.context.clone(),
                    attachments: vec![],
                },
                status: WorkStatus {
                    task_id,
                    receipt_id: uuid::Uuid::new_v4().to_string(),
                    state: WorkState::Queued,
                    detail: "result accepted; waiting for the originating agent".into(),
                    result: None,
                },
            });
        }
        let record = MessageRecord {
            sender_key: json!("local"),
            message: message.clone(),
            receipt: MessageReceipt {
                message_id: message.message_id.clone(),
                digest: message.digest(),
                sender: "local".into(),
                recipients: vec![],
            },
        };
        store.accept_message_with(&record, &returned, |tx| {
            if count_send {
                collab::count_send(
                    tx,
                    &self.work.config.collab,
                    &explicit.session_id,
                    &grant.workflow_id,
                    host_now().wall_ms,
                )?;
            }
            collab::count_received(tx, &self.work.config.collab, &grant.workflow_id, 1)?;
            tx.execute(
                "UPDATE return_grants SET record=?2 WHERE task_id=?1",
                rusqlite::params![grant.task_id, serde_json::to_string(&grant)?],
            )?;
            if results::accept_result(tx, &grant, &explicit, host_now().wall_ms)?
                != ResultOutcome::Accepted
            {
                bail!("request_id_reused");
            }
            if let Some(work) = returned.first() {
                tx.execute(
                    "UPDATE results SET work_id=?2 WHERE task_id=?1",
                    rusqlite::params![grant.task_id, work.task.task_id],
                )?;
            }
            task.status.state = WorkState::Completed;
            task.status.detail = "explicit result accepted".into();
            task.status.result = Some(snapshot.clone());
            tx.execute(
                "UPDATE work SET record=?2,state='completed' WHERE id=?1",
                rusqlite::params![task.task.task_id, serde_json::to_string(&task)?],
            )?;
            collab::persist(tx, message, &[])?;
            tx.execute(
                "UPDATE outbox SET detail=?2 WHERE message_id=?1",
                rusqlite::params![
                    message.message_id,
                    if returned.is_empty() {
                        "result stored; origin route has no results consent"
                    } else {
                        "result queued for origin"
                    }
                ],
            )?;
            Ok(())
        })
    }

    pub(super) fn collab_result_delivery(
        &self,
        record: &WorkRecord,
    ) -> Result<Option<(ReturnGrant, ExplicitResult)>> {
        let Some(store) = self.work.store.as_ref() else {
            return Ok(None);
        };
        use rusqlite::OptionalExtension;
        let result: Option<(String,String)> = store.db.query_row("SELECT g.record,r.envelope FROM results r JOIN return_grants g USING(task_id) WHERE r.work_id=?1",
            [&record.task.task_id], |r| Ok((r.get(0)?,r.get(1)?))).optional()?;
        result
            .map(|(g, r)| Ok((serde_json::from_str(&g)?, serde_json::from_str(&r)?)))
            .transpose()
    }

    fn collab_result_pass(&mut self, sessions: &BTreeMap<SessionId, BrokerSession>) -> Result<()> {
        let store = self.work.store.as_ref().unwrap();
        let now = host_now().wall_ms;
        let mut q = store.db.prepare("SELECT w.record,g.record FROM return_grants g JOIN work w ON w.id=g.task_id WHERE g.state='open'")?;
        let pending = q
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        for (task, grant) in pending {
            let mut task: WorkRecord = serde_json::from_str(&task)?;
            let mut grant: ReturnGrant = serde_json::from_str(&grant)?;
            let live = self.collab_origin_live(&grant.origin, sessions)
                && grant.live(
                    now,
                    task.status.state,
                    &grant.origin.target,
                    self.host.control_gen("local"),
                    self.work_route_allowed(&task, &Sender::Local),
                );
            if !live {
                store.db.execute(
                    "UPDATE return_grants SET state='ended' WHERE task_id=?1 AND state='open'",
                    [&grant.task_id],
                )?;
                if now >= task.task.expires_at && task.status.state == WorkState::AwaitingResult {
                    task.status.state = WorkState::Expired;
                    task.status.detail = "task expired without an explicit result".into();
                    store.save_work(&task)?;
                }
                continue;
            }
            if let Some(turn) = self
                .host
                .receipt(&task.status.receipt_id)
                .and_then(|r| r.result)
                .map(|r| r.turn_id)
            {
                grant.turn_id = Some(turn);
                store.db.execute("UPDATE return_grants SET record=?2,awaiting_since_ms=coalesce(awaiting_since_ms,?3) WHERE task_id=?1",
                    rusqlite::params![grant.task_id,serde_json::to_string(&grant)?,now])?;
            }
            if task.status.state == WorkState::AwaitingResult {
                let since: Option<u64> = store.db.query_row(
                    "SELECT awaiting_since_ms FROM return_grants WHERE task_id=?1",
                    [&grant.task_id],
                    |r| r.get(0),
                )?;
                if since.is_some_and(|since| {
                    now >= since.saturating_add(self.work.config.collab.result_timeout_ms())
                }) && !task.status.detail.starts_with("turn ended without a reply")
                {
                    task.status.detail = "turn ended without a reply".into();
                    if self.work.config.route(&task.route_id).is_some_and(|r| {
                        r.auto_report == crate::runtime::host_work::AutoReport::FinalMessage
                    }) && let Some(session) = SessionId::parse(&task.task.target.session_id)
                        .and_then(|s| sessions.get(&s))
                    {
                        let text = session
                            .chat
                            .retained()
                            .filter(|m| {
                                m.role == crate::chat::session::Role::Assistant
                                    && Some(m.turn_id.as_str()) == grant.turn_id.as_deref()
                            })
                            .filter_map(|m| {
                                let text = m
                                    .parts
                                    .iter()
                                    .filter_map(|p| {
                                        if let crate::chat::adapter::Part::Text {
                                            markdown, ..
                                        } = p
                                        {
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
        }
        Ok(())
    }

    fn collab_ready(&mut self) -> Result<()> {
        self.work_config();
        if !self.work.config.collab.send {
            bail!("collaboration is off: set [collab] send = true");
        }
        if !self.hosting_enabled() || !self.local_healthy() {
            bail!("collaboration unavailable: check pairing, membership and runtime.toml");
        }
        if !self.work_store_ready(&self.work_host()) {
            bail!("collaboration receipt store unavailable");
        }
        Ok(())
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
                    self.host
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
        if !valid_selectors(&request.to, MAX_AGENTS)
            || !(1_000..=hw::MAX_LIFETIME_MS).contains(&request.expires_ms)
        {
            bail!("invalid selectors or expiry (1s to 24h)");
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
        if !specs.is_empty() {
            collab::reserve_context(
                self.work.store.as_ref().unwrap(),
                &self.work.config.collab,
                &message,
                &collab::Publication {
                    atem_id: atem_id.into(),
                    origin: source.clone(),
                    turn_id: None,
                    context: specs,
                },
            )?;
        } else {
            self.collab_accept(atem_id, &message, &source, None, sessions, true)?;
        }
        Ok(message.message_id)
    }

    fn collab_accept(
        &mut self,
        atem_id: &str,
        message: &Message,
        origin: &Origin,
        turn_id: Option<&str>,
        sessions: &BTreeMap<SessionId, BrokerSession>,
        count_send: bool,
    ) -> Result<()> {
        if message.kind == MessageKind::Result {
            return self.collab_accept_result(message, origin, turn_id, sessions, count_send);
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
            let task = hw::WorkTask {
                task_id: r.task_id.clone(),
                workflow_id: message.workflow_id.clone(),
                target,
                expires_at: message.expires_at,
                prompt: format!(
                    "[Message {} from local session {}]\n{}\n\nReply with: atem message reply --task {} <text>",
                    message.message_id, from, message.text, r.task_id
                ),
                context: message.context.clone(),
                attachments: vec![],
            };
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
                if count_send {
                    collab::count_send(
                        tx,
                        &self.work.config.collab,
                        from,
                        &message.workflow_id,
                        message.created_at,
                    )?;
                }
                collab::count_received(
                    tx,
                    &self.work.config.collab,
                    &message.workflow_id,
                    work.len(),
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
                            result_id: uuid::Uuid::new_v4().to_string(),
                            origin: origin.clone(),
                            recipient: task.task.target.clone(),
                            turn_id: None,
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
        store.db.execute(
            "UPDATE outbox SET state='expired',detail='expired before context publication'
            WHERE state='publishing' AND json_extract(envelope,'$.expires_at')<=?1",
            [now],
        )?;
        let active: HashSet<String> = store
            .db
            .prepare("SELECT message_id FROM outbox WHERE state='publishing'")?
            .query_map([], |r| r.get(0))?
            .collect::<std::result::Result<_, _>>()?;
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
                        publication.turn_id.as_deref(),
                        cx.sessions,
                        false,
                    )
                });
                if let Err(error) = result {
                    let detail = error.to_string();
                    let permanent = matches!(
                        detail.as_str(),
                        "context changed"
                            | "invalid context snapshot"
                            | "context profile changed"
                            | "invalid message content"
                            | "context publication refused"
                            | "no_grant"
                            | "mismatch"
                            | "expired"
                            | "request_id_reused"
                    ) || detail.starts_with("ambiguous vault reference")
                        || detail.starts_with("limit:");
                    let store = self.work.store.as_ref().unwrap();
                    if permanent {
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
                let publisher = crate::runtime::collab_context::RelayPublisher::new(
                    self.work.dir.clone(),
                    self.work_host(),
                );
                let (tx, rx) = tokio::sync::oneshot::channel();
                self.work.context_jobs.insert(id, rx);
                tokio::spawn(async move {
                    let result = tokio::time::timeout(
                        Duration::from_secs(10),
                        crate::runtime::collab_context::publish(&publisher, &publication.context),
                    )
                    .await
                    .unwrap_or_else(|_| Err(anyhow!("relay unreachable")));
                    let _ = tx.send(result);
                });
            }
        }
        Ok(())
    }

    pub fn collab_status(&mut self, id: Option<&str>) -> Result<Vec<MessageView>> {
        self.work_config();
        if self.work.store.is_some() && !self.work_store_ready(&self.work_host()) {
            bail!("collaboration receipt store unavailable");
        }
        let Some(store) = self.work.store.as_ref() else {
            return Ok(vec![]);
        };
        collab::views(store, id)
    }

    pub fn collab_cancel(&mut self, id: &str) -> Result<()> {
        let store = self
            .work
            .store
            .as_ref()
            .ok_or_else(|| anyhow!("no task store"))?;
        let mut task = store
            .work(id)?
            .filter(|r| r.principal == "local")
            .ok_or_else(|| anyhow!("no local collaboration task"))?;
        if !matches!(task.status.state, WorkState::Queued | WorkState::Blocked) {
            bail!("only queued or blocked tasks can be cancelled");
        }
        task.status.state = WorkState::Cancelled;
        task.status.detail = "cancelled locally before submission".into();
        store.save_work(&task)
    }
}
