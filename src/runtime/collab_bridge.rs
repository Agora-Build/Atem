//! Same-runtime collaboration, using the host's ordinary receipt scheduler.
use super::*;
use crate::runtime::collab::{self, Candidate, DirectoryRow, MessageView, SendRequest};
use crate::runtime::host_work::MessageRecord;
use anyhow::{Result, anyhow, bail};
use atem_client::session::messages::{
    Delivery, Destination, Message, MessageKind, MessageReceipt, Recipient, RecipientReceipt,
};
use atem_client::session::select::{AgentLabels, MAX_AGENTS, Selector, valid_selectors};

impl HostBridge {
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

    fn collab_candidates(&self, sessions: &BTreeMap<SessionId, BrokerSession>) -> Vec<Candidate> {
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
        &self,
        atem_id: &str,
        selector: Option<&str>,
        sessions: &BTreeMap<SessionId, BrokerSession>,
    ) -> Result<Vec<DirectoryRow>> {
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
        if request.launch {
            bail!("launch on message is not available yet");
        }
        let origin = sessions
            .get(from)
            .filter(|s| s.is_live())
            .ok_or_else(|| anyhow!("originating session ended"))?;
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
                    origin_process_gen: origin.process_gen.clone(),
                    context: specs,
                },
            )?;
        } else {
            self.collab_accept(atem_id, &message, sessions, true)?;
        }
        Ok(message.message_id)
    }

    fn collab_accept(
        &mut self,
        atem_id: &str,
        message: &Message,
        sessions: &BTreeMap<SessionId, BrokerSession>,
        count_send: bool,
    ) -> Result<()> {
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
        let Destination::Select { selectors, .. } = &message.recipients[0].destination else {
            bail!("invalid local destination");
        };
        let selectors = selectors
            .iter()
            .map(|s| s.parse())
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| anyhow!("{e}"))?;
        let resolved = collab::resolve(
            atem_id,
            &self.collab_candidates(sessions),
            &selectors,
            MAX_AGENTS,
            from,
            &message.message_id,
            &message.recipients[0].recipient_id,
        );
        let mut work = Vec::new();
        for r in &resolved {
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
            if !self.work_allowed(&record, &Sender::Local, sessions) {
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
                collab::persist(tx, &message, &resolved)
            })?;
        Ok(())
    }

    pub(super) fn collab_pass(&mut self, cx: &mut Cx) -> Result<()> {
        if !self.local_healthy() {
            return Ok(());
        }
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
            let origin_live = SessionId::parse(message.from_session.as_deref().unwrap_or(""))
                .and_then(|s| cx.sessions.get(&s))
                .is_some_and(|s| s.is_live() && s.process_gen == publication.origin_process_gen);
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
                    self.collab_accept(&publication.atem_id, &message, cx.sessions, false)
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

    pub fn collab_status(&self, id: Option<&str>) -> Result<Vec<MessageView>> {
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
