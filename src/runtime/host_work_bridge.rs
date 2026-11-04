//! Opt-in host operations. Work reaches agents only through session-v1 receipts.
use super::*;
use crate::runtime::host_work::{Config, LaunchRecord, Profile, Store, WorkRecord};
use crate::session_protocol::r9::ProjectScope;
use atem_client::principal::{Authority, Need, Op};
use atem_client::session::host_work::{
    self as hw, HostTarget, LaunchState, LaunchStatus, ResultBody, WorkState, WorkStatus,
};
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;

pub struct RemoteLaunch {
    pub request_id: String,
    pub profile: Profile,
    pub session_id: String,
    pub process_gen: String,
    pub guard: super::super::adopt::SpawnGuard,
}

struct PendingLaunch {
    attachment: String,
    principal: String,
    control_gen: u64,
    profile: Profile,
    expires_at: u64,
    permit: Arc<AtomicBool>,
}

pub(super) struct State {
    available: bool,
    dir: PathBuf,
    config: Config,
    store: Option<Store>,
    error: bool,
    refresh: Instant,
    scheduled: Instant,
    recovered: bool,
    pending: HashMap<String, PendingLaunch>,
    launches: VecDeque<RemoteLaunch>,
}

impl State {
    pub(super) fn open(journal: &Path, available: bool) -> Self {
        let dir = journal
            .parent()
            .and_then(Path::parent)
            .unwrap_or(journal)
            .to_path_buf();
        Self {
            available,
            dir,
            config: Config::default(),
            store: None,
            error: false,
            refresh: Instant::now(),
            scheduled: Instant::now(),
            recovered: false,
            pending: HashMap::new(),
            launches: VecDeque::new(),
        }
    }
}

impl Drop for State {
    fn drop(&mut self) {
        for p in self.pending.values() {
            p.permit.store(false, Ordering::SeqCst);
        }
    }
}

impl HostBridge {
    pub fn hosting_enabled(&self) -> bool {
        self.work.config.enabled && !self.work.error
    }

    pub fn take_remote_launches(&mut self) -> Vec<RemoteLaunch> {
        self.work.launches.drain(..).collect()
    }

    pub fn remote_launched(&mut self, request_id: &str, state: LaunchState) {
        if self.work.pending.remove(request_id).is_none() {
            // Fenced when the host's identity changed: its record went
            // aside with the old database (`work_store_ready`).
            return;
        }
        let result = (|| -> anyhow::Result<()> {
            let store = self
                .work
                .store
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("no work store"))?;
            let mut record = store
                .launch(request_id)?
                .ok_or_else(|| anyhow::anyhow!("missing launch"))?;
            // A start failure can follow a delivered worker Start. Never retry it.
            record.status.state = state;
            store.save_launch(&record)
        })();
        if result.is_err() {
            self.work_fail();
        }
    }

    fn work_fail(&mut self) {
        if !self.work.error {
            eprintln!(
                "atem runtime: agent hosting unavailable; inspect the private host configuration and receipt database"
            );
        }
        self.work.error = true;
        self.r9.enable_host_work(false);
        for p in self.work.pending.values() {
            p.permit.store(false, Ordering::SeqCst);
        }
    }

    pub(super) fn work_config(&mut self) {
        if !self.work.available {
            return;
        }
        if Instant::now() < self.work.refresh {
            return;
        }
        self.work.refresh = Instant::now() + Duration::from_secs(1);
        match Config::load(&self.work.dir) {
            Ok(config) => {
                let retained: HashSet<String> =
                    config.profiles.iter().map(Profile::scope_key).collect();
                for profile in &self.work.config.profiles {
                    if !retained.contains(&profile.scope_key()) {
                        self.projects.forget(&profile.scope_key());
                    }
                }
                self.work.config = config;
                if self.work.config.enabled && self.work.store.is_none() && !self.work.error {
                    match Store::open(self.dir.parent().unwrap_or(&self.dir)) {
                        Ok(store) => self.work.store = Some(store),
                        Err(_) => self.work_fail(),
                    }
                }
                for p in &self.work.config.profiles {
                    self.projects
                        .session(&p.scope_key(), Some(p.project.clone()));
                }
            }
            Err(_) => self.work_fail(),
        }
        self.r9
            .enable_host_work(self.hosting_enabled() && self.work.store.is_some());
    }

    fn work_host(&self) -> HostTarget {
        let ctx = self.host.context();
        HostTarget {
            account_id: ctx.account_id.clone(),
            atem_device_id: ctx.atem_device_id.clone(),
            host_trust_gen: ctx.host_trust_gen,
        }
    }

    fn work_authority(&mut self, attachment: &str) -> Option<Authority> {
        self.r9_call(|r9, parts| r9.current_work_authority(attachment, parts))
    }

    fn profile_allowed(&self, profile: &Profile, authority: &Authority, launch: bool) -> bool {
        (!launch || profile.permits(authority))
            && authority.session_in_scope(
                &self.host.context().atem_device_id,
                &profile.scope_key(),
                &|entry| self.projects.matches(&profile.scope_key(), entry),
            )
    }

    fn work_allowed(
        &self,
        record: &WorkRecord,
        a: &Authority,
        sessions: &BTreeMap<SessionId, BrokerSession>,
    ) -> bool {
        let Some(profile) = self.work.config.profile(&record.profile_id) else {
            return false;
        };
        let Some(session) =
            SessionId::parse(&record.task.target.session_id).and_then(|id| sessions.get(&id))
        else {
            return false;
        };
        self.work_route_allowed(record, a)
            && session.process_gen == record.task.target.process_gen
            && session.cwd == profile.cwd
            && session.provider == profile.provider
            && authority_session(a, &record.task.target, &self.projects)
            && self.projects.key_of(&record.task.target.session_id) == Some(record.project.as_str())
    }

    fn work_route_allowed(&self, record: &WorkRecord, a: &Authority) -> bool {
        let Some(route) = self.work.config.route(&record.route_id) else {
            return false;
        };
        let Some(profile) = self.work.config.profile(&route.profile_id) else {
            return false;
        };
        route.revision == record.route_revision
            && (record.attachment_owner.is_empty()
                || record.attachment_owner == attachment_owner(a))
            && route.principals.contains(&a.name())
            && profile.id == record.profile_id
            && profile.revision == record.profile_revision
            && profile.project == record.project
            && a.allows(Need::Op(Op::Notify))
            && a.allows(Need::Op(Op::Prompt))
            && self.host.control_gen(&a.name()) == record.control_gen
            && self.work_host().contains(&record.task.target)
            && a.session_in_scope(
                &record.task.target.atem_device_id,
                &record.task.target.session_id,
                &|e| self.projects.matches(&profile.scope_key(), e),
            )
    }

    pub(super) fn work_pass(&mut self, cx: &mut Cx) {
        let identity = self.work_host();
        // An unverified host has no identity to keep records under yet.
        if !self.hosting_enabled() || identity.account_id == UNPAIRED {
            for request in self.r9.take_host_work() {
                self.r9.host_work_reply(
                    &request.attachment,
                    &request.request,
                    Err("busy"),
                    self.clock.now(),
                );
            }
            self.work_fence_launches();
            return;
        }
        if !self.work_store_ready(&identity) {
            self.work_fail();
            return;
        }
        if !self.work.recovered {
            if self
                .work
                .store
                .as_ref()
                .unwrap()
                .recover(cx.sessions)
                .is_err()
            {
                self.work_fail();
                return;
            }
            let reconciled = (|| -> anyhow::Result<()> {
                let store = self.work.store.as_ref().unwrap();
                for mut record in store.tasks()? {
                    if record.status.state == WorkState::OutcomeUnknown {
                        self.reconcile_work(&mut record);
                        store.save_work(&record)?;
                    }
                }
                Ok(())
            })();
            if reconciled.is_err() {
                self.work_fail();
                return;
            }
            self.work.recovered = true;
        }
        for request in self.r9.take_host_work() {
            let reply = self.work_request(&request.attachment, &request.request, cx);
            self.r9.host_work_reply(
                &request.attachment,
                &request.request,
                reply,
                self.clock.now(),
            );
        }
        self.work_fence_launches();
        if Instant::now() >= self.work.scheduled {
            self.work.scheduled = Instant::now() + Duration::from_millis(100);
            if self.schedule_work(cx).is_err() {
                self.work_fail();
            }
        }
    }

    /// The store, bound to `identity`. One bound to another identity (this
    /// host was verified or paired again since) is moved aside and a new one
    /// started; launches not yet started under the old one are fenced.
    fn work_store_ready(&mut self, identity: &HostTarget) -> bool {
        let Some(store) = self.work.store.as_ref() else {
            return false;
        };
        match store.bound() {
            Ok(Some(bound)) if bound != *identity => {}
            Ok(_) => return store.bind(identity).is_ok(),
            Err(_) => return false,
        }
        for p in self.work.pending.drain().map(|(_, p)| p) {
            p.permit.store(false, Ordering::SeqCst);
        }
        self.work.launches.clear();
        self.work.recovered = false;
        let state = self.dir.parent().unwrap_or(&self.dir).to_path_buf();
        let store = self.work.store.take().expect("checked above");
        let next = store.retire(host_now().wall_ms).and_then(|aside| {
            let store = Store::open(&state)?;
            store.bind(identity)?;
            Ok((store, aside))
        });
        match next {
            Ok((store, aside)) => {
                eprintln!(
                    "atem runtime: agent hosting records of this host's previous identity moved aside to {}",
                    aside.display()
                );
                self.work.store = Some(store);
                true
            }
            Err(_) => false,
        }
    }

    fn work_fence_launches(&mut self) {
        let ids: Vec<String> = self.work.pending.keys().cloned().collect();
        for id in ids {
            let attachment = self.work.pending[&id].attachment.clone();
            let authority = self.work_authority(&attachment);
            let p = &self.work.pending[&id];
            let allowed = self.hosting_enabled()
                && host_now().wall_ms < p.expires_at
                && self.work.config.profile(&p.profile.id) == Some(&p.profile)
                && self.host.control_gen(&p.principal) == p.control_gen
                && authority.as_ref().is_some_and(|a| {
                    a.name() == p.principal && self.profile_allowed(&p.profile, a, true)
                });
            if !allowed {
                p.permit.store(false, Ordering::SeqCst);
            }
        }
    }

    fn work_request(
        &mut self,
        attachment: &str,
        req: &hw::Request,
        cx: &mut Cx,
    ) -> Result<ResultBody, &'static str> {
        use hw::Request;
        if req.host() != &self.work_host() {
            return Err("stale_target");
        }
        let a = self.work_authority(attachment).ok_or("unauthorized")?;
        let principal = a.name();
        let wall = host_now().wall_ms;
        if let Request::AttachmentPut {
            attachment,
            offset,
            data,
            ..
        } = req
        {
            use base64::Engine;
            if !a.allows(Need::Op(Op::Message))
                || a.client_kind == atem_client::principal::ClientKind::Browser
                || a.scope
                    .as_ref()
                    .and_then(|s| s.hosts.as_ref())
                    .is_some_and(|hosts| !hosts.contains(&req.host().atem_device_id))
            {
                return Err("forbidden");
            }
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(data)
                .map_err(|_| "invalid_request")?;
            let upload = self.work.store.as_ref().ok_or("busy")?.put_attachment(
                &attachment_owner(&a),
                attachment,
                *offset,
                &bytes,
            )?;
            return Ok(ResultBody::Attachment { upload });
        }
        if matches!(req, Request::Publish { .. } | Request::MessageQuery { .. }) {
            return self.message_request(req, &a, cx);
        }
        let store = self.work.store.as_ref().ok_or("busy")?;
        match req {
            Request::Profiles { .. } => Ok(ResultBody::Profiles {
                profiles: self
                    .work
                    .config
                    .profiles
                    .iter()
                    .filter(|p| self.profile_allowed(p, &a, true))
                    .map(Profile::info)
                    .collect(),
            }),
            Request::Launch {
                request_id,
                profile_id,
                profile_revision,
                expires_at,
                ..
            } => {
                let p = self
                    .work
                    .config
                    .profile(profile_id)
                    .filter(|p| {
                        p.revision == *profile_revision && self.profile_allowed(p, &a, true)
                    })
                    .cloned()
                    .ok_or("forbidden")?;
                let digest = hw::digest(
                    serde_json::to_vec(&(req.host(), profile_id, profile_revision, expires_at))
                        .map_err(|_| "invalid_request")?
                        .as_slice(),
                );
                if let Some(old) = store.launch(request_id).map_err(|_| "busy")? {
                    if old.principal != principal || old.digest != digest {
                        return Err("request_id_reused");
                    }
                    return Ok(ResultBody::Launch { launch: old.status });
                }
                if *expires_at <= wall || *expires_at > wall.saturating_add(hw::MAX_LIFETIME_MS) {
                    return Err("invalid_request");
                }
                if cx.sessions.values().filter(|s| s.is_live()).count() + self.work.pending.len()
                    >= crate::session::MAX_LIVE
                {
                    return Err("busy");
                }
                let status = LaunchStatus {
                    request_id: request_id.clone(),
                    session_id: SessionId::new().to_string(),
                    process_gen: uuid::Uuid::new_v4().to_string(),
                    state: LaunchState::Starting,
                };
                store
                    .reserve_launch(&LaunchRecord {
                        principal: principal.clone(),
                        profile_id: profile_id.clone(),
                        profile_revision: *profile_revision,
                        expires_at: *expires_at,
                        digest,
                        status: status.clone(),
                    })
                    .map_err(|_| "busy")?;
                let permit = Arc::new(AtomicBool::new(true));
                let (flag, approved, dir, deadline) = (
                    permit.clone(),
                    p.clone(),
                    self.work.dir.clone(),
                    *expires_at,
                );
                let guard = Arc::new(move || {
                    flag.load(Ordering::SeqCst)
                        && host_now().wall_ms < deadline
                        && Config::load(&dir)
                            .is_ok_and(|c| c.enabled && c.profile(&approved.id) == Some(&approved))
                        && crate::memory::project::project_key_for(&approved.cwd)
                            == approved.project
                });
                self.work.pending.insert(
                    request_id.clone(),
                    PendingLaunch {
                        attachment: attachment.to_string(),
                        principal: principal.clone(),
                        control_gen: self.host.control_gen(&principal),
                        profile: p.clone(),
                        expires_at: *expires_at,
                        permit,
                    },
                );
                self.work.launches.push_back(RemoteLaunch {
                    request_id: request_id.clone(),
                    profile: p,
                    session_id: status.session_id.clone(),
                    process_gen: status.process_gen.clone(),
                    guard,
                });
                Ok(ResultBody::Launch { launch: status })
            }
            Request::LaunchQuery { request_id, .. } => {
                let old = store
                    .launch(request_id)
                    .map_err(|_| "busy")?
                    .ok_or("forbidden")?;
                if old.principal != principal
                    || self.work.config.profile(&old.profile_id).is_none_or(|p| {
                        p.revision != old.profile_revision || !self.profile_allowed(p, &a, true)
                    })
                {
                    return Err("forbidden");
                }
                Ok(ResultBody::Launch { launch: old.status })
            }
            Request::Enqueue {
                route_id,
                route_revision,
                task,
                ..
            } => {
                let route = self.work.config.route(route_id).ok_or("forbidden")?;
                let profile = self
                    .work
                    .config
                    .profile(&route.profile_id)
                    .ok_or("forbidden")?;
                let digest = hw::digest(
                    &serde_json::to_vec(&(req.host(), route_id, route_revision, task))
                        .map_err(|_| "invalid_request")?,
                );
                let record = WorkRecord {
                    attachment_owner: attachment_owner(&a),
                    principal,
                    control_gen: self.host.control_gen(&a.name()),
                    route_id: route_id.clone(),
                    route_revision: *route_revision,
                    profile_id: profile.id.clone(),
                    profile_revision: profile.revision,
                    project: profile.project.clone(),
                    digest,
                    task: task.clone(),
                    status: WorkStatus {
                        task_id: task.task_id.clone(),
                        receipt_id: uuid::Uuid::new_v4().to_string(),
                        state: WorkState::Queued,
                        detail: "waiting for a ready agent".into(),
                        result: None,
                    },
                };
                if let Some(old) = store.work(&task.task_id).map_err(|_| "busy")? {
                    if old.principal != record.principal || old.digest != record.digest {
                        return Err("request_id_reused");
                    }
                    if !self.work_route_allowed(&old, &a) {
                        return Err("forbidden");
                    }
                    return Ok(ResultBody::Work { work: old.status });
                }
                if !self.work_allowed(&record, &a, cx.sessions) {
                    return Err("forbidden");
                }
                if task.expires_at <= wall
                    || task.expires_at > wall.saturating_add(hw::MAX_LIFETIME_MS)
                {
                    return Err("invalid_request");
                }
                store.enqueue(&record).map_err(|_| "busy")?;
                Ok(ResultBody::Work {
                    work: record.status,
                })
            }
            Request::WorkQuery { task_id, .. }
            | Request::Cancel { task_id, .. }
            | Request::Complete { task_id, .. } => {
                let mut r = store
                    .work(task_id)
                    .map_err(|_| "busy")?
                    .ok_or("forbidden")?;
                if r.principal != principal || !self.work_route_allowed(&r, &a) {
                    return Err("forbidden");
                }
                if r.status.state == WorkState::OutcomeUnknown {
                    self.reconcile_work(&mut r);
                    store.save_work(&r).map_err(|_| "busy")?;
                }
                match req {
                    Request::Cancel { .. } => {
                        if !matches!(
                            r.status.state,
                            WorkState::Queued | WorkState::Blocked | WorkState::Cancelled
                        ) {
                            return Err("busy");
                        }
                        r.status.state = WorkState::Cancelled;
                        r.status.detail = "cancelled before submission".into();
                    }
                    Request::Complete { result, .. } => {
                        if r.status.state == WorkState::Completed {
                            if r.status.result.as_ref() != Some(result) {
                                return Err("request_id_reused");
                            }
                        } else {
                            if r.status.state != WorkState::AwaitingResult {
                                return Err("busy");
                            }
                            r.status.state = WorkState::Completed;
                            r.status.result = Some(result.clone());
                            r.status.detail = "explicit correlated result published".into();
                        }
                    }
                    _ => return Ok(ResultBody::Work { work: r.status }),
                }
                store.save_work(&r).map_err(|_| "busy")?;
                Ok(ResultBody::Work { work: r.status })
            }
            Request::Publish { .. }
            | Request::MessageQuery { .. }
            | Request::AttachmentPut { .. } => unreachable!(),
        }
    }

    fn message_scope(
        &self,
        recipient: &atem_client::session::messages::Recipient,
        a: &Authority,
    ) -> bool {
        use atem_client::session::messages::Destination;
        match &recipient.destination {
            Destination::Host => a.scope.as_ref().is_none_or(|scope| {
                scope.projects.is_none()
                    && scope.sessions.is_none()
                    && scope
                        .hosts
                        .as_ref()
                        .is_none_or(|hosts| hosts.contains(&recipient.host.atem_device_id))
            }),
            Destination::Project {
                route_id,
                route_revision,
            }
            | Destination::Agent {
                route_id,
                route_revision,
                ..
            } => {
                let Some(route) = self.work.config.route(route_id) else {
                    return false;
                };
                let Some(profile) = self.work.config.profile(&route.profile_id) else {
                    return false;
                };
                if route.revision != *route_revision {
                    return false;
                }
                let sid = match &recipient.destination {
                    Destination::Agent { target, .. } => target.session_id.as_str(),
                    _ => {
                        if a.scope.as_ref().is_some_and(|s| s.sessions.is_some()) {
                            return false;
                        }
                        &profile.scope_key()
                    }
                };
                a.session_in_scope(&recipient.host.atem_device_id, sid, &|entry| {
                    self.projects.matches(&profile.scope_key(), entry)
                })
            }
        }
    }

    fn message_request(
        &self,
        req: &hw::Request,
        a: &Authority,
        cx: &Cx,
    ) -> Result<ResultBody, &'static str> {
        use crate::runtime::host_work::MessageRecord;
        use atem_client::session::messages::{
            Delivery, Destination, MessageReceipt, RecipientReceipt,
        };
        if !a.allows(Need::Op(Op::Message))
            || a.client_kind == atem_client::principal::ClientKind::Browser
        {
            return Err("forbidden");
        }
        let store = self.work.store.as_ref().ok_or("busy")?;
        let message_id = match req {
            hw::Request::Publish { message, .. } => {
                if message.sender != a.name() {
                    return Err("forbidden");
                }
                &message.message_id
            }
            hw::Request::MessageQuery { message_id, .. } => message_id,
            _ => return Err("invalid_request"),
        };
        if let Some(old) = store.message(message_id).map_err(|_| "busy")? {
            if old.message.sender != a.name() || old.sender_key != a.key.to_json() {
                return Err("forbidden");
            }
            if let hw::Request::Publish { message, .. } = req
                && old.message != *message
            {
                return Err("request_id_reused");
            }
            for r in old
                .message
                .recipients
                .iter()
                .filter(|r| &r.host == req.host())
            {
                let accepted = old.receipt.recipients.iter().any(|p| {
                    p.recipient_id == r.recipient_id
                        && !matches!(p.delivery, Delivery::Refused { .. })
                });
                if accepted && !self.message_scope(r, a) {
                    return Err("forbidden");
                }
            }
            return Ok(ResultBody::Message {
                message: store.message_receipt(&old).map_err(|_| "busy")?,
            });
        }
        let hw::Request::Publish { message, .. } = req else {
            return Err("forbidden");
        };
        let now = host_now().wall_ms;
        if message.created_at > now.saturating_add(60_000) || message.expires_at <= now {
            return Err("invalid_request");
        }
        let digest = message.digest();
        let mut tasks = Vec::new();
        let mut recipients = Vec::new();
        for r in message.recipients.iter().filter(|r| &r.host == req.host()) {
            let delivery = if !self.message_scope(r, a) {
                Delivery::Refused {
                    code: "forbidden".into(),
                }
            } else if let Destination::Agent {
                route_id,
                route_revision,
                ..
            } = &r.destination
            {
                let route = self.work.config.route(route_id).ok_or("forbidden")?;
                let profile = self
                    .work
                    .config
                    .profile(&route.profile_id)
                    .ok_or("forbidden")?;
                let task = message.task(r).ok_or("invalid_request")?;
                let record = WorkRecord {
                    attachment_owner: attachment_owner(a),
                    principal: a.name(),
                    control_gen: self.host.control_gen(&a.name()),
                    route_id: route_id.clone(),
                    route_revision: *route_revision,
                    profile_id: profile.id.clone(),
                    profile_revision: profile.revision,
                    project: profile.project.clone(),
                    digest: hw::digest(
                        &serde_json::to_vec(&(&digest, &r.recipient_id))
                            .map_err(|_| "invalid_request")?,
                    ),
                    task,
                    status: WorkStatus {
                        task_id: r.recipient_id.clone(),
                        receipt_id: uuid::Uuid::new_v4().to_string(),
                        state: WorkState::Queued,
                        detail: "waiting for a ready agent".into(),
                        result: None,
                    },
                };
                if self.work_allowed(&record, a, cx.sessions) {
                    let delivery = Delivery::Work {
                        work: (&record.status).into(),
                    };
                    tasks.push(record);
                    delivery
                } else {
                    Delivery::Refused {
                        code: "forbidden".into(),
                    }
                }
            } else {
                Delivery::Stored
            };
            recipients.push(RecipientReceipt {
                recipient_id: r.recipient_id.clone(),
                delivery,
            });
        }
        let record = MessageRecord {
            sender_key: a.key.to_json(),
            message: message.clone(),
            receipt: MessageReceipt {
                message_id: message.message_id.clone(),
                digest,
                sender: a.name(),
                recipients,
            },
        };
        store.accept_message(&record, &tasks).map_err(|_| "busy")?;
        Ok(ResultBody::Message {
            message: record.receipt,
        })
    }

    fn schedule_work(&mut self, cx: &mut Cx) -> anyhow::Result<()> {
        let tasks = self.work.store.as_ref().unwrap().active_tasks()?;
        let mut occupied = HashSet::new();
        for mut r in tasks {
            if r.status.state.terminal() && r.status.state != WorkState::OutcomeUnknown {
                continue;
            }
            if matches!(
                r.status.state,
                WorkState::Submitting | WorkState::Submitted | WorkState::OutcomeUnknown
            ) {
                let before = r.status.clone();
                self.reconcile_work(&mut r);
                if r.status != before {
                    self.work.store.as_ref().unwrap().save_work(&r)?;
                }
                if matches!(
                    r.status.state,
                    WorkState::Submitting | WorkState::Submitted | WorkState::OutcomeUnknown
                ) {
                    occupied.insert(r.task.target.session_id.clone());
                }
                continue;
            }
            if r.status.state == WorkState::AwaitingResult {
                continue;
            }
            if host_now().wall_ms >= r.task.expires_at {
                r.status.state = WorkState::Expired;
                r.status.detail = "expired before submission".into();
                self.work.store.as_ref().unwrap().save_work(&r)?;
                continue;
            }
            let attachment = self
                .r9
                .attachments()
                .into_iter()
                .map(|(attachment, _)| attachment)
                .find(|att| {
                    self.work_authority(att).is_some_and(|a| {
                        a.name() == r.principal && self.work_allowed(&r, &a, cx.sessions)
                    })
                });
            let first = occupied.insert(r.task.target.session_id.clone());
            let reason = if !first {
                Some("waiting for an earlier task on this session")
            } else {
                match attachment.as_ref() {
                    None => Some("waiting for the sender's authorized channel and current route"),
                    Some(_) => {
                        let session = SessionId::parse(&r.task.target.session_id)
                            .and_then(|sid| cx.sessions.get(&sid));
                        match session {
                            None => Some("target session unavailable"),
                            Some(s)
                                if !s.is_live()
                                    || !s.chat_v1
                                    || s.chat.status().state != ChatState::Ready =>
                            {
                                Some("agent is busy, unavailable or readiness is unknown")
                            }
                            Some(s) if s.chat.has_unsent_input(s.input_count) => {
                                Some("terminal has unsent input")
                            }
                            Some(_)
                                if self.host.lease_holder(&r.task.target.session_id).is_some() =>
                            {
                                Some("waiting for controller to release the lease")
                            }
                            Some(_)
                                if self
                                    .approvals
                                    .values()
                                    .any(|p| p.sid == r.task.target.session_id) =>
                            {
                                Some("waiting for approval resolution")
                            }
                            _ => None,
                        }
                    }
                }
            };
            if let Some(reason) = reason {
                if r.status.state != WorkState::Blocked || r.status.detail != reason {
                    r.status.state = WorkState::Blocked;
                    r.status.detail = reason.into();
                    self.work.store.as_ref().unwrap().save_work(&r)?;
                }
                continue;
            }
            let attachment = attachment.unwrap();
            let mut prompt = r.task.render_prompt();
            let paths = self
                .work
                .store
                .as_ref()
                .unwrap()
                .attachment_paths(&r.attachment_owner, &r.task.attachments);
            let Ok(paths) = paths else {
                let detail = "waiting for verified screenshot attachments";
                if r.status.state != WorkState::Blocked || r.status.detail != detail {
                    r.status.state = WorkState::Blocked;
                    r.status.detail = detail.into();
                    self.work.store.as_ref().unwrap().save_work(&r)?;
                }
                continue;
            };
            for (reference, path) in r.task.attachments.iter().zip(paths) {
                prompt.push_str(&format!(
                    "\n[Verified screenshot {} sha256 {}]\nRead this PNG: {}\n",
                    reference.attachment_id,
                    reference.digest,
                    path.display()
                ));
            }
            if prompt.len() > wire::MAX_PROMPT_BYTES
                || prompt
                    .chars()
                    .any(|c| c.is_control() && c != '\n' && c != '\t')
            {
                r.status.state = WorkState::Failed;
                r.status.detail = "attachment paths exceed the prompt bounds".into();
                self.work.store.as_ref().unwrap().save_work(&r)?;
                continue;
            }
            let Some((binding, _)) = self.host.binding_for_work(&attachment, &r.task.target) else {
                continue;
            };
            let message = json!({"type":"session", "data": {"v":1,"op":"submit", "id":uuid::Uuid::new_v4().to_string(),
                "binding":binding, "request_id":r.status.receipt_id, "kind":"prompt", "payload":{"text":prompt}, "acquire":true}});
            r.status.state = WorkState::Submitting;
            r.status.detail = "dispatch intent persisted".into();
            self.work.store.as_ref().unwrap().save_work(&r)?;
            let effects = self.host.receive(
                &attachment,
                message.to_string().as_bytes(),
                self.clock.now(),
            );
            self.exec(effects, cx);
            // No receipt after a persisted intent remains uncertain, never replayed.
            r.status.state = if self.host.receipt(&r.status.receipt_id).is_some() {
                WorkState::Submitted
            } else {
                WorkState::OutcomeUnknown
            };
            self.work.store.as_ref().unwrap().save_work(&r)?;
        }
        Ok(())
    }

    fn reconcile_work(&self, r: &mut WorkRecord) {
        use crate::session_protocol::wire::ReceiptState;
        let Some(receipt) = self.host.receipt(&r.status.receipt_id) else {
            return;
        };
        r.status.state = match receipt.state {
            ReceiptState::Accepted | ReceiptState::Executing => WorkState::Submitted,
            ReceiptState::Completed => WorkState::AwaitingResult,
            ReceiptState::Rejected => WorkState::Failed,
            ReceiptState::OutcomeUnknown => WorkState::OutcomeUnknown,
        };
        r.status.detail =
            "agent submission receipt reconciled; task completion requires an explicit result"
                .into();
    }
}

fn attachment_owner(a: &Authority) -> String {
    hw::digest(&serde_json::to_vec(&(a.name(), a.key.to_json())).expect("serializable identity"))
}

fn authority_session(a: &Authority, target: &wire::Target, projects: &ProjectScopes) -> bool {
    a.session_in_scope(&target.atem_device_id, &target.session_id, &|e| {
        projects.matches(&target.session_id, e)
    })
}
