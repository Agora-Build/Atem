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

/// The longest `paused: <reason>` detail a waiting local task carries.
const MAX_PAUSE_DETAIL: usize = 240;

#[path = "collab_bridge.rs"]
mod collab_bridge;
#[path = "collab_launch_bridge.rs"]
mod collab_launch_bridge;

/// The local sender exists only on the broker's internal attachment.
pub(crate) enum Sender {
    Remote(Box<Authority>),
    Local,
}

impl Sender {
    fn remote(&self) -> Option<&Authority> {
        match self {
            Self::Remote(a) => Some(a),
            Self::Local => None,
        }
    }
    fn name(&self) -> String {
        self.remote()
            .map_or_else(|| "local".into(), Authority::name)
    }
    fn key_json(&self) -> Value {
        self.remote()
            .map_or_else(|| json!("local"), |a| a.key.to_json())
    }
    fn owner(&self) -> String {
        hw::digest(
            &serde_json::to_vec(&(self.name(), self.key_json())).expect("serializable identity"),
        )
    }
    fn allows(&self, need: Need) -> bool {
        self.remote().is_none_or(|a| a.allows(need))
    }
    fn is_browser(&self) -> bool {
        self.remote()
            .is_some_and(|a| a.client_kind == atem_client::principal::ClientKind::Browser)
    }
    fn in_scope(&self, host: &str, session: &str, projects: &dyn Fn(&str) -> Option<bool>) -> bool {
        self.remote()
            .is_none_or(|a| a.session_in_scope(host, session, projects))
    }
}

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
    local_route: Option<crate::runtime::host_work::Route>,
}

pub(super) struct State {
    available: bool,
    dir: PathBuf,
    config: Config,
    store: Option<Store>,
    /// A receipt database fault: hosting stays off until a restart.
    error: bool,
    /// Why `runtime.toml` didn't load: hosting is off until it does.
    config_problem: Option<String>,
    refresh: Instant,
    scheduled: Instant,
    recovered: bool,
    pending: HashMap<String, PendingLaunch>,
    launches: VecDeque<RemoteLaunch>,
    context_jobs:
        HashMap<String, tokio::sync::oneshot::Receiver<anyhow::Result<Vec<hw::ContextSnapshot>>>>,
}

impl State {
    pub(super) fn collaboration_enabled(&self) -> bool {
        self.config.collab.send
    }
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
            config_problem: None,
            refresh: Instant::now(),
            scheduled: Instant::now(),
            recovered: false,
            pending: HashMap::new(),
            launches: VecDeque::new(),
            context_jobs: HashMap::new(),
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
    /// Local input uses the same durable receiver as an authenticated remote
    /// message, with an attachment that never crosses a transport link.
    #[cfg(test)]
    fn local_publish(
        &mut self,
        message: &atem_client::session::messages::Message,
        cx: &mut Cx,
    ) -> Result<atem_client::session::messages::MessageReceipt, &'static str> {
        if !self.local_healthy() || !message.valid_local() {
            return Err("forbidden");
        }
        let host = self.work_host();
        if !self.work_store_ready(&host) {
            return Err("busy");
        }
        let request = hw::Request::Publish {
            v: 1,
            id: uuid::Uuid::new_v4().to_string(),
            host,
            message: message.clone(),
        };
        match self.message_request(&request, &Sender::Local, cx)? {
            ResultBody::Message { message } => Ok(message),
            _ => Err("invalid_request"),
        }
    }

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

    /// A receipt database fault: a write's outcome may be unknown, so
    /// hosting stays off until a restart (like a halted session journal).
    fn work_fail(&mut self) {
        if !self.work.error {
            eprintln!(
                "atem runtime: agent hosting stopped: its receipt database ({}) failed; run `atem runtime restart`",
                self.dir
                    .parent()
                    .unwrap_or(&self.dir)
                    .join("host-work.sqlite")
                    .display()
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
        // An invalid file turns hosting off only while it lasts: launches
        // not started are fenced, requests are `busy` and queued local tasks
        // wait as `paused` (`work_pass`); nothing else is fenced.
        let config = match Config::load(&self.work.dir) {
            Ok(config) => {
                if self.work.config_problem.take().is_some() {
                    eprintln!(
                        "atem runtime: runtime.toml is valid again; agent hosting follows it"
                    );
                }
                config
            }
            Err(error) => {
                let problem = format!("{error:#}");
                if self.work.config_problem.as_deref() != Some(problem.as_str()) {
                    eprintln!(
                        "atem runtime: runtime.toml: {problem}; agent hosting is off until it is fixed (`atem runtime check`)"
                    );
                }
                self.work.config_problem = Some(problem);
                Config::default()
            }
        };
        let retained: HashSet<String> = config.profiles.iter().map(Profile::scope_key).collect();
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

    fn work_authority(&mut self, attachment: &str) -> Option<Sender> {
        if !attachment.is_empty() && attachment == self.local_attachment() {
            return self.local_healthy().then_some(Sender::Local);
        }
        self.r9_call(|r9, parts| r9.current_work_authority(attachment, parts))
            .map(|authority| Sender::Remote(Box::new(authority)))
    }

    fn profile_allowed(&self, profile: &Profile, authority: &Sender, launch: bool) -> bool {
        (!launch || authority.remote().is_none_or(|a| profile.permits(a)))
            && authority.in_scope(
                &self.host.context().atem_device_id,
                &profile.scope_key(),
                &|entry| self.projects.matches(&profile.scope_key(), entry),
            )
    }

    fn work_allowed(
        &self,
        record: &WorkRecord,
        a: &Sender,
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
            && self.collab_result_delivery(record).is_ok_and(|result| {
                result.is_none_or(|(grant, _)| {
                    grant.origin.route.as_ref().is_some_and(|r| r.results)
                        && self.collab_origin_live(&grant.origin, sessions)
                })
            })
    }

    fn work_route_allowed(&self, record: &WorkRecord, a: &Sender) -> bool {
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
            && a.in_scope(
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
            self.pause_local_tasks();
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
            if self
                .collab_pass(cx)
                .and_then(|_| self.collab_reply_pass())
                .and_then(|_| self.schedule_work(cx))
                .is_err()
            {
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
        self.work.context_jobs.clear();
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
                    a.name() == p.principal
                        && match &p.local_route {
                            Some(route) => {
                                matches!(a, Sender::Local)
                                    && self.local_healthy()
                                    && self.work.config.route(&route.id) == Some(route)
                                    && route.principals.iter().any(|p| p == "local")
                                    && route.launch
                                        == crate::runtime::host_work::RouteLaunch::OnMessage
                            }
                            None => self.profile_allowed(&p.profile, a, true),
                        }
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
                || a.is_browser()
                || a.remote()
                    .and_then(|a| a.scope.as_ref())
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
                        local_route: None,
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
                    turn_id: None,
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
            | Request::ReplyQuery { task_id, .. }
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
                    // The reply its agent submitted, to the sender that asked
                    // for the task: the check above is `work_query`'s.
                    Request::ReplyQuery { .. } => {
                        let reply = crate::runtime::collab::results::load(&store.db, task_id)
                            .map_err(|_| "busy")?;
                        return Ok(ResultBody::Reply {
                            reply: reply.map(|row| row.wire()),
                        });
                    }
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
        a: &Sender,
    ) -> bool {
        use atem_client::session::messages::Destination;
        match &recipient.destination {
            // Select expansion is local until the cross-instance contract is agreed.
            Destination::Select { .. } => false,
            Destination::Host => a
                .remote()
                .and_then(|a| a.scope.as_ref())
                .is_none_or(|scope| {
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
                        if a.remote()
                            .and_then(|a| a.scope.as_ref())
                            .is_some_and(|s| s.sessions.is_some())
                        {
                            return false;
                        }
                        &profile.scope_key()
                    }
                };
                a.in_scope(&recipient.host.atem_device_id, sid, &|entry| {
                    self.projects.matches(&profile.scope_key(), entry)
                })
            }
        }
    }

    fn message_request(
        &self,
        req: &hw::Request,
        a: &Sender,
        cx: &Cx,
    ) -> Result<ResultBody, &'static str> {
        use crate::runtime::host_work::MessageRecord;
        use atem_client::session::messages::{
            Delivery, Destination, MessageReceipt, RecipientReceipt,
        };
        if !a.allows(Need::Op(Op::Message)) || a.is_browser() {
            return Err("forbidden");
        }
        let store = self.work.store.as_ref().ok_or("busy")?;
        let message_id = match req {
            hw::Request::Publish { message, .. } => {
                // The sending session and the reply link are local-only.
                if message.kind != atem_client::session::messages::MessageKind::Request
                    || a.remote().is_some()
                        && (message.from_session.is_some() || message.reply_to.is_some())
                {
                    return Err("unsupported_version");
                }
                if message.sender != a.name() {
                    return Err("forbidden");
                }
                &message.message_id
            }
            hw::Request::MessageQuery { message_id, .. } => message_id,
            _ => return Err("invalid_request"),
        };
        if let Some(old) = store.message(message_id).map_err(|_| "busy")? {
            if old.message.sender != a.name() || old.sender_key != a.key_json() {
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
                    turn_id: None,
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
            sender_key: a.key_json(),
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

    /// While local collaboration is paused (`collab_paused`) queued and
    /// blocked local tasks wait with the reason as their detail. They keep
    /// their place and their return grants, and nothing is fenced: they go on
    /// as soon as the pause is over (spec section 9). Remote tasks are not
    /// touched (their senders' authority is rechecked as before).
    fn pause_local_tasks(&mut self) {
        if Instant::now() < self.work.scheduled {
            return;
        }
        self.work.scheduled = Instant::now() + Duration::from_millis(100);
        if self.work.error || !self.local_authorized() {
            return;
        }
        let Some(detail) = self.local_pause_detail() else {
            return;
        };
        let Some(store) = self.work.store.as_ref() else {
            return;
        };
        let saved = store.active_tasks().and_then(|tasks| {
            for mut r in tasks {
                if r.principal == "local"
                    && matches!(r.status.state, WorkState::Queued | WorkState::Blocked)
                    && r.status.detail != detail
                {
                    r.status.detail = detail.clone();
                    store.save_work(&r)?;
                }
            }
            Ok(())
        });
        if saved.is_err() {
            self.work_fail();
        }
    }

    /// `paused: <reason>` for a local task while `runtime.toml` or a failed
    /// receipt database pauses local collaboration; one line, bounded.
    fn local_pause_detail(&self) -> Option<String> {
        let paused = self.collab_paused();
        if paused.is_empty() {
            return None;
        }
        let reason = paused
            .join("; ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        let detail = format!("paused: {reason}");
        Some(match detail.char_indices().nth(MAX_PAUSE_DETAIL) {
            Some((end, _)) => format!("{}…", &detail[..end]),
            None => detail,
        })
    }

    fn schedule_work(&mut self, cx: &mut Cx) -> anyhow::Result<()> {
        let tasks = self.work.store.as_ref().unwrap().active_tasks()?;
        let pause = self
            .local_authorized()
            .then(|| self.local_pause_detail())
            .flatten();
        let mut occupied = HashSet::new();
        for mut r in tasks {
            if r.status.state.terminal() && r.status.state != WorkState::OutcomeUnknown {
                continue;
            }
            if matches!(
                r.status.state,
                WorkState::Submitting | WorkState::Submitted | WorkState::OutcomeUnknown
            ) {
                let before = (r.status.clone(), r.turn_id.clone());
                // The turn its prompt became, stored once known: a reply is
                // bound to it, after a restart too (spec section 10).
                if r.turn_id.is_none() {
                    r.turn_id = self.collab_task_turn(&r, cx.sessions);
                }
                self.reconcile_work(&mut r);
                if (&r.status, &r.turn_id) != (&before.0, &before.1) {
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
            if self.collab_wait_for_launch(&mut r)? {
                continue;
            }
            if r.principal == "local"
                && let Some(detail) = &pause
            {
                // Waiting, not fenced: it keeps its place in the session's
                // queue, and resumes with the same authority.
                occupied.insert(r.task.target.session_id.clone());
                if r.status.detail != *detail {
                    r.status.detail = detail.clone();
                    self.work.store.as_ref().unwrap().save_work(&r)?;
                }
                continue;
            }
            let local = (r.principal == "local" && !self.local_attachment().is_empty())
                .then(|| self.local_attachment().to_string());
            let attachment = local
                .into_iter()
                .chain(
                    self.r9
                        .attachments()
                        .into_iter()
                        .map(|(attachment, _)| attachment),
                )
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
            if self.collab_result_delivery(&r)?.is_some() {
                prompt = prompt
                    .split_once('\n')
                    .map_or(prompt.clone(), |(_, body)| body.to_string());
            }
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
        if receipt.state == ReceiptState::Completed
            && let Ok(Some((_, result))) = self.collab_result_delivery(r)
        {
            r.status.state = WorkState::Completed;
            r.status.result = Some(result.snapshot());
            r.status.detail = "explicit result delivered to the originating agent".into();
            return;
        }
        r.status.detail = if r.status.state == WorkState::Submitted && r.turn_id.is_some() {
            collab_bridge::IN_TURN
        } else {
            "agent submission receipt reconciled; task completion requires an explicit result"
        }
        .into();
        if let Some(reply) = self.collab_reply_of(&r.task.task_id) {
            collab_bridge::apply_reply(r, &reply);
        }
    }
}

fn attachment_owner(a: &Sender) -> String {
    a.owner()
}

fn authority_session(a: &Sender, target: &wire::Target, projects: &ProjectScopes) -> bool {
    a.in_scope(&target.atem_device_id, &target.session_id, &|e| {
        projects.matches(&target.session_id, e)
    })
}

#[cfg(test)]
mod local_tests {
    use super::*;
    use crate::runtime::adopt::SpawnRequest;
    use crate::runtime::broker::{InProcess, Launcher};
    use crate::runtime::protocol::LaunchEnv;
    use atem_client::session::messages::{Delivery, Destination, Message, Recipient};

    struct LocalRig {
        bridge: HostBridge,
        app: App,
        sessions: BTreeMap<SessionId, BrokerSession>,
        sid: SessionId,
        fake: PathBuf,
    }

    impl LocalRig {
        async fn new(root: &Path) -> Self {
            let app = App::new();
            let mut bridge =
                HostBridge::open(&root.join("runtime/journal"), None, Clock::default()).unwrap();
            let cwd = root.join("project");
            std::fs::create_dir_all(&cwd).unwrap();
            let fake = root.join("fake");
            std::fs::create_dir_all(&fake).unwrap();
            let config: Config = toml::from_str(&format!(
                r#"
version = 1
enabled = true
[collab]
send = true
[[profiles]]
id = "p"
revision = 1
label = "p"
provider = "claude"
cwd = {cwd:?}
project = "local:project"
principals = ["member:owner"]
[[routes]]
id = "r"
revision = 1
profile_id = "p"
principals = ["local"]
"#
            ))
            .unwrap();
            config.validate().unwrap();
            bridge.work.config = config;
            bridge.work.store = Some(Store::open(&root.join("runtime")).unwrap());
            let launcher = Launcher::InProcess(InProcess {
                state: root.join("runtime"),
                socket_dir: root.join("ws"),
                chat_root: root.join("chat"),
            });
            let sid = SessionId::new();
            let request = SpawnRequest {
                session_id: sid.clone(),
                process_gen: uuid::Uuid::new_v4().to_string(),
                provider: crate::session::Provider::Claude,
                args: vec![],
                cwd,
                rows: 24,
                cols: 80,
            };
            let bin = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/approvals/fake-agent.py");
            let (handle, created) = launcher
                .spawn(
                    request.clone(),
                    LaunchEnv(vec![
                        ("PATH".into(), "/usr/bin:/bin".into()),
                        ("HOME".into(), root.display().to_string()),
                        ("CLAUDE_CLI_BIN".into(), bin.display().to_string()),
                        ("FAKE_DIR".into(), fake.display().to_string()),
                    ]),
                )
                .await
                .unwrap();
            let mut sessions = BTreeMap::from([(
                sid.clone(),
                BrokerSession::launched(handle, &request, created),
            )]);
            let mut cx = Cx {
                client: &app.astation_client,
                sessions: &mut sessions,
            };
            assert!(bridge.adopt_identity(
                &Identity {
                    account_id: "acct".into(),
                    atem_device_id: "host".into(),
                    host_trust_gen: 1
                },
                &mut cx
            ));
            let mut rig = Self {
                bridge,
                app,
                sessions,
                sid,
                fake,
            };
            rig.until(|r| {
                r.sessions[&r.sid].chat_v1
                    && r.sessions[&r.sid].chat.status().state == ChatState::Ready
            })
            .await;
            rig
        }

        async fn until(&mut self, mut predicate: impl FnMut(&Self) -> bool) {
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                for s in self.sessions.values_mut() {
                    s.pump();
                }
                self.bridge.tick(&mut self.app, &mut self.sessions, false);
                if predicate(self) {
                    break;
                }
                assert!(Instant::now() < deadline, "local work did not progress");
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }

        fn message(&self) -> Message {
            let host = self.bridge.work_host();
            Message {
                message_id: uuid::Uuid::new_v4().to_string(),
                workflow_id: uuid::Uuid::new_v4().to_string(),
                sender: "local".into(),
                kind: Default::default(),
                reply_to: None,
                from_session: Some(SessionId::new().to_string()),
                created_at: host_now().wall_ms,
                expires_at: host_now().wall_ms + 60_000,
                text: "COLLAB_TEST_PROMPT".into(),
                context: vec![],
                mark: None,
                recipients: vec![Recipient {
                    recipient_id: uuid::Uuid::new_v4().to_string(),
                    host: host.clone(),
                    destination: Destination::Agent {
                        route_id: "r".into(),
                        route_revision: 1,
                        target: wire::Target {
                            account_id: host.account_id,
                            atem_device_id: host.atem_device_id,
                            host_trust_gen: host.host_trust_gen,
                            session_id: self.sid.to_string(),
                            process_gen: self.sessions[&self.sid].process_gen.clone(),
                        },
                    },
                }],
            }
        }

        fn publish(&mut self, message: &Message) -> atem_client::session::messages::MessageReceipt {
            self.bridge
                .local_publish(
                    message,
                    &mut Cx {
                        client: &self.app.astation_client,
                        sessions: &mut self.sessions,
                    },
                )
                .unwrap()
        }

        fn work(&self, m: &Message) -> WorkRecord {
            self.bridge
                .work
                .store
                .as_ref()
                .unwrap()
                .work(&m.recipients[0].recipient_id)
                .unwrap()
                .unwrap()
        }
    }

    impl Drop for LocalRig {
        fn drop(&mut self) {
            for s in self.sessions.values() {
                let _ = s.stop();
            }
        }
    }

    fn local_test(body: impl AsyncFnOnce(&Path)) {
        let dir = tempfile::Builder::new()
            .prefix("atem-cw")
            .tempdir_in("/tmp")
            .unwrap();
        let _profile = crate::test_profile::use_dir(dir.path());
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        tokio::task::LocalSet::new().block_on(&rt, body(dir.path()));
    }

    #[test]
    fn a_local_task_dispatches_as_a_prompt_with_a_receipt() {
        local_test(async |root| {
            let mut rig = LocalRig::new(root).await;
            let message = rig.message();
            assert!(matches!(
                rig.publish(&message).recipients[0].delivery,
                Delivery::Work { .. }
            ));
            rig.until(|r| {
                r.fake.join("input").is_file()
                    && std::fs::read_to_string(r.fake.join("input"))
                        .unwrap()
                        .contains("COLLAB_TEST_PROMPT")
            })
            .await;
            rig.publish(&message); // immutable retry, never a second submission
            std::fs::write(rig.fake.join("complete"), "").unwrap();
            rig.until(|r| r.work(&message).status.state == WorkState::AwaitingResult)
                .await;
            let work = rig.work(&message);
            assert_eq!(
                rig.bridge
                    .host
                    .receipt(&work.status.receipt_id)
                    .unwrap()
                    .state,
                wire::ReceiptState::Completed
            );
            assert_eq!(
                std::fs::read_to_string(rig.fake.join("input"))
                    .unwrap()
                    .matches("COLLAB_TEST_PROMPT")
                    .count(),
                1
            );
        });
    }

    #[test]
    fn a_route_without_local_refuses_it() {
        local_test(async |root| {
            let mut rig = LocalRig::new(root).await;
            rig.bridge.work.config.routes[0].principals = vec!["member:owner".into()];
            let message = rig.message();
            assert!(
                matches!(&rig.publish(&message).recipients[0].delivery, Delivery::Refused { code } if code == "forbidden")
            );
            assert!(
                rig.bridge
                    .work
                    .store
                    .as_ref()
                    .unwrap()
                    .tasks()
                    .unwrap()
                    .is_empty()
            );
        });
    }

    #[test]
    fn a_local_task_waits_for_a_remote_lease_and_never_takes_it() {
        local_test(async |root| {
            let mut rig = LocalRig::new(root).await;
            let att = uuid::Uuid::new_v4().to_string();
            rig.bridge
                .host
                .connect(Attach {
                    client: "test-controller".into(),
                    principal: "service:holder".into(),
                    attachment_gen: att.clone(),
                    permissions: vec![Permission::View, Permission::Control],
                    client_kind: ClientKind::Native,
                    authorization_ms: 60_000,
                })
                .unwrap();
            rig.bridge
                .host
                .welcome_r9(&att, rig.bridge.clock.now())
                .unwrap();
            let message = rig.message();
            let target = message.task(&message.recipients[0]).unwrap().target;
            let (binding, _) = rig.bridge.host.binding_for_work(&att, &target).unwrap();
            let acquire = json!({"type":"session","data":{"v":1,"op":"acquire","id":uuid::Uuid::new_v4().to_string(),"binding":binding,"takeover":false}});
            let effects = rig.bridge.host.receive(
                &att,
                acquire.to_string().as_bytes(),
                rig.bridge.clock.now(),
            );
            rig.bridge.exec(
                effects,
                &mut Cx {
                    client: &rig.app.astation_client,
                    sessions: &mut rig.sessions,
                },
            );
            assert_eq!(
                rig.bridge.host.lease_holder(rig.sid.as_str()),
                Some(att.as_str())
            );
            rig.publish(&message);
            rig.until(|r| r.work(&message).status.state == WorkState::Blocked)
                .await;
            assert_eq!(
                rig.work(&message).status.detail,
                "waiting for controller to release the lease"
            );
            assert_eq!(
                rig.bridge.host.lease_holder(rig.sid.as_str()),
                Some(att.as_str())
            );
            let mut binding = binding;
            binding.lease_epoch = rig.bridge.host.lease_epoch(rig.sid.as_str());
            let release = json!({"type":"session","data":{"v":1,"op":"release","id":uuid::Uuid::new_v4().to_string(),"binding":binding}});
            let effects = rig.bridge.host.receive(
                &att,
                release.to_string().as_bytes(),
                rig.bridge.clock.now(),
            );
            rig.bridge.exec(
                effects,
                &mut Cx {
                    client: &rig.app.astation_client,
                    sessions: &mut rig.sessions,
                },
            );
            rig.until(|r| r.work(&message).status.state == WorkState::Submitted)
                .await;
            assert_eq!(
                rig.bridge.host.lease_holder(rig.sid.as_str()),
                Some(rig.bridge.local_attachment())
            );
            rig.bridge
                .local_input(
                    &rig.sid,
                    vec![],
                    &rig.app.astation_client,
                    &mut rig.sessions,
                )
                .unwrap();
            assert_eq!(rig.bridge.host.lease_holder(rig.sid.as_str()), None);
        });
    }

    fn send_request(to: &[&str]) -> crate::runtime::collab::SendRequest {
        crate::runtime::collab::SendRequest {
            to: to.iter().map(|s| s.to_string()).collect(),
            text: "check".into(),
            memory: vec![],
            vault: vec![],
            launch: false,
            expires_ms: 60_000,
        }
    }

    fn rows(rig: &LocalRig, table: &str) -> i64 {
        rig.bridge
            .work
            .store
            .as_ref()
            .unwrap()
            .db
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    }

    fn counted(rig: &LocalRig, key: &str) -> i64 {
        rig.bridge
            .work
            .store
            .as_ref()
            .unwrap()
            .db
            .query_row(
                "SELECT coalesce(sum(count),0) FROM counters WHERE key=?1",
                [key],
                |r| r.get(0),
            )
            .unwrap()
    }

    fn snapshot(text: &str) -> hw::ContextSnapshot {
        hw::ContextSnapshot {
            kind: hw::ContextKind::Vault,
            id: "v-context:1".into(),
            version: 1,
            digest: hw::digest(text.as_bytes()),
            text: text.into(),
        }
    }

    #[test]
    fn a_message_that_could_never_dispatch_is_refused_before_anything_is_counted() {
        local_test(async |root| {
            let mut rig = LocalRig::new(root).await;
            let host = rig.bridge.work_host();
            let origin = crate::runtime::collab::results::Origin {
                target: wire::Target {
                    account_id: host.account_id.clone(),
                    atem_device_id: host.atem_device_id.clone(),
                    host_trust_gen: host.host_trust_gen,
                    session_id: rig.sid.to_string(),
                    process_gen: rig.sessions[&rig.sid].process_gen.clone(),
                },
                control_gen: 0,
                route: None,
            };
            let mut message = rig.message();
            message.from_session = Some(rig.sid.to_string());
            message.recipients[0].destination = Destination::Select {
                selectors: vec!["tag:x".into()],
                budget: 32,
            };
            // Both pass the shared message rules; only the task rules refuse.
            for (text, problem) in [
                (
                    "x".repeat(40_000),
                    "the prompt with its context is over 32 KiB",
                ),
                (
                    "escape \u{1b}[2J".to_string(),
                    "context has control characters",
                ),
            ] {
                message.context = vec![snapshot(&text)];
                assert!(message.valid_local(), "{problem}");
                let error = rig
                    .bridge
                    .collab_accept("atem-host", &message, &origin, &rig.sessions)
                    .unwrap_err();
                assert_eq!(error.to_string(), problem);
                assert_eq!(rows(&rig, "counters"), 0, "{problem}");
                assert_eq!(rows(&rig, "outbox"), 0, "{problem}");
            }
            // The same message without the problem is accepted, and counts once.
            message.context = vec![snapshot("fits")];
            rig.bridge
                .collab_accept("atem-host", &message, &origin, &rig.sessions)
                .unwrap();
            assert_eq!(counted(&rig, &format!("send:{}", message.workflow_id)), 1);
            assert_eq!(
                counted(&rig, &format!("receive:{}", message.workflow_id)),
                1
            );
            assert_eq!(rows(&rig, "outbox"), 1);
        });
    }

    #[test]
    fn a_memory_that_could_never_dispatch_is_refused_at_send() {
        local_test(async |root| {
            let mut rig = LocalRig::new(root).await;
            let memories = crate::memory::store::Store::open(&root.join("knowledge.db")).unwrap();
            memories
                .upsert_memory(&crate::memory::model::Memory {
                    id: "mem_f00dbabe".into(),
                    content: "x".repeat(40_000),
                    ..Default::default()
                })
                .unwrap();
            let mut request = send_request(&["tag:x"]);
            request.memory = vec!["mem_f00dbabe".into()];
            let error = rig
                .bridge
                .collab_send("atem-host", &rig.sid, request, &rig.sessions)
                .unwrap_err();
            assert_eq!(
                error.to_string(),
                "the prompt with its context is over 32 KiB"
            );
            assert_eq!(rows(&rig, "outbox"), 0);
            assert_eq!(rows(&rig, "counters"), 0);
        });
    }

    #[test]
    fn a_bad_selector_or_expiry_is_refused_with_its_own_reason() {
        local_test(async |root| {
            let mut rig = LocalRig::new(root).await;
            let error = rig
                .bridge
                .collab_send(
                    "atem-host",
                    &rig.sid,
                    send_request(&["tag:ok", "project:ok", "tag:Bad"]),
                    &rig.sessions,
                )
                .unwrap_err();
            assert_eq!(
                error.to_string(),
                "selector 3: names are 1-32 of a-z, 0-9 and -"
            );
            let mut request = send_request(&["tag:ok"]);
            request.expires_ms = 500;
            let error = rig
                .bridge
                .collab_send("atem-host", &rig.sid, request, &rig.sessions)
                .unwrap_err();
            assert_eq!(error.to_string(), "expiry must be between 1s and 24h");
            assert_eq!(rows(&rig, "counters"), 0);
        });
    }

    #[test]
    fn unavailable_collaboration_says_what_is_missing() {
        local_test(async |root| {
            let mut rig = LocalRig::new(root).await;
            let why = |rig: &mut LocalRig| {
                rig.bridge
                    .collab_send(
                        "atem-host",
                        &rig.sid,
                        send_request(&["tag:ok"]),
                        &rig.sessions,
                    )
                    .unwrap_err()
                    .to_string()
            };
            rig.bridge.work.config.collab.send = false;
            assert_eq!(
                why(&mut rig),
                "collaboration unavailable: set `[collab] send = true` in runtime.toml"
            );
            rig.bridge.work.config.enabled = false;
            assert_eq!(
                why(&mut rig),
                "collaboration unavailable: set `enabled = true` in runtime.toml; \
                 set `[collab] send = true` in runtime.toml"
            );
            rig.bridge.work.config.enabled = true;
            rig.bridge.work.config.collab.send = true;
            rig.bridge.work.config_problem = Some("profile `p`: bad".into());
            assert_eq!(
                why(&mut rig),
                "collaboration unavailable: runtime.toml is not valid (profile `p`: bad); \
                 fix it, then see `atem runtime check`"
            );
        });
    }

    #[test]
    fn collaboration_needs_a_pairing() {
        local_test(async |root| {
            let mut bridge =
                HostBridge::open(&root.join("runtime/journal"), None, Clock::default()).unwrap();
            bridge.work.config = Config {
                version: 1,
                enabled: true,
                collab: crate::runtime::host_work::Collab {
                    send: true,
                    ..Default::default()
                },
                ..Default::default()
            };
            let error = bridge
                .collab_send(
                    "atem-host",
                    &SessionId::new(),
                    send_request(&["tag:ok"]),
                    &BTreeMap::new(),
                )
                .unwrap_err();
            assert_eq!(
                error.to_string(),
                "collaboration unavailable: pair and verify this device with Astation (`atem pair`)"
            );
        });
    }

    #[test]
    fn the_local_attachment_survives_a_link_drop_and_returns_after_a_rebind() {
        let dir = tempfile::tempdir().unwrap();
        let _profile = crate::test_profile::use_dir(dir.path());
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let app = App::new();
            let mut sessions = BTreeMap::new();
            let mut cx = Cx {
                client: &app.astation_client,
                sessions: &mut sessions,
            };
            let mut bridge =
                HostBridge::open(&dir.path().join("runtime/journal"), None, Clock::default())
                    .unwrap();
            let identity = Identity {
                account_id: "acct-local".into(),
                atem_device_id: "host-local".into(),
                host_trust_gen: 1,
            };
            assert!(bridge.adopt_identity(&identity, &mut cx));
            bridge.work.config.enabled = true;
            bridge.work.config.collab.send = true;
            bridge.sync_local(&mut cx);
            let attachment = bridge.local_attachment().to_string();
            assert!(!attachment.is_empty());
            assert_eq!(bridge.host.attachment_principal(&attachment), Some("local"));
            bridge.sync_link(None, &mut cx);
            assert_eq!(bridge.local_attachment(), attachment);
            let mut other = identity;
            other.host_trust_gen += 1;
            assert!(bridge.adopt_identity(&other, &mut cx));
            bridge.sync_local(&mut cx);
            assert_ne!(bridge.local_attachment(), attachment);
            assert_eq!(bridge.host.attachment_principal(&attachment), None);
            let effects = bridge.host.membership_fault(None);
            bridge.exec(effects, &mut cx);
            bridge.sync_local(&mut cx);
            assert!(bridge.local_attachment().is_empty());
        });
    }

    /// The switches in `runtime.toml` pause local work; they never fence it.
    /// Only a real change of authority does.
    #[test]
    fn a_pause_keeps_the_local_attachment_and_its_control_generation() {
        let dir = tempfile::tempdir().unwrap();
        let _profile = crate::test_profile::use_dir(dir.path());
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let app = App::new();
            let mut sessions = BTreeMap::new();
            let mut cx = Cx {
                client: &app.astation_client,
                sessions: &mut sessions,
            };
            let mut bridge =
                HostBridge::open(&dir.path().join("runtime/journal"), None, Clock::default())
                    .unwrap();
            let identity = Identity {
                account_id: "acct-local".into(),
                atem_device_id: "host-local".into(),
                host_trust_gen: 1,
            };
            assert!(bridge.adopt_identity(&identity, &mut cx));
            bridge.work.config.enabled = true;
            bridge.work.config.collab.send = true;
            bridge.sync_local(&mut cx);
            let attachment = bridge.local_attachment().to_string();
            assert!(!attachment.is_empty());
            assert!(bridge.local_healthy());
            assert!(bridge.collab_paused().is_empty());
            let generation = bridge.host.control_gen("local");

            // Each pause, then the recovery: the same attachment, the same
            // generation, nothing fenced.
            let good = bridge.work.config.clone();
            for pause in 0..4 {
                match pause {
                    0 => bridge.work.config.enabled = false,
                    1 => bridge.work.config.collab.send = false,
                    2 => {
                        bridge.work.config = Config::default();
                        bridge.work.config_problem = Some("expected a table".into());
                    }
                    _ => bridge.work.error = true,
                }
                bridge.sync_local(&mut cx);
                assert!(!bridge.local_healthy(), "pause {pause}");
                assert!(!bridge.collab_paused().is_empty(), "pause {pause}");
                assert_eq!(bridge.local_attachment(), attachment, "pause {pause}");
                assert_eq!(bridge.host.control_gen("local"), generation);
                assert_eq!(bridge.host.attachment_principal(&attachment), Some("local"));
                bridge.work.config = good.clone();
                bridge.work.config_problem = None;
                bridge.work.error = false;
                bridge.sync_local(&mut cx);
                assert!(bridge.local_healthy(), "pause {pause}");
                assert!(bridge.collab_paused().is_empty(), "pause {pause}");
                assert_eq!(bridge.local_attachment(), attachment, "pause {pause}");
                assert_eq!(bridge.host.control_gen("local"), generation);
            }

            // A pause that began before any attachment: it comes with the
            // recovery, and still nothing was fenced.
            bridge.work.config.collab.send = false;
            let mut other = identity;
            other.host_trust_gen += 1;
            assert!(bridge.adopt_identity(&other, &mut cx));
            bridge.sync_local(&mut cx);
            assert!(bridge.local_attachment().is_empty());
            let fenced = bridge.host.control_gen("local");
            assert!(fenced > generation, "a new host identity fences `local`");
            bridge.sync_local(&mut cx);
            assert_eq!(bridge.host.control_gen("local"), fenced);
            bridge.work.config.collab.send = true;
            bridge.sync_local(&mut cx);
            assert!(!bridge.local_attachment().is_empty());
            assert_eq!(bridge.host.control_gen("local"), fenced);
        });
    }
}
