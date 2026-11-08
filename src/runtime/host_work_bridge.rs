//! Opt-in host operations. Work reaches agents only through session-v1 receipts.
use super::*;
use crate::runtime::host_work::{
    AUTHORIZATION_EXPIRED, Accepted, Config, LaunchRecord, Profile, Store, WorkRecord,
};
use crate::session_protocol::r9::ProjectScope;
use atem_client::principal::{Authority, Need, Op};
use atem_client::session::host_work::{
    self as hw, HostTarget, LaunchState, LaunchStatus, ResultBody, WorkState, WorkStatus,
};
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;

/// The longest `paused: <reason>` detail a waiting local task carries.
const MAX_PAUSE_DETAIL: usize = 240;

/// How often the payloads of host-work records settled a day past their
/// deadline are dropped, and collaboration counters whose windows passed
/// are pruned (counters also at each counted send).
const CLEANUP_EVERY: Duration = Duration::from_secs(60);

/// A task whose sender's authority changed since it was accepted: its
/// principal's control generation moved on (a fence: a removal, any change
/// of a service's grant, a renewal too, a revoked grant, a device-list
/// freeze or fault, `local` losing the host's authority). Nothing of it
/// goes on under the new authority, and no later grant revives it.
const AUTHORITY_CHANGED: &str = "sender's authority changed";

/// A submitted task whose session receipt the session host no longer has
/// (evicted or lost): its outcome can't be known any more.
const RECEIPT_GONE: &str = "receipt no longer available";

/// A task whose turn ended interrupted (its prompt receipt completed with
/// the outcome `interrupted`): it awaits its result like any other.
const TURN_INTERRUPTED: &str = "turn interrupted";

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

/// What the authority, route and grant checks of tasks awaiting their
/// result (or of unknown outcome) and of return grants depend on, besides
/// time (`work_inputs`): they are re-run only when one of these changed;
/// deadlines and authorization expiries are found by their due times.
#[derive(Clone, PartialEq)]
struct WorkInputs {
    control: (usize, u64),
    local: (bool, bool, bool, String),
    config: Config,
    config_problem: Option<String>,
    host: HostTarget,
    sessions: Vec<SessionInput>,
}

/// One session as `WorkInputs` sees it.
#[derive(Clone, PartialEq)]
struct SessionInput {
    id: String,
    process_gen: String,
    live: bool,
    cwd: PathBuf,
    provider: String,
    project: Option<String>,
    project_unread: bool,
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
    /// The project scopes (`Profile::scope_key`) of the profiles of the
    /// last `runtime.toml` that loaded.
    scoped: HashSet<String>,
    refresh: Instant,
    scheduled: Instant,
    recovered: bool,
    pending: HashMap<String, PendingLaunch>,
    launches: VecDeque<RemoteLaunch>,
    context_jobs:
        HashMap<String, tokio::sync::oneshot::Receiver<anyhow::Result<Vec<hw::ContextSnapshot>>>>,
    /// When the next cleanup (`work_cleanup`) runs.
    cleanup: Instant,
    /// What the checks of waiting tasks and grants last ran under.
    inputs: Option<WorkInputs>,
    /// Those inputs changed: every waiting task (`settle_lost`) and every
    /// return grant (`collab_result_pass`) is to be checked again.
    recheck_tasks: bool,
    recheck_grants: bool,
    /// The principals of tasks not settled (awaiting ones as of the last
    /// full check, and every task active since): their control states are
    /// kept (`SessionHost::keep_principals`).
    named: HashSet<String>,
    /// Why the runtime refused to start a launch it was handed (the
    /// live-session limit, a restart): the detail of its local tasks.
    refused: HashMap<String, String>,
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
            config_problem: None,
            scoped: HashSet::new(),
            refresh: Instant::now(),
            scheduled: Instant::now(),
            recovered: false,
            pending: HashMap::new(),
            launches: VecDeque::new(),
            context_jobs: HashMap::new(),
            cleanup: Instant::now(),
            inputs: None,
            recheck_tasks: true,
            recheck_grants: true,
            named: HashSet::new(),
            refused: HashMap::new(),
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

    /// The launches to start now. A launch that has not started, local or
    /// remote, waits out a `runtime.toml` that doesn't load and starts when
    /// it loads again (spec section 9); hosting switched off (`enabled =
    /// false`, a deliberate stop) and a receipt database fault, which lasts
    /// until a restart (`work_fail`), fence it instead. Fences are evaluated
    /// first, so what changed while it waited is not started on the old
    /// approval (a fenced one is handed out to fail at its guard).
    pub fn take_remote_launches(&mut self) -> Vec<RemoteLaunch> {
        if self.work.launches.is_empty() {
            return Vec::new();
        }
        #[cfg(debug_assertions)]
        if crate::runtime::test_hooks::launches_held() {
            return Vec::new();
        }
        self.work_fence_launches();
        let paused = self.work.config_problem.is_some();
        let pending = &self.work.pending;
        let waits = |id: &str| {
            paused
                && pending
                    .get(id)
                    .is_some_and(|p| p.permit.load(Ordering::SeqCst))
        };
        let (mut ready, mut waiting) = (Vec::new(), VecDeque::new());
        for launch in self.work.launches.drain(..) {
            if waits(&launch.request_id) {
                waiting.push_back(launch);
            } else {
                ready.push(launch);
            }
        }
        self.work.launches = waiting;
        ready
    }

    /// The runtime refused to start launch `request_id` (`why`: the
    /// live-session limit, a restart): it failed, nothing was started, and
    /// its local tasks say why.
    pub fn launch_refused(&mut self, request_id: &str, why: String) {
        if self.work.refused.len() >= 256 {
            self.work.refused.clear();
        }
        self.work.refused.insert(request_id.to_string(), why);
        self.remote_launched(request_id, LaunchState::Failed);
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
        // Launches that haven't started are fenced, remote and local: this
        // pause lasts until a restart, so none can wait it out.
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
        // not started wait, requests are `busy` and queued local tasks wait
        // as `paused` (`work_pass`); nothing is fenced.
        let config = match Config::load(&self.work.dir) {
            Ok(config) => {
                if self.work.config_problem.take().is_some() {
                    eprintln!(
                        "atem runtime: runtime.toml is valid again; agent hosting follows it"
                    );
                }
                // Only a file that loads drops the project scopes of the
                // profiles it no longer names: their hashes stay through an
                // invalid file's pause, so what waited out the pause is
                // compared with them at once when it ends.
                let retained: HashSet<String> =
                    config.profiles.iter().map(Profile::scope_key).collect();
                for key in self.work.scoped.difference(&retained) {
                    self.projects.forget(key);
                }
                self.work.scoped = retained;
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
                for mut record in store.tasks_in(WorkState::OutcomeUnknown)? {
                    self.reconcile_work(&mut record)?;
                    store.save_work(&record)?;
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
            let inputs = self.work_inputs(cx.sessions);
            if self.work.inputs.as_ref() != Some(&inputs) {
                self.work.inputs = Some(inputs);
                self.work.recheck_tasks = true;
                self.work.recheck_grants = true;
            }
            let passed = self
                .collab_pass(cx, self.work.recheck_grants)
                .and_then(|looked| {
                    if looked {
                        self.work.recheck_grants = false;
                    }
                    self.collab_reply_pass()
                })
                .and_then(|_| self.schedule_work(cx))
                .and_then(|_| self.work_cleanup());
            if passed.is_err() {
                self.work_fail();
            }
        }
    }

    /// The inputs of the checks of waiting tasks and return grants
    /// (`WorkInputs`): the session host's control generations, `local`'s
    /// standing, the configuration that loaded, the host identity and the
    /// sessions (process generation, liveness, directory, provider, launch
    /// project). Its cost doesn't depend on how many tasks wait.
    fn work_inputs(&self, sessions: &BTreeMap<SessionId, BrokerSession>) -> WorkInputs {
        WorkInputs {
            control: self.host.control_gens(),
            local: (
                self.local_authorized(),
                self.local_halted(),
                self.hosting_enabled(),
                self.local_attachment().to_string(),
            ),
            config: self.work.config.clone(),
            config_problem: self.work.config_problem.clone(),
            host: self.work_host(),
            sessions: sessions
                .values()
                .map(|s| {
                    let sid = s.id.as_str();
                    SessionInput {
                        id: sid.to_string(),
                        process_gen: s.process_gen.clone(),
                        live: s.is_live(),
                        cwd: s.cwd.clone(),
                        provider: s.provider.clone(),
                        project: self.projects.key_of(sid).map(str::to_string),
                        project_unread: self.project_unread.contains_key(sid),
                    }
                })
                .collect(),
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
        // Only a file that doesn't load is waited out; `enabled = false`
        // fences (a receipt database fault already did, `work_fail`).
        let paused = self.work.config_problem.is_some();
        let ids: Vec<String> = self.work.pending.keys().cloned().collect();
        for id in ids {
            let attachment = self.work.pending[&id].attachment.clone();
            let remote = self.work.pending[&id].local_route.is_none();
            let authority = if remote {
                self.work_authority(&attachment)
            } else {
                None
            };
            let p = &self.work.pending[&id];
            let allowed = host_now().wall_ms < p.expires_at
                && self.host.control_gen(&p.principal) == p.control_gen
                && match &p.local_route {
                    // A change of authority fences a local launch: a new host
                    // identity, a lost device list, a changed approval. So
                    // does a plain session-journal halt (`local` is fenced in
                    // memory): only a restart ends it, and the restart drops
                    // a launch not started anyway. So does hosting switched
                    // off. A file that doesn't load is waited out
                    // (`take_remote_launches`); while it doesn't the
                    // approval can't be compared, which is no change: it is
                    // compared again once it loads. `[collab] send` never
                    // matters.
                    Some(route) => {
                        !p.attachment.is_empty()
                            && p.attachment == self.local_attachment()
                            && self.local_authorized()
                            && (paused
                                || self.work.config.enabled
                                    && self.work.config.profile(&p.profile.id) == Some(&p.profile)
                                    && self.work.config.route(&route.id) == Some(route)
                                    && route.principals.iter().any(|p| p == "local")
                                    && route.launch
                                        == crate::runtime::host_work::RouteLaunch::OnMessage)
                    }
                    // A remote launch waits out a file that doesn't load the
                    // same way while its sender's authority holds (the same
                    // attachment and principal, the control generation
                    // checked above); its approval is compared again once it
                    // loads. Hosting switched off fences it, as v0.8.2 did.
                    None => authority.as_ref().is_some_and(|a| {
                        a.name() == p.principal
                            && (paused
                                || self.hosting_enabled()
                                    && self.work.config.profile(&p.profile.id) == Some(&p.profile)
                                    && self.profile_allowed(&p.profile, a, true))
                    }),
                };
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
            // Its tasks compare their sender's control generation with this
            // one: it is kept from now on (`schedule_work` renews the set).
            self.host.keep_principal(&principal);
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
                    authorization_expires_at: a.remote().and_then(|a| a.expires_at),
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
                self.host.keep_principal(&record.principal);
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
                    self.reconcile_work(&mut r).map_err(|_| "busy")?;
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
                // The sending session and the reply link are local-only. A
                // remote envelope with one doesn't decode (`Message::valid`);
                // this check stays as the last line.
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
            // By the digest recorded at acceptance, which stays when the
            // message's text is dropped (`Store::drop_payloads`).
            if let hw::Request::Publish { message, .. } = req
                && old.receipt.digest != message.digest()
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
                    authorization_expires_at: a.remote().and_then(|a| a.expires_at),
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

    /// About once a minute, after a scheduling pass: the payloads of
    /// host-work records settled a day past their deadline go, remote and
    /// local alike (`Store::drop_payloads`; every record stays, one
    /// runtime.log line says how many), and collaboration counters whose
    /// windows passed.
    fn work_cleanup(&mut self) -> anyhow::Result<()> {
        if Instant::now() < self.work.cleanup {
            return Ok(());
        }
        self.work.cleanup = Instant::now() + CLEANUP_EVERY;
        let store = self.work.store.as_ref().unwrap();
        let now = host_now().wall_ms;
        let dropped = store.drop_payloads(now)?;
        if dropped != Default::default() {
            let count =
                |n: usize, what: &str| format!("{n} {what}{}", if n == 1 { "" } else { "s" });
            eprintln!(
                "atem runtime: host work: dropped the payloads of {}, {}, {} (records kept)",
                count(dropped.tasks, "task"),
                count(dropped.messages, "message"),
                count(dropped.uploads, "upload")
            );
        }
        crate::runtime::collab::prune_counters(&store.db, now)
    }

    /// One scheduling pass. It runs only while hosting runs, so no pause
    /// applies here (`pause_local_tasks` marks local tasks during one).
    fn schedule_work(&mut self, cx: &mut Cx) -> anyhow::Result<()> {
        let now = host_now().wall_ms;
        // Awaiting a result, or of unknown outcome: past the deadline,
        // expired, and past the sender's authorization, failed (their due
        // times, through an index); under a sender's authority, a route or a
        // profile approval that is gone, failed (every one of them read, but
        // only when what that depends on changed: `work_inputs`). Either
        // frees an unknown outcome's session queue.
        let store = self.work.store.as_ref().unwrap();
        store.settle_due(now)?;
        if self.work.recheck_tasks {
            let mut named = HashSet::new();
            store.settle_lost(now, |accepted| {
                let lost = self.work_lost(accepted, now);
                if lost.is_none() {
                    named.insert(accepted.principal.clone());
                }
                lost
            })?;
            self.work.named = named;
            self.work.recheck_tasks = false;
        }
        let tasks = self.work.store.as_ref().unwrap().active_tasks()?;
        self.work
            .named
            .extend(tasks.iter().map(|r| r.principal.clone()));
        // Their control states stay known while a task names them.
        self.host.keep_principals(self.work.named.clone());
        // A task of unknown outcome holds its session's queue.
        let mut occupied = HashSet::new();
        for session in tasks
            .iter()
            .map(|r| r.task.target.session_id.as_str())
            .collect::<HashSet<_>>()
        {
            if self
                .work
                .store
                .as_ref()
                .unwrap()
                .holds_unknown_outcome(session)?
            {
                occupied.insert(session.to_string());
            }
        }
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
                self.reconcile_work(&mut r)?;
                // A turn that ended (or an outcome no longer known) under a
                // sender's authority, a route or a profile approval that is
                // gone: the task fails. A turn that runs is left to its end,
                // never interrupted.
                if matches!(
                    r.status.state,
                    WorkState::AwaitingResult | WorkState::OutcomeUnknown
                ) && let Some(lost) = self.work_lost(&r.accepted(), now)
                {
                    self.work_fail_lost(&mut r, lost)?;
                    continue;
                }
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
            if now >= r.task.expires_at {
                r.status.state = WorkState::Expired;
                r.status.detail = "expired before submission".into();
                self.work.store.as_ref().unwrap().save_work(&r)?;
                continue;
            }
            // A task can never be dispatched under a sender's authority that
            // is gone, nor under a route or profile approval that changed:
            // it fails at once, before it takes its session's place, rather
            // than hold the session's queue until it expires.
            if let Some(lost) = self.work_lost(&r.accepted(), now) {
                self.work_fail_lost(&mut r, lost)?;
                continue;
            }
            if self.collab_wait_for_launch(&mut r)? {
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

    fn reconcile_work(&self, r: &mut WorkRecord) -> anyhow::Result<()> {
        use crate::session_protocol::wire::ReceiptState;
        let Some(receipt) = self.host.receipt(&r.status.receipt_id) else {
            // Submitted, and its receipt gone (evicted or lost): what became
            // of it can't be known any more.
            if r.status.state == WorkState::Submitted {
                r.status.state = WorkState::OutcomeUnknown;
                r.status.detail = RECEIPT_GONE.into();
            }
            return Ok(());
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
            return Ok(());
        }
        // A rejected receipt says why (`control revoked`, `host trust
        // changed`, `session closed`, …).
        if let (ReceiptState::Rejected, Some(detail)) = (receipt.state, &receipt.detail) {
            r.status.detail = detail.clone();
            return Ok(());
        }
        r.status.detail = if r.status.state == WorkState::Submitted && r.turn_id.is_some() {
            collab_bridge::IN_TURN
        } else if turn_interrupted(&receipt) {
            TURN_INTERRUPTED
        } else {
            "agent submission receipt reconciled; task completion requires an explicit result"
        }
        .into();
        if let Some(reply) = self.collab_reply_of(&r.task.task_id) {
            collab_bridge::apply_reply(r, &reply);
        }
        self.collab_early_end(r)?;
        Ok(())
    }

    /// The task's prompt turn ended interrupted (its receipt's journaled
    /// outcome).
    pub(super) fn work_interrupted(&self, r: &WorkRecord) -> bool {
        self.host
            .receipt(&r.status.receipt_id)
            .is_some_and(|receipt| turn_interrupted(&receipt))
    }

    /// Why a task accepted under `a` can no longer go on at wall time
    /// `now`, if it can't: its sender's authorization expired, its
    /// principal's control generation moved on (a fence), or its route or
    /// profile approval changed (`work_route_changed`). The host keeps the
    /// control state of every principal a task names
    /// (`SessionHost::keep_principals`), so forgetting one is no change. A
    /// halted session journal is a pause of `local`, no change of its
    /// authority (`local_halted`): its tasks wait for the restart.
    pub(super) fn work_lost(&self, a: &Accepted, now: u64) -> Option<&'static str> {
        if a.authorization_expires_at.is_some_and(|at| now >= at) {
            return Some(AUTHORIZATION_EXPIRED);
        }
        if (a.principal != "local" || !self.local_halted())
            && self.host.control_gen(&a.principal) != a.control_gen
        {
            return Some(AUTHORITY_CHANGED);
        }
        self.work_route_changed(a)
            .then_some(collab_bridge::ROUTE_CHANGED)
    }

    /// The session journal halted while the device list stays usable (not
    /// faulted, frozen or held): `local` is fenced in memory only, until the
    /// restart brings back its durable control state. Nothing local
    /// dispatches meanwhile (`local_healthy`).
    fn local_halted(&self) -> bool {
        self.host.journal_halted()
            && self.membership_error.is_none()
            && self
                .membership
                .as_ref()
                .is_none_or(|m| !m.is_frozen() && m.faulted().is_none() && m.held().is_none())
    }

    /// `r` fails for the reason `work_lost` named, and its return grant ends
    /// with it: no delivery, no completion, no reply.
    fn work_fail_lost(&self, r: &mut WorkRecord, lost: &'static str) -> anyhow::Result<()> {
        let store = self.work.store.as_ref().unwrap();
        r.status.state = WorkState::Failed;
        r.status.detail = lost.into();
        let tx = store.db.unchecked_transaction()?;
        store.save_work(r)?;
        tx.execute(
            "UPDATE return_grants SET state='ended' WHERE task_id=?1 AND state IN ('open','consumed')",
            [&r.task.task_id],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// The route or profile approval a task was accepted under is no
    /// longer the one in `runtime.toml`: the route is gone or has another
    /// revision or profile, no longer names the task's principal, or its
    /// profile has another revision or project.
    fn work_route_changed(&self, a: &Accepted) -> bool {
        let Some(route) = self.work.config.route(&a.route_id) else {
            return true;
        };
        let Some(profile) = self.work.config.profile(&route.profile_id) else {
            return true;
        };
        route.revision != a.route_revision
            || !route.principals.contains(&a.principal)
            || profile.id != a.profile_id
            || profile.revision != a.profile_revision
            || profile.project != a.project
    }
}

/// A prompt receipt completed with the outcome `interrupted` (journaled as
/// its detail).
fn turn_interrupted(receipt: &wire::Receipt) -> bool {
    receipt.state == wire::ReceiptState::Completed
        && receipt.kind == wire::ReceiptKind::Prompt
        && receipt.detail.as_deref() == Some("interrupted")
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
            // A host with a pinned device list, which refuses r8: collaboration
            // runs nowhere else.
            bridge.host.set_refuse_r8(true);
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
            // The first agent on a cold machine (CI's x86_64 macOS job under
            // Rosetta) can take minutes to start; this only bounds a failure.
            rig.until_within(Duration::from_secs(300), |r| {
                r.sessions[&r.sid].chat_v1
                    && r.sessions[&r.sid].chat.status().state == ChatState::Ready
            })
            .await;
            rig
        }

        /// Passes until `predicate` holds; the deadline only bounds a
        /// failure (slow CI hosts take several times longer).
        async fn until(&mut self, predicate: impl FnMut(&Self) -> bool) {
            self.until_within(Duration::from_secs(60), predicate).await;
        }

        /// `until`, failing after `limit`.
        async fn until_within(
            &mut self,
            limit: Duration,
            mut predicate: impl FnMut(&Self) -> bool,
        ) {
            let deadline = Instant::now() + limit;
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

    /// The account's signed encryption mode is `on` in the profile at
    /// `root`, as vault context needs it (spec section 8).
    fn encryption_on(root: &Path) {
        use crate::memory::fake_astation::{pin, set_state};
        let paths = crate::paths::CredPaths::in_dir(root);
        std::fs::create_dir_all(&paths.dir).unwrap();
        let astation = crate::memory::statements::FakeAstation::new();
        let keys = crate::memory::device_keys::DeviceKeys::generate();
        pin(&paths, &astation, &keys, true);
        set_state(
            &paths,
            &astation,
            crate::memory::crypto::EncryptionMode::On,
            Some("0a1b2c3d"),
            2,
        );
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
                    .open_tasks()
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

    /// Counts the rows written to `return_grants`, `results` and `work` from
    /// now on (temporary triggers: inserts, updates, deletes).
    fn count_writes(rig: &LocalRig) {
        let mut sql = "CREATE TEMP TABLE writes(t TEXT NOT NULL);".to_string();
        for table in ["return_grants", "results", "work"] {
            for (n, event) in ["INSERT", "UPDATE", "DELETE"].iter().enumerate() {
                sql.push_str(&format!(
                    "CREATE TEMP TRIGGER w_{table}_{n} AFTER {event} ON main.{table}
                    BEGIN INSERT INTO writes VALUES('{table}'); END;"
                ));
            }
        }
        rig.bridge
            .work
            .store
            .as_ref()
            .unwrap()
            .db
            .execute_batch(&sql)
            .unwrap();
    }

    fn writes(rig: &LocalRig, table: &str) -> i64 {
        rig.bridge
            .work
            .store
            .as_ref()
            .unwrap()
            .db
            .query_row("SELECT count(*) FROM writes WHERE t=?1", [table], |r| {
                r.get(0)
            })
            .unwrap()
    }

    /// Passes of the runtime for `ms` (each a scheduling pass, 100 ms apart).
    async fn idle(rig: &mut LocalRig, ms: u64) {
        let until = Instant::now() + Duration::from_millis(ms);
        rig.until(|_| Instant::now() >= until).await;
    }

    /// The task of `message` under a return grant whose sender is the
    /// rig's own session (stage 1: an open grant per local request task).
    fn grant(rig: &LocalRig, message: &Message) {
        use crate::runtime::collab::results::{self, Origin, ReturnGrant};
        let task = rig.work(message);
        let store = rig.bridge.work.store.as_ref().unwrap();
        let tx = store.db.unchecked_transaction().unwrap();
        results::save_grant(
            &tx,
            &ReturnGrant {
                task_id: task.task.task_id.clone(),
                message_id: message.message_id.clone(),
                workflow_id: message.workflow_id.clone(),
                origin: Origin {
                    target: task.task.target.clone(),
                    control_gen: rig.bridge.host.control_gen("local"),
                    route: None,
                },
                recipient: task.task.target.clone(),
                expires_at: message.expires_at,
                ended: None,
            },
        )
        .unwrap();
        tx.commit().unwrap();
    }

    fn reply(rig: &mut LocalRig, task: &str, text: &str, vault: &[&str]) -> Result<String, String> {
        rig.bridge
            .collab_reply(
                &rig.sid,
                crate::runtime::collab::ReplyRequest {
                    task_id: Some(task.into()),
                    text: text.into(),
                    memory: vec![],
                    vault: vault.iter().map(|v| v.to_string()).collect(),
                },
                &rig.sessions,
            )
            .map(|row| row.result_id)
            .map_err(|e| e.to_string())
    }

    /// Spec section 10, "Storage": a grant or result is written when its
    /// state changes, never on a pass where nothing did. "Ending early": a
    /// sender that is gone cancels nothing: its task keeps awaiting its
    /// result, its detail written once.
    #[test]
    fn grants_are_written_on_change_only_and_a_gone_sender_keeps_its_task() {
        local_test(async |root| {
            let mut rig = LocalRig::new(root).await;
            let message = rig.message();
            rig.publish(&message);
            grant(&rig, &message);
            count_writes(&rig);
            let task = rig.work(&message).task.task_id;
            rig.until(|r| r.work(&message).turn_id.is_some()).await;
            assert_eq!(reply(&mut rig, &task, "done", &[]).map(|_| ()), Ok(()));
            std::fs::write(rig.fake.join("complete"), "").unwrap();
            rig.until(|r| r.work(&message).status.state == WorkState::AwaitingResult)
                .await;
            idle(&mut rig, 300).await;
            let (grants, results) = (writes(&rig, "return_grants"), writes(&rig, "results"));
            assert_eq!(results, 1, "the reply, once");
            // Nothing changes: nothing is written, pass after pass.
            idle(&mut rig, 800).await;
            assert_eq!(writes(&rig, "return_grants"), grants);
            assert_eq!(writes(&rig, "results"), results);
            assert_eq!(rig.work(&message).status.state, WorkState::AwaitingResult);

            // The sending process ends: the grant ends once, and the task
            // keeps awaiting its result, its detail written once.
            let tasks = writes(&rig, "work");
            rig.sessions[&rig.sid].stop().unwrap();
            rig.until(|r| r.work(&message).status.detail == collab_bridge::SENDER_GONE)
                .await;
            assert_eq!(rig.work(&message).status.state, WorkState::AwaitingResult);
            idle(&mut rig, 500).await;
            assert_eq!(writes(&rig, "return_grants"), grants + 1);
            assert_eq!(writes(&rig, "results"), results);
            assert_eq!(writes(&rig, "work"), tasks + 1);
            let state: String = rig
                .bridge
                .work
                .store
                .as_ref()
                .unwrap()
                .db
                .query_row(
                    "SELECT state FROM return_grants WHERE task_id=?1",
                    [&task],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(state, "ended");
        });
    }

    /// A queued local task whose target route or profile approval changed
    /// fails at once ("route changed") instead of holding its session's
    /// queue until it expires, the one in its turn once that ends; the
    /// session's next task goes on.
    #[test]
    fn a_queued_local_task_whose_route_changed_fails_and_frees_its_session() {
        local_test(async |root| {
            let mut rig = LocalRig::new(root).await;
            let first = rig.message();
            rig.publish(&first);
            rig.until(|r| r.work(&first).turn_id.is_some()).await;
            let queued = rig.message();
            rig.publish(&queued);
            rig.until(|r| {
                r.work(&queued).status.detail == "waiting for an earlier task on this session"
            })
            .await;
            // The owner approves a new revision of the route.
            rig.bridge.work.config.routes[0].revision = 2;
            rig.until(|r| r.work(&queued).status.state == WorkState::Failed)
                .await;
            assert_eq!(rig.work(&queued).status.detail, "route changed");
            // The turn in progress is not touched; once it ends, its task
            // fails too: it can't await a result under the old route.
            assert_eq!(rig.work(&first).status.state, WorkState::Submitted);
            std::fs::write(rig.fake.join("complete"), "").unwrap();
            rig.until(|r| r.work(&first).status.state == WorkState::Failed)
                .await;
            assert_eq!(rig.work(&first).status.detail, "route changed");
            let mut next = rig.message();
            next.text = "UNDER_THE_NEW_REVISION".into();
            if let Destination::Agent { route_revision, .. } = &mut next.recipients[0].destination {
                *route_revision = 2;
            }
            rig.publish(&next);
            rig.until(|r| {
                std::fs::read_to_string(r.fake.join("input"))
                    .unwrap_or_default()
                    .contains("UNDER_THE_NEW_REVISION")
            })
            .await;
        });
    }

    /// A task of `principal` (accepted at `control_gen`) to the rig's
    /// session, written as it is in `state` with a receipt no host has; its
    /// id.
    fn insert_task(
        rig: &LocalRig,
        principal: &str,
        control_gen: u64,
        state: WorkState,
        expires_at: u64,
    ) -> String {
        let message = rig.message();
        let mut task = message.task(&message.recipients[0]).unwrap();
        task.expires_at = expires_at;
        let record = WorkRecord {
            principal: principal.into(),
            attachment_owner: String::new(),
            control_gen,
            route_id: "r".into(),
            route_revision: 1,
            profile_id: "p".into(),
            profile_revision: 1,
            project: "local:project".into(),
            digest: hw::digest(b"task"),
            status: WorkStatus {
                task_id: task.task_id.clone(),
                receipt_id: uuid::Uuid::new_v4().to_string(),
                state,
                detail: String::new(),
                result: None,
            },
            task,
            turn_id: None,
            authorization_expires_at: None,
        };
        rig.bridge
            .work
            .store
            .as_ref()
            .unwrap()
            .db
            .execute(
                "INSERT INTO work(id,record,state) VALUES(?1,?2,?3)",
                rusqlite::params![
                    record.task.task_id,
                    serde_json::to_string(&record).unwrap(),
                    serde_json::to_value(state).unwrap().as_str().unwrap()
                ],
            )
            .unwrap();
        record.task.task_id
    }

    fn stored(rig: &LocalRig, id: &str) -> WorkStatus {
        rig.bridge
            .work
            .store
            .as_ref()
            .unwrap()
            .work(id)
            .unwrap()
            .unwrap()
            .status
    }

    /// A remote controller (`service:holder`) attached with `control`; its
    /// attachment.
    fn controller(rig: &mut LocalRig) -> String {
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
        att
    }

    /// A submitted task whose receipt was rejected names the receipt's own
    /// reason: here its sender's control was revoked before the held prompt
    /// was dispatched.
    #[test]
    fn a_rejected_receipt_gives_the_task_its_reason() {
        local_test(async |root| {
            let mut rig = LocalRig::new(root).await;
            rig.bridge.host.hold_dispatch(true);
            let message = rig.message();
            rig.publish(&message);
            rig.until(|r| r.work(&message).status.state == WorkState::Submitted)
                .await;
            let effects = rig.bridge.host.fence_principal("local", 0);
            rig.bridge.exec(
                effects,
                &mut Cx {
                    client: &rig.app.astation_client,
                    sessions: &mut rig.sessions,
                },
            );
            rig.until(|r| r.work(&message).status.state == WorkState::Failed)
                .await;
            assert_eq!(rig.work(&message).status.detail, "control revoked");
            assert!(
                !rig.fake.join("input").is_file() || {
                    !std::fs::read_to_string(rig.fake.join("input"))
                        .unwrap()
                        .contains("COLLAB_TEST_PROMPT")
                }
            );
        });
    }

    /// Two local tasks of the rig's session: one awaiting its result under
    /// a return grant, one blocked behind a remote controller's lease.
    async fn awaiting_and_blocked(rig: &mut LocalRig) -> (Message, Message) {
        let done = rig.message();
        rig.publish(&done);
        grant(rig, &done);
        rig.until(|r| r.work(&done).turn_id.is_some()).await;
        std::fs::write(rig.fake.join("complete"), "").unwrap();
        rig.until(|r| r.work(&done).status.state == WorkState::AwaitingResult)
            .await;
        let att = controller(rig);
        let queued = rig.message();
        let target = queued.task(&queued.recipients[0]).unwrap().target;
        let (binding, _) = rig.bridge.host.binding_for_work(&att, &target).unwrap();
        let acquire = json!({"type":"session","data":{"v":1,"op":"acquire","id":uuid::Uuid::new_v4().to_string(),"binding":binding,"takeover":false}});
        let effects =
            rig.bridge
                .host
                .receive(&att, acquire.to_string().as_bytes(), rig.bridge.clock.now());
        rig.bridge.exec(
            effects,
            &mut Cx {
                client: &rig.app.astation_client,
                sessions: &mut rig.sessions,
            },
        );
        rig.publish(&queued);
        rig.until(|r| r.work(&queued).status.state == WorkState::Blocked)
            .await;
        (done, queued)
    }

    /// A device-list write fault (§R9.3) holds the list, fences every
    /// remote principal and `local` in memory, and halts the session
    /// journal: `local`'s tasks that are not in a turn fail ("sender's
    /// authority changed"), never "sender gone", the one awaiting its result
    /// with its return grant ended.
    #[test]
    fn a_device_list_fault_fails_local_tasks() {
        use crate::session_protocol::membership::r9log::{TestLog, secret};
        use crate::session_protocol::membership::{HostFences, HostPin, MembershipHost};
        local_test(async |root| {
            let mut rig = LocalRig::new(root).await;
            let (done, queued) = awaiting_and_blocked(&mut rig).await;
            // The list as a write fault leaves it: its fault record, so it
            // opens held.
            let pairing = crate::paths::ProfilePaths::in_dir(root).pairing;
            let journal = root.join("runtime/journal");
            let mut log = TestLog::genesis("acct", &secret("rig astation"));
            log.add_host("host", 1, &secret("rig host"));
            let pin = HostPin {
                host_id: "host".into(),
                host_trust_gen: 1,
            };
            MembershipHost::pin(&pairing, &journal, &pin, &log.log, &secret("rig host")).unwrap();
            std::fs::write(
                root.join("pairing/membership.fault"),
                br#"{"v":1,"runtime_epoch":1,"file":"membership.json","at":1}"#,
            )
            .unwrap();
            let mut fences = HostFences::new(&mut rig.bridge.host);
            let (m, _) = MembershipHost::open(&pairing, &journal, 1, &host_now(), &mut fences)
                .unwrap()
                .unwrap();
            let mut effects = fences.effects;
            assert!(m.held().is_some() || m.faulted().is_some());
            rig.bridge.membership = Some(m);
            effects.extend(rig.bridge.host.membership_fault(None));
            rig.bridge.exec(
                effects,
                &mut Cx {
                    client: &rig.app.astation_client,
                    sessions: &mut rig.sessions,
                },
            );
            for message in [&done, &queued] {
                rig.until(|r| r.work(message).status.state == WorkState::Failed)
                    .await;
                assert_eq!(
                    rig.work(message).status.detail,
                    "sender's authority changed"
                );
            }
            let grant: String = rig
                .bridge
                .work
                .store
                .as_ref()
                .unwrap()
                .db
                .query_row(
                    "SELECT state FROM return_grants WHERE task_id=?1",
                    [&done.recipients[0].recipient_id],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(grant, "ended");
        });
    }

    /// A session journal halted by a failed write, the device list usable,
    /// is a pause, not a change of `local`'s authority: `local` is fenced in
    /// memory only, its tasks wait (none is failed) and its durable control
    /// generation, the one they were accepted under, is what the restart
    /// brings back.
    #[test]
    fn a_halted_session_journal_pauses_local_tasks() {
        local_test(async |root| {
            let mut rig = LocalRig::new(root).await;
            let (done, queued) = awaiting_and_blocked(&mut rig).await;
            let accepted = rig.work(&queued).control_gen;
            rig.bridge.host.journal_mut().fail_append_of(1, false);
            let effects = rig.bridge.host.fence_principal("service:other", 0);
            rig.bridge.exec(
                effects,
                &mut Cx {
                    client: &rig.app.astation_client,
                    sessions: &mut rig.sessions,
                },
            );
            assert!(rig.bridge.host.journal_halted());
            idle(&mut rig, 500).await;
            assert_ne!(
                rig.bridge.host.control_gen("local"),
                accepted,
                "fenced in memory"
            );
            assert_eq!(rig.work(&done).status.state, WorkState::AwaitingResult);
            assert!(!rig.work(&queued).status.state.terminal());
            // The durable control state, read as the restart reads it.
            let text = std::fs::read_to_string(root.join("runtime/journal/principals")).unwrap();
            let file: Value =
                serde_json::from_str(text.splitn(3, ' ').nth(2).unwrap().trim_end()).unwrap();
            assert_eq!(
                file["principals"]["local"]["control_gen"].as_u64(),
                Some(accepted)
            );
        });
    }

    /// Forgetting a principal's control state is no revocation, and can't
    /// hide one: the host keeps the control state of every principal a task
    /// names (browser principals are forgotten otherwise once nothing of
    /// theirs is live).
    #[test]
    fn principals_named_by_tasks_keep_their_control_state() {
        local_test(async |root| {
            let mut rig = LocalRig::new(root).await;
            rig.bridge.work.config.routes[0].principals =
                vec!["local".into(), "browser:a".into(), "browser:b".into()];
            let now = host_now().wall_ms;
            // `b` was fenced once before its task was accepted.
            let effects = rig.bridge.host.fence_principal("browser:b", 0);
            rig.bridge.exec(
                effects,
                &mut Cx {
                    client: &rig.app.astation_client,
                    sessions: &mut rig.sessions,
                },
            );
            let a = insert_task(&rig, "browser:a", 1, WorkState::Blocked, now + 60_000);
            let b = insert_task(&rig, "browser:b", 2, WorkState::Blocked, now + 60_000);
            idle(&mut rig, 300).await;
            // `a` is fenced; then another principal's control write, which
            // forgets browser principals nothing names.
            let effects = rig.bridge.host.fence_principal("browser:a", 0);
            rig.bridge.exec(
                effects,
                &mut Cx {
                    client: &rig.app.astation_client,
                    sessions: &mut rig.sessions,
                },
            );
            controller(&mut rig);
            assert_eq!(rig.bridge.host.control_gen("browser:a"), 2);
            assert_eq!(rig.bridge.host.control_gen("browser:b"), 2);
            rig.until(|r| stored(r, &a).state == WorkState::Failed)
                .await;
            assert_eq!(stored(&rig, &a).detail, "sender's authority changed");
            idle(&mut rig, 300).await;
            assert_eq!(stored(&rig, &b).state, WorkState::Blocked);
        });
    }

    /// A submitted task whose receipt the session host no longer has is of
    /// unknown outcome, and then expires at its deadline, freeing its
    /// session for the next task.
    #[test]
    fn a_submitted_task_whose_receipt_is_gone_ends() {
        local_test(async |root| {
            let mut rig = LocalRig::new(root).await;
            let control = rig.bridge.host.control_gen("local");
            let lost = insert_task(
                &rig,
                "local",
                control,
                WorkState::Submitted,
                host_now().wall_ms + 1_500,
            );
            rig.until(|r| stored(r, &lost).state == WorkState::OutcomeUnknown)
                .await;
            assert_eq!(stored(&rig, &lost).detail, "receipt no longer available");
            let next = rig.message();
            rig.publish(&next);
            rig.until(|r| {
                r.work(&next).status.detail == "waiting for an earlier task on this session"
            })
            .await;
            rig.until(|r| stored(r, &lost).state == WorkState::Expired)
                .await;
            assert_eq!(
                stored(&rig, &lost).detail,
                crate::runtime::host_work::EXPIRED_UNKNOWN
            );
            rig.until(|r| {
                std::fs::read_to_string(r.fake.join("input"))
                    .unwrap_or_default()
                    .contains("COLLAB_TEST_PROMPT")
            })
            .await;
        });
    }

    /// A send accepted while its context was still publishing goes on when
    /// its session ends meanwhile: its tasks are made and run, with their
    /// return grants ended from the start, and the task then awaits its
    /// result (the reply kept, never delivered).
    #[test]
    fn a_context_send_whose_session_ended_still_makes_its_tasks() {
        use crate::runtime::collab::Publication;
        use crate::runtime::collab_context::{ContextSpec, VaultRef};
        local_test(async |root| {
            let mut rig = LocalRig::new(root).await;
            encryption_on(root);
            let mut message = rig.message();
            message.recipients[0].destination = Destination::Select {
                selectors: vec!["atem:atem-host/r".into()],
                budget: 32,
            };
            // The sending session is no longer there.
            let mut origin = origin_of(&rig);
            origin.target.session_id = message.from_session.clone().unwrap();
            origin.target.process_gen = uuid::Uuid::new_v4().to_string();
            crate::runtime::collab::reserve_context(
                rig.bridge.work.store.as_ref().unwrap(),
                &rig.bridge.work.config.collab,
                &message,
                &Publication {
                    atem_id: "atem-host".into(),
                    origin,
                    launch: false,
                    context: vec![ContextSpec::Vault {
                        reference: VaultRef::parse("v-context:1@1").unwrap(),
                    }],
                },
            )
            .unwrap();
            rig.until(|r| {
                outbox_detail(r, &message) == "relay unreachable; publication will retry"
            })
            .await;
            let (tx, rx) = tokio::sync::oneshot::channel();
            tx.send(Ok(vec![snapshot("the published context")]))
                .unwrap();
            rig.bridge
                .work
                .context_jobs
                .insert(message.message_id.clone(), rx);
            rig.until(|r| outbox_detail(r, &message) == "delivered to local queue")
                .await;
            let task = rig
                .bridge
                .work
                .store
                .as_ref()
                .unwrap()
                .open_tasks()
                .unwrap()
                .remove(0);
            let id = task.task.task_id.clone();
            let grant: String = rig
                .bridge
                .work
                .store
                .as_ref()
                .unwrap()
                .db
                .query_row(
                    "SELECT state FROM return_grants WHERE task_id=?1",
                    [&id],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(grant, "ended", "ended from the start");
            rig.until(|r| {
                std::fs::read_to_string(r.fake.join("input"))
                    .unwrap_or_default()
                    .contains("the published context")
            })
            .await;
            std::fs::write(rig.fake.join("complete"), "").unwrap();
            rig.until(|r| stored(r, &id).state == WorkState::AwaitingResult)
                .await;
            rig.until(|r| stored(r, &id).detail == collab_bridge::SENDER_GONE)
                .await;
        });
    }

    /// A send whose context was still publishing when `local` lost the
    /// authority it was accepted under makes no task: its publication is
    /// refused ("sender's authority changed").
    #[test]
    fn a_context_send_under_a_changed_authority_is_refused() {
        use crate::runtime::collab::Publication;
        use crate::runtime::collab_context::{ContextSpec, VaultRef};
        local_test(async |root| {
            let mut rig = LocalRig::new(root).await;
            let mut message = rig.message();
            message.recipients[0].destination = Destination::Select {
                selectors: vec!["atem:atem-host/r".into()],
                budget: 32,
            };
            let mut origin = origin_of(&rig);
            origin.control_gen -= 1;
            crate::runtime::collab::reserve_context(
                rig.bridge.work.store.as_ref().unwrap(),
                &rig.bridge.work.config.collab,
                &message,
                &Publication {
                    atem_id: "atem-host".into(),
                    origin,
                    launch: false,
                    context: vec![ContextSpec::Vault {
                        reference: VaultRef::parse("v-context:1@1").unwrap(),
                    }],
                },
            )
            .unwrap();
            rig.until(|r| outbox_detail(r, &message) == "sender's authority changed")
                .await;
            assert_eq!(rows(&rig, "work"), 0);
        });
    }

    /// `[collab] send = false` refuses new sends only: a send accepted while
    /// its context was publishing still completes.
    #[test]
    fn a_context_send_completes_after_sending_is_switched_off() {
        use crate::runtime::collab::Publication;
        use crate::runtime::collab_context::{ContextSpec, VaultRef};
        local_test(async |root| {
            let mut rig = LocalRig::new(root).await;
            encryption_on(root);
            let mut message = rig.message();
            message.recipients[0].destination = Destination::Select {
                selectors: vec!["atem:atem-host/r".into()],
                budget: 32,
            };
            crate::runtime::collab::reserve_context(
                rig.bridge.work.store.as_ref().unwrap(),
                &rig.bridge.work.config.collab,
                &message,
                &Publication {
                    atem_id: "atem-host".into(),
                    origin: origin_of(&rig),
                    launch: false,
                    context: vec![ContextSpec::Vault {
                        reference: VaultRef::parse("v-context:1@1").unwrap(),
                    }],
                },
            )
            .unwrap();
            rig.until(|r| {
                outbox_detail(r, &message) == "relay unreachable; publication will retry"
            })
            .await;
            rig.bridge.work.config.collab.send = false;
            let (tx, rx) = tokio::sync::oneshot::channel();
            tx.send(Ok(vec![snapshot("published after send = false")]))
                .unwrap();
            rig.bridge
                .work
                .context_jobs
                .insert(message.message_id.clone(), rx);
            rig.until(|r| outbox_detail(r, &message) == "delivered to local queue")
                .await;
            assert_eq!(rows(&rig, "work"), 1);
        });
    }

    /// The work pass drops, about once a minute, the payloads of what
    /// settled a day past its deadline and keeps the record; a task still
    /// in its turn keeps its payload whatever its deadline.
    #[test]
    fn the_work_pass_drops_the_payloads_of_settled_records_past_the_retention() {
        local_test(async |root| {
            let mut rig = LocalRig::new(root).await;
            let old = host_now().wall_ms - crate::runtime::host_work::PAYLOAD_RETENTION_MS - 1;
            // A task in its turn, its deadline (as stored) a day past.
            let running = rig.message();
            rig.publish(&running);
            rig.until(|r| r.work(&running).turn_id.is_some()).await;
            let store = rig.bridge.work.store.as_ref().unwrap();
            store
                .db
                .execute(
                    "UPDATE work SET record=json_set(record,'$.task.expires_at',?2) WHERE id=?1",
                    rusqlite::params![running.recipients[0].recipient_id, old],
                )
                .unwrap();
            // A completed one, as old.
            let message = rig.message();
            let mut task = message.task(&message.recipients[0]).unwrap();
            task.expires_at = old;
            let record = WorkRecord {
                principal: "member:owner".into(),
                attachment_owner: String::new(),
                control_gen: 0,
                route_id: "r".into(),
                route_revision: 1,
                profile_id: "p".into(),
                profile_revision: 1,
                project: "local:project".into(),
                digest: hw::digest(b"task"),
                status: WorkStatus {
                    task_id: task.task_id.clone(),
                    receipt_id: uuid::Uuid::new_v4().to_string(),
                    state: WorkState::Completed,
                    detail: String::new(),
                    result: None,
                },
                task,
                turn_id: None,
                authorization_expires_at: None,
            };
            store
                .db
                .execute(
                    "INSERT INTO work(id,record,state) VALUES(?1,?2,'completed')",
                    rusqlite::params![record.task.task_id, serde_json::to_string(&record).unwrap()],
                )
                .unwrap();
            let ids = [
                record.task.task_id,
                running.recipients[0].recipient_id.clone(),
            ];
            let prompt = |rig: &LocalRig, id: &str| {
                rig.bridge
                    .work
                    .store
                    .as_ref()
                    .unwrap()
                    .work(id)
                    .unwrap()
                    .unwrap()
                    .task
                    .prompt
            };
            idle(&mut rig, 300).await;
            assert!(
                !prompt(&rig, &ids[0]).is_empty(),
                "not before the next pass"
            );
            rig.bridge.work.cleanup = Instant::now();
            idle(&mut rig, 300).await;
            assert_eq!(prompt(&rig, &ids[0]), "", "settled and past the retention");
            assert!(!prompt(&rig, &ids[1]).is_empty(), "still in its turn");
        });
    }

    /// A retry of a request whose payload was dropped is answered from its
    /// record by its digest, as before the drop: the same `work_enqueue` or
    /// `message_publish` gets the receipt recorded, another content
    /// `request_id_reused`.
    #[test]
    fn a_retry_after_its_payload_was_dropped_is_deduplicated_by_its_digest() {
        local_test(async |root| {
            let mut rig = LocalRig::new(root).await;
            let local = rig.bridge.local_attachment().to_string();
            let host = rig.bridge.work_host();
            let message = rig.message();
            rig.publish(&message);
            let mut task = message.task(&message.recipients[0]).unwrap();
            task.task_id = uuid::Uuid::new_v4().to_string();
            let enqueue = |task: &hw::WorkTask| hw::Request::Enqueue {
                v: 1,
                id: uuid::Uuid::new_v4().to_string(),
                host: host.clone(),
                route_id: "r".into(),
                route_revision: 1,
                task: task.clone(),
            };
            let request = |rig: &mut LocalRig, req: &hw::Request| {
                rig.bridge.work_request(
                    &local,
                    req,
                    &mut Cx {
                        client: &rig.app.astation_client,
                        sessions: &mut rig.sessions,
                    },
                )
            };
            assert!(request(&mut rig, &enqueue(&task)).is_ok());
            // Both settle before they are dispatched.
            for task_id in [&task.task_id, &message.recipients[0].recipient_id] {
                let cancel = hw::Request::Cancel {
                    v: 1,
                    id: uuid::Uuid::new_v4().to_string(),
                    host: host.clone(),
                    task_id: task_id.clone(),
                };
                assert!(request(&mut rig, &cancel).is_ok());
            }
            let recorded = request(&mut rig, &enqueue(&task)).unwrap();
            let published = rig.publish(&message);
            let dropped = rig
                .bridge
                .work
                .store
                .as_ref()
                .unwrap()
                .drop_payloads(message.expires_at + crate::runtime::host_work::PAYLOAD_RETENTION_MS)
                .unwrap();
            assert_eq!((dropped.tasks, dropped.messages), (2, 1));
            assert_eq!(rig.work(&message).task.prompt, "");
            assert_eq!(request(&mut rig, &enqueue(&task)), Ok(recorded));
            assert_eq!(rig.publish(&message), published);
            let mut other = task.clone();
            other.prompt.push('!');
            assert_eq!(
                request(&mut rig, &enqueue(&other)),
                Err("request_id_reused")
            );
            let mut other = message.clone();
            other.text.push('!');
            assert_eq!(
                rig.bridge.local_publish(
                    &other,
                    &mut Cx {
                        client: &rig.app.astation_client,
                        sessions: &mut rig.sessions,
                    },
                ),
                Err("request_id_reused")
            );
        });
    }

    /// A submitted reply that can't be carried to its sender (here its text
    /// was damaged after it was checked) uses up its one delivery with a
    /// trace in status, never silently.
    #[test]
    fn an_undeliverable_result_leaves_a_trace() {
        use crate::runtime::collab::results::{self, Origin, OriginRoute, ReturnGrant};
        local_test(async |root| {
            let mut rig = LocalRig::new(root).await;
            // The rig's session sends to itself, through a route that takes
            // results.
            rig.bridge.work.config.routes[0].results = true;
            let message = rig.message();
            rig.publish(&message);
            let task = rig.work(&message);
            {
                let store = rig.bridge.work.store.as_ref().unwrap();
                let tx = store.db.unchecked_transaction().unwrap();
                results::save_grant(
                    &tx,
                    &ReturnGrant {
                        task_id: task.task.task_id.clone(),
                        message_id: message.message_id.clone(),
                        workflow_id: message.workflow_id.clone(),
                        origin: Origin {
                            target: task.task.target.clone(),
                            control_gen: rig.bridge.host.control_gen("local"),
                            route: Some(OriginRoute {
                                id: "r".into(),
                                revision: 1,
                                profile_id: "p".into(),
                                profile_revision: 1,
                                project: "local:project".into(),
                                results: true,
                            }),
                        },
                        recipient: task.task.target.clone(),
                        expires_at: message.expires_at,
                        ended: None,
                    },
                )
                .unwrap();
                tx.commit().unwrap();
            }
            let id = task.task.task_id.clone();
            rig.until(|r| r.work(&message).turn_id.is_some()).await;
            assert!(reply(&mut rig, &id, "a fine reply", &[]).is_ok());
            rig.bridge
                .work
                .store
                .as_ref()
                .unwrap()
                .db
                .execute(
                    "UPDATE results SET record=json_set(record,'$.text',?2) WHERE task_id=?1",
                    rusqlite::params![id, "bell \u{7}"],
                )
                .unwrap();
            let grant_state = |rig: &LocalRig| -> String {
                rig.bridge
                    .work
                    .store
                    .as_ref()
                    .unwrap()
                    .db
                    .query_row(
                        "SELECT state FROM return_grants WHERE task_id=?1",
                        [&id],
                        |r| r.get(0),
                    )
                    .unwrap()
            };
            rig.until(|r| grant_state(r) != "open").await;
            let trace = "result could not be delivered: context has control characters";
            rig.until(|r| r.work(&message).status.detail == trace).await;
            let row = results::load(&rig.bridge.work.store.as_ref().unwrap().db, &id)
                .unwrap()
                .unwrap();
            assert_eq!(row.detail, trace);
            assert!(row.work_id.is_none(), "nothing was queued");
            assert_eq!(grant_state(&rig), "consumed");
        });
    }

    /// Malformed references and text out of bounds are refused before a
    /// result row exists (spec section 10; a reply's vault reference names
    /// its entry).
    #[test]
    fn a_malformed_reply_is_refused_before_a_row_exists() {
        local_test(async |root| {
            let mut rig = LocalRig::new(root).await;
            let message = rig.message();
            rig.publish(&message);
            let task = rig.work(&message).task.task_id;
            rig.until(|r| r.work(&message).turn_id.is_some()).await;
            let stored = |rig: &LocalRig| {
                crate::runtime::collab::results::load(
                    &rig.bridge.work.store.as_ref().unwrap().db,
                    &task,
                )
                .unwrap()
                .is_some()
            };
            let long = "x".repeat(16 * 1024 + 1);
            for (text, vault, error) in [
                (
                    "a bare reference",
                    &["v-context@1"][..],
                    "ambiguous vault reference v-context@1: a reply names the entry, ID:ENTRY@VERSION",
                ),
                (long.as_str(), &[][..], "a reply's text is at most 16 KiB"),
                ("a bell \u{7}", &[][..], "the reply has control characters"),
                (
                    "clear \u{1b}[2J",
                    &[][..],
                    "the reply has control characters",
                ),
                ("over\rwritten", &[][..], "the reply has control characters"),
            ] {
                assert_eq!(
                    reply(&mut rig, &task, text, vault),
                    Err(error.to_string()),
                    "{text:.20}"
                );
                assert!(!stored(&rig), "{text:.20}");
            }
            // At the bound, with newlines and tabs: stored.
            let text = format!("{}\n\t", "x".repeat(16 * 1024 - 2));
            assert!(reply(&mut rig, &task, &text, &[]).is_ok());
            assert!(stored(&rig));
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
                    .collab_accept("atem-host", &message, &origin, false, &rig.sessions)
                    .unwrap_err();
                assert_eq!(error.to_string(), problem);
                assert_eq!(rows(&rig, "counters"), 0, "{problem}");
                assert_eq!(rows(&rig, "outbox"), 0, "{problem}");
            }
            // The same message without the problem is accepted, and counts once.
            message.context = vec![snapshot("fits")];
            rig.bridge
                .collab_accept("atem-host", &message, &origin, false, &rig.sessions)
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

    /// A host whose session host still serves r8 (no pinned device list)
    /// runs no collaboration: `local` loses its authority, so a queued local
    /// task fails and is never dispatched, and a new send is refused with the
    /// fix.
    #[test]
    fn collaboration_needs_a_pinned_device_list() {
        local_test(async |root| {
            let mut rig = LocalRig::new(root).await;
            let first = rig.message();
            rig.publish(&first);
            rig.until(|r| r.work(&first).status.state == WorkState::Submitted)
                .await;
            let mut second = rig.message();
            second.text = "QUEUED_BEHIND_THE_FIRST".into();
            rig.publish(&second);
            rig.bridge.host.set_refuse_r8(false);
            rig.until(|r| r.work(&second).status.state == WorkState::Failed)
                .await;
            assert_eq!(
                rig.work(&second).status.detail,
                "sender's authority changed"
            );
            std::fs::write(rig.fake.join("complete"), "").unwrap();
            let error = rig
                .bridge
                .collab_send(
                    "atem-host",
                    &rig.sid,
                    send_request(&["tag:ok"]),
                    &rig.sessions,
                )
                .unwrap_err();
            assert_eq!(
                error.to_string(),
                "collaboration unavailable: collaboration needs a pinned device list: \
                 run `atem pair verify`"
            );
            assert!(
                !std::fs::read_to_string(rig.fake.join("input"))
                    .unwrap_or_default()
                    .contains("QUEUED_BEHIND_THE_FIRST")
            );
        });
    }

    /// `runtime.toml` text of a launch route `q` (Claude, `tag:q`,
    /// `launch = "on_message"`) whose directory runs no session.
    fn launch_toml(cwd: &Path, route_revision: u64) -> String {
        format!(
            r#"
version = 1
enabled = true
[[profiles]]
id = "q"
revision = 1
label = "q"
provider = "claude"
cwd = {cwd:?}
project = "local:launch-project"
principals = ["member:owner"]
[[routes]]
id = "q"
revision = {route_revision}
profile_id = "q"
labels = ["tag:q"]
principals = ["local"]
launch = "on_message"
"#
        )
    }

    /// The rig's configuration plus the launch route `q`.
    fn launch_route(rig: &mut LocalRig, root: &Path) -> PathBuf {
        let cwd = root.join("launch-project");
        std::fs::create_dir_all(&cwd).unwrap();
        let extra: Config = toml::from_str(&launch_toml(&cwd, 1)).unwrap();
        let mut config = rig.bridge.work.config.clone();
        config.profiles.extend(extra.profiles);
        config.routes.extend(extra.routes);
        config.validate().unwrap();
        rig.bridge.work.config = config;
        cwd
    }

    /// A message of the rig's own session to the agents `selector` names.
    fn select_message(rig: &LocalRig, selector: &str) -> Message {
        let mut message = rig.message();
        message.from_session = Some(rig.sid.to_string());
        message.recipients[0].destination = Destination::Select {
            selectors: vec![selector.into()],
            budget: 32,
        };
        message
    }

    fn origin_of(rig: &LocalRig) -> crate::runtime::collab::results::Origin {
        let host = rig.bridge.work_host();
        crate::runtime::collab::results::Origin {
            target: wire::Target {
                account_id: host.account_id,
                atem_device_id: host.atem_device_id,
                host_trust_gen: host.host_trust_gen,
                session_id: rig.sid.to_string(),
                process_gen: rig.sessions[&rig.sid].process_gen.clone(),
            },
            control_gen: rig.bridge.host.control_gen("local"),
            route: None,
        }
    }

    fn accept(rig: &mut LocalRig, message: &Message, launch: bool) {
        let origin = origin_of(rig);
        rig.bridge
            .collab_accept("atem-host", message, &origin, launch, &rig.sessions)
            .unwrap();
    }

    /// Accepts a message to the launch route `q` by its instance address
    /// (`--launch` needs one), with or without `--launch`.
    fn send_q(rig: &mut LocalRig, launch: bool) -> Message {
        let message = select_message(rig, "atem:atem-host/q");
        accept(rig, &message, launch);
        message
    }

    fn outbox_detail(rig: &LocalRig, message: &Message) -> String {
        rig.bridge
            .work
            .store
            .as_ref()
            .unwrap()
            .db
            .query_row(
                "SELECT detail FROM outbox WHERE message_id=?1",
                [&message.message_id],
                |r| r.get(0),
            )
            .unwrap()
    }

    fn launch_records(rig: &LocalRig) -> Vec<LaunchRecord> {
        rig.bridge
            .work
            .store
            .as_ref()
            .unwrap()
            .open_launches()
            .unwrap()
    }

    fn task_targets(rig: &LocalRig) -> Vec<(String, Option<String>)> {
        let store = rig.bridge.work.store.as_ref().unwrap();
        store
            .open_tasks()
            .unwrap()
            .into_iter()
            .map(|t| {
                let launch: Option<String> = store
                    .db
                    .query_row(
                        "SELECT launch_request_id FROM resolutions WHERE task_id=?1",
                        [&t.task.task_id],
                        |r| r.get(0),
                    )
                    .unwrap();
                (t.task.target.session_id, launch)
            })
            .collect()
    }

    /// The worker the launcher would start for the launch `record` reserved.
    async fn start_reserved(rig: &mut LocalRig, root: &Path, record: &LaunchRecord, cwd: &Path) {
        let launcher = Launcher::InProcess(InProcess {
            state: root.join("runtime"),
            socket_dir: root.join("ws"),
            chat_root: root.join("chat"),
        });
        let request = SpawnRequest {
            session_id: SessionId::parse(&record.status.session_id).unwrap(),
            process_gen: record.status.process_gen.clone(),
            provider: crate::session::Provider::Claude,
            args: vec![],
            cwd: cwd.into(),
            rows: 24,
            cols: 80,
        };
        let fake = root.join("fake-q");
        std::fs::create_dir_all(&fake).unwrap();
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
        rig.sessions.insert(
            request.session_id.clone(),
            BrokerSession::launched(handle, &request, created),
        );
    }

    /// Spec section 5: only a send that asks (`--launch`) starts a session,
    /// and only on a route whose owner allows it; without it the route has
    /// no match.
    #[test]
    fn a_route_launches_only_for_a_message_that_asks() {
        local_test(async |root| {
            let mut rig = LocalRig::new(root).await;
            launch_route(&mut rig, root);
            let quiet = select_message(&rig, "atem:atem-host/q");
            accept(&mut rig, &quiet, false);
            assert_eq!(rows(&rig, "launches"), 0);
            assert_eq!(rows(&rig, "resolutions"), 0);
            assert_eq!(rows(&rig, "work"), 0);
            assert!(rig.bridge.work.launches.is_empty());
            assert!(rig.bridge.work.pending.is_empty());
            assert_eq!(outbox_detail(&rig, &quiet), "no_match");

            let asked = select_message(&rig, "atem:atem-host/q");
            accept(&mut rig, &asked, true);
            assert_eq!(rows(&rig, "launches"), 1);
            assert_eq!(rows(&rig, "work"), 1);
            assert_eq!(rig.bridge.work.launches.len(), 1);
            assert_eq!(rig.bridge.work.pending.len(), 1);
            assert_eq!(outbox_detail(&rig, &asked), "delivered to local queue");
        });
    }

    /// Spec section 5: `--launch` starts only a route that an
    /// `atem:<atem_id>/<route_id>` selector of the same send names; a route
    /// that another selector (a label, the bare instance) matches gets none.
    #[test]
    fn launch_starts_only_a_route_its_send_names() {
        local_test(async |root| {
            let mut rig = LocalRig::new(root).await;
            launch_route(&mut rig, root);
            let mut message = select_message(&rig, "tag:q");
            message.recipients[0].destination = Destination::Select {
                selectors: vec![
                    "atem:atem-host/r".into(),
                    "tag:q".into(),
                    "atem:atem-host".into(),
                ],
                budget: 32,
            };
            accept(&mut rig, &message, true);
            assert_eq!(rows(&rig, "launches"), 0);
            assert_eq!(outbox_detail(&rig, &message), "no_match");
            let named = select_message(&rig, "atem:atem-host/q");
            accept(&mut rig, &named, true);
            assert_eq!(rows(&rig, "launches"), 1);
            assert_eq!(outbox_detail(&rig, &named), "delivered to local queue");
        });
    }

    /// A send with context is accepted once its context is published, after
    /// any retries: with `--launch` that is when its route launches, and
    /// without it no session is started (spec sections 5 and 8). The first
    /// attempt finds no relay (no pairing here); the retry gets the
    /// publication's result as the publisher's job would hand it over.
    #[test]
    fn a_context_send_launches_once_published_and_only_with_the_flag() {
        use crate::runtime::collab::Publication;
        use crate::runtime::collab_context::{ContextSpec, VaultRef};
        local_test(async |root| {
            let mut rig = LocalRig::new(root).await;
            encryption_on(root);
            launch_route(&mut rig, root);
            for launch in [false, true] {
                let message = select_message(&rig, "atem:atem-host/q");
                crate::runtime::collab::reserve_context(
                    rig.bridge.work.store.as_ref().unwrap(),
                    &rig.bridge.work.config.collab,
                    &message,
                    &Publication {
                        atem_id: "atem-host".into(),
                        origin: origin_of(&rig),
                        launch,
                        context: vec![ContextSpec::Vault {
                            reference: VaultRef::parse("v-context:1@1").unwrap(),
                        }],
                    },
                )
                .unwrap();
                rig.until(|r| {
                    outbox_detail(r, &message) == "relay unreachable; publication will retry"
                })
                .await;
                assert_eq!(
                    rows(&rig, "launches"),
                    0,
                    "{launch}: not before publication"
                );
                let (tx, rx) = tokio::sync::oneshot::channel();
                tx.send(Ok(vec![snapshot("the published context")]))
                    .unwrap();
                rig.bridge
                    .work
                    .context_jobs
                    .insert(message.message_id.clone(), rx);
                rig.until(|r| {
                    outbox_detail(r, &message) != "relay unreachable; publication will retry"
                })
                .await;
                assert_eq!(
                    (
                        outbox_detail(&rig, &message).as_str(),
                        rows(&rig, "launches")
                    ),
                    if launch {
                        ("delivered to local queue", 1)
                    } else {
                        ("no_match", 0)
                    },
                    "{launch}"
                );
            }
        });
    }

    /// Spec section 5: messages share a pending launch, including one that
    /// just started and whose project isn't known yet (no second session in
    /// that window), and a later one reaches the session by its project.
    #[test]
    fn a_pending_launch_is_shared_until_its_project_is_known() {
        local_test(async |root| {
            let mut rig = LocalRig::new(root).await;
            let cwd = launch_route(&mut rig, root);
            let first = select_message(&rig, "atem:atem-host/q");
            accept(&mut rig, &first, true);
            let record = launch_records(&rig).remove(0);
            let (session, request) = (
                record.status.session_id.clone(),
                record.status.request_id.clone(),
            );
            // Still starting: shared.
            send_q(&mut rig, true);
            assert_eq!(rows(&rig, "launches"), 1);
            // The launcher has started the worker; no pass has read its
            // launch project yet.
            start_reserved(&mut rig, root, &record, &cwd).await;
            rig.bridge.remote_launched(&request, LaunchState::Started);
            assert!(rig.bridge.work.pending.is_empty());
            assert!(rig.bridge.projects.key_of(&session).is_none());
            send_q(&mut rig, true);
            assert_eq!(rows(&rig, "launches"), 1, "no second launch in the window");
            // Even a message that didn't ask reaches it: the agent is there.
            send_q(&mut rig, false);
            // The project becomes known: the session is found as any other.
            rig.until(|r| r.bridge.projects.key_of(&session) == Some("local:launch-project"))
                .await;
            send_q(&mut rig, true);
            assert_eq!(rows(&rig, "launches"), 1);
            let targets = task_targets(&rig);
            assert_eq!(targets.len(), 5);
            assert!(targets.iter().all(|(s, _)| *s == session), "{targets:?}");
            assert_eq!(
                targets.iter().filter(|(_, l)| l.is_some()).count(),
                4,
                "{targets:?}"
            );
        });
    }

    /// Spec section 9, "Pauses, not fences": a local launch that has not
    /// started when `runtime.toml` stops loading waits for it to load again,
    /// then starts. Its task is not failed meanwhile. Hosting switched off
    /// is a deliberate stop instead: it fences a launch not started (below).
    #[test]
    fn a_launch_that_has_not_started_waits_out_an_invalid_file() {
        local_test(async |root| {
            let mut rig = LocalRig::new(root).await;
            launch_route(&mut rig, root);
            let message = select_message(&rig, "atem:atem-host/q");
            accept(&mut rig, &message, true);
            let request = launch_records(&rig)[0].status.request_id.clone();
            let good = rig.bridge.work.config.clone();
            {
                rig.bridge.work.config = Config::default();
                rig.bridge.work.config_problem = Some("expected a table".into());
                idle(&mut rig, 350).await;
                assert!(rig.bridge.take_remote_launches().is_empty(), "held");
                assert!(
                    rig.bridge.work.pending[&request]
                        .permit
                        .load(Ordering::SeqCst),
                    "not fenced"
                );
                assert_eq!(launch_records(&rig)[0].status.state, LaunchState::Starting);
                let task = rig
                    .bridge
                    .work
                    .store
                    .as_ref()
                    .unwrap()
                    .open_tasks()
                    .unwrap()
                    .remove(0);
                assert!(!task.status.state.terminal(), "{:?}", task.status);
                rig.bridge.work.config = good.clone();
                rig.bridge.work.config_problem = None;
            }
            idle(&mut rig, 350).await;
            let launches = rig.bridge.take_remote_launches();
            assert_eq!(launches.len(), 1);
            assert_eq!(launches[0].request_id, request);
            assert!(
                rig.bridge.work.pending[&request]
                    .permit
                    .load(Ordering::SeqCst)
            );
            let task = rig
                .bridge
                .work
                .store
                .as_ref()
                .unwrap()
                .open_tasks()
                .unwrap()
                .remove(0);
            assert_eq!(task.status.state, WorkState::Blocked);
            assert_eq!(task.status.detail, "launching the approved route");
        });
    }

    /// Hosting switched off (`enabled = false` in a file that loads) is a
    /// deliberate stop: a local launch that has not started is fenced, as a
    /// remote one is (handed out to fail at its guard, never held), and
    /// switching hosting on again doesn't revive it. Its task waits, as
    /// queued tasks do, and then takes the launch's outcome.
    #[test]
    fn hosting_switched_off_fences_a_local_launch_not_started() {
        local_test(async |root| {
            let mut rig = LocalRig::new(root).await;
            launch_route(&mut rig, root);
            send_q(&mut rig, true);
            let request = launch_records(&rig)[0].status.request_id.clone();
            let good = rig.bridge.work.config.clone();
            rig.bridge.work.config.enabled = false;
            idle(&mut rig, 350).await;
            let launches = rig.bridge.take_remote_launches();
            assert_eq!(launches.len(), 1, "released to fail, never held");
            assert_eq!(launches[0].request_id, request);
            assert!(
                !rig.bridge.work.pending[&request]
                    .permit
                    .load(Ordering::SeqCst)
            );
            assert!(!(launches[0].guard)());
            let task = rig
                .bridge
                .work
                .store
                .as_ref()
                .unwrap()
                .open_tasks()
                .unwrap()
                .remove(0);
            assert!(!task.status.state.terminal(), "{:?}", task.status);
            rig.bridge.work.config = good;
            idle(&mut rig, 350).await;
            assert!(
                !rig.bridge.work.pending[&request]
                    .permit
                    .load(Ordering::SeqCst),
                "never revived"
            );
        });
    }

    /// A receipt database fault can't end without a restart, so a local
    /// launch that has not started is fenced at once, like a remote one: it
    /// is handed out to fail at its guard, never held.
    #[test]
    fn a_receipt_database_fault_fences_a_waiting_local_launch() {
        local_test(async |root| {
            let mut rig = LocalRig::new(root).await;
            launch_route(&mut rig, root);
            send_q(&mut rig, true);
            let request = launch_records(&rig)[0].status.request_id.clone();
            rig.bridge.work_fail();
            let launches = rig.bridge.take_remote_launches();
            assert_eq!(launches.len(), 1, "released to fail, never held");
            assert_eq!(launches[0].request_id, request);
            assert!(
                !rig.bridge.work.pending[&request]
                    .permit
                    .load(Ordering::SeqCst)
            );
            assert!(!(launches[0].guard)());
        });
    }

    /// A plain session-journal halt fences a local launch that has not
    /// started (only a restart ends the halt, and the restart drops the
    /// launch anyway): it is handed out to be refused at its guard, like
    /// every fenced launch.
    #[test]
    fn a_halted_journal_fences_a_local_launch_not_started() {
        local_test(async |root| {
            let mut rig = LocalRig::new(root).await;
            launch_route(&mut rig, root);
            send_q(&mut rig, true);
            let request = launch_records(&rig)[0].status.request_id.clone();
            rig.bridge.host.journal_mut().fail_append_of(1, false);
            let effects = rig.bridge.host.fence_principal("service:other", 0);
            rig.bridge.exec(
                effects,
                &mut Cx {
                    client: &rig.app.astation_client,
                    sessions: &mut rig.sessions,
                },
            );
            assert!(rig.bridge.host.journal_halted());
            idle(&mut rig, 350).await;
            let launches = rig.bridge.take_remote_launches();
            assert_eq!(launches.len(), 1, "released to fail, never held");
            assert_eq!(launches[0].request_id, request);
            assert!(
                !rig.bridge.work.pending[&request]
                    .permit
                    .load(Ordering::SeqCst)
            );
            assert!(!(launches[0].guard)());
        });
    }

    /// Every statement traced (`plans_scan_no_kept_table`).
    static TRACED: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

    fn traced(sql: &str) {
        TRACED.lock().unwrap().push(sql.to_string());
    }

    /// Every statement a start (recovery, the reconcile of unknown
    /// outcomes), the 100 ms passes, the payload pass, a send (one that
    /// launches, one while that session's project is unknown) and a reply
    /// (with `--task`, and an identical one without) run on the work store
    /// reads the tables that keep closed records only through an index
    /// that leaves them out: no plan scans one, and beside 3000 closed
    /// records no statement takes more VM steps than beside 1000.
    #[test]
    fn a_start_a_pass_a_send_and_a_reply_scan_no_kept_table() {
        local_test(async |root| {
            let mut rig = LocalRig::new(root).await;
            let cwd = launch_route(&mut rig, root);
            TRACED.lock().unwrap().clear();
            rig.bridge
                .work
                .store
                .as_mut()
                .unwrap()
                .db
                .trace(Some(traced));
            rig.bridge.work.recovered = false;
            rig.bridge.work.cleanup = Instant::now();
            idle(&mut rig, 300).await;
            let mut launching = send_request(&["atem:atem-host/q"]);
            launching.launch = true;
            rig.bridge
                .collab_send("atem-host", &rig.sid, launching, &rig.sessions)
                .unwrap();
            let record = launch_records(&rig).remove(0);
            start_reserved(&mut rig, root, &record, &cwd).await;
            rig.bridge
                .remote_launched(&record.status.request_id, LaunchState::Started);
            let sent = rig
                .bridge
                .collab_send(
                    "atem-host",
                    &rig.sid,
                    send_request(&["atem:atem-host/q"]),
                    &rig.sessions,
                )
                .unwrap();
            let message = rig.message();
            rig.publish(&message);
            rig.until(|r| r.work(&message).turn_id.is_some()).await;
            let task = message.recipients[0].recipient_id.clone();
            let first = reply(&mut rig, &task, "the answer", &[]).unwrap();
            let again = rig
                .bridge
                .collab_reply(
                    &rig.sid,
                    crate::runtime::collab::ReplyRequest {
                        task_id: None,
                        text: "the answer".into(),
                        memory: vec![],
                        vault: vec![],
                    },
                    &rig.sessions,
                )
                .unwrap();
            assert_eq!(again.result_id, first);
            // `atem message status`: inside the session and from outside
            // any, the latest and one message.
            let sid = rig.sid.clone();
            for (caller, id) in [
                (Some(&sid), None),
                (None, None),
                (Some(&sid), Some(sent.as_str())),
                (None, Some(sent.as_str())),
            ] {
                assert!(!rig.bridge.collab_status(caller, id).unwrap().is_empty());
            }
            idle(&mut rig, 300).await;
            rig.bridge.work.store.as_mut().unwrap().db.trace(None);
            let statements: std::collections::BTreeSet<String> = TRACED
                .lock()
                .unwrap()
                .iter()
                .filter(|sql| {
                    let head = sql.trim_start().to_ascii_uppercase();
                    ["SELECT", "INSERT", "UPDATE", "DELETE", "WITH"]
                        .iter()
                        .any(|verb| head.starts_with(verb))
                })
                .cloned()
                .collect();
            // What each of those runs is among them.
            for seen in [
                "WHERE state='submitting'",
                "WHERE state='outcome_unknown'",
                "CROSS JOIN launches l",
                "FROM return_grants g",
                "FROM grant_dues WHERE due_ms",
                "CROSS JOIN work w ON w.id=g.task_id WHERE g.task_id=",
                "FROM work_waits WHERE due_ms",
                "FROM work_waits WHERE session_id",
                "route_id,route_revision,profile_id,profile_revision,project FROM work_waits",
                "CROSS JOIN publications p",
                "FROM resolutions WHERE session_id",
                "FROM results WHERE digest",
                "ORDER BY created_ms DESC,rowid DESC LIMIT 32",
                "FROM outbox o\n    WHERE message_id=",
                "CROSS JOIN work w ON w.id=o.id WHERE o.kind='work' ORDER BY",
                "FROM open_records o CROSS JOIN work w ON w.id=o.id\n    WHERE o.kind='work' AND",
            ] {
                assert!(
                    statements.iter().any(|sql| sql.contains(seen)),
                    "never ran: {seen}"
                );
            }
            let db = &rig.bridge.work.store.as_ref().unwrap().db;
            let scans: Vec<(String, Vec<String>)> = statements
                .iter()
                .map(|sql| {
                    (
                        sql.clone(),
                        crate::runtime::host_work::kept_table_scans(db, sql),
                    )
                })
                .filter(|(_, (_, scans))| !scans.is_empty())
                .map(|(sql, (steps, _))| (sql, steps))
                .collect();
            assert!(scans.is_empty(), "{scans:#?}");
            // Nor does any step through an index over closed records: run
            // again (and rolled back) beside 1200, then 3600 of them (their
            // resolutions spread over the rig's session and two others),
            // each statement takes as many VM steps.
            let steps = |db: &rusqlite::Connection| -> Vec<i32> {
                statements
                    .iter()
                    .map(|sql| {
                        db.execute_batch("SAVEPOINT measure").unwrap();
                        let steps = db.prepare(sql).map_or(0, |mut q| {
                            let n = q.parameter_count();
                            if let Ok(mut rows) =
                                q.query(rusqlite::params_from_iter(std::iter::repeat_n("x", n)))
                            {
                                while let Ok(Some(_)) = rows.next() {}
                            }
                            q.get_status(rusqlite::StatementStatus::VmStep)
                        });
                        db.execute_batch("ROLLBACK TO measure; RELEASE measure")
                            .unwrap();
                        steps
                    })
                    .collect()
            };
            let sessions = ["ses-closedaaaaaa", sid.as_str(), "ses-closedbbbbbb"];
            add_closed_records(db, 0..1200, &sessions);
            let fewer = steps(db);
            add_closed_records(db, 1200..3600, &sessions);
            let more = steps(db);
            let grown: Vec<_> = statements
                .iter()
                .zip(fewer.iter().zip(&more))
                .filter(|(_, (a, b))| a != b)
                .collect();
            assert!(grown.is_empty(), "{grown:#?}");
        });
    }

    /// VM steps of every statement the work store ran since the counter was
    /// read (`count_steps`, through `sqlite3_trace_v2`).
    static STEPS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    unsafe extern "C" fn count_steps(
        kind: std::os::raw::c_uint,
        _context: *mut std::os::raw::c_void,
        statement: *mut std::os::raw::c_void,
        _elapsed: *mut std::os::raw::c_void,
    ) -> std::os::raw::c_int {
        if kind == rusqlite::ffi::SQLITE_TRACE_PROFILE as std::os::raw::c_uint {
            // SAFETY: a profile event's `statement` is the statement that
            // just ran, valid for the call.
            let steps = unsafe {
                rusqlite::ffi::sqlite3_stmt_status(
                    statement.cast(),
                    rusqlite::ffi::SQLITE_STMTSTATUS_VM_STEP,
                    1,
                )
            };
            STEPS.fetch_add(steps.max(0) as u64, Ordering::SeqCst);
        }
        0
    }

    /// Counts the VM steps of every statement the rig's work store runs.
    fn count_store_steps(rig: &LocalRig) {
        let db = &rig.bridge.work.store.as_ref().unwrap().db;
        // SAFETY: the callback reads only the statement it is given; the
        // connection outlives the rig's passes.
        unsafe {
            rusqlite::ffi::sqlite3_trace_v2(
                db.handle(),
                rusqlite::ffi::SQLITE_TRACE_PROFILE as std::os::raw::c_uint,
                Some(count_steps),
                std::ptr::null_mut(),
            );
        }
    }

    /// `n` tasks of the rig's session awaiting their result, each with a
    /// prompt of `prompt` bytes and an open return grant from that session
    /// (as `collab_accept` records them), an hour before their deadline.
    fn add_awaiting(rig: &LocalRig, n: usize, prompt: usize) {
        use crate::runtime::collab::results::{self, Origin, ReturnGrant};
        let store = rig.bridge.work.store.as_ref().unwrap();
        let control_gen = rig.bridge.host.control_gen("local");
        let tx = store.db.unchecked_transaction().unwrap();
        for _ in 0..n {
            let message = rig.message();
            let mut task = message.task(&message.recipients[0]).unwrap();
            task.expires_at = host_now().wall_ms + 3_600_000;
            task.prompt = "x".repeat(prompt);
            let record = WorkRecord {
                principal: "local".into(),
                attachment_owner: Sender::Local.owner(),
                control_gen,
                route_id: "r".into(),
                route_revision: 1,
                profile_id: "p".into(),
                profile_revision: 1,
                project: "local:project".into(),
                digest: hw::digest(b"task"),
                status: WorkStatus {
                    task_id: task.task_id.clone(),
                    receipt_id: uuid::Uuid::new_v4().to_string(),
                    state: WorkState::AwaitingResult,
                    detail: "agent submission receipt reconciled; task completion requires an explicit result".into(),
                    result: None,
                },
                task,
                turn_id: Some("turn-0".into()),
                authorization_expires_at: None,
            };
            tx.execute(
                "INSERT INTO work(id,record,state) VALUES(?1,?2,'awaiting_result')",
                rusqlite::params![record.task.task_id, serde_json::to_string(&record).unwrap()],
            )
            .unwrap();
            results::save_grant(
                &tx,
                &ReturnGrant {
                    task_id: record.task.task_id.clone(),
                    message_id: message.message_id.clone(),
                    workflow_id: message.workflow_id.clone(),
                    origin: Origin {
                        target: record.task.target.clone(),
                        control_gen,
                        route: None,
                    },
                    recipient: record.task.target.clone(),
                    expires_at: record.task.expires_at,
                    ended: None,
                },
            )
            .unwrap();
        }
        tx.commit().unwrap();
    }

    /// One scheduling pass of the rig, now: the VM steps the work store ran
    /// in it and how long it took.
    fn one_pass(rig: &mut LocalRig) -> (u64, Duration) {
        for s in rig.sessions.values_mut() {
            s.pump();
        }
        rig.bridge.work.scheduled = Instant::now();
        STEPS.store(0, Ordering::SeqCst);
        let started = Instant::now();
        rig.bridge.tick(&mut rig.app, &mut rig.sessions, false);
        (STEPS.load(Ordering::SeqCst), started.elapsed())
    }

    fn awaiting(rig: &LocalRig) -> i64 {
        rig.bridge
            .work
            .store
            .as_ref()
            .unwrap()
            .db
            .query_row(
                "SELECT count(*) FROM work WHERE state='awaiting_result'",
                [],
                |r| r.get(0),
            )
            .unwrap()
    }

    /// Passes until no return grant is due (after a change, at most
    /// `GRANTS_PER_PASS` are looked at a pass); how many it took.
    fn drain(rig: &mut LocalRig) -> usize {
        for n in 1..=64 {
            one_pass(rig);
            let due: i64 = rig
                .bridge
                .work
                .store
                .as_ref()
                .unwrap()
                .db
                .query_row(
                    "SELECT count(*) FROM grant_dues WHERE due_ms<=?1",
                    [host_now().wall_ms],
                    |r| r.get(0),
                )
                .unwrap();
            if due == 0 {
                return n;
            }
        }
        panic!("grants still due after 64 passes");
    }

    /// Spec section 17, "Scaling": a 100 ms pass where nothing relevant
    /// changed reads no task awaiting its result and no return grant: beside
    /// 4,000 of them (4 KiB prompts) it runs exactly the VM steps it runs
    /// beside 500. A changed input (here: none recorded yet) checks every
    /// task again in that pass, and makes every grant due, looked at 256 a
    /// pass.
    #[test]
    fn a_pass_where_nothing_changed_does_the_same_work_beside_thousands_of_awaiting_tasks() {
        local_test(async |root| {
            let mut rig = LocalRig::new(root).await;
            // The payload pass (once a minute) is not this pass.
            rig.bridge.work.cleanup = Instant::now() + Duration::from_secs(3600);
            count_store_steps(&rig);
            add_awaiting(&rig, 500, 4096);
            drain(&mut rig);
            let fewer: Vec<u64> = (0..3).map(|_| one_pass(&mut rig).0).collect();
            add_awaiting(&rig, 3500, 4096);
            assert!(drain(&mut rig) >= 3500 / 256, "new grants, 256 a pass");
            let more: Vec<u64> = (0..3).map(|_| one_pass(&mut rig).0).collect();
            assert_eq!(fewer, more);
            assert_eq!(awaiting(&rig), 4000);
            rig.bridge.work.inputs = None;
            let (recheck, _) = one_pass(&mut rig);
            assert!(
                recheck > more[0] + 4000 * 10,
                "{recheck} steps re-check 4000 tasks"
            );
            assert!(drain(&mut rig) >= 4000 / 256 - 1);
            assert_eq!(one_pass(&mut rig).0, more[0]);
            assert_eq!(awaiting(&rig), 4000);
        });
    }

    /// Timings of a pass beside 4,096 tasks awaiting their result, with 4 KiB
    /// and 30 KiB prompts (each with an open return grant). Run in release:
    /// `cargo test --release --bin atem -- --ignored --nocapture pass_timings`.
    #[test]
    #[ignore = "a timing report, not a check"]
    fn pass_timings_beside_awaiting_tasks() {
        for prompt in [4 * 1024, 30 * 1024] {
            local_test(async |root| {
                let mut rig = LocalRig::new(root).await;
                rig.bridge.work.cleanup = Instant::now() + Duration::from_secs(3600);
                count_store_steps(&rig);
                add_awaiting(&rig, 4096, prompt);
                drain(&mut rig);
                let mut times: Vec<Duration> = (0..21).map(|_| one_pass(&mut rig).1).collect();
                times.sort();
                rig.bridge.work.inputs = None;
                let (_, recheck) = one_pass(&mut rig);
                let mut draining = Vec::new();
                for _ in 0..64 {
                    let (steps, took) = one_pass(&mut rig);
                    if steps <= 1_000 {
                        break;
                    }
                    draining.push(took);
                }
                eprintln!(
                    "4096 awaiting tasks, {} KiB prompts: pass median {:?}, max {:?}; after an input change {:?}, then {} passes of at most {:?}",
                    prompt / 1024,
                    times[10],
                    times[20],
                    recheck,
                    draining.len(),
                    draining.iter().max().copied().unwrap_or_default()
                );
            });
        }
    }

    /// Records closed long ago, numbered `n` (`closed-<n>`), in every table
    /// that keeps them: settled tasks, ended grants, replies, messages,
    /// accepted, refused and expired sends with their publications,
    /// launches and resolutions (to `sessions` in turn). None is open
    /// (`open_records`).
    fn add_closed_records(db: &rusqlite::Connection, n: std::ops::Range<usize>, sessions: &[&str]) {
        let tx = db.unchecked_transaction().unwrap();
        for i in n {
            let id = format!("closed-{i}");
            let settled = ["completed", "failed", "cancelled", "expired"][i % 4];
            let sent = ["accepted", "refused", "expired"][i % 3];
            let replied = ["submitted", "refused"][i % 2];
            let session = sessions[i % sessions.len()];
            for (sql, state) in [
                (
                    "INSERT INTO work(id,record,state) VALUES(?1,'{}',?2)",
                    settled,
                ),
                (
                    "INSERT INTO return_grants(task_id,record,state) VALUES(?1,'{}',?2)",
                    "ended",
                ),
                (
                    "INSERT INTO results(task_id,result_id,state,detail,digest,created_ms,record,
                    next_try_ms,attempts) VALUES(?1,?1,?2,'',?1,0,'{}',0,0)",
                    replied,
                ),
                ("INSERT INTO messages(id,record) VALUES(?1,?2)", "{}"),
                (
                    "INSERT INTO outbox(message_id,envelope,state,detail,next_try_ms,created_ms)
                    VALUES(?1,'{}',?2,'',0,0)",
                    sent,
                ),
                (
                    "INSERT INTO publications(message_id,record) VALUES(?1,?2)",
                    "{}",
                ),
                ("INSERT INTO origins(message_id,record) VALUES(?1,?2)", "{}"),
                ("INSERT INTO launches(id,record) VALUES(?1,?2)", "{}"),
                (
                    "INSERT INTO resolutions(message_id,recipient_id,task_id,route_id,session_id,
                    process_gen,record) VALUES(?1,?1,?1,'r',?2,'p','{}')",
                    session,
                ),
                (
                    "INSERT INTO closed_records(kind,id,at_ms) VALUES('work',?1,0)",
                    "",
                ),
            ] {
                let params: &[&dyn rusqlite::ToSql] = if sql.contains("?2") {
                    &[&id, &state]
                } else {
                    &[&id]
                };
                tx.execute(sql, params).unwrap();
            }
        }
        tx.execute("DELETE FROM open_records WHERE id LIKE 'closed-%'", [])
            .unwrap();
        tx.commit().unwrap();
    }

    /// The local launch-on-message cap counts open launches only: with
    /// `MAX_RECORDS` launches settled a day past their deadline, a send
    /// that would launch is refused until the pass closes them.
    #[test]
    fn a_local_launch_counts_only_open_launches() {
        local_test(async |root| {
            let mut rig = LocalRig::new(root).await;
            launch_route(&mut rig, root);
            {
                let store = rig.bridge.work.store.as_ref().unwrap();
                let tx = store.db.unchecked_transaction().unwrap();
                for _ in 0..crate::runtime::host_work::MAX_RECORDS {
                    let record = LaunchRecord {
                        principal: "local".into(),
                        profile_id: "q".into(),
                        profile_revision: 1,
                        expires_at: 1,
                        digest: hw::digest(b"launch"),
                        status: LaunchStatus {
                            request_id: uuid::Uuid::new_v4().to_string(),
                            session_id: SessionId::new().to_string(),
                            process_gen: uuid::Uuid::new_v4().to_string(),
                            state: LaunchState::Failed,
                        },
                    };
                    tx.execute(
                        "INSERT INTO launches(id,record) VALUES(?1,?2)",
                        rusqlite::params![
                            record.status.request_id,
                            serde_json::to_string(&record).unwrap()
                        ],
                    )
                    .unwrap();
                }
                tx.commit().unwrap();
            }
            let message = select_message(&rig, "atem:atem-host/q");
            let origin = origin_of(&rig);
            let refused = rig
                .bridge
                .collab_accept("atem-host", &message, &origin, true, &rig.sessions)
                .unwrap_err();
            assert!(
                refused
                    .to_string()
                    .contains("launch receipt capacity reached"),
                "{refused}"
            );
            assert_eq!(rows(&rig, "work"), 0);
            rig.bridge
                .work
                .store
                .as_ref()
                .unwrap()
                .drop_payloads(host_now().wall_ms)
                .unwrap();
            send_q(&mut rig, true);
            assert_eq!(rows(&rig, "work"), 1);
            assert_eq!(
                crate::runtime::host_work::open_records(
                    &rig.bridge.work.store.as_ref().unwrap().db,
                    "launches"
                )
                .unwrap(),
                1
            );
        });
    }

    /// A return grant records why it ended only for an early end, its task
    /// going on: a grant whose task was cancelled records none, its sender
    /// gone or not; one whose sender left while its task waits records it.
    #[test]
    fn a_grant_records_why_it_ended_only_when_it_ended_early() {
        use crate::runtime::collab::results::{self, EarlyEnd, Origin, ReturnGrant};
        local_test(async |root| {
            let mut rig = LocalRig::new(root).await;
            let (cancelled, waiting) = (rig.message(), rig.message());
            for message in [&cancelled, &waiting] {
                rig.publish(message);
                let task = rig.work(message);
                let mut gone = task.task.target.clone();
                gone.session_id = SessionId::new().to_string();
                let store = rig.bridge.work.store.as_ref().unwrap();
                let tx = store.db.unchecked_transaction().unwrap();
                results::save_grant(
                    &tx,
                    &ReturnGrant {
                        task_id: task.task.task_id.clone(),
                        message_id: message.message_id.clone(),
                        workflow_id: message.workflow_id.clone(),
                        origin: Origin {
                            target: gone,
                            control_gen: rig.bridge.host.control_gen("local"),
                            route: None,
                        },
                        recipient: task.task.target.clone(),
                        expires_at: message.expires_at,
                        ended: None,
                    },
                )
                .unwrap();
                tx.commit().unwrap();
            }
            rig.bridge
                .collab_cancel(None, &cancelled.recipients[0].recipient_id)
                .unwrap();
            idle(&mut rig, 300).await;
            let ended = |message: &Message| -> (String, Option<EarlyEnd>) {
                let store = rig.bridge.work.store.as_ref().unwrap();
                let state = store
                    .db
                    .query_row(
                        "SELECT state FROM return_grants WHERE task_id=?1",
                        [&message.recipients[0].recipient_id],
                        |r| r.get(0),
                    )
                    .unwrap();
                let grant = results::grant(store, &message.recipients[0].recipient_id)
                    .unwrap()
                    .unwrap();
                (state, grant.ended)
            };
            assert_eq!(ended(&cancelled), ("ended".to_string(), None));
            assert_eq!(
                ended(&waiting),
                ("ended".to_string(), Some(EarlyEnd::SenderGone))
            );
        });
    }

    /// An identical reply without `--task` after its task closed (a day
    /// past its deadline) answers as before the close: the recorded reply
    /// (`results::replied_with`), as with `--task`; another reply still
    /// finds no task.
    #[test]
    fn an_identical_reply_after_its_task_closed_answers_as_before() {
        local_test(async |root| {
            let mut rig = LocalRig::new(root).await;
            let message = rig.message();
            rig.publish(&message);
            grant(&rig, &message);
            rig.until(|r| r.work(&message).turn_id.is_some()).await;
            let task = message.recipients[0].recipient_id.clone();
            let first = reply(&mut rig, &task, "the answer", &[]).unwrap();
            std::fs::write(rig.fake.join("complete"), "").unwrap();
            rig.until(|r| r.work(&message).status.state == WorkState::AwaitingResult)
                .await;
            rig.bridge
                .collab_complete(None, &task, &rig.sessions)
                .unwrap();
            let retries = |rig: &mut LocalRig| {
                let untasked = |rig: &mut LocalRig, text: &str| {
                    rig.bridge
                        .collab_reply(
                            &rig.sid,
                            crate::runtime::collab::ReplyRequest {
                                task_id: None,
                                text: text.into(),
                                memory: vec![],
                                vault: vec![],
                            },
                            &rig.sessions,
                        )
                        .map(|row| row.result_id)
                        .map_err(|e| e.to_string())
                };
                [
                    untasked(rig, "the answer"),
                    reply(rig, &task, "the answer", &[]),
                    untasked(rig, "another answer"),
                ]
            };
            let before = retries(&mut rig);
            assert_eq!(before[0], Ok(first.clone()));
            let store = rig.bridge.work.store.as_ref().unwrap();
            store
                .drop_payloads(message.expires_at + crate::runtime::host_work::PAYLOAD_RETENTION_MS)
                .unwrap();
            assert!(
                !store
                    .open_tasks()
                    .unwrap()
                    .iter()
                    .any(|t| t.task.task_id == task)
            );
            assert_eq!(retries(&mut rig), before);
        });
    }

    /// `[collab] send = false` is no pause: it refuses new sends and never
    /// stops a launch already accepted.
    #[test]
    fn turning_sending_off_does_not_stop_an_accepted_launch() {
        local_test(async |root| {
            let mut rig = LocalRig::new(root).await;
            launch_route(&mut rig, root);
            send_q(&mut rig, true);
            rig.bridge.work.config.collab.send = false;
            idle(&mut rig, 350).await;
            let launches = rig.bridge.take_remote_launches();
            assert_eq!(launches.len(), 1);
            assert!(
                rig.bridge.work.pending[&launches[0].request_id]
                    .permit
                    .load(Ordering::SeqCst)
            );
        });
    }

    /// A real change still fences: a route changed while paused fences the
    /// launch the moment the pause ends, before it can start.
    #[test]
    fn a_route_changed_during_a_pause_fences_the_waiting_launch() {
        local_test(async |root| {
            let mut rig = LocalRig::new(root).await;
            launch_route(&mut rig, root);
            send_q(&mut rig, true);
            let request = launch_records(&rig)[0].status.request_id.clone();
            let good = rig.bridge.work.config.clone();
            rig.bridge.work.config = Config::default();
            rig.bridge.work.config_problem = Some("expected a table".into());
            idle(&mut rig, 350).await;
            assert!(rig.bridge.take_remote_launches().is_empty());
            // The owner fixes the file, and the route has a new revision.
            let mut changed = good.clone();
            changed
                .routes
                .iter_mut()
                .find(|r| r.id == "q")
                .unwrap()
                .revision = 2;
            rig.bridge.work.config = changed;
            rig.bridge.work.config_problem = None;
            let launches = rig.bridge.take_remote_launches();
            assert_eq!(launches.len(), 1, "released to fail, never to start");
            assert!(
                !rig.bridge.work.pending[&request]
                    .permit
                    .load(Ordering::SeqCst)
            );
            assert!(!(launches[0].guard)());
        });
    }

    /// A launch that waits out a pause does not wait past its message: once
    /// that expired it is handed out to fail at its guard, not held for good.
    #[test]
    fn a_waiting_launch_whose_message_expired_is_released() {
        local_test(async |root| {
            let mut rig = LocalRig::new(root).await;
            launch_route(&mut rig, root);
            send_q(&mut rig, true);
            let request = launch_records(&rig)[0].status.request_id.clone();
            rig.bridge.work.config = Config::default();
            rig.bridge.work.config_problem = Some("expected a table".into());
            idle(&mut rig, 350).await;
            assert!(rig.bridge.take_remote_launches().is_empty());
            rig.bridge
                .work
                .pending
                .get_mut(&request)
                .unwrap()
                .expires_at = 0;
            let launches = rig.bridge.take_remote_launches();
            assert_eq!(launches.len(), 1);
            assert!(!(launches[0].guard)());
        });
    }

    /// A launch handed to the spawner re-reads `runtime.toml` at the spawn
    /// boundary, as a remote one does: a file that doesn't load, hosting
    /// switched off or a changed approval stops it.
    #[test]
    fn a_launch_under_way_stops_on_an_invalid_file_hosting_off_or_a_change() {
        use std::os::unix::fs::PermissionsExt;
        local_test(async |root| {
            let mut rig = LocalRig::new(root).await;
            let cwd = launch_route(&mut rig, root);
            send_q(&mut rig, true);
            let launches = rig.bridge.take_remote_launches();
            assert_eq!(launches.len(), 1);
            let guard = &launches[0].guard;
            let write = |text: &str| {
                let path = root.join("runtime.toml");
                std::fs::write(&path, text).unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            };
            write(&launch_toml(&cwd, 1));
            assert!(guard(), "the approved file");
            // At the spawn boundary the guard fails closed: a file that
            // doesn't load may be the edit that removes the route.
            write("not = [valid");
            assert!(!guard(), "an invalid file fences it");
            write(&launch_toml(&cwd, 1).replace("enabled = true", "enabled = false"));
            assert!(!guard(), "hosting off fences it");
            write(&launch_toml(&cwd, 1));
            assert!(guard(), "the approved file again");
            write(&launch_toml(&cwd, 2));
            assert!(!guard(), "a changed route is a change");
            write(&launch_toml(&cwd, 1).replace("launch = \"on_message\"", "launch = \"off\""));
            assert!(!guard(), "a route that no longer launches");
        });
    }

    /// A queued local task under an open return grant, as
    /// `collab_accept` records it; its id.
    fn queued_with_grant(rig: &LocalRig) -> String {
        use crate::runtime::collab::results::{self, Origin, ReturnGrant};
        let control_gen = rig.bridge.host.control_gen("local");
        let id = insert_task(
            rig,
            "local",
            control_gen,
            WorkState::Queued,
            host_now().wall_ms + 60_000,
        );
        let task = stored_record(rig, &id);
        let store = rig.bridge.work.store.as_ref().unwrap();
        let tx = store.db.unchecked_transaction().unwrap();
        results::save_grant(
            &tx,
            &ReturnGrant {
                task_id: id.clone(),
                message_id: uuid::Uuid::new_v4().to_string(),
                workflow_id: task.task.workflow_id.clone(),
                origin: Origin {
                    target: task.task.target.clone(),
                    control_gen,
                    route: None,
                },
                recipient: task.task.target.clone(),
                expires_at: task.task.expires_at,
                ended: None,
            },
        )
        .unwrap();
        tx.commit().unwrap();
        id
    }

    fn stored_record(rig: &LocalRig, id: &str) -> WorkRecord {
        rig.bridge
            .work
            .store
            .as_ref()
            .unwrap()
            .work(id)
            .unwrap()
            .unwrap()
    }

    fn grant_state(rig: &LocalRig, id: &str) -> String {
        rig.bridge
            .work
            .store
            .as_ref()
            .unwrap()
            .db
            .query_row(
                "SELECT state FROM return_grants WHERE task_id=?1",
                [id],
                |r| r.get(0),
            )
            .unwrap()
    }

    /// `atem message cancel` ends the task's return grant in the same
    /// transaction, needs the store as a reply or a completion does
    /// (`collab_store_ready`: refused during a receipt-database fault), and
    /// a write that fails stops hosting until a restart (`work_fail`).
    #[test]
    fn a_cancel_ends_its_grant_with_the_task_and_needs_a_working_store() {
        local_test(async |root| {
            let mut rig = LocalRig::new(root).await;
            let id = queued_with_grant(&rig);
            rig.bridge.collab_cancel(None, &id).unwrap();
            let task = stored_record(&rig, &id);
            assert_eq!(task.status.state, WorkState::Cancelled);
            assert_eq!(grant_state(&rig, &id), "ended", "no pass needed");

            let id = queued_with_grant(&rig);
            rig.bridge.work.error = true;
            let refused = rig.bridge.collab_cancel(None, &id).unwrap_err().to_string();
            assert!(
                refused.contains("agent hosting records are unavailable"),
                "{refused}"
            );
            assert_eq!(stored_record(&rig, &id).status.state, WorkState::Queued);
            assert_eq!(grant_state(&rig, &id), "open");
            rig.bridge.work.error = false;

            rig.bridge
                .work
                .store
                .as_ref()
                .unwrap()
                .db
                .execute_batch(
                    "CREATE TEMP TRIGGER no_write BEFORE UPDATE ON main.work
                    BEGIN SELECT RAISE(FAIL,'injected write failure'); END;",
                )
                .unwrap();
            assert!(rig.bridge.collab_cancel(None, &id).is_err());
            assert!(rig.bridge.work.error, "hosting stopped");
            assert_eq!(grant_state(&rig, &id), "open", "nothing half-written");
        });
    }

    /// A task whose record can't be read stops no pass and no hosting: a
    /// waiting one (not JSON, so `work_waits` has no deadline for it) and
    /// a queued one (a shape this build doesn't know) are settled once,
    /// failed with "record unreadable", their return grants ended, and the
    /// queue goes on: a local task behind them is dispatched.
    #[test]
    fn a_task_whose_record_cant_be_read_stops_no_pass() {
        local_test(async |root| {
            let mut rig = LocalRig::new(root).await;
            let waiting = queued_with_grant(&rig);
            let queued = queued_with_grant(&rig);
            let db = &rig.bridge.work.store.as_ref().unwrap().db;
            db.execute(
                "UPDATE work SET state='awaiting_result',record='{not json' WHERE id=?1",
                [&waiting],
            )
            .unwrap();
            db.execute(
                "UPDATE work SET record=json_set(record,'$.status.state','nonsense') WHERE id=?1",
                [&queued],
            )
            .unwrap();
            let behind = insert_task(
                &rig,
                "local",
                rig.bridge.host.control_gen("local"),
                WorkState::Queued,
                host_now().wall_ms + 60_000,
            );
            let state = |r: &LocalRig, id: &str| -> String {
                r.bridge
                    .work
                    .store
                    .as_ref()
                    .unwrap()
                    .db
                    .query_row("SELECT state FROM work WHERE id=?1", [id], |r| r.get(0))
                    .unwrap()
            };
            rig.until(|r| state(r, &behind) == "submitted").await;
            assert!(!rig.bridge.work.error, "hosting goes on");
            for id in [&waiting, &queued] {
                assert_eq!(state(&rig, id), "failed");
                assert_eq!(grant_state(&rig, id), "ended");
            }
        });
    }

    /// A local launch the runtime refused to start (the live-session limit,
    /// a restart) fails its tasks with that cause, not with a hint at the
    /// route's directory or environment.
    #[test]
    fn a_refused_launch_says_why_in_its_tasks() {
        local_test(async |root| {
            let mut rig = LocalRig::new(root).await;
            launch_route(&mut rig, root);
            send_q(&mut rig, true);
            let request = launch_records(&rig)[0].status.request_id.clone();
            rig.bridge
                .launch_refused(&request, "at most 16 sessions can run at once".into());
            assert_eq!(launch_records(&rig)[0].status.state, LaunchState::Failed);
            rig.until(|r| {
                r.bridge
                    .work
                    .store
                    .as_ref()
                    .unwrap()
                    .open_tasks()
                    .unwrap()
                    .first()
                    .is_some_and(|t| t.status.state == WorkState::Failed)
            })
            .await;
            let task = rig
                .bridge
                .work
                .store
                .as_ref()
                .unwrap()
                .open_tasks()
                .unwrap()
                .remove(0);
            assert_eq!(
                task.status.detail,
                "approved route launch not started: at most 16 sessions can run at once"
            );
        });
    }

    /// The principals a store's unfinished tasks name are kept from the
    /// bridge's open on (`HostBridge::open`), before any control write: a
    /// browser principal fenced before the restart keeps its control state
    /// through another principal's control write, so its task, accepted at
    /// that generation, isn't failed.
    #[test]
    fn principals_named_by_tasks_are_kept_from_the_start() {
        let dir = tempfile::tempdir().unwrap();
        let _profile = crate::test_profile::use_dir(dir.path());
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let journal = dir.path().join("runtime/journal");
            let state = dir.path().join("runtime");
            let host = HostTarget {
                account_id: "acct".into(),
                atem_device_id: "host".into(),
                host_trust_gen: 1,
            };
            let task_id = uuid::Uuid::new_v4().to_string();
            {
                let mut bridge = HostBridge::open(&journal, None, Clock::default()).unwrap();
                // `browser:b` was fenced once; its task came after.
                let _ = bridge.host.fence_principal("browser:b", 0);
                assert_eq!(bridge.host.control_gen("browser:b"), 2);
                let store = Store::open(&state).unwrap();
                store.bind(&host).unwrap();
                store
                    .enqueue(&WorkRecord {
                        principal: "browser:b".into(),
                        attachment_owner: String::new(),
                        control_gen: 2,
                        route_id: "r".into(),
                        route_revision: 1,
                        profile_id: "p".into(),
                        profile_revision: 1,
                        project: "local:project".into(),
                        digest: hw::digest(b"task"),
                        task: hw::WorkTask {
                            task_id: task_id.clone(),
                            workflow_id: uuid::Uuid::new_v4().to_string(),
                            target: wire::Target {
                                account_id: host.account_id.clone(),
                                atem_device_id: host.atem_device_id.clone(),
                                host_trust_gen: host.host_trust_gen,
                                session_id: SessionId::new().to_string(),
                                process_gen: uuid::Uuid::new_v4().to_string(),
                            },
                            expires_at: host_now().wall_ms + 60_000,
                            prompt: "kept".into(),
                            context: vec![],
                            attachments: vec![],
                        },
                        status: WorkStatus {
                            task_id: task_id.clone(),
                            receipt_id: uuid::Uuid::new_v4().to_string(),
                            state: WorkState::Queued,
                            detail: String::new(),
                            result: None,
                        },
                        turn_id: None,
                        authorization_expires_at: None,
                    })
                    .unwrap();
            }
            let app = App::new();
            let mut sessions = BTreeMap::new();
            let mut cx = Cx {
                client: &app.astation_client,
                sessions: &mut sessions,
            };
            let mut bridge = HostBridge::open(&journal, None, Clock::default()).unwrap();
            // Another principal's control write, which forgets the browser
            // principals nothing names.
            let effects = bridge.host.fence_principal("service:other", 0);
            bridge.exec(effects, &mut cx);
            assert_eq!(bridge.host.control_gen("browser:b"), 2);
            assert!(bridge.adopt_identity(
                &Identity {
                    account_id: host.account_id.clone(),
                    atem_device_id: host.atem_device_id.clone(),
                    host_trust_gen: host.host_trust_gen,
                },
                &mut cx
            ));
            let cwd = dir.path().join("project");
            let config: Config = toml::from_str(&format!(
                r#"
version = 1
enabled = true
[[profiles]]
id = "p"
revision = 1
label = "p"
provider = "claude"
cwd = {cwd:?}
project = "local:project"
principals = ["browser:b"]
[[routes]]
id = "r"
revision = 1
profile_id = "p"
principals = ["browser:b"]
"#
            ))
            .unwrap();
            bridge.work.config = config;
            bridge.work.store = Some(Store::open(&state).unwrap());
            for _ in 0..3 {
                bridge.work.scheduled = Instant::now();
                bridge.work_pass(&mut cx);
            }
            let task = bridge
                .work
                .store
                .as_ref()
                .unwrap()
                .work(&task_id)
                .unwrap()
                .unwrap();
            assert_eq!(task.status.state, WorkState::Blocked, "{:?}", task.status);
        });
    }

    /// An interrupted turn is read from its prompt receipt's journaled
    /// outcome (its detail), whether or not the receipt names its turn.
    #[test]
    fn an_interrupted_turn_is_its_completed_prompt_receipts_outcome() {
        let receipt = |kind, state, detail: &str| wire::Receipt {
            request_id: uuid::Uuid::new_v4().to_string(),
            target: wire::Target {
                account_id: "acct".into(),
                atem_device_id: "host".into(),
                host_trust_gen: 1,
                session_id: SessionId::new().to_string(),
                process_gen: uuid::Uuid::new_v4().to_string(),
            },
            kind,
            state,
            detail: Some(detail.into()),
            updated_at: 1,
            lease: None,
            result: None,
        };
        use wire::{ReceiptKind, ReceiptState};
        assert!(turn_interrupted(&receipt(
            ReceiptKind::Prompt,
            ReceiptState::Completed,
            "interrupted"
        )));
        assert!(!turn_interrupted(&receipt(
            ReceiptKind::Prompt,
            ReceiptState::Completed,
            "done"
        )));
        assert!(!turn_interrupted(&receipt(
            ReceiptKind::Interrupt,
            ReceiptState::Completed,
            "interrupted"
        )));
        assert!(!turn_interrupted(&receipt(
            ReceiptKind::Prompt,
            ReceiptState::Rejected,
            "interrupted"
        )));
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
            // A host with a pinned device list (it refuses r8).
            bridge.host.set_refuse_r8(true);
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
    /// Only a real change of authority does. `[collab] send = false` is no
    /// pause at all: it refuses new sends, and local work goes on.
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
            // A host with a pinned device list (it refuses r8).
            bridge.host.set_refuse_r8(true);
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
            for pause in 0..3 {
                match pause {
                    0 => bridge.work.config.enabled = false,
                    1 => {
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

            // Sending switched off: local work goes on as it was.
            bridge.work.config.collab.send = false;
            bridge.sync_local(&mut cx);
            assert!(bridge.local_healthy());
            assert!(bridge.collab_paused().is_empty());
            assert_eq!(bridge.local_attachment(), attachment);
            assert_eq!(bridge.host.control_gen("local"), generation);
            bridge.work.config.collab.send = true;

            // A pause that began before any attachment: it comes with the
            // recovery, and still nothing was fenced.
            bridge.work.config.enabled = false;
            let mut other = identity;
            other.host_trust_gen += 1;
            assert!(bridge.adopt_identity(&other, &mut cx));
            bridge.sync_local(&mut cx);
            assert!(bridge.local_attachment().is_empty());
            let fenced = bridge.host.control_gen("local");
            assert!(fenced > generation, "a new host identity fences `local`");
            bridge.sync_local(&mut cx);
            assert_eq!(bridge.host.control_gen("local"), fenced);
            // Back with sending still off: the attachment the queued local
            // work needs comes back too.
            bridge.work.config.enabled = true;
            bridge.work.config.collab.send = false;
            bridge.sync_local(&mut cx);
            assert!(!bridge.local_attachment().is_empty());
            assert_eq!(bridge.host.control_gen("local"), fenced);
        });
    }
}
