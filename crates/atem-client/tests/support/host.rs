//! A test host built from the crate's responder role and its host-side
//! pieces (the real runtime host is Task 7): `atem-ch1` responder, the r9
//! hello parse and check, the carriage evaluation, §R9.6 authority
//! (native, service, browser; scope and expiry), the welcome, and a small
//! session-v1 host (registry, 15 s leases with Send acquire, prompt
//! receipts that complete at once, receipt queries, `revoke_grant`,
//! `membership`, `approval_seen` with the push outbox).
//!
//! Sans-I/O: [`HostConn::on_frame`] takes one transport frame and returns
//! the frames to send; [`HostConn::poll`] drains what other connections or
//! timers queued for it (fences, events). The tests move the frames over
//! real sockets.
#![allow(dead_code)]

use std::collections::BTreeMap;

use atem_client::channel::responder::{AwaitFinish, HostContext, InitLimiter, Responder};
use atem_client::channel::wire::{self as chwire, Frame, Parsed};
use atem_client::channel::{Channel, Principal};
use atem_client::membership::{Effect, HostNow, Membership};
use atem_client::principal::{
    Authority, Denied, GRANT_ISSUED_AHEAD_MS, GRANT_MAX_LIFETIME_MS, JournalFull, Need, Refusal,
    RevokedGrants, SessionRef, admission_error,
};
use atem_client::push::{self, HintPlain, HostApproval, Outbox, SeenOutcome};
use atem_client::session::r9::{
    self, Hello, PendingRecovery, R9_FEATURES, REVISION, SessionError, Welcome, code,
};
use atem_client::session::revision::KNOWN_FEATURES;
use atem_client::session::wire::{
    self, Activity, Binding, Descriptor, Envelope, ErrorCode, Op as WireOp, Receipt, ReceiptLease,
    ReceiptState, SessionMessage, SessionState, Target,
};
use atem_client::{KeyId, SoftwareKeys};
use serde_json::{Value, json};

pub const LEASE_MS: u64 = 15_000;

/// A session the host runs.
#[derive(Debug, Clone)]
pub struct HostSession {
    pub session_id: String,
    pub process_gen: String,
    /// The recorded launch project hash (`h1.<kid>.<hex>`).
    pub project: String,
}

#[derive(Debug)]
struct Attachment {
    authority: Authority,
    attachment_gen: String,
    controller_session: String,
    channel_id: String,
    /// Plaintexts queued for this connection by other connections/timers.
    queue: Vec<Vec<u8>>,
    /// Close after sending the queue.
    fenced: bool,
}

#[derive(Debug, Clone)]
struct Lease {
    conn: u64,
    controller_session: String,
    epoch: u64,
    deadline_mono: u64,
}

/// The host's shared state.
pub struct HostCore {
    pub log: Membership,
    pub now: HostNow,
    pub host_id: String,
    pub trust_gen: u64,
    pub keys: SoftwareKeys,
    pub host_key: KeyId,
    pub sessions: Vec<HostSession>,
    /// Revoked grant ids until their grant's expiry, at most 256 (§R9.6).
    pub revoked: RevokedGrants,
    pub runtime_gen: String,
    attachments: BTreeMap<u64, Attachment>,
    leases: BTreeMap<String, Lease>,
    next_epoch: u64,
    receipts: BTreeMap<String, Receipt>,
    pub approvals: BTreeMap<String, HostApproval>,
    pub outbox: Outbox,
    /// Relay messages the host sent (push_hint, push_seen), in order.
    pub relay_sent: Vec<Value>,
    next_conn: u64,
    /// Every refusal sent as a first record (for assertions).
    pub refusals: Vec<SessionError>,
    /// A misbehaving host for client tests: rewrites the welcome it sends.
    pub welcome_override: Option<fn(&mut Welcome)>,
    /// The host policy (§R9.8a), in memory: (relay_only, revision) and the
    /// recorded changes (request_id, principal, relay_only, expected
    /// revision, committed revision).
    pub policy: (bool, u64),
    policy_requests: Vec<(String, String, bool, u64, u64)>,
}

fn uuid(n: u64) -> String {
    format!("aaaaaaaa-0000-4000-8000-{n:012x}")
}

impl HostCore {
    pub fn new(
        log: Membership,
        now: HostNow,
        host_seed: &[u8; 32],
        sessions: Vec<HostSession>,
    ) -> Self {
        let mut keys = SoftwareKeys::new();
        let host_key = KeyId::new("host_channel_key");
        keys.insert_ed25519(host_key.clone(), host_seed);
        HostCore {
            log,
            now,
            host_id: "host-a".into(),
            trust_gen: 1,
            keys,
            host_key,
            sessions,
            revoked: RevokedGrants::new(),
            runtime_gen: "11111111-1111-4111-8111-111111111111".into(),
            attachments: BTreeMap::new(),
            leases: BTreeMap::new(),
            next_epoch: 0,
            receipts: BTreeMap::new(),
            approvals: BTreeMap::new(),
            outbox: Outbox::new(),
            relay_sent: Vec::new(),
            next_conn: 0,
            refusals: Vec::new(),
            welcome_override: None,
            policy: (false, 0),
            policy_requests: Vec::new(),
        }
    }

    pub fn attachments(&self) -> usize {
        self.attachments.len()
    }

    /// The host's wall clock jumps / time passes: expiry timers fence, and
    /// the outbox resends.
    pub fn tick(&mut self) {
        self.revoked.prune(self.now.wall_ms);
        let now = self.now.wall_ms;
        let expired: Vec<u64> = self
            .attachments
            .iter()
            .filter(|(_, a)| a.authority.expired(now) && !a.fenced)
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            self.fence(id, "expired");
        }
        let resends = self.outbox.tick(self.now.mono_ms);
        self.relay_sent.extend(resends);
    }

    /// Journals a revoked grant id until its grant's expiry: the expiry of
    /// an attached browser holding it, else the latest a grant can still
    /// live (1 h + 300 s of `issued_at` lead). Full of unexpired
    /// revocations: refused (the caller answers `busy`).
    pub fn revoke(&mut self, grant_id: &str) -> Result<(), JournalFull> {
        let now = self.now.wall_ms;
        let until = self
            .attachments
            .values()
            .filter(|a| a.authority.name() == format!("browser:{grant_id}"))
            .find_map(|a| a.authority.expires_at)
            .unwrap_or(now + GRANT_MAX_LIFETIME_MS + GRANT_ISSUED_AHEAD_MS);
        self.revoked.revoke(grant_id, until, now)
    }

    fn fence(&mut self, conn: u64, detail: &str) {
        self.leases.retain(|_, l| l.conn != conn);
        if let Some(a) = self.attachments.get_mut(&conn) {
            let error = SessionError {
                detail: Some(detail.into()),
                ..SessionError::new(code::UNAUTHORIZED)
            };
            a.queue.push(error.to_bytes());
            a.fenced = true;
        }
    }

    fn fence_principal(&mut self, name: &str, detail: &str) {
        let ids: Vec<u64> = self
            .attachments
            .iter()
            .filter(|(_, a)| a.authority.name() == name)
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            self.fence(id, detail);
        }
    }

    /// A native member holding `manage` at the head (§R9.8a).
    fn holds_manage(&self, authority: &Authority) -> bool {
        authority
            .name()
            .strip_prefix("member:")
            .and_then(|d| self.log.member(d))
            .is_some_and(|m| {
                m.status == atem_client::membership::MemberStatus::Active
                    && m.member.is_manager()
                    && m.member.auth_key == authority.key
            })
    }

    /// `host_policy_set`/`host_policy_get` (§R9.8a) from attachment `conn`,
    /// as the runtime host answers them (no storage faults here): the
    /// reply, and `host_policy_changed` queued for the other managers.
    fn host_policy(&mut self, conn: u64, data: &Value) -> Vec<u8> {
        use atem_client::session::host_policy::{
            HostPolicyChanged, HostPolicyResult, Outcome, Policy, PolicyState, Request,
        };
        let authority = self.attachments[&conn].authority.clone();
        let re = data["id"].as_str().map(str::to_owned);
        let error = |code: &str| {
            SessionError {
                re: re.clone(),
                ..SessionError::new(code)
            }
            .to_bytes()
        };
        let Ok(request) = Request::from_data(data) else {
            return error(code::INVALID_REQUEST);
        };
        if !self.holds_manage(&authority) {
            return error(code::FORBIDDEN);
        }
        let principal = authority.name();
        let mut changed = false;
        let (request_id, outcome) = match &request {
            Request::Get { .. } => (None, Outcome::Current),
            Request::Set {
                request_id,
                relay_only,
                expected_revision,
                ..
            } => {
                let (value, revision) = self.policy;
                let outcome = match self.policy_requests.iter().find(|r| r.0 == *request_id) {
                    Some(r)
                        if r.1 != principal || r.2 != *relay_only || r.3 != *expected_revision =>
                    {
                        return error("request_id_reused");
                    }
                    Some(r) if r.4 == revision => Outcome::Committed,
                    Some(_) => Outcome::Superseded,
                    None if *expected_revision != revision => Outcome::Conflict,
                    None if *relay_only == value => Outcome::Unchanged,
                    None => {
                        self.policy = (*relay_only, revision + 1);
                        self.policy_requests.push((
                            request_id.clone(),
                            principal.clone(),
                            *relay_only,
                            *expected_revision,
                            revision + 1,
                        ));
                        if self.policy_requests.len() > 64 {
                            self.policy_requests.remove(0);
                        }
                        changed = true;
                        Outcome::Committed
                    }
                };
                (Some(request_id.clone()), outcome)
            }
        };
        let policy = Policy {
            relay_only: self.policy.0,
            revision: self.policy.1,
            state: PolicyState::Durable,
        };
        let a = &self.attachments[&conn];
        let result = HostPolicyResult {
            id: uuid(0x9100 + policy.revision),
            re: request.id().to_owned(),
            request_id,
            outcome,
            policy,
            account_id: self.log.account_id().to_owned(),
            atem_device_id: self.host_id.clone(),
            host_trust_gen: self.trust_gen,
            head: self.log.head(),
            channel_id: a.channel_id.clone(),
            attachment_gen: a.attachment_gen.clone(),
        };
        if changed {
            let others: Vec<u64> = self
                .attachments
                .iter()
                .filter(|(id, a)| **id != conn && !a.fenced && self.holds_manage(&a.authority))
                .map(|(id, _)| *id)
                .collect();
            for id in others {
                let a = self.attachments.get_mut(&id).unwrap();
                let change = HostPolicyChanged {
                    id: uuid(0x9200 + policy.revision),
                    policy,
                    account_id: result.account_id.clone(),
                    atem_device_id: result.atem_device_id.clone(),
                    host_trust_gen: result.host_trust_gen,
                    head: result.head,
                    channel_id: a.channel_id.clone(),
                    attachment_gen: a.attachment_gen.clone(),
                };
                a.queue.push(change.to_bytes());
            }
        }
        result.to_bytes()
    }

    fn in_scope(&self, authority: &Authority, session: &HostSession) -> bool {
        authority.session_in_scope(&self.host_id, &session.session_id, &|entry| {
            Some(entry == session.project)
        })
    }

    fn descriptor(&self, s: &HostSession) -> Descriptor {
        Descriptor {
            session_id: s.session_id.clone(),
            process_gen: s.process_gen.clone(),
            provider: "claude".into(),
            cwd_label: "proj".into(),
            state: SessionState::Running,
            activity: Activity::Ready,
            activity_since: 0,
            controller: self.leases.get(&s.session_id).map(|l| wire::Controller {
                controller_session: l.controller_session.clone(),
                lease_epoch: l.epoch,
            }),
            capabilities: vec!["chat-v1".into(), "terminal-v1".into()],
            created_at: 0,
        }
    }

    /// Opens an approval on a session and sends its sealed hints.
    pub fn open_approval(&mut self, session_id: &str, approval_id: &str, plain: &HintPlain) {
        let s = self
            .sessions
            .iter()
            .find(|s| s.session_id == session_id)
            .unwrap()
            .clone();
        let key = push::ApprovalKey::new(
            &self.log,
            &self.host_id,
            self.trust_gen,
            &s.session_id,
            &s.process_gen,
            approval_id,
        );
        let created = self.now.wall_ms;
        let approval = HostApproval::new(key, created, created + 600_000);
        let hints: Vec<push::Hint> = approval
            .open_hints(&self.keys, &self.host_key, &self.log, plain)
            .unwrap()
            .iter()
            .map(|o| push::Hint::verify(o, &self.log, created, push::Verifier::Client).unwrap())
            .collect();
        let message = self.outbox.send_hints(&hints, self.now.mono_ms);
        self.relay_sent.push(message);
        self.approvals.insert(approval_id.into(), approval);
    }

    /// Closes an approval: the resolved hint.
    pub fn close_approval(&mut self, approval_id: &str, reason: &str) {
        let approval = self.approvals.get_mut(approval_id).unwrap();
        let resolved = approval
            .close(&self.keys, &self.host_key, reason, self.now.wall_ms)
            .unwrap();
        let hint = push::Hint::verify(
            &resolved,
            &self.log,
            self.now.wall_ms,
            push::Verifier::Client,
        )
        .unwrap();
        let message = self.outbox.send_hints(&[hint], self.now.mono_ms);
        self.relay_sent.push(message);
    }
}

enum State {
    Init,
    AwaitFinish(AwaitFinish),
    Open(Box<Channel>),
    Closed,
}

/// One transport connection to the host.
pub struct HostConn {
    pub id: u64,
    state: State,
    limiter: InitLimiter,
}

/// What the host sends on a frame, and whether it then closes.
pub struct Out {
    pub frames: Vec<Vec<u8>>,
    pub close: bool,
}

impl HostConn {
    pub fn new(core: &mut HostCore) -> Self {
        core.next_conn += 1;
        HostConn {
            id: core.next_conn,
            state: State::Init,
            limiter: InitLimiter::new(),
        }
    }

    pub fn is_open(&self) -> bool {
        matches!(self.state, State::Open(_))
    }

    fn close(&mut self, core: &mut HostCore, frames: Vec<Vec<u8>>) -> Out {
        self.state = State::Closed;
        core.attachments.remove(&self.id);
        core.leases.retain(|_, l| l.conn != self.id);
        Out {
            frames,
            close: true,
        }
    }

    pub fn on_frame(&mut self, core: &mut HostCore, frame: &[u8]) -> Out {
        let mono = core.now.mono_ms;
        match std::mem::replace(&mut self.state, State::Closed) {
            State::Init => {
                if matches!(chwire::parse(frame), Ok(Parsed::Plain(_))) {
                    // A session message outside any channel.
                    let e = SessionError::new(code::UNSUPPORTED_VERSION);
                    self.state = State::Init;
                    return Out {
                        frames: vec![e.to_bytes()],
                        close: false,
                    };
                }
                if !self.limiter.admit(mono) {
                    let r = InitLimiter::busy();
                    return self.close(core, r.reply.into_iter().collect());
                }
                let ctx = HostContext {
                    log: &core.log,
                    host_id: &core.host_id,
                    host_trust_gen: core.trust_gen,
                    provider: &core.keys,
                    key: &core.host_key,
                };
                match Responder::on_init(&ctx, frame, mono) {
                    Ok((next, accept)) => {
                        self.state = State::AwaitFinish(next);
                        Out {
                            frames: vec![accept],
                            close: false,
                        }
                    }
                    Err(r) => self.close(core, r.reply.into_iter().collect()),
                }
            }
            State::AwaitFinish(await_finish) => self.on_finish(core, await_finish, frame),
            State::Open(mut channel) => {
                let plain = match channel.open(frame, mono) {
                    Ok(p) => p,
                    Err(_) => return self.close(core, Vec::new()),
                };
                let replies = self.on_message(core, &plain);
                let mut frames = Vec::new();
                for r in replies {
                    match channel.seal(&r, mono) {
                        Ok(f) => frames.push(f),
                        Err(_) => return self.close(core, frames),
                    }
                }
                self.state = State::Open(channel);
                let mut out = self.poll(core);
                frames.append(&mut out.frames);
                Out {
                    frames,
                    close: out.close,
                }
            }
            State::Closed => self.close(core, Vec::new()),
        }
    }

    /// Drains what was queued for this connection (fences, events).
    pub fn poll(&mut self, core: &mut HostCore) -> Out {
        let mono = core.now.mono_ms;
        let State::Open(channel) = &mut self.state else {
            return Out {
                frames: Vec::new(),
                close: false,
            };
        };
        let Some(a) = core.attachments.get_mut(&self.id) else {
            return Out {
                frames: Vec::new(),
                close: false,
            };
        };
        let queue = std::mem::take(&mut a.queue);
        let fenced = a.fenced;
        let mut frames = Vec::new();
        for q in queue {
            if let Ok(f) = channel.seal(&q, mono) {
                frames.push(f);
            }
        }
        if fenced {
            return self.close(core, frames);
        }
        Out {
            frames,
            close: false,
        }
    }

    fn on_finish(&mut self, core: &mut HostCore, await_finish: AwaitFinish, frame: &[u8]) -> Out {
        let mono = core.now.mono_ms;
        let opened = match await_finish.on_finish(frame, mono) {
            Ok(o) => o,
            Err(r) => return self.close(core, r.reply.into_iter().collect()),
        };
        let Some(hello) = Hello::parse(opened.hello()) else {
            let r = opened.malformed();
            return self.close(core, r.reply.into_iter().collect());
        };
        let keyed = opened.key(&hello.proof);
        let refuse = |core: &mut HostCore, keyed: atem_client::channel::Keyed, e: SessionError| {
            core.refusals.push(e.clone());
            keyed.refuse(&e.to_bytes(), mono).unwrap()
        };
        let membership = match hello.check() {
            Ok(m) => m.clone(),
            Err(r) => {
                let f = refuse(core, keyed, r.to_error(hello.id.as_deref()));
                return self.close(core, vec![f]);
            }
        };
        // The carriage before judging the sender (§R9.7 step 6).
        let now = core.now.clone();
        let eval = core.log.evaluate(&membership.entries, &now);
        core.log = eval.next.clone();
        for effect in &eval.effects {
            if let Effect::MemberRemoved { device_id } | Effect::RolesChanged { device_id } = effect
            {
                core.fence_principal(&format!("member:{device_id}"), "removed");
                core.fence_principal(&format!("service:{device_id}"), "removed");
            }
        }
        let re = hello.id.as_deref();
        let authority = match &hello.proof.principal {
            Principal::Native { device_id } | Principal::Service { device_id } => {
                match eval.admission(device_id, membership.more, &now) {
                    atem_client::membership::Admission::Member { state, .. } => {
                        Authority::of_member(
                            &hello.proof.principal,
                            &state.member,
                            &core.host_id,
                            now.wall_ms,
                        )
                    }
                    other => Err(Refusal::Membership(Box::new(other))),
                }
            }
            Principal::Browser { .. } => {
                let revoked = core.revoked.clone();
                let wall = now.wall_ms;
                Authority::resolve(
                    &core.log,
                    &hello.proof.principal,
                    hello.grant.as_ref(),
                    &core.host_id,
                    core.trust_gen,
                    &now,
                    &|id| revoked.contains(id, wall),
                )
            }
        };
        let authority = match authority {
            Ok(a) => a,
            Err(Refusal::Membership(admission)) => {
                let e = admission_error(&admission, re).unwrap();
                let f = refuse(core, keyed, e);
                return self.close(core, vec![f]);
            }
            Err(r) => {
                let f = refuse(core, keyed, r.to_error(re));
                return self.close(core, vec![f]);
            }
        };
        let mut channel = match keyed.admit(&authority.key, authority.channel_deadline_ms(&now)) {
            Ok(c) => c,
            Err(refusal) => {
                let e = SessionError {
                    re: re.map(str::to_owned),
                    ..SessionError::new(code::HANDSHAKE_FAILED)
                };
                core.refusals.push(e.clone());
                let f = refusal.reply(&e.to_bytes(), mono).unwrap();
                return self.close(core, vec![f]);
            }
        };
        let attachment_gen = uuid(0x1000 + self.id);
        let controller_session = uuid(0x2000 + self.id);
        let mut features: Vec<String> = KNOWN_FEATURES.iter().map(|f| f.to_string()).collect();
        features.extend(R9_FEATURES.iter().map(|f| f.to_string()));
        let welcome = Welcome {
            id: uuid(0x3000 + self.id),
            re: hello.id.clone(),
            account_id: core.log.account_id().into(),
            atem_device_id: core.host_id.clone(),
            host_trust_gen: core.trust_gen,
            runtime_gen: core.runtime_gen.clone(),
            controller_session: controller_session.clone(),
            attachment_gen: attachment_gen.clone(),
            client_kind: authority.client_kind,
            permissions: authority.permissions.iter().copied().collect(),
            authorization_ms_left: authority.authorization_ms_left(now.wall_ms, 86_400_000),
            server_time: now.wall_ms,
            revision: REVISION,
            features,
            principal: authority.name(),
            scope: authority.scope.clone(),
            head: core.log.head(),
            pending_recovery: core
                .log
                .pending_recovery(&now)
                .iter()
                .map(PendingRecovery::of)
                .collect(),
            channel_id: channel.channel_id().to_owned(),
        };
        let mut welcome = welcome;
        if let Some(rewrite) = core.welcome_override {
            rewrite(&mut welcome);
        }
        let frame = channel.seal(&welcome.to_bytes(), mono).unwrap();
        core.attachments.insert(
            self.id,
            Attachment {
                authority,
                attachment_gen,
                controller_session,
                channel_id: channel.channel_id().to_owned(),
                queue: Vec::new(),
                fenced: false,
            },
        );
        self.state = State::Open(Box::new(channel));
        Out {
            frames: vec![frame],
            close: false,
        }
    }

    fn on_message(&mut self, core: &mut HostCore, plain: &[u8]) -> Vec<Vec<u8>> {
        let value: Value = serde_json::from_slice(plain).unwrap_or(Value::Null);
        let data = &value["data"];
        let id = data["id"].as_str().unwrap_or_default().to_owned();
        let error = |code: &str, detail: Option<&str>| {
            SessionError {
                re: Some(id.clone()),
                detail: detail.map(str::to_owned),
                ..SessionError::new(code)
            }
            .to_bytes()
        };
        let authority = core.attachments[&self.id].authority.clone();
        // The one authority check for every request (§R9.6), before any
        // field decoding: the named session first (out of scope or unknown:
        // `unknown_session`), then the op (`forbidden`).
        let family = value["type"].as_str().unwrap_or_default().to_owned();
        let need = match Need::of_request(&family, data) {
            Ok(need) => need,
            Err(denied) => {
                return vec![match family.as_str() {
                    "session" => error(denied.code(), None),
                    _ => family_error(&family, data, denied.code()),
                }];
            }
        };
        {
            let named = Need::session_of(data)
                .map(|sid| core.sessions.iter().find(|s| s.session_id == sid).cloned());
            let host_id = core.host_id.clone();
            let check = |s: &HostSession| -> Result<(), Denied> {
                let project = s.project.clone();
                let matches = move |entry: &str| Some(entry == project);
                let r = SessionRef {
                    host_id: &host_id,
                    session_id: &s.session_id,
                    project_matches: &matches,
                };
                authority.authorize(need, Some(Some(&r)))
            };
            let verdict = match &named {
                None => authority.authorize(need, None),
                Some(None) => Err(Denied::UnknownSession),
                Some(Some(s)) => check(s),
            };
            if let Err(denied) = verdict {
                return vec![match family.as_str() {
                    "session" => error(denied.code(), None),
                    _ => family_error(&family, data, denied.code()),
                }];
            }
        }
        // r9's own ops.
        if value["type"] == "session" {
            match data["op"].as_str() {
                Some("host_policy_set" | "host_policy_get") => {
                    return vec![core.host_policy(self.id, data)];
                }
                Some("revoke_grant") => {
                    let grant_id = data["grant_id"].as_str().unwrap_or_default().to_owned();
                    if core.revoke(&grant_id).is_err() {
                        return vec![error(code::BUSY, Some("revoked grants journal full"))];
                    }
                    core.fence_principal(&format!("browser:{grant_id}"), "grant revoked");
                    return vec![
                        r9::grant_revoked(&uuid(0x9000), &id)
                            .to_string()
                            .into_bytes(),
                    ];
                }
                Some("membership") => {
                    let entries: Vec<_> = data["entries"]
                        .as_array()
                        .cloned()
                        .unwrap_or_default()
                        .iter()
                        .map(|e| {
                            atem_client::canonical::StrictValue::parse(
                                e.to_string().as_bytes(),
                                usize::MAX,
                            )
                            .unwrap()
                        })
                        .collect();
                    let now = core.now.clone();
                    let eval = core.log.evaluate(&entries, &now);
                    core.log = eval.next.clone();
                    for effect in &eval.effects {
                        if let Effect::MemberRemoved { device_id } = effect {
                            core.fence_principal(&format!("member:{device_id}"), "removed");
                            core.fence_principal(&format!("service:{device_id}"), "removed");
                        }
                    }
                    let pending: Vec<_> = core
                        .log
                        .pending_recovery(&now)
                        .iter()
                        .map(PendingRecovery::of)
                        .collect();
                    return vec![
                        r9::membership_head(&uuid(0x9001), Some(&id), core.log.head(), &pending)
                            .to_string()
                            .into_bytes(),
                    ];
                }
                Some("approval_seen") => {
                    let approval_id = data["approval_id"].as_str().unwrap_or_default();
                    let target = &data["binding"]["target"];
                    let Some(approval) = core.approvals.get_mut(approval_id) else {
                        return vec![error(code::STALE_TARGET, None)];
                    };
                    let device = match &authority.principal {
                        Principal::Native { device_id } | Principal::Service { device_id } => {
                            device_id.clone()
                        }
                        Principal::Browser { grant_id, .. } => grant_id.clone(),
                    };
                    let outcome = approval
                        .seen(
                            &core.keys,
                            &core.host_key,
                            &device,
                            authority.allows(Need::Seen),
                            target["session_id"].as_str().unwrap_or_default(),
                            target["process_gen"].as_str().unwrap_or_default(),
                            core.now.wall_ms,
                        )
                        .unwrap();
                    return match outcome {
                        SeenOutcome::Signed(object) => {
                            let seen = push::Seen::verify(&object, &core.log).unwrap();
                            let expires = approval.expires_at;
                            let m = core.outbox.send_seen(&seen, expires, core.now.mono_ms);
                            core.relay_sent.push(m);
                            vec![r9::seen(&uuid(0x9002), &id).to_string().into_bytes()]
                        }
                        SeenOutcome::Repeat => {
                            vec![r9::seen(&uuid(0x9003), &id).to_string().into_bytes()]
                        }
                        SeenOutcome::Forbidden => vec![error(code::FORBIDDEN, None)],
                        SeenOutcome::StaleTarget => vec![error(code::STALE_TARGET, None)],
                    };
                }
                _ => {}
            }
        }
        let env = match wire::decode(plain) {
            Ok(e) => e,
            Err(_) => return vec![error(code::INVALID_REQUEST, None)],
        };
        let reply = |op: WireOp| {
            wire::encode(&Envelope::Session(SessionMessage {
                id: uuid(0xa000 + core_rand()),
                re: Some(id.clone()),
                op,
            }))
        };
        let wire_error = |code: ErrorCode, detail: Option<&str>| {
            wire::encode(&Envelope::Session(SessionMessage {
                id: uuid(0xb000 + core_rand()),
                re: Some(id.clone()),
                op: WireOp::Error {
                    code,
                    detail: detail.map(str::to_owned),
                    revision: None,
                    controller: None,
                },
            }))
        };
        match env {
            Envelope::Session(msg) => match msg.op {
                WireOp::List {} => {
                    let sessions = core
                        .sessions
                        .iter()
                        .filter(|s| core.in_scope(&authority, s))
                        .map(|s| core.descriptor(s))
                        .collect();
                    vec![reply(WireOp::Sessions {
                        runtime_gen: core.runtime_gen.clone(),
                        runtime_epoch: 1,
                        seq: 1,
                        sessions,
                    })]
                }
                WireOp::Acquire { binding, .. } => match self.grant(core, &binding) {
                    Ok((epoch, _)) => {
                        let mut b = binding.clone();
                        b.lease_epoch = Some(epoch);
                        vec![reply(WireOp::Lease {
                            binding: b,
                            ms_left: LEASE_MS,
                        })]
                    }
                    Err(e) => vec![wire_error(e, None)],
                },
                WireOp::Submit {
                    binding,
                    request_id,
                    kind,
                    acquire,
                    ..
                } => {
                    let mut lease = None;
                    if acquire == Some(true) {
                        match self.grant(core, &binding) {
                            Ok((epoch, _)) => {
                                lease = Some(ReceiptLease {
                                    lease_epoch: epoch,
                                    ms_left: LEASE_MS,
                                })
                            }
                            Err(e) => return vec![wire_error(e, None)],
                        }
                    } else {
                        let held = core.leases.get(&binding.target.session_id);
                        if held.map(|l| (l.conn, l.epoch))
                            != binding.lease_epoch.map(|e| (self.id, e))
                        {
                            return vec![wire_error(ErrorCode::StaleLease, None)];
                        }
                    }
                    let mut receipt = Receipt {
                        request_id: request_id.clone(),
                        target: binding.target.clone(),
                        kind,
                        state: ReceiptState::Accepted,
                        detail: None,
                        updated_at: core.now.wall_ms,
                        lease,
                        result: None,
                    };
                    let accepted = reply(WireOp::Receipt(receipt.clone()));
                    receipt.state = ReceiptState::Completed;
                    receipt.detail = Some("done".into());
                    receipt.lease = None;
                    core.receipts.insert(request_id, receipt.clone());
                    let completed = wire::encode(&Envelope::Session(SessionMessage {
                        id: uuid(0xc000 + core_rand()),
                        re: None,
                        op: WireOp::Receipt(receipt),
                    }));
                    vec![accepted, completed]
                }
                WireOp::Renew { binding } => {
                    let mono = core.now.mono_ms;
                    match core.leases.get_mut(&binding.target.session_id) {
                        Some(l) if l.conn == self.id && Some(l.epoch) == binding.lease_epoch => {
                            l.deadline_mono = mono + LEASE_MS;
                            vec![reply(WireOp::Lease {
                                binding,
                                ms_left: LEASE_MS,
                            })]
                        }
                        _ => vec![wire_error(ErrorCode::StaleLease, None)],
                    }
                }
                WireOp::Release { binding } => {
                    let session = binding.target.session_id.clone();
                    match core.leases.get(&session) {
                        Some(l) if l.conn == self.id && Some(l.epoch) == binding.lease_epoch => {
                            core.leases.remove(&session);
                            vec![reply(WireOp::LeaseReleased {})]
                        }
                        _ => vec![wire_error(ErrorCode::StaleLease, None)],
                    }
                }
                WireOp::ReceiptQuery {
                    binding,
                    request_ids,
                } => {
                    // Only that (in-scope, checked above) session's receipts.
                    let receipts = request_ids
                        .iter()
                        .filter_map(|r| core.receipts.get(r).cloned())
                        .filter(|r| r.target.session_id == binding.target.session_id)
                        .collect();
                    vec![reply(WireOp::Receipts { receipts })]
                }
                _ => vec![wire_error(ErrorCode::InvalidRequest, None)],
            },
            // Allowed terminal-v1/chat-v1 requests: the model has no
            // terminal or chat behind them.
            Envelope::Family(_) => Vec::new(),
        }
    }

    /// A lease for this connection: free, expired or its own.
    fn grant(&self, core: &mut HostCore, binding: &Binding) -> Result<(u64, String), ErrorCode> {
        let session = binding.target.session_id.clone();
        let mono = core.now.mono_ms;
        let a = &core.attachments[&self.id];
        if let Some(l) = core.leases.get(&session)
            && l.conn != self.id
            && l.deadline_mono > mono
        {
            return Err(ErrorCode::LeaseHeld);
        }
        if let Some(l) = core.leases.get_mut(&session)
            && l.conn == self.id
        {
            return Ok((l.epoch, l.controller_session.clone()));
        }
        core.next_epoch += 1;
        let lease = Lease {
            conn: self.id,
            controller_session: a.controller_session.clone(),
            epoch: core.next_epoch,
            deadline_mono: mono + LEASE_MS,
        };
        let out = (lease.epoch, lease.controller_session.clone());
        core.leases.insert(session, lease);
        Ok(out)
    }
}

/// A family's error in the r8 host's shapes: terminal `error{terminal_id,
/// code, message}`, chat `error{conversationId, agentId, code, text}`.
fn family_error(family: &str, d: &Value, code: &str) -> Vec<u8> {
    let data = if family == "agentChat" {
        json!({"v": 1, "op": "error", "conversationId": d["conversationId"],
               "agentId": d["agentId"], "code": code, "text": code})
    } else {
        json!({"v": 1, "op": "error", "terminal_id": d["terminal_id"],
               "code": code, "message": code})
    };
    json!({"type": family, "data": data})
        .to_string()
        .into_bytes()
}

/// Distinct message ids within a process.
fn core_rand() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(1);
    N.fetch_add(1, Ordering::Relaxed)
}

/// The target a test client names (unused by the host model).
pub fn target(core: &HostCore, session: &HostSession) -> Target {
    Target {
        account_id: core.log.account_id().into(),
        atem_device_id: core.host_id.clone(),
        host_trust_gen: core.trust_gen,
        session_id: session.session_id.clone(),
        process_gen: session.process_gen.clone(),
    }
}

/// A plain (non-channel) frame's reply, for completeness.
pub fn is_channel_frame(bytes: &[u8]) -> bool {
    matches!(chwire::parse(bytes), Ok(Parsed::Channel(Frame::Init(_))))
}
