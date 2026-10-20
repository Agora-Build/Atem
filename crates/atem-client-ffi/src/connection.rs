//! One connection to a host: `atem-ch1` (§R9.7), the r9 hello/welcome
//! (§R9.8) and r8's session-v1 machines inside the channel, as a
//! byte-in/byte-out object. The app owns the transport (WebSocket through
//! the relay, the Astation link, direct :8080) and the clock: it sends the
//! frames this object returns, passes every frame it receives, and passes
//! a monotonic time in milliseconds to every call.
//!
//! ```text
//! new(host_id, identity)
//! start(log, now)                    → init frame          ── send
//! on_accept(frame, log, provider, now) → finish frame      ── send
//!   (or on_accept_deferred → SignRequest; finish_with_signature → finish)
//! on_welcome(frame, log, now)        → WelcomeInfo (or Refused + NextStep)
//! list / acquire / submit_* / …      → Outgoing{id, frame} ── send
//! on_frame(frame, now)               → [ClientEvent]
//! ```
//!
//! Any error from a channel step means: close the transport (the object is
//! then `Closed`). A refused hello carries the next step (reconnect with
//! `need_before`, wait for a recovery, retry later, or stop).
use std::sync::{Arc, Mutex, MutexGuard};

use atem_client::SignedObject;
use atem_client::connect::{
    Attached, AwaitWelcome, Connecting, Connector, Event, Identity, NextStep as CoreNextStep,
    PendingSignature,
};
use atem_client::provider::{KeyId, KeyProvider};
use atem_client::session::r9::{PendingRecovery, SessionError, Welcome};
use atem_client::session::wire::{self, Envelope, ReceiptKind};
use serde_json::{Value, json};

use crate::encoding::{canonical, not_attached, signed, strict};
use crate::error::{AtemError, Result};
use crate::log::{MembershipLog, objects_of};
use crate::provider::sign_request;
use crate::types::{
    ApprovalChoice, ClientEvent, ClientIdentity, ConnectionState, LeaseInfo, LogHead, NextStep,
    Outgoing, PendingRecoveryInfo, PrincipalKind, PublicKeyData, SessionInfo, SignRequest,
    WelcomeInfo,
};

impl From<&CoreNextStep> for NextStep {
    fn from(n: &CoreNextStep) -> Self {
        match n {
            CoreNextStep::Reconnect { need_before } => NextStep::Reconnect {
                need_before: *need_before,
            },
            CoreNextStep::WaitForRecovery {
                entry_hash,
                effective_at,
            } => NextStep::WaitForRecovery {
                entry_hash: entry_hash.to_hex(),
                effective_at: *effective_at,
            },
            CoreNextStep::RetryLater => NextStep::RetryLater,
            CoreNextStep::Stop => NextStep::Stop,
        }
    }
}

fn pending_info(p: &PendingRecovery) -> PendingRecoveryInfo {
    PendingRecoveryInfo {
        entry_hash: p.entry_hash.to_hex(),
        seq: p.seq,
        action: p.action.clone(),
        subject: p.subject.clone(),
        effective_at: p.effective_at,
    }
}

fn welcome_info(w: &Welcome) -> WelcomeInfo {
    WelcomeInfo {
        principal: w.principal.clone(),
        client_kind: w.client_kind.as_str().into(),
        permissions: w.permissions.iter().map(|p| p.as_str().into()).collect(),
        revision: w.revision,
        features: w.features.clone(),
        account_id: w.account_id.clone(),
        atem_device_id: w.atem_device_id.clone(),
        host_trust_gen: w.host_trust_gen,
        attachment_gen: w.attachment_gen.clone(),
        controller_session: w.controller_session.clone(),
        runtime_gen: w.runtime_gen.clone(),
        authorization_ms_left: w.authorization_ms_left,
        server_time: w.server_time,
        head: w.head.into(),
        pending_recovery: w.pending_recovery.iter().map(pending_info).collect(),
        channel_id: w.channel_id.clone(),
        scope_json: w.scope.as_ref().map(|s| canonical(&s.to_json())),
        json: canonical(&w.to_json()),
    }
}

/// `StaleEpoch` → `stale_epoch` (the outcome names are the machines' own).
fn snake(debug: &str) -> String {
    let name = debug.split(['(', ' ', '{']).next().unwrap_or(debug);
    let mut out = String::new();
    for (i, c) in name.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i > 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

fn error_event(e: &SessionError, fenced: bool) -> ClientEvent {
    let json = canonical(&e.to_json());
    if fenced {
        ClientEvent::Fenced {
            code: e.code.clone(),
            detail: e.detail.clone(),
            json,
        }
    } else {
        ClientEvent::Error {
            code: e.code.clone(),
            re: e.re.clone(),
            detail: e.detail.clone(),
            json,
        }
    }
}

fn event_info(event: Event) -> ClientEvent {
    match event {
        Event::Session(msg) => {
            let value = wire::to_value(&Envelope::Session(msg.clone()));
            ClientEvent::Session {
                op: value["data"]["op"].as_str().unwrap_or_default().into(),
                id: msg.id,
                re: msg.re,
                json: canonical(&value),
            }
        }
        Event::Registry(outcome) => ClientEvent::Registry {
            outcome: snake(&format!("{outcome:?}")),
        },
        Event::Lease {
            session_id,
            outcome,
        } => ClientEvent::Lease {
            session_id,
            outcome: snake(&format!("{outcome:?}")),
        },
        Event::Family(family) => {
            let op = family
                .data
                .as_ref()
                .and_then(|d| d["op"].as_str())
                .map(str::to_owned);
            let name = family.family.clone();
            ClientEvent::Family {
                family: name,
                op,
                json: canonical(&wire::to_value(&Envelope::Family(family))),
            }
        }
        Event::Outgoing(frame) => ClientEvent::Outgoing { frame },
        Event::MembershipHead {
            re,
            head,
            pending_recovery,
        } => ClientEvent::MembershipHead {
            re,
            head: head.into(),
            pending_recovery: pending_recovery.iter().map(pending_info).collect(),
        },
        Event::GrantRevoked { re } => ClientEvent::GrantRevoked { re },
        Event::Seen { re } => ClientEvent::Seen { re },
        Event::Error(e) => error_event(&e, false),
        Event::Fenced(e) => error_event(&e, true),
    }
}

enum Phase {
    New,
    AwaitAccept(Box<Connecting>),
    AwaitSignature(Box<PendingSignature>),
    AwaitWelcome(Box<AwaitWelcome>),
    Attached(Box<Attached>),
    Closed,
}

struct Inner {
    phase: Phase,
    host_id: String,
    identity: Identity,
    need_before: Option<u64>,
}

impl Inner {
    fn take(&mut self) -> Phase {
        std::mem::replace(&mut self.phase, Phase::Closed)
    }

    fn attached(&mut self) -> Result<&mut Attached> {
        match &mut self.phase {
            Phase::Attached(a) if !a.is_closed() => Ok(a),
            Phase::Attached(_) => Err(AtemError::Channel {
                code: "closed".into(),
                detail: "the channel is closed".into(),
            }),
            _ => Err(not_attached()),
        }
    }

    /// A failed channel call closes the object (the app closes the
    /// transport).
    fn on_err<T>(
        &mut self,
        r: std::result::Result<T, atem_client::connect::ConnectError>,
    ) -> Result<T> {
        r.map_err(|e| {
            if matches!(
                e,
                atem_client::connect::ConnectError::Channel(_)
                    | atem_client::connect::ConnectError::Malformed(_)
            ) {
                if let Phase::Attached(a) = &mut self.phase {
                    a.close();
                }
                self.phase = Phase::Closed;
            }
            e.into()
        })
    }
}

fn identity_of(i: &ClientIdentity) -> Result<Identity> {
    let key = KeyId::new(i.key_id.clone());
    let device = || {
        i.device_id
            .clone()
            .ok_or_else(|| AtemError::malformed("a native or service identity names its device_id"))
    };
    match i.kind {
        PrincipalKind::Native => Ok(Identity::native(&device()?, key)),
        PrincipalKind::Service => Ok(Identity::service(&device()?, key)),
        PrincipalKind::Browser => {
            let grant = i
                .grant_json
                .as_deref()
                .ok_or_else(|| AtemError::malformed("a browser identity carries its grant"))?;
            Ok(Identity::browser(signed(grant)?, key)?)
        }
    }
}

/// A connection to one host (see the module docs for the order of calls).
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct ClientConnection {
    inner: Mutex<Inner>,
}

impl ClientConnection {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(crate) fn on_accept_with(
        &self,
        frame: &[u8],
        log: &MembershipLog,
        provider: &dyn KeyProvider,
        now_ms: u64,
    ) -> Result<Vec<u8>> {
        let mut inner = self.lock();
        if !matches!(inner.phase, Phase::AwaitAccept(_)) {
            return Err(AtemError::state("not waiting for accept"));
        }
        let Phase::AwaitAccept(connecting) = inner.take() else {
            unreachable!("checked above");
        };
        let identity = inner.identity.clone();
        let r = connecting.on_accept(frame, &log.lock(), provider, &identity, now_ms);
        let (await_welcome, finish) = inner.on_err(r)?;
        inner.phase = Phase::AwaitWelcome(Box::new(await_welcome));
        Ok(finish)
    }

    fn request(
        &self,
        f: impl FnOnce(
            &mut Attached,
        )
            -> std::result::Result<(String, Vec<u8>), atem_client::connect::ConnectError>,
    ) -> Result<Outgoing> {
        let mut inner = self.lock();
        let attached = inner.attached()?;
        let r = f(attached);
        let (id, frame) = inner.on_err(r)?;
        Ok(Outgoing { id, frame })
    }

    /// A read binding (no `lease_epoch`: subscribe, open, history), or a
    /// mutation binding (the held lease's epoch: terminal input, resize).
    fn binding_value(
        attached: &Attached,
        session_id: &str,
        mutation: bool,
        now_ms: u64,
    ) -> Result<Value> {
        let mut binding = attached
            .binding(session_id, now_ms)
            .ok_or_else(|| AtemError::request("unknown session"))?;
        if !mutation {
            binding.lease_epoch = None;
        } else if binding.lease_epoch.is_none() {
            return Err(AtemError::request("no lease"));
        }
        Ok(serde_json::to_value(binding).expect("a binding serializes"))
    }

    fn family(
        &self,
        build: impl FnOnce(&mut Attached) -> Result<Value>,
        now_ms: u64,
    ) -> Result<Outgoing> {
        let mut inner = self.lock();
        let attached = inner.attached()?;
        let message = build(attached)?;
        let id = message["data"]["id"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let r = attached.send(&message, now_ms);
        let frame = inner.on_err(r)?;
        Ok(Outgoing { id, frame })
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl ClientConnection {
    /// A connection to `host_id` as `identity`. After a refusal with
    /// `NextStep::Reconnect{need_before}`, pass that `need_before` to the
    /// next connection.
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn new(
        host_id: String,
        identity: ClientIdentity,
        need_before: Option<u64>,
    ) -> Result<Arc<Self>> {
        Ok(Arc::new(ClientConnection {
            inner: Mutex::new(Inner {
                phase: Phase::New,
                host_id,
                identity: identity_of(&identity)?,
                need_before,
            }),
        }))
    }

    pub fn state(&self) -> ConnectionState {
        match &self.lock().phase {
            Phase::New => ConnectionState::New,
            Phase::AwaitAccept(_) => ConnectionState::AwaitAccept,
            Phase::AwaitSignature(_) => ConnectionState::AwaitSignature,
            Phase::AwaitWelcome(_) => ConnectionState::AwaitWelcome,
            Phase::Attached(a) if !a.is_closed() => ConnectionState::Attached,
            _ => ConnectionState::Closed,
        }
    }

    /// §R9.7 step 1: the `init` frame (refused, nothing to send, unless the
    /// host is current in `log`).
    pub fn start(&self, log: Arc<MembershipLog>, now_ms: u64) -> Result<Vec<u8>> {
        let mut inner = self.lock();
        if !matches!(inner.phase, Phase::New) {
            return Err(AtemError::state("already started"));
        }
        let connector = Connector::after(
            &inner.host_id,
            &CoreNextStep::Reconnect {
                need_before: inner.need_before,
            },
        );
        let r = connector.start(&log.lock(), now_ms);
        let (connecting, init) = inner.on_err(r)?;
        inner.phase = Phase::AwaitAccept(Box::new(connecting));
        Ok(init)
    }

    /// When the handshake gives up waiting for `accept`.
    pub fn accept_deadline_ms(&self) -> Option<u64> {
        match &self.lock().phase {
            Phase::AwaitAccept(c) => Some(c.deadline_ms()),
            _ => None,
        }
    }

    /// For a signer that answers later (WebCrypto, an owner-auth prompt
    /// handled by the app): verifies `accept`, plans the carriage and
    /// returns what to sign. Answer with `finish_with_signature` within the
    /// 10 s handshake step.
    pub fn on_accept_deferred(
        &self,
        frame: Vec<u8>,
        log: Arc<MembershipLog>,
        now_ms: u64,
    ) -> Result<SignRequest> {
        let mut inner = self.lock();
        if !matches!(inner.phase, Phase::AwaitAccept(_)) {
            return Err(AtemError::state("not waiting for accept"));
        }
        let Phase::AwaitAccept(connecting) = inner.take() else {
            unreachable!("checked above");
        };
        let identity = inner.identity.clone();
        let r = connecting.on_accept_unsigned(&frame, &log.lock(), &identity, now_ms);
        let pending = inner.on_err(r)?;
        let request = sign_request(pending.key(), pending.signing_input());
        inner.phase = Phase::AwaitSignature(Box::new(pending));
        Ok(request)
    }

    /// The signature for `on_accept_deferred`'s request, by the identity's
    /// key (`public_key`): verified before use. Returns the `finish` frame.
    pub fn finish_with_signature(
        &self,
        public_key: PublicKeyData,
        signature: Vec<u8>,
        now_ms: u64,
    ) -> Result<Vec<u8>> {
        let mut inner = self.lock();
        if !matches!(inner.phase, Phase::AwaitSignature(_)) {
            return Err(AtemError::state("no signature pending"));
        }
        let public = public_key.to_key()?;
        let Phase::AwaitSignature(pending) = inner.take() else {
            unreachable!("checked above");
        };
        let r = pending.finish(&public, &signature, now_ms);
        let (await_welcome, finish) = inner.on_err(r)?;
        inner.phase = Phase::AwaitWelcome(Box::new(await_welcome));
        Ok(finish)
    }

    /// The host's first record: the welcome (checked against what this
    /// client verified) or its refusal (`AtemError::Refused` with the next
    /// step).
    pub fn on_welcome(
        &self,
        frame: Vec<u8>,
        log: Arc<MembershipLog>,
        now_ms: u64,
    ) -> Result<WelcomeInfo> {
        let mut inner = self.lock();
        if !matches!(inner.phase, Phase::AwaitWelcome(_)) {
            return Err(AtemError::state("not waiting for the welcome"));
        }
        let Phase::AwaitWelcome(await_welcome) = inner.take() else {
            unreachable!("checked above");
        };
        let attached = await_welcome
            .on_frame(&frame, &log.lock(), now_ms)
            .map_err(AtemError::from)?;
        let info = welcome_info(attached.welcome());
        inner.phase = Phase::Attached(Box::new(attached));
        Ok(info)
    }

    pub fn welcome(&self) -> Option<WelcomeInfo> {
        match &self.lock().phase {
            Phase::Attached(a) => Some(welcome_info(a.welcome())),
            _ => None,
        }
    }

    /// The host's head as last told (welcome, then `membership_head`).
    pub fn head(&self) -> Option<LogHead> {
        match &self.lock().phase {
            Phase::Attached(a) => Some(a.head().into()),
            _ => None,
        }
    }

    /// What is pending on the host (show it with approve/cancel).
    pub fn pending_recovery(&self) -> Vec<PendingRecoveryInfo> {
        match &self.lock().phase {
            Phase::Attached(a) => a.pending_recovery().iter().map(pending_info).collect(),
            _ => Vec::new(),
        }
    }

    /// The host's head when it is beyond (or off) `log`: fetch from the
    /// relay and `extend` the log; the head is never adopted unverified.
    pub fn fetch_to(&self, log: Arc<MembershipLog>) -> Option<LogHead> {
        match &self.lock().phase {
            Phase::Attached(a) => a.fetch_to(&log.lock()).map(Into::into),
            _ => None,
        }
    }

    pub fn is_closed(&self) -> bool {
        matches!(self.state(), ConnectionState::Closed)
    }

    /// Closes the channel (keys wiped); close the transport too. (Named
    /// `disconnect`: `close` is the generated objects' `AutoCloseable`.)
    pub fn disconnect(&self) {
        let mut inner = self.lock();
        if let Phase::Attached(a) = &mut inner.phase {
            a.close();
        }
        inner.phase = Phase::Closed;
    }

    /// Opens one record and runs it through the machines. An error closes
    /// the channel.
    pub fn on_frame(&self, frame: Vec<u8>, now_ms: u64) -> Result<Vec<ClientEvent>> {
        let mut inner = self.lock();
        let attached = inner.attached()?;
        let r = attached.on_frame(&frame, now_ms);
        let events = inner.on_err(r)?;
        Ok(events.into_iter().map(event_info).collect())
    }

    /// The registry's sessions (after `list`).
    pub fn sessions(&self) -> Vec<SessionInfo> {
        let inner = self.lock();
        let Phase::Attached(a) = &inner.phase else {
            return Vec::new();
        };
        a.registry()
            .sessions()
            .map(|d| {
                let value = serde_json::to_value(d).expect("a descriptor serializes");
                SessionInfo {
                    session_id: d.session_id.clone(),
                    process_gen: d.process_gen.clone(),
                    provider: d.provider.clone(),
                    cwd_label: d.cwd_label.clone(),
                    state: value["state"].as_str().unwrap_or_default().into(),
                    activity: value["activity"].as_str().unwrap_or_default().into(),
                    controller_session: d.controller.as_ref().map(|c| c.controller_session.clone()),
                    lease_epoch: d.controller.as_ref().map(|c| c.lease_epoch),
                    capabilities: d.capabilities.clone(),
                    json: canonical(&value),
                }
            })
            .collect()
    }

    /// This attachment's lease on a session (none before an `acquire` or a
    /// Send).
    pub fn lease(&self, session_id: String, now_ms: u64) -> Option<LeaseInfo> {
        let inner = self.lock();
        let Phase::Attached(a) = &inner.phase else {
            return None;
        };
        a.lease(&session_id).map(|l| LeaseInfo {
            controls: l.controls(now_ms),
            input_enabled: l.input_enabled(now_ms),
            lease_epoch: l.lease_epoch(),
            deadline_ms: l.deadline_ms(now_ms),
        })
    }

    /// The session's binding for terminal-v1/chat-v1 messages the app
    /// builds: a read binding (`mutation` false: subscribe, open, history,
    /// ack), or a mutation binding carrying the held lease's epoch
    /// (`mutation` true: terminal input, resize; none without the lease).
    pub fn binding_json(&self, session_id: String, mutation: bool, now_ms: u64) -> Option<String> {
        let inner = self.lock();
        let Phase::Attached(a) = &inner.phase else {
            return None;
        };
        Self::binding_value(a, &session_id, mutation, now_ms)
            .ok()
            .map(|b| canonical(&b))
    }

    /// `list`: the registry snapshot (and subscribes to changes).
    pub fn list(&self, now_ms: u64) -> Result<Outgoing> {
        self.request(|a| a.list(now_ms))
    }

    /// `acquire` (`takeover` only after the user confirmed taking over).
    pub fn acquire(&self, session_id: String, takeover: bool, now_ms: u64) -> Result<Outgoing> {
        self.request(|a| a.acquire(&session_id, takeover, now_ms))
    }

    /// `renew`: every 5 s while controlling.
    pub fn renew(&self, session_id: String, now_ms: u64) -> Result<Outgoing> {
        self.request(|a| a.renew(&session_id, now_ms))
    }

    pub fn release(&self, session_id: String, now_ms: u64) -> Result<Outgoing> {
        self.request(|a| a.release(&session_id, now_ms))
    }

    /// A prompt: under the held lease, or with Send `acquire` when none is
    /// held (r8 §F). `request_id` is a UUID v4 the app keeps for
    /// `receipt_query`.
    pub fn submit_prompt(
        &self,
        session_id: String,
        request_id: String,
        text: String,
        now_ms: u64,
    ) -> Result<Outgoing> {
        self.request(|a| a.submit_prompt(&session_id, &request_id, &text, now_ms))
    }

    /// `interrupt` (needs the lease).
    pub fn submit_interrupt(
        &self,
        session_id: String,
        request_id: String,
        now_ms: u64,
    ) -> Result<Outgoing> {
        self.request(|a| {
            a.submit(
                &session_id,
                ReceiptKind::Interrupt,
                &request_id,
                json!({}),
                now_ms,
            )
        })
    }

    /// `stop` (needs the lease).
    pub fn submit_stop(
        &self,
        session_id: String,
        request_id: String,
        now_ms: u64,
    ) -> Result<Outgoing> {
        self.request(|a| {
            a.submit(
                &session_id,
                ReceiptKind::Stop,
                &request_id,
                json!({}),
                now_ms,
            )
        })
    }

    /// An approval answer (no lease, r8 §G): `rule_id` only with
    /// `AllowAlways`, `message` only with `Deny`.
    #[allow(clippy::too_many_arguments)]
    pub fn submit_approval(
        &self,
        session_id: String,
        request_id: String,
        approval_id: String,
        decision: ApprovalChoice,
        rule_id: Option<String>,
        message: Option<String>,
        now_ms: u64,
    ) -> Result<Outgoing> {
        let mut payload = json!({
            "approval_id": approval_id,
            "decision": match decision {
                ApprovalChoice::AllowOnce => "allow_once",
                ApprovalChoice::AllowAlways => "allow_always",
                ApprovalChoice::Deny => "deny",
            },
        });
        if let Some(rule_id) = rule_id {
            payload["rule_id"] = json!(rule_id);
        }
        if let Some(message) = message {
            payload["message"] = json!(message);
        }
        wire::ApprovalAnswer::parse(&payload).map_err(|e| AtemError::malformed(&e))?;
        self.request(|a| {
            a.submit(
                &session_id,
                ReceiptKind::Approval,
                &request_id,
                payload,
                now_ms,
            )
        })
    }

    /// Revokes one of the session's Atem session rules (no lease, r7.3).
    pub fn submit_rule_revoke(
        &self,
        session_id: String,
        request_id: String,
        rule_id: String,
        now_ms: u64,
    ) -> Result<Outgoing> {
        self.request(|a| {
            a.submit(
                &session_id,
                ReceiptKind::ApprovalRuleRevoke,
                &request_id,
                json!({ "rule_id": rule_id }),
                now_ms,
            )
        })
    }

    /// `receipt_query` (after a reconnect: what became of these requests).
    pub fn receipt_query(
        &self,
        session_id: String,
        request_ids: Vec<String>,
        now_ms: u64,
    ) -> Result<Outgoing> {
        self.request(|a| a.receipt_query(&session_id, &request_ids, now_ms))
    }

    /// `approval_seen` (§R9.9): only when the card was rendered in a
    /// focused foreground window and the user was active in the last 60 s;
    /// never from a background delivery or a notification.
    pub fn approval_seen(
        &self,
        session_id: String,
        approval_id: String,
        now_ms: u64,
    ) -> Result<Outgoing> {
        self.request(|a| a.approval_seen(&session_id, &approval_id, now_ms))
    }

    /// `revoke_grant` (a browser grant's issuer, or a member with control).
    pub fn revoke_grant(&self, grant_id: String, now_ms: u64) -> Result<Outgoing> {
        self.request(|a| a.revoke_grant(&grant_id, now_ms))
    }

    /// `membership{entries}`: entries carried on the open channel (a new
    /// entry, a veto); the host answers `membership_head`.
    pub fn send_membership(&self, entries: Vec<String>, now_ms: u64) -> Result<Outgoing> {
        let objects: Vec<SignedObject> = objects_of(&entries)?;
        self.request(|a| a.send_membership(&objects, now_ms))
    }

    /// terminal-v1 `subscribe` to a session's canonical screen.
    pub fn terminal_subscribe(&self, session_id: String, now_ms: u64) -> Result<Outgoing> {
        self.family(
            |a| {
                let binding = Self::binding_value(a, &session_id, false, now_ms)?;
                let generation = binding["target"]["process_gen"].clone();
                Ok(json!({"type": "terminal", "data": {
                    "v": 1, "op": "subscribe", "terminal_id": session_id,
                    "generation": generation, "binding": binding}}))
            },
            now_ms,
        )
    }

    /// chat-v1 `open` of a conversation on a session (the machines track
    /// its ordering and resync).
    pub fn chat_open(
        &self,
        session_id: String,
        conversation_id: String,
        now_ms: u64,
    ) -> Result<Outgoing> {
        self.family(
            |a| {
                let binding = Self::binding_value(a, &session_id, false, now_ms)?;
                a.chat_mut().open(&conversation_id, &session_id);
                Ok(json!({"type": "agentChat", "data": {
                    "v": 1, "op": "open", "conversationId": conversation_id,
                    "agentId": session_id, "binding": binding}}))
            },
            now_ms,
        )
    }

    /// Any other session-family message the app built (terminal-v1 input,
    /// chat-v1 history, …), sealed as one record.
    pub fn send_json(&self, message_json: String, now_ms: u64) -> Result<Vec<u8>> {
        let message = strict(&message_json)?;
        let mut inner = self.lock();
        let attached = inner.attached()?;
        let r = attached.send(&message, now_ms);
        inner.on_err(r)
    }
}

#[cfg(feature = "uniffi")]
#[uniffi::export]
impl ClientConnection {
    /// Verifies `accept` (`sig_h` with the host key from the log), plans the
    /// carriage, has the provider sign `sig_c` (purpose `Channel`) and
    /// builds the hello. Returns the `finish` frame.
    pub fn on_accept(
        &self,
        frame: Vec<u8>,
        log: Arc<MembershipLog>,
        provider: Arc<dyn crate::provider::AppKeyProvider>,
        now_ms: u64,
    ) -> Result<Vec<u8>> {
        self.on_accept_with(&frame, &log, &crate::provider::Platform(provider), now_ms)
    }
}
