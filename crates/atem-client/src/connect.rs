//! The r9 client connection (§R9.7, §R9.8): a phone, a desktop, a bot or a
//! browser reaches a host through `atem-ch1` and gets welcomed, then runs
//! r8's session-v1 client machines inside the channel.
//!
//! ```text
//! Connector::start ── init ─────────────▶ host
//! Connecting::on_accept ◀── accept ─────── (sig_h verified, head related to the log)
//!   carriage planned (§R9.3), sig_c signed, hello built by the crate
//!                    ── finish(hello) ──▶
//! AwaitWelcome::on_frame ◀── rec 0 ─────── welcome | session error
//! Attached: list / acquire / submit / receipt_query / approval_seen /
//!           revoke_grant / membership, and on_frame → events
//! ```
//!
//! Sans-I/O like the channel: the caller moves frames, passes the monotonic
//! time and closes the transport when a call fails. The client never adopts
//! the host's head: `accept`'s head and `welcome.head` are verified (by
//! `sig_h` and by the channel keys that bind it) and only *related* to the
//! client's log; a head beyond it is a reason to fetch from the relay and
//! verify ([`Attached::fetch_to`]). A `welcome` that contradicts what the
//! client verified (another revision, channel, principal or kind, a head
//! behind the signed `accept`, or another entry at a seq the client holds
//! on the same chain) is refused and the channel dropped.
use std::collections::{BTreeMap, HashMap};

use serde_json::{Value, json};

use crate::SignedObject;
use crate::channel::carriage::{Carriage, CarryError, HeadRelation};
use crate::channel::{
    Accepted, AwaitAccept, Channel, ChannelError, HostHead, Initiator, NATIVE_LIFETIME_MS,
    Principal, Signed,
};
use crate::domain::SigningInput;
use crate::error::Error;
use crate::keys::PublicKey;
use crate::membership::{Head, Membership};
use crate::principal::{BrowserGrant, ClientKind};
use crate::provider::{KeyId, KeyProvider};
use crate::session::client::{
    ChatClient, LeaseClient, LeaseRequest, RegistryClient, RegistryOutcome, ReplyOutcome,
    RequestRefused,
};
use crate::session::new_id;
use crate::session::r9::{Incoming, PendingRecovery, REVISION, SessionError, Welcome, code};
use crate::session::wire::{
    self, Binding, Envelope, FamilyMessage, Op, ReceiptKind, SessionMessage, Target,
};

/// Who connects, and with which key (behind the platform's provider).
#[derive(Debug, Clone)]
pub struct Identity {
    pub principal: Principal,
    pub key: KeyId,
    /// A browser's signed grant.
    pub grant: Option<SignedObject>,
}

impl Identity {
    /// A native member (`auth_key`).
    pub fn native(device_id: &str, key: KeyId) -> Self {
        Identity {
            principal: Principal::Native {
                device_id: device_id.into(),
            },
            key,
            grant: None,
        }
    }

    /// A service (bot) with its software `auth_key`.
    pub fn service(device_id: &str, key: KeyId) -> Self {
        Identity {
            principal: Principal::Service {
                device_id: device_id.into(),
            },
            key,
            grant: None,
        }
    }

    /// A browser with the grant it was given and its `browser_key`. The
    /// grant must parse strictly; its authority is the host's to judge.
    pub fn browser(grant: SignedObject, key: KeyId) -> Result<Self, Error> {
        let parsed = BrowserGrant::parse(grant.clone())?;
        Ok(Identity {
            principal: parsed.principal(),
            key,
            grant: Some(grant),
        })
    }
}

/// What the client should do after a refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NextStep {
    /// Reconnect (a new handshake); for `membership_invalid` with
    /// `need_before`, with [`Connector::after`] so the next carriage is the
    /// earlier window; for `membership_incomplete`, the next window comes
    /// from the host's newer head on its own.
    Reconnect { need_before: Option<u64> },
    /// `recovery_pending`: this device is the subject of a pending recovery
    /// (or added behind one): show it, retry after `effective_at`.
    WaitForRecovery {
        entry_hash: crate::Hash32,
        effective_at: u64,
    },
    /// `busy`: retry later.
    RetryLater,
    /// Anything else (`unauthorized`, `account_frozen`, a bad `sig_c`,
    /// `unsupported_version`, …): show the error, don't loop.
    Stop,
}

impl NextStep {
    fn of(error: &SessionError) -> NextStep {
        match error.code.as_str() {
            code::MEMBERSHIP_INVALID if error.need_before.is_some() => NextStep::Reconnect {
                need_before: error.need_before,
            },
            code::MEMBERSHIP_INCOMPLETE => NextStep::Reconnect { need_before: None },
            code::RECOVERY_PENDING => match (error.entry_hash, error.effective_at) {
                (Some(entry_hash), Some(effective_at)) => NextStep::WaitForRecovery {
                    entry_hash,
                    effective_at,
                },
                _ => NextStep::Stop,
            },
            code::BUSY => NextStep::RetryLater,
            _ => NextStep::Stop,
        }
    }
}

/// Why a connection ended.
#[derive(Debug, Clone, PartialEq)]
pub enum ConnectError {
    /// The channel failed (handshake, a record, a limit, a clear advisory
    /// error, a host missing from the log, a local signing failure).
    Channel(ChannelError),
    /// The client can't carry the window the host asked for.
    Carry(CarryError),
    /// The host's encrypted refusal (its first record), and what to do.
    Refused {
        error: Box<SessionError>,
        next: NextStep,
    },
    /// A `welcome` that contradicts what the client verified; the channel
    /// is dropped (detail names the check).
    BadWelcome(&'static str),
    /// A record that isn't a readable message.
    Malformed(&'static str),
    /// A request this attachment can't make (no such session, no lease,
    /// too many in flight).
    Request(&'static str),
}

impl From<ChannelError> for ConnectError {
    fn from(e: ChannelError) -> Self {
        ConnectError::Channel(e)
    }
}

/// Starts connections to one host.
#[derive(Debug, Clone)]
pub struct Connector {
    host_id: String,
    need_before: Option<u64>,
}

impl Connector {
    pub fn new(host_id: &str) -> Self {
        Connector {
            host_id: host_id.into(),
            need_before: None,
        }
    }

    /// The reconnect after a refusal: carries the earlier window the host
    /// asked for (`NextStep::Reconnect`).
    pub fn after(host_id: &str, next: &NextStep) -> Self {
        Connector {
            host_id: host_id.into(),
            need_before: match next {
                NextStep::Reconnect { need_before } => *need_before,
                _ => None,
            },
        }
    }

    /// §R9.7 step 1: refuses (nothing sent) unless the host is current in
    /// the client's verified log. Returns the `init` frame to send.
    pub fn start(
        &self,
        log: &Membership,
        now_ms: u64,
    ) -> Result<(Connecting, Vec<u8>), ConnectError> {
        let (state, init) = Initiator::start(log, &self.host_id, now_ms)?;
        Ok((
            Connecting {
                state,
                need_before: self.need_before,
            },
            init,
        ))
    }
}

/// `init` sent.
#[derive(Debug)]
pub struct Connecting {
    state: AwaitAccept,
    need_before: Option<u64>,
}

impl Connecting {
    /// The client gives up on `accept` at this time.
    pub fn deadline_ms(&self) -> u64 {
        self.state.deadline_ms()
    }

    /// Verifies `accept` (`sig_h` with the pinned host key), plans the
    /// carriage against the signed head, signs `sig_c` through `provider`
    /// (owner confirmation is the provider's) and builds the `hello`.
    /// Returns the `finish` frame to send.
    pub fn on_accept(
        self,
        frame: &[u8],
        log: &Membership,
        provider: &dyn KeyProvider,
        identity: &Identity,
        now_ms: u64,
    ) -> Result<(AwaitWelcome, Vec<u8>), ConnectError> {
        self.on_accept_unsigned(frame, log, identity, now_ms)?
            .sign(provider, now_ms)
    }

    /// [`Connecting::on_accept`] for a signer that answers later (signing
    /// as an effect: WebCrypto's promise, an owner-auth prompt): verifies
    /// `accept` and plans the carriage, then stops at `sig_c`. The caller
    /// signs [`PendingSignature::signing_input`] with the identity's key
    /// and calls [`PendingSignature::finish`] (within the 10 s handshake
    /// step).
    pub fn on_accept_unsigned(
        self,
        frame: &[u8],
        log: &Membership,
        identity: &Identity,
        now_ms: u64,
    ) -> Result<PendingSignature, ConnectError> {
        let host_trust_gen = self.state.init().host_trust_gen;
        let accepted = self.state.on_frame(frame, log, now_ms)?;
        let host_head = accepted.host_head().clone();
        let relation = accepted.relation();
        let carriage =
            Carriage::plan(log, host_head.head(), self.need_before).map_err(ConnectError::Carry)?;
        let input = accepted.signing_input(&identity.principal);
        Ok(PendingSignature {
            accepted,
            identity: identity.clone(),
            input,
            host_head,
            host_trust_gen,
            relation,
            carriage,
        })
    }
}

/// `accept` verified and the carriage planned; `sig_c` not made yet.
pub struct PendingSignature {
    accepted: Accepted,
    identity: Identity,
    input: SigningInput,
    host_head: HostHead,
    host_trust_gen: u64,
    relation: HeadRelation,
    carriage: Carriage,
}

impl PendingSignature {
    /// Exactly what the identity's key signs (`enc(["atem-ch1-client-sig-v1",
    /// th3])`; P-256 over SHA-256 of these bytes, Ed25519 over them).
    pub fn signing_input(&self) -> &SigningInput {
        &self.input
    }

    /// The key that must sign (the identity's).
    pub fn key(&self) -> &KeyId {
        &self.identity.key
    }

    /// What the `hello` will carry.
    pub fn carriage(&self) -> &Carriage {
        &self.carriage
    }

    /// Signs through `provider` and builds the `finish`.
    pub fn sign(
        self,
        provider: &dyn KeyProvider,
        now_ms: u64,
    ) -> Result<(AwaitWelcome, Vec<u8>), ConnectError> {
        let signed = self.accepted.sign(
            self.identity.principal.clone(),
            provider,
            &self.identity.key,
        )?;
        Self::hello(
            signed,
            self.identity,
            self.host_head,
            self.host_trust_gen,
            self.relation,
            self.carriage,
            now_ms,
        )
    }

    /// Builds the `finish` around a signature made elsewhere over
    /// [`PendingSignature::signing_input`]. `public` is the identity's
    /// public key: the signature (P-256 normalized to low S) must verify
    /// with it, else `ConnectError::Channel(Signing)` and nothing is sent.
    pub fn finish(
        self,
        public: &PublicKey,
        sig: &[u8],
        now_ms: u64,
    ) -> Result<(AwaitWelcome, Vec<u8>), ConnectError> {
        let signed = self
            .accepted
            .signed_with(self.identity.principal.clone(), public, sig)?;
        Self::hello(
            signed,
            self.identity,
            self.host_head,
            self.host_trust_gen,
            self.relation,
            self.carriage,
            now_ms,
        )
    }

    fn hello(
        signed: Signed,
        identity: Identity,
        host_head: HostHead,
        host_trust_gen: u64,
        relation: HeadRelation,
        carriage: Carriage,
        now_ms: u64,
    ) -> Result<(AwaitWelcome, Vec<u8>), ConnectError> {
        let id = new_id();
        let (channel, finish) =
            signed.finish_hello(&id, &carriage, identity.grant.as_ref(), now_ms)?;
        Ok((
            AwaitWelcome {
                channel,
                hello_id: id,
                principal: identity.principal,
                host_head,
                host_trust_gen,
                relation,
                carriage,
            },
            finish,
        ))
    }
}

impl std::fmt::Debug for PendingSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingSignature").finish_non_exhaustive()
    }
}

/// `finish` sent; the host's first record is the `welcome` or a refusal.
pub struct AwaitWelcome {
    channel: Channel,
    hello_id: String,
    principal: Principal,
    host_head: HostHead,
    /// The trust generation the `init` named and `sig_h` covered.
    host_trust_gen: u64,
    relation: HeadRelation,
    carriage: Carriage,
}

impl AwaitWelcome {
    /// What the `hello` carried.
    pub fn carriage(&self) -> &Carriage {
        &self.carriage
    }

    /// The `accept` head, verified with the host key (never adopted).
    pub fn host_head(&self) -> &HostHead {
        &self.host_head
    }

    /// Opens the first record: the `welcome` (checked, then the attachment)
    /// or the host's refusal (`ConnectError::Refused` with the next step).
    pub fn on_frame(
        mut self,
        frame: &[u8],
        log: &Membership,
        now_ms: u64,
    ) -> Result<Attached, ConnectError> {
        let plain = self.channel.open(frame, now_ms)?;
        let welcome = match Incoming::parse(&plain).map_err(ConnectError::Malformed)? {
            Incoming::Welcome(w) => *w,
            Incoming::Error(error) => {
                self.channel.close();
                let next = NextStep::of(&error);
                return Err(ConnectError::Refused {
                    error: Box::new(error),
                    next,
                });
            }
            _ => {
                self.channel.close();
                return Err(ConnectError::Malformed("the first record is not a welcome"));
            }
        };
        if let Err(why) = self.check(&welcome, log) {
            self.channel.close();
            return Err(ConnectError::BadWelcome(why));
        }
        let lifetime = welcome.authorization_ms_left.min(NATIVE_LIFETIME_MS);
        self.channel.limit_lifetime(now_ms + lifetime);
        let mut attached = Attached {
            channel: self.channel,
            authorization_deadline: now_ms + lifetime,
            head: welcome.head,
            pending_recovery: welcome.pending_recovery.clone(),
            welcome,
            host_head: self.host_head,
            carriage: self.carriage,
            registry: RegistryClient::default(),
            chat: ChatClient::default(),
            leases: BTreeMap::new(),
            outstanding: HashMap::new(),
        };
        attached.registry.new_attachment();
        Ok(attached)
    }

    /// The welcome against what this client verified and sent.
    fn check(&self, welcome: &Welcome, log: &Membership) -> Result<(), &'static str> {
        if welcome.revision != REVISION {
            return Err("revision");
        }
        if welcome.re.as_deref() != Some(self.hello_id.as_str()) {
            return Err("re");
        }
        if welcome.channel_id != self.channel.channel_id() {
            return Err("channel_id");
        }
        if welcome.principal != self.principal.name()
            || welcome.client_kind != ClientKind::of(&self.principal)
        {
            return Err("principal");
        }
        if welcome.account_id != log.account_id() {
            return Err("account_id");
        }
        // The host's identity the transcript bound (th2): every `Target`
        // is built from these.
        if welcome.atem_device_id != self.host_head.host_id()
            || welcome.host_trust_gen != self.host_trust_gen
        {
            return Err("host");
        }
        // The head after the carriage never goes behind the signed accept,
        // and on the chain the client shares with the host it is the
        // client's own entry.
        let signed = self.host_head.head();
        if welcome.head.seq < signed.seq
            || (welcome.head.seq == signed.seq && welcome.head.hash != signed.hash)
        {
            return Err("head");
        }
        if self.relation != HeadRelation::Diverged
            && let Some(entry) = log.entry(welcome.head.seq)
            && entry.hash() != welcome.head.hash
        {
            return Err("head");
        }
        Ok(())
    }
}

impl std::fmt::Debug for AwaitWelcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwaitWelcome").finish_non_exhaustive()
    }
}

/// One thing that happened on an attachment.
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    /// An r8 session message (receipts, `lease_changed`, `sessions`,
    /// approvals, …), after the machines below saw it.
    Session(SessionMessage),
    /// What the registry did with a `sessions`/`session_changed`/approval.
    Registry(RegistryOutcome),
    /// What a session's lease client did with a reply.
    Lease {
        session_id: String,
        outcome: ReplyOutcome,
    },
    /// terminal-v1 and chat-v1 messages.
    Family(FamilyMessage),
    /// A record the client must send now (a chat resync `open`).
    Outgoing(Vec<u8>),
    /// The host's head moved or a pending entry changed (`membership_head`):
    /// `fetch_to` when it is beyond the client's log (fetch and verify).
    MembershipHead {
        re: Option<String>,
        head: Head,
        pending_recovery: Vec<PendingRecovery>,
    },
    GrantRevoked {
        re: String,
    },
    Seen {
        re: String,
    },
    /// A session `error` (r9 fields included). With no `re` and code
    /// `unauthorized` or `account_frozen` it is a fence: the attachment is
    /// over and the channel closed (reconnect to learn more).
    Error(SessionError),
    Fenced(SessionError),
}

#[derive(Debug, Clone)]
enum Outstanding {
    Lease(String),
}

/// A welcomed attachment: the channel, the `welcome`, and r8's machines.
pub struct Attached {
    channel: Channel,
    welcome: Welcome,
    host_head: HostHead,
    carriage: Carriage,
    head: Head,
    pending_recovery: Vec<PendingRecovery>,
    authorization_deadline: u64,
    registry: RegistryClient,
    chat: ChatClient,
    leases: BTreeMap<String, LeaseClient>,
    outstanding: HashMap<String, Outstanding>,
}

impl Attached {
    pub fn welcome(&self) -> &Welcome {
        &self.welcome
    }

    pub fn channel_id(&self) -> &str {
        self.channel.channel_id()
    }

    /// The host's head as last told (welcome, then `membership_head`).
    pub fn head(&self) -> Head {
        self.head
    }

    /// The `accept` head.
    pub fn host_head(&self) -> &HostHead {
        &self.host_head
    }

    /// What the hello carried.
    pub fn carriage(&self) -> &Carriage {
        &self.carriage
    }

    /// What is pending on the host (show it: "Recovery of <device> pending,
    /// takes effect <time>: approve or cancel").
    pub fn pending_recovery(&self) -> &[PendingRecovery] {
        &self.pending_recovery
    }

    /// The host's head when it is beyond `log` (or on another branch): the
    /// client fetches the suffix from the relay and verifies it, never
    /// adopting the head itself.
    pub fn fetch_to(&self, log: &Membership) -> Option<Head> {
        match HeadRelation::of(log, self.head) {
            HeadRelation::HostAhead | HeadRelation::Diverged => Some(self.head),
            HeadRelation::Same | HeadRelation::HostBehind => None,
        }
    }

    pub fn registry(&self) -> &RegistryClient {
        &self.registry
    }

    pub fn chat(&self) -> &ChatClient {
        &self.chat
    }

    pub fn chat_mut(&mut self) -> &mut ChatClient {
        &mut self.chat
    }

    /// The lease client of a session (after an `acquire` or a Send).
    pub fn lease(&self, session_id: &str) -> Option<&LeaseClient> {
        self.leases.get(session_id)
    }

    pub fn is_closed(&self) -> bool {
        self.channel.is_closed()
    }

    /// Closes the channel (keys wiped).
    pub fn close(&mut self) {
        self.channel.close();
    }

    /// The session's target, from the welcome and the registry.
    pub fn target(&self, session_id: &str) -> Option<Target> {
        let d = self.registry.session(session_id)?;
        Some(Target {
            account_id: self.welcome.account_id.clone(),
            atem_device_id: self.welcome.atem_device_id.clone(),
            host_trust_gen: self.welcome.host_trust_gen,
            session_id: session_id.into(),
            process_gen: d.process_gen.clone(),
        })
    }

    /// A read binding, or a mutation binding when this attachment holds
    /// the session's lease.
    pub fn binding(&self, session_id: &str, now_ms: u64) -> Option<Binding> {
        let lease_epoch = self
            .leases
            .get(session_id)
            .filter(|l| l.controls(now_ms))
            .and_then(LeaseClient::lease_epoch);
        Some(Binding {
            target: self.target(session_id)?,
            attachment_gen: self.welcome.attachment_gen.clone(),
            lease_epoch,
        })
    }

    fn read_binding(&self, session_id: &str) -> Result<Binding, ConnectError> {
        Ok(Binding {
            target: self
                .target(session_id)
                .ok_or(ConnectError::Request("unknown session"))?,
            attachment_gen: self.welcome.attachment_gen.clone(),
            lease_epoch: None,
        })
    }

    fn seal(&mut self, message: &Value, now_ms: u64) -> Result<Vec<u8>, ConnectError> {
        Ok(self.channel.seal(message.to_string().as_bytes(), now_ms)?)
    }

    fn seal_op(&mut self, id: &str, op: Op, now_ms: u64) -> Result<Vec<u8>, ConnectError> {
        let env = Envelope::Session(SessionMessage {
            id: id.into(),
            re: None,
            op,
        });
        self.seal(&wire::to_value(&env), now_ms)
    }

    /// Any session-family message the app built (terminal-v1, chat-v1).
    pub fn send(&mut self, message: &Value, now_ms: u64) -> Result<Vec<u8>, ConnectError> {
        self.seal(message, now_ms)
    }

    /// `list`: the registry snapshot (and subscribes to changes).
    pub fn list(&mut self, now_ms: u64) -> Result<(String, Vec<u8>), ConnectError> {
        let id = new_id();
        self.registry.note_list_sent();
        let frame = self.seal_op(&id, Op::List {}, now_ms)?;
        Ok((id, frame))
    }

    fn lease_client(&mut self, session_id: &str) -> Result<&mut LeaseClient, ConnectError> {
        let target = self
            .target(session_id)
            .ok_or(ConnectError::Request("unknown session"))?;
        let attachment_gen = self.welcome.attachment_gen.clone();
        let deadline = self.authorization_deadline;
        Ok(self.leases.entry(session_id.into()).or_insert_with(|| {
            let mut l = LeaseClient::new(target, attachment_gen);
            l.set_authorization_deadline(Some(deadline));
            l
        }))
    }

    fn note_lease(
        &mut self,
        session_id: &str,
        id: &str,
        kind: LeaseRequest,
        now_ms: u64,
    ) -> Result<(), ConnectError> {
        self.lease_client(session_id)?
            .sent(id, kind, now_ms)
            .map_err(|e| {
                ConnectError::Request(match e {
                    RequestRefused::NotControlling => "no lease",
                    RequestRefused::DuplicateId => "duplicate id",
                    RequestRefused::TooManyInFlight => "too many requests in flight",
                })
            })?;
        self.outstanding
            .insert(id.into(), Outstanding::Lease(session_id.into()));
        Ok(())
    }

    /// `acquire` (with `takeover` for a confirmed takeover).
    pub fn acquire(
        &mut self,
        session_id: &str,
        takeover: bool,
        now_ms: u64,
    ) -> Result<(String, Vec<u8>), ConnectError> {
        let id = new_id();
        let binding = self.read_binding(session_id)?;
        self.note_lease(session_id, &id, LeaseRequest::Acquire, now_ms)?;
        let frame = self.seal_op(&id, Op::Acquire { binding, takeover }, now_ms)?;
        Ok((id, frame))
    }

    /// `renew` (every 5 s while controlling).
    pub fn renew(
        &mut self,
        session_id: &str,
        now_ms: u64,
    ) -> Result<(String, Vec<u8>), ConnectError> {
        let id = new_id();
        let binding = self
            .binding(session_id, now_ms)
            .filter(|b| b.lease_epoch.is_some())
            .ok_or(ConnectError::Request("no lease"))?;
        self.note_lease(session_id, &id, LeaseRequest::Renew, now_ms)?;
        let frame = self.seal_op(&id, Op::Renew { binding }, now_ms)?;
        Ok((id, frame))
    }

    /// `release`.
    pub fn release(
        &mut self,
        session_id: &str,
        now_ms: u64,
    ) -> Result<(String, Vec<u8>), ConnectError> {
        let id = new_id();
        let binding = self
            .binding(session_id, now_ms)
            .filter(|b| b.lease_epoch.is_some())
            .ok_or(ConnectError::Request("no lease"))?;
        self.note_lease(session_id, &id, LeaseRequest::Release, now_ms)?;
        let frame = self.seal_op(&id, Op::Release { binding }, now_ms)?;
        Ok((id, frame))
    }

    /// A prompt: under the held lease, or with `acquire` (r8 §F: the
    /// acceptance and the grant are one step; the admitting receipt carries
    /// the lease).
    pub fn submit_prompt(
        &mut self,
        session_id: &str,
        request_id: &str,
        text: &str,
        now_ms: u64,
    ) -> Result<(String, Vec<u8>), ConnectError> {
        let id = new_id();
        let held = self
            .binding(session_id, now_ms)
            .ok_or(ConnectError::Request("unknown session"))?;
        let acquire = held.lease_epoch.is_none();
        if acquire {
            self.note_lease(session_id, &id, LeaseRequest::Send, now_ms)?;
        }
        let op = Op::Submit {
            binding: held,
            request_id: request_id.into(),
            kind: ReceiptKind::Prompt,
            payload: json!({ "text": text }),
            acquire: acquire.then_some(true),
            takeover: None,
            expected_controller: None,
        };
        let frame = self.seal_op(&id, op, now_ms)?;
        Ok((id, frame))
    }

    /// Another submission (`interrupt`, `stop` with the lease; `approval`,
    /// `approval_rule_revoke` lease-free): the binding is a mutation one
    /// when the lease is held, else a read one.
    pub fn submit(
        &mut self,
        session_id: &str,
        kind: ReceiptKind,
        request_id: &str,
        payload: Value,
        now_ms: u64,
    ) -> Result<(String, Vec<u8>), ConnectError> {
        let id = new_id();
        let binding = self
            .binding(session_id, now_ms)
            .ok_or(ConnectError::Request("unknown session"))?;
        let op = Op::Submit {
            binding,
            request_id: request_id.into(),
            kind,
            payload,
            acquire: None,
            takeover: None,
            expected_controller: None,
        };
        let frame = self.seal_op(&id, op, now_ms)?;
        Ok((id, frame))
    }

    /// `receipt_query`.
    pub fn receipt_query(
        &mut self,
        session_id: &str,
        request_ids: &[String],
        now_ms: u64,
    ) -> Result<(String, Vec<u8>), ConnectError> {
        let id = new_id();
        let binding = self.read_binding(session_id)?;
        let op = Op::ReceiptQuery {
            binding,
            request_ids: request_ids.to_vec(),
        };
        let frame = self.seal_op(&id, op, now_ms)?;
        Ok((id, frame))
    }

    /// `approval_seen` (§R9.9). The app calls it only when the card was
    /// rendered in a focused foreground window and the user was active in
    /// the last 60 s; never from a background delivery or a notification.
    pub fn approval_seen(
        &mut self,
        session_id: &str,
        approval_id: &str,
        now_ms: u64,
    ) -> Result<(String, Vec<u8>), ConnectError> {
        let id = new_id();
        let binding =
            serde_json::to_value(self.read_binding(session_id)?).expect("a binding serializes");
        let message = crate::session::r9::approval_seen(&id, &binding, approval_id);
        let frame = self.seal(&message, now_ms)?;
        Ok((id, frame))
    }

    /// `revoke_grant` (the issuer, or a native member with `control`).
    pub fn revoke_grant(
        &mut self,
        grant_id: &str,
        now_ms: u64,
    ) -> Result<(String, Vec<u8>), ConnectError> {
        let id = new_id();
        let frame = self.seal(&crate::session::r9::revoke_grant(&id, grant_id), now_ms)?;
        Ok((id, frame))
    }

    /// `membership{entries}`: entries carried on the open channel (a
    /// manager's new entry, a veto) — the host answers `membership_head`.
    pub fn send_membership(
        &mut self,
        entries: &[SignedObject],
        now_ms: u64,
    ) -> Result<(String, Vec<u8>), ConnectError> {
        let id = new_id();
        let frame = self.seal(&crate::session::r9::membership_op(&id, entries), now_ms)?;
        Ok((id, frame))
    }

    /// Opens one record and runs it through the machines. A failed record
    /// closes the channel (`ConnectError::Channel`).
    pub fn on_frame(&mut self, frame: &[u8], now_ms: u64) -> Result<Vec<Event>, ConnectError> {
        let plain = self.channel.open(frame, now_ms)?;
        let mut events = Vec::new();
        match Incoming::parse(&plain).map_err(ConnectError::Malformed)? {
            Incoming::Welcome(_) => return Err(ConnectError::Malformed("a second welcome")),
            Incoming::MembershipHead {
                re,
                head,
                pending_recovery,
            } => {
                self.head = head;
                self.pending_recovery = pending_recovery.clone();
                events.push(Event::MembershipHead {
                    re,
                    head,
                    pending_recovery,
                });
                return Ok(events);
            }
            Incoming::GrantRevoked { re } => return Ok(vec![Event::GrantRevoked { re }]),
            Incoming::Seen { re } => return Ok(vec![Event::Seen { re }]),
            Incoming::Error(error) => {
                // r8's machines see r8's errors (a lease request's refusal).
                if let Ok(Envelope::Session(msg)) = wire::decode(&plain) {
                    self.session_message(&msg, now_ms, &mut events);
                }
                let fence = error.re.is_none()
                    && matches!(
                        error.code.as_str(),
                        code::UNAUTHORIZED | code::ACCOUNT_FROZEN
                    );
                if fence {
                    self.channel.close();
                    events.push(Event::Fenced(error));
                } else {
                    events.push(Event::Error(error));
                }
                return Ok(events);
            }
            Incoming::Other => {}
        }
        match wire::decode(&plain) {
            Ok(Envelope::Session(msg)) => {
                self.session_message(&msg, now_ms, &mut events);
                events.push(Event::Session(msg));
            }
            Ok(Envelope::Family(family)) => {
                if family.family == "agentChat"
                    && let Some(data) = &family.data
                    && let Some(mut open) = self.chat.on_message(data)
                {
                    // A resync `open` needs the session's read binding.
                    if let Some(binding) = open["data"]["agentId"]
                        .as_str()
                        .and_then(|s| self.read_binding(s).ok())
                    {
                        open["data"]["binding"] =
                            serde_json::to_value(binding).expect("a binding serializes");
                        events.push(Event::Outgoing(self.seal(&open, now_ms)?));
                    }
                }
                events.push(Event::Family(family));
            }
            Err(_) => return Err(ConnectError::Malformed("not a session-family message")),
        }
        Ok(events)
    }

    fn session_message(&mut self, msg: &SessionMessage, now_ms: u64, events: &mut Vec<Event>) {
        match &msg.op {
            Op::Sessions { .. }
            | Op::SessionChanged { .. }
            | Op::ApprovalRequest(_)
            | Op::ApprovalClosed { .. } => {
                events.push(Event::Registry(self.registry.on_message(&msg.op)));
            }
            Op::LeaseChanged {
                session_id,
                process_gen,
                lease_epoch,
                ..
            } => {
                if let Some(l) = self.leases.get_mut(session_id) {
                    l.on_lease_changed(session_id, process_gen, *lease_epoch);
                }
            }
            _ => {}
        }
        if let Some(Outstanding::Lease(session_id)) = msg
            .re
            .as_ref()
            .and_then(|re| self.outstanding.get(re))
            .cloned()
            && let Some(l) = self.leases.get_mut(&session_id)
        {
            let outcome = l.on_reply(msg, now_ms);
            if outcome != ReplyOutcome::NotALeaseReply {
                self.outstanding
                    .remove(msg.re.as_deref().unwrap_or_default());
                events.push(Event::Lease {
                    session_id,
                    outcome,
                });
            }
        }
    }
}

impl std::fmt::Debug for Attached {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Attached")
            .field("channel_id", &self.channel.channel_id())
            .field("principal", &self.welcome.principal)
            .finish_non_exhaustive()
    }
}
