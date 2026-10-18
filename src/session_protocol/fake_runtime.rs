//! A fake runtime around `SessionHost` for the shared fixtures and the host
//! unit tests: it performs the host's effects against a fake PTY and
//! dispatcher (with the fixtures' failure injection), keeps a `MemJournal`,
//! and plays each fixture client's transport (connect, `hello`/`welcome`,
//! reconnect).
//!
//! The fixtures describe clients that are already attached; the harness does
//! the `hello`/`welcome` itself (checking the welcome) and, for
//! `holds_lease_epoch`, a real `acquire`, so every lease and attachment comes
//! from the host's own rules. Each client name is its own principal (r8
//! §H).
//!
//! Sessions with `chat` get a `ChatSession` the r8 steps feed
//! (`chat_history`, `chat_message`, `chat_evict`, `chat_turn`,
//! `worker_gap`) and chat-v1 conversations served by `chat::history`, the
//! code the runtime serves them with.

use super::fixtures::{HostEvent, HostUnderTest, Setup};
use super::host::{
    Attach, ChatReply, DispatchReport, Effect, HostConfig, HostContext, Origin, SessionHost,
    SessionSpec, random_ids,
};
use super::journal::{Journal, MemJournal};
use super::revision::{FEATURES, REVISION};
use super::wire::{
    self, ApprovalCloseReason, Binding, ClientKind, DecodeError, Envelope, Op, Permission,
    ReceiptKind, SessionMessage, Target,
};
use crate::chat::adapter::{ApprovalCard, ApprovalCardState, Outcome, Part};
use crate::chat::history::{self, Conversations, HistoryCall, HistoryKey, Opening, is_card};
use crate::chat::session::{ChatMessage, ChatSession, Origin as ChatOrigin, Out, Role};
use crate::chat::wire::{self as chat_wire, ChatEnvelope};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

/// The authenticated link's authorization in the fixtures (24 h).
pub const AUTHORIZATION_MS: u64 = 24 * 60 * 60 * 1000;

/// The adapter's draft check refusing a prompt (`chat::session`).
pub const DRAFT_REFUSAL: &str = "the terminal has unsent input; finish or clear it there";

/// The fake PTY and dispatcher.
#[derive(Debug)]
pub struct Pty {
    pub fail_next_enqueue: bool,
    pub fail_next_partial: bool,
    /// Every `Dispatch` the host asked for.
    pub dispatch_attempts: u64,
    /// Dispatches that reached the PTY/agent (not refused before any effect).
    pub dispatches: u64,
    /// `None` once a writer failed after a possible partial write.
    pub bytes_written: Option<u64>,
    pub writes_local: u64,
    pub writes_remote: u64,
    /// Remote chunks refused at the write boundary.
    pub dropped_remote: u64,
    pub resizes: u64,
    pub stops: u64,
    /// Decisions handed to the agent (`Effect::Approval`), as wire JSON.
    pub approval_decisions: Vec<Value>,
    /// Approvals the host released ("no decision").
    pub approvals_released: u64,
    /// Push requests to the relay, in order: `{op, approval_id, reason?}`.
    pub pushes: Vec<Value>,
    /// Session rules the runtime was asked to revoke, in order.
    pub rule_revokes: Vec<String>,
}

impl Default for Pty {
    fn default() -> Self {
        Self {
            fail_next_enqueue: false,
            fail_next_partial: false,
            dispatch_attempts: 0,
            dispatches: 0,
            bytes_written: Some(0),
            writes_local: 0,
            writes_remote: 0,
            dropped_remote: 0,
            resizes: 0,
            stops: 0,
            approval_decisions: Vec::new(),
            approvals_released: 0,
            pushes: Vec::new(),
            rule_revokes: Vec::new(),
        }
    }
}

impl Pty {
    fn wrote(&mut self, n: usize) {
        self.bytes_written = self.bytes_written.map(|b| b + n as u64);
    }
}

#[derive(Debug, Clone)]
struct Client {
    attachment_gen: String,
    permissions: Vec<Permission>,
    client_kind: ClientKind,
}

/// Fixture failure injection on a journal (r8 schema: `fail_next_fsync`
/// with `undo_fails`, `fail_fsync_of`, `crash_after_accepted`).
pub trait FailFsync {
    fn fail_next_fsync(&mut self) {
        self.fail_fsync_of(1, false);
    }
    /// The `n`-th next append fails; with `undo_fails` its record stays.
    fn fail_fsync_of(&mut self, n: u64, undo_fails: bool);
    fn crash_after_accepted(&mut self);
    fn crashed(&self) -> bool;
}

impl FailFsync for MemJournal {
    fn fail_fsync_of(&mut self, n: u64, undo_fails: bool) {
        if undo_fails {
            MemJournal::fail_fsync_and_undo_of(self, n);
        } else {
            MemJournal::fail_fsync_of(self, n);
        }
    }
    fn crash_after_accepted(&mut self) {
        MemJournal::crash_after_accepted(self);
    }
    fn crashed(&self) -> bool {
        MemJournal::crashed(self)
    }
}

impl FailFsync for super::file_journal::FileJournal {
    fn fail_fsync_of(&mut self, n: u64, undo_fails: bool) {
        self.fail_append_of(n, undo_fails);
    }
    fn crash_after_accepted(&mut self) {
        super::file_journal::FileJournal::crash_after_accepted(self);
    }
    fn crashed(&self) -> bool {
        super::file_journal::FileJournal::crashed(self)
    }
}

pub struct FakeRuntime<J: Journal = MemJournal> {
    pub host: SessionHost<J>,
    pub pty: Pty,
    /// Hold remote PTY writes in a queue instead of writing them at once
    /// (`flush_writes` writes them through the write boundary).
    pub hold_writes: bool,
    /// Whether the clock runs the host's timers (`advance`); off, the host
    /// sees time only through `receive` and `admit_write`.
    pub ticks: bool,
    queued_writes: Vec<Effect>,
    /// How a `Reconcile` is answered.
    pub reconcile_answer: DispatchReport,
    /// session_id → the prompt whose turn is running.
    turns: HashMap<String, String>,
    /// Sessions whose terminal has unsent local input (a `local_input`
    /// ending without CR/LF): the adapter's draft check refuses prompts.
    drafts: HashSet<String>,
    /// `crash_after_accepted`: the restart to perform once the next
    /// `accepted` record is durable.
    crash_after: Option<(String, u64)>,
    clients: BTreeMap<String, Client>,
    /// Every attachment ever used → client name.
    names: HashMap<String, String>,
    live: HashMap<String, String>,
    sessions: Vec<String>,
    out: Vec<(String, Envelope)>,
    /// Every effect the host produced, in order.
    pub effects: Vec<Effect>,
    now: u64,
    /// r8: the chat of each session with `chat`, and its conversations.
    chats: HashMap<String, FakeChat>,
    history_key: HistoryKey,
    /// approval_id → (session, card, turn) of the chat's approval cards.
    cards: HashMap<String, (String, ApprovalCard, String)>,
    /// request id → (session, conversation) of chat submits.
    chat_submitters: HashMap<String, (String, String)>,
    chat_opens: u64,
    chat_closes: u64,
}

struct FakeChat {
    chat: ChatSession,
    conversations: Conversations,
}

fn text_part(markdown: &str) -> Vec<Part> {
    vec![Part::Text {
        id: "p1".into(),
        markdown: markdown.to_string(),
    }]
}

fn chat_family(env: &ChatEnvelope) -> Envelope {
    Envelope::Family(wire::FamilyMessage {
        family: "agentChat".into(),
        data: Some(serde_json::to_value(env).expect("chat envelopes serialize")),
        binding: None,
        request: None,
    })
}

fn message(op: Op) -> Envelope {
    Envelope::Session(SessionMessage {
        id: uuid::Uuid::new_v4().to_string(),
        re: None,
        op,
    })
}

/// Renders a chat reply as the chat runtime would; `head` (generation and
/// sequence) when its conversation is open.
fn render_chat(
    conversation_id: &str,
    session_id: &str,
    reply: ChatReply,
    head: Option<(String, u64)>,
) -> Envelope {
    let mut data = json!({"v": 1, "conversationId": conversation_id, "agentId": session_id});
    let body = match reply {
        ChatReply::Accepted { request_id, lease } => {
            let mut b = json!({"op": "accepted", "requestId": request_id});
            if let Some(l) = lease {
                b["lease"] = json!({"lease_epoch": l.lease_epoch, "ms_left": l.ms_left});
            }
            b
        }
        ChatReply::Complete {
            request_id,
            turn_id,
            interrupted,
        } => {
            let outcome = if interrupted { "interrupted" } else { "done" };
            let mut b = json!({"op": "complete", "requestId": request_id, "outcome": outcome});
            if let Some(t) = turn_id {
                b["turnId"] = Value::String(t);
            }
            b
        }
        ChatReply::Error {
            request_id,
            code,
            text,
            controller,
            page_id,
            ..
        } => {
            let mut b = json!({"op": "error", "code": code, "text": text});
            if let Some(r) = request_id {
                b["requestId"] = Value::String(r);
            }
            if let Some(p) = page_id {
                b["page_id"] = Value::String(p);
            }
            if let Some(c) = controller {
                b["controller"] = json!(c);
            }
            b
        }
    };
    data.as_object_mut()
        .unwrap()
        .extend(body.as_object().unwrap().clone());
    if let Some((generation, sequence)) = head {
        data["generation"] = Value::String(generation);
        data["sequence"] = Value::from(sequence);
    }
    Envelope::Family(wire::FamilyMessage {
        family: "agentChat".into(),
        data: Some(data),
        binding: None,
        request: None,
    })
}

impl FakeRuntime {
    /// The fixtures' host: the default configuration over a `MemJournal`.
    pub fn new(setup: &Setup) -> Result<Self, String> {
        Self::with_config(setup, HostConfig::default())
    }

    pub fn with_config(setup: &Setup, config: HostConfig) -> Result<Self, String> {
        Self::with_journal(setup, config, MemJournal::default())
    }

    pub fn from_json(setup: Value, config: HostConfig) -> Self {
        Self::from_json_with(setup, config, MemJournal::default())
    }
}

impl<J: Journal> FakeRuntime<J> {
    pub fn with_journal(setup: &Setup, config: HostConfig, journal: J) -> Result<Self, String> {
        let h = &setup.host;
        let ctx = HostContext {
            account_id: h.account_id.clone(),
            atem_device_id: h.atem_device_id.clone(),
            host_trust_gen: h.host_trust_gen,
            runtime_gen: h.runtime_gen.clone(),
            runtime_epoch: h.runtime_epoch,
        };
        let host = SessionHost::new(ctx, config, journal, random_ids()).map_err(|e| e.0)?;
        let mut rt = Self {
            host,
            pty: Pty::default(),
            hold_writes: false,
            ticks: true,
            queued_writes: Vec::new(),
            reconcile_answer: DispatchReport::Unknown,
            turns: HashMap::new(),
            drafts: HashSet::new(),
            crash_after: None,
            clients: BTreeMap::new(),
            names: HashMap::new(),
            live: HashMap::new(),
            sessions: Vec::new(),
            out: Vec::new(),
            effects: Vec::new(),
            now: 0,
            chats: HashMap::new(),
            history_key: HistoryKey::random(),
            cards: HashMap::new(),
            chat_submitters: HashMap::new(),
            chat_opens: 0,
            chat_closes: 0,
        };
        for s in &setup.sessions {
            let fx = rt.host.add_session(SessionSpec {
                session_id: s.session_id.clone(),
                process_gen: s.process_gen.clone(),
                provider: "claude".into(),
                cwd_label: "Atem".into(),
                chat: s.chat,
                rows: 24,
                cols: 80,
            })?;
            rt.apply(fx);
            rt.sessions.push(s.session_id.clone());
            if s.chat {
                rt.chats.insert(
                    s.session_id.clone(),
                    FakeChat {
                        chat: ChatSession::new(s.process_gen.clone(), 0),
                        conversations: Conversations::default(),
                    },
                );
            }
        }
        for c in &setup.clients {
            rt.clients.insert(
                c.name.clone(),
                Client {
                    attachment_gen: c.attachment_gen.clone(),
                    permissions: c.permissions.clone(),
                    client_kind: c.client_kind,
                },
            );
            if c.welcome == Some(false) {
                // r8: the steps send this client's `hello`.
                rt.connect_unwelcomed(&c.name, &c.attachment_gen)?;
            } else {
                rt.attach(&c.name, &c.attachment_gen)?;
            }
            if let Some(epoch) = c.holds_lease_epoch {
                rt.setup_lease(&c.name, epoch)?;
            }
        }
        // Setup traffic (e.g. other viewers' `lease_changed` for a setup
        // lease) is not visible to the steps.
        rt.out.clear();
        Ok(rt)
    }

    pub fn from_json_with(setup: Value, config: HostConfig, journal: J) -> Self {
        let setup: Setup = serde_json::from_value(setup).expect("setup");
        Self::with_journal(&setup, config, journal).expect("fake runtime")
    }

    /// Connects `client` on a new attachment without `hello`.
    pub fn connect_only(
        &mut self,
        client: &str,
        attachment_gen: &str,
        permissions: Vec<Permission>,
        authorization_ms: u64,
    ) {
        let c = Client {
            attachment_gen: attachment_gen.to_string(),
            permissions: permissions.clone(),
            client_kind: ClientKind::Native,
        };
        self.clients.insert(client.to_string(), c);
        let fx = self
            .host
            .connect(Attach {
                client: client.to_string(),
                principal: client.to_string(),
                attachment_gen: attachment_gen.to_string(),
                permissions,
                client_kind: ClientKind::Native,
                authorization_ms,
            })
            .expect("connect");
        self.apply(fx);
        self.names
            .insert(attachment_gen.to_string(), client.to_string());
        self.live
            .insert(attachment_gen.to_string(), client.to_string());
    }

    pub fn now(&self) -> u64 {
        self.now
    }

    pub fn attachment(&self, client: &str) -> String {
        self.clients[client].attachment_gen.clone()
    }

    /// A new attachment for `client` without `hello` (fencing the previous
    /// one).
    fn connect_unwelcomed(&mut self, client: &str, attachment_gen: &str) -> Result<(), String> {
        let c = self.clients.get_mut(client).ok_or("unknown client")?;
        c.attachment_gen = attachment_gen.to_string();
        let attach = Attach {
            client: client.to_string(),
            principal: client.to_string(),
            attachment_gen: attachment_gen.to_string(),
            permissions: c.permissions.clone(),
            client_kind: c.client_kind,
            authorization_ms: AUTHORIZATION_MS,
        };
        let fx = self.host.connect(attach)?;
        self.apply(fx);
        self.names
            .insert(attachment_gen.to_string(), client.to_string());
        self.live
            .insert(attachment_gen.to_string(), client.to_string());
        Ok(())
    }

    /// A new attachment for `client`: connect (fencing the previous one),
    /// `hello{revision: 8}`, and the checked `welcome` (r8: it echoes the
    /// revision and advertises `revision::FEATURES`) taken off the queue. A
    /// halted journal welcomes nobody (r8 §I): the client stays connected,
    /// unwelcomed.
    pub fn attach(&mut self, client: &str, attachment_gen: &str) -> Result<(), String> {
        self.connect_unwelcomed(client, attachment_gen)?;
        let hello = Op::Hello {
            revision: Some(REVISION),
            resume: None,
        };
        let fx = self
            .host
            .receive_decoded(attachment_gen, Ok(message(hello)), self.now);
        self.apply(fx);
        let i = self.out.iter().rposition(|(n, m)| {
            n == client && matches!(m, Envelope::Session(s) if matches!(s.op, Op::Welcome { .. }))
        });
        let i = match i {
            Some(i) => i,
            None if self.host.journal_halted() => return Ok(()),
            None => return Err("no welcome".into()),
        };
        let (_, welcome) = self.out.remove(i);
        match welcome {
            Envelope::Session(SessionMessage {
                op:
                    Op::Welcome {
                        attachment_gen: g,
                        revision,
                        features,
                        ..
                    },
                ..
            }) if g == attachment_gen => {
                let advertised: Vec<&str> = FEATURES.to_vec();
                let got: Option<Vec<&str>> = features
                    .as_ref()
                    .map(|f| f.iter().map(String::as_str).collect());
                if revision != Some(REVISION) || got.as_ref() != Some(&advertised) {
                    return Err(format!("welcome revision {revision:?} features {got:?}"));
                }
                Ok(())
            }
            other => Err(format!("unexpected welcome {other:?}")),
        }
    }

    fn only_session(&self) -> Result<String, String> {
        match self.sessions.as_slice() {
            [only] => Ok(only.clone()),
            _ => Err("this needs exactly one session".into()),
        }
    }

    pub fn target(&self, session_id: &str) -> Target {
        let ctx = self.host.context();
        Target {
            account_id: ctx.account_id.clone(),
            atem_device_id: ctx.atem_device_id.clone(),
            host_trust_gen: ctx.host_trust_gen,
            session_id: session_id.to_string(),
            process_gen: self.process_gen(session_id),
        }
    }

    fn process_gen(&self, session_id: &str) -> String {
        self.host
            .descriptor_of(session_id)
            .map(|d| d.process_gen)
            .unwrap_or_default()
    }

    /// `holds_lease_epoch`: a real `acquire`, whose reply must carry `epoch`.
    fn setup_lease(&mut self, client: &str, epoch: u64) -> Result<(), String> {
        let sid = self.only_session()?;
        let att = self.attachment(client);
        let binding = Binding {
            target: self.target(&sid),
            attachment_gen: att.clone(),
            lease_epoch: None,
        };
        let fx = self.host.receive_decoded(
            &att,
            Ok(message(Op::Acquire {
                binding,
                takeover: false,
            })),
            self.now,
        );
        self.apply(fx);
        let i = self
            .out
            .iter()
            .position(|(n, m)| {
                n == client && matches!(m, Envelope::Session(s) if matches!(s.op, Op::Lease { .. }))
            })
            .ok_or("setup acquire got no lease")?;
        match self.out.remove(i).1 {
            Envelope::Session(SessionMessage {
                op: Op::Lease { binding, .. },
                ..
            }) if binding.lease_epoch == Some(epoch) => Ok(()),
            other => Err(format!("setup lease is not epoch {epoch}: {other:?}")),
        }
    }

    /// Performs effects until none are left.
    pub fn apply(&mut self, fx: Vec<Effect>) {
        let mut work: VecDeque<Effect> = fx.into();
        while let Some(effect) = work.pop_front() {
            self.effects.push(effect.clone());
            match effect {
                Effect::Send {
                    attachment,
                    mut message,
                } => {
                    // r8 §D: replies from the retained history, as the
                    // runtime fills them.
                    let chats = &self.chats;
                    super::host::fill_results(&mut message, |target, result| {
                        chats
                            .get(&target.session_id)
                            .filter(|c| c.chat.generation() == target.process_gen)
                            .map(|c| {
                                history::turn_replies(
                                    &c.chat,
                                    &result.turn_id,
                                    &result.user_message_id,
                                )
                            })
                    });
                    if let Some(name) = self.live.get(&attachment) {
                        self.out.push((name.clone(), message));
                    }
                }
                Effect::Close { attachment } => {
                    self.live.remove(&attachment);
                }
                // A second `hello` replaced the client's attachment on the
                // same transport: its messages go to the new one.
                Effect::Replaced { old, new } => {
                    if let Some(name) = self.live.remove(&old) {
                        if let Some(c) = self.clients.get_mut(&name) {
                            c.attachment_gen = new.clone();
                        }
                        self.names.insert(new.clone(), name.clone());
                        self.live.insert(new, name);
                    }
                }
                Effect::PtyWrite { ref origin, .. } => {
                    if self.hold_writes && matches!(origin, Origin::Remote { .. }) {
                        self.queued_writes.push(effect);
                    } else {
                        self.write(effect);
                    }
                }
                Effect::Resize { .. } => self.pty.resizes += 1,
                Effect::Stop { .. } => self.pty.stops += 1,
                Effect::Dispatch {
                    request_id,
                    kind,
                    payload,
                    target,
                } => {
                    self.pty.dispatch_attempts += 1;
                    let draft =
                        kind == ReceiptKind::Prompt && self.drafts.contains(&target.session_id);
                    let report = if std::mem::take(&mut self.pty.fail_next_enqueue) {
                        Some(DispatchReport::FailedNoEffect)
                    } else if draft {
                        // The chat adapter's draft check: nothing is pasted.
                        Some(DispatchReport::Refused {
                            detail: DRAFT_REFUSAL.into(),
                        })
                    } else if std::mem::take(&mut self.pty.fail_next_partial) {
                        self.pty.bytes_written = None;
                        Some(DispatchReport::FailedAfterPossibleEffect)
                    } else {
                        if kind == ReceiptKind::Prompt {
                            let n = payload["text"].as_str().map_or(0, str::len);
                            self.pty.wrote(n);
                            self.turns
                                .insert(target.session_id.clone(), request_id.clone());
                        }
                        if kind == ReceiptKind::ApprovalRuleRevoke {
                            // The worker drops the rule at once: it answers,
                            // then reports the rules left.
                            let rule_id = payload["rule_id"].as_str().unwrap_or_default();
                            self.pty.rule_revokes.push(rule_id.to_string());
                            let sid = &target.session_id;
                            let mut left = self.host.approval_rules(sid);
                            left.retain(|r| r.rule_id != rule_id);
                            let report = DispatchReport::Completed {
                                detail: None,
                                turn_id: None,
                                user_message_id: None,
                            };
                            work.extend(self.host.dispatch_report(&request_id, report));
                            work.extend(
                                self.host
                                    .set_approval_rules(sid, &target.process_gen, left)
                                    .unwrap_or_default(),
                            );
                        }
                        // Written; completion comes from the provider later.
                        None
                    };
                    let refused = matches!(
                        report,
                        Some(DispatchReport::FailedNoEffect | DispatchReport::Refused { .. })
                    );
                    if !refused {
                        self.pty.dispatches += 1;
                    }
                    if let Some(report) = report {
                        work.extend(self.host.dispatch_report(&request_id, report));
                    }
                }
                Effect::Approval {
                    approval_id,
                    decision,
                    rule_id,
                    message,
                    ..
                } => {
                    // Handed to the agent; it reports later (`approval_applied`).
                    self.pty.dispatch_attempts += 1;
                    self.pty.dispatches += 1;
                    let mut d = json!({"approval_id": approval_id, "decision": decision});
                    if let Some(r) = rule_id {
                        d["rule_id"] = Value::String(r);
                    }
                    if let Some(m) = message {
                        d["message"] = Value::String(m);
                    }
                    self.pty.approval_decisions.push(d);
                }
                Effect::ApprovalReleased { .. } => self.pty.approvals_released += 1,
                Effect::PushApproval { request } => self
                    .pty
                    .pushes
                    .push(json!({"op": "push_approval", "approval_id": request.approval_id})),
                Effect::PushResolved {
                    approval_id,
                    reason,
                } => self.pty.pushes.push(json!({
                    "op": "push_resolved",
                    "approval_id": approval_id,
                    "reason": reason,
                })),
                Effect::Reconcile { request_id, .. } => {
                    let answer = self.reconcile_answer.clone();
                    work.extend(self.host.dispatch_report(&request_id, answer));
                }
                Effect::Chat {
                    attachment,
                    conversation_id,
                    session_id,
                    reply,
                } => {
                    if let ChatReply::Accepted { request_id, .. } = &reply {
                        self.chat_submitters.insert(
                            request_id.clone(),
                            (session_id.clone(), conversation_id.clone()),
                        );
                    }
                    let sequenced = !matches!(
                        reply,
                        ChatReply::Error {
                            sequenced: false,
                            ..
                        }
                    );
                    let head = self
                        .chats
                        .get_mut(&session_id)
                        .filter(|_| sequenced)
                        .filter(|c| {
                            c.conversations
                                .map
                                .get(&conversation_id)
                                .is_some_and(|v| v.attachment == attachment)
                        })
                        .and_then(|c| {
                            let generation = c.chat.generation().to_string();
                            c.conversations
                                .next_head(&conversation_id)
                                .map(|s| (generation, s))
                        });
                    if let Some(name) = self.live.get(&attachment) {
                        let msg = render_chat(&conversation_id, &session_id, reply, head);
                        self.out.push((name.clone(), msg));
                    }
                }
                Effect::Forward {
                    attachment,
                    session_id,
                    message,
                } => {
                    if message.family == "agentChat" {
                        self.chat_request(&attachment, &session_id, &message);
                    }
                }
                Effect::StreamOpened { .. } | Effect::StreamClosed { .. } => {}
            }
        }
    }

    /// chat-v1 `open`, `close` and `history`, authorized by the host.
    fn chat_request(&mut self, attachment: &str, sid: &str, message: &wire::FamilyMessage) {
        let Some(data) = message.data.clone() else {
            return;
        };
        let control = self.host.attachment_can(attachment, Permission::Control);
        let rules = if control {
            self.host.approval_rules(sid)
        } else {
            Vec::new()
        };
        let now = self.now;
        let conversation = data["conversationId"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        let Some(c) = self.chats.get_mut(sid) else {
            return;
        };
        let envelopes = match data["op"].as_str() {
            Some("open") => {
                let opening = Opening {
                    conversation: &conversation,
                    agent: sid,
                    attachment,
                    control,
                    status: c.chat.status(),
                    unavailable: &[],
                    rules: &rules,
                };
                c.conversations.open(&c.chat, &self.history_key, &opening)
            }
            Some("close") => {
                c.conversations.close(&conversation, attachment);
                Vec::new()
            }
            Some("history") => {
                let call = HistoryCall {
                    data: &data,
                    conversation: &conversation,
                    agent: sid,
                    attachment,
                    control,
                    now_ms: now,
                };
                c.conversations.history(&c.chat, &self.history_key, &call)
            }
            _ => Vec::new(),
        };
        self.send_chat(attachment, envelopes);
    }

    fn send_chat(&mut self, attachment: &str, envelopes: Vec<ChatEnvelope>) {
        let Some(name) = self.live.get(attachment).cloned() else {
            return;
        };
        for env in envelopes {
            match env.op.as_str() {
                "opened" => self.chat_opens += 1,
                "close" => self.chat_closes += 1,
                _ => {}
            }
            self.out.push((name.clone(), chat_family(&env)));
        }
    }

    /// `out` to every open conversation of `sid` on a live attachment (with
    /// `control_only`, of attachments with `control`), except `except`.
    fn broadcast(&mut self, sid: &str, out: &Out, except: Option<&str>, control_only: bool) {
        let live: HashSet<String> = self.live.keys().cloned().collect();
        let Some(c) = self.chats.get_mut(sid) else {
            return;
        };
        // Conversations of fenced attachments end with them.
        c.conversations
            .map
            .retain(|_, v| live.contains(&v.attachment));
        let mut ids: Vec<(String, String)> = c
            .conversations
            .map
            .iter()
            .filter(|(id, _)| Some(id.as_str()) != except)
            .filter(|(_, v)| {
                !control_only || self.host.attachment_can(&v.attachment, Permission::Control)
            })
            .map(|(id, v)| (id.clone(), v.attachment.clone()))
            .collect();
        ids.sort();
        let generation = c.chat.generation().to_string();
        let mut sends = Vec::new();
        for (id, attachment) in ids {
            if let Some(sequence) = c.conversations.next_head(&id) {
                sends.push((
                    attachment,
                    chat_wire::event(&id, sid, &generation, sequence, out),
                ));
            }
        }
        for (attachment, env) in sends {
            self.send_chat(&attachment, vec![env]);
        }
    }

    /// A message the agent produced: kept, and sent live.
    fn chat_produced(&mut self, sid: &str, message: ChatMessage) {
        let Some(c) = self.chats.get_mut(sid) else {
            return;
        };
        c.chat.put_message(message.clone());
        let card = is_card(&message);
        self.broadcast(sid, &Out::Message(message), None, card);
    }

    fn chat_event(&mut self, event: &HostEvent) -> Result<(), String> {
        let chat_of = |rt: &mut Self, sid: &str| -> Result<(), String> {
            if rt.chats.contains_key(sid) {
                Ok(())
            } else {
                Err(format!("{sid} has no chat"))
            }
        };
        match event {
            HostEvent::ChatHistory {
                session_id,
                messages,
            } => {
                chat_of(self, session_id)?;
                for m in messages {
                    let m = chat_wire::parse_message(m)?;
                    self.chats.get_mut(session_id).unwrap().chat.put_message(m);
                }
            }
            HostEvent::ChatMessage {
                session_id,
                message,
            } => {
                chat_of(self, session_id)?;
                let m = chat_wire::parse_message(message)?;
                self.chat_produced(session_id, m);
            }
            HostEvent::ChatEvict { session_id, count } => {
                chat_of(self, session_id)?;
                self.chats.get_mut(session_id).unwrap().chat.evict(*count);
            }
            HostEvent::ChatTurn {
                session_id,
                turn_id,
                request_id,
                origin,
                assistant_messages,
                text_bytes,
                control,
            } => {
                chat_of(self, session_id)?;
                let origin = match origin.as_str() {
                    "local" => ChatOrigin::Local,
                    "remote" => ChatOrigin::Remote,
                    other => return Err(format!("origin {other:?}")),
                };
                let text = |markdown: String| {
                    vec![Part::Text {
                        id: "p1".into(),
                        markdown,
                    }]
                };
                self.chat_produced(
                    session_id,
                    ChatMessage {
                        message_id: format!("{turn_id}-u"),
                        role: Role::User,
                        origin: Some(origin),
                        turn_id: turn_id.clone(),
                        request_id: request_id.clone(),
                        created_at_ms: 0,
                        parts: text("run the task".into()),
                    },
                );
                let fill = if *control { "\u{1}" } else { "x" };
                for n in 1..=*assistant_messages {
                    self.chat_produced(
                        session_id,
                        ChatMessage {
                            message_id: format!("{turn_id}-a-{n:04}"),
                            role: Role::Assistant,
                            origin: None,
                            turn_id: turn_id.clone(),
                            request_id: None,
                            created_at_ms: 0,
                            parts: text(fill.repeat(*text_bytes)),
                        },
                    );
                }
            }
            HostEvent::WorkerGap {
                session_id,
                dropped,
                recoverable,
                delivered_after,
            } => {
                chat_of(self, session_id)?;
                let delivered: Vec<ChatMessage> = delivered_after
                    .iter()
                    .map(chat_wire::parse_message)
                    .collect::<Result<_, _>>()?;
                let before_gap = self.chats[session_id]
                    .chat
                    .newest_retained()
                    .map(str::to_string);
                for m in &delivered {
                    self.chat_produced(session_id, m.clone());
                }
                // The worker's history: what was retained here, with what it
                // still has of the dropped items where they were.
                let first_after = delivered.first().map(|m| m.message_id.clone());
                let turn = delivered
                    .first()
                    .map_or_else(|| "turn-gap".to_string(), |m| m.turn_id.clone());
                let recovered: Vec<ChatMessage> = dropped
                    .iter()
                    .filter(|id| recoverable.contains(id))
                    .map(|id| ChatMessage {
                        message_id: id.clone(),
                        role: Role::Assistant,
                        origin: None,
                        turn_id: turn.clone(),
                        request_id: None,
                        created_at_ms: 0,
                        parts: text_part(&format!("recovered {id}")),
                    })
                    .collect();
                let c = self.chats.get_mut(session_id).unwrap();
                let mut worker: Vec<ChatMessage> = c.chat.retained().cloned().collect();
                let at = first_after
                    .as_ref()
                    .and_then(|f| worker.iter().position(|m| &m.message_id == f))
                    .unwrap_or(worker.len());
                worker.splice(at..at, recovered);
                let outs: Vec<Out> = c
                    .chat
                    .reload(worker)
                    .into_iter()
                    .map(|(message, after)| Out::Recovered { message, after })
                    .collect();
                // What stays missing: each run of dropped items the reload
                // didn't find, between its retained neighbours.
                let mut holes = Vec::new();
                let mut prev = before_gap;
                let mut run = 0u64;
                for id in dropped {
                    if recoverable.contains(id) {
                        if run > 0 {
                            holes.push((prev.clone(), Some(id.clone()), run));
                        }
                        run = 0;
                        prev = Some(id.clone());
                    } else {
                        run += 1;
                    }
                }
                if run > 0 {
                    holes.push((prev, first_after, run));
                }
                let mut holed = false;
                for (after, before, count) in holes {
                    holed |= c
                        .chat
                        .add_hole(after.as_deref(), before.as_deref(), Some(count));
                }
                let coverage = c.chat.coverage();
                for out in outs {
                    let card = matches!(&out, Out::Recovered { message, .. } if is_card(message));
                    self.broadcast(session_id, &out, None, card);
                }
                if holed {
                    self.broadcast(session_id, &Out::Coverage(coverage), None, false);
                }
            }
            _ => unreachable!("not a chat event"),
        }
        Ok(())
    }

    /// The card of `approval_id` (opened or changed), in the history and
    /// the conversations of attachments with `control`.
    fn show_card(&mut self, approval_id: &str) {
        let Some((sid, card, turn)) = self.cards.get(approval_id).cloned() else {
            return;
        };
        self.chat_produced(
            &sid,
            ChatMessage {
                message_id: format!("approval-{approval_id}"),
                role: Role::Assistant,
                origin: None,
                turn_id: turn,
                request_id: None,
                created_at_ms: 0,
                parts: vec![Part::Approval(card)],
            },
        );
    }

    /// The write boundary: remote chunks are written only if the host still
    /// admits their input epoch.
    fn write(&mut self, effect: Effect) {
        let Effect::PtyWrite {
            session_id,
            bytes,
            origin,
        } = effect
        else {
            return;
        };
        match origin {
            Origin::Local => {
                self.pty.writes_local += 1;
                self.pty.wrote(bytes.len());
            }
            Origin::Remote { input_epoch, .. } => {
                if self.host.admit_write(&session_id, input_epoch, self.now) {
                    self.pty.writes_remote += 1;
                    self.pty.wrote(bytes.len());
                } else {
                    self.pty.dropped_remote += 1;
                }
            }
        }
    }

    pub fn flush_writes(&mut self) {
        for w in std::mem::take(&mut self.queued_writes) {
            self.write(w);
        }
    }

    pub fn set_now(&mut self, now: u64) {
        self.now = now;
        if self.ticks {
            let fx = self.host.advance(now);
            self.apply(fx);
        }
    }

    /// `client` sends `json` on its current attachment.
    pub fn send(&mut self, client: &str, json: &Value) {
        let att = self.attachment(client);
        self.send_on(&att, json);
    }

    /// Sends `json` on a specific (possibly fenced) attachment.
    pub fn send_on(&mut self, attachment: &str, json: &Value) {
        let msg = wire::decode(&serde_json::to_vec(json).unwrap());
        let fx = self.host.receive_decoded(attachment, msg, self.now);
        self.apply(fx);
    }

    /// Messages `client` received since the last call, as wire JSON.
    pub fn take(&mut self, client: &str) -> Vec<Value> {
        let (mine, rest) = std::mem::take(&mut self.out)
            .into_iter()
            .partition(|(n, _)| n == client);
        self.out = rest;
        mine.into_iter()
            .map(|(_, m): (String, Envelope)| wire::to_value(&m))
            .collect()
    }

    pub fn lease_holder(&self) -> Result<Value, String> {
        let sid = self.only_session()?;
        Ok(self
            .host
            .lease_holder(&sid)
            .map_or(Value::Null, |att| Value::from(self.names[att].clone())))
    }
}

impl<J: Journal + FailFsync> FakeRuntime<J> {
    /// The runtime stops (orderly: it writes its clean close when the
    /// journal is healthy; a crash doesn't) and starts with these values at
    /// the current clock; workers are adopted, every link drops.
    fn restart_runtime(
        &mut self,
        runtime_gen: &str,
        epoch: u64,
        orderly: bool,
    ) -> Result<(), String> {
        self.live.clear();
        self.queued_writes.clear();
        // Every link drops with its conversations; a new run has a new
        // `next` key.
        for c in self.chats.values_mut() {
            c.conversations = Conversations::default();
        }
        self.history_key = HistoryKey::random();
        let fx = self
            .host
            .restart_at(runtime_gen, epoch, self.now, orderly)?;
        self.apply(fx);
        Ok(())
    }
}

impl<J: Journal + FailFsync> HostUnderTest for FakeRuntime<J> {
    /// The host sees the time with the message; no timer tick is run.
    fn receive(&mut self, client: &str, msg: Result<Envelope, DecodeError>, now_ms: u64) {
        self.now = now_ms;
        let att = self.attachment(client);
        let fx = self.host.receive_decoded(&att, msg, now_ms);
        if self.crash_after.is_some() && self.host.journal().crashed() {
            // The `accepted` record is durable; the runtime dies before
            // acting on it: nothing it produced happens.
            let (runtime_gen, epoch) = self.crash_after.take().unwrap();
            self.restart_runtime(&runtime_gen, epoch, false)
                .expect("crash restart");
            return;
        }
        self.apply(fx);
    }

    fn advance(&mut self, now_ms: u64) {
        self.set_now(now_ms);
    }

    /// Events don't tick the host's timers either (`advance_ms` does).
    fn event(&mut self, event: &HostEvent, now_ms: u64) -> Result<(), String> {
        self.now = now_ms;
        let fx = match event {
            HostEvent::Disconnect { client } => {
                let att = self.attachment(client);
                self.live.remove(&att);
                self.host.disconnect(&att)
            }
            HostEvent::Resume {
                client,
                attachment_gen,
            } => {
                // Compatibility mode has no resume: the host refuses it and
                // the new attachment stays unwelcomed.
                let c = self.clients.get_mut(client).ok_or("unknown client")?;
                c.attachment_gen = attachment_gen.clone();
                let attach = Attach {
                    client: client.clone(),
                    principal: client.clone(),
                    attachment_gen: attachment_gen.clone(),
                    permissions: c.permissions.clone(),
                    client_kind: c.client_kind,
                    authorization_ms: AUTHORIZATION_MS,
                };
                let fx = self.host.connect(attach)?;
                self.apply(fx);
                self.names.insert(attachment_gen.clone(), client.clone());
                self.live.insert(attachment_gen.clone(), client.clone());
                let resume = Some(wire::Resume {
                    controller_session: uuid::Uuid::new_v4().to_string(),
                });
                let hello = Op::Hello {
                    revision: Some(REVISION),
                    resume,
                };
                self.host
                    .receive_decoded(attachment_gen, Ok(message(hello)), self.now)
            }
            HostEvent::Reconnect {
                client,
                attachment_gen,
            } => return self.attach(client, attachment_gen),
            HostEvent::LocalInput { session_id, bytes } => {
                if bytes.ends_with(b"\r") || bytes.ends_with(b"\n") {
                    self.drafts.remove(session_id);
                } else {
                    self.drafts.insert(session_id.clone());
                }
                self.host.local_input(session_id, bytes.clone())
            }
            HostEvent::CrashWorker { session_id } => self.host.process_exited(session_id, None),
            HostEvent::RestartRuntime {
                runtime_gen,
                runtime_epoch,
            } => return self.restart_runtime(runtime_gen, *runtime_epoch, true),
            HostEvent::CrashRuntime {
                runtime_gen,
                runtime_epoch,
            } => return self.restart_runtime(runtime_gen, *runtime_epoch, false),
            HostEvent::CrashAfterAccepted {
                runtime_gen,
                runtime_epoch,
            } => {
                self.host.journal_mut().crash_after_accepted();
                self.crash_after = Some((runtime_gen.clone(), *runtime_epoch));
                Vec::new()
            }
            HostEvent::FailFsyncOf { n, undo_fails } => {
                self.host.journal_mut().fail_fsync_of(*n, *undo_fails);
                Vec::new()
            }
            HostEvent::SetPermissions {
                client,
                permissions,
                attachment_gen,
            } => {
                // The principal re-authenticates: a new attachment with these
                // permissions (the host fences first when `control` is gone).
                let c = self.clients.get_mut(client).ok_or("unknown client")?;
                c.permissions = permissions.clone();
                return self.attach(client, attachment_gen);
            }
            HostEvent::ReplaceProcess {
                session_id,
                process_gen,
            } => {
                self.turns.remove(session_id);
                if let Some(c) = self.chats.get_mut(session_id) {
                    c.chat = ChatSession::new(process_gen.clone(), 0);
                    c.conversations = Conversations::default();
                }
                self.host.replace_process(session_id, process_gen)?
            }
            HostEvent::ChangeTrustGen(n) => self.host.change_trust_gen(*n)?,
            HostEvent::FailNextPtyEnqueue => {
                self.pty.fail_next_enqueue = true;
                Vec::new()
            }
            HostEvent::FailNextPtyWriteAfterPartial => {
                self.pty.fail_next_partial = true;
                Vec::new()
            }
            HostEvent::CloseSession { session_id } => self.host.close_session(session_id, false),
            HostEvent::TurnComplete {
                session_id,
                turn_id,
            } => {
                let rid = self.turns.remove(session_id).ok_or("no running turn")?;
                // A prompt's completion names its turn's outcome (§6) and,
                // r8 §D, its user message in the chat history.
                let user_message_id = self
                    .chats
                    .get(session_id)
                    .and_then(|c| c.chat.user_message_of(&rid))
                    .map(str::to_string);
                let report = DispatchReport::Completed {
                    detail: Some(super::host::DETAIL_TURN_DONE.into()),
                    turn_id: Some(turn_id.clone()),
                    user_message_id,
                };
                let fx = self.host.dispatch_report(&rid, report);
                // The chat's turn end, to every conversation but the chat
                // submitter's (it hears through its receipt).
                let except = self.chat_submitters.remove(&rid).map(|(_, c)| c);
                let complete = Out::Complete {
                    turn_id: turn_id.clone(),
                    request_id: Some(rid),
                    outcome: Outcome::Done,
                };
                self.apply(fx);
                self.broadcast(session_id, &complete, except.as_deref(), false);
                Vec::new()
            }
            HostEvent::HoldPtyWrites => {
                self.hold_writes = true;
                Vec::new()
            }
            HostEvent::FlushPtyWrites => {
                self.flush_writes();
                Vec::new()
            }
            HostEvent::OpenApproval {
                session_id,
                tool,
                summary,
                always_rules,
                turn_id,
            } => {
                let info = super::host::ApprovalInfo {
                    tool: tool.clone(),
                    summary: summary.clone(),
                    always_rules: always_rules.clone(),
                };
                let process_gen = self.process_gen(session_id);
                // Refused: the agent's own prompt asks; nothing is sent.
                let (opened, fx) = self
                    .host
                    .open_approval(session_id, &process_gen, info, now_ms);
                self.apply(fx);
                if let (Ok(approval_id), true) = (opened, self.chats.contains_key(session_id)) {
                    let card = ApprovalCard {
                        id: "approval".into(),
                        approval_id: approval_id.clone(),
                        tool: tool.clone(),
                        summary: summary.clone(),
                        always_rules: always_rules.clone(),
                        state: ApprovalCardState::Pending,
                        rule_id: None,
                        note: None,
                        reason: None,
                    };
                    let turn = turn_id.clone().unwrap_or_else(|| "approval".into());
                    self.cards
                        .insert(approval_id.clone(), (session_id.clone(), card, turn));
                    self.show_card(&approval_id);
                }
                Vec::new()
            }
            HostEvent::CloseApproval {
                approval_id,
                reason,
            } => {
                let fx = self.host.close_approval(approval_id, *reason);
                self.apply(fx);
                // The card says how it ended (as the runtime's does).
                let state = match reason {
                    ApprovalCloseReason::AnsweredRemote => None,
                    ApprovalCloseReason::AnsweredTerminal => {
                        Some(ApprovalCardState::AnsweredTerminal)
                    }
                    ApprovalCloseReason::TimedOut => Some(ApprovalCardState::Expired),
                    _ => Some(ApprovalCardState::Closed),
                };
                if let (Some(state), Some((_, card, _))) = (state, self.cards.get_mut(approval_id))
                {
                    card.state = state;
                    card.reason.get_or_insert(*reason);
                    self.show_card(approval_id);
                }
                Vec::new()
            }
            HostEvent::ChatHistory { .. }
            | HostEvent::ChatMessage { .. }
            | HostEvent::ChatEvict { .. }
            | HostEvent::ChatTurn { .. }
            | HostEvent::WorkerGap { .. } => {
                self.chat_event(event)?;
                Vec::new()
            }
            HostEvent::ApprovalApplied { approval_id, ok } => {
                self.host.approval_applied(approval_id, *ok)
            }
            HostEvent::ApprovalRules { session_id, rules } => {
                let process_gen = self.process_gen(session_id);
                self.host
                    .set_approval_rules(session_id, &process_gen, rules.clone())?
            }
        };
        self.apply(fx);
        Ok(())
    }

    fn drain_outgoing(&mut self) -> Vec<(String, Envelope)> {
        std::mem::take(&mut self.out)
    }

    fn counter(&self, key: &str) -> Result<Value, String> {
        let p = &self.pty;
        Ok(match key {
            "dispatch_attempts" => p.dispatch_attempts.into(),
            "dispatches" => p.dispatches.into(),
            "pty_bytes_written" => p.bytes_written.map_or("unknown".into(), Value::from),
            "pty_writes" => (p.writes_local + p.writes_remote).into(),
            "pty_writes_local" => p.writes_local.into(),
            "pty_writes_remote" => p.writes_remote.into(),
            "pty_writes_dropped" => p.dropped_remote.into(),
            "resizes" => p.resizes.into(),
            "stops" => p.stops.into(),
            "lease_holder" => self.lease_holder()?,
            "attachments" => self.host.welcomed_attachments().into(),
            "chat_opens" => self.chat_opens.into(),
            "chat_closes" => self.chat_closes.into(),
            "chat_conversations" => self
                .chats
                .values()
                .map(|c| c.conversations.map.len())
                .sum::<usize>()
                .into(),
            "journal_halted" => self.host.journal_halted().into(),
            "approval_decisions" => Value::from(p.approval_decisions.clone()),
            "approvals_released" => p.approvals_released.into(),
            "pushes" => Value::from(p.pushes.clone()),
            "rule_revokes" => Value::from(p.rule_revokes.clone()),
            "approvals_pending" => self
                .host
                .pending_approvals(&self.only_session()?)
                .len()
                .into(),
            "receipts_visible" => Value::Object(
                self.clients
                    .iter()
                    .map(|(name, c)| {
                        let n = self.host.receipts_visible(&c.attachment_gen);
                        (name.clone(), Value::from(n))
                    })
                    .collect(),
            ),
            other => return Err(format!("unknown host counter {other:?}")),
        })
    }
}
