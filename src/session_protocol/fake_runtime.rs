//! A fake runtime around `SessionHost` for the shared fixtures and the host
//! unit tests: it performs the host's effects against a fake PTY and
//! dispatcher (with the fixtures' failure injection), keeps a `MemJournal`,
//! and plays each fixture client's transport (connect, `hello`/`welcome`,
//! reconnect).
//!
//! The fixtures describe clients that are already attached; the harness does
//! the `hello`/`welcome` itself (checking the welcome) and, for
//! `holds_lease_epoch`, a real `acquire`, so every lease and attachment comes
//! from the host's own rules.

use super::fixtures::{HostEvent, HostUnderTest, Setup};
use super::host::{
    Attach, ChatReply, DispatchReport, Effect, HostConfig, HostContext, Origin, SessionHost,
    SessionSpec, random_ids,
};
use super::journal::{Journal, MemJournal};
use super::wire::{
    self, Binding, ClientKind, DecodeError, Envelope, Op, Permission, ReceiptKind, SessionMessage,
    Target,
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap, VecDeque};

/// The authenticated link's authorization in the fixtures (24 h).
pub const AUTHORIZATION_MS: u64 = 24 * 60 * 60 * 1000;

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

/// Fixture failure injection on a journal (`fail_next_fsync`).
pub trait FailFsync {
    fn fail_next_fsync(&mut self);
}

impl FailFsync for MemJournal {
    fn fail_next_fsync(&mut self) {
        MemJournal::fail_next_fsync(self);
    }
}

impl FailFsync for super::file_journal::FileJournal {
    fn fail_next_fsync(&mut self) {
        self.inject(super::file_journal::Fault::Fsync);
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
    clients: BTreeMap<String, Client>,
    /// Every attachment ever used → client name.
    names: HashMap<String, String>,
    live: HashMap<String, String>,
    sessions: Vec<String>,
    out: Vec<(String, Envelope)>,
    /// Every effect the host produced, in order.
    pub effects: Vec<Effect>,
    now: u64,
}

fn message(op: Op) -> Envelope {
    Envelope::Session(SessionMessage {
        id: uuid::Uuid::new_v4().to_string(),
        re: None,
        op,
    })
}

/// Renders a chat reply as the chat runtime would (without its stream head).
fn render_chat(conversation_id: &str, session_id: &str, reply: ChatReply) -> Envelope {
    let mut data = json!({"v": 1, "conversationId": conversation_id, "agentId": session_id});
    let body = match reply {
        ChatReply::Accepted { request_id } => json!({"op": "accepted", "requestId": request_id}),
        ChatReply::Complete {
            request_id,
            turn_id,
        } => {
            let mut b = json!({"op": "complete", "requestId": request_id, "outcome": "done"});
            if let Some(t) = turn_id {
                b["turnId"] = Value::String(t);
            }
            b
        }
        ChatReply::Error {
            request_id,
            code,
            text,
        } => {
            let mut b = json!({"op": "error", "code": code, "text": text});
            if let Some(r) = request_id {
                b["requestId"] = Value::String(r);
            }
            b
        }
    };
    data.as_object_mut()
        .unwrap()
        .extend(body.as_object().unwrap().clone());
    Envelope::Family(wire::FamilyMessage {
        family: "agentChat".into(),
        data: Some(data),
        binding: None,
        request: None,
    })
}

impl FakeRuntime {
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
            clients: BTreeMap::new(),
            names: HashMap::new(),
            live: HashMap::new(),
            sessions: Vec::new(),
            out: Vec::new(),
            effects: Vec::new(),
            now: 0,
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
            rt.attach(&c.name, &c.attachment_gen)?;
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

    /// A new attachment for `client`: connect (fencing the previous one),
    /// `hello`, and the checked `welcome` taken off the queue.
    pub fn attach(&mut self, client: &str, attachment_gen: &str) -> Result<(), String> {
        let c = self.clients.get_mut(client).ok_or("unknown client")?;
        c.attachment_gen = attachment_gen.to_string();
        let attach = Attach {
            client: client.to_string(),
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
        let fx = self.host.receive_decoded(
            attachment_gen,
            Ok(message(Op::Hello { resume: None })),
            self.now,
        );
        self.apply(fx);
        let i = self
            .out
            .iter()
            .rposition(|(n, m)| {
                n == client
                    && matches!(m, Envelope::Session(s) if matches!(s.op, Op::Welcome { .. }))
            })
            .ok_or("no welcome")?;
        let (_, welcome) = self.out.remove(i);
        match welcome {
            Envelope::Session(SessionMessage {
                op: Op::Welcome {
                    attachment_gen: g, ..
                },
                ..
            }) if g == attachment_gen => Ok(()),
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
                    message,
                } => {
                    if let Some(name) = self.live.get(&attachment) {
                        self.out.push((name.clone(), message));
                    }
                }
                Effect::Close { attachment } => {
                    self.live.remove(&attachment);
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
                    let report = if std::mem::take(&mut self.pty.fail_next_enqueue) {
                        Some(DispatchReport::FailedNoEffect)
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
                        // Written; completion comes from the provider later.
                        None
                    };
                    if report != Some(DispatchReport::FailedNoEffect) {
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
                    if let Some(name) = self.live.get(&attachment) {
                        let msg = render_chat(&conversation_id, &session_id, reply);
                        self.out.push((name.clone(), msg));
                    }
                }
                Effect::StreamOpened { .. }
                | Effect::StreamClosed { .. }
                | Effect::Forward { .. } => {}
            }
        }
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

impl<J: Journal + FailFsync> HostUnderTest for FakeRuntime<J> {
    /// The host sees the time with the message; no timer tick is run.
    fn receive(&mut self, client: &str, msg: Result<Envelope, DecodeError>, now_ms: u64) {
        self.now = now_ms;
        let att = self.attachment(client);
        let fx = self.host.receive_decoded(&att, msg, now_ms);
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
                self.host.receive_decoded(
                    attachment_gen,
                    Ok(message(Op::Hello { resume })),
                    self.now,
                )
            }
            HostEvent::Reconnect {
                client,
                attachment_gen,
            } => return self.attach(client, attachment_gen),
            HostEvent::LocalInput { session_id, bytes } => {
                self.host.local_input(session_id, bytes.clone())
            }
            HostEvent::CrashWorker { session_id } => self.host.process_exited(session_id, None),
            HostEvent::RestartRuntime {
                runtime_gen,
                runtime_epoch,
            } => {
                self.live.clear();
                self.queued_writes.clear();
                self.host.restart(runtime_gen, *runtime_epoch)?
            }
            HostEvent::FailNextFsync => {
                self.host.journal_mut().fail_next_fsync();
                Vec::new()
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
                let report = DispatchReport::Completed {
                    detail: None,
                    turn_id: Some(turn_id.clone()),
                };
                self.host.dispatch_report(&rid, report)
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
            } => {
                let info = super::host::ApprovalInfo {
                    tool: tool.clone(),
                    summary: summary.clone(),
                    always_rules: always_rules.clone(),
                };
                let process_gen = self.process_gen(session_id);
                // Refused: the agent's own prompt asks; nothing is sent.
                let (_, fx) = self
                    .host
                    .open_approval(session_id, &process_gen, info, now_ms);
                fx
            }
            HostEvent::CloseApproval {
                approval_id,
                reason,
            } => self.host.close_approval(approval_id, *reason),
            HostEvent::ApprovalApplied { approval_id, ok } => {
                self.host.approval_applied(approval_id, *ok)
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
            "approval_decisions" => Value::from(p.approval_decisions.clone()),
            "approvals_released" => p.approvals_released.into(),
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
