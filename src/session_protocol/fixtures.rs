//! Data-driven runner for the shared atem-session v1 fixtures
//! (`designs/protocol/fixtures/*.json`, format in `fixtures/schema.md`).
//!
//! Every scenario file in the directory is read at test time, so a new fixture
//! needs no Rust change. Wire messages in both directions go through the strict
//! `wire::decode`. `side:"client"` scenarios run against `LeaseClient` and
//! `RegistryClient` with the fixture playing the host; host scenarios run
//! against a `HostUnderTest` (`SessionHost` inside `fake_runtime::FakeRuntime`)
//! with the fixture playing the clients. `run_all` without a host reports host
//! scenarios as skipped, by name; the fixture test runs them all and asserts
//! that nothing was skipped.
//!
//! Unknown actions, unknown assertion keys and unknown `setup` fields fail the
//! scenario instead of being ignored.

use super::client::{LeaseClient, LeaseRequest, RegistryClient};
use super::wire::{
    self, AlwaysRule, ApprovalCloseReason, ClientKind, DecodeError, Envelope, Op, Permission,
};
use serde::Deserialize;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::{Path, PathBuf};

// ── Scenario model ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostSetup {
    pub account_id: String,
    pub atem_device_id: String,
    pub host_trust_gen: u64,
    pub runtime_gen: String,
    pub runtime_epoch: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionSetup {
    pub session_id: String,
    pub process_gen: String,
    #[serde(default)]
    pub chat: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientSetup {
    pub name: String,
    pub attachment_gen: String,
    pub permissions: Vec<Permission>,
    pub client_kind: ClientKind,
    #[serde(default)]
    pub holds_lease_epoch: Option<u64>,
    /// r8 draft: `false` leaves the client without the harness's `hello`.
    #[serde(default)]
    pub welcome: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Setup {
    pub host: HostSetup,
    #[serde(default)]
    pub sessions: Vec<SessionSetup>,
    pub clients: Vec<ClientSetup>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Side {
    #[default]
    Host,
    Client,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    pub name: String,
    #[serde(default)]
    pub side: Side,
    /// A contract revision this runner doesn't implement yet (`"r8"`): the
    /// scenario is parsed and reported as not run.
    #[serde(default)]
    pub requires: Option<String>,
    pub setup: Setup,
    pub steps: Vec<Value>,
    /// Documentation for readers; not interpreted.
    #[serde(default)]
    #[allow(dead_code)]
    pub note: Option<String>,
}

/// Transport, failure and durability events a host scenario injects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostEvent {
    Disconnect {
        client: String,
    },
    Resume {
        client: String,
        attachment_gen: String,
    },
    Reconnect {
        client: String,
        attachment_gen: String,
    },
    LocalInput {
        session_id: String,
        bytes: Vec<u8>,
    },
    CrashWorker {
        session_id: String,
    },
    RestartRuntime {
        runtime_gen: String,
        runtime_epoch: u64,
    },
    FailNextFsync,
    ChangeTrustGen(u64),
    FailNextPtyEnqueue,
    FailNextPtyWriteAfterPartial,
    /// The runtime closes the session (it no longer accepts work).
    CloseSession {
        session_id: String,
    },
    /// The provider reports the end of the session's executing prompt turn.
    TurnComplete {
        session_id: String,
        turn_id: String,
    },
    /// Remote PTY writes queue at the writer until `FlushPtyWrites`.
    HoldPtyWrites,
    /// The writer writes the queued chunks now (each checked at the write
    /// boundary).
    FlushPtyWrites,
    /// The agent asks a permission prompt the runtime offers for remote
    /// answers (r7); refused silently when the host won't open it.
    OpenApproval {
        session_id: String,
        tool: String,
        summary: String,
        always_rules: Vec<AlwaysRule>,
    },
    /// The runtime saw the approval end without the remote answer.
    CloseApproval {
        approval_id: String,
        reason: ApprovalCloseReason,
    },
    /// The agent's report on a handed-over answer.
    ApprovalApplied {
        approval_id: String,
        ok: bool,
    },
    /// The runtime reports the session's active Atem session rules (r7.2).
    ApprovalRules {
        session_id: String,
        rules: Vec<AlwaysRule>,
    },
}

/// The host authority under test (`fake_runtime::FakeRuntime`).
pub trait HostUnderTest {
    /// A client's message arrives at `now_ms` (monotonic). It already went
    /// through the strict decoder; a decode failure is passed on so the host
    /// can answer it.
    fn receive(&mut self, client: &str, msg: Result<Envelope, DecodeError>, now_ms: u64);
    /// The clock moved to `now_ms`; timers due by then fire.
    fn advance(&mut self, now_ms: u64);
    fn event(&mut self, event: &HostEvent, now_ms: u64) -> Result<(), String>;
    /// Host→client messages produced since the last call, in send order.
    fn drain_outgoing(&mut self) -> Vec<(String, Envelope)>;
    /// The value of an `assert` key (`dispatch_attempts`, `pty_writes`,
    /// `lease_holder` (client name or null), `receipts_visible` (object by
    /// client), …); an unknown key is an `Err`.
    fn counter(&self, key: &str) -> Result<Value, String>;
}

pub type HostFactory<'a> = &'a dyn Fn(&Setup) -> Result<Box<dyn HostUnderTest>, String>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Passed,
    Skipped,
    /// Needs a contract revision not implemented yet (`requires`).
    NotRun,
}

#[derive(Debug, Default)]
pub struct Report {
    pub passed: Vec<String>,
    pub skipped: Vec<String>,
    pub not_run: Vec<String>,
    pub failed: Vec<(String, String)>,
}

pub fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("designs/protocol/fixtures")
}

/// Every scenario file in `dir` (all `*.json` except the digest vectors),
/// sorted by name.
pub fn scenario_paths(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .expect("read fixtures dir")
        .map(|e| e.expect("fixtures dir entry").path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .filter(|p| p.file_name().is_some_and(|n| n != "digest-vectors.json"))
        .collect();
    files.sort();
    files
}

/// Runs every scenario in `dir`; host scenarios are skipped when `host` is
/// `None`.
pub fn run_all(dir: &Path, host: Option<HostFactory>) -> Report {
    let mut report = Report::default();
    for path in scenario_paths(dir) {
        let file = path.file_name().unwrap().to_string_lossy().into_owned();
        let parsed = std::fs::read(&path)
            .map_err(|e| e.to_string())
            .and_then(|b| serde_json::from_slice::<Value>(&b).map_err(|e| e.to_string()));
        let (name, result) = match parsed {
            Ok(v) => {
                let name = v["name"].as_str().unwrap_or(&file).to_string();
                let stem = file.trim_end_matches(".json");
                let result = if name != stem {
                    Err(format!("scenario name {name:?} differs from its file name"))
                } else {
                    run_scenario(&v, host)
                };
                (name, result)
            }
            Err(e) => (file, Err(e)),
        };
        match result {
            Ok(Outcome::Passed) => report.passed.push(name),
            Ok(Outcome::Skipped) => report.skipped.push(name),
            Ok(Outcome::NotRun) => report.not_run.push(name),
            Err(e) => report.failed.push((name, e)),
        }
    }
    report
}

/// Runs one scenario (the parsed JSON of a fixture file).
pub fn run_scenario(file: &Value, host: Option<HostFactory>) -> Result<Outcome, String> {
    let scenario: Scenario =
        serde_json::from_value(file.clone()).map_err(|e| format!("scenario: {e}"))?;
    if scenario.requires.is_some() {
        return Ok(Outcome::NotRun);
    }
    if scenario.setup.clients.iter().any(|c| c.welcome.is_some()) {
        return Err(format!("{}: welcome needs requires", scenario.name));
    }
    let mut runner = match scenario.side {
        Side::Host => match host {
            None => return Ok(Outcome::Skipped),
            Some(factory) => {
                let host = factory(&scenario.setup)
                    .map_err(|e| format!("{}: setup: {e}", scenario.name))?;
                Runner::new(&scenario, Some(host))
            }
        },
        Side::Client => {
            if scenario
                .setup
                .clients
                .iter()
                .any(|c| c.holds_lease_epoch.is_some())
            {
                return Err(format!(
                    "{}: holds_lease_epoch is a host-side setup",
                    scenario.name
                ));
            }
            Runner::new(&scenario, None)
        }
    };
    for (i, step) in scenario.steps.iter().enumerate() {
        runner
            .step(step)
            .map_err(|e| format!("{}: step {i} {step}: {e}", scenario.name))?;
    }
    runner
        .all_consumed()
        .map_err(|e| format!("{}: at the end: {e}", scenario.name))?;
    Ok(Outcome::Passed)
}

/// Replaces `${name}` in every string with the captured value: a string that
/// is exactly one placeholder takes the value itself (any JSON type).
pub fn substitute(v: &mut Value, vars: &HashMap<String, Value>) -> Result<(), String> {
    match v {
        Value::String(s) if s.contains("${") => {
            let whole = s
                .strip_prefix("${")
                .and_then(|r| r.strip_suffix('}'))
                .filter(|n| !n.contains(['$', '{', '}']));
            if let Some(name) = whole {
                *v = vars
                    .get(name)
                    .cloned()
                    .ok_or(format!("${{{name}}} not captured"))?;
                return Ok(());
            }
            let mut out = String::new();
            let mut rest = s.as_str();
            while let Some(start) = rest.find("${") {
                out.push_str(&rest[..start]);
                let end = rest[start..].find('}').ok_or("unterminated ${")? + start;
                let name = &rest[start + 2..end];
                match vars.get(name) {
                    Some(Value::String(t)) => out.push_str(t),
                    Some(other) => out.push_str(&other.to_string()),
                    None => return Err(format!("${{{name}}} not captured")),
                }
                rest = &rest[end + 1..];
            }
            out.push_str(rest);
            *s = out;
            Ok(())
        }
        Value::Array(a) => a.iter_mut().try_for_each(|c| substitute(c, vars)),
        Value::Object(m) => m.values_mut().try_for_each(|c| substitute(c, vars)),
        _ => Ok(()),
    }
}

// ── Runner ────────────────────────────────────────────────────────────────

/// The client machines one fixture client drives (client scenarios).
struct ClientMachines {
    registry: RegistryClient,
    leases: BTreeMap<String, LeaseClient>,
    /// `list` requests the registry machine asked for (not fixture sends).
    lists_requested: u64,
    authorization_deadline: Option<u64>,
    attachment_gen: String,
}

struct Runner {
    now: u64,
    vars: HashMap<String, Value>,
    side: Side,
    client_names: Vec<String>,
    sessions: Vec<String>,
    host: Option<Box<dyn HostUnderTest>>,
    /// Host→client messages (wire JSON) not yet expected, per client.
    queues: HashMap<String, VecDeque<Value>>,
    holds: Vec<(String, String)>,
    held: Vec<(String, Value)>,
    clients: HashMap<String, ClientMachines>,
}

/// Decodes `msg` strictly, as the receiving side would.
fn decode_value(msg: &Value) -> Result<Envelope, DecodeError> {
    wire::decode(&serde_json::to_vec(msg).expect("JSON serializes"))
}

fn take<'a>(step: &'a Map<String, Value>, key: &str) -> Result<&'a Value, String> {
    step.get(key).ok_or(format!("missing {key:?}"))
}

fn as_str<'a>(v: &'a Value, what: &str) -> Result<&'a str, String> {
    v.as_str().ok_or(format!("{what} must be a string"))
}

fn as_u64(v: &Value, what: &str) -> Result<u64, String> {
    v.as_u64()
        .ok_or(format!("{what} must be a non-negative integer"))
}

/// Dotted path into a message's `data` (`receipts.0.state`); `#` is an
/// array's length (`receipts.#`).
fn lookup(data: &Value, path: &str) -> Option<Value> {
    path.split('.').try_fold(data.clone(), |v, part| match v {
        Value::Object(mut m) => m.remove(part),
        Value::Array(a) if part == "#" => Some(Value::from(a.len())),
        Value::Array(mut a) => part
            .parse::<usize>()
            .ok()
            .filter(|i| *i < a.len())
            .map(|i| a.swap_remove(i)),
        _ => None,
    })
}

fn same(expected: &Value, got: Option<&Value>, what: &str) -> Result<(), String> {
    match got {
        Some(g) if g == expected => Ok(()),
        _ => Err(format!(
            "{what}: expected {expected}, got {}",
            got.map_or("nothing".into(), |g| g.to_string())
        )),
    }
}

impl Runner {
    fn new(s: &Scenario, host: Option<Box<dyn HostUnderTest>>) -> Self {
        let client_names: Vec<String> = s.setup.clients.iter().map(|c| c.name.clone()).collect();
        let clients = if s.side == Side::Client {
            s.setup
                .clients
                .iter()
                .map(|c| {
                    let m = ClientMachines {
                        registry: RegistryClient::default(),
                        leases: BTreeMap::new(),
                        lists_requested: 0,
                        authorization_deadline: None,
                        attachment_gen: c.attachment_gen.clone(),
                    };
                    (c.name.clone(), m)
                })
                .collect()
        } else {
            HashMap::new()
        };
        Self {
            now: 0,
            vars: HashMap::new(),
            side: s.side,
            queues: client_names
                .iter()
                .map(|n| (n.clone(), VecDeque::new()))
                .collect(),
            client_names,
            sessions: s
                .setup
                .sessions
                .iter()
                .map(|x| x.session_id.clone())
                .collect(),
            host,
            holds: Vec::new(),
            held: Vec::new(),
            clients,
        }
    }

    fn client<'a>(&self, v: &'a Value) -> Result<&'a str, String> {
        let name = as_str(v, "client")?;
        if self.client_names.iter().any(|n| n == name) {
            Ok(name)
        } else {
            Err(format!("unknown client {name:?}"))
        }
    }

    fn host(&mut self) -> Result<&mut Box<dyn HostUnderTest>, String> {
        self.host
            .as_mut()
            .ok_or("this action needs side \"host\"".to_string())
    }

    fn step(&mut self, raw: &Value) -> Result<(), String> {
        let mut step = raw.clone();
        substitute(&mut step, &self.vars)?;
        let Value::Object(step) = step else {
            return Err("a step must be an object".into());
        };
        // The action key, and the companion keys it allows.
        const ACTIONS: &[(&str, &[&str])] = &[
            ("send", &["json"]),
            ("expect", &["type", "match", "capture"]),
            ("expect_all", &[]),
            ("expect_none", &["for_ms"]),
            ("advance_ms", &["timers"]),
            ("hold", &[]),
            ("deliver", &[]),
            ("deliver_to_client", &["json"]),
            ("disconnect", &[]),
            ("resume", &["attachment_gen"]),
            ("reconnect", &["attachment_gen"]),
            ("local_input", &["bytes"]),
            ("crash_worker", &[]),
            ("restart_runtime", &[]),
            ("fail_next_fsync", &[]),
            ("change_trust_gen", &[]),
            ("fail_next_pty_enqueue", &[]),
            ("fail_next_pty_write_after_partial", &[]),
            ("close_session", &[]),
            ("turn_complete", &["turn_id"]),
            ("hold_pty_writes", &[]),
            ("flush_pty_writes", &[]),
            ("open_approval", &["tool", "summary", "always_rules"]),
            ("close_approval", &["reason"]),
            ("approval_applied", &["ok"]),
            ("approval_rules", &["rules"]),
            ("assert", &[]),
            ("assert_client", &[]),
        ];
        let found: Vec<_> = ACTIONS
            .iter()
            .filter(|(a, _)| step.contains_key(*a))
            .collect();
        let [(action, companions)] = found.as_slice() else {
            return Err(format!(
                "expected exactly one action, found {}",
                found.len()
            ));
        };
        if let Some(k) = step
            .keys()
            .find(|k| *k != action && !companions.contains(&k.as_str()))
        {
            return Err(format!("unexpected key {k:?} for {action}"));
        }
        let arg = &step[*action];
        match (*action, self.side) {
            ("advance_ms", _) => {
                self.now += as_u64(arg, "advance_ms")?;
                match step.get("timers") {
                    None | Some(Value::Bool(true)) => self.pump_advance(),
                    // Only the clock moves: the host sees the time with the
                    // next message or write check, never through a tick.
                    Some(Value::Bool(false)) => Ok(()),
                    Some(_) => Err("timers must be a boolean".into()),
                }
            }
            ("send", Side::Host) => {
                let client = self.client(arg)?.to_string();
                let msg = decode_value(take(&step, "json")?);
                let now = self.now;
                self.host()?.receive(&client, msg, now);
                self.pump()
            }
            ("send", Side::Client) => {
                let client = self.client(arg)?.to_string();
                self.client_send(&client, take(&step, "json")?)
            }
            ("deliver_to_client", Side::Client) => {
                let client = self.client(arg)?.to_string();
                self.client_deliver(&client, take(&step, "json")?)
            }
            ("assert_client", Side::Client) => self.assert_client(arg),
            ("expect", Side::Host) => {
                let client = self.client(arg)?.to_string();
                let empty = Value::Object(Map::new());
                let matches = step.get("match").unwrap_or(&empty);
                let ty = step.get("type").map(|t| as_str(t, "type")).transpose()?;
                let data = self.expect(&client, ty, matches)?;
                if let Some(capture) = step.get("capture") {
                    let capture = capture.as_object().ok_or("capture must be an object")?;
                    for (name, path) in capture {
                        let path = as_str(path, "capture path")?;
                        let v = lookup(&data, path)
                            .ok_or(format!("capture {path:?}: not in message"))?;
                        self.vars.insert(name.clone(), v.clone());
                    }
                }
                Ok(())
            }
            ("expect_all", Side::Host) => {
                for client in self.client_names.clone() {
                    self.expect(&client, None, arg)
                        .map_err(|e| format!("{client}: {e}"))?;
                }
                Ok(())
            }
            ("expect_none", Side::Host) => {
                let client = self.client(arg)?.to_string();
                self.now += as_u64(take(&step, "for_ms")?, "for_ms")?;
                self.pump_advance()?;
                match self.queues[&client].front() {
                    None => Ok(()),
                    Some(m) => Err(format!("{client} received {m}")),
                }
            }
            ("hold", Side::Host) => {
                let to = self.client(take(
                    arg.as_object().ok_or("hold must be an object")?,
                    "to",
                )?)?;
                let op = as_str(take(arg.as_object().unwrap(), "op")?, "hold.op")?;
                if arg.as_object().unwrap().len() != 2 {
                    return Err("hold takes exactly to and op".into());
                }
                self.holds.push((to.to_string(), op.to_string()));
                Ok(())
            }
            ("deliver", Side::Host) => {
                if arg != "held" {
                    return Err("deliver must be \"held\"".into());
                }
                if self.held.is_empty() {
                    return Err("nothing held".into());
                }
                for (client, msg) in std::mem::take(&mut self.held) {
                    self.queues.get_mut(&client).unwrap().push_back(msg);
                }
                Ok(())
            }
            ("assert", Side::Host) => self.assert_host(arg),
            (_, Side::Host) if !matches!(*action, "deliver_to_client" | "assert_client") => {
                let event = self.event(action, arg, &step)?;
                let now = self.now;
                self.host()?.event(&event, now)?;
                self.pump()
            }
            (action, side) => Err(format!("{action} is not supported for side {side:?}")),
        }
    }

    fn event(
        &self,
        action: &str,
        arg: &Value,
        step: &Map<String, Value>,
    ) -> Result<HostEvent, String> {
        let yes = |v: &Value| {
            if v == &Value::Bool(true) {
                Ok(())
            } else {
                Err(format!("{action} must be true"))
            }
        };
        let uuid = |v: &Value, what: &str| -> Result<String, String> {
            let s = as_str(v, what)?;
            if wire::is_uuid_v4(s) {
                Ok(s.to_string())
            } else {
                Err(format!("{what}: not a UUID v4"))
            }
        };
        Ok(match action {
            "disconnect" => HostEvent::Disconnect {
                client: self.client(arg)?.into(),
            },
            "resume" => HostEvent::Resume {
                client: self.client(arg)?.into(),
                attachment_gen: uuid(take(step, "attachment_gen")?, "attachment_gen")?,
            },
            "reconnect" => HostEvent::Reconnect {
                client: self.client(arg)?.into(),
                attachment_gen: uuid(take(step, "attachment_gen")?, "attachment_gen")?,
            },
            "local_input" => {
                use base64::{Engine, engine::general_purpose::STANDARD};
                let bytes = STANDARD
                    .decode(as_str(take(step, "bytes")?, "bytes")?)
                    .map_err(|e| format!("bytes: {e}"))?;
                HostEvent::LocalInput {
                    session_id: as_str(arg, "local_input")?.into(),
                    bytes,
                }
            }
            "crash_worker" => HostEvent::CrashWorker {
                session_id: as_str(arg, "crash_worker")?.into(),
            },
            "restart_runtime" => {
                let o = arg.as_object().ok_or("restart_runtime must be an object")?;
                if o.len() != 2 {
                    return Err("restart_runtime takes runtime_gen and runtime_epoch".into());
                }
                HostEvent::RestartRuntime {
                    runtime_gen: uuid(take(o, "runtime_gen")?, "runtime_gen")?,
                    runtime_epoch: as_u64(take(o, "runtime_epoch")?, "runtime_epoch")?,
                }
            }
            "fail_next_fsync" => yes(arg).map(|_| HostEvent::FailNextFsync)?,
            "change_trust_gen" => HostEvent::ChangeTrustGen(as_u64(arg, "change_trust_gen")?),
            "fail_next_pty_enqueue" => yes(arg).map(|_| HostEvent::FailNextPtyEnqueue)?,
            "fail_next_pty_write_after_partial" => {
                yes(arg).map(|_| HostEvent::FailNextPtyWriteAfterPartial)?
            }
            "close_session" => HostEvent::CloseSession {
                session_id: as_str(arg, "close_session")?.into(),
            },
            "turn_complete" => HostEvent::TurnComplete {
                session_id: as_str(arg, "turn_complete")?.into(),
                turn_id: as_str(take(step, "turn_id")?, "turn_id")?.into(),
            },
            "hold_pty_writes" => yes(arg).map(|_| HostEvent::HoldPtyWrites)?,
            "flush_pty_writes" => yes(arg).map(|_| HostEvent::FlushPtyWrites)?,
            "open_approval" => HostEvent::OpenApproval {
                session_id: as_str(arg, "open_approval")?.into(),
                tool: as_str(take(step, "tool")?, "tool")?.into(),
                summary: as_str(take(step, "summary")?, "summary")?.into(),
                always_rules: match step.get("always_rules") {
                    None => Vec::new(),
                    Some(v) => serde_json::from_value(v.clone())
                        .map_err(|e| format!("always_rules: {e}"))?,
                },
            },
            "close_approval" => HostEvent::CloseApproval {
                approval_id: as_str(arg, "close_approval")?.into(),
                reason: serde_json::from_value(take(step, "reason")?.clone())
                    .map_err(|e| format!("reason: {e}"))?,
            },
            "approval_applied" => HostEvent::ApprovalApplied {
                approval_id: as_str(arg, "approval_applied")?.into(),
                ok: take(step, "ok")?.as_bool().ok_or("ok must be a boolean")?,
            },
            "approval_rules" => HostEvent::ApprovalRules {
                session_id: as_str(arg, "approval_rules")?.into(),
                rules: serde_json::from_value(take(step, "rules")?.clone())
                    .map_err(|e| format!("rules: {e}"))?,
            },
            other => return Err(format!("{other} is not a host event")),
        })
    }

    // ── host side ──

    /// Every host message must have been expected: nothing may be left in a
    /// client's queue or held at the end of a scenario.
    fn all_consumed(&self) -> Result<(), String> {
        if let Some((client, msg)) = self.held.first() {
            return Err(format!("held message for {client} never delivered: {msg}"));
        }
        let mut names: Vec<&String> = self.queues.keys().collect();
        names.sort();
        for client in names {
            if let Some(m) = self.queues[client].front() {
                return Err(format!(
                    "{client} has {} unexpected message(s), first: {m}",
                    self.queues[client].len()
                ));
            }
        }
        Ok(())
    }

    fn pump_advance(&mut self) -> Result<(), String> {
        let now = self.now;
        if let Some(h) = self.host.as_mut() {
            h.advance(now);
            self.pump()?;
        }
        Ok(())
    }

    /// Moves the host's messages into the client queues, through the strict
    /// decoder, holding the first message of each armed `hold`.
    fn pump(&mut self) -> Result<(), String> {
        let out = self.host()?.drain_outgoing();
        for (client, env) in out {
            let bytes = wire::encode(&env);
            let env = wire::decode(&bytes)
                .map_err(|e| format!("host sent an invalid message to {client}: {e:?}"))?;
            let msg = wire::to_value(&env);
            let queue = self
                .queues
                .get_mut(&client)
                .ok_or(format!("host sent to unknown client {client:?}"))?;
            let op = msg["data"]["op"].as_str().unwrap_or_default();
            if let Some(i) = self.holds.iter().position(|(c, o)| *c == client && o == op) {
                self.holds.remove(i);
                self.held.push((client, msg));
            } else {
                queue.push_back(msg);
            }
        }
        Ok(())
    }

    /// Takes `client`'s next message of the selected `type` (when given) and
    /// `op` (`match.op`, when given) — messages of other types/ops stay queued
    /// for later expectations — and checks every `path: value` against its
    /// `data`; returns the `data`. A selected message that doesn't match fails.
    fn expect(&mut self, client: &str, ty: Option<&str>, matches: &Value) -> Result<Value, String> {
        let matches = matches.as_object().ok_or("match must be an object")?;
        let op = matches.get("op");
        let queue = self.queues.get_mut(client).unwrap();
        let selected = queue.iter().position(|m| {
            ty.is_none_or(|t| m["type"] == t) && op.is_none_or(|o| &m["data"]["op"] == o)
        });
        let msg = selected.and_then(|i| queue.remove(i)).ok_or(format!(
            "{client} received no {} message{}; queued: {queue:?}",
            ty.unwrap_or("matching"),
            op.map_or(String::new(), |o| format!(" with op {o}"))
        ))?;
        let data = msg.get("data").cloned().unwrap_or(Value::Null);
        for (path, expected) in matches {
            same(expected, lookup(&data, path).as_ref(), path)
                .map_err(|e| format!("{e} in {msg}"))?;
        }
        Ok(data)
    }

    fn assert_host(&mut self, arg: &Value) -> Result<(), String> {
        let o = arg.as_object().ok_or("assert must be an object")?;
        let host = self.host()?;
        for (key, expected) in o {
            let got = host.counter(key)?;
            match expected {
                Value::Object(per) => {
                    for (sub, exp) in per {
                        same(exp, got.get(sub), &format!("{key}.{sub}"))?;
                    }
                }
                _ => same(expected, Some(&got), key)?,
            }
        }
        Ok(())
    }

    // ── client side ──

    fn client_send(&mut self, client: &str, json: &Value) -> Result<(), String> {
        let env =
            decode_value(json).map_err(|e| format!("client request does not decode: {e:?}"))?;
        let Envelope::Session(msg) = env else {
            return Err("client machines only send session messages".into());
        };
        let now = self.now;
        let m = self.clients.get_mut(client).unwrap();
        let (kind, binding) = match &msg.op {
            Op::List {} => {
                m.registry.note_list_sent();
                return Ok(());
            }
            Op::Acquire { binding, .. } => (LeaseRequest::Acquire, binding),
            Op::Renew { binding } => (LeaseRequest::Renew, binding),
            Op::Release { binding } => (LeaseRequest::Release, binding),
            other => return Err(format!("client machines don't send {other:?}")),
        };
        if binding.attachment_gen != m.attachment_gen {
            return Err(format!("{client} sent with another attachment_gen"));
        }
        let auth = m.authorization_deadline;
        let lease = m
            .leases
            .entry(binding.target.session_id.clone())
            .or_insert_with(|| {
                let mut l =
                    LeaseClient::new(binding.target.clone(), binding.attachment_gen.clone());
                l.set_authorization_deadline(auth);
                l
            });
        if lease.target() != &binding.target {
            return Err("request targets another process of a known session".into());
        }
        lease
            .sent(&msg.id, kind, now)
            .map_err(|e| format!("client refused to send: {e:?}"))
    }

    fn client_deliver(&mut self, client: &str, json: &Value) -> Result<(), String> {
        let env = decode_value(json).map_err(|e| format!("host message does not decode: {e:?}"))?;
        let Envelope::Session(msg) = env else {
            return Err("client machines only model session messages".into());
        };
        let now = self.now;
        let m = self.clients.get_mut(client).unwrap();
        match &msg.op {
            Op::Lease { .. } | Op::LeaseReleased {} | Op::Error { .. } => {
                // Routed by `re`; a reply nobody is waiting for is dropped (rule 1).
                let re = msg.re.as_deref().unwrap_or_default();
                if let Some(l) = m.leases.values_mut().find(|l| l.is_outstanding(re)) {
                    l.on_reply(&msg, now);
                }
            }
            Op::LeaseChanged {
                session_id,
                process_gen,
                lease_epoch,
                ..
            } => {
                if let Some(l) = m.leases.get_mut(session_id) {
                    l.on_lease_changed(session_id, process_gen, *lease_epoch);
                }
            }
            Op::Sessions { .. }
            | Op::SessionChanged { .. }
            | Op::ApprovalRequest(_)
            | Op::ApprovalClosed { .. } => {
                m.registry.on_message(&msg.op);
                if m.registry.take_list_request() {
                    m.lists_requested += 1;
                    m.registry.note_list_sent();
                }
            }
            Op::Welcome {
                authorization_ms_left,
                ..
            } => {
                // A new attachment: its registry `seq` starts over.
                m.registry.new_attachment();
                let deadline = now.saturating_add(*authorization_ms_left);
                m.authorization_deadline = Some(deadline);
                m.leases
                    .values_mut()
                    .for_each(|l| l.set_authorization_deadline(Some(deadline)));
            }
            other => return Err(format!("client machines don't model {other:?}")),
        }
        Ok(())
    }

    fn assert_client(&mut self, arg: &Value) -> Result<(), String> {
        let o = arg.as_object().ok_or("assert_client must be an object")?;
        let now = self.now;
        // Client scenarios have one fixture client.
        let [name] = self.client_names.as_slice() else {
            return Err("assert_client needs exactly one client".into());
        };
        let m = &self.clients[name];
        let lease = match m.leases.len() {
            0 => None,
            1 => m.leases.values().next(),
            _ => match self.sessions.as_slice() {
                [only] => m.leases.get(only),
                _ => return Err("several leases: the assertion is ambiguous".into()),
            },
        };
        for (key, expected) in o {
            let got = match key.as_str() {
                "controls" => Value::Bool(lease.is_some_and(|l| l.controls(now))),
                "input_enabled" => Value::Bool(lease.is_some_and(|l| l.input_enabled(now))),
                "deadline_ms" => lease
                    .and_then(|l| l.deadline_ms(now))
                    .map_or(Value::Null, Value::from),
                "registry" => {
                    let mut want: Vec<String> = serde_json::from_value(expected.clone())
                        .map_err(|_| "registry must be a list of session ids")?;
                    want.sort();
                    let got = m.registry.session_ids();
                    if got != want {
                        return Err(format!("registry: expected {want:?}, got {got:?}"));
                    }
                    continue;
                }
                "registry_state" => {
                    let want = expected
                        .as_object()
                        .ok_or("registry_state must be an object")?;
                    for (id, state) in want {
                        let got = m
                            .registry
                            .session(id)
                            .map(|d| serde_json::to_value(d.state).unwrap());
                        same(state, got.as_ref(), &format!("registry_state.{id}"))?;
                    }
                    continue;
                }
                "approvals" => Value::from(
                    m.registry
                        .pending_approvals()
                        .map(|a| Value::from(a.approval_id.clone()))
                        .collect::<Vec<_>>(),
                ),
                "runtime_epoch" => m.registry.runtime_epoch().map_or(Value::Null, Value::from),
                "seq" => m.registry.seq().map_or(Value::Null, Value::from),
                "sent_list" => Value::Bool(m.lists_requested > 0),
                other => return Err(format!("unknown assert_client key {other:?}")),
            };
            same(expected, Some(&got), key)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The scenarios this runner implements (r8-draft ones, with
    /// `requires`, are left out; see `r8_draft_fixtures_parse_and_are_not_run`).
    fn scenario_files() -> Vec<(String, Value)> {
        scenario_paths(&fixtures_dir())
            .into_iter()
            .map(|p| {
                let v: Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
                (p.file_name().unwrap().to_string_lossy().into_owned(), v)
            })
            .filter(|(_, v)| v.get("requires").is_none())
            .collect()
    }

    #[test]
    fn r8_draft_fixtures_parse_and_are_not_run() {
        let mut draft = Vec::new();
        for p in scenario_paths(&fixtures_dir()) {
            let v: Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
            if v.get("requires").is_some() {
                let s: Scenario = serde_json::from_value(v.clone()).expect("r8 fixture parses");
                assert_eq!(s.requires.as_deref(), Some("r8"), "{}", s.name);
                assert_eq!(run_scenario(&v, Some(&fake_runtime)), Ok(Outcome::NotRun));
                draft.push(s.name);
            }
        }
        assert!(!draft.is_empty(), "r8 draft fixtures missing");
        let report = run_all(&fixtures_dir(), Some(&fake_runtime));
        assert_eq!(report.not_run, draft);
    }

    fn fake_runtime(setup: &Setup) -> Result<Box<dyn HostUnderTest>, String> {
        Ok(Box::new(super::super::fake_runtime::FakeRuntime::new(
            setup,
        )?))
    }

    #[test]
    fn every_fixture_runs_and_passes_with_none_skipped() {
        let files = scenario_files();
        let host: Vec<String> = files
            .iter()
            .filter(|(_, v)| v.get("side").is_none_or(|s| s == "host"))
            .map(|(_, v)| v["name"].as_str().unwrap().to_string())
            .collect();
        let client = files.len() - host.len();
        assert!(client >= 2 && host.len() >= 5, "fixtures missing");

        let report = run_all(&fixtures_dir(), Some(&fake_runtime));
        assert!(report.failed.is_empty(), "failed: {:#?}", report.failed);
        eprintln!(
            "fixtures passed ({}): {:?}",
            report.passed.len(),
            report.passed
        );
        assert!(report.skipped.is_empty(), "skipped: {:?}", report.skipped);
        assert_eq!(report.passed.len(), files.len());
        for name in &host {
            assert!(report.passed.contains(name), "host scenario {name} ran");
        }

        // Without a host, exactly the host scenarios are reported as skipped.
        let hostless = run_all(&fixtures_dir(), None);
        assert_eq!(hostless.skipped, host);
        assert_eq!(hostless.passed.len(), client);
    }

    /// The same fixtures with receipts in a `FileJournal` on disk.
    #[test]
    fn every_fixture_passes_with_the_file_journal() {
        use super::super::fake_runtime::FakeRuntime;
        use super::super::file_journal::FileJournal;
        use super::super::host::HostConfig;
        let dirs = std::cell::RefCell::new(Vec::new());
        let factory = |setup: &Setup| -> Result<Box<dyn HostUnderTest>, String> {
            let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
            let journal = FileJournal::open(&dir.path().join("state")).map_err(|e| e.0)?;
            dirs.borrow_mut().push(dir);
            Ok(Box::new(FakeRuntime::with_journal(
                setup,
                HostConfig::default(),
                journal,
            )?))
        };
        let report = run_all(&fixtures_dir(), Some(&factory));
        assert!(report.failed.is_empty(), "failed: {:#?}", report.failed);
        assert!(report.skipped.is_empty(), "skipped: {:?}", report.skipped);
        assert_eq!(report.passed.len(), scenario_files().len());
    }

    /// Each host fixture fails when one of its expectations is changed, so
    /// passing means the host produced exactly what the fixture says.
    #[test]
    fn host_fixtures_fail_on_a_changed_expectation() {
        let mutations: &[(&str, &str, Value)] = &[
            ("lease-expires-without-renewal", "lease_epoch", json!(3)),
            ("removed-ops-have-no-effect", "code", json!("stale_lease")),
            (
                "dispatch-failure-before-any-effect-is-rejected",
                "detail",
                json!("write interrupted"),
            ),
            (
                "dispatch-failure-after-partial-write-is-outcome-unknown",
                "state",
                json!("rejected"),
            ),
            (
                "duplicate-submit-returns-receipt-and-reuse-is-rejected",
                "code",
                json!("busy"),
            ),
            ("family-errors-and-chat-results", "code", json!("busy")),
            (
                "receipt-query-is-scoped-to-the-exact-target",
                "receipts.#",
                json!(2),
            ),
            ("reconnect-restarts-the-registry-sequence", "seq", json!(3)),
            (
                "takeover-moves-control-and-the-old-holder-becomes-a-viewer",
                "reason",
                json!("granted"),
            ),
            (
                "exited-session-refuses-work-before-the-lease-check",
                "code",
                json!("stale_lease"),
            ),
            (
                "lease-expiry-at-the-deadline-needs-no-timer",
                "code",
                json!("lease_held"),
            ),
            (
                "approval-allow-once-is-handed-to-the-agent-and-completes",
                "state",
                json!("outcome_unknown"),
            ),
            (
                "approval-allow-always-must-name-an-offered-rule",
                "code",
                json!("forbidden"),
            ),
            (
                "approval-answered-in-the-terminal-first-refuses-the-late-remote-answer",
                "code",
                json!("forbidden"),
            ),
            (
                "approval-stays-pending-when-the-lease-ends",
                "reason",
                json!("timed_out"),
            ),
            (
                "approval-opens-without-a-lease-holder",
                "reason",
                json!("takeover"),
            ),
            (
                "approval-answer-with-acquire-takes-control-from-the-holder",
                "code",
                json!("forbidden"),
            ),
            (
                "approval-late-answer-after-push-resolved-is-stale-target",
                "code",
                json!("stale_lease"),
            ),
            (
                "approval-needs-control-and-the-lease",
                "code",
                json!("stale_lease"),
            ),
            (
                "approval-duplicate-submit-returns-the-receipt",
                "code",
                json!("busy"),
            ),
            (
                "approval-pending-is-sent-again-after-list",
                "reason",
                json!("answered_remote"),
            ),
            ("approval-survives-takeover", "code", json!("forbidden")),
        ];
        for (name, key, to) in mutations {
            let mut f = fixture(name);
            assert_eq!(
                run_scenario(&f, Some(&fake_runtime)),
                Ok(Outcome::Passed),
                "{name}"
            );
            let step = f["steps"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .rev()
                .find(|s| s.get("match").is_some_and(|m| m.get(*key).is_some()))
                .unwrap();
            step["match"][*key] = to.clone();
            assert!(
                run_scenario(&f, Some(&fake_runtime)).is_err(),
                "{name} {key}"
            );
        }
        // And on a changed counter.
        let mut f = fixture("dispatch-failure-before-any-effect-is-rejected");
        let last = f["steps"].as_array_mut().unwrap().last_mut().unwrap();
        last["assert"]["dispatch_attempts"] = json!(2);
        assert!(run_scenario(&f, Some(&fake_runtime)).is_err());
        // And on a changed decision handed to the agent.
        let mut f = fixture("approval-deny-carries-the-message-to-the-agent");
        let step = f["steps"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|s| s["assert"].get("approval_decisions").is_some())
            .unwrap();
        step["assert"]["approval_decisions"][0]["message"] = json!("something else");
        assert!(run_scenario(&f, Some(&fake_runtime)).is_err());
        // And on a changed push request.
        let mut f = fixture("approval-late-answer-after-push-resolved-is-stale-target");
        let step = f["steps"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|s| s["assert"].get("pushes").is_some())
            .unwrap();
        step["assert"]["pushes"][1]["reason"] = json!("answered_remote");
        assert!(run_scenario(&f, Some(&fake_runtime)).is_err());
    }

    fn fixture(name: &str) -> Value {
        let p = fixtures_dir().join(format!("{name}.json"));
        serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
    }

    /// Sets the first `assert_client` value at `key` equal to `from` to `to`.
    fn mutate_assert(v: &mut Value, key: &str, from: &Value, to: Value) {
        for step in v["steps"].as_array_mut().unwrap() {
            let asserts = step
                .get_mut("assert_client")
                .and_then(|a| a.as_object_mut());
            if let Some(a) = asserts.filter(|a| a.get(key) == Some(from)) {
                a.insert(key.into(), to);
                return;
            }
        }
        panic!("no assert_client {key} = {from}");
    }

    #[test]
    fn client_fixtures_pass_and_wrong_expectations_fail() {
        for name in [
            "late-renew-reply-does-not-resurrect-control",
            "runtime-epoch-and-sequence-ordering",
        ] {
            assert_eq!(
                run_scenario(&fixture(name), None),
                Ok(Outcome::Passed),
                "{name}"
            );
        }
        let mut f = fixture("late-renew-reply-does-not-resurrect-control");
        mutate_assert(&mut f, "deadline_ms", &json!(32000), json!(32001));
        assert!(run_scenario(&f, None).is_err());
        let mut f = fixture("late-renew-reply-does-not-resurrect-control");
        mutate_assert(&mut f, "controls", &json!(false), json!(true));
        assert!(run_scenario(&f, None).is_err());

        let mut f = fixture("runtime-epoch-and-sequence-ordering");
        mutate_assert(&mut f, "registry", &json!([]), json!(["ses-aaaaaaaaaaaa"]));
        assert!(run_scenario(&f, None).is_err());
        let mut f = fixture("runtime-epoch-and-sequence-ordering");
        mutate_assert(&mut f, "sent_list", &json!(true), json!(false));
        assert!(run_scenario(&f, None).is_err());
    }

    fn client_scenario(steps: Value) -> Value {
        let mut f = fixture("runtime-epoch-and-sequence-ordering");
        f["steps"] = steps;
        f
    }

    #[test]
    fn unknown_actions_keys_and_bad_messages_fail() {
        for steps in [
            json!([{"frobnicate": 1}]),
            json!([{"assert_client": {"colour": "red"}}]),
            json!([{"advance_ms": 1, "extra": 2}]),
            json!([{"deliver_to_client": "c1", "json": {"type": "session", "data": {"v": 2, "op": "list", "id": "11111111-1111-4111-8111-000000000001"}}}]),
            json!([{"deliver_to_client": "nobody", "json": {"type": "session", "data": {"v": 1, "op": "list", "id": "11111111-1111-4111-8111-000000000001"}}}]),
            json!([{"expect": "c1", "match": {"op": "lease"}}]),
            json!([{"assert_client": {"seq": "${never_captured}"}}]),
        ] {
            assert!(
                run_scenario(&client_scenario(steps.clone()), None).is_err(),
                "{steps}"
            );
        }
        let mut f = fixture("runtime-epoch-and-sequence-ordering");
        f["setup"]["clients"][0]["colour"] = json!("red");
        assert!(run_scenario(&f, None).is_err());
        let mut f = fixture("runtime-epoch-and-sequence-ordering");
        f["setup"]["clients"][0]["upgraded"] = json!(true);
        assert!(run_scenario(&f, None).is_err(), "upgraded is gone (r6)");
        // A client scenario can't start holding a lease.
        let mut f = fixture("runtime-epoch-and-sequence-ordering");
        f["setup"]["clients"][0]["holds_lease_epoch"] = json!(1);
        assert!(run_scenario(&f, None).is_err());
        // Requests must come from the client's own attachment.
        let mut f = fixture("late-renew-reply-does-not-resurrect-control");
        f["steps"][0]["json"]["data"]["binding"]["attachment_gen"] =
            json!("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
        assert!(run_scenario(&f, None).is_err());
    }

    #[test]
    fn sent_list_counts_only_lists_the_client_machine_requested() {
        let list = json!({"type": "session", "data": {"v": 1, "op": "list",
            "id": "11111111-1111-4111-8111-000000000001"}});
        let steps = json!([{"send": "c1", "json": list}, {"assert_client": {"sent_list": false}}]);
        assert_eq!(
            run_scenario(&client_scenario(steps), None),
            Ok(Outcome::Passed)
        );
    }

    #[test]
    fn unexpected_messages_left_at_the_end_fail_a_host_scenario() {
        let mut f = fixture("takeover-moves-control-and-the-old-holder-becomes-a-viewer");
        let steps = f["steps"].as_array_mut().unwrap();
        let i = steps
            .iter()
            .rposition(|s| s.get("expect").is_some())
            .unwrap();
        steps.remove(i);
        let err = run_scenario(&f, Some(&fake_runtime)).unwrap_err();
        assert!(err.contains("unexpected message"), "{err}");
    }

    #[test]
    fn lookup_paths_index_and_count_arrays() {
        let v = json!({"a": [{"b": 1}, {"b": 2}], "c": null});
        assert_eq!(lookup(&v, "a.#"), Some(json!(2)));
        assert_eq!(lookup(&v, "a.1.b"), Some(json!(2)));
        assert_eq!(lookup(&v, "a.5"), None);
        assert_eq!(lookup(&v, "c"), Some(Value::Null));
        assert_eq!(lookup(&v, "d"), None);
    }

    #[test]
    fn substitution_replaces_captures_anywhere() {
        let vars = HashMap::from([("s".to_string(), json!("abc")), ("n".to_string(), json!(5))]);
        let mut v = json!({"a": "x-${s}-y", "b": ["${n}"], "c": {"d": "${s}"}});
        substitute(&mut v, &vars).unwrap();
        assert_eq!(v, json!({"a": "x-abc-y", "b": [5], "c": {"d": "abc"}}));
        assert!(substitute(&mut json!("${missing}"), &vars).is_err());
    }

    /// A scripted host: answers every session request with `error{busy}`,
    /// every other message with a terminal-v1 `exited`, and counts events, to
    /// exercise the host-side plumbing.
    struct EchoHost {
        out: Vec<(String, Envelope)>,
        events: u64,
        now: u64,
    }

    impl HostUnderTest for EchoHost {
        fn receive(&mut self, client: &str, msg: Result<Envelope, DecodeError>, _now: u64) {
            if let Ok(Envelope::Session(m)) = msg {
                self.out.push((
                    client.to_string(),
                    Envelope::Session(wire::SessionMessage {
                        id: "11111111-1111-4111-8111-00000000beef".into(),
                        re: Some(m.id),
                        op: Op::Error {
                            code: wire::ErrorCode::Busy,
                            detail: None,
                        },
                    }),
                ));
            } else if let Ok(Envelope::Family(_)) = msg {
                let exited = json!({"v": 1, "op": "exited", "terminal_id": "ses-aaaaaaaaaaaa",
                    "generation": "22222222-2222-4222-8222-222222222222", "status": "0"});
                self.out.push((
                    client.to_string(),
                    Envelope::Family(wire::FamilyMessage {
                        family: "terminal".into(),
                        data: Some(exited),
                        binding: None,
                        request: None,
                    }),
                ));
            }
        }
        fn advance(&mut self, now: u64) {
            self.now = now;
        }
        fn event(&mut self, _e: &HostEvent, _now: u64) -> Result<(), String> {
            self.events += 1;
            Ok(())
        }
        fn drain_outgoing(&mut self) -> Vec<(String, Envelope)> {
            std::mem::take(&mut self.out)
        }
        fn counter(&self, key: &str) -> Result<Value, String> {
            match key {
                "events" => Ok(json!(self.events)),
                "now" => Ok(json!(self.now)),
                "receipts_visible" => Ok(json!({"c1": 0, "c2": 3})),
                _ => Err(format!("unknown counter {key}")),
            }
        }
    }

    #[test]
    fn host_scenarios_dispatch_to_a_host_under_test() {
        let list = |id: &str| json!({"type": "session", "data": {"v": 1, "op": "list", "id": id}});
        let mut f = fixture("lease-expires-without-renewal");
        f["steps"] = json!([
            {"hold": {"to": "c1", "op": "error"}},
            {"send": "c1", "json": list("11111111-1111-4111-8111-000000000001")},
            {"expect_none": "c1", "for_ms": 10},
            {"send": "c1", "json": list("11111111-1111-4111-8111-000000000002")},
            {"expect": "c1", "match": {"re": "11111111-1111-4111-8111-000000000002"}, "capture": {"code": "code"}},
            {"deliver": "held"},
            {"expect": "c1", "match": {"op": "error", "code": "${code}", "re": "11111111-1111-4111-8111-000000000001"}},
            {"local_input": "ses-aaaaaaaaaaaa", "bytes": "eA=="},
            {"restart_runtime": {"runtime_gen": "99999999-9999-4999-8999-999999999999", "runtime_epoch": 8}},
            {"assert": {"events": 2, "now": 10, "receipts_visible": {"c2": 3}}}
        ]);
        let factory = |_: &Setup| -> Result<Box<dyn HostUnderTest>, String> {
            Ok(Box::new(EchoHost {
                out: vec![],
                events: 0,
                now: 0,
            }))
        };
        assert_eq!(run_scenario(&f, Some(&factory)), Ok(Outcome::Passed));
        assert_eq!(run_scenario(&f, None), Ok(Outcome::Skipped));

        for bad in [
            json!({"assert": {"events": 3}}),
            json!({"assert": {"nope": 1}}),
            json!({"assert": {"after": "labels belong in note"}}),
            json!({"expect": "c1", "match": {"op": "lease"}}),
            json!({"expect_all": {"op": "error"}}),
        ] {
            let mut g = f.clone();
            g["steps"].as_array_mut().unwrap().push(bad.clone());
            assert!(run_scenario(&g, Some(&factory)).is_err(), "{bad}");
        }
    }

    #[test]
    fn expect_selects_the_next_message_of_its_type_and_op() {
        let list = json!({"type": "session", "data": {"v": 1, "op": "list",
            "id": "11111111-1111-4111-8111-000000000001"}});
        let beat = json!({"type": "heartbeat", "data": {"ts": 1}});
        let factory = |_: &Setup| -> Result<Box<dyn HostUnderTest>, String> {
            Ok(Box::new(EchoHost {
                out: vec![],
                events: 0,
                now: 0,
            }))
        };
        let run = |steps: Value| {
            let mut f = fixture("lease-expires-without-renewal");
            f["steps"] = steps;
            run_scenario(&f, Some(&factory))
        };
        // Queued: terminal exited, then session error. Each expect picks its own.
        let base = json!([{"send": "c1", "json": beat}, {"send": "c1", "json": list}]);
        let with = |extra: Value| {
            let mut steps = base.clone();
            steps
                .as_array_mut()
                .unwrap()
                .extend(extra.as_array().unwrap().iter().cloned());
            steps
        };
        assert_eq!(
            run(with(json!([
                {"expect": "c1", "match": {"op": "error", "code": "busy"}},
                {"expect": "c1", "type": "terminal", "match": {"status": "0"}},
                {"expect_none": "c1", "for_ms": 1}
            ]))),
            Ok(Outcome::Passed)
        );
        assert_eq!(
            run(with(json!([
                {"expect": "c1", "type": "session", "match": {"code": "busy"}},
                {"expect": "c1", "match": {"op": "exited"}}
            ]))),
            Ok(Outcome::Passed)
        );
        // Without a selector the very next message is taken.
        assert_eq!(
            run(with(json!([{"expect": "c1", "match": {"op": "exited"}},
                {"expect": "c1", "match": {"code": "busy"}}]))),
            Ok(Outcome::Passed)
        );
        for bad in [
            // The selected message must match fully.
            json!([{"expect": "c1", "match": {"op": "error", "code": "forbidden"}}]),
            json!([{"expect": "c1", "type": "terminal", "match": {"op": "error"}}]),
            // Without a selector the next message is the terminal one.
            json!([{"expect": "c1", "match": {"code": "busy"}}]),
            // expect_none sees every type.
            json!([{"expect": "c1", "match": {"op": "error"}}, {"expect_none": "c1", "for_ms": 1}]),
            json!([{"expect": "c1", "type": 7}]),
        ] {
            assert!(run(with(bad.clone())).is_err(), "{bad}");
        }
    }
}
