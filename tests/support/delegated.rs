//! What the delegated host-work binary tests share (`delegated_binary`,
//! `control_feed_binary`): an encrypted r9 client of the host ([`Dev`]),
//! its tasks and how the host's store holds them, the fake agent's turns,
//! and the `runtime.toml` that turns agent hosting on. The host's ids are
//! the test's ([`HostIds`]); its rig names its profile and fake agent
//! ([`HostRig`]).

use super::r9::{Out, Router, client_ms};
use super::r9log::{self, TestLog, auth};
use super::within;
use atem_client::connect::{Attached, Event, Identity};
use serde_json::{Value, json};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// The longest a "wait until" helper waits; it only bounds a failure.
pub const WAIT: Duration = Duration::from_secs(60);

pub fn uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// `text` into `path`, private (0600).
pub fn private(path: &Path, text: &str) {
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// `text` into `path`, renamed into place (a runtime reading it never sees
/// half of it).
pub fn replace(path: &Path, text: &str) {
    let tmp = path.with_extension("tmp");
    private(&tmp, text);
    std::fs::rename(&tmp, path).unwrap();
}

/// The host a test's clients name: its account and its device id, in
/// trust generation 1.
#[derive(Debug, Clone, Copy)]
pub struct HostIds {
    pub account: &'static str,
    pub host: &'static str,
}

impl HostIds {
    /// The `host` of a host-work request.
    pub fn json(self) -> Value {
        json!({"account_id": self.account, "atem_device_id": self.host, "host_trust_gen": 1})
    }
}

/// A test's rig: where its profile and its fake agent are.
pub trait HostRig {
    /// The profile's config directory (`~/.config/atem`).
    fn config_dir(&self) -> PathBuf;
    /// The fake agent's directory (`input`, `complete`, `run-<n>`).
    fn fake_dir(&self) -> PathBuf;
}

/// `runtime.toml` with agent hosting on: the profile `backend` (the fake
/// Claude, its environment from `env_file`, its directory `home`) and its
/// route of the same name, both for `principals`.
pub fn hosting_toml(home: &Path, env_file: &Path, principals: &[String]) -> String {
    let principals = format!("{principals:?}");
    format!(
        r#"
version = 1
enabled = true
[[profiles]]
id = "backend"
revision = 1
label = "Backend"
provider = "claude"
cwd = {cwd:?}
project = "local:home"
principals = {principals}
env_names = ["CLAUDE_CLI_BIN", "FAKE_DIR"]
env_file = {env_file:?}
[[routes]]
id = "backend"
revision = 1
profile_id = "backend"
principals = {principals}
"#,
        cwd = home.to_str().unwrap(),
        env_file = env_file.to_str().unwrap()
    )
}

/// An r9 client of the host.
pub struct Dev {
    handle: String,
    pub a: Attached,
    backlog: Vec<Value>,
    ids: HostIds,
}

impl Dev {
    /// Admitted as `id` (a native member, or a service) on a relay
    /// channel.
    pub fn new(r: &mut Router, ids: HostIds, log: &TestLog, id: &str, service: bool) -> Dev {
        Dev::new_via(r, "relay", ids, log, id, service)
    }

    /// Admitted on a channel the router labels `transport` (`relay`, or
    /// `direct`: Astation's :8080 on the local network).
    pub fn new_via(
        r: &mut Router,
        transport: &str,
        ids: HostIds,
        log: &TestLog,
        id: &str,
        service: bool,
    ) -> Dev {
        let identity = if service {
            Identity::service(id, auth(id))
        } else {
            Identity::native(id, auth(id))
        };
        Dev::admitted(r, transport, ids, log, &identity)
    }

    pub fn admitted(
        r: &mut Router,
        transport: &str,
        ids: HostIds,
        log: &TestLog,
        identity: &Identity,
    ) -> Dev {
        let handle = uuid();
        let a = r
            .connect_via(&handle, transport, log, ids.host, identity)
            .unwrap_or_else(|e| panic!("admission failed: {e:?}"));
        Dev {
            handle,
            a,
            backlog: Vec::new(),
            ids,
        }
    }

    pub fn request(&mut self, r: &mut Router, data: Value) -> Value {
        let id = self.send(r, data);
        self.wait(r, |v| v["re"] == id.as_str())
    }

    /// Sends a session request; its id.
    pub fn send(&mut self, r: &mut Router, mut data: Value) -> String {
        let id = uuid();
        data["v"] = json!(1);
        data["id"] = json!(id);
        let frame = self
            .a
            .send(&json!({"type":"session","data":data}), client_ms())
            .unwrap();
        r.frame(&self.handle, &frame);
        id
    }

    /// The first message (in the backlog, or arriving) `matches` takes.
    pub fn wait(&mut self, r: &mut Router, matches: impl Fn(&Value) -> bool) -> Value {
        let deadline = Instant::now() + WAIT;
        loop {
            if let Some(at) = self.backlog.iter().position(&matches) {
                return self.backlog.remove(at);
            }
            assert!(
                Instant::now() < deadline,
                "nothing matched in time: {:?}",
                self.backlog
            );
            match r.next(&self.handle) {
                Out::Close(reason) => panic!("channel closed: {reason:?}"),
                Out::Frame(frame) => {
                    for e in self.a.on_frame(&frame, client_ms()).unwrap() {
                        let value = match e {
                            Event::Family(f) => f.data,
                            Event::Session(m) => Some(
                                atem_client::session::wire::to_value(
                                    &atem_client::session::wire::Envelope::Session(m),
                                )["data"]
                                    .clone(),
                            ),
                            Event::Error(e) => Some(
                                serde_json::from_slice::<Value>(&e.to_bytes()).unwrap()["data"]
                                    .clone(),
                            ),
                            _ => None,
                        };
                        if let Some(v) = value {
                            self.backlog.push(v);
                        }
                    }
                }
            }
        }
    }

    /// The read binding of `sid` (after `list`).
    pub fn read(&self, sid: &str) -> Value {
        json!({"target": self.a.target(sid).expect("listed"),
               "attachment_gen": self.a.welcome().attachment_gen})
    }

    /// Lists the sessions until `sid` is among them.
    pub fn list(&mut self, r: &mut Router, sid: &str) {
        let deadline = Instant::now() + WAIT;
        loop {
            self.send(r, json!({"op":"list"}));
            let sessions = self.wait(r, |v| v["op"] == "sessions");
            if sessions["sessions"]
                .as_array()
                .is_some_and(|all| all.iter().any(|d| d["session_id"] == sid))
            {
                return;
            }
            assert!(Instant::now() < deadline, "{sid} never listed: {sessions}");
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// The client goes: its channel closed.
    pub fn close(self, r: &mut Router) {
        r.close(&self.handle);
    }

    /// A session it launches on profile `backend`: its `launch` (session
    /// id and process generation).
    pub fn session(&mut self, r: &mut Router) -> Value {
        let rid = uuid();
        let host = self.ids.json();
        let launch = self.request(
            r,
            json!({"op":"host_launch","host":host,"request_id":rid,
                "profile_id":"backend","profile_revision":1,
                "expires_at":r9log::host_now().wall_ms + 60_000}),
        );
        assert!(launch["result"].is_object(), "{launch}");
        let deadline = Instant::now() + WAIT;
        loop {
            let value = self.request(
                r,
                json!({"op":"host_launch_query","host":host,"request_id":rid}),
            );
            if value["result"]["launch"]["state"] == "started" {
                return value["result"]["launch"].clone();
            }
            assert!(Instant::now() < deadline, "launch failed: {value}");
            std::thread::sleep(Duration::from_millis(40));
        }
    }

    /// Carries `entries` on its channel (the `membership` op) and waits for
    /// the host's head in answer.
    pub fn carry(&mut self, r: &mut Router, entries: &[Value]) {
        let signed: Vec<_> = entries
            .iter()
            .map(|e| atem_client::SignedObject::parse(e.to_string().as_bytes()).unwrap())
            .collect();
        let (id, frame) = self.a.send_membership(&signed, client_ms()).unwrap();
        r.frame(&self.handle, &frame);
        loop {
            let Out::Frame(frame) = r.next(&self.handle) else {
                panic!("membership channel closed");
            };
            let events = self.a.on_frame(&frame, client_ms()).unwrap();
            if events
                .iter()
                .any(|e| matches!(e, Event::MembershipHead { re: Some(re), .. } if re == &id))
            {
                return;
            }
        }
    }
}

/// A task of `text` for `launch`'s session on the host `ids`, its
/// deadline at host time `expires_at`.
pub fn task_until(ids: HostIds, launch: &Value, text: &str, expires_at: u64) -> Value {
    let mut target = ids.json();
    target["session_id"] = launch["session_id"].clone();
    target["process_gen"] = launch["process_gen"].clone();
    json!({"task_id":uuid(),"workflow_id":uuid(),"target":target,"expires_at":expires_at,
        "prompt":text,"context":[]})
}

/// [`task_until`], its deadline `ms` from now.
pub fn task(ids: HostIds, launch: &Value, text: &str, ms: u64) -> Value {
    task_until(ids, launch, text, r9log::host_now().wall_ms + ms)
}

/// `work_enqueue` of `task` on the route `backend`.
pub fn enqueue_data(ids: HostIds, task: &Value) -> Value {
    json!({"op":"work_enqueue","host":ids.json(),"route_id":"backend","route_revision":1,
        "task":task})
}

/// `dev` enqueues `task`: the reply's `work`.
pub fn enqueue(dev: &mut Dev, r: &mut Router, task: &Value) -> Value {
    let reply = dev.request(r, enqueue_data(dev.ids, task));
    assert!(reply["result"]["work"].is_object(), "{reply}");
    reply["result"]["work"].clone()
}

/// The host-work store (`runtime/host-work.sqlite`).
pub fn host_db(rig: &impl HostRig) -> rusqlite::Connection {
    let db = rusqlite::Connection::open(rig.config_dir().join("runtime/host-work.sqlite")).unwrap();
    db.busy_timeout(Duration::from_secs(5)).unwrap();
    db
}

/// Task `tid`'s record as `runtime/host-work.sqlite` stores it.
pub fn record(rig: &impl HostRig, tid: &Value) -> Value {
    let record: String = host_db(rig)
        .query_row(
            "SELECT record FROM work WHERE id=?1",
            [tid.as_str().unwrap()],
            |r| r.get(0),
        )
        .unwrap();
    serde_json::from_str(&record).unwrap()
}

/// Task `tid`'s status as stored (whatever its sender may read).
pub fn stored(rig: &impl HostRig, tid: &Value) -> Value {
    record(rig, tid)["status"].clone()
}

/// Waits until task `tid` is stored in `state`, with `detail`.
#[track_caller]
pub fn wait_stored(rig: &impl HostRig, tid: &Value, state: &str, detail: &str) {
    let deadline = Instant::now() + WAIT;
    loop {
        let status = stored(rig, tid);
        if status["state"] == state && status["detail"] == detail {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "expected {state} ({detail}): {status}"
        );
        std::thread::sleep(Duration::from_millis(40));
    }
}

/// Task `tid`'s attempts: (id, end), in order.
pub fn attempts(rig: &impl HostRig, tid: &Value) -> Vec<(String, Option<String>)> {
    let db = host_db(rig);
    let mut q = db
        .prepare(r#"SELECT attempt_id,"end" FROM attempts WHERE task_id=?1 ORDER BY n"#)
        .unwrap();
    q.query_map([tid.as_str().unwrap()], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

/// What the agent of the rig's sessions was given, in order.
pub fn input(rig: &impl HostRig) -> String {
    std::fs::read_to_string(rig.fake_dir().join("input")).unwrap_or_default()
}

/// Task `tid` (of prompt `text`) is in its agent's turn: pasted once, the
/// turn its prompt became stored.
#[track_caller]
pub fn in_turn(rig: &impl HostRig, tid: &Value, text: &str) {
    within("the task's prompt", || input(rig).contains(text));
    wait_stored(rig, tid, "submitted", "in the agent's turn");
}

/// The rig's agent ends its turn: task `tid` awaits its result.
#[track_caller]
pub fn complete_turn(rig: &impl HostRig, tid: &Value) {
    std::fs::write(rig.fake_dir().join("complete"), "").unwrap();
    let deadline = Instant::now() + WAIT;
    loop {
        let status = stored(rig, tid);
        if status["state"] == "awaiting_result" {
            return;
        }
        assert!(Instant::now() < deadline, "the turn never ended: {status}");
        std::thread::sleep(Duration::from_millis(40));
    }
}

/// Task `tid` never ran: no attempt, its prompt never written.
#[track_caller]
pub fn never_ran(rig: &impl HostRig, tid: &Value, text: &str) {
    assert!(attempts(rig, tid).is_empty(), "{:?}", attempts(rig, tid));
    assert!(!input(rig).contains(text));
}

/// The bare Esc bytes the rig's agent was given (a bracketed paste's
/// `ESC [` doesn't count): the host interrupts it wrote.
pub fn escs(rig: &impl HostRig) -> usize {
    let text = input(rig);
    text.matches('\x1b').count() - text.matches("\x1b[").count()
}

/// One interrupt intent as `runtime/host-work.sqlite` stores it.
#[derive(Debug)]
pub struct Intent {
    pub attempt_id: String,
    pub reason: String,
    /// A revocation's record id (none for a deadline).
    pub revocation: Option<String>,
    pub done: bool,
    pub delivered_turn: Option<String>,
}

/// Task `tid`'s interrupt intents, oldest first (none before the table
/// exists).
pub fn intents(rig: &impl HostRig, tid: &Value) -> Vec<Intent> {
    let db = host_db(rig);
    let Ok(mut q) = db.prepare(
        "SELECT attempt_id,reason,revocation,done_ms IS NOT NULL,delivered_turn FROM intents
        WHERE task_id=?1 ORDER BY rowid",
    ) else {
        return Vec::new();
    };
    q.query_map([tid.as_str().unwrap()], |r| {
        Ok(Intent {
            attempt_id: r.get(0)?,
            reason: r.get(1)?,
            revocation: r.get(2)?,
            done: r.get(3)?,
            delivered_turn: r.get(4)?,
        })
    })
    .unwrap()
    .map(Result::unwrap)
    .collect()
}

/// Every interrupt intent of the store, as (task, reason) in order: what a
/// page that applies nothing must leave as it was.
pub fn all_intents(rig: &impl HostRig) -> Vec<(String, String)> {
    let db = host_db(rig);
    let Ok(mut q) = db.prepare("SELECT task_id,reason FROM intents ORDER BY rowid") else {
        return Vec::new();
    };
    q.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

/// `dev` (a native member holding `control`) takes session `sid`'s lease
/// over (session-v1 `acquire` with `takeover`): granted.
pub fn take_over(dev: &mut Dev, r: &mut Router, sid: &str) {
    dev.list(r, sid);
    let reply = dev.request(
        r,
        json!({"op":"acquire","binding":dev.read(sid),"takeover":true}),
    );
    assert_eq!(reply["op"], "lease", "{reply}");
}

/// A `hello` of `id` (a native member, or a service) on a fresh channel,
/// expected refused: its code and detail.
pub fn refused_hello(
    r: &mut Router,
    ids: HostIds,
    log: &TestLog,
    id: &str,
    service: bool,
) -> (String, Option<String>) {
    let identity = if service {
        Identity::service(id, auth(id))
    } else {
        Identity::native(id, auth(id))
    };
    match r.connect_via(&uuid(), "relay", log, ids.host, &identity) {
        Ok(_) => panic!("{id} admitted"),
        Err(refused) => refused,
    }
}
