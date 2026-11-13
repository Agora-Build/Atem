//! Delegated host work in the real runtime (the delegated host-work design,
//! Part I; VII.A; host-work-v1 §11.6): the debug hook turns `host.delegated`
//! on (`ATEM_TEST_HOST_FEATURES`), and where a test needs a Station's
//! revocation gate open or a service a feed covers, the fake Station
//! (tests/support/station.rs) serves the host's own Station's control feed,
//! its `cover` records included, and its heads: the host syncs it as it
//! would its Station's (Task 33). Encrypted r9 clients, fake agents, temp
//! profiles; clocks move on the debug host clock (`ATEM_TEST_HOST_CLOCK`),
//! never by waiting.
#![cfg(target_os = "linux")]
mod support;

use atem_client::connect::Identity;
use atem_client::control::{ControlAction, MembershipFetch, RelayError, ToStation};
use atem_client::membership::ServiceScope;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use support::astation::{FakeAstation, write_verified_pairing};
use support::delegated::{
    Dev, HostIds, HostRig, WAIT, attempts, complete_turn, enqueue, enqueue_data, hosting_toml,
    in_turn, input, private, record, replace, stored, task, task_until, uuid, wait_stored,
};
use support::host_clock::HostClock;
use support::r9::{Router, write_pin};
use support::r9log::{self, MAC, TestLog, auth, secret};
use support::station::{FakeStation, Pump};
use support::{Sandbox, within};

const HOST: &str = "host-delegated";
const ACCOUNT: &str = "acct-delegated";
/// A native member holding `control`: a delegated sender.
const PHONE: &str = "dev-phone";
/// The service the tests launch sessions with (`svc-work`); delegated only
/// while the fake Station's feed covers it.
const SVC: &str = "svc-work";
/// The relay setting the rig gives the runtime (its link is the fake
/// Astation's local one): the selected Station's origin, normalized, so the
/// fake Station's ([`Rig::with_station`]): the host's own Station.
const STATION: &str = "http://127.0.0.1:1";
/// After a fetch whose carriage moved nothing, the host fetches nothing at
/// a `heads` for this long (its monotonic clock).
const STALL_PAUSE: u64 = 30_000;
/// The browser grant the route lists (v1's lifecycle).
const GRANT: &str = "5f0c8a52-2c1e-4b7a-9d3e-1a2b3c4d5e6f";
const MIN: u64 = 60_000;
const HOUR: u64 = 60 * MIN;
/// What a delegated task waits with while its sender's gate is closed.
const GATE_CLOSED: &str = "revocations not yet checked";
const BEHIND: &str = "waiting for an earlier task on this session";
/// The host the clients name.
const IDS: HostIds = HostIds {
    account: ACCOUNT,
    host: HOST,
};

struct Rig {
    sandbox: Sandbox,
    astation: FakeAstation,
    log: TestLog,
    runtime: Option<Child>,
    fake: PathBuf,
    /// The debug host clock (`ATEM_TEST_HOST_CLOCK`), when on.
    clock: Option<HostClock>,
    /// The broker faults (`ATEM_TEST_PTY_FAULTS`).
    faults: bool,
    /// The device-list hooks (`ATEM_TEST_MEMBERSHIP_FAULTS`).
    membership: bool,
    /// The broker's state after each pass (`ATEM_TEST_STATE_DUMP`).
    dump: bool,
    /// The fake Station on the link ([`Rig::with_station`]).
    station: Option<Arc<Mutex<FakeStation>>>,
    /// The thread serving it while it is online ([`Rig::station_online`]).
    pump: Mutex<Option<Pump>>,
    /// The debug hook turns `host.delegated` on (`ATEM_TEST_HOST_FEATURES`);
    /// off: a restart without it.
    hook: bool,
    /// Context snapshots from `<sandbox>/context` (`ATEM_TEST_CONTEXT_DIR`).
    context: bool,
}

impl Rig {
    /// A verified host with a pinned device list: the Mac, this host, the
    /// phone (`control`, `view`) and [`SVC`] (`launch`, `message`, `notify`,
    /// `prompt`, `view`, expiring `svc_expiry` ms from now); the profile
    /// `backend` (the fake Claude) and its route of the same name, for the
    /// Mac, the phone, [`SVC`] and the browser grant [`GRANT`]; with
    /// `collab`, a route `peer` that lists `local` (`tag:peer`) and agents
    /// may send. Not started: set the hooks, then `start`.
    fn prepared(svc_expiry: u64, collab: bool) -> Rig {
        let sandbox = Sandbox::new();
        write_verified_pairing(&sandbox.config(), ACCOUNT, HOST, 1);
        let mut log = TestLog::genesis(ACCOUNT, &secret("delegated astation"));
        let host_seed = secret("delegated host");
        log.add_host(HOST, 1, &host_seed);
        log.add_native(PHONE, &["control", "view"]);
        log.enroll_service(
            SVC,
            &ServiceScope::new([HOST]).ops(["launch", "message", "notify", "prompt", "view"]),
            r9log::host_now().wall_ms + svc_expiry,
        );
        write_pin(&sandbox.config(), &log, HOST, 1, &host_seed);
        let fake = sandbox.dir.path().join("fake");
        std::fs::create_dir_all(&fake).unwrap();
        let bin = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/approvals/fake-agent.py");
        let env_file = sandbox.dir.path().join("provider.json");
        private(
            &env_file,
            &json!({"CLAUDE_CLI_BIN": bin, "FAKE_DIR": fake}).to_string(),
        );
        let principals = [
            format!("member:{MAC}"),
            format!("member:{PHONE}"),
            format!("service:{SVC}"),
            format!("browser:{GRANT}"),
        ];
        let mut toml = hosting_toml(&sandbox.home, &env_file, &principals);
        if collab {
            toml.push_str(
                "[[routes]]\nid = \"peer\"\nrevision = 1\nprofile_id = \"backend\"\n\
                 labels = [\"tag:peer\"]\nprincipals = [\"local\"]\n[collab]\nsend = true\n",
            );
        }
        private(&sandbox.config().join("runtime.toml"), &toml);
        Rig {
            sandbox,
            astation: FakeAstation::start(),
            log,
            runtime: None,
            fake,
            clock: None,
            faults: false,
            membership: false,
            dump: false,
            station: None,
            pump: Mutex::new(None),
            hook: true,
            context: false,
        }
    }

    /// The fake Station of [`STATION`] on the link, holding the rig's list
    /// and an empty control feed, announcing only when a test says (made
    /// before the runtime: it takes the host's calls from the start), and
    /// the state dump on (where the gate shows).
    fn with_station(&mut self) {
        let mut station = FakeStation::new(&self.astation, STATION, &self.log, HOST, 1);
        station.silence_heads(true);
        self.station = Some(Arc::new(Mutex::new(station)));
        self.dump = true;
    }

    fn station(&self) -> MutexGuard<'_, FakeStation> {
        self.station
            .as_ref()
            .expect("the fake Station")
            .lock()
            .unwrap()
    }

    /// The fake Station online from now on, as a Station is: a thread
    /// answers every call of the host's newest link and announces `heads`
    /// (on a new link at once, then every second), with `cover`, its feed
    /// covering [`SVC`] first. Then waits until the host's own Station's
    /// gate is open (its feed read to the announced head, the device list
    /// holding the announced head).
    fn station_online(&self, cover: bool) {
        {
            let mut station = self.station();
            if cover {
                let record = station.record_for(SVC, ControlAction::Cover);
                station.append(record);
            }
            station.silence_heads(false);
        }
        let station = self.station.clone().expect("the fake Station");
        *self.pump.lock().unwrap() = Some(Pump::start(station));
        self.gate_open();
    }

    /// Waits until the host's own Station's gate is open (state dump).
    fn gate_open(&self) {
        within("the host's own Station's gate", || {
            let station = dumped(self)["station"].clone();
            station["feed"]["open"] == true && station["list_part"] == true
        });
    }

    /// The debug host clock on, at the real clocks.
    fn with_clock(&mut self) {
        self.clock = Some(HostClock::start(self.sandbox.dir.path(), "host-clock"));
    }

    fn clock(&self) -> &HostClock {
        self.clock.as_ref().expect("the host clock hook")
    }

    fn faults(&self) -> PathBuf {
        self.sandbox.dir.path().join("faults")
    }

    fn membership_dir(&self) -> PathBuf {
        self.sandbox.dir.path().join("membership")
    }

    fn dump_file(&self) -> PathBuf {
        self.sandbox.dir.path().join("state.json")
    }

    fn start(&mut self) {
        let output = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.sandbox.dir.path().join("runtime.log"))
            .unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_atem"));
        command.env_clear();
        if self.hook {
            command.env("ATEM_TEST_HOST_FEATURES", "host.delegated");
        }
        if self.context {
            let context = self.sandbox.dir.path().join("context");
            std::fs::create_dir_all(&context).unwrap();
            command.env("ATEM_TEST_CONTEXT_DIR", context);
        }
        if let Some(clock) = &self.clock {
            command.env("ATEM_TEST_HOST_CLOCK", &clock.path);
        }
        if self.faults {
            std::fs::create_dir_all(self.faults()).unwrap();
            command.env("ATEM_TEST_PTY_FAULTS", self.faults());
        }
        if self.membership {
            std::fs::create_dir_all(self.membership_dir()).unwrap();
            command.env("ATEM_TEST_MEMBERSHIP_FAULTS", self.membership_dir());
        }
        if self.dump {
            command.env("ATEM_TEST_STATE_DUMP", self.dump_file());
        }
        // A stale socket file of a killed runtime isn't the new one's.
        let _ = std::fs::remove_file(self.sandbox.config().join("runtime.socket"));
        self.runtime = Some(
            command
                .arg("runtime")
                .env("HOME", &self.sandbox.home)
                .env("XDG_RUNTIME_DIR", &self.sandbox.run)
                .env("PATH", "/usr/bin:/bin")
                .env("ASTATION_WS", &self.astation.url)
                .env("ASTATION_RELAY_URL", STATION)
                .env("ATEM_RUNTIME_IDLE_SECS", "1")
                .env("ATEM_TEST_NO_INIT_LIMIT", "1")
                .stdin(Stdio::null())
                .stdout(output.try_clone().unwrap())
                .stderr(output)
                .spawn()
                .unwrap(),
        );
        within("runtime socket", || {
            self.sandbox.config().join("runtime.socket").exists()
        });
    }

    /// The runtime is killed (`SIGKILL`); its workers live on.
    fn kill(&mut self) {
        self.sandbox.track();
        let mut child = self.runtime.take().unwrap();
        child.kill().unwrap();
        child.wait().unwrap();
    }

    /// The runtime killed itself (a crash hook): it exited on `SIGKILL`
    /// (within [`within`]'s bound: a hook that never fired fails the test,
    /// never hangs it).
    fn died(&mut self) {
        use std::os::unix::process::ExitStatusExt;
        self.sandbox.track();
        let child = self.runtime.as_mut().unwrap();
        let mut status = None;
        within("the runtime to die", || {
            status = child.try_wait().unwrap();
            status.is_some()
        });
        self.runtime = None;
        let status = status.unwrap();
        assert_eq!(status.signal(), Some(libc::SIGKILL), "{status:?}");
    }
}

impl HostRig for Rig {
    fn config_dir(&self) -> PathBuf {
        self.sandbox.config()
    }

    fn fake_dir(&self) -> PathBuf {
        self.fake.clone()
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        drop(self.pump.get_mut().unwrap().take());
        self.sandbox.track();
        if let Some(mut child) = self.runtime.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn host() -> Value {
    IDS.json()
}

fn work(dev: &mut Dev, r: &mut Router, tid: &Value) -> Value {
    dev.request(r, json!({"op":"work_query","host":host(),"task_id":tid}))
}

fn reply_query(dev: &mut Dev, r: &mut Router, tid: &Value) -> Value {
    dev.request(r, json!({"op":"reply_query","host":host(),"task_id":tid}))
}

/// The ends of task `tid`'s attempts, in order.
fn ends(rig: &Rig, tid: &Value) -> Vec<Option<String>> {
    attempts(rig, tid).into_iter().map(|(_, end)| end).collect()
}

fn delegated(rig: &Rig, tid: &Value) -> bool {
    record(rig, tid)["delegated"].is_object()
}

/// `argv` run by the fake agent of `fake` as its own child (`run-<n>.json`).
fn agent_run(fake: &Path, n: u32, args: &[&str]) -> Value {
    let argv: Vec<_> = std::iter::once(env!("CARGO_BIN_EXE_atem"))
        .chain(args.iter().copied())
        .collect();
    private(
        &fake.join(format!("run-{n}.tmp")),
        &json!({ "argv": argv }).to_string(),
    );
    std::fs::rename(
        fake.join(format!("run-{n}.tmp")),
        fake.join(format!("run-{n}.json")),
    )
    .unwrap();
    let out = fake.join(format!("run-{n}.out"));
    within("agent child command", || out.exists());
    serde_json::from_slice(&std::fs::read(out).unwrap()).unwrap()
}

/// The rig's agent replies `text` in its turn (`atem message reply`).
fn reply(rig: &Rig, n: u32, text: &str) {
    let run = agent_run(&rig.fake, n, &["message", "reply", text]);
    assert_eq!(run["code"], 0, "{run}");
}

/// VII.A test 1 (design I.4.3: "The sender's channel and online status are
/// not conditions"): the phone enqueues two tasks and goes while the first
/// runs; the first ends and the second starts and ends with the phone
/// offline. Later the phone reads both replies. Each ran once, on one
/// attempt.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES and ATEM_TEST_STATE_DUMP hooks"
)]
fn sender_disconnects_and_later_reads_both_replies() {
    let mut rig = Rig::prepared(4 * HOUR, false);
    rig.with_station();
    rig.start();
    let mut r = Router::new(&rig.astation);
    rig.station_online(false);
    let mut svc = Dev::new(&mut r, IDS, &rig.log, SVC, true);
    let launch = svc.session(&mut r);
    let mut phone = Dev::new(&mut r, IDS, &rig.log, PHONE, false);
    let first = task(IDS, &launch, "OFFLINE_FIRST", HOUR);
    let second = task(IDS, &launch, "OFFLINE_SECOND", HOUR);
    for t in [&first, &second] {
        assert_eq!(enqueue(&mut phone, &mut r, t)["state"], "queued");
        assert!(delegated(&rig, &t["task_id"]), "a delegated task");
    }
    in_turn(&rig, &first["task_id"], "OFFLINE_FIRST");
    // The phone goes while the first task runs.
    phone.close(&mut r);
    reply(&rig, 1, "ANSWER_FIRST");
    complete_turn(&rig, &first["task_id"]);
    in_turn(&rig, &second["task_id"], "OFFLINE_SECOND");
    reply(&rig, 2, "ANSWER_SECOND");
    complete_turn(&rig, &second["task_id"]);
    // Later, the phone reads both.
    let mut phone = Dev::new(&mut r, IDS, &rig.log, PHONE, false);
    for (t, answer) in [(&first, "ANSWER_FIRST"), (&second, "ANSWER_SECOND")] {
        let status = work(&mut phone, &mut r, &t["task_id"]);
        assert_eq!(
            status["result"]["work"]["state"], "awaiting_result",
            "{status}"
        );
        let read = reply_query(&mut phone, &mut r, &t["task_id"]);
        assert_eq!(read["result"]["reply"]["text"], answer, "{read}");
    }
    let text = input(&rig);
    for t in [&first, &second] {
        let prompt = t["prompt"].as_str().unwrap();
        assert_eq!(text.matches(prompt).count(), 1, "{prompt}");
        assert_eq!(ends(&rig, &t["task_id"]), [Some("started".to_string())]);
    }
}

/// VII.A test 2 (design I.2, I.3.3 "Grant or integration expires"): a
/// service the fake Station's feed covers enqueues two tasks; its grant
/// expires (the host clock 25 minutes on) while the first runs and the
/// second waits. The second still runs, before its deadline. The expired
/// service can't even connect to ask; after the Mac renews it, it reads
/// both replies, and each task ran once.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES, ATEM_TEST_HOST_CLOCK and ATEM_TEST_STATE_DUMP hooks"
)]
fn an_expired_grants_task_still_runs_and_nothing_runs_twice() {
    let mut rig = Rig::prepared(20 * MIN, false);
    rig.with_station();
    rig.with_clock();
    rig.start();
    let mut r = Router::new(&rig.astation);
    rig.station_online(true);
    let mut svc = Dev::new(&mut r, IDS, &rig.log, SVC, true);
    let launch = svc.session(&mut r);
    let first = task(IDS, &launch, "EXPIRY_FIRST", 2 * HOUR);
    let second = task(IDS, &launch, "EXPIRY_SECOND", 2 * HOUR);
    for t in [&first, &second] {
        enqueue(&mut svc, &mut r, t);
        let admission = record(&rig, &t["task_id"])["delegated"].clone();
        assert_eq!(
            admission["principal"],
            format!("service:{SVC}"),
            "{admission}"
        );
        assert_eq!(admission["feed"]["origin"], STATION, "{admission}");
    }
    in_turn(&rig, &first["task_id"], "EXPIRY_FIRST");
    wait_stored(&rig, &second["task_id"], "blocked", BEHIND);
    reply(&rig, 1, "ANSWER_FIRST");
    // The grant expires.
    svc.close(&mut r);
    rig.clock().set_wall((25 * MIN) as i64);
    complete_turn(&rig, &first["task_id"]);
    in_turn(&rig, &second["task_id"], "EXPIRY_SECOND");
    reply(&rig, 2, "ANSWER_SECOND");
    complete_turn(&rig, &second["task_id"]);
    // Until a renewal it can't ask: its channel isn't admitted.
    let Err(refused) = r.connect(&uuid(), &rig.log, HOST, &Identity::service(SVC, auth(SVC)))
    else {
        panic!("an expired service was admitted");
    };
    assert_eq!(
        refused,
        ("unauthorized".to_string(), Some("expired".to_string()))
    );
    // The Mac renews it.
    let mut mac = Dev::new(&mut r, IDS, &rig.log, MAC, false);
    let until = rig.clock().wall() + 3 * HOUR;
    let renewal = rig.log.renew_service(SVC, until);
    mac.carry(&mut r, &[renewal]);
    let mut svc = Dev::new(&mut r, IDS, &rig.log, SVC, true);
    for (t, answer) in [(&first, "ANSWER_FIRST"), (&second, "ANSWER_SECOND")] {
        let status = work(&mut svc, &mut r, &t["task_id"]);
        assert_eq!(
            status["result"]["work"]["state"], "awaiting_result",
            "{status}"
        );
        let read = reply_query(&mut svc, &mut r, &t["task_id"]);
        assert_eq!(read["result"]["reply"]["text"], answer, "{read}");
    }
    let text = input(&rig);
    for t in [&first, &second] {
        let prompt = t["prompt"].as_str().unwrap();
        assert_eq!(text.matches(prompt).count(), 1, "{prompt}");
        assert_eq!(ends(&rig, &t["task_id"]), [Some("started".to_string())]);
    }
}

/// VII.A test 11 (design I.1.3): with `host.delegated` on, a browser
/// grant's task and a service no feed covers keep v1's lifecycle: no
/// admission record, they wait for their sender's channel, and each fails
/// at its sender's expiry (`sender's authorization expired`), never run.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES and ATEM_TEST_HOST_CLOCK hooks"
)]
fn browser_and_uncovered_service_keep_v1() {
    const EXPIRED: &str = "sender's authorization expired";
    let mut rig = Rig::prepared(20 * MIN, false);
    rig.with_clock();
    rig.start();
    let mut r = Router::new(&rig.astation);
    let mut svc = Dev::new(&mut r, IDS, &rig.log, SVC, true);
    let launch = svc.session(&mut r);
    // The session is busy with a task of the service's.
    let busy = task(IDS, &launch, "V1_BUSY", 2 * HOUR);
    enqueue(&mut svc, &mut r, &busy);
    in_turn(&rig, &busy["task_id"], "V1_BUSY");
    let wall = rig.clock().wall();
    let (grant, key) = rig.log.grant(
        MAC,
        GRANT,
        HOST,
        1,
        None,
        &["view", "notify", "prompt"],
        wall,
        wall + 30 * MIN,
    );
    let mut browser = Dev::admitted(
        &mut r,
        "relay",
        IDS,
        &rig.log,
        &Identity::browser(grant, key).unwrap(),
    );
    let from_svc = task(IDS, &launch, "V1_SERVICE", 2 * HOUR);
    let from_browser = task(IDS, &launch, "V1_BROWSER", 2 * HOUR);
    enqueue(&mut svc, &mut r, &from_svc);
    enqueue(&mut browser, &mut r, &from_browser);
    for t in [&busy, &from_svc, &from_browser] {
        assert!(!delegated(&rig, &t["task_id"]), "v1: no admission record");
    }
    svc.close(&mut r);
    browser.close(&mut r);
    complete_turn(&rig, &busy["task_id"]);
    // They wait for their channel.
    wait_stored(
        &rig,
        &from_svc["task_id"],
        "blocked",
        "waiting for the sender's authorized channel and current route",
    );
    // The service's grant expires (20 minutes), the browser's not yet (30).
    rig.clock().set_wall((25 * MIN) as i64);
    wait_stored(&rig, &from_svc["task_id"], "failed", EXPIRED);
    wait_stored(
        &rig,
        &from_browser["task_id"],
        "blocked",
        "waiting for the sender's authorized channel and current route",
    );
    rig.clock().set_wall((35 * MIN) as i64);
    wait_stored(&rig, &from_browser["task_id"], "failed", EXPIRED);
    let text = input(&rig);
    assert!(!text.contains("V1_SERVICE") && !text.contains("V1_BROWSER"));
    for t in [&from_svc, &from_browser] {
        assert!(attempts(&rig, &t["task_id"]).is_empty());
    }
}

/// A local session launched from this host's terminal, its agent the fake
/// of `name`: its fake directory.
fn local_session(rig: &Rig, name: &str) -> PathBuf {
    use std::io::{BufRead, BufReader, Write};
    let fake = rig.sandbox.dir.path().join(name);
    std::fs::create_dir_all(&fake).unwrap();
    let mut env = rig.sandbox.env();
    env.push((
        "CLAUDE_CLI_BIN".into(),
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/approvals/fake-agent.py")
            .display()
            .to_string(),
    ));
    env.push(("FAKE_DIR".into(), fake.display().to_string()));
    let path = std::fs::read_to_string(rig.sandbox.config().join("runtime.socket")).unwrap();
    let socket = std::os::unix::net::UnixStream::connect(path).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    let mut write = socket.try_clone().unwrap();
    writeln!(
        write,
        "{}",
        json!({"v":1,"op":"hello","protocol":1,"build":"test"})
    )
    .unwrap();
    writeln!(
        write,
        "{}",
        json!({"v":1,"op":"launch","provider":"claude","cwd":rig.sandbox.home,
            "env":env,"rows":24,"cols":80})
    )
    .unwrap();
    let launched = BufReader::new(socket)
        .lines()
        .map(|line| serde_json::from_str::<Value>(&line.unwrap()).unwrap())
        .find(|m| m["op"] == "error" || m["op"] == "launched")
        .unwrap();
    assert_eq!(launched["op"], "launched", "{launched}");
    within("the local agent", || fake.join("events").exists());
    fake
}

/// The local (stage 1) tasks in the store.
fn local_tasks(rig: &Rig) -> Vec<Value> {
    let db =
        rusqlite::Connection::open(rig.sandbox.config().join("runtime/host-work.sqlite")).unwrap();
    db.busy_timeout(Duration::from_secs(5)).unwrap();
    let mut q = db
        .prepare("SELECT record FROM work WHERE json_extract(record,'$.principal')='local'")
        .unwrap();
    q.query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .map(|t| serde_json::from_str(&t.unwrap()).unwrap())
        .collect()
}

/// VII.A test 14 (design I.6.2 step 7, I.5.8; collaboration §10): a local
/// task never waits for a gate. The phone's task waits `revocations not
/// yet checked` (the phone gone, no Station: its gate closed) without
/// holding its session, and a local agent's task to that session runs past
/// it and keeps stage 1's lifecycle: no admission record, `awaiting_result`
/// after its turn, completed by its sender. The phone's never runs.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES hook"
)]
fn local_tasks_never_wait_for_a_gate() {
    let mut rig = Rig::prepared(4 * HOUR, true);
    rig.start();
    let mut r = Router::new(&rig.astation);
    let mut svc = Dev::new(&mut r, IDS, &rig.log, SVC, true);
    let launch = svc.session(&mut r);
    let busy = task(IDS, &launch, "GATE_BUSY", HOUR);
    enqueue(&mut svc, &mut r, &busy);
    in_turn(&rig, &busy["task_id"], "GATE_BUSY");
    let mut phone = Dev::new(&mut r, IDS, &rig.log, PHONE, false);
    let gated = task(IDS, &launch, "GATE_PHONE", HOUR);
    enqueue(&mut phone, &mut r, &gated);
    assert!(delegated(&rig, &gated["task_id"]));
    phone.close(&mut r);
    complete_turn(&rig, &busy["task_id"]);
    wait_stored(&rig, &gated["task_id"], "blocked", GATE_CLOSED);
    // A local agent sends to the session (`tag:peer`).
    let other = local_session(&rig, "other");
    let sent = agent_run(
        &other,
        1,
        &["message", "send", "--to", "tag:peer", "GATE_LOCAL"],
    );
    assert_eq!(sent["code"], 0, "{sent}");
    within("the local task's prompt", || {
        input(&rig).contains("GATE_LOCAL")
    });
    let local = local_tasks(&rig);
    assert_eq!(local.len(), 1, "{local:?}");
    let tid = local[0]["task"]["task_id"].clone();
    assert!(
        !delegated(&rig, &tid),
        "stage 1's task: no admission record"
    );
    complete_turn(&rig, &tid);
    let done = agent_run(&other, 2, &["message", "complete", tid.as_str().unwrap()]);
    assert_eq!(done["code"], 0, "{done}");
    within("the local task completed", || {
        stored(&rig, &tid)["state"] == "completed"
    });
    assert_eq!(
        stored(&rig, &gated["task_id"])["detail"],
        GATE_CLOSED,
        "the phone's task still waits for its gate"
    );
    assert!(!input(&rig).contains("GATE_PHONE"));
    assert!(attempts(&rig, &gated["task_id"]).is_empty());
}

/// The broker's state after a pass (`ATEM_TEST_STATE_DUMP`), as a JSON
/// value (`Null` before the first).
fn dumped(rig: &Rig) -> Value {
    std::fs::read_to_string(rig.dump_file())
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or(Value::Null)
}

/// Waits for two passes of the broker begun after now: whatever a marker
/// file said before was read again since.
fn two_passes(rig: &Rig) {
    let pass = |rig: &Rig| dumped(rig)["pass"].as_u64().unwrap_or(0);
    let now = pass(rig);
    within("two passes", || pass(rig) >= now + 2);
}

/// The session host's receipt of `rid`, as the state dump shows it.
fn receipt(rig: &Rig, rid: &str) -> Value {
    dumped(rig)["receipts"][rid].clone()
}

/// VII.A test 17 (design I.4.3 condition 2a, Decision 16; session-v1 R9.14
/// item 3): the start check refuses an attempt a freeze stops, before
/// host-work has processed the freeze. The session's queue holds the Mac's
/// own prompt, then the phone's attempt (host-work's submit, made once the
/// broker's `hold_dispatch` is gone, starts the Mac's turn ahead of it), so
/// the attempt waits `accepted` behind a running turn. Host-work's
/// scheduling is then held (`hold_host_work`) and a conflicting entry (the
/// runtime's own fetch carries it) freezes the device list. The Mac's turn
/// ends; the session host asks the start check, which withdraws the attempt
/// (`withdrawn by the host`) while host-work's store still shows the task
/// `submitted` with its attempt live. Released, host-work settles it from
/// the withdrawal: `failed`, `sender's authority changed`, one attempt
/// `withdrawn`, its prompt never written.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES, ATEM_TEST_PTY_FAULTS, ATEM_TEST_MEMBERSHIP_FAULTS and ATEM_TEST_STATE_DUMP hooks"
)]
fn a_freeze_at_the_start_fails_the_attempt() {
    let mut rig = Rig::prepared(4 * HOUR, false);
    rig.with_station();
    rig.faults = true;
    rig.membership = true;
    rig.start();
    let mut r = Router::new(&rig.astation);
    rig.station_online(false);
    let mut svc = Dev::new(&mut r, IDS, &rig.log, SVC, true);
    let launch = svc.session(&mut r);
    let sid = launch["session_id"].as_str().unwrap().to_string();
    let mut mac = Dev::new(&mut r, IDS, &rig.log, MAC, false);
    mac.list(&mut r, &sid);
    let mut phone = Dev::new(&mut r, IDS, &rig.log, PHONE, false);
    let hold_host_work = rig.faults().join("hold_host_work");
    let hold_dispatch = rig.faults().join("hold_dispatch");
    private(&hold_host_work, "");
    private(&hold_dispatch, "");
    two_passes(&rig);
    let held = task(IDS, &launch, "FROZEN_AT_START", HOUR);
    assert_eq!(enqueue(&mut phone, &mut r, &held)["state"], "queued");
    // The Mac's prompt is accepted first; the Mac gives the lease back.
    let accepted = mac.request(
        &mut r,
        json!({"op":"submit","binding":mac.read(&sid),"kind":"prompt","request_id":uuid(),
            "acquire":true,"payload":{"text":"MAC_TURN"}}),
    );
    assert_eq!(
        (&accepted["op"], &accepted["state"]),
        (&json!("receipt"), &json!("accepted")),
        "{accepted}"
    );
    let lease = mac.request(
        &mut r,
        json!({"op":"acquire","binding":mac.read(&sid),"takeover":false}),
    );
    assert_eq!(lease["op"], "lease", "{lease}");
    let released = mac.request(&mut r, json!({"op":"release","binding":lease["binding"]}));
    assert_eq!(released["op"], "lease_released", "{released}");
    // The dispatch goes on (seen by the broker before host-work's next
    // pass); then host-work's submit queues the attempt behind the Mac's
    // prompt, whose turn begins.
    std::fs::remove_file(&hold_dispatch).unwrap();
    two_passes(&rig);
    std::fs::remove_file(&hold_host_work).unwrap();
    within("the Mac's turn", || input(&rig).contains("MAC_TURN"));
    let deadline = Instant::now() + WAIT;
    let attempt = loop {
        let all = attempts(&rig, &held["task_id"]);
        if let [(id, None)] = all.as_slice()
            && receipt(&rig, id)["state"] == "accepted"
            && stored(&rig, &held["task_id"])["state"] == "submitted"
        {
            break id.clone();
        }
        assert!(
            Instant::now() < deadline,
            "no attempt waits accepted: {all:?} {}",
            stored(&rig, &held["task_id"])
        );
        std::thread::sleep(Duration::from_millis(40));
    };
    // Host-work's scheduling held; the freeze: an entry at the head's own
    // `seq` with another body.
    private(&hold_host_work, "");
    two_passes(&rig);
    let conflict = rig.log.conflicting_add("dev-other");
    replace(
        &rig.membership_dir().join("carry.json"),
        &json!({"entries": [conflict]}).to_string(),
    );
    within("the carriage applied", || {
        rig.membership_dir().join("carried").exists()
    });
    let carried = std::fs::read_to_string(rig.membership_dir().join("carried")).unwrap();
    assert!(carried.starts_with("Frozen"), "{carried}");
    // The Mac's turn ends: the session host asks the start check.
    std::fs::write(rig.fake.join("complete"), "").unwrap();
    within("the start check's withdrawal", || {
        let rc = receipt(&rig, &attempt);
        rc["state"] == "rejected" && rc["detail"] == "withdrawn by the host"
    });
    // Before host-work processed the freeze.
    assert_eq!(stored(&rig, &held["task_id"])["state"], "submitted");
    assert_eq!(ends(&rig, &held["task_id"]), [None]);
    assert!(!input(&rig).contains("FROZEN_AT_START"));
    std::fs::remove_file(&hold_host_work).unwrap();
    wait_stored(
        &rig,
        &held["task_id"],
        "failed",
        "sender's authority changed",
    );
    assert_eq!(
        attempts(&rig, &held["task_id"]),
        [(attempt, Some("withdrawn".to_string()))]
    );
    assert!(!input(&rig).contains("FROZEN_AT_START"));
}

/// VII.A test 20 (design I.5.8, "Native senders"; Task 19 review M2): no
/// Station is reachable and the phone is on the local network (Astation's
/// :8080). Its channel's carriage brings the host up to its head (a new
/// entry the host lacked), so its task runs. A later carriage on the same
/// channel stops short (an entry deferred behind a pending recovery): the
/// next task waits `device list update pending`; the Mac's approval ends
/// the wait, but the phone hasn't carried the host to its head since, so
/// the task waits for its gate; once the phone carries the head, it runs.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES hook"
)]
fn native_on_a_lan_runs_after_its_carriage() {
    use atem_client::membership::entry::Action;
    let mut rig = Rig::prepared(4 * HOUR, false);
    rig.start();
    let mut r = Router::new(&rig.astation);
    let mut svc = Dev::new_via(&mut r, "direct", IDS, &rig.log, SVC, true);
    let launch = svc.session(&mut r);
    // The phone's list is a head ahead of the host's.
    rig.log.add_native("dev-tablet", &["view"]);
    let mut phone = Dev::new_via(&mut r, "direct", IDS, &rig.log, PHONE, false);
    let first = task(IDS, &launch, "LAN_FIRST", HOUR);
    enqueue(&mut phone, &mut r, &first);
    in_turn(&rig, &first["task_id"], "LAN_FIRST");
    complete_turn(&rig, &first["task_id"]);
    // A carriage that stops short: a pending recovery and an entry its new
    // member signed, deferred.
    let recovery = rig.log.recovery_add("dev-new");
    let recovery_hash = rig.log.entries.last().unwrap().hash();
    let body = rig.log.log.draft(
        "dev-new",
        r9log::host_now().wall_ms,
        &Action::Remove {
            device_id: PHONE.into(),
        },
    );
    let deferred = atem_client::membership::sign_entry(&rig.log.keys, &auth("dev-new"), body)
        .unwrap()
        .object()
        .to_json();
    phone.carry(&mut r, &[recovery, deferred]);
    let second = task(IDS, &launch, "LAN_SECOND", HOUR);
    enqueue(&mut phone, &mut r, &second);
    wait_stored(
        &rig,
        &second["task_id"],
        "blocked",
        "device list update pending",
    );
    // The Mac approves the recovery: the wait ends; the phone's last
    // carriage didn't bring the host to its head.
    let approve = rig.log.append(
        MAC,
        Action::RecoveryApprove {
            target: recovery_hash,
        },
    );
    let mut mac = Dev::new_via(&mut r, "direct", IDS, &rig.log, MAC, false);
    mac.carry(&mut r, std::slice::from_ref(&approve));
    wait_stored(&rig, &second["task_id"], "blocked", GATE_CLOSED);
    assert!(!input(&rig).contains("LAN_SECOND"));
    // The phone carries the head: caught up, its task runs.
    phone.carry(&mut r, &[approve]);
    in_turn(&rig, &second["task_id"], "LAN_SECOND");
    complete_turn(&rig, &second["task_id"]);
    assert_eq!(input(&rig).matches("LAN_SECOND").count(), 1);
}

/// VII.A test 9 (host-work-v1 §11.6, "Deadline comparisons"): the host's
/// wall clock is set an hour back while its boot-time counter goes on past
/// a waiting task's deadline: the task expires and never runs, the wall
/// clock before its deadline notwithstanding. Again across a restart: the
/// runtime is killed, the counter goes past another task's deadline while
/// it is down, and the start's recovery expires that one (design I.6.2
/// step 6). A task enqueued after them runs; they never do.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES, ATEM_TEST_HOST_CLOCK and ATEM_TEST_STATE_DUMP hooks"
)]
fn clock_set_back_never_runs_an_expired_task() {
    const EXPIRED: &str = "expired before submission";
    let mut rig = Rig::prepared(4 * HOUR, false);
    rig.with_station();
    rig.with_clock();
    rig.start();
    let mut r = Router::new(&rig.astation);
    rig.station_online(false);
    let mut svc = Dev::new(&mut r, IDS, &rig.log, SVC, true);
    let launch = svc.session(&mut r);
    let mut phone = Dev::new(&mut r, IDS, &rig.log, PHONE, false);
    let wall = rig.clock().wall();
    let running = task_until(IDS, &launch, "BACK_RUNNING", wall + 3 * HOUR);
    let soon = task_until(IDS, &launch, "BACK_SOON", wall + 10 * MIN);
    let later = task_until(IDS, &launch, "BACK_LATER", wall + 20 * MIN);
    for t in [&running, &soon, &later] {
        enqueue(&mut phone, &mut r, t);
    }
    in_turn(&rig, &running["task_id"], "BACK_RUNNING");
    for t in [&soon, &later] {
        wait_stored(&rig, &t["task_id"], "blocked", BEHIND);
    }
    // The wall clock an hour back; 11 minutes on the boot-time counter.
    rig.clock().set(-((HOUR) as i64), 11 * MIN);
    wait_stored(&rig, &soon["task_id"], "expired", EXPIRED);
    assert_eq!(stored(&rig, &later["task_id"])["state"], "blocked");
    // The runtime is killed; while it is down the counter passes the
    // later deadline, the wall clock still behind.
    drop((r, svc, phone));
    rig.kill();
    rig.clock().set(-((HOUR) as i64), 21 * MIN);
    rig.start();
    let mut r = Router::new(&rig.astation);
    wait_stored(&rig, &later["task_id"], "expired", EXPIRED);
    complete_turn(&rig, &running["task_id"]);
    let mut phone = Dev::new(&mut r, IDS, &rig.log, PHONE, false);
    let next = task_until(IDS, &launch, "BACK_NEXT", rig.clock().wall() + 3 * HOUR);
    enqueue(&mut phone, &mut r, &next);
    in_turn(&rig, &next["task_id"], "BACK_NEXT");
    let text = input(&rig);
    assert!(!text.contains("BACK_SOON") && !text.contains("BACK_LATER"));
    for t in [&soon, &later] {
        assert!(attempts(&rig, &t["task_id"]).is_empty());
    }
}

/// VII.A test 7, its first two crash points (design I.6.2, I.6.3, I.6.4;
/// session-v1 R9.14 item 6): the runtime is killed (`SIGKILL`) right after
/// an attempt's row committed, before its submit, and, for another task,
/// after the session host `accepted` its attempt (the broker's
/// `hold_dispatch` keeps it from starting). At each restart the attempt is
/// reconciled (never admitted; withdrawn at recovery), never sent again,
/// and the task runs once, on a new attempt.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES, ATEM_TEST_PTY_FAULTS and ATEM_TEST_STATE_DUMP hooks"
)]
fn sigkill_after_attempt_commit_and_after_accepted_runs_once() {
    let mut rig = Rig::prepared(4 * HOUR, false);
    rig.with_station();
    rig.faults = true;
    rig.start();
    let mut r = Router::new(&rig.astation);
    rig.station_online(false);
    let mut svc = Dev::new(&mut r, IDS, &rig.log, SVC, true);
    let launch = svc.session(&mut r);
    let mut phone = Dev::new(&mut r, IDS, &rig.log, PHONE, false);

    // Killed after the attempt's commit, before its submit.
    private(&rig.faults().join("crash_after_attempt_commit"), "");
    let first = task(IDS, &launch, "KILLED_AT_COMMIT", HOUR);
    // Its reply may never be sent: the runtime dies in the same pass.
    phone.send(&mut r, enqueue_data(IDS, &first));
    drop((r, svc, phone));
    rig.died();
    let committed = attempts(&rig, &first["task_id"]);
    assert_eq!(committed.len(), 1, "{committed:?}");
    assert_eq!(committed[0].1, None, "live at the crash");
    assert_eq!(stored(&rig, &first["task_id"])["state"], "submitting");
    assert!(!input(&rig).contains("KILLED_AT_COMMIT"));
    rig.start();
    let mut r = Router::new(&rig.astation);
    in_turn(&rig, &first["task_id"], "KILLED_AT_COMMIT");
    complete_turn(&rig, &first["task_id"]);
    assert_eq!(input(&rig).matches("KILLED_AT_COMMIT").count(), 1);
    let all = attempts(&rig, &first["task_id"]);
    assert_eq!(
        all[0],
        (committed[0].0.clone(), Some("not_admitted".into()))
    );
    assert_eq!(
        ends(&rig, &first["task_id"])[1..],
        [Some("started".to_string())]
    );

    // Killed after the session `accepted` the attempt.
    private(&rig.faults().join("hold_dispatch"), "");
    let mut phone = Dev::new(&mut r, IDS, &rig.log, PHONE, false);
    let second = task(IDS, &launch, "KILLED_AFTER_ACCEPTED", HOUR);
    enqueue(&mut phone, &mut r, &second);
    let deadline = Instant::now() + WAIT;
    while !(stored(&rig, &second["task_id"])["state"] == "submitted"
        && ends(&rig, &second["task_id"]) == [None])
    {
        assert!(
            Instant::now() < deadline,
            "no attempt waits accepted: {}",
            stored(&rig, &second["task_id"])
        );
        std::thread::sleep(Duration::from_millis(40));
    }
    let accepted = attempts(&rig, &second["task_id"])[0].0.clone();
    drop((r, phone));
    rig.kill();
    std::fs::remove_file(rig.faults().join("hold_dispatch")).unwrap();
    assert!(!input(&rig).contains("KILLED_AFTER_ACCEPTED"));
    rig.start();
    in_turn(&rig, &second["task_id"], "KILLED_AFTER_ACCEPTED");
    complete_turn(&rig, &second["task_id"]);
    assert_eq!(input(&rig).matches("KILLED_AFTER_ACCEPTED").count(), 1);
    let all = attempts(&rig, &second["task_id"]);
    assert_eq!(all.len(), 2, "{all:?}");
    assert_eq!(all[0], (accepted, Some("withdrawn".into())));
    assert_eq!(all[1].1.as_deref(), Some("started"));
}

// ── The host's own device-list fetch and deferred entries (design I.4.3,
// I.5.8; session-v1 R9.3, R9.5) ──

/// The host's Station link in its state dump.
fn until_station(rig: &Rig, what: &str, done: impl Fn(&Value) -> bool) -> Value {
    let mut last = Value::Null;
    within(what, || {
        last = dumped(rig)["station"].clone();
        done(&last)
    });
    last
}

/// The head `seq` of the host's device list, as written.
fn list_head(rig: &Rig) -> u64 {
    let path = rig.sandbox.config().join("pairing/membership.json");
    let state: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    state["head"]["seq"].as_u64().unwrap()
}

fn fetch(after: u64) -> Result<ToStation, RelayError> {
    Ok(ToStation::MembershipFetch(MembershipFetch { after }))
}

/// The host's next device-list fetch on `link`, answered; its feed syncs
/// (`control_sync`) on the way answered too.
fn next_fetch(station: &mut FakeStation, link: u64) -> Result<ToStation, RelayError> {
    loop {
        let call = station.next_call(link);
        if !matches!(call, Ok(ToStation::ControlSync(_))) {
            return call;
        }
    }
}

/// The host's next feed sync on `link`, answered (its fetches on the way
/// answered too): a Station answers each call at once, and an unanswered
/// sync ends the sync on its link generation (ruling T33d), so a test
/// answers it before it moves the host's clock past 30 s.
fn next_sync(station: &mut FakeStation, link: u64) {
    loop {
        if matches!(station.next_call(link), Ok(ToStation::ControlSync(_))) {
            return;
        }
    }
}

/// The device-list fetches the host sent so far (its feed syncs aside).
fn fetches(station: &FakeStation) -> usize {
    station
        .sent()
        .iter()
        .filter(|bytes| {
            matches!(
                ToStation::decode(bytes.as_bytes()),
                Ok(ToStation::MembershipFetch(_))
            )
        })
        .count()
}

/// The phone's removal, signed by `dev-new` (the subject of `log`'s
/// pending recovery) on `log`'s head: deferred on a host until the wait
/// ends (R9.5). Not appended: `log` itself can't verify it before then.
fn removal_by_the_pending(log: &TestLog) -> Value {
    use atem_client::membership::entry::Action;
    let body = log.log.draft(
        "dev-new",
        r9log::host_now().wall_ms,
        &Action::Remove {
            device_id: PHONE.into(),
        },
    );
    atem_client::membership::sign_entry(&log.keys, &auth("dev-new"), body)
        .unwrap()
        .object()
        .to_json()
}

/// Design I.4.3 ("Deferred entries"), I.5.8: the host's own fetch brings a
/// pending `recovery_add` and an entry its subject signed, which the host
/// defers. The fetch stops there (no fetch again from the new head), and
/// every unstarted delegated remote task waits, `device list update
/// pending`: the phone's too, though its own channel is caught up. The stop
/// is the gate's device-list part ("fetched up to a deferred entry"), and
/// while it holds the list isn't behind: the Station's next `heads`, naming
/// the same head past the pacing, brings no fetch.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES, ATEM_TEST_HOST_CLOCK and ATEM_TEST_STATE_DUMP hooks"
)]
fn a_fetch_stopping_at_a_deferred_entry_marks_device_list_update_pending() {
    let mut rig = Rig::prepared(4 * HOUR, false);
    rig.with_clock();
    rig.with_station();
    rig.start();
    let mut r = Router::new(&rig.astation);
    let link = r.link;
    let mut svc = Dev::new(&mut r, IDS, &rig.log, SVC, true);
    let launch = svc.session(&mut r);
    let mut phone = Dev::new(&mut r, IDS, &rig.log, PHONE, false);
    let pinned = list_head(&rig);
    // The Station's list: a pending recovery, then an entry its subject
    // signed.
    rig.log.recovery_add("dev-new");
    let deferred = removal_by_the_pending(&rig.log);
    let log = &rig.log;
    let mut station = rig.station();
    station.set_log_beyond(log, &[deferred]);
    station.serve(link);
    station.heads_now();
    assert_eq!(next_fetch(&mut station, link), fetch(pinned));
    drop(station);
    let s = until_station(&rig, "the stop at the deferred entry", |s| {
        s["fetch"]["stopped"] == pinned + 2
    });
    assert_eq!(list_head(&rig), pinned + 1, "the recovery applied");
    assert!(s["fetch"]["in_flight"].is_null(), "no fetch again: {s}");
    assert_eq!(s["list_part"], true, "fetched up to a deferred entry: {s}");
    assert!(
        rig.sandbox
            .config()
            .join("runtime/journal/membership_deferred")
            .is_file()
    );

    let t = task_until(
        IDS,
        &launch,
        "DEFERRED_BY_THE_FETCH",
        rig.clock().wall() + HOUR,
    );
    enqueue(&mut phone, &mut r, &t);
    wait_stored(&rig, &t["task_id"], "blocked", "device list update pending");

    // The same head announced again, past every pacing: not behind.
    let heads = s["heads"].as_u64().unwrap();
    rig.clock().add_mono(STALL_PAUSE + 1_000);
    rig.station().heads_now();
    let s = until_station(&rig, "the next heads", |s| s["heads"] == heads + 1);
    assert!(s["fetch"]["in_flight"].is_null(), "{s}");
    assert_eq!(s["fetch"]["stopped"], pinned + 2, "{s}");
    two_passes(&rig);
    rig.station().serve(link);
    assert_eq!(fetches(&rig.station()), 1, "{:?}", rig.station().sent());
    wait_stored(&rig, &t["task_id"], "blocked", "device list update pending");
    assert!(attempts(&rig, &t["task_id"]).is_empty());
    assert!(!input(&rig).contains("DEFERRED_BY_THE_FETCH"));
}

/// VII.A test 15 (design I.4.3, "Deferred entries"; session-v1 R9.5): the
/// host's fetch stops at an entry the subject of a pending recovery signed
/// (the phone's removal), and every unstarted delegated remote task waits,
/// `device list update pending`. The wait ends on the host's clock: the
/// deferral ends, the host fetches the entry again at once (no `heads`),
/// and nothing dispatches before it is checked again: a task whose deadline
/// passed meanwhile expires, and the others wait `revocations not yet
/// checked` (the gate's device-list part no longer holds: the list is
/// behind the announced head) until the fetch applies the entry. Then the
/// removed phone's task is cancelled, `sender revoked`, and the Mac's runs
/// once the Station's next heads opens the feed part again (none came for
/// the 24 hours the host's clock moved).
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES, ATEM_TEST_HOST_CLOCK and ATEM_TEST_STATE_DUMP hooks"
)]
fn the_deferral_ends_with_the_recovery_wait_and_tasks_are_checked_again() {
    let mut rig = Rig::prepared(48 * HOUR, false);
    rig.with_clock();
    rig.with_station();
    rig.start();
    let mut r = Router::new(&rig.astation);
    let link = r.link;
    let mut svc = Dev::new(&mut r, IDS, &rig.log, SVC, true);
    let launch = svc.session(&mut r);
    let pinned = list_head(&rig);
    // The recovery reaches the host by its fetch: its wait starts now on
    // the host's clock.
    rig.log.recovery_add("dev-new");
    let log = &rig.log;
    let mut station = rig.station();
    station.set_log(log);
    station.serve(link);
    station.heads_now();
    assert_eq!(next_fetch(&mut station, link), fetch(pinned));
    // The feed's sync answered before the host's clock moves on.
    next_sync(&mut station, link);
    drop(station);
    within("the recovery", || list_head(&rig) == pinned + 1);

    // Five minutes before the wait ends, the entry its subject signed.
    rig.clock()
        .set((24 * HOUR - 5 * MIN) as i64, 24 * HOUR - 5 * MIN);
    let deferred = removal_by_the_pending(&rig.log);
    let log = &rig.log;
    let mut station = rig.station();
    station.set_log_beyond(log, &[deferred]);
    station.heads_now();
    assert_eq!(next_fetch(&mut station, link), fetch(pinned + 1));
    drop(station);
    until_station(&rig, "the stop at the deferred entry", |s| {
        s["fetch"]["stopped"] == pinned + 2
    });

    // The phone's task and two of the Mac's, one due in two minutes.
    let mut phone = Dev::new(&mut r, IDS, &rig.log, PHONE, false);
    let mut mac = Dev::new(&mut r, IDS, &rig.log, MAC, false);
    let wall = rig.clock().wall();
    let removed = task_until(IDS, &launch, "BY_THE_REMOVED_PHONE", wall + HOUR);
    let runs = task_until(IDS, &launch, "BY_THE_MAC", wall + HOUR);
    let due = task_until(IDS, &launch, "DUE_DURING_THE_WAIT", wall + 2 * MIN);
    enqueue(&mut phone, &mut r, &removed);
    enqueue(&mut mac, &mut r, &runs);
    enqueue(&mut mac, &mut r, &due);
    for t in [&removed, &runs, &due] {
        wait_stored(&rig, &t["task_id"], "blocked", "device list update pending");
    }
    // The senders go: their gate is the host's own Station's now, with no
    // caught-up channel of their own.
    phone.close(&mut r);
    mac.close(&mut r);

    // The wait ends on the host's clock (24 h and a minute since the host
    // first saw the recovery). Checked again before anything dispatches.
    rig.clock().set((24 * HOUR + MIN) as i64, 24 * HOUR + MIN);
    wait_stored(
        &rig,
        &due["task_id"],
        "expired",
        "expired before submission",
    );
    for t in [&removed, &runs] {
        wait_stored(&rig, &t["task_id"], "blocked", GATE_CLOSED);
    }
    let s = until_station(&rig, "the deferral's end", |s| {
        s["fetch"]["stopped"].is_null()
    });
    assert_eq!(s["list_part"], false, "{s}");
    // The host fetched the entry again at once, with no heads.
    let heads = s["heads"].clone();
    assert_eq!(next_fetch(&mut rig.station(), link), fetch(pinned + 1));
    within("the removal", || list_head(&rig) == pinned + 2);
    wait_stored(&rig, &removed["task_id"], "cancelled", "sender revoked");
    let s = dumped(&rig)["station"].clone();
    assert_eq!(s["heads"], heads, "no heads since: {s}");
    assert_eq!(s["list_part"], true, "{s}");
    // No heads came for 24 h on the host's clock: the feed part opens at
    // the Station's next heads, and the Mac's task runs.
    rig.station().heads_now();
    within("the gate open again", || {
        rig.station().serve(link);
        dumped(&rig)["station"]["feed"]["open"] == true
    });
    in_turn(&rig, &runs["task_id"], "BY_THE_MAC");
    complete_turn(&rig, &runs["task_id"]);
    for t in [&removed, &due] {
        assert!(attempts(&rig, &t["task_id"]).is_empty());
    }
    assert!(!input(&rig).contains("BY_THE_REMOVED_PHONE"));
    assert!(!input(&rig).contains("DUE_DURING_THE_WAIT"));
}

/// What the owner's terminal (outside any session) prints for `atem
/// <args>`: its stdout; the command must succeed.
fn owner(rig: &Rig, args: &[&str]) -> String {
    let (out, err, ok) = rig.sandbox.atem(args);
    assert!(ok, "atem {args:?} failed: {out}{err}");
    out
}

/// Host-work-v1 §11.6 "On the host", step 4's open question 2: `atem task
/// list --unknown` and `atem task resolve` are the owner's, run from a
/// terminal outside any agent session. Run by an agent of the runtime (its
/// own child) both are refused with the reason, and nothing changes; from
/// the owner's terminal the same runtime answers.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES and ATEM_TEST_STATE_DUMP hooks"
)]
fn task_resolve_refused_inside_an_agent_session() {
    let mut rig = Rig::prepared(4 * HOUR, false);
    rig.with_station();
    rig.start();
    let mut r = Router::new(&rig.astation);
    rig.station_online(false);
    let mut svc = Dev::new(&mut r, IDS, &rig.log, SVC, true);
    let launch = svc.session(&mut r);
    let mut phone = Dev::new(&mut r, IDS, &rig.log, PHONE, false);
    let t = task(IDS, &launch, "IN_ITS_TURN", HOUR);
    enqueue(&mut phone, &mut r, &t);
    in_turn(&rig, &t["task_id"], "IN_ITS_TURN");
    let tid = t["task_id"].as_str().unwrap();
    let inside = "atem task runs from the owner's terminal, not inside an Atem session";
    for (n, args) in [
        (1, vec!["task", "resolve", tid, "failed"]),
        (
            2,
            vec![
                "task",
                "resolve",
                tid,
                "failed",
                "--detail",
                "from the agent",
            ],
        ),
        (3, vec!["task", "list", "--unknown"]),
    ] {
        let run = agent_run(&rig.fake, n, &args);
        assert_ne!(run["code"], 0, "{run}");
        assert!(
            run["stderr"].as_str().unwrap().contains(inside),
            "{args:?}: {run}"
        );
    }
    let status = stored(&rig, &t["task_id"]);
    assert_eq!(
        (status["state"].as_str(), status.get("resolved")),
        (Some("submitted"), None),
        "{status}"
    );
    // The owner's terminal: answered (nothing is unknown yet).
    assert_eq!(owner(&rig, &["task", "list", "--unknown"]), "");
    let (out, err, ok) = rig.sandbox.atem(&["task", "resolve", tid, "failed"]);
    assert!(!ok, "{out}");
    assert!(
        err.contains(&format!(
            "task {tid} is submitted; only a task of unknown outcome is resolved"
        )),
        "{err}"
    );
}

/// Host-work-v1 §11.6 "On the host" ("`atem task list --unknown` lists the
/// unresolved outcomes: the task, session, sender, reason and when"; "`atem
/// task resolve <task_id> failed|done` resolves one as the owner, on the
/// host. Its `resolved.by` is `local`"), step 4's open question 2 and
/// ruling T23a, through the CLI and the real runtime: two of the phone's
/// tasks run on two sessions and their agents exit, so both outcomes are
/// unknown. The owner lists them and resolves one `failed` (the default
/// detail). The runtime restarts without the hook: the other is still
/// listed and the owner resolves it `done` with a vault entry, taken as a
/// reply's context is (encryption on, read back). Each is stored resolved
/// by `local`; nothing is left unresolved.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES, ATEM_TEST_STATE_DUMP and ATEM_TEST_CONTEXT_DIR hooks"
)]
fn the_owner_lists_and_resolves_unknown_outcomes_from_the_terminal() {
    use sha2::{Digest, Sha256};
    let mut rig = Rig::prepared(4 * HOUR, false);
    support::astation::write_encryption_mode(&rig.sandbox.config(), "on");
    rig.with_station();
    rig.context = true;
    rig.start();
    let mut r = Router::new(&rig.astation);
    rig.station_online(false);
    let mut svc = Dev::new(&mut r, IDS, &rig.log, SVC, true);
    let (first, second) = (svc.session(&mut r), svc.session(&mut r));
    let mut phone = Dev::new(&mut r, IDS, &rig.log, PHONE, false);
    let one = task(IDS, &first, "OWNER_ONE", HOUR);
    let two = task(IDS, &second, "OWNER_TWO", HOUR);
    for t in [&one, &two] {
        enqueue(&mut phone, &mut r, t);
    }
    in_turn(&rig, &one["task_id"], "OWNER_ONE");
    in_turn(&rig, &two["task_id"], "OWNER_TWO");
    // Both agents exit in their turns.
    private(&rig.fake.join("exit"), "");
    for t in [&one, &two] {
        wait_stored(&rig, &t["task_id"], "outcome_unknown", "agent exited");
    }
    let (one_id, two_id) = (
        one["task_id"].as_str().unwrap(),
        two["task_id"].as_str().unwrap(),
    );
    let listed = owner(&rig, &["task", "list", "--unknown"]);
    let lines: Vec<&str> = listed.lines().collect();
    assert_eq!(lines.len(), 2, "{listed}");
    for (line, (tid, launch)) in lines.iter().zip([(one_id, &first), (two_id, &second)]) {
        let head = format!(
            "{tid}  {}  member:{PHONE}  agent exited  ",
            launch["session_id"].as_str().unwrap()
        );
        assert!(line.starts_with(&head), "{line}");
        // When: the local `YYYY-MM-DD HH:MM`.
        assert_eq!(line.len(), head.len() + 16, "{line}");
    }
    assert_eq!(
        owner(&rig, &["task", "resolve", one_id, "failed"]),
        format!("{one_id}: resolved as failed\n")
    );
    let failed = stored(&rig, &one["task_id"]);
    assert_eq!(
        (
            failed["state"].as_str(),
            failed["detail"].as_str(),
            failed["resolved"]["by"].as_str()
        ),
        (
            Some("failed"),
            Some("resolved as failed on the host"),
            Some("local")
        ),
        "{failed}"
    );
    // A restart without the hook: the other is still the owner's to settle.
    drop((r, svc, phone));
    rig.kill();
    rig.hook = false;
    rig.start();
    let listed = owner(&rig, &["task", "list", "--unknown"]);
    assert_eq!(listed.lines().count(), 1, "{listed}");
    assert!(listed.starts_with(&format!("{two_id}  ")), "{listed}");
    let text = "The change landed; the owner checked it.";
    let digest = format!("{:x}", Sha256::digest(text.as_bytes()));
    let name = format!("{:x}", Sha256::digest(b"v-result:1@1"));
    private(
        &rig.sandbox
            .dir
            .path()
            .join("context")
            .join(format!("{name}.json")),
        &json!({"kind":"vault","id":"v-result:1","version":1,"digest":digest,"text":text})
            .to_string(),
    );
    assert_eq!(
        owner(
            &rig,
            &["task", "resolve", two_id, "done", "--vault", "v-result:1@1"]
        ),
        format!("{two_id}: resolved as done\n")
    );
    let done = stored(&rig, &two["task_id"]);
    assert_eq!(
        (
            done["state"].as_str(),
            done["result"]["text"].as_str(),
            done["resolved"]["by"].as_str()
        ),
        (Some("completed"), Some(text), Some("local")),
        "{done}"
    );
    assert_eq!(owner(&rig, &["task", "list", "--unknown"]), "");
    // The same resolution again: the recorded status.
    assert_eq!(
        owner(&rig, &["task", "resolve", one_id, "failed"]),
        format!("{one_id}: resolved as failed\n")
    );
}

/// Review M1 and M3 (ruling T25a). Without a runtime, the task commands say
/// how to start one. A `done` whose client goes away while its snapshot is
/// being published resolves nothing (the owner runs it again), and
/// runtime.log says so, since its memory may already be on the relay. The
/// same command run again resolves the task.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES, ATEM_TEST_STATE_DUMP and ATEM_TEST_CONTEXT_DIR hooks"
)]
fn a_done_whose_client_goes_away_resolves_nothing_and_says_so() {
    use sha2::{Digest, Sha256};
    let mut rig = Rig::prepared(4 * HOUR, false);
    support::astation::write_encryption_mode(&rig.sandbox.config(), "on");
    let (out, err, ok) = rig.sandbox.atem(&["task", "list", "--unknown"]);
    assert!(!ok, "{out}");
    assert!(
        err.contains(
            "no Atem runtime is running; delegated tasks are listed and resolved through it (`atem runtime start`)"
        ),
        "{err}"
    );
    rig.with_station();
    rig.context = true;
    rig.start();
    let mut r = Router::new(&rig.astation);
    rig.station_online(false);
    let mut svc = Dev::new(&mut r, IDS, &rig.log, SVC, true);
    let launch = svc.session(&mut r);
    let mut phone = Dev::new(&mut r, IDS, &rig.log, PHONE, false);
    let t = task(IDS, &launch, "GOES_AWAY", HOUR);
    enqueue(&mut phone, &mut r, &t);
    in_turn(&rig, &t["task_id"], "GOES_AWAY");
    private(&rig.fake.join("exit"), "");
    wait_stored(&rig, &t["task_id"], "outcome_unknown", "agent exited");
    let tid = t["task_id"].as_str().unwrap();
    // The snapshot, held while it is published.
    let context = rig.sandbox.dir.path().join("context");
    let name = format!("{:x}", Sha256::digest(b"v-result:1@1"));
    let text = "Checked by the owner.";
    let digest = format!("{:x}", Sha256::digest(text.as_bytes()));
    private(
        &context.join(format!("{name}.json")),
        &json!({"kind":"vault","id":"v-result:1","version":1,"digest":digest,"text":text})
            .to_string(),
    );
    private(&context.join(format!("{name}.hold")), "");
    let mut cli = Command::new(env!("CARGO_BIN_EXE_atem"))
        .args(["task", "resolve", tid, "done", "--vault", "v-result:1@1"])
        .env_clear()
        .envs(rig.sandbox.env())
        .current_dir(&rig.sandbox.home)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    // The runtime takes the request and starts the publication, which the
    // hold parks (`.held` says so); the owner gives up (Ctrl-C) before it
    // is read back.
    within("the publication parked", || {
        context.join(format!("{name}.held")).exists()
    });
    cli.kill().unwrap();
    cli.wait().unwrap();
    std::fs::remove_file(context.join(format!("{name}.hold"))).unwrap();
    let log = rig.sandbox.dir.path().join("runtime.log");
    let line = format!(
        "atem runtime: task {tid}: `atem task resolve … done` ended before its snapshot was read back; nothing was resolved (a memory may already be on the relay)"
    );
    within("the discarded snapshot's line", || {
        std::fs::read_to_string(&log)
            .unwrap_or_default()
            .contains(&line)
    });
    let status = stored(&rig, &t["task_id"]);
    assert_eq!(
        (status["state"].as_str(), status.get("resolved")),
        (Some("outcome_unknown"), None),
        "{status}"
    );
    // Run again: resolved.
    assert_eq!(
        owner(
            &rig,
            &["task", "resolve", tid, "done", "--vault", "v-result:1@1"]
        ),
        format!("{tid}: resolved as done\n")
    );
    assert_eq!(stored(&rig, &t["task_id"])["resolved"]["by"], "local");
}
