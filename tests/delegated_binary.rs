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
    Dev, HostIds, HostRig, WAIT, attempts, complete_turn, enqueue, enqueue_data, escs, host_db,
    hosting_toml, in_turn, input, intents, never_ran, private, record, refused_hello, replace,
    stored, task, task_until, uuid, wait_stored,
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
/// What a held sender's task waits with (§11.6 "Details").
const PAUSED: &str = "paused";
const REVOKED: &str = "sender revoked";
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
    /// With the hook, `host.alerts` too.
    alerts: bool,
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
            alerts: false,
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
            let features = if self.alerts {
                "host.delegated,host.alerts"
            } else {
                "host.delegated"
            };
            command.env("ATEM_TEST_HOST_FEATURES", features);
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
    rig.with_station();
    rig.start();
    let mut r = Router::new(&rig.astation);
    // Services wait for the host's first complete read of its Station's
    // feed (ruling T35d, B): an empty one, read.
    rig.station_online(false);
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
    // The state dump: where the host's channels show.
    rig.dump = true;
    rig.start();
    let mut r = Router::new(&rig.astation);
    // No Station: services wait for the host's first read of its feed
    // (ruling T35d, B). The phone, its channel caught up (I.5.8), launches
    // the session and keeps it busy.
    let mut phone = Dev::new(&mut r, IDS, &rig.log, PHONE, false);
    let launch = phone.session(&mut r);
    let busy = task(IDS, &launch, "GATE_BUSY", HOUR);
    enqueue(&mut phone, &mut r, &busy);
    in_turn(&rig, &busy["task_id"], "GATE_BUSY");
    let gated = task(IDS, &launch, "GATE_PHONE", HOUR);
    enqueue(&mut phone, &mut r, &gated);
    assert!(delegated(&rig, &gated["task_id"]));
    // The phone goes: its gate is the host's own Station's (none) once the
    // host has dropped its channel. A close reaches the host at one of its
    // passes: until then the phone's caught-up channel would pass its gate
    // (I.5.8, "Native senders"; C1b flake, its siblings).
    let open = dumped(&rig)["channels"].as_u64().unwrap();
    phone.close(&mut r);
    within("the phone's channel closed", || {
        dumped(&rig)["channels"].as_u64() == Some(open - 1)
    });
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
    // The phone's list is a head ahead of the host's. (It launches the
    // session: with no Station, services wait for the host's first read of
    // its feed, ruling T35d, B.)
    rig.log.add_native("dev-tablet", &["view"]);
    let mut phone = Dev::new_via(&mut r, "direct", IDS, &rig.log, PHONE, false);
    let launch = phone.session(&mut r);
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

/// Task `tid`'s attempts as stored: (id, end, counted), in order.
fn attempt_rows(rig: &Rig, tid: &Value) -> Vec<(String, Option<String>, bool)> {
    let db = host_db(rig);
    let mut q = db
        .prepare(r#"SELECT attempt_id,"end",counted FROM attempts WHERE task_id=?1 ORDER BY n"#)
        .unwrap();
    q.query_map([tid.as_str().unwrap()], |r| {
        Ok((r.get(0)?, r.get(1)?, r.get(2)?))
    })
    .unwrap()
    .map(Result::unwrap)
    .collect()
}

/// `principal`'s stored control part (`control_principals`).
fn part(rig: &Rig, principal: &str) -> Option<String> {
    host_db(rig)
        .query_row(
            "SELECT part FROM control_principals WHERE principal=?1",
            [principal],
            |r| r.get(0),
        )
        .ok()
}

/// The host's own Station's feed cursor as stored (`control_feeds`).
fn stored_cursor(rig: &Rig) -> Option<u64> {
    host_db(rig)
        .query_row(
            "SELECT cursor FROM control_feeds WHERE origin=?1",
            [STATION],
            |r| r.get::<_, i64>(0),
        )
        .ok()
        .map(|c| c as u64)
}

/// Whether the host's book holds a result for `record_id` (`control_acks`).
fn ack_owed(rig: &Rig, record_id: &str) -> bool {
    host_db(rig)
        .query_row(
            "SELECT count(*) FROM control_acks WHERE key=?1",
            [record_id],
            |r| r.get::<_, i64>(0),
        )
        .is_ok_and(|n| n > 0)
}

/// Task `tid` has an unresolved alert (`alerts`, its owner's).
fn alerted(rig: &Rig, tid: &Value) -> bool {
    host_db(rig)
        .query_row(
            "SELECT count(*) FROM alerts WHERE task_id=?1 AND ended_ms IS NULL",
            [tid.as_str().unwrap()],
            |r| r.get::<_, i64>(0),
        )
        .is_ok_and(|n| n == 1)
}

/// VII.A test 7 (design I.6.2 to I.6.4, I.5.5; session-v1 R9.14 item 6;
/// Task 35 and 36 reviews, notes for Task 37): the runtime is killed
/// (`SIGKILL`) at each crash point, and after each restart nothing runs
/// twice, nothing revoked runs, and every `outcome_unknown` stays
/// unresolved:
/// 1. after an attempt's commit, before its submit
///    (`crash_after_attempt_commit`): the attempt is never admitted, and
///    the task runs once, on a new attempt;
/// 2. after the session `accepted` the attempt (the broker's
///    `hold_dispatch` keeps it from starting): withdrawn at recovery, then
///    the task runs once, on a new attempt;
/// 3. after `executing`: right after its record is durable, before the
///    prompt is dispatched (`crash_after_executing`): the turn was never
///    written, and the task can't be shown to have run or not: it is
///    `outcome_unknown` (`outcome could not be established`), alerted,
///    never written, never dispatched again; and with the turn running
///    (killed from outside): the turn goes on, adopted, and ends once;
/// 4. between storing a record and acknowledging it
///    (`crash_after_page_commit`): a hold committed while the service's
///    attempt waits `accepted`, its withdrawal not yet made: the restart
///    withdraws it at recovery, uncounted (the hold's mark), the task
///    waits `paused`, and the hold's result goes;
/// 5. between handing a result to the link and writing its sent mark
///    (`crash_after_ack_handoff`, held until the Station read it): the
///    release's result goes again after the restart, and the ledger counts
///    nothing twice; a result that goes once goes once more after a later
///    restart (its connection's end unknown);
/// 6. during a record's application (`crash_during_record_application`): a
///    revoke with `interrupt_running` while the service's turn runs and
///    another of its tasks waits: nothing of it stored (cursor, part,
///    tasks, intents, results); after the restart it applies once: the
///    waiting task cancelled, never run, the turn interrupted once.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES, ATEM_TEST_PTY_FAULTS and ATEM_TEST_STATE_DUMP hooks"
)]
fn sigkill_at_each_crash_point() {
    let mut rig = Rig::prepared(4 * HOUR, false);
    rig.with_station();
    rig.faults = true;
    rig.start();
    let mut r = Router::new(&rig.astation);
    rig.station_online(true);
    let mut svc = Dev::new(&mut r, IDS, &rig.log, SVC, true);
    let launch = svc.session(&mut r);
    let other = svc.session(&mut r);
    let mut phone = Dev::new(&mut r, IDS, &rig.log, PHONE, false);
    let crash = |rig: &Rig, name: &str| private(&rig.faults().join(name), "");
    // What every restart keeps: each prompt written at most once, the
    // revoked service's waiting task never, the unknown outcome unresolved.
    let once = |rig: &Rig, prompts: &[&str]| {
        let text = input(rig);
        for prompt in prompts {
            assert!(text.matches(prompt).count() <= 1, "{prompt} ran twice");
        }
    };
    let principal = format!("service:{SVC}");

    // 1. After an attempt's commit, before its submit.
    crash(&rig, "crash_after_attempt_commit");
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

    // 2. After the session `accepted` the attempt.
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
    let mut r = Router::new(&rig.astation);
    in_turn(&rig, &second["task_id"], "KILLED_AFTER_ACCEPTED");
    complete_turn(&rig, &second["task_id"]);
    once(&rig, &["KILLED_AT_COMMIT", "KILLED_AFTER_ACCEPTED"]);
    assert_eq!(input(&rig).matches("KILLED_AFTER_ACCEPTED").count(), 1);
    let all = attempts(&rig, &second["task_id"]);
    assert_eq!(all.len(), 2, "{all:?}");
    assert_eq!(all[0], (accepted, Some("withdrawn".into())));
    assert_eq!(all[1].1.as_deref(), Some("started"));

    // 3. After `executing`, before the dispatch (on the other session: an
    // unknown outcome holds its session until its deadline).
    crash(&rig, "crash_after_executing");
    let mut phone = Dev::new(&mut r, IDS, &rig.log, PHONE, false);
    let unknown = task(IDS, &other, "KILLED_AFTER_EXECUTING", HOUR);
    phone.send(&mut r, enqueue_data(IDS, &unknown));
    drop((r, phone));
    rig.died();
    let executing = attempts(&rig, &unknown["task_id"]);
    assert_eq!(executing.len(), 1, "{executing:?}");
    assert!(!input(&rig).contains("KILLED_AFTER_EXECUTING"));
    rig.start();
    let mut r = Router::new(&rig.astation);
    wait_stored(
        &rig,
        &unknown["task_id"],
        "outcome_unknown",
        "outcome could not be established",
    );
    assert!(alerted(&rig, &unknown["task_id"]));
    work_passes(&rig, 3);
    assert_eq!(attempts(&rig, &unknown["task_id"]).len(), 1);
    assert!(!input(&rig).contains("KILLED_AFTER_EXECUTING"));
    // Its turn running, killed from outside: adopted, it ends once.
    let mut phone = Dev::new(&mut r, IDS, &rig.log, PHONE, false);
    let running = task(IDS, &launch, "KILLED_IN_ITS_TURN", HOUR);
    enqueue(&mut phone, &mut r, &running);
    in_turn(&rig, &running["task_id"], "KILLED_IN_ITS_TURN");
    drop((r, phone));
    rig.kill();
    rig.start();
    let mut r = Router::new(&rig.astation);
    complete_turn(&rig, &running["task_id"]);
    assert_eq!(input(&rig).matches("KILLED_IN_ITS_TURN").count(), 1);
    assert_eq!(
        ends(&rig, &running["task_id"]),
        [Some("started".to_string())]
    );

    // 4. Between storing a record and acknowledging it: a hold, its
    // withdrawal of the service's accepted attempt not yet made.
    private(&rig.faults().join("hold_dispatch"), "");
    let mut svc = Dev::new(&mut r, IDS, &rig.log, SVC, true);
    let held = task(IDS, &launch, "KILLED_BEFORE_THE_WITHDRAWAL", HOUR);
    enqueue(&mut svc, &mut r, &held);
    within("the service's attempt accepted", || {
        stored(&rig, &held["task_id"])["state"] == "submitted"
            && ends(&rig, &held["task_id"]) == [None]
    });
    let withdrawn = attempts(&rig, &held["task_id"])[0].0.clone();
    crash(&rig, "crash_after_page_commit");
    let hold = {
        let mut station = rig.station();
        let record = station.record_for(SVC, ControlAction::Hold);
        let at = station.append(record);
        drop(station);
        record_id_at(&rig, at)
    };
    drop((r, svc));
    rig.died();
    assert!(ack_owed(&rig, &hold), "the hold's result stored");
    assert!(results_of(&rig, &hold).is_empty(), "and never sent");
    assert_eq!(
        attempt_rows(&rig, &held["task_id"]),
        [(withdrawn.clone(), None, false)],
        "live, its withdrawal marked uncounted"
    );
    std::fs::remove_file(rig.faults().join("hold_dispatch")).unwrap();
    rig.start();
    let r = Router::new(&rig.astation);
    wait_stored(&rig, &held["task_id"], "blocked", PAUSED);
    assert_eq!(
        attempt_rows(&rig, &held["task_id"]),
        [(withdrawn.clone(), Some("withdrawn".into()), false)]
    );
    assert_eq!(receipt(&rig, &withdrawn)["detail"], "withdrawn at recovery");
    within("the hold's result sent", || {
        results_of(&rig, &hold) == [[("hold".to_string(), "applied".to_string())]]
    });
    assert!(!input(&rig).contains("KILLED_BEFORE_THE_WITHDRAWAL"));

    // 5. Between handing a result to the link and its sent mark: the
    // release's, the Station reading it before the kill.
    crash(&rig, "crash_after_ack_handoff");
    private(&rig.faults().join("hold_crash"), "");
    let release = {
        let mut station = rig.station();
        let record = station.record_for(SVC, ControlAction::Release);
        let at = station.append(record);
        drop(station);
        record_id_at(&rig, at)
    };
    within("the release's result read", || {
        !results_of(&rig, &release).is_empty()
    });
    std::fs::remove_file(rig.faults().join("hold_crash")).unwrap();
    drop(r);
    rig.died();
    let done = counted(&rig);
    rig.start();
    let r = Router::new(&rig.astation);
    within("the release's result again", || {
        results_of(&rig, &release).len() == 2
    });
    assert_eq!(counted(&rig), done, "nothing counted twice");
    // It released the task: it runs, once, on a second attempt.
    in_turn(&rig, &held["task_id"], "KILLED_BEFORE_THE_WITHDRAWAL");
    complete_turn(&rig, &held["task_id"]);
    let rows = attempt_rows(&rig, &held["task_id"]);
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert_eq!(rows[1].1.as_deref(), Some("started"));
    // Sent, marked, then a restart: the release's (sent once) goes once
    // more, since the restart can't know its connection wasn't refused.
    within("the release's result marked sent", || {
        host_db(&rig)
            .query_row(
                "SELECT sent_gen IS NOT NULL FROM control_acks WHERE key=?1",
                [release.as_str()],
                |r| r.get::<_, bool>(0),
            )
            .unwrap_or(false)
    });
    drop(r);
    rig.kill();
    rig.start();
    let mut r = Router::new(&rig.astation);
    within("the release's result once more", || {
        results_of(&rig, &release).len() == 3
    });
    assert_eq!(counted(&rig), done);

    // 6. During a record's application: a revoke with its interrupt.
    let mut svc = Dev::new(&mut r, IDS, &rig.log, SVC, true);
    let turn = task(IDS, &launch, "REVOKED_MID_APPLICATION_TURN", HOUR);
    let waits = task(IDS, &launch, "REVOKED_MID_APPLICATION_WAITS", HOUR);
    for t in [&turn, &waits] {
        enqueue(&mut svc, &mut r, t);
    }
    in_turn(&rig, &turn["task_id"], "REVOKED_MID_APPLICATION_TURN");
    wait_stored(&rig, &waits["task_id"], "blocked", BEHIND);
    let covered = part(&rig, &principal).unwrap();
    let cursor = stored_cursor(&rig);
    crash(&rig, "crash_during_record_application");
    let revoke = {
        let mut station = rig.station();
        let record = station.record_for(
            SVC,
            ControlAction::Revoke {
                interrupt_running: true,
            },
        );
        let at = station.append(record);
        drop(station);
        record_id_at(&rig, at)
    };
    drop((r, svc));
    rig.died();
    assert_eq!(stored_cursor(&rig), cursor, "no partial cursor");
    assert_eq!(part(&rig, &principal), Some(covered.clone()));
    assert_eq!(stored(&rig, &waits["task_id"])["state"], "blocked");
    assert!(intents(&rig, &turn["task_id"]).is_empty());
    assert!(!ack_owed(&rig, &revoke));
    assert_eq!(escs(&rig), 0);
    rig.start();
    let mut r = Router::new(&rig.astation);
    wait_stored(&rig, &waits["task_id"], "cancelled", REVOKED);
    within("the revoke's interrupt", || {
        intents(&rig, &turn["task_id"])
            .first()
            .is_some_and(|i| i.delivered_turn.is_some())
    });
    within("the Esc", || escs(&rig) == 1);
    std::fs::write(rig.fake.join("interrupt"), "").unwrap();
    wait_stored(
        &rig,
        &turn["task_id"],
        "awaiting_result",
        "turn interrupted",
    );
    assert_ne!(part(&rig, &principal), Some(covered));
    assert_eq!(
        refused_hello(&mut r, IDS, &rig.log, SVC, true),
        ("unauthorized".to_string(), Some("revoked".to_string()))
    );
    within("the revoke counted", || {
        counted(&rig)
            .iter()
            .filter(|(p, _, id)| *p == principal && *id == revoke)
            .count()
            == 2
    });

    // Every restart: nothing ran twice, nothing revoked ran, the unknown
    // outcome unresolved.
    once(
        &rig,
        &[
            "KILLED_AT_COMMIT",
            "KILLED_AFTER_ACCEPTED",
            "KILLED_IN_ITS_TURN",
            "KILLED_BEFORE_THE_WITHDRAWAL",
            "REVOKED_MID_APPLICATION_TURN",
        ],
    );
    never_ran(&rig, &waits["task_id"], "REVOKED_MID_APPLICATION_WAITS");
    assert!(!input(&rig).contains("KILLED_AFTER_EXECUTING"));
    let status = stored(&rig, &unknown["task_id"]);
    assert_eq!(status["state"], "outcome_unknown", "{status}");
    assert!(status.get("resolved").is_none(), "{status}");
    assert!(alerted(&rig, &unknown["task_id"]));
    assert_eq!(escs(&rig), 1);
    assert!(rig.station().ack_refusals().is_empty());
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
/// (`control_sync`) and acknowledgments (`control_ack`, Task 36) on the way
/// answered too.
fn next_fetch(station: &mut FakeStation, link: u64) -> Result<ToStation, RelayError> {
    loop {
        let call = station.next_call(link);
        if !matches!(
            call,
            Ok(ToStation::ControlSync(_) | ToStation::ControlAck(_))
        ) {
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
    // The phone launches the session: services wait for the host's first
    // complete read of its feed (ruling T35d, B).
    let mut phone = Dev::new(&mut r, IDS, &rig.log, PHONE, false);
    let launch = phone.session(&mut r);
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
    // The Mac launches the session (services wait for the host's first
    // complete read of its feed, ruling T35d, B), and its channel goes: a
    // native channel left open would pass its gate (I.5.8).
    let mut launcher = Dev::new(&mut r, IDS, &rig.log, MAC, false);
    let launch = launcher.session(&mut r);
    launcher.close(&mut r);
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
    // caught-up channel of their own. A close reaches the host at one of its
    // passes, maybe after the one that sees the clock below: wait until it
    // has dropped both channels, or a native whose close is still on its
    // way passes its gate by that channel (I.5.8, "Native senders") the
    // moment the deferral ends.
    let open = dumped(&rig)["channels"].as_u64().unwrap();
    phone.close(&mut r);
    mac.close(&mut r);
    within("the senders' channels closed", || {
        dumped(&rig)["channels"].as_u64() == Some(open - 2)
    });

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
    // The dump is written at the end of a pass; the cancellation is in the
    // store mid-pass.
    two_passes(&rig);
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

/// The host interrupt writes the runtime handed to a worker so far (the
/// state dump's count).
fn interrupt_writes(rig: &Rig) -> u64 {
    dumped(rig)["host_work"]["interrupt_writes"]
        .as_u64()
        .unwrap_or(0)
}

/// Waits for `n` host-work scheduling passes begun after now (every 100
/// ms; a broker tick isn't one): the count moves past `now + n`, so the
/// pass under way at `now` doesn't count.
fn work_passes(rig: &Rig, n: u64) {
    let passes = |rig: &Rig| dumped(rig)["host_work"]["passes"].as_u64().unwrap_or(0);
    let now = passes(rig);
    within("host-work's scheduling passes", || passes(rig) > now + n);
}

/// VII.A test 12 (design I.4.4, I.5.7; session-v1 R9.14 item 5): a
/// delegated turn still running when the delegated clock reaches its task's
/// deadline is interrupted on the host's authority: an intent with reason
/// `deadline` is stored for its attempt, the Esc is written once (no blind
/// second one while the turn goes on), and the turn it reached recorded.
/// The turn ends interrupted (its receipt `completed`, `interrupted`), and
/// the task, after `awaiting_result` (`interrupted at deadline`), expires
/// as today (`expired awaiting a result`); the intent is done. The clock
/// moves only on the debug host clock (its boot-time counter), never by
/// waiting.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES, ATEM_TEST_HOST_CLOCK and ATEM_TEST_STATE_DUMP hooks"
)]
fn a_turn_running_at_its_deadline_is_interrupted_and_expires() {
    let mut rig = Rig::prepared(4 * HOUR, false);
    rig.with_station();
    rig.with_clock();
    rig.start();
    let mut r = Router::new(&rig.astation);
    rig.station_online(false);
    let mut svc = Dev::new(&mut r, IDS, &rig.log, SVC, true);
    let launch = svc.session(&mut r);
    let mut phone = Dev::new(&mut r, IDS, &rig.log, PHONE, false);
    let t = task_until(IDS, &launch, "DEADLINE_TURN", rig.clock().wall() + 10 * MIN);
    let tid = &t["task_id"];
    enqueue(&mut phone, &mut r, &t);
    in_turn(&rig, tid, "DEADLINE_TURN");
    let attempt = stored(&rig, tid)["receipt_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(intents(&rig, tid).is_empty(), "nothing before the deadline");
    assert_eq!(escs(&rig), 0);
    // The boot-time counter passes the deadline (the wall clock where it
    // is): `D` reaches it.
    rig.clock().set(0, 10 * MIN);
    within("the deadline's interrupt", || {
        intents(&rig, tid)
            .first()
            .is_some_and(|i| i.delivered_turn.is_some())
    });
    let stored_intents = intents(&rig, tid);
    let [intent] = stored_intents.as_slice() else {
        panic!("one intent: {stored_intents:?}");
    };
    assert_eq!(
        (
            intent.attempt_id.as_str(),
            intent.reason.as_str(),
            intent.done
        ),
        (attempt.as_str(), "deadline", false)
    );
    // The fake agent appends what it read on its own poll.
    within("the Esc", || escs(&rig) == 1);
    assert_eq!(escs(&rig), 1);
    assert_eq!(interrupt_writes(&rig), 1);
    // The turn goes on (the fake agent ignores the Esc): only the lease
    // revocation repeats, nothing is written again in three more
    // scheduling passes (the writes counted as the runtime makes them).
    work_passes(&rig, 3);
    assert_eq!(interrupt_writes(&rig), 1, "once per turn");
    assert_eq!(escs(&rig), 1, "once per turn");
    assert_eq!(stored(&rig, tid)["state"], "submitted");
    // The agent's turn ends interrupted, as after an Esc.
    std::fs::write(rig.fake.join("interrupt"), "").unwrap();
    wait_stored(&rig, tid, "expired", "expired awaiting a result");
    let rc = receipt(&rig, &attempt);
    assert_eq!(
        (&rc["state"], &rc["detail"]),
        (&json!("completed"), &json!("interrupted")),
        "{rc}"
    );
    let stored_intents = intents(&rig, tid);
    let [intent] = stored_intents.as_slice() else {
        panic!("one intent: {stored_intents:?}");
    };
    assert!(intent.done, "{intent:?}");
    assert_eq!(escs(&rig), 1);
    assert_eq!(input(&rig).matches("DEADLINE_TURN").count(), 1);
    assert_eq!(ends(&rig, tid), [Some("started".to_string())]);
    let status = work(&mut phone, &mut r, tid);
    assert_eq!(status["result"]["work"]["state"], "expired", "{status}");
}

/// VII.A test 12 while hosting is paused (ruling T26a; design I.4.4): the
/// turn runs when `runtime.toml` stops loading (agent hosting off until it
/// is fixed), and the delegated clock then reaches its task's deadline.
/// The deadline's interrupt is still delivered, once, while paused; the
/// turn ends interrupted, and the task's record waits untouched until the
/// file loads again: then it expires (`expired awaiting a result`).
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES, ATEM_TEST_HOST_CLOCK and ATEM_TEST_STATE_DUMP hooks"
)]
fn a_paused_host_still_interrupts_a_turn_at_its_deadline() {
    let mut rig = Rig::prepared(4 * HOUR, false);
    rig.with_station();
    rig.with_clock();
    rig.start();
    let mut r = Router::new(&rig.astation);
    rig.station_online(false);
    let mut svc = Dev::new(&mut r, IDS, &rig.log, SVC, true);
    let launch = svc.session(&mut r);
    let mut phone = Dev::new(&mut r, IDS, &rig.log, PHONE, false);
    let t = task_until(IDS, &launch, "PAUSED_TURN", rig.clock().wall() + 10 * MIN);
    let tid = &t["task_id"];
    enqueue(&mut phone, &mut r, &t);
    in_turn(&rig, tid, "PAUSED_TURN");
    let attempt = stored(&rig, tid)["receipt_id"]
        .as_str()
        .unwrap()
        .to_string();
    // `runtime.toml` stops loading: hosting is paused.
    let file = rig.sandbox.config().join("runtime.toml");
    let valid = std::fs::read_to_string(&file).unwrap();
    replace(&file, "this is not a runtime.toml");
    let log = rig.sandbox.dir.path().join("runtime.log");
    within("hosting paused", || {
        std::fs::read_to_string(&log)
            .unwrap_or_default()
            .contains("agent hosting is off until it is fixed")
    });
    rig.clock().set(0, 10 * MIN);
    within("the deadline's interrupt while paused", || {
        intents(&rig, tid)
            .first()
            .is_some_and(|i| i.delivered_turn.is_some())
    });
    work_passes(&rig, 3);
    assert_eq!(interrupt_writes(&rig), 1, "once per turn");
    within("the Esc while paused", || escs(&rig) == 1);
    assert_eq!(escs(&rig), 1);
    assert_eq!(intents(&rig, tid)[0].attempt_id, attempt);
    // The turn ends interrupted, still paused.
    std::fs::write(rig.fake.join("interrupt"), "").unwrap();
    within("the turn's interrupted end", || {
        receipt(&rig, &attempt)["state"] == "completed"
    });
    assert_eq!(receipt(&rig, &attempt)["detail"], "interrupted");
    within("the intent done while paused", || {
        intents(&rig, tid)[0].done
    });
    assert_eq!(
        stored(&rig, tid)["state"],
        "submitted",
        "untouched while paused"
    );
    // The file loads again.
    replace(&file, &valid);
    wait_stored(&rig, tid, "expired", "expired awaiting a result");
    assert_eq!(interrupt_writes(&rig), 1);
    assert_eq!(escs(&rig), 1);
    assert_eq!(input(&rig).matches("PAUSED_TURN").count(), 1);
}

/// `dev` asks `work_interrupt` of task `tid` (feature `host.delegated`).
fn interrupt(dev: &mut Dev, r: &mut Router, tid: &Value) -> Value {
    dev.request(
        r,
        json!({"op":"work_interrupt","host":host(),"task_id":tid}),
    )
}

/// Design I.4.5, host-work-v1 §11.2, over a real channel: the phone (its
/// task's sender, a native member holding `control`) sends `work_interrupt`
/// while the task's turn runs. The client core takes the `work` result,
/// the task's status before the interrupt (`submitted`, in the agent's
/// turn); one Esc reaches the agent and no intent is stored (a one-shot
/// request). The service, neither the sender nor the owner, is `forbidden`
/// (its channel let the request through: it holds `notify`). The turn
/// ends interrupted, the task awaits its result (`turn interrupted`), and
/// the same request then answers that status with `not running`, which
/// isn't stored.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES and ATEM_TEST_STATE_DUMP hooks"
)]
fn work_interrupt_over_the_senders_channel() {
    let mut rig = Rig::prepared(4 * HOUR, false);
    rig.with_station();
    rig.start();
    let mut r = Router::new(&rig.astation);
    rig.station_online(false);
    let mut svc = Dev::new(&mut r, IDS, &rig.log, SVC, true);
    let launch = svc.session(&mut r);
    let mut phone = Dev::new(&mut r, IDS, &rig.log, PHONE, false);
    let t = task(IDS, &launch, "CHANNEL_INTERRUPT", HOUR);
    let tid = &t["task_id"];
    enqueue(&mut phone, &mut r, &t);
    in_turn(&rig, tid, "CHANNEL_INTERRUPT");
    let refused = interrupt(&mut svc, &mut r, tid);
    assert_eq!(refused["code"], "forbidden", "{refused}");
    let reply = interrupt(&mut phone, &mut r, tid);
    let work = &reply["result"]["work"];
    assert_eq!(
        (&work["state"], &work["detail"], &work["receipt_id"]),
        (
            &json!("submitted"),
            &json!("in the agent's turn"),
            &stored(&rig, tid)["receipt_id"]
        ),
        "{reply}"
    );
    within("the Esc", || escs(&rig) == 1);
    assert!(intents(&rig, tid).is_empty(), "no intent");
    std::fs::write(rig.fake.join("interrupt"), "").unwrap();
    wait_stored(&rig, tid, "awaiting_result", "turn interrupted");
    let again = interrupt(&mut phone, &mut r, tid);
    let work = &again["result"]["work"];
    assert_eq!(
        (&work["state"], &work["detail"]),
        (&json!("awaiting_result"), &json!("not running")),
        "{again}"
    );
    assert_eq!(stored(&rig, tid)["detail"], "turn interrupted");
    assert_eq!(escs(&rig), 1);
    assert_eq!(input(&rig).matches("CHANNEL_INTERRUPT").count(), 1);
}

/// Ruling T27a (2): `work_interrupt` is a stop, so it is served while
/// hosting is paused (`runtime.toml` stops loading), as the deadline's
/// interrupt is (T26a). The phone's channel, admitted before the pause,
/// sends it: the result is the task's status, and one Esc reaches the
/// agent. Its other host-work requests stay `busy` meanwhile, and a second
/// `work_interrupt` of the same turn writes nothing (one Esc per attempt
/// and turn). The turn ends interrupted; the task's record waits for the
/// file to load again, then reads `turn interrupted`.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES and ATEM_TEST_STATE_DUMP hooks"
)]
fn work_interrupt_is_served_while_hosting_is_paused() {
    let mut rig = Rig::prepared(4 * HOUR, false);
    rig.with_station();
    rig.start();
    let mut r = Router::new(&rig.astation);
    rig.station_online(false);
    let mut svc = Dev::new(&mut r, IDS, &rig.log, SVC, true);
    let launch = svc.session(&mut r);
    let mut phone = Dev::new(&mut r, IDS, &rig.log, PHONE, false);
    let t = task(IDS, &launch, "PAUSED_INTERRUPT", HOUR);
    let tid = &t["task_id"];
    enqueue(&mut phone, &mut r, &t);
    in_turn(&rig, tid, "PAUSED_INTERRUPT");
    let attempt = stored(&rig, tid)["receipt_id"]
        .as_str()
        .unwrap()
        .to_string();
    // `runtime.toml` stops loading: hosting is paused.
    let file = rig.sandbox.config().join("runtime.toml");
    let valid = std::fs::read_to_string(&file).unwrap();
    replace(&file, "this is not a runtime.toml");
    let log = rig.sandbox.dir.path().join("runtime.log");
    within("hosting paused", || {
        std::fs::read_to_string(&log)
            .unwrap_or_default()
            .contains("agent hosting is off until it is fixed")
    });
    let query = work(&mut phone, &mut r, tid);
    assert_eq!(query["code"], "busy", "{query}");
    let reply = interrupt(&mut phone, &mut r, tid);
    let work_status = &reply["result"]["work"];
    assert_eq!(
        (&work_status["state"], &work_status["detail"]),
        (&json!("submitted"), &json!("in the agent's turn")),
        "{reply}"
    );
    within("the Esc while paused", || escs(&rig) == 1);
    assert_eq!(interrupt_writes(&rig), 1);
    // Reported and taken in, then asked again: nothing written.
    work_passes(&rig, 2);
    let again = interrupt(&mut phone, &mut r, tid);
    assert_eq!(again["result"]["work"]["state"], "submitted", "{again}");
    work_passes(&rig, 3);
    assert_eq!(interrupt_writes(&rig), 1, "one Esc per turn");
    assert_eq!(escs(&rig), 1);
    assert!(intents(&rig, tid).is_empty(), "no intent");
    // The turn ends interrupted, still paused; the record waits.
    std::fs::write(rig.fake.join("interrupt"), "").unwrap();
    within("the turn's interrupted end", || {
        receipt(&rig, &attempt)["state"] == "completed"
    });
    assert_eq!(receipt(&rig, &attempt)["detail"], "interrupted");
    assert_eq!(
        stored(&rig, tid)["state"],
        "submitted",
        "untouched while paused"
    );
    replace(&file, &valid);
    wait_stored(&rig, tid, "awaiting_result", "turn interrupted");
    assert_eq!(escs(&rig), 1);
}

/// A record of the fake Station's about [`SVC`] at its feed's next
/// position, with the Station online ([`Rig::station_online`]): announced
/// at once, and read by the host before this returns (its cursor there).
fn control(rig: &Rig, action: ControlAction) {
    let at = {
        let mut station = rig.station();
        let record = station.record_for(SVC, action);
        station.append(record)
    };
    within("the record read", || {
        dumped(rig)["station"]["feed"]["synced"]["cursor"].as_u64() >= Some(at)
    });
}

/// `dev`'s `host_launch` of profile `backend`, expiring in ten minutes
/// (room for a slow runner): its request id and session id (the reply
/// says `starting`).
fn launch_backend(dev: &mut Dev, r: &mut Router) -> (String, String) {
    let rid = uuid();
    let reply = dev.request(
        r,
        json!({"op":"host_launch","host":host(),"request_id":rid,
            "profile_id":"backend","profile_revision":1,
            "expires_at":r9log::host_now().wall_ms + 10 * MIN}),
    );
    let launch = &reply["result"]["launch"];
    assert_eq!(launch["state"], "starting", "{reply}");
    (rid, launch["session_id"].as_str().unwrap().to_string())
}

/// Launch `rid`'s state, as its sender's `host_launch_query` reads it.
fn launch_state(dev: &mut Dev, r: &mut Router, rid: &str) -> Value {
    let reply = dev.request(
        r,
        json!({"op":"host_launch_query","host":host(),"request_id":rid}),
    );
    reply["result"]["launch"]["state"].clone()
}

/// No worker was ever spawned for session `sid` (no spec, no record).
fn never_spawned(rig: &Rig, sid: &str) -> bool {
    let workers = rig.sandbox.config().join("runtime/workers");
    !workers.join(format!("{sid}.spec.json")).exists()
        && !workers.join(format!("{sid}.json")).exists()
}

/// VII.A test 19, its launch half (design I.4.3, "Launches"; host-work-v1
/// §11.6): in the real runtime, a covered service's `host_launch` while the
/// fake Station's feed holds it waits at the spawn boundary through
/// host-work's passes: `starting`, no worker spawned, its reason in
/// `runtime.log`. The feed's release lets it start. Held again, a launch
/// waits; the feed's revoke then ends it `failed` (`sender revoked`),
/// nothing spawned, never `outcome_unknown`, read from the store and
/// `runtime.log`: the revoke fenced the service's channel (design I.5.5
/// step 2), and a new `hello` of it is refused (`unauthorized`, `revoked`),
/// so no later request of it reaches the host (one that did would be
/// `forbidden`: the bridge's tests).
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES and ATEM_TEST_STATE_DUMP hooks"
)]
fn a_held_senders_launch_waits_and_a_revoked_ones_fails() {
    let mut rig = Rig::prepared(4 * HOUR, false);
    rig.with_station();
    rig.start();
    let log = rig.sandbox.dir.path().join("runtime.log");
    let logged = |text: &str| {
        std::fs::read_to_string(&log)
            .unwrap_or_default()
            .contains(text)
    };
    let mut r = Router::new(&rig.astation);
    rig.station_online(true);
    control(&rig, ControlAction::Hold);
    let mut svc = Dev::new(&mut r, IDS, &rig.log, SVC, true);
    let (held, sid) = launch_backend(&mut svc, &mut r);
    within("the wait logged", || {
        logged(&format!(
            "launch {held} waits at the spawn boundary: paused"
        ))
    });
    work_passes(&rig, 5);
    assert_eq!(launch_state(&mut svc, &mut r, &held), "starting");
    assert!(never_spawned(&rig, &sid), "nothing spawned while held");
    // Released: it starts.
    control(&rig, ControlAction::Release);
    within("the released launch started", || {
        launch_state(&mut svc, &mut r, &held) == "started"
    });
    // Held again, a launch waits at the spawn boundary; revoked: it fails
    // there, nothing spawned (its sender's channel is fenced by then: its
    // state is the store's and runtime.log's).
    control(&rig, ControlAction::Hold);
    let (waiting, sid) = launch_backend(&mut svc, &mut r);
    within("the second wait logged", || {
        logged(&format!(
            "launch {waiting} waits at the spawn boundary: paused"
        ))
    });
    control(
        &rig,
        ControlAction::Revoke {
            interrupt_running: false,
        },
    );
    let state = |rig: &Rig| {
        host_db(rig)
            .query_row(
                "SELECT record FROM launches WHERE id=?1",
                [waiting.as_str()],
                |row| row.get::<_, String>(0),
            )
            .map(|text| serde_json::from_str::<Value>(&text).unwrap()["status"]["state"].clone())
            .unwrap()
    };
    within("the waiting launch failed", || {
        let state = state(&rig);
        assert_ne!(state, "outcome_unknown");
        state == "failed"
    });
    assert!(never_spawned(&rig, &sid), "nothing spawned when revoked");
    assert!(logged(&format!(
        "launch {waiting} failed before its spawn: sender revoked"
    )));
    // At the request: the revoked service can't come back.
    assert_eq!(
        refused_hello(&mut r, IDS, &rig.log, SVC, true),
        ("unauthorized".to_string(), Some("revoked".to_string()))
    );
}

// ── VII.A against the fake Station (Task 37) ──

/// `record` stored at the fake Station's feed's next position, the
/// Station online ([`Rig::station_online`]): announced at once, and read by
/// the host before this returns (its cursor there). Its position.
fn control_record(rig: &Rig, record: atem_client::SignedObject) -> u64 {
    let at = rig.station().append(record);
    within("the record read", || {
        dumped(rig)["station"]["feed"]["synced"]["cursor"].as_u64() >= Some(at)
    });
    at
}

/// [`control`], the record kept (to serve it again).
fn control_kept(rig: &Rig, action: ControlAction) -> atem_client::SignedObject {
    let record = rig.station().record_for(SVC, action);
    control_record(rig, record.clone());
    record
}

/// The id of the record at `seq` of the fake Station's feed.
fn record_id_at(rig: &Rig, seq: u64) -> String {
    let station = rig.station();
    let records = station.records();
    let (_, record) = records
        .iter()
        .find(|(at, _)| *at == seq)
        .unwrap_or_else(|| panic!("no record at {seq}"));
    record.record_id().to_owned()
}

/// The results of `record_id` in the acks the fake Station read so far,
/// each as its (effect, result) codes.
fn results_of(rig: &Rig, record_id: &str) -> Vec<Vec<(String, String)>> {
    rig.station()
        .acks_sent()
        .iter()
        .flat_map(|ack| ack.results.iter())
        .filter_map(|r| match r {
            atem_client::control::AckResult::Record {
                record_id: id,
                effects,
            } if id == record_id => Some(
                effects
                    .iter()
                    .map(|e| (e.effect.code().to_string(), e.result.code().to_string()))
                    .collect(),
            ),
            _ => None,
        })
        .collect()
}

/// What the Station's reference ledger counted for the host: (principal,
/// effect, record id), in order.
fn counted(rig: &Rig) -> Vec<(String, String, String)> {
    rig.station().acks().to_json()["done"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| {
            assert_eq!(d["host"], HOST, "{d}");
            let text = |k: &str| d[k].as_str().unwrap().to_string();
            (text("principal"), text("effect"), text("record_id"))
        })
        .collect()
}

/// VII.A test 5 (design I.3.3 "Pause" and "Resume", I.4.3 "Holding tasks
/// don't hold the session", I.5.5 step 4; host-work-v1 §11.1 rule 1): the
/// Station holds the covered service while its task waits behind the
/// phone's turn: the task waits `paused`, and doesn't hold its session: the
/// phone's next task and a local agent's task, queued after it, run past
/// it. The release lets it run. The Station holds the service again (its
/// next task waits `paused`), then serves the earlier release again at a
/// later position: the same record, a `duplicate` the host ignores, so the
/// task stays paused until a new release. Each ran once.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES and ATEM_TEST_STATE_DUMP hooks"
)]
fn pause_holds_and_resume_releases() {
    let mut rig = Rig::prepared(4 * HOUR, true);
    rig.with_station();
    rig.start();
    let mut r = Router::new(&rig.astation);
    rig.station_online(true);
    let mut svc = Dev::new(&mut r, IDS, &rig.log, SVC, true);
    let launch = svc.session(&mut r);
    let mut phone = Dev::new(&mut r, IDS, &rig.log, PHONE, false);
    let busy = task(IDS, &launch, "PAUSE_PHONE_BUSY", HOUR);
    enqueue(&mut phone, &mut r, &busy);
    in_turn(&rig, &busy["task_id"], "PAUSE_PHONE_BUSY");
    let held = task(IDS, &launch, "PAUSE_HELD", HOUR);
    enqueue(&mut svc, &mut r, &held);
    wait_stored(&rig, &held["task_id"], "blocked", BEHIND);
    // The hold: the service's task waits paused.
    control(&rig, ControlAction::Hold);
    wait_stored(&rig, &held["task_id"], "blocked", PAUSED);
    // The phone's next task and a local agent's pass it.
    let after = task(IDS, &launch, "PAUSE_PHONE_AFTER", HOUR);
    enqueue(&mut phone, &mut r, &after);
    complete_turn(&rig, &busy["task_id"]);
    in_turn(&rig, &after["task_id"], "PAUSE_PHONE_AFTER");
    let other = local_session(&rig, "other");
    let sent = agent_run(
        &other,
        1,
        &["message", "send", "--to", "tag:peer", "PAUSE_LOCAL"],
    );
    assert_eq!(sent["code"], 0, "{sent}");
    complete_turn(&rig, &after["task_id"]);
    within("the local task's prompt", || {
        input(&rig).contains("PAUSE_LOCAL")
    });
    let local = local_tasks(&rig);
    assert_eq!(local.len(), 1, "{local:?}");
    let tid = local[0]["task"]["task_id"].clone();
    complete_turn(&rig, &tid);
    let done = agent_run(&other, 2, &["message", "complete", tid.as_str().unwrap()]);
    assert_eq!(done["code"], 0, "{done}");
    assert_eq!(stored(&rig, &held["task_id"])["detail"], PAUSED);
    never_ran(&rig, &held["task_id"], "PAUSE_HELD");
    // The release: it runs.
    let release = control_kept(&rig, ControlAction::Release);
    in_turn(&rig, &held["task_id"], "PAUSE_HELD");
    complete_turn(&rig, &held["task_id"]);
    // Held again; the earlier release served again is ignored.
    control(&rig, ControlAction::Hold);
    let again = task(IDS, &launch, "PAUSE_HELD_AGAIN", HOUR);
    enqueue(&mut svc, &mut r, &again);
    wait_stored(&rig, &again["task_id"], "blocked", PAUSED);
    let release_id = {
        let record = atem_client::control::ControlRecord::from_signed(release.clone()).unwrap();
        record.record_id().to_owned()
    };
    let replayed = control_record(&rig, release);
    assert_eq!(record_id_at(&rig, replayed), release_id, "the same record");
    work_passes(&rig, 3);
    assert_eq!(stored(&rig, &again["task_id"])["detail"], PAUSED);
    never_ran(&rig, &again["task_id"], "PAUSE_HELD_AGAIN");
    within("the replay's result", || {
        results_of(&rig, &release_id)
            .iter()
            .any(|r| r == &[("release".to_string(), "duplicate".to_string())])
    });
    // A new release: it runs.
    control(&rig, ControlAction::Release);
    in_turn(&rig, &again["task_id"], "PAUSE_HELD_AGAIN");
    complete_turn(&rig, &again["task_id"]);
    let text = input(&rig);
    for prompt in [
        "PAUSE_PHONE_BUSY",
        "PAUSE_PHONE_AFTER",
        "PAUSE_LOCAL",
        "PAUSE_HELD",
        "PAUSE_HELD_AGAIN",
    ] {
        let n = text.matches(prompt).count();
        // `PAUSE_HELD` is a prefix of `PAUSE_HELD_AGAIN`.
        let expected = if prompt == "PAUSE_HELD" { 2 } else { 1 };
        assert_eq!(n, expected, "{prompt}");
    }
    assert!(rig.station().ack_refusals().is_empty());
}

/// The Mac's prompt, accepted first on `launch`'s session, then `dev`'s
/// task `t`, whose attempt host-work's dispatch (made once the broker's
/// `hold_dispatch` is gone) queues behind it: the attempt waits `accepted`
/// behind the Mac's running turn (as in
/// `a_freeze_at_the_start_fails_the_attempt`). The attempt's id.
fn accepted_behind_the_macs_turn(
    rig: &Rig,
    r: &mut Router,
    mac: &mut Dev,
    dev: &mut Dev,
    launch: &Value,
    t: &Value,
) -> String {
    let sid = launch["session_id"].as_str().unwrap().to_string();
    mac.list(r, &sid);
    let hold_host_work = rig.faults().join("hold_host_work");
    let hold_dispatch = rig.faults().join("hold_dispatch");
    private(&hold_host_work, "");
    private(&hold_dispatch, "");
    two_passes(rig);
    assert_eq!(enqueue(dev, r, t)["state"], "queued");
    let accepted = mac.request(
        r,
        json!({"op":"submit","binding":mac.read(&sid),"kind":"prompt","request_id":uuid(),
            "acquire":true,"payload":{"text":"MAC_TURN"}}),
    );
    assert_eq!(accepted["state"], "accepted", "{accepted}");
    let lease = mac.request(
        r,
        json!({"op":"acquire","binding":mac.read(&sid),"takeover":false}),
    );
    assert_eq!(lease["op"], "lease", "{lease}");
    let released = mac.request(r, json!({"op":"release","binding":lease["binding"]}));
    assert_eq!(released["op"], "lease_released", "{released}");
    std::fs::remove_file(&hold_dispatch).unwrap();
    two_passes(rig);
    std::fs::remove_file(&hold_host_work).unwrap();
    within("the Mac's turn", || input(rig).contains("MAC_TURN"));
    let deadline = Instant::now() + WAIT;
    loop {
        let all = attempts(rig, &t["task_id"]);
        if let [(id, None)] = all.as_slice()
            && receipt(rig, id)["state"] == "accepted"
            && stored(rig, &t["task_id"])["state"] == "submitted"
        {
            return id.clone();
        }
        assert!(
            Instant::now() < deadline,
            "no attempt waits accepted: {all:?} {}",
            stored(rig, &t["task_id"])
        );
        std::thread::sleep(Duration::from_millis(40));
    }
}

/// After an event against task `t`'s attempt `attempt`, waiting `accepted`
/// behind the Mac's turn, and the end of that turn (when the start check
/// runs at the latest): the attempt was withdrawn and the task settled
/// `state`/`detail` from it; its prompt is never written and no other
/// attempt is made, whatever more passes run (design I.5.9: never both; a
/// withdrawn attempt isn't retried).
#[track_caller]
fn withdrawn_never_run(rig: &Rig, t: &Value, attempt: &str, state: &str, detail: &str) {
    std::fs::write(rig.fake.join("complete"), "").unwrap();
    within("the Mac's turn ended", || {
        !rig.fake.join("complete").exists()
    });
    wait_stored(rig, &t["task_id"], state, detail);
    within("the withdrawal recorded", || {
        let rc = receipt(rig, attempt);
        rc["state"] == "rejected" && rc["detail"] == "withdrawn by the host"
    });
    work_passes(rig, 3);
    let status = stored(rig, &t["task_id"]);
    assert_eq!(
        (&status["state"], &status["detail"]),
        (&json!(state), &json!(detail))
    );
    assert_eq!(
        attempts(rig, &t["task_id"]),
        [(attempt.to_string(), Some("withdrawn".to_string()))]
    );
    let prompt = t["prompt"].as_str().unwrap();
    assert!(!input(rig).contains(prompt), "{prompt} written");
}

/// VII.A test 6 (design I.4.3 "The same check runs at the start", I.5.6,
/// I.5.9; session-v1 R9.14 item 3): an event against an attempt waiting
/// `accepted` behind another turn ends it one way only: withdrawn
/// (`withdrawn by the host`) and the task settled from the event, never
/// written, never retried. The Station's revoke (`cancelled`, `sender
/// revoked`), an R9 removal of the sender (the phone: `cancelled`, `sender
/// revoked`), a narrowing that drops `prompt` (`failed`, `sender's
/// authorization narrowed`) and a route change (`failed`, `route
/// changed`), each on a host of its own. A revoke at the moment of dispatch
/// (the queued task's dispatch held while the record commits) cancels the
/// task before any attempt: none is ever made. (A revoke landing after the
/// attempt reached `executing`, where the task runs, is
/// `a_record_against_a_live_attempt`.)
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES, ATEM_TEST_PTY_FAULTS and ATEM_TEST_STATE_DUMP hooks"
)]
fn revoke_at_dispatch_and_while_accepted_never_both() {
    #[derive(Clone, Copy, Debug)]
    enum Event {
        Revoke,
        Removal,
        Narrowing,
        RouteChange,
    }
    for event in [
        Event::Revoke,
        Event::Removal,
        Event::Narrowing,
        Event::RouteChange,
    ] {
        let mut rig = Rig::prepared(4 * HOUR, false);
        rig.with_station();
        rig.faults = true;
        rig.start();
        let mut r = Router::new(&rig.astation);
        rig.station_online(true);
        let mut svc = Dev::new(&mut r, IDS, &rig.log, SVC, true);
        let launch = svc.session(&mut r);
        let mut mac = Dev::new(&mut r, IDS, &rig.log, MAC, false);
        let mut phone = Dev::new(&mut r, IDS, &rig.log, PHONE, false);
        let t = task(IDS, &launch, &format!("ACCEPTED_{event:?}"), HOUR);
        let sender = match event {
            Event::Removal => &mut phone,
            _ => &mut svc,
        };
        let attempt = accepted_behind_the_macs_turn(&rig, &mut r, &mut mac, sender, &launch, &t);
        let (state, detail) = match event {
            Event::Revoke => {
                control(
                    &rig,
                    ControlAction::Revoke {
                        interrupt_running: false,
                    },
                );
                ("cancelled", REVOKED)
            }
            Event::Removal => {
                let removal = rig.log.remove(PHONE);
                mac.carry(&mut r, &[removal]);
                ("cancelled", REVOKED)
            }
            Event::Narrowing => {
                let narrower =
                    ServiceScope::new([HOST]).ops(["launch", "message", "notify", "view"]);
                let narrowing = rig.log.narrow_service(SVC, &narrower, None);
                mac.carry(&mut r, &[narrowing]);
                ("failed", "sender's authorization narrowed")
            }
            Event::RouteChange => {
                let file = rig.sandbox.config().join("runtime.toml");
                let toml = std::fs::read_to_string(&file).unwrap();
                let route = "revision = 1\nprofile_id = \"backend\"";
                assert_eq!(toml.matches(route).count(), 1, "{toml}");
                replace(
                    &file,
                    &toml.replace(route, "revision = 2\nprofile_id = \"backend\""),
                );
                // A change is the runtime's once it loaded the file (at most
                // a second on): a task naming the new revision is accepted
                // then. (Its turn would otherwise end first, a start the
                // change didn't precede: never both still, but not this
                // case.)
                let deadline = Instant::now() + WAIT;
                loop {
                    let probe = task(IDS, &launch, "ROUTE_PROBE", HOUR);
                    let mut data = enqueue_data(IDS, &probe);
                    data["route_revision"] = json!(2);
                    let reply = phone.request(&mut r, data);
                    if reply["result"]["work"].is_object() {
                        break;
                    }
                    assert!(
                        Instant::now() < deadline,
                        "the new route never loaded: {reply}"
                    );
                    std::thread::sleep(Duration::from_millis(100));
                }
                ("failed", "route changed")
            }
        };
        withdrawn_never_run(&rig, &t, &attempt, state, detail);
        drop((r, svc, mac, phone));
    }

    // A revoke at the moment of dispatch: the record commits while the
    // task's dispatch is held; no attempt is ever made.
    let mut rig = Rig::prepared(4 * HOUR, false);
    rig.with_station();
    rig.faults = true;
    rig.start();
    let mut r = Router::new(&rig.astation);
    rig.station_online(true);
    let mut svc = Dev::new(&mut r, IDS, &rig.log, SVC, true);
    let launch = svc.session(&mut r);
    let hold_host_work = rig.faults().join("hold_host_work");
    private(&hold_host_work, "");
    two_passes(&rig);
    let t = task(IDS, &launch, "REVOKED_AT_DISPATCH", HOUR);
    assert_eq!(enqueue(&mut svc, &mut r, &t)["state"], "queued");
    control(
        &rig,
        ControlAction::Revoke {
            interrupt_running: false,
        },
    );
    wait_stored(&rig, &t["task_id"], "cancelled", REVOKED);
    std::fs::remove_file(&hold_host_work).unwrap();
    work_passes(&rig, 3);
    assert_eq!(stored(&rig, &t["task_id"])["state"], "cancelled");
    never_ran(&rig, &t["task_id"], "REVOKED_AT_DISPATCH");
}

/// `dev`'s `work_resolve` of task `tid`: the reply.
fn resolve(dev: &mut Dev, r: &mut Router, tid: &Value, resolution: Value) -> Value {
    dev.request(
        r,
        json!({"op":"work_resolve","host":host(),"task_id":tid,"resolution":resolution}),
    )
}

/// `dev`'s `alert_list` (`host.alerts`), first page: the alerts.
fn alert_list(dev: &mut Dev, r: &mut Router) -> Vec<Value> {
    let reply = dev.request(r, json!({"op":"alert_list","host":host()}));
    reply["result"]["alerts"]
        .as_array()
        .unwrap_or_else(|| panic!("no alerts: {reply}"))
        .clone()
}

/// `n` unresolved outcomes of `sender` recorded in the host's store (their
/// alerts: what the capacity limits count), on session `sid`.
fn unresolved_outcomes(rig: &Rig, sender: &str, sid: &str, n: u32) {
    let db = host_db(rig);
    let base: i64 = db
        .query_row("SELECT coalesce(max(seq),0) FROM alerts", [], |r| r.get(0))
        .unwrap();
    for k in 0..n {
        db.execute(
            "INSERT INTO alerts(alert_id,seq,task_id,session_id,sender,reason,created_ms)
            VALUES(?1,?2,?3,?4,?5,'agent exited',?6)",
            rusqlite::params![
                uuid(),
                base + 1_000_000 + i64::from(k),
                uuid(),
                sid,
                sender,
                r9log::host_now().wall_ms as i64
            ],
        )
        .unwrap();
    }
}

/// A task of the phone's on a session of its own whose agent exits in its
/// turn: `outcome_unknown`, `agent exited`. The session's launch.
fn an_unknown_outcome(
    rig: &Rig,
    r: &mut Router,
    svc: &mut Dev,
    phone: &mut Dev,
    prompt: &str,
) -> (Value, Value) {
    let launch = svc.session(r);
    let t = task(IDS, &launch, prompt, HOUR);
    enqueue(phone, r, &t);
    in_turn(rig, &t["task_id"], prompt);
    private(&rig.fake.join("exit"), "");
    wait_stored(rig, &t["task_id"], "outcome_unknown", "agent exited");
    std::fs::remove_file(rig.fake.join("exit")).unwrap();
    (t, launch)
}

/// VII.A test 13, Atem's side (design I.4.6; host-work-v1 §11.2, §11.3,
/// §11.6 "Unknown outcomes" and "Capacity"): an unknown outcome raises an
/// alert the owner lists (`alert_list`: the task, its sender and reason);
/// "Mark failed" (the owner's `work_resolve`, `failed`) and "Mark done"
/// (the sender's, `done` with a snapshot) resolve one each, ending its
/// alert. With 64 unresolved from the phone (one real, the rest recorded in
/// the store), the phone's requests that would make a task are refused
/// `busy`, `too many unresolved outcomes`, storing nothing (`work_enqueue`,
/// and `message_publish` to an agent), while the service's go on; with 256
/// on the host every remote sender's are, and a local agent's message is
/// still accepted. The owner resolving the real one lets both senders in.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES and ATEM_TEST_STATE_DUMP hooks"
)]
fn unresolved_limits_refuse_new_tasks() {
    const TOO_MANY: &str = "too many unresolved outcomes";
    let mut rig = Rig::prepared(4 * HOUR, true);
    rig.with_station();
    rig.alerts = true;
    rig.start();
    let mut r = Router::new(&rig.astation);
    rig.station_online(false);
    let mut svc = Dev::new(&mut r, IDS, &rig.log, SVC, true);
    let mut phone = Dev::new(&mut r, IDS, &rig.log, PHONE, false);
    let mut mac = Dev::new(&mut r, IDS, &rig.log, MAC, false);
    let phone_name = format!("member:{PHONE}");

    // An unknown outcome: alerted; the owner marks it failed.
    let (first, _) = an_unknown_outcome(&rig, &mut r, &mut svc, &mut phone, "UNKNOWN_FIRST");
    let alerts = alert_list(&mut mac, &mut r);
    assert_eq!(alerts.len(), 1, "{alerts:?}");
    assert_eq!(
        (
            &alerts[0]["task_id"],
            &alerts[0]["sender"],
            &alerts[0]["reason"]
        ),
        (
            &first["task_id"],
            &json!(phone_name),
            &json!("agent exited")
        ),
        "{alerts:?}"
    );
    let failed = resolve(
        &mut mac,
        &mut r,
        &first["task_id"],
        json!({"kind":"failed","detail":"agent exited"}),
    );
    let work = &failed["result"]["work"];
    assert_eq!(
        (&work["state"], &work["resolved"]["by"]),
        (&json!("failed"), &json!(format!("member:{MAC}"))),
        "{failed}"
    );
    assert!(alert_list(&mut mac, &mut r).is_empty());
    // Another: its sender marks it done.
    let (second, _) = an_unknown_outcome(&rig, &mut r, &mut svc, &mut phone, "UNKNOWN_SECOND");
    assert_eq!(alert_list(&mut mac, &mut r).len(), 1);
    let text = "Checked by hand: it landed.";
    let snapshot = json!({"kind":"vault","id":"v-done:1","version":1,"text":text,
        "digest":atem_client::session::host_work::digest(text.as_bytes())});
    let done = resolve(
        &mut phone,
        &mut r,
        &second["task_id"],
        json!({"kind":"done","result":snapshot}),
    );
    let work = &done["result"]["work"];
    assert_eq!(
        (&work["state"], &work["resolved"]["by"]),
        (&json!("completed"), &json!(phone_name)),
        "{done}"
    );
    assert!(alert_list(&mut mac, &mut r).is_empty());

    // A third, left unresolved, and 63 more of the phone's: 64.
    let (third, _) = an_unknown_outcome(&rig, &mut r, &mut svc, &mut phone, "UNKNOWN_THIRD");
    let open = svc.session(&mut r);
    let sid = open["session_id"].as_str().unwrap().to_string();
    unresolved_outcomes(&rig, &phone_name, &sid, 63);
    let stored_before = stored_tasks(&rig);
    let refused = phone.request(
        &mut r,
        enqueue_data(IDS, &task(IDS, &open, "PHONE_OVER_ITS_LIMIT", HOUR)),
    );
    assert_eq!(
        (&refused["code"], &refused["detail"]),
        (&json!("busy"), &json!(TOO_MANY)),
        "{refused}"
    );
    let mut target = IDS.json();
    target["session_id"] = open["session_id"].clone();
    target["process_gen"] = open["process_gen"].clone();
    let now = r9log::host_now().wall_ms;
    let message = json!({"message_id":uuid(),"workflow_id":uuid(),"sender":phone_name,
        "created_at":now,"expires_at":now + HOUR,"text":"PHONE_MESSAGE_OVER_ITS_LIMIT",
        "context":[],"recipients":[{"recipient_id":uuid(),"host":host(),
            "destination":{"kind":"agent","route_id":"backend","route_revision":1,
                "target":target}}]});
    let refused = phone.request(
        &mut r,
        json!({"op":"message_publish","host":host(),"message":message}),
    );
    assert_eq!(
        (&refused["code"], &refused["detail"]),
        (&json!("busy"), &json!(TOO_MANY)),
        "{refused}"
    );
    assert_eq!(stored_tasks(&rig), stored_before, "nothing stored");
    // Another sender's go on.
    let by_svc = task(IDS, &open, "SERVICE_UNDER_THE_LIMIT", HOUR);
    enqueue(&mut svc, &mut r, &by_svc);
    in_turn(&rig, &by_svc["task_id"], "SERVICE_UNDER_THE_LIMIT");
    complete_turn(&rig, &by_svc["task_id"]);

    // 256 on the host: every remote sender's refused; a local one isn't.
    unresolved_outcomes(&rig, "service:svc-other", &sid, 256 - 64);
    for (dev, prompt) in [
        (&mut svc, "SERVICE_OVER_THE_HOSTS_LIMIT"),
        (&mut phone, "PHONE_OVER_THE_HOSTS_LIMIT"),
    ] {
        let refused = dev.request(&mut r, enqueue_data(IDS, &task(IDS, &open, prompt, HOUR)));
        assert_eq!(
            (&refused["code"], &refused["detail"]),
            (&json!("busy"), &json!(TOO_MANY)),
            "{prompt}: {refused}"
        );
    }
    let other = local_session(&rig, "other");
    let sent = agent_run(
        &other,
        1,
        &[
            "message",
            "send",
            "--to",
            "tag:peer",
            "LOCAL_OVER_THE_HOSTS_LIMIT",
        ],
    );
    assert_eq!(sent["code"], 0, "{sent}");
    within("the local task's prompt", || {
        input(&rig).contains("LOCAL_OVER_THE_HOSTS_LIMIT")
    });

    // The owner resolves the real one: 63 of the phone's, 255 on the host.
    let failed = resolve(
        &mut mac,
        &mut r,
        &third["task_id"],
        json!({"kind":"failed","detail":"checked by the owner"}),
    );
    assert_eq!(failed["result"]["work"]["state"], "failed", "{failed}");
    let local = local_tasks(&rig);
    complete_turn(&rig, &local[0]["task"]["task_id"]);
    for (dev, prompt) in [
        (&mut phone, "PHONE_UNDER_ITS_LIMIT_AGAIN"),
        (&mut svc, "SERVICE_UNDER_THE_HOSTS_LIMIT_AGAIN"),
    ] {
        let t = task(IDS, &open, prompt, HOUR);
        assert_eq!(enqueue(dev, &mut r, &t)["state"], "queued");
        in_turn(&rig, &t["task_id"], prompt);
        complete_turn(&rig, &t["task_id"]);
    }
    let text = input(&rig);
    for prompt in [
        "PHONE_OVER_ITS_LIMIT",
        "PHONE_MESSAGE_OVER_ITS_LIMIT",
        "SERVICE_OVER_THE_HOSTS_LIMIT",
        "PHONE_OVER_THE_HOSTS_LIMIT",
    ] {
        assert!(!text.contains(prompt), "{prompt} ran");
    }
}

/// The tasks the host's store holds.
fn stored_tasks(rig: &Rig) -> i64 {
    host_db(rig)
        .query_row("SELECT count(*) FROM work", [], |r| r.get(0))
        .unwrap()
}

/// Launch `rid` waits at the spawn boundary for `reason` (its runtime.log
/// line), never spawned, `starting` to its sender, through host-work's
/// passes.
#[track_caller]
fn launch_waits(rig: &Rig, svc: &mut Dev, r: &mut Router, rid: &str, sid: &str, reason: &str) {
    let log = rig.sandbox.dir.path().join("runtime.log");
    let line = format!("launch {rid} waits at the spawn boundary: {reason}");
    within(&line, || {
        std::fs::read_to_string(&log)
            .unwrap_or_default()
            .contains(&line)
    });
    work_passes(rig, 3);
    assert_eq!(launch_state(svc, r, rid), "starting");
    assert!(never_spawned(rig, sid), "nothing spawned while it waits");
}

/// The launch `rid` ended `failed` with `detail` (runtime.log), never
/// `outcome_unknown`, nothing spawned (read from the store: its sender's
/// channel may be fenced by then).
#[track_caller]
fn launch_failed(rig: &Rig, rid: &str, sid: &str, detail: &str) {
    let state = |rig: &Rig| {
        host_db(rig)
            .query_row("SELECT record FROM launches WHERE id=?1", [rid], |row| {
                row.get::<_, String>(0)
            })
            .map(|text| serde_json::from_str::<Value>(&text).unwrap()["status"]["state"].clone())
            .unwrap()
    };
    within("the launch failed", || {
        let state = state(rig);
        assert_ne!(state, "outcome_unknown");
        state == "failed"
    });
    assert!(never_spawned(rig, sid), "nothing spawned");
    let log = std::fs::read_to_string(rig.sandbox.dir.path().join("runtime.log")).unwrap();
    assert!(
        log.contains(&format!("launch {rid} failed before its spawn: {detail}")),
        "{log}"
    );
}

/// VII.A test 19 (design I.4.3, "Launches"; host-work-v1 §11.6,
/// "Launches"): a covered service's `host_launch` checked at the spawn
/// boundary. Each reason that can clear makes it wait there, `starting`,
/// nothing spawned, its reason in runtime.log, and it starts once the
/// reason clears: a hold (then a release); 60 seconds with no `heads` on
/// the host's clock, the gate closed (then the Station's `heads`); the
/// host's own fetch stopped at a deferred device-list entry (then the
/// Mac's approval of the pending recovery ends the wait). A reason that
/// can't clear ends it `failed` at once, never `outcome_unknown`, nothing
/// spawned: the Station's revoke of a waiting launch (`sender revoked`),
/// and, on another host, a frozen device list (`sender's authority
/// changed`). (A launch on message has no delegated sender in step 4, and
/// a receipt-database fault keeps v1's fence: see the report.)
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES, ATEM_TEST_HOST_CLOCK, ATEM_TEST_MEMBERSHIP_FAULTS and ATEM_TEST_STATE_DUMP hooks"
)]
fn launch_at_the_spawn_boundary_waits_for_hold_gap_and_deferral_and_fails_on_revoke() {
    use atem_client::membership::entry::Action;
    let mut rig = Rig::prepared(4 * HOUR, false);
    rig.with_station();
    rig.with_clock();
    rig.start();
    let mut r = Router::new(&rig.astation);
    rig.station_online(true);
    let mut svc = Dev::new(&mut r, IDS, &rig.log, SVC, true);
    let started = |svc: &mut Dev, r: &mut Router, rid: &str| {
        within("the launch started", || {
            launch_state(svc, r, rid) == "started"
        });
    };

    // A hold, then the release.
    control(&rig, ControlAction::Hold);
    let (rid, sid) = launch_backend(&mut svc, &mut r);
    launch_waits(&rig, &mut svc, &mut r, &rid, &sid, "paused");
    control(&rig, ControlAction::Release);
    started(&mut svc, &mut r, &rid);

    // No heads for 60 s on the host's clock, then the Station's heads.
    drop(rig.pump.lock().unwrap().take());
    rig.clock().add_mono(61_000);
    within("the gate closed", || {
        dumped(&rig)["station"]["feed"]["open"] == false
    });
    let (rid, sid) = launch_backend(&mut svc, &mut r);
    launch_waits(
        &rig,
        &mut svc,
        &mut r,
        &rid,
        &sid,
        "revocations not yet checked",
    );
    let station = rig.station.clone().expect("the fake Station");
    *rig.pump.lock().unwrap() = Some(Pump::start(station));
    started(&mut svc, &mut r, &rid);

    // The host's own fetch stops at a deferred entry; the Mac approves the
    // pending recovery.
    let pinned = list_head(&rig);
    rig.log.recovery_add("dev-new");
    let recovery = rig.log.entries.last().unwrap().hash();
    let deferred = removal_by_the_pending(&rig.log);
    let log = &rig.log;
    rig.station().set_log_beyond(log, &[deferred]);
    until_station(&rig, "the stop at the deferred entry", |s| {
        s["fetch"]["stopped"] == pinned + 2
    });
    let (rid, sid) = launch_backend(&mut svc, &mut r);
    launch_waits(
        &rig,
        &mut svc,
        &mut r,
        &rid,
        &sid,
        "device list update pending",
    );
    let approve = rig
        .log
        .append(MAC, Action::RecoveryApprove { target: recovery });
    let log = &rig.log;
    rig.station().set_log(log);
    let mut mac = Dev::new(&mut r, IDS, &rig.log, MAC, false);
    mac.carry(&mut r, &[approve]);
    started(&mut svc, &mut r, &rid);

    // Held again, waiting; the revoke fails it.
    control(&rig, ControlAction::Hold);
    let (rid, sid) = launch_backend(&mut svc, &mut r);
    launch_waits(&rig, &mut svc, &mut r, &rid, &sid, "paused");
    control(
        &rig,
        ControlAction::Revoke {
            interrupt_running: false,
        },
    );
    launch_failed(&rig, &rid, &sid, REVOKED);
    drop((r, svc, mac));

    // Another host: the device list frozen under a waiting launch.
    let mut rig = Rig::prepared(4 * HOUR, false);
    rig.with_station();
    rig.membership = true;
    rig.start();
    let mut r = Router::new(&rig.astation);
    rig.station_online(true);
    let mut svc = Dev::new(&mut r, IDS, &rig.log, SVC, true);
    control(&rig, ControlAction::Hold);
    let (rid, sid) = launch_backend(&mut svc, &mut r);
    launch_waits(&rig, &mut svc, &mut r, &rid, &sid, "paused");
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
    launch_failed(&rig, &rid, &sid, "sender's authority changed");
}

/// VII.A test 21 (design I.5.5 "A task with a live attempt", I.5.6;
/// host-work-v1 §11.1, "The effects on tasks, as built in step 4"): the
/// service's attempt waits `accepted` behind the Mac's turn; host-work's
/// scheduling is held, and the Mac's turn ends, so the session host starts
/// the attempt (its start check passes): `executing`, its turn running,
/// before host-work saw it start. Then the Station's revoke lands: the
/// record's transaction finds the attempt live and settles nothing; its
/// withdrawal, asked after the commit, finds it started, so the task runs.
/// Polled throughout, the task never shows `cancelled` while its turn
/// runs: it ends `awaiting_result` from its turn's end, on the one attempt,
/// which started; its prompt written once, no interrupt.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES, ATEM_TEST_PTY_FAULTS and ATEM_TEST_STATE_DUMP hooks"
)]
fn a_record_against_a_live_attempt() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let mut rig = Rig::prepared(4 * HOUR, false);
    rig.with_station();
    rig.faults = true;
    rig.start();
    let mut r = Router::new(&rig.astation);
    rig.station_online(true);
    let mut svc = Dev::new(&mut r, IDS, &rig.log, SVC, true);
    let launch = svc.session(&mut r);
    let mut mac = Dev::new(&mut r, IDS, &rig.log, MAC, false);
    let t = task(IDS, &launch, "REVOKED_AS_IT_STARTS", HOUR);
    let tid = t["task_id"].clone();
    let attempt = accepted_behind_the_macs_turn(&rig, &mut r, &mut mac, &mut svc, &launch, &t);
    // Every state the store shows from now on.
    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let poll = {
        let (seen, stop) = (seen.clone(), stop.clone());
        let db = rig.sandbox.config().join("runtime/host-work.sqlite");
        let id = tid.as_str().unwrap().to_string();
        std::thread::spawn(move || {
            let db = rusqlite::Connection::open(db).unwrap();
            db.busy_timeout(Duration::from_secs(5)).unwrap();
            while !stop.load(Ordering::SeqCst) {
                let state: String = db
                    .query_row("SELECT state FROM work WHERE id=?1", [&id], |r| r.get(0))
                    .unwrap();
                let mut seen = seen.lock().unwrap();
                if seen.last() != Some(&state) {
                    seen.push(state);
                }
                drop(seen);
                std::thread::sleep(Duration::from_millis(5));
            }
        })
    };
    // Host-work held; the Mac's turn ends: the attempt starts.
    let hold_host_work = rig.faults().join("hold_host_work");
    private(&hold_host_work, "");
    two_passes(&rig);
    std::fs::write(rig.fake.join("complete"), "").unwrap();
    within("its turn", || input(&rig).contains("REVOKED_AS_IT_STARTS"));
    assert_eq!(receipt(&rig, &attempt)["state"], "executing");
    assert_eq!(ends(&rig, &tid), [None], "host-work hasn't seen it start");
    // The revoke lands.
    control(
        &rig,
        ControlAction::Revoke {
            interrupt_running: false,
        },
    );
    two_passes(&rig);
    assert_eq!(stored(&rig, &tid)["state"], "submitted");
    assert_eq!(ends(&rig, &tid), [None]);
    std::fs::remove_file(&hold_host_work).unwrap();
    wait_stored(&rig, &tid, "submitted", "in the agent's turn");
    complete_turn(&rig, &tid);
    stop.store(true, Ordering::SeqCst);
    poll.join().unwrap();
    let seen = seen.lock().unwrap().clone();
    assert!(!seen.iter().any(|s| s == "cancelled"), "{seen:?}");
    assert_eq!(
        seen.last().map(String::as_str),
        Some("awaiting_result"),
        "{seen:?}"
    );
    assert_eq!(attempts(&rig, &tid), [(attempt, Some("started".into()))]);
    assert_eq!(input(&rig).matches("REVOKED_AS_IT_STARTS").count(), 1);
    assert!(intents(&rig, &tid).is_empty());
    assert_eq!(escs(&rig), 0);
}
