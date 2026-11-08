//! Performance measurements of the end-to-end encrypted path
//! (designs/e2e-encryption.md). Measurement code only: never run by default
//! (every test is `#[ignore]`), never committed.
//!
//! Temp profiles only: the in-process test agent (`UnlockedDevice`), or a
//! real `atem cred-agent` process (the release binary beside the test
//! binary) on a temp HOME and XDG_RUNTIME_DIR with its environment cleared,
//! and a local fake relay. Nothing reaches the network or the real profile.
//!
//!   CARGO_TARGET_DIR=<dir> cargo build --release
//!   CARGO_TARGET_DIR=<dir> cargo test --release --bin atem perf_ -- --ignored --nocapture --test-threads=1
use crate::memory::account_keys::{AccountKey, AccountKeys, CryptOp};
use crate::memory::adapters::Ctx;
use crate::memory::agent_socket::{CredAgentClient, encode_request};
use crate::memory::api::{KnowledgeClient, op_to_wire};
use crate::memory::cred_agent::{CredAgentApi, Reply, Request, build_unlock_request};
use crate::memory::crypto::{EncryptionContext, EncryptionMode};
use crate::memory::device_keys::{DeviceKeys, UnlockAuthKey};
use crate::memory::fake_astation::{
    ACCOUNT, ASTATION_ID, DEVICE_ID, UnlockedDevice, pin, set_state,
};
use crate::memory::grant::seal_k_grant;
use crate::memory::model::{Memory, Scope, Skill, content_hash, skill_hash};
use crate::memory::statements::FakeAstation;
use crate::memory::store::{PendingOp, SearchQuery, Store};
use crate::memory::sync::{SyncOptions, apply_all, run_sync};
use crate::paths::CredPaths;
use crate::vault_client::VaultClient;
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const KID: &str = "0123abcd";
const NEW_KID: &str = "89abcdef";
const KEY: [u8; 32] = [7; 32];
const NEW_KEY: [u8; 32] = [8; 32];

// ───────────────────────── timing helpers ─────────────────────────

fn median(mut samples: Vec<Duration>) -> Duration {
    samples.sort();
    samples[samples.len() / 2]
}

/// Median of `reps` timed runs of `f` (after one warm-up run).
fn bench(reps: usize, mut f: impl FnMut()) -> Duration {
    f();
    median(
        (0..reps)
            .map(|_| {
                let t = Instant::now();
                f();
                t.elapsed()
            })
            .collect(),
    )
}

fn us(d: Duration) -> f64 {
    d.as_secs_f64() * 1e6
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1e3
}

fn mib_s(bytes: usize, d: Duration) -> f64 {
    bytes as f64 / (1 << 20) as f64 / d.as_secs_f64()
}

fn text(len: usize, seed: usize) -> String {
    let mut out = format!("[{seed}] ");
    const WORDS: &[&str] = &[
        "the", "relay", "listens", "on", "port", "for", "staging", "deploy", "station", "build",
        "uses", "token", "agent", "skill", "memory", "sync", "check", "before", "release",
    ];
    let mut i = seed;
    while out.len() < len {
        out.push_str(WORDS[i % WORDS.len()]);
        out.push(' ');
        i = i.wrapping_mul(31).wrapping_add(7);
    }
    out.truncate(len);
    out
}

/// A fact of 100–700 bytes (mean ~400, like the facts Atem harvests); half
/// project-scoped, half global.
fn fact(i: usize) -> Memory {
    let content = text(100 + (i * 37) % 600, i);
    let project = if i.is_multiple_of(2) {
        "github.com/agora/atem".to_string()
    } else {
        String::new()
    };
    Memory {
        id: format!("mem-{i:06}"),
        scope: if project.is_empty() {
            Scope::Global
        } else {
            Scope::Project
        },
        project,
        content_hash: content_hash(&content),
        content,
        confidence: "high".into(),
        source_agent: "claude".into(),
        source_machine: "perf-machine".into(),
        created_at: 1_760_000_000 + i as i64,
        ..Memory::default()
    }
}

fn skill(i: usize, files: usize, file_bytes: usize) -> Skill {
    let files: BTreeMap<String, Vec<u8>> = (0..files)
        .map(|f| {
            let path = if f == 0 {
                "SKILL.md".to_string()
            } else {
                format!("reference/part-{f:03}.md")
            };
            (path, text(file_bytes, i * 1000 + f).into_bytes())
        })
        .collect();
    Skill {
        scope: Scope::Global,
        project: String::new(),
        name: format!("perf-skill-{i:03}"),
        version: 1,
        content_hash: skill_hash(&files),
        files,
        source_agent: "claude".into(),
        source_machine: "perf-machine".into(),
        created_at: 1,
        deleted: false,
        seq: 0,
    }
}

// ───────────────────────── metered agents ─────────────────────────

#[derive(Default)]
struct Counts {
    calls: AtomicUsize,
    crypts: AtomicUsize,
    /// `Crypt` requests that open (pull, read-back); the others seal or hash.
    open_crypts: AtomicUsize,
    ops: AtomicUsize,
    nanos: AtomicU64,
}

impl Counts {
    fn reset(&self) {
        self.calls.store(0, Ordering::SeqCst);
        self.crypts.store(0, Ordering::SeqCst);
        self.open_crypts.store(0, Ordering::SeqCst);
        self.ops.store(0, Ordering::SeqCst);
        self.nanos.store(0, Ordering::SeqCst);
    }
    fn agent_time(&self) -> Duration {
        Duration::from_nanos(self.nanos.load(Ordering::SeqCst))
    }
}

/// Counts and times every request that reaches `inner`.
struct Meter {
    inner: Arc<dyn CredAgentApi>,
    counts: Arc<Counts>,
}

impl CredAgentApi for Meter {
    fn call(&self, request: Request) -> anyhow::Result<Reply> {
        self.counts.calls.fetch_add(1, Ordering::SeqCst);
        if let Request::Crypt { ops, .. } = &request {
            self.counts.crypts.fetch_add(1, Ordering::SeqCst);
            if ops.iter().any(|op| matches!(op, CryptOp::Open { .. })) {
                self.counts.open_crypts.fetch_add(1, Ordering::SeqCst);
            }
            self.counts.ops.fetch_add(ops.len(), Ordering::SeqCst);
        }
        let start = Instant::now();
        let reply = self.inner.call(request);
        self.counts
            .nanos
            .fetch_add(start.elapsed().as_nanos() as u64, Ordering::SeqCst);
        reply
    }
}

/// The agent's racy window has passed for every file written so far: from
/// now on it serves cred/state.json from its cache (`CredAgent::trust_view`).
fn settle() {
    std::thread::sleep(crate::memory::cred_agent::RACY_WINDOW + Duration::from_millis(100));
    // The CPU is back at full clock speed before anything is timed.
    let spin = Instant::now();
    while spin.elapsed() < Duration::from_millis(300) {
        std::hint::black_box(spin);
    }
}

// ───────────────────────── a real agent process ─────────────────────────

fn atem_binary() -> PathBuf {
    let exe = std::env::current_exe()
        .unwrap()
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .join("atem");
    assert!(
        exe.exists(),
        "build the release binary first: {}",
        exe.display()
    );
    exe
}

fn short_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("atem-perf")
        .tempdir_in("/tmp")
        .unwrap()
}

fn private_dir(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

/// `atem cred-agent` with only HOME, XDG_RUNTIME_DIR and PATH set (temp
/// dirs), optionally with `RLIMIT_MEMLOCK` lowered to `memlock` bytes.
fn spawn_agent(home: &Path, run: &Path, log: &Path, memlock: Option<u64>) -> std::process::Child {
    spawn_agent_with(home, run, log, memlock, &[])
}

/// [`spawn_agent`] with `extra` variables added (e.g. TOKIO_WORKER_THREADS).
fn spawn_agent_with(
    home: &Path,
    run: &Path,
    log: &Path,
    memlock: Option<u64>,
    extra: &[(&str, &str)],
) -> std::process::Child {
    use std::os::unix::process::CommandExt;
    let log = std::fs::File::create(log).unwrap();
    let mut command = std::process::Command::new(atem_binary());
    command
        .arg("cred-agent")
        .env_clear()
        .env("HOME", home)
        .env("XDG_RUNTIME_DIR", run)
        .env("PATH", "/usr/bin:/bin")
        .envs(extra.iter().copied())
        .stdin(std::process::Stdio::null())
        .stdout(log.try_clone().unwrap())
        .stderr(log);
    if let Some(limit) = memlock {
        unsafe {
            command.pre_exec(move || {
                let limit = libc::rlimit {
                    rlim_cur: limit,
                    rlim_max: limit,
                };
                if libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    command.spawn().unwrap()
}

fn rss_kib(pid: u32) -> (u64, u64) {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
    let field = |name: &str| {
        status
            .lines()
            .find(|line| line.starts_with(name))
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|value| value.parse().ok())
            .unwrap_or(0)
    };
    (field("VmRSS:"), field("VmHWM:"))
}

/// A verified device whose real agent process started unlocked (from a
/// plain `device_keys`, as a fresh device's does) and holds `K`.
struct RealAgent {
    child: std::process::Child,
    _dir: tempfile::TempDir,
    run: PathBuf,
    paths: CredPaths,
    build: String,
    started: Duration,
}

impl Drop for RealAgent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl RealAgent {
    fn start(mode: EncryptionMode, memlock: Option<u64>) -> Self {
        let dir = short_dir();
        let home = dir.path().join("h");
        let run = dir.path().join("r");
        std::fs::create_dir_all(&home).unwrap();
        private_dir(&run);
        let config = home.join(".config").join("atem");
        let paths = CredPaths::in_dir(&config);
        crate::paths::create_private_dir(&paths.dir).unwrap();
        let keys = DeviceKeys::generate();
        keys.save_to(&paths.device_keys).unwrap();
        let astation = FakeAstation::new();
        pin(&paths, &astation, &keys, false);
        set_state(&paths, &astation, mode, Some(KID), 2);
        let start = Instant::now();
        let child = spawn_agent(&home, &run, &dir.path().join("agent.log"), memlock);
        let client = CredAgentClient::for_paths(&paths, Some(run.clone().into_os_string()), None);
        let status = loop {
            if let Ok(status) = client.status()
                && status.unlocked
            {
                break status;
            }
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "the agent didn't come up"
            );
            std::thread::sleep(Duration::from_millis(1));
        };
        let started = start.elapsed();
        let grant = seal_k_grant(&astation, ACCOUNT, DEVICE_ID, keys.device_pub(), KID, KEY);
        client.install_grant(ASTATION_ID, &grant).unwrap();
        Self {
            child,
            _dir: dir,
            run,
            paths,
            build: status.build,
            started,
        }
    }

    fn reuse(&self) -> Arc<CredAgentClient> {
        Arc::new(CredAgentClient::for_paths(
            &self.paths,
            Some(self.run.clone().into_os_string()),
            None,
        ))
    }

    /// What production does: `default_agent` hands every `EncryptionContext`
    /// of a process the same client (`agent_socket::shared`), which keeps one
    /// connection and checks the build once per connection. A new one is a
    /// new process's.
    fn production(&self) -> Arc<CredAgentClient> {
        Arc::new(self.reuse_client().checking_build(&self.build))
    }

    fn reuse_client(&self) -> CredAgentClient {
        CredAgentClient::for_paths(&self.paths, Some(self.run.clone().into_os_string()), None)
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }
}

// ───────────────────────── a fake relay ─────────────────────────

#[derive(Default)]
struct RelayData {
    memories: BTreeMap<i64, Memory>,
    memory_seq: HashMap<String, i64>,
    skills: BTreeMap<i64, Skill>,
    skill_seq: HashMap<(String, i64), i64>,
    vaults: BTreeMap<String, (String, Vec<Value>)>,
    next_seq: i64,
    requests: usize,
    up_bytes: usize,
    down_bytes: usize,
}

impl RelayData {
    fn seq(&mut self) -> i64 {
        self.next_seq += 1;
        self.next_seq
    }

    fn put_memory(&mut self, mut memory: Memory) -> i64 {
        let seq = self.seq();
        if let Some(old) = self.memory_seq.insert(memory.id.clone(), seq) {
            self.memories.remove(&old);
        }
        memory.seq = seq;
        self.memories.insert(seq, memory);
        seq
    }

    fn put_skill(&mut self, mut skill: Skill) -> i64 {
        let seq = self.seq();
        if let Some(old) = self
            .skill_seq
            .insert((skill.name.clone(), skill.version), seq)
        {
            self.skills.remove(&old);
        }
        skill.seq = seq;
        self.skills.insert(seq, skill);
        seq
    }
}

#[derive(Clone)]
struct Relay {
    base: String,
    data: Arc<Mutex<RelayData>>,
    /// Added to every response, in µs: a real relay's round trip.
    latency: Arc<AtomicU64>,
}

impl Relay {
    /// A relay on its own runtime and threads (so its work doesn't share the
    /// client's), HTTP/1.1 keep-alive like the real one behind Cloudflare.
    fn start() -> Self {
        let data = Arc::new(Mutex::new(RelayData::default()));
        let latency = Arc::new(AtomicU64::new(0));
        let (tx, rx) = std::sync::mpsc::channel();
        let served = data.clone();
        let delay = latency.clone();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                tx.send(format!("http://{}", listener.local_addr().unwrap()))
                    .unwrap();
                loop {
                    let Ok((socket, _)) = listener.accept().await else {
                        return;
                    };
                    let data = served.clone();
                    let delay = delay.clone();
                    tokio::spawn(async move {
                        let _ = serve_http(socket, data, delay).await;
                    });
                }
            });
        });
        Self {
            base: rx.recv().unwrap(),
            data,
            latency,
        }
    }

    /// Every later response waits `latency` first.
    fn set_latency(&self, latency: Duration) {
        self.latency
            .store(latency.as_micros() as u64, Ordering::SeqCst);
    }

    fn reset(&self) {
        *self.data.lock().unwrap() = RelayData::default();
    }

    fn reset_counters(&self) {
        let mut data = self.data.lock().unwrap();
        data.requests = 0;
        data.up_bytes = 0;
        data.down_bytes = 0;
    }

    fn traffic(&self) -> (usize, usize, usize) {
        let data = self.data.lock().unwrap();
        (data.requests, data.up_bytes, data.down_bytes)
    }

    fn knowledge(&self, paths: &CredPaths, agent: Arc<dyn CredAgentApi>) -> KnowledgeClient {
        KnowledgeClient::new(
            self.base.clone(),
            "atem-perf".into(),
            "session-perf".into(),
            ASTATION_ID.into(),
        )
        .with_encryption(paths.clone(), agent)
    }

    fn vault(&self, paths: &CredPaths, agent: Arc<dyn CredAgentApi>) -> VaultClient {
        VaultClient::new(
            self.base.clone(),
            "atem-perf".into(),
            "session-perf".into(),
            ASTATION_ID.into(),
        )
        .with_encryption(paths.clone(), agent)
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

async fn serve_http(
    mut socket: tokio::net::TcpStream,
    data: Arc<Mutex<RelayData>>,
    latency: Arc<AtomicU64>,
) -> std::io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    socket.set_nodelay(true)?;
    // ACK every segment at once: the client writes a request's head and body
    // separately, and Nagle on its side plus a delayed ACK here would stall
    // some requests 40 ms (a loopback artifact, not relay work).
    let quickack = |socket: &tokio::net::TcpStream| {
        use std::os::unix::io::AsRawFd;
        let on: libc::c_int = 1;
        unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_QUICKACK,
                &on as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    };
    let mut buffer: Vec<u8> = Vec::with_capacity(1 << 16);
    let mut chunk = vec![0u8; 1 << 16];
    loop {
        let header_end = loop {
            if let Some(index) = find(&buffer, b"\r\n\r\n") {
                break index + 4;
            }
            let count = socket.read(&mut chunk).await?;
            quickack(&socket);
            if count == 0 {
                return Ok(());
            }
            buffer.extend_from_slice(&chunk[..count]);
        };
        let header = String::from_utf8_lossy(&buffer[..header_end]).into_owned();
        let mut lines = header.lines();
        let mut first = lines.next().unwrap_or("").split(' ');
        let method = first.next().unwrap_or("").to_string();
        let target = first.next().unwrap_or("").to_string();
        let length = lines
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.trim().eq_ignore_ascii_case("content-length"))
            .and_then(|(_, value)| value.trim().parse::<usize>().ok())
            .unwrap_or(0);
        while buffer.len() < header_end + length {
            let count = socket.read(&mut chunk).await?;
            quickack(&socket);
            if count == 0 {
                return Ok(());
            }
            buffer.extend_from_slice(&chunk[..count]);
        }
        let body: Value = if length == 0 {
            Value::Null
        } else {
            serde_json::from_slice(&buffer[header_end..header_end + length]).unwrap_or(Value::Null)
        };
        buffer.drain(..header_end + length);
        let response = handle(&data, &method, &target, &body, length);
        let delay = latency.load(Ordering::SeqCst);
        if delay > 0 {
            tokio::time::sleep(Duration::from_micros(delay)).await;
        }
        let bytes = serde_json::to_vec(&response).unwrap();
        data.lock().unwrap().down_bytes += bytes.len();
        // One write (and TCP_NODELAY): a separate head and body would meet
        // Nagle plus the client's delayed ACK, a 40 ms stall per response.
        let mut wire = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
            bytes.len()
        )
        .into_bytes();
        wire.extend_from_slice(&bytes);
        socket.write_all(&wire).await?;
    }
}

fn query(target: &str, key: &str) -> Option<String> {
    let (_, query) = target.split_once('?')?;
    query.split('&').find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        (name == key).then(|| value.to_string())
    })
}

fn handle(
    data: &Mutex<RelayData>,
    method: &str,
    target: &str,
    body: &Value,
    length: usize,
) -> Value {
    let mut data = data.lock().unwrap();
    data.requests += 1;
    data.up_bytes += length;
    let path = target.split_once('?').map_or(target, |(path, _)| path);
    let since: i64 = query(target, "since")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let limit: usize = query(target, "limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(200);
    match (method, path) {
        ("GET", "/api/memory") => {
            json!({"memories": data.memories.range(since + 1..).take(limit).map(|(_, m)| m).collect::<Vec<_>>()})
        }
        ("GET", "/api/skills") => {
            json!({"skills": data.skills.range(since + 1..).take(limit).map(|(_, s)| s).collect::<Vec<_>>()})
        }
        ("POST", "/api/memory/batch") => {
            let mut results = Vec::new();
            for op in body["ops"].as_array().unwrap() {
                match op["op"].as_str().unwrap() {
                    "add" => {
                        let memory: Memory = serde_json::from_value(op["memory"].clone()).unwrap();
                        let id = memory.id.clone();
                        let seq = data.put_memory(memory);
                        results.push(json!({"ok": true, "id": id, "seq": seq}));
                    }
                    "rewrite" => {
                        let id = op["id"].as_str().unwrap().to_string();
                        let old = data.memory_seq[&id];
                        let mut memory = data.memories.remove(&old).unwrap();
                        memory.project = op["project"].as_str().unwrap().into();
                        memory.content = op["content"].as_str().unwrap().into();
                        memory.content_hash = op["content_hash"].as_str().unwrap().into();
                        let seq = data.put_memory(memory);
                        results.push(json!({"ok": true, "seq": seq}));
                    }
                    _ => results.push(json!({"ok": true})),
                }
            }
            json!({"results": results})
        }
        ("POST", "/api/skills/batch") => {
            let mut results = Vec::new();
            for op in body["ops"].as_array().unwrap() {
                match op["op"].as_str().unwrap() {
                    "push" => {
                        let skill: Skill = serde_json::from_value(op["skill"].clone()).unwrap();
                        let version = skill.version;
                        let seq = data.put_skill(skill);
                        results.push(json!({"ok": true, "version": version, "seq": seq}));
                    }
                    "rewrite" => {
                        let key = (
                            op["name"].as_str().unwrap().to_string(),
                            op["version"].as_i64().unwrap(),
                        );
                        let old = data.skill_seq[&key];
                        let mut skill = data.skills.remove(&old).unwrap();
                        skill.project = op["project"].as_str().unwrap().into();
                        skill.files = serde_json::from_value(op["files"].clone()).unwrap();
                        skill.content_hash = op["content_hash"].as_str().unwrap().into();
                        let version = skill.version;
                        let seq = data.put_skill(skill);
                        results.push(json!({"ok": true, "version": version, "seq": seq}));
                    }
                    _ => results.push(json!({"ok": true})),
                }
            }
            json!({"results": results})
        }
        ("POST", "/api/vault") => {
            let id = format!("v-{}", data.vaults.len() + 1);
            data.vaults.insert(
                id.clone(),
                (body["summary"].as_str().unwrap_or("").into(), Vec::new()),
            );
            json!({"vault_id": id})
        }
        ("GET", "/api/vault") => Value::Array(
            data.vaults
                .iter()
                .map(|(id, (summary, _))| json!({"vault_id": id, "summary": summary}))
                .collect(),
        ),
        _ if path.starts_with("/api/vault/") => {
            let rest = &path["/api/vault/".len()..];
            let (id, action) = rest
                .split_once('/')
                .map_or((rest, ""), |(id, action)| (id, action));
            let id = id.to_string();
            let seq = data.seq();
            let (summary, entries) = data.vaults.get_mut(&id).unwrap();
            match (method, action) {
                ("GET", "") => {
                    if query(target, "history").is_some() {
                        Value::Array(entries.clone())
                    } else {
                        let mut latest: BTreeMap<u64, Value> = BTreeMap::new();
                        for entry in entries.iter() {
                            latest.insert(entry["entry_no"].as_u64().unwrap(), entry.clone());
                        }
                        Value::Array(latest.into_values().collect())
                    }
                }
                ("POST", "") => {
                    let entry_no = body["entry_id"].as_u64().unwrap_or_else(|| {
                        entries
                            .iter()
                            .map(|e| e["entry_no"].as_u64().unwrap())
                            .max()
                            .unwrap_or(0)
                            + 1
                    });
                    let version = entries
                        .iter()
                        .filter(|e| e["entry_no"].as_u64() == Some(entry_no))
                        .count() as u64
                        + 1;
                    entries.push(json!({"seq": seq, "entry_no": entry_no, "version": version, "kind": "content",
                        "writer_id": "atem-perf", "content": body["text"], "created_at": "2026-11-08T00:00:00Z"}));
                    json!({"entry_no": entry_no, "version": version, "seq": seq})
                }
                ("POST", "summary") => {
                    *summary = body["text"].as_str().unwrap().into();
                    json!({"ok": true})
                }
                ("POST", "encryption") => {
                    *summary = body["summary"].as_str().unwrap().into();
                    for replacement in body["entries"].as_array().unwrap() {
                        let entry = entries
                            .iter_mut()
                            .find(|e| {
                                e["entry_no"] == replacement["entry_no"]
                                    && e["version"] == replacement["version"]
                            })
                            .unwrap();
                        entry["content"] = replacement["content"].clone();
                    }
                    json!({"ok": true})
                }
                _ => panic!("unexpected vault request {method} {target}"),
            }
        }
        _ => panic!("unexpected relay request {method} {target}"),
    }
}

// ───────────────────────── profiles per mode ─────────────────────────

#[derive(Clone, Copy, Debug, PartialEq)]
enum Mode {
    /// Verified device, signed mode `off`: no agent call.
    Off,
    /// `on`, the agent in this process (crypto + agent logic, no socket).
    InProcess,
    /// `on`, a real agent process, one client reused (one connection, no
    /// build check, so JSON lines).
    SocketReuse,
    /// `on`, a real agent process, a process's client as production makes
    /// it (one connection, the build check on it, which agrees to frames).
    Production,
}

const ALL_MODES: [Mode; 4] = [
    Mode::Off,
    Mode::InProcess,
    Mode::SocketReuse,
    Mode::Production,
];

struct Profiles {
    _dirs: Vec<tempfile::TempDir>,
    off: UnlockedDevice,
    on: UnlockedDevice,
    real: RealAgent,
}

impl Profiles {
    fn new(target: EncryptionMode) -> Self {
        let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let mut off = UnlockedDevice::new(a.path());
        off.state(EncryptionMode::Off, None);
        let mut on = UnlockedDevice::new(b.path());
        on.set_key(target, KID, KEY);
        let real = RealAgent::start(target, None);
        settle();
        Self {
            _dirs: vec![a, b],
            off,
            on,
            real,
        }
    }

    /// The paths and agent of `mode`, and the socket client behind it.
    fn agent(
        &self,
        mode: Mode,
    ) -> (
        CredPaths,
        Arc<dyn CredAgentApi>,
        Option<Arc<CredAgentClient>>,
    ) {
        let socket = |client: Arc<CredAgentClient>| {
            (
                self.real.paths.clone(),
                client.clone() as Arc<dyn CredAgentApi>,
                Some(client),
            )
        };
        match mode {
            Mode::Off => (
                self.off.paths.clone(),
                self.off.agent.clone() as Arc<dyn CredAgentApi>,
                None,
            ),
            Mode::InProcess => (
                self.on.paths.clone(),
                self.on.agent.clone() as Arc<dyn CredAgentApi>,
                None,
            ),
            Mode::SocketReuse => socket(self.real.reuse()),
            Mode::Production => socket(self.real.production()),
        }
    }

    /// The same mode for `paths` (to seal seed rows, unmetered).
    fn context(&self, mode: Mode) -> EncryptionContext {
        let (paths, agent, _) = self.agent(match mode {
            Mode::Production => Mode::SocketReuse,
            other => other,
        });
        EncryptionContext::for_astation_with(ASTATION_ID, &paths, agent).unwrap()
    }
}

fn metered(agent: Arc<dyn CredAgentApi>) -> (Arc<dyn CredAgentApi>, Arc<Counts>) {
    let counts = Arc::new(Counts::default());
    (
        Arc::new(Meter {
            inner: agent,
            counts: counts.clone(),
        }),
        counts,
    )
}

fn agents_home(dir: &Path) -> PathBuf {
    let home = dir.join("home");
    std::fs::create_dir_all(home.join(".claude")).unwrap();
    std::fs::create_dir_all(home.join(".codex")).unwrap();
    home
}

/// Socket round trips (request lines, build checks included) and
/// connections `client` made so far.
fn traffic(client: Option<&Arc<CredAgentClient>>) -> (usize, usize) {
    client.map_or((0, 0), |client| {
        (client.traffic().requests(), client.traffic().connections())
    })
}

// ───────────────────────── 1. Crypt costs ─────────────────────────

#[test]
#[ignore]
fn perf_1a_field_ops_inside_the_agent() {
    let mut keys = AccountKeys::default();
    keys.install(ACCOUNT, KID, Zeroizing::new(KEY));
    let key = AccountKey {
        kid: KID.into(),
        key: Zeroizing::new(KEY),
    };
    println!(
        "\n## 1a. Field operations inside the agent (AccountKeys::crypt: base64 in, AEAD/HMAC, base64 out), per op"
    );
    println!(
        "| field | seal µs | open µs | keyed_hash µs | seal MiB/s | open MiB/s | raw seal_field µs | client CryptOp::seal build µs |"
    );
    println!("|---|---|---|---|---|---|---|---|");
    for size in [100usize, 1 << 10, 64 << 10, 1 << 20] {
        let plain = text(size, 1).into_bytes();
        let n = match size {
            s if s >= 1 << 20 => 8,
            s if s >= 64 << 10 => 64,
            _ => 1024,
        };
        let build = || {
            (0..n)
                .map(|_| CryptOp::seal("mem-000001", "content", &plain))
                .collect::<Vec<_>>()
        };
        let build_t = bench(5, || {
            std::hint::black_box(build());
        }) / n as u32;
        let seal_t = median(
            (0..7)
                .map(|_| {
                    let ops = build();
                    let t = Instant::now();
                    std::hint::black_box(
                        keys.crypt(ACCOUNT, EncryptionMode::On, Some(KID), ops)
                            .unwrap(),
                    );
                    t.elapsed()
                })
                .collect(),
        ) / n as u32;
        let sealed: Vec<String> = keys
            .crypt(ACCOUNT, EncryptionMode::On, Some(KID), build())
            .unwrap()
            .into_iter()
            .map(|out| out.into_text().unwrap())
            .collect();
        let open_t = median(
            (0..7)
                .map(|_| {
                    let ops: Vec<CryptOp> = sealed
                        .iter()
                        .map(|v| CryptOp::open("mem-000001", "content", v))
                        .collect();
                    let t = Instant::now();
                    std::hint::black_box(
                        keys.crypt(ACCOUNT, EncryptionMode::On, Some(KID), ops)
                            .unwrap(),
                    );
                    t.elapsed()
                })
                .collect(),
        ) / n as u32;
        let hash_t = median(
            (0..7)
                .map(|_| {
                    let ops: Vec<CryptOp> = (0..n).map(|_| CryptOp::keyed_hash(&plain)).collect();
                    let t = Instant::now();
                    std::hint::black_box(
                        keys.crypt(ACCOUNT, EncryptionMode::On, Some(KID), ops)
                            .unwrap(),
                    );
                    t.elapsed()
                })
                .collect(),
        ) / n as u32;
        let raw_t = bench(5, || {
            for _ in 0..n {
                std::hint::black_box(
                    crate::memory::account_keys::seal_field(&key, "mem-000001", "content", &plain)
                        .unwrap(),
                );
            }
        }) / n as u32;
        println!(
            "| {} B | {:.2} | {:.2} | {:.2} | {:.0} | {:.0} | {:.2} | {:.2} |",
            size,
            us(seal_t),
            us(open_t),
            us(hash_t),
            mib_s(size, seal_t),
            mib_s(size, open_t),
            us(raw_t),
            us(build_t)
        );
    }

    // Pieces of the per-op cost.
    println!("\n### 1a'. Pieces");
    let nonce = bench(9, || {
        for _ in 0..1000 {
            std::hint::black_box(<chacha20poly1305::XChaCha20Poly1305 as chacha20poly1305::aead::AeadCore>::generate_nonce(&mut rand::rngs::OsRng));
        }
    }) / 1000;
    println!(
        "- XChaCha nonce from OsRng (getrandom): {:.3} µs",
        us(nonce)
    );
    for size in [64usize << 10, 1 << 20] {
        let wipe = bench(9, || {
            let buffer = Zeroizing::new(vec![1u8; size]);
            drop(std::hint::black_box(buffer));
        });
        let plain_vec = bench(9, || {
            let buffer = vec![1u8; size];
            drop(std::hint::black_box(buffer));
        });
        println!(
            "- alloc+fill+zeroize-drop {size} B: {:.1} µs (alloc+fill+drop without zeroize {:.1} µs)",
            us(wipe),
            us(plain_vec)
        );
        let b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, vec![1u8; size]);
        let encode = bench(9, || {
            std::hint::black_box(base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &b64.as_bytes()[..size],
            ));
        });
        let decode = bench(9, || {
            std::hint::black_box(
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &b64).unwrap(),
            );
        });
        let line = serde_json::to_string(&json!({"v": 2, "op": "crypt", "ops": [{"seal": {"record": "r", "field": "f", "plain": b64}}]})).unwrap();
        let parse = bench(9, || {
            std::hint::black_box(serde_json::from_str::<Value>(&line).unwrap());
        });
        println!(
            "- base64 encode {size} B: {:.1} µs, decode: {:.1} µs; serde_json parse of a {}-byte line: {:.1} µs",
            us(encode),
            us(decode),
            line.len(),
            us(parse)
        );
    }
}

#[test]
#[ignore]
fn perf_1b_crypt_requests_in_process_and_over_the_socket() {
    let dir = tempfile::tempdir().unwrap();
    let mut device = UnlockedDevice::new(dir.path());
    device.set_key(EncryptionMode::On, KID, KEY);
    let real = RealAgent::start(EncryptionMode::On, None);
    let real_nolock = RealAgent::start(EncryptionMode::On, Some(8 << 20));
    settle();
    let plain = text(100, 3).into_bytes();
    let sealed_one = device
        .agent
        .crypt(
            ASTATION_ID,
            vec![CryptOp::seal("mem-000001", "content", &plain)],
        )
        .unwrap()
        .remove(0)
        .into_text()
        .unwrap();
    let transports: Vec<(&str, Arc<dyn CredAgentApi>)> = vec![
        (
            "in-process agent (no socket)",
            device.agent.clone() as Arc<dyn CredAgentApi>,
        ),
        (
            "socket, client reused, no build check: JSON lines (mlockall on)",
            real.reuse(),
        ),
        (
            "socket, production: one client per process, frames (mlockall on)",
            real.production(),
        ),
        (
            "socket, client reused, JSON lines (RLIMIT_MEMLOCK 8 MiB: no mlockall)",
            real_nolock.reuse(),
        ),
        (
            "socket, production, frames (no mlockall)",
            real_nolock.production(),
        ),
    ];
    println!("\n## 1b. One Crypt request, by batch size (100-byte fields), median");
    println!(
        "| transport | op | batch 1 µs | batch 16 µs | batch 128 µs | batch 1024 µs | per op at 1024 µs |"
    );
    println!("|---|---|---|---|---|---|---|");
    for (name, agent) in &transports {
        for kind in ["seal", "open", "keyed_hash"] {
            let mut row = format!("| {name} | {kind} |");
            let mut last = Duration::ZERO;
            for batch in [1usize, 16, 128, 1024] {
                let reps = match batch {
                    1 => 300,
                    16 => 200,
                    128 => 60,
                    _ => 20,
                };
                let ops = || -> Vec<CryptOp> {
                    (0..batch)
                        .map(|_| match kind {
                            "seal" => CryptOp::seal("mem-000001", "content", &plain),
                            "open" => CryptOp::open("mem-000001", "content", &sealed_one),
                            _ => CryptOp::keyed_hash(&plain),
                        })
                        .collect()
                };
                let t = median(
                    (0..reps)
                        .map(|_| {
                            let ops = ops();
                            let t = Instant::now();
                            std::hint::black_box(agent.crypt(ASTATION_ID, ops).unwrap());
                            t.elapsed()
                        })
                        .collect(),
                );
                row.push_str(&format!(" {:.1} |", us(t)));
                last = t;
            }
            row.push_str(&format!(" {:.2} |", us(last) / 1024.0));
            println!("{row}");
        }
    }

    println!("\n## 1b'. One large field per request (seal, then open), median");
    println!(
        "| transport | 64 KiB seal ms | 64 KiB open ms | 1 MiB seal ms | 1 MiB open ms | 2 MiB seal ms |"
    );
    println!("|---|---|---|---|---|---|");
    for (name, agent) in &transports {
        let mut row = format!("| {name} |");
        for size in [64usize << 10, 1 << 20, 2 << 20] {
            let plain = text(size, 9).into_bytes();
            let reps = if size > 64 << 10 { 15 } else { 50 };
            let seal = bench(reps, || {
                std::hint::black_box(
                    agent
                        .crypt(ASTATION_ID, vec![CryptOp::seal("v-1", "content", &plain)])
                        .unwrap(),
                );
            });
            row.push_str(&format!(" {:.2} |", ms(seal)));
            if size <= 1 << 20 {
                let sealed = agent
                    .crypt(ASTATION_ID, vec![CryptOp::seal("v-1", "content", &plain)])
                    .unwrap()
                    .remove(0)
                    .into_text()
                    .unwrap();
                let open = bench(reps, || {
                    std::hint::black_box(
                        agent
                            .crypt(ASTATION_ID, vec![CryptOp::open("v-1", "content", &sealed)])
                            .unwrap(),
                    );
                });
                row.push_str(&format!(" {:.2} |", ms(open)));
            }
        }
        println!("{row}");
    }

    println!("\n## 1c. Fixed costs per request / per context");
    let status_reuse = bench(300, || {
        real.reuse_client().status().unwrap();
    });
    let client = real.reuse();
    let status_same = bench(300, || {
        client.status().unwrap();
    });
    let connect = bench(300, || {
        std::hint::black_box(
            std::os::unix::net::UnixStream::connect(
                real.paths.agent_sock(Some(real.run.as_path())),
            )
            .unwrap(),
        );
    });
    let context = bench(300, || {
        std::hint::black_box(
            EncryptionContext::for_astation_with(ASTATION_ID, &device.paths, device.agent.clone())
                .unwrap(),
        );
    });
    let mode = bench(300, || {
        std::hint::black_box(
            crate::memory::verification::account_mode(&device.paths.trust, ASTATION_ID).unwrap(),
        );
    });
    let held = bench(300, || {
        std::hint::black_box(device.agent.held_kid(ASTATION_ID).unwrap());
    });
    let tiny = bench(300, || {
        std::hint::black_box(
            device
                .agent
                .crypt(ASTATION_ID, vec![CryptOp::keyed_hash(b"x")])
                .unwrap(),
        );
    });
    println!("- Unix socket connect only: {:.1} µs", us(connect));
    println!(
        "- Status round trip (connect + request + reply): {:.1} µs (same client {:.1} µs)",
        us(status_reuse),
        us(status_same)
    );
    println!(
        "- In-process Crypt with one 1-byte keyed_hash (agent's fixed per-request work: prune check, 2× cred/state.json read+parse): {:.1} µs",
        us(tiny)
    );
    println!(
        "- In-process HeldKid (prune check + 1 state.json read): {:.1} µs",
        us(held)
    );
    println!(
        "- EncryptionContext::for_astation_with (2× state.json read+parse): {:.1} µs",
        us(context)
    );
    println!(
        "- verification::account_mode (the planned injection gate's check): {:.1} µs",
        us(mode)
    );
    println!(
        "- cred/state.json size: {} bytes",
        std::fs::metadata(&device.paths.trust).unwrap().len()
    );
}

// ───────────────────────── 2. Sync cycle ─────────────────────────

#[derive(Clone, Copy, PartialEq, Debug)]
enum Scenario {
    /// N facts changed here: pushed, pulled back (this device's own rows) and applied.
    PushPull,
    /// N facts from another device: pulled and applied (a fresh device's first sync).
    Pull,
    /// Skills: `skills` × `files` files of 4 KiB pushed, pulled back and applied.
    Skills { skills: usize, files: usize },
}

struct SyncRun {
    total: Duration,
    apply: Duration,
    agent: Duration,
    crypts: usize,
    open_crypts: usize,
    ops: usize,
    round_trips: usize,
    connections: usize,
    http: usize,
    up: usize,
    down: usize,
}

async fn sync_run(
    relay: &Relay,
    profiles: &Profiles,
    mode: Mode,
    n: usize,
    scenario: Scenario,
    work: &Path,
    file_store: bool,
) -> SyncRun {
    relay.reset();
    let _ = std::fs::remove_dir_all(work);
    std::fs::create_dir_all(work).unwrap();
    let (paths, agent, client) = profiles.agent(mode);
    let (agent, counts) = metered(agent);
    let knowledge = relay.knowledge(&paths, agent);
    let store = if file_store {
        Store::open(&work.join("knowledge.db")).unwrap()
    } else {
        Store::open_in_memory().unwrap()
    };
    let ctx = Ctx {
        home: agents_home(work),
        repo: None,
        atem_id: "atem-perf".into(),
        allow_tracked: false,
    };
    match scenario {
        Scenario::PushPull => {
            store
                .in_transaction(|| {
                    for memory in (0..n).map(fact) {
                        store.upsert_memory(&memory)?;
                        store.enqueue(&PendingOp::AddMemory { memory })?;
                    }
                    Ok(())
                })
                .unwrap();
        }
        Scenario::Pull => {
            let memories: Vec<Memory> = (0..n).map(fact).collect();
            let wire = profiles.context(mode).encrypt_memories(memories).unwrap();
            let mut data = relay.data.lock().unwrap();
            for memory in wire {
                data.put_memory(memory);
            }
        }
        Scenario::Skills { skills, files } => {
            store
                .in_transaction(|| {
                    for skill in (0..skills).map(|i| skill(i, files, 4 << 10)) {
                        store.put_skill(&skill)?;
                        store.enqueue(&PendingOp::PushSkill {
                            skill,
                            base_version: 0,
                        })?;
                    }
                    Ok(())
                })
                .unwrap();
        }
    }
    relay.reset_counters();
    counts.reset();
    let traffic_before = traffic(client.as_ref());
    let start = Instant::now();
    let out = run_sync(
        &store,
        Some(&knowledge),
        &ctx,
        &SyncOptions { harvest: false },
    )
    .await
    .unwrap();
    let total = start.elapsed();
    assert!(
        !out.relay_error && !out.offline,
        "{mode:?} {scenario:?}: {:?}",
        out.notes
    );
    let (http, up, down) = relay.traffic();
    let traffic_after = traffic(client.as_ref());
    let start = Instant::now();
    apply_all(&store, &ctx).unwrap();
    let apply = start.elapsed();
    SyncRun {
        total,
        apply,
        agent: counts.agent_time(),
        crypts: counts.crypts.load(Ordering::SeqCst),
        open_crypts: counts.open_crypts.load(Ordering::SeqCst),
        ops: counts.ops.load(Ordering::SeqCst),
        round_trips: traffic_after.0 - traffic_before.0,
        connections: traffic_after.1 - traffic_before.1,
        http,
        up,
        down,
    }
}

fn median_run(mut runs: Vec<SyncRun>) -> SyncRun {
    runs.sort_by_key(|run| run.total);
    runs.remove(runs.len() / 2)
}

async fn sync_table(file_store: bool, sizes: &[usize], reps_for: impl Fn(usize) -> usize) {
    let (_profile, _scope) = crate::test_profile::temp();
    let relay = Relay::start();
    let profiles = Profiles::new(EncryptionMode::On);
    let scratch = tempfile::tempdir().unwrap();
    let mut scenarios: Vec<(Scenario, usize)> = Vec::new();
    for &n in sizes {
        scenarios.push((Scenario::PushPull, n));
    }
    for &n in sizes {
        scenarios.push((Scenario::Pull, n));
    }
    scenarios.push((
        Scenario::Skills {
            skills: 1,
            files: 10,
        },
        10,
    ));
    scenarios.push((
        Scenario::Skills {
            skills: 10,
            files: 10,
        },
        100,
    ));
    println!(
        "\n## 2{}. Sync cycle (run_sync, harvest off), {} store, median of runs; apply = apply_all measured again on the same store",
        if file_store { "" } else { "b" },
        if file_store {
            "file knowledge.db (as shipped)"
        } else {
            "in-memory SQLite (store cost removed, isolates relay + crypto)"
        }
    );
    println!(
        "| scenario | N | mode | total ms | added vs off ms | added % | agent ms | apply ms | Crypt reqs (seal / open) | agent socket round trips | agent connections | ops | HTTP reqs | up KiB | down KiB |"
    );
    println!("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|");
    for (scenario, n) in scenarios {
        let reps = reps_for(n);
        let mut off_total = Duration::ZERO;
        for mode in ALL_MODES {
            let mut runs = Vec::new();
            for rep in 0..reps {
                let work = scratch.path().join(format!("{rep}"));
                runs.push(sync_run(&relay, &profiles, mode, n, scenario, &work, file_store).await);
            }
            let run = median_run(runs);
            if mode == Mode::Off {
                off_total = run.total;
            }
            let added = run.total.as_secs_f64() - off_total.as_secs_f64();
            let label = match scenario {
                Scenario::PushPull => "push+pull+apply".to_string(),
                Scenario::Pull => "pull+apply (other device's facts)".to_string(),
                Scenario::Skills { skills, files } => {
                    format!("skills {skills}×{files} files of 4 KiB, push+pull+apply")
                }
            };
            println!(
                "| {label} | {n} | {mode:?} | {:.1} | {:.1} | {:.1}% | {:.1} | {:.1} | {} ({} / {}) | {} | {} | {} | {} | {:.0} | {:.0} |",
                ms(run.total),
                added * 1e3,
                added / off_total.as_secs_f64() * 100.0,
                ms(run.agent),
                ms(run.apply),
                run.crypts,
                run.crypts - run.open_crypts,
                run.open_crypts,
                run.round_trips,
                run.connections,
                run.ops,
                run.http,
                run.up as f64 / 1024.0,
                run.down as f64 / 1024.0
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn perf_2_sync_cycle() {
    sync_table(
        true,
        &[10, 100, 1000, 5000],
        |n| if n >= 1000 { 3 } else { 7 },
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn perf_2b_sync_cycle_in_memory_store() {
    sync_table(false, &[10, 100, 1000, 5000], |n| {
        if n >= 5000 {
            7
        } else if n >= 1000 {
            9
        } else {
            15
        }
    })
    .await;
}

/// The sync against a relay with a fixed round trip: what encryption adds
/// to the wall time once the network, not the loopback, sets the pace.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn perf_2c_sync_against_a_relay_with_latency() {
    let (_profile, _scope) = crate::test_profile::temp();
    let relay = Relay::start();
    let profiles = Profiles::new(EncryptionMode::On);
    let scratch = tempfile::tempdir().unwrap();
    const REPS: usize = 7;
    println!(
        "\n## 2c. Sync cycle against a relay that answers each request after a fixed latency, file store; {REPS} reps, off and on interleaved; medians, and the median of the paired differences (on − off, same rep)"
    );
    println!(
        "| latency ms | scenario | N | off ms | on (production) ms | added ms (median of pairs) | added % | agent ms | Crypt reqs (seal / open) | HTTP reqs |"
    );
    println!("|---|---|---|---|---|---|---|---|---|---|");
    for latency in [5u64, 20] {
        relay.set_latency(Duration::from_millis(latency));
        for (scenario, n) in [
            (Scenario::PushPull, 1000usize),
            (Scenario::PushPull, 5000),
            (Scenario::Pull, 1000),
            (Scenario::Pull, 5000),
        ] {
            let (mut offs, mut ons, mut pairs) = (Vec::new(), Vec::new(), Vec::new());
            for rep in 0..REPS {
                let work = scratch.path().join(format!("{rep}"));
                let off = sync_run(&relay, &profiles, Mode::Off, n, scenario, &work, true).await;
                let on = sync_run(
                    &relay,
                    &profiles,
                    Mode::Production,
                    n,
                    scenario,
                    &work,
                    true,
                )
                .await;
                pairs.push(on.total.as_secs_f64() - off.total.as_secs_f64());
                offs.push(off);
                ons.push(on);
            }
            pairs.sort_by(f64::total_cmp);
            let added = pairs[REPS / 2];
            let (off, on) = (median_run(offs), median_run(ons));
            let label = match scenario {
                Scenario::PushPull => "push+pull+apply",
                _ => "pull+apply (other device's facts)",
            };
            println!(
                "| {latency} | {label} | {n} | {:.1} | {:.1} | {:.1} | {:.1}% | {:.1} | {} ({} / {}) | {} |",
                ms(off.total),
                ms(on.total),
                added * 1e3,
                added / off.total.as_secs_f64() * 100.0,
                ms(on.agent),
                on.crypts,
                on.crypts - on.open_crypts,
                on.open_crypts,
                on.http
            );
        }
    }
    relay.set_latency(Duration::ZERO);
}

// ───────────────────────── 3. Vault ─────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn perf_3_vault_write_and_read_back() {
    let relay = Relay::start();
    let profiles = Profiles::new(EncryptionMode::On);
    println!(
        "\n## 3. Vault: write one entry, then read the vault back (current view, one entry); median"
    );
    println!(
        "| entry | mode | write ms | read ms | write+read-back ms | added vs off ms | agent calls per write+read | agent connections over the runs |"
    );
    println!("|---|---|---|---|---|---|---|---|");
    for size in [1usize << 10, 64 << 10, 1 << 20] {
        let payload = text(size, 42);
        let reps = if size >= 1 << 20 { 15 } else { 40 };
        let mut off_both = Duration::ZERO;
        for mode in ALL_MODES {
            relay.reset();
            let (paths, agent, client) = profiles.agent(mode);
            let (agent, counts) = metered(agent);
            let vault = relay.vault(&paths, agent);
            let id = vault.create("perf vault").await.unwrap().vault_id;
            vault.write(&id, &payload, None).await.unwrap();
            let mut writes = Vec::new();
            let mut reads = Vec::new();
            let mut both = Vec::new();
            counts.reset();
            let traffic_before = traffic(client.as_ref());
            for _ in 0..reps {
                let start = Instant::now();
                vault.write(&id, &payload, Some(1)).await.unwrap();
                let wrote = start.elapsed();
                let start = Instant::now();
                let entries = vault.read(&id, None, false).await.unwrap();
                let read = start.elapsed();
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].content, payload);
                writes.push(wrote);
                reads.push(read);
                both.push(wrote + read);
            }
            let calls = counts.calls.load(Ordering::SeqCst) / reps;
            let traffic_after = traffic(client.as_ref());
            let both = median(both);
            if mode == Mode::Off {
                off_both = both;
            }
            println!(
                "| {} KiB | {mode:?} | {:.2} | {:.2} | {:.2} | {:.2} | {} ({} socket round trips) | {} |",
                size >> 10,
                ms(median(writes)),
                ms(median(reads)),
                ms(both),
                ms(both) - ms(off_both),
                calls,
                (traffic_after.0 - traffic_before.0) / reps,
                traffic_after.1 - traffic_before.1
            );
        }
    }
}

// ───────────────────────── 4. Migration ─────────────────────────

struct MigrationRun {
    knowledge: Duration,
    vault: Duration,
    verify: Duration,
    calls: usize,
    /// `Crypt` requests of the memory+skills rewrite, the vault rewrite and
    /// the read-back.
    crypts: (usize, usize, usize),
    http: usize,
}

/// Seeds `relay` with `n` plain-text facts, `skills` skills of 10 × 4 KiB
/// files and one vault of `entries` 1 KiB entries, then migrates and reads
/// everything back under `agent`.
async fn migrate_run(
    relay: &Relay,
    paths: &CredPaths,
    agent: Arc<dyn CredAgentApi>,
    n: usize,
    skills: usize,
    entries: usize,
    sealed_under: Option<&EncryptionContext>,
) -> MigrationRun {
    relay.reset();
    {
        let mut memories: Vec<Memory> = (0..n).map(fact).collect();
        let mut all_skills: Vec<Skill> = (0..skills).map(|i| skill(i, 10, 4 << 10)).collect();
        if let Some(context) = sealed_under {
            memories = context.encrypt_memories(memories).unwrap();
            all_skills = context.encrypt_skills(all_skills).unwrap();
        }
        let mut data = relay.data.lock().unwrap();
        for memory in memories {
            data.put_memory(memory);
        }
        for skill in all_skills {
            data.put_skill(skill);
        }
        let mut rows = Vec::new();
        for e in 0..entries {
            let mut content = text(1 << 10, e);
            if let Some(context) = sealed_under {
                content = context.seal("v-1", "content", content.as_bytes()).unwrap();
            }
            rows.push(json!({"seq": e + 1, "entry_no": e + 1, "version": 1, "kind": "content", "writer_id": "seed",
                "content": content, "created_at": "2026-11-08T00:00:00Z"}));
        }
        let summary = match sealed_under {
            Some(context) => context.seal("v-1", "summary", b"perf vault").unwrap(),
            None => "perf vault".to_string(),
        };
        data.vaults.insert("v-1".into(), (summary, rows));
    }
    let (agent, counts) = metered(agent);
    let knowledge = relay.knowledge(paths, agent.clone());
    let vault = relay.vault(paths, agent);
    relay.reset_counters();
    let crypts = || counts.crypts.load(Ordering::SeqCst);
    let start = Instant::now();
    knowledge.migrate_encryption().await.unwrap();
    let knowledge_t = start.elapsed();
    let rewrite_crypts = crypts();
    let start = Instant::now();
    vault.migrate_encryption().await.unwrap();
    let vault_t = start.elapsed();
    let vault_crypts = crypts() - rewrite_crypts;
    let start = Instant::now();
    knowledge.verify_encryption_migration().await.unwrap();
    vault.verify_encryption_migration().await.unwrap();
    let verify = start.elapsed();
    MigrationRun {
        knowledge: knowledge_t,
        vault: vault_t,
        verify,
        calls: counts.calls.load(Ordering::SeqCst),
        crypts: (
            rewrite_crypts,
            vault_crypts,
            crypts() - rewrite_crypts - vault_crypts,
        ),
        http: relay.traffic().0,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn perf_4_migration() {
    let relay = Relay::start();
    // Baseline: the same rewrite and read-back passes without crypto
    // (`disabling` over plain-text rows makes no agent call).
    let base_dir = tempfile::tempdir().unwrap();
    let mut baseline = UnlockedDevice::new(base_dir.path());
    baseline.set_key(EncryptionMode::Disabling, KID, KEY);
    let on_dir = tempfile::tempdir().unwrap();
    let mut device = UnlockedDevice::new(on_dir.path());
    device.set_key(EncryptionMode::Enabling, KID, KEY);
    let real = RealAgent::start(EncryptionMode::Enabling, None);
    println!(
        "\n## 4. Migration off → on (enabling): rewrite every row, then the read-back pass; median of 3"
    );
    println!(
        "| facts | skills (10×4 KiB files) | vault entries (1 KiB) | mode | memory+skills rewrite ms | vault rewrite ms | read-back ms | total ms | added vs no-crypto ms | records/s | agent calls | Crypt reqs (rewrite / vault / read-back) | HTTP reqs |"
    );
    println!("|---|---|---|---|---|---|---|---|---|---|---|---|---|");
    for (n, skills, entries) in [
        (10usize, 1usize, 10usize),
        (100, 10, 100),
        (1000, 10, 1000),
        (5000, 10, 1000),
    ] {
        let mut base_total = 0.0;
        let modes: Vec<(&str, CredPaths, Arc<dyn CredAgentApi>)> = vec![
            (
                "no crypto (disabling over plain rows)",
                baseline.paths.clone(),
                baseline.agent.clone() as Arc<dyn CredAgentApi>,
            ),
            (
                "in-process agent",
                device.paths.clone(),
                device.agent.clone() as Arc<dyn CredAgentApi>,
            ),
            (
                "socket, client reused",
                real.paths.clone(),
                real.reuse() as Arc<dyn CredAgentApi>,
            ),
            (
                "socket, production (one client per process)",
                real.paths.clone(),
                real.production() as Arc<dyn CredAgentApi>,
            ),
        ];
        for (name, paths, agent) in modes {
            let mut runs = Vec::new();
            for _ in 0..3 {
                runs.push(
                    migrate_run(&relay, &paths, agent.clone(), n, skills, entries, None).await,
                );
            }
            runs.sort_by_key(|run| run.knowledge + run.vault + run.verify);
            let run = runs.remove(1);
            let total = ms(run.knowledge + run.vault + run.verify);
            if base_total == 0.0 {
                base_total = total;
            }
            let records = n + skills + entries;
            println!(
                "| {n} | {skills} | {entries} | {name} | {:.1} | {:.1} | {:.1} | {:.1} | {:.1} | {:.0} | {} | {} / {} / {} | {} |",
                ms(run.knowledge),
                ms(run.vault),
                ms(run.verify),
                total,
                total - base_total,
                records as f64 / (total / 1e3),
                run.calls,
                run.crypts.0,
                run.crypts.1,
                run.crypts.2,
                run.http
            );
        }
    }
    // The same against a relay with a round trip: what encryption adds once
    // the network sets the pace.
    println!(
        "\n### 4''. Migration against a relay that answers each request after 20 ms, median of 3"
    );
    println!(
        "| facts | skills | vault entries | mode | total ms | added vs no-crypto ms | added % | Crypt reqs (rewrite / vault / read-back) | HTTP reqs |"
    );
    println!("|---|---|---|---|---|---|---|---|---|");
    relay.set_latency(Duration::from_millis(20));
    for (n, skills, entries) in [(1000usize, 10usize, 1000usize), (5000, 10, 1000)] {
        let mut base_total = 0.0;
        let modes: Vec<(&str, CredPaths, Arc<dyn CredAgentApi>)> = vec![
            (
                "no crypto (disabling over plain rows)",
                baseline.paths.clone(),
                baseline.agent.clone() as Arc<dyn CredAgentApi>,
            ),
            (
                "socket, production (one client per process)",
                real.paths.clone(),
                real.production() as Arc<dyn CredAgentApi>,
            ),
        ];
        for (name, paths, agent) in modes {
            let mut runs = Vec::new();
            for _ in 0..3 {
                runs.push(
                    migrate_run(&relay, &paths, agent.clone(), n, skills, entries, None).await,
                );
            }
            runs.sort_by_key(|run| run.knowledge + run.vault + run.verify);
            let run = runs.remove(1);
            let total = ms(run.knowledge + run.vault + run.verify);
            if base_total == 0.0 {
                base_total = total;
            }
            println!(
                "| {n} | {skills} | {entries} | {name} | {:.1} | {:.1} | {:.1}% | {} / {} / {} | {} |",
                total,
                total - base_total,
                (total - base_total) / base_total * 100.0,
                run.crypts.0,
                run.crypts.1,
                run.crypts.2,
                run.http
            );
        }
    }
    relay.set_latency(Duration::ZERO);
    // Key rotation: every row already sealed under the old kid, re-sealed under the new one.
    println!(
        "\n### 4'. Rotation (enabling with a new kid over rows sealed under the old one), in-process agent"
    );
    for (n, skills, entries) in [(1000usize, 10usize, 1000usize), (5000, 10, 1000)] {
        let rot_dir = tempfile::tempdir().unwrap();
        let mut rotating = UnlockedDevice::new(rot_dir.path());
        rotating.set_key(EncryptionMode::Enabling, KID, KEY);
        let old = EncryptionContext::for_astation_with(
            ASTATION_ID,
            &rotating.paths,
            rotating.agent.clone(),
        )
        .unwrap();
        // Seal the seed under the old kid first, then rotate.
        relay.reset();
        let seeded = {
            let memories = old.encrypt_memories((0..n).map(fact).collect()).unwrap();
            let skills_sealed = old
                .encrypt_skills((0..skills).map(|i| skill(i, 10, 4 << 10)).collect())
                .unwrap();
            let rows: Vec<String> = (0..entries)
                .map(|e| {
                    old.seal("v-1", "content", text(1 << 10, e).as_bytes())
                        .unwrap()
                })
                .collect();
            (
                memories,
                skills_sealed,
                rows,
                old.seal("v-1", "summary", b"perf vault").unwrap(),
            )
        };
        rotating.set_key(EncryptionMode::Enabling, NEW_KID, NEW_KEY);
        let mut times = Vec::new();
        for _ in 0..3 {
            relay.reset();
            {
                let mut data = relay.data.lock().unwrap();
                for memory in seeded.0.clone() {
                    data.put_memory(memory);
                }
                for skill in seeded.1.clone() {
                    data.put_skill(skill);
                }
                let rows = seeded.2.iter().enumerate().map(|(e, content)| json!({"seq": e + 1, "entry_no": e + 1, "version": 1,
                    "kind": "content", "writer_id": "seed", "content": content, "created_at": "2026-11-08T00:00:00Z"})).collect();
                data.vaults.insert("v-1".into(), (seeded.3.clone(), rows));
            }
            let (agent, counts) = metered(rotating.agent.clone() as Arc<dyn CredAgentApi>);
            let knowledge = relay.knowledge(&rotating.paths, agent.clone());
            let vault = relay.vault(&rotating.paths, agent);
            let start = Instant::now();
            knowledge.migrate_encryption().await.unwrap();
            vault.migrate_encryption().await.unwrap();
            knowledge.verify_encryption_migration().await.unwrap();
            vault.verify_encryption_migration().await.unwrap();
            times.push((start.elapsed(), counts.calls.load(Ordering::SeqCst)));
        }
        times.sort();
        let (time, calls) = times[1];
        println!(
            "- {n} facts + {skills} skills + {entries} vault entries: {:.1} ms ({:.0} records/s), {calls} agent calls",
            ms(time),
            (n + skills + entries) as f64 / time.as_secs_f64()
        );
    }
}

// ───────────────────────── 5. Cold start, unlock, memory ─────────────────────────

#[test]
#[ignore]
fn perf_5_cold_start_unlock_and_memory() {
    println!("\n## 5. Cold start of the cred agent");
    // (a) A locked agent on an empty profile: spawn → first status reply.
    let mut locked = Vec::new();
    let mut listening = Vec::new();
    for _ in 0..10 {
        let dir = short_dir();
        let home = dir.path().join("h");
        let run = dir.path().join("r");
        std::fs::create_dir_all(&home).unwrap();
        private_dir(&run);
        let config = home.join(".config").join("atem");
        let paths = CredPaths::in_dir(&config);
        let socket = paths.agent_sock(Some(run.as_path()));
        let start = Instant::now();
        let mut child = spawn_agent(&home, &run, &dir.path().join("a.log"), None);
        while std::os::unix::net::UnixStream::connect(&socket).is_err() {
            std::thread::sleep(Duration::from_micros(200));
        }
        listening.push(start.elapsed());
        let client = CredAgentClient::for_paths(&paths, Some(run.clone().into_os_string()), None);
        while client.status().is_err() {
            std::thread::sleep(Duration::from_micros(200));
        }
        locked.push(start.elapsed());
        let _ = child.kill();
        let _ = child.wait();
    }
    println!(
        "- locked agent, empty profile: socket listening after {:.1} ms, first status reply after {:.1} ms (median of 10)",
        ms(median(listening)),
        ms(median(locked))
    );

    // (b) An agent that starts unlocked from a plain device_keys (seals it first).
    let mut unlocked = Vec::new();
    for _ in 0..5 {
        unlocked.push(RealAgent::start(EncryptionMode::On, None).started);
    }
    println!(
        "- agent starting unlocked from a plain device_keys (seals it under a new storage key, fsyncs): first unlocked status after {:.1} ms (median of 5)",
        ms(median(unlocked))
    );

    // (c) The client's autostart path (what the first encrypted command after boot does).
    let mut first = Vec::new();
    let mut to_locked_error = Vec::new();
    for _ in 0..5 {
        let dir = short_dir();
        let home = dir.path().join("h");
        let run = dir.path().join("r");
        std::fs::create_dir_all(&home).unwrap();
        private_dir(&run);
        let config = home.join(".config").join("atem");
        let paths = CredPaths::in_dir(&config);
        let children: Arc<Mutex<Vec<std::process::Child>>> = Arc::default();
        let spawned = children.clone();
        let (h, r, log) = (home.clone(), run.clone(), dir.path().join("a.log"));
        let client = CredAgentClient::with_launcher(
            paths.agent_sock(Some(run.as_path())),
            Box::new(move || {
                spawned
                    .lock()
                    .unwrap()
                    .push(spawn_agent(&h, &r, &log, None));
                Ok(())
            }),
        );
        let start = Instant::now();
        client.status().unwrap();
        first.push(start.elapsed());
        let start = Instant::now();
        let failed = CredAgentClient::for_paths(&paths, Some(run.clone().into_os_string()), None)
            .crypt(ASTATION_ID, vec![CryptOp::seal("m", "content", b"x")]);
        assert!(failed.is_err());
        to_locked_error.push(start.elapsed());
        for mut child in children.lock().unwrap().drain(..) {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
    println!(
        "- client autostart (no agent running): first status after {:.1} ms (spawn + the client's polls); then a Crypt is refused (locked) in {:.2} ms",
        ms(median(first)),
        ms(median(to_locked_error))
    );

    // (d) Unlock, agent side only (Astation's Touch ID and the network are not measured).
    println!("\n### 5'. Unlock and storage-key rotation, agent side (in-process), median of 10");
    let mut phases: BTreeMap<&str, Vec<Duration>> = BTreeMap::new();
    for _ in 0..10 {
        let dir = tempfile::tempdir().unwrap();
        let mut device = UnlockedDevice::new(dir.path());
        device.set_key(EncryptionMode::On, KID, KEY);
        device.agent.lock_keys().unwrap();
        let t = Instant::now();
        let challenge = device.agent.begin_unlock(ASTATION_ID).unwrap();
        phases
            .entry("agent begin_unlock (ephemeral key, challenge)")
            .or_default()
            .push(t.elapsed());
        let t = Instant::now();
        let unlock_auth = UnlockAuthKey::load_from(&device.paths.unlock_auth_key)
            .unwrap()
            .unwrap();
        let request = build_unlock_request(&challenge, "boot-1", 1_760_000_000, &unlock_auth);
        phases
            .entry("CLI signs the unlock request")
            .or_default()
            .push(t.elapsed());
        let t = Instant::now();
        let grant = device.server.grant_unlock(&request).unwrap();
        phases
            .entry("(fake Astation grants; not Atem's cost)")
            .or_default()
            .push(t.elapsed());
        let t = Instant::now();
        device
            .agent
            .finish_unlock(ASTATION_ID, &request.statement, &grant)
            .unwrap();
        phases
            .entry("agent finish_unlock (open grant + sealed file with K)")
            .or_default()
            .push(t.elapsed());
        let t = Instant::now();
        let rotation = device.agent.begin_rotation(ASTATION_ID).unwrap();
        phases
            .entry("agent begin_rotation (write .next, fsync, sign)")
            .or_default()
            .push(t.elapsed());
        let ack = device.server.accept_rotation(&rotation).unwrap();
        let t = Instant::now();
        let (_, confirm) = device.agent.confirm_rotation(ASTATION_ID, &ack).unwrap();
        phases
            .entry("agent confirm_rotation (renames, state.json)")
            .or_default()
            .push(t.elapsed());
        device.server.confirm(&confirm).unwrap();
        let t = Instant::now();
        device
            .agent
            .crypt(ASTATION_ID, vec![CryptOp::seal("m", "content", b"x")])
            .unwrap();
        phases
            .entry("first Crypt after unlock")
            .or_default()
            .push(t.elapsed());
    }
    for (phase, samples) in phases {
        println!("- {phase}: {:.2} ms", ms(median(samples)));
    }

    // (e) Memory of the agent process.
    println!("\n### 5''. Agent process memory (VmRSS / VmHWM, KiB)");
    for (label, memlock) in [
        (
            "mlockall on (this machine's RLIMIT_MEMLOCK ≥ 512 MiB)",
            None,
        ),
        (
            "RLIMIT_MEMLOCK 8 MiB (the usual default: no mlockall)",
            Some(8u64 << 20),
        ),
    ] {
        let dir = short_dir();
        let home = dir.path().join("h");
        let run = dir.path().join("r");
        std::fs::create_dir_all(&home).unwrap();
        private_dir(&run);
        let paths = CredPaths::in_dir(&home.join(".config").join("atem"));
        let mut child = spawn_agent(&home, &run, &dir.path().join("a.log"), memlock);
        let client = CredAgentClient::for_paths(&paths, Some(run.clone().into_os_string()), None);
        while client.status().is_err() {
            std::thread::sleep(Duration::from_millis(1));
        }
        std::thread::sleep(Duration::from_millis(50));
        let idle_locked = rss_kib(child.id());
        let _ = child.kill();
        let _ = child.wait();
        let real = RealAgent::start(EncryptionMode::On, memlock);
        std::thread::sleep(Duration::from_millis(50));
        let with_k = rss_kib(real.pid());
        let client = real.reuse();
        let plain = text(100, 1).into_bytes();
        client
            .crypt(
                ASTATION_ID,
                (0..1024)
                    .map(|_| CryptOp::seal("m", "content", &plain))
                    .collect(),
            )
            .unwrap();
        let after_batch = rss_kib(real.pid());
        let big = text(1 << 20, 2).into_bytes();
        let sealed = client
            .crypt(ASTATION_ID, vec![CryptOp::seal("v", "content", &big)])
            .unwrap()
            .remove(0)
            .into_text()
            .unwrap();
        client
            .crypt(ASTATION_ID, vec![CryptOp::open("v", "content", &sealed)])
            .unwrap();
        let after_mib = rss_kib(real.pid());
        let huge = text(2 << 20, 3).into_bytes();
        client
            .crypt(ASTATION_ID, vec![CryptOp::seal("v", "content", &huge)])
            .unwrap();
        let after_2mib = rss_kib(real.pid());
        for _ in 0..20 {
            client
                .crypt(ASTATION_ID, vec![CryptOp::seal("v", "content", &big)])
                .unwrap();
        }
        let after_20 = rss_kib(real.pid());
        let threads = std::fs::read_dir(format!("/proc/{}/task", real.pid()))
            .map(|d| d.count())
            .unwrap_or(0);
        println!(
            "- {label}: idle locked {:?}; unlocked with K {:?}; after a 1024-op batch {:?}; after 1 MiB seal+open {:?}; after a 2 MiB seal {:?}; after 20 more 1 MiB seals {:?}; {threads} threads",
            idle_locked, with_k, after_batch, after_mib, after_2mib, after_20
        );
    }

    // (f) A cold `atem memory search` touches no agent: the local FTS query alone.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("knowledge.db");
    {
        let store = Store::open(&path).unwrap();
        store
            .in_transaction(|| {
                for memory in (0..5000).map(fact) {
                    store.upsert_memory(&memory)?;
                }
                Ok(())
            })
            .unwrap();
    }
    let search = bench(20, || {
        let store = Store::open(&path).unwrap();
        std::hint::black_box(
            store
                .search_memories(&SearchQuery {
                    text: "staging deploy".into(),
                    scope: None,
                    project: None,
                    history: false,
                    limit: 20,
                })
                .unwrap(),
        );
    });
    println!(
        "\n- `atem memory search` work on 5,000 facts (open knowledge.db + FTS query; no cred agent involved): {:.2} ms",
        ms(search)
    );
}

/// Kills the detached agents a test started, even when it panics.
struct Detached(Vec<u32>);

impl Drop for Detached {
    fn drop(&mut self) {
        for pid in &self.0 {
            unsafe { libc::kill(*pid as i32, libc::SIGKILL) };
        }
    }
}

/// What a client's launcher does in production (`agent_socket::spawn_agent`,
/// the detached spawn of `daemon`), with only HOME, XDG_RUNTIME_DIR and PATH
/// set (temp dirs); the pid goes on `started`.
fn detached_launcher(
    home: &Path,
    run: &Path,
    log: &Path,
    started: Arc<Mutex<Detached>>,
) -> Box<dyn Fn() -> anyhow::Result<()> + Send + Sync> {
    let (home, run, log) = (home.to_path_buf(), run.to_path_buf(), log.to_path_buf());
    Box::new(move || {
        let envs = [
            ("HOME".into(), home.clone().into_os_string()),
            ("XDG_RUNTIME_DIR".into(), run.clone().into_os_string()),
            ("PATH".into(), "/usr/bin:/bin".into()),
        ];
        let pid = crate::daemon::spawn_detached_clean(
            &atem_binary(),
            "cred-agent",
            Path::new("/"),
            &log,
            &envs,
        )?;
        started.lock().unwrap().0.push(pid);
        Ok(())
    })
}

/// F7: from the spawn of an agent to a client's first contact with it.
/// Three clocks per run, each from just before the (detached) spawn:
/// the socket accepting connections, a client that starts the agent getting
/// its first `status` reply, and a command as production makes it (the
/// build check on the connection, then a `Crypt` that the locked agent
/// refuses).
#[test]
#[ignore]
fn perf_5c_cold_autostart_first_contact() {
    println!(
        "\n## 5c. Cold autostart: first contact after the spawn (detached spawn, release agent)"
    );
    let build = RealAgent::start(EncryptionMode::On, None).build.clone();
    let runs = 30;
    let mut listening = Vec::new();
    let mut first_status = Vec::new();
    let mut command = Vec::new();
    for _ in 0..runs {
        let started = Arc::new(Mutex::new(Detached(Vec::new())));
        // (i) the socket accepting connections (a raw 200 µs poll).
        {
            let dir = short_dir();
            let (home, run) = (dir.path().join("h"), dir.path().join("r"));
            std::fs::create_dir_all(&home).unwrap();
            private_dir(&run);
            let paths = CredPaths::in_dir(&home.join(".config").join("atem"));
            let socket = paths.agent_sock(Some(run.as_path()));
            let launch = detached_launcher(&home, &run, &dir.path().join("a.log"), started.clone());
            let start = Instant::now();
            launch().unwrap();
            while std::os::unix::net::UnixStream::connect(&socket).is_err() {
                assert!(start.elapsed() < Duration::from_secs(10), "no agent");
                std::thread::sleep(Duration::from_micros(200));
            }
            listening.push(start.elapsed());
        }
        // (ii) a client that starts the agent: its first `status` reply.
        // (iii) a command: build check, then a `Crypt` the locked agent refuses.
        for (clock, checked) in [(&mut first_status, false), (&mut command, true)] {
            let dir = short_dir();
            let (home, run) = (dir.path().join("h"), dir.path().join("r"));
            std::fs::create_dir_all(&home).unwrap();
            private_dir(&run);
            let paths = CredPaths::in_dir(&home.join(".config").join("atem"));
            let launch = detached_launcher(&home, &run, &dir.path().join("a.log"), started.clone());
            let mut client =
                CredAgentClient::with_launcher(paths.agent_sock(Some(run.as_path())), launch);
            if checked {
                client = client.checking_build(&build);
            }
            let start = Instant::now();
            if checked {
                assert!(
                    client
                        .crypt(ASTATION_ID, vec![CryptOp::seal("m", "content", b"x")])
                        .is_err()
                );
            } else {
                client.status().unwrap();
            }
            clock.push(start.elapsed());
        }
        drop(started);
    }
    let spread = |samples: &[Duration]| {
        let mut sorted = samples.to_vec();
        sorted.sort();
        format!(
            "median {:.1} ms, min {:.1}, p90 {:.1}, max {:.1}",
            ms(median(samples.to_vec())),
            ms(sorted[0]),
            ms(sorted[sorted.len() * 9 / 10]),
            ms(*sorted.last().unwrap())
        )
    };
    println!(
        "- spawn to socket accepting connections ({runs} runs): {}",
        spread(&listening)
    );
    println!(
        "- spawn to a starting client's first `status` reply: {}",
        spread(&first_status)
    );
    println!(
        "- cold command (build check + refused `Crypt`, locked agent): {}",
        spread(&command)
    );
    // Startup alone, with and without `mlockall` (RLIMIT_MEMLOCK 8 MiB: no
    // lock), to see what the lock costs.
    let mut unlocked_limit = Vec::new();
    for _ in 0..runs {
        let dir = short_dir();
        let (home, run) = (dir.path().join("h"), dir.path().join("r"));
        std::fs::create_dir_all(&home).unwrap();
        private_dir(&run);
        let paths = CredPaths::in_dir(&home.join(".config").join("atem"));
        let socket = paths.agent_sock(Some(run.as_path()));
        let start = Instant::now();
        let mut child = spawn_agent(&home, &run, &dir.path().join("a.log"), Some(8 << 20));
        while std::os::unix::net::UnixStream::connect(&socket).is_err() {
            assert!(start.elapsed() < Duration::from_secs(10), "no agent");
            std::thread::sleep(Duration::from_micros(200));
        }
        unlocked_limit.push(start.elapsed());
        let _ = child.kill();
        let _ = child.wait();
    }
    println!(
        "- spawn to socket accepting connections, RLIMIT_MEMLOCK 8 MiB (no mlockall; plain spawn): {}",
        spread(&unlocked_limit)
    );
}

// ───────────────────────── 6. Sizes ─────────────────────────

#[test]
#[ignore]
fn perf_6_ciphertext_sizes() {
    let dir = tempfile::tempdir().unwrap();
    let mut device = UnlockedDevice::new(dir.path());
    device.set_key(EncryptionMode::On, KID, KEY);
    let context =
        EncryptionContext::for_astation_with(ASTATION_ID, &device.paths, device.agent.clone())
            .unwrap();
    println!("\n## 6. Sizes");
    println!("### 6a. One memory add op on the wire (JSON), project-scoped");
    println!("| content B | plain e1 field B | ratio | op JSON off B | op JSON on B | op ratio |");
    println!("|---|---|---|---|---|---|");
    for size in [32usize, 100, 200, 400, 1000, 4000] {
        let mut memory = fact(0);
        memory.content = text(size, 5);
        memory.content_hash = content_hash(&memory.content);
        let off = serde_json::to_vec(&op_to_wire(&PendingOp::AddMemory {
            memory: memory.clone(),
        }))
        .unwrap()
        .len();
        let sealed = context
            .encrypt_memories(vec![memory.clone()])
            .unwrap()
            .remove(0);
        let on = serde_json::to_vec(&json!({"op": "add", "memory": sealed}))
            .unwrap()
            .len();
        println!(
            "| {size} | {} | {:.2} | {off} | {on} | {:.2} |",
            sealed.content.len(),
            sealed.content.len() as f64 / size as f64,
            on as f64 / off as f64
        );
    }
    let sealed = context.encrypt_memories(vec![fact(0)]).unwrap().remove(0);
    println!(
        "- content_hash: {} B plain (hex SHA-256) → {} B (`h1.<kid>.<hex HMAC>`); project `github.com/agora/atem` ({} B) → {} B",
        content_hash("x").len(),
        sealed.content_hash.len(),
        "github.com/agora/atem".len(),
        sealed.project.len()
    );

    println!(
        "\n### 6b. One skill file (push op JSON; files are base64 on the wire, so a sealed file is base64 of the e1 text)"
    );
    println!(
        "| file B | path B plain→sealed | stored file B (e1 text) | ratio | push JSON off B | push JSON on B | wire ratio |"
    );
    println!("|---|---|---|---|---|---|---|");
    for size in [1usize << 10, 4 << 10, 64 << 10, 1 << 20] {
        let files = BTreeMap::from([("SKILL.md".to_string(), text(size, 6).into_bytes())]);
        let skill = Skill {
            content_hash: skill_hash(&files),
            files,
            ..skill(0, 1, 1)
        };
        let off = serde_json::to_vec(&op_to_wire(&PendingOp::PushSkill {
            skill: skill.clone(),
            base_version: 0,
        }))
        .unwrap()
        .len();
        let sealed = context.encrypt_skills(vec![skill]).unwrap().remove(0);
        let (path, bytes) = sealed.files.iter().next().unwrap();
        let on = serde_json::to_vec(&json!({"op": "push", "skill": sealed, "base_version": 0}))
            .unwrap()
            .len();
        println!(
            "| {size} | 8→{} | {} | {:.2} | {off} | {on} | {:.2} |",
            path.len(),
            bytes.len(),
            bytes.len() as f64 / size as f64,
            on as f64 / off as f64
        );
    }

    println!("\n### 6c. One vault write body and one cred-agent request/reply line");
    println!(
        "| entry B | write body off B | write body on B | ratio | Crypt seal request line B | its reply B | Crypt open reply B |"
    );
    println!("|---|---|---|---|---|---|---|");
    for size in [1usize << 10, 64 << 10, 1 << 20] {
        let payload = text(size, 7);
        let off = serde_json::to_vec(
            &crate::vault_client::write_vault_request("https://r", "c", "v-1", &payload, Some(1))
                .body
                .unwrap(),
        )
        .unwrap()
        .len();
        let sealed = context.seal("v-1", "content", payload.as_bytes()).unwrap();
        let on = serde_json::to_vec(
            &crate::vault_client::write_vault_request("https://r", "c", "v-1", &sealed, Some(1))
                .body
                .unwrap(),
        )
        .unwrap()
        .len();
        let request = encode_request(&Request::Crypt {
            astation_id: ASTATION_ID.into(),
            ops: vec![CryptOp::seal("v-1", "content", payload.as_bytes())],
        })
        .unwrap()
        .len();
        let reply = serde_json::to_vec(&json!({"v": 2, "ok": true, "reply": {"kind": "crypted", "results": [{"sealed": sealed}]}})).unwrap().len();
        let opened = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            payload.as_bytes(),
        );
        let open_reply = serde_json::to_vec(&json!({"v": 2, "ok": true, "reply": {"kind": "crypted", "results": [{"opened": opened}]}})).unwrap().len();
        println!(
            "| {size} | {off} | {on} | {:.3} | {request} | {reply} | {open_reply} |",
            on as f64 / off as f64
        );
    }
    // Formula check.
    for n in [0usize, 100, 1000] {
        let sealed = context.seal("r", "f", &vec![b'a'; n.max(1)]).unwrap();
        println!(
            "- e1 length for {} B: {} (formula 12 + 4·⌈(n+40)/3⌉ = {})",
            n.max(1),
            sealed.len(),
            12 + 4 * (n.max(1) + 40).div_ceil(3)
        );
    }
}

// ───────────────────────── a check found while reading ─────────────────────────

/// A project-scoped fact from a project this device never hashed fails the
/// whole pulled page (UNKNOWN_PROJECT), so the cursor never moves.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn perf_x_an_unknown_project_hash_stops_the_pull() {
    let relay = Relay::start();
    let dir = tempfile::tempdir().unwrap();
    let mut device = UnlockedDevice::new(dir.path());
    device.set_key(EncryptionMode::On, KID, KEY);
    let other_dir = tempfile::tempdir().unwrap();
    // Another device of the same account (same K), which used a project this one never did.
    let mut other = UnlockedDevice::new(other_dir.path());
    other.set_key(EncryptionMode::On, KID, KEY);
    {
        let context =
            EncryptionContext::for_astation_with(ASTATION_ID, &other.paths, other.agent.clone())
                .unwrap();
        let mut memories: Vec<Memory> = (0..10).map(fact).collect();
        memories[3].project = "github.com/agora/only-elsewhere".into();
        memories[3].scope = Scope::Project;
        let sealed = context.encrypt_memories(memories).unwrap();
        let mut data = relay.data.lock().unwrap();
        for memory in sealed {
            data.put_memory(memory);
        }
    }
    // This device knows github.com/agora/atem (it pushed there), not the other project.
    EncryptionContext::for_astation_with(ASTATION_ID, &device.paths, device.agent.clone())
        .unwrap()
        .wire_project("github.com/agora/atem")
        .unwrap();
    let knowledge = relay.knowledge(&device.paths, device.agent.clone() as Arc<dyn CredAgentApi>);
    let error = knowledge.pull_memories(0).await.unwrap_err().to_string();
    println!("\npull of 10 facts with one from an unknown project: {error}");
    assert!(error.contains("unknown on this Atem"));
}

// ───────────────────────── 1d. Where a large field's time goes ─────────────────────────

/// Median time of `f` on a fresh `setup()` value; what `f` returns is dropped
/// outside the timed region.
fn timed<S, R>(reps: usize, mut setup: impl FnMut() -> S, mut f: impl FnMut(S) -> R) -> Duration {
    median(
        (0..reps)
            .map(|_| {
                let input = setup();
                let start = Instant::now();
                let out = f(input);
                let elapsed = start.elapsed();
                drop(out);
                elapsed
            })
            .collect(),
    )
}

/// Replays, in this process, each step a large `seal` takes on its way
/// through the socket path (client encode → agent read/parse/crypt/encode →
/// client read/parse), with the real functions where they are reachable.
/// Socket writes/reads and task wake-ups are not included.
#[test]
#[ignore]
fn perf_1d_large_field_breakdown() {
    use crate::memory::agent_socket::{decode_request, decode_response};
    use crate::memory::encoding::WipingBuf;
    let mut keys = AccountKeys::default();
    keys.install(ACCOUNT, KID, Zeroizing::new(KEY));
    for size in [64usize << 10, 1 << 20] {
        let plain = text(size, 11).into_bytes();
        let reps = 21;
        let request = || Request::Crypt {
            astation_id: ASTATION_ID.into(),
            ops: vec![CryptOp::seal("v-1", "content", &plain)],
        };
        let line = encode_request(&request()).unwrap();
        let bytes = line.as_bytes().to_vec();
        let text_line = line.trim_end().to_string();
        let results = keys
            .crypt(
                ACCOUNT,
                EncryptionMode::On,
                Some(KID),
                vec![CryptOp::seal("v-1", "content", &plain)],
            )
            .unwrap();
        let sealed = results.into_iter().next().unwrap().into_text().unwrap();
        let reply_value = json!({"v": 2, "ok": true, "reply": {"kind": "crypted", "results": [{"sealed": sealed}]}});
        let reply_line = serde_json::to_string(&reply_value).unwrap() + "\n";
        let reply_bytes = reply_line.as_bytes().to_vec();
        let read_loop = |input: &[u8]| {
            let mut pending = WipingBuf::new();
            for chunk in input.chunks(4096) {
                pending.append(chunk);
            }
            let end = pending.0.len() - 1;
            let copied = Zeroizing::new(pending.0.drain(..=end).collect::<Vec<u8>>());
            assert!(std::str::from_utf8(&copied[..end]).is_ok());
            (pending, copied)
        };
        let steps: Vec<(&str, Duration)> = vec![
            (
                "client: CryptOp::seal (base64 of the plain text)",
                timed(reps, || (), |_| request()),
            ),
            (
                "client: encode_request (JSON into a growing WipingBuf)",
                timed(reps, request, |r| (encode_request(&r).unwrap(), r)),
            ),
            (
                "client: wipe the request's base64 plain text",
                timed(reps, request, drop),
            ),
            (
                "client: wipe the request line after writing it",
                timed(reps, || encode_request(&request()).unwrap(), drop),
            ),
            (
                "agent: 4 KiB reads into a growing WipingBuf, line copied out, UTF-8 check",
                timed(reps, || (), |_| read_loop(&bytes)),
            ),
            (
                "agent: wipe the read buffer and the line copy",
                timed(reps, || read_loop(&bytes), drop),
            ),
            (
                "agent: decode_request (a RequestHead pass over the whole line, then CryptWire)",
                timed(reps, || (), |_| decode_request(&text_line).unwrap()),
            ),
            (
                "agent: AccountKeys::crypt (base64 decode, AEAD, base64 encode, wipe plain text and its base64)",
                timed(
                    reps,
                    || vec![CryptOp::seal("v-1", "content", &plain)],
                    |ops| {
                        keys.crypt(ACCOUNT, EncryptionMode::On, Some(KID), ops)
                            .unwrap()
                    },
                ),
            ),
            (
                "agent: serialize the reply into a growing WipingBuf",
                timed(
                    reps,
                    || (),
                    |_| {
                        let mut buf = WipingBuf::new();
                        serde_json::to_writer(&mut buf, &reply_value).unwrap();
                        buf
                    },
                ),
            ),
            (
                "agent: wipe the reply buffer",
                timed(
                    reps,
                    || {
                        let mut buf = WipingBuf::new();
                        serde_json::to_writer(&mut buf, &reply_value).unwrap();
                        buf
                    },
                    drop,
                ),
            ),
            (
                "client: read_reply (4 KiB reads into a growing WipingBuf)",
                timed(
                    reps,
                    || (),
                    |_| {
                        let mut buf = WipingBuf::new();
                        for chunk in reply_bytes.chunks(4096) {
                            buf.append(chunk);
                        }
                        buf
                    },
                ),
            ),
            (
                "client: decode_response (a ResponseHead pass, then CryptedResponse)",
                timed(reps, || (), |_| decode_response(&reply_line).unwrap()),
            ),
            (
                "client: wipe the reply buffer",
                timed(
                    reps,
                    || {
                        let mut buf = WipingBuf::new();
                        buf.append(&reply_bytes);
                        buf
                    },
                    drop,
                ),
            ),
        ];
        let total: Duration = steps.iter().map(|(_, d)| *d).sum();
        println!(
            "\n## 1d. A {} KiB seal through the JSON line path, step by step (median of {reps}; sum {:.2} ms; socket I/O and wake-ups not included)",
            size >> 10,
            ms(total)
        );
        println!("| step | ms | share |");
        println!("|---|---|---|");
        for (step, d) in &steps {
            println!(
                "| {step} | {:.3} | {:.0}% |",
                ms(*d),
                d.as_secs_f64() / total.as_secs_f64() * 100.0
            );
        }
        let wipes: Duration = steps
            .iter()
            .filter(|(step, _)| step.starts_with("client: wipe") || step.starts_with("agent: wipe"))
            .map(|(_, d)| *d)
            .sum();
        println!(
            "- the wipe-only steps: {:.2} ms ({:.0}%), not counting the wipes inside AccountKeys::crypt and at each WipingBuf growth",
            ms(wipes),
            wipes.as_secs_f64() / total.as_secs_f64() * 100.0
        );
    }
}

/// Diagnostic: per-request latency of the fake relay by body size (Off).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn perf_y_relay_latency_by_body_size() {
    let relay = Relay::start();
    let dir = tempfile::tempdir().unwrap();
    let mut device = UnlockedDevice::new(dir.path());
    device.state(EncryptionMode::Off, None);
    let knowledge = relay.knowledge(&device.paths, device.agent.clone() as Arc<dyn CredAgentApi>);
    for ops_n in [1usize, 5, 10, 20, 30, 40, 50] {
        let ops: Vec<PendingOp> = (0..ops_n)
            .map(|i| PendingOp::AddMemory { memory: fact(i) })
            .collect();
        let refs: Vec<&PendingOp> = ops.iter().collect();
        let mut samples = Vec::new();
        for _ in 0..9 {
            let start = Instant::now();
            knowledge.push(&refs, true).await.unwrap();
            samples.push(start.elapsed());
        }
        let bytes =
            serde_json::to_vec(&json!({"ops": ops.iter().map(op_to_wire).collect::<Vec<_>>()}))
                .unwrap()
                .len();
        let mut sorted = samples.clone();
        sorted.sort();
        println!(
            "push of {ops_n} ops ({bytes} B): median {:.2} ms, min {:.2} ms, max {:.2} ms",
            ms(median(samples)),
            ms(sorted[0]),
            ms(sorted[8])
        );
    }
    for rows in [10usize, 100, 200] {
        relay.reset();
        {
            let mut data = relay.data.lock().unwrap();
            for memory in (0..rows).map(fact) {
                data.put_memory(memory);
            }
        }
        let samples: Vec<Duration> = {
            let mut s = Vec::new();
            for _ in 0..9 {
                let start = Instant::now();
                knowledge.pull_memories(0).await.unwrap();
                s.push(start.elapsed());
            }
            s
        };
        println!("pull of {rows} rows: median {:.2} ms", ms(median(samples)));
    }
}

/// Diagnostic: where a pulled page's non-agent time goes (in-process agent).
#[test]
#[ignore]
fn perf_z_pull_page_client_costs() {
    let dir = tempfile::tempdir().unwrap();
    let mut device = UnlockedDevice::new(dir.path());
    device.set_key(EncryptionMode::On, KID, KEY);
    let (agent, counts) = metered(device.agent.clone() as Arc<dyn CredAgentApi>);
    let context = EncryptionContext::for_astation_with(ASTATION_ID, &device.paths, agent).unwrap();
    let plain: Vec<Memory> = (0..200).map(fact).collect();
    let sealed = context.encrypt_memories(plain.clone()).unwrap();
    let plain_json = serde_json::to_vec(&json!({"memories": plain})).unwrap();
    let sealed_json = serde_json::to_vec(&json!({"memories": sealed})).unwrap();
    let parse_plain = bench(21, || {
        std::hint::black_box(serde_json::from_slice::<Value>(&plain_json).unwrap());
    });
    let parse_sealed = bench(21, || {
        std::hint::black_box(serde_json::from_slice::<Value>(&sealed_json).unwrap());
    });
    counts.reset();
    let decrypt = bench(21, || {
        std::hint::black_box(context.decrypt_memories(sealed.clone()).unwrap());
    });
    let agent_per = counts.agent_time() / 22;
    let hashes = bench(21, || {
        for m in &plain {
            std::hint::black_box(content_hash(&m.content));
        }
    });
    let names = bench(21, || {
        std::hint::black_box(
            crate::memory::project_names::ProjectNames::load_from(&device.paths.project_names)
                .unwrap(),
        );
    });
    println!(
        "\n200-row page: JSON parse {:.2} ms plain vs {:.2} ms sealed ({} vs {} B); decrypt_memories {:.2} ms of which agent {:.2} ms; content_hash recompute {:.2} ms; project_names load {:.3} ms",
        ms(parse_plain),
        ms(parse_sealed),
        plain_json.len(),
        sealed_json.len(),
        ms(decrypt),
        ms(agent_per),
        ms(hashes),
        ms(names)
    );
    let ops: Vec<PendingOp> = plain
        .iter()
        .take(50)
        .cloned()
        .map(|memory| PendingOp::AddMemory { memory })
        .collect();
    counts.reset();
    let encrypt = bench(21, || {
        std::hint::black_box(
            context
                .encrypt_memories(
                    ops.iter()
                        .map(|op| match op {
                            PendingOp::AddMemory { memory } => memory.clone(),
                            _ => unreachable!(),
                        })
                        .collect(),
                )
                .unwrap(),
        );
    });
    println!(
        "50-memory push chunk: encrypt_memories {:.2} ms of which agent {:.2} ms",
        ms(encrypt),
        ms(counts.agent_time() / 22)
    );
}

/// The agent's memory by tokio worker count: what a current-thread agent
/// would save (TOKIO_WORKER_THREADS only sizes the multi-thread runtime).
#[test]
#[ignore]
fn perf_5b_agent_memory_by_worker_threads() {
    println!("\n### 5b. Locked agent at rest by worker threads (VmRSS/VmHWM KiB, threads)");
    for workers in ["16 (default here)", "2", "1"] {
        for (label, memlock) in [("mlockall on", None), ("no mlockall", Some(8u64 << 20))] {
            let dir = short_dir();
            let home = dir.path().join("h");
            let run = dir.path().join("r");
            std::fs::create_dir_all(&home).unwrap();
            private_dir(&run);
            let paths = CredPaths::in_dir(&home.join(".config").join("atem"));
            let count = workers.split(' ').next().unwrap();
            let extra: Vec<(&str, &str)> = if count == "16" {
                vec![]
            } else {
                vec![("TOKIO_WORKER_THREADS", count)]
            };
            let mut child =
                spawn_agent_with(&home, &run, &dir.path().join("a.log"), memlock, &extra);
            let client =
                CredAgentClient::for_paths(&paths, Some(run.clone().into_os_string()), None);
            while client.status().is_err() {
                std::thread::sleep(Duration::from_millis(1));
            }
            std::thread::sleep(Duration::from_millis(50));
            let rss = rss_kib(child.id());
            let threads = std::fs::read_dir(format!("/proc/{}/task", child.id()))
                .map(|d| d.count())
                .unwrap_or(0);
            println!("- workers {workers}, {label}: {:?}, {threads} threads", rss);
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
