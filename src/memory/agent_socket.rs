//! The key agent's Unix socket: newline-delimited JSON, `"v": 2` on every
//! request, same-user peers only. `atem key-agent` serves it; commands that
//! need keys connect, starting the agent when none is running.
//! See designs/e2e-encryption.md "Keys on disk (atem)".
//!
//! Both sides check who is on the other end: the agent refuses peers that
//! aren't its user, and the client refuses a socket whose listener isn't its
//! user (a directory someone else can write to could hold a fake agent that
//! collects keys). The socket's directories must be real (no symlinks), owned
//! by this user and not writable by anyone else.
//!
//! Serialized requests and replies can carry secrets, so they live in
//! `Zeroizing` buffers that are dropped right after use. Nothing here goes
//! through a `serde_json::Value`, a `BufReader`, or serde's internally tagged
//! enum buffering for a message that carries a secret.
use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use zeroize::Zeroizing;

use crate::memory::account_keys::{CryptOp, CryptOut};
use crate::memory::encoding::WipingBuf;
use crate::memory::key_agent::{KeyAgent, KeyAgentApi, PROTOCOL_VERSION, Reply, Request};
use crate::memory::verification::KeyPaths;

/// Bounds a misbehaving peer. A `Crypt` batch is kept under 2 MiB of input by
/// `EncryptionContext`, and one skill (at most 1 MiB, base64 on the wire)
/// always fits.
const MAX_LINE: usize = 8 << 20;
/// A connection that says nothing for this long is dropped.
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

fn own_uid() -> u32 {
    unsafe { libc::getuid() }
}

/// `$XDG_RUNTIME_DIR/atem/agent.sock` when that directory is safe, else
/// `~/.config/atem/agent.sock`.
pub fn agent_socket_path() -> PathBuf {
    socket_path_in(
        &crate::config::AtemConfig::config_dir(),
        std::env::var_os("XDG_RUNTIME_DIR"),
    )
}

/// The socket path for `config_dir` and the runtime dir `runtime_dir`
/// (used only when it is safe).
fn socket_path_in(config_dir: &Path, runtime_dir: Option<OsString>) -> PathBuf {
    // A relative runtime dir would depend on the current directory: unset.
    let runtime = runtime_dir.filter(|dir| {
        Path::new(dir).is_absolute() && check_parent_dir(Path::new(dir), own_uid()).is_ok()
    });
    socket_path_from(runtime, config_dir)
}

fn socket_path_from(runtime_dir: Option<OsString>, config_dir: &Path) -> PathBuf {
    match runtime_dir {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir).join("atem").join("agent.sock"),
        _ => config_dir.join("agent.sock"),
    }
}

pub fn agent_log_path() -> PathBuf {
    crate::config::AtemConfig::config_dir().join("key-agent.log")
}

/// A directory the socket's directory lives in: a real directory (not a
/// symlink) owned by `uid` that nobody else can write to.
fn check_parent_dir(dir: &Path, uid: u32) -> Result<()> {
    let meta = std::fs::symlink_metadata(dir)
        .with_context(|| format!("cannot inspect {}", dir.display()))?;
    if meta.file_type().is_symlink() {
        bail!("{} is a symlink", dir.display());
    }
    if !meta.is_dir() {
        bail!("{} is not a directory", dir.display());
    }
    if meta.uid() != uid {
        bail!("{} is owned by another user", dir.display());
    }
    if meta.mode() & 0o022 != 0 {
        bail!("{} can be written by other users", dir.display());
    }
    Ok(())
}

/// The socket's own directory: created if missing, never a symlink, owned by
/// `uid`; then tightened to 0700.
fn prepare_socket_dir(dir: &Path, uid: u32) -> Result<()> {
    match std::fs::symlink_metadata(dir) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                bail!(
                    "{} is a symlink; refusing to put the key agent socket there",
                    dir.display()
                );
            }
            if !meta.is_dir() {
                bail!("{} is not a directory", dir.display());
            }
            if meta.uid() != uid {
                bail!("{} is owned by another user", dir.display());
            }
            if meta.mode() & 0o022 != 0 {
                // Others could already have planted entries in it.
                bail!(
                    "{} can be written by other users; refusing to use it (make it private with `chmod 700` after checking its contents)",
                    dir.display()
                );
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = dir.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::create_dir(dir)
                .with_context(|| format!("could not create {}", dir.display()))?;
        }
        Err(error) => return Err(error.into()),
    }
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Response {
    v: u64,
    ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reply: Option<Reply>,
}

/// A request with the protocol version added beside its fields.
#[derive(Serialize)]
struct Envelope<'a> {
    #[serde(flatten)]
    request: &'a Request,
    v: u64,
}

fn to_wiping_json<T: Serialize>(value: &T) -> Result<WipingBuf> {
    let mut buf = WipingBuf::new();
    serde_json::to_writer(&mut buf, value)?;
    buf.append(b"\n");
    Ok(buf)
}

pub(crate) fn encode_request(request: &Request) -> Result<Zeroizing<String>> {
    let mut buf = to_wiping_json(&Envelope {
        request,
        v: PROTOCOL_VERSION,
    })?;
    let text = String::from_utf8(std::mem::take(&mut *buf.0))
        .map_err(|_| anyhow!("key agent request is not UTF-8"))?;
    Ok(Zeroizing::new(text))
}

#[derive(Deserialize)]
struct RequestHead {
    v: Option<u64>,
    op: Option<String>,
}

/// `load_unlocked` carries the device secrets: parsed straight from the line
/// (the tagged `Request` would buffer them in serde's unwiped `Content`).
#[derive(Deserialize)]
struct LoadUnlockedWire {
    device_id: String,
    device: Zeroizing<String>,
    device_sign: Zeroizing<String>,
    unlock_auth: Zeroizing<String>,
    storage_kid: String,
    storage_key: Zeroizing<String>,
}

/// `crypt` carries plain text to seal or hash: parsed straight from the
/// line into `Zeroizing` fields (`CryptOp` is externally tagged).
#[derive(Deserialize)]
struct CryptWire {
    astation_id: String,
    ops: Vec<CryptOp>,
}

pub(crate) fn decode_request(line: &str) -> Result<Request> {
    let head: RequestHead = serde_json::from_str(line).context("key agent request is not JSON")?;
    match head.v {
        Some(PROTOCOL_VERSION) => {}
        other => bail!(
            "unsupported key agent protocol version {}; this agent speaks v{PROTOCOL_VERSION}",
            other.map_or_else(|| "(none)".to_string(), |v| v.to_string())
        ),
    }
    if head.op.as_deref() == Some("load_unlocked") {
        let wire: LoadUnlockedWire =
            serde_json::from_str(line).context("key agent request is malformed")?;
        return Ok(Request::LoadUnlocked {
            device_id: wire.device_id,
            device: wire.device,
            device_sign: wire.device_sign,
            unlock_auth: wire.unlock_auth,
            storage_kid: wire.storage_kid,
            storage_key: wire.storage_key,
        });
    }
    if head.op.as_deref() == Some("crypt") {
        let wire: CryptWire =
            serde_json::from_str(line).context("key agent request is malformed")?;
        return Ok(Request::Crypt {
            astation_id: wire.astation_id,
            ops: wire.ops,
        });
    }
    serde_json::from_str(line).context("key agent request is malformed")
}

#[derive(Deserialize)]
struct ResponseHead {
    v: u64,
    ok: bool,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    reply: Option<ReplyHead>,
}

/// A reply's `kind`, everything else skipped.
#[derive(Deserialize)]
struct ReplyHead {
    kind: Option<String>,
}

/// The `crypt` reply carries opened plain text: parsed straight from the line.
#[derive(Deserialize)]
struct CryptedResponse {
    reply: CryptedReply,
}

#[derive(Deserialize)]
struct CryptedReply {
    results: Vec<CryptOut>,
}

/// What to do about a running agent of another protocol version.
fn version_mismatch(version: u64) -> anyhow::Error {
    anyhow!(
        "the running key agent speaks protocol v{version}, this atem speaks v{PROTOCOL_VERSION}; check `atem cred status` first (a storage key not yet held by Astation needs `atem cred unlock` from the atem that started the agent), then stop it with `pkill -u \"$USER\" -f 'atem key-agent'` (its keys stay sealed on disk) and retry"
    )
}

pub(crate) fn decode_response(line: &str) -> Result<Reply> {
    let line = line.trim();
    let head: ResponseHead =
        serde_json::from_str(line).context("the key agent sent an unreadable reply")?;
    if head.v != PROTOCOL_VERSION {
        return Err(version_mismatch(head.v));
    }
    if !head.ok {
        bail!(
            "{}",
            head.error
                .unwrap_or_else(|| "the key agent refused the request".into())
        );
    }
    let Some(reply) = head.reply else {
        bail!("the key agent sent an empty reply");
    };
    if reply.kind.as_deref() == Some("crypted") {
        let crypted: CryptedResponse =
            serde_json::from_str(line).context("the key agent sent an unreadable reply")?;
        return Ok(Reply::Crypted {
            results: crypted.reply.results,
        });
    }
    let response: Response =
        serde_json::from_str(line).context("the key agent sent an unreadable reply")?;
    response
        .reply
        .ok_or_else(|| anyhow!("the key agent sent an empty reply"))
}

fn respond(agent: &Mutex<KeyAgent>, line: &str) -> WipingBuf {
    let response = match decode_request(line).and_then(|request| agent.call(request)) {
        Ok(reply) => Response {
            v: PROTOCOL_VERSION,
            ok: true,
            error: None,
            reply: Some(reply),
        },
        Err(error) => Response {
            v: PROTOCOL_VERSION,
            ok: false,
            error: Some(format!("{error:#}")),
            reply: None,
        },
    };
    to_wiping_json(&response).unwrap_or_else(|_| {
        let mut buf = WipingBuf::new();
        buf.append(
            b"{\"v\":2,\"ok\":false,\"error\":\"the key agent could not encode its reply\"}\n",
        );
        buf
    })
}

/// Another key agent holds a lock or answers on the socket.
#[derive(Debug)]
pub struct AlreadyRunning(String);

impl AlreadyRunning {
    fn at(socket: &Path) -> Self {
        Self(format!("at {}", socket.display()))
    }
}

impl std::fmt::Display for AlreadyRunning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "a key agent is already running {}", self.0)
    }
}

impl std::error::Error for AlreadyRunning {}

/// Lock files of the agents this process serves; held until it exits.
static HELD_LOCKS: Mutex<Vec<std::fs::File>> = Mutex::new(Vec::new());

/// An exclusive lock on `agent.lock` beside the socket, so two agents starting
/// together can't both replace the socket. Waits briefly for a starting agent.
fn lock_agent(socket: &Path) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let lock_path = socket.with_file_name("agent.lock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&lock_path)
        .with_context(|| {
            format!(
                "could not open {} (a symlink there is refused)",
                lock_path.display()
            )
        })?;
    for attempt in 0..30 {
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(file);
        }
        if UnixStream::connect(socket).is_ok() {
            return Err(AlreadyRunning::at(socket).into());
        }
        if attempt < 29 {
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    Err(AlreadyRunning::at(socket).into())
}

/// How long a starting agent waits for the key directory's lock when the
/// agent holding it answers on no socket: an orphaned agent notices within
/// `ORPHAN_CHECK` and exits.
const CLAIM_WAIT: Duration = Duration::from_secs(8);
/// How often a running agent checks that clients can still reach it.
const ORPHAN_CHECK: Duration = Duration::from_secs(5);
/// How long a client waits for an agent it started.
const START_WAIT: Duration = Duration::from_secs(10);

/// Another agent holds the key directory's lock but answers on no socket
/// (e.g. its runtime dir was removed while it kept running).
#[derive(Debug)]
pub struct StuckAgent(String);

impl std::fmt::Display for StuckAgent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for StuckAgent {}

/// Whether some process holds the key directory's lock (`None` when that
/// can't be told). A shared, non-blocking try: it never waits, and a
/// starting agent that meets it retries for `CLAIM_WAIT`.
fn lock_is_held(lock_path: &Path) -> Option<bool> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(lock_path)
        .ok()?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } == 0 {
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
        return Some(false);
    }
    (std::io::Error::last_os_error().raw_os_error() == Some(libc::EWOULDBLOCK)).then_some(true)
}

/// The pid recorded in the (held) lock file, only when that process is
/// confirmed to be an `atem key-agent`: the pid survives the agent (and
/// reboots), so it may name an unrelated process. Linux: its command line
/// has a `key-agent` argument and, where its fds can be listed (the agent
/// is not dumpable, so usually they can't), one of them is the lock file.
/// Elsewhere nothing can be confirmed.
fn confirmed_holder(lock_path: &Path) -> Option<u32> {
    let pid: u32 = std::fs::read_to_string(lock_path)
        .ok()?
        .trim()
        .parse()
        .ok()?;
    if pid == 0 || unsafe { libc::kill(pid as libc::pid_t, 0) } != 0 {
        return None;
    }
    #[cfg(target_os = "linux")]
    {
        let proc = PathBuf::from(format!("/proc/{pid}"));
        let cmdline = std::fs::read(proc.join("cmdline")).ok()?;
        if !cmdline
            .split(|byte| *byte == 0)
            .any(|arg| arg == b"key-agent")
        {
            return None;
        }
        if let Ok(fds) = std::fs::read_dir(proc.join("fd")) {
            let lock = std::fs::canonicalize(lock_path).ok()?;
            let holds = fds
                .flatten()
                .any(|fd| std::fs::read_link(fd.path()).is_ok_and(|target| target == lock));
            if !holds {
                return None;
            }
        }
        Some(pid)
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// What to say when the key files' agent can't be reached (its lock is
/// held): names the holder's pid when it is confirmed to be a key agent,
/// else how to find and stop one.
fn stuck_message(lock_path: &Path) -> String {
    let dir = lock_path.parent().unwrap_or(Path::new(".")).display();
    match confirmed_holder(lock_path) {
        Some(pid) => format!(
            "a key agent (pid {pid}) holds the key files in {dir} but answers on no socket (its runtime dir may have been removed); stop it with `kill {pid}` and retry (its keys stay sealed on disk)"
        ),
        None => format!(
            "a key agent holds the key files in {dir} but answers on no socket; find it with `pgrep -af '[a]tem key-agent'` and stop it (`pkill -u \"$USER\" -f 'atem key-agent'`), then retry (its keys stay sealed on disk)"
        ),
    }
}

/// An exclusive lock on `paths.agent_lock`, so one agent serves a key
/// directory whatever runtime dir (and so socket path) it was started with:
/// two agents rotating one storage key could each strand the other's files.
/// The holder writes its pid into the lock file. When another agent holds
/// it, this is `AlreadyRunning` as soon as that agent answers on its
/// recorded socket, and `StuckAgent` if it still doesn't after `wait` (an
/// orphaned agent exits by itself well within that, freeing the lock).
/// Held by the returned file until it is dropped or the process exits.
fn lock_key_dir(paths: &KeyPaths, wait: Duration) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let lock_path = &paths.agent_lock;
    if let Some(dir) = lock_path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(lock_path)
        .with_context(|| {
            format!(
                "could not open {} (a symlink there is refused)",
                lock_path.display()
            )
        })?;
    let deadline = std::time::Instant::now() + wait;
    while unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EWOULDBLOCK) {
            return Err(anyhow!(error).context(format!("could not lock {}", lock_path.display())));
        }
        if recorded_socket(&paths.agent_socket)
            .is_some_and(|socket| UnixStream::connect(socket).is_ok())
        {
            return Err(AlreadyRunning(format!(
                "for the key files in {}",
                lock_path.parent().unwrap_or(Path::new(".")).display()
            ))
            .into());
        }
        if std::time::Instant::now() >= deadline {
            return Err(StuckAgent(stuck_message(lock_path)).into());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    file.set_len(0)?;
    file.write_all(format!("{}\n", std::process::id()).as_bytes())?;
    Ok(file)
}

/// Takes the key directory for this agent and listens on `socket`, then
/// records `socket` in `paths.agent_socket` (0600, atomic) for clients that
/// would look elsewhere. The returned lock must live as long as the agent.
pub fn claim(paths: &KeyPaths, socket: &Path) -> Result<(std::fs::File, tokio::net::UnixListener)> {
    claim_waiting(paths, socket, CLAIM_WAIT)
}

fn claim_waiting(
    paths: &KeyPaths,
    socket: &Path,
    wait: Duration,
) -> Result<(std::fs::File, tokio::net::UnixListener)> {
    let lock = lock_key_dir(paths, wait)?;
    let listener = bind(socket)?;
    {
        use std::os::unix::ffi::OsStrExt;
        crate::memory::crypto::write_private(&paths.agent_socket, socket.as_os_str().as_bytes())?;
    }
    Ok((lock, listener))
}

/// What a running agent checks to know clients can still reach it: its
/// socket file is still the one it bound (same inode), and `agent.socket`
/// still names it. When either stops holding (the runtime dir was removed
/// at logout, or the socket replaced), the agent is orphaned: nobody can
/// reach it, and its lock would keep every later agent out.
pub(crate) struct Watch {
    socket: PathBuf,
    record: PathBuf,
    identity: (u64, u64),
    every: Duration,
}

impl Watch {
    /// Watches `socket` (just bound) and the record `record`, every `every`.
    pub(crate) fn new(socket: &Path, record: &Path, every: Duration) -> Result<Self> {
        let meta = std::fs::symlink_metadata(socket)
            .with_context(|| format!("cannot inspect {}", socket.display()))?;
        Ok(Self {
            socket: socket.to_path_buf(),
            record: record.to_path_buf(),
            identity: (meta.dev(), meta.ino()),
            every,
        })
    }

    /// Why the agent can no longer be reached, if it can't.
    /// Only what proves it counts: the socket or the record is NotFound,
    /// the socket is another file, or the record names another path. Any
    /// other error (out of file descriptors, permissions) proves nothing.
    fn orphaned(&self) -> Option<String> {
        match std::fs::symlink_metadata(&self.socket) {
            Ok(meta) if (meta.dev(), meta.ino()) != self.identity => {
                return Some(format!("{} was replaced", self.socket.display()));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Some(format!("{} is gone", self.socket.display()));
            }
            _ => {}
        }
        match read_record(&self.record) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Some(format!("{} is gone", self.record.display()))
            }
            Ok(named) if named.as_deref() != Some(self.socket.as_path()) => Some(format!(
                "{} no longer names {}",
                self.record.display(),
                self.socket.display()
            )),
            _ => None,
        }
    }

    /// Removes the record if it still names this agent's socket and nothing
    /// else listens there now (the lock is still held, so no other agent
    /// can have written it).
    fn clean_up(&self) {
        let replaced = std::fs::symlink_metadata(&self.socket)
            .is_ok_and(|meta| (meta.dev(), meta.ino()) != self.identity);
        if !replaced && recorded_socket(&self.record).as_deref() == Some(self.socket.as_path()) {
            let _ = std::fs::remove_file(&self.record);
        }
    }
}

/// The socket path recorded in `record` by the running agent, if any.
fn recorded_socket(record: &Path) -> Option<PathBuf> {
    read_record(record).ok().flatten()
}

/// `record` read: `Ok(None)` when it names no absolute path.
fn read_record(record: &Path) -> std::io::Result<Option<PathBuf>> {
    use std::os::unix::ffi::OsStrExt;
    let bytes = std::fs::read(record)?;
    let path = PathBuf::from(std::ffi::OsStr::from_bytes(&bytes));
    Ok(path.is_absolute().then_some(path))
}

/// Listens on `socket`: directory 0700, socket 0600. A socket file nobody
/// answers on is left by an agent that died, and is replaced; anything else
/// at that path is left alone and refused. The lock stays held while the
/// process lives.
pub fn bind(socket: &Path) -> Result<tokio::net::UnixListener> {
    bind_as(socket, own_uid())
}

fn bind_as(socket: &Path, uid: u32) -> Result<tokio::net::UnixListener> {
    let dir = socket
        .parent()
        .ok_or_else(|| anyhow!("the agent socket path has no directory"))?;
    prepare_socket_dir(dir, uid)?;
    let lock = lock_agent(socket)?;
    match std::fs::symlink_metadata(socket) {
        Ok(meta) => {
            if !meta.file_type().is_socket() {
                bail!(
                    "{} exists and is not a socket; refusing to replace it",
                    socket.display()
                );
            }
            if UnixStream::connect(socket).is_ok() {
                return Err(AlreadyRunning::at(socket).into());
            }
            std::fs::remove_file(socket)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let listener = tokio::net::UnixListener::bind(socket)
        .with_context(|| format!("could not listen on {}", socket.display()))?;
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;
    if let Ok(mut held) = HELD_LOCKS.lock() {
        held.push(lock);
    }
    Ok(listener)
}

/// Serves `agent` to peers running as `allowed_uid`; others are dropped.
#[cfg(test)]
pub async fn serve(
    listener: tokio::net::UnixListener,
    agent: Arc<Mutex<KeyAgent>>,
    allowed_uid: u32,
) -> Result<()> {
    serve_watched(listener, agent, allowed_uid, None).await
}

/// `serve`, and with a `watch`, checks every `watch.every` that clients can
/// still reach the agent; once they can't, wipes its keys and returns.
pub(crate) async fn serve_watched(
    listener: tokio::net::UnixListener,
    agent: Arc<Mutex<KeyAgent>>,
    allowed_uid: u32,
    watch: Option<Watch>,
) -> Result<()> {
    let mut checks = tokio::time::interval(
        watch
            .as_ref()
            .map_or(Duration::from_secs(3600), |w| w.every),
    );
    checks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            _ = checks.tick(), if watch.is_some() => {
                if let Some(watch) = &watch
                    && let Some(why) = watch.orphaned()
                {
                    eprintln!("key agent: {why}; no client can reach this agent, so it wipes its keys and exits");
                    if let Ok(mut agent) = agent.lock() {
                        let _ = agent.handle(Request::Lock);
                    }
                    watch.clean_up();
                    return Ok(());
                }
                continue;
            }
        };
        let stream = match accepted {
            Ok((stream, _)) => stream,
            Err(error) => {
                // e.g. out of file descriptors: keep serving once there is room.
                eprintln!("key agent: accept failed: {error}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let agent = agent.clone();
        tokio::spawn(async move {
            if let Err(error) = serve_connection(stream, &agent, allowed_uid).await {
                eprintln!("key agent: {error:#}");
            }
        });
    }
}

async fn serve_connection(
    stream: tokio::net::UnixStream,
    agent: &Mutex<KeyAgent>,
    allowed_uid: u32,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let peer = stream.peer_cred()?.uid();
    if peer != allowed_uid {
        bail!("refused a connection from uid {peer}");
    }
    let (mut read, mut write) = stream.into_split();
    let mut pending = WipingBuf::new();
    let mut chunk = Zeroizing::new([0u8; 4096]);
    // Bytes of `pending` already known to hold no newline: a multi-MiB
    // `Crypt` line arrives in 4 KiB reads, and rescanning it all each time
    // would be quadratic.
    let mut scanned = 0;
    loop {
        while let Some(offset) = pending.0[scanned..].iter().position(|byte| *byte == b'\n') {
            let end = scanned + offset;
            scanned = 0;
            let line = Zeroizing::new(pending.0.drain(..=end).collect::<Vec<u8>>());
            let reply = match std::str::from_utf8(&line[..end]) {
                Ok(text) => respond(agent, text),
                Err(_) => respond(agent, ""),
            };
            write.write_all(&reply.0).await?;
        }
        scanned = pending.0.len();
        if pending.0.len() > MAX_LINE {
            bail!("a request is too long");
        }
        let n = tokio::time::timeout(IDLE_TIMEOUT, read.read(&mut chunk[..]))
            .await
            .map_err(|_| anyhow!("closed an idle connection"))??;
        if n == 0 {
            return Ok(());
        }
        pending.append(&chunk[..n]);
    }
}

/// No core dumps, no ptrace by the same user, and (when the limit allows)
/// no swapping. Linux only; elsewhere a no-op.
fn harden_process() {
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0 as libc::c_ulong) } != 0 {
            eprintln!(
                "key agent: PR_SET_DUMPABLE failed ({})",
                std::io::Error::last_os_error()
            );
        }
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        let known = unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut limit) } == 0;
        // With MCL_FUTURE, every allocation past the limit fails, so lock only
        // when the limit leaves room for the whole process.
        if !known || (limit.rlim_cur != libc::RLIM_INFINITY && limit.rlim_cur < 512 << 20) {
            eprintln!(
                "key agent: not locking memory (RLIMIT_MEMLOCK is too low); keys could reach swap"
            );
        } else if unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) } != 0 {
            eprintln!(
                "key agent: mlockall failed ({}); keys could reach swap",
                std::io::Error::last_os_error()
            );
        }
    }
}

/// `atem key-agent`: serve this user's agent until the process exits.
pub async fn run_key_agent() -> Result<()> {
    harden_process();
    let paths = KeyPaths::default_paths();
    let socket = agent_socket_path();
    // `key_dir` holds the key directory's lock until the process exits.
    let (key_dir, listener) = match claim(&paths, &socket) {
        Ok(claimed) => claimed,
        Err(error) if error.downcast_ref::<AlreadyRunning>().is_some() => {
            eprintln!("{error}; exiting");
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    let watch = Watch::new(&socket, &paths.agent_socket, ORPHAN_CHECK)?;
    // A key-file error never stops the agent: it starts locked and says why
    // on `atem cred status` (see KeyAgent::new).
    let agent = KeyAgent::new(paths)?;
    eprintln!(
        "atem key agent (protocol v{PROTOCOL_VERSION}, pid {}) listening on {}",
        std::process::id(),
        socket.display()
    );
    let served = serve_watched(
        listener,
        Arc::new(Mutex::new(agent)),
        own_uid(),
        Some(watch),
    )
    .await;
    // A clean exit takes its pid out of the lock file before releasing it.
    let _ = key_dir.set_len(0);
    served
}

/// Starts `exe key-agent` detached from this command and its terminal, with
/// `envs` added to its environment. Returns the agent's pid.
fn spawn_agent(exe: &Path, log: &Path, envs: &[(&str, &Path)]) -> Result<u32> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::process::CommandExt;
    if let Some(dir) = log.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(log)?;
    // `mode` only applies to a new file; tighten one that already existed.
    log_file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    let mut command = std::process::Command::new(exe);
    command
        .arg("key-agent")
        .envs(envs.iter().copied())
        .stdin(std::process::Stdio::null())
        .stdout(log_file.try_clone()?)
        .stderr(log_file);
    let detach = || -> std::io::Result<()> {
        if unsafe { libc::setsid() } == -1 {
            return Err(std::io::Error::last_os_error());
        }
        // Don't pin the directory the command was run from.
        if unsafe { libc::chdir(c"/".as_ptr()) } == -1 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    };
    // SAFETY: setsid and chdir are async-signal-safe, as pre_exec requires.
    unsafe {
        command.pre_exec(detach);
    }
    let mut child = command.spawn().context("could not start the key agent")?;
    let pid = child.id();
    // Reap the agent if it exits while this process is still running.
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(pid)
}

/// The user id of the process listening on the other end of `stream`.
fn peer_uid(stream: &UnixStream) -> std::io::Result<u32> {
    #[cfg(target_os = "linux")]
    {
        let mut cred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut cred as *mut libc::ucred).cast(),
                &mut len,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(cred.uid)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let (mut uid, mut gid) = (0 as libc::uid_t, 0 as libc::gid_t);
        if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(uid)
    }
}

/// How a client starts an agent when none answers.
type Launcher = Box<dyn Fn() -> Result<()> + Send + Sync>;

pub struct KeyAgentClient {
    /// Where this session's agent would listen (from its runtime dir).
    socket: PathBuf,
    /// The running agent's own record of its socket (`agent.socket`), tried
    /// first: it may have been started from another session.
    record: Option<PathBuf>,
    launcher: Option<Launcher>,
    /// Where a started agent writes; named when it doesn't come up.
    log: PathBuf,
    /// The key directory's lock: when an agent holds it but answers on no
    /// socket, the error names that agent's pid.
    lock: Option<PathBuf>,
    /// How long to wait for an agent this client started.
    start_wait: Duration,
    /// The user the listener must run as (this user; settable in tests).
    expected_uid: u32,
}

impl KeyAgentClient {
    /// A client for the agent at `socket` that never starts one.
    #[cfg(test)]
    pub(crate) fn at(socket: PathBuf) -> Self {
        Self {
            socket,
            record: None,
            launcher: None,
            log: agent_log_path(),
            lock: None,
            start_wait: START_WAIT,
            expected_uid: own_uid(),
        }
    }

    /// A client for this user's agent that starts it when none answers.
    pub fn autostart() -> Self {
        Self::finding(
            &crate::config::AtemConfig::config_dir(),
            std::env::var_os("XDG_RUNTIME_DIR"),
            Some(Box::new(|| {
                spawn_agent(&std::env::current_exe()?, &agent_log_path(), &[]).map(|_| ())
            })),
        )
    }

    /// A client for this user's running agent that never starts one.
    pub fn existing() -> Self {
        Self::finding(
            &crate::config::AtemConfig::config_dir(),
            std::env::var_os("XDG_RUNTIME_DIR"),
            None,
        )
    }

    /// A client for the agent of the key files in `config_dir`, as seen from
    /// a session whose runtime dir is `runtime_dir`; `launcher` starts one
    /// when none answers.
    pub(crate) fn finding(
        config_dir: &Path,
        runtime_dir: Option<OsString>,
        launcher: Option<Launcher>,
    ) -> Self {
        Self {
            socket: socket_path_in(config_dir, runtime_dir),
            record: Some(config_dir.join("agent.socket")),
            launcher,
            log: config_dir.join("key-agent.log"),
            lock: Some(config_dir.join("key_agent.lock")),
            start_wait: START_WAIT,
            expected_uid: own_uid(),
        }
    }

    /// A client for the agent at `socket` that starts it with `launcher`.
    #[cfg(test)]
    pub(crate) fn with_launcher(socket: PathBuf, launcher: Launcher) -> Self {
        Self {
            socket,
            record: None,
            launcher: Some(launcher),
            log: agent_log_path(),
            lock: None,
            start_wait: START_WAIT,
            expected_uid: own_uid(),
        }
    }

    /// Names `log` when an agent doesn't come up.
    #[cfg(test)]
    pub(crate) fn logging_to(mut self, log: PathBuf) -> Self {
        self.log = log;
        self
    }

    /// Waits `wait` for an agent this client started.
    #[cfg(test)]
    pub(crate) fn waiting(mut self, wait: Duration) -> Self {
        self.start_wait = wait;
        self
    }

    /// Expects the listener to run as `uid` instead of this user.
    #[cfg(test)]
    pub(crate) fn expecting_uid(mut self, uid: u32) -> Self {
        self.expected_uid = uid;
        self
    }

    /// Connects to the recorded socket, else this session's, and refuses a
    /// listener that isn't `expected_uid`.
    fn dial(&self) -> std::io::Result<Result<UnixStream>> {
        if let Some(recorded) = self.record.as_deref().and_then(recorded_socket)
            && recorded != self.socket
            && let Ok(checked) = self.dial_at(&recorded)
        {
            return Ok(checked);
        }
        self.dial_at(&self.socket)
    }

    fn dial_at(&self, socket: &Path) -> std::io::Result<Result<UnixStream>> {
        let stream = UnixStream::connect(socket)?;
        let peer = peer_uid(&stream)?;
        if peer != self.expected_uid {
            return Ok(Err(anyhow!(
                "the socket at {} is served by another user (uid {peer}); refusing to talk to it",
                socket.display()
            )));
        }
        Ok(Ok(stream))
    }

    pub fn is_running(&self) -> bool {
        matches!(self.dial(), Ok(Ok(_)))
    }

    fn connect(&self) -> Result<UnixStream> {
        match self.dial() {
            Ok(checked) => checked,
            Err(error)
                if self.launcher.is_some()
                    && matches!(
                        error.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                    ) =>
            {
                if let Some(launch) = &self.launcher {
                    launch()?;
                }
                let deadline = std::time::Instant::now() + self.start_wait;
                while std::time::Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(100));
                    if let Ok(checked) = self.dial() {
                        return checked;
                    }
                }
                // An agent nobody can reach still holds the key files.
                if let Some(lock) = self.lock.as_deref()
                    && lock_is_held(lock) == Some(true)
                {
                    return Err(StuckAgent(stuck_message(lock)).into());
                }
                bail!("the key agent didn't start; see {}", self.log.display())
            }
            Err(error) => Err(anyhow!(error).context(format!(
                "the key agent isn't running at {}",
                self.socket.display()
            ))),
        }
    }
}

/// Reads one reply line without a `BufReader`, so no unwiped copy stays behind.
fn read_reply(mut stream: &UnixStream) -> std::io::Result<WipingBuf> {
    let mut line = WipingBuf::new();
    let mut chunk = Zeroizing::new([0u8; 4096]);
    loop {
        let n = stream.read(&mut chunk[..])?;
        if n == 0 || line.0.len() > MAX_LINE {
            return Ok(line);
        }
        line.append(&chunk[..n]);
        if chunk[..n].contains(&b'\n') {
            return Ok(line);
        }
    }
}

impl KeyAgentClient {
    /// Why the agent hung up (or timed out). An agent of an older atem
    /// closes the connection on a request it can't read (a step-2a agent
    /// reads at most 1 MiB), so a short `status` asks for its version first.
    fn closed(&self, error: Option<std::io::Error>) -> anyhow::Error {
        if let Some(version) = self.probe_version()
            && version != PROTOCOL_VERSION
        {
            return version_mismatch(version);
        }
        // The listener's uid was checked when connecting: the agent's log
        // says why it hung up.
        let log = self.log.display();
        match error {
            Some(error) => anyhow!("the key agent closed the connection ({error}); see {log}"),
            None => anyhow!("the key agent closed the connection; see {log}"),
        }
    }

    /// The protocol version the running agent answers a `status` in (no
    /// autostart); `None` when it doesn't answer.
    fn probe_version(&self) -> Option<u64> {
        let stream = self.dial().ok()?.ok()?;
        stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .ok()?;
        let line = encode_request(&Request::Status).ok()?;
        (&stream).write_all(line.as_bytes()).ok()?;
        let reply = read_reply(&stream).ok()?;
        let text = std::str::from_utf8(&reply.0).ok()?;
        serde_json::from_str::<ResponseHead>(text.trim())
            .ok()
            .map(|head| head.v)
    }
}

impl KeyAgentApi for KeyAgentClient {
    fn call(&self, request: Request) -> Result<Reply> {
        let line = encode_request(&request)?;
        drop(request);
        let stream = self.connect()?;
        let closed = |error: std::io::Error| self.closed(Some(error));
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .map_err(closed)?;
        stream
            .set_write_timeout(Some(Duration::from_secs(30)))
            .map_err(closed)?;
        (&stream).write_all(line.as_bytes()).map_err(closed)?;
        drop(line);
        let reply = read_reply(&stream).map_err(closed)?;
        if reply.0.is_empty() {
            return Err(self.closed(None));
        }
        let text = std::str::from_utf8(&reply.0)
            .map_err(|_| anyhow!("the key agent sent a non-UTF-8 reply"))?;
        decode_response(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};

    /// Unix socket paths are limited to ~100 bytes; keep them short.
    fn short_dir() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("atem-ka")
            .tempdir_in("/tmp")
            .unwrap()
    }

    fn own_uid() -> u32 {
        unsafe { libc::getuid() }
    }

    /// `attempt`'s value, retried for up to three seconds: a child that
    /// another test is forking holds copies of this process's descriptors
    /// (a dropped listener, a released lock) until it execs.
    fn retrying<T>(mut attempt: impl FnMut() -> Result<T>) -> T {
        for _ in 0..30 {
            if let Ok(value) = attempt() {
                return value;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        attempt().unwrap()
    }

    /// Creates `path` private, whatever the umask: the agent refuses a socket
    /// directory others can write to.
    fn make_private(path: &Path) {
        std::fs::create_dir_all(path).unwrap();
        std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .unwrap();
    }

    /// Serves an agent for the key files in `dir` on its own thread.
    fn start_agent(dir: &Path, allowed_uid: u32) -> PathBuf {
        let socket = dir.join("run").join("agent.sock");
        let paths = KeyPaths::in_dir(dir);
        let (ready, started) = std::sync::mpsc::channel();
        let path = socket.clone();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let listener = bind(&path).unwrap();
                let agent = Arc::new(Mutex::new(KeyAgent::new(paths).unwrap()));
                ready.send(()).unwrap();
                let _ = serve(listener, agent, allowed_uid).await;
            });
        });
        started.recv().unwrap();
        socket
    }

    #[test]
    fn the_socket_prefers_the_runtime_dir() {
        let config = Path::new("/home/u/.config/atem");
        assert_eq!(
            socket_path_from(Some("/run/user/1000".into()), config),
            Path::new("/run/user/1000/atem/agent.sock")
        );
        assert_eq!(
            socket_path_from(None, config),
            Path::new("/home/u/.config/atem/agent.sock")
        );
        assert_eq!(
            socket_path_from(Some("".into()), config),
            Path::new("/home/u/.config/atem/agent.sock")
        );
    }

    #[test]
    fn every_request_carries_the_protocol_version() {
        let line = encode_request(&Request::Status).unwrap();
        assert!(line.ends_with('\n'));
        let value: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(value, serde_json::json!({"op": "status", "v": 2}));
        assert!(matches!(
            decode_request(line.trim()).unwrap(),
            Request::Status
        ));
        let newer = decode_request(r#"{"op":"status","v":3}"#).err().unwrap();
        assert!(format!("{newer:#}").contains("protocol version 3"));
        let older = decode_request(r#"{"op":"status","v":1}"#).err().unwrap();
        assert!(format!("{older:#}").contains("protocol version 1"));
        assert!(decode_request(r#"{"op":"status"}"#).is_err());
    }

    #[test]
    fn a_newer_cli_gets_a_clear_error_from_an_older_agent() {
        // A step-2a agent (v1) left running after an upgrade.
        let older_agent = decode_response(r#"{"v":1,"ok":true,"reply":{"kind":"done"}}"#);
        let hint = format!("{:#}", older_agent.err().unwrap());
        // Check first that Astation holds the storage key, then stop it.
        let (status, pkill) = (
            hint.find("atem cred status").expect(&hint),
            hint.find("pkill").expect(&hint),
        );
        assert!(status < pkill, "{hint}");
        let refused = decode_response(
            r#"{"v":2,"ok":false,"error":"unsupported key agent protocol version 3"}"#,
        );
        assert!(format!("{:#}", refused.err().unwrap()).contains("protocol version 3"));
        assert!(matches!(
            decode_response(r#"{"v":2,"ok":true,"reply":{"kind":"done"}}"#).unwrap(),
            Reply::Done
        ));
    }

    #[test]
    fn the_same_user_talks_to_the_agent() {
        use std::os::unix::fs::PermissionsExt;
        let dir = short_dir();
        let socket = start_agent(dir.path(), own_uid());
        let client = KeyAgentClient::at(socket.clone());
        assert!(client.is_running());
        assert!(!client.status().unwrap().unlocked);
        client.lock_keys().unwrap();
        assert_eq!(
            std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(socket.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        // A request in an unknown version is answered with an error, not dropped.
        let mut stream = std::os::unix::net::UnixStream::connect(&socket).unwrap();
        stream.write_all(b"{\"op\":\"status\",\"v\":3}\n").unwrap();
        let mut line = String::new();
        BufReader::new(&stream).read_line(&mut line).unwrap();
        let response: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(response["v"], 2);
        assert_eq!(response["ok"], false);
        assert!(
            response["error"]
                .as_str()
                .unwrap()
                .contains("protocol version 3")
        );
    }

    #[test]
    fn another_user_is_refused() {
        let dir = short_dir();
        let socket = start_agent(dir.path(), own_uid().wrapping_add(1));
        let error = format!("{:#}", KeyAgentClient::at(socket).status().err().unwrap());
        assert!(error.contains("closed the connection"), "{error}");
        // The client checked the listener's uid already: the hint is the log.
        assert!(
            error.contains(&format!("see {}", agent_log_path().display())),
            "{error}"
        );
        assert!(!error.contains("another user"), "{error}");
    }

    #[test]
    fn bind_replaces_a_stale_socket_but_not_a_live_agent() {
        let dir = short_dir();
        let socket = start_agent(dir.path(), own_uid());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let live = bind(&socket).err().unwrap();
            assert!(format!("{live:#}").contains("already running"));
            let stale = dir.path().join("stale").join("agent.sock");
            make_private(stale.parent().unwrap());
            drop(std::os::unix::net::UnixListener::bind(&stale).unwrap());
            assert!(stale.exists());
            retrying(|| bind(&stale));
        });
    }

    #[test]
    fn a_client_that_may_not_start_an_agent_says_so() {
        let dir = short_dir();
        let client = KeyAgentClient::at(dir.path().join("none.sock"));
        assert!(!client.is_running());
        assert!(format!("{:#}", client.status().err().unwrap()).contains("isn't running"));
    }

    #[test]
    fn every_request_survives_the_wire_and_reaches_the_agent() {
        use crate::memory::key_agent::{error_of, test_agent};
        use crate::memory::statements::SignedWire;
        use crate::memory::storage_key::UnlockGrantWire;
        let dir = short_dir();
        let socket = start_agent(dir.path(), own_uid());
        let client = KeyAgentClient::at(socket);
        let local = test_agent(&KeyPaths::in_dir(dir.path()));
        let signed = || SignedWire {
            statement: "AA==".into(),
            signature: "AA==".into(),
        };
        let grant = || UnlockGrantWire {
            grant: signed(),
            encapped_key: "AA==".into(),
            ciphertext: "AA==".into(),
        };
        // The locked agent's answer must be the same over the socket as in
        // process: the request reached `KeyAgent::handle` intact.
        assert_eq!(
            error_of(client.public_keys()),
            error_of(local.public_keys())
        );
        assert_eq!(
            error_of(client.begin_unlock("a")),
            error_of(local.begin_unlock("a"))
        );
        assert_eq!(
            error_of(client.finish_unlock("a", "AA==", &grant())),
            error_of(local.finish_unlock("a", "AA==", &grant()))
        );
        assert_eq!(
            error_of(client.begin_rotation("a")),
            error_of(local.begin_rotation("a"))
        );
        assert_eq!(
            error_of(client.confirm_rotation("a", &signed())),
            error_of(local.confirm_rotation("a", &signed()))
        );
        assert_eq!(
            error_of(client.abandon_pending("a", "abcd1234")),
            error_of(local.abandon_pending("a", "abcd1234"))
        );
        assert_eq!(client.pending_rotation().unwrap(), None);
        // None of them was rejected for its shape.
        let shape = error_of(client.begin_rotation("a"));
        assert!(
            !shape.contains("malformed") && !shape.contains("protocol version"),
            "{shape}"
        );
    }

    #[test]
    fn every_request_variant_encodes_and_decodes() {
        use crate::memory::statements::SignedWire;
        let signed = SignedWire {
            statement: "s".into(),
            signature: "g".into(),
        };
        let requests = vec![
            Request::Status,
            Request::PublicKeys,
            Request::BeginUnlock {
                astation_id: "a".into(),
            },
            Request::BeginRotation {
                astation_id: "a".into(),
            },
            Request::PendingRotation,
            Request::ConfirmRotation {
                astation_id: "a".into(),
                ack: signed,
            },
            Request::AbandonPending {
                astation_id: "a".into(),
                storage_kid: "abcd1234".into(),
            },
            Request::Lock,
        ];
        for request in requests {
            let line = encode_request(&request).unwrap();
            let back = decode_request(line.trim()).unwrap();
            let again = encode_request(&back).unwrap();
            assert_eq!(*line, *again);
        }
    }

    #[test]
    fn a_client_starts_the_agent_when_none_answers() {
        use std::os::unix::fs::PermissionsExt;
        // Starts the real binary (built because integration tests exist).
        let dir = short_dir();
        let home = dir.path().join("home");
        let runtime = dir.path().join("run");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&runtime).unwrap();
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
        let exe = std::env::current_exe()
            .unwrap()
            .parent()
            .and_then(Path::parent)
            .unwrap()
            .join("atem");
        assert!(
            exe.exists(),
            "atem binary missing or stale at {}: run `cargo build` first",
            exe.display()
        );
        let socket = runtime.join("atem").join("agent.sock");
        let pid = Arc::new(Mutex::new(None));
        let launcher = {
            let (home, runtime, pid, log) = (
                home.clone(),
                runtime.clone(),
                pid.clone(),
                dir.path().join("agent.log"),
            );
            Box::new(move || {
                let started = spawn_agent(
                    &exe,
                    &log,
                    &[("HOME", &home), ("XDG_RUNTIME_DIR", &runtime)],
                )?;
                *pid.lock().unwrap() = Some(started);
                Ok(())
            })
        };
        struct Kill(Arc<Mutex<Option<u32>>>);
        impl Drop for Kill {
            fn drop(&mut self) {
                if let Some(pid) = *self.0.lock().unwrap() {
                    unsafe { libc::kill(pid as i32, libc::SIGKILL) };
                }
            }
        }
        let _kill = Kill(pid.clone());
        let client = KeyAgentClient::with_launcher(socket.clone(), launcher)
            .logging_to(dir.path().join("agent.log"));
        assert!(!client.is_running());
        let status = client.status().unwrap();
        assert!(!status.unlocked);
        assert!(client.is_running());
        assert!(pid.lock().unwrap().is_some());
        // A second client finds the same agent without starting another.
        let second = KeyAgentClient::with_launcher(
            socket,
            Box::new(|| -> Result<()> { panic!("a second agent must not be started") }),
        );
        assert!(!second.status().unwrap().unlocked);
    }

    #[test]
    fn bind_refuses_a_symlinked_socket_directory() {
        let dir = short_dir();
        let real = dir.path().join("real");
        std::fs::create_dir_all(&real).unwrap();
        let link = dir.path().join("atem");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let error = bind(&link.join("agent.sock")).err().unwrap();
        assert!(format!("{error:#}").contains("symlink"), "{error:#}");
        assert!(!real.join("agent.sock").exists());
    }

    #[test]
    fn bind_does_not_delete_a_file_that_is_not_a_socket() {
        let dir = short_dir();
        let socket = dir.path().join("run").join("agent.sock");
        make_private(socket.parent().unwrap());
        std::fs::write(&socket, b"precious").unwrap();
        let error = bind(&socket).err().unwrap();
        assert!(format!("{error:#}").contains("not a socket"), "{error:#}");
        assert_eq!(std::fs::read(&socket).unwrap(), b"precious");
    }

    #[test]
    fn an_endless_line_closes_the_connection() {
        let dir = short_dir();
        let socket = start_agent(dir.path(), own_uid());
        let mut stream = std::os::unix::net::UnixStream::connect(&socket).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        let chunk = vec![b'a'; 64 << 10];
        // The agent hangs up once the line passes the cap; a write may fail then.
        for _ in 0..(MAX_LINE / chunk.len() + 8) {
            if stream.write_all(&chunk).is_err() {
                break;
            }
        }
        let mut byte = [0u8; 1];
        let closed = match std::io::Read::read(&mut stream, &mut byte) {
            Ok(0) => true,
            Err(error) => !matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ),
            Ok(_) => false,
        };
        assert!(closed);
        // The agent still serves others.
        assert!(KeyAgentClient::at(socket).status().is_ok());
    }

    #[test]
    fn a_listener_run_by_someone_else_is_not_trusted() {
        let dir = short_dir();
        let socket = start_agent(dir.path(), own_uid());
        let client = KeyAgentClient::at(socket.clone()).expecting_uid(own_uid().wrapping_add(1));
        assert!(!client.is_running());
        let error = format!("{:#}", client.status().err().unwrap());
        assert!(error.contains("served by another user"), "{error}");
        // The same socket is fine for its own user.
        assert!(KeyAgentClient::at(socket).is_running());
    }

    #[test]
    fn socket_directories_must_be_private_and_ours() {
        use std::os::unix::fs::PermissionsExt;
        let dir = short_dir();
        let config = dir.path().join("config");
        let open = dir.path().join("open");
        let private = dir.path().join("private");
        for (path, mode) in [(&open, 0o777), (&private, 0o700)] {
            std::fs::create_dir_all(path).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        let uid = own_uid();
        assert!(check_parent_dir(&private, uid).is_ok());
        assert!(format!("{:#}", check_parent_dir(&open, uid).unwrap_err()).contains("written"));
        assert!(
            format!("{:#}", check_parent_dir(&private, uid + 1).unwrap_err())
                .contains("another user")
        );
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&private, &link).unwrap();
        assert!(format!("{:#}", check_parent_dir(&link, uid).unwrap_err()).contains("symlink"));
        assert!(check_parent_dir(&dir.path().join("missing"), uid).is_err());
        // A socket directory owned by someone else is refused outright.
        let error = prepare_socket_dir(&private, uid + 1).unwrap_err();
        assert!(format!("{error:#}").contains("another user"));
        // And the socket path falls back to the config dir for an unsafe runtime dir.
        let pick = |runtime: &Path| {
            let ok = check_parent_dir(runtime, uid).is_ok();
            socket_path_from(ok.then(|| runtime.as_os_str().to_owned()), &config)
        };
        assert_eq!(pick(&private), private.join("atem").join("agent.sock"));
        assert_eq!(pick(&open), config.join("agent.sock"));
        assert_eq!(pick(&link), config.join("agent.sock"));
    }

    #[test]
    fn replies_decode_through_their_kind() {
        let line = |reply: &str| format!(r#"{{"v":{PROTOCOL_VERSION},"ok":true,"reply":{reply}}}"#);
        assert!(matches!(
            decode_response(&line(r#"{"kind":"grant_installed","kid":"ab12cd34"}"#)).unwrap(),
            Reply::GrantInstalled { kid } if kid == "ab12cd34"
        ));
        assert!(matches!(
            decode_response(&line(
                r#"{"kind":"status","unlocked":false,"storage_kid":null,"escrowed":false}"#
            ))
            .unwrap(),
            Reply::Status {
                unlocked: false,
                ..
            }
        ));
        // No reply carries K any more.
        assert!(
            decode_response(&line(r#"{"kind":"grant","kid":"ab12cd34","key":"AAAA"}"#)).is_err()
        );
    }

    /// Requests that carry secrets, grants (with and without trust) and an unlock answer.
    fn rich_requests() -> Vec<Request> {
        use crate::memory::grant::GrantWire;
        use crate::memory::statements::SignedWire;
        use crate::memory::storage_key::UnlockGrantWire;
        use crate::memory::trust::AstationTrust;
        let signed = || SignedWire {
            statement: "AA==".into(),
            signature: "AA==".into(),
        };
        let grant = || GrantWire {
            signed: signed(),
            encapped_key: "AA==".into(),
            ciphertext: "AA==".into(),
        };
        let trust = AstationTrust {
            device_id: "dev".into(),
            data_account: "acct".into(),
            sign_gen: 3,
            astation_sign_pub: "AA==".into(),
            astation_enc_pub: "AA==".into(),
            recovery_sign_pub: "AA==".into(),
            device_pub: "AA==".into(),
            device_sign_pub: "AA==".into(),
            unlock_auth_pub: "AA==".into(),
            safety_code: "code".into(),
            transcript: "t".into(),
            epoch_floor: 1,
            account_state: Some(signed()),
            account_epoch: 2,
        };
        vec![
            Request::LoadUnlocked {
                device_id: "dev".into(),
                device: Zeroizing::new("ZGV2".into()),
                device_sign: Zeroizing::new("c2ln".into()),
                unlock_auth: Zeroizing::new("dWE=".into()),
                storage_kid: "abcd1234".into(),
                storage_key: Zeroizing::new("a2V5".into()),
            },
            Request::InstallGrant {
                astation_id: "a".into(),
                grant: grant(),
            },
            Request::CheckGrant {
                grant: grant(),
                trust,
            },
            Request::FinishUnlock {
                astation_id: "a".into(),
                request: "AA==".into(),
                grant: UnlockGrantWire {
                    grant: signed(),
                    encapped_key: "AA==".into(),
                    ciphertext: "AA==".into(),
                },
            },
            Request::Crypt {
                astation_id: "a".into(),
                ops: vec![
                    crate::memory::account_keys::CryptOp::seal("r", "f", b"hi"),
                    crate::memory::account_keys::CryptOp::open("r", "f", "e1.x.AA=="),
                    crate::memory::account_keys::CryptOp::keyed_hash(b"p"),
                ],
            },
            Request::HeldKid {
                astation_id: "a".into(),
            },
        ]
    }

    /// A step-2a (v1) agent left running: answers a line in v1 and, like
    /// it, closes the connection unanswered on a request over 1 MiB.
    fn start_v1_agent(dir: &Path) -> PathBuf {
        let socket = dir.join("run").join("agent.sock");
        make_private(socket.parent().unwrap());
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut pending = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    if pending.contains(&b'\n') {
                        let _ = stream.write_all(
                            b"{\"v\":1,\"ok\":true,\"reply\":{\"kind\":\"status\",\"unlocked\":true,\"storage_kid\":null,\"escrowed\":true}}\n",
                        );
                        break;
                    }
                    if pending.len() > 1 << 20 {
                        break;
                    }
                    match std::io::Read::read(&mut stream, &mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => pending.extend_from_slice(&chunk[..n]),
                    }
                }
            }
        });
        socket
    }

    #[test]
    fn a_big_first_request_to_an_old_agent_says_to_stop_it() {
        use crate::memory::account_keys::CryptOp;
        let dir = short_dir();
        let client = KeyAgentClient::at(start_v1_agent(dir.path()));
        // Over the step-2a agent's 1 MiB line limit: it hangs up unanswered.
        let big = vec![7u8; 3 << 19];
        let error = format!(
            "{:#}",
            client
                .crypt("astation-1", vec![CryptOp::seal("r", "f", &big)])
                .err()
                .unwrap()
        );
        assert!(error.contains("speaks protocol v1"), "{error}");
        assert!(error.contains("pkill"), "{error}");
        assert!(!error.contains("another user"), "{error}");
    }

    #[test]
    fn pipelined_requests_get_one_reply_each() {
        let dir = short_dir();
        let socket = start_agent(dir.path(), own_uid());
        let mut stream = std::os::unix::net::UnixStream::connect(&socket).unwrap();
        let one = encode_request(&Request::Status).unwrap();
        let two = encode_request(&Request::Lock).unwrap();
        stream
            .write_all(format!("{}{}", one.as_str(), two.as_str()).as_bytes())
            .unwrap();
        let mut reader = BufReader::new(&stream);
        let mut first = String::new();
        let mut second = String::new();
        reader.read_line(&mut first).unwrap();
        reader.read_line(&mut second).unwrap();
        assert!(matches!(
            decode_response(&first).unwrap(),
            Reply::Status {
                unlocked: false,
                ..
            }
        ));
        assert!(matches!(decode_response(&second).unwrap(), Reply::Done));
    }

    #[test]
    fn cred_status_against_an_old_agent_says_to_stop_it() {
        use crate::memory::trust::TrustStore;
        use crate::memory::unlock::{AgentState, agent_state, status_report};
        let dir = short_dir();
        let client = KeyAgentClient::at(start_v1_agent(dir.path()));
        assert!(client.is_running());
        let state = agent_state(Some(&client));
        let report = status_report(
            &TrustStore::default(),
            "astation-1",
            &state,
            Some("0a1b2c3d"),
            None,
        );
        // The report is printed, not an error: the mismatch and what to do.
        assert!(
            report.contains("Key agent: not answering (the running key agent speaks protocol v1, this atem speaks v2"),
            "{report}"
        );
        assert!(report.contains("pkill"), "{report}");
        assert!(report.contains("retry"), "{report}");
        assert!(report.contains("Storage key: 0a1b2c3d"), "{report}");
        assert!(matches!(agent_state(None), AgentState::NotRunning));
    }

    #[test]
    fn crypt_requests_and_replies_parse_without_the_tagged_enum() {
        use crate::memory::account_keys::CryptOp;
        let request = Request::Crypt {
            astation_id: "a".into(),
            ops: vec![
                CryptOp::seal("r", "f", b"hi"),
                CryptOp::open("r", "f", "e1.x"),
                CryptOp::keyed_hash(b"p"),
            ],
        };
        let line = encode_request(&request).unwrap();
        assert!(line.contains(r#""op":"crypt""#), "{}", *line);
        assert!(
            line.contains(r#"{"seal":{"record":"r","field":"f","plain":"aGk="}}"#),
            "{}",
            *line
        );
        match decode_request(line.trim()).unwrap() {
            Request::Crypt { astation_id, ops } => {
                assert_eq!(astation_id, "a");
                assert_eq!(ops.len(), 3);
            }
            _ => panic!("expected a crypt request"),
        }
        let reply = decode_response(
            r#"{"v":2,"ok":true,"reply":{"kind":"crypted","results":[{"sealed":"e1.x"},{"opened":"aGk="},{"hashed":"h1.y"}]}}"#,
        )
        .unwrap();
        let Reply::Crypted { results } = reply else {
            panic!("expected crypted");
        };
        let mut results = results.into_iter();
        assert_eq!(results.next().unwrap().into_text().unwrap(), "e1.x");
        assert_eq!(&*results.next().unwrap().into_plain().unwrap(), b"hi");
        assert_eq!(results.next().unwrap().into_text().unwrap(), "h1.y");
    }

    #[test]
    fn a_crypt_batch_bigger_than_a_mebibyte_reaches_the_agent() {
        use crate::memory::account_keys::CryptOp;
        use crate::memory::key_agent::error_of;
        let dir = short_dir();
        let socket = start_agent(dir.path(), own_uid());
        let client = KeyAgentClient::at(socket);
        let big = vec![b'x'; 3 << 20];
        let error = error_of(client.crypt("a", vec![CryptOp::seal("r", "f", &big)]));
        // The locked agent's answer, not a refused line.
        assert!(error.contains("locked"), "{error}");
    }

    #[test]
    fn secret_and_grant_requests_survive_encode_and_decode() {
        for request in rich_requests() {
            let line = encode_request(&request).unwrap();
            let back = decode_request(line.trim()).unwrap();
            assert_eq!(*line, *encode_request(&back).unwrap());
        }
    }

    #[test]
    fn secret_and_grant_requests_reach_the_agent_over_the_wire() {
        use crate::memory::key_agent::{error_of, test_agent};
        let dir = short_dir();
        let socket = start_agent(dir.path(), own_uid());
        let client = KeyAgentClient::at(socket);
        let local = test_agent(&KeyPaths::in_dir(dir.path()));
        for (over_wire, in_process) in rich_requests().into_iter().zip(rich_requests()) {
            let wire_error = error_of(client.call(over_wire));
            let local_error = error_of(local.call(in_process));
            assert_eq!(wire_error, local_error);
            assert!(!wire_error.contains("malformed"), "{wire_error}");
        }
    }

    #[test]
    fn a_socket_directory_others_can_write_is_refused_not_tightened() {
        use std::os::unix::fs::PermissionsExt;
        let dir = short_dir();
        let open = dir.path().join("atem");
        std::fs::create_dir_all(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o770)).unwrap();
        let error = bind(&open.join("agent.sock")).err().unwrap();
        let text = format!("{error:#}");
        assert!(text.contains("written by other users"), "{text}");
        assert!(text.contains(open.to_str().unwrap()), "{text}");
        assert_eq!(
            std::fs::metadata(&open).unwrap().permissions().mode() & 0o777,
            0o770
        );
    }

    /// The atem binary next to the test binary (built because integration
    /// tests exist).
    fn atem_binary() -> PathBuf {
        let exe = std::env::current_exe()
            .unwrap()
            .parent()
            .and_then(Path::parent)
            .unwrap()
            .join("atem");
        assert!(
            exe.exists(),
            "atem binary missing or stale at {}: run `cargo build` first",
            exe.display()
        );
        exe
    }

    /// Kills the child when the test ends, however it ends.
    struct Reaped(std::process::Child);

    impl Drop for Reaped {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// `atem key-agent` for `home`, with its socket under `runtime`.
    fn key_agent_process(home: &Path, runtime: &Path, log: &Path) -> Reaped {
        let log = std::fs::File::create(log).unwrap();
        Reaped(
            std::process::Command::new(atem_binary())
                .arg("key-agent")
                .env("HOME", home)
                .env("XDG_RUNTIME_DIR", runtime)
                .stdin(std::process::Stdio::null())
                .stdout(log.try_clone().unwrap())
                .stderr(log)
                .spawn()
                .unwrap(),
        )
    }

    /// Polls `done` for up to five seconds.
    fn eventually(mut done: impl FnMut() -> bool) -> bool {
        for _ in 0..50 {
            if done() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        false
    }

    #[test]
    fn one_agent_serves_a_key_directory_whatever_the_runtime_dir() {
        let dir = short_dir();
        let home = dir.path().join("home");
        let (run_a, run_b) = (dir.path().join("ra"), dir.path().join("rb"));
        std::fs::create_dir_all(&home).unwrap();
        make_private(&run_a);
        make_private(&run_b);
        let mut first = key_agent_process(&home, &run_a, &dir.path().join("a.log"));
        let socket_a = run_a.join("atem").join("agent.sock");
        assert!(eventually(
            || KeyAgentClient::at(socket_a.clone()).is_running()
        ));
        // A second agent for the same key files (another login session with
        // its own runtime dir) must not run beside the first: two agents
        // rotating one storage key could each strand the other's files.
        let mut second = key_agent_process(&home, &run_b, &dir.path().join("b.log"));
        assert!(
            eventually(|| second.0.try_wait().unwrap().is_some()),
            "the second agent kept running"
        );
        assert!(!run_b.join("atem").join("agent.sock").exists());
        let log = std::fs::read_to_string(dir.path().join("b.log")).unwrap();
        assert!(log.contains("already running"), "{log}");
        // A client from the second session finds the first agent through
        // the socket path it recorded, and starts no other.
        let client = KeyAgentClient::finding(
            &home.join(".config").join("atem"),
            Some(run_b.clone().into_os_string()),
            Some(Box::new(|| -> Result<()> {
                panic!("a second agent must not be started")
            })),
        );
        assert!(client.is_running());
        assert!(!client.status().unwrap().unlocked);
        assert!(first.0.try_wait().unwrap().is_none());
    }

    #[test]
    fn a_second_claim_on_the_same_key_files_is_refused_and_the_socket_recorded() {
        let dir = short_dir();
        let paths = KeyPaths::in_dir(&dir.path().join("config"));
        let (run_a, run_b) = (dir.path().join("ra"), dir.path().join("rb"));
        make_private(&run_a);
        make_private(&run_b);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let socket_a = run_a.join("atem").join("agent.sock");
            let (lock, listener) = claim(&paths, &socket_a).unwrap();
            assert_eq!(recorded_socket(&paths.agent_socket), Some(socket_a.clone()));
            assert_eq!(
                std::fs::metadata(&paths.agent_socket)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            let error = claim(&paths, &run_b.join("atem").join("agent.sock"))
                .err()
                .unwrap();
            assert!(
                error.downcast_ref::<AlreadyRunning>().is_some(),
                "{error:#}"
            );
            assert!(!run_b.join("atem").join("agent.sock").exists());
            assert_eq!(recorded_socket(&paths.agent_socket), Some(socket_a));
            // Once the first agent is gone, another may take the directory.
            drop((lock, listener));
            retrying(|| claim(&paths, &run_b.join("atem").join("agent.sock")));
        });
    }

    #[test]
    fn a_symlinked_key_directory_lock_is_refused() {
        let dir = short_dir();
        let paths = KeyPaths::in_dir(dir.path());
        let target = dir.path().join("target");
        std::fs::write(&target, b"keep").unwrap();
        std::os::unix::fs::symlink(&target, &paths.agent_lock).unwrap();
        let error = lock_key_dir(&paths, Duration::ZERO).err().unwrap();
        assert!(format!("{error:#}").contains("symlink"), "{error:#}");
        assert_eq!(std::fs::read(&target).unwrap(), b"keep");
    }

    #[test]
    fn a_symlinked_lock_file_is_refused() {
        let dir = short_dir();
        let run = dir.path().join("run");
        let target = dir.path().join("target");
        std::fs::create_dir(&run).unwrap();
        std::fs::write(&target, b"keep").unwrap();
        std::os::unix::fs::symlink(&target, run.join("agent.lock")).unwrap();
        let _ = std::fs::set_permissions(&run, std::os::unix::fs::PermissionsExt::from_mode(0o700));
        let error = bind(&run.join("agent.sock")).err().unwrap();
        assert!(format!("{error:#}").contains("symlink"), "{error:#}");
        assert_eq!(std::fs::read(&target).unwrap(), b"keep");
    }

    /// An agent that holds keys (a migrated plain step-1 file), claimed and
    /// served on its own thread with `watch` checks every 50 ms. Returns the
    /// socket, the agent and a receiver that fires when serving stops.
    fn watched_agent(
        dir: &Path,
    ) -> (
        PathBuf,
        KeyPaths,
        Arc<Mutex<KeyAgent>>,
        std::sync::mpsc::Receiver<()>,
    ) {
        use crate::memory::device_keys::DeviceKeys;
        use crate::memory::statements::FakeAstation;
        let paths = KeyPaths::in_dir(&dir.join("config"));
        let keys = DeviceKeys::generate();
        crate::memory::fake_astation::pin(&paths, &FakeAstation::new(), &keys, true);
        keys.save_to(&paths.device_keys).unwrap();
        let agent = Arc::new(Mutex::new(KeyAgent::new(paths.clone()).unwrap()));
        assert!(
            agent.status().unwrap().unlocked,
            "the plain keys were migrated"
        );
        let socket = dir.join("run").join("atem").join("agent.sock");
        make_private(&dir.join("run"));
        let (ready, started) = std::sync::mpsc::channel();
        let (done, stopped) = std::sync::mpsc::channel();
        let (path, served, claim_paths) = (socket.clone(), agent.clone(), paths.clone());
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let (_lock, listener) = claim(&claim_paths, &path).unwrap();
                let watch = Watch::new(&path, &claim_paths.agent_socket, Duration::from_millis(50))
                    .unwrap();
                ready.send(()).unwrap();
                let _ = serve_watched(listener, served, own_uid(), Some(watch)).await;
                let _ = done.send(());
            });
        });
        started.recv().unwrap();
        (socket, paths, agent, stopped)
    }

    #[test]
    fn an_agent_whose_socket_is_removed_wipes_its_keys_and_stops() {
        let dir = short_dir();
        let (socket, paths, agent, stopped) = watched_agent(dir.path());
        assert!(KeyAgentClient::at(socket.clone()).is_running());
        // Still reachable: it keeps serving.
        assert!(stopped.recv_timeout(Duration::from_millis(300)).is_err());
        // logind removes the runtime dir after the last session ends.
        std::fs::remove_dir_all(dir.path().join("run")).unwrap();
        stopped
            .recv_timeout(Duration::from_secs(5))
            .expect("the orphaned agent kept serving");
        assert!(!agent.status().unwrap().unlocked, "its keys are wiped");
        assert!(
            !paths.agent_socket.exists(),
            "its record (naming the removed socket) is gone"
        );
    }

    #[test]
    fn an_agent_whose_socket_is_replaced_stops() {
        let dir = short_dir();
        let (socket, paths, agent, stopped) = watched_agent(dir.path());
        std::fs::remove_file(&socket).unwrap();
        let _other = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        stopped
            .recv_timeout(Duration::from_secs(5))
            .expect("an agent whose socket was replaced kept serving");
        assert!(!agent.status().unwrap().unlocked);
        // Another listener owns that path now: the record is left alone.
        assert_eq!(recorded_socket(&paths.agent_socket), Some(socket));
    }

    #[test]
    fn an_agent_whose_record_names_another_socket_stops_and_leaves_it() {
        let dir = short_dir();
        let (_socket, paths, agent, stopped) = watched_agent(dir.path());
        let elsewhere = dir.path().join("elsewhere.sock");
        {
            use std::os::unix::ffi::OsStrExt;
            crate::memory::crypto::write_private(
                &paths.agent_socket,
                elsewhere.as_os_str().as_bytes(),
            )
            .unwrap();
        }
        stopped
            .recv_timeout(Duration::from_secs(5))
            .expect("an agent clients no longer find kept serving");
        assert!(!agent.status().unwrap().unlocked);
        assert_eq!(recorded_socket(&paths.agent_socket), Some(elsewhere));
    }

    /// A client for the key files in `config` from a session whose runtime
    /// dir is `runtime`, whose launcher starts nothing, waiting 300 ms.
    fn idle_launch_client(config: &Path, runtime: &Path) -> KeyAgentClient {
        KeyAgentClient::finding(
            config,
            Some(runtime.as_os_str().to_owned()),
            Some(Box::new(|| -> Result<()> { Ok(()) })),
        )
        .waiting(Duration::from_millis(300))
    }

    #[test]
    fn a_holder_that_cant_be_confirmed_as_a_key_agent_is_not_named() {
        let dir = short_dir();
        let config = dir.path().join("config");
        let paths = KeyPaths::in_dir(&config);
        make_private(&dir.path().join("rb"));
        // The holder (this test process) records its pid and answers on no
        // socket, but it isn't an `atem key-agent`: no pid is named.
        let _held = lock_key_dir(&paths, Duration::ZERO).unwrap();
        let pid = std::process::id();
        assert_eq!(
            std::fs::read_to_string(&paths.agent_lock).unwrap().trim(),
            pid.to_string()
        );
        let socket = dir.path().join("rb").join("atem").join("agent.sock");
        let started = std::time::Instant::now();
        let error = claim_waiting(&paths, &socket, Duration::from_millis(300))
            .err()
            .unwrap();
        assert!(started.elapsed() >= Duration::from_millis(300), "it waited");
        assert!(error.downcast_ref::<StuckAgent>().is_some(), "{error:#}");
        for text in [
            format!("{error:#}"),
            format!(
                "{:#}",
                idle_launch_client(&config, &dir.path().join("rb"))
                    .status()
                    .err()
                    .unwrap()
            ),
        ] {
            assert!(!text.contains(&format!("{pid}")), "{text}");
            assert!(text.contains("pgrep -af '[a]tem key-agent'"), "{text}");
            assert!(text.contains("pkill -u"), "{text}");
            assert!(!text.contains("didn't start"), "{text}");
        }
        assert!(!socket.exists());
    }

    #[test]
    fn an_unheld_lock_naming_a_live_pid_names_no_one() {
        let dir = short_dir();
        let config = dir.path().join("config");
        let paths = KeyPaths::in_dir(&config);
        make_private(&dir.path().join("rb"));
        // Left by an agent that exited (or from before a reboot): the pid
        // now belongs to a live, unrelated process (here: this one).
        std::fs::create_dir_all(&config).unwrap();
        let pid = std::process::id();
        std::fs::write(&paths.agent_lock, format!("{pid}\n")).unwrap();
        let text = format!(
            "{:#}",
            idle_launch_client(&config, &dir.path().join("rb"))
                .status()
                .err()
                .unwrap()
        );
        assert!(text.contains("didn't start"), "{text}");
        assert!(!text.contains(&format!("{pid}")), "{text}");
        assert!(!text.contains("kill"), "{text}");
    }

    /// Makes `dir` unreadable until dropped (then 0700 again, so the temp
    /// dir can be removed).
    struct Unreadable(PathBuf);

    impl Unreadable {
        fn new(dir: &Path) -> Self {
            std::fs::set_permissions(dir, std::os::unix::fs::PermissionsExt::from_mode(0o000))
                .unwrap();
            Self(dir.to_path_buf())
        }
    }

    impl Drop for Unreadable {
        fn drop(&mut self) {
            let _ = std::fs::set_permissions(
                &self.0,
                std::os::unix::fs::PermissionsExt::from_mode(0o700),
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_confirmed_key_agent_that_no_one_can_reach_is_named_with_its_pid() {
        let dir = short_dir();
        let home = dir.path().join("home");
        let (run_a, run_b) = (dir.path().join("ra"), dir.path().join("rb"));
        std::fs::create_dir_all(&home).unwrap();
        make_private(&run_a);
        make_private(&run_b);
        let agent = key_agent_process(&home, &run_a, &dir.path().join("a.log"));
        let socket_a = run_a.join("atem").join("agent.sock");
        assert!(eventually(
            || KeyAgentClient::at(socket_a.clone()).is_running()
        ));
        let pid = agent.0.id();
        // Its socket directory can't be entered: nobody can connect, yet the
        // agent itself can't tell (not a NotFound) and keeps its lock.
        let _blocked = Unreadable::new(&run_a.join("atem"));
        let config = home.join(".config").join("atem");
        let paths = KeyPaths::in_dir(&config);
        let error = claim_waiting(
            &paths,
            &run_b.join("atem").join("agent.sock"),
            Duration::from_millis(300),
        )
        .err()
        .unwrap();
        let client = idle_launch_client(&config, &run_b);
        for text in [
            format!("{error:#}"),
            format!("{:#}", client.status().err().unwrap()),
        ] {
            assert!(text.contains(&format!("pid {pid}")), "{text}");
            assert!(text.contains(&format!("`kill {pid}`")), "{text}");
        }
    }

    #[test]
    fn only_a_missing_or_renamed_socket_orphans_the_agent() {
        let dir = short_dir();
        let run = dir.path().join("run");
        make_private(&run);
        let socket = run.join("agent.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let record = dir.path().join("agent.socket");
        let write_record = |path: &Path| {
            use std::os::unix::ffi::OsStrExt;
            crate::memory::crypto::write_private(&record, path.as_os_str().as_bytes()).unwrap();
        };
        write_record(&socket);
        let watch = Watch::new(&socket, &record, Duration::from_secs(5)).unwrap();
        assert_eq!(watch.orphaned(), None);
        // Errors other than NotFound (here: EACCES on the socket, EISDIR on
        // the record) say nothing about the agent: it keeps serving.
        {
            let _blocked = Unreadable::new(&run);
            assert_eq!(watch.orphaned(), None);
        }
        std::fs::remove_file(&record).unwrap();
        std::fs::create_dir(&record).unwrap();
        assert_eq!(watch.orphaned(), None);
        std::fs::remove_dir(&record).unwrap();
        // A missing record, or one naming another path, orphans it.
        assert!(watch.orphaned().is_some());
        write_record(&dir.path().join("other.sock"));
        assert!(watch.orphaned().is_some());
        write_record(&socket);
        assert_eq!(watch.orphaned(), None);
        std::fs::remove_file(&socket).unwrap();
        assert!(watch.orphaned().is_some());
    }

    #[test]
    fn a_relative_runtime_dir_is_ignored() {
        let dir = short_dir();
        let config = dir.path().join("config");
        let private = dir.path().join("private");
        make_private(&private);
        // `private` as seen from the current directory.
        let cwd = std::env::current_dir().unwrap();
        let mut relative = PathBuf::new();
        for _ in cwd.components().skip(1) {
            relative.push("..");
        }
        relative.push(private.strip_prefix("/").unwrap());
        assert!(relative.is_relative() && relative.is_dir());
        assert_eq!(
            socket_path_in(&config, Some(relative.into_os_string())),
            config.join("agent.sock")
        );
        assert_eq!(
            socket_path_in(&config, Some(private.clone().into_os_string())),
            private.join("atem").join("agent.sock")
        );
    }
}
