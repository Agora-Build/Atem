//! The cred agent's Unix socket: newline-delimited JSON, `"v": 2` on every
//! request, same-user peers only, and binary frames for `Crypt` on a
//! connection that agreed to them in its build check (agent_frame.rs).
//! `atem cred-agent` serves it; commands that need keys connect, starting
//! the agent when none is running. A process shares one client per agent
//! (`shared`), which keeps one connection between requests
//! (`CredAgentClient::call`).
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
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use zeroize::Zeroizing;

use crate::daemon::{
    self, check_parent_dir, lock_is_held, peer_uid, prepare_socket_dir, recorded_socket,
};
use crate::memory::account_keys::{CryptOp, CryptOut};
use crate::memory::agent_frame::{self, Head};
use crate::memory::cred_agent::{
    CredAgent, CredAgentApi, PROTOCOL_VERSION, Reply, Request, build_id,
};
use crate::memory::encoding::{SecretBytes, WipingBuf, wipe, wipe_uninit};
use crate::paths::CredPaths;

/// Bounds a misbehaving peer. A `Crypt` batch is kept under 2 MiB of input by
/// `EncryptionContext`, and one skill (at most 1 MiB, base64 on the wire)
/// always fits.
const MAX_LINE: usize = 8 << 20;
/// The read buffer an agent keeps for a connection between requests (what
/// `WipingBuf::new` allocates): a bigger one goes once its request is answered.
const KEPT_BUFFER: usize = 4 << 10;
/// A connection that says nothing for this long is dropped.
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// How long a stopping agent lets requests already in flight finish.
const DRAIN_WAIT: Duration = Duration::from_secs(1);
/// How long `atem cred lock` waits for the agent to go away.
const STOP_WAIT: Duration = Duration::from_secs(2);

fn own_uid() -> u32 {
    unsafe { libc::getuid() }
}

/// `$XDG_RUNTIME_DIR/atem/cred-agent.sock` when that directory is safe,
/// else `~/.config/atem/cred/agent.sock` (`CredPaths::agent_sock`).
pub fn agent_socket_path() -> PathBuf {
    #[cfg(test)]
    return socket_path_in(&crate::test_profile::dir(), None);
    #[cfg(not(test))]
    socket_path_in(
        &crate::config::AtemConfig::config_dir(),
        std::env::var_os("XDG_RUNTIME_DIR"),
    )
}

/// The socket path for `config_dir` and the runtime dir `runtime_dir`
/// (used only when it is safe).
fn socket_path_in(config_dir: &Path, runtime_dir: Option<OsString>) -> PathBuf {
    socket_path_for(&CredPaths::in_dir(config_dir), runtime_dir)
}

/// The socket path for the cred directory `paths` and the runtime dir
/// `runtime_dir` (used only when it is safe).
fn socket_path_for(paths: &CredPaths, runtime_dir: Option<OsString>) -> PathBuf {
    // A relative runtime dir would depend on the current directory: unset.
    let runtime = runtime_dir.filter(|dir| {
        Path::new(dir).is_absolute() && check_parent_dir(Path::new(dir), own_uid()).is_ok()
    });
    paths.agent_sock(runtime.as_deref().map(Path::new))
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
        .map_err(|_| anyhow!("cred agent request is not UTF-8"))?;
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
    let head: RequestHead = serde_json::from_str(line).context("cred agent request is not JSON")?;
    match head.v {
        Some(PROTOCOL_VERSION) => {}
        other => bail!(
            "unsupported cred agent protocol version {}; this agent speaks v{PROTOCOL_VERSION}",
            other.map_or_else(|| "(none)".to_string(), |v| v.to_string())
        ),
    }
    if head.op.as_deref() == Some("load_unlocked") {
        let wire: LoadUnlockedWire =
            serde_json::from_str(line).context("cred agent request is malformed")?;
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
            serde_json::from_str(line).context("cred agent request is malformed")?;
        return Ok(Request::Crypt {
            astation_id: wire.astation_id,
            ops: wire.ops,
        });
    }
    serde_json::from_str(line).context("cred agent request is malformed")
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
        "the running cred agent speaks protocol v{version}, this atem speaks v{PROTOCOL_VERSION}; check `atem status` first (a storage key not yet held by Astation needs `atem cred unlock` from the atem that started the agent), then stop it with `pkill -u \"$USER\" -f 'atem cred-agent'` (its keys stay sealed on disk) and retry"
    )
}

pub(crate) fn decode_response(line: &str) -> Result<Reply> {
    let line = line.trim();
    let head: ResponseHead =
        serde_json::from_str(line).context("the cred agent sent an unreadable reply")?;
    if head.v != PROTOCOL_VERSION {
        return Err(version_mismatch(head.v));
    }
    if !head.ok {
        bail!(
            "{}",
            head.error
                .unwrap_or_else(|| "the cred agent refused the request".into())
        );
    }
    let Some(reply) = head.reply else {
        bail!("the cred agent sent an empty reply");
    };
    if reply.kind.as_deref() == Some("crypted") {
        let crypted: CryptedResponse =
            serde_json::from_str(line).context("the cred agent sent an unreadable reply")?;
        return Ok(Reply::Crypted {
            results: crypted.reply.results,
        });
    }
    let response: Response =
        serde_json::from_str(line).context("the cred agent sent an unreadable reply")?;
    response
        .reply
        .ok_or_else(|| anyhow!("the cred agent sent an empty reply"))
}

/// A refused request's response.
fn refused(error: &anyhow::Error) -> Response {
    Response {
        v: PROTOCOL_VERSION,
        ok: false,
        error: Some(format!("{error:#}")),
        reply: None,
    }
}

const UNENCODABLE: &[u8] =
    b"{\"v\":2,\"ok\":false,\"error\":\"the cred agent could not encode its reply\"}";
const NOT_CRYPTED: &[u8] = b"{\"v\":2,\"ok\":false,\"error\":\"the cred agent answered a Crypt request with another kind of reply\"}";

/// The reply to the line `line`; whether it was a lock that stops the agent;
/// and whether it was a `status` that told the client this connection reads
/// frames (only when this agent reads them: `frames`).
fn respond(agent: &Mutex<CredAgent>, line: &str, frames: bool) -> (SecretBytes, bool, bool) {
    let mut stop = false;
    let mut agreed = false;
    let response = match decode_request(line).and_then(|request| {
        stop = matches!(request, Request::Lock { stop: true });
        agent.call(request)
    }) {
        Ok(mut reply) => {
            if let Reply::Status {
                frames: offered, ..
            } = &mut reply
                && frames
            {
                *offered = Some(agent_frame::VERSION);
                agreed = true;
            }
            Response {
                v: PROTOCOL_VERSION,
                ok: true,
                error: None,
                reply: Some(reply),
            }
        }
        Err(error) => refused(&error),
    };
    let stop = stop && response.ok;
    let reply = to_wiping_json(&response).unwrap_or_else(|_| {
        let mut buf = WipingBuf::new();
        buf.append(UNENCODABLE);
        buf.append(b"\n");
        buf
    });
    (reply.into_secret(), stop, agreed)
}

/// The reply frame to the `Crypt` frame `body`: its results, or the refusal
/// a JSON line would get, from the same `CredAgent::handle` (every check
/// of a `Crypt` applies). `Err` for a malformed frame.
fn respond_frame(agent: &Mutex<CredAgent>, head: Head, body: SecretBytes) -> Result<SecretBytes> {
    let (astation_id, ops) = agent_frame::decode_crypt(head, &body)?;
    // The ops hold their own copies.
    drop(body);
    Ok(match agent.call(Request::Crypt { astation_id, ops }) {
        Ok(Reply::Crypted { results }) => agent_frame::crypted_reply(&results),
        Ok(_) => agent_frame::json_reply(NOT_CRYPTED),
        // A refusal carries no secret.
        Err(error) => match serde_json::to_vec(&refused(&error)) {
            Ok(json) => agent_frame::json_reply(&json),
            Err(_) => agent_frame::json_reply(UNENCODABLE),
        },
    })
}

/// Another cred agent holds a lock or answers on the socket.
#[derive(Debug)]
pub struct AlreadyRunning(String);

impl AlreadyRunning {
    fn at(socket: &Path) -> Self {
        Self(format!("at {}", socket.display()))
    }
}

impl std::fmt::Display for AlreadyRunning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "a cred agent is already running {}", self.0)
    }
}

impl std::error::Error for AlreadyRunning {}

/// Lock files of the agents this process serves, by socket; held until it
/// exits or the agent on that socket stops.
static HELD_LOCKS: Mutex<Vec<(PathBuf, std::fs::File)>> = Mutex::new(Vec::new());

/// An exclusive lock on `agent.lock` beside the socket, so two agents starting
/// together can't both replace the socket. Waits briefly for a starting agent.
fn lock_agent(socket: &Path) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let lock_path = crate::paths::socket_lock(socket);
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

/// The pauses before a client's polls of an agent it just started, in ms. A
/// started agent listens within about 15 ms (its budget is 25), so the first
/// look is at 5 ms and the next ones stay close, then back off; a pause
/// after the last entry is `START_POLL_MAX`.
const START_POLLS_MS: [u64; 16] = [5, 5, 5, 5, 5, 5, 5, 5, 10, 10, 10, 20, 20, 20, 50, 50];
/// The pause between polls once an agent is slow to start (what every poll
/// used to be).
const START_POLL_MAX: Duration = Duration::from_millis(100);

/// The pause before poll number `poll` (from 0) of a started agent.
fn start_poll_pause(poll: usize) -> Duration {
    START_POLLS_MS
        .get(poll)
        .map_or(START_POLL_MAX, |ms| Duration::from_millis(*ms))
}

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

/// The pid recorded in the (held) lock file, only when that process is
/// confirmed to be an `atem cred-agent`: the pid survives the agent (and
/// reboots), so it may name an unrelated process. Linux: its command line
/// has a `cred-agent` argument and, where its fds can be listed (the agent
/// is not dumpable, so usually they can't), one of them is the lock file.
/// Elsewhere nothing can be confirmed.
fn confirmed_holder(lock_path: &Path) -> Option<u32> {
    let pid = daemon::read_lock_pid(lock_path)?;
    if !daemon::confirmed_atem_pid(pid, "cred-agent") {
        return None;
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) {
            let lock = std::fs::canonicalize(lock_path).ok()?;
            let holds = fds
                .flatten()
                .any(|fd| std::fs::read_link(fd.path()).is_ok_and(|target| target == lock));
            if !holds {
                return None;
            }
        }
    }
    Some(pid)
}

/// What to say when the key files' agent can't be reached (its lock is
/// held): names the holder's pid when it is confirmed to be a cred agent,
/// else how to find and stop one.
fn stuck_message(lock_path: &Path) -> String {
    let dir = lock_path.parent().unwrap_or(Path::new(".")).display();
    match confirmed_holder(lock_path) {
        Some(pid) => format!(
            "a cred agent (pid {pid}) holds the key files in {dir} but answers on no socket (its runtime dir may have been removed); stop it with `kill {pid}` and retry (its keys stay sealed on disk)"
        ),
        None => format!(
            "a cred agent holds the key files in {dir} but answers on no socket; find it with `pgrep -af '[a]tem cred-agent'` and stop it (`pkill -u \"$USER\" -f 'atem cred-agent'`), then retry (its keys stay sealed on disk)"
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
fn lock_key_dir(paths: &CredPaths, wait: Duration) -> Result<std::fs::File> {
    let lock_path = &paths.agent_lock;
    let deadline = std::time::Instant::now() + wait;
    loop {
        if let Some(lock) = daemon::lock_exclusive_with_pid(lock_path)? {
            return Ok(lock.into_file());
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
}

/// Takes the key directory for this agent and listens on `socket`, then
/// records `socket` in `paths.agent_socket` (0600, atomic) for clients that
/// would look elsewhere. The returned lock must live as long as the agent.
pub fn claim(
    paths: &CredPaths,
    socket: &Path,
) -> Result<(std::fs::File, tokio::net::UnixListener)> {
    claim_waiting(paths, socket, CLAIM_WAIT)
}

fn claim_waiting(
    paths: &CredPaths,
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
    let listener = daemon::listen_replacing_dead(socket).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AddrInUse {
            anyhow::Error::from(AlreadyRunning::at(socket))
        } else {
            error.into()
        }
    })?;
    if let Ok(mut held) = HELD_LOCKS.lock() {
        held.push((socket.to_path_buf(), lock));
    }
    Ok(listener)
}

/// Serves `agent` to peers running as `allowed_uid`; others are dropped.
#[cfg(test)]
pub async fn serve(
    listener: tokio::net::UnixListener,
    agent: Arc<Mutex<CredAgent>>,
    allowed_uid: u32,
) -> Result<()> {
    serve_with(listener, agent, allowed_uid, None, true).await
}

/// `serve` as a released agent (v0.6.11 to v0.8.3) would: its `status`
/// offers no frames and it reads only JSON lines (a frame's first byte is
/// the start of a line that isn't JSON).
#[cfg(test)]
pub(crate) async fn serve_without_frames(
    listener: tokio::net::UnixListener,
    agent: Arc<Mutex<CredAgent>>,
    allowed_uid: u32,
) -> Result<()> {
    serve_with(listener, agent, allowed_uid, None, false).await
}

/// `serve`, and with a `watch`, checks every `watch.every` that clients can
/// still reach the agent; once they can't, wipes its keys and returns.
/// A `Lock { stop: true }` (already wiped while handling it) makes it stop
/// accepting, remove its socket (and record), give requests in flight up to
/// `DRAIN_WAIT` to finish, then drop the rest and return.
pub(crate) async fn serve_watched(
    listener: tokio::net::UnixListener,
    agent: Arc<Mutex<CredAgent>>,
    allowed_uid: u32,
    watch: Option<Watch>,
) -> Result<()> {
    serve_with(listener, agent, allowed_uid, watch, true).await
}

/// `serve_watched`, reading frames on connections that agree to them only
/// with `frames`.
async fn serve_with(
    listener: tokio::net::UnixListener,
    agent: Arc<Mutex<CredAgent>>,
    allowed_uid: u32,
    watch: Option<Watch>,
    frames: bool,
) -> Result<()> {
    // The socket this listener is bound to, to remove it when stopping (only
    // while it is still the file bound here).
    let bound = listener
        .local_addr()
        .ok()
        .and_then(|addr| addr.as_pathname().map(Path::to_path_buf))
        .and_then(|path| {
            let meta = std::fs::symlink_metadata(&path).ok()?;
            Some((path, (meta.dev(), meta.ino())))
        });
    let (stopping, mut stop_requested) = tokio::sync::watch::channel(false);
    let stopping = Arc::new(stopping);
    let mut connections = tokio::task::JoinSet::new();
    let mut checks = tokio::time::interval(
        watch
            .as_ref()
            .map_or(Duration::from_secs(3600), |w| w.every),
    );
    checks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // When the freed memory is given back: `TrimDue`, pushed back by the
    // connections; the sleep is armed while a trim is due.
    let trim_due = Arc::new(TrimDue::default());
    let mut trim = std::pin::pin!(tokio::time::sleep(TRIM_IDLE));
    let mut trim_armed = false;
    loop {
        while connections.try_join_next().is_some() {}
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            _ = stop_requested.wait_for(|stop| *stop) => break,
            _ = trim_due.pushed.notified() => {
                if let Some(at) = trim_due.at() {
                    trim.as_mut().reset(at);
                    trim_armed = true;
                }
                continue;
            }
            _ = trim.as_mut(), if trim_armed => {
                match trim_due.trim_if_due() {
                    Some(later) => trim.as_mut().reset(later),
                    None => trim_armed = false,
                }
                continue;
            }
            _ = checks.tick(), if watch.is_some() => {
                if let Some(watch) = &watch
                    && let Some(why) = watch.orphaned()
                {
                    eprintln!("cred agent: {why}; no client can reach this agent, so it wipes its keys and exits");
                    if let Ok(mut agent) = agent.lock() {
                        let _ = agent.handle(Request::Lock { stop: false });
                    }
                    watch.clean_up();
                    return Ok(());
                }
                continue;
            }
        };
        let stream = match accepted {
            Ok((stream, _)) => stream,
            // A client that left before it was accepted (macOS can say so
            // here): nothing to serve, nothing to wait for.
            Err(error)
                if peer_gone(&error) || error.kind() == std::io::ErrorKind::ConnectionAborted =>
            {
                continue;
            }
            Err(error) => {
                // e.g. out of file descriptors: keep serving once there is room.
                eprintln!("cred agent: accept failed: {error}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let (agent, stopping, trim_due) = (agent.clone(), stopping.clone(), trim_due.clone());
        connections.spawn(async move {
            if let Err(error) =
                serve_connection(stream, &agent, allowed_uid, &stopping, &trim_due, frames).await
            {
                eprintln!("cred agent: {error:#}");
            }
            trim_due.push_back();
        });
    }
    eprintln!("cred agent: locked by `atem cred lock`; exiting");
    // Unlink before closing the listener: clients count the agent as stopped
    // once a dial fails, and by then its socket file must be gone too.
    if let Some((path, identity)) = &bound
        && std::fs::symlink_metadata(path).is_ok_and(|meta| (meta.dev(), meta.ino()) == *identity)
    {
        let _ = std::fs::remove_file(path);
    }
    drop(listener);
    if let Some((path, _)) = &bound
        && let Ok(mut held) = HELD_LOCKS.lock()
    {
        held.retain(|(socket, _)| socket != path);
    }
    if let Some(watch) = &watch {
        watch.clean_up();
    }
    let drained = tokio::time::timeout(DRAIN_WAIT, async {
        while connections.join_next().await.is_some() {}
    })
    .await;
    if drained.is_err() {
        eprintln!("cred agent: dropped requests still in flight");
        connections.abort_all();
    }
    // A request that finished after the lock (an unlock, say) is wiped too.
    if let Ok(mut agent) = agent.lock() {
        let _ = agent.handle(Request::Lock { stop: false });
    }
    Ok(())
}

/// One connection: JSON lines, and frames once a `status` answered here
/// offered them (only when this agent reads them: `frames`). A malformed
/// frame closes it with an error. A request or reply of `TRIM_BYTES` or
/// more pushes `trim_due` back before its reply is written, and again once
/// its buffers are freed.
async fn serve_connection(
    stream: tokio::net::UnixStream,
    agent: &Mutex<CredAgent>,
    allowed_uid: u32,
    stopping: &tokio::sync::watch::Sender<bool>,
    trim_due: &TrimDue,
    frames: bool,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let peer = match stream.peer_cred() {
        Ok(cred) => cred.uid(),
        // The client left before it was served (a liveness check such as
        // `is_running`): nothing to answer and nothing to report. macOS says
        // so here (its peer pid needs a connected peer: ENOTCONN), Linux
        // only at the first read.
        Err(error) if peer_gone(&error) => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if peer != allowed_uid {
        bail!("refused a connection from uid {peer}");
    }
    let mut stopped = stopping.subscribe();
    let (mut read, mut write) = stream.into_split();
    let mut lines = Lines::new();
    loop {
        let mut answered = false;
        let mut large = false;
        while let Some(message) = lines.next_message()? {
            let (reply, stop, size) = match message {
                Message::Line(line) => {
                    let end = line.len() - 1;
                    let (reply, stop, agreed) = match std::str::from_utf8(&line[..end]) {
                        Ok(text) => respond(agent, text, frames),
                        Err(_) => respond(agent, "", frames),
                    };
                    let size = line.len();
                    drop(line);
                    if agreed {
                        lines.frames = true;
                    }
                    (reply, stop, size)
                }
                Message::Frame(head, body) => (respond_frame(agent, head, body)?, false, head.len),
            };
            if size.max(reply.len()) >= TRIM_BYTES {
                large = true;
                trim_due.push_back();
            }
            write.write_all(&reply).await?;
            drop(reply);
            answered = true;
            if stop {
                stopping.send_replace(true);
                return Ok(());
            }
        }
        if answered {
            lines.settle();
            #[cfg(test)]
            SETTLED.with(|log| {
                if let Some(log) = &*log.borrow() {
                    log.lock().unwrap().push(lines.held());
                }
            });
        }
        if large {
            trim_due.push_back();
        }
        if lines.too_long() {
            bail!("a request is too long");
        }
        // A stopping agent takes no further request; one only partly read
        // is dropped (its client sees the connection close).
        let n = tokio::select! {
            read = tokio::time::timeout(IDLE_TIMEOUT, read.read(lines.buffer())) => {
                read.map_err(|_| anyhow!("closed an idle connection"))??
            }
            _ = stopped.wait_for(|stop| *stop) => return Ok(()),
        };
        if n == 0 {
            return Ok(());
        }
        lines.take(n);
    }
}

/// Tests: what connections held once they had answered, one entry each time.
#[cfg(test)]
type HeldLog = Arc<Mutex<Vec<Vec<u8>>>>;

#[cfg(test)]
thread_local! {
    /// Tests: what the connections served on this thread hold once they
    /// have answered (`Lines::held`), when a test asks for it.
    static SETTLED: std::cell::RefCell<Option<HeldLog>> = const { std::cell::RefCell::new(None) };
    /// Tests: when the agent served on this thread gives its freed memory
    /// back (`TrimLog`), when a test asks for it.
    static TRIMS: std::cell::RefCell<Option<Arc<TrimLog>>> =
        const { std::cell::RefCell::new(None) };
}

/// A message read on an agent connection.
enum Message {
    /// A JSON line, with its newline.
    Line(SecretBytes),
    /// A frame's header and body.
    Frame(Head, SecretBytes),
}

/// The frame a connection is reading: its body is allocated at the length
/// its header declared (within the bounds), and read straight into.
struct Incoming {
    head: Head,
    body: SecretBytes,
    filled: usize,
}

/// Whether `error` says the other end of a connection has gone (closed or
/// reset). macOS reports a peer that closed as ENOTCONN or ECONNRESET in
/// places where Linux reports EOF.
fn peer_gone(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::NotConnected | std::io::ErrorKind::ConnectionReset
    )
}

/// Whether `error`, from connecting to an agent's socket path, proves that
/// no agent listens there: the path is missing, or nothing listens on it
/// (refused). Nothing else does: a reset or not-connected socket (how macOS
/// reports a listener that is closing, or a peer that closed), a permission
/// error or anything unexpected may hide a running, unlocked agent, so it is
/// an error, never "not running".
fn proves_absent(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
    )
}

/// What an agent connection has read and not yet handled (`pending`, or the
/// body of a frame being read: `frame`), and the chunk lines are read into.
/// Requests carry secrets (device keys, plain text to seal) and clients keep
/// their connection between requests, so once the messages read so far are
/// answered, `settle` wipes every byte they left in `pending` and the chunk
/// (a frame's body goes, wiped, with its answer). All of them are wiped
/// whole when the connection ends.
struct Lines {
    pending: WipingBuf,
    chunk: Zeroizing<[u8; 4096]>,
    /// Bytes of `pending` already known to hold no newline: a multi-MiB
    /// `Crypt` line arrives in 4 KiB reads, and rescanning it all each time
    /// would be quadratic.
    scanned: usize,
    /// Frames are read on this connection: a `status` answered here said so.
    frames: bool,
    frame: Option<Incoming>,
    /// Tests: how much of `pending`'s allocation is known written.
    #[cfg(test)]
    written: usize,
}

impl Lines {
    fn new() -> Self {
        Self {
            pending: WipingBuf::new(),
            chunk: Zeroizing::new([0u8; 4096]),
            scanned: 0,
            frames: false,
            frame: None,
            #[cfg(test)]
            written: 0,
        }
    }

    /// The next whole message read, if one has arrived. `Err` for a frame
    /// whose header is out of bounds: nothing is allocated for it.
    fn next_message(&mut self) -> Result<Option<Message>> {
        if self.frame.is_none()
            && self.frames
            && self.pending.0.first() == Some(&agent_frame::MAGIC)
        {
            let Some(head) = self.pending.0.first_chunk::<{ agent_frame::HEADER }>() else {
                return Ok(None);
            };
            let head = agent_frame::request_head(head)?;
            let mut body = SecretBytes::zeroed(head.len);
            let read = &self.pending.0[agent_frame::HEADER..];
            let filled = head.len.min(read.len());
            body[..filled].copy_from_slice(&read[..filled]);
            self.pending.0.drain(..agent_frame::HEADER + filled);
            self.scanned = 0;
            self.frame = Some(Incoming { head, body, filled });
        }
        if let Some(incoming) = &self.frame {
            if incoming.filled < incoming.body.len() {
                return Ok(None);
            }
            let Some(Incoming { head, body, .. }) = self.frame.take() else {
                unreachable!("a frame is being read");
            };
            return Ok(Some(Message::Frame(head, body)));
        }
        Ok(self.next_line().map(Message::Line))
    }

    /// The next whole line read (with its newline), if one has arrived.
    fn next_line(&mut self) -> Option<SecretBytes> {
        let Some(offset) = self.pending.0[self.scanned..]
            .iter()
            .position(|byte| *byte == b'\n')
        else {
            self.scanned = self.pending.0.len();
            return None;
        };
        let end = self.scanned + offset;
        self.scanned = 0;
        Some(SecretBytes::from_vec(
            self.pending.0.drain(..=end).collect(),
        ))
    }

    /// Where the next read goes: the rest of a frame's body, else the chunk.
    fn buffer(&mut self) -> &mut [u8] {
        match &mut self.frame {
            Some(incoming) => &mut incoming.body[incoming.filled..],
            None => &mut self.chunk[..],
        }
    }

    /// Takes the `n` bytes just read into `buffer`.
    fn take(&mut self, n: usize) {
        match &mut self.frame {
            Some(incoming) => incoming.filled += n,
            None => self.pending.append(&self.chunk[..n]),
        }
    }

    fn too_long(&self) -> bool {
        self.pending.0.len() > MAX_LINE
    }

    /// Once the messages read so far are answered: wipes the whole of
    /// `pending` past its unread bytes (the start of a next request, if any),
    /// so its allocation holds nothing of an answered request, and the whole
    /// chunk. A buffer that grew for a big request goes instead, wiped whole
    /// as it is dropped.
    fn settle(&mut self) {
        if self.pending.0.is_empty() && self.pending.0.capacity() > KEPT_BUFFER {
            self.pending = WipingBuf::new();
            #[cfg(test)]
            {
                self.written = 0;
            }
        } else {
            wipe_uninit(self.pending.0.spare_capacity_mut());
            #[cfg(test)]
            {
                self.written = self.pending.0.capacity();
            }
        }
        wipe(&mut self.chunk[..]);
    }

    /// Tests: everything this connection holds in user space whose bytes
    /// are known written (`retained`).
    #[cfg(test)]
    fn held(&self) -> Vec<u8> {
        self.retained(self.written)
    }

    /// The first `len` bytes of everything this connection holds in user
    /// space: `pending`'s allocation (its unread bytes, then the rest of its
    /// capacity), then `chunk`, then what a frame being read has of its body.
    /// Only bytes that were written are read.
    #[cfg(test)]
    fn retained(&self, len: usize) -> Vec<u8> {
        let capacity = self.pending.0.capacity();
        let len = len.min(capacity);
        // SAFETY: the first `len` bytes of the allocation were all written
        // (read data or a wipe), and the allocation is `capacity` long.
        let pending = unsafe { std::slice::from_raw_parts(self.pending.0.as_ptr(), len) };
        let frame = self
            .frame
            .as_ref()
            .map_or(&[][..], |incoming| &incoming.body[..incoming.filled]);
        [pending, &self.chunk[..], frame].concat()
    }
}

/// No core dumps, no ptrace by the same user, and (when the limit allows)
/// no swapping (`lock_memory`). Linux only; elsewhere a no-op.
fn harden_process() {
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0 as libc::c_ulong) } != 0 {
            eprintln!(
                "cred agent: PR_SET_DUMPABLE failed ({})",
                std::io::Error::last_os_error()
            );
        }
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        let known = unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut limit) } == 0;
        let locked = lock_memory(known.then_some(limit), |flags| {
            // SAFETY: mlockall takes flags only.
            if unsafe { libc::mlockall(flags) } == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
        if let Some(line) = locked.log_line() {
            eprintln!("{line}");
        }
    }
}

/// What `lock_memory` did.
#[cfg(target_os = "linux")]
#[derive(Debug)]
enum MemoryLock {
    /// Every page, mapped now or later, locked as it is first touched.
    OnFault,
    /// Every page locked and faulted in at once (a kernel without
    /// `MCL_ONFAULT`).
    AllAtOnce,
    /// Not attempted: `RLIMIT_MEMLOCK` unknown or too low.
    TooLow,
    /// `mlockall` failed: nothing is locked.
    Failed(std::io::Error),
}

#[cfg(target_os = "linux")]
impl MemoryLock {
    /// The agent's log line for it (`None` once memory is locked).
    fn log_line(&self) -> Option<String> {
        match self {
            Self::OnFault | Self::AllAtOnce => None,
            Self::TooLow => Some(
                "cred agent: not locking memory (RLIMIT_MEMLOCK is too low); keys could reach swap"
                    .to_string(),
            ),
            Self::Failed(error) => Some(format!(
                "cred agent: mlockall failed ({error}); keys could reach swap"
            )),
        }
    }
}

/// Locks every page of the process, mapped now or later, so none can reach
/// swap, through `mlockall` (the system call, or a test's stand-in), when
/// `limit` (`RLIMIT_MEMLOCK`, `None` when unknown) is unlimited or at least
/// 512 MiB: with `MCL_FUTURE` every allocation past the limit would fail.
/// Each page is locked as it is first touched (`MCL_ONFAULT`, Linux 4.4): a
/// page that holds anything was touched, so it is locked before it holds
/// it, and the pages never touched (most of the mapped executable, the
/// unused parts of stacks and reservations) aren't read in just to be
/// locked. A kernel without `MCL_ONFAULT` (EINVAL) gets every page faulted
/// in and locked at once, as before. Locked only when a call returned
/// success; a failed call locks nothing.
#[cfg(target_os = "linux")]
fn lock_memory(
    limit: Option<libc::rlimit>,
    mut mlockall: impl FnMut(libc::c_int) -> std::io::Result<()>,
) -> MemoryLock {
    let Some(limit) = limit else {
        return MemoryLock::TooLow;
    };
    if limit.rlim_cur != libc::RLIM_INFINITY && limit.rlim_cur < 512 << 20 {
        return MemoryLock::TooLow;
    }
    let all = libc::MCL_CURRENT | libc::MCL_FUTURE;
    match mlockall(all | libc::MCL_ONFAULT) {
        Ok(()) => MemoryLock::OnFault,
        Err(error) if error.raw_os_error() == Some(libc::EINVAL) => match mlockall(all) {
            Ok(()) => MemoryLock::AllAtOnce,
            Err(error) => MemoryLock::Failed(error),
        },
        Err(error) => MemoryLock::Failed(error),
    }
}

/// The agent's heap: every block up to `HEAP_BLOCKS` comes from it, and
/// it gives nothing back by itself until `HEAP_KEPT` is free at its top
/// (glibc's `M_MMAP_THRESHOLD`, at its largest value, and
/// `M_TRIM_THRESHOLD`). So the next large request reuses the pages the last
/// one freed instead of faulting them in (and locking them) again: left to
/// itself glibc gives big blocks back as they are freed, and a 2 MiB seal
/// then took about 1.6 times as long. `give_back_freed_memory` returns
/// what is free once the agent is idle.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
const HEAP_BLOCKS: libc::c_int = 32 << 20;
#[cfg(all(target_os = "linux", target_env = "gnu"))]
const HEAP_KEPT: libc::c_int = 64 << 20;

/// Sets the agent's heap (`HEAP_BLOCKS`). glibc only; elsewhere a no-op.
fn tune_allocator() {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    // SAFETY: mallopt only sets the allocator's parameters; called before
    // the agent starts its runtime.
    unsafe {
        if libc::mallopt(libc::M_MMAP_THRESHOLD, HEAP_BLOCKS) != 1
            || libc::mallopt(libc::M_TRIM_THRESHOLD, HEAP_KEPT) != 1
        {
            eprintln!("cred agent: could not set the allocator's thresholds");
        }
    }
}

/// A request or reply at least this big, or a connection's end, leaves
/// freed memory in the heap (`HEAP_BLOCKS`); the agent gives it back once
/// neither happened for `TRIM_IDLE`, so a burst of large requests reuses it.
const TRIM_BYTES: usize = 128 << 10;
#[cfg(not(test))]
const TRIM_IDLE: Duration = Duration::from_secs(1);
#[cfg(test)]
const TRIM_IDLE: Duration = Duration::from_millis(100);

/// When the agent gives its freed memory back (`give_back_freed_memory`):
/// `TRIM_IDLE` after the last request or reply of `TRIM_BYTES` or more, or
/// the last connection's end. The connections push it back as they go; the
/// serve loop sleeps until it and trims only once it has really passed.
#[derive(Default)]
struct TrimDue {
    at: Mutex<Option<tokio::time::Instant>>,
    /// Wakes the serve loop when `at` was pushed back.
    pushed: tokio::sync::Notify,
}

impl TrimDue {
    /// Puts the trim `TRIM_IDLE` from now.
    fn push_back(&self) {
        if let Ok(mut at) = self.at.lock() {
            *at = Some(tokio::time::Instant::now() + TRIM_IDLE);
        }
        #[cfg(test)]
        trim_log(|log| log.due.store(true, std::sync::atomic::Ordering::SeqCst));
        self.pushed.notify_one();
    }

    /// When the trim is due, if one is.
    fn at(&self) -> Option<tokio::time::Instant> {
        self.at.lock().ok().and_then(|at| *at)
    }

    /// Gives the freed memory back if the trim's time has come (then none
    /// is due any more); else when it is due, if it still is.
    fn trim_if_due(&self) -> Option<tokio::time::Instant> {
        let mut at = self.at.lock().ok()?;
        match *at {
            Some(when) if when > tokio::time::Instant::now() => Some(when),
            Some(_) => {
                *at = None;
                give_back_freed_memory();
                #[cfg(test)]
                trim_log(|log| log.due.store(false, std::sync::atomic::Ordering::SeqCst));
                None
            }
            None => None,
        }
    }
}

/// Tests: how many times the agent gave its freed memory back, and whether
/// a trim is due (set before a large request's reply is written, cleared
/// only after the trim that covers it).
#[cfg(test)]
#[derive(Default)]
pub(crate) struct TrimLog {
    trims: std::sync::atomic::AtomicUsize,
    due: std::sync::atomic::AtomicBool,
}

#[cfg(test)]
impl TrimLog {
    fn trims(&self) -> usize {
        self.trims.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn due(&self) -> bool {
        self.due.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Tests: `record` on the `TrimLog` of the agent served on this thread.
#[cfg(test)]
fn trim_log(record: impl FnOnce(&TrimLog)) {
    TRIMS.with(|log| {
        if let Some(log) = &*log.borrow() {
            record(log);
        }
    });
}

/// Gives the heap's free memory back to the system (glibc's `malloc_trim`):
/// what requests' buffers left there once they were wiped and freed. Under
/// `mlockall` only the free top of the heap can go (the kernel keeps locked
/// pages, free or not, in the middle of it): a block still in use above
/// freed ones, such as a connection opened while a large request was being
/// read, keeps them until it is freed and the next trim. glibc only;
/// elsewhere a no-op.
fn give_back_freed_memory() {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    // SAFETY: malloc_trim takes no pointer; the allocator locks itself.
    unsafe {
        libc::malloc_trim(0);
    }
    #[cfg(test)]
    trim_log(|log| {
        log.trims.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    });
}

/// `atem cred-agent`, called by `main` before any runtime exists: hardens
/// the process (`mlockall` among it) and sets its heap, then serves on a
/// current-thread runtime. The agent has no use for worker threads: every
/// request already runs under the agent's one lock, and each thread would
/// bring a 2 MiB stack and a malloc arena of its own
/// (designs/e2e-encryption.md, "Performance", F5). Every connection's I/O
/// waits without blocking the thread, so a client that stalls holds up
/// nobody; a request's own work (within the request limits) runs to its
/// end before another's starts.
pub fn cred_agent_main() -> Result<()> {
    harden_process();
    tune_allocator();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("could not start the cred agent's runtime")?
        .block_on(run_cred_agent())
}

/// Serves this user's agent until the process exits (`cred_agent_main`).
async fn run_cred_agent() -> Result<()> {
    // Taken now, before a rebuild can replace the executable on disk.
    let _ = build_id();
    let paths = CredPaths::default_paths();
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
    // Bound: a poll may connect from here; if the agent dies before serving, `open()` may relaunch it (rare, accepted).
    let watch = Watch::new(&socket, &paths.agent_socket, ORPHAN_CHECK)?;
    // A key-file error never stops the agent: it starts locked and says why
    // on `atem status` (see CredAgent::new).
    let agent = CredAgent::new(paths)?;
    eprintln!(
        "atem cred agent (protocol v{PROTOCOL_VERSION}, pid {}) listening on {}",
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

/// Starts `exe cred-agent` detached from this command and its terminal, with
/// `envs` added to its environment. Returns the agent's pid.
fn spawn_agent(exe: &Path, log: &Path, envs: &[(&str, &Path)]) -> Result<u32> {
    let envs: Vec<(OsString, OsString)> = envs
        .iter()
        .map(|(key, value)| (OsString::from(key), value.as_os_str().to_owned()))
        .collect();
    daemon::spawn_detached(exe, "cred-agent", Path::new("/"), log, &envs)
        .context("could not start the cred agent")
}

/// Where a test client's agent logs: beside its socket's directory.
#[cfg(test)]
fn test_log(socket: &Path) -> PathBuf {
    CredPaths::in_dir(socket.parent().unwrap_or(Path::new("/"))).agent_log
}

/// What a client sent (tests): connections opened for requests, requests
/// written (the build checks' included), build checks, and the requests
/// that went as frames.
#[cfg(test)]
#[derive(Default, Debug)]
pub(crate) struct Traffic {
    connections: std::sync::atomic::AtomicUsize,
    requests: std::sync::atomic::AtomicUsize,
    probes: std::sync::atomic::AtomicUsize,
    frames: std::sync::atomic::AtomicUsize,
    /// Looks for an agent this client started (`connect`).
    polls: std::sync::atomic::AtomicUsize,
    /// The pause slept before each of those looks.
    pauses: Mutex<Vec<Duration>>,
}

#[cfg(test)]
impl Traffic {
    fn add(counter: &std::sync::atomic::AtomicUsize) {
        counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    pub(crate) fn connections(&self) -> usize {
        self.connections.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub(crate) fn requests(&self) -> usize {
        self.requests.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub(crate) fn probes(&self) -> usize {
        self.probes.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub(crate) fn frames(&self) -> usize {
        self.frames.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub(crate) fn polls(&self) -> usize {
        self.polls.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub(crate) fn pauses(&self) -> Vec<Duration> {
        self.pauses.lock().unwrap().clone()
    }
}

/// How a client starts an agent when none answers.
type Launcher = Box<dyn Fn() -> Result<()> + Send + Sync>;

/// A connection idle this long is replaced before it carries the next
/// request. The agent drops connections idle for `IDLE_TIMEOUT`, and one it
/// may be dropping must never carry a request: nothing would tell whether
/// the agent read it.
const REUSE_IDLE: Duration = Duration::from_secs(30);
/// How long writing a request and getting its reply may take.
const REPLY_WAIT: Duration = Duration::from_secs(30);
/// How long the build check's `status` may take.
const CHECK_WAIT: Duration = Duration::from_secs(5);

/// The connection a client keeps between requests.
struct Conn {
    stream: UnixStream,
    /// When the last reply arrived: the agent's idle timer starts then.
    idle_since: std::time::Instant,
    /// Replies read on it: a request dropped unanswered goes once more only
    /// when its connection had answered before (a kept or checked one).
    replies: u32,
    /// The build check's `status` said the agent reads frames here
    /// (agent_frame.rs).
    frames: bool,
}

impl Conn {
    fn new(stream: UnixStream) -> Self {
        Self {
            stream,
            idle_since: std::time::Instant::now(),
            replies: 0,
            frames: false,
        }
    }

    fn idle(&self, reuse_idle: Duration) -> bool {
        self.idle_since.elapsed() >= reuse_idle
    }

    /// Whether the agent has closed it (or sent anything unasked).
    fn closed(&self) -> bool {
        let mut byte = 0u8;
        // SAFETY: peeks at most one byte into `byte`, without blocking.
        let peeked = unsafe {
            libc::recv(
                self.stream.as_raw_fd(),
                (&raw mut byte).cast(),
                1,
                libc::MSG_PEEK | libc::MSG_DONTWAIT,
            )
        };
        !(peeked < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::WouldBlock)
    }

    /// Writes `out`, wipes it while the agent works, and reads the reply (a
    /// frame to a frame).
    fn round_trip(&mut self, out: Outgoing) -> Result<Answer, Failed> {
        (&self.stream)
            .write_all(out.bytes())
            .map_err(|error| Failed::from_io(error, false))?;
        let frame = match &out {
            Outgoing::Line(_) => None,
            Outgoing::Frame { count, .. } => Some(*count),
        };
        drop(out);
        let answer = match frame {
            None => read_answer(&self.stream)?,
            Some(count) => read_frame(&self.stream, count)?,
        };
        self.idle_since = std::time::Instant::now();
        self.replies += 1;
        Ok(answer)
    }
}

/// What goes on a connection: a JSON line, or a `Crypt` frame of `count` ops.
enum Outgoing {
    Line(Zeroizing<String>),
    Frame { bytes: SecretBytes, count: usize },
}

impl Outgoing {
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Line(line) => line.as_bytes(),
            Self::Frame { bytes, .. } => bytes,
        }
    }
}

/// A reply as it was read.
enum Received {
    Line(WipingBuf),
    /// A reply frame's results.
    Results(Vec<CryptOut>),
    /// A reply frame's JSON response (a refusal).
    Json(SecretBytes),
    /// A reply frame that doesn't read (out of bounds, or its body): the
    /// connection goes with it.
    Unreadable,
}

/// A reply, and whether it was exactly one line with nothing after it, or
/// one whole frame: only then is its connection used again (anything the
/// agent sent after a frame is found before the next request).
struct Answer {
    reply: Received,
    in_step: bool,
}

/// Why a request got no reply.
enum Failed {
    /// The agent closed (or reset) the connection before any byte of the
    /// reply arrived.
    Unanswered(Option<std::io::Error>),
    /// Anything else: a timeout, or a reply cut short.
    Broken(std::io::Error),
}

impl Failed {
    fn from_io(error: std::io::Error, replying: bool) -> Self {
        use std::io::ErrorKind::{BrokenPipe, ConnectionAborted, ConnectionReset, NotConnected};
        if !replying
            && matches!(
                error.kind(),
                BrokenPipe | ConnectionReset | ConnectionAborted | NotConnected
            )
        {
            Self::Unanswered(Some(error))
        } else {
            Self::Broken(error)
        }
    }

    fn into_error(self) -> Option<std::io::Error> {
        match self {
            Self::Unanswered(error) => error,
            Self::Broken(error) => Some(error),
        }
    }
}

/// Reads one reply line without a `BufReader`, so no unwiped copy stays
/// behind. A reply cut short by the agent closing the connection is
/// returned as it is (it won't decode).
fn read_answer(mut stream: &UnixStream) -> Result<Answer, Failed> {
    let mut line = WipingBuf::new();
    let mut chunk = Zeroizing::new([0u8; 4096]);
    loop {
        let n = match stream.read(&mut chunk[..]) {
            Ok(0) if line.0.is_empty() => return Err(Failed::Unanswered(None)),
            Ok(n) => n,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(Failed::from_io(error, !line.0.is_empty())),
        };
        if n == 0 || line.0.len() > MAX_LINE {
            return Ok(Answer {
                reply: Received::Line(line),
                in_step: false,
            });
        }
        line.append(&chunk[..n]);
        // `contains` is memchr; a byte loop over every chunk of a MiB reply
        // would cost a millisecond.
        if chunk[..n].contains(&b'\n') {
            let first = chunk[..n].iter().position(|byte| *byte == b'\n');
            return Ok(Answer {
                reply: Received::Line(line),
                in_step: first == Some(n - 1),
            });
        }
    }
}

/// Reads the reply frame to a request of `count` ops: its header, then its
/// body, once its length passed the bounds, straight into one buffer of
/// that length, and parses it once. A header out of bounds (nothing more is
/// read) or a body that doesn't parse is `Unreadable`.
fn read_frame(stream: &UnixStream, count: usize) -> Result<Answer, Failed> {
    let mut head = [0u8; agent_frame::HEADER];
    read_full(stream, &mut head, false)?;
    let Ok(head) = agent_frame::reply_head(&head, count) else {
        return Ok(Answer {
            reply: Received::Unreadable,
            in_step: false,
        });
    };
    let mut body = SecretBytes::zeroed(head.len);
    read_full(stream, &mut body, true)?;
    let reply = if head.kind == agent_frame::REPLY_JSON {
        match std::str::from_utf8(&body) {
            Ok(_) => Received::Json(body),
            Err(_) => Received::Unreadable,
        }
    } else {
        match agent_frame::decode_crypted(head, &body) {
            Ok(results) => Received::Results(results),
            Err(_) => Received::Unreadable,
        }
    };
    let in_step = !matches!(reply, Received::Unreadable);
    Ok(Answer { reply, in_step })
}

/// Fills `buf` from `stream`. Closed before any byte of the reply (none read
/// yet: `replying` false): `Unanswered`; cut short later: `Broken`.
fn read_full(mut stream: &UnixStream, buf: &mut [u8], mut replying: bool) -> Result<(), Failed> {
    let mut filled = 0;
    while filled < buf.len() {
        match stream.read(&mut buf[filled..]) {
            Ok(0) if !replying => return Err(Failed::Unanswered(None)),
            Ok(0) => return Err(Failed::Broken(std::io::ErrorKind::UnexpectedEof.into())),
            Ok(n) => {
                filled += n;
                replying = true;
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(Failed::from_io(error, replying)),
        }
    }
    Ok(())
}

/// `request` as `conn` takes it: a `Crypt` as a frame where `conn` agreed to
/// frames and it fits their bounds, anything else as a JSON line.
fn outgoing(conn: &Conn, request: &Request) -> Result<Outgoing> {
    if conn.frames
        && let Request::Crypt { astation_id, ops } = request
        && let Some(bytes) = agent_frame::crypt_request(astation_id, ops)
    {
        return Ok(Outgoing::Frame {
            bytes,
            count: ops.len(),
        });
    }
    Ok(Outgoing::Line(encode_request(request)?))
}

/// Whether `request` may go once more on a new connection when its
/// connection dropped before any byte of the reply: only requests that
/// leave the agent as they found them (reads, signatures over the current
/// state, field operations; the prune `Crypt` and `HeldKid` run follows the
/// signed states, so running it twice changes nothing more). A request that
/// changes the agent never goes twice: a dropped connection is its error.
fn resendable(request: &Request) -> bool {
    match request {
        Request::Status
        | Request::PublicKeys
        | Request::Crypt { .. }
        | Request::HeldKid { .. }
        | Request::PendingRotation
        | Request::CheckGrant { .. }
        | Request::MigrationComplete { .. } => true,
        Request::CredentialProjects { .. }
        | Request::LoadUnlocked { .. }
        | Request::InstallGrant { .. }
        | Request::BeginUnlock { .. }
        | Request::FinishUnlock { .. }
        | Request::BeginRotation { .. }
        | Request::ConfirmRotation { .. }
        | Request::AbandonPending { .. }
        | Request::Lock { .. } => false,
    }
}

/// The clients this process shares (`shared`).
static SHARED: Mutex<Vec<Arc<CredAgentClient>>> = Mutex::new(Vec::new());

/// The process-wide client of the agent `client` reaches, built the way
/// `client` is: the one already shared for the same socket and key
/// directory, the same ability to start an agent and the same build to
/// check, else `client`, shared from now on. Every `EncryptionContext`,
/// knowledge and vault client of a process then uses one connection, checked
/// once (`autostart`), and `running_agent` callers another that never starts
/// an agent (`existing`). Keyed by the resolved paths, so clients of two
/// agents (two tests' temp profiles) never share.
pub(crate) fn shared(client: CredAgentClient) -> Arc<CredAgentClient> {
    let mut shared = SHARED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(known) = shared.iter().find(|known| {
        known.socket == client.socket
            && known.record == client.record
            && known.launcher.is_some() == client.launcher.is_some()
            && known.build == client.build
    }) {
        return known.clone();
    }
    let client = Arc::new(client);
    shared.push(client.clone());
    client
}

/// A client of the cred agent: one request at a time over one connection,
/// kept between requests.
pub struct CredAgentClient {
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
    /// With a build to compare (clients that may start an agent), every new
    /// connection first checks that the agent it reached is this build (a
    /// new connection may reach a restarted agent): a locked agent of
    /// another build is replaced, an unlocked one kept with a warning.
    build: Option<String>,
    /// `OLDER_BUILD`, once the check found an unlocked older agent.
    older_build: Mutex<Option<String>>,
    /// Look whether Atem's runtime is another build too, for the warning
    /// (this user's clients; never in tests).
    runtime_check: bool,
    /// The connection kept between requests; holding it is holding the
    /// right to send the next request.
    conn: Mutex<Option<Conn>>,
    #[cfg(test)]
    traffic: Traffic,
}

impl CredAgentClient {
    fn new(
        socket: PathBuf,
        record: Option<PathBuf>,
        launcher: Option<Launcher>,
        log: PathBuf,
        lock: Option<PathBuf>,
    ) -> Self {
        Self {
            socket,
            record,
            launcher,
            log,
            lock,
            start_wait: START_WAIT,
            expected_uid: own_uid(),
            build: None,
            older_build: Mutex::new(None),
            runtime_check: false,
            conn: Mutex::new(None),
            #[cfg(test)]
            traffic: Traffic::default(),
        }
    }

    /// A client for the agent at `socket` that never starts one.
    #[cfg(test)]
    pub(crate) fn at(socket: PathBuf) -> Self {
        Self::new(socket.clone(), None, None, test_log(&socket), None)
    }

    /// A client for this user's agent that starts it when none answers.
    #[cfg_attr(test, allow(dead_code))]
    pub fn autostart() -> Self {
        let mut client = Self::finding(
            &crate::config::AtemConfig::config_dir(),
            std::env::var_os("XDG_RUNTIME_DIR"),
            Some(Box::new(|| {
                spawn_agent(
                    &std::env::current_exe()?,
                    &CredPaths::default_paths().agent_log,
                    &[],
                )
                .map(|_| ())
            })),
        );
        client.build = Some(build_id().to_string());
        client.runtime_check = true;
        client
    }

    /// A client for this user's running agent that never starts one.
    #[cfg_attr(test, allow(dead_code))]
    pub fn existing() -> Self {
        let mut client = Self::finding(
            &crate::config::AtemConfig::config_dir(),
            std::env::var_os("XDG_RUNTIME_DIR"),
            None,
        );
        client.runtime_check = true;
        client
    }

    /// The warning for an unlocked agent of another build.
    fn older_build_text(&self) -> &'static str {
        crate::memory::cred_agent::older_build_warning(
            self.runtime_check && crate::memory::cred_agent::runtime_differs(),
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
        Self::for_paths(&CredPaths::in_dir(config_dir), runtime_dir, launcher)
    }

    /// A client for the agent of the cred directory `paths`, as seen from a
    /// session whose runtime dir is `runtime_dir`.
    pub(crate) fn for_paths(
        paths: &CredPaths,
        runtime_dir: Option<OsString>,
        launcher: Option<Launcher>,
    ) -> Self {
        Self::new(
            socket_path_for(paths, runtime_dir),
            Some(paths.agent_socket.clone()),
            launcher,
            paths.agent_log.clone(),
            Some(paths.agent_lock.clone()),
        )
    }

    /// A client for the agent at `socket` that starts it with `launcher`.
    #[cfg(test)]
    pub(crate) fn with_launcher(socket: PathBuf, launcher: Launcher) -> Self {
        Self::new(
            socket.clone(),
            None,
            Some(launcher),
            test_log(&socket),
            None,
        )
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

    /// Checks the agent behind every new connection against `build`.
    #[cfg(test)]
    pub(crate) fn checking_build(mut self, build: &str) -> Self {
        self.build = Some(build.to_string());
        self
    }

    /// `OLDER_BUILD` once an unlocked agent of an older build was found.
    #[cfg(test)]
    pub(crate) fn older_build_warning(&self) -> Option<String> {
        self.older_build.lock().ok()?.clone()
    }

    /// What this client sent.
    #[cfg(test)]
    pub(crate) fn traffic(&self) -> &Traffic {
        &self.traffic
    }

    /// Unread bytes queued on the kept connection; `None` when none is kept.
    #[cfg(test)]
    pub(crate) fn kept_unread(&self) -> Option<usize> {
        let kept = self.conn.lock().ok()?;
        let conn = kept.as_ref()?;
        let mut bytes = [0u8; 256];
        // SAFETY: peeks at most `bytes.len()` bytes into `bytes`, without blocking.
        let peeked = unsafe {
            libc::recv(
                conn.stream.as_raw_fd(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
                libc::MSG_PEEK | libc::MSG_DONTWAIT,
            )
        };
        Some(usize::try_from(peeked).unwrap_or(0))
    }

    /// Moves the kept connection's last reply `by` into the past, as if it
    /// had sat idle that much longer (tests move the clock, never wait).
    #[cfg(test)]
    pub(crate) fn idle_for(&self, by: Duration) {
        if let Some(conn) = &mut *self.conn.lock().unwrap() {
            conn.idle_since = conn.idle_since.checked_sub(by).unwrap();
        }
    }

    /// Expects the listener to run as `uid` instead of this user.
    #[cfg(test)]
    pub(crate) fn expecting_uid(mut self, uid: u32) -> Self {
        self.expected_uid = uid;
        self
    }

    /// Connects to the recorded socket, else this session's, and refuses a
    /// listener that isn't `expected_uid`. When neither answers, the error
    /// proves no agent (`proves_absent`) only if both paths prove it; one
    /// that doesn't names its path.
    fn dial(&self) -> std::io::Result<Result<UnixStream>> {
        let unproven_at = |socket: &Path, error: std::io::Error| {
            if proves_absent(&error) {
                error
            } else {
                std::io::Error::new(error.kind(), format!("{}: {error}", socket.display()))
            }
        };
        let mut unproven = None;
        if let Some(record) = self.record.as_deref()
            && let Some(recorded) = recorded_socket(record)
            && recorded != self.socket
        {
            match self.dial_at(&recorded) {
                Ok(checked) => return Ok(checked),
                Err(error) if !proves_absent(&error) => {
                    unproven = Some(std::io::Error::new(
                        error.kind(),
                        format!(
                            "{} (named by {}; remove that file if no cred agent runs): {error}",
                            recorded.display(),
                            record.display()
                        ),
                    ));
                }
                Err(_) => {}
            }
        }
        match self.dial_at(&self.socket) {
            Ok(checked) => Ok(checked),
            Err(error) => Err(match unproven {
                Some(unproven) if proves_absent(&error) => unproven,
                _ => unproven_at(&self.socket, error),
            }),
        }
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

    /// Whether an agent answers on its socket: `Ok(false)` only when that
    /// is proven (a missing path, or refused: `proves_absent`). A listener
    /// of another user, or any other error, may hide a running agent:
    /// `Err`, never "not running". Starts nothing.
    pub fn probe(&self) -> Result<bool> {
        match self.dial() {
            Ok(Ok(_)) => Ok(true),
            Ok(Err(other_user)) => Err(other_user),
            Err(error) if proves_absent(&error) => Ok(false),
            Err(error) => Err(anyhow!(error).context("could not reach the cred agent")),
        }
    }

    /// Whether an agent answers now (tests; callers use `probe`, which
    /// tells "not running" from "can't tell").
    #[cfg(test)]
    pub(crate) fn is_running(&self) -> bool {
        matches!(self.probe(), Ok(true))
    }

    /// Whether an agent may answer: the kept connection is open (when no
    /// request holds it), else anything but a proven absence (`probe`) of
    /// an agent that doesn't hold the key files either (`key_dir_held`), so
    /// a caller's request reports what is wrong with an agent it can't
    /// reach instead of taking it for none. Starts nothing.
    #[cfg_attr(test, allow(dead_code))]
    pub fn answers(&self) -> bool {
        if let Ok(mut kept) = self.conn.try_lock() {
            drop_unusable(&mut kept);
            if kept.is_some() {
                return true;
            }
        }
        match self.probe() {
            Ok(false) => self.key_dir_held(),
            _ => true,
        }
    }

    /// Whether an agent holds the key files (`agent.lock`): a live agent
    /// holds it for its whole life, from before it listens, so one that
    /// answers on no socket (starting, stopping, orphaned, or behind a full
    /// accept queue, which macOS refuses like a missing listener) may still
    /// run unlocked.
    fn key_dir_held(&self) -> bool {
        self.lock
            .as_deref()
            .is_some_and(|lock| lock_is_held(lock) == Some(true))
    }

    fn connect(&self) -> Result<UnixStream> {
        match self.dial() {
            Ok(checked) => checked,
            // No agent (proven), or something that proves nothing while no
            // agent holds the key files (a stale record, say): start one. It
            // takes the key files' lock and records its socket, and gives way
            // to an agent that took them first.
            Err(error)
                if self.launcher.is_some()
                    && (proves_absent(&error)
                        || self
                            .lock
                            .as_deref()
                            .is_some_and(|lock| lock_is_held(lock) == Some(false))) =>
            {
                if let Some(launch) = &self.launcher {
                    launch()?;
                }
                // Ready is a same-user agent accepting a connection on the
                // expected socket (`dial`); a missing or stale socket is "not
                // yet" until `start_wait` has passed, and a listener of
                // another user is the error it always was.
                let deadline = std::time::Instant::now() + self.start_wait;
                let mut polls = 0;
                loop {
                    let left = deadline.saturating_duration_since(std::time::Instant::now());
                    if left.is_zero() {
                        break;
                    }
                    let pause = start_poll_pause(polls).min(left);
                    #[cfg(test)]
                    self.traffic.pauses.lock().unwrap().push(pause);
                    std::thread::sleep(pause);
                    polls += 1;
                    #[cfg(test)]
                    Traffic::add(&self.traffic.polls);
                    // Any io error is "not yet" while the agent starts: a
                    // missing or refused socket, or a reset / not-connected
                    // one (macOS, a listener coming up).
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
                bail!("the cred agent didn't start; see {}", self.log.display())
            }
            // No agent was started. One that holds the key files may run
            // unlocked, whatever its socket said (nothing, or something that
            // proves nothing): it is named, with what the socket said.
            Err(error) => {
                if let Some(lock) = self.lock.as_deref()
                    && lock_is_held(lock) == Some(true)
                {
                    return Err(anyhow!(error).context(StuckAgent(stuck_message(lock))));
                }
                if proves_absent(&error) {
                    Err(anyhow!(error).context(format!(
                        "the cred agent isn't running at {}",
                        self.socket.display()
                    )))
                } else {
                    // A reset or not-connected socket, a permission error: no
                    // agent is started beside one that may be running.
                    Err(anyhow!(error).context("could not reach the cred agent"))
                }
            }
        }
    }
}

impl CredAgentClient {
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
            Some(error) => anyhow!("the cred agent closed the connection ({error}); see {log}"),
            None => anyhow!("the cred agent closed the connection; see {log}"),
        }
    }

    /// The protocol version the running agent answers a `status` in (no
    /// autostart, on a connection of its own); `None` when it doesn't answer.
    fn probe_version(&self) -> Option<u64> {
        let stream = self.dial().ok()?.ok()?;
        stream.set_read_timeout(Some(CHECK_WAIT)).ok()?;
        stream.set_write_timeout(Some(CHECK_WAIT)).ok()?;
        let line = encode_request(&Request::Status).ok()?;
        let answer = Conn::new(stream).round_trip(Outgoing::Line(line)).ok()?;
        let Received::Line(reply) = answer.reply else {
            return None;
        };
        let text = std::str::from_utf8(&reply.0).ok()?;
        serde_json::from_str::<ResponseHead>(text.trim())
            .ok()
            .map(|head| head.v)
    }

    /// Waits up to `wait` for the agent to be gone; true once that is
    /// proven (`probe`: its socket is missing or refused) and it no longer
    /// holds the key files (`key_dir_held`). An agent that can't be reached
    /// for another reason is not gone.
    fn wait_gone(&self, wait: Duration) -> bool {
        let deadline = std::time::Instant::now() + wait;
        loop {
            if matches!(self.probe(), Ok(false)) && !self.key_dir_held() {
                return true;
            }
            if std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// A new connection with this client's timeouts, unchecked; the agent
    /// started first when none answers and this client may.
    fn connection(&self) -> Result<Conn> {
        let stream = self.connect()?;
        let closed = |error: std::io::Error| self.closed(Some(error));
        stream.set_read_timeout(Some(REPLY_WAIT)).map_err(closed)?;
        stream.set_write_timeout(Some(REPLY_WAIT)).map_err(closed)?;
        #[cfg(test)]
        Traffic::add(&self.traffic.connections);
        Ok(Conn::new(stream))
    }

    /// A new connection, checked against this build first when the client
    /// has one to compare (`check_build`): every new connection may reach
    /// another agent process than the last one did.
    fn open(&self) -> Result<Conn> {
        let conn = self.connection()?;
        let Some(build) = self.build.as_deref() else {
            return Ok(conn);
        };
        match self.check_build(conn, build)? {
            Some(conn) => Ok(conn),
            // The check got no answer, or stopped a locked agent of another
            // build: the request goes on a new connection, to the agent
            // `connect` finds or starts, unchecked (as before).
            None => self.connection(),
        }
    }

    /// `request` on `conn` within `wait`: its reply, `None` without a
    /// readable one.
    fn ask(&self, conn: &mut Conn, request: &Request, wait: Duration) -> Option<Reply> {
        let line = encode_request(request).ok()?;
        conn.stream.set_read_timeout(Some(wait)).ok()?;
        #[cfg(test)]
        Traffic::add(&self.traffic.requests);
        let answer = conn.round_trip(Outgoing::Line(line)).ok()?;
        // Back to the reply wait for the requests that follow. macOS refuses
        // this (EINVAL) once the agent has closed the connection: the answer
        // still counts, and the next request on the connection fails as it
        // does on Linux (its error, or a resend of a stateless one).
        let _ = conn.stream.set_read_timeout(Some(REPLY_WAIT));
        match answer.reply {
            Received::Line(reply) if answer.in_step => {
                decode_response(std::str::from_utf8(&reply.0).ok()?).ok()
            }
            _ => None,
        }
    }

    /// The build check on the new connection `conn`: the agent it reached
    /// must be this build. A locked agent of another build holds no keys, so
    /// it is asked to stop (`None`: the next connection starts this build's).
    /// An unlocked one is never restarted: it is used, with a warning. `None`
    /// too when the agent didn't answer the check. Its answer also says
    /// whether the agent reads frames on `conn` (agent_frame.rs).
    fn check_build(&self, mut conn: Conn, build: &str) -> Result<Option<Conn>> {
        use std::sync::atomic::Ordering;
        #[cfg(test)]
        Traffic::add(&self.traffic.probes);
        let Some(Reply::Status {
            unlocked,
            build: theirs,
            frames,
            ..
        }) = self.ask(&mut conn, &Request::Status, CHECK_WAIT)
        else {
            return Ok(None);
        };
        conn.frames = frames == Some(agent_frame::VERSION);
        if theirs == build {
            return Ok(Some(conn));
        }
        if unlocked {
            // Once per process, however many connections a command makes.
            static WARNED: std::sync::atomic::AtomicBool =
                std::sync::atomic::AtomicBool::new(false);
            let text = self.older_build_text();
            if !WARNED.swap(true, Ordering::SeqCst) {
                crate::diagnostics::warn(text);
            }
            if let Ok(mut older) = self.older_build.lock() {
                *older = Some(text.to_string());
            }
            return Ok(Some(conn));
        }
        let _ = self.ask(&mut conn, &Request::Lock { stop: true }, CHECK_WAIT);
        drop(conn);
        if self.wait_gone(STOP_WAIT) {
            return Ok(None);
        }
        bail!(
            "the running cred agent is another atem build and didn't stop when asked; run `atem cred lock`, then retry (it is locked: its keys stay sealed on disk)"
        )
    }

    /// Writes `out` on `conn` and reads the reply.
    fn send(&self, conn: &mut Conn, out: Outgoing) -> Result<Answer, Failed> {
        #[cfg(test)]
        {
            Traffic::add(&self.traffic.requests);
            if matches!(out, Outgoing::Frame { .. }) {
                Traffic::add(&self.traffic.frames);
            }
        }
        conn.round_trip(out)
    }

    /// The request on the kept connection (opened, and checked, when none
    /// is kept, or when the kept one can't carry it: `drop_unusable`):
    /// `line`, or without one, `again` encoded for the connection
    /// (`outgoing`: a `Crypt` as a frame where it agreed to them).
    ///
    /// When the connection drops after the request was written but before
    /// any byte of the reply, the request in `again` (a `resendable` one)
    /// goes once more, on a new connection, when the dropped one had
    /// answered before (the agent stopped or restarted meanwhile); every
    /// other failure is the request's error. Every released agent serves
    /// several requests per connection; one that closed a connection after
    /// a reply would only make the next request on it fail this way.
    fn exchange(
        &self,
        kept: &mut Option<Conn>,
        mut line: Option<Zeroizing<String>>,
        again: Option<&Request>,
    ) -> Result<Received> {
        let mut resent = false;
        loop {
            drop_unusable(kept);
            let conn = match kept {
                Some(conn) => conn,
                None => kept.insert(self.open()?),
            };
            let out = match line.take() {
                Some(line) => Outgoing::Line(line),
                None => outgoing(conn, again.ok_or_else(unencoded)?)?,
            };
            let replies = conn.replies;
            let failed = match self.send(conn, out) {
                Ok(answer) => return Ok(keep(kept, answer)),
                Err(failed) => failed,
            };
            *kept = None;
            let resend = matches!(failed, Failed::Unanswered(_)) && replies > 0 && !resent;
            if !resend || again.is_none() {
                return Err(self.closed(failed.into_error()));
            }
            // `line` is taken: the new connection encodes `again` its way.
            resent = true;
        }
    }
}

/// Drops the kept connection when it can't carry a request: idle for
/// `REUSE_IDLE`, or closed by the agent (it stopped or restarted). Nothing
/// has been written on it, so no request goes twice.
fn drop_unusable(kept: &mut Option<Conn>) {
    if kept
        .as_ref()
        .is_some_and(|conn| conn.idle(REUSE_IDLE) || conn.closed())
    {
        *kept = None;
    }
}

/// A request that is neither encoded nor kept to be encoded.
fn unencoded() -> anyhow::Error {
    anyhow!("the cred agent request was not kept to be encoded")
}

/// `answer`'s reply; its connection stays kept only while in step.
fn keep(kept: &mut Option<Conn>, answer: Answer) -> Received {
    if !answer.in_step {
        *kept = None;
    }
    answer.reply
}

/// An agent from an older atem rejects a request it doesn't know as
/// malformed (`unknown variant`): say what to do instead.
fn explain_unknown_request(error: anyhow::Error, older: &str) -> anyhow::Error {
    if format!("{error:#}").contains("unknown variant") {
        anyhow!("{older} (It doesn't know this request.)")
    } else {
        error
    }
}

impl CredAgentApi for CredAgentClient {
    fn lock_and_stop(&self) -> Result<bool> {
        // Nothing answers, yet an agent holds the key files: one starting
        // (not listening yet) or stopping (draining). Up to `STOP_WAIT` for
        // it to answer, or to go (an agent's keys go with its process).
        // Still neither: the request below names it, never "locked".
        if matches!(self.probe(), Ok(false)) && self.key_dir_held() {
            let deadline = std::time::Instant::now() + STOP_WAIT;
            while matches!(self.probe(), Ok(false)) && std::time::Instant::now() < deadline {
                if !self.key_dir_held() {
                    return Ok(true);
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        match self.call(Request::Lock { stop: true })? {
            Reply::Done => Ok(self.wait_gone(STOP_WAIT)),
            _ => bail!("the cred agent sent an unexpected reply"),
        }
    }

    fn call(&self, request: Request) -> Result<Reply> {
        let stops = matches!(request, Request::Lock { stop: true });
        // A `Crypt` (resendable) is encoded once its connection is known, as
        // a frame where that connection agreed to them; any other request is
        // encoded now.
        let line = match &request {
            Request::Crypt { .. } => None,
            _ => Some(encode_request(&request)?),
        };
        // Kept to go once more if its connection drops unanswered (what is
        // written is wiped as soon as it is); any other request is wiped now.
        let again = resendable(&request).then_some(request);
        let reply = {
            let mut kept = self.conn.lock().unwrap_or_else(|poisoned| {
                // A request that panicked midway leaves no usable connection.
                self.conn.clear_poison();
                let mut kept = poisoned.into_inner();
                *kept = None;
                kept
            });
            let reply = self.exchange(&mut kept, line, again.as_ref());
            if stops {
                // The agent closes it once it has answered.
                *kept = None;
            }
            reply
        };
        drop(again);
        let reply = match reply? {
            Received::Line(reply) => {
                let text = std::str::from_utf8(&reply.0)
                    .map_err(|_| anyhow!("the cred agent sent a non-UTF-8 reply"))?;
                decode_response(text)
            }
            Received::Results(results) => Ok(Reply::Crypted { results }),
            Received::Json(body) => std::str::from_utf8(&body)
                .map_err(|_| anyhow!("the cred agent sent a non-UTF-8 reply"))
                .and_then(decode_response),
            Received::Unreadable => Err(anyhow!("the cred agent sent an unreadable reply")),
        };
        reply.map_err(|error| explain_unknown_request(error, self.older_build_text()))
    }
}

#[cfg(test)]
#[path = "agent_client_tests.rs"]
mod client_tests;

#[cfg(test)]
#[path = "agent_frame_tests.rs"]
mod frame_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::fs::PermissionsExt;

    /// Unix socket paths are limited to ~100 bytes; keep them short.
    pub(super) fn short_dir() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("atem-ka")
            .tempdir_in("/tmp")
            .unwrap()
    }

    pub(super) fn own_uid() -> u32 {
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

    /// The agent socket under the runtime dir `run` (`CredPaths::agent_sock`).
    pub(super) fn sock(run: &Path) -> PathBuf {
        CredPaths::in_dir(run).agent_sock(Some(run))
    }

    /// Creates `path` private, whatever the umask: the agent refuses a socket
    /// directory others can write to.
    pub(super) fn make_private(path: &Path) {
        std::fs::create_dir_all(path).unwrap();
        std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .unwrap();
    }

    /// Serves an agent for the key files in `dir` on its own thread.
    pub(super) fn start_agent(dir: &Path, allowed_uid: u32) -> PathBuf {
        start_agent_counting_trims(dir, allowed_uid, None)
    }

    /// `start_agent`, recording in `trims` when it gives its freed memory
    /// back.
    fn start_agent_counting_trims(
        dir: &Path,
        allowed_uid: u32,
        trims: Option<Arc<TrimLog>>,
    ) -> PathBuf {
        let socket = sock(&dir.join("run"));
        let paths = CredPaths::in_dir(dir);
        let (ready, started) = std::sync::mpsc::channel();
        let path = socket.clone();
        std::thread::spawn(move || {
            TRIMS.with(|counter| *counter.borrow_mut() = trims);
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let listener = bind(&path).unwrap();
                let agent = Arc::new(Mutex::new(CredAgent::new(paths).unwrap()));
                ready.send(()).unwrap();
                let _ = serve(listener, agent, allowed_uid).await;
            });
        });
        started.recv().unwrap();
        socket
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
            hint.find("atem status").expect(&hint),
            hint.find("pkill").expect(&hint),
        );
        assert!(status < pkill, "{hint}");
        let refused = decode_response(
            r#"{"v":2,"ok":false,"error":"unsupported cred agent protocol version 3"}"#,
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
        let client = CredAgentClient::at(socket.clone());
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
        let log = test_log(&socket);
        let error = format!("{:#}", CredAgentClient::at(socket).status().err().unwrap());
        assert!(error.contains("closed the connection"), "{error}");
        // The client checked the listener's uid already: the hint is the log.
        assert!(error.contains(&format!("see {}", log.display())), "{error}");
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
            let stale = sock(&dir.path().join("stale"));
            make_private(stale.parent().unwrap());
            drop(std::os::unix::net::UnixListener::bind(&stale).unwrap());
            assert!(stale.exists());
            retrying(|| bind(&stale));
        });
    }

    #[test]
    fn a_client_that_may_not_start_an_agent_says_so() {
        let dir = short_dir();
        let client = CredAgentClient::at(dir.path().join("none.sock"));
        assert!(!client.is_running());
        assert!(format!("{:#}", client.status().err().unwrap()).contains("isn't running"));
    }

    #[test]
    fn every_request_survives_the_wire_and_reaches_the_agent() {
        use crate::memory::cred_agent::{error_of, test_agent};
        use crate::memory::statements::SignedWire;
        use crate::memory::storage_key::UnlockGrantWire;
        let dir = short_dir();
        let socket = start_agent(dir.path(), own_uid());
        let client = CredAgentClient::at(socket);
        let local = test_agent(&CredPaths::in_dir(dir.path()));
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
        // process: the request reached `CredAgent::handle` intact.
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
            Request::Lock { stop: false },
            Request::Lock { stop: true },
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
        let socket = sock(&runtime);
        let pid = Arc::new(Mutex::new(None));
        let launcher = {
            let (home, runtime, pid, log) = (
                home.clone(),
                runtime.clone(),
                pid.clone(),
                CredPaths::in_dir(dir.path()).agent_log,
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
        let client = CredAgentClient::with_launcher(socket.clone(), launcher)
            .logging_to(CredPaths::in_dir(dir.path()).agent_log);
        assert!(!client.is_running());
        let status = client.status().unwrap();
        assert!(!status.unlocked);
        assert!(client.is_running());
        assert!(pid.lock().unwrap().is_some());
        // A second client finds the same agent without starting another.
        let second = CredAgentClient::with_launcher(
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
        let error = bind(&sock(dir.path())).err().unwrap();
        assert!(format!("{error:#}").contains("symlink"), "{error:#}");
        assert!(!real.join(sock(dir.path()).file_name().unwrap()).exists());
    }

    #[test]
    fn bind_does_not_delete_a_file_that_is_not_a_socket() {
        let dir = short_dir();
        let socket = sock(&dir.path().join("run"));
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
        assert!(CredAgentClient::at(socket).status().is_ok());
    }

    #[test]
    fn a_listener_run_by_someone_else_is_not_trusted() {
        let dir = short_dir();
        let socket = start_agent(dir.path(), own_uid());
        let client = CredAgentClient::at(socket.clone()).expecting_uid(own_uid().wrapping_add(1));
        assert!(!client.is_running());
        let error = format!("{:#}", client.status().err().unwrap());
        assert!(error.contains("served by another user"), "{error}");
        // The same socket is fine for its own user.
        assert!(CredAgentClient::at(socket).is_running());
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
            socket_path_in(&config, ok.then(|| runtime.as_os_str().to_owned()))
        };
        assert_eq!(pick(&private), sock(&private));
        assert_eq!(pick(&open), CredPaths::in_dir(&config).agent_sock(None));
        assert_eq!(pick(&link), CredPaths::in_dir(&config).agent_sock(None));
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
                r#"{"kind":"status","unlocked":false,"storage_kid":null,"escrowed":false,"build":"b"}"#
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
        let socket = sock(&dir.join("run"));
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
        let client = CredAgentClient::at(start_v1_agent(dir.path()));
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
        let two = encode_request(&Request::Lock { stop: false }).unwrap();
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
    fn status_against_an_old_agent_says_to_stop_it() {
        let dir = short_dir();
        let client = CredAgentClient::at(start_v1_agent(dir.path()));
        assert!(client.is_running());
        let profile = tempfile::tempdir().unwrap();
        crate::paths::write_test_file(
            &crate::paths::CredPaths::in_dir(profile.path()).device_keys_sealed,
            b"{}",
        );
        let src = crate::profile::Sources::in_dir(profile.path());
        let credentials = crate::status::gather_with(&src, Some(&client))
            .credentials
            .value;
        // Shown, not an error: the mismatch and what to do.
        assert!(
            credentials.starts_with("unknown (cred agent not answering: the running cred agent speaks protocol v1, this atem speaks v2"),
            "{credentials}"
        );
        assert!(credentials.contains("pkill"), "{credentials}");
        assert!(credentials.contains("retry"), "{credentials}");
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
        use crate::memory::cred_agent::error_of;
        let dir = short_dir();
        let socket = start_agent(dir.path(), own_uid());
        let client = CredAgentClient::at(socket);
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
        use crate::memory::cred_agent::{error_of, test_agent};
        let dir = short_dir();
        let socket = start_agent(dir.path(), own_uid());
        let client = CredAgentClient::at(socket);
        let local = test_agent(&CredPaths::in_dir(dir.path()));
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
        let error = bind(&sock(dir.path())).err().unwrap();
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
    pub(super) fn atem_binary() -> PathBuf {
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
    pub(super) struct Reaped(pub(super) std::process::Child);

    impl Drop for Reaped {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// `atem cred-agent` for `home`, with its socket under `runtime`.
    pub(super) fn cred_agent_process(home: &Path, runtime: &Path, log: &Path) -> Reaped {
        let log = std::fs::File::create(log).unwrap();
        Reaped(
            std::process::Command::new(atem_binary())
                .arg("cred-agent")
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
    pub(super) fn eventually(mut done: impl FnMut() -> bool) -> bool {
        for _ in 0..50 {
            if done() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        false
    }

    #[test]
    fn a_locked_cred_agent_process_exits_and_clears_its_records() {
        let dir = short_dir();
        let home = dir.path().join("home");
        let run = dir.path().join("run");
        std::fs::create_dir_all(&home).unwrap();
        make_private(&run);
        let mut agent = cred_agent_process(&home, &run, &dir.path().join("a.log"));
        let config = home.join(".config").join("atem");
        let client = CredAgentClient::finding(&config, Some(run.clone().into_os_string()), None);
        assert!(eventually(|| client.is_running()));
        assert!(client.lock_and_stop().unwrap(), "the agent stopped");
        assert!(
            eventually(|| agent.0.try_wait().unwrap().is_some()),
            "the agent process kept running"
        );
        assert!(!sock(&run).exists());
        assert!(
            !CredPaths::in_dir(&config).agent_socket.exists(),
            "its record is gone"
        );
        assert_eq!(
            std::fs::read_to_string(CredPaths::in_dir(&config).agent_lock).unwrap(),
            "",
            "a clean exit clears its pid"
        );
        let log = std::fs::read_to_string(dir.path().join("a.log")).unwrap();
        assert!(log.contains("exiting"), "{log}");
    }

    /// The agent process serves every connection on its one thread (F5,
    /// designs/e2e-encryption.md "Performance"), and a client that stalls
    /// mid-request (a frame or a line half sent) or never reads its replies
    /// holds up no other client's request: all of its I/O waits without
    /// blocking the thread.
    #[test]
    fn the_agent_runs_on_one_thread_and_a_stalled_client_holds_up_no_one() {
        let dir = short_dir();
        let home = dir.path().join("home");
        let run = dir.path().join("run");
        std::fs::create_dir_all(&home).unwrap();
        make_private(&run);
        let agent = cred_agent_process(&home, &run, &dir.path().join("a.log"));
        let socket = sock(&run);
        let client = CredAgentClient::at(socket.clone());
        assert!(eventually(|| client.status().is_ok()));
        #[cfg(target_os = "linux")]
        assert_eq!(
            std::fs::read_dir(format!("/proc/{}/task", agent.0.id()))
                .unwrap()
                .count(),
            1,
            "the agent runs on one thread"
        );
        // A frame half sent, on a connection whose status agreed to frames.
        let mut framed = UnixStream::connect(&socket).unwrap();
        framed
            .write_all(encode_request(&Request::Status).unwrap().as_bytes())
            .unwrap();
        let mut agreed = String::new();
        BufReader::new(&framed).read_line(&mut agreed).unwrap();
        assert!(agreed.contains("\"frames\":1"), "{agreed}");
        let frame =
            agent_frame::crypt_request("astation", &[CryptOp::seal("r", "f", &vec![1; 1 << 20])])
                .unwrap();
        framed.write_all(&frame[..frame.len() / 2]).unwrap();
        // A line half sent.
        let mut line = UnixStream::connect(&socket).unwrap();
        line.write_all(&vec![b'x'; 1 << 20]).unwrap();
        // Requests whose replies are never read, written until the agent
        // stops reading them (its replies have filled the socket).
        let mut deaf = UnixStream::connect(&socket).unwrap();
        deaf.set_write_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        let requests = encode_request(&Request::Status).unwrap().repeat(1_000);
        while deaf.write_all(requests.as_bytes()).is_ok() {}
        let start = std::time::Instant::now();
        let status = CredAgentClient::at(socket.clone()).status().unwrap();
        assert!(!status.unlocked);
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "another client waited {:?}",
            start.elapsed()
        );
        drop((framed, line, deaf, agent));
    }

    /// After a request or reply of `TRIM_BYTES` or more, or a connection's
    /// end, the agent gives its freed memory back once neither happened for
    /// `TRIM_IDLE`; small requests never make it trim. Each assertion of
    /// "no trim" holds whatever the timing: a trim can come only while one
    /// is due, which a large request sets before its reply is written.
    #[test]
    fn the_agent_gives_freed_memory_back_once_idle_after_a_large_request() {
        let dir = short_dir();
        let log = Arc::new(TrimLog::default());
        let socket = start_agent_counting_trims(dir.path(), own_uid(), Some(log.clone()));
        let client = CredAgentClient::at(socket.clone());
        for _ in 0..20 {
            client.status().unwrap();
        }
        assert!(!log.due(), "small requests never make a trim due");
        std::thread::sleep(TRIM_IDLE * 3);
        assert_eq!(log.trims(), 0, "small requests never trim");
        // Large lines (refused or not, each gets its reply), back to back.
        let large = format!(
            "{{\"v\":2,\"op\":\"status\",\"pad\":\"{}\"}}\n",
            "x".repeat(TRIM_BYTES)
        );
        let stream = UnixStream::connect(&socket).unwrap();
        for _ in 0..3 {
            (&stream).write_all(large.as_bytes()).unwrap();
            let mut reply = String::new();
            BufReader::new(&stream).read_line(&mut reply).unwrap();
            assert!(reply.ends_with('\n'), "{reply}");
        }
        assert!(
            eventually(|| !log.due() && log.trims() > 0),
            "it trims once idle"
        );
        let after = log.trims();
        std::thread::sleep(TRIM_IDLE * 3);
        assert_eq!(
            log.trims(),
            after,
            "and not again until another large request"
        );
        client.status().unwrap();
        std::thread::sleep(TRIM_IDLE * 3);
        assert!(!log.due());
        assert_eq!(log.trims(), after);
        drop(stream);
        assert!(
            eventually(|| !log.due() && log.trims() > after),
            "a connection's end makes it trim"
        );
    }

    /// Where the limit lets the agent lock its memory, every page it maps is
    /// locked (VmLck), but only the pages it touches are read in
    /// (`MCL_ONFAULT`): most of the mapped executable never is. It says
    /// whether it ran; with `ATEM_TEST_REQUIRE_MLOCK` set (the Linux CI job,
    /// which raises the limit) a limit too low to run it is a failure.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_locked_agent_reads_in_only_the_pages_it_touches() {
        use std::os::unix::process::CommandExt;
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut limit) },
            0
        );
        let hard = if limit.rlim_max == libc::RLIM_INFINITY {
            "unlimited".to_string()
        } else {
            format!("{} KiB", limit.rlim_max >> 10)
        };
        if limit.rlim_max != libc::RLIM_INFINITY && limit.rlim_max < 512 << 20 {
            assert!(
                std::env::var_os("ATEM_TEST_REQUIRE_MLOCK").is_none(),
                "RLIMIT_MEMLOCK's hard limit is {hard}, under 512 MiB: raise it for this job"
            );
            println!(
                "a_locked_agent_reads_in_only_the_pages_it_touches: skipped: RLIMIT_MEMLOCK's hard limit is {hard}, under 512 MiB (the agent locks nothing)"
            );
            return;
        }
        let dir = short_dir();
        let home = dir.path().join("home");
        let run = dir.path().join("run");
        std::fs::create_dir_all(&home).unwrap();
        make_private(&run);
        let log_path = dir.path().join("a.log");
        let log = std::fs::File::create(&log_path).unwrap();
        let mut command = std::process::Command::new(atem_binary());
        command
            .arg("cred-agent")
            .env("HOME", &home)
            .env("XDG_RUNTIME_DIR", &run)
            .stdin(std::process::Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log);
        // SAFETY: setrlimit only, between fork and exec.
        unsafe {
            command.pre_exec(move || {
                let raised = libc::rlimit {
                    rlim_cur: limit.rlim_max,
                    rlim_max: limit.rlim_max,
                };
                if libc::setrlimit(libc::RLIMIT_MEMLOCK, &raised) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let agent = Reaped(command.spawn().unwrap());
        let client = CredAgentClient::at(sock(&run));
        assert!(eventually(|| client.status().is_ok()));
        let status = std::fs::read_to_string(format!("/proc/{}/status", agent.0.id())).unwrap();
        let kib = |name: &str| -> u64 {
            status
                .lines()
                .find(|line| line.starts_with(name))
                .and_then(|line| line.split_whitespace().nth(1))
                .and_then(|value| value.parse().ok())
                .unwrap()
        };
        let (locked, resident) = (kib("VmLck:"), kib("VmRSS:"));
        let log = std::fs::read_to_string(&log_path).unwrap();
        assert!(locked > 0, "the agent locked nothing: {log}");
        assert!(!log.contains("keys could reach swap"), "{log}");
        // Read in at once, the pages would all be resident (VmRSS about
        // VmLck); how much of the rest is depends on the page cache.
        assert!(
            resident * 4 < locked * 3,
            "{resident} KiB resident of {locked} KiB locked: the pages were all read in"
        );
        println!(
            "a_locked_agent_reads_in_only_the_pages_it_touches: ran (RLIMIT_MEMLOCK hard limit {hard}): {resident} KiB resident of {locked} KiB locked"
        );
        drop(agent);
    }

    /// `lock_memory`'s `mlockall` calls (their flags, in order), what it
    /// did and the line the agent logs, with `RLIMIT_MEMLOCK` at `limit`
    /// (`None`: unknown) and each call answering from `answers` (0 for
    /// success, else that errno).
    #[cfg(target_os = "linux")]
    fn locking(
        limit: Option<libc::rlim_t>,
        answers: &[i32],
    ) -> (Vec<libc::c_int>, MemoryLock, Option<String>) {
        let mut calls = Vec::new();
        let mut answers = answers.iter();
        let limit = limit.map(|limit| libc::rlimit {
            rlim_cur: limit,
            rlim_max: limit,
        });
        let locked = lock_memory(limit, |flags| {
            calls.push(flags);
            match answers
                .next()
                .expect("an mlockall call no answer was given for")
            {
                0 => Ok(()),
                errno => Err(std::io::Error::from_raw_os_error(*errno)),
            }
        });
        let line = locked.log_line();
        (calls, locked, line)
    }

    #[cfg(target_os = "linux")]
    const ON_FAULT: libc::c_int = libc::MCL_CURRENT | libc::MCL_FUTURE | libc::MCL_ONFAULT;
    #[cfg(target_os = "linux")]
    const ALL_AT_ONCE: libc::c_int = libc::MCL_CURRENT | libc::MCL_FUTURE;
    #[cfg(target_os = "linux")]
    const ENOUGH: libc::rlim_t = 512 << 20;

    #[cfg(target_os = "linux")]
    #[test]
    fn memory_is_locked_as_it_is_touched_where_the_kernel_can() {
        for limit in [ENOUGH, 4 << 30, libc::RLIM_INFINITY] {
            let (calls, locked, line) = locking(Some(limit), &[0]);
            assert_eq!(calls, [ON_FAULT], "one call, every page as it is touched");
            assert!(matches!(locked, MemoryLock::OnFault), "{locked:?}");
            assert_eq!(line, None);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_kernel_without_on_fault_gets_every_page_locked_at_once() {
        let (calls, locked, line) = locking(Some(ENOUGH), &[libc::EINVAL, 0]);
        assert_eq!(calls, [ON_FAULT, ALL_AT_ONCE]);
        assert!(matches!(locked, MemoryLock::AllAtOnce), "{locked:?}");
        assert_eq!(line, None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_failed_fallback_locks_nothing_and_says_so_with_its_own_error() {
        let (calls, locked, line) = locking(Some(ENOUGH), &[libc::EINVAL, libc::ENOMEM]);
        assert_eq!(calls, [ON_FAULT, ALL_AT_ONCE]);
        assert!(
            matches!(&locked, MemoryLock::Failed(error) if error.raw_os_error() == Some(libc::ENOMEM)),
            "{locked:?}"
        );
        assert_eq!(
            line.as_deref(),
            Some(
                "cred agent: mlockall failed (Cannot allocate memory (os error 12)); keys could reach swap"
            )
        );
        let (calls, locked, line) = locking(Some(ENOUGH), &[libc::EINVAL, libc::EINVAL]);
        assert_eq!(calls, [ON_FAULT, ALL_AT_ONCE]);
        assert!(matches!(locked, MemoryLock::Failed(_)), "{locked:?}");
        assert_eq!(
            line.as_deref(),
            Some(
                "cred agent: mlockall failed (Invalid argument (os error 22)); keys could reach swap"
            )
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn another_error_locks_nothing_and_tries_no_fallback() {
        for (errno, text) in [
            (libc::ENOMEM, "Cannot allocate memory (os error 12)"),
            (libc::EPERM, "Operation not permitted (os error 1)"),
            (
                libc::EAGAIN,
                "Resource temporarily unavailable (os error 11)",
            ),
        ] {
            let (calls, locked, line) = locking(Some(ENOUGH), &[errno]);
            assert_eq!(calls, [ON_FAULT], "errno {errno}: no fallback");
            assert!(
                matches!(&locked, MemoryLock::Failed(error) if error.raw_os_error() == Some(errno)),
                "{locked:?}"
            );
            assert_eq!(
                line,
                Some(format!(
                    "cred agent: mlockall failed ({text}); keys could reach swap"
                ))
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn memory_is_not_locked_under_a_low_or_unknown_limit() {
        for limit in [
            None,
            Some(0),
            Some(64 << 10),
            Some(8 << 20),
            Some(ENOUGH - 1),
        ] {
            let (calls, locked, line) = locking(limit, &[]);
            assert!(calls.is_empty(), "{limit:?}: no mlockall at all");
            assert!(matches!(locked, MemoryLock::TooLow), "{locked:?}");
            assert_eq!(
                line.as_deref(),
                Some(
                    "cred agent: not locking memory (RLIMIT_MEMLOCK is too low); keys could reach swap"
                )
            );
        }
    }

    #[test]
    fn one_agent_serves_a_key_directory_whatever_the_runtime_dir() {
        let dir = short_dir();
        let home = dir.path().join("home");
        let (run_a, run_b) = (dir.path().join("ra"), dir.path().join("rb"));
        std::fs::create_dir_all(&home).unwrap();
        make_private(&run_a);
        make_private(&run_b);
        let mut first = cred_agent_process(&home, &run_a, &dir.path().join("a.log"));
        let socket_a = sock(&run_a);
        assert!(eventually(
            || CredAgentClient::at(socket_a.clone()).is_running()
        ));
        // A second agent for the same key files (another login session with
        // its own runtime dir) must not run beside the first: two agents
        // rotating one storage key could each strand the other's files.
        let mut second = cred_agent_process(&home, &run_b, &dir.path().join("b.log"));
        assert!(
            eventually(|| second.0.try_wait().unwrap().is_some()),
            "the second agent kept running"
        );
        assert!(!sock(&run_b).exists());
        let log = std::fs::read_to_string(dir.path().join("b.log")).unwrap();
        assert!(log.contains("already running"), "{log}");
        // A client from the second session finds the first agent through
        // the socket path it recorded, and starts no other.
        let client = CredAgentClient::finding(
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
        let paths = CredPaths::in_dir(&dir.path().join("config"));
        let (run_a, run_b) = (dir.path().join("ra"), dir.path().join("rb"));
        make_private(&run_a);
        make_private(&run_b);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let socket_a = sock(&run_a);
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
            let error = claim(&paths, &sock(&run_b)).err().unwrap();
            assert!(
                error.downcast_ref::<AlreadyRunning>().is_some(),
                "{error:#}"
            );
            assert!(!sock(&run_b).exists());
            assert_eq!(recorded_socket(&paths.agent_socket), Some(socket_a));
            // Once the first agent is gone, another may take the directory.
            drop((lock, listener));
            retrying(|| claim(&paths, &sock(&run_b)));
        });
    }

    #[test]
    fn a_symlinked_key_directory_lock_is_refused() {
        let dir = short_dir();
        let paths = CredPaths::in_dir(dir.path());
        let target = dir.path().join("target");
        std::fs::write(&target, b"keep").unwrap();
        crate::paths::create_private_dir(&paths.dir).unwrap();
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
        let socket = sock(&run);
        make_private(socket.parent().unwrap());
        std::fs::write(&target, b"keep").unwrap();
        std::os::unix::fs::symlink(&target, crate::paths::socket_lock(&socket)).unwrap();
        let error = bind(&socket).err().unwrap();
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
        CredPaths,
        Arc<Mutex<CredAgent>>,
        std::sync::mpsc::Receiver<()>,
    ) {
        use crate::memory::device_keys::DeviceKeys;
        use crate::memory::statements::FakeAstation;
        let paths = CredPaths::in_dir(&dir.join("config"));
        let keys = DeviceKeys::generate();
        crate::memory::fake_astation::pin(&paths, &FakeAstation::new(), &keys, true);
        keys.save_to(&paths.device_keys).unwrap();
        let agent = Arc::new(Mutex::new(CredAgent::new(paths.clone()).unwrap()));
        assert!(
            agent.status().unwrap().unlocked,
            "the plain keys were migrated"
        );
        let socket = sock(&dir.join("run"));
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
        assert!(CredAgentClient::at(socket.clone()).is_running());
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
        // Another listener takes the path in one step: it is never missing.
        let staged = socket.with_extension("new");
        let _other = std::os::unix::net::UnixListener::bind(&staged).unwrap();
        std::fs::rename(&staged, &socket).unwrap();
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
    fn idle_launch_client(config: &Path, runtime: &Path) -> CredAgentClient {
        CredAgentClient::finding(
            config,
            Some(runtime.as_os_str().to_owned()),
            Some(Box::new(|| -> Result<()> { Ok(()) })),
        )
        .waiting(Duration::from_millis(300))
    }

    #[test]
    fn a_holder_that_cant_be_confirmed_as_a_cred_agent_is_not_named() {
        let dir = short_dir();
        let config = dir.path().join("config");
        let paths = CredPaths::in_dir(&config);
        make_private(&dir.path().join("rb"));
        // The holder (this test process) records its pid and answers on no
        // socket, but it isn't an `atem cred-agent`: no pid is named.
        let _held = lock_key_dir(&paths, Duration::ZERO).unwrap();
        let pid = std::process::id();
        assert_eq!(
            std::fs::read_to_string(&paths.agent_lock).unwrap().trim(),
            pid.to_string()
        );
        let socket = sock(&dir.path().join("rb"));
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
            assert!(text.contains("pgrep -af '[a]tem cred-agent'"), "{text}");
            assert!(text.contains("pkill -u"), "{text}");
            assert!(!text.contains("didn't start"), "{text}");
        }
        assert!(!socket.exists());
    }

    #[test]
    fn an_unheld_lock_naming_a_live_pid_names_no_one() {
        let dir = short_dir();
        let config = dir.path().join("config");
        let paths = CredPaths::in_dir(&config);
        make_private(&dir.path().join("rb"));
        // Left by an agent that exited (or from before a reboot): the pid
        // now belongs to a live, unrelated process (here: this one).
        std::fs::create_dir_all(&config).unwrap();
        let pid = std::process::id();
        crate::paths::write_test_file(&paths.agent_lock, format!("{pid}\n"));
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
    pub(super) struct Unreadable(PathBuf);

    impl Unreadable {
        pub(super) fn new(dir: &Path) -> Self {
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
    fn a_confirmed_cred_agent_that_no_one_can_reach_is_named_with_its_pid() {
        let dir = short_dir();
        let home = dir.path().join("home");
        let (run_a, run_b) = (dir.path().join("ra"), dir.path().join("rb"));
        std::fs::create_dir_all(&home).unwrap();
        make_private(&run_a);
        make_private(&run_b);
        let agent = cred_agent_process(&home, &run_a, &dir.path().join("a.log"));
        let socket_a = sock(&run_a);
        assert!(eventually(
            || CredAgentClient::at(socket_a.clone()).is_running()
        ));
        let pid = agent.0.id();
        // Its socket directory can't be entered: nobody can connect, yet the
        // agent itself can't tell (not a NotFound) and keeps its lock.
        let _blocked = Unreadable::new(&run_a.join("atem"));
        let config = home.join(".config").join("atem");
        let paths = CredPaths::in_dir(&config);
        let error = claim_waiting(&paths, &sock(&run_b), Duration::from_millis(300))
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
        let socket = sock(&run);
        make_private(socket.parent().unwrap());
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let record = CredPaths::in_dir(dir.path()).agent_socket;
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
            CredPaths::in_dir(&config).agent_sock(None)
        );
        assert_eq!(
            socket_path_in(&config, Some(private.clone().into_os_string())),
            sock(&private)
        );
    }

    /// `start_agent`, plus a receiver that fires once serving stops.
    pub(super) fn start_stoppable_agent(dir: &Path) -> (PathBuf, std::sync::mpsc::Receiver<()>) {
        let socket = sock(&dir.join("run"));
        let paths = CredPaths::in_dir(dir);
        let (ready, started) = std::sync::mpsc::channel();
        let (done, stopped) = std::sync::mpsc::channel();
        let path = socket.clone();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let listener = bind(&path).unwrap();
                let agent = Arc::new(Mutex::new(CredAgent::new(paths).unwrap()));
                ready.send(()).unwrap();
                let _ = serve(listener, agent, own_uid()).await;
                let _ = done.send(());
            });
        });
        started.recv().unwrap();
        (socket, stopped)
    }

    /// An agent of an older build: answers `status` with `status` (a JSON
    /// reply) and every other request with `other`, and never exits.
    pub(super) fn start_scripted_agent(
        dir: &Path,
        status: &'static str,
        other: &'static str,
    ) -> PathBuf {
        let socket = sock(&dir.join("run"));
        make_private(socket.parent().unwrap());
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                std::thread::spawn(move || {
                    let mut reader = BufReader::new(&stream);
                    let mut line = String::new();
                    while reader.read_line(&mut line).is_ok_and(|n| n > 0) {
                        let reply = if line.contains("\"op\":\"status\"") {
                            status
                        } else {
                            other
                        };
                        if (&stream)
                            .write_all(format!("{reply}\n").as_bytes())
                            .is_err()
                        {
                            return;
                        }
                        line.clear();
                    }
                });
            }
        });
        socket
    }

    /// A locked agent of another build that never stops when asked.
    const OTHER_LOCKED: &str = r#"{"v":2,"ok":true,"reply":{"kind":"status","unlocked":false,"storage_kid":null,"escrowed":false,"build":"0.0.0+other"}}"#;
    pub(super) const OTHER_DONE: &str = r#"{"v":2,"ok":true,"reply":{"kind":"done"}}"#;

    #[test]
    fn lock_wipes_the_agent_and_stops_it() {
        let dir = short_dir();
        let (socket, stopped) = start_stoppable_agent(dir.path());
        // A client that keeps its connection open doesn't hold the agent up.
        let idle = std::os::unix::net::UnixStream::connect(&socket).unwrap();
        let client = CredAgentClient::at(socket.clone());
        assert!(client.lock_and_stop().unwrap(), "the agent stopped");
        assert!(!socket.exists(), "its socket is gone");
        assert!(!client.is_running());
        stopped
            .recv_timeout(Duration::from_secs(3))
            .expect("the agent kept serving after a lock");
        drop(idle);
    }

    #[test]
    fn lock_stops_a_watched_agent_and_removes_its_record() {
        let dir = short_dir();
        let (socket, paths, agent, stopped) = watched_agent(dir.path());
        let client = CredAgentClient::at(socket.clone());
        assert!(client.lock_and_stop().unwrap());
        stopped
            .recv_timeout(Duration::from_secs(3))
            .expect("the agent kept serving after a lock");
        assert!(!agent.status().unwrap().unlocked, "its keys are wiped");
        assert!(!socket.exists());
        assert!(!paths.agent_socket.exists(), "its record is gone");
    }

    #[test]
    fn lock_with_an_agent_that_doesnt_stop_says_it_is_still_running() {
        use crate::memory::unlock::lock_keys_message;
        let dir = short_dir();
        let socket = start_scripted_agent(dir.path(), OTHER_LOCKED, OTHER_DONE);
        let client = CredAgentClient::at(socket);
        assert!(!client.lock_and_stop().unwrap(), "it stays");
        let message = lock_keys_message(Some(&client)).unwrap();
        assert!(message.starts_with("Locked"), "{message}");
        assert!(message.contains("hasn't stopped"), "{message}");
    }

    #[test]
    fn the_status_reply_carries_the_build() {
        use crate::memory::cred_agent::build_id;
        let dir = short_dir();
        let (socket, _stopped) = start_stoppable_agent(dir.path());
        let line = encode_request(&Request::Status).unwrap();
        let mut stream = std::os::unix::net::UnixStream::connect(&socket).unwrap();
        stream.write_all(line.as_bytes()).unwrap();
        let mut reply = String::new();
        BufReader::new(&stream).read_line(&mut reply).unwrap();
        let value: serde_json::Value = serde_json::from_str(&reply).unwrap();
        assert_eq!(value["reply"]["build"], build_id());
        assert!(build_id().starts_with(env!("CARGO_PKG_VERSION")));
        let status = CredAgentClient::at(socket).status().unwrap();
        assert!(!status.older_build);
        let old = short_dir();
        let status =
            CredAgentClient::at(start_scripted_agent(old.path(), OTHER_LOCKED, OTHER_DONE))
                .status()
                .unwrap();
        assert!(status.older_build);
    }

    /// Counts launches; each starts a fresh agent for `dir`.
    fn relaunching(dir: &Path, launches: Arc<std::sync::atomic::AtomicUsize>) -> Launcher {
        let dir = dir.to_path_buf();
        Box::new(move || {
            launches.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            start_agent(&dir, own_uid());
            Ok(())
        })
    }

    #[test]
    fn a_locked_agent_of_another_build_is_replaced() {
        let dir = short_dir();
        let (socket, stopped) = start_stoppable_agent(dir.path());
        let launches = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let client = CredAgentClient::with_launcher(
            socket.clone(),
            relaunching(dir.path(), launches.clone()),
        )
        .checking_build("0.0.0+another-build");
        assert!(!client.status().unwrap().unlocked);
        stopped
            .recv_timeout(Duration::from_secs(3))
            .expect("the older agent kept serving");
        assert_eq!(launches.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(client.is_running(), "the new agent serves");
        assert_eq!(client.older_build_warning(), None);
    }

    #[test]
    fn a_locked_agent_of_another_build_that_wont_stop_gets_guidance() {
        let dir = short_dir();
        let socket = start_scripted_agent(dir.path(), OTHER_LOCKED, OTHER_DONE);
        let launches = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let client =
            CredAgentClient::with_launcher(socket, relaunching(dir.path(), launches.clone()))
                .checking_build("0.0.0+another-build");
        let error = format!("{:#}", client.status().err().unwrap());
        assert!(error.contains("didn't stop when asked"), "{error}");
        assert!(error.contains("atem cred lock"), "{error}");
        assert_eq!(launches.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[test]
    fn an_unlocked_older_agent_is_kept_with_a_warning() {
        let dir = short_dir();
        let (socket, _paths, agent, stopped) = watched_agent(dir.path());
        let launches = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let client =
            CredAgentClient::with_launcher(socket, relaunching(dir.path(), launches.clone()))
                .checking_build("0.0.0+another-build");
        assert!(client.status().unwrap().unlocked, "the old agent answered");
        assert_eq!(
            client.older_build_warning().as_deref(),
            Some(crate::memory::cred_agent::OLDER_BUILD)
        );
        assert_eq!(
            crate::memory::cred_agent::OLDER_BUILD,
            "The cred agent was started by another atem build; run `atem cred lock`, then `atem cred unlock` to use this one."
        );
        // When Atem's runtime (which starts the agent for an unlock) is
        // another build too, unlocking again alone wouldn't help.
        assert_eq!(
            crate::memory::cred_agent::older_build_warning(true),
            "The cred agent was started by another atem build, and Atem's runtime is another build too; run `atem runtime restart`, then `atem cred lock` and `atem cred unlock` to use this one."
        );
        assert_eq!(
            crate::memory::cred_agent::older_build_warning(false),
            crate::memory::cred_agent::OLDER_BUILD
        );
        assert_eq!(launches.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(
            stopped.recv_timeout(Duration::from_millis(300)).is_err(),
            "never restarted silently"
        );
        assert!(agent.status().unwrap().unlocked, "its keys stay");
    }

    #[test]
    fn a_request_an_older_agent_doesnt_know_gets_the_hint() {
        let dir = short_dir();
        let socket = start_scripted_agent(
            dir.path(),
            OTHER_LOCKED,
            r#"{"v":2,"ok":false,"error":"cred agent request is malformed: unknown variant `credential_projects`, expected one of `status`, `lock`"}"#,
        );
        let client = CredAgentClient::at(socket);
        let error = format!(
            "{:#}",
            client
                .credential_projects("astation-1", None)
                .err()
                .unwrap()
        );
        assert!(error.contains("another atem build"), "{error}");
        assert!(
            error.contains("`atem cred lock`, then `atem cred unlock`"),
            "{error}"
        );
        assert!(!error.contains("unknown variant"), "{error}");
    }
}
