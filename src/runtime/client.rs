//! A frontend's connection to `atem runtime`: JSON lines over the same-user
//! socket, started detached when no runtime answers.

use super::protocol::{
    ClientMsg, PROTOCOL, RuntimeMsg, RuntimeStatus, SessionSummary, decode_runtime, encode_client,
};
pub use super::server::{BUSY_RESTART, RESTARTING};
use anyhow::{Context, Result, anyhow, bail};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};

/// How long a client waits for a runtime it started.
pub const START_WAIT: Duration = Duration::from_secs(5);

/// The runtime's `welcome`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Welcome {
    pub protocol: u32,
    pub build: String,
    pub pid: u32,
    /// The runtime's Astation link was up when it greeted.
    pub astation: bool,
    /// Why remote sessions are off in this runtime, if they are.
    pub host_error: Option<String>,
    /// The worker protocol its workers speak (`None`: from before the
    /// field, i.e. worker protocol 1).
    pub worker_protocol: Option<u32>,
}

/// Where a runtime listens and logs.
#[derive(Clone, Debug)]
pub struct Locator {
    /// The socket this session's runtime dir implies.
    pub socket: PathBuf,
    /// The running runtime's own record of its socket, tried first (it may
    /// have been started from a session with another runtime dir).
    pub record: PathBuf,
    pub log: PathBuf,
    /// `runtime.lock`: held (with its pid) while a runtime runs.
    pub lock: PathBuf,
    /// `runtime.replaced`: the last time a client replaced the runtime by
    /// its own build (the guard against two builds replacing each other).
    pub replaced: PathBuf,
}

impl Locator {
    /// This user's runtime (`~/.config/atem`, `$XDG_RUNTIME_DIR`).
    pub fn default_paths() -> Self {
        Self::in_config(
            &crate::config::AtemConfig::config_dir(),
            std::env::var_os("XDG_RUNTIME_DIR"),
        )
    }

    /// The runtime of `config_dir`, as seen from a session whose runtime
    /// dir is `runtime_dir`.
    pub fn in_config(config_dir: &Path, runtime_dir: Option<OsString>) -> Self {
        let files = super::files(config_dir, runtime_dir);
        Self {
            socket: files.socket,
            record: files.record,
            log: files.log,
            lock: files.lock,
            replaced: config_dir.join("runtime.replaced"),
        }
    }

    /// Files in `dir` (tests).
    #[cfg(test)]
    pub fn in_dir(dir: &Path) -> Self {
        Self {
            socket: dir.join("rt.sock"),
            record: dir.join("runtime.socket"),
            log: dir.join("runtime.log"),
            lock: dir.join("runtime.lock"),
            replaced: dir.join("runtime.replaced"),
        }
    }
}

pub struct RuntimeClient {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
    line: Vec<u8>,
    pub welcome: Welcome,
}

/// The environment `atem runtime` is started with: what it needs to find its
/// files and settings, never the user's whole environment (sessions get
/// their launching frontend's environment instead) and never the
/// `ATEM_TEST_*` hooks (`test_hooks.rs`), which only tests set, on the
/// process they start.
pub fn runtime_env_from(
    vars: impl Iterator<Item = (OsString, OsString)>,
) -> Vec<(OsString, OsString)> {
    vars.filter(|(key, _)| {
        let key = key.to_string_lossy();
        matches!(
            key.as_ref(),
            "PATH" | "HOME" | "XDG_RUNTIME_DIR" | "RUST_LOG"
        ) || (key.starts_with("ATEM_") && !key.starts_with("ATEM_TEST_"))
            || key.starts_with("ASTATION_")
    })
    .collect()
}

/// Starts `atem runtime` detached, in `$HOME`, logging to `log`.
fn start_runtime(log: &Path) -> Result<()> {
    let exe = std::env::current_exe().context("could not find the atem executable")?;
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/"));
    let envs = runtime_env_from(std::env::vars_os());
    crate::daemon::spawn_detached_clean(&exe, "runtime", &home, log, &envs)
        .context("could not start the atem runtime")?;
    Ok(())
}

/// Why connecting failed.
enum Failure {
    /// Nothing answers: start one.
    Absent,
    /// The runtime is restarting for another protocol: start one once it's gone.
    Restarting,
    Other(anyhow::Error),
}

impl RuntimeClient {
    /// The running runtime, else a new one started detached (waits up to 5 s).
    /// A runtime of another atem build is replaced by this build first
    /// (`replace_other_build`); what happened is one warning line.
    pub async fn connect_or_start() -> Result<Self> {
        let locator = Locator::default_paths();
        let log = locator.log.clone();
        let start = move || start_runtime(&log);
        let client = Self::connect_or_start_with(&locator, &start, START_WAIT).await?;
        let own = crate::memory::cred_agent::build_id();
        replace_other_build(client, &locator, own, &start, START_WAIT, |line| {
            crate::diagnostics::warn(line)
        })
        .await
    }

    /// A frontend's way back after its runtime restarted: the next runtime
    /// (started by the client that asked for the restart; this build's when
    /// none comes up), never replacing it.
    pub async fn reconnect() -> Result<Self> {
        let locator = Locator::default_paths();
        let log = locator.log.clone();
        Self::connect_or_start_with(&locator, &move || start_runtime(&log), START_WAIT).await
    }

    /// The runtime at `locator`, if one answers; `passive`: a client that
    /// never keeps an idle runtime running (the menu's look at the sessions).
    pub(crate) async fn existing_at(locator: &Locator, passive: bool) -> Result<Option<Self>> {
        match Self::connect_as(locator, passive).await {
            Ok(client) => Ok(Some(client)),
            Err(Failure::Absent | Failure::Restarting) => Ok(None),
            Err(Failure::Other(error)) => Err(error),
        }
    }

    pub(crate) async fn connect_or_start_with(
        locator: &Locator,
        start: impl FnOnce() -> Result<()>,
        wait: Duration,
    ) -> Result<Self> {
        match Self::connect(locator).await {
            Ok(client) => return Ok(client),
            Err(Failure::Other(error)) => return Err(error),
            Err(Failure::Restarting) => {
                // Wait for it to go before starting this build's runtime.
                let deadline = tokio::time::Instant::now() + wait;
                while tokio::time::Instant::now() < deadline && dial(locator).await.is_ok() {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
            Err(Failure::Absent) => {}
        }
        start()?;
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            tokio::time::sleep(Duration::from_millis(50)).await;
            match Self::connect(locator).await {
                Ok(client) => return Ok(client),
                Err(Failure::Other(error)) => return Err(error),
                Err(_) if tokio::time::Instant::now() < deadline => {}
                Err(_) => bail!(
                    "the atem runtime didn't start; see {}",
                    locator.log.display()
                ),
            }
        }
    }

    /// A passive client of the runtime at `socket`.
    #[cfg(test)]
    pub async fn connect_passive_at(socket: &Path) -> Result<Self> {
        let stream = dial_at(socket).await?;
        match Self::greet(stream, true).await {
            Ok(client) => Ok(client),
            Err(Failure::Other(error)) => Err(error),
            Err(_) => bail!("the atem runtime at {} is restarting", socket.display()),
        }
    }

    /// Connects to the runtime at `socket` and greets it.
    #[cfg(test)]
    pub async fn connect_at(socket: &Path) -> Result<Self> {
        let stream = dial_at(socket)
            .await
            .with_context(|| format!("no atem runtime at {}", socket.display()))?;
        match Self::greet(stream, false).await {
            Ok(client) => Ok(client),
            Err(Failure::Other(error)) => Err(error),
            Err(_) => bail!("the atem runtime at {} is restarting", socket.display()),
        }
    }

    async fn connect(locator: &Locator) -> Result<Self, Failure> {
        Self::connect_as(locator, false).await
    }

    async fn connect_as(locator: &Locator, passive: bool) -> Result<Self, Failure> {
        match dial(locator).await {
            Ok(stream) => Self::greet(stream, passive).await,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                ) =>
            {
                Err(Failure::Absent)
            }
            Err(error) => Err(Failure::Other(anyhow!(error).context(format!(
                "could not reach the atem runtime at {}",
                locator.socket.display()
            )))),
        }
    }

    async fn greet(stream: UnixStream, passive: bool) -> Result<Self, Failure> {
        let (read, writer) = stream.into_split();
        let mut client = Self {
            reader: BufReader::new(read),
            writer,
            line: Vec::new(),
            welcome: Welcome {
                protocol: 0,
                build: String::new(),
                pid: 0,
                astation: false,
                host_error: None,
                worker_protocol: None,
            },
        };
        let hello = ClientMsg::Hello {
            protocol: PROTOCOL,
            build: crate::memory::cred_agent::build_id().to_string(),
            passive,
        };
        let reply = tokio::time::timeout(Duration::from_secs(10), async {
            client.send(&hello).await?;
            client.recv().await
        })
        .await
        .map_err(|_| Failure::Other(anyhow!("the atem runtime didn't answer")))?;
        match reply {
            Ok(Some(RuntimeMsg::Welcome {
                protocol,
                build,
                pid,
                astation,
                host_error,
                worker_protocol,
            })) => {
                client.welcome = Welcome {
                    protocol,
                    build,
                    pid,
                    astation,
                    host_error,
                    worker_protocol,
                };
                Ok(client)
            }
            Ok(Some(RuntimeMsg::Error { text, .. })) if text.starts_with(RESTARTING) => {
                Err(Failure::Restarting)
            }
            Ok(Some(RuntimeMsg::Error { text, .. })) => Err(Failure::Other(anyhow!(text))),
            Ok(Some(other)) => Err(Failure::Other(anyhow!(
                "unexpected reply from the atem runtime: {other:?}"
            ))),
            // Closed without a word: it was going away.
            Ok(None) => Err(Failure::Absent),
            Err(error) => Err(Failure::Other(error)),
        }
    }

    pub async fn send(&mut self, message: &ClientMsg) -> Result<()> {
        self.writer
            .write_all(encode_client(message).as_bytes())
            .await
            .context("the atem runtime closed the connection")
    }

    /// The next message; `None` once the runtime closed the connection.
    pub async fn recv(&mut self) -> Result<Option<RuntimeMsg>> {
        if !super::server::read_line(&mut self.reader, &mut self.line).await? {
            return Ok(None);
        }
        let text = std::str::from_utf8(&self.line).context("the runtime sent invalid text")?;
        decode_runtime(text)
            .map(Some)
            .map_err(|error| anyhow!("the runtime sent an invalid message: {error}"))
    }
}

/// The receiving half of a split client.
pub struct RuntimeReader {
    reader: BufReader<OwnedReadHalf>,
    line: Vec<u8>,
}

/// The sending half of a split client.
pub struct RuntimeWriter {
    writer: OwnedWriteHalf,
}

impl RuntimeClient {
    /// Halves that receive and send independently (a frontend reads on its
    /// own task: `recv` isn't cancel-safe).
    pub fn split(self) -> (RuntimeReader, RuntimeWriter) {
        (
            RuntimeReader {
                reader: self.reader,
                line: self.line,
            },
            RuntimeWriter {
                writer: self.writer,
            },
        )
    }
}

impl RuntimeReader {
    /// The next message; `None` once the runtime closed the connection.
    pub async fn recv(&mut self) -> Result<Option<RuntimeMsg>> {
        if !super::server::read_line(&mut self.reader, &mut self.line).await? {
            return Ok(None);
        }
        let text = std::str::from_utf8(&self.line).context("the runtime sent invalid text")?;
        decode_runtime(text)
            .map(Some)
            .map_err(|error| anyhow!("the runtime sent an invalid message: {error}"))
    }
}

impl RuntimeWriter {
    pub async fn send(&mut self, message: &ClientMsg) -> Result<()> {
        self.writer
            .write_all(encode_client(message).as_bytes())
            .await
            .context("the atem runtime closed the connection")
    }
}

/// The recorded socket, else the derived one.
async fn dial(locator: &Locator) -> std::io::Result<UnixStream> {
    if let Some(recorded) = crate::daemon::recorded_socket(&locator.record)
        && recorded != locator.socket
        && let Ok(stream) = dial_at(&recorded).await
    {
        return Ok(stream);
    }
    dial_at(&locator.socket).await
}

/// Connects to `socket`, refusing a listener of another user.
async fn dial_at(socket: &Path) -> std::io::Result<UnixStream> {
    let stream = UnixStream::connect(socket).await?;
    let peer = stream.peer_cred()?.uid();
    let own = unsafe { libc::getuid() };
    if peer != own {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "the socket at {} is served by another user (uid {peer}); refusing to talk to it",
                socket.display()
            ),
        ));
    }
    Ok(stream)
}

// ── Replacing a runtime of another build ──

/// No second replacement within this long: two atem builds in use would
/// otherwise keep replacing each other's runtime.
pub const REPLACE_WINDOW: Duration = Duration::from_secs(60);
/// How long a client waits for the old runtime to go.
const GONE_WAIT: Duration = Duration::from_secs(5);

/// The version part of a build id (`0.7.1+…` → `0.7.1`).
pub fn version_of(build: &str) -> &str {
    build.split('+').next().unwrap_or(build)
}

/// Why a runtime of another build is kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kept {
    /// Its workers speak another worker protocol: this build couldn't adopt
    /// the sessions it lists.
    Incompatible {
        worker_protocol: u32,
        sessions: Vec<String>,
    },
    /// It was replaced less than `REPLACE_WINDOW` ago.
    Flapping { build: String },
    /// An Astation operation runs in it.
    Busy,
    /// It doesn't know `restart` and its process can't be confirmed for a
    /// signal.
    Unconfirmed,
}

/// What `kept` means for the user, about the runtime of build `theirs`.
pub fn kept_message(kept: &Kept, theirs: &str, own: &str) -> String {
    let head = format!("Atem's runtime is build {theirs}, not this atem's {own}");
    match kept {
        Kept::Incompatible {
            worker_protocol,
            sessions,
        } => format!(
            "{head}; it is kept because this build can't adopt its sessions (worker protocol {worker_protocol}, this build speaks {}): {}. Stop them (`atem agent stop <id>`), then run `atem runtime restart`.",
            super::worker_protocol::WORKER_PROTOCOL,
            sessions.join(", ")
        ),
        Kept::Flapping { build } => format!(
            "{head}; it was replaced by build {build} less than a minute ago, so it is kept: two atem builds seem to be in use. Use one atem, or run `atem runtime restart`."
        ),
        Kept::Busy => format!(
            "{head}; it is kept while it is busy (an Astation operation runs, or a session is starting). Run `atem runtime restart` when that ends."
        ),
        Kept::Unconfirmed => format!(
            "{head} and can't be restarted from here. Stop it (`atem agent list` shows its pid), then retry; its sessions keep running."
        ),
    }
}

/// The last replacement recorded in `path`: (Unix ms, the build it started).
fn last_replacement(path: &Path) -> Option<(u64, String)> {
    let value: serde_json::Value = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
    Some((value["at_ms"].as_u64()?, value["to"].as_str()?.to_string()))
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

fn record_replacement(path: &Path, from: &str, to: &str) {
    let value = serde_json::json!({"at_ms": now_ms(), "from": from, "to": to});
    let _ = crate::daemon::write_private(path, value.to_string().as_bytes());
}

/// Whether `client`'s runtime can be replaced by build `own` now: `Err`
/// says why it is kept. `flap_guard`: refuse within `REPLACE_WINDOW` of
/// the last replacement (an explicit `atem runtime restart` skips it).
async fn may_replace(
    client: &mut RuntimeClient,
    locator: &Locator,
    flap_guard: bool,
) -> Result<(), Kept> {
    let theirs = client.welcome.worker_protocol.unwrap_or(1);
    if theirs != super::worker_protocol::WORKER_PROTOCOL {
        let sessions = super::commands::sessions(client)
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|s| s.state == "running")
            .map(|s| s.id)
            .collect();
        return Err(Kept::Incompatible {
            worker_protocol: theirs,
            sessions,
        });
    }
    if flap_guard
        && let Some((at_ms, build)) = last_replacement(&locator.replaced)
        && now_ms().saturating_sub(at_ms) < REPLACE_WINDOW.as_millis() as u64
    {
        return Err(Kept::Flapping { build });
    }
    Ok(())
}

/// Asks `client`'s runtime to exit for a restart (an older runtime that
/// doesn't know `restart` gets SIGTERM, only when `runtime.lock` names its
/// pid and that pid is confirmed as this user's `atem runtime`), then waits
/// for it to go.
async fn stop_for_restart(
    mut client: RuntimeClient,
    locator: &Locator,
) -> Result<Result<(), Kept>> {
    client.send(&ClientMsg::Restart).await?;
    let reply = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match client.recv().await {
                Ok(Some(RuntimeMsg::Restarting)) | Ok(None) | Err(_) => return Ok(()),
                Ok(Some(RuntimeMsg::Error { text, op })) => {
                    if op.as_deref() == Some("restart") || op.is_none() {
                        return Err(text);
                    }
                }
                Ok(Some(_)) => {}
            }
        }
    })
    .await
    .map_err(|_| anyhow!("the atem runtime didn't answer the restart"))?;
    match reply {
        Ok(()) => {}
        Err(text) if text.starts_with(BUSY_RESTART) => return Ok(Err(Kept::Busy)),
        // Already on its way out (another client asked first): just wait for it.
        Err(text) if text == crate::runtime::server::RESTARTING_NOW => {}
        Err(_) => {
            // A runtime from before `restart`: a confirmed SIGTERM ends it
            // as cleanly (workers survive; the journal is closed).
            let pid = client.welcome.pid;
            if crate::daemon::read_lock_pid(&locator.lock) != Some(pid)
                || !crate::daemon::confirmed_atem_pid(pid, "runtime")
            {
                return Ok(Err(Kept::Unconfirmed));
            }
            unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
        }
    }
    let old = client.welcome.pid;
    drop(client);
    let deadline = tokio::time::Instant::now() + GONE_WAIT;
    while !old_runtime_gone(locator, old).await {
        if tokio::time::Instant::now() >= deadline {
            bail!(
                "the old atem runtime didn't exit; see {}",
                locator.log.display()
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Ok(Ok(()))
}

/// Whether the runtime of pid `old` no longer serves `locator`: nothing
/// answers and nobody holds `runtime.lock`, or another runtime already does
/// (another client of this build replaced it first): the caller connects
/// to that one.
async fn old_runtime_gone(locator: &Locator, old: u32) -> bool {
    let held = crate::daemon::lock_is_held(&locator.lock) == Some(true);
    if held && crate::daemon::read_lock_pid(&locator.lock).is_some_and(|pid| pid != old) {
        return true;
    }
    if dial(locator).await.is_err() {
        return !held;
    }
    matches!(
        RuntimeClient::existing_at(locator, true).await,
        Ok(Some(client)) if client.welcome.pid != old
    )
}

/// Replaces a runtime of another build by this one, keeping its sessions.
///
/// When: every non-passive client (`connect_or_start`: `atem agent …`, the
/// menu's launches, `atem pair …`, `atem cred …`) whose build `own` differs
/// from the runtime's. Passive clients (`atem status`, `atem --version`, the
/// menu's background look) never replace.
///
/// How: `restart` (a runtime from before it gets SIGTERM, only when
/// `runtime.lock` names its pid and that pid is confirmed as this user's
/// `atem runtime`), wait until the old one is gone, `start` this build,
/// which adopts the workers; `note` gets "Atem's runtime updated to <new>
/// (was <old>); sessions kept.". Only ever toward the client's own build.
///
/// It refuses, keeping the runtime and telling `note` why
/// (`kept_message`), when:
/// - its workers speak another worker protocol (this build couldn't adopt
///   them; the running sessions that block it are named);
/// - an Astation operation (pairing, verification, unlock) runs in it;
/// - it was replaced less than `REPLACE_WINDOW` ago (`runtime.replaced`):
///   two atem builds in use would otherwise keep replacing each other.
///
/// `atem runtime restart` (`restart_runtime`) applies it on request,
/// without the anti-flap guard.
pub(crate) async fn replace_other_build(
    mut client: RuntimeClient,
    locator: &Locator,
    own: &str,
    start: &impl Fn() -> Result<()>,
    wait: Duration,
    mut note: impl FnMut(String),
) -> Result<RuntimeClient> {
    let theirs = client.welcome.build.clone();
    if theirs == own {
        return Ok(client);
    }
    if let Err(kept) = may_replace(&mut client, locator, true).await {
        note(kept_message(&kept, &theirs, own));
        return Ok(client);
    }
    match stop_for_restart(client, locator).await? {
        Ok(()) => {}
        Err(kept) => {
            note(kept_message(&kept, &theirs, own));
            return RuntimeClient::connect_or_start_with(locator, start, wait).await;
        }
    }
    record_replacement(&locator.replaced, &theirs, own);
    let client = RuntimeClient::connect_or_start_with(locator, start, wait).await?;
    note(format!(
        "Atem's runtime updated to {} (was {theirs}); sessions kept.",
        client.welcome.build
    ));
    Ok(client)
}

/// `atem runtime restart`: the running runtime is restarted as this build
/// (`start`); its sessions keep running and the new one adopts them. What
/// to print, or why it couldn't.
pub(crate) async fn restart_runtime(
    locator: &Locator,
    own: &str,
    start: &impl Fn() -> Result<()>,
    wait: Duration,
) -> Result<String> {
    let Some(mut client) = RuntimeClient::existing_at(locator, true).await? else {
        return Ok(
            "Atem's runtime isn't running; the next atem command that needs it starts this build."
                .into(),
        );
    };
    let theirs = client.welcome.build.clone();
    if let Err(kept) = may_replace(&mut client, locator, false).await {
        bail!(kept_message(&kept, &theirs, own));
    }
    if let Err(kept) = stop_for_restart(client, locator).await? {
        bail!(kept_message(&kept, &theirs, own));
    }
    record_replacement(&locator.replaced, &theirs, own);
    let mut client = RuntimeClient::connect_or_start_with(locator, start, wait).await?;
    let sessions = super::commands::sessions(&mut client).await?;
    let running = sessions.iter().filter(|s| s.state == "running").count();
    Ok(format!(
        "Atem's runtime restarted as build {} (was {theirs}); sessions kept: {running} running.",
        client.welcome.build
    ))
}

/// `atem runtime restart` for this user's runtime.
pub async fn restart() -> Result<()> {
    let locator = Locator::default_paths();
    let log = locator.log.clone();
    let start = move || start_runtime(&log);
    let own = crate::memory::cred_agent::build_id();
    println!(
        "{}",
        restart_runtime(&locator, own, &start, START_WAIT).await?
    );
    Ok(())
}

// ── A passive, synchronous look (`atem status`, `atem --version`) ──

/// What a passive look at the runtime found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Look {
    NotRunning,
    /// Something answers but couldn't be asked (or didn't answer in time).
    Unreachable(String),
    Running {
        welcome: Welcome,
        /// `None`: a runtime from before `status`.
        status: Option<RuntimeStatus>,
    },
}

impl Look {
    /// The sessions it reported.
    pub fn sessions(&self) -> &[SessionSummary] {
        match self {
            Look::Running {
                status: Some(status),
                ..
            } => &status.sessions,
            _ => &[],
        }
    }
}

/// How long a passive look may take.
pub const LOOK_TIMEOUT: Duration = Duration::from_millis(500);

/// Asks the runtime at `locator` for its status as a passive client: never
/// starts one, never keeps one running, never writes a file; within
/// `timeout` (blocking socket I/O).
pub fn look(locator: &Locator, timeout: Duration) -> Look {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream as StdStream;
    let deadline = std::time::Instant::now() + timeout;
    let connect = |socket: &Path| -> std::io::Result<StdStream> {
        let stream = StdStream::connect(socket)?;
        let peer = crate::daemon::peer_uid(&stream)?;
        if peer != unsafe { libc::getuid() } {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "{} is served by another user (uid {peer})",
                    socket.display()
                ),
            ));
        }
        Ok(stream)
    };
    let recorded = crate::daemon::recorded_socket(&locator.record)
        .filter(|recorded| *recorded != locator.socket)
        .and_then(|recorded| connect(&recorded).ok());
    let stream = match recorded.map_or_else(|| connect(&locator.socket), Ok) {
        Ok(stream) => stream,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) =>
        {
            return Look::NotRunning;
        }
        Err(error) => return Look::Unreachable(error.to_string()),
    };
    let mut reader = match stream.try_clone() {
        Ok(read) => BufReader::new(read),
        Err(error) => return Look::Unreachable(error.to_string()),
    };
    let mut writer = stream;
    let next = |reader: &mut BufReader<StdStream>| -> Result<Option<RuntimeMsg>, String> {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return Err("it didn't answer in time".into());
        }
        reader
            .get_ref()
            .set_read_timeout(Some(left))
            .map_err(|e| e.to_string())?;
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => Ok(None),
            Ok(_) => decode_runtime(&line).map(Some).map_err(|e| e.to_string()),
            Err(_) => Err("it didn't answer in time".into()),
        }
    };
    let _ = writer.set_write_timeout(Some(timeout));
    let hello = ClientMsg::Hello {
        protocol: PROTOCOL,
        build: crate::memory::cred_agent::build_id().to_string(),
        passive: true,
    };
    if let Err(error) = writer.write_all(encode_client(&hello).as_bytes()) {
        return Look::Unreachable(error.to_string());
    }
    let welcome = match next(&mut reader) {
        Ok(Some(RuntimeMsg::Welcome {
            protocol,
            build,
            pid,
            astation,
            host_error,
            worker_protocol,
        })) => Welcome {
            protocol,
            build,
            pid,
            astation,
            host_error,
            worker_protocol,
        },
        Ok(Some(RuntimeMsg::Error { text, .. })) => return Look::Unreachable(text),
        Ok(Some(other)) => {
            return Look::Unreachable(format!("unexpected reply {}", other_op(&other)));
        }
        // Closed without a word: it was going away.
        Ok(None) => return Look::NotRunning,
        Err(error) => return Look::Unreachable(error),
    };
    if let Err(error) = writer.write_all(encode_client(&ClientMsg::Status).as_bytes()) {
        return Look::Unreachable(error.to_string());
    }
    loop {
        match next(&mut reader) {
            Ok(Some(RuntimeMsg::Status { status })) => {
                return Look::Running {
                    welcome,
                    status: Some(status),
                };
            }
            // A runtime from before `status` refuses the unknown op.
            Ok(Some(RuntimeMsg::Error { .. })) | Ok(None) => {
                return Look::Running {
                    welcome,
                    status: None,
                };
            }
            Ok(Some(_)) => {}
            Err(error) => return Look::Unreachable(error),
        }
    }
}

fn other_op(message: &RuntimeMsg) -> String {
    serde_json::to_value(message)
        .ok()
        .and_then(|v| v["op"].as_str().map(str::to_string))
        .unwrap_or_default()
}
