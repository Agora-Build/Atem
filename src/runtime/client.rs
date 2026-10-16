//! A frontend's connection to `atem runtime`: JSON lines over the same-user
//! socket, started detached when no runtime answers.

use super::protocol::{ClientMsg, PROTOCOL, RuntimeMsg, decode_runtime, encode_client};
pub use super::server::RESTARTING;
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
}

impl Locator {
    /// This user's runtime (`~/.config/atem`, `$XDG_RUNTIME_DIR`).
    pub fn default_paths() -> Self {
        let files = super::files(
            &crate::config::AtemConfig::config_dir(),
            std::env::var_os("XDG_RUNTIME_DIR"),
        );
        Self {
            socket: files.socket,
            record: files.record,
            log: files.log,
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
/// their launching frontend's environment instead).
pub fn runtime_env_from(
    vars: impl Iterator<Item = (OsString, OsString)>,
) -> Vec<(OsString, OsString)> {
    vars.filter(|(key, _)| {
        let key = key.to_string_lossy();
        matches!(
            key.as_ref(),
            "PATH" | "HOME" | "XDG_RUNTIME_DIR" | "RUST_LOG"
        ) || key.starts_with("ATEM_")
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
    pub async fn connect_or_start() -> Result<Self> {
        let locator = Locator::default_paths();
        let log = locator.log.clone();
        Self::connect_or_start_with(&locator, move || start_runtime(&log), START_WAIT).await
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
            },
        };
        let hello = ClientMsg::Hello {
            protocol: PROTOCOL,
            build: crate::memory::key_agent::build_id().to_string(),
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
            })) => {
                client.welcome = Welcome {
                    protocol,
                    build,
                    pid,
                    astation,
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
