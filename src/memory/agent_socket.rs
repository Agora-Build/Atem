//! The key agent's Unix socket: newline-delimited JSON, `"v": 1` on every
//! request, same-user peers only. `atem key-agent` serves it; commands that
//! need keys connect, starting the agent when none is running.
//! See designs/e2e-encryption.md "Keys on disk (atem)".
//!
//! Serialized requests and replies can carry secrets, so they live in
//! `Zeroizing` buffers that are dropped right after use, and nothing here
//! goes through a `serde_json::Value` or a `BufReader` (which would keep
//! unzeroized copies).
use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use zeroize::Zeroizing;

use crate::memory::key_agent::{KeyAgent, KeyAgentApi, PROTOCOL_VERSION, Reply, Request};
use crate::memory::verification::KeyPaths;

/// No request or reply is anywhere near this; it only bounds a misbehaving peer.
const MAX_LINE: usize = 16 << 20;

/// `$XDG_RUNTIME_DIR/atem/agent.sock`, else `~/.config/atem/agent.sock`.
pub fn agent_socket_path() -> PathBuf {
    socket_path_from(
        std::env::var_os("XDG_RUNTIME_DIR"),
        &crate::config::AtemConfig::config_dir(),
    )
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

#[derive(Deserialize)]
struct VersionOnly {
    v: Option<u64>,
}

pub(crate) fn encode_request(request: &Request) -> Result<Zeroizing<String>> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(4096));
    serde_json::to_writer(
        &mut *bytes,
        &Envelope {
            request,
            v: PROTOCOL_VERSION,
        },
    )?;
    bytes.push(b'\n');
    let text = String::from_utf8(std::mem::take(&mut *bytes))
        .map_err(|_| anyhow!("key agent request is not UTF-8"))?;
    Ok(Zeroizing::new(text))
}

pub(crate) fn decode_request(line: &str) -> Result<Request> {
    let version: VersionOnly =
        serde_json::from_str(line).context("key agent request is not JSON")?;
    match version.v {
        Some(PROTOCOL_VERSION) => {}
        other => bail!(
            "unsupported key agent protocol version {}; this agent speaks v{PROTOCOL_VERSION}",
            other.map_or_else(|| "(none)".to_string(), |v| v.to_string())
        ),
    }
    serde_json::from_str(line).context("key agent request is malformed")
}

pub(crate) fn decode_response(line: &str) -> Result<Reply> {
    let response: Response =
        serde_json::from_str(line.trim()).context("the key agent sent an unreadable reply")?;
    if response.v != PROTOCOL_VERSION {
        bail!(
            "the running key agent speaks protocol v{}, this atem speaks v{PROTOCOL_VERSION}; stop it with `pkill -u \"$USER\" -f 'atem key-agent'` (its keys stay sealed on disk) and retry",
            response.v
        );
    }
    if !response.ok {
        bail!(
            "{}",
            response
                .error
                .unwrap_or_else(|| "the key agent refused the request".into())
        );
    }
    response
        .reply
        .ok_or_else(|| anyhow!("the key agent sent an empty reply"))
}

fn respond(agent: &Mutex<KeyAgent>, line: &str) -> Zeroizing<Vec<u8>> {
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
    let mut bytes = Zeroizing::new(Vec::with_capacity(4096));
    if serde_json::to_writer(&mut *bytes, &response).is_err() {
        bytes.clear();
        bytes.extend_from_slice(
            br#"{"v":1,"ok":false,"error":"the key agent could not encode its reply"}"#,
        );
    }
    bytes.push(b'\n');
    bytes
}

/// Listens on `socket`: directory 0700, socket 0600. A socket file nobody
/// answers on is left by an agent that died, and is replaced.
pub fn bind(socket: &Path) -> Result<tokio::net::UnixListener> {
    use std::os::unix::fs::PermissionsExt;
    let dir = socket
        .parent()
        .ok_or_else(|| anyhow!("the agent socket path has no directory"))?;
    std::fs::create_dir_all(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    if socket.exists() {
        if UnixStream::connect(socket).is_ok() {
            bail!("a key agent is already running at {}", socket.display());
        }
        std::fs::remove_file(socket)?;
    }
    let listener = tokio::net::UnixListener::bind(socket)
        .with_context(|| format!("could not listen on {}", socket.display()))?;
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// Serves `agent` to peers running as `allowed_uid`; others are dropped.
pub async fn serve(
    listener: tokio::net::UnixListener,
    agent: Arc<Mutex<KeyAgent>>,
    allowed_uid: u32,
) -> Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
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
    let mut pending = Zeroizing::new(Vec::<u8>::with_capacity(8192));
    let mut chunk = Zeroizing::new([0u8; 4096]);
    loop {
        while let Some(end) = pending.iter().position(|byte| *byte == b'\n') {
            let line = Zeroizing::new(pending.drain(..=end).collect::<Vec<u8>>());
            let reply = match std::str::from_utf8(&line[..end]) {
                Ok(text) => respond(agent, text),
                Err(_) => respond(agent, ""),
            };
            write.write_all(&reply).await?;
        }
        if pending.len() > MAX_LINE {
            bail!("a request is too long");
        }
        let n = read.read(&mut chunk[..]).await?;
        if n == 0 {
            return Ok(());
        }
        pending.extend_from_slice(&chunk[..n]);
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
    let socket = agent_socket_path();
    let listener = bind(&socket)?;
    // A key-file error never stops the agent: it starts locked and says why
    // on `atem cred status` (see KeyAgent::new).
    let agent = KeyAgent::new(KeyPaths::default_paths())?;
    eprintln!(
        "atem key agent (protocol v{PROTOCOL_VERSION}) listening on {}",
        socket.display()
    );
    serve(listener, Arc::new(Mutex::new(agent)), unsafe {
        libc::getuid()
    })
    .await
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
        Ok(())
    };
    // SAFETY: setsid is async-signal-safe, as pre_exec requires.
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

/// How a client starts an agent when none answers.
type Launcher = Box<dyn Fn() -> Result<()> + Send + Sync>;

pub struct KeyAgentClient {
    socket: PathBuf,
    launcher: Option<Launcher>,
}

impl KeyAgentClient {
    /// A client for the agent at `socket` that never starts one.
    pub fn at(socket: PathBuf) -> Self {
        Self {
            socket,
            launcher: None,
        }
    }

    /// A client for this user's agent that starts it when none answers.
    pub fn autostart() -> Self {
        Self {
            socket: agent_socket_path(),
            launcher: Some(Box::new(|| {
                spawn_agent(&std::env::current_exe()?, &agent_log_path(), &[]).map(|_| ())
            })),
        }
    }

    /// A client for the agent at `socket` that starts it with `launcher`.
    #[cfg(test)]
    pub(crate) fn with_launcher(socket: PathBuf, launcher: Launcher) -> Self {
        Self {
            socket,
            launcher: Some(launcher),
        }
    }

    pub fn is_running(&self) -> bool {
        UnixStream::connect(&self.socket).is_ok()
    }

    fn connect(&self) -> Result<UnixStream> {
        match UnixStream::connect(&self.socket) {
            Ok(stream) => Ok(stream),
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
                for _ in 0..50 {
                    std::thread::sleep(Duration::from_millis(100));
                    if let Ok(stream) = UnixStream::connect(&self.socket) {
                        return Ok(stream);
                    }
                }
                bail!(
                    "the key agent didn't start; see {}",
                    agent_log_path().display()
                )
            }
            Err(error) => Err(anyhow!(error).context(format!(
                "the key agent isn't running at {}",
                self.socket.display()
            ))),
        }
    }
}

/// Reads one reply line without a `BufReader`, so no unzeroized copy stays behind.
fn read_reply(mut stream: &UnixStream) -> std::io::Result<Zeroizing<Vec<u8>>> {
    let mut line = Zeroizing::new(Vec::<u8>::with_capacity(4096));
    let mut chunk = Zeroizing::new([0u8; 4096]);
    loop {
        let n = stream.read(&mut chunk[..])?;
        if n == 0 || line.len() > MAX_LINE {
            return Ok(line);
        }
        line.extend_from_slice(&chunk[..n]);
        if chunk[..n].contains(&b'\n') {
            return Ok(line);
        }
    }
}

impl KeyAgentApi for KeyAgentClient {
    fn call(&self, request: Request) -> Result<Reply> {
        let line = encode_request(&request)?;
        drop(request);
        let stream = self.connect()?;
        let closed = |error: std::io::Error| {
            anyhow!("the key agent closed the connection ({error}); is it running as another user?")
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .map_err(closed)?;
        (&stream).write_all(line.as_bytes()).map_err(closed)?;
        drop(line);
        let reply = read_reply(&stream).map_err(closed)?;
        if reply.is_empty() {
            bail!("the key agent closed the connection; is it running as another user?");
        }
        let text = std::str::from_utf8(&reply)
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
        assert_eq!(value, serde_json::json!({"op": "status", "v": 1}));
        assert!(matches!(
            decode_request(line.trim()).unwrap(),
            Request::Status
        ));
        let newer = decode_request(r#"{"op":"status","v":2}"#).err().unwrap();
        assert!(format!("{newer:#}").contains("protocol version 2"));
        assert!(decode_request(r#"{"op":"status"}"#).is_err());
    }

    #[test]
    fn a_newer_cli_gets_a_clear_error_from_an_older_agent() {
        let newer_agent = decode_response(r#"{"v":2,"ok":true,"reply":{"kind":"done"}}"#);
        assert!(format!("{:#}", newer_agent.err().unwrap()).contains("pkill"));
        let refused = decode_response(
            r#"{"v":1,"ok":false,"error":"unsupported key agent protocol version 2"}"#,
        );
        assert!(format!("{:#}", refused.err().unwrap()).contains("protocol version 2"));
        assert!(matches!(
            decode_response(r#"{"v":1,"ok":true,"reply":{"kind":"done"}}"#).unwrap(),
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
        stream.write_all(b"{\"op\":\"status\",\"v\":2}\n").unwrap();
        let mut line = String::new();
        BufReader::new(&stream).read_line(&mut line).unwrap();
        let response: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(response["v"], 1);
        assert_eq!(response["ok"], false);
        assert!(
            response["error"]
                .as_str()
                .unwrap()
                .contains("protocol version 2")
        );
    }

    #[test]
    fn another_user_is_refused() {
        let dir = short_dir();
        let socket = start_agent(dir.path(), own_uid().wrapping_add(1));
        let error = format!("{:#}", KeyAgentClient::at(socket).status().err().unwrap());
        assert!(error.contains("closed the connection"), "{error}");
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
            std::fs::create_dir_all(stale.parent().unwrap()).unwrap();
            drop(std::os::unix::net::UnixListener::bind(&stale).unwrap());
            assert!(stale.exists());
            bind(&stale).unwrap();
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
        // Starts the real binary (built because integration tests exist).
        let dir = short_dir();
        let home = dir.path().join("home");
        let runtime = dir.path().join("run");
        std::fs::create_dir_all(&home).unwrap();
        let exe = std::env::current_exe()
            .unwrap()
            .parent()
            .and_then(Path::parent)
            .unwrap()
            .join("atem");
        assert!(
            exe.exists(),
            "build the atem binary first: {}",
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
        let client = KeyAgentClient::with_launcher(socket.clone(), launcher);
        assert!(!client.is_running());
        let status = client.status().unwrap();
        assert!(!status.unlocked);
        assert!(client.is_running());
        assert!(pid.lock().unwrap().is_some());
        // A second client finds the same agent without starting another.
        assert!(!KeyAgentClient::at(socket).status().unwrap().unlocked);
    }
}
