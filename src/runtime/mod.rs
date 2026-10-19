//! `atem runtime`: one background process per config directory, the broker:
//! every agent session runs in its own `atem worker` that the broker started
//! or adopted (`broker.rs`), and the broker serves local frontends behind a
//! same-user Unix socket and holds the Astation connection. See
//! `designs/agent-runtime.md`.
pub mod adopt;
pub mod broker;
pub mod client;
pub mod commands;
pub mod host_bridge;
pub mod op_client;
pub mod ops;
pub mod protocol;
pub mod push_queue;
pub mod refusal_log;
pub mod server;
pub mod session_log;
pub mod test_hooks;
pub mod worker;
pub mod worker_approvals;
pub mod worker_chat;
pub mod worker_protocol;

#[cfg(test)]
mod ops_tests;
#[cfg(test)]
mod server_tests;

use crate::daemon::{self, DaemonFiles};
use anyhow::Result;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The runtime's files: socket in `$XDG_RUNTIME_DIR/atem` (else the config
/// dir); lock (`runtime.lock`, with the pid), socket record
/// (`runtime.socket`) and log (`runtime.log`) in the config dir, so there is
/// one runtime per config dir whatever the runtime dir.
pub fn files(config_dir: &Path, runtime_dir: Option<OsString>) -> DaemonFiles {
    let mut files = DaemonFiles::for_name(config_dir, runtime_dir, "runtime");
    files.lock = config_dir.join("runtime.lock");
    files.record = config_dir.join("runtime.socket");
    files
}

/// The broker's state directory (`<config>/runtime`): worker records and
/// specs under `workers/`.
pub fn state_dir(config_dir: &Path) -> PathBuf {
    config_dir.join("runtime")
}

static IN_RUNTIME: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// This process is `atem runtime` (it holds the Astation link itself).
pub fn in_runtime() -> bool {
    IN_RUNTIME.load(std::sync::atomic::Ordering::SeqCst)
}

/// `ATEM_RUNTIME_IDLE_SECS` (for tests), else 10 minutes.
fn idle_timeout() -> Duration {
    std::env::var("ATEM_RUNTIME_IDLE_SECS")
        .ok()
        .and_then(|secs| secs.parse().ok())
        .map(Duration::from_secs)
        .unwrap_or(server::IDLE_EXIT)
}

async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let (Ok(mut term), Ok(mut int)) = (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
    ) else {
        return std::future::pending().await;
    };
    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
    }
}

/// `atem runtime` (hidden): serves this config dir's sessions until it is
/// idle, signalled or replaced. A runtime already serving the config dir
/// makes this one exit successfully. Its sessions' workers outlive it; the
/// next runtime adopts them.
pub async fn run_runtime(config_dir: PathBuf) -> Result<()> {
    // Taken now, before a rebuild can replace the executable on disk.
    let build = crate::memory::cred_agent::build_id();
    IN_RUNTIME.store(true, std::sync::atomic::Ordering::SeqCst);
    if let Some(home) = dirs::home_dir() {
        let _ = std::env::set_current_dir(home);
    }
    let files = files(&config_dir, std::env::var_os("XDG_RUNTIME_DIR"));
    let uid = unsafe { libc::getuid() };
    let listener = match daemon::bind_socket(&files, uid) {
        Ok(listener) => listener,
        Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
            eprintln!("atem runtime: {error}; another runtime serves this config dir, exiting");
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    eprintln!(
        "atem runtime (protocol v{}, build {build}, pid {}) listening on {}",
        protocol::PROTOCOL,
        std::process::id(),
        files.socket.display()
    );
    let paths =
        adopt::WorkerPaths::new(&state_dir(&config_dir), std::env::var_os("XDG_RUNTIME_DIR"))?;
    // Chat directories of workers that are gone (a live worker's names its pid).
    crate::chat::claude::hooks::sweep_stale(&crate::chat::claude::hooks::session_dir_root());
    // The identity the host starts under, read before the Astation connect
    // starts writing to the profile (`instance_id`, `atem_id`).
    let profile = crate::status::Sources::current().ok();
    let mut app = crate::app::App::new();
    app.spawn_astation_connect();
    let options = server::Options {
        idle: idle_timeout(),
        uid,
        launcher: broker::Launcher::Process(paths),
        profile,
        clock: host_bridge::Clock::default(),
        ops: ops::OpEnv::for_user(),
    };
    let served = server::serve(app, listener, options, shutdown_signal()).await;
    // A clean exit takes its pid out of the lock and removes its socket.
    daemon::clear_held_pids();
    daemon::remove_socket(&files);
    eprintln!("atem runtime (pid {}) exiting", std::process::id());
    served
}
