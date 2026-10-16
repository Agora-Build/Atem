//! `atem runtime`: one background process per config directory that hosts
//! every agent session and the Astation connection behind a same-user Unix
//! socket. See `designs/agent-runtime.md`.
// The frontends (`atem agent launch|attach|list|stop`, next task) use it.
#[allow(dead_code)]
pub mod client;
// The broker drives workers from the next task on; until then it only
// adopts them at start.
#[allow(dead_code)]
pub mod adopt;
pub mod protocol;
pub mod server;
#[allow(dead_code)]
pub mod worker;
#[allow(dead_code)]
pub mod worker_protocol;

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

/// Adopts the workers an earlier broker left (see `adopt.rs`), logging what
/// became of each, and keeps the adopted connections until they close. The
/// broker routes sessions through them from the next task on.
async fn adopt_workers(state: PathBuf) {
    for adoption in adopt::adopt(&state).await {
        let sid = adoption.session_id().to_string();
        match adoption {
            adopt::Adoption::Adopted(mut handle) => {
                eprintln!(
                    "atem runtime: adopted worker {sid} (process_gen {}, pid {})",
                    handle.info.process_gen, handle.info.pid
                );
                tokio::spawn(async move {
                    while let Some(message) = handle.recv().await {
                        if let worker_protocol::WorkerMsg::Exited { status } = message {
                            eprintln!("atem runtime: {sid} exited ({status})");
                        }
                    }
                });
            }
            adopt::Adoption::RecoveryRequired { reason, .. } => {
                eprintln!("atem runtime: {sid}: recovery_required ({reason})");
            }
            other => eprintln!("atem runtime: {sid}: {}", other.status()),
        }
    }
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
/// makes this one exit successfully. Its sessions end with it.
pub async fn run_runtime(config_dir: PathBuf) -> Result<()> {
    // Taken now, before a rebuild can replace the executable on disk.
    let build = crate::memory::key_agent::build_id();
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
    tokio::spawn(adopt_workers(state_dir(&config_dir)));
    let mut app = crate::app::App::new();
    app.spawn_astation_connect();
    let options = server::Options {
        idle: idle_timeout(),
        uid,
    };
    let served = server::serve(app, listener, options, shutdown_signal()).await;
    // A clean exit takes its pid out of the lock and removes its socket.
    daemon::clear_held_pids();
    daemon::remove_socket(&files);
    eprintln!("atem runtime (pid {}) exiting", std::process::id());
    served
}
