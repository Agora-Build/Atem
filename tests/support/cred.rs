//! The cred directory's layout for binary tests, which can't reach the
//! crate's `CredPaths` (src/memory/verification.rs): keep the two in step.
use std::path::{Path, PathBuf};

/// `<config>/cred`.
pub fn dir(config: &Path) -> PathBuf {
    config.join("cred")
}

/// The trust state (`CredPaths::trust`).
pub fn state(config: &Path) -> PathBuf {
    dir(config).join("state.json")
}

/// The cred agent's lock, with its pid (`CredPaths::agent_lock`).
pub fn agent_lock(config: &Path) -> PathBuf {
    dir(config).join("agent.lock")
}

/// The cred agent's socket under the runtime dir `run`
/// (`CredPaths::agent_sock`).
pub fn agent_sock(run: &Path) -> PathBuf {
    run.join("atem").join("cred-agent.sock")
}
