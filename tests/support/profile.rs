//! The profile's layout and files for binary tests, which can't reach the
//! crate: keep in step with `src/paths.rs` (`ProfilePaths`, `CredPaths`) and
//! `src/pairing.rs` (`PairingRecord`). The machine-bound encryption is the
//! crate's own file.
use serde_json::json;
use std::path::{Path, PathBuf};

#[path = "../../src/machine_key.rs"]
mod machine_key;

/// `<config>/cred`.
pub fn cred_dir(config: &Path) -> PathBuf {
    config.join("cred")
}

/// The trust state (`CredPaths::trust`).
pub fn cred_state(config: &Path) -> PathBuf {
    cred_dir(config).join("state.json")
}

/// The cred agent's lock, with its pid (`CredPaths::agent_lock`).
pub fn agent_lock(config: &Path) -> PathBuf {
    cred_dir(config).join("agent.lock")
}

/// The cred agent's socket under the runtime dir `run`
/// (`CredPaths::agent_sock`).
pub fn agent_sock(run: &Path) -> PathBuf {
    run.join("atem").join("cred-agent.sock")
}

/// Writes `config` as paired with `astation_id`, bound in generation
/// `trust_gen`, with the session `session-1`/`token-1`
/// (`PairingPaths`, `PairingRecord`).
pub fn write_pairing(config: &Path, astation_id: &str, trust_gen: u64) {
    let dir = config.join("pairing");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("trust_gen"), format!("{trust_gen}\n")).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let record = json!({
        "astation_id": astation_id,
        "binding": {"binding_id": "binding-1", "host_trust_gen": trust_gen, "created_at": 1},
        "session": {"session_id": "session-1", "token": "token-1", "hostname": "h",
                    "last_activity": now},
        "save_credentials": false,
    });
    let sealed = machine_key::encrypt(record.to_string().as_bytes()).unwrap();
    std::fs::write(dir.join("pairing.enc"), sealed).unwrap();
}
