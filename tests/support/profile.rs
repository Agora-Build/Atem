//! Profile fixtures for binary tests, which can't reach the crate: the
//! crate's own layout (`paths.rs`), stored types (`records.rs`) and
//! machine-bound encryption (`machine_key.rs`), included as they are.
use std::path::{Path, PathBuf};

#[path = "../../src/machine_key.rs"]
mod machine_key;
#[path = "../../src/paths.rs"]
pub mod paths;
#[path = "../../src/records.rs"]
pub mod records;

pub use paths::{CredPaths, ProfilePaths};

/// The cred agent's socket under the runtime dir `run`.
pub fn agent_sock(run: &Path) -> PathBuf {
    // The config dir doesn't matter for a runtime-dir socket.
    CredPaths::in_dir(Path::new("/")).agent_sock(Some(run))
}

/// Writes `config` as paired with `astation_id`, bound in generation
/// `trust_gen`, with the session `session-1`/`token-1`.
pub fn write_pairing(config: &Path, astation_id: &str, trust_gen: u64) {
    let paths = ProfilePaths::in_dir(config).pairing;
    std::fs::create_dir_all(paths.record.parent().unwrap()).unwrap();
    std::fs::write(&paths.trust_gen, format!("{trust_gen}\n")).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let record = records::PairingRecord {
        astation_id: astation_id.into(),
        binding: Some(records::BindingRecord {
            binding_id: "binding-1".into(),
            host_trust_gen: trust_gen,
            created_at: 1,
        }),
        session: Some(records::SavedSession {
            session_id: "session-1".into(),
            token: "token-1".into(),
            hostname: "h".into(),
            last_activity: now,
        }),
        shared: None,
        save_credentials: false,
        disconnected_at: None,
        relay_only: false,
    };
    let plain = serde_json::to_vec(&record).unwrap();
    let sealed = machine_key::encrypt(machine_key::PAIRING, &plain).unwrap();
    std::fs::write(&paths.record, sealed).unwrap();
}

/// The saved session of `config`'s pairing record (`session_id`), if any.
pub fn saved_session_id(config: &Path) -> Option<String> {
    let paths = ProfilePaths::in_dir(config).pairing;
    let raw = std::fs::read(&paths.record).ok()?;
    let plain = machine_key::decrypt(machine_key::PAIRING, &raw).ok()?;
    let record: records::PairingRecord = serde_json::from_slice(&plain).ok()?;
    record.session.map(|s| s.session_id)
}
