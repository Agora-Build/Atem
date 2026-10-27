//! Every file of the profile (`~/.config/atem`): the one definition of its
//! layout. Code and tests take paths from here; std only, so binary tests
//! include this file (`#[path]`). This user's profile is
//! `profile::default_paths`. The runtime's own files are `runtime::files`
//! and `runtime::state_dir`.
//!
//! ```text
//! ~/.config/atem/
//!   login.enc        the user's own login (`atem login`), machine-bound
//!   pairing.json     legacy (until v0.7.1): read only, a trust generation floor
//!   pairing/         0700: the one pairing
//!     pairing.enc    the pairing record, machine-bound
//!     trust_gen      the host trust generation (+ trust_gen.lock)
//!   cred/            0700: this device's keys, trust state, cred agent
//!     trust_gen_floor  a floor copy of the host trust generation
//! ```
use std::path::{Path, PathBuf};

/// The profile's layout.
#[derive(Debug, Clone)]
pub struct ProfilePaths {
    /// `config.toml`.
    pub config: PathBuf,
    /// `login.enc`: the user's own login (`credentials::Login`).
    pub login: PathBuf,
    /// `pairing.json`: before `pairing/` (until v0.7.1) the host trust
    /// generation lived here; read only, as a witness the generation never
    /// goes below (`pairing::load`), never written or removed.
    pub legacy_pairing: PathBuf,
    pub pairing: PairingPaths,
    pub cred: CredPaths,
}

impl ProfilePaths {
    /// The layout under the profile directory `dir`.
    pub fn in_dir(dir: &Path) -> Self {
        Self {
            config: dir.join("config.toml"),
            login: dir.join("login.enc"),
            legacy_pairing: dir.join("pairing.json"),
            pairing: PairingPaths::in_dir(dir),
            cred: CredPaths::in_dir(dir),
        }
    }
}

/// `<profile>/pairing/` (0700, created by the first write): the one
/// pairing.
#[derive(Debug, Clone)]
pub struct PairingPaths {
    /// `pairing.enc`: the pairing record (`pairing::PairingRecord`).
    pub record: PathBuf,
    /// `trust_gen`: the host trust generation; its lock (`trust_gen.lock`)
    /// guards every pairing change and every bound apply.
    pub trust_gen: PathBuf,
    /// r9 device list (§R9.3; `session_protocol::membership`):
    /// `membership.json` (the verified log, head, recovery, evidence, freeze).
    pub membership: PathBuf,
    /// `membership.carriage`: a carriage, durable before it is evaluated.
    pub carriage: PathBuf,
    /// `membership.intent`: the head about to be written.
    pub intent: PathBuf,
    /// `membership.freeze`: both conflicting entries of a freeze.
    pub freeze: PathBuf,
    /// `membership.fault`: a device-list write fault was observed.
    pub fault: PathBuf,
    /// `frozen_genesis`: genesis hashes this host was frozen on (kept by
    /// `atem unpair`; ≤ 16).
    pub frozen_genesis: PathBuf,
    /// `revoked_floor`: a copy of the revoked browser grants' bound
    /// (`runtime/journal/revoked_quarantine`), outside the journal directory
    /// (kept by `atem unpair`; only ever raised).
    pub revoked_floor: PathBuf,
    /// `host_channel_key`: the host's atem-ch1 key (deleted by `atem unpair`).
    pub host_channel_key: PathBuf,
    /// `host_policy.json`: the relay-only policy a manager set (§R9.8a;
    /// deleted by `atem unpair` and at a new pin).
    pub host_policy: PathBuf,
    /// `host_policy.pending`: the policy a write left uncertain (its bytes,
    /// rolled forward at start); no local link while it exists.
    pub host_policy_pending: PathBuf,
}

impl PairingPaths {
    fn in_dir(profile: &Path) -> Self {
        let dir = profile.join("pairing");
        Self {
            record: dir.join("pairing.enc"),
            trust_gen: dir.join("trust_gen"),
            membership: dir.join("membership.json"),
            carriage: dir.join("membership.carriage"),
            intent: dir.join("membership.intent"),
            freeze: dir.join("membership.freeze"),
            fault: dir.join("membership.fault"),
            frozen_genesis: dir.join("frozen_genesis"),
            revoked_floor: dir.join("revoked_floor"),
            host_channel_key: dir.join("host_channel_key"),
            host_policy: dir.join("host_policy.json"),
            host_policy_pending: dir.join("host_policy.pending"),
        }
    }

    /// `<profile>/pairing`.
    pub fn dir(&self) -> &Path {
        self.trust_gen
            .parent()
            .expect("trust_gen is in the pairing dir")
    }
}

/// The cred directory's layout: every file of this device's keys, its trust
/// state and the cred agent, under `<profile>/cred/` (0700, files 0600).
/// The only place these names are written down; tests use it too.
#[derive(Debug, Clone)]
pub struct CredPaths {
    /// `<profile>/cred`.
    pub dir: PathBuf,
    /// `project_names.json`: `h1.` project hash → readable project key
    /// (its lock: `project_names.lock`).
    pub project_names: PathBuf,
    /// `state.json`: pinned Astations, the signed account state (its lock:
    /// `state.lock`).
    pub trust: PathBuf,
    /// The plain file (a step-1 device's, or a fresh device's until its
    /// first escrow); the cred agent seals it into `device_keys_sealed` and
    /// deletes it once Astation is known to hold the storage key.
    pub device_keys: PathBuf,
    pub device_keys_sealed: PathBuf,
    /// Written in rotation phase 1, renamed over `device_keys_sealed` in phase 3.
    pub device_keys_next: PathBuf,
    /// The sealed file a rotation replaced, kept until an unlock proves
    /// Astation holds the new storage key.
    pub device_keys_prev: PathBuf,
    pub unlock_auth_key: PathBuf,
    /// Held (flock, with its pid) by the one cred agent serving these
    /// files, for its life.
    pub agent_lock: PathBuf,
    /// The socket path that agent listens on, for clients whose runtime
    /// dir differs from the agent's.
    pub agent_socket: PathBuf,
    /// Output of the detached cred agent.
    pub agent_log: PathBuf,
    /// `trust_gen_floor`: a copy of the host trust generation beside the
    /// device id Astation keys its floor by, so losing `pairing/` never
    /// lowers it (`pairing::load`).
    pub trust_gen_floor: PathBuf,
}

impl CredPaths {
    /// The layout under the profile directory `profile`.
    pub fn in_dir(profile: &Path) -> Self {
        let dir = profile.join("cred");
        Self {
            project_names: dir.join("project_names.json"),
            trust: dir.join("state.json"),
            device_keys: dir.join("device_keys"),
            device_keys_sealed: dir.join("device_keys.sealed"),
            device_keys_next: dir.join("device_keys.sealed.next"),
            device_keys_prev: dir.join("device_keys.sealed.prev"),
            unlock_auth_key: dir.join("unlock_auth_key"),
            agent_lock: dir.join("agent.lock"),
            agent_socket: dir.join("agent.socket"),
            agent_log: dir.join("agent.log"),
            trust_gen_floor: dir.join("trust_gen_floor"),
            dir,
        }
    }

    /// The agent's socket: `<runtime_dir>/atem/cred-agent.sock` when
    /// `runtime_dir` is set (the caller checked it is safe), else
    /// `cred/agent.sock`.
    pub fn agent_sock(&self, runtime_dir: Option<&Path>) -> PathBuf {
        match runtime_dir {
            Some(dir) if !dir.as_os_str().is_empty() => dir.join("atem").join("cred-agent.sock"),
            _ => self.dir.join("agent.sock"),
        }
    }
}

/// The lock beside an agent socket: `<socket>.lock`.
pub fn socket_lock(socket: &Path) -> PathBuf {
    let mut name = socket.as_os_str().to_owned();
    name.push(".lock");
    PathBuf::from(name)
}

/// Tests: writes `bytes` to `path`, creating its directory (the cred dir).
#[cfg(test)]
pub(crate) fn write_test_file(path: &Path, bytes: impl AsRef<[u8]>) {
    create_private_dir(path.parent().expect("a file in a directory")).unwrap();
    std::fs::write(path, bytes).unwrap();
}

/// Creates `dir` (and missing parents) private to this user (0700).
pub fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_profile_layout() {
        let profile = ProfilePaths::in_dir(Path::new("/home/u/.config/atem"));
        let dir = Path::new("/home/u/.config/atem");
        assert_eq!(profile.login, dir.join("login.enc"));
        assert_eq!(profile.config, dir.join("config.toml"));
        assert_eq!(profile.legacy_pairing, dir.join("pairing.json"));
        assert_eq!(profile.pairing.record, dir.join("pairing/pairing.enc"));
        assert_eq!(profile.pairing.trust_gen, dir.join("pairing/trust_gen"));
        assert_eq!(profile.cred.dir, dir.join("cred"));
    }

    #[test]
    fn the_cred_layout_lives_under_cred() {
        let paths = CredPaths::in_dir(Path::new("/home/u/.config/atem"));
        let cred = Path::new("/home/u/.config/atem/cred");
        assert_eq!(paths.dir, cred);
        for (path, name) in [
            (&paths.trust, "state.json"),
            (&paths.project_names, "project_names.json"),
            (&paths.device_keys, "device_keys"),
            (&paths.device_keys_sealed, "device_keys.sealed"),
            (&paths.device_keys_next, "device_keys.sealed.next"),
            (&paths.device_keys_prev, "device_keys.sealed.prev"),
            (&paths.unlock_auth_key, "unlock_auth_key"),
            (&paths.agent_lock, "agent.lock"),
            (&paths.agent_socket, "agent.socket"),
            (&paths.agent_log, "agent.log"),
            (&paths.trust_gen_floor, "trust_gen_floor"),
        ] {
            assert_eq!(path, &cred.join(name));
        }
        assert_eq!(
            paths.agent_sock(Some(Path::new("/run/user/1000"))),
            Path::new("/run/user/1000/atem/cred-agent.sock")
        );
        assert_eq!(paths.agent_sock(None), cred.join("agent.sock"));
        assert_eq!(
            paths.agent_sock(Some(Path::new(""))),
            cred.join("agent.sock")
        );
        assert_eq!(
            socket_lock(&cred.join("agent.sock")),
            cred.join("agent.sock.lock")
        );
    }
}
