//! `atem status` and its `atem cred status` alias: one read-only, offline
//! report of the account, the pairing, this device's verification and its
//! credentials. It never connects anywhere, never starts the key agent (it
//! asks only one that is already running) and never writes a file. Remote
//! facts it can't check offline are shown as unknown and stale.
//!
//! The same facts decide `atem pair` (a no-op once paired), `atem pair
//! verify` (only for an existing pairing, never after a revocation) and the
//! `atem cred unlock` gate.
use anyhow::{Result, anyhow};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::auth::SessionManager;
use crate::config::AtemConfig;
use crate::credentials::{CredentialEntry, CredentialSource, CredentialStore};
use crate::memory::key_agent::KeyAgentApi;
use crate::memory::trust::TrustStore;
use crate::memory::verification::KeyPaths;

/// `atem pair` on a profile that is already paired (after the status).
pub const ALREADY_PAIRED: &str = "Already paired. Verify this device: atem pair verify · Replace the pairing: atem unpair, then atem pair";
/// `atem pair verify` without a pairing.
pub const NOT_PAIRED: &str = "Not paired. Run atem pair first.";
/// `atem cred unlock` on a device no Astation verified.
pub const UNVERIFIED_UNLOCK: &str = "This device isn't verified. Run atem pair verify first.";

/// `atem pair verify` on a device the Astation revoked.
pub fn revoked_message(astation_id: &str) -> String {
    format!(
        "This device was revoked by Astation {astation_id}. Run atem unpair, then atem pair, to set it up again."
    )
}

/// `atem pair verify` when the paired Astation already verified this device.
pub fn already_verified_message(safety_code: &str) -> String {
    format!("Already verified (safety code {safety_code}).")
}

/// One status value; `stale` marks cached or unchecked remote information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    pub value: String,
    pub stale: bool,
}

impl Line {
    fn fresh(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            stale: false,
        }
    }

    fn stale(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            stale: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusReport {
    pub account: Line,
    pub pairing: Line,
    pub verification: Line,
    pub credentials: Line,
    pub authorization: Line,
    pub relay: Line,
    pub local_agents: Line,
}

/// Where the status is read from. `current()` is this user's profile;
/// `in_dir` a profile directory (tests).
#[derive(Debug, Clone)]
pub struct Sources {
    /// Connection settings (`pair` and `pair verify` connect with them;
    /// `astation_relay_code` selects the Astation `require_pairing` uses).
    pub config: AtemConfig,
    pub credentials: PathBuf,
    pub sessions: PathBuf,
    pub keys: KeyPaths,
    /// Ask an already running key agent whether the keys are unlocked
    /// (never starts one). Off in tests, so they never reach the user's agent.
    pub query_agent: bool,
}

impl Sources {
    /// This user's profile: `config.toml` with its env overrides, the
    /// credential store, the saved sessions and the key files.
    pub fn current() -> Result<Self> {
        Ok(Self {
            config: AtemConfig::load()?,
            credentials: CredentialStore::path(),
            sessions: SessionManager::sessions_path()?,
            keys: KeyPaths::default_paths(),
            query_agent: true,
        })
    }

    /// A profile directory: its `config.toml` (no env overrides), and every
    /// file in it. Never queries a key agent.
    #[cfg(test)]
    pub fn in_dir(dir: &Path) -> Self {
        let config = std::fs::read_to_string(dir.join("config.toml"))
            .ok()
            .and_then(|content| toml::from_str(&content).ok())
            .unwrap_or_default();
        Self {
            config,
            credentials: dir.join("credentials.enc"),
            sessions: dir.join("sessions.json"),
            keys: KeyPaths::in_dir(dir),
            query_agent: false,
        }
    }
}

/// The Astation this profile is paired with: the one `require_pairing`
/// resolves when it does, else the first paired one by id; `others` counts
/// the other paired Astations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pairing {
    pub astation_id: String,
    pub others: usize,
}

/// The saved sessions, read without touching the file (no permission repair).
fn saved_sessions(path: &Path) -> SessionManager {
    std::fs::read(path)
        .ok()
        .and_then(|raw| serde_json::from_slice(&raw).ok())
        .unwrap_or_default()
}

fn paired_entries(store: &CredentialStore) -> impl Iterator<Item = &CredentialEntry> {
    store
        .entries
        .iter()
        .filter(|entry| entry.source == CredentialSource::AstationPaired)
}

/// Whether this profile is paired: any paired credential entry or saved
/// (valid) Astation session.
pub fn pairing(src: &Sources) -> Option<Pairing> {
    let store = CredentialStore::load_from(&src.credentials);
    let sessions = saved_sessions(&src.sessions);
    let mut ids: BTreeSet<String> = paired_entries(&store)
        .map(|entry| {
            entry
                .astation_id
                .clone()
                .unwrap_or_else(|| "unknown".into())
        })
        .collect();
    ids.extend(
        sessions
            .active_sessions()
            .into_iter()
            .map(|s| s.astation_id.clone()),
    );
    // What `require_pairing` resolves: the configured Astation with a session.
    let resolved = src
        .config
        .astation_relay_code
        .as_deref()
        .filter(|id| sessions.get(id).is_some())
        .map(str::to_string);
    let astation_id = resolved.or_else(|| ids.iter().next().cloned())?;
    ids.insert(astation_id.clone());
    Some(Pairing {
        astation_id,
        others: ids.len() - 1,
    })
}

/// This device's verification with the paired Astation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verification {
    Verified {
        safety_code: String,
    },
    NotVerified,
    /// Revoked by this Astation (a revocation wins over any pin).
    Revoked {
        by: String,
    },
    /// `cred_state.json` can't be read.
    Unknown(String),
}

pub fn verification(keys: &KeyPaths, astation_id: &str) -> Verification {
    let trust = match TrustStore::load_from(&keys.trust) {
        Ok(trust) => trust,
        Err(error) => return Verification::Unknown(format!("{error:#}")),
    };
    if let Some(revoked) = trust.revoked() {
        return Verification::Revoked {
            by: revoked.astation_id.clone(),
        };
    }
    match trust.verified(astation_id) {
        Some(entry) => Verification::Verified {
            safety_code: entry.safety_code.clone(),
        },
        None => Verification::NotVerified,
    }
}

fn account_line(store: &CredentialStore, now: u64) -> Line {
    Line::fresh(if store.entries.is_empty() {
        "signed out"
    } else if store.entries.iter().any(|entry| entry.expires_at > now) {
        "signed in"
    } else {
        "signed in (expired)"
    })
}

fn credentials_line(keys: &KeyPaths, agent: Option<&dyn KeyAgentApi>) -> Line {
    let status = agent.map(|agent| agent.status());
    Line::fresh(match status {
        Some(Ok(status)) if status.unlocked => "unlocked",
        _ if !crate::memory::verification::has_device_keys(keys) => "not set up",
        // No running agent holds them: locked.
        None | Some(Ok(_)) => "locked",
        Some(Err(error)) => {
            return Line::fresh(format!("unknown (key agent not answering: {error:#})"));
        }
    })
}

/// The status from `src`, with `agent` the already running key agent (if any).
pub fn gather_with(src: &Sources, agent: Option<&dyn KeyAgentApi>) -> StatusReport {
    let store = CredentialStore::load_from(&src.credentials);
    let paired = pairing(src);
    let (pairing_line, verification_line) = match &paired {
        None => (Line::fresh("not paired"), Line::fresh("—")),
        Some(pairing) => {
            let more = match pairing.others {
                0 => String::new(),
                n => format!(" (+{n} more)"),
            };
            let verification = match verification(&src.keys, &pairing.astation_id) {
                Verification::Verified { safety_code } => {
                    format!("verified (safety code {safety_code})")
                }
                Verification::NotVerified => "not verified".into(),
                Verification::Revoked { by } => format!("revoked by {by}"),
                Verification::Unknown(error) => format!("unknown ({error})"),
            };
            (
                Line::fresh(format!("paired ({}){more}", pairing.astation_id)),
                Line::fresh(verification),
            )
        }
    };
    StatusReport {
        account: account_line(&store, CredentialEntry::now_secs()),
        pairing: pairing_line,
        verification: verification_line,
        credentials: credentials_line(&src.keys, agent),
        // No freshness contract yet: never "fresh" without proof.
        authorization: Line::stale("unknown"),
        // Status never connects.
        relay: Line::stale("unknown"),
        // No shared runtime to ask yet.
        local_agents: Line::fresh("unknown"),
    }
}

/// The status from `src`, asking an already running key agent when
/// `src.query_agent` (blocking: socket I/O).
pub fn gather(src: &Sources) -> StatusReport {
    let agent = if src.query_agent {
        crate::memory::key_agent::running_agent()
    } else {
        None
    };
    gather_with(src, agent.as_deref())
}

/// The aligned block `atem status` prints.
pub fn render(report: &StatusReport) -> String {
    let rows = [
        ("Account:", &report.account),
        ("Pairing:", &report.pairing),
        ("Verification:", &report.verification),
        ("Credentials:", &report.credentials),
        ("Authorization:", &report.authorization),
        ("Relay:", &report.relay),
        ("Local agents:", &report.local_agents),
    ];
    let mut out = String::new();
    for (label, line) in rows {
        let stale = if line.stale { " (stale)" } else { "" };
        out.push_str(&format!("{label:<16}{}{stale}\n", line.value));
    }
    out
}

/// `atem status` / `atem cred status` (blocking: may ask a running agent).
pub fn text(src: &Sources) -> String {
    render(&gather(src))
}

/// `atem pair`: when the profile is already paired, what to print instead
/// of pairing (the status, then `ALREADY_PAIRED`).
pub fn already_paired(src: &Sources) -> Option<String> {
    pairing(src)?;
    Some(format!("{}{ALREADY_PAIRED}\n", text(src)))
}

/// What `atem pair verify` does before connecting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyStart {
    /// Nothing to do: print this.
    AlreadyVerified(String),
    /// Run the verification with this Astation.
    Verify(String),
}

/// `atem pair verify`'s offline checks: an existing pairing, not revoked,
/// not already verified with the paired Astation.
pub fn verify_start(src: &Sources) -> Result<VerifyStart> {
    let pairing = pairing(src).ok_or_else(|| anyhow!(NOT_PAIRED))?;
    match verification(&src.keys, &pairing.astation_id) {
        Verification::Verified { safety_code } => Ok(VerifyStart::AlreadyVerified(
            already_verified_message(&safety_code),
        )),
        Verification::Revoked { by } => Err(anyhow!(revoked_message(&by))),
        Verification::Unknown(error) => Err(anyhow!(error)),
        Verification::NotVerified => Ok(VerifyStart::Verify(pairing.astation_id)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthSession;
    use crate::memory::key_agent::{Reply, Request};
    use crate::memory::trust::AstationTrust;

    const ASTATION: &str = "astation-1";

    struct UnlockedAgent;

    impl KeyAgentApi for UnlockedAgent {
        fn call(&self, request: Request) -> Result<Reply> {
            match request {
                Request::Status => Ok(Reply::Status {
                    unlocked: true,
                    storage_kid: Some("0a1b2c3d".into()),
                    escrowed: true,
                    build: None,
                }),
                _ => Err(anyhow!("not in this test")),
            }
        }
    }

    struct LockedAgent;

    impl KeyAgentApi for LockedAgent {
        fn call(&self, request: Request) -> Result<Reply> {
            match request {
                Request::Status => Ok(Reply::Status {
                    unlocked: false,
                    storage_kid: None,
                    escrowed: false,
                    build: None,
                }),
                _ => Err(anyhow!("not in this test")),
            }
        }
    }

    fn pin(code: &str) -> AstationTrust {
        AstationTrust {
            device_id: "device".into(),
            data_account: "account".into(),
            sign_gen: 1,
            astation_sign_pub: "s".into(),
            astation_enc_pub: "e".into(),
            recovery_sign_pub: "r".into(),
            device_pub: "d".into(),
            device_sign_pub: "ds".into(),
            unlock_auth_pub: "u".into(),
            safety_code: code.into(),
            transcript: String::new(),
            epoch_floor: 0,
            account_state: None,
            account_epoch: 0,
        }
    }

    /// Writes `cred_state.json`: verified with `verified` (if any), revoked
    /// by `revoked` (if any).
    fn write_trust(dir: &Path, verified: Option<&str>, revoked: Option<&str>) {
        let mut astations = serde_json::Map::new();
        if let Some(id) = verified {
            astations.insert(
                id.into(),
                serde_json::to_value(pin("MN3H-A74N-FJE4")).unwrap(),
            );
        }
        let mut store = serde_json::json!({
            "version": 1,
            "home_astation": verified,
            "astations": astations,
        });
        if let Some(id) = revoked {
            store["revoked"] = serde_json::json!({"astation_id": id, "at": 1_700_000_000u64});
        }
        std::fs::write(dir.join("cred_state.json"), store.to_string()).unwrap();
    }

    fn write_paired(dir: &Path, astation_id: &str, expires_at: u64) {
        let mut store = CredentialStore::load_from(&dir.join("credentials.enc"));
        store.upsert(CredentialEntry::new_paired(
            "access".into(),
            "refresh".into(),
            expires_at,
            Some("me".into()),
            astation_id.into(),
            true,
            1,
        ));
        store.save_to(&dir.join("credentials.enc")).unwrap();
    }

    fn write_session(dir: &Path, astation_id: &str) {
        let path = dir.join("sessions.json");
        let mut sessions = saved_sessions(&path);
        sessions.insert_session(AuthSession::new(
            format!("session-{astation_id}"),
            "token".into(),
            astation_id.into(),
            "host".into(),
        ));
        sessions.save_to(&path).unwrap();
    }

    fn write_device_keys(dir: &Path) {
        std::fs::write(dir.join("device_keys.sealed"), b"{}").unwrap();
    }

    fn later() -> u64 {
        CredentialEntry::now_secs() + 3600
    }

    fn report(dir: &Path) -> StatusReport {
        gather_with(&Sources::in_dir(dir), None)
    }

    #[test]
    fn render_aligns_every_label_and_marks_stale_lines() {
        let report = StatusReport {
            account: Line::fresh("signed in"),
            pairing: Line::fresh("paired (astation-1)"),
            verification: Line::fresh("verified (safety code MN3H-A74N-FJE4)"),
            credentials: Line::fresh("locked"),
            authorization: Line::stale("unknown"),
            relay: Line::stale("unknown"),
            local_agents: Line::fresh("unknown"),
        };
        assert_eq!(
            render(&report),
            "Account:        signed in\n\
             Pairing:        paired (astation-1)\n\
             Verification:   verified (safety code MN3H-A74N-FJE4)\n\
             Credentials:    locked\n\
             Authorization:  unknown (stale)\n\
             Relay:          unknown (stale)\n\
             Local agents:   unknown\n"
        );
    }

    #[test]
    fn an_empty_profile_is_signed_out_unpaired_and_not_set_up() {
        let dir = tempfile::tempdir().unwrap();
        let report = report(dir.path());
        assert_eq!(report.account.value, "signed out");
        assert_eq!(report.pairing.value, "not paired");
        assert_eq!(report.verification.value, "—");
        assert_eq!(report.credentials.value, "not set up");
        assert_eq!(report.authorization, Line::stale("unknown"));
        assert_eq!(report.relay, Line::stale("unknown"));
        assert_eq!(report.local_agents, Line::fresh("unknown"));
        assert_eq!(pairing(&Sources::in_dir(dir.path())), None);
    }

    #[test]
    fn paired_but_unverified() {
        let dir = tempfile::tempdir().unwrap();
        write_paired(dir.path(), ASTATION, later());
        let report = report(dir.path());
        assert_eq!(report.account.value, "signed in");
        assert_eq!(report.pairing.value, "paired (astation-1)");
        assert_eq!(report.verification.value, "not verified");
        assert_eq!(report.credentials.value, "not set up");
    }

    #[test]
    fn paired_and_verified_shows_the_safety_code_and_lock_state() {
        let dir = tempfile::tempdir().unwrap();
        write_paired(dir.path(), ASTATION, later());
        write_trust(dir.path(), Some(ASTATION), None);
        write_device_keys(dir.path());
        let src = Sources::in_dir(dir.path());
        let report = gather_with(&src, None);
        assert_eq!(
            report.verification.value,
            "verified (safety code MN3H-A74N-FJE4)"
        );
        // No running agent holds the keys.
        assert_eq!(report.credentials.value, "locked");
        assert_eq!(
            gather_with(&src, Some(&LockedAgent)).credentials.value,
            "locked"
        );
        assert_eq!(
            gather_with(&src, Some(&UnlockedAgent)).credentials.value,
            "unlocked"
        );
    }

    #[test]
    fn revoked_is_shown_with_the_revoking_astation() {
        let dir = tempfile::tempdir().unwrap();
        write_paired(dir.path(), ASTATION, later());
        write_trust(dir.path(), Some(ASTATION), Some(ASTATION));
        assert_eq!(
            report(dir.path()).verification.value,
            "revoked by astation-1"
        );
    }

    #[test]
    fn expired_credentials_still_count_as_signed_in() {
        let dir = tempfile::tempdir().unwrap();
        write_paired(dir.path(), ASTATION, 1);
        assert_eq!(report(dir.path()).account.value, "signed in (expired)");
    }

    #[test]
    fn a_saved_session_alone_is_a_pairing_and_the_configured_one_wins() {
        let dir = tempfile::tempdir().unwrap();
        write_session(dir.path(), "astation-0");
        let src = Sources::in_dir(dir.path());
        assert_eq!(
            pairing(&src),
            Some(Pairing {
                astation_id: "astation-0".into(),
                others: 0
            })
        );
        write_paired(dir.path(), "astation-2", later());
        write_session(dir.path(), "astation-2");
        std::fs::write(
            dir.path().join("config.toml"),
            "astation_relay_code = \"astation-2\"\n",
        )
        .unwrap();
        let src = Sources::in_dir(dir.path());
        assert_eq!(
            pairing(&src),
            Some(Pairing {
                astation_id: "astation-2".into(),
                others: 1
            })
        );
        assert_eq!(
            report(dir.path()).pairing.value,
            "paired (astation-2) (+1 more)"
        );
    }

    #[test]
    fn gathering_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        write_paired(dir.path(), ASTATION, later());
        write_session(dir.path(), ASTATION);
        write_trust(dir.path(), Some(ASTATION), None);
        let before = snapshot(dir.path());
        let _ = text(&Sources::in_dir(dir.path()));
        assert_eq!(snapshot(dir.path()), before);
    }

    #[test]
    fn already_paired_prints_the_status_and_the_next_steps() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(already_paired(&Sources::in_dir(dir.path())), None);
        write_paired(dir.path(), ASTATION, later());
        let src = Sources::in_dir(dir.path());
        assert_eq!(
            already_paired(&src).unwrap(),
            format!("{}{ALREADY_PAIRED}\n", text(&src))
        );
    }

    #[test]
    fn pair_verify_needs_a_pairing() {
        let dir = tempfile::tempdir().unwrap();
        let error = verify_start(&Sources::in_dir(dir.path())).unwrap_err();
        assert_eq!(error.to_string(), "Not paired. Run atem pair first.");
    }

    #[test]
    fn pair_verify_does_nothing_when_already_verified() {
        let dir = tempfile::tempdir().unwrap();
        write_paired(dir.path(), ASTATION, later());
        write_trust(dir.path(), Some(ASTATION), None);
        assert_eq!(
            verify_start(&Sources::in_dir(dir.path())).unwrap(),
            VerifyStart::AlreadyVerified("Already verified (safety code MN3H-A74N-FJE4).".into())
        );
    }

    #[test]
    fn pair_verify_refuses_a_revoked_device() {
        let dir = tempfile::tempdir().unwrap();
        write_paired(dir.path(), ASTATION, later());
        write_trust(dir.path(), Some(ASTATION), Some(ASTATION));
        let error = verify_start(&Sources::in_dir(dir.path())).unwrap_err();
        assert_eq!(
            error.to_string(),
            "This device was revoked by Astation astation-1. Run atem unpair, then atem pair, to set it up again."
        );
    }

    #[test]
    fn pair_verify_verifies_the_paired_astation() {
        let dir = tempfile::tempdir().unwrap();
        write_paired(dir.path(), ASTATION, later());
        // Verified with another Astation only.
        write_trust(dir.path(), Some("astation-9"), None);
        assert_eq!(
            verify_start(&Sources::in_dir(dir.path())).unwrap(),
            VerifyStart::Verify(ASTATION.into())
        );
    }

    /// Every file under `dir` with its contents (to prove nothing changed).
    pub(crate) fn snapshot(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
        let mut files = Vec::new();
        let mut pending = vec![dir.to_path_buf()];
        while let Some(next) = pending.pop() {
            for entry in std::fs::read_dir(&next).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    pending.push(path);
                } else {
                    let contents = std::fs::read(&path).unwrap();
                    files.push((path, contents));
                }
            }
        }
        files.sort();
        files
    }
}
