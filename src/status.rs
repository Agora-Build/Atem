//! `atem status`: one read-only report of the account, the pairing, this
//! device's verification and its credentials, and — from an `atem runtime`
//! that is already running, asked as a passive client within 500 ms — the
//! Astation link, its session authorization and the local agents. It never
//! connects to the network, never starts the cred agent or the runtime (it
//! asks only ones already running) and never writes a file.
//!
//! The same facts decide `atem pair` (a no-op once paired), `atem pair
//! verify` (only for an existing pairing, never after a revocation) and the
//! `atem cred unlock` gate.
use anyhow::{Result, anyhow};
#[cfg(test)]
use std::path::Path;

use crate::memory::cred_agent::AgentStatus;
#[cfg(test)]
use crate::memory::cred_agent::CredAgentApi;
use crate::memory::trust::TrustStore;
use crate::paths::CredPaths;
use crate::profile::Sources;
use crate::records::Login;
use crate::records::PairingRecord;
use crate::runtime::client::Look;

/// `atem pair` on a profile that is already paired (after the status).
pub const ALREADY_PAIRED: &str = "Already paired. Verify this device: atem pair verify · Replace the pairing: atem unpair, then atem pair";
/// `atem pair verify` without a pairing.
pub const NOT_PAIRED: &str = "Not paired. Run atem pair first.";
/// `atem cred unlock` on a device no Astation verified.
pub const UNVERIFIED_UNLOCK: &str = "This device isn't verified. Run atem pair verify first.";
/// What to do when a paired profile can't authenticate: `atem pair` alone
/// would only print the status.
pub const SESSION_GONE: &str =
    "The saved Astation session expired or was refused. Run `atem unpair`, then `atem pair`.";
/// Credentials note: the running cred agent was started by another build.
const OLDER_BUILD_NOTE: &str =
    " (started by another atem build; run atem cred lock, then atem cred unlock)";
/// The same when Atem's runtime (which starts the agent for an unlock) is
/// another build too.
const OLDER_RUNTIME_NOTE: &str = " (started by another atem build, and Atem's runtime is another build too; run atem runtime restart, then atem cred lock and atem cred unlock)";
/// Authorization, relay and local agents without a running runtime.
pub const NO_RUNTIME: &str = "no runtime running";

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

/// One status value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    pub value: String,
}

impl Line {
    fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
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
    /// Printed after the block (e.g. the reset steps for broken key files).
    pub notes: Vec<String>,
}

/// The Astation this profile is paired with; `session_expired` when its
/// saved session expired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pairing {
    pub astation_id: String,
    pub session_expired: bool,
    /// Astation's transport policy (`transportPolicy`): relay only.
    pub relay_only: bool,
}

/// The pairing, if this profile has one (an unreadable record reads as
/// none here; `atem status` shows why).
pub fn pairing(src: &Sources) -> Option<Pairing> {
    let record = PairingRecord::load(&src.paths.pairing).ok()??;
    Some(Pairing {
        session_expired: record.session_expired(),
        relay_only: record.relay_only,
        astation_id: record.astation_id,
    })
}

/// Whether the pairing with `astation_id` has its current binding: only
/// `atem pair` finishes one. A record without one (a pairing that never
/// finished, an `atem unpair` interrupted after its commit) is not a pairing:
/// `atem pair` replaces it.
fn bound(src: &Sources, astation_id: &str) -> bool {
    crate::pairing::load(src)
        .ok()
        .and_then(|state| state.binding)
        .is_some_and(|binding| binding.astation_id == astation_id)
}

/// Whether this profile holds a pairing record `atem unpair` removes.
pub fn profile_paired(src: &Sources) -> bool {
    src.paths.pairing.record.exists()
}

/// `profile_paired` for this user's profile (production entry points only;
/// everything below them takes `paired` or a `Sources`).
pub fn current_profile_paired() -> bool {
    Sources::current().is_ok_and(|src| profile_paired(&src))
}

/// The advice for a profile that can't authenticate: `SESSION_GONE` when
/// it is paired (`atem pair` would only print the status), else `fallback`.
pub fn pairing_advice(paired: bool, fallback: &str) -> String {
    if paired {
        SESSION_GONE.to_string()
    } else {
        fallback.to_string()
    }
}

/// This device's verification with the paired Astation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verification {
    Verified {
        safety_code: String,
    },
    NotVerified,
    /// Revoked by this Astation (its revocation wins over its pin).
    Revoked {
        by: String,
    },
    /// `cred/state.json` can't be read.
    Unknown(String),
}

pub fn verification(keys: &CredPaths, astation_id: &str) -> Verification {
    let trust = match TrustStore::load_from(&keys.trust) {
        Ok(trust) => trust,
        Err(error) => return Verification::Unknown(format!("{error:#}")),
    };
    if let Some(revoked) = trust
        .revoked()
        .filter(|revoked| revoked.astation_id == astation_id)
    {
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

/// The Account line: the user's own login, else the login Astation shares.
fn account_line(src: &Sources, now: u64) -> Line {
    let expired = |login: &Login| {
        if login.tokens.expires_at > now {
            ""
        } else {
            " (expired)"
        }
    };
    match Login::load(&src.paths.login) {
        Ok(Some(login)) => return Line::new(format!("signed in{}", expired(&login))),
        Ok(None) => {}
        Err(error) => return Line::new(format!("unknown ({error:#})")),
    }
    let shared = PairingRecord::load(&src.paths.pairing)
        .ok()
        .flatten()
        .and_then(|record| record.shared);
    Line::new(match shared {
        Some(login) => format!("signed in through Astation{}", expired(&login)),
        None => "signed out".into(),
    })
}

/// The credentials line, and the notes printed after the block;
/// `runtime_differs`: Atem's runtime is another build than this atem.
fn credentials_line(
    keys: &CredPaths,
    agent: Option<&Result<AgentStatus, String>>,
    runtime_differs: bool,
) -> (Line, Vec<String>) {
    let status = match agent {
        None => None,
        Some(Ok(status)) => Some(status),
        Some(Err(error)) => {
            let line = format!("unknown (cred agent not answering: {error})");
            return (Line::new(line), Vec::new());
        }
    };
    let older = match status.as_ref().is_some_and(|status| status.older_build) {
        true if runtime_differs => OLDER_RUNTIME_NOTE,
        true => OLDER_BUILD_NOTE,
        false => "",
    };
    let value = match &status {
        Some(status) if status.unlocked && !status.escrowed => {
            "unlocked (storage key not yet held by Astation; run atem cred unlock)"
        }
        Some(status) if status.unlocked => "unlocked",
        _ => {
            let problem = TrustStore::load_from(&keys.trust)
                .ok()
                .and_then(|trust| crate::memory::unlock::key_file_problem(keys, &trust));
            if let Some(problem) = problem {
                let line = format!("broken ({problem}){older}");
                let reset = crate::memory::cred_agent::RESET.to_string();
                return (Line::new(line), vec![reset]);
            }
            if crate::memory::verification::has_device_keys(keys) {
                // No running agent holds them unlocked: locked.
                "locked"
            } else {
                "not set up"
            }
        }
    };
    (Line::new(format!("{value}{older}")), Vec::new())
}

/// The pairing and verification lines.
fn pairing_lines(src: &Sources, pairing: Option<&Pairing>) -> (Line, Line) {
    let Some(pairing) = pairing else {
        if let Err(error) = PairingRecord::load(&src.paths.pairing) {
            return (Line::new(format!("unknown ({error:#})")), Line::new("—"));
        }
        return (Line::new("not paired"), Line::new("—"));
    };
    let astation_id = &pairing.astation_id;
    let expired = if pairing.session_expired {
        ", session expired"
    } else {
        ""
    };
    if let Ok(state) = crate::pairing::load(src)
        && state.binding.is_none()
    {
        return (
            Line::new(format!(
                "not paired (unfinished pairing with {astation_id}; run `atem pair`)"
            )),
            Line::new("—"),
        );
    }
    let trust = trust_note(src, astation_id);
    let verification = match verification(&src.paths.cred, astation_id) {
        Verification::Verified { safety_code } => format!("verified (safety code {safety_code})"),
        Verification::NotVerified => "not verified".into(),
        Verification::Revoked { by } => format!("revoked by {by}"),
        Verification::Unknown(error) => format!("unknown ({error})"),
    };
    let relay_only = if pairing.relay_only {
        "; relay only (set by Astation)"
    } else {
        ""
    };
    (
        Line::new(format!(
            "paired ({astation_id}{trust}{expired}){relay_only}"
        )),
        Line::new(verification),
    )
}

/// The Pairing line's trust generation: `, trust gen N` for the binding with
/// `astation_id`. Read-only.
fn trust_note(src: &Sources, astation_id: &str) -> String {
    match crate::pairing::load(src) {
        Ok(state) => match state.binding {
            Some(binding) if binding.astation_id == astation_id => {
                format!(", trust gen {}", binding.host_trust_gen)
            }
            Some(binding) => format!(
                ", trust gen {} is with {}; run `atem unpair`, then `atem pair`",
                binding.host_trust_gen, binding.astation_id
            ),
            // `pairing_lines` shows a pairing without a binding as not paired.
            None => ", no pairing binding; run `atem pair`".into(),
        },
        Err(error) => format!(", trust gen unknown: {error:#}"),
    }
}

/// After the block while relay only is set and Astation isn't connected.
pub const RELAY_ONLY_NOTE: &str = "Astation's Station AI disabled the local connection: Atem reaches Astation only through the relay. It clears when Astation turns it off, or with `atem unpair`.";

/// The status from `src`, with `agent` the already running cred agent (if
/// any) and no runtime running.
#[cfg(test)]
pub fn gather_with(src: &Sources, agent: Option<&dyn CredAgentApi>) -> StatusReport {
    let agent = agent.map(|agent| agent.status().map_err(|error| format!("{error:#}")));
    gather_full(src, agent.as_ref(), &Look::NotRunning)
}

/// The status from `src`, with what the running cred agent answered (if
/// one runs) and what a passive look at the runtime found.
pub fn gather_full(
    src: &Sources,
    agent: Option<&Result<AgentStatus, String>>,
    runtime: &Look,
) -> StatusReport {
    let paired = pairing(src);
    let (pairing_line, verification_line) = pairing_lines(src, paired.as_ref());
    let runtime_differs = matches!(runtime, Look::Running { welcome, .. }
        if welcome.build != crate::memory::cred_agent::build_id());
    let (credentials, mut notes) = credentials_line(&src.paths.cred, agent, runtime_differs);
    let (authorization, relay, local_agents) = runtime_lines(runtime, local_hhmm);
    let connected =
        matches!(runtime, Look::Running { status: Some(status), .. } if status.astation);
    if paired.as_ref().is_some_and(|p| p.relay_only) && !connected {
        notes.push(RELAY_ONLY_NOTE.into());
    }
    StatusReport {
        account: account_line(src, crate::credentials::now_secs()),
        pairing: pairing_line,
        verification: verification_line,
        credentials,
        authorization,
        relay,
        local_agents,
        notes,
    }
}

/// The status from `src`, asking an already running cred agent when
/// `src.query_agent` and an already running runtime when `src.runtime`
/// (blocking: socket I/O).
pub fn gather(src: &Sources) -> StatusReport {
    let agent = if src.query_agent {
        crate::memory::cred_agent::look(&src.paths.cred, crate::runtime::client::LOOK_TIMEOUT)
            .map(|found| found.map(|(status, _pid)| status))
    } else {
        None
    };
    let runtime = match &src.runtime {
        Some(locator) => {
            crate::runtime::client::look(locator, crate::runtime::client::LOOK_TIMEOUT)
        }
        None => Look::NotRunning,
    };
    gather_full(src, agent.as_ref(), &runtime)
}

/// `HH:MM` of the Unix ms `at` in the local time zone.
fn local_hhmm(at: u64) -> String {
    let t = (at / 1000) as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::localtime_r(&t, &mut tm) }.is_null() {
        return "?".into();
    }
    format!("{:02}:{:02}", tm.tm_hour, tm.tm_min)
}

/// What is left of an authorization: `23 h left`, `5 min left`.
fn time_left(ms: u64) -> String {
    let minutes = ms / 60_000;
    if minutes >= 60 {
        format!("{} h left", minutes / 60)
    } else {
        format!("{minutes} min left")
    }
}

/// The Authorization, Relay and Local agents lines from a passive look at
/// the runtime (`hhmm` formats a Unix ms time of day).
pub fn runtime_lines(look: &Look, hhmm: impl Fn(u64) -> String) -> (Line, Line, Line) {
    use crate::runtime::protocol::Transport;
    let status = match look {
        Look::NotRunning => {
            return (
                Line::new(NO_RUNTIME),
                Line::new(NO_RUNTIME),
                Line::new(NO_RUNTIME),
            );
        }
        Look::Unreachable(error) => {
            let line = format!("unknown (the runtime didn't answer: {error})");
            return (
                Line::new(line.clone()),
                Line::new(line.clone()),
                Line::new(line),
            );
        }
        Look::Running {
            status: None,
            welcome,
        } => {
            let line = format!(
                "unknown (Atem's runtime is build {}, which doesn't report it; run atem runtime restart)",
                welcome.build
            );
            return (
                Line::new(line.clone()),
                Line::new(line.clone()),
                Line::new(line),
            );
        }
        Look::Running {
            status: Some(status),
            ..
        } => status,
    };
    let authorization = if let Some(error) = &status.host_error {
        format!("unavailable ({error})")
    } else if status.journal_halted {
        "paused (journal halted; run atem runtime restart)".into()
    } else if status.reauthenticating {
        "not authorized (Astation is authenticating the link again)".into()
    } else if !status.astation {
        "not authorized (Astation not connected)".into()
    } else if !status.attachment {
        "not authorized (the Astation link isn't a verified pairing; run atem pair verify)".into()
    } else if let Some(welcomed) = &status.welcomed {
        format!(
            "authorized (r{}, since {}, {})",
            welcomed.revision,
            hhmm(welcomed.at_ms),
            time_left(welcomed.ms_left)
        )
    } else if let Some(refused) = &status.refused {
        match refused.revision {
            Some(revision) => format!(
                "refused (Astation sent revision {revision}; needs r{})",
                refused.needs
            ),
            None => format!(
                "refused (Astation sent no revision; needs r{})",
                refused.needs
            ),
        }
    } else {
        "not authorized (Astation connected but no session hello yet)".into()
    };
    let relay = match (status.astation || status.reauthenticating, status.transport) {
        (true, Some(Transport::Relay)) => match &status.relay {
            Some(label) => format!("connected via relay ({label})"),
            None => "connected via relay".into(),
        },
        (true, Some(Transport::Local)) => "connected locally".into(),
        (true, None) => "connected".into(),
        (false, _) if status.retrying => "not connected (retrying)".into(),
        (false, _) => "not connected".into(),
    };
    (
        Line::new(authorization),
        Line::new(relay),
        Line::new(local_agents(&status.sessions, status.adopting)),
    )
}

/// `2 running (claude ready, codex working)`, `none`, `1 running (…); 1 exited`.
fn local_agents(sessions: &[crate::runtime::protocol::SessionSummary], adopting: bool) -> String {
    let running: Vec<String> = sessions
        .iter()
        .filter(|s| s.state == "running")
        .map(|s| format!("{} {}", s.provider, s.status))
        .collect();
    let mut others: std::collections::BTreeMap<&str, usize> = Default::default();
    for s in sessions.iter().filter(|s| s.state != "running") {
        *others.entry(s.state.as_str()).or_default() += 1;
    }
    let mut text = if running.is_empty() {
        "none running".to_string()
    } else {
        format!("{} running ({})", running.len(), running.join(", "))
    };
    for (state, n) in others {
        text.push_str(&format!("; {n} {}", state.replace('_', " ")));
    }
    if adopting {
        text.push_str(" (still adopting sessions)");
    }
    text
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
        out.push_str(&format!("{label:<16}{}\n", line.value));
    }
    for note in &report.notes {
        out.push_str(note);
        out.push('\n');
    }
    out
}

/// `atem status` (blocking: may ask a running agent).
pub fn text(src: &Sources) -> String {
    render(&gather(src))
}

/// `atem pair`: when the profile is already paired, what to print instead
/// of pairing (the status, then `ALREADY_PAIRED`).
pub fn already_paired(src: &Sources) -> Option<String> {
    let pairing = pairing(src)?;
    if !bound(src, &pairing.astation_id) {
        return None;
    }
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
    let pairing = pairing(src)
        .filter(|pairing| bound(src, &pairing.astation_id))
        .ok_or_else(|| anyhow!(NOT_PAIRED))?;
    let astation_id = pairing.astation_id;
    match verification(&src.paths.cred, &astation_id) {
        Verification::Verified { safety_code } => Ok(VerifyStart::AlreadyVerified(
            already_verified_message(&safety_code),
        )),
        Verification::Revoked { by } => Err(anyhow!(revoked_message(&by))),
        Verification::Unknown(error) => Err(anyhow!(error)),
        Verification::NotVerified => Ok(VerifyStart::Verify(astation_id)),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::memory::cred_agent::{Reply, Request};
    use crate::memory::trust::AstationTrust;
    use crate::paths::ProfilePaths;
    use std::path::PathBuf;

    const ASTATION: &str = "astation-1";

    /// A running cred agent that answers `Status` as told.
    struct StubAgent {
        unlocked: bool,
        escrowed: bool,
        build: String,
    }

    impl StubAgent {
        fn new(unlocked: bool) -> Self {
            Self {
                unlocked,
                escrowed: true,
                build: crate::memory::cred_agent::build_id().to_string(),
            }
        }
    }

    impl CredAgentApi for StubAgent {
        fn call(&self, request: Request) -> Result<Reply> {
            match request {
                Request::Status => Ok(Reply::Status {
                    unlocked: self.unlocked,
                    storage_kid: Some("0a1b2c3d".into()),
                    escrowed: self.escrowed,
                    build: self.build.clone(),
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

    /// Writes `cred/state.json`: verified with `verified` (if any), revoked
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
        crate::paths::write_test_file(
            &crate::paths::CredPaths::in_dir(dir).trust,
            store.to_string(),
        );
    }

    /// Paired and bound with `astation_id` (generation 1); the login it
    /// shares expires at `expires_at`.
    fn write_paired(dir: &Path, astation_id: &str, expires_at: u64) {
        crate::pairing::tests::bound_profile(dir, astation_id);
        crate::pairing::tests::edit(dir, |record| {
            record.shared.as_mut().unwrap().tokens.expires_at = expires_at;
        });
    }

    /// A plain `device_keys` file: keys on disk that `key_file_problem`
    /// accepts (the agent seals it when it starts).
    fn write_device_keys(dir: &Path) {
        crate::paths::write_test_file(&crate::paths::CredPaths::in_dir(dir).device_keys, b"{}");
    }

    fn later() -> u64 {
        crate::credentials::now_secs() + 3600
    }

    fn report(dir: &Path) -> StatusReport {
        gather_with(&Sources::in_dir(dir), None)
    }

    #[test]
    fn render_aligns_every_label() {
        let report = StatusReport {
            account: Line::new("signed in"),
            pairing: Line::new("paired (astation-1)"),
            verification: Line::new("verified (safety code MN3H-A74N-FJE4)"),
            credentials: Line::new("locked"),
            authorization: Line::new("authorized (r8, since 18:25, 23 h left)"),
            relay: Line::new("connected locally"),
            local_agents: Line::new("2 running (claude ready, codex ready)"),
            notes: Vec::new(),
        };
        assert_eq!(
            render(&report),
            "Account:        signed in\n\
             Pairing:        paired (astation-1)\n\
             Verification:   verified (safety code MN3H-A74N-FJE4)\n\
             Credentials:    locked\n\
             Authorization:  authorized (r8, since 18:25, 23 h left)\n\
             Relay:          connected locally\n\
             Local agents:   2 running (claude ready, codex ready)\n"
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
        // No runtime runs.
        assert_eq!(report.authorization, Line::new(NO_RUNTIME));
        assert_eq!(report.relay, Line::new(NO_RUNTIME));
        assert_eq!(report.local_agents, Line::new(NO_RUNTIME));
        assert_eq!(pairing(&Sources::in_dir(dir.path())), None);
    }

    #[test]
    fn paired_but_unverified() {
        let dir = tempfile::tempdir().unwrap();
        write_paired(dir.path(), ASTATION, later());
        let report = report(dir.path());
        assert_eq!(report.account.value, "signed in through Astation");
        assert_eq!(report.pairing.value, "paired (astation-1, trust gen 1)");
        assert_eq!(report.verification.value, "not verified");
        assert_eq!(report.credentials.value, "not set up");
    }

    #[test]
    fn relay_only_set_by_astation_is_shown_on_the_pairing_line() {
        let dir = tempfile::tempdir().unwrap();
        write_paired(dir.path(), ASTATION, later());
        crate::pairing::tests::edit(dir.path(), |record| record.relay_only = true);
        let report = report(dir.path());
        assert_eq!(
            report.pairing.value,
            "paired (astation-1, trust gen 1); relay only (set by Astation)"
        );
        // No runtime, so Astation isn't connected: the hint says why.
        assert!(report.notes.iter().any(|note| note == RELAY_ONLY_NOTE));
        // Connected (through the relay): no hint.
        let src = Sources::in_dir(dir.path());
        let online = gather_full(&src, None, &running(connected(Transport::Relay)));
        assert!(!online.notes.iter().any(|note| note == RELAY_ONLY_NOTE));
        let offline = gather_full(&src, None, &running(RuntimeStatus::default()));
        assert!(offline.notes.iter().any(|note| note == RELAY_ONLY_NOTE));
        // Astation turned it off: no hint.
        crate::pairing::tests::edit(dir.path(), |record| record.relay_only = false);
        let report = super::tests::report(dir.path());
        assert!(!report.notes.iter().any(|note| note == RELAY_ONLY_NOTE));
        assert_eq!(report.pairing.value, "paired (astation-1, trust gen 1)");
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
            gather_with(&src, Some(&StubAgent::new(false)))
                .credentials
                .value,
            "locked"
        );
        assert_eq!(
            gather_with(&src, Some(&StubAgent::new(true)))
                .credentials
                .value,
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
        assert_eq!(
            report(dir.path()).account.value,
            "signed in through Astation (expired)"
        );
        // The user's own login comes first.
        let login = Login::from_sso(
            "https://sso2.agora.io",
            Some("me".into()),
            crate::records::Tokens {
                access_token: "a".into(),
                refresh_token: "r".into(),
                expires_at: later(),
            },
        );
        login.save(&ProfilePaths::in_dir(dir.path()).login).unwrap();
        assert_eq!(report(dir.path()).account.value, "signed in");
    }

    #[test]
    fn a_pairing_in_progress_is_a_pairing_without_a_binding() {
        let dir = tempfile::tempdir().unwrap();
        crate::pairing::tests::set_session(dir.path(), "astation-0", "s", "t");
        let src = Sources::in_dir(dir.path());
        assert_eq!(
            pairing(&src),
            Some(Pairing {
                astation_id: "astation-0".into(),
                session_expired: false,
                relay_only: false,
            })
        );
        // Not a pairing: `atem pair` proceeds and replaces it.
        let report = report(dir.path());
        assert_eq!(
            report.pairing.value,
            "not paired (unfinished pairing with astation-0; run `atem pair`)"
        );
        assert_eq!(report.verification.value, "—");
        assert_eq!(already_paired(&src), None);
        assert_eq!(verify_start(&src).unwrap_err().to_string(), NOT_PAIRED);
    }

    #[test]
    fn an_unreadable_pairing_is_shown_as_unknown() {
        let dir = tempfile::tempdir().unwrap();
        let paths = ProfilePaths::in_dir(dir.path());
        crate::paths::write_test_file(&paths.pairing.record, b"another machine's");
        let pairing = report(dir.path()).pairing.value;
        assert!(pairing.starts_with("unknown ("), "{pairing}");
        assert!(
            profile_paired(&Sources::in_dir(dir.path())),
            "unpair removes it"
        );
    }

    #[test]
    fn gathering_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        write_paired(dir.path(), ASTATION, later());
        write_trust(dir.path(), Some(ASTATION), None);
        let before = snapshot(dir.path());
        let text = text(&Sources::in_dir(dir.path()));
        assert_eq!(snapshot(dir.path()), before);
        assert!(text.contains("paired (astation-1, trust gen 1)"), "{text}");
    }

    #[test]
    fn the_pairing_line_shows_the_trust_generation() {
        let dir = tempfile::tempdir().unwrap();
        let src = Sources::in_dir(dir.path());
        // Paired, unpaired, paired again: generation 3.
        let before = crate::pairing::capture(&src).unwrap();
        crate::pairing::bind_new(&src, &before, ASTATION).unwrap();
        crate::pairing::unpair(&src).unwrap();
        let before = crate::pairing::capture(&src).unwrap();
        crate::pairing::bind_new(&src, &before, ASTATION).unwrap();
        assert_eq!(
            report(dir.path()).pairing.value,
            "paired (astation-1, trust gen 3)"
        );
        // An unpair interrupted after its commit: the old binding is gone.
        crate::pairing::tests::interrupted_unpair(dir.path());
        assert_eq!(
            report(dir.path()).pairing.value,
            "not paired (unfinished pairing with astation-1; run `atem pair`)"
        );
        assert_eq!(already_paired(&src), None);
    }

    #[test]
    fn a_binding_below_the_legacy_generation_is_an_unfinished_pairing() {
        let dir = tempfile::tempdir().unwrap();
        let src = Sources::in_dir(dir.path());
        // Upgraded across the move to `pairing/`: the legacy file says 6, the
        // new files restarted and were paired again at 3.
        std::fs::write(
            &src.paths.legacy_pairing,
            br#"{"version":1,"host_trust_gen":6,"binding_id":"b","astation_id":"astation-1","created_at":1}"#,
        )
        .unwrap();
        crate::pairing::tests::write_bound(dir.path(), ASTATION, 3, "binding-3", ("s", "t"));
        let before = snapshot(dir.path());
        assert_eq!(
            report(dir.path()).pairing.value,
            "not paired (unfinished pairing with astation-1; run `atem pair`)"
        );
        assert_eq!(snapshot(dir.path()), before, "status writes nothing");
        assert_eq!(already_paired(&src), None, "`atem pair` proceeds");
        let before = crate::pairing::capture(&src).unwrap();
        crate::pairing::bind_new(&src, &before, ASTATION).unwrap();
        assert_eq!(
            report(dir.path()).pairing.value,
            "paired (astation-1, trust gen 7)"
        );
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

    #[test]
    fn an_expired_session_is_shown_and_advises_unpair_then_pair() {
        let dir = tempfile::tempdir().unwrap();
        write_paired(dir.path(), ASTATION, later());
        crate::pairing::tests::edit(dir.path(), |record| {
            record.session.as_mut().unwrap().last_activity = 0;
        });
        let src = Sources::in_dir(dir.path());
        assert_eq!(
            report(dir.path()).pairing.value,
            "paired (astation-1, trust gen 1, session expired)"
        );
        assert!(profile_paired(&src));
        assert_eq!(
            pairing_advice(true, "run `atem pair`"),
            "The saved Astation session expired or was refused. Run `atem unpair`, then `atem pair`."
        );
        assert_eq!(pairing_advice(false, "run `atem pair`"), "run `atem pair`");
        assert_eq!(
            crate::auth::pairing_gate_message_for("Vault", profile_paired(&src)),
            format!("Vault can't use your Astation pairing. {SESSION_GONE}")
        );
        assert_eq!(
            crate::auth::pairing_gate_message_for("Vault", false),
            crate::auth::pairing_gate_message("Vault")
        );
        assert!(!profile_paired(&Sources::in_dir(
            tempfile::tempdir().unwrap().path()
        )));
    }

    #[test]
    fn a_revocation_by_another_astation_is_not_this_pairings() {
        let dir = tempfile::tempdir().unwrap();
        write_paired(dir.path(), ASTATION, later());
        write_trust(dir.path(), Some(ASTATION), Some("astation-9"));
        let src = Sources::in_dir(dir.path());
        assert_eq!(
            report(dir.path()).verification.value,
            "verified (safety code MN3H-A74N-FJE4)"
        );
        assert!(matches!(
            verify_start(&src).unwrap(),
            VerifyStart::AlreadyVerified(_)
        ));
    }

    #[test]
    fn broken_key_files_are_shown_with_the_reset_steps() {
        let dir = tempfile::tempdir().unwrap();
        write_paired(dir.path(), ASTATION, later());
        // Verified with a home Astation, but no key files at all.
        write_trust(dir.path(), Some(ASTATION), None);
        let report = report(dir.path());
        assert_eq!(report.credentials.value, "broken (no sealed keys on disk)");
        let text = render(&report);
        assert!(
            text.ends_with(&format!(
                "Local agents:   no runtime running\n{}\n",
                crate::memory::cred_agent::RESET
            )),
            "{text}"
        );
    }

    #[test]
    fn the_running_agent_adds_what_to_do() {
        let dir = tempfile::tempdir().unwrap();
        write_paired(dir.path(), ASTATION, later());
        write_trust(dir.path(), Some(ASTATION), None);
        write_device_keys(dir.path());
        let src = Sources::in_dir(dir.path());
        let older = StubAgent {
            build: "other".into(),
            ..StubAgent::new(false)
        };
        assert_eq!(
            gather_with(&src, Some(&older)).credentials.value,
            "locked (started by another atem build; run atem cred lock, then atem cred unlock)"
        );
        let waiting = StubAgent {
            escrowed: false,
            ..StubAgent::new(true)
        };
        assert_eq!(
            gather_with(&src, Some(&waiting)).credentials.value,
            "unlocked (storage key not yet held by Astation; run atem cred unlock)"
        );
        // Unlocked keys need no reset note.
        assert!(
            gather_with(&src, Some(&StubAgent::new(true)))
                .notes
                .is_empty()
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

    // ── The runtime's lines ──

    use crate::runtime::client::{Locator, Welcome, look};
    use crate::runtime::protocol::{
        Refusal, RuntimeMsg, RuntimeStatus, SessionSummary, Transport, Welcomed,
    };

    fn welcome(build: &str) -> Welcome {
        Welcome {
            protocol: crate::runtime::protocol::PROTOCOL,
            build: build.into(),
            pid: 42,
            astation: true,
            host_error: None,
            worker_protocol: Some(1),
        }
    }

    fn running(status: RuntimeStatus) -> Look {
        Look::Running {
            welcome: welcome(crate::memory::cred_agent::build_id()),
            status: Some(status),
        }
    }

    fn session(provider: &str, state: &str, status: &str) -> SessionSummary {
        SessionSummary {
            id: "ses-aaaaaaaaaaaa".into(),
            provider: provider.into(),
            cwd: "/w".into(),
            created_at_ms: 1,
            state: state.into(),
            status: status.into(),
            attached: false,
            remote_controlled: false,
            exited: None,
            rows: 24,
            cols: 80,
            generation: "g".into(),
            worker_build: None,
        }
    }

    /// The three lines' values for `look`, with times shown as `@<ms>`.
    fn lines(look: &Look) -> [String; 3] {
        let (a, r, l) = runtime_lines(look, |ms| format!("@{ms}"));
        [a.value, r.value, l.value]
    }

    fn connected(transport: Transport) -> RuntimeStatus {
        RuntimeStatus {
            astation: true,
            transport: Some(transport),
            relay: (transport == Transport::Relay)
                .then(|| "station.agora.build as Genie-dc1649f-956631ec".into()),
            attachment: true,
            ..Default::default()
        }
    }

    #[test]
    fn a_welcomed_link_is_authorized_with_its_revision_time_and_what_is_left() {
        let status = RuntimeStatus {
            welcomed: Some(Welcomed {
                revision: 8,
                at_ms: 1_000,
                ms_left: 23 * 3_600_000 + 59 * 60_000,
            }),
            sessions: vec![
                session("claude", "running", "ready"),
                session("codex", "running", "working"),
                session("codex", "exited", "unknown"),
            ],
            ..connected(Transport::Relay)
        };
        assert_eq!(
            lines(&running(status)),
            [
                "authorized (r8, since @1000, 23 h left)",
                "connected via relay (station.agora.build as Genie-dc1649f-956631ec)",
                "2 running (claude ready, codex working); 1 exited",
            ]
        );
        let status = RuntimeStatus {
            welcomed: Some(Welcomed {
                revision: 8,
                at_ms: 5,
                ms_left: 5 * 60_000,
            }),
            ..connected(Transport::Local)
        };
        let [authorization, relay, agents] = lines(&running(status));
        assert_eq!(authorization, "authorized (r8, since @5, 5 min left)");
        assert_eq!(relay, "connected locally");
        assert_eq!(agents, "none running");
    }

    #[test]
    fn a_connected_link_without_a_welcome_says_why() {
        let [authorization, ..] = lines(&running(connected(Transport::Local)));
        assert_eq!(
            authorization,
            "not authorized (Astation connected but no session hello yet)"
        );
        // The last refused hello, by revision.
        let refused = |revision| RuntimeStatus {
            refused: Some(Refusal {
                revision,
                needs: 8,
                at_ms: 1,
            }),
            ..connected(Transport::Local)
        };
        assert_eq!(
            lines(&running(refused(Some(7))))[0],
            "refused (Astation sent revision 7; needs r8)"
        );
        assert_eq!(
            lines(&running(refused(None)))[0],
            "refused (Astation sent no revision; needs r8)"
        );
        // A link that isn't a verified pairing gets no attachment.
        let unverified = RuntimeStatus {
            attachment: false,
            ..connected(Transport::Local)
        };
        assert!(lines(&running(unverified))[0].contains("isn't a verified pairing"));
    }

    #[test]
    fn a_disconnected_link_and_a_halted_journal() {
        let retrying = RuntimeStatus {
            retrying: true,
            ..Default::default()
        };
        assert_eq!(
            lines(&running(retrying))[..2],
            [
                "not authorized (Astation not connected)",
                "not connected (retrying)"
            ]
        );
        assert_eq!(
            lines(&running(RuntimeStatus::default()))[1],
            "not connected"
        );
        let halted = RuntimeStatus {
            journal_halted: true,
            ..connected(Transport::Local)
        };
        assert_eq!(
            lines(&running(halted))[0],
            "paused (journal halted; run atem runtime restart)"
        );
        let disabled = RuntimeStatus {
            host_error: Some("remote sessions disabled: x".into()),
            ..connected(Transport::Local)
        };
        assert_eq!(
            lines(&running(disabled))[0],
            "unavailable (remote sessions disabled: x)"
        );
    }

    #[test]
    fn without_a_runtime_every_line_says_so() {
        assert_eq!(lines(&Look::NotRunning), [NO_RUNTIME; 3].map(String::from));
        let old = Look::Running {
            welcome: welcome("0.7.1+1"),
            status: None,
        };
        assert!(
            lines(&old)[0].contains("run atem runtime restart"),
            "{:?}",
            lines(&old)
        );
        assert!(lines(&Look::Unreachable("x".into()))[1].contains("didn't answer: x"));
    }

    /// A fake runtime on `socket`: answers one client's `hello` with a
    /// welcome of `build`, then its `status` with `status` (`None`: an
    /// unknown-op error, as a runtime from before `status`).
    fn fake_runtime(socket: &Path, build: &str, status: Option<RuntimeStatus>) {
        use crate::runtime::protocol::{ClientMsg, decode_client, encode_runtime};
        use std::io::{BufRead, BufReader, Write};
        let listener = std::os::unix::net::UnixListener::bind(socket).unwrap();
        let build = build.to_string();
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut writer = stream;
            let mut line = String::new();
            while reader.read_line(&mut line).unwrap_or(0) > 0 {
                let reply = match decode_client(&line) {
                    Ok(ClientMsg::Hello { passive, .. }) => {
                        assert!(passive, "status is a passive client");
                        RuntimeMsg::Welcome {
                            protocol: crate::runtime::protocol::PROTOCOL,
                            build: build.clone(),
                            pid: 42,
                            astation: true,
                            host_error: None,
                            worker_protocol: Some(1),
                        }
                    }
                    Ok(ClientMsg::Status) => match status.clone() {
                        Some(status) => RuntimeMsg::Status { status },
                        None => RuntimeMsg::error("unknown variant `status`", None),
                    },
                    other => panic!("status sent {other:?}"),
                };
                writer.write_all(encode_runtime(&reply).as_bytes()).unwrap();
                line.clear();
            }
        });
    }

    #[test]
    fn status_asks_a_running_runtime_passively() {
        let dir = tempfile::tempdir().unwrap();
        let locator = Locator::in_dir(dir.path());
        let status = RuntimeStatus {
            sessions: vec![session("claude", "running", "ready")],
            ..connected(Transport::Local)
        };
        fake_runtime(
            &locator.socket,
            crate::memory::cred_agent::build_id(),
            Some(status),
        );
        let mut src = Sources::in_dir(dir.path());
        src.runtime = Some(locator);
        let report = gather(&src);
        assert_eq!(
            report.authorization.value,
            "not authorized (Astation connected but no session hello yet)"
        );
        assert_eq!(report.relay.value, "connected locally");
        assert_eq!(report.local_agents.value, "1 running (claude ready)");
    }

    #[test]
    fn a_runtime_from_before_status_is_named_with_its_fix() {
        let dir = tempfile::tempdir().unwrap();
        let locator = Locator::in_dir(dir.path());
        fake_runtime(&locator.socket, "0.7.1+1", None);
        let found = look(&locator, crate::runtime::client::LOOK_TIMEOUT);
        assert!(
            matches!(&found, Look::Running { welcome, status: None } if welcome.build == "0.7.1+1"),
            "{found:?}"
        );
        assert!(lines(&found)[0].contains("Atem's runtime is build 0.7.1+1"));
    }

    #[test]
    fn status_starts_nothing_and_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let locator = Locator::in_dir(dir.path());
        let mut src = Sources::in_dir(dir.path());
        src.runtime = Some(locator.clone());
        let started = std::time::Instant::now();
        let report = gather(&src);
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        assert_eq!(report.authorization.value, NO_RUNTIME);
        assert!(!locator.socket.exists(), "no runtime was started");
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            0,
            "nothing written"
        );
        // A socket that accepts but never answers costs at most the timeout.
        let _silent = std::os::unix::net::UnixListener::bind(&locator.socket).unwrap();
        let started = std::time::Instant::now();
        let report = gather(&src);
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        assert!(
            report
                .authorization
                .value
                .starts_with("unknown (the runtime didn't answer")
        );
    }

    #[test]
    fn another_build_of_runtime_and_agent_points_to_the_runtime_restart() {
        let dir = tempfile::tempdir().unwrap();
        write_paired(dir.path(), ASTATION, later());
        write_trust(dir.path(), Some(ASTATION), None);
        write_device_keys(dir.path());
        let src = Sources::in_dir(dir.path());
        let older = StubAgent {
            build: "other".into(),
            ..StubAgent::new(true)
        };
        let agent = older.status().map_err(|e| e.to_string());
        let runtime = Look::Running {
            welcome: welcome("other"),
            status: Some(RuntimeStatus::default()),
        };
        assert_eq!(
            gather_full(&src, Some(&agent), &runtime).credentials.value,
            "unlocked (started by another atem build, and Atem's runtime is another build too; run atem runtime restart, then atem cred lock and atem cred unlock)"
        );
        // Only the agent differs: the lock/unlock advice.
        assert_eq!(
            gather_full(&src, Some(&agent), &running(RuntimeStatus::default()))
                .credentials
                .value,
            "unlocked (started by another atem build; run atem cred lock, then atem cred unlock)"
        );
    }
}
