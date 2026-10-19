use anyhow::{Result, anyhow};
use rand::Rng;

// ===== Capability tiers: shared pairing/login gates =====
//
// Tier 1 (`atem login`) unlocks a limited set of functions; tier 2 (paired
// with Astation, the control plane) unlocks the full set. These helpers are
// the single shared implementation — callers across the CLI (memory, vault,
// project, …) gate through `require_pairing`/`require_login` rather than
// re-deriving the session/credential checks themselves.

/// Why a pairing session couldn't be resolved. A purely local determination
/// — no network involved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingProblem {
    /// No pairing (or the config can't be read).
    NotConfigured,
    /// A pairing without a valid session.
    NotPaired,
}

/// A resolved pairing: the relay base URL, the paired Astation's id, and
/// this machine's session with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairedSession {
    pub relay_base: String,
    pub astation_id: String,
    pub session_id: String,
}

/// Pure: derive a `PairedSession` from already-resolved inputs. No network,
/// no disk access — everything is fed in.
pub fn pairing_from(
    relay_base: &str,
    astation_id: Option<&str>,
    session_id: Option<String>,
) -> std::result::Result<PairedSession, PairingProblem> {
    let astation_id = astation_id.ok_or(PairingProblem::NotConfigured)?;
    let session_id = session_id.ok_or(PairingProblem::NotPaired)?;
    Ok(PairedSession {
        relay_base: relay_base.to_string(),
        astation_id: astation_id.to_string(),
        session_id,
    })
}

/// This user's pairing: the configured relay and the pairing's valid
/// session. A config load failure maps to `NotConfigured`, no pairing (or
/// no valid session) to `NotPaired`.
pub fn pairing_session() -> std::result::Result<PairedSession, PairingProblem> {
    let src = crate::profile::Sources::current().map_err(|_| PairingProblem::NotConfigured)?;
    pairing_session_in(&src)
}

/// `pairing_session` for the profile `src`.
pub fn pairing_session_in(
    src: &crate::profile::Sources,
) -> std::result::Result<PairedSession, PairingProblem> {
    let record = crate::records::PairingRecord::load(&src.paths.pairing)
        .ok()
        .flatten()
        .ok_or(PairingProblem::NotConfigured)?;
    let session_id = record
        .session_for(&record.astation_id)
        .map(|session| session.session_id.clone());
    pairing_from(src.config.astation_relay_url(), Some(&record.astation_id), session_id)
}

/// The tier-2 gate message: `feature` refused because this machine isn't
/// paired with an Astation.
pub fn pairing_gate_message(feature: &str) -> String {
    format!(
        "{feature} works only on machines paired with your Astation. Run `atem pair` (Astation approves this machine), then retry."
    )
}

/// The tier-2 gate message for `paired`: a paired profile without a usable
/// session can't pair again with `atem pair` (it only shows the status).
pub fn pairing_gate_message_for(feature: &str, paired: bool) -> String {
    if paired {
        format!(
            "{feature} can't use your Astation pairing. {}",
            crate::status::SESSION_GONE
        )
    } else {
        pairing_gate_message(feature)
    }
}

/// The tier-2 gate: a local check with no network. Fails with an actionable
/// message when this machine isn't paired with an Astation.
pub fn require_pairing(feature: &str) -> Result<PairedSession> {
    pairing_session().map_err(|_| {
        anyhow!(pairing_gate_message_for(
            feature,
            crate::status::current_profile_paired()
        ))
    })
}

/// The tier-1 gate message: `feature` refused because there's no `atem
/// login`.
pub fn login_gate_message(feature: &str) -> String {
    format!("{feature} requires `atem login` (your Agora account).")
}

/// The tier-1 gate: a local check with no network. Passes with the user's
/// own login or a login Astation shared with the pairing.
pub fn require_login(feature: &str) -> Result<()> {
    let paths = crate::paths::ProfilePaths::default_paths();
    let shared = crate::records::PairingRecord::load(&paths.pairing)
        .ok()
        .flatten()
        .is_some_and(|record| record.shared.is_some());
    let own = crate::records::Login::load(&paths.login).ok().flatten();
    if own.is_none() && !shared {
        return Err(anyhow!(login_gate_message(feature)));
    }
    Ok(())
}

/// Generate a random 8-digit OTP code.
pub fn generate_otp() -> String {
    let mut rng = rand::thread_rng();
    let code: u32 = rng.gen_range(10_000_000..100_000_000);
    code.to_string()
}

/// Get the local machine hostname.
pub fn get_hostname() -> String {
    hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== Capability tier gates =====

    #[test]
    fn pairing_from_not_configured_without_astation_id() {
        assert_eq!(
            pairing_from("https://relay.example.com", None, Some("sess-1".to_string())),
            Err(PairingProblem::NotConfigured)
        );
    }

    #[test]
    fn pairing_from_not_paired_without_session() {
        assert_eq!(
            pairing_from("https://relay.example.com", Some("astation-1"), None),
            Err(PairingProblem::NotPaired)
        );
    }

    #[test]
    fn pairing_from_ok_with_both() {
        assert_eq!(
            pairing_from("https://relay.example.com", Some("astation-1"), Some("sess-1".to_string())),
            Ok(PairedSession {
                relay_base: "https://relay.example.com".to_string(),
                astation_id: "astation-1".to_string(),
                session_id: "sess-1".to_string(),
            })
        );
    }

    #[test]
    fn pairing_gate_message_text_is_exact() {
        assert_eq!(
            pairing_gate_message("Atem Memory"),
            "Atem Memory works only on machines paired with your Astation. Run `atem pair` (Astation approves this machine), then retry."
        );
    }

    #[test]
    fn login_gate_message_text_is_exact() {
        assert_eq!(
            login_gate_message("atem project"),
            "atem project requires `atem login` (your Agora account)."
        );
    }

    #[test]
    fn otp_is_8_digits() {
        let otp = generate_otp();
        assert_eq!(otp.len(), 8);
        assert!(otp.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn otp_is_random() {
        let a = generate_otp();
        let b = generate_otp();
        assert_ne!(a, b);
    }

    #[test]
    fn hostname_returns_non_empty() {
        let h = get_hostname();
        assert!(!h.is_empty());
    }
}
