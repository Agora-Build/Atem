//! Logins: the user's own (`login.enc`, `atem login`) and the one Astation
//! shares with a pairing (inside `pairing/pairing.enc`), both a `Login`.
//!
//! Identity and Agora connection are kept apart. A login is issued by an
//! identity provider (`issuer`, the host of the SSO URL that issued it, today
//! Agora SSO `sso2.agora.io`) for a `subject` (the login id). Agora API calls
//! (project list, the BFF) need Agora tokens: a login of another issuer would
//! carry them as `connections.agora`; Agora SSO's own identity tokens are the
//! Agora tokens. Callers get them only through `Login::agora_tokens`.
//!
//! Stored machine-bound (`machine_key`) and written atomically (0600).
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// An access token, its refresh token and when it expires (Unix seconds).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tokens {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: u64,
}

impl Tokens {
    /// Expired, or within a minute of it.
    pub fn needs_refresh(&self) -> bool {
        self.expires_at < now_secs() + 60
    }
}

/// An Agora account linked to a login of another issuer (none yet).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgoraConnection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    pub tokens: Tokens,
}

/// Service connections of a login.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Connections {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agora: Option<AgoraConnection>,
}

/// One login: who issued it, for whom, its identity tokens and its
/// connections.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Login {
    pub issuer: String,
    /// The login id.
    pub subject: Option<String>,
    pub tokens: Tokens,
    #[serde(default)]
    pub connections: Connections,
}

/// `agora_tokens` of a login that has none.
pub const NO_AGORA_CONNECTION: &str =
    "This login has no Agora connection. Run `atem login` (Agora Console).";

/// What `atem` says without any login.
pub const NOT_LOGGED_IN: &str = "Not logged in. Run 'atem login' or 'atem pair'.";

/// The issuer of logins from `sso_url`: its host.
pub fn issuer_of(sso_url: &str) -> String {
    let rest = sso_url.split_once("://").map_or(sso_url, |(_, rest)| rest);
    rest.split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .to_string()
}

/// Whether `issuer` is Agora SSO (any `*.agora.io` host), whose identity
/// tokens are Agora API tokens.
pub fn issues_agora_tokens(issuer: &str) -> bool {
    let host = issuer.split(':').next().unwrap_or_default();
    host == "agora.io" || host.ends_with(".agora.io")
}

impl Login {
    /// A login Agora SSO at `sso_url` issued for `subject`.
    pub fn from_sso(sso_url: &str, subject: Option<String>, tokens: Tokens) -> Self {
        Self {
            issuer: issuer_of(sso_url),
            subject,
            tokens,
            connections: Connections::default(),
        }
    }

    /// The tokens for Agora API calls: the Agora connection's, else the
    /// identity tokens when the issuer is Agora SSO.
    pub fn agora_tokens(&self) -> Result<&Tokens> {
        match &self.connections.agora {
            Some(agora) => Ok(&agora.tokens),
            None if issues_agora_tokens(&self.issuer) => Ok(&self.tokens),
            None => Err(anyhow!(NO_AGORA_CONNECTION)),
        }
    }

    /// The Agora tokens refresh with the identity's own refresh token
    /// (Agora SSO), not a connection's.
    pub fn agora_tokens_are_identity(&self) -> bool {
        self.connections.agora.is_none() && issues_agora_tokens(&self.issuer)
    }

    /// The login at `path`; `None` when there is none or it can't be read
    /// (another machine's file).
    pub fn load(path: &Path) -> Option<Self> {
        let raw = std::fs::read(path).ok()?;
        let plain = crate::machine_key::decrypt(&raw).ok()?;
        serde_json::from_slice(&plain).ok()
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let sealed = crate::machine_key::encrypt(&serde_json::to_vec(self)?)?;
        crate::memory::crypto::write_private(path, &sealed)
    }

    /// Removes the login at `path` (nothing when there is none).
    pub fn remove(path: &Path) -> Result<()> {
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tokens(access: &str) -> Tokens {
        Tokens {
            access_token: access.into(),
            refresh_token: "r".into(),
            expires_at: now_secs() + 3600,
        }
    }

    #[test]
    fn the_issuer_is_the_sso_host() {
        assert_eq!(issuer_of("https://sso2.agora.io"), "sso2.agora.io");
        assert_eq!(issuer_of("https://sso2.agora.io/path?x"), "sso2.agora.io");
        assert_eq!(issuer_of("http://127.0.0.1:9/"), "127.0.0.1:9");
        assert!(issues_agora_tokens("sso2.agora.io"));
        assert!(issues_agora_tokens("sso.staging.agora.io"));
        assert!(!issues_agora_tokens("auth.agora.build"));
        assert!(!issues_agora_tokens("notagora.io"));
    }

    #[test]
    fn agora_sso_tokens_are_the_agora_tokens() {
        let login = Login::from_sso("https://sso2.agora.io", Some("me".into()), tokens("id"));
        assert_eq!(login.issuer, "sso2.agora.io");
        assert_eq!(login.agora_tokens().unwrap().access_token, "id");
        assert!(login.agora_tokens_are_identity());
    }

    #[test]
    fn another_issuer_needs_an_agora_connection() {
        let mut login = Login {
            issuer: "auth.agora.build".into(),
            subject: Some("me".into()),
            tokens: tokens("identity"),
            connections: Connections::default(),
        };
        assert_eq!(
            login.agora_tokens().unwrap_err().to_string(),
            NO_AGORA_CONNECTION
        );
        login.connections.agora = Some(AgoraConnection {
            account_id: Some("acct".into()),
            tokens: tokens("agora"),
        });
        assert_eq!(login.agora_tokens().unwrap().access_token, "agora");
        assert!(!login.agora_tokens_are_identity());
    }

    #[test]
    fn a_login_round_trips_machine_bound_and_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = crate::paths::ProfilePaths::in_dir(dir.path()).login;
        assert_eq!(Login::load(&path), None);
        let login = Login::from_sso("https://sso2.agora.io", Some("me".into()), tokens("a"));
        login.save(&path).unwrap();
        assert_eq!(Login::load(&path), Some(login));
        let raw = std::fs::read(&path).unwrap();
        assert!(!String::from_utf8_lossy(&raw).contains("sso2"), "encrypted");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        Login::remove(&path).unwrap();
        Login::remove(&path).unwrap();
        assert_eq!(Login::load(&path), None);
    }
}
