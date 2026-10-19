//! Logins: the user's own (`login.enc`, `atem login`) and the one Astation
//! shares with a pairing (inside `pairing/pairing.enc`), both a `Login`.
//!
//! Identity and Agora connection are kept apart. A login is issued by an
//! identity provider (`issuer`: the host of the SSO URL `atem login` used,
//! or `AGORA_SSO_ISSUER` for the login Astation shares) for a `subject` (the
//! login id). Agora API calls (project list, the BFF) need Agora tokens: a
//! login of another issuer would carry them as `connections.agora`; the
//! identity tokens of Agora SSO (`AGORA_SSO_ISSUER`, or the host of the
//! configured `sso_url`) are the Agora tokens. Callers get them only through
//! `Login::agora_tokens`.
//!
//! Stored machine-bound (`machine_key`) and written atomically (0600).
use anyhow::{Context, Result, anyhow};
use crate::records::{Connections, Login, Tokens};
use std::path::Path;

impl Tokens {
    /// Expired, or within a minute of it.
    pub fn needs_refresh(&self) -> bool {
        self.expires_at < now_secs() + 60
    }
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

/// The issuer of Agora SSO logins (the default `sso_url`'s host), and of the
/// login Astation shares (`credentialSync` carries Agora tokens).
pub const AGORA_SSO_ISSUER: &str = "sso2.agora.io";

/// Whether `issuer` is Agora SSO, whose identity tokens are Agora API tokens:
/// exactly `AGORA_SSO_ISSUER` or the host of the configured `sso_url`.
pub fn issues_agora_tokens(issuer: &str, sso_url: &str) -> bool {
    issuer == AGORA_SSO_ISSUER || issuer == issuer_of(sso_url)
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

    /// The login Astation shares (`credentialSync`): Agora tokens.
    pub fn shared_by_astation(subject: Option<String>, tokens: Tokens) -> Self {
        Self {
            issuer: AGORA_SSO_ISSUER.into(),
            subject,
            tokens,
            connections: Connections::default(),
        }
    }

    /// The tokens for Agora API calls: the Agora connection's, else the
    /// identity tokens when the issuer is Agora SSO (`sso_url`: the
    /// configured one).
    pub fn agora_tokens(&self, sso_url: &str) -> Result<&Tokens> {
        match &self.connections.agora {
            Some(agora) => Ok(&agora.tokens),
            None if issues_agora_tokens(&self.issuer, sso_url) => Ok(&self.tokens),
            None => Err(anyhow!(NO_AGORA_CONNECTION)),
        }
    }

    /// The Agora tokens refresh with the identity's own refresh token
    /// (Agora SSO), not a connection's.
    pub fn agora_tokens_are_identity(&self, sso_url: &str) -> bool {
        self.connections.agora.is_none() && issues_agora_tokens(&self.issuer, sso_url)
    }

    /// The login at `path`: `None` without one; an error when it can't be
    /// read (another machine's file, damaged).
    pub fn load(path: &Path) -> Result<Option<Self>> {
        let raw = match std::fs::read(path) {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(anyhow!(error).context(format!("could not read {}", path.display())));
            }
        };
        let unreadable = || format!("{} is unreadable", path.display());
        let plain = crate::machine_key::decrypt(crate::machine_key::LOGIN, &raw)
            .with_context(unreadable)?;
        Ok(Some(serde_json::from_slice(&plain).with_context(unreadable)?))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let sealed =
            crate::machine_key::encrypt(crate::machine_key::LOGIN, &serde_json::to_vec(self)?)?;
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
    use crate::records::AgoraConnection;

    const SSO: &str = "https://sso2.agora.io";

    fn tokens(access: &str) -> Tokens {
        Tokens {
            access_token: access.into(),
            refresh_token: "r".into(),
            expires_at: now_secs() + 3600,
        }
    }

    #[test]
    fn agora_sso_is_an_exact_allowlist() {
        assert_eq!(issuer_of("https://sso2.agora.io"), "sso2.agora.io");
        assert_eq!(issuer_of("https://sso2.agora.io/path?x"), "sso2.agora.io");
        assert_eq!(issuer_of("http://127.0.0.1:9/"), "127.0.0.1:9");
        assert!(issues_agora_tokens("sso2.agora.io", SSO));
        // The configured sso_url's host, and only that one besides.
        assert!(issues_agora_tokens("sso.staging.example", "https://sso.staging.example"));
        assert!(issues_agora_tokens("sso2.agora.io", "https://sso.staging.example"));
        assert!(!issues_agora_tokens("sso.staging.agora.io", SSO));
        assert!(!issues_agora_tokens("auth.agora.build", SSO));
    }

    #[test]
    fn agora_sso_tokens_are_the_agora_tokens() {
        let login = Login::from_sso(SSO, Some("me".into()), tokens("id"));
        assert_eq!(login.issuer, "sso2.agora.io");
        assert_eq!(login.agora_tokens(SSO).unwrap().access_token, "id");
        assert!(login.agora_tokens_are_identity(SSO));
        // Astation's shared login is Agora SSO's whatever sso_url says.
        let shared = Login::shared_by_astation(None, tokens("shared"));
        assert_eq!(shared.issuer, AGORA_SSO_ISSUER);
        assert!(shared.agora_tokens("https://sso.staging.example").is_ok());
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
            login.agora_tokens(SSO).unwrap_err().to_string(),
            NO_AGORA_CONNECTION
        );
        login.connections.agora = Some(AgoraConnection {
            account_id: Some("acct".into()),
            tokens: tokens("agora"),
        });
        assert_eq!(login.agora_tokens(SSO).unwrap().access_token, "agora");
        assert!(!login.agora_tokens_are_identity(SSO));
    }

    #[test]
    fn a_login_round_trips_machine_bound_and_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = crate::paths::ProfilePaths::in_dir(dir.path()).login;
        assert_eq!(Login::load(&path).unwrap(), None);
        let login = Login::from_sso(SSO, Some("me".into()), tokens("a"));
        login.save(&path).unwrap();
        assert_eq!(Login::load(&path).unwrap(), Some(login));
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
        assert_eq!(Login::load(&path).unwrap(), None);
        // Unreadable: an error, never "no login".
        std::fs::write(&path, b"damaged").unwrap();
        assert!(Login::load(&path).is_err());
    }
}
