use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoSession {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: u64, // Unix seconds
}

impl SsoSession {
    // ── canonical path ──────────────────────────────────────────────

    pub fn session_path() -> PathBuf {
        crate::config::AtemConfig::config_dir().join("sso_session.json")
    }

    // ── persistence (public path) ────────────────────────────────────

    pub fn load() -> Option<Self> {
        Self::load_from(&Self::session_path())
    }

    pub fn save(&self) -> Result<()> {
        self.save_to(&Self::session_path())
    }

    pub fn delete() -> Result<()> {
        Self::delete_at(&Self::session_path())
    }

    // ── persistence (path-injectable, for tests) ─────────────────────

    pub fn load_from(path: &std::path::Path) -> Option<Self> {
        let content = fs::read_to_string(path).ok()?;
        serde_json::from_str(&content).ok()
    }

    pub fn save_to(&self, path: &std::path::Path) -> Result<()> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, &json)?;
        // chmod 0600
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    pub fn delete_at(path: &std::path::Path) -> Result<()> {
        if path.exists() {
            fs::remove_file(path)?;
        }
        Ok(())
    }

    // ── token access ─────────────────────────────────────────────────

    pub fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    pub fn is_expired(&self) -> bool {
        self.expires_at < Self::now_secs() + 60
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn now() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }

    #[test]
    fn sso_session_save_and_load_round_trip() {
        // Use a temp path so we don't touch real config
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sso_session.json");

        let session = SsoSession {
            access_token: "access_abc".to_string(),
            refresh_token: "refresh_xyz".to_string(),
            expires_at: now() + 3600,
        };
        session.save_to(&path).unwrap();

        let loaded = SsoSession::load_from(&path).unwrap();
        assert_eq!(loaded.access_token, "access_abc");
        assert_eq!(loaded.refresh_token, "refresh_xyz");
    }

    #[test]
    fn sso_session_delete_removes_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sso_session.json");

        let session = SsoSession {
            access_token: "tok".to_string(),
            refresh_token: "ref".to_string(),
            expires_at: now() + 3600,
        };
        session.save_to(&path).unwrap();
        assert!(path.exists());
        SsoSession::delete_at(&path).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn load_returns_none_when_file_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("no_such_file.json");
        assert!(SsoSession::load_from(&path).is_none());
    }
}
