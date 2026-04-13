//! Unified credential store — `~/.config/atem/credentials.enc`
//!
//! Holds a list of credential entries, one per source (own SSO login, or per-Astation
//! paired sessions). AES-256-GCM encrypted with a machine-bound key so the file cannot
//! be decrypted on another machine.

use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use anyhow::Result;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fs;
use std::path::{Path, PathBuf};

type HmacSha256 = Hmac<Sha256>;

/// One credential entry — either the user's own SSO login or an Astation-paired session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CredentialEntry {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: u64,
    #[serde(default)]
    pub login_id: Option<String>,
    pub source: CredentialSource,
    pub save_credentials: bool,
    #[serde(default)]
    pub astation_id: Option<String>,
    #[serde(default)]
    pub paired_at: Option<u64>,
    #[serde(default)]
    pub disconnected_at: Option<u64>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CredentialSource {
    Sso,
    AstationPaired,
}

impl CredentialEntry {
    pub fn new_sso(
        access_token: String,
        refresh_token: String,
        expires_at: u64,
        login_id: Option<String>,
    ) -> Self {
        Self {
            access_token,
            refresh_token,
            expires_at,
            login_id,
            source: CredentialSource::Sso,
            save_credentials: true,
            astation_id: None,
            paired_at: None,
            disconnected_at: None,
        }
    }

    pub fn new_paired(
        access_token: String,
        refresh_token: String,
        expires_at: u64,
        login_id: Option<String>,
        astation_id: String,
        save_credentials: bool,
        paired_at: u64,
    ) -> Self {
        Self {
            access_token,
            refresh_token,
            expires_at,
            login_id,
            source: CredentialSource::AstationPaired,
            save_credentials,
            astation_id: Some(astation_id),
            paired_at: Some(paired_at),
            disconnected_at: None,
        }
    }

    pub fn needs_refresh(&self) -> bool {
        self.expires_at < Self::now_secs() + 60
    }

    pub fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

/// Multi-entry credential store persisted to ~/.config/atem/credentials.enc
#[derive(Debug, Clone)]
pub struct CredentialStore {
    pub entries: Vec<CredentialEntry>,
}

impl CredentialStore {
    /// Grace period after disconnect for non-saved paired entries (seconds).
    pub const GRACE_PERIOD_SECS: u64 = 5 * 60;

    pub fn path() -> PathBuf {
        crate::config::AtemConfig::config_dir().join("credentials.enc")
    }

    pub fn load() -> Self {
        Self::load_from(&Self::path())
    }

    pub fn load_from(path: &Path) -> Self {
        let Ok(raw) = fs::read(path) else {
            return Self { entries: vec![] };
        };
        let Ok(plain) = decrypt_bytes(&raw) else {
            return Self { entries: vec![] };
        };
        let entries: Vec<CredentialEntry> = serde_json::from_slice(&plain).unwrap_or_default();
        Self { entries }
    }

    pub fn save(&self) -> Result<()> {
        self.save_to(&Self::path())
    }

    pub fn save_to(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_vec(&self.entries)?;
        let ct = encrypt_bytes(&json)?;
        fs::write(path, ct)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    pub fn upsert(&mut self, entry: CredentialEntry) {
        let key = (entry.source, entry.astation_id.clone());
        if let Some(pos) = self
            .entries
            .iter()
            .position(|e| (e.source, e.astation_id.clone()) == key)
        {
            self.entries[pos] = entry;
        } else {
            self.entries.push(entry);
        }
    }

    pub fn find_sso(&self) -> Option<&CredentialEntry> {
        self.entries
            .iter()
            .find(|e| e.source == CredentialSource::Sso)
    }

    pub fn find_sso_mut(&mut self) -> Option<&mut CredentialEntry> {
        self.entries
            .iter_mut()
            .find(|e| e.source == CredentialSource::Sso)
    }

    pub fn find_paired(&self, astation_id: &str) -> Option<&CredentialEntry> {
        self.entries.iter().find(|e| {
            e.source == CredentialSource::AstationPaired
                && e.astation_id.as_deref() == Some(astation_id)
        })
    }

    pub fn find_paired_mut(&mut self, astation_id: &str) -> Option<&mut CredentialEntry> {
        self.entries.iter_mut().find(|e| {
            e.source == CredentialSource::AstationPaired
                && e.astation_id.as_deref() == Some(astation_id)
        })
    }

    pub fn remove_sso(&mut self) {
        self.entries.retain(|e| e.source != CredentialSource::Sso);
    }

    pub fn remove_paired(&mut self, astation_id: &str) {
        self.entries.retain(|e| {
            !(e.source == CredentialSource::AstationPaired
                && e.astation_id.as_deref() == Some(astation_id))
        });
    }

    /// Pick the best credential entry given current Astation connection state.
    ///
    /// Priority:
    /// 1. Paired entry matching `connected_astation_id` (active connection wins)
    /// 2. Own SSO entry
    /// 3. Paired entry with `save_credentials: true` (saved offline credentials)
    /// 4. Paired entry within grace period after disconnect
    pub fn resolve(
        &self,
        connected_astation_id: Option<&str>,
        now: u64,
    ) -> Result<&CredentialEntry> {
        if let Some(aid) = connected_astation_id {
            if let Some(e) = self.find_paired(aid) {
                return Ok(e);
            }
        }
        if let Some(e) = self.find_sso() {
            return Ok(e);
        }
        if let Some(e) = self.entries.iter().find(|e| {
            e.source == CredentialSource::AstationPaired && e.save_credentials
        }) {
            return Ok(e);
        }
        if let Some(e) = self.entries.iter().find(|e| {
            if e.source != CredentialSource::AstationPaired || e.save_credentials {
                return false;
            }
            match e.disconnected_at {
                None => true,
                Some(t) => now.saturating_sub(t) < Self::GRACE_PERIOD_SECS,
            }
        }) {
            return Ok(e);
        }
        anyhow::bail!("Not logged in. Run 'atem login' or 'atem pair'.")
    }
}

fn derive_key() -> [u8; 32] {
    let id = machine_id();
    let mut mac = <HmacSha256 as Mac>::new_from_slice(b"atem-credentials-v1").expect("hmac");
    mac.update(id.as_bytes());
    let out = mac.finalize().into_bytes();
    let mut key = [0u8; 32];
    key.copy_from_slice(&out[..32]);
    key
}

fn machine_id() -> String {
    #[cfg(target_os = "linux")]
    {
        if let Ok(s) = fs::read_to_string("/etc/machine-id") {
            return s.trim().to_string();
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(out) = std::process::Command::new("ioreg")
            .args(["-rd1", "-c", "IOPlatformExpertDevice"])
            .output()
        {
            let s = String::from_utf8_lossy(&out.stdout);
            for line in s.lines() {
                if let Some((_, rest)) = line.split_once("IOPlatformUUID") {
                    if let Some(v) = rest.split('"').nth(1) {
                        return v.to_string();
                    }
                }
            }
        }
    }
    let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".into());
    let user = std::env::var("USER").unwrap_or_else(|_| "unknown".into());
    format!("{host}-{user}")
}

fn encrypt_bytes(plain: &[u8]) -> Result<Vec<u8>> {
    let key = derive_key();
    let cipher = Aes256Gcm::new((&key).into());
    let mut nonce_bytes = [0u8; 12];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plain)
        .map_err(|e| anyhow::anyhow!("encrypt: {e}"))?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn decrypt_bytes(raw: &[u8]) -> Result<Vec<u8>> {
    if raw.len() < 12 {
        anyhow::bail!("ciphertext too short");
    }
    let (nonce_bytes, ct) = raw.split_at(12);
    let key = derive_key();
    let cipher = Aes256Gcm::new((&key).into());
    let nonce = Nonce::from_slice(nonce_bytes);
    let plain = cipher
        .decrypt(nonce, ct)
        .map_err(|e| anyhow::anyhow!("decrypt: {e}"))?;
    Ok(plain)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> u64 {
        CredentialEntry::now_secs()
    }

    #[test]
    fn sso_entry_round_trip() {
        let e = CredentialEntry::new_sso("a".into(), "r".into(), 123, Some("uid".into()));
        let json = serde_json::to_string(&e).unwrap();
        let back: CredentialEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
        assert!(e.save_credentials);
        assert_eq!(e.source, CredentialSource::Sso);
    }

    #[test]
    fn paired_entry_round_trip() {
        let e = CredentialEntry::new_paired(
            "a".into(),
            "r".into(),
            123,
            Some("uid".into()),
            "astation-1".into(),
            false,
            100,
        );
        let json = serde_json::to_string(&e).unwrap();
        let back: CredentialEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
        assert_eq!(e.source, CredentialSource::AstationPaired);
        assert_eq!(e.astation_id.as_deref(), Some("astation-1"));
    }

    #[test]
    fn load_returns_empty_when_file_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nope.enc");
        let store = CredentialStore::load_from(&path);
        assert_eq!(store.entries.len(), 0);
    }

    #[test]
    fn save_and_load_round_trip_encrypted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.enc");
        let mut store = CredentialStore::load_from(&path);
        store.upsert(CredentialEntry::new_sso(
            "acc".into(),
            "ref".into(),
            999,
            Some("u".into()),
        ));
        store.save_to(&path).unwrap();

        let raw = fs::read(&path).unwrap();
        assert!(!raw.starts_with(b"["));
        assert!(!raw.starts_with(b"{"));

        let loaded = CredentialStore::load_from(&path);
        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(loaded.entries[0].access_token, "acc");
    }

    #[test]
    fn upsert_replaces_by_source_and_astation_id() {
        let mut store = CredentialStore { entries: vec![] };
        store.upsert(CredentialEntry::new_sso("a1".into(), "r1".into(), 1, None));
        store.upsert(CredentialEntry::new_sso("a2".into(), "r2".into(), 2, None));
        assert_eq!(store.entries.len(), 1);
        assert_eq!(store.entries[0].access_token, "a2");

        store.upsert(CredentialEntry::new_paired(
            "p1".into(),
            "pr1".into(),
            1,
            None,
            "ast-1".into(),
            false,
            100,
        ));
        store.upsert(CredentialEntry::new_paired(
            "p2".into(),
            "pr2".into(),
            2,
            None,
            "ast-2".into(),
            true,
            101,
        ));
        assert_eq!(store.entries.len(), 3);

        store.upsert(CredentialEntry::new_paired(
            "p1b".into(),
            "pr1b".into(),
            3,
            None,
            "ast-1".into(),
            false,
            102,
        ));
        assert_eq!(store.entries.len(), 3);
        assert_eq!(store.find_paired("ast-1").unwrap().access_token, "p1b");
    }

    #[test]
    fn remove_sso_leaves_paired() {
        let mut store = CredentialStore { entries: vec![] };
        store.upsert(CredentialEntry::new_sso("a".into(), "r".into(), 1, None));
        store.upsert(CredentialEntry::new_paired(
            "p".into(),
            "pr".into(),
            1,
            None,
            "ast-1".into(),
            false,
            100,
        ));
        store.remove_sso();
        assert_eq!(store.entries.len(), 1);
        assert_eq!(store.entries[0].source, CredentialSource::AstationPaired);
    }

    #[test]
    fn resolve_picks_paired_when_connected() {
        let store = CredentialStore {
            entries: vec![
                CredentialEntry::new_sso("sso_tok".into(), "r".into(), now() + 3600, None),
                CredentialEntry::new_paired(
                    "paired_tok".into(),
                    "r".into(),
                    now() + 3600,
                    None,
                    "ast-1".into(),
                    false,
                    100,
                ),
            ],
        };
        let r = store.resolve(Some("ast-1"), now()).unwrap();
        assert_eq!(r.access_token, "paired_tok");
    }

    #[test]
    fn resolve_falls_back_to_sso_when_not_connected() {
        let store = CredentialStore {
            entries: vec![
                CredentialEntry::new_sso("sso_tok".into(), "r".into(), now() + 3600, None),
                CredentialEntry::new_paired(
                    "paired_tok".into(),
                    "r".into(),
                    now() + 3600,
                    None,
                    "ast-1".into(),
                    false,
                    100,
                ),
            ],
        };
        let r = store.resolve(None, now()).unwrap();
        assert_eq!(r.access_token, "sso_tok");
    }

    #[test]
    fn resolve_saved_paired_when_disconnected() {
        let mut e = CredentialEntry::new_paired(
            "paired_tok".into(),
            "r".into(),
            now() + 3600,
            None,
            "ast-1".into(),
            true,
            100,
        );
        e.disconnected_at = Some(now() - 10 * 60);
        let store = CredentialStore { entries: vec![e] };
        let r = store.resolve(None, now()).unwrap();
        assert_eq!(r.access_token, "paired_tok");
    }

    #[test]
    fn resolve_non_saved_paired_within_grace_period() {
        let mut e = CredentialEntry::new_paired(
            "paired_tok".into(),
            "r".into(),
            now() + 3600,
            None,
            "ast-1".into(),
            false,
            100,
        );
        e.disconnected_at = Some(now() - 60);
        let store = CredentialStore { entries: vec![e] };
        let r = store.resolve(None, now()).unwrap();
        assert_eq!(r.access_token, "paired_tok");
    }

    #[test]
    fn resolve_errors_when_non_saved_paired_grace_expired() {
        let mut e = CredentialEntry::new_paired(
            "paired_tok".into(),
            "r".into(),
            now() + 3600,
            None,
            "ast-1".into(),
            false,
            100,
        );
        e.disconnected_at = Some(now() - 10 * 60);
        let store = CredentialStore { entries: vec![e] };
        assert!(store.resolve(None, now()).is_err());
    }

    #[test]
    fn resolve_errors_when_empty() {
        let store = CredentialStore { entries: vec![] };
        assert!(store.resolve(None, now()).is_err());
    }
}
