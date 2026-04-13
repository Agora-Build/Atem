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

/// Encrypt bytes with machine-bound AES-256-GCM. Output prepends 12-byte nonce to ciphertext.
/// Shared by credentials.enc and project_cache.enc.
pub(crate) fn encrypt_machine_bound(plain: &[u8]) -> Result<Vec<u8>> {
    encrypt_bytes(plain)
}

/// Decrypt bytes produced by `encrypt_machine_bound`. Returns Err if ciphertext is invalid
/// or was encrypted on a different machine.
pub(crate) fn decrypt_machine_bound(raw: &[u8]) -> Result<Vec<u8>> {
    decrypt_bytes(raw)
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

    // ── Practical scenario tests ──────────────────────────────────────

    #[test]
    fn user_logs_in_then_pairs_with_astation() {
        // Scenario: user runs `atem login`, then later runs `atem pair`.
        // After pairing, resolve with connected astation should prefer paired tokens
        // (Astation identity wins while connected).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.enc");
        let mut store = CredentialStore::load_from(&path);

        // Step 1: atem login
        store.upsert(CredentialEntry::new_sso(
            "sso_tok".into(), "sso_ref".into(), now() + 3600, Some("user@agora".into()),
        ));
        store.save_to(&path).unwrap();

        // Step 2: atem pair
        let mut store = CredentialStore::load_from(&path);
        store.upsert(CredentialEntry::new_paired(
            "paired_tok".into(), "paired_ref".into(), now() + 3600,
            Some("user@agora".into()), "astation-1".into(), true, now(),
        ));
        store.save_to(&path).unwrap();

        // Step 3: resolve while connected — paired wins
        let store = CredentialStore::load_from(&path);
        assert_eq!(store.entries.len(), 2);
        let e = store.resolve(Some("astation-1"), now()).unwrap();
        assert_eq!(e.access_token, "paired_tok");
    }

    #[test]
    fn atem_falls_back_to_own_sso_when_paired_astation_different() {
        // User paired with astation-1, but is now connected to astation-2 (no paired entry there)
        let store = CredentialStore {
            entries: vec![
                CredentialEntry::new_sso("sso_tok".into(), "r".into(), now() + 3600, None),
                CredentialEntry::new_paired(
                    "p1".into(), "r".into(), now() + 3600, None,
                    "astation-1".into(), true, 100,
                ),
            ],
        };
        // Connected to astation-2 — no matching paired entry → fallback to SSO
        let e = store.resolve(Some("astation-2"), now()).unwrap();
        assert_eq!(e.access_token, "sso_tok");
    }

    #[test]
    fn disconnect_then_reconnect_within_grace_period() {
        // Simulates: paired (no save), disconnect, reconnect within 5 min
        let mut store = CredentialStore { entries: vec![] };
        store.upsert(CredentialEntry::new_paired(
            "paired_tok".into(), "r".into(), now() + 3600, None,
            "astation-1".into(), false, 100,
        ));

        // Connected: resolves fine
        assert!(store.resolve(Some("astation-1"), now()).is_ok());

        // Mark disconnected
        if let Some(e) = store.find_paired_mut("astation-1") {
            e.disconnected_at = Some(now());
        }

        // Not connected but within grace (60s)
        let e = store.resolve(None, now() + 60).unwrap();
        assert_eq!(e.access_token, "paired_tok");

        // Past grace — fails
        assert!(store.resolve(None, now() + 400).is_err());

        // Reconnect: clear disconnected_at
        if let Some(e) = store.find_paired_mut("astation-1") {
            e.disconnected_at = None;
        }
        let e = store.resolve(Some("astation-1"), now() + 500).unwrap();
        assert_eq!(e.access_token, "paired_tok");
    }

    #[test]
    fn multiple_astations_paired_simultaneously() {
        let mut store = CredentialStore { entries: vec![] };
        store.upsert(CredentialEntry::new_paired(
            "tok_a".into(), "r".into(), now() + 3600, None,
            "astation-A".into(), true, 100,
        ));
        store.upsert(CredentialEntry::new_paired(
            "tok_b".into(), "r".into(), now() + 3600, None,
            "astation-B".into(), true, 100,
        ));
        assert_eq!(store.entries.len(), 2);

        // Connected to A → A's tokens
        assert_eq!(store.resolve(Some("astation-A"), now()).unwrap().access_token, "tok_a");
        // Connected to B → B's tokens
        assert_eq!(store.resolve(Some("astation-B"), now()).unwrap().access_token, "tok_b");
        // Not connected → first saved one wins (priority 3)
        let r = store.resolve(None, now()).unwrap();
        assert!(r.access_token == "tok_a" || r.access_token == "tok_b");
    }

    #[test]
    fn remove_paired_leaves_others_intact() {
        let mut store = CredentialStore { entries: vec![] };
        store.upsert(CredentialEntry::new_sso("sso".into(), "r".into(), 1, None));
        store.upsert(CredentialEntry::new_paired(
            "a".into(), "r".into(), 1, None, "ast-A".into(), false, 100,
        ));
        store.upsert(CredentialEntry::new_paired(
            "b".into(), "r".into(), 1, None, "ast-B".into(), false, 100,
        ));

        store.remove_paired("ast-A");
        assert_eq!(store.entries.len(), 2);
        assert!(store.find_sso().is_some());
        assert!(store.find_paired("ast-A").is_none());
        assert!(store.find_paired("ast-B").is_some());
    }

    #[test]
    fn corrupted_file_returns_empty_store() {
        // Any file that can't be decrypted (wrong machine, truncated, etc) should fall back
        // to empty rather than panicking.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.enc");
        std::fs::write(&path, b"this is not encrypted data").unwrap();
        let store = CredentialStore::load_from(&path);
        assert_eq!(store.entries.len(), 0);
    }

    #[test]
    fn empty_store_saves_and_loads_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.enc");
        let store = CredentialStore { entries: vec![] };
        store.save_to(&path).unwrap();
        let loaded = CredentialStore::load_from(&path);
        assert_eq!(loaded.entries.len(), 0);
    }

    #[test]
    fn file_permissions_are_0600_on_unix() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("creds.enc");
            let mut store = CredentialStore { entries: vec![] };
            store.upsert(CredentialEntry::new_sso("a".into(), "r".into(), 1, None));
            store.save_to(&path).unwrap();
            let meta = std::fs::metadata(&path).unwrap();
            let mode = meta.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "expected 0o600 permissions, got {:o}", mode);
        }
    }

    #[test]
    fn needs_refresh_true_when_near_expiry() {
        let e = CredentialEntry::new_sso("t".into(), "r".into(), CredentialEntry::now_secs() + 30, None);
        assert!(e.needs_refresh());
    }

    #[test]
    fn needs_refresh_false_when_plenty_of_time() {
        let e = CredentialEntry::new_sso("t".into(), "r".into(), CredentialEntry::now_secs() + 3600, None);
        assert!(!e.needs_refresh());
    }

    #[test]
    fn sso_source_always_has_save_credentials_true() {
        let e = CredentialEntry::new_sso("t".into(), "r".into(), 100, None);
        assert!(e.save_credentials, "SSO entries must always be saved");
    }

    #[test]
    fn disconnect_sets_timestamp_and_grace_applies() {
        // Simulates what App::on_astation_disconnect does.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.enc");
        let mut store = CredentialStore::load_from(&path);
        store.upsert(CredentialEntry::new_paired(
            "paired_tok".into(), "r".into(), now() + 3600, None,
            "ast-1".into(), false, 100,
        ));
        store.save_to(&path).unwrap();

        // simulate disconnect
        let mut store = CredentialStore::load_from(&path);
        if let Some(e) = store.find_paired_mut("ast-1") {
            e.disconnected_at = Some(now());
        }
        store.save_to(&path).unwrap();

        // Reload — disconnected_at persisted
        let store = CredentialStore::load_from(&path);
        let e = store.find_paired("ast-1").unwrap();
        assert!(e.disconnected_at.is_some());

        // Within grace: usable
        assert!(store.resolve(None, now() + 60).is_ok());
        // Past grace: not usable
        assert!(store.resolve(None, now() + 400).is_err());
    }

    #[test]
    fn saved_paired_survives_disconnect_forever() {
        // save_credentials=true → grace period is irrelevant, always resolves
        let mut e = CredentialEntry::new_paired(
            "saved_tok".into(), "r".into(), now() + 3600, None,
            "ast-1".into(), true, 100,
        );
        e.disconnected_at = Some(now() - 10_000); // disconnected forever
        let store = CredentialStore { entries: vec![e] };
        let r = store.resolve(None, now()).unwrap();
        assert_eq!(r.access_token, "saved_tok");
    }

    #[test]
    fn paired_source_respects_save_credentials_flag() {
        let saved = CredentialEntry::new_paired(
            "t".into(), "r".into(), 100, None, "ast".into(), true, 100,
        );
        let ephemeral = CredentialEntry::new_paired(
            "t".into(), "r".into(), 100, None, "ast".into(), false, 100,
        );
        assert!(saved.save_credentials);
        assert!(!ephemeral.save_credentials);
    }
}
