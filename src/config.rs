use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;

/// Main Atem configuration loaded from ~/.config/atem/config.toml + env vars
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct AtemConfig {
    pub rtm_channel: Option<String>,
    pub rtm_account: Option<String>,
    pub astation_ws: Option<String>,
    pub astation_relay_url: Option<String>,
    pub astation_relay_code: Option<String>,
    pub diagram_server_url: Option<String>,
    pub bff_url: Option<String>,
    pub sso_url: Option<String>,
}

/// Active project state (in-memory, plaintext).
#[derive(Debug, Clone)]
pub struct ActiveProject {
    pub app_id: String,
    pub app_certificate: String,
    pub name: String,
}

/// On-disk format with encrypted certificate.
#[derive(Serialize, Deserialize)]
struct EncryptedActiveProject {
    app_id: String,
    app_certificate_encrypted: String,
    name: String,
}

impl AtemConfig {
    /// Load config from file + env var overrides.
    ///
    /// Env var resolution order (lowest → highest priority):
    ///   config.toml → env vars
    pub fn load() -> Result<Self> {
        let config_path = Self::config_path();

        let mut config = if config_path.exists() {
            let content = fs::read_to_string(&config_path)
                .with_context(|| format!("Failed to read config file: {}", config_path.display()))?;
            toml::from_str::<AtemConfig>(&content)
                .with_context(|| format!("Failed to parse config file: {}", config_path.display()))?
        } else {
            AtemConfig::default()
        };

        if let Ok(val) = std::env::var("ATEM_RTM_CHANNEL") {
            config.rtm_channel = Some(val);
        }
        if let Ok(val) = std::env::var("ATEM_RTM_ACCOUNT") {
            config.rtm_account = Some(val);
        }
        if let Ok(val) = std::env::var("ASTATION_WS") {
            config.astation_ws = Some(val);
        }
        if let Ok(val) = std::env::var("ASTATION_RELAY_URL") {
            config.astation_relay_url = Some(val);
        }
        if let Ok(val) = std::env::var("ASTATION_RELAY_CODE") {
            config.astation_relay_code = Some(val);
        }
        if let Ok(val) = std::env::var("DIAGRAM_SERVER_URL") {
            config.diagram_server_url = Some(val);
        }
        if let Ok(val) = std::env::var("ATEM_BFF_URL") {
            if !val.is_empty() {
                config.bff_url = Some(val);
            }
        }
        if let Ok(val) = std::env::var("ATEM_SSO_URL") {
            if !val.is_empty() {
                config.sso_url = Some(val);
            }
        }

        Ok(config)
    }

    /// Persist the config to disk.
    ///
    /// Non-sensitive settings → `~/.config/atem/config.toml` (plaintext)
    pub fn save_to_disk(&self) -> Result<()> {
        let path = Self::config_path();
        let dir = path.parent().unwrap();
        fs::create_dir_all(dir)
            .with_context(|| format!("Failed to create config dir: {}", dir.display()))?;

        // Load existing config.toml so we don't clobber other keys
        let mut existing = if path.exists() {
            let content = fs::read_to_string(&path)?;
            toml::from_str::<toml::Value>(&content).unwrap_or(toml::Value::Table(Default::default()))
        } else {
            toml::Value::Table(Default::default())
        };

        let table = existing.as_table_mut().expect("config is a TOML table");

        // Write non-sensitive settings
        if let Some(ch) = &self.rtm_channel {
            table.insert("rtm_channel".into(), toml::Value::String(ch.clone()));
        }
        if let Some(acc) = &self.rtm_account {
            table.insert("rtm_account".into(), toml::Value::String(acc.clone()));
        }
        if let Some(ws) = &self.astation_ws {
            table.insert("astation_ws".into(), toml::Value::String(ws.clone()));
        }
        if let Some(relay) = &self.astation_relay_url {
            table.insert("astation_relay_url".into(), toml::Value::String(relay.clone()));
        }
        if let Some(code) = &self.astation_relay_code {
            table.insert("astation_relay_code".into(), toml::Value::String(code.clone()));
        }
        if let Some(ds) = &self.diagram_server_url {
            table.insert("diagram_server_url".into(), toml::Value::String(ds.clone()));
        }
        if let Some(bff) = &self.bff_url {
            table.insert("bff_url".into(), toml::Value::String(bff.clone()));
        }
        if let Some(sso) = &self.sso_url {
            table.insert("sso_url".into(), toml::Value::String(sso.clone()));
        }
        if self.bff_url.is_none() {
            table.remove("bff_url");
        }
        if self.sso_url.is_none() {
            table.remove("sso_url");
        }

        let content = toml::to_string_pretty(&existing)
            .with_context(|| "Failed to serialize config")?;
        fs::write(&path, content)
            .with_context(|| format!("Failed to write config file: {}", path.display()))?;
        Ok(())
    }

    /// Get the config directory path: ~/.config/atem/ (same on all platforms)
    pub fn config_dir() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".config")
            .join("atem")
    }

    /// Get the config file path: ~/.config/atem/config.toml
    pub fn config_path() -> PathBuf {
        Self::config_dir().join("config.toml")
    }

    /// Display config with secrets masked
    pub fn display_masked(&self) -> String {
        let mask = |opt: &Option<String>| -> String {
            match opt {
                Some(s) if s.len() > 4 => {
                    let chars: Vec<char> = s.chars().collect();
                    let start: String = chars[..2].iter().collect();
                    let end: String = chars[chars.len() - 2..].iter().collect();
                    format!("{}...{}", start, end)
                }
                Some(s) if !s.is_empty() => "****".to_string(),
                _ => "(not set)".to_string(),
            }
        };

        let mut lines = Vec::new();
        lines.push(format!("Config file: {}", Self::config_path().display()));
        lines.push(format!(
            "rtm_channel: {}",
            self.rtm_channel.as_deref().unwrap_or("(not set)")
        ));
        lines.push(format!(
            "rtm_account: {}",
            self.rtm_account.as_deref().unwrap_or("(not set)")
        ));
        lines.push(format!(
            "astation_ws: {}",
            self.astation_ws.as_deref().unwrap_or("(not set)")
        ));
        lines.push(format!(
            "astation_relay_url: {}",
            self.astation_relay_url.as_deref().unwrap_or("(not set)")
        ));
        lines.push(format!(
            "diagram_server_url: {}",
            self.diagram_server_url.as_deref().unwrap_or("(not set)")
        ));

        // SSO login state
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        match crate::sso_auth::SsoSession::load() {
            Some(session) if session.expires_at > now_secs => {
                let expires = format_unix_timestamp_hhmm(session.expires_at);
                lines.push(format!("SSO:    logged in  (expires {})", expires));
            }
            _ => {
                lines.push("SSO:    not logged in  (run 'atem login')".to_string());
            }
        }

        // Show active project info
        match ActiveProject::load() {
            Some(proj) => {
                lines.push(String::new());
                lines.push(format!(
                    "Active project: {} ({})",
                    proj.name, proj.app_id
                ));
                lines.push(format!(
                    "App certificate: {}",
                    mask(&Some(proj.app_certificate))
                ));
            }
            None => {
                lines.push(String::new());
                lines.push("Active project: (none) — run `atem list project`, then `atem project use <APP_ID>`".to_string());
            }
        }

        // Show env var overrides if set
        let env_app_id = std::env::var("AGORA_APP_ID").ok().filter(|s| !s.is_empty());
        let env_cert = std::env::var("AGORA_APP_CERTIFICATE").ok().filter(|s| !s.is_empty());
        if env_app_id.is_some() || env_cert.is_some() {
            lines.push(String::new());
            lines.push("Env var overrides:".to_string());
            if let Some(id) = &env_app_id {
                lines.push(format!("  AGORA_APP_ID={}", id));
            }
            if env_cert.is_some() {
                lines.push(format!("  AGORA_APP_CERTIFICATE={}", mask(&env_cert)));
            }
        }

        lines.join("\n")
    }

    /// Get RTM channel with fallback default
    pub fn rtm_channel(&self) -> &str {
        self.rtm_channel.as_deref().unwrap_or("atem_channel")
    }

    /// Get RTM account with fallback default
    pub fn rtm_account(&self) -> &str {
        self.rtm_account.as_deref().unwrap_or("atem01")
    }

    /// Get Astation URL with fallback default
    pub fn astation_ws(&self) -> &str {
        self.astation_ws
            .as_deref()
            .unwrap_or("ws://127.0.0.1:8080/ws")
    }

    /// Get Station relay URL with fallback default
    pub fn astation_relay_url(&self) -> &str {
        self.astation_relay_url
            .as_deref()
            .unwrap_or("https://station.agora.build")
    }

    /// Get the BFF URL with fallback default
    pub fn effective_bff_url(&self) -> &str {
        self.bff_url.as_deref().unwrap_or("https://agora-cli-bff.staging.la3.agoralab.co")
    }

    /// Get the SSO URL with fallback default
    pub fn effective_sso_url(&self) -> &str {
        self.sso_url.as_deref().unwrap_or("https://sso.agora.io")
    }
}

impl ActiveProject {
    /// Active project file path: ~/.config/atem/active_project.json
    pub fn path() -> PathBuf {
        AtemConfig::config_dir().join("active_project.json")
    }

    /// Load active project from disk. Returns None if not set.
    pub fn load() -> Option<Self> {
        let path = Self::path();
        if !path.exists() {
            return None;
        }
        let content = fs::read_to_string(&path).ok()?;

        // Try encrypted format first
        if let Ok(encrypted) = serde_json::from_str::<EncryptedActiveProject>(&content) {
            let key = derive_cache_key();
            let cert = decrypt_field(&encrypted.app_certificate_encrypted, &key).ok()?;
            return Some(ActiveProject {
                app_id: encrypted.app_id,
                app_certificate: cert,
                name: encrypted.name,
            });
        }

        // Fall back to legacy plaintext format (auto-migrate on next save)
        #[derive(Deserialize)]
        struct LegacyActiveProject {
            app_id: String,
            app_certificate: String,
            name: String,
        }
        let legacy: LegacyActiveProject = serde_json::from_str(&content).ok()?;
        let proj = ActiveProject {
            app_id: legacy.app_id,
            app_certificate: legacy.app_certificate,
            name: legacy.name,
        };
        // Auto-migrate: re-save in encrypted format
        let _ = proj.save();
        Some(proj)
    }

    /// Save active project to disk (certificate encrypted).
    pub fn save(&self) -> Result<()> {
        let path = Self::path();
        let dir = path.parent().unwrap();
        fs::create_dir_all(dir)?;
        let key = derive_cache_key();
        let encrypted = EncryptedActiveProject {
            app_id: self.app_id.clone(),
            app_certificate_encrypted: encrypt_field(&self.app_certificate, &key),
            name: self.name.clone(),
        };
        let json = serde_json::to_string_pretty(&encrypted)?;
        fs::write(&path, json)?;
        Ok(())
    }

    /// Clear the active project.
    pub fn clear() -> Result<()> {
        let path = Self::path();
        if path.exists() {
            fs::remove_file(&path)?;
        }
        Ok(())
    }

    /// Resolve app_id: CLI flag > env var > active project > error
    pub fn resolve_app_id(cli_app_id: Option<&str>) -> Result<String> {
        if let Some(id) = cli_app_id {
            return Ok(id.to_string());
        }
        if let Ok(id) = std::env::var("AGORA_APP_ID") {
            if !id.is_empty() {
                return Ok(id);
            }
        }
        if let Some(proj) = Self::load() {
            return Ok(proj.app_id);
        }
        anyhow::bail!(
            "No active project. Run `atem config set --app-id <ID> --app-certificate <CERT>`, \
             `atem project use <APP_ID>`, set AGORA_APP_ID env var, or pass `--app-id`"
        )
    }

    /// Resolve app_certificate: CLI flag > env var > active project > error
    pub fn resolve_app_certificate(cli_cert: Option<&str>) -> Result<String> {
        if let Some(cert) = cli_cert {
            return Ok(cert.to_string());
        }
        if let Ok(cert) = std::env::var("AGORA_APP_CERTIFICATE") {
            if !cert.is_empty() {
                return Ok(cert);
            }
        }
        if let Some(proj) = Self::load() {
            return Ok(proj.app_certificate);
        }
        anyhow::bail!(
            "No active project. Run `atem config set --app-id <ID> --app-certificate <CERT>`, \
             `atem project use <APP_ID>`, set AGORA_APP_CERTIFICATE env var, or pass `--app-id`"
        )
    }
}

// ── Encrypted project cache ─────────────────────────────────────────

/// Get machine ID for cache encryption key derivation.
fn get_machine_id() -> String {
    #[cfg(target_os = "linux")]
    {
        if let Ok(id) = fs::read_to_string("/etc/machine-id") {
            let trimmed = id.trim().to_string();
            if !trimmed.is_empty() {
                return trimmed;
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = std::process::Command::new("ioreg")
            .args(["-rd1", "-c", "IOPlatformExpertDevice"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if line.contains("IOPlatformUUID") {
                    if let Some(uuid) = line.split('"').nth(3) {
                        return uuid.to_string();
                    }
                }
            }
        }
    }

    // Fallback: hostname
    hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "atem-fallback-id".to_string())
}

/// Derive a 32-byte encryption key from the machine ID.
fn derive_cache_key() -> [u8; 32] {
    type HmacSha256 = Hmac<Sha256>;
    let machine_id = get_machine_id();
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(b"atem-project-cache-v1").expect("HMAC accepts any key size");
    mac.update(machine_id.as_bytes());
    let result = mac.finalize();
    result.into_bytes().into()
}

/// XOR-encrypt `plaintext` with a SHA256-based keystream derived from `key`.
pub fn encrypt_field(plaintext: &str, key: &[u8; 32]) -> String {
    let pt = plaintext.as_bytes();
    let keystream = generate_keystream(key, pt.len());
    let encrypted: Vec<u8> = pt.iter().zip(keystream.iter()).map(|(a, b)| a ^ b).collect();
    general_purpose::STANDARD.encode(&encrypted)
}

/// Decrypt a base64-encoded ciphertext using the same XOR keystream.
pub fn decrypt_field(ciphertext_b64: &str, key: &[u8; 32]) -> Result<String> {
    let encrypted = general_purpose::STANDARD
        .decode(ciphertext_b64)
        .map_err(|e| anyhow::anyhow!("Failed to decode base64: {}", e))?;
    let keystream = generate_keystream(key, encrypted.len());
    let decrypted: Vec<u8> = encrypted
        .iter()
        .zip(keystream.iter())
        .map(|(a, b)| a ^ b)
        .collect();
    String::from_utf8(decrypted).map_err(|e| anyhow::anyhow!("Invalid UTF-8 after decrypt: {}", e))
}

/// Generate a keystream of `len` bytes: SHA256(key || 0) || SHA256(key || 1) || ...
fn generate_keystream(key: &[u8; 32], len: usize) -> Vec<u8> {
    let mut stream = Vec::with_capacity(len);
    let mut counter: u32 = 0;
    while stream.len() < len {
        let mut hasher = Sha256::new();
        hasher.update(key);
        hasher.update(counter.to_le_bytes());
        let block = hasher.finalize();
        stream.extend_from_slice(&block);
        counter += 1;
    }
    stream.truncate(len);
    stream
}

/// A single cached project with encrypted sign_key.
#[derive(Debug, Serialize, Deserialize)]
struct CachedProject {
    project_id: String,
    name: String,
    app_id: String,
    sign_key_encrypted: String,
    status: String,
    created_at: String,
}

/// Encrypted project cache stored at ~/.config/atem/project_cache.json
#[derive(Debug, Serialize, Deserialize)]
pub struct ProjectCache {
    projects: Vec<CachedProject>,
}

impl ProjectCache {
    /// Cache file path: ~/.config/atem/project_cache.json
    pub fn path() -> PathBuf {
        AtemConfig::config_dir().join("project_cache.json")
    }

    /// Save projects to the encrypted cache.
    pub fn save(projects: &[crate::agora_api::BffProject]) -> Result<()> {
        let key = derive_cache_key();
        let cached: Vec<CachedProject> = projects
            .iter()
            .map(|p| CachedProject {
                project_id: p.project_id.clone(),
                name: p.name.clone(),
                app_id: p.app_id.clone(),
                sign_key_encrypted: encrypt_field(
                    p.sign_key.as_deref().unwrap_or(""),
                    &key,
                ),
                status: p.status.clone(),
                created_at: p.created_at.clone(),
            })
            .collect();

        let cache = ProjectCache { projects: cached };
        let path = Self::path();
        let dir = path.parent().unwrap();
        fs::create_dir_all(dir)?;
        let json = serde_json::to_string_pretty(&cache)?;
        fs::write(&path, json)?;
        Ok(())
    }

    /// Load projects from the encrypted cache.
    pub fn load() -> Option<Vec<crate::agora_api::BffProject>> {
        let path = Self::path();
        if !path.exists() {
            return None;
        }
        let content = fs::read_to_string(&path).ok()?;
        let cache: ProjectCache = serde_json::from_str(&content).ok()?;
        let key = derive_cache_key();

        let projects: Vec<crate::agora_api::BffProject> = cache
            .projects
            .iter()
            .filter_map(|cp| {
                let sign_key_str = decrypt_field(&cp.sign_key_encrypted, &key).ok()?;
                let sign_key = if sign_key_str.is_empty() { None } else { Some(sign_key_str) };
                Some(crate::agora_api::BffProject {
                    project_id: cp.project_id.clone(),
                    name: cp.name.clone(),
                    app_id: cp.app_id.clone(),
                    sign_key,
                    status: cp.status.clone(),
                    created_at: cp.created_at.clone(),
                })
            })
            .collect();

        Some(projects)
    }

    /// Get a project by 1-based index from the cache.
    pub fn get(index: usize) -> Option<crate::agora_api::BffProject> {
        let projects = Self::load()?;
        if index == 0 || index > projects.len() {
            return None;
        }
        Some(projects[index - 1].clone())
    }
}

/// Format a Unix timestamp (seconds) as "YYYY-MM-DD HH:MM UTC".
fn format_unix_timestamp_hhmm(secs: u64) -> String {
    use crate::agora_api::is_leap_year;

    let days_since_epoch = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;

    let mut remaining_days = days_since_epoch as i64;
    let mut year = 1970i64;
    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }
    let days_in_months: [i64; 12] = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut month = 0;
    for (i, &dim) in days_in_months.iter().enumerate() {
        if remaining_days < dim {
            month = i + 1;
            break;
        }
        remaining_days -= dim;
    }
    let day = remaining_days + 1;
    format!("{:04}-{:02}-{:02} {:02}:{:02} UTC", year, month, day, hours, minutes)
}

/// Persisted auth session at ~/.config/atem/session.json
impl crate::auth::AuthSession {
    /// Session file path: ~/.config/atem/session.json
    pub fn session_path() -> PathBuf {
        AtemConfig::config_dir().join("session.json")
    }

    /// Load saved session from disk. Returns None if not found.
    pub fn load_saved() -> Option<Self> {
        let path = Self::session_path();
        if !path.exists() {
            return None;
        }
        let content = fs::read_to_string(&path).ok()?;
        serde_json::from_str(&content).ok()
    }

    /// Save session to disk.
    pub fn save(&self) -> Result<()> {
        let path = Self::session_path();
        let dir = path.parent().unwrap();
        fs::create_dir_all(dir)?;
        let json = serde_json::to_string_pretty(self)?;
        fs::write(&path, json)?;
        Ok(())
    }

    /// Clear saved session.
    pub fn clear_saved() -> Result<()> {
        let path = Self::session_path();
        if path.exists() {
            fs::remove_file(&path)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Tests that touch ~/.config/atem/active_project.json must hold this lock.
    static ACTIVE_PROJECT_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn default_config_has_none_fields() {
        let config = AtemConfig::default();
        assert!(config.rtm_channel.is_none());
        assert!(config.rtm_account.is_none());
        assert!(config.astation_ws.is_none());
        assert!(config.astation_relay_url.is_none());
        assert!(config.diagram_server_url.is_none());
        assert!(config.bff_url.is_none());
        assert!(config.sso_url.is_none());
    }

    #[test]
    fn config_defaults() {
        let config = AtemConfig::default();
        assert_eq!(config.rtm_channel(), "atem_channel");
        assert_eq!(config.rtm_account(), "atem01");
        assert_eq!(config.astation_ws(), "ws://127.0.0.1:8080/ws");
        assert_eq!(config.astation_relay_url(), "https://station.agora.build");
    }

    #[test]
    fn effective_bff_url_default() {
        let config = AtemConfig::default();
        assert_eq!(
            config.effective_bff_url(),
            "https://agora-cli-bff.staging.la3.agoralab.co"
        );
    }

    #[test]
    fn effective_bff_url_custom() {
        let config = AtemConfig {
            bff_url: Some("https://my-bff.example.com".to_string()),
            ..Default::default()
        };
        assert_eq!(config.effective_bff_url(), "https://my-bff.example.com");
    }

    #[test]
    fn effective_sso_url_default() {
        let config = AtemConfig::default();
        assert_eq!(config.effective_sso_url(), "https://sso.agora.io");
    }

    #[test]
    fn effective_sso_url_custom() {
        let config = AtemConfig {
            sso_url: Some("https://my-sso.example.com".to_string()),
            ..Default::default()
        };
        assert_eq!(config.effective_sso_url(), "https://my-sso.example.com");
    }

    #[test]
    fn display_masked_shows_sso_not_logged_in() {
        let config = AtemConfig {
            rtm_channel: Some("test_channel".to_string()),
            ..Default::default()
        };
        let display = config.display_masked();
        assert!(display.contains("test_channel")); // non-secret shown
        assert!(display.contains("SSO:"));
        assert!(display.contains("not logged in"));
        // No credentials in config anymore
        assert!(!display.contains("customer_id"));
        assert!(!display.contains("customer_secret"));
    }

    #[test]
    fn active_project_round_trip() {
        let _lock = ACTIVE_PROJECT_LOCK.lock().unwrap();
        let proj = ActiveProject {
            app_id: "test_app_id".to_string(),
            app_certificate: "test_cert_value".to_string(),
            name: "Test Project".to_string(),
        };

        // Save and reload through the real path
        let path = ActiveProject::path();
        let backup = path.with_extension("json.bak");
        let had_file = path.exists();
        if had_file {
            let _ = fs::rename(&path, &backup);
        }

        proj.save().unwrap();

        // Verify on-disk format has encrypted certificate (not plaintext)
        let raw = fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("test_cert_value"), "certificate should be encrypted on disk");
        assert!(raw.contains("app_certificate_encrypted"));

        let loaded = ActiveProject::load().unwrap();
        assert_eq!(loaded.app_id, "test_app_id");
        assert_eq!(loaded.app_certificate, "test_cert_value");
        assert_eq!(loaded.name, "Test Project");

        // Restore
        if had_file {
            let _ = fs::rename(&backup, &path);
        } else {
            let _ = fs::remove_file(&path);
        }
    }

    #[test]
    fn active_project_migrates_legacy_plaintext() {
        let _lock = ACTIVE_PROJECT_LOCK.lock().unwrap();
        let path = ActiveProject::path();
        let backup = path.with_extension("json.bak");
        let had_file = path.exists();
        if had_file {
            let _ = fs::rename(&path, &backup);
        }

        // Write legacy plaintext format
        let legacy = serde_json::json!({
            "app_id": "legacy_id",
            "app_certificate": "legacy_cert",
            "name": "Legacy Project"
        });
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, serde_json::to_string_pretty(&legacy).unwrap()).unwrap();

        // Load should succeed and auto-migrate
        let loaded = ActiveProject::load().unwrap();
        assert_eq!(loaded.app_id, "legacy_id");
        assert_eq!(loaded.app_certificate, "legacy_cert");

        // File should now be encrypted
        let raw = fs::read_to_string(&path).unwrap();
        assert!(raw.contains("app_certificate_encrypted"));
        assert!(!raw.contains("\"app_certificate\""));

        if had_file {
            let _ = fs::rename(&backup, &path);
        } else {
            let _ = fs::remove_file(&path);
        }
    }

    #[test]
    fn resolve_app_id_cli_takes_precedence() {
        let result = ActiveProject::resolve_app_id(Some("cli_app_id"));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "cli_app_id");
    }

    #[test]
    fn resolve_app_id_errors_when_nothing_set() {
        let _lock = ACTIVE_PROJECT_LOCK.lock().unwrap();
        // Clear active project (if any) -- save original and restore
        let path = ActiveProject::path();
        let backup = path.with_extension("json.bak");
        let had_file = path.exists();
        if had_file {
            let _ = fs::rename(&path, &backup);
        }

        let result = ActiveProject::resolve_app_id(None);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("No active project"));

        // Restore
        if had_file {
            let _ = fs::rename(&backup, &path);
        }
    }

    #[test]
    fn resolve_app_id_env_var_overrides() {
        let _lock = ACTIVE_PROJECT_LOCK.lock().unwrap();
        // Temporarily back up active project + env
        let path = ActiveProject::path();
        let backup = path.with_extension("json.bak2");
        let had_file = path.exists();
        if had_file {
            let _ = fs::rename(&path, &backup);
        }
        let old_env = std::env::var("AGORA_APP_ID").ok();

        unsafe { std::env::set_var("AGORA_APP_ID", "env_app_id") };
        let result = ActiveProject::resolve_app_id(None);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "env_app_id");

        // Restore
        unsafe {
            match old_env {
                Some(v) => std::env::set_var("AGORA_APP_ID", v),
                None => std::env::remove_var("AGORA_APP_ID"),
            }
        }
        if had_file {
            let _ = fs::rename(&backup, &path);
        }
    }

    #[test]
    fn resolve_app_id_cli_beats_env() {
        let old_env = std::env::var("AGORA_APP_ID").ok();
        unsafe { std::env::set_var("AGORA_APP_ID", "env_app_id") };

        let result = ActiveProject::resolve_app_id(Some("cli_app_id"));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "cli_app_id");

        unsafe {
            match old_env {
                Some(v) => std::env::set_var("AGORA_APP_ID", v),
                None => std::env::remove_var("AGORA_APP_ID"),
            }
        }
    }

    #[test]
    fn resolve_app_certificate_env_var() {
        let _lock = ACTIVE_PROJECT_LOCK.lock().unwrap();
        let path = ActiveProject::path();
        let backup = path.with_extension("json.bak3");
        let had_file = path.exists();
        if had_file {
            let _ = fs::rename(&path, &backup);
        }
        let old_env = std::env::var("AGORA_APP_CERTIFICATE").ok();

        unsafe { std::env::set_var("AGORA_APP_CERTIFICATE", "env_cert") };
        let result = ActiveProject::resolve_app_certificate(None);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "env_cert");

        unsafe {
            match old_env {
                Some(v) => std::env::set_var("AGORA_APP_CERTIFICATE", v),
                None => std::env::remove_var("AGORA_APP_CERTIFICATE"),
            }
        }
        if had_file {
            let _ = fs::rename(&backup, &path);
        }
    }

    #[test]
    fn test_astation_relay_url_default() {
        let config = AtemConfig::default();
        assert_eq!(config.astation_relay_url(), "https://station.agora.build");
    }

    #[test]
    fn test_astation_relay_url_custom() {
        let config = AtemConfig {
            astation_relay_url: Some("https://custom.station.example.com".to_string()),
            ..Default::default()
        };
        assert_eq!(config.astation_relay_url(), "https://custom.station.example.com");
    }

    #[test]
    fn test_display_masked_includes_astation_relay_url() {
        let config = AtemConfig::default();
        let display = config.display_masked();
        assert!(display.contains("astation_relay_url"));
    }

    // ── project cache + crypto tests ────────────────────────────────────

    #[test]
    fn encrypt_decrypt_round_trip() {
        let key = derive_cache_key();
        let plaintext = "my-secret-certificate-abc123";
        let encrypted = encrypt_field(plaintext, &key);
        assert_ne!(encrypted, plaintext);
        let decrypted = decrypt_field(&encrypted, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_decrypt_empty_string() {
        let key = derive_cache_key();
        let encrypted = encrypt_field("", &key);
        let decrypted = decrypt_field(&encrypted, &key).unwrap();
        assert_eq!(decrypted, "");
    }

    #[test]
    fn project_cache_round_trip() {
        use crate::agora_api::BffProject;

        let projects = vec![
            BffProject {
                project_id: "pid1".to_string(),
                name: "Project One".to_string(),
                app_id: "appid1".to_string(),
                sign_key: Some("secret-cert-1".to_string()),
                status: "active".to_string(),
                created_at: "2025-01-01T00:00:00Z".to_string(),
            },
            BffProject {
                project_id: "pid2".to_string(),
                name: "Project Two".to_string(),
                app_id: "appid2".to_string(),
                sign_key: None,
                status: "inactive".to_string(),
                created_at: "2025-01-02T00:00:00Z".to_string(),
            },
        ];

        // Save
        ProjectCache::save(&projects).unwrap();

        // Verify the file exists and sign_key is NOT in plaintext
        let raw = fs::read_to_string(ProjectCache::path()).unwrap();
        assert!(!raw.contains("secret-cert-1"), "sign_key should be encrypted on disk");
        assert!(raw.contains("appid1"), "app_id (non-sensitive) should be readable");

        // Load and verify
        let loaded = ProjectCache::load().expect("cache should load");
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].name, "Project One");
        assert_eq!(loaded[0].sign_key.as_deref(), Some("secret-cert-1"));
        assert!(loaded[1].sign_key.is_none());

        // Also test get-by-index (1-based) on the same data to avoid file races
        let p1 = ProjectCache::get(1).expect("index 1 should exist");
        assert_eq!(p1.name, "Project One");
        assert_eq!(p1.sign_key.as_deref(), Some("secret-cert-1"));

        let p2 = ProjectCache::get(2).expect("index 2 should exist");
        assert_eq!(p2.name, "Project Two");

        // Out of range
        assert!(ProjectCache::get(0).is_none());
        assert!(ProjectCache::get(3).is_none());
    }

    #[test]
    fn format_unix_timestamp_hhmm_known_date() {
        // 1743497400 = 2025-04-01 08:50:00 UTC
        let ts = 1743497400u64;
        let result = format_unix_timestamp_hhmm(ts);
        assert!(result.contains("UTC"), "should contain UTC");
        assert!(result.contains("08:50"), "should contain HH:MM");
        assert!(result.contains("2025-04-01"), "should contain date");
    }
}
