use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, Nonce};
use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;

/// Where the active credentials were loaded from.
#[derive(Debug, Clone, PartialEq, Default)]
pub enum CredentialSource {
    #[default]
    None,
    ConfigFile,
    EnvVar,
    Astation,
}

/// Main Atem configuration loaded from ~/.config/atem/config.toml + env vars
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct AtemConfig {
    pub customer_id: Option<String>,
    pub customer_secret: Option<String>,
    pub rtm_channel: Option<String>,
    pub rtm_account: Option<String>,
    pub astation_ws: Option<String>,
    pub astation_relay_url: Option<String>,
    pub astation_relay_code: Option<String>,

    /// Tracks where credentials were loaded from (not serialized).
    #[serde(skip)]
    pub credential_source: CredentialSource,
}

/// Active project state persisted to ~/.config/atem/active_project.json
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveProject {
    pub app_id: String,
    pub app_certificate: String,
    pub name: String,
}

impl AtemConfig {
    /// Load config from file + encrypted credentials + env var overrides.
    ///
    /// Credentials come from credentials.enc (encrypted) or env vars only.
    /// config.toml holds non-sensitive settings; any legacy plaintext credentials are ignored.
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

        // Never read credentials from config.toml — they belong in credentials.enc
        config.customer_id = None;
        config.customer_secret = None;

        // Load credentials from encrypted store
        if let Some((cid, csecret)) = CredentialStore::load() {
            config.customer_id = Some(cid);
            config.customer_secret = Some(csecret);
            config.credential_source = CredentialSource::ConfigFile;
        }

        // Env var overrides
        let env_id = std::env::var("AGORA_CUSTOMER_ID").ok();
        let env_secret = std::env::var("AGORA_CUSTOMER_SECRET").ok();
        if env_id.is_some() || env_secret.is_some() {
            if let Some(val) = env_id {
                config.customer_id = Some(val);
            }
            if let Some(val) = env_secret {
                config.customer_secret = Some(val);
            }
            config.credential_source = CredentialSource::EnvVar;
        }
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

        Ok(config)
    }

    /// Persist the config to disk.
    ///
    /// - Credentials → encrypted `~/.config/atem/credentials.enc` (AES-256-GCM)
    /// - Non-sensitive settings → `~/.config/atem/config.toml` (plaintext)
    pub fn save_to_disk(&self) -> Result<()> {
        let path = Self::config_path();
        let dir = path.parent().unwrap();
        fs::create_dir_all(dir)
            .with_context(|| format!("Failed to create config dir: {}", dir.display()))?;

        // Save credentials to encrypted store
        if let (Some(cid), Some(cs)) = (&self.customer_id, &self.customer_secret) {
            CredentialStore::save(cid, cs)?;
        }

        // Load existing config.toml so we don't clobber other keys
        let mut existing = if path.exists() {
            let content = fs::read_to_string(&path)?;
            toml::from_str::<toml::Value>(&content).unwrap_or(toml::Value::Table(Default::default()))
        } else {
            toml::Value::Table(Default::default())
        };

        let table = existing.as_table_mut().expect("config is a TOML table");

        // Remove plaintext credentials from config.toml (migrated to credentials.enc)
        table.remove("customer_id");
        table.remove("customer_secret");

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

        let content = toml::to_string_pretty(&existing)
            .with_context(|| "Failed to serialize config")?;
        fs::write(&path, content)
            .with_context(|| format!("Failed to write config file: {}", path.display()))?;
        Ok(())
    }

    /// Get the config directory path: ~/.config/atem/
    pub fn config_dir() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
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
                Some(s) if s.len() > 4 => format!("{}...{}", &s[..2], &s[s.len() - 2..]),
                Some(s) if !s.is_empty() => "****".to_string(),
                _ => "(not set)".to_string(),
            }
        };

        let mut lines = Vec::new();
        lines.push(format!("Config file: {}", Self::config_path().display()));
        lines.push(format!("customer_id: {}", mask(&self.customer_id)));
        lines.push(format!("customer_secret: {}", mask(&self.customer_secret)));
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
                lines.push("Active project: (none)".to_string());
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
        serde_json::from_str(&content).ok()
    }

    /// Save active project to disk.
    pub fn save(&self) -> Result<()> {
        let path = Self::path();
        let dir = path.parent().unwrap();
        fs::create_dir_all(dir)?;
        let json = serde_json::to_string_pretty(self)?;
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

// ── Encrypted credential store (AES-256-GCM, machine-bound) ─────────

/// Encrypted credentials stored at ~/.config/atem/credentials.enc
///
/// File format: nonce (12 bytes) || ciphertext || auth tag (16 bytes)
/// Key: HMAC-SHA256(salt="atem-credentials-v1", machine_id)
/// Matches Astation's CredentialManager pattern (AES-GCM + hardware-bound key).
pub struct CredentialStore;

#[derive(Serialize, Deserialize)]
struct StoredCredentials {
    customer_id: String,
    customer_secret: String,
}

impl CredentialStore {
    /// Encrypted credentials file path: ~/.config/atem/credentials.enc
    pub fn path() -> PathBuf {
        AtemConfig::config_dir().join("credentials.enc")
    }

    /// Derive a 32-byte AES-256 key from the machine ID.
    fn derive_key() -> [u8; 32] {
        type HmacSha256 = Hmac<Sha256>;
        let machine_id = get_machine_id();
        let mut mac = <HmacSha256 as Mac>::new_from_slice(b"atem-credentials-v1")
            .expect("HMAC accepts any key size");
        mac.update(machine_id.as_bytes());
        mac.finalize().into_bytes().into()
    }

    /// Save credentials to encrypted file.
    pub fn save(customer_id: &str, customer_secret: &str) -> Result<()> {
        let path = Self::path();
        let dir = path.parent().unwrap();
        fs::create_dir_all(dir)?;

        let creds = StoredCredentials {
            customer_id: customer_id.to_string(),
            customer_secret: customer_secret.to_string(),
        };
        let plaintext = serde_json::to_vec(&creds)?;

        let key = Self::derive_key();
        let cipher = <Aes256Gcm as aes_gcm::KeyInit>::new((&key).into());

        // Generate random 96-bit nonce
        let mut nonce_bytes = [0u8; 12];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::<Aes256Gcm>::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

        // Write: nonce (12) || ciphertext+tag
        let mut combined = Vec::with_capacity(12 + ciphertext.len());
        combined.extend_from_slice(&nonce_bytes);
        combined.extend_from_slice(&ciphertext);
        fs::write(&path, &combined)?;

        Ok(())
    }

    /// Load and decrypt credentials. Returns None on any failure.
    pub fn load() -> Option<(String, String)> {
        let path = Self::path();
        let combined = fs::read(&path).ok()?;

        if combined.len() < 12 + 16 {
            // Too short: need at least nonce (12) + tag (16)
            return None;
        }

        let (nonce_bytes, ciphertext) = combined.split_at(12);
        let nonce = Nonce::<Aes256Gcm>::from_slice(nonce_bytes);

        let key = Self::derive_key();
        let cipher = <Aes256Gcm as aes_gcm::KeyInit>::new((&key).into());

        let plaintext = cipher.decrypt(nonce, ciphertext).ok()?;
        let creds: StoredCredentials = serde_json::from_slice(&plaintext).ok()?;

        Some((creds.customer_id, creds.customer_secret))
    }

    /// Delete the encrypted credential file.
    pub fn delete() -> Result<()> {
        let path = Self::path();
        if path.exists() {
            fs::remove_file(&path)?;
        }
        Ok(())
    }
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
    name: String,
    vendor_key: String,
    sign_key_encrypted: String,
    id: String,
    status: i32,
    created: u64,
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
    pub fn save(projects: &[crate::agora_api::AgoraApiProject]) -> Result<()> {
        let key = derive_cache_key();
        let cached: Vec<CachedProject> = projects
            .iter()
            .map(|p| CachedProject {
                name: p.name.clone(),
                vendor_key: p.vendor_key.clone(),
                sign_key_encrypted: encrypt_field(&p.sign_key, &key),
                id: p.id.clone(),
                status: p.status,
                created: p.created,
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
    pub fn load() -> Option<Vec<crate::agora_api::AgoraApiProject>> {
        let path = Self::path();
        if !path.exists() {
            return None;
        }
        let content = fs::read_to_string(&path).ok()?;
        let cache: ProjectCache = serde_json::from_str(&content).ok()?;
        let key = derive_cache_key();

        let projects: Vec<crate::agora_api::AgoraApiProject> = cache
            .projects
            .iter()
            .filter_map(|cp| {
                let sign_key = decrypt_field(&cp.sign_key_encrypted, &key).ok()?;
                Some(crate::agora_api::AgoraApiProject {
                    id: cp.id.clone(),
                    name: cp.name.clone(),
                    vendor_key: cp.vendor_key.clone(),
                    sign_key,
                    recording_server: None,
                    status: cp.status,
                    created: cp.created,
                })
            })
            .collect();

        Some(projects)
    }

    /// Get a project by 1-based index from the cache.
    pub fn get(index: usize) -> Option<crate::agora_api::AgoraApiProject> {
        let projects = Self::load()?;
        if index == 0 || index > projects.len() {
            return None;
        }
        Some(projects[index - 1].clone())
    }
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

    #[test]
    fn default_config_has_none_fields() {
        let config = AtemConfig::default();
        assert!(config.customer_id.is_none());
        assert!(config.customer_secret.is_none());
        assert!(config.rtm_channel.is_none());
        assert!(config.rtm_account.is_none());
        assert!(config.astation_ws.is_none());
        assert!(config.astation_relay_url.is_none());
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
    fn toml_parsing() {
        let toml_str = r#"
            customer_id = "test_id"
            customer_secret = "test_secret"
            rtm_channel = "my_channel"
        "#;
        let config: AtemConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.customer_id.as_deref(), Some("test_id"));
        assert_eq!(config.customer_secret.as_deref(), Some("test_secret"));
        assert_eq!(config.rtm_channel(), "my_channel");
        assert_eq!(config.rtm_account(), "atem01"); // default fallback
    }

    #[test]
    fn display_masked_hides_secrets() {
        let config = AtemConfig {
            customer_id: Some("abcdef123456".to_string()),
            customer_secret: Some("secret_key_here".to_string()),
            rtm_channel: Some("test_channel".to_string()),
            ..Default::default()
        };
        let display = config.display_masked();
        assert!(display.contains("ab...56")); // customer_id masked
        assert!(display.contains("se...re")); // customer_secret masked
        assert!(display.contains("test_channel")); // non-secret shown
        assert!(!display.contains("abcdef123456")); // full value NOT shown
        assert!(!display.contains("secret_key_here")); // full value NOT shown
    }

    #[test]
    fn active_project_round_trip() {
        // Use a temp directory to avoid polluting real config
        let tmp = std::env::temp_dir().join("atem_test_active_project");
        let _ = fs::remove_file(&tmp);

        let proj = ActiveProject {
            app_id: "test_app_id".to_string(),
            app_certificate: "test_cert".to_string(),
            name: "Test Project".to_string(),
        };

        let json = serde_json::to_string_pretty(&proj).unwrap();
        fs::write(&tmp, &json).unwrap();

        let content = fs::read_to_string(&tmp).unwrap();
        let loaded: ActiveProject = serde_json::from_str(&content).unwrap();

        assert_eq!(loaded.app_id, "test_app_id");
        assert_eq!(loaded.app_certificate, "test_cert");
        assert_eq!(loaded.name, "Test Project");

        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn resolve_app_id_cli_takes_precedence() {
        let result = ActiveProject::resolve_app_id(Some("cli_app_id"));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "cli_app_id");
    }

    #[test]
    fn resolve_app_id_errors_when_nothing_set() {
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

    // ── credential store tests ──────────────────────────────────────────

    /// Helper to test AES-GCM encryption directly (avoids shared file conflicts).
    fn test_encrypt_decrypt_credentials(cid: &str, csecret: &str) {
        let key = CredentialStore::derive_key();
        let cipher = <Aes256Gcm as aes_gcm::KeyInit>::new((&key).into());

        let creds = super::StoredCredentials {
            customer_id: cid.to_string(),
            customer_secret: csecret.to_string(),
        };
        let plaintext = serde_json::to_vec(&creds).unwrap();

        let mut nonce_bytes = [0u8; 12];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = aes_gcm::aead::Nonce::<Aes256Gcm>::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();

        // Verify ciphertext doesn't contain plaintext
        let ct_str = String::from_utf8_lossy(&ciphertext);
        assert!(!ct_str.contains(cid));
        assert!(!ct_str.contains(csecret));

        // Decrypt
        let decrypted = cipher.decrypt(nonce, ciphertext.as_ref()).unwrap();
        let loaded: super::StoredCredentials = serde_json::from_slice(&decrypted).unwrap();
        assert_eq!(loaded.customer_id, cid);
        assert_eq!(loaded.customer_secret, csecret);
    }

    #[test]
    fn credential_store_encrypt_decrypt() {
        test_encrypt_decrypt_credentials("test-cid-abc123", "test-secret-xyz");
    }

    #[test]
    fn credential_store_file_round_trip() {
        // Use a temp file to avoid races with other tests
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();

        let key = CredentialStore::derive_key();
        let cipher = <Aes256Gcm as aes_gcm::KeyInit>::new((&key).into());

        let creds = super::StoredCredentials {
            customer_id: "file-test-id".to_string(),
            customer_secret: "file-test-secret".to_string(),
        };
        let plaintext = serde_json::to_vec(&creds).unwrap();

        let mut nonce_bytes = [0u8; 12];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = aes_gcm::aead::Nonce::<Aes256Gcm>::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();

        // Write combined: nonce || ciphertext+tag
        let mut combined = Vec::new();
        combined.extend_from_slice(&nonce_bytes);
        combined.extend_from_slice(&ciphertext);
        fs::write(&path, &combined).unwrap();

        // Verify file is not readable as plaintext
        let raw_bytes = fs::read(&path).unwrap();
        let raw = String::from_utf8_lossy(&raw_bytes);
        assert!(!raw.contains("file-test-id"));

        // Read back and decrypt
        let data = fs::read(&path).unwrap();
        let (n, ct) = data.split_at(12);
        let decrypted = cipher.decrypt(
            aes_gcm::aead::Nonce::<Aes256Gcm>::from_slice(n),
            ct,
        ).unwrap();
        let loaded: super::StoredCredentials = serde_json::from_slice(&decrypted).unwrap();
        assert_eq!(loaded.customer_id, "file-test-id");
        assert_eq!(loaded.customer_secret, "file-test-secret");
    }

    #[test]
    fn credential_store_tampered_data_fails() {
        let key = CredentialStore::derive_key();
        let cipher = <Aes256Gcm as aes_gcm::KeyInit>::new((&key).into());

        let plaintext = b"test data";
        let mut nonce_bytes = [0u8; 12];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = aes_gcm::aead::Nonce::<Aes256Gcm>::from_slice(&nonce_bytes);
        let mut ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();

        // Tamper: flip a byte
        if !ciphertext.is_empty() {
            ciphertext[0] ^= 0xFF;
        }

        // Decryption must fail (AES-GCM auth tag mismatch)
        assert!(cipher.decrypt(nonce, ciphertext.as_ref()).is_err());
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
        use crate::agora_api::AgoraApiProject;

        let projects = vec![
            AgoraApiProject {
                id: "id1".to_string(),
                name: "Project One".to_string(),
                vendor_key: "appid1".to_string(),
                sign_key: "secret-cert-1".to_string(),
                recording_server: None,
                status: 1,
                created: 1700000000,
            },
            AgoraApiProject {
                id: "id2".to_string(),
                name: "Project Two".to_string(),
                vendor_key: "appid2".to_string(),
                sign_key: "".to_string(),
                recording_server: None,
                status: 0,
                created: 1700000001,
            },
        ];

        // Save
        ProjectCache::save(&projects).unwrap();

        // Verify the file exists and sign_key is NOT in plaintext
        let raw = fs::read_to_string(ProjectCache::path()).unwrap();
        assert!(!raw.contains("secret-cert-1"), "sign_key should be encrypted on disk");
        assert!(raw.contains("appid1"), "vendor_key (non-sensitive) should be readable");

        // Load and verify
        let loaded = ProjectCache::load().expect("cache should load");
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].name, "Project One");
        assert_eq!(loaded[0].sign_key, "secret-cert-1");
        assert_eq!(loaded[1].sign_key, "");

        // Also test get-by-index (1-based) on the same data to avoid file races
        let p1 = ProjectCache::get(1).expect("index 1 should exist");
        assert_eq!(p1.name, "Project One");
        assert_eq!(p1.sign_key, "secret-cert-1");

        let p2 = ProjectCache::get(2).expect("index 2 should exist");
        assert_eq!(p2.name, "Project Two");

        // Out of range
        assert!(ProjectCache::get(0).is_none());
        assert!(ProjectCache::get(3).is_none());
    }
}
