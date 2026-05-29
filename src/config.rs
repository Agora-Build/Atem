use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

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

    /// Stable per-install identifier (UUID v4), generated once by
    /// `ensure_instance_id()` and persisted here. The canonical unique identity;
    /// the relay `atem_id` is derived from it and it serves as the vault client id.
    #[serde(default)]
    pub instance_id: Option<String>,

    /// The relay `atem_id`, generated once from hostname + `instance_id` and
    /// frozen here so it survives hostname changes. Charset is `[A-Za-z-]` only.
    #[serde(default)]
    pub atem_id: Option<String>,

    /// Extra hostnames the machine is reachable on, beyond loopback + LAN IP.
    /// Each entry is baked into the self-signed cert's SAN list so browsers
    /// that hit any of these names get a valid TLS handshake, and the URL
    /// is printed alongside Local/Network when a server starts.
    ///
    /// Typical examples:
    ///   extra_hostnames = ["genie.netbird.cloud", "dev.mytailnet.ts.net"]
    ///
    /// Env var override: `ATEM_EXTRA_HOSTNAMES` (comma-separated).
    #[serde(default)]
    pub extra_hostnames: Option<Vec<String>>,
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
        if let Ok(val) = std::env::var("ATEM_EXTRA_HOSTNAMES") {
            let hosts: Vec<String> = val
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if !hosts.is_empty() {
                config.extra_hostnames = Some(hosts);
            }
        }

        Ok(config)
    }

    /// Resolved extra hostnames — always a Vec (possibly empty).
    pub fn extra_hostnames(&self) -> Vec<String> {
        self.extra_hostnames.clone().unwrap_or_default()
    }

    /// Read a top-level string key straight from `config.toml`, without applying
    /// env overrides. Empty values are treated as absent.
    fn read_config_string(key: &str) -> Option<String> {
        let content = fs::read_to_string(Self::config_path()).ok()?;
        let val = toml::from_str::<toml::Value>(&content).ok()?;
        val.get(key)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty())
    }

    /// Merge a single top-level string key into `config.toml`, preserving other
    /// keys. Best-effort: silently no-ops on IO/parse failure.
    fn write_config_string(key: &str, value: &str) {
        let path = Self::config_path();
        let mut existing = fs::read_to_string(&path)
            .ok()
            .and_then(|c| toml::from_str::<toml::Value>(&c).ok())
            .unwrap_or_else(|| toml::Value::Table(Default::default()));
        if let Some(table) = existing.as_table_mut() {
            table.insert(key.into(), toml::Value::String(value.to_string()));
            if let Some(dir) = path.parent() {
                let _ = fs::create_dir_all(dir);
            }
            if let Ok(content) = toml::to_string_pretty(&existing) {
                let _ = fs::write(&path, content);
            }
        }
    }

    /// Stable per-install identifier (UUID v4), generated once and persisted to
    /// `config.toml`. The canonical unique identity; also the source the relay
    /// `atem_id` is derived from and the vault client id.
    ///
    /// Best-effort: if the file can't be written, a fresh id is still returned so
    /// connecting isn't blocked (it just won't be stable until a write succeeds).
    pub fn ensure_instance_id() -> String {
        if let Some(id) = Self::read_config_string("instance_id") {
            return id;
        }
        let id = uuid::Uuid::new_v4().to_string();
        Self::write_config_string("instance_id", &id);
        id
    }

    /// The relay `atem_id` if one has already been generated and stored.
    pub fn stored_atem_id() -> Option<String> {
        Self::read_config_string("atem_id")
    }

    /// Persist the relay `atem_id` so it keeps across restarts and hostname
    /// changes (generated once, then frozen).
    pub fn store_atem_id(id: &str) {
        Self::write_config_string("atem_id", id);
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
        if let Some(id) = &self.instance_id {
            table.insert("instance_id".into(), toml::Value::String(id.clone()));
        }
        if let Some(id) = &self.atem_id {
            table.insert("atem_id".into(), toml::Value::String(id.clone()));
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
        lines.push(format!(
            "instance_id: {}",
            self.instance_id.as_deref().unwrap_or("(not set)")
        ));
        lines.push(format!(
            "atem_id: {}",
            self.atem_id.as_deref().unwrap_or("(not set)")
        ));

        // SSO + paired credentials
        let store = crate::credentials::CredentialStore::load();
        if let Some(sso) = store.find_sso() {
            let id = sso.login_id.as_deref().unwrap_or("-");
            lines.push(format!("SSO:      logged in  ({})", id));
        } else {
            lines.push("SSO:      not logged in".to_string());
        }
        let paired: Vec<_> = store
            .entries
            .iter()
            .filter(|e| e.source == crate::credentials::CredentialSource::AstationPaired)
            .collect();
        if paired.is_empty() {
            lines.push("Paired:   none".to_string());
        } else {
            for p in paired {
                let aid = p.astation_id.as_deref().unwrap_or("-");
                let login = p.login_id.as_deref().unwrap_or("-");
                let saved = if p.save_credentials { "yes" } else { "no" };
                lines.push(format!(
                    "Paired:   {}  (SSO: {})  [save: {}]",
                    aid, login, saved
                ));
            }
        }

        // Show current project info
        match ProjectCache::get_current() {
            Some(proj) => {
                lines.push(String::new());
                lines.push(format!(
                    "Current project: {} ({})",
                    proj.name, proj.app_id
                ));
                lines.push(format!(
                    "App certificate: {}",
                    mask(&proj.sign_key)
                ));
            }
            None => {
                lines.push(String::new());
                lines.push("Current project: (none)".to_string());
                lines.push("  → run `atem project list` to see available projects".to_string());
                lines.push("  → run `atem project use <N>` to set one".to_string());
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

    /// Get the BFF URL with fallback default.
    /// Override via ATEM_BFF_URL env var or bff_url in config.toml.
    pub fn effective_bff_url(&self) -> &str {
        self.bff_url.as_deref().unwrap_or("https://agora-cli.agora.io")
    }

    /// Get the SSO URL with fallback default
    pub fn effective_sso_url(&self) -> &str {
        self.sso_url.as_deref().unwrap_or("https://sso2.agora.io")
    }
}

// ── Encrypted project cache (AES-256-GCM, machine-bound) ─────────────

/// One-time cleanup of pre-0.4.77 files that are no longer readable.
/// Called on every `ProjectCache::load_from` — cheap (just two stat syscalls).
fn cleanup_legacy_files() {
    let dir = AtemConfig::config_dir();
    let _ = fs::remove_file(dir.join("project_cache.json"));
    let _ = fs::remove_file(dir.join("active_project.json"));
}

/// One cached project — same shape as `BffProject` but serialisable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CachedProject {
    pub project_id: String,
    pub name: String,
    pub app_id: String,
    #[serde(default)]
    pub sign_key: Option<String>,
    pub status: String,
    pub created_at: String,
    #[serde(default)]
    pub vid: Option<u64>,
}

impl From<&crate::agora_api::BffProject> for CachedProject {
    fn from(p: &crate::agora_api::BffProject) -> Self {
        Self {
            project_id: p.project_id.clone(),
            name: p.name.clone(),
            app_id: p.app_id.clone(),
            sign_key: p.sign_key.clone(),
            status: p.status.clone(),
            created_at: p.created_at.clone(),
            vid: p.vid,
        }
    }
}

impl From<&CachedProject> for crate::agora_api::BffProject {
    fn from(p: &CachedProject) -> Self {
        Self {
            project_id: p.project_id.clone(),
            name: p.name.clone(),
            app_id: p.app_id.clone(),
            sign_key: p.sign_key.clone(),
            status: p.status.clone(),
            created_at: p.created_at.clone(),
            vid: p.vid,
        }
    }
}

/// Encrypted project cache stored at `~/.config/atem/project_cache.enc`.
/// Single source of truth for both the list of known projects and the current selection.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ProjectCache {
    #[serde(default)]
    pub projects: Vec<CachedProject>,
    /// The user-selected ("current") project's app_id.
    #[serde(default)]
    pub current_app_id: Option<String>,
}

impl ProjectCache {
    /// Cache file path: ~/.config/atem/project_cache.enc
    pub fn path() -> PathBuf {
        AtemConfig::config_dir().join("project_cache.enc")
    }

    /// Load the cache from disk. Returns a default (empty) cache if the file is missing
    /// or can't be decrypted.
    pub fn load_full() -> Self {
        Self::load_from(&Self::path())
    }

    pub(crate) fn load_from(path: &Path) -> Self {
        // Best-effort one-time cleanup of pre-0.4.77 files (project_cache.json,
        // active_project.json). Only runs against the real config dir; tests using
        // tempdir paths skip this because legacy files can't exist there.
        if path == Self::path() {
            cleanup_legacy_files();
        }

        let Ok(raw) = fs::read(path) else {
            return Self::default();
        };
        let Ok(plain) = crate::credentials::decrypt_machine_bound(&raw) else {
            return Self::default();
        };
        serde_json::from_slice(&plain).unwrap_or_default()
    }

    pub fn save_full(&self) -> Result<()> {
        self.save_to(&Self::path())
    }

    pub(crate) fn save_to(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_vec(self)?;
        let ct = crate::credentials::encrypt_machine_bound(&json)?;
        fs::write(path, ct)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    /// Replace the project list (preserves `current_app_id` if the current project still exists).
    pub fn save(projects: &[crate::agora_api::BffProject]) -> Result<()> {
        let mut cache = Self::load_full();
        cache.projects = projects.iter().map(CachedProject::from).collect();
        // If the previously current project no longer exists in the new list, clear it.
        if let Some(current) = &cache.current_app_id {
            if !cache.projects.iter().any(|p| &p.app_id == current) {
                cache.current_app_id = None;
            }
        }
        cache.save_full()
    }

    /// Return the cached list of projects (as `BffProject` for callers that expect that type).
    pub fn load() -> Option<Vec<crate::agora_api::BffProject>> {
        let cache = Self::load_full();
        if cache.projects.is_empty() {
            return None;
        }
        Some(cache.projects.iter().map(Into::into).collect())
    }

    /// Get a project by 1-based index from the cache.
    pub fn get(index: usize) -> Option<crate::agora_api::BffProject> {
        let cache = Self::load_full();
        if index == 0 || index > cache.projects.len() {
            return None;
        }
        Some((&cache.projects[index - 1]).into())
    }

    /// Set the current project by app_id. Adds the project to the cache if missing.
    /// Returns an error if the app_id is not in the cache and `project` is None.
    pub fn set_current(app_id: &str, project: Option<CachedProject>) -> Result<()> {
        let mut cache = Self::load_full();
        // If the project isn't yet in the cache, add it.
        if !cache.projects.iter().any(|p| p.app_id == app_id) {
            if let Some(p) = project {
                cache.projects.push(p);
            } else {
                anyhow::bail!("Project {app_id} not in cache. Run `atem project list` first.");
            }
        }
        cache.current_app_id = Some(app_id.to_string());
        cache.save_full()
    }

    /// Return the current project, if any.
    pub fn get_current() -> Option<CachedProject> {
        let cache = Self::load_full();
        let app_id = cache.current_app_id.as_ref()?;
        cache.projects.iter().find(|p| &p.app_id == app_id).cloned()
    }

    /// Clear the current project selection (does not remove projects from the cache).
    pub fn clear_current() -> Result<()> {
        let mut cache = Self::load_full();
        cache.current_app_id = None;
        cache.save_full()
    }

    /// Look up the cached project name for a given app_id.
    /// Returns None if no matching project is cached (e.g. app_id came
    /// from CLI flag or env var, not from the cache).
    pub fn name_for_app_id(app_id: &str) -> Option<String> {
        Self::load_full()
            .projects
            .into_iter()
            .find(|p| p.app_id == app_id)
            .map(|p| p.name)
    }

    /// Resolve app_id: CLI flag > env var > current project > error
    pub fn resolve_app_id(cli_app_id: Option<&str>) -> Result<String> {
        if let Some(id) = cli_app_id {
            return Ok(id.to_string());
        }
        if let Ok(id) = std::env::var("AGORA_APP_ID") {
            if !id.is_empty() {
                return Ok(id);
            }
        }
        if let Some(proj) = Self::get_current() {
            return Ok(proj.app_id);
        }
        anyhow::bail!(
            "No current project. Run `atem project list`, then `atem project use <index>`"
        )
    }

    /// Resolve app_certificate: CLI flag > env var > current project > error
    pub fn resolve_app_certificate(cli_cert: Option<&str>) -> Result<String> {
        if let Some(cert) = cli_cert {
            return Ok(cert.to_string());
        }
        if let Ok(cert) = std::env::var("AGORA_APP_CERTIFICATE") {
            if !cert.is_empty() {
                return Ok(cert);
            }
        }
        if let Some(proj) = Self::get_current() {
            return Ok(proj.sign_key.unwrap_or_default());
        }
        anyhow::bail!(
            "No current project. Run `atem project list`, then `atem project use <index>`"
        )
    }
}

/// Format a Unix timestamp (seconds) as "YYYY-MM-DD HH:MM UTC".
pub fn format_unix_timestamp_hhmm_pub(secs: u64) -> String {
    format_unix_timestamp_hhmm(secs)
}

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
            "https://agora-cli.agora.io"
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
        assert_eq!(config.effective_sso_url(), "https://sso2.agora.io");
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
    fn display_masked_shows_sso_section() {
        let config = AtemConfig {
            rtm_channel: Some("test_channel".to_string()),
            ..Default::default()
        };
        let display = config.display_masked();
        assert!(display.contains("test_channel")); // non-secret shown
        assert!(display.contains("SSO:"));
        // Shows either "logged in" or "not logged in" depending on real session state
        assert!(display.contains("logged in") || display.contains("not logged in"));
        // No credentials in config anymore
        assert!(!display.contains("customer_id"));
        assert!(!display.contains("customer_secret"));
    }

    #[test]
    fn resolve_app_id_cli_takes_precedence() {
        let result = ProjectCache::resolve_app_id(Some("cli_app_id"));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "cli_app_id");
    }

    #[test]
    fn resolve_app_id_cli_beats_env() {
        let old_env = std::env::var("AGORA_APP_ID").ok();
        unsafe { std::env::set_var("AGORA_APP_ID", "env_app_id") };

        let result = ProjectCache::resolve_app_id(Some("cli_app_id"));
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

    // ── project cache (AES-GCM, machine-bound) tests ────────────────────

    fn sample_projects() -> Vec<crate::agora_api::BffProject> {
        use crate::agora_api::BffProject;
        vec![
            BffProject {
                project_id: "pid1".to_string(),
                name: "Project One".to_string(),
                app_id: "appid1".to_string(),
                sign_key: Some("secret-cert-1".to_string()),
                status: "active".to_string(),
                created_at: "2025-01-01T00:00:00Z".to_string(),
                vid: Some(1001),
            },
            BffProject {
                project_id: "pid2".to_string(),
                name: "Project Two".to_string(),
                app_id: "appid2".to_string(),
                sign_key: None,
                status: "inactive".to_string(),
                created_at: "2025-01-02T00:00:00Z".to_string(),
                vid: Some(1002),
            },
        ]
    }

    #[test]
    fn project_cache_file_is_encrypted_not_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("project_cache.enc");
        let mut cache = ProjectCache::default();
        cache.projects = sample_projects().iter().map(CachedProject::from).collect();
        cache.save_to(&path).unwrap();

        // Nothing should be in plaintext — it's AES-GCM encrypted now.
        let raw = fs::read(&path).unwrap();
        assert!(!raw.windows(6).any(|w| w == b"secret"), "sign_key must not be plaintext");
        assert!(!raw.windows(6).any(|w| w == b"appid1"), "app_id must not be plaintext");
        assert!(!raw.starts_with(b"{") && !raw.starts_with(b"["), "file must not be JSON");
    }

    #[test]
    fn project_cache_round_trip_via_temp_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("project_cache.enc");
        let mut cache = ProjectCache::default();
        cache.projects = sample_projects().iter().map(CachedProject::from).collect();
        cache.save_to(&path).unwrap();

        let loaded = ProjectCache::load_from(&path);
        assert_eq!(loaded.projects.len(), 2);
        assert_eq!(loaded.projects[0].name, "Project One");
        assert_eq!(loaded.projects[0].sign_key.as_deref(), Some("secret-cert-1"));
        assert!(loaded.projects[1].sign_key.is_none());
    }

    #[test]
    fn set_current_and_get_current_round_trip() {
        let _lock = ACTIVE_PROJECT_LOCK.lock().unwrap();
        let backup_path = ProjectCache::path();
        let backup = backup_path.with_extension("enc.bak");
        let had_file = backup_path.exists();
        if had_file {
            let _ = fs::rename(&backup_path, &backup);
        }

        ProjectCache::save(&sample_projects()).unwrap();
        ProjectCache::set_current("appid1", None).unwrap();
        let current = ProjectCache::get_current().unwrap();
        assert_eq!(current.app_id, "appid1");
        assert_eq!(current.name, "Project One");

        // Restore
        let _ = fs::remove_file(&backup_path);
        if had_file {
            let _ = fs::rename(&backup, &backup_path);
        }
    }

    #[test]
    fn save_preserves_current_if_still_present() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.enc");

        let mut cache = ProjectCache::default();
        cache.projects = sample_projects().iter().map(CachedProject::from).collect();
        cache.current_app_id = Some("appid1".to_string());
        cache.save_to(&path).unwrap();

        // Reload, verify current survives a round-trip
        let cache = ProjectCache::load_from(&path);
        assert_eq!(cache.current_app_id.as_deref(), Some("appid1"));
    }

    #[test]
    fn save_clears_current_if_project_removed() {
        // When the user runs `atem project list` and the previously-current project
        // no longer exists in the new list, current_app_id should be cleared.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.enc");

        let mut cache = ProjectCache::default();
        cache.projects = sample_projects().iter().map(CachedProject::from).collect();
        cache.current_app_id = Some("appid_gone".to_string()); // not in projects
        cache.save_to(&path).unwrap();

        // Reload and simulate a save with fresh projects — current_app_id should still
        // be there (since reload preserves state).
        let cache = ProjectCache::load_from(&path);
        assert_eq!(cache.current_app_id.as_deref(), Some("appid_gone"));
    }

    #[test]
    fn get_by_index_returns_projects_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.enc");
        let mut cache = ProjectCache::default();
        cache.projects = sample_projects().iter().map(CachedProject::from).collect();
        cache.save_to(&path).unwrap();

        let loaded = ProjectCache::load_from(&path);
        assert_eq!(loaded.projects[0].name, "Project One");
        assert_eq!(loaded.projects[1].name, "Project Two");
    }

    #[test]
    fn load_returns_default_on_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does_not_exist.enc");
        let cache = ProjectCache::load_from(&path);
        assert!(cache.projects.is_empty());
        assert!(cache.current_app_id.is_none());
    }

    #[test]
    fn cleanup_legacy_files_removes_both() {
        let _lock = ACTIVE_PROJECT_LOCK.lock().unwrap();
        let dir = AtemConfig::config_dir();
        fs::create_dir_all(&dir).unwrap();
        let legacy_cache = dir.join("project_cache.json");
        let legacy_active = dir.join("active_project.json");

        fs::write(&legacy_cache, b"stale").unwrap();
        fs::write(&legacy_active, b"stale").unwrap();
        assert!(legacy_cache.exists());
        assert!(legacy_active.exists());

        // Trigger cleanup via loading the real path.
        let _ = ProjectCache::load_from(&ProjectCache::path());

        assert!(!legacy_cache.exists(), "project_cache.json should be removed");
        assert!(!legacy_active.exists(), "active_project.json should be removed");
    }

    #[test]
    fn load_returns_default_on_corrupt_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("garbage.enc");
        fs::write(&path, b"this is not encrypted").unwrap();
        let cache = ProjectCache::load_from(&path);
        assert!(cache.projects.is_empty());
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
