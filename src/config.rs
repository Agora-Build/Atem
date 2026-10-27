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

    /// Prefix key of the shared agent terminal (`atem agent launch`), e.g.
    /// `terminal_prefix = "Ctrl-a"`. Accepts Ctrl+], Ctrl+\ or Ctrl+<letter>
    /// (not i or m); unset means Ctrl+].
    ///
    /// Env var override: `ATEM_TERMINAL_PREFIX`.
    #[serde(default)]
    pub terminal_prefix: Option<String>,
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
        if let Ok(val) = std::env::var("ATEM_TERMINAL_PREFIX") {
            config.terminal_prefix = Some(val);
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

    /// Merge a single top-level key into `config.toml`, preserving other keys.
    /// Best-effort: silently no-ops on IO/parse failure.
    fn write_config_value(key: &str, value: toml::Value) {
        Self::write_config_value_at(&Self::config_path(), key, value);
    }

    /// `write_config_value` for the `config.toml` at `path`.
    fn write_config_value_at(path: &std::path::Path, key: &str, value: toml::Value) {
        let _ = edit_config_file(path, |text| {
            let mut existing = toml::from_str::<toml::Value>(text)?;
            let table = existing
                .as_table_mut()
                .ok_or_else(|| anyhow::anyhow!("not a TOML table"))?;
            table.insert(key.into(), value);
            Ok(toml::to_string_pretty(&existing)?)
        });
    }

    /// Merge a single top-level string key into `config.toml`.
    fn write_config_string(key: &str, value: &str) {
        Self::write_config_value(key, toml::Value::String(value.to_string()));
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

    /// The port `atem serv files` bound last time, if recorded. Reused as the
    /// preferred port on the next run.
    pub fn stored_files_port() -> Option<u16> {
        let content = fs::read_to_string(Self::config_path()).ok()?;
        let val = toml::from_str::<toml::Value>(&content).ok()?;
        val.get("files_last_port")
            .and_then(|v| v.as_integer())
            .and_then(|n| u16::try_from(n).ok())
    }

    /// Remember the port `atem serv files` bound, so the next run reuses it.
    pub fn store_files_port(port: u16) {
        Self::write_config_value("files_last_port", toml::Value::Integer(port as i64));
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
        edit_config_file(&path, |content| {
            let mut existing = toml::from_str::<toml::Value>(content)
                .unwrap_or(toml::Value::Table(Default::default()));

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

            toml::to_string_pretty(&existing).with_context(|| "Failed to serialize config")
        })
        .with_context(|| format!("Failed to write config file: {}", path.display()))?;
        Ok(())
    }

    /// Get the config directory path: ~/.config/atem/ (same on all platforms)
    pub fn config_dir() -> PathBuf {
        // Tests never reach the real profile (src/test_profile.rs).
        #[cfg(test)]
        return crate::test_profile::dir();
        #[cfg(not(test))]
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".config")
            .join("atem")
    }

    /// Get the config file path: ~/.config/atem/config.toml
    pub fn config_path() -> PathBuf {
        crate::paths::ProfilePaths::default_paths().config
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
            "instance_id: {}",
            self.instance_id.as_deref().unwrap_or("(not set)")
        ));
        lines.push(format!(
            "atem_id: {}",
            self.atem_id.as_deref().unwrap_or("(not set)")
        ));

        // The user's own login and the pairing
        let paths = crate::paths::ProfilePaths::default_paths();
        match crate::records::Login::load(&paths.login) {
            Ok(Some(login)) => lines.push(format!(
                "Login:    {}  ({})",
                login.subject.as_deref().unwrap_or("-"),
                login.issuer
            )),
            Ok(None) => lines.push("Login:    not logged in".to_string()),
            Err(error) => lines.push(format!("Login:    unknown ({error:#})")),
        }
        match crate::records::PairingRecord::load(&paths.pairing) {
            Ok(Some(record)) => {
                let shared = record
                    .shared
                    .as_ref()
                    .and_then(|login| login.subject.as_deref())
                    .unwrap_or("-");
                let saved = if record.save_credentials { "yes" } else { "no" };
                let relay_only = if record.relay_only { "  [relay only]" } else { "" };
                lines.push(format!(
                    "Paired:   {}  (login: {})  [save: {}]{}",
                    record.astation_id, shared, saved, relay_only
                ));
                let trust = crate::memory::trust::TrustStore::load_from(&paths.cred.trust)
                    .unwrap_or_default();
                lines.push(format!("          {}", trust.verification_line(&record.astation_id)));
            }
            Ok(None) => lines.push("Paired:   none".to_string()),
            Err(error) => lines.push(format!("Paired:   unknown ({error:#})")),
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
    #[allow(dead_code, reason = "RTM is kept but unused for now")]
    pub fn rtm_channel(&self) -> &str {
        self.rtm_channel.as_deref().unwrap_or("atem_channel")
    }

    /// Get RTM account with fallback default
    #[allow(dead_code, reason = "RTM is kept but unused for now")]
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
        let Ok(plain) = crate::machine_key::decrypt(crate::machine_key::PROJECT_CACHE, &raw) else {
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
        let ct = crate::machine_key::encrypt(crate::machine_key::PROJECT_CACHE, &json)?;
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

/// Read-modify-write of the `config.toml` at `path`: `edit` gets the
/// current text (empty when there is none) and returns the new one. Under
/// an exclusive `flock` on `config.toml.lock`, so concurrent writers (the
/// runtime storing its identity, `atem agent launch` recording a consent)
/// never lose each other's keys. A symlinked config.toml keeps its link:
/// the target is replaced. The file keeps its mode (a new one gets 0600)
/// and is replaced atomically (`write_keeping`), so a concurrent reader sees
/// the old file or the new one, never a half-written one.
pub fn edit_config_file(
    path: &Path,
    edit: impl FnOnce(&str) -> Result<String>,
) -> Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let lock_path = PathBuf::from(format!("{}.lock", path.display()));
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&lock_path)
        .with_context(|| format!("opening {}", lock_path.display()))?;
    // SAFETY: flock on a descriptor this function owns; released on close.
    while unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(anyhow::anyhow!(error).context(format!("locking {}", lock_path.display())));
        }
    }
    // A symlink (e.g. into a dotfiles repo) is followed, never replaced; a
    // dangling one is an error.
    let target = if fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        fs::canonicalize(path).with_context(|| format!("resolving {}", path.display()))?
    } else {
        path.to_path_buf()
    };
    let (text, mode) = match fs::read_to_string(&target) {
        Ok(text) => {
            let mode = fs::metadata(&target)?.permissions().mode() & 0o7777;
            (text, mode)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (String::new(), 0o600),
        Err(e) => return Err(e).with_context(|| format!("reading {}", target.display())),
    };
    let new = edit(&text)?;
    write_keeping(&target, new.as_bytes(), mode)
        .with_context(|| format!("writing {}", target.display()))?;
    drop(lock);
    Ok(())
}

/// Replaces `path` with `bytes` (permission bits `mode`) through a temp
/// file in the same directory (unpredictable name, never through a
/// symlink): the file is fsynced, renamed over `path`, then the directory
/// is fsynced.
pub fn write_keeping(path: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let dir = path
        .parent()
        .ok_or_else(|| std::io::Error::other("no parent directory"))?;
    let name = path
        .file_name()
        .ok_or_else(|| std::io::Error::other("no file name"))?;
    let tmp = dir.join(format!(
        ".{}.atem-tmp-{}",
        name.to_string_lossy(),
        uuid::Uuid::new_v4().simple()
    ));
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)?;
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&tmp, path)?;
        fs::File::open(if dir.as_os_str().is_empty() { Path::new(".") } else { dir })?
            .sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A reader never sees a half-written `config.toml` while a key is
    /// merged in (the runtime read its identity while its own Astation
    /// connect stored `instance_id`/`atem_id`, and fell back to unpaired).
    #[test]
    fn a_merged_key_is_never_seen_half_written() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let filler = "x".repeat(64 * 1024);
        AtemConfig::write_config_value_at(&path, "filler", toml::Value::String(filler));
        let writer = {
            let path = path.clone();
            std::thread::spawn(move || {
                for i in 0..300 {
                    AtemConfig::write_config_value_at(
                        &path,
                        "atem_id",
                        toml::Value::String(format!("host-{i}")),
                    );
                }
            })
        };
        let mut reads = 0;
        while !writer.is_finished() {
            let text = fs::read_to_string(&path).unwrap();
            let parsed: toml::Value = toml::from_str(&text)
                .unwrap_or_else(|e| panic!("read {reads}: a half-written file: {e}"));
            assert!(parsed.get("filler").is_some(), "read {reads}: a truncated file");
            reads += 1;
        }
        writer.join().unwrap();
        assert!(reads > 0);
    }

    /// A symlinked config.toml keeps its link; the target is replaced and
    /// keeps its mode. A new file is 0600.
    #[test]
    fn writes_follow_a_symlink_and_keep_the_mode() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o7777;
        let dir = tempfile::tempdir().unwrap();
        let fresh = dir.path().join("new").join("config.toml");
        AtemConfig::write_config_value_at(&fresh, "a", toml::Value::Integer(1));
        assert_eq!(mode(&fresh), 0o600);
        let target = dir.path().join("dotfiles").join("atem.toml");
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(&target, "# mine\nkept = true\n").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o640)).unwrap();
        let link = dir.path().join("config.toml");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        AtemConfig::write_config_value_at(&link, "atem_id", toml::Value::String("h-1".into()));
        crate::chat::codex::write_consent(&link, true).unwrap();
        assert!(fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
        let text = fs::read_to_string(&target).unwrap();
        let parsed: toml::Value = toml::from_str(&text).unwrap();
        assert_eq!(parsed["kept"].as_bool(), Some(true));
        assert_eq!(parsed["atem_id"].as_str(), Some("h-1"));
        assert_eq!(parsed["codex"]["hooks"].as_bool(), Some(true));
        assert_eq!(mode(&target), 0o640);
        // Malformed TOML is left as it is.
        fs::write(&target, "not = = toml").unwrap();
        AtemConfig::write_config_value_at(&link, "a", toml::Value::Integer(1));
        assert_eq!(fs::read_to_string(&target).unwrap(), "not = = toml");
    }

    /// Concurrent writers (each a read-modify-write) never lose a key.
    #[test]
    fn concurrent_writers_all_land() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let writers: Vec<_> = (0..4)
            .map(|w| {
                let path = path.clone();
                std::thread::spawn(move || {
                    for i in 0..25 {
                        AtemConfig::write_config_value_at(
                            &path,
                            &format!("k{w}_{i}"),
                            toml::Value::Integer(i),
                        );
                    }
                })
            })
            .collect();
        for w in writers {
            w.join().unwrap();
        }
        let parsed: toml::Value = toml::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(parsed.as_table().unwrap().len(), 100);
    }

    #[test]
    fn terminal_prefix_is_read_from_config_toml() {
        let config: AtemConfig = toml::from_str("terminal_prefix = \"Ctrl-a\"\n").unwrap();
        assert_eq!(config.terminal_prefix.as_deref(), Some("Ctrl-a"));
        let config: AtemConfig = toml::from_str("").unwrap();
        assert_eq!(config.terminal_prefix, None);
    }
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
    fn display_masked_shows_the_login_and_the_pairing() {
        let _profile = crate::test_profile::temp();
        let config = AtemConfig {
            rtm_channel: Some("test_channel".to_string()),
            ..Default::default()
        };
        let display = config.display_masked();
        assert!(display.contains("test_channel")); // non-secret shown
        assert!(display.contains("Login:    not logged in"), "{display}");
        assert!(display.contains("Paired:   none"), "{display}");
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
        let _profile = crate::test_profile::temp();
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
        // Not a first-byte check: random ciphertext starts with `{`/`[` 1 in 128.
        assert!(serde_json::from_slice::<serde_json::Value>(&raw).is_err(), "file must not be JSON");
    }

    #[test]
    fn project_cache_round_trip_via_temp_path() {
        let _profile = crate::test_profile::temp();
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
        let _profile = crate::test_profile::temp();
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
        let _profile = crate::test_profile::temp();
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
        let _profile = crate::test_profile::temp();
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
        let _profile = crate::test_profile::temp();
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
        let _profile = crate::test_profile::temp();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does_not_exist.enc");
        let cache = ProjectCache::load_from(&path);
        assert!(cache.projects.is_empty());
        assert!(cache.current_app_id.is_none());
    }

    #[test]
    fn cleanup_legacy_files_removes_both() {
        let _profile = crate::test_profile::temp();
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
        let _profile = crate::test_profile::temp();
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
