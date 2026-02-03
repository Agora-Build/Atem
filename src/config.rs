use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Main Atem configuration loaded from ~/.config/atem/config.toml + env vars
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct AtemConfig {
    pub customer_id: Option<String>,
    pub customer_secret: Option<String>,
    pub rtm_channel: Option<String>,
    pub rtm_account: Option<String>,
    pub astation_url: Option<String>,
}

/// Active project state persisted to ~/.config/atem/active_project.json
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveProject {
    pub app_id: String,
    pub app_certificate: String,
    pub name: String,
}

impl AtemConfig {
    /// Load config from file + env var overrides. Env vars take precedence.
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

        // Env var overrides
        if let Ok(val) = std::env::var("AGORA_CUSTOMER_ID") {
            config.customer_id = Some(val);
        }
        if let Ok(val) = std::env::var("AGORA_CUSTOMER_SECRET") {
            config.customer_secret = Some(val);
        }
        if let Ok(val) = std::env::var("ATEM_RTM_CHANNEL") {
            config.rtm_channel = Some(val);
        }
        if let Ok(val) = std::env::var("ATEM_RTM_ACCOUNT") {
            config.rtm_account = Some(val);
        }
        if let Ok(val) = std::env::var("ASTATION_URL") {
            config.astation_url = Some(val);
        }

        Ok(config)
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
            "astation_url: {}",
            self.astation_url.as_deref().unwrap_or("(not set)")
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
    pub fn astation_url(&self) -> &str {
        self.astation_url
            .as_deref()
            .unwrap_or("ws://127.0.0.1:8080/ws")
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

    /// Resolve app_id: CLI flag > active project > error
    pub fn resolve_app_id(cli_app_id: Option<&str>) -> Result<String> {
        if let Some(id) = cli_app_id {
            return Ok(id.to_string());
        }
        if let Some(proj) = Self::load() {
            return Ok(proj.app_id);
        }
        anyhow::bail!("No active project. Run `atem project use <APP_ID>` or pass `--app-id`")
    }

    /// Resolve app_certificate: CLI flag > active project > error
    pub fn resolve_app_certificate(cli_cert: Option<&str>) -> Result<String> {
        if let Some(cert) = cli_cert {
            return Ok(cert.to_string());
        }
        if let Some(proj) = Self::load() {
            return Ok(proj.app_certificate);
        }
        anyhow::bail!("No active project. Run `atem project use <APP_ID>` or pass `--app-id`")
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
        assert!(config.astation_url.is_none());
    }

    #[test]
    fn config_defaults() {
        let config = AtemConfig::default();
        assert_eq!(config.rtm_channel(), "atem_channel");
        assert_eq!(config.rtm_account(), "atem01");
        assert_eq!(config.astation_url(), "ws://127.0.0.1:8080/ws");
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
}
