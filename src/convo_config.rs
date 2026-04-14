//! ConvoAI config: TOML → strongly-typed struct → Agora REST JSON payload.
//!
//! Mapping is mechanical; see docs/superpowers/specs/2026-04-14-atem-serv-convo-design.md §2.
//! `params` sub-tables are passed through as `toml::Value` (converted to
//! `serde_json::Value` later) so atem does not need to know every vendor's shape.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub struct ConvoConfig {
    pub channel: Option<String>,
    pub rtc_user_id: Option<String>,
    pub agent_user_id: Option<String>,
    pub idle_timeout_secs: Option<u32>,
    pub preset: Option<String>,
    pub agent: Option<AgentConfig>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub struct AgentConfig {
    pub llm: Option<LlmConfig>,
    pub asr: Option<ServiceConfig>,
    pub tts: Option<ServiceConfig>,
    pub avatar: Option<ServiceConfig>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub struct LlmConfig {
    pub url: Option<String>,
    pub api_key: Option<String>,
    pub greeting_message: Option<String>,
    pub failure_message: Option<String>,
    pub max_history: Option<u32>,
    pub system_messages: Vec<SystemMessage>,
    pub params: BTreeMap<String, toml::Value>,
}

#[derive(Debug, Deserialize, Default)]
pub struct SystemMessage {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub struct ServiceConfig {
    pub vendor: Option<String>,
    pub language: Option<String>,
    pub params: BTreeMap<String, toml::Value>,
}

impl ConvoConfig {
    pub fn from_file(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;
        let cfg: ConvoConfig = toml::from_str(&content)
            .with_context(|| format!("Failed to parse {}", path.display()))?;
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixtures() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
    }

    #[test]
    fn parses_full_fixture() {
        let cfg = ConvoConfig::from_file(&fixtures().join("convo_full.toml")).unwrap();
        assert_eq!(cfg.channel.as_deref(), Some("demo"));
        assert_eq!(cfg.rtc_user_id.as_deref(), Some("42"));
        assert_eq!(cfg.agent_user_id.as_deref(), Some("1001"));
        assert_eq!(cfg.idle_timeout_secs, Some(120));
        assert_eq!(
            cfg.preset.as_deref(),
            Some("deepgram_nova_3,openai_gpt_5_mini,minimax_speech_2_6_turbo")
        );

        let agent = cfg.agent.unwrap();
        let llm = agent.llm.unwrap();
        assert_eq!(llm.greeting_message.as_deref(), Some("Hi"));
        assert_eq!(llm.system_messages.len(), 1);
        assert_eq!(llm.system_messages[0].role, "system");
        assert_eq!(
            llm.params.get("model").and_then(|v| v.as_str()),
            Some("openai/gpt-oss-120b")
        );

        assert!(agent.asr.is_some());
        assert!(agent.tts.is_some());
        assert!(agent.avatar.is_some());
    }

    #[test]
    fn empty_config_parses_to_all_none() {
        let cfg: ConvoConfig = toml::from_str("").unwrap();
        assert!(cfg.channel.is_none());
        assert!(cfg.agent.is_none());
    }

    #[test]
    fn nested_params_preserve_tables() {
        let cfg = ConvoConfig::from_file(&fixtures().join("convo_full.toml")).unwrap();
        let tts = cfg.agent.unwrap().tts.unwrap();
        let voice_setting = tts.params.get("voice_setting").unwrap();
        assert!(voice_setting.is_table());
        assert_eq!(
            voice_setting.get("voice_id").and_then(|v| v.as_str()),
            Some("voice_1")
        );
    }
}
