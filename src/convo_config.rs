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
    /// Single preset name — backward compat. Ignored if `presets` is non-empty.
    pub preset: Option<String>,
    /// Named preset bundles the page can switch between via dropdown.
    /// The selected name is forwarded verbatim as `properties.preset`
    /// in the Agora ConvoAI `/join` body, so entries here must be valid
    /// preset identifiers on the Agora side.
    pub presets: Option<Vec<String>>,
    pub agent: Option<AgentConfig>,
}

impl ConvoConfig {
    /// The effective list of selectable preset names: prefer `presets`
    /// when set + non-empty, otherwise fall back to the single `preset`
    /// field (as a one-element list), otherwise empty.
    pub fn preset_list(&self) -> Vec<String> {
        if let Some(list) = &self.presets {
            if !list.is_empty() {
                return list.clone();
            }
        }
        self.preset.clone().map(|p| vec![p]).unwrap_or_default()
    }
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
    pub avatar_id: Option<String>,
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

use serde_json::{Map, Value, json};

pub struct JoinArgs<'a> {
    pub name:           &'a str,
    pub channel:        &'a str,
    pub token:          &'a str,
    pub agent_rtc_uid:  &'a str,
    pub remote_uids:    &'a [String],
    pub include_avatar: bool,
    /// Runtime override for `properties.preset`. When `Some`, replaces
    /// the config-level `preset` / `presets[0]`. Usually comes from the
    /// browser dropdown selection via /api/convo/start's body.
    pub preset:         Option<&'a str>,
}

impl ConvoConfig {
    /// Build the Agora Conversational AI `/join` request body from this config.
    ///
    /// Mechanical mapping:
    ///   - top-level scalars go under `properties.*`
    ///   - [agent.llm] / .asr / .tts / .avatar go under `properties.llm` / etc.
    ///   - `params` sub-tables map to `properties.<svc>.params` verbatim.
    ///   - [[agent.llm.system_messages]] → `properties.llm.system_messages[]`
    pub fn build_join_payload(&self, args: JoinArgs<'_>) -> Value {
        let mut props = Map::new();
        props.insert("channel".into(),         json!(args.channel));
        props.insert("token".into(),           json!(args.token));
        props.insert("agent_rtc_uid".into(),   json!(args.agent_rtc_uid));
        props.insert("remote_rtc_uids".into(), json!(args.remote_uids));
        if let Some(t) = self.idle_timeout_secs {
            props.insert("idle_timeout".into(), json!(t));
        }
        // Runtime override (browser dropdown) > self.preset > first entry of presets.
        let effective_preset: Option<&str> = args.preset
            .or(self.preset.as_deref())
            .or_else(|| self.presets.as_ref().and_then(|v| v.first().map(|s| s.as_str())));
        if let Some(p) = effective_preset {
            if !p.is_empty() {
                props.insert("preset".into(), json!(p));
            }
        }
        if let Some(agent) = &self.agent {
            if let Some(llm) = &agent.llm {
                props.insert("llm".into(), llm_to_json(llm));
            }
            if let Some(asr) = &agent.asr {
                props.insert("asr".into(), service_to_json(asr));
            }
            if let Some(tts) = &agent.tts {
                props.insert("tts".into(), service_to_json(tts));
            }
            if args.include_avatar {
                if let Some(av) = &agent.avatar {
                    props.insert("avatar".into(), service_to_json(av));
                }
            }
        }
        json!({ "name": args.name, "properties": Value::Object(props) })
    }
}

fn llm_to_json(c: &LlmConfig) -> Value {
    let mut m = Map::new();
    if let Some(v) = &c.url              { m.insert("url".into(), json!(v)); }
    if let Some(v) = &c.api_key          { m.insert("api_key".into(), json!(v)); }
    if let Some(v) = &c.greeting_message { m.insert("greeting_message".into(), json!(v)); }
    if let Some(v) = &c.failure_message  { m.insert("failure_message".into(), json!(v)); }
    if let Some(v) = c.max_history       { m.insert("max_history".into(), json!(v)); }
    if !c.system_messages.is_empty() {
        let arr: Vec<Value> = c.system_messages
            .iter()
            .map(|sm| json!({ "role": sm.role, "content": sm.content }))
            .collect();
        m.insert("system_messages".into(), Value::Array(arr));
    }
    if !c.params.is_empty() {
        m.insert("params".into(), toml_map_to_json(&c.params));
    }
    Value::Object(m)
}

fn service_to_json(c: &ServiceConfig) -> Value {
    let mut m = Map::new();
    if let Some(v) = &c.vendor    { m.insert("vendor".into(), json!(v)); }
    if let Some(v) = &c.language  { m.insert("language".into(), json!(v)); }
    if let Some(v) = &c.avatar_id { m.insert("avatar_id".into(), json!(v)); }
    if !c.params.is_empty() {
        m.insert("params".into(), toml_map_to_json(&c.params));
    }
    Value::Object(m)
}

fn toml_map_to_json(m: &BTreeMap<String, toml::Value>) -> Value {
    let mut out = Map::new();
    for (k, v) in m {
        out.insert(k.clone(), toml_value_to_json(v));
    }
    Value::Object(out)
}

fn toml_value_to_json(v: &toml::Value) -> Value {
    match v {
        toml::Value::String(s)   => Value::String(s.clone()),
        toml::Value::Integer(n)  => json!(n),
        toml::Value::Float(f)    => json!(f),
        toml::Value::Boolean(b)  => Value::Bool(*b),
        toml::Value::Datetime(d) => Value::String(d.to_string()),
        toml::Value::Array(a)    => Value::Array(a.iter().map(toml_value_to_json).collect()),
        toml::Value::Table(t)    => {
            let mut m = Map::new();
            for (k, vv) in t {
                m.insert(k.clone(), toml_value_to_json(vv));
            }
            Value::Object(m)
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct CliOverrides {
    pub channel:       Option<String>,
    pub rtc_user_id:   Option<String>,
    pub agent_user_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedConfig {
    pub channel:           String,
    pub rtc_user_id:       String,
    pub agent_user_id:     String,
    pub idle_timeout_secs: Option<u32>,
    /// True iff `[agent.avatar]` is present in convo.toml.
    pub avatar_configured: bool,
    /// Non-secret summary of the `[agent.avatar]` block for display on
    /// the page (vendor + avatar_id). `None` when no avatar block is
    /// configured. Never includes `params` — those may carry secrets.
    pub avatar_summary:    Option<AvatarSummary>,
    /// Legacy single-preset field (kept for page display fallback when
    /// the full `presets` list is empty).
    pub preset:            Option<String>,
    /// Selectable preset names for the page checkboxes. Derived from
    /// `presets` in TOML, falling back to `preset` as a one-element
    /// list. Empty means no checkboxes rendered.
    pub presets:           Vec<String>,
}

/// Public display fields from `[agent.avatar]`. Excludes `params`,
/// which can contain API keys or session tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvatarSummary {
    pub vendor:    Option<String>,
    pub avatar_id: Option<String>,
}

impl ConvoConfig {
    /// Resolve runtime values from CLI overrides + TOML + defaults.
    /// Precedence: CLI > TOML > default/error.
    ///
    /// - `channel`: required (CLI or TOML); errors if missing.
    /// - `rtc_user_id`: optional (CLI > TOML > "0" default).
    /// - `agent_user_id`: required (CLI or TOML); errors if missing.
    /// - `avatar_configured`: true iff `[agent.avatar]` is present in TOML.
    pub fn resolve(&self, cli: &CliOverrides) -> Result<ResolvedConfig> {
        let channel = cli.channel.clone()
            .or_else(|| self.channel.clone())
            .ok_or_else(|| anyhow::anyhow!(
                "channel required (pass --channel or set 'channel' in convo.toml)"
            ))?;
        let rtc_user_id = cli.rtc_user_id.clone()
            .or_else(|| self.rtc_user_id.clone())
            .unwrap_or_else(|| "0".to_string());
        let agent_user_id = cli.agent_user_id.clone()
            .or_else(|| self.agent_user_id.clone())
            .ok_or_else(|| anyhow::anyhow!(
                "agent_user_id required (pass --agent-user-id or set 'agent_user_id' in convo.toml)"
            ))?;
        let avatar_block = self.agent.as_ref().and_then(|a| a.avatar.as_ref());
        let avatar_configured = avatar_block.is_some();
        let avatar_summary = avatar_block.map(|av| AvatarSummary {
            vendor:    av.vendor.clone(),
            avatar_id: av.avatar_id.clone(),
        });
        Ok(ResolvedConfig {
            channel,
            rtc_user_id,
            agent_user_id,
            idle_timeout_secs: self.idle_timeout_secs,
            avatar_configured,
            avatar_summary,
            preset: self.preset.clone(),
            presets: self.preset_list(),
        })
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

    #[test]
    fn build_join_payload_maps_toml_to_agora_shape() {
        let cfg = ConvoConfig::from_file(&fixtures().join("convo_full.toml")).unwrap();

        let body = cfg.build_join_payload(JoinArgs {
            name:          "atem-convo-1234",
            channel:       "demo",
            token:         "007TOK",
            agent_rtc_uid: "1001",
            remote_uids:   &["42".to_string()],
            include_avatar: true,
            preset:        None,
        });

        // Top-level
        assert_eq!(body["name"], "atem-convo-1234");
        let props = &body["properties"];
        assert_eq!(props["channel"], "demo");
        assert_eq!(props["token"], "007TOK");
        assert_eq!(props["agent_rtc_uid"], "1001");
        assert_eq!(props["remote_rtc_uids"][0], "42");
        assert_eq!(props["idle_timeout"], 120);
        assert_eq!(
            props["preset"],
            "deepgram_nova_3,openai_gpt_5_mini,minimax_speech_2_6_turbo"
        );

        // LLM
        assert_eq!(props["llm"]["url"], "https://api.groq.com/openai/v1/chat/completions");
        assert_eq!(props["llm"]["greeting_message"], "Hi");
        assert_eq!(props["llm"]["system_messages"][0]["role"], "system");
        assert_eq!(props["llm"]["params"]["model"], "openai/gpt-oss-120b");

        // ASR
        assert_eq!(props["asr"]["vendor"], "soniox");
        assert_eq!(props["asr"]["language"], "en-US");
        assert_eq!(props["asr"]["params"]["model"], "stt-rt-v3");

        // TTS (nested params sub-table)
        assert_eq!(props["tts"]["vendor"], "minimax");
        assert_eq!(props["tts"]["params"]["model"], "speech-02-turbo");
        assert_eq!(props["tts"]["params"]["voice_setting"]["voice_id"], "voice_1");

        // Avatar included when the flag is true
        assert_eq!(props["avatar"]["vendor"], "heygen");
        assert_eq!(props["avatar"]["avatar_id"], "a1");
    }

    #[test]
    fn build_join_payload_omits_avatar_when_flag_false() {
        let cfg = ConvoConfig::from_file(&fixtures().join("convo_full.toml")).unwrap();
        let body = cfg.build_join_payload(JoinArgs {
            name: "x",
            channel: "c",
            token: "t",
            agent_rtc_uid: "1",
            remote_uids: &["2".to_string()],
            include_avatar: false,
            preset: None,
        });
        assert!(body["properties"].get("avatar").is_none());
    }

    #[test]
    fn preset_list_from_presets_array() {
        let toml_str = r#"
            channel = "c"
            agent_user_id = "a"
            presets = ["first", "second"]
        "#;
        let cfg: ConvoConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.preset_list(), vec!["first".to_string(), "second".to_string()]);
    }

    #[test]
    fn preset_list_falls_back_to_single_preset() {
        let toml_str = r#"
            channel = "c"
            agent_user_id = "a"
            preset = "only_one"
        "#;
        let cfg: ConvoConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.preset_list(), vec!["only_one".to_string()]);
    }

    #[test]
    fn preset_list_empty_when_neither_set() {
        let cfg: ConvoConfig = toml::from_str("").unwrap();
        assert!(cfg.preset_list().is_empty());
    }

    #[test]
    fn join_payload_runtime_preset_overrides_config() {
        let toml_str = r#"preset = "from_config""#;
        let cfg: ConvoConfig = toml::from_str(toml_str).unwrap();
        let body = cfg.build_join_payload(JoinArgs {
            name: "x", channel: "c", token: "t",
            agent_rtc_uid: "1", remote_uids: &[],
            include_avatar: false,
            preset: Some("from_runtime"),
        });
        assert_eq!(body["properties"]["preset"], "from_runtime");
    }

    #[test]
    fn join_payload_uses_first_preset_from_list_when_no_runtime() {
        let toml_str = r#"presets = ["first", "second"]"#;
        let cfg: ConvoConfig = toml::from_str(toml_str).unwrap();
        let body = cfg.build_join_payload(JoinArgs {
            name: "x", channel: "c", token: "t",
            agent_rtc_uid: "1", remote_uids: &[],
            include_avatar: false,
            preset: None,
        });
        assert_eq!(body["properties"]["preset"], "first");
    }

    #[test]
    fn resolve_uses_cli_over_toml() {
        let cfg = ConvoConfig::from_file(&fixtures().join("convo_full.toml")).unwrap();
        let r = cfg.resolve(&CliOverrides {
            channel:       Some("override_channel".into()),
            rtc_user_id:   None,
            agent_user_id: None,
        }).unwrap();
        assert_eq!(r.channel, "override_channel");
        assert_eq!(r.rtc_user_id, "42");         // from TOML
        assert_eq!(r.agent_user_id, "1001");     // from TOML
        assert!(r.avatar_configured);
    }

    #[test]
    fn resolve_errors_when_channel_missing() {
        let cfg: ConvoConfig = toml::from_str(r#"
            rtc_user_id = "1"
            agent_user_id = "9"
        "#).unwrap();
        let err = cfg.resolve(&CliOverrides::default()).unwrap_err().to_string();
        assert!(err.contains("channel"), "got: {err}");
    }

    #[test]
    fn resolve_errors_when_agent_user_id_missing() {
        let cfg: ConvoConfig = toml::from_str(r#"
            channel = "c"
            rtc_user_id = "1"
        "#).unwrap();
        let err = cfg.resolve(&CliOverrides::default()).unwrap_err().to_string();
        assert!(err.contains("agent_user_id"), "got: {err}");
    }

    #[test]
    fn resolve_defaults_rtc_user_id_to_0() {
        let cfg: ConvoConfig = toml::from_str(r#"
            channel = "c"
            agent_user_id = "9"
        "#).unwrap();
        let r = cfg.resolve(&CliOverrides::default()).unwrap();
        assert_eq!(r.rtc_user_id, "0");
    }

    #[test]
    fn resolve_avatar_configured_false_when_section_absent() {
        let cfg: ConvoConfig = toml::from_str(r#"
            channel = "c"
            agent_user_id = "9"
        "#).unwrap();
        let r = cfg.resolve(&CliOverrides::default()).unwrap();
        assert!(!r.avatar_configured);
    }
}
