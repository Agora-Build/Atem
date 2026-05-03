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

    // ── Pass-through top-level properties ────────────────────────────
    //
    // Agora ConvoAI's /join body accepts several top-level keys that atem
    // has no opinion on (enable_string_uid, advanced_features, vad, sal,
    // parameters). Rather than type each one, we pass them through
    // verbatim so the user can set any Agora-supported field in
    // `convo.toml` without waiting for an atem release. Notably:
    //
    //   [advanced_features]
    //   enable_rtm = true      # required for word-by-word transcripts
    //   enable_sal = true
    //   [parameters]
    //   data_channel = "rtm"
    //   [parameters.transcript]
    //   enable_words = true
    //
    // Without `enable_rtm=true` + `data_channel=rtm` + `transcript
    // .enable_words=true` the agent runs but never streams transcripts.

    /// `properties.advanced_features` — pass-through sub-table.
    pub advanced_features: Option<BTreeMap<String, toml::Value>>,

    /// `properties.vad` — pass-through sub-table.
    pub vad: Option<BTreeMap<String, toml::Value>>,

    /// `properties.sal` — pass-through sub-table.
    pub sal: Option<BTreeMap<String, toml::Value>>,

    /// `properties.parameters` — pass-through sub-table. Can carry
    /// arbitrary nested tables like `[parameters.transcript]` and
    /// `[parameters.turn_detector]`.
    pub parameters: Option<BTreeMap<String, toml::Value>>,

    // ── Routing / security defaults (testing convenience) ────────────
    //
    // Same values reused across all channels — for fleet test loops we
    // don't want to mint a fresh salt or pick a region per launch. The
    // browser UI form fields are pre-filled from these but remain
    // editable; --background mode forwards them to the agent's /join.

    /// Route through Agora's HIPAA-compliant `/hipaa/api/...` endpoint.
    /// Default false (regular path).
    pub hipaa: Option<bool>,

    /// Geofence area: GLOBAL (default) | NORTH_AMERICA | EUROPE | ASIA |
    /// JAPAN | INDIA. None / "GLOBAL" → no geofence sent.
    pub geofence: Option<String>,

    /// `[encryption]` block. When `mode > 0`, encryption is active.
    pub encryption: Option<EncryptionConfig>,
}

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(default)]
pub struct EncryptionConfig {
    /// 0 = off; 1..=8 per Agora's encryption_mode integer table.
    pub mode: u8,
    /// Encryption key. Required when `mode > 0`.
    pub key: String,
    /// Base64-encoded 32-byte salt. Required for gcm2 modes (7, 8);
    /// ignored otherwise.
    pub salt: String,
}

impl ConvoConfig {
    /// If `[agent.avatar.params]` carries both `agora_appid` and
    /// `agora_app_cert`, return them. These are used by the caller to
    /// mint a fresh avatar RTC token (akool and similar vendors run
    /// their video in their OWN Agora project, not the user's, so we
    /// need a token scoped to that appid). Returns None when the user
    /// has pre-minted a token and put it in `agora_token` directly.
    pub fn avatar_mint_credentials(&self) -> Option<(String, String)> {
        let av = self.agent.as_ref()?.avatar.as_ref()?;
        let appid = av.params.get("agora_appid")?.as_str()?.to_string();
        let cert  = av.params.get("agora_app_cert")?.as_str()?.to_string();
        if appid.is_empty() || cert.is_empty() { return None; }
        Some((appid, cert))
    }

    /// True iff `[agent.avatar.params]` already has an agora_token.
    /// When true, the caller should skip minting and let the pre-set
    /// token flow through verbatim.
    pub fn avatar_has_preset_token(&self) -> bool {
        self.agent.as_ref()
            .and_then(|a| a.avatar.as_ref())
            .and_then(|av| av.params.get("agora_token"))
            .and_then(|v| v.as_str())
            .map(|s| !s.is_empty())
            .unwrap_or(false)
    }

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
    /// Dedicated RTC uid for the avatar's video stream. Required when
    /// `include_avatar` is true — the Agora ConvoAI backend publishes
    /// the avatar video as this uid (distinct from agent_rtc_uid which
    /// publishes voice). Caller generates a random number so it doesn't
    /// collide with the agent or the user.
    pub avatar_user_id: &'a str,
    /// Fresh RTC channel name for the avatar's own Agora project
    /// (akool etc. run in their own project, not the user's). Injected
    /// as `avatar.params.agora_channel` when the user's TOML didn't
    /// already provide one. Typical shape: "convoai-<uuid>".
    pub avatar_channel: Option<&'a str>,
    /// RTC token minted by atem for (agora_appid, avatar_channel,
    /// avatar_user_id) using `agora_app_cert` from [agent.avatar.params].
    /// Injected as `avatar.params.agora_token`.
    pub avatar_token:   Option<&'a str>,
    /// Runtime override for `properties.preset`. When `Some`, replaces
    /// the config-level `preset` / `presets[0]`. Usually comes from the
    /// browser dropdown selection via /api/convo/start's body.
    pub preset:         Option<&'a str>,
    /// RTC encryption mode (1..=8). See Agora ConvoAI docs for the integer
    /// table. When `encryption_key` is set and `encryption_mode` is `None`,
    /// the agent uses Agora's default (AES_128_GCM).
    pub encryption_mode: Option<u8>,
    /// RTC encryption key. Empty / `None` → no encryption.
    pub encryption_key:  Option<&'a str>,
    /// Base64-encoded 32-byte salt. Required by gcm2 modes (7, 8). Ignored
    /// for other modes by the Agora server.
    pub encryption_salt: Option<&'a str>,
    /// Agora geofence area. Valid values: GLOBAL, NORTH_AMERICA, EUROPE,
    /// ASIA, JAPAN, INDIA. `None` or "GLOBAL" → no `properties.geofence`
    /// emitted (default global behaviour).
    pub geofence_area: Option<&'a str>,
    /// Inject `properties.parameters.enable_dump = true`. Asks Agora
    /// to capture audio frames on the agent side for debugging — the
    /// dump itself is server-side and retrieved via Agora support.
    pub enable_dump: bool,
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
        // Preset moves to top-level `info.preset` per the current
        // Agora /join contract. Resolution order: runtime (browser
        // dropdown) > self.preset > first entry of presets.
        let effective_preset: Option<&str> = args.preset
            .or(self.preset.as_deref())
            .or_else(|| self.presets.as_ref().and_then(|v| v.first().map(|s| s.as_str())));
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
        }

        // Avatar emission. The Agora ConvoAI /join endpoint requires a
        // concrete `vendor` when an `avatar` block is present, and will
        // return 400 "unsupported avatar vendor" if vendor is empty.
        // The preset does NOT back-fill the vendor, so the browser
        // "Enable Avatar" checkbox alone is not enough — the user must
        // also have at least `vendor = "..."` in [agent.avatar].
        //
        // Emitted shape (matches Agora's Conversational-AI-Demo):
        //   avatar: {
        //     enable: true,
        //     vendor: <[agent.avatar].vendor — required>,
        //     params: {
        //       agora_uid: <args.avatar_user_id — dedicated RTC uid
        //                   the avatar video publishes to>,
        //       avatar_id: <[agent.avatar].avatar_id if set>,
        //       …any pass-through keys from [agent.avatar.params]
        //     }
        //   }
        //
        // When Enable Avatar is ticked but no vendor configured we skip
        // the avatar block entirely so the /join doesn't error. The
        // browser surfaces a warning in that case (see startAgent()).
        if args.include_avatar {
            // Emit avatar whenever Enable Avatar is ticked. We send
            // whatever atem can compute locally (enable, channel, uid,
            // token); everything else — vendor, avatar_id, api_key,
            // host, etc. — is pulled from [agent.avatar] in TOML when
            // provided, otherwise left for the downstream preset or
            // proxy backend to back-fill.
            //
            // agora_app_cert (when present in TOML) is a secret that
            // atem used internally to mint agora_token — it must NEVER
            // leak to the wire.
            let mut av_obj = Map::new();
            av_obj.insert("enable".into(), json!(true));
            let mut av_params = Map::new();
            if let Some(av) = self.agent.as_ref().and_then(|a| a.avatar.as_ref()) {
                if let Some(vendor) = &av.vendor {
                    av_obj.insert("vendor".into(), json!(vendor));
                }
                if let Some(id) = &av.avatar_id {
                    av_params.insert("avatar_id".into(), json!(id));
                }
                for (k, v) in &av.params {
                    if k == "agora_app_cert" { continue; }
                    av_params.insert(k.clone(), toml_value_to_json(v));
                }
            }
            // Inject computed fields only if not already in TOML — user
            // explicit values win (e.g. pre-minted agora_token).
            av_params
                .entry("agora_uid".to_string())
                .or_insert_with(|| json!(args.avatar_user_id));
            if let Some(ch) = args.avatar_channel {
                av_params
                    .entry("agora_channel".to_string())
                    .or_insert_with(|| json!(ch));
            }
            if let Some(tk) = args.avatar_token {
                av_params
                    .entry("agora_token".to_string())
                    .or_insert_with(|| json!(tk));
            }
            av_obj.insert("params".into(), Value::Object(av_params));
            props.insert("avatar".into(), Value::Object(av_obj));
        }

        // Pass-through top-level properties from convo.toml. Any sub-table
        // (e.g. [parameters.transcript]) is preserved as nested JSON.
        if let Some(m) = &self.advanced_features {
            props.insert("advanced_features".into(), map_to_json(m));
        }
        if let Some(m) = &self.vad {
            props.insert("vad".into(), map_to_json(m));
        }
        if let Some(m) = &self.sal {
            props.insert("sal".into(), map_to_json(m));
        }
        if let Some(m) = &self.parameters {
            props.insert("parameters".into(), map_to_json(m));
        }
        // Inject runtime UI knobs into `properties.parameters`. We may
        // need to create the table if convo.toml didn't declare one.
        if args.enable_dump {
            let entry = props.entry("parameters".to_string())
                .or_insert_with(|| Value::Object(Map::new()));
            if let Value::Object(map) = entry {
                map.insert("enable_dump".into(), json!(true));
            }
        }

        // Geofence — restrict the agent's media routing to a specific
        // Agora region. Skip emission when None or GLOBAL (Agora's default).
        if let Some(area) = args.geofence_area
            .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("GLOBAL"))
        {
            let mut g = Map::new();
            g.insert("area".into(), json!(area));
            props.insert("geofence".into(), Value::Object(g));
        }

        // RTC encryption (https://docs.agora.io/en/conversational-ai/rest-api/agent/join).
        // Emit `properties.rtc` only when an encryption_key is supplied;
        // omitting the block keeps the call unencrypted, which is the
        // ConvoAI default.
        if let Some(key) = args.encryption_key.filter(|s| !s.is_empty()) {
            let mut rtc = Map::new();
            rtc.insert("encryption_key".into(), json!(key));
            if let Some(mode) = args.encryption_mode {
                rtc.insert("encryption_mode".into(), json!(mode));
            }
            if let Some(salt) = args.encryption_salt.filter(|s| !s.is_empty()) {
                rtc.insert("encryption_salt".into(), json!(salt));
            }
            props.insert("rtc".into(), Value::Object(rtc));
        }

        // Top-level request envelope:
        //   { "name": "...", "preset": "...", "properties": { ... } }
        // `preset` sits at the same level as `properties`, before it.
        let mut envelope = Map::new();
        envelope.insert("name".into(), json!(args.name));
        if let Some(p) = effective_preset {
            if !p.is_empty() {
                envelope.insert("preset".into(), json!(p));
            }
        }
        envelope.insert("properties".into(), Value::Object(props));
        Value::Object(envelope)
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

/// Convert a BTreeMap<String, toml::Value> (our sub-table shape for
/// pass-through config blocks) into a JSON Object.
fn map_to_json(m: &BTreeMap<String, toml::Value>) -> Value {
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
    /// HIPAA mode (TOML default). UI checkbox + background mode both
    /// honour this; user can still toggle in the browser form.
    pub hipaa:             bool,
    /// Geofence area (TOML default). Empty / "GLOBAL" → no geofence.
    pub geofence:          String,
    /// Encryption mode 0..=8 (TOML default). 0 = off.
    pub encryption_mode:   u8,
    /// Encryption key (TOML default). Empty when mode = 0.
    pub encryption_key:    String,
    /// Encryption salt base64 (TOML default). Required for gcm2 modes.
    pub encryption_salt:   String,
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
        let enc = self.encryption.clone().unwrap_or_default();
        Ok(ResolvedConfig {
            channel,
            rtc_user_id,
            agent_user_id,
            idle_timeout_secs: self.idle_timeout_secs,
            avatar_configured,
            avatar_summary,
            preset: self.preset.clone(),
            presets: self.preset_list(),
            hipaa: self.hipaa.unwrap_or(false),
            geofence: self.geofence.clone().unwrap_or_default(),
            encryption_mode: enc.mode,
            encryption_key:  enc.key,
            encryption_salt: enc.salt,
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
            avatar_user_id: "999",
            avatar_channel: None,
            avatar_token:   None,
            preset:        None,
            encryption_mode: None,
            encryption_key: None,
            encryption_salt: None,
            geofence_area: None,
            enable_dump: false,
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
            body["preset"],
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

        // Avatar included when the flag is true — new shape:
        //   enable: true, vendor at top, avatar_id inside params,
        //   agora_uid auto-injected from caller.
        assert_eq!(props["avatar"]["enable"],            true);
        assert_eq!(props["avatar"]["vendor"],            "heygen");
        assert_eq!(props["avatar"]["params"]["avatar_id"], "a1");
        assert_eq!(props["avatar"]["params"]["agora_uid"], "999");
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
            avatar_user_id: "999",
            avatar_channel: None,
            avatar_token:   None,
            preset: None,
            encryption_mode: None,
            encryption_key: None,
            encryption_salt: None,
            geofence_area: None,
            enable_dump: false,
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
    fn join_payload_emits_rtc_encryption_when_key_set() {
        let cfg: ConvoConfig = toml::from_str("").unwrap();
        let body = cfg.build_join_payload(JoinArgs {
            name: "x", channel: "c", token: "t",
            agent_rtc_uid: "1", remote_uids: &[],
            include_avatar: false,
            avatar_user_id: "999",
            avatar_channel: None,
            avatar_token:   None,
            preset: None,
            encryption_mode: Some(8),
            encryption_key:  Some("hunter2"),
            encryption_salt: Some("c2FsdC1iYXNlNjQ="),
            geofence_area: None,
            enable_dump: false,
        });
        let rtc = &body["properties"]["rtc"];
        assert_eq!(rtc["encryption_mode"], 8);
        assert_eq!(rtc["encryption_key"], "hunter2");
        assert_eq!(rtc["encryption_salt"], "c2FsdC1iYXNlNjQ=");
    }

    #[test]
    fn join_payload_omits_rtc_encryption_when_key_empty() {
        let cfg: ConvoConfig = toml::from_str("").unwrap();
        // Empty key behaves like None — no `properties.rtc` block.
        let body = cfg.build_join_payload(JoinArgs {
            name: "x", channel: "c", token: "t",
            agent_rtc_uid: "1", remote_uids: &[],
            include_avatar: false,
            avatar_user_id: "999",
            avatar_channel: None,
            avatar_token:   None,
            preset: None,
            encryption_mode: Some(8),
            encryption_key:  Some(""),
            encryption_salt: Some("c2FsdC1iYXNlNjQ="),
            geofence_area: None,
            enable_dump: false,
        });
        assert!(body["properties"].get("rtc").is_none());
    }

    #[test]
    fn join_payload_injects_enable_dump_into_parameters() {
        // No `[parameters]` in TOML → parameters object is created
        // just to hold enable_dump.
        let cfg: ConvoConfig = toml::from_str("").unwrap();
        let body = cfg.build_join_payload(JoinArgs {
            name: "x", channel: "c", token: "t",
            agent_rtc_uid: "1", remote_uids: &[],
            include_avatar: false,
            avatar_user_id: "999",
            avatar_channel: None, avatar_token: None,
            preset: None,
            encryption_mode: None, encryption_key: None, encryption_salt: None,
            geofence_area: None,
            enable_dump: true,
        });
        assert_eq!(body["properties"]["parameters"]["enable_dump"], true);
    }

    #[test]
    fn join_payload_merges_enable_dump_with_existing_parameters() {
        // Existing [parameters] from TOML must be preserved when
        // enable_dump is injected.
        let toml_str = r#"
            channel = "c"
            agent_user_id = "a"
            [parameters]
            audio_scenario = "default"
        "#;
        let cfg: ConvoConfig = toml::from_str(toml_str).unwrap();
        let body = cfg.build_join_payload(JoinArgs {
            name: "x", channel: "c", token: "t",
            agent_rtc_uid: "1", remote_uids: &[],
            include_avatar: false,
            avatar_user_id: "999",
            avatar_channel: None, avatar_token: None,
            preset: None,
            encryption_mode: None, encryption_key: None, encryption_salt: None,
            geofence_area: None,
            enable_dump: true,
        });
        let p = &body["properties"]["parameters"];
        assert_eq!(p["audio_scenario"], "default");
        assert_eq!(p["enable_dump"], true);
    }

    #[test]
    fn join_payload_emits_geofence_when_area_set() {
        let cfg: ConvoConfig = toml::from_str("").unwrap();
        let body = cfg.build_join_payload(JoinArgs {
            name: "x", channel: "c", token: "t",
            agent_rtc_uid: "1", remote_uids: &[],
            include_avatar: false,
            avatar_user_id: "999",
            avatar_channel: None,
            avatar_token:   None,
            preset: None,
            encryption_mode: None,
            encryption_key:  None,
            encryption_salt: None,
            geofence_area:   Some("ASIA"),
            enable_dump: false,
        });
        assert_eq!(body["properties"]["geofence"]["area"], "ASIA");
    }

    #[test]
    fn join_payload_omits_geofence_for_global_or_none() {
        let cfg: ConvoConfig = toml::from_str("").unwrap();
        for area in [None, Some("GLOBAL"), Some("global"), Some("")] {
            let body = cfg.build_join_payload(JoinArgs {
                name: "x", channel: "c", token: "t",
                agent_rtc_uid: "1", remote_uids: &[],
                include_avatar: false,
                avatar_user_id: "999",
                avatar_channel: None,
                avatar_token:   None,
                preset: None,
                encryption_mode: None,
                encryption_key:  None,
                encryption_salt: None,
                geofence_area:   area,
                enable_dump: false,
            });
            assert!(body["properties"].get("geofence").is_none(),
                "geofence should be absent for area={:?}", area);
        }
    }

    #[test]
    fn join_payload_runtime_preset_overrides_config() {
        let toml_str = r#"preset = "from_config""#;
        let cfg: ConvoConfig = toml::from_str(toml_str).unwrap();
        let body = cfg.build_join_payload(JoinArgs {
            name: "x", channel: "c", token: "t",
            agent_rtc_uid: "1", remote_uids: &[],
            include_avatar: false,
            avatar_user_id: "999",
            avatar_channel: None,
            avatar_token:   None,
            preset: Some("from_runtime"),
            encryption_mode: None,
            encryption_key: None,
            encryption_salt: None,
            geofence_area: None,
            enable_dump: false,
        });
        assert_eq!(body["preset"], "from_runtime");
    }

    #[test]
    fn join_payload_avatar_emits_skeleton_without_vendor() {
        // [agent.avatar] empty + include_avatar=true → still emit the
        // block with just enable + agora_uid. vendor/avatar_id/etc.
        // are expected to be back-filled by the downstream preset or
        // proxy backend.
        let toml_str = r#"
[agent.avatar]
"#;
        let cfg: ConvoConfig = toml::from_str(toml_str).unwrap();
        let body = cfg.build_join_payload(JoinArgs {
            name: "x", channel: "c", token: "t",
            agent_rtc_uid: "1", remote_uids: &[],
            include_avatar: true,
            avatar_user_id: "777",
            avatar_channel: None,
            avatar_token:   None,
            preset: None,
            encryption_mode: None,
            encryption_key: None,
            encryption_salt: None,
            geofence_area: None,
            enable_dump: false,
        });
        let av = &body["properties"]["avatar"];
        assert_eq!(av["enable"], true);
        assert_eq!(av["params"]["agora_uid"], "777");
        assert!(av.get("vendor").is_none(),
            "vendor absent from TOML → not emitted (backend/preset back-fills)");
    }

    #[test]
    fn join_payload_avatar_block_overrides_preset_when_fields_present() {
        // [agent.avatar] with concrete fields → explicit override.
        // enable:true + vendor + params.avatar_id + params.api_key +
        // auto-injected params.agora_uid.
        let toml_str = r#"
preset = "some_preset"
[agent.avatar]
vendor = "akool"
avatar_id = "abc"
[agent.avatar.params]
api_key = "secret"
"#;
        let cfg: ConvoConfig = toml::from_str(toml_str).unwrap();
        let body = cfg.build_join_payload(JoinArgs {
            name: "x", channel: "c", token: "t",
            agent_rtc_uid: "1", remote_uids: &[],
            include_avatar: true,
            avatar_user_id: "777",
            avatar_channel: None,
            avatar_token:   None,
            preset: None,
            encryption_mode: None,
            encryption_key: None,
            encryption_salt: None,
            geofence_area: None,
            enable_dump: false,
        });
        let av = &body["properties"]["avatar"];
        assert_eq!(av["enable"],                 true);
        assert_eq!(av["vendor"],                 "akool");
        assert_eq!(av["params"]["avatar_id"],    "abc");
        assert_eq!(av["params"]["api_key"],      "secret");
        assert_eq!(av["params"]["agora_uid"],    "777");
        assert_eq!(body["preset"], "some_preset");
    }

    #[test]
    fn join_payload_avatar_absent_when_checkbox_unchecked() {
        // include_avatar=false → no avatar key emitted, regardless of
        // whether [agent.avatar] is configured.
        let toml_str = r#"
[agent.avatar]
vendor = "akool"
avatar_id = "abc"
"#;
        let cfg: ConvoConfig = toml::from_str(toml_str).unwrap();
        let body = cfg.build_join_payload(JoinArgs {
            name: "x", channel: "c", token: "t",
            agent_rtc_uid: "1", remote_uids: &[],
            include_avatar: false,
            avatar_user_id: "777",
            avatar_channel: None,
            avatar_token:   None,
            preset: None,
            encryption_mode: None,
            encryption_key: None,
            encryption_salt: None,
            geofence_area: None,
            enable_dump: false,
        });
        assert!(body["properties"].get("avatar").is_none());
    }

    #[test]
    fn join_payload_avatar_emits_even_without_toml_block() {
        // No [agent.avatar] block at all + include_avatar=true → still
        // emit the avatar skeleton (enable + agora_uid). Downstream
        // preset/proxy is expected to provide vendor + avatar_id +
        // credentials.
        let toml_str = r#"preset = "x""#;
        let cfg: ConvoConfig = toml::from_str(toml_str).unwrap();
        let body = cfg.build_join_payload(JoinArgs {
            name: "x", channel: "c", token: "t",
            agent_rtc_uid: "1", remote_uids: &[],
            include_avatar: true,
            avatar_user_id: "777",
            avatar_channel: Some("convoai-ch"),
            avatar_token:   Some("007tk"),
            preset: None,
            encryption_mode: None,
            encryption_key: None,
            encryption_salt: None,
            geofence_area: None,
            enable_dump: false,
        });
        let av = &body["properties"]["avatar"];
        assert_eq!(av["enable"], true);
        assert_eq!(av["params"]["agora_uid"],     "777");
        assert_eq!(av["params"]["agora_channel"], "convoai-ch");
        assert_eq!(av["params"]["agora_token"],   "007tk");
    }

    #[test]
    fn join_payload_avatar_strips_cert_and_injects_channel_token() {
        // agora_app_cert in TOML is secret — must NOT reach the wire.
        // Computed channel + token are injected when not in TOML.
        let toml_str = r#"
[agent.avatar]
vendor = "akool"
avatar_id = "dvp_Sean_agora"
[agent.avatar.params]
api_key        = "pma-test"
host           = "ws://1.2.3.4:8055"
agora_appid    = "54faa34804aa4411a5a1c5f81a2a95b3"
agora_app_cert = "<SECRET>"
"#;
        let cfg: ConvoConfig = toml::from_str(toml_str).unwrap();
        let body = cfg.build_join_payload(JoinArgs {
            name: "x", channel: "c", token: "t",
            agent_rtc_uid: "1", remote_uids: &[],
            include_avatar: true,
            avatar_user_id: "333",
            avatar_channel: Some("convoai-fake-uuid"),
            avatar_token:   Some("007fake"),
            preset: None,
            encryption_mode: None,
            encryption_key: None,
            encryption_salt: None,
            geofence_area: None,
            enable_dump: false,
        });
        let ap = &body["properties"]["avatar"]["params"];
        assert_eq!(ap["agora_appid"],   "54faa34804aa4411a5a1c5f81a2a95b3");
        assert_eq!(ap["agora_channel"], "convoai-fake-uuid");
        assert_eq!(ap["agora_token"],   "007fake");
        assert_eq!(ap["agora_uid"],     "333");
        assert_eq!(ap["avatar_id"],     "dvp_Sean_agora");
        assert_eq!(ap["api_key"],       "pma-test");
        assert_eq!(ap["host"],          "ws://1.2.3.4:8055");
        // Cert never leaves atem.
        assert!(ap.get("agora_app_cert").is_none(),
            "agora_app_cert is a secret — must be stripped from the outgoing request");
    }

    #[test]
    fn avatar_mint_credentials_reads_appid_and_cert() {
        let toml_str = r#"
[agent.avatar]
vendor = "akool"
[agent.avatar.params]
agora_appid    = "54fa"
agora_app_cert = "cert-bytes"
"#;
        let cfg: ConvoConfig = toml::from_str(toml_str).unwrap();
        let (appid, cert) = cfg.avatar_mint_credentials().unwrap();
        assert_eq!(appid, "54fa");
        assert_eq!(cert,  "cert-bytes");
    }

    #[test]
    fn avatar_mint_credentials_none_without_both() {
        let toml_str = r#"
[agent.avatar.params]
agora_appid = "54fa"
"#;
        let cfg: ConvoConfig = toml::from_str(toml_str).unwrap();
        assert!(cfg.avatar_mint_credentials().is_none());
    }

    #[test]
    fn avatar_has_preset_token_detects_user_supplied_value() {
        let toml_str = r#"
[agent.avatar.params]
agora_token = "007pre-minted"
"#;
        let cfg: ConvoConfig = toml::from_str(toml_str).unwrap();
        assert!(cfg.avatar_has_preset_token());
    }

    #[test]
    fn avatar_user_supplied_token_not_overridden_by_caller() {
        // If the TOML already has agora_token, caller-provided one
        // must NOT overwrite it (user intent wins).
        let toml_str = r#"
[agent.avatar]
vendor = "akool"
avatar_id = "abc"
[agent.avatar.params]
agora_token = "007user"
"#;
        let cfg: ConvoConfig = toml::from_str(toml_str).unwrap();
        let body = cfg.build_join_payload(JoinArgs {
            name: "x", channel: "c", token: "t",
            agent_rtc_uid: "1", remote_uids: &[],
            include_avatar: true,
            avatar_user_id: "333",
            avatar_channel: Some("convoai-caller"),
            avatar_token:   Some("007caller"),
            preset: None,
            encryption_mode: None,
            encryption_key: None,
            encryption_salt: None,
            geofence_area: None,
            enable_dump: false,
        });
        assert_eq!(body["properties"]["avatar"]["params"]["agora_token"], "007user");
    }

    #[test]
    fn join_payload_avatar_params_agora_uid_override_wins() {
        // If user explicitly set agora_uid in [agent.avatar.params],
        // it wins over the caller-provided avatar_user_id arg.
        // (vendor + avatar_id both required for avatar block to be emitted)
        let toml_str = r#"
[agent.avatar]
vendor = "akool"
avatar_id = "abc"
[agent.avatar.params]
agora_uid = "explicit_from_toml"
"#;
        let cfg: ConvoConfig = toml::from_str(toml_str).unwrap();
        let body = cfg.build_join_payload(JoinArgs {
            name: "x", channel: "c", token: "t",
            agent_rtc_uid: "1", remote_uids: &[],
            include_avatar: true,
            avatar_user_id: "caller_provided",
            avatar_channel: None,
            avatar_token:   None,
            preset: None,
            encryption_mode: None,
            encryption_key: None,
            encryption_salt: None,
            geofence_area: None,
            enable_dump: false,
        });
        assert_eq!(body["properties"]["avatar"]["params"]["agora_uid"],
                   "explicit_from_toml");
    }

    #[test]
    fn join_payload_passes_through_top_level_tables() {
        // Pass-through blocks at the top level of convo.toml land as
        // nested JSON in properties.*, including deeply nested tables.
        let toml_str = r#"
[advanced_features]
enable_rtm  = true
enable_sal  = true
enable_aivad = false

[vad]
silence_duration_ms = 800

[sal]
sal_mode = "locking"

[parameters]
audio_scenario = "default"
data_channel   = "rtm"
enable_dump    = true

[parameters.transcript]
enable_words = true

[parameters.turn_detector]
validate_asr_result_timestamp = false
"#;
        let cfg: ConvoConfig = toml::from_str(toml_str).unwrap();
        let body = cfg.build_join_payload(JoinArgs {
            name: "x", channel: "c", token: "t",
            agent_rtc_uid: "1", remote_uids: &[],
            include_avatar: false,
            avatar_user_id: "999",
            avatar_channel: None,
            avatar_token:   None,
            preset: None,
            encryption_mode: None,
            encryption_key: None,
            encryption_salt: None,
            geofence_area: None,
            enable_dump: false,
        });
        let props = &body["properties"];
        assert_eq!(props["advanced_features"]["enable_rtm"],  true);
        assert_eq!(props["advanced_features"]["enable_sal"],  true);
        assert_eq!(props["advanced_features"]["enable_aivad"], false);
        assert_eq!(props["vad"]["silence_duration_ms"], 800);
        assert_eq!(props["sal"]["sal_mode"], "locking");
        assert_eq!(props["parameters"]["data_channel"], "rtm");
        assert_eq!(props["parameters"]["transcript"]["enable_words"], true);
        assert_eq!(props["parameters"]["turn_detector"]["validate_asr_result_timestamp"], false);
    }

    #[test]
    fn join_payload_uses_first_preset_from_list_when_no_runtime() {
        let toml_str = r#"presets = ["first", "second"]"#;
        let cfg: ConvoConfig = toml::from_str(toml_str).unwrap();
        let body = cfg.build_join_payload(JoinArgs {
            name: "x", channel: "c", token: "t",
            agent_rtc_uid: "1", remote_uids: &[],
            include_avatar: false,
            avatar_user_id: "999",
            avatar_channel: None,
            avatar_token:   None,
            preset: None,
            encryption_mode: None,
            encryption_key: None,
            encryption_salt: None,
            geofence_area: None,
            enable_dump: false,
        });
        assert_eq!(body["preset"], "first");
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
