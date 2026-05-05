//! `atem config convo` — interactive wizard for ConvoAI agent configuration.
//!
//! Walks the user through ASR / LLM / TTS / Avatar provider selection,
//! collects API keys and vendor-specific params, and writes
//! `~/.config/atem/convo.toml`. Always loads existing config as
//! defaults so re-runs only change what's needed.

use anyhow::{Context, Result};
use dialoguer::{Confirm, Input, Select};
use std::collections::BTreeMap;
use std::fmt::Write as FmtWrite;
use std::path::Path;

// ── Provider registry ───────────────────────────────────────────────
//
// Each provider definition has the exact param keys that Agora's
// ConvoAI /join endpoint expects. The wizard collects these and writes
// them into the appropriate TOML section.

struct Provider {
    name: &'static str,
    vendor_id: &'static str,
    beta: bool,
    /// For LLM: the `style` field value (e.g. "openai", "gemini", "anthropic").
    /// Empty string means default (OpenAI-compatible, no explicit style needed).
    style: &'static str,
    params: &'static [Param],
}

struct Param {
    key: &'static str,
    label: &'static str,
    secret: bool,
    default_value: &'static str,
    /// Hint shown to the user.
    hint: &'static str,
}

impl Provider {
    fn display(&self) -> String {
        if self.beta {
            format!("{} (Beta)", self.name)
        } else {
            self.name.to_string()
        }
    }
}

// ── ASR providers (per docs.agora.io/en/conversational-ai/models/asr/overview)

const ASR_PROVIDERS: &[Provider] = &[
    Provider { name: "ARES (Agora built-in)", vendor_id: "ares", beta: false, style: "", params: &[
        // ARES needs no API key — Agora-managed. language sits at asr level, not params.
    ]},
    Provider { name: "Microsoft Azure", vendor_id: "microsoft", beta: false, style: "", params: &[
        Param { key: "key", label: "API Key", secret: true, default_value: "", hint: "Azure Portal → Keys" },
        Param { key: "region", label: "Region", secret: false, default_value: "eastus", hint: "e.g. eastus, westus2" },
    ]},
    Provider { name: "Deepgram", vendor_id: "deepgram", beta: false, style: "", params: &[
        Param { key: "key", label: "API Key", secret: true, default_value: "", hint: "Deepgram Console → API Keys" },
        Param { key: "model", label: "Model", secret: false, default_value: "nova-2", hint: "e.g. nova-2, nova-3" },
    ]},
    Provider { name: "Soniox", vendor_id: "soniox", beta: false, style: "", params: &[
        Param { key: "api_key", label: "API Key", secret: true, default_value: "", hint: "" },
        Param { key: "model", label: "Model", secret: false, default_value: "stt-rt-v3", hint: "" },
    ]},
    Provider { name: "Speechmatics", vendor_id: "speechmatics", beta: false, style: "", params: &[
        Param { key: "api_key", label: "API Key", secret: true, default_value: "", hint: "" },
    ]},
    Provider { name: "OpenAI Whisper", vendor_id: "openai", beta: true, style: "", params: &[
        Param { key: "api_key", label: "API Key", secret: true, default_value: "", hint: "" },
        Param { key: "input_audio_transcription.model", label: "Model", secret: false, default_value: "gpt-4o-mini-transcribe", hint: "" },
        Param { key: "input_audio_transcription.language", label: "Language", secret: false, default_value: "en", hint: "" },
    ]},
    Provider { name: "AssemblyAI", vendor_id: "assemblyai", beta: true, style: "", params: &[
        Param { key: "api_key", label: "API Key", secret: true, default_value: "", hint: "" },
    ]},
    Provider { name: "Amazon Transcribe", vendor_id: "amazon", beta: true, style: "", params: &[
        Param { key: "access_key_id", label: "AWS Access Key ID", secret: true, default_value: "", hint: "" },
        Param { key: "secret_access_key", label: "AWS Secret Access Key", secret: true, default_value: "", hint: "" },
        Param { key: "region", label: "AWS Region", secret: false, default_value: "us-east-1", hint: "" },
        Param { key: "language_code", label: "Language Code", secret: false, default_value: "en-US", hint: "" },
    ]},
    Provider { name: "Google", vendor_id: "google", beta: true, style: "", params: &[
        Param { key: "project_id", label: "GCP Project ID", secret: false, default_value: "", hint: "" },
        Param { key: "location", label: "Location", secret: false, default_value: "global", hint: "" },
        Param { key: "adc_credentials_string", label: "Service Account JSON", secret: true, default_value: "", hint: "Full JSON string" },
    ]},
    Provider { name: "Sarvam", vendor_id: "sarvam", beta: true, style: "", params: &[
        Param { key: "api_key", label: "API Key", secret: true, default_value: "", hint: "" },
    ]},
];

// ── LLM providers (per docs.agora.io/en/conversational-ai/models/llm/overview)
//
// LLM uses url + api_key + style at the top level, and model inside params.
// The `vendor_id` here is used only for display/matching; the actual
// TOML uses `url` + `style` to identify the provider.

const LLM_PROVIDERS: &[Provider] = &[
    Provider { name: "OpenAI", vendor_id: "openai", beta: false, style: "", params: &[
        Param { key: "url", label: "API URL", secret: false, default_value: "https://api.openai.com/v1/chat/completions", hint: "" },
        Param { key: "api_key", label: "API Key", secret: true, default_value: "", hint: "" },
        Param { key: "model", label: "Model", secret: false, default_value: "gpt-4o-mini", hint: "e.g. gpt-4o, gpt-4o-mini" },
    ]},
    Provider { name: "Azure OpenAI", vendor_id: "azure", beta: false, style: "openai", params: &[
        Param { key: "url", label: "Azure Endpoint URL", secret: false, default_value: "", hint: "https://<resource>.openai.azure.com/openai/deployments/<deploy>/chat/completions?api-version=<ver>" },
        Param { key: "api_key", label: "API Key", secret: true, default_value: "", hint: "" },
        Param { key: "model", label: "Deployment Name", secret: false, default_value: "", hint: "Azure deployment name" },
    ]},
    Provider { name: "Groq", vendor_id: "groq", beta: false, style: "", params: &[
        Param { key: "url", label: "API URL", secret: false, default_value: "https://api.groq.com/openai/v1/chat/completions", hint: "" },
        Param { key: "api_key", label: "API Key", secret: true, default_value: "", hint: "" },
        Param { key: "model", label: "Model", secret: false, default_value: "llama-3.3-70b-versatile", hint: "" },
    ]},
    Provider { name: "Google Gemini", vendor_id: "gemini", beta: false, style: "gemini", params: &[
        Param { key: "url", label: "API URL (with key)", secret: true, default_value: "", hint: "https://generativelanguage.googleapis.com/v1beta/models/<model>:streamGenerateContent?alt=sse&key=<key>" },
        Param { key: "model", label: "Model", secret: false, default_value: "gemini-2.0-flash", hint: "" },
    ]},
    Provider { name: "Google Vertex AI", vendor_id: "vertex", beta: false, style: "gemini", params: &[
        Param { key: "url", label: "Vertex AI Endpoint", secret: false, default_value: "", hint: "https://<region>-aiplatform.googleapis.com/v1/projects/<proj>/locations/<region>/publishers/google/models/<model>:streamGenerateContent?alt=sse" },
        Param { key: "api_key", label: "GCP Access Token", secret: true, default_value: "", hint: "gcloud auth print-access-token" },
        Param { key: "model", label: "Model", secret: false, default_value: "gemini-2.0-flash-001", hint: "" },
    ]},
    Provider { name: "Claude (Anthropic)", vendor_id: "anthropic", beta: false, style: "anthropic", params: &[
        Param { key: "url", label: "API URL", secret: false, default_value: "https://api.anthropic.com/v1/messages", hint: "" },
        Param { key: "api_key", label: "API Key", secret: true, default_value: "", hint: "" },
        Param { key: "model", label: "Model", secret: false, default_value: "claude-sonnet-4-20250514", hint: "" },
        Param { key: "max_tokens", label: "Max Tokens", secret: false, default_value: "1024", hint: "Required for Anthropic" },
    ]},
    Provider { name: "Amazon Bedrock", vendor_id: "bedrock", beta: false, style: "bedrock", params: &[
        Param { key: "url", label: "Bedrock Endpoint URL", secret: false, default_value: "", hint: "https://bedrock-runtime.<region>.amazonaws.com/model/<model>/converse-stream" },
        Param { key: "access_key", label: "AWS Access Key", secret: true, default_value: "", hint: "" },
        Param { key: "secret_key", label: "AWS Secret Key", secret: true, default_value: "", hint: "" },
        Param { key: "region", label: "AWS Region", secret: false, default_value: "us-east-1", hint: "" },
        Param { key: "model", label: "Model", secret: false, default_value: "", hint: "" },
    ]},
    Provider { name: "Dify", vendor_id: "dify", beta: false, style: "dify", params: &[
        Param { key: "url", label: "Dify Endpoint URL", secret: false, default_value: "", hint: "" },
        Param { key: "api_key", label: "API Key", secret: true, default_value: "", hint: "" },
        Param { key: "model", label: "Model", secret: false, default_value: "default", hint: "" },
    ]},
    Provider { name: "Custom LLM (OpenAI-compatible)", vendor_id: "custom", beta: false, style: "", params: &[
        Param { key: "url", label: "Endpoint URL", secret: false, default_value: "", hint: "Any OpenAI-compatible /chat/completions endpoint" },
        Param { key: "api_key", label: "API Key", secret: true, default_value: "", hint: "" },
        Param { key: "model", label: "Model", secret: false, default_value: "", hint: "" },
    ]},
];

// ── TTS providers (per docs.agora.io/en/conversational-ai/models/tts/overview)

const TTS_PROVIDERS: &[Provider] = &[
    Provider { name: "Microsoft Azure", vendor_id: "microsoft", beta: false, style: "", params: &[
        Param { key: "key", label: "API Key", secret: true, default_value: "", hint: "" },
        Param { key: "region", label: "Region", secret: false, default_value: "eastus", hint: "" },
        Param { key: "voice_name", label: "Voice Name", secret: false, default_value: "en-US-AndrewMultilingualNeural", hint: "" },
        Param { key: "sample_rate", label: "Sample Rate", secret: false, default_value: "24000", hint: "16000, 24000, or 48000" },
    ]},
    Provider { name: "ElevenLabs", vendor_id: "elevenlabs", beta: false, style: "", params: &[
        Param { key: "key", label: "API Key", secret: true, default_value: "", hint: "" },
        Param { key: "model_id", label: "Model ID", secret: false, default_value: "eleven_flash_v2_5", hint: "" },
        Param { key: "voice_id", label: "Voice ID", secret: false, default_value: "", hint: "" },
        Param { key: "base_url", label: "Base URL", secret: false, default_value: "wss://api.elevenlabs.io/v1", hint: "" },
        Param { key: "sample_rate", label: "Sample Rate", secret: false, default_value: "24000", hint: "" },
    ]},
    Provider { name: "MiniMax", vendor_id: "minimax", beta: false, style: "", params: &[
        Param { key: "key", label: "API Key", secret: true, default_value: "", hint: "" },
        Param { key: "group_id", label: "Group ID", secret: false, default_value: "", hint: "" },
        Param { key: "model", label: "Model", secret: false, default_value: "speech-02-turbo", hint: "" },
        Param { key: "url", label: "WebSocket URL", secret: false, default_value: "wss://api-uw.minimax.io/ws/v1/t2a_v2", hint: "" },
        Param { key: "voice_setting.voice_id", label: "Voice ID", secret: false, default_value: "", hint: "" },
        Param { key: "audio_setting.sample_rate", label: "Sample Rate", secret: false, default_value: "16000", hint: "" },
    ]},
    Provider { name: "Cartesia", vendor_id: "cartesia", beta: true, style: "", params: &[
        Param { key: "api_key", label: "API Key", secret: true, default_value: "", hint: "" },
        Param { key: "model_id", label: "Model ID", secret: false, default_value: "sonic-2", hint: "" },
        Param { key: "voice.id", label: "Voice ID", secret: false, default_value: "", hint: "" },
        Param { key: "output_format.sample_rate", label: "Sample Rate", secret: false, default_value: "16000", hint: "" },
    ]},
    Provider { name: "OpenAI TTS", vendor_id: "openai", beta: true, style: "", params: &[
        Param { key: "base_url", label: "Base URL", secret: false, default_value: "https://api.openai.com/v1", hint: "" },
        Param { key: "api_key", label: "API Key", secret: true, default_value: "", hint: "" },
        Param { key: "model", label: "Model", secret: false, default_value: "gpt-4o-mini-tts", hint: "" },
        Param { key: "voice", label: "Voice", secret: false, default_value: "coral", hint: "e.g. alloy, echo, fable, onyx, nova, shimmer, coral" },
    ]},
    Provider { name: "Hume AI", vendor_id: "humeai", beta: true, style: "", params: &[
        Param { key: "key", label: "API Key", secret: true, default_value: "", hint: "" },
        Param { key: "voice_id", label: "Voice ID", secret: false, default_value: "", hint: "" },
    ]},
    Provider { name: "Rime", vendor_id: "rime", beta: true, style: "", params: &[
        Param { key: "api_key", label: "API Key", secret: true, default_value: "", hint: "" },
        Param { key: "speaker", label: "Speaker", secret: false, default_value: "cove", hint: "" },
        Param { key: "modelId", label: "Model ID", secret: false, default_value: "mistv2", hint: "camelCase: modelId" },
    ]},
    Provider { name: "Fish Audio", vendor_id: "fishaudio", beta: true, style: "", params: &[
        Param { key: "api_key", label: "API Key", secret: true, default_value: "", hint: "" },
        Param { key: "reference_id", label: "Reference ID", secret: false, default_value: "", hint: "Voice model ID" },
        Param { key: "backend", label: "Backend", secret: false, default_value: "speech-1.5", hint: "" },
    ]},
    Provider { name: "Google", vendor_id: "google", beta: true, style: "", params: &[
        Param { key: "credentials", label: "Service Account JSON", secret: true, default_value: "", hint: "Full GCP service account JSON" },
        Param { key: "VoiceSelectionParams.name", label: "Voice Name", secret: false, default_value: "", hint: "e.g. en-US-Chirp3-HD-Charon" },
    ]},
    Provider { name: "Amazon Polly", vendor_id: "amazon", beta: true, style: "", params: &[
        Param { key: "aws_access_key_id", label: "AWS Access Key ID", secret: true, default_value: "", hint: "" },
        Param { key: "aws_secret_access_key", label: "AWS Secret Key", secret: true, default_value: "", hint: "" },
        Param { key: "region_name", label: "AWS Region", secret: false, default_value: "us-east-1", hint: "" },
        Param { key: "voice", label: "Voice", secret: false, default_value: "Joanna", hint: "" },
        Param { key: "engine", label: "Engine", secret: false, default_value: "neural", hint: "standard, neural, long-form, generative" },
    ]},
    Provider { name: "Murf", vendor_id: "murf", beta: true, style: "", params: &[
        Param { key: "api_key", label: "API Key", secret: true, default_value: "", hint: "" },
        Param { key: "voiceId", label: "Voice ID", secret: false, default_value: "", hint: "" },
    ]},
    Provider { name: "Sarvam", vendor_id: "sarvam", beta: true, style: "", params: &[
        Param { key: "api_subscription_key", label: "API Subscription Key", secret: true, default_value: "", hint: "Note: key name is api_subscription_key, not api_key" },
        Param { key: "speaker", label: "Speaker", secret: false, default_value: "anushka", hint: "e.g. anushka, manisha, vidya, abhilash, karun" },
        Param { key: "target_language_code", label: "Language", secret: false, default_value: "en-IN", hint: "" },
    ]},
];

// ── Avatar providers (per docs.agora.io/en/conversational-ai/models/avatar/overview)

const AVATAR_PROVIDERS: &[Provider] = &[
    Provider { name: "Akool", vendor_id: "akool", beta: true, style: "", params: &[
        Param { key: "api_key", label: "API Key", secret: true, default_value: "", hint: "Contact Agora sales" },
        Param { key: "avatar_id", label: "Avatar ID", secret: false, default_value: "", hint: "" },
        // agora_uid + agora_token + agora_channel are auto-generated by atem
    ]},
    Provider { name: "LiveAvatar", vendor_id: "liveavatar", beta: true, style: "", params: &[
        Param { key: "api_key", label: "API Key", secret: true, default_value: "", hint: "" },
        Param { key: "quality", label: "Quality", secret: false, default_value: "high", hint: "high (720p), medium (480p), low (360p)" },
    ]},
    Provider { name: "Anam", vendor_id: "anam", beta: true, style: "", params: &[
        Param { key: "api_key", label: "API Key", secret: true, default_value: "", hint: "" },
        Param { key: "avatar_id", label: "Avatar ID", secret: false, default_value: "", hint: "" },
    ]},
];

// ── MLLM providers (per docs.agora.io/en/conversational-ai/models/mllm/overview)

// vendor_id values match Agora's `/join` body contract — server
// rejects anything outside the set {"openai","gemini","vertexai","xai"}.
const MLLM_PROVIDERS: &[Provider] = &[
    Provider { name: "OpenAI Realtime API", vendor_id: "openai", beta: false, style: "", params: &[
        Param { key: "api_key", label: "API Key", secret: true, default_value: "", hint: "" },
        Param { key: "model", label: "Model", secret: false, default_value: "gpt-realtime", hint: "" },
        Param { key: "voice", label: "Voice", secret: false, default_value: "alloy", hint: "alloy, echo, fable, onyx, nova, shimmer" },
        Param { key: "instructions", label: "Instructions", secret: false, default_value: "You are a Conversational AI Agent, developed by Agora.", hint: "System prompt sent to the model" },
    ]},
    Provider { name: "Google Gemini Live", vendor_id: "gemini", beta: false, style: "", params: &[
        Param { key: "api_key", label: "API Key", secret: true, default_value: "", hint: "" },
        Param { key: "model", label: "Model", secret: false, default_value: "gemini-2.0-flash-live-001", hint: "" },
    ]},
    Provider { name: "Google Gemini Live (Vertex AI)", vendor_id: "vertexai", beta: false, style: "", params: &[
        Param { key: "project_id", label: "GCP Project ID", secret: false, default_value: "", hint: "" },
        Param { key: "location", label: "Location", secret: false, default_value: "us-central1", hint: "" },
        Param { key: "adc_credentials_string", label: "Service Account JSON", secret: true, default_value: "", hint: "Full JSON string" },
        Param { key: "model", label: "Model", secret: false, default_value: "gemini-2.0-flash-live-001", hint: "" },
    ]},
    Provider { name: "xAI Grok Realtime", vendor_id: "xai", beta: true, style: "", params: &[
        Param { key: "api_key", label: "API Key", secret: true, default_value: "", hint: "" },
        Param { key: "model", label: "Model", secret: false, default_value: "grok-4", hint: "" },
    ]},
];

// ── Wizard answers ──────────────────────────────────────────────────

#[derive(Default)]
struct WizardAnswers {
    use_preset: bool,
    presets: Vec<String>,

    channel: String,
    rtc_user_id: String,
    agent_user_id: String,
    idle_timeout_secs: u32,

    // ASR
    asr_vendor: String,
    asr_language: String,
    asr_params: BTreeMap<String, String>,

    // LLM
    llm_style: String,         // "openai", "gemini", "anthropic", "bedrock", "dify", ""
    llm_vendor: String,        // "azure" when applicable
    llm_url: String,
    llm_api_key: String,
    llm_greeting: String,
    llm_failure: String,
    llm_system_prompt: String,
    llm_params: BTreeMap<String, String>,

    // TTS
    tts_vendor: String,
    tts_params: BTreeMap<String, String>,

    // MLLM (optional — replaces ASR+LLM+TTS when set)
    mllm_vendor: String,
    mllm_url: String,
    mllm_api_key: String,
    mllm_greeting_message: String,
    mllm_params: BTreeMap<String, String>,

    // Avatar
    avatar_vendor: String,
    avatar_id_value: String,
    avatar_params: BTreeMap<String, String>,

    // Advanced
    enable_rtm: bool,
    enable_sal: bool,
    data_channel: String,
    enable_words: bool,
    vad_silence_ms: u32,
}

// ── Helpers ─────────────────────────────────────────────────────────

fn mask_secret(s: &str) -> String {
    if s.len() <= 8 { "****".to_string() }
    else { format!("{}...{}", &s[..4], &s[s.len()-4..]) }
}

fn find_provider_index(providers: &[Provider], vendor_id: &str) -> Option<usize> {
    providers.iter().position(|p| p.vendor_id == vendor_id)
}

fn prompt_input(label: &str, default: &str, secret: bool) -> Result<String> {
    if secret && !default.is_empty() {
        // Secret with existing value: show masked hint, DON'T pass
        // the raw value to .default() — dialoguer would print it in
        // plaintext on the terminal. Empty input = keep existing.
        let masked = mask_secret(default);
        let input: String = Input::new()
            .with_prompt(format!("{} [{}] (Enter to keep)", label, masked))
            .allow_empty(true)
            .interact_text()?;
        Ok(if input.trim().is_empty() { default.to_string() } else { input })
    } else if secret {
        // Secret, no existing value: plain prompt, no default shown
        let input: String = Input::new()
            .with_prompt(label)
            .allow_empty(true)
            .interact_text()?;
        Ok(input)
    } else {
        let mut builder = Input::<String>::new().with_prompt(label);
        if !default.is_empty() {
            builder = builder.default(default.to_string());
        }
        builder = builder.allow_empty(true);
        Ok(builder.interact_text()?)
    }
}

fn select_provider(category: &str, providers: &[Provider], current_vendor: &str) -> Result<usize> {
    let items: Vec<String> = providers.iter().map(|p| p.display()).collect();
    let default = find_provider_index(providers, current_vendor).unwrap_or(0);
    Ok(Select::new()
        .with_prompt(format!("{} Provider", category))
        .items(&items)
        .default(default)
        .interact()?)
}

fn collect_provider_params(provider: &Provider, existing: &BTreeMap<String, String>) -> Result<BTreeMap<String, String>> {
    let mut result = BTreeMap::new();
    for param in provider.params {
        let current = existing.get(param.key).map(|s| s.as_str()).unwrap_or(param.default_value);
        let hint = if param.hint.is_empty() { String::new() } else { format!(" ({})", param.hint) };
        let value = prompt_input(&format!("{}{}", param.label, hint), current, param.secret)?;
        if !value.is_empty() {
            result.insert(param.key.to_string(), value);
        }
    }
    Ok(result)
}

fn service_params_flat(cfg: &crate::convo_config::ServiceConfig) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    flatten_toml_map("", &cfg.params, &mut m);
    m
}

/// Flatten nested toml tables into dot-separated keys: {a: {b: "c"}} → "a.b" = "c"
fn flatten_toml_map(prefix: &str, map: &BTreeMap<String, toml::Value>, out: &mut BTreeMap<String, String>) {
    for (k, v) in map {
        let key = if prefix.is_empty() { k.clone() } else { format!("{}.{}", prefix, k) };
        match v {
            toml::Value::String(s) => { out.insert(key, s.clone()); }
            toml::Value::Integer(n) => { out.insert(key, n.to_string()); }
            toml::Value::Float(f) => { out.insert(key, f.to_string()); }
            toml::Value::Boolean(b) => { out.insert(key, b.to_string()); }
            toml::Value::Table(t) => {
                let inner: BTreeMap<String, toml::Value> = t.iter().map(|(k2, v2)| (k2.clone(), v2.clone())).collect();
                flatten_toml_map(&key, &inner, out);
            }
            _ => {}
        }
    }
}

// ── Wizard ──────────────────────────────────────────────────────────

pub fn run_wizard(config_path: &Path) -> Result<()> {
    println!("ConvoAI Agent Configuration Wizard");
    println!("Config: {}\n", config_path.display());

    let existing = if config_path.exists() {
        crate::convo_config::ConvoConfig::from_file(config_path).ok()
    } else { None };
    let existing = existing.unwrap_or_default();

    let mut a = WizardAnswers::default();
    let existing_atem  = existing.atem.as_ref();
    let existing_agent = existing.agent.as_ref();

    // Step 1: Channel & User (writes under [atem] in convo.toml)
    println!("\n── Channel & User ──");
    a.channel = prompt_input(
        "Channel (empty = auto-generate)",
        existing_atem.and_then(|x| x.channel.as_deref()).unwrap_or(""),
        false,
    )?;
    a.rtc_user_id = prompt_input(
        "RTC User",
        existing_atem.and_then(|x| x.rtc_user_id.as_deref()).unwrap_or("0"),
        false,
    )?;

    // Step 2: Agent (writes under [agent] in convo.toml)
    println!("\n── Agent ──");
    a.agent_user_id = prompt_input(
        "Agent User",
        existing_agent.and_then(|x| x.user_id.as_deref()).unwrap_or("1001"),
        false,
    )?;
    let t_default = existing_agent
        .and_then(|x| x.idle_timeout_secs)
        .unwrap_or(120)
        .to_string();
    a.idle_timeout_secs = prompt_input("Idle timeout (seconds)", &t_default, false)?.parse().unwrap_or(120);

    // Step 3: Preset (empty to skip). Independent of Custom — preset
    // sets defaults; explicit cascaded/MLLM blocks override per-field.
    let cur_preset = existing_agent.and_then(|x| x.preset.as_deref()).unwrap_or("");
    let preset_input = prompt_input("Preset name(s), comma-separated (empty = skip)", cur_preset, false)?;
    a.presets = preset_input
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    a.use_preset = !a.presets.is_empty();

    // Step 4: Custom override (optional). User picks zero, one, or
    // both pipelines via multi-select. [atem].pipeline still selects
    // which one is sent in /join; the other parks in convo.toml.
    let has_cascaded = existing_agent.map(|ag|
        ag.asr.is_some() || ag.llm.is_some() || ag.tts.is_some()).unwrap_or(false);
    let has_mllm = existing_agent.and_then(|ag| ag.mllm.as_ref()).is_some();
    let any_custom = has_cascaded || has_mllm;
    let prompt_label = if a.use_preset { "Add Custom override?" } else { "Configure Custom?" };
    let configure_providers = Confirm::new()
        .with_prompt(prompt_label)
        .default(if a.use_preset { any_custom } else { true })
        .interact()?;

    let mut do_cascaded = false;
    let mut do_mllm = false;
    if configure_providers {
        let pipeline_items = &[
            "Cascaded (ASR + LLM + TTS)",
            "Multimodal LLM",
        ];
        let prior_pipeline = existing_atem.and_then(|x| x.pipeline.as_deref());
        let default_idx = match prior_pipeline {
            Some("mllm") => 1,
            _            => if has_mllm && !has_cascaded { 1 } else { 0 },
        };
        let chosen = Select::new()
            .with_prompt("Pipeline")
            .items(pipeline_items)
            .default(default_idx)
            .interact()?;
        do_cascaded = chosen == 0;
        do_mllm     = chosen == 1;

        if do_mllm {
            // MLLM — single multimodal model. Pre-fill from any
            // existing [agent.mllm] block: vendor for the provider
            // dropdown's default + params for each prompt's default.
            println!("\n── MLLM (Multimodal LLM) ──");
            let cur_vendor = existing.agent.as_ref()
                .and_then(|ag| ag.mllm.as_ref())
                .and_then(|m| m.vendor.as_deref())
                .unwrap_or("");
            let idx = select_provider("MLLM", MLLM_PROVIDERS, cur_vendor)?;
            let prov = &MLLM_PROVIDERS[idx];
            a.mllm_vendor = prov.vendor_id.to_string();
            let url_default = match prov.vendor_id {
                "openai" => "wss://api.openai.com/v1/realtime",
                _        => "",
            };
            let cur_url = existing.agent.as_ref()
                .and_then(|ag| ag.mllm.as_ref())
                .and_then(|m| m.url.as_deref())
                .unwrap_or(url_default);
            a.mllm_url = prompt_input("Endpoint URL", cur_url, false)?;

            // collect_provider_params returns api_key inside the
            // params map for prompt-flow consistency. Agora's MLLM
            // schema expects api_key at the top of the `mllm` block,
            // so hoist it after collection.
            let mut existing_p = existing.agent.as_ref()
                .and_then(|ag| ag.mllm.as_ref())
                .map(service_params_flat)
                .unwrap_or_default();
            if let Some(k) = existing.agent.as_ref()
                .and_then(|ag| ag.mllm.as_ref())
                .and_then(|m| m.api_key.as_deref())
            {
                existing_p.entry("api_key".into()).or_insert(k.to_string());
            }
            a.mllm_params = collect_provider_params(prov, &existing_p)?;
            if let Some(k) = a.mllm_params.remove("api_key") {
                a.mllm_api_key = k;
            }

            // greeting_message is top-level on the mllm block.
            let cur_greet = existing.agent.as_ref()
                .and_then(|ag| ag.mllm.as_ref())
                .and_then(|m| m.greeting_message.as_deref())
                .unwrap_or("");
            a.mllm_greeting_message = prompt_input("Greeting message (empty = skip)", cur_greet, false)?;
        }

        if do_cascaded {
            // Cascaded — ASR + LLM + TTS
            let suffix = if a.use_preset { " — override" } else { "" };

            // ASR
            println!("\n── ASR (Speech-to-Text){} ──", suffix);
            let cur_vendor = existing.agent.as_ref().and_then(|ag| ag.asr.as_ref()).and_then(|s| s.vendor.as_deref()).unwrap_or("");
            let idx = select_provider("ASR", ASR_PROVIDERS, cur_vendor)?;
            let prov = &ASR_PROVIDERS[idx];
            a.asr_vendor = prov.vendor_id.to_string();
            let existing_p = existing.agent.as_ref().and_then(|ag| ag.asr.as_ref()).map(service_params_flat).unwrap_or_default();
            a.asr_params = collect_provider_params(prov, &existing_p)?;
            let cur_lang = existing.agent.as_ref().and_then(|ag| ag.asr.as_ref()).and_then(|s| s.language.as_deref()).unwrap_or("en-US");
            a.asr_language = prompt_input("Language", cur_lang, false)?;

            // LLM
            println!("\n── LLM (Language Model){} ──", suffix);
            let cur_llm_vendor = existing.agent.as_ref().and_then(|ag| ag.llm.as_ref()).and_then(|l| {
                l.url.as_deref().and_then(|u| {
                    if u.contains("groq.com") { Some("groq") }
                    else if u.contains("anthropic") { Some("anthropic") }
                    else if u.contains("openai.com") { Some("openai") }
                    else if u.contains("generativelanguage.googleapis.com") { Some("gemini") }
                    else if u.contains("aiplatform.googleapis.com") { Some("vertex") }
                    else if u.contains("bedrock") { Some("bedrock") }
                    else { None }
                })
            }).unwrap_or("");
            let idx = select_provider("LLM", LLM_PROVIDERS, cur_llm_vendor)?;
            let prov = &LLM_PROVIDERS[idx];
            a.llm_style = prov.style.to_string();
            if prov.vendor_id == "azure" { a.llm_vendor = "azure".to_string(); }

            let mut existing_p = BTreeMap::new();
            if let Some(l) = existing.agent.as_ref().and_then(|ag| ag.llm.as_ref()) {
                if let Some(u) = &l.url { existing_p.insert("url".to_string(), u.clone()); }
                if let Some(k) = &l.api_key { existing_p.insert("api_key".to_string(), k.clone()); }
                for (k, v) in &l.params {
                    if let Some(s) = v.as_str() { existing_p.insert(k.clone(), s.to_string()); }
                }
            }
            a.llm_params = collect_provider_params(prov, &existing_p)?;
            a.llm_url = a.llm_params.remove("url").unwrap_or_default();
            a.llm_api_key = a.llm_params.remove("api_key").unwrap_or_default();

            let existing_llm = existing.agent.as_ref().and_then(|ag| ag.llm.as_ref());
            a.llm_greeting = prompt_input("Greeting message", existing_llm.and_then(|l| l.greeting_message.as_deref()).unwrap_or("Hi, how can I help?"), false)?;
            a.llm_failure = prompt_input("Failure message", existing_llm.and_then(|l| l.failure_message.as_deref()).unwrap_or("Error, please hold on."), false)?;
            let cur_prompt = existing_llm.and_then(|l| l.system_messages.first()).map(|m| m.content.as_str()).unwrap_or("You are a helpful conversational AI agent.");
            println!("System prompt (single line; for multiline edit TOML directly):");
            a.llm_system_prompt = prompt_input("  Prompt", cur_prompt, false)?;

            // TTS
            println!("\n── TTS (Text-to-Speech){} ──", suffix);
            let cur_vendor = existing.agent.as_ref().and_then(|ag| ag.tts.as_ref()).and_then(|s| s.vendor.as_deref()).unwrap_or("");
            let idx = select_provider("TTS", TTS_PROVIDERS, cur_vendor)?;
            let prov = &TTS_PROVIDERS[idx];
            a.tts_vendor = prov.vendor_id.to_string();
            let existing_p = existing.agent.as_ref().and_then(|ag| ag.tts.as_ref()).map(service_params_flat).unwrap_or_default();
            a.tts_params = collect_provider_params(prov, &existing_p)?;
        }
    }

    // Step 5: Avatar (optional, both modes)
    println!("\n── Avatar (optional) ──");
    let mut avatar_items = vec!["Skip".to_string()];
    avatar_items.extend(AVATAR_PROVIDERS.iter().map(|p| p.display()));
    let cur_av = existing.agent.as_ref().and_then(|ag| ag.avatar.as_ref()).and_then(|s| s.vendor.as_deref())
        .and_then(|v| find_provider_index(AVATAR_PROVIDERS, v)).map(|i| i + 1).unwrap_or(0);
    let av_idx = Select::new().with_prompt("Avatar Provider").items(&avatar_items).default(cur_av).interact()?;
    if av_idx > 0 {
        let prov = &AVATAR_PROVIDERS[av_idx - 1];
        a.avatar_vendor = prov.vendor_id.to_string();
        // `service_params_flat` only flattens [agent.avatar.params], but
        // `avatar_id` lives at the top of [agent.avatar] (sibling to
        // `params`). Inject it into the params map under the key the
        // provider definition expects, so the "Avatar ID" prompt
        // pre-fills with the existing value instead of empty.
        let mut existing_p = existing.agent.as_ref()
            .and_then(|ag| ag.avatar.as_ref())
            .map(service_params_flat)
            .unwrap_or_default();
        if let Some(cur_id) = existing.agent.as_ref()
            .and_then(|ag| ag.avatar.as_ref())
            .and_then(|s| s.avatar_id.as_deref())
            .filter(|s| !s.is_empty())
        {
            existing_p.entry("avatar_id".to_string())
                .or_insert_with(|| cur_id.to_string());
        }
        a.avatar_params = collect_provider_params(prov, &existing_p)?;
        a.avatar_id_value = a.avatar_params.remove("avatar_id").unwrap_or_default();
    }

    // Advanced
    println!("\n── Advanced Features ──");
    a.enable_rtm = Confirm::new().with_prompt("Enable RTM (required for transcription)").default(true).interact()?;
    a.enable_sal = Confirm::new().with_prompt("Enable SAL").default(true).interact()?;
    a.data_channel = prompt_input("Data channel", "rtm", false)?;
    a.enable_words = Confirm::new().with_prompt("Enable word-level transcription").default(true).interact()?;
    a.vad_silence_ms = prompt_input("VAD silence duration (ms)", "800", false)?.parse().unwrap_or(800);

    // Generate + preview + save. Round-trip via toml_edit so the
    // user's existing comments, key ordering, and any sections the
    // wizard didn't ask about (e.g., parked MLLM/ASR-LLM-TTS blocks
    // when toggling pipelines) are preserved.
    let existing = if config_path.exists() {
        std::fs::read_to_string(config_path).unwrap_or_default()
    } else {
        String::new()
    };
    let mut doc: toml_edit::DocumentMut = existing
        .parse()
        .with_context(|| format!("Failed to parse existing {}", config_path.display()))?;
    apply_to_doc(&mut doc, &a);
    let toml = doc.to_string();
    println!("\n── Preview ──\n{}", toml);

    if Confirm::new().with_prompt(format!("Save to {}?", config_path.display())).default(true).interact()? {
        if let Some(dir) = config_path.parent() { std::fs::create_dir_all(dir)?; }
        // Rotate backups (max 5: .bak, .bak.1, ..., .bak.4) before
        // overwriting. Lets the operator recover from a wizard run
        // that nuked something they wanted to keep.
        rotate_backups(config_path, 5)
            .with_context(|| format!("Failed to back up {}", config_path.display()))?;
        std::fs::write(config_path, &toml).with_context(|| format!("Failed to write {}", config_path.display()))?;
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(config_path, std::fs::Permissions::from_mode(0o600));
        }
        println!("\nSaved to {}", config_path.display());
        println!("Run `atem serv convo` to launch the agent.");
    } else {
        println!("Cancelled.");
    }
    Ok(())
}

/// Rotate `path` to a numbered `.bak` series, keeping at most `max`
/// generations. Strategy:
///   * `<file>.bak`     — most recent backup
///   * `<file>.bak.1`   — one save ago
///   * `<file>.bak.2`   ... up to `<file>.bak.<max-1>` (oldest kept)
///
/// On each save: drop the oldest, shift each existing `.bak.N` to
/// `.bak.N+1`, then copy current → `.bak`.
pub(crate) fn rotate_backups(path: &Path, max: usize) -> Result<()> {
    if !path.exists() || max == 0 {
        return Ok(());
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name   = path.file_name()
        .ok_or_else(|| anyhow::anyhow!("no filename in {}", path.display()))?
        .to_string_lossy()
        .into_owned();
    let bak = |i: usize| -> std::path::PathBuf {
        if i == 0 { parent.join(format!("{}.bak",     name)) }
        else      { parent.join(format!("{}.bak.{}",  name, i)) }
    };
    // Drop the oldest if it would otherwise push past `max`.
    let oldest = bak(max - 1);
    if oldest.exists() {
        let _ = std::fs::remove_file(&oldest);
    }
    // Shift down: bak.(max-2) → bak.(max-1), ..., bak.1 → bak.2, bak → bak.1
    for i in (0..max - 1).rev() {
        let from = bak(i);
        let to   = bak(i + 1);
        if from.exists() {
            std::fs::rename(&from, &to)?;
        }
    }
    // Current file → .bak
    std::fs::copy(path, bak(0))?;
    Ok(())
}

/// Apply wizard answers to a `toml_edit::DocumentMut`, preserving any
/// content (comments, ordering, unrelated keys, parked provider
/// blocks) the wizard didn't explicitly touch.
///
/// Sections the wizard ALWAYS owns and replaces: `[atem]`,
/// `[agent]` scalars (user_id/idle_timeout_secs/preset),
/// `[advanced_features]`, `[vad]`, `[sal]`, `[parameters]` (+ its
/// `transcript` / `turn_detector` sub-tables).
///
/// Sections written ONLY when the wizard collected fresh data:
/// `[agent.avatar]`, `[agent.mllm]`, `[agent.llm]` / `[agent.asr]` /
/// `[agent.tts]`. If the user picks MLLM mode this run, the
/// cascaded blocks stay parked in the file as-is.
fn apply_to_doc(doc: &mut toml_edit::DocumentMut, a: &WizardAnswers) {
    use toml_edit::{value, Item, Table};

    // ── [atem] ────────────────────────────────────────────────
    if doc.get("atem").is_none() {
        doc["atem"] = Item::Table(Table::new());
    }
    let atem = doc["atem"].as_table_mut().expect("atem is table");
    if !a.channel.is_empty() {
        atem["channel"] = value(a.channel.as_str());
    } else {
        atem.remove("channel");
    }
    atem["rtc_user_id"] = value(a.rtc_user_id.as_str());
    // Pipeline: explicit so re-parses survive even when both blocks
    // are parked. If the user configured exactly one this run, that
    // wins; otherwise preserve the prior choice (default cascaded).
    let prior_pipeline = atem.get("pipeline")
        .and_then(|v| v.as_str())
        .map(String::from);
    let configured_mllm     = !a.mllm_vendor.is_empty();
    let configured_cascaded = !a.asr_vendor.is_empty();
    let pipeline_value: String = match (configured_mllm, configured_cascaded) {
        (true,  false) => "mllm".into(),
        (false, true)  => "cascaded".into(),
        _              => prior_pipeline.unwrap_or_else(|| "cascaded".into()),
    };
    atem["pipeline"] = value(pipeline_value.as_str());

    // ── [agent] ───────────────────────────────────────────────
    if doc.get("agent").is_none() {
        doc["agent"] = Item::Table(Table::new());
    }
    let agent = doc["agent"].as_table_mut().expect("agent is table");
    agent["user_id"] = value(a.agent_user_id.as_str());
    agent["idle_timeout_secs"] = value(a.idle_timeout_secs as i64);
    if a.use_preset && !a.presets.is_empty() {
        agent["preset"] = value(a.presets.join(","));
    } else {
        agent.remove("preset");
    }

    // ── Pass-through tables (always wizard-managed) ───────────
    let af = ensure_table(doc, "advanced_features");
    af["enable_rtm"]   = value(a.enable_rtm);
    af["enable_sal"]   = value(a.enable_sal);
    af["enable_aivad"] = value(false);

    let vad = ensure_table(doc, "vad");
    vad["silence_duration_ms"] = value(a.vad_silence_ms as i64);

    let sal = ensure_table(doc, "sal");
    sal["sal_mode"] = value("locking");

    let parameters = ensure_table(doc, "parameters");
    parameters["audio_scenario"] = value("default");
    parameters["data_channel"]   = value(a.data_channel.as_str());
    let transcript = ensure_subtable(parameters, "transcript");
    transcript["enable_words"] = value(a.enable_words);
    let turn_detector = ensure_subtable(parameters, "turn_detector");
    turn_detector["validate_asr_result_timestamp"] = value(false);

    // ── [agent.avatar] (only when user picked an avatar) ─────
    if !a.avatar_vendor.is_empty() {
        let agent = doc["agent"].as_table_mut().unwrap();
        let av = ensure_subtable(agent, "avatar");
        av["vendor"] = value(a.avatar_vendor.as_str());
        if !a.avatar_id_value.is_empty() {
            av["avatar_id"] = value(a.avatar_id_value.as_str());
        } else {
            av.remove("avatar_id");
        }
        if !a.avatar_params.is_empty() {
            // Replace the params table in full so removed keys go away.
            av.remove("params");
            let params = ensure_subtable(av, "params");
            apply_flat_params(params, &a.avatar_params);
        }
    }

    // ── [agent.mllm] (only when user picked MLLM mode) ───────
    if !a.mllm_vendor.is_empty() {
        let agent = doc["agent"].as_table_mut().unwrap();
        let m = ensure_subtable(agent, "mllm");
        m["vendor"] = value(a.mllm_vendor.as_str());
        if !a.mllm_url.is_empty() {
            m["url"] = value(a.mllm_url.as_str());
        } else {
            m.remove("url");
        }
        if !a.mllm_api_key.is_empty() {
            m["api_key"] = value(a.mllm_api_key.as_str());
        } else {
            m.remove("api_key");
        }
        if !a.mllm_greeting_message.is_empty() {
            m["greeting_message"] = value(a.mllm_greeting_message.as_str());
        } else {
            m.remove("greeting_message");
        }
        if !a.mllm_params.is_empty() {
            m.remove("params");
            let p = ensure_subtable(m, "params");
            apply_flat_params(p, &a.mllm_params);
        }
    }

    // ── [agent.llm/asr/tts] (only when user picked cascaded) ─
    let cascaded_filled = !a.asr_vendor.is_empty()
        || !a.llm_url.is_empty()
        || !a.llm_api_key.is_empty()
        || !a.tts_vendor.is_empty();
    if cascaded_filled {
        let agent = doc["agent"].as_table_mut().unwrap();

        // LLM
        let llm = ensure_subtable(agent, "llm");
        if !a.llm_url.is_empty()      { llm["url"]              = value(a.llm_url.as_str()); }
        if !a.llm_api_key.is_empty()  { llm["api_key"]          = value(a.llm_api_key.as_str()); }
        if !a.llm_vendor.is_empty()   { llm["vendor"]           = value(a.llm_vendor.as_str()); }
        if !a.llm_style.is_empty()    { llm["style"]            = value(a.llm_style.as_str()); }
        if !a.llm_greeting.is_empty() { llm["greeting_message"] = value(a.llm_greeting.as_str()); }
        if !a.llm_failure.is_empty()  { llm["failure_message"]  = value(a.llm_failure.as_str()); }

        // system_messages — replace as a single-element array of tables.
        if !a.llm_system_prompt.is_empty() {
            let mut arr = toml_edit::ArrayOfTables::new();
            let mut row = Table::new();
            row["role"]    = value("system");
            row["content"] = value(a.llm_system_prompt.as_str());
            arr.push(row);
            llm.insert("system_messages", Item::ArrayOfTables(arr));
        }

        // params — replace in full.
        llm.remove("params");
        if !a.llm_params.is_empty() {
            let p = ensure_subtable(llm, "params");
            apply_flat_params(p, &a.llm_params);
        }

        // Anthropic needs a versioned header.
        if a.llm_style == "anthropic" {
            llm.remove("headers");
            let h = ensure_subtable(llm, "headers");
            h["anthropic-version"] = value("2023-06-01");
        }

        // ASR
        let asr = ensure_subtable(agent, "asr");
        asr["vendor"] = value(a.asr_vendor.as_str());
        if !a.asr_language.is_empty() { asr["language"] = value(a.asr_language.as_str()); }
        asr.remove("params");
        if !a.asr_params.is_empty() {
            let p = ensure_subtable(asr, "params");
            apply_flat_params(p, &a.asr_params);
        }

        // TTS
        let tts = ensure_subtable(agent, "tts");
        tts["vendor"] = value(a.tts_vendor.as_str());
        tts.remove("params");
        if !a.tts_params.is_empty() {
            let p = ensure_subtable(tts, "params");
            apply_flat_params(p, &a.tts_params);
        }
    }
}

fn ensure_table<'a>(doc: &'a mut toml_edit::DocumentMut, name: &str) -> &'a mut toml_edit::Table {
    if doc.get(name).is_none() {
        doc[name] = toml_edit::Item::Table(toml_edit::Table::new());
    }
    doc[name].as_table_mut().expect("table")
}

fn ensure_subtable<'a>(parent: &'a mut toml_edit::Table, name: &str) -> &'a mut toml_edit::Table {
    if !parent.contains_key(name) {
        parent.insert(name, toml_edit::Item::Table(toml_edit::Table::new()));
    }
    parent.get_mut(name).and_then(|i| i.as_table_mut()).expect("subtable")
}

/// Apply a flat `BTreeMap<String, String>` (where keys may contain
/// dots indicating nested sub-tables) to a toml_edit Table. Values
/// are coerced into the appropriate TOML type heuristically.
fn apply_flat_params(table: &mut toml_edit::Table, params: &std::collections::BTreeMap<String, String>) {
    for (k, v) in params {
        if let Some((head, tail)) = k.split_once('.') {
            let sub = ensure_subtable(table, head);
            // Recurse for deeper nesting via a small helper map.
            let mut one = std::collections::BTreeMap::new();
            one.insert(tail.to_string(), v.clone());
            apply_flat_params(sub, &one);
        } else {
            table[k] = coerce_value(v);
        }
    }
}

/// Heuristic value coercion: booleans stay booleans, integers stay
/// integers IF they fit JS-safe range (≤ 2^53), everything else
/// stays a quoted string. The JS-safe cap protects values like
/// minimax's `group_id = 1967483817044222128` which would lose
/// precision when serialized to JSON downstream.
fn coerce_value(s: &str) -> toml_edit::Item {
    use toml_edit::value;
    const JS_SAFE_MAX: i64 = 9_007_199_254_740_992;
    if s == "true"  { return value(true);  }
    if s == "false" { return value(false); }
    if let Ok(n) = s.parse::<i64>() {
        if n.abs() <= JS_SAFE_MAX {
            return value(n);
        }
    }
    value(s)
}

// ── TOML builder ────────────────────────────────────────────────────

/// Write a param to TOML. Dotted keys (e.g. "voice_setting.voice_id")
/// become nested tables. Values are ALWAYS quoted as strings — never
/// written as bare integers — because:
///   1. Large numeric-looking strings (e.g. group_id "1967483817044222128")
///      overflow JS safe-integer if serialized as numbers, causing
///      precision loss and Agora 400 errors.
///   2. The ConvoConfig parser uses BTreeMap<String, toml::Value> which
///      preserves TOML types, and toml_value_to_json faithfully converts
///      String→String. Writing them as TOML strings is always safe.
/// Booleans are the one exception (true/false without quotes).
/// Keys that should be written as bare integers in TOML (not quoted).
/// Everything else stays as a quoted string to avoid precision loss
/// on large numeric-looking values like group_id.
const NUMERIC_KEYS: &[&str] = &[
    "sample_rate", "sample_rate_hertz", "max_tokens",
    "media_sample_rate_hz", "speed", "volume", "rate", "pitch",
    "loudness", "pace", "stability", "similarity_boost",
    "trailing_silence",
];

fn write_param(t: &mut String, section: &str, key: &str, value: &str) {
    let write_value = |t: &mut String, leaf: &str, val: &str| {
        if val == "true" || val == "false" {
            let _ = writeln!(t, "{} = {}", leaf, val);
        } else if NUMERIC_KEYS.contains(&leaf) {
            if let Ok(n) = val.parse::<i64>() {
                let _ = writeln!(t, "{} = {}", leaf, n);
            } else if let Ok(f) = val.parse::<f64>() {
                let _ = writeln!(t, "{} = {}", leaf, f);
            } else {
                let _ = writeln!(t, "{} = {:?}", leaf, val);
            }
        } else {
            let _ = writeln!(t, "{} = {:?}", leaf, val);
        }
    };
    if let Some(dot) = key.rfind('.') {
        let sub = &key[..dot];
        let leaf = &key[dot+1..];
        let _ = writeln!(t, "\n[{}.{}]", section, sub);
        write_value(t, leaf, value);
    } else {
        write_value(t, key, value);
    }
}

fn build_toml(a: &WizardAnswers) -> String {
    let mut t = String::new();
    let _ = writeln!(t, "# ConvoAI Agent Configuration");
    let _ = writeln!(t, "# Generated by `atem config convo`\n");

    // [atem] — atem-managed runtime control surface
    let _ = writeln!(t, "[atem]");
    if !a.channel.is_empty() {
        let _ = writeln!(t, "channel     = {:?}", a.channel);
    } else {
        let _ = writeln!(t, "# channel auto-generated when omitted");
    }
    let _ = writeln!(t, "rtc_user_id = {:?}", a.rtc_user_id);

    // [agent] — about the AI agent itself
    let _ = writeln!(t, "\n[agent]");
    let _ = writeln!(t, "user_id           = {:?}", a.agent_user_id);
    let _ = writeln!(t, "idle_timeout_secs = {}", a.idle_timeout_secs);
    if a.use_preset && !a.presets.is_empty() {
        // Single comma-separated string — atem splits for the UI
        // checkboxes and joins selections back as properties.preset.
        let _ = writeln!(t, "preset            = {:?}", a.presets.join(","));
    }

    // Advanced features
    let _ = writeln!(t, "\n[advanced_features]");
    let _ = writeln!(t, "enable_rtm   = {}", a.enable_rtm);
    let _ = writeln!(t, "enable_sal   = {}", a.enable_sal);
    let _ = writeln!(t, "enable_aivad = false");

    let _ = writeln!(t, "\n[vad]");
    let _ = writeln!(t, "silence_duration_ms = {}", a.vad_silence_ms);

    let _ = writeln!(t, "\n[sal]");
    let _ = writeln!(t, "sal_mode = \"locking\"");

    let _ = writeln!(t, "\n[parameters]");
    let _ = writeln!(t, "audio_scenario = \"default\"");
    let _ = writeln!(t, "data_channel   = {:?}", a.data_channel);

    let _ = writeln!(t, "\n[parameters.transcript]");
    let _ = writeln!(t, "enable_words = {}", a.enable_words);

    let _ = writeln!(t, "\n[parameters.turn_detector]");
    let _ = writeln!(t, "validate_asr_result_timestamp = false");

    // Avatar
    if !a.avatar_vendor.is_empty() {
        let _ = writeln!(t, "\n[agent.avatar]");
        let _ = writeln!(t, "vendor    = {:?}", a.avatar_vendor);
        if !a.avatar_id_value.is_empty() {
            let _ = writeln!(t, "avatar_id = {:?}", a.avatar_id_value);
        }
        if !a.avatar_params.is_empty() {
            let _ = writeln!(t, "\n[agent.avatar.params]");
            // Write flat params first, then nested
            let (flat, nested): (Vec<_>, Vec<_>) = a.avatar_params.iter().partition(|(k, _)| !k.contains('.'));
            for (k, v) in &flat { write_param(&mut t, "agent.avatar.params", k, v); }
            for (k, v) in &nested { write_param(&mut t, "agent.avatar.params", k, v); }
        }
    }

    // MLLM (if chosen instead of the cascaded pipeline)
    if !a.mllm_vendor.is_empty() {
        let _ = writeln!(t, "\n# Multimodal LLM — replaces the ASR + LLM + TTS pipeline");
        let _ = writeln!(t, "[agent.mllm]");
        let _ = writeln!(t, "vendor = {:?}", a.mllm_vendor);
        if !a.mllm_url.is_empty() {
            let _ = writeln!(t, "url    = {:?}", a.mllm_url);
        }
        if !a.mllm_api_key.is_empty() {
            let _ = writeln!(t, "api_key = {:?}", a.mllm_api_key);
        }
        if !a.mllm_greeting_message.is_empty() {
            let _ = writeln!(t, "greeting_message = {:?}", a.mllm_greeting_message);
        }
        if !a.mllm_params.is_empty() {
            let _ = writeln!(t, "\n[agent.mllm.params]");
            let (flat, nested): (Vec<_>, Vec<_>) = a.mllm_params.iter().partition(|(k, _)| !k.contains('.'));
            for (k, v) in &flat { write_param(&mut t, "agent.mllm.params", k, v); }
            for (k, v) in &nested { write_param(&mut t, "agent.mllm.params", k, v); }
        }
    }

    // ASR + LLM + TTS (cascaded pipeline — written when any has data,
    // regardless of preset mode since presets can have overrides)
    if !a.asr_vendor.is_empty() || !a.llm_url.is_empty() || !a.llm_api_key.is_empty() || !a.tts_vendor.is_empty() {
        // LLM
        let _ = writeln!(t, "\n[agent.llm]");
        if !a.llm_url.is_empty() { let _ = writeln!(t, "url              = {:?}", a.llm_url); }
        if !a.llm_api_key.is_empty() { let _ = writeln!(t, "api_key          = {:?}", a.llm_api_key); }
        if !a.llm_vendor.is_empty() { let _ = writeln!(t, "vendor           = {:?}", a.llm_vendor); }
        if !a.llm_style.is_empty() { let _ = writeln!(t, "style            = {:?}", a.llm_style); }
        if !a.llm_greeting.is_empty() { let _ = writeln!(t, "greeting_message = {:?}", a.llm_greeting); }
        if !a.llm_failure.is_empty() { let _ = writeln!(t, "failure_message  = {:?}", a.llm_failure); }

        if !a.llm_system_prompt.is_empty() {
            let _ = writeln!(t, "\n[[agent.llm.system_messages]]");
            let _ = writeln!(t, "role    = \"system\"");
            let _ = writeln!(t, "content = '''");
            let _ = writeln!(t, "{}", a.llm_system_prompt);
            let _ = writeln!(t, "'''");
        }

        let _ = writeln!(t, "\n[agent.llm.params]");
        for (k, v) in &a.llm_params {
            write_param(&mut t, "agent.llm.params", k, v);
        }

        // Anthropic needs headers
        if a.llm_style == "anthropic" {
            let _ = writeln!(t, "\n[agent.llm.headers]");
            let _ = writeln!(t, "anthropic-version = \"2023-06-01\"");
        }

        // ASR
        let _ = writeln!(t, "\n[agent.asr]");
        let _ = writeln!(t, "vendor   = {:?}", a.asr_vendor);
        if !a.asr_language.is_empty() { let _ = writeln!(t, "language = {:?}", a.asr_language); }

        if !a.asr_params.is_empty() {
            let _ = writeln!(t, "\n[agent.asr.params]");
            let (flat, nested): (Vec<_>, Vec<_>) = a.asr_params.iter().partition(|(k, _)| !k.contains('.'));
            for (k, v) in &flat { write_param(&mut t, "agent.asr.params", k, v); }
            for (k, v) in &nested { write_param(&mut t, "agent.asr.params", k, v); }
        }

        // TTS
        let _ = writeln!(t, "\n[agent.tts]");
        let _ = writeln!(t, "vendor = {:?}", a.tts_vendor);

        if !a.tts_params.is_empty() {
            let _ = writeln!(t, "\n[agent.tts.params]");
            let (flat, nested): (Vec<_>, Vec<_>) = a.tts_params.iter().partition(|(k, _)| !k.contains('.'));
            for (k, v) in &flat { write_param(&mut t, "agent.tts.params", k, v); }
            for (k, v) in &nested { write_param(&mut t, "agent.tts.params", k, v); }
        }
    }

    t
}

// ── Validation ──────────────────────────────────────────────────────

pub fn run_validate(config_path: &Path) -> Result<()> {
    println!("Validating: {}\n", config_path.display());
    if !config_path.exists() {
        anyhow::bail!("Config file not found: {}", config_path.display());
    }

    let cfg = crate::convo_config::ConvoConfig::from_file(config_path)?;
    let mut errors: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    if cfg.agent.as_ref().and_then(|a| a.user_id.as_ref()).is_none() {
        errors.push("[agent].user_id is required".into());
    }

    // [atem] sub-field value validation
    if let Some(atem) = &cfg.atem {
        const VALID_GEOFENCES: &[&str] = &[
            "GLOBAL", "NORTH_AMERICA", "EUROPE", "ASIA", "JAPAN", "INDIA",
        ];
        if let Some(g) = atem.geofence.as_deref() {
            if !g.is_empty() && !VALID_GEOFENCES.iter().any(|v| v.eq_ignore_ascii_case(g)) {
                errors.push(format!(
                    "[atem].geofence = {:?} is not one of {:?}",
                    g, VALID_GEOFENCES
                ));
            }
        }
        if let Some(enc) = &atem.encryption {
            // mode 0 = off; 1..=8 valid per Agora's table.
            if enc.mode > 8 {
                errors.push(format!(
                    "[atem.encryption].mode = {} is out of range (valid: 0..=8; 0 = off)",
                    enc.mode
                ));
            }
            // mode > 0 → key must be set.
            if enc.mode > 0 && enc.key.is_empty() {
                errors.push(format!(
                    "[atem.encryption].mode = {} requires a non-empty `key`",
                    enc.mode
                ));
            }
            // gcm2 modes (7, 8) need a 32-byte salt.
            if enc.mode == 7 || enc.mode == 8 {
                if enc.salt.is_empty() {
                    errors.push(format!(
                        "[atem.encryption].mode = {} (gcm2) requires `salt` (base64 of 32 bytes). \
                         Generate one with: openssl rand -base64 32",
                        enc.mode
                    ));
                } else {
                    use base64::Engine;
                    let decoded = base64::engine::general_purpose::STANDARD
                        .decode(enc.salt.as_bytes())
                        .ok()
                        .map(|b| b.len())
                        .unwrap_or(0);
                    if decoded != 32 {
                        errors.push(format!(
                            "[atem.encryption].salt decodes to {} bytes; gcm2 requires exactly 32. \
                             Re-generate with: openssl rand -base64 32",
                            decoded
                        ));
                    }
                }
            }
        }
        // Avatar + encryption interaction warning.
        if atem.enable_avatar.unwrap_or(false) {
            let enc_on = atem.encryption.as_ref().map(|e| e.mode > 0).unwrap_or(false);
            if enc_on {
                warnings.push(
                    "[atem].enable_avatar = true with [atem.encryption].mode > 0 — \
                     avatar vendors don't currently support encrypted channels, \
                     audio will be silent. Pick one or the other.".into()
                );
            }
            if cfg.agent.as_ref().and_then(|a| a.avatar.as_ref()).is_none() {
                warnings.push(
                    "[atem].enable_avatar = true but no [agent.avatar] block — \
                     no avatar will be sent in /join.".into()
                );
            }
        }
    }

    let has_preset = cfg.agent.as_ref()
        .and_then(|a| a.preset.as_deref())
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);
    let has_asr  = cfg.agent.as_ref().and_then(|a| a.asr.as_ref()).is_some();
    let has_llm  = cfg.agent.as_ref().and_then(|a| a.llm.as_ref()).is_some();
    let has_tts  = cfg.agent.as_ref().and_then(|a| a.tts.as_ref()).is_some();
    let has_mllm = cfg.agent.as_ref().and_then(|a| a.mllm.as_ref()).is_some();
    let has_seg  = has_asr || has_llm || has_tts;
    // Pipeline detection (mirrors `resolve()`'s logic but doesn't
    // require a channel — validation runs against any draft).
    enum P { Cascaded, Mllm, Ambiguous, BadValue(String) }
    let detected = match cfg.atem.as_ref()
        .and_then(|a| a.pipeline.as_deref())
        .map(|s| s.trim().to_ascii_lowercase())
    {
        Some(s) if matches!(s.as_str(), "cascaded" | "cascade" | "chained" | "segmented") => P::Cascaded,
        Some(s) if s == "mllm" => P::Mllm,
        Some(other) => P::BadValue(other),
        None => match (has_seg, has_mllm) {
            (false, true) => P::Mllm,
            (true,  false) | (false, false) => P::Cascaded,
            (true,  true) => P::Ambiguous,
        },
    };
    match detected {
        P::Cascaded => {
            if !has_preset && !(has_asr && has_llm && has_tts) {
                errors.push(
                    "Active pipeline is cascaded — need a preset, OR \
                     all three of [agent.asr] / [agent.llm] / [agent.tts]".into()
                );
            }
        }
        P::Mllm => {
            if !has_mllm {
                errors.push("Active pipeline is mllm — need [agent.mllm] block".into());
            }
        }
        P::Ambiguous => {
            errors.push(
                "Both [agent.mllm] and [agent.asr/llm/tts] are configured; \
                 set [atem].pipeline = \"cascaded\" or \"mllm\" to pick one".into()
            );
        }
        P::BadValue(v) => {
            errors.push(format!(
                "[atem].pipeline = {:?} is not one of \"cascaded\", \"mllm\"", v
            ));
        }
    }

    if has_llm {
        let llm = cfg.agent.as_ref().unwrap().llm.as_ref().unwrap();
        if llm.api_key.as_deref().unwrap_or("").is_empty() && llm.url.as_deref().unwrap_or("").is_empty() {
            warnings.push("[agent.llm] has no api_key or url".into());
        }
    }

    let rtm = cfg.advanced_features.as_ref().and_then(|m| m.get("enable_rtm")).and_then(|v| v.as_bool()).unwrap_or(false);
    if !rtm { warnings.push("advanced_features.enable_rtm is not true — transcription won't work".into()); }

    // Check for large integers in param maps that would lose precision
    // when serialized to JSON (> 2^53 = 9007199254740992). These should
    // be quoted strings in TOML, not bare integers.
    fn check_large_ints(section: &str, map: &BTreeMap<String, toml::Value>, warnings: &mut Vec<String>) {
        const JS_SAFE_MAX: i64 = 9007199254740992;
        for (k, v) in map {
            if let toml::Value::Integer(n) = v {
                if n.abs() > JS_SAFE_MAX {
                    warnings.push(format!(
                        "{}.{} = {} is a bare integer > 2^53 — will lose precision in JSON. \
                         Quote it as a string: {} = {:?}",
                        section, k, n, k, n.to_string()
                    ));
                }
            }
            if let toml::Value::Table(sub) = v {
                let sub_map: BTreeMap<String, toml::Value> = sub.iter().map(|(k2, v2)| (k2.clone(), v2.clone())).collect();
                check_large_ints(&format!("{}.{}", section, k), &sub_map, warnings);
            }
        }
    }
    if let Some(agent) = &cfg.agent {
        if let Some(asr) = &agent.asr { check_large_ints("[agent.asr.params]", &asr.params, &mut warnings); }
        if let Some(llm) = &agent.llm { check_large_ints("[agent.llm.params]", &llm.params, &mut warnings); }
        if let Some(tts) = &agent.tts { check_large_ints("[agent.tts.params]", &tts.params, &mut warnings); }
        if let Some(av) = &agent.avatar { check_large_ints("[agent.avatar.params]", &av.params, &mut warnings); }
    }

    // Check data_channel = "rtm" (common misconfiguration)
    let data_ch = cfg.parameters.as_ref().and_then(|m| m.get("data_channel")).and_then(|v| v.as_str()).unwrap_or("");
    if !data_ch.is_empty() && data_ch != "rtm" {
        warnings.push(format!("parameters.data_channel = {:?} — transcripts usually need \"rtm\"", data_ch));
    }

    // Check ASR vendor is set when ASR block exists
    if has_asr {
        let asr = cfg.agent.as_ref().unwrap().asr.as_ref().unwrap();
        if asr.vendor.is_none() { warnings.push("[agent.asr] has no vendor".into()); }
    }

    // Check TTS vendor is set when TTS block exists
    if has_tts {
        let tts = cfg.agent.as_ref().unwrap().tts.as_ref().unwrap();
        if tts.vendor.is_none() { warnings.push("[agent.tts] has no vendor".into()); }
    }

    for e in &errors { println!("  ERROR:   {}", e); }
    for w in &warnings { println!("  WARNING: {}", w); }
    if errors.is_empty() && warnings.is_empty() {
        println!("  Config OK.");
    } else if errors.is_empty() {
        println!("\n  Config valid (with warnings).");
    }
    if !errors.is_empty() { anyhow::bail!("{} error(s) found", errors.len()); }
    Ok(())
}

#[cfg(test)]
mod validate_tests {
    use super::*;
    use std::io::Write;

    fn write_temp(contents: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        p.push(format!("atem-validate-{}.toml", ts));
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        p
    }

    #[test]
    fn validate_rejects_unknown_geofence() {
        let p = write_temp(r#"
            [atem]
            geofence = "MOON"
            [agent]
            user_id = "1001"
            preset  = "x"
            [advanced_features]
            enable_rtm = true
        "#);
        let err = run_validate(&p).unwrap_err().to_string();
        assert!(err.contains("error"), "expected error: {}", err);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn validate_rejects_gcm2_mode_without_salt() {
        let p = write_temp(r#"
            [atem.encryption]
            mode = 8
            key  = "k"
            # salt missing
            [agent]
            user_id = "1001"
            preset  = "x"
            [advanced_features]
            enable_rtm = true
        "#);
        let err = run_validate(&p).unwrap_err().to_string();
        assert!(err.contains("error"), "expected error: {}", err);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn validate_rejects_encryption_mode_without_key() {
        let p = write_temp(r#"
            [atem.encryption]
            mode = 6
            # key missing
            [agent]
            user_id = "1001"
            preset  = "x"
            [advanced_features]
            enable_rtm = true
        "#);
        let err = run_validate(&p).unwrap_err().to_string();
        assert!(err.contains("error"), "expected error: {}", err);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn validate_accepts_mllm_alone() {
        // [agent.mllm] is a valid third path alongside preset and the
        // segmented (asr+llm+tts) trio. With it set, no preset and no
        // asr/llm/tts blocks are needed.
        let p = write_temp(r#"
            [atem]
            channel = "c"
            [agent]
            user_id = "1001"
            [agent.mllm]
            vendor = "openai"
            [agent.mllm.params]
            api_key = "sk-x"
            [advanced_features]
            enable_rtm = true
        "#);
        let res = run_validate(&p);
        assert!(res.is_ok(), "expected Ok, got: {:?}", res);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn validate_requires_explicit_pipeline_when_both_present() {
        // Both [agent.mllm] and [agent.asr/llm/tts] in one file —
        // ambiguous, so resolve() refuses to auto-pick. User must
        // set [atem].pipeline.
        let p = write_temp(r#"
            [atem]
            channel = "c"
            [agent]
            user_id = "1001"
            [agent.mllm]
            vendor = "openai"
            [agent.mllm.params]
            api_key = "x"
            [agent.asr]
            vendor = "soniox"
            [agent.llm]
            api_key = "x"
            [agent.tts]
            vendor = "minimax"
            [advanced_features]
            enable_rtm = true
        "#);
        let err = run_validate(&p).unwrap_err().to_string();
        assert!(err.contains("error"), "expected error: {}", err);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn validate_picks_pipeline_when_explicit() {
        // Both blocks present + explicit `pipeline = "mllm"` → ok,
        // resolves to mllm and `validate_*` only checks for mllm.
        let p = write_temp(r#"
            [atem]
            channel  = "c"
            pipeline = "mllm"
            [agent]
            user_id = "1001"
            [agent.mllm]
            vendor = "openai"
            [agent.mllm.params]
            api_key = "x"
            [agent.asr]
            vendor = "soniox"
            [advanced_features]
            enable_rtm = true
        "#);
        let res = run_validate(&p);
        assert!(res.is_ok(), "expected Ok, got: {:?}", res);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn backup_rotation_keeps_at_most_max_generations() {
        use std::io::Write;
        let mut p = std::env::temp_dir();
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        p.push(format!("atem-bak-test-{}.toml", unique));
        // Seed with six sequential "saves".
        for n in 0..6 {
            let mut f = std::fs::File::create(&p).unwrap();
            writeln!(f, "n = {}", n).unwrap();
            super::rotate_backups(&p, 5).unwrap();
        }
        // After 6 saves at max=5, expect: original + .bak + .bak.1..=.bak.4
        let bak  = p.with_file_name(format!("{}.bak",   p.file_name().unwrap().to_string_lossy()));
        let bak1 = p.with_file_name(format!("{}.bak.1", p.file_name().unwrap().to_string_lossy()));
        let bak2 = p.with_file_name(format!("{}.bak.2", p.file_name().unwrap().to_string_lossy()));
        let bak3 = p.with_file_name(format!("{}.bak.3", p.file_name().unwrap().to_string_lossy()));
        let bak4 = p.with_file_name(format!("{}.bak.4", p.file_name().unwrap().to_string_lossy()));
        let bak5 = p.with_file_name(format!("{}.bak.5", p.file_name().unwrap().to_string_lossy()));
        assert!(bak.exists()  && bak1.exists() && bak2.exists() && bak3.exists() && bak4.exists());
        assert!(!bak5.exists(), "5th-old should have been dropped");

        // Cleanup
        for path in [&p, &bak, &bak1, &bak2, &bak3, &bak4, &bak5] {
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn apply_to_doc_preserves_unrelated_sections_and_comments() {
        // Drop a file with a [agent.mllm] block + a top-level comment.
        // Run wizard answers that pick CASCADED mode (so the wizard
        // doesn't touch [agent.mllm]) and verify the parked block is
        // still in the output.
        let starting = r#"# my custom comment
[atem]
channel = "old-channel"

[agent]
user_id = "1001"

# parked MLLM — kept across switches to cascaded
[agent.mllm]
vendor = "openai"
[agent.mllm.params]
api_key = "sk-keep-me"
"#;
        let mut doc: toml_edit::DocumentMut = starting.parse().unwrap();
        let answers = super::WizardAnswers {
            use_preset: false,
            channel: "new-channel".into(),
            rtc_user_id: "0".into(),
            agent_user_id: "1001".into(),
            idle_timeout_secs: 120,
            presets: vec![],
            asr_vendor: "soniox".into(),
            asr_language: "en-US".into(),
            asr_params: Default::default(),
            llm_vendor: String::new(),
            llm_url: "https://api.example.com".into(),
            llm_api_key: "k".into(),
            llm_style: String::new(),
            llm_greeting: String::new(),
            llm_failure: String::new(),
            llm_system_prompt: String::new(),
            llm_params: Default::default(),
            tts_vendor: "minimax".into(),
            tts_params: Default::default(),
            mllm_vendor: String::new(),  // ← didn't pick MLLM this run
            mllm_url: String::new(),
            mllm_api_key: String::new(),
            mllm_greeting_message: String::new(),
            mllm_params: Default::default(),
            avatar_vendor: String::new(),
            avatar_params: Default::default(),
            avatar_id_value: String::new(),
            enable_rtm: true,
            enable_sal: true,
            data_channel: "rtm".into(),
            enable_words: true,
            vad_silence_ms: 800,
        };
        super::apply_to_doc(&mut doc, &answers);
        let out = doc.to_string();
        // Top-level comment preserved.
        assert!(out.contains("# my custom comment"), "comment lost:\n{}", out);
        // Channel updated.
        assert!(out.contains("new-channel"), "channel not updated:\n{}", out);
        // Parked MLLM block intact.
        assert!(out.contains("[agent.mllm]"), "MLLM block dropped:\n{}", out);
        assert!(out.contains("sk-keep-me"), "MLLM api_key dropped:\n{}", out);
        // Pipeline now explicitly set.
        assert!(out.contains(r#"pipeline = "cascaded""#), "pipeline not written:\n{}", out);
    }

    #[test]
    fn validate_accepts_well_formed_config() {
        // Minimal valid config — should pass without error.
        let p = write_temp(r#"
            [atem]
            hipaa    = false
            geofence = "GLOBAL"
            [atem.encryption]
            mode = 0
            [agent]
            user_id = "1001"
            preset  = "demo_preset"
            [advanced_features]
            enable_rtm = true
            [parameters]
            data_channel = "rtm"
        "#);
        let res = run_validate(&p);
        assert!(res.is_ok(), "expected Ok, got: {:?}", res);
        let _ = std::fs::remove_file(&p);
    }
}
