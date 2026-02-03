use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

const DEFAULT_API_URL: &str = "https://api.anthropic.com/v1/messages";
const DEFAULT_MODEL: &str = "claude-sonnet-4-20250514";

#[derive(Debug, Clone)]
pub struct AiClient {
    api_key: String,
    api_url: String,
    model: String,
    http: reqwest::Client,
}

#[derive(Debug, Clone)]
pub struct CommandIntent {
    pub command: String,
    pub explanation: String,
}

#[derive(Serialize)]
struct ApiRequest {
    model: String,
    max_tokens: u32,
    system: String,
    messages: Vec<ApiMessage>,
}

#[derive(Serialize)]
struct ApiMessage {
    role: String,
    content: String,
}

#[derive(Deserialize)]
struct ApiResponse {
    content: Vec<ContentBlock>,
}

#[derive(Deserialize)]
struct ContentBlock {
    text: Option<String>,
}

const SYSTEM_PROMPT: &str = r#"You are an assistant that translates natural language into Atem CLI commands.

Available commands:
- atem list project [--show-certificates]  — List all Agora projects
- atem project use <APP_ID>                — Set the active project by App ID
- atem project show                        — Show the current active project
- atem config show                         — Show resolved configuration
- atem token rtc create [--channel <NAME>] [--uid <ID>] [--role publisher|subscriber] [--expire <SECS>]
                                           — Generate an RTC token
- atem token rtc decode <TOKEN>            — Decode an existing RTC token
- atem token rtm create [--user-id <ID>] [--expire <SECS>]
                                           — Generate an RTM token

Respond with ONLY a JSON object in this exact format:
{"command": "<the full atem command>", "explanation": "<brief explanation of what it does>"}

If the user's input doesn't map to any known command, respond with:
{"command": "", "explanation": "<why no command matches>"}

Do not include any text outside the JSON object."#;

impl AiClient {
    pub fn new() -> Result<Self> {
        let api_key = std::env::var("ANTHROPIC_API_KEY")
            .map_err(|_| anyhow!("ANTHROPIC_API_KEY not set. Set it to use AI-powered command interpretation."))?;

        let api_url = std::env::var("ATEM_AI_API_URL")
            .unwrap_or_else(|_| DEFAULT_API_URL.to_string());
        let model = std::env::var("ATEM_AI_MODEL")
            .unwrap_or_else(|_| DEFAULT_MODEL.to_string());

        Ok(Self {
            api_key,
            api_url,
            model,
            http: reqwest::Client::new(),
        })
    }

    pub async fn interpret_command(&self, user_input: &str) -> Result<CommandIntent> {
        let request = ApiRequest {
            model: self.model.clone(),
            max_tokens: 256,
            system: SYSTEM_PROMPT.to_string(),
            messages: vec![ApiMessage {
                role: "user".to_string(),
                content: user_input.to_string(),
            }],
        };

        let response = self
            .http
            .post(&self.api_url)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&request)
            .send()
            .await
            .map_err(|e| anyhow!("AI API request failed: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("AI API returned {}: {}", status, body));
        }

        let api_response: ApiResponse = response
            .json()
            .await
            .map_err(|e| anyhow!("Failed to parse AI response: {}", e))?;

        let text = api_response
            .content
            .first()
            .and_then(|b| b.text.as_deref())
            .ok_or_else(|| anyhow!("Empty AI response"))?;

        parse_command_intent(text)
    }
}

fn parse_command_intent(text: &str) -> Result<CommandIntent> {
    // Try to extract JSON from the response (may have markdown fences)
    let json_str = if let Some(start) = text.find('{') {
        if let Some(end) = text.rfind('}') {
            &text[start..=end]
        } else {
            text
        }
    } else {
        text
    };

    #[derive(Deserialize)]
    struct IntentJson {
        command: String,
        explanation: String,
    }

    let parsed: IntentJson = serde_json::from_str(json_str)
        .map_err(|e| anyhow!("Failed to parse AI intent: {} (raw: {})", e, text))?;

    Ok(CommandIntent {
        command: parsed.command,
        explanation: parsed.explanation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_intent() {
        let json = r#"{"command": "atem list project", "explanation": "Lists all projects"}"#;
        let intent = parse_command_intent(json).unwrap();
        assert_eq!(intent.command, "atem list project");
        assert_eq!(intent.explanation, "Lists all projects");
    }

    #[test]
    fn parse_intent_with_markdown_fences() {
        let text = "```json\n{\"command\": \"atem config show\", \"explanation\": \"Shows config\"}\n```";
        let intent = parse_command_intent(text).unwrap();
        assert_eq!(intent.command, "atem config show");
    }

    #[test]
    fn parse_empty_command_intent() {
        let json = r#"{"command": "", "explanation": "No matching command found"}"#;
        let intent = parse_command_intent(json).unwrap();
        assert!(intent.command.is_empty());
    }

    #[test]
    fn parse_invalid_json_fails() {
        let text = "not json at all";
        assert!(parse_command_intent(text).is_err());
    }

    #[test]
    fn client_requires_api_key() {
        // Clear the env var for this test
        let prev = std::env::var("ANTHROPIC_API_KEY").ok();
        // SAFETY: test is single-threaded and we restore the value after
        unsafe { std::env::remove_var("ANTHROPIC_API_KEY") };
        let result = AiClient::new();
        assert!(result.is_err());
        // Restore
        if let Some(key) = prev {
            // SAFETY: restoring the original value
            unsafe { std::env::set_var("ANTHROPIC_API_KEY", key) };
        }
    }
}
