//! chat-v1's inbound envelope (`{"type":"agentChat","data":{"v":1,"op":…,
//! "conversationId":…,"agentId":…,…}}`) and the parse of a client's request
//! (`open`, `submit`, `close`), shared by the session-v1 decoder, the host
//! (`src/chat/wire.rs` re-exports them) and apps.
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

const MAX_ID: usize = 128;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ChatEnvelope {
    pub v: u32,
    pub op: String,
    pub conversation_id: String,
    pub agent_id: String,
    #[serde(flatten)]
    pub body: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Inbound {
    /// Opens a conversation at the newest page. r8 removed `open.before`/
    /// `open.generation` (the r7.2 paging form): the session host refuses
    /// such an open (`unsupported_version`) before it gets here.
    Open,
    Submit {
        generation: String,
        request_id: String,
        text: String,
    },
    /// An approval card answered from chat (`approval` instead of `text`):
    /// the session-v1 approval submission, payload as it is.
    Answer {
        generation: String,
        request_id: String,
        approval: Value,
    },
    /// An Atem session rule revoked from chat (`approval_rule_revoke`
    /// instead of `text`, r7.2): the session-v1 revoke payload as it is.
    RevokeRule {
        generation: String,
        request_id: String,
        revoke: Value,
    },
    Close,
}

fn valid_id(s: &str) -> bool {
    (1..=MAX_ID).contains(&s.len())
}

fn str_field(env: &ChatEnvelope, name: &str) -> Result<String, String> {
    match env.body.get(name) {
        Some(Value::String(s)) => Ok(s.clone()),
        _ => Err(format!("missing field {name}")),
    }
}

pub fn parse_inbound(env: &ChatEnvelope) -> Result<Inbound, String> {
    if env.v != 1 {
        return Err("unsupported version".into());
    }
    if !matches!(env.op.as_str(), "open" | "submit" | "close") {
        return Err("unsupported op".into());
    }
    if !valid_id(&env.conversation_id) {
        return Err("invalid conversationId".into());
    }
    if !valid_id(&env.agent_id) {
        return Err("invalid agentId".into());
    }
    match env.op.as_str() {
        "open" => Ok(Inbound::Open),
        "submit" => {
            let generation = str_field(env, "generation")?;
            let request_id = str_field(env, "requestId")?;
            if !valid_id(&request_id) {
                return Err("invalid requestId".into());
            }
            let field = super::wire::RULE_REVOKE_FIELD;
            let carried = ["text", "approval", field]
                .iter()
                .filter(|k| env.body.contains_key(**k))
                .count();
            if carried > 1 {
                return Err(format!("a submit carries one of text, approval or {field}"));
            }
            if let Some(revoke) = env.body.get(field) {
                if !revoke.is_object() {
                    return Err(format!("invalid {field}"));
                }
                return Ok(Inbound::RevokeRule {
                    generation,
                    request_id,
                    revoke: revoke.clone(),
                });
            }
            if let Some(approval) = env.body.get("approval") {
                if !approval.is_object() {
                    return Err("invalid approval".into());
                }
                return Ok(Inbound::Answer {
                    generation,
                    request_id,
                    approval: approval.clone(),
                });
            }
            let text = str_field(env, "text")?;
            Ok(Inbound::Submit {
                generation,
                request_id,
                text,
            })
        }
        _ => Ok(Inbound::Close),
    }
}
