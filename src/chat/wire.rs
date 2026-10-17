//! agentChat v1: JSON shapes exchanged with Astation (see designs/agent-chat-host.md).

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::adapter::{Outcome, Part};
use super::session::{ChatMessage, Origin, Out, Role, State, Status};

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
    Open {
        before: Option<String>,
    },
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
        "open" => {
            let before = match env.body.get("before") {
                None | Some(Value::Null) => None,
                Some(Value::String(s)) if s.len() <= MAX_ID => Some(s.clone()),
                Some(_) => return Err("invalid before".into()),
            };
            Ok(Inbound::Open { before })
        }
        "submit" => {
            let generation = str_field(env, "generation")?;
            let request_id = str_field(env, "requestId")?;
            if !valid_id(&request_id) {
                return Err("invalid requestId".into());
            }
            let field = crate::session_protocol::wire::RULE_REVOKE_FIELD;
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

// ── Bodies ────────────────────────────────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Head<'a> {
    generation: &'a str,
    sequence: u64,
}

#[derive(Serialize)]
struct StatusBody<'a> {
    state: &'static str,
    since: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<&'a str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OpenedBody<'a> {
    generation: &'a str,
    sequence: u64,
    status: StatusBody<'a>,
    /// What this agent's chat can't provide (`streaming`, `reasoning`,
    /// `error_details`); empty for Claude.
    unavailable: &'a [String],
    /// The session's active Atem session rules (r7.2; `[]` for a
    /// conversation of an attachment without `control`).
    approval_rules: &'a [crate::session_protocol::wire::AlwaysRule],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RulesBody<'a> {
    approval_rules: &'a [crate::session_protocol::wire::AlwaysRule],
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
enum PartBody<'a> {
    Text {
        id: &'a str,
        markdown: &'a str,
    },
    Tool {
        id: &'a str,
        name: &'a str,
        summary: &'a str,
    },
    Approval {
        id: &'a str,
        approval_id: &'a str,
        tool: &'a str,
        summary: &'a str,
        always_rules: &'a [crate::session_protocol::wire::AlwaysRule],
        state: super::adapter::ApprovalCardState,
        #[serde(skip_serializing_if = "Option::is_none")]
        rule_id: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        note: Option<&'a str>,
    },
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MessageBody<'a> {
    message_id: &'a str,
    role: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    origin: Option<&'static str>,
    turn_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<&'a str>,
    created_at: i64,
    parts: Vec<PartBody<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    history: Option<bool>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeltaBody<'a> {
    message_id: &'a str,
    part: PartBody<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AcceptedBody<'a> {
    request_id: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CompleteBody<'a> {
    turn_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<&'a str>,
    outcome: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ErrorBody<'a> {
    text: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<&'a str>,
}

fn state_name(s: State) -> &'static str {
    match s {
        State::Ready => "ready",
        State::Working => "working",
        State::Waiting => "waiting",
        State::Unknown => "unknown",
    }
}

fn status_body(s: &Status) -> StatusBody<'_> {
    StatusBody {
        state: state_name(s.state),
        since: s.since_ms,
        detail: s.detail.as_deref(),
    }
}

fn part_body(p: &Part) -> PartBody<'_> {
    match p {
        Part::Text { id, markdown } => PartBody::Text { id, markdown },
        Part::Tool { id, name, summary } => PartBody::Tool { id, name, summary },
        Part::Approval(c) => PartBody::Approval {
            id: &c.id,
            approval_id: &c.approval_id,
            tool: &c.tool,
            summary: &c.summary,
            always_rules: &c.always_rules,
            state: c.state,
            rule_id: c.rule_id.as_deref(),
            note: c.note.as_deref(),
        },
    }
}

fn message_body(m: &ChatMessage, history: bool) -> MessageBody<'_> {
    MessageBody {
        message_id: &m.message_id,
        role: match m.role {
            Role::User => "user",
            Role::Assistant => "assistant",
        },
        origin: m.origin.map(|o| match o {
            Origin::Local => "local",
            Origin::Remote => "remote",
        }),
        turn_id: &m.turn_id,
        request_id: m.request_id.as_deref(),
        created_at: m.created_at_ms,
        parts: m.parts.iter().map(part_body).collect(),
        history: history.then_some(true),
    }
}

fn envelope(
    conv: &str,
    agent: &str,
    op: &str,
    head: Option<Head<'_>>,
    body: impl Serialize,
) -> ChatEnvelope {
    let mut map = match serde_json::to_value(body) {
        Ok(Value::Object(m)) => m,
        _ => Map::new(),
    };
    if let Some(Ok(Value::Object(hm))) = head.map(serde_json::to_value) {
        map.extend(hm);
    }
    ChatEnvelope {
        v: 1,
        op: op.into(),
        conversation_id: conv.into(),
        agent_id: agent.into(),
        body: map,
    }
}

pub fn opened(
    conv: &str,
    agent: &str,
    generation: &str,
    status: &Status,
    unavailable: &[String],
    approval_rules: &[crate::session_protocol::wire::AlwaysRule],
) -> ChatEnvelope {
    envelope(
        conv,
        agent,
        "opened",
        None,
        OpenedBody {
            generation,
            sequence: 0,
            status: status_body(status),
            unavailable,
            approval_rules,
        },
    )
}

/// The session's active Atem session rules changed (r7.2): `rules` with
/// the whole list.
pub fn rules(
    conv: &str,
    agent: &str,
    generation: &str,
    sequence: u64,
    approval_rules: &[crate::session_protocol::wire::AlwaysRule],
) -> ChatEnvelope {
    envelope(
        conv,
        agent,
        "rules",
        Some(Head {
            generation,
            sequence,
        }),
        RulesBody { approval_rules },
    )
}

pub fn event(conv: &str, agent: &str, generation: &str, sequence: u64, out: &Out) -> ChatEnvelope {
    let head = Head {
        generation,
        sequence,
    };
    match out {
        Out::Message(m) => envelope(conv, agent, "message", Some(head), message_body(m, false)),
        Out::Delta { message_id, part } => envelope(
            conv,
            agent,
            "delta",
            Some(head),
            DeltaBody {
                message_id,
                part: part_body(part),
            },
        ),
        Out::Status(s) => envelope(conv, agent, "status", Some(head), status_body(s)),
        Out::Accepted { request_id } => envelope(
            conv,
            agent,
            "accepted",
            Some(head),
            AcceptedBody { request_id },
        ),
        Out::Complete {
            turn_id,
            request_id,
            outcome,
        } => envelope(
            conv,
            agent,
            "complete",
            Some(head),
            CompleteBody {
                turn_id,
                request_id: request_id.as_deref(),
                outcome: match outcome {
                    Outcome::Done => "done",
                    Outcome::Interrupted => "interrupted",
                },
            },
        ),
        Out::Error { text, request_id } => envelope(
            conv,
            agent,
            "error",
            Some(head),
            ErrorBody {
                text,
                request_id: request_id.as_deref(),
            },
        ),
    }
}

pub fn history_message(
    conv: &str,
    agent: &str,
    generation: &str,
    sequence: u64,
    m: &ChatMessage,
) -> ChatEnvelope {
    envelope(
        conv,
        agent,
        "message",
        Some(Head {
            generation,
            sequence,
        }),
        message_body(m, true),
    )
}

/// Atem ends a conversation: after an `error` saying why, or without one when a
/// ninth conversation replaces the oldest.
pub fn close(conv: &str, agent: &str) -> ChatEnvelope {
    envelope(conv, agent, "close", None, Map::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn env(op: &str, body: Value) -> ChatEnvelope {
        let mut v = json!({"v":1,"op":op,"conversationId":"c1","agentId":"claude"});
        for (k, x) in body.as_object().unwrap() {
            v[k] = x.clone();
        }
        serde_json::from_value(v).unwrap()
    }

    fn msg() -> ChatMessage {
        ChatMessage {
            message_id: "m1".into(),
            role: Role::User,
            origin: Some(Origin::Remote),
            turn_id: "t1".into(),
            request_id: Some("r1".into()),
            created_at_ms: 1700000000000,
            parts: vec![
                Part::Text {
                    id: "p1".into(),
                    markdown: "hi".into(),
                },
                Part::Tool {
                    id: "p2".into(),
                    name: "Bash".into(),
                    summary: "ls".into(),
                },
            ],
        }
    }

    fn body(e: &ChatEnvelope) -> Value {
        serde_json::to_value(e).unwrap()
    }

    #[test]
    fn an_approval_answer_is_a_submit_with_approval_instead_of_text() {
        let answer = json!({"approval_id": "a1", "decision": "allow_once", "acquire": true});
        assert_eq!(
            parse_inbound(&env(
                "submit",
                json!({"generation": "g", "requestId": "r1", "approval": answer.clone()})
            ))
            .unwrap(),
            Inbound::Answer {
                generation: "g".into(),
                request_id: "r1".into(),
                approval: answer.clone(),
            }
        );
        for bad in [
            json!({"generation": "g", "requestId": "r1", "approval": answer, "text": "hi"}),
            json!({"generation": "g", "requestId": "r1", "approval": "allow"}),
        ] {
            assert!(parse_inbound(&env("submit", bad.clone())).is_err(), "{bad}");
        }
    }

    #[test]
    fn an_approval_card_is_a_message_part() {
        use crate::chat::adapter::{ApprovalCard, ApprovalCardState};
        use crate::session_protocol::wire::AlwaysRule;
        let mut m = msg();
        m.role = Role::Assistant;
        m.origin = None;
        m.parts = vec![Part::Approval(ApprovalCard {
            id: "approval".into(),
            approval_id: "a1".into(),
            tool: "Bash".into(),
            summary: "npm test".into(),
            always_rules: vec![AlwaysRule {
                rule_id: "r0-1".into(),
                label: "Allow Bash(npm test:*)".into(),
                scope: "this project".into(),
            }],
            state: ApprovalCardState::AlwaysAllowed,
            rule_id: None,
            note: None,
        })];
        let e = body(&event("c1", "claude", "g", 3, &Out::Message(m)));
        assert_eq!(
            e["parts"][0],
            json!({"id": "approval", "kind": "approval", "approval_id": "a1", "tool": "Bash",
                   "summary": "npm test", "state": "always_allowed",
                   "always_rules": [{"rule_id": "r0-1", "label": "Allow Bash(npm test:*)",
                                     "scope": "this project"}]})
        );
    }

    #[test]
    fn a_rule_revoke_is_a_submit_with_approval_rule_revoke() {
        let revoke = json!({"rule_id": "s-1"});
        assert_eq!(
            parse_inbound(&env(
                "submit",
                json!({"generation": "g", "requestId": "r1", "approval_rule_revoke": revoke.clone()})
            ))
            .unwrap(),
            Inbound::RevokeRule {
                generation: "g".into(),
                request_id: "r1".into(),
                revoke: revoke.clone(),
            }
        );
        for bad in [
            json!({"generation": "g", "requestId": "r1", "approval_rule_revoke": revoke, "text": "hi"}),
            json!({"generation": "g", "requestId": "r1", "approval_rule_revoke": revoke,
                   "approval": {"approval_id": "a"}}),
            json!({"generation": "g", "requestId": "r1", "approval_rule_revoke": "s-1"}),
        ] {
            assert!(parse_inbound(&env("submit", bad.clone())).is_err(), "{bad}");
        }
    }

    #[test]
    fn an_auto_allowed_card_names_its_rule() {
        use crate::chat::adapter::{ApprovalCard, ApprovalCardState};
        let mut m = msg();
        m.role = Role::Assistant;
        m.origin = None;
        m.parts = vec![Part::Approval(ApprovalCard {
            id: "approval".into(),
            approval_id: "a1".into(),
            tool: "Bash".into(),
            summary: "ls".into(),
            always_rules: Vec::new(),
            state: ApprovalCardState::AutoAllowed,
            rule_id: Some("s-1".into()),
            note: None,
        })];
        let e = body(&event("c1", "codex", "g", 3, &Out::Message(m)));
        assert_eq!(
            e["parts"][0],
            json!({"id": "approval", "kind": "approval", "approval_id": "a1", "tool": "Bash",
                   "summary": "ls", "state": "auto_allowed", "always_rules": [],
                   "rule_id": "s-1"})
        );
    }

    #[test]
    fn parse_each_op() {
        assert_eq!(
            parse_inbound(&env("open", json!({}))).unwrap(),
            Inbound::Open { before: None }
        );
        assert_eq!(
            parse_inbound(&env("open", json!({"before":"m9"}))).unwrap(),
            Inbound::Open {
                before: Some("m9".into())
            }
        );
        assert_eq!(
            parse_inbound(&env(
                "submit",
                json!({"generation":"g","requestId":"r","text":"t"})
            ))
            .unwrap(),
            Inbound::Submit {
                generation: "g".into(),
                request_id: "r".into(),
                text: "t".into()
            }
        );
        assert_eq!(
            parse_inbound(&env("close", json!({"extra":1}))).unwrap(),
            Inbound::Close
        );
    }

    #[test]
    fn parse_rejects() {
        let mut e = env("open", json!({}));
        e.v = 2;
        assert_eq!(parse_inbound(&e).unwrap_err(), "unsupported version");
        assert_eq!(
            parse_inbound(&env("nope", json!({}))).unwrap_err(),
            "unsupported op"
        );
        assert_eq!(
            parse_inbound(&env("accepted", json!({}))).unwrap_err(),
            "unsupported op"
        );
        assert_eq!(
            parse_inbound(&env("submit", json!({"requestId":"r","text":"t"}))).unwrap_err(),
            "missing field generation"
        );
        assert_eq!(
            parse_inbound(&env("submit", json!({"generation":"g","text":"t"}))).unwrap_err(),
            "missing field requestId"
        );
        assert_eq!(
            parse_inbound(&env(
                "submit",
                json!({"generation":"g","requestId":"r","text":5})
            ))
            .unwrap_err(),
            "missing field text"
        );
        let long = "x".repeat(129);
        assert_eq!(
            parse_inbound(&env(
                "submit",
                json!({"generation":"g","requestId":long,"text":"t"})
            ))
            .unwrap_err(),
            "invalid requestId"
        );
        let mut e = env("open", json!({}));
        e.conversation_id = long.clone();
        assert_eq!(parse_inbound(&e).unwrap_err(), "invalid conversationId");
        let mut e = env("open", json!({}));
        e.agent_id = String::new();
        assert_eq!(parse_inbound(&e).unwrap_err(), "invalid agentId");
        assert_eq!(
            parse_inbound(&env("open", json!({"before":long}))).unwrap_err(),
            "invalid before"
        );
        // text size is not checked here
        let big = "y".repeat(100_000);
        assert!(
            parse_inbound(&env(
                "submit",
                json!({"generation":"g","requestId":"r","text":big})
            ))
            .is_ok()
        );
    }

    #[test]
    fn opened_shape() {
        let st = Status {
            state: State::Working,
            since_ms: 5,
            detail: None,
        };
        assert_eq!(
            body(&opened("c1", "claude", "g", &st, &[], &[])),
            json!({"v":1,"op":"opened","conversationId":"c1","agentId":"claude","generation":"g","sequence":0,
                   "status":{"state":"working","since":5},"unavailable":[],"approvalRules":[]})
        );
        let codex = ["streaming".to_string(), "reasoning".to_string()];
        let rule = crate::session_protocol::wire::AlwaysRule {
            rule_id: "s-1".into(),
            label: "Always allow `ls` in /p for this session".into(),
            scope: "session".into(),
        };
        let v = body(&opened(
            "c1",
            "codex",
            "g",
            &st,
            &codex,
            std::slice::from_ref(&rule),
        ));
        assert_eq!(v["unavailable"], json!(["streaming", "reasoning"]));
        assert_eq!(
            v["approvalRules"],
            json!([{"rule_id": "s-1", "label": "Always allow `ls` in /p for this session",
                    "scope": "session"}])
        );
        assert_eq!(
            body(&rules("c1", "codex", "g", 4, &[rule])),
            json!({"v":1,"op":"rules","conversationId":"c1","agentId":"codex","generation":"g",
                   "sequence":4,"approvalRules":[{"rule_id": "s-1",
                   "label": "Always allow `ls` in /p for this session", "scope": "session"}]})
        );
        let st = Status {
            state: State::Waiting,
            since_ms: 6,
            detail: Some("Bash".into()),
        };
        assert_eq!(
            body(&opened("c1", "claude", "g", &st, &[], &[]))["status"],
            json!({"state":"waiting","since":6,"detail":"Bash"})
        );
    }

    #[test]
    fn event_shapes() {
        let b = |o: &Out| body(&event("c1", "claude", "g", 3, o));
        let head = |op: &str| json!({"v":1,"op":op,"conversationId":"c1","agentId":"claude","generation":"g","sequence":3});
        let merged = |op: &str, extra: Value| {
            let mut h = head(op);
            for (k, v) in extra.as_object().unwrap() {
                h[k] = v.clone();
            }
            h
        };
        assert_eq!(
            b(&Out::Message(msg())),
            merged(
                "message",
                json!({"messageId":"m1","role":"user","origin":"remote","turnId":"t1","requestId":"r1",
                "createdAt":1700000000000u64,
                "parts":[{"id":"p1","kind":"text","markdown":"hi"},{"id":"p2","kind":"tool","name":"Bash","summary":"ls"}]})
            )
        );
        let mut a = msg();
        a.role = Role::Assistant;
        a.origin = None;
        a.request_id = None;
        let v = b(&Out::Message(a));
        assert_eq!(v["role"], "assistant");
        assert!(v.get("origin").is_none() && v.get("requestId").is_none());
        assert_eq!(
            b(&Out::Delta {
                message_id: "m1".into(),
                part: Part::Text {
                    id: "p3".into(),
                    markdown: "x".into()
                }
            }),
            merged(
                "delta",
                json!({"messageId":"m1","part":{"id":"p3","kind":"text","markdown":"x"}})
            )
        );
        assert_eq!(
            b(&Out::Status(Status {
                state: State::Unknown,
                since_ms: 9,
                detail: None
            })),
            merged("status", json!({"state":"unknown","since":9}))
        );
        assert_eq!(
            b(&Out::Status(Status {
                state: State::Ready,
                since_ms: 9,
                detail: Some("d".into())
            })),
            merged("status", json!({"state":"ready","since":9,"detail":"d"}))
        );
        assert_eq!(
            b(&Out::Accepted {
                request_id: "r1".into()
            }),
            merged("accepted", json!({"requestId":"r1"}))
        );
        assert_eq!(
            b(&Out::Complete {
                turn_id: "t1".into(),
                request_id: None,
                outcome: Outcome::Interrupted
            }),
            merged("complete", json!({"turnId":"t1","outcome":"interrupted"}))
        );
        assert_eq!(
            b(&Out::Complete {
                turn_id: "t1".into(),
                request_id: Some("r1".into()),
                outcome: Outcome::Done
            }),
            merged(
                "complete",
                json!({"turnId":"t1","requestId":"r1","outcome":"done"})
            )
        );
        assert_eq!(
            b(&Out::Error {
                text: "bad".into(),
                request_id: Some("r1".into())
            }),
            merged("error", json!({"text":"bad","requestId":"r1"}))
        );
        assert_eq!(
            b(&Out::Error {
                text: "bad".into(),
                request_id: None
            }),
            merged("error", json!({"text":"bad"}))
        );
    }

    #[test]
    fn history_message_is_marked() {
        let v = body(&history_message("c1", "claude", "g", 4, &msg()));
        assert_eq!(v["op"], "message");
        assert_eq!(v["history"], true);
        assert_eq!(v["sequence"], 4);
        assert_eq!(v["messageId"], "m1");
    }

    #[test]
    fn envelope_round_trip() {
        let e = event(
            "c1",
            "claude",
            "g",
            1,
            &Out::Accepted {
                request_id: "r".into(),
            },
        );
        let back: ChatEnvelope = serde_json::from_str(&serde_json::to_string(&e).unwrap()).unwrap();
        assert_eq!(back, e);
    }

    #[test]
    fn close_carries_only_the_ids() {
        assert_eq!(
            serde_json::to_value(close("c1", "claude")).unwrap(),
            json!({"v":1,"op":"close","conversationId":"c1","agentId":"claude"})
        );
    }
}
