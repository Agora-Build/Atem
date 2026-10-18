//! One runtime.log line per refused session-family request (session-v1,
//! terminal-v1, chat-v1): its family, op, submit kind, error code and
//! session id, never its content. Decode failures keep only the error's
//! category and the field name (serde errors can echo values). Lines are
//! rate-limited per link: at most `MAX_LINES` per `WINDOW_MS`, then one
//! "… N more refusals suppressed" line.
use crate::session_protocol::wire::{
    self, DecodeError, Envelope, RULE_REVOKE_FIELD, ReceiptKind, is_session_id,
};
use serde_json::Value;
use std::collections::HashMap;

pub const MAX_LINES: u32 = 20;
pub const WINDOW_MS: u64 = 10_000;

/// Op names a refusal line may show; anything else is `?` (an unknown op
/// is the peer's text, not protocol vocabulary).
const OPS: &[&str] = &[
    // session-v1
    "hello",
    "challenge",
    "resume_proof",
    "welcome",
    "list",
    "sessions",
    "session_changed",
    "acquire",
    "renew",
    "release",
    "lease",
    "lease_released",
    "lease_changed",
    "submit",
    "receipt",
    "receipt_query",
    "receipts",
    "approval_request",
    "approval_closed",
    "approval_rules",
    "error",
    // terminal-v1
    "subscribe",
    "unsubscribe",
    "ack",
    "input",
    "resize",
    "stop",
    "control",
    "controller",
    "attached",
    "frame",
    "exited",
    "written",
    // chat-v1
    "open",
    "close",
    "opened",
    "accepted",
    "complete",
    "message",
    "status",
    "history",
    "heartbeat",
    "gap",
    "closed",
];

const FAMILIES: &[&str] = &["session", "terminal", "agentChat"];

/// What a refusal line says about the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub family: String,
    pub op: String,
    pub kind: Option<String>,
    pub session: Option<String>,
}

fn known_op(op: Option<&str>) -> String {
    op.filter(|op| OPS.contains(op)).unwrap_or("?").to_string()
}

fn kind_name(kind: ReceiptKind) -> String {
    serde_json::to_value(kind)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

fn session_in(v: &Value) -> Option<String> {
    [
        &v["binding"]["target"]["session_id"],
        &v["terminal_id"],
        &v["agentId"],
    ]
    .into_iter()
    .find_map(|s| s.as_str().filter(|s| is_session_id(s)).map(str::to_string))
}

fn chat_kind(data: &Value) -> Option<String> {
    (data["op"] == "submit").then(|| {
        if data.get(RULE_REVOKE_FIELD).is_some() {
            kind_name(ReceiptKind::ApprovalRuleRevoke)
        } else if data.get("approval").is_some() {
            kind_name(ReceiptKind::Approval)
        } else {
            kind_name(ReceiptKind::Prompt)
        }
    })
}

impl Request {
    /// The request as decoded, or (a decode failure) as far as `text` shows
    /// it: a known family and op, a valid session id, a receipt kind.
    pub fn of(decoded: &Result<Envelope, DecodeError>, text: &str) -> Self {
        match decoded {
            Ok(Envelope::Session(m)) => {
                let v = serde_json::to_value(&m.op).unwrap_or(Value::Null);
                Self {
                    family: "session".into(),
                    op: known_op(v["op"].as_str()),
                    kind: match &m.op {
                        wire::Op::Submit { kind, .. } => Some(kind_name(*kind)),
                        _ => None,
                    },
                    session: session_in(&v),
                }
            }
            Ok(Envelope::Family(f)) => {
                let data = f.data.clone().unwrap_or(Value::Null);
                let family = FAMILIES.iter().find(|k| **k == f.family).map_or("?", |k| k);
                Self {
                    family: family.into(),
                    op: known_op(data["op"].as_str()),
                    kind: (family == "agentChat").then(|| chat_kind(&data)).flatten(),
                    session: f
                        .binding
                        .as_ref()
                        .map(|b| b.target.session_id.clone())
                        .filter(|s| is_session_id(s))
                        .or_else(|| session_in(&data)),
                }
            }
            Err(_) => Self::peek(text),
        }
    }

    /// A message that failed to decode, from its raw text.
    pub fn peek(text: &str) -> Self {
        let root: Value = serde_json::from_str(text).unwrap_or(Value::Null);
        let family = root["type"]
            .as_str()
            .and_then(|t| FAMILIES.iter().find(|k| **k == t))
            .map_or("?", |k| k);
        let data = &root["data"];
        let kind = match family {
            "session" if data["op"] == "submit" => {
                serde_json::from_value::<ReceiptKind>(data["kind"].clone())
                    .ok()
                    .map(kind_name)
            }
            "agentChat" => chat_kind(data),
            _ => None,
        };
        Self {
            family: family.into(),
            op: known_op(data["op"].as_str()),
            kind,
            session: session_in(data),
        }
    }

    /// An oversize message: only its family is known.
    pub fn family_only(family: &str) -> Self {
        Self {
            family: FAMILIES
                .iter()
                .find(|k| **k == family)
                .map_or("?", |k| k)
                .into(),
            op: "?".into(),
            kind: None,
            session: None,
        }
    }
}

/// The line's text after the time stamp.
pub fn line(request: &Request, code: &str, reason: Option<&str>) -> String {
    let mut line = format!("atem runtime: refused {}/{}", request.family, request.op);
    if let Some(kind) = &request.kind {
        line.push_str(&format!(" kind={kind}"));
    }
    line.push_str(&format!(" {code}"));
    if let Some(session) = &request.session {
        line.push_str(&format!(" session={session}"));
    }
    if let Some(reason) = reason {
        line.push_str(&format!(" ({reason})"));
    }
    line
}

/// Why a message failed to decode, without any value it carried.
pub fn decode_reason(error: &DecodeError) -> String {
    if error.removed.is_some() {
        return "removed in atem-session r6".into();
    }
    format!("decode: {}", sanitize(&error.reason))
}

/// A field name from a serde message (`` `name` ``), if it is one.
fn field_name(rest: &str) -> Option<&str> {
    let name = rest.strip_prefix('`')?.split('`').next()?;
    (!name.is_empty()
        && name.len() <= 40
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
    .then_some(name)
}

/// Keeps the category of a decode error (and a field name), never a value.
pub fn sanitize(reason: &str) -> String {
    // Contexts this crate prefixes (`binding: `, `agentChat: `,
    // `approval_rule_revoke: `): names written in code.
    let mut prefix = String::new();
    let mut rest = reason;
    while let Some((context, r)) = rest.split_once(": ")
        && !context.is_empty()
        && context.len() <= 40
        && context
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        prefix.push_str(context);
        prefix.push_str(": ");
        rest = r;
    }
    // Messages this crate writes itself (no peer text).
    const FIXED: &[&str] = &[
        "unsupported v",
        "missing or invalid id",
        "invalid re",
        "missing type",
        "missing op",
        "message is not an object",
        "data must be an object",
        "session data must be an object",
        crate::session_protocol::wire::REMOVED_IN_R8,
        crate::session_protocol::wire::FEATURE_NOT_ADVERTISED,
    ];
    // `canonical::StrictError` variants (`Syntax(offset)`).
    const STRICT: &[&str] = &[
        "TooLarge",
        "InvalidUtf8",
        "Syntax",
        "DuplicateKey",
        "LoneSurrogate",
        "NonInteger",
        "UnsafeInteger",
        "TooDeep",
    ];
    let core = 'core: {
        for category in ["unknown field ", "missing field ", "duplicate field "] {
            if let Some(after) = rest.strip_prefix(category) {
                break 'core match field_name(after) {
                    Some(name) => format!("{category}`{name}`"),
                    None => category.trim_end().to_string(),
                };
            }
        }
        for category in [
            "unknown variant",
            "invalid type",
            "invalid value",
            "invalid length",
        ] {
            if rest.starts_with(category) {
                break 'core category.to_string();
            }
        }
        if FIXED.contains(&rest) {
            break 'core rest.to_string();
        }
        let head = rest.split('(').next().unwrap_or_default();
        if STRICT.contains(&head) {
            break 'core format!("json: {head}");
        }
        // `invalid <field>` from the validators: a name written in code.
        if let Some(what) = rest.strip_prefix("invalid ")
            && what.len() <= 40
            && what
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | ' ' | '.'))
        {
            break 'core rest.to_string();
        }
        if rest.ends_with("cannot carry a binding") {
            break 'core "unexpected binding".to_string();
        }
        "invalid".to_string()
    };
    format!("{prefix}{core}")
}

#[derive(Debug)]
struct Window {
    start: u64,
    lines: u32,
    suppressed: u64,
}

/// The rate limit, per link generation (one link's attachments share it,
/// so a client that says `hello` again can't escape it).
#[derive(Debug, Default)]
pub struct RefusalLog {
    windows: HashMap<u64, Window>,
}

fn suppressed_line(n: u64) -> String {
    format!("atem runtime: \u{2026} {n} more refusals suppressed")
}

impl RefusalLog {
    /// `line` for `link` at `now` (ms): the lines to write (none while
    /// suppressed; the previous window's summary first after one).
    pub fn record(&mut self, link: u64, now: u64, line: String) -> Vec<String> {
        let mut out = Vec::new();
        let window = self.windows.entry(link).or_insert(Window {
            start: now,
            lines: 0,
            suppressed: 0,
        });
        if now.saturating_sub(window.start) >= WINDOW_MS {
            if window.suppressed > 0 {
                out.push(suppressed_line(window.suppressed));
            }
            *window = Window {
                start: now,
                lines: 0,
                suppressed: 0,
            };
        }
        if window.lines < MAX_LINES {
            window.lines += 1;
            out.push(line);
        } else {
            window.suppressed += 1;
        }
        out
    }

    /// Summaries of windows that ended with refusals suppressed; ended
    /// windows are forgotten.
    pub fn flush(&mut self, now: u64) -> Vec<String> {
        let mut out = Vec::new();
        self.windows.retain(|_, w| {
            if now.saturating_sub(w.start) < WINDOW_MS {
                return true;
            }
            if w.suppressed > 0 {
                out.push(suppressed_line(w.suppressed));
            }
            false
        });
        out
    }
}

#[cfg(test)]
thread_local! {
    /// Lines written on this thread (tests read them).
    pub static WRITTEN: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Writes `lines` to runtime.log (stderr) with the UTC `HH:MM:SS` stamp.
pub fn write(lines: Vec<String>) {
    if lines.is_empty() {
        return;
    }
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
        % 86_400;
    for line in lines {
        eprintln!(
            "{:02}:{:02}:{:02} {line}",
            secs / 3600,
            secs / 60 % 60,
            secs % 60
        );
        #[cfg(test)]
        WRITTEN.with(|w| w.borrow_mut().push(line));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_values_never_survive_sanitizing() {
        let cases = [
            (
                "unknown field `SECRET_x`, expected one of `a`",
                "unknown field `SECRET_x`",
            ),
            (
                "missing field `rule_id` at line 1 column 2",
                "missing field `rule_id`",
            ),
            (
                "invalid value: string \"SECRET\", expected a uuid",
                "invalid value",
            ),
            (
                "invalid type: string \"SECRET\", expected u64",
                "invalid type",
            ),
            (
                "unknown variant `SECRET`, expected `prompt`",
                "unknown variant",
            ),
            ("unknown field `has space SECRET`", "unknown field"),
            (
                "binding: missing field `target`",
                "binding: missing field `target`",
            ),
            (
                "agentChat: invalid requestId",
                "agentChat: invalid requestId",
            ),
            (
                "agentChat: approval_rule_revoke: unknown field `rule`, expected `rule_id`",
                "agentChat: approval_rule_revoke: unknown field `rule`",
            ),
            ("invalid value: string \"a: b\"", "invalid value"),
            ("Syntax(12)", "json: Syntax"),
            (
                "terminal SECRET cannot carry a binding",
                "unexpected binding",
            ),
            ("approval: removed in r8", "approval: removed in r8"),
            (
                "agentChat: feature not advertised",
                "agentChat: feature not advertised",
            ),
            ("SECRET free text", "invalid"),
            ("invalid \"SECRET\"", "invalid"),
        ];
        for (reason, want) in cases {
            let got = sanitize(reason);
            assert_eq!(got, want, "{reason}");
            if !want.contains("SECRET") {
                assert!(!got.contains("SECRET"), "{got}");
            }
        }
    }

    #[test]
    fn at_most_twenty_lines_per_window_then_one_summary() {
        let mut log = RefusalLog::default();
        let mut out = Vec::new();
        for i in 0..50 {
            out.extend(log.record(1, i * 10, format!("l{i}")));
        }
        assert_eq!(out.len(), MAX_LINES as usize);
        // Another link has its own budget.
        assert_eq!(
            log.record(2, 100, "other".into()),
            vec!["other".to_string()]
        );
        // The next window starts with the summary.
        let next = log.record(1, WINDOW_MS + 5, "again".into());
        assert_eq!(next, vec![suppressed_line(30), "again".to_string()]);
        // A window that ends quietly is summarized by `flush`.
        for i in 0..25 {
            log.record(1, WINDOW_MS + 10 + i, "x".into());
        }
        assert!(log.flush(WINDOW_MS + 100).is_empty());
        assert_eq!(log.flush(3 * WINDOW_MS), vec![suppressed_line(6)]);
        assert!(log.flush(4 * WINDOW_MS).is_empty());
    }

    #[test]
    fn a_line_names_family_op_kind_code_and_session() {
        let request = Request {
            family: "session".into(),
            op: "submit".into(),
            kind: Some("approval_rule_revoke".into()),
            session: Some("ses-abcdefghijkl".into()),
        };
        assert_eq!(
            line(&request, "stale_target", Some("decode: invalid value")),
            "atem runtime: refused session/submit kind=approval_rule_revoke stale_target \
             session=ses-abcdefghijkl (decode: invalid value)"
        );
        let unknown = Request::peek(r#"{"type":"session","data":{"op":"SECRET"}}"#);
        assert_eq!(
            line(&unknown, "unsupported_version", None),
            "atem runtime: refused session/? unsupported_version"
        );
    }
}
