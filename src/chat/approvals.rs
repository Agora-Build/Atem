//! Agent permission prompts answered from Astation (approvals, step 1b):
//! the shared `PermissionRequest` hook script, what an approval card shows
//! (`ApprovalInfo`, redacted here) and the decision a hook prints.
//!
//! The hook (`approval_hook.sh`) finds the session through
//! `ATEM_APPROVAL_DIR`: it writes the request to
//! `<dir>/approvals/req-<id>.json` (its pid in `pid-<id>`) and waits for
//! `dec-<id>.json`, which holds the exact output for the agent (empty: "no
//! decision", the agent asks as usual). Claude gets the variable inside its
//! per-launch hook command; Codex gets it from the worker's environment and
//! runs one stable command from `~/.codex/hooks.json` (`chat::codex`).
//!
//! Codex can't take a persistent decision: its docs reserve
//! `updatedPermissions` ("fail closed today"), so Codex cards offer Allow
//! once and Deny only (`always_rules` is empty).

use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::session_protocol::host::ApprovalInfo;
use crate::session_protocol::wire::{
    AlwaysRule, ApprovalDecision, MAX_ALWAYS_RULES, MAX_APPROVAL_SUMMARY_BYTES,
    MAX_APPROVAL_TOOL_BYTES, MAX_RULE_TEXT_BYTES,
};

/// The hook script (POSIX sh).
pub const SCRIPT: &str = include_str!("approval_hook.sh");
/// The environment variable naming the session directory.
pub const ENV: &str = "ATEM_APPROVAL_DIR";
/// The script's file name in a Claude session directory.
pub const SCRIPT_NAME: &str = "approval-hook.sh";
/// Hook timeouts (seconds): Claude shows its dialog meanwhile, Codex holds
/// its prompt until the hook returns, so its wait is shorter.
pub const CLAUDE_TIMEOUT: u64 = 600;
pub const CODEX_TIMEOUT: u64 = 300;
/// What a deny without a message tells the agent.
pub const DEFAULT_DENY: &str = "Denied from Astation";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Agent {
    Claude,
    Codex,
}

impl Agent {
    pub fn timeout_secs(self) -> u64 {
        match self {
            Agent::Claude => CLAUDE_TIMEOUT,
            Agent::Codex => CODEX_TIMEOUT,
        }
    }
}

/// `<dir>/approvals`.
pub fn approvals_dir(dir: &Path) -> PathBuf {
    dir.join("approvals")
}

pub fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Writes the script to `path` (0600) unless it already holds it; replaced
/// atomically, never through a symlink.
pub fn install_script(path: &Path) -> std::io::Result<()> {
    if std::fs::symlink_metadata(path).is_ok_and(|m| m.is_file())
        && std::fs::read(path).is_ok_and(|b| b == SCRIPT.as_bytes())
    {
        return Ok(());
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    crate::runtime::worker::write_atomic(path, SCRIPT.as_bytes())
}

/// Claude's `PermissionRequest` hook command for session directory `dir`
/// (the script installed there).
pub fn claude_command(dir: &Path) -> String {
    format!(
        "{ENV}={} exec /bin/sh {} claude {CLAUDE_TIMEOUT}",
        shell_quote(&dir.to_string_lossy()),
        shell_quote(&dir.join(SCRIPT_NAME).to_string_lossy())
    )
}

/// Claude's `PostToolUse` command telling the worker a tool ran.
pub fn claude_post_command(dir: &Path) -> String {
    format!(
        "{ENV}={} exec /bin/sh {} post",
        shell_quote(&dir.to_string_lossy()),
        shell_quote(&dir.join(SCRIPT_NAME).to_string_lossy())
    )
}

/// One line, no control characters, at most `max` bytes (cut at a char
/// boundary, ending with `…` when cut).
fn bounded(text: &str, max: usize) -> String {
    let clean: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let clean = clean.trim();
    if clean.len() <= max {
        return clean.to_string();
    }
    let mut end = max.saturating_sub('…'.len_utf8());
    while !clean.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &clean[..end])
}

/// Secrets redacted first (a cut can't leave part of one), then bounded.
fn redacted(text: &str, max: usize) -> String {
    bounded(&crate::memory::secrets::redact_secrets(text), max)
}

/// The card's summary: Bash's command's first line, a file tool's path,
/// `apply_patch`'s files, else the tool's name. Redacted, never full inputs.
pub fn summary(tool: &str, input: &Value) -> String {
    let s = |k: &str| input.get(k).and_then(Value::as_str);
    let text = match tool {
        "Bash" | "shell" | "exec_command" => s("command")
            .map(|c| c.lines().find(|l| !l.trim().is_empty()).unwrap_or(""))
            .map(str::to_string),
        "apply_patch" => s("command").map(|patch| {
            let files: Vec<&str> = patch
                .lines()
                .filter_map(|l| {
                    ["*** Add File: ", "*** Update File: ", "*** Delete File: "]
                        .iter()
                        .find_map(|p| l.strip_prefix(p))
                })
                .collect();
            if files.is_empty() {
                tool.to_string()
            } else {
                files.join(", ")
            }
        }),
        _ => s("file_path")
            .or_else(|| s("notebook_path"))
            .or_else(|| s("path"))
            .map(str::to_string),
    };
    redacted(
        &text.unwrap_or_else(|| tool.to_string()),
        MAX_APPROVAL_SUMMARY_BYTES,
    )
}

/// Where a Claude suggestion applies, in words.
fn scope(destination: Option<&str>) -> String {
    match destination {
        Some("session") => "this session only".into(),
        Some("localSettings") => "this project, only you (.claude/settings.local.json)".into(),
        Some("projectSettings") => "this project, shared (.claude/settings.json)".into(),
        Some("userSettings") => "all your projects (~/.claude/settings.json)".into(),
        Some("cliArg") => "this launch only".into(),
        Some(other) => format!("{other} settings"),
        None => "as Claude proposes".into(),
    }
}

/// A Claude `permission_suggestions` entry as a rule the card offers, or
/// `None` when it isn't an allow rule (removals, deny/ask rules, bypass).
fn rule_label(suggestion: &Value) -> Option<String> {
    let s = |k: &str| suggestion.get(k).and_then(Value::as_str);
    let label = match s("type")? {
        "addRules" => {
            if s("behavior").is_some_and(|b| b != "allow") {
                return None;
            }
            let rules: Vec<String> = suggestion
                .get("rules")?
                .as_array()?
                .iter()
                .filter_map(|r| {
                    let tool = r.get("toolName")?.as_str()?;
                    Some(match r.get("ruleContent").and_then(Value::as_str) {
                        Some(content) if !content.is_empty() => format!("{tool}({content})"),
                        _ => tool.to_string(),
                    })
                })
                .collect();
            if rules.is_empty() {
                return None;
            }
            format!("Allow {}", rules.join(", "))
        }
        "addDirectories" => {
            let dirs: Vec<&str> = suggestion
                .get("directories")?
                .as_array()?
                .iter()
                .filter_map(Value::as_str)
                .collect();
            if dirs.is_empty() {
                return None;
            }
            format!("Allow access to {}", dirs.join(", "))
        }
        "setMode" => match s("mode")? {
            "bypassPermissions" => return None,
            "acceptEdits" => "Accept edits without asking".into(),
            mode => format!("Switch to {mode} mode"),
        },
        _ => return None,
    };
    Some(label)
}

fn rule_id(index: usize, suggestion: &Value) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(suggestion.to_string().as_bytes());
    let hex: String = digest[..4].iter().map(|b| format!("{b:02x}")).collect();
    format!("r{index}-{hex}")
}

/// A request as the hook wrote it, with the raw rules to echo back.
#[derive(Debug, Clone, PartialEq)]
pub struct Request {
    pub info: ApprovalInfo,
    /// `rule_id` → the agent's own suggestion, echoed as `updatedPermissions`.
    pub rules: Vec<(String, Value)>,
    pub tool_name: String,
    pub tool_input: Value,
}

/// What the card shows for `input` (the hook's stdin): tool, redacted
/// summary and, for Claude, its own allow suggestions (labels redacted).
pub fn request(agent: Agent, input: &Value) -> Option<Request> {
    let tool_name = input.get("tool_name")?.as_str()?.to_string();
    let tool_input = input.get("tool_input").cloned().unwrap_or(Value::Null);
    let mut tool = bounded(&tool_name, MAX_APPROVAL_TOOL_BYTES);
    if tool.is_empty() {
        tool = "unknown".into();
    }
    let mut rules = Vec::new();
    let mut always_rules = Vec::new();
    if agent == Agent::Claude
        && let Some(suggestions) = input
            .get("permission_suggestions")
            .and_then(Value::as_array)
    {
        for (i, suggestion) in suggestions.iter().enumerate() {
            if always_rules.len() >= MAX_ALWAYS_RULES {
                break;
            }
            let Some(label) = rule_label(suggestion) else {
                continue;
            };
            let id = rule_id(i, suggestion);
            always_rules.push(AlwaysRule {
                rule_id: id.clone(),
                label: redacted(&label, MAX_RULE_TEXT_BYTES),
                scope: redacted(
                    &scope(suggestion.get("destination").and_then(Value::as_str)),
                    MAX_RULE_TEXT_BYTES,
                ),
            });
            rules.push((id, suggestion.clone()));
        }
    }
    Some(Request {
        info: ApprovalInfo {
            summary: summary(&tool_name, &tool_input),
            tool,
            always_rules,
        },
        rules,
        tool_name,
        tool_input,
    })
}

fn output(decision: &str) -> String {
    format!(
        r#"{{"hookSpecificOutput":{{"hookEventName":"PermissionRequest","decision":{decision}}}}}"#
    )
}

/// What the hook prints for a decision: the same shape for both agents;
/// `allow_always` echoes the chosen suggestion as `updatedPermissions`
/// (`None` when it isn't one of `request`'s rules, or for Codex, which has
/// none). A deny without a message gets `DEFAULT_DENY`.
pub fn decision_output(
    request: &Request,
    decision: ApprovalDecision,
    rule_id: Option<&str>,
    message: Option<&str>,
) -> Option<String> {
    Some(match decision {
        ApprovalDecision::AllowOnce => output(r#"{"behavior":"allow"}"#),
        ApprovalDecision::AllowAlways => {
            let id = rule_id?;
            let (_, rule) = request.rules.iter().find(|(r, _)| r == id)?;
            output(&format!(
                r#"{{"behavior":"allow","updatedPermissions":[{rule}]}}"#
            ))
        }
        ApprovalDecision::Deny => {
            let message = message
                .map(str::trim)
                .filter(|m| !m.is_empty())
                .unwrap_or(DEFAULT_DENY);
            output(&format!(
                r#"{{"behavior":"deny","message":{}}}"#,
                Value::String(message.to_string())
            ))
        }
    })
}

#[cfg(test)]
mod tests;
