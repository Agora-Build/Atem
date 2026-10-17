use super::*;
use serde_json::json;
use std::fs;
use std::io::Write;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn fixture(name: &str) -> String {
    fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/approvals")
            .join(name),
    )
    .unwrap()
}

/// A session directory with `approvals/` and the installed script.
fn session() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(approvals_dir(dir.path())).unwrap();
    install_script(&dir.path().join(SCRIPT_NAME)).unwrap();
    dir
}

/// Runs `command` like an agent does (`sh -c`, stdin piped then closed).
fn spawn(command: &str, env: &[(&str, &Path)], stdin: &str) -> Child {
    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c")
        .arg(command)
        .env_remove(ENV)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child
}

fn finish(child: Child) -> (bool, String, String) {
    let out = child.wait_with_output().unwrap();
    (
        out.status.success(),
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
    )
}

/// The id of the one request the hook wrote (waits up to 5 s).
fn wait_request(dir: &Path) -> String {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        for e in fs::read_dir(approvals_dir(dir)).unwrap().flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if let Some(id) = name
                .strip_prefix("req-")
                .and_then(|n| n.strip_suffix(".json"))
            {
                return id.to_string();
            }
        }
        assert!(Instant::now() < deadline, "no request written");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn decide(dir: &Path, id: &str, output: &str) {
    crate::runtime::worker::write_atomic(
        &approvals_dir(dir).join(format!("dec-{id}.json")),
        output.as_bytes(),
    )
    .unwrap();
}

/// Runs Claude's real command on the fixture, answers with `output` and
/// returns what the hook printed.
fn claude_round(output: &str) -> String {
    let s = session();
    let input = fixture("claude-permission-request.json");
    let child = spawn(&claude_command(s.path()), &[], &input);
    let id = wait_request(s.path());
    let req = approvals_dir(s.path()).join(format!("req-{id}.json"));
    assert_eq!(fs::read_to_string(&req).unwrap(), input);
    let ids = fs::read_to_string(approvals_dir(s.path()).join(format!("pid-{id}"))).unwrap();
    let ids: Vec<u32> = ids.split_whitespace().map(|p| p.parse().unwrap()).collect();
    assert_eq!(
        ids,
        [child.id(), std::process::id()],
        "the hook's pid (the process the agent started) and its parent's"
    );
    decide(s.path(), &id, output);
    let (ok, stdout, stderr) = finish(child);
    assert!(ok && stderr.is_empty(), "{stderr}");
    assert!(
        !approvals_dir(s.path())
            .join(format!("dec-{id}.json"))
            .exists()
            && !approvals_dir(s.path())
                .join(format!("taken-{id}.json"))
                .exists()
            && approvals_dir(s.path())
                .join(format!("claimed-{id}"))
                .exists(),
        "the hook claimed the decision, read it and set it aside"
    );
    stdout
}

fn claude_request() -> Request {
    let input: Value = serde_json::from_str(&fixture("claude-permission-request.json")).unwrap();
    request(Agent::Claude, &input).unwrap()
}

#[test]
fn claude_allow_once_is_printed_exactly() {
    let r = claude_request();
    let out = decision_output(&r, ApprovalDecision::AllowOnce, None, None).unwrap();
    assert_eq!(
        claude_round(&out),
        r#"{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"allow"}}}"#
    );
}

#[test]
fn claude_allow_always_echoes_the_chosen_suggestion() {
    let r = claude_request();
    assert_eq!(r.info.always_rules.len(), 1);
    let rule = &r.info.always_rules[0];
    assert_eq!(rule.label, "Allow access to /tmp");
    assert_eq!(rule.scope, "this session only");
    let out =
        decision_output(&r, ApprovalDecision::AllowAlways, Some(&rule.rule_id), None).unwrap();
    assert_eq!(
        claude_round(&out),
        r#"{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"allow","updatedPermissions":[{"destination":"session","directories":["/tmp"],"type":"addDirectories"}]}}}"#
    );
    // Only an offered rule.
    assert!(decision_output(&r, ApprovalDecision::AllowAlways, Some("r9-x"), None).is_none());
    assert!(decision_output(&r, ApprovalDecision::AllowAlways, None, None).is_none());
}

#[test]
fn claude_deny_carries_the_message() {
    let r = claude_request();
    let out = decision_output(
        &r,
        ApprovalDecision::Deny,
        None,
        Some("not \"now\"\nuse the staging db"),
    )
    .unwrap();
    assert_eq!(
        claude_round(&out),
        r#"{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"deny","message":"not \"now\"\nuse the staging db"}}}"#
    );
    let plain = decision_output(&r, ApprovalDecision::Deny, None, None).unwrap();
    assert!(plain.contains(r#""message":"Denied from Astation""#));
}

#[test]
fn no_decision_prints_nothing() {
    assert_eq!(claude_round(""), "");
}

#[test]
fn the_hook_gives_up_at_its_timeout_silently() {
    let s = session();
    let script = s.path().join(SCRIPT_NAME);
    let cmd = format!(
        "exec /bin/sh {} claude 1",
        shell_quote(&script.to_string_lossy())
    );
    let started = Instant::now();
    let child = spawn(&cmd, &[(ENV, s.path())], "{}");
    wait_request(s.path());
    let (ok, stdout, stderr) = finish(child);
    assert!(ok && stdout.is_empty() && stderr.is_empty());
    let took = started.elapsed();
    assert!(
        took >= Duration::from_millis(900) && took < Duration::from_secs(5),
        "{took:?}"
    );
}

#[test]
fn a_withdrawn_request_ends_the_wait() {
    let s = session();
    let child = spawn(&claude_command(s.path()), &[], "{}");
    let id = wait_request(s.path());
    fs::remove_file(approvals_dir(s.path()).join(format!("req-{id}.json"))).unwrap();
    let (ok, stdout, stderr) = finish(child);
    assert!(ok && stdout.is_empty() && stderr.is_empty());
}

#[test]
fn outside_atem_the_hook_exits_at_once_without_output() {
    let s = session();
    let script = s.path().join(SCRIPT_NAME);
    let cmd = format!(
        "/bin/sh {} codex 300",
        shell_quote(&script.to_string_lossy())
    );
    let input = fixture("codex-permission-request.json");
    for env in [vec![], vec![(ENV, Path::new(""))]] {
        let started = Instant::now();
        let (ok, stdout, stderr) = finish(spawn(&cmd, &env, &input));
        assert!(ok && stdout.is_empty() && stderr.is_empty());
        assert!(started.elapsed() < Duration::from_secs(2));
    }
    // A directory without approvals/ (not a session): the same.
    let plain = tempfile::tempdir().unwrap();
    let (ok, stdout, _) = finish(spawn(&cmd, &[(ENV, plain.path())], &input));
    assert!(ok && stdout.is_empty());
    assert_eq!(fs::read_dir(approvals_dir(s.path())).unwrap().count(), 0);
}

#[test]
fn codex_round_trip_with_the_stable_command() {
    let s = session();
    let script = s.path().join(SCRIPT_NAME);
    let cmd = crate::chat::codex::hook_command(&script);
    let input = fixture("codex-permission-request.json");
    let value: Value = serde_json::from_str(&input).unwrap();
    let r = request(Agent::Codex, &value).unwrap();
    assert_eq!(r.info.tool, "Bash");
    assert_eq!(r.info.summary, "touch probe.txt");
    // Codex takes no persistent rule: the card offers an Atem session rule,
    // and the hook only ever gets a plain allow.
    let [rule] = r.info.always_rules.as_slice() else {
        panic!("one session rule: {:?}", r.info.always_rules)
    };
    assert_eq!(
        rule.label,
        "Always allow `touch probe.txt` in /home/user/proj for this session"
    );
    assert_eq!(rule.scope, "session");
    assert!(rule.rule_id.starts_with("s-") && rule.rule_id.len() == 18);
    let rule_id = rule.rule_id.clone();
    for (decision, rule_id, message, expected) in [
        (
            ApprovalDecision::AllowOnce,
            None,
            None,
            r#"{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"allow"}}}"#,
        ),
        (
            ApprovalDecision::AllowAlways,
            Some(rule_id.as_str()),
            None,
            r#"{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"allow"}}}"#,
        ),
        (
            ApprovalDecision::Deny,
            None,
            Some("Denied by phone"),
            r#"{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"deny","message":"Denied by phone"}}}"#,
        ),
    ] {
        let child = spawn(&cmd, &[(ENV, s.path())], &input);
        let id = wait_request(s.path());
        decide(
            s.path(),
            &id,
            &decision_output(&r, decision, rule_id, message).unwrap(),
        );
        let (ok, stdout, stderr) = finish(child);
        assert!(ok && stderr.is_empty());
        assert_eq!(stdout, expected);
        for f in ["req", "pid"] {
            let _ = fs::remove_file(approvals_dir(s.path()).join(match f {
                "req" => format!("req-{id}.json"),
                _ => format!("pid-{id}"),
            }));
        }
    }
    assert!(decision_output(&r, ApprovalDecision::AllowAlways, Some("r0-x"), None).is_none());
    // Outside Atem the stable command does nothing, even without the script.
    let (ok, stdout, stderr) = finish(spawn(&cmd, &[], &input));
    assert!(ok && stdout.is_empty() && stderr.is_empty());
    let missing = crate::chat::codex::hook_command(&s.path().join("gone.sh"));
    let (ok, stdout, stderr) = finish(spawn(&missing, &[(ENV, s.path())], &input));
    assert!(ok && stdout.is_empty() && stderr.is_empty());
}

#[test]
fn post_files_are_written_only_while_a_request_waits() {
    let s = session();
    let post = claude_post_command(s.path());
    let posts = |dir: &Path| {
        fs::read_dir(approvals_dir(dir))
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with("post-"))
            .count()
    };
    let (ok, stdout, _) = finish(spawn(&post, &[], r#"{"tool_name":"Bash"}"#));
    assert!(ok && stdout.is_empty());
    assert_eq!(posts(s.path()), 0);
    fs::write(approvals_dir(s.path()).join("req-abc.json"), "{}").unwrap();
    let (ok, stdout, _) = finish(spawn(&post, &[], r#"{"tool_name":"Bash"}"#));
    assert!(ok && stdout.is_empty());
    assert_eq!(posts(s.path()), 1);
}

#[test]
fn the_summary_is_short_and_redacted() {
    let j = |s: &str| serde_json::from_str::<Value>(s).unwrap();
    let bash = j(
        r#"{"command":"curl -H 'Authorization: Bearer sk-proj-abcdef1234567890ABCDEF' https://x.example\nrm -rf /","description":"d"}"#,
    );
    let s = summary("Bash", &bash);
    assert!(s.contains("[redacted]") && !s.contains("sk-proj"), "{s}");
    assert!(!s.contains("rm -rf"), "first line only: {s}");
    assert_eq!(
        summary(
            "Write",
            &j(r#"{"file_path":"/w/a.rs","content":"SECRET BODY"}"#)
        ),
        "/w/a.rs"
    );
    assert_eq!(
        summary("Edit", &j(r#"{"file_path":"/w/b.rs","old_string":"x"}"#)),
        "/w/b.rs"
    );
    assert_eq!(
        summary("WebFetch", &j(r#"{"url":"https://u:p@h/x"}"#)),
        "WebFetch"
    );
    assert_eq!(
        summary(
            "apply_patch",
            &j(
                r#"{"command":"*** Begin Patch\n*** Update File: src/a.rs\n+secret\n*** Add File: b.txt\n*** End Patch"}"#
            )
        ),
        "src/a.rs, b.txt"
    );
    let long = j(&format!(r#"{{"command":"echo {}"}}"#, "é".repeat(400)));
    let s = summary("Bash", &long);
    assert!(s.len() <= MAX_APPROVAL_SUMMARY_BYTES && s.ends_with('…'));
    assert_eq!(summary("Bash", &j(r#"{"command":"a\tb\u0007c"}"#)), "a b c");
}

#[test]
fn rules_are_the_agents_own_allow_suggestions() {
    let input = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": {"command": "npm test"},
        "permission_suggestions": [
            {"type":"addRules","rules":[{"toolName":"Bash","ruleContent":"npm test:*"}],"behavior":"allow","destination":"localSettings"},
            {"type":"addRules","rules":[{"toolName":"Bash","ruleContent":"rm:*"}],"behavior":"deny","destination":"session"},
            {"type":"setMode","mode":"bypassPermissions","destination":"session"},
            {"type":"setMode","mode":"acceptEdits","destination":"session"},
            {"type":"removeRules","rules":[],"behavior":"allow","destination":"session"},
            {"type":"addRules","rules":[{"toolName":"Bash","ruleContent":"export K=sk-proj-abcdef1234567890ABCDEF"}],"behavior":"allow","destination":"userSettings"}
        ]
    });
    let r = request(Agent::Claude, &input).unwrap();
    let labels: Vec<(&str, &str)> = r
        .info
        .always_rules
        .iter()
        .map(|x| (x.label.as_str(), x.scope.as_str()))
        .collect();
    assert_eq!(
        labels,
        [
            (
                "Allow Bash(npm test:*)",
                "this project, only you (.claude/settings.local.json)"
            ),
            ("Accept edits without asking", "this session only"),
            (
                "Allow Bash(export K=[redacted])",
                "all your projects (~/.claude/settings.json)"
            ),
        ]
    );
    crate::session_protocol::wire::validate_approval_info(
        &r.info.tool,
        &r.info.summary,
        &r.info.always_rules,
    )
    .unwrap();
    // The raw rule is echoed (the redaction is only for the card).
    let id = &r.info.always_rules[2].rule_id;
    assert!(id.starts_with("r5-"));
    let out = decision_output(&r, ApprovalDecision::AllowAlways, Some(id), None).unwrap();
    assert!(out.contains("sk-proj-abcdef1234567890ABCDEF"));
    // Codex: never any rule.
    assert!(
        request(Agent::Codex, &input)
            .unwrap()
            .info
            .always_rules
            .is_empty()
    );
    assert!(request(Agent::Claude, &serde_json::json!({})).is_none());
}

#[test]
fn settings_default_to_claude_on_and_codex_off() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    assert!(enabled(&config, Agent::Claude));
    assert!(!enabled(&config, Agent::Codex));
    fs::write(&config, "[codex]\napprovals_hook = true\n").unwrap();
    assert!(
        !enabled(&config, Agent::Codex),
        "the setting is [codex] hooks"
    );
    fs::write(&config, "[codex]\nhooks = true\n").unwrap();
    assert!(enabled(&config, Agent::Claude));
    assert!(enabled(&config, Agent::Codex));
    fs::write(&config, "[claude]\napprovals_hook = false\n").unwrap();
    assert!(!enabled(&config, Agent::Claude));
    assert_eq!(read_setting(&config, Agent::Claude).unwrap(), Some(false));
    // An unreadable config.toml turns both off.
    fs::write(&config, "not = = toml").unwrap();
    assert!(!enabled(&config, Agent::Claude));
    assert!(!enabled(&config, Agent::Codex));
}

#[test]
fn a_codex_session_rule_matches_exactly_what_was_asked() {
    let ask = |tool: &str, input: Value, cwd: Option<&str>| {
        let mut v = json!({"tool_name": tool, "tool_input": input});
        if let Some(cwd) = cwd {
            v["cwd"] = json!(cwd);
        }
        request(Agent::Codex, &v).unwrap()
    };
    let r = ask("Bash", json!({"command": "npm test"}), Some("/p"));
    assert_eq!(
        r.matcher,
        Some(RuleMatch::Command {
            tool: "Bash".into(),
            command: "npm test".into(),
            cwd: "/p".into(),
        })
    );
    // Each request offers its own rule id.
    let again = ask("Bash", json!({"command": "npm test"}), Some("/p"));
    assert_eq!(r.matcher, again.matcher);
    assert_ne!(
        r.info.always_rules[0].rule_id,
        again.info.always_rules[0].rule_id
    );
    // Not the same request: anything that differs at all.
    for other in [
        ask("Bash", json!({"command": "npm test; rm -rf ~"}), Some("/p")),
        ask("Bash", json!({"command": "npm test "}), Some("/p")),
        ask("Bash", json!({"command": "npm test"}), Some("/q")),
        ask("shell", json!({"command": "npm test"}), Some("/p")),
    ] {
        assert_ne!(r.matcher, other.matcher, "{:?}", other.matcher);
    }
    // No cwd, or a tool it can't tell exactly: no rule offered.
    for none in [
        ask("Bash", json!({"command": "npm test"}), None),
        ask("Bash", json!({"command": ["npm", "test"]}), Some("/p")),
        ask("WebFetch", json!({"url": "https://x"}), Some("/p")),
    ] {
        assert!(none.matcher.is_none() && none.session_rule.is_none());
        assert!(none.info.always_rules.is_empty());
    }
    // A multi-line command: the label shows its first line and says how
    // many more there are; the rule matches all of it.
    let multi = ask(
        "Bash",
        json!({"command": "echo one\necho two\necho three"}),
        Some("/p"),
    );
    assert_eq!(
        multi.info.always_rules[0].label,
        "Always allow `echo one` (+2 more lines) in /p for this session"
    );
    // File changes: exact paths and kinds.
    let patch = "*** Begin Patch\n*** Update File: src/a.rs\n@@\n-x\n+y\n*** Add File: b.txt\n+hi\n*** End Patch";
    let p = ask("apply_patch", json!({"command": patch}), Some("/p"));
    assert_eq!(
        p.matcher,
        Some(RuleMatch::Files {
            tool: "apply_patch".into(),
            changes: vec![
                ("update".into(), "src/a.rs".into()),
                ("add".into(), "b.txt".into())
            ],
            cwd: "/p".into(),
        })
    );
    assert_eq!(
        p.info.always_rules[0].label,
        "Always allow update src/a.rs, add b.txt in /p for this session"
    );
}

#[test]
fn a_session_rule_label_is_redacted_and_claude_gets_none() {
    let secret = "sk-proj-abcdef1234567890ABCDEF";
    let v = json!({"tool_name": "Bash", "cwd": "/p",
                   "tool_input": {"command": format!("curl -H 'x-api-key: {secret}' https://x")}});
    let r = request(Agent::Codex, &v).unwrap();
    let label = &r.info.always_rules[0].label;
    assert!(!label.contains(secret), "{label}");
    // The matcher keeps the exact command (it never leaves the worker).
    assert!(
        matches!(&r.matcher, Some(RuleMatch::Command { command, .. }) if command.contains(secret))
    );
    // An allow_always naming another id is not deliverable.
    assert!(decision_output(&r, ApprovalDecision::AllowAlways, Some("s-other"), None).is_none());
    // Claude keeps its own suggestions only.
    let claude = request(Agent::Claude, &v).unwrap();
    assert!(claude.matcher.is_none() && claude.session_rule.is_none());
    assert!(claude.info.always_rules.is_empty());
}
