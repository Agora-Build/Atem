//! Claude Code hooks: settings file, hook command, and the event-file reader.

use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::chat::adapter::AgentEvent;

pub const HOOK_EVENTS: [&str; 6] = [
    "SessionStart",
    "UserPromptSubmit",
    "PreToolUse",
    "PostToolUse",
    "Notification",
    "Stop",
];

/// `$XDG_RUNTIME_DIR/atem` when set and non-empty, else `~/.config/atem/run`.
pub fn session_dir_root() -> PathBuf {
    match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(v) if !v.is_empty() => PathBuf::from(v).join("atem"),
        _ => crate::config::AtemConfig::config_dir().join("run"),
    }
}

fn private_dir(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// `root/chat-<uuid>` (0700) with an `events/` subdirectory (0700).
pub fn create_session_dir(root: &Path) -> anyhow::Result<PathBuf> {
    private_dir(root)?;
    let dir = root.join(format!("chat-{}", uuid::Uuid::new_v4()));
    private_dir(&dir)?;
    private_dir(&dir.join("events"))?;
    Ok(dir)
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// The hook command: one event file per event, silent, always exit 0.
pub fn hook_command(dir: &Path) -> String {
    let template = format!("{}/events/ev.XXXXXXXX", dir.display());
    format!(
        "{{ f=$(mktemp {}) && cat > \"$f\" && mv \"$f\" \"$f.json\"; }} 2>/dev/null; exit 0",
        shell_quote(&template)
    )
}

/// Write `dir/settings.json` (0600) registering the hook for every event.
pub fn write_settings(dir: &Path) -> anyhow::Result<PathBuf> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let cmd = hook_command(dir);
    let mut hooks = serde_json::Map::new();
    for ev in HOOK_EVENTS {
        let mut entry = serde_json::Map::new();
        if ev == "PreToolUse" || ev == "PostToolUse" {
            entry.insert("matcher".into(), "".into());
        }
        entry.insert(
            "hooks".into(),
            serde_json::json!([{ "type": "command", "command": cmd }]),
        );
        hooks.insert(ev.into(), Value::Array(vec![Value::Object(entry)]));
    }
    let body = serde_json::to_string_pretty(&serde_json::json!({ "hooks": hooks }))?;
    let path = dir.join("settings.json");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)?;
    f.write_all(body.as_bytes())?;
    Ok(path)
}

pub struct EventReader {
    dir: PathBuf,
}

impl EventReader {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    /// Read events/*.json ordered by (mtime ns, name), delete each, map to AgentEvent.
    /// Skips names without .json; removes non-.json leftovers older than 60 s.
    pub fn poll(&mut self) -> Vec<AgentEvent> {
        let Ok(rd) = std::fs::read_dir(self.dir.join("events")) else {
            return Vec::new();
        };
        let now = std::time::SystemTime::now();
        let mut files = Vec::new();
        for e in rd.flatten() {
            let path = e.path();
            let Ok(meta) = e.metadata() else { continue };
            if !meta.is_file() {
                continue;
            }
            let mtime = meta.modified().unwrap_or(std::time::UNIX_EPOCH);
            if path.extension().is_some_and(|x| x == "json") {
                files.push((mtime, e.file_name(), path));
            } else if now
                .duration_since(mtime)
                .is_ok_and(|age| age > std::time::Duration::from_secs(60))
            {
                let _ = std::fs::remove_file(&path);
            }
        }
        files.sort();
        let mut out = Vec::new();
        for (_, _, path) in files {
            let text = std::fs::read_to_string(&path);
            let _ = std::fs::remove_file(&path);
            let Ok(text) = text else { continue };
            let Ok(v) = serde_json::from_str::<Value>(&text) else {
                continue;
            };
            out.extend(map_hook(&v));
        }
        out
    }
}

pub fn map_hook(json: &Value) -> Option<AgentEvent> {
    let s = |k: &str| json.get(k).and_then(Value::as_str);
    match s("hook_event_name")? {
        "SessionStart" => Some(AgentEvent::SessionStarted {
            session_id: s("session_id")?.to_string(),
            log_path: PathBuf::from(s("transcript_path")?),
        }),
        "UserPromptSubmit" => Some(AgentEvent::PromptSubmitted {
            text: s("prompt")?.to_string(),
        }),
        "PreToolUse" => Some(AgentEvent::ToolStarted),
        "PostToolUse" => Some(AgentEvent::ToolFinished),
        "Notification" => {
            let message = s("message").unwrap_or_default();
            let permission = match s("notification_type") {
                Some(t) => t == "permission_prompt",
                None => message.to_lowercase().contains("permission"),
            };
            permission.then(|| AgentEvent::WaitingForPermission {
                detail: message.to_string(),
            })
        }
        "Stop" => Some(AgentEvent::TurnEnded),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, SystemTime};

    fn mode(p: &Path) -> u32 {
        fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    fn fixture(name: &str) -> Value {
        let p = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/chat/claude/events")
            .join(name);
        serde_json::from_str(&fs::read_to_string(p).unwrap()).unwrap()
    }

    #[test]
    fn hook_command_matches_the_spec_and_quotes_the_dir() {
        let cmd = hook_command(Path::new("/tmp/a b/it's"));
        assert_eq!(
            cmd,
            "{ f=$(mktemp '/tmp/a b/it'\\''s/events/ev.XXXXXXXX') && cat > \"$f\" && mv \"$f\" \"$f.json\"; } 2>/dev/null; exit 0"
        );
    }

    #[test]
    fn settings_register_every_event_with_the_command() {
        let root = tempfile::tempdir().unwrap();
        let dir = create_session_dir(root.path()).unwrap();
        let path = write_settings(&dir).unwrap();
        assert_eq!(path, dir.join("settings.json"));
        let v: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let cmd = hook_command(&dir);
        for ev in HOOK_EVENTS {
            let entry = &v["hooks"][ev][0];
            assert_eq!(entry["hooks"][0]["type"], "command", "{ev}");
            assert_eq!(entry["hooks"][0]["command"], cmd.as_str(), "{ev}");
            if ev == "PreToolUse" || ev == "PostToolUse" {
                assert_eq!(entry["matcher"], "", "{ev}");
            } else {
                assert!(entry.get("matcher").is_none(), "{ev}");
            }
        }
        assert_eq!(v["hooks"].as_object().unwrap().len(), 6);
    }

    #[test]
    fn session_dir_and_files_are_private() {
        let root = tempfile::tempdir().unwrap();
        let dir = create_session_dir(root.path()).unwrap();
        assert!(dir.starts_with(root.path()));
        assert!(
            dir.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("chat-")
        );
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&dir.join("events")), 0o700);
        let s = write_settings(&dir).unwrap();
        assert_eq!(mode(&s), 0o600);
    }

    fn run_hook(cmd: &str, input: &str) -> std::process::Output {
        use std::io::Write;
        let mut child = Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }

    #[test]
    fn hook_command_really_writes_one_event_file() {
        let root = tempfile::tempdir().unwrap();
        let dir = create_session_dir(root.path()).unwrap();
        let cmd = hook_command(&dir);
        let handles: Vec<_> = (0..2)
            .map(|i| {
                let cmd = cmd.clone();
                std::thread::spawn(move || run_hook(&cmd, &format!("{{\"n\":{i}}}")))
            })
            .collect();
        for h in handles {
            let out = h.join().unwrap();
            assert!(out.status.success());
            assert!(out.stdout.is_empty() && out.stderr.is_empty());
        }
        let files: Vec<_> = fs::read_dir(dir.join("events")).unwrap().collect();
        assert_eq!(files.len(), 2);
        for f in files {
            let p = f.unwrap().path();
            assert_eq!(p.extension().unwrap(), "json");
            let _: Value = serde_json::from_str(&fs::read_to_string(p).unwrap()).unwrap();
        }
        // Unwritable events dir: still exit 0 and silent.
        fs::set_permissions(dir.join("events"), fs::Permissions::from_mode(0o500)).unwrap();
        let out = run_hook(&cmd, "{}");
        fs::set_permissions(dir.join("events"), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(out.status.success());
        assert!(out.stdout.is_empty() && out.stderr.is_empty());
    }

    fn put(dir: &Path, name: &str, body: &str, age_secs: u64) {
        let p = dir.join("events").join(name);
        fs::write(&p, body).unwrap();
        let t = SystemTime::now() - Duration::from_secs(age_secs);
        fs::File::options()
            .write(true)
            .open(&p)
            .unwrap()
            .set_modified(t)
            .unwrap();
    }

    #[test]
    fn events_are_read_in_order_and_deleted() {
        let root = tempfile::tempdir().unwrap();
        let dir = create_session_dir(root.path()).unwrap();
        let stop = r#"{"hook_event_name":"Stop"}"#;
        let tool = r#"{"hook_event_name":"PreToolUse"}"#;
        let prompt = r#"{"hook_event_name":"UserPromptSubmit","prompt":"hi"}"#;
        put(&dir, "ev.a.json", stop, 1);
        put(&dir, "ev.b.json", prompt, 3);
        put(&dir, "ev.c.json", tool, 2);
        let mut r = EventReader::new(dir.clone());
        assert_eq!(
            r.poll(),
            vec![
                AgentEvent::PromptSubmitted { text: "hi".into() },
                AgentEvent::ToolStarted,
                AgentEvent::TurnEnded
            ]
        );
        assert_eq!(fs::read_dir(dir.join("events")).unwrap().count(), 0);
        assert!(r.poll().is_empty());
    }

    #[test]
    fn same_mtime_orders_by_name_and_bad_json_is_dropped() {
        let root = tempfile::tempdir().unwrap();
        let dir = create_session_dir(root.path()).unwrap();
        let t = SystemTime::now() - Duration::from_secs(5);
        for (n, body) in [
            ("ev.2.json", r#"{"hook_event_name":"Stop"}"#),
            ("ev.1.json", r#"{"hook_event_name":"PreToolUse"}"#),
            ("ev.0.json", "not json"),
        ] {
            let p = dir.join("events").join(n);
            fs::write(&p, body).unwrap();
            fs::File::options()
                .write(true)
                .open(&p)
                .unwrap()
                .set_modified(t)
                .unwrap();
        }
        let mut r = EventReader::new(dir.clone());
        assert_eq!(
            r.poll(),
            vec![AgentEvent::ToolStarted, AgentEvent::TurnEnded]
        );
        assert_eq!(fs::read_dir(dir.join("events")).unwrap().count(), 0);
    }

    #[test]
    fn tmp_files_are_skipped_then_cleaned() {
        let root = tempfile::tempdir().unwrap();
        let dir = create_session_dir(root.path()).unwrap();
        put(&dir, "ev.young", "{", 1);
        put(&dir, "ev.old", "{", 120);
        let mut r = EventReader::new(dir.clone());
        assert!(r.poll().is_empty());
        assert!(dir.join("events/ev.young").exists());
        assert!(!dir.join("events/ev.old").exists());
    }

    #[test]
    fn map_hook_fixtures() {
        assert_eq!(
            map_hook(&fixture("01-session-start.json")),
            Some(AgentEvent::SessionStarted {
                session_id: "c142b440-2f9a-4f2e-bf30-d99335ab2e7e".into(),
                log_path: PathBuf::from(
                    "/home/user/.claude/projects/-home-user-proj/c142b440-2f9a-4f2e-bf30-d99335ab2e7e.jsonl"
                ),
            })
        );
        assert!(matches!(
            map_hook(&fixture("02-user-prompt-submit.json")),
            Some(AgentEvent::PromptSubmitted { text }) if !text.is_empty()
        ));
        assert_eq!(
            map_hook(&fixture("03-pre-tool-use.json")),
            Some(AgentEvent::ToolStarted)
        );
        assert_eq!(
            map_hook(&fixture("04-post-tool-use.json")),
            Some(AgentEvent::ToolFinished)
        );
        assert_eq!(
            map_hook(&fixture("05-stop.json")),
            Some(AgentEvent::TurnEnded)
        );
        assert_eq!(
            map_hook(&fixture("08-notification.json")),
            Some(AgentEvent::WaitingForPermission {
                detail: "Claude needs your permission".into()
            })
        );
        let clear = map_hook(&fixture("12-session-start.json"));
        assert!(matches!(clear, Some(AgentEvent::SessionStarted { .. })));
    }

    #[test]
    fn map_hook_edge_cases() {
        let j = |s: &str| serde_json::from_str::<Value>(s).unwrap();
        assert_eq!(map_hook(&j(r#"{"hook_event_name":"Nope"}"#)), None);
        assert_eq!(map_hook(&j(r#"{}"#)), None);
        assert_eq!(map_hook(&j(r#"{"hook_event_name":"SessionStart"}"#)), None);
        assert_eq!(
            map_hook(&j(r#"{"hook_event_name":"UserPromptSubmit"}"#)),
            None
        );
        // idle reminder
        assert_eq!(
            map_hook(&j(
                r#"{"hook_event_name":"Notification","notification_type":"idle_prompt","message":"Claude is waiting for your permission"}"#
            )),
            None
        );
        // no notification_type: fall back to the message
        assert_eq!(
            map_hook(&j(
                r#"{"hook_event_name":"Notification","message":"Claude needs your permission"}"#
            )),
            Some(AgentEvent::WaitingForPermission {
                detail: "Claude needs your permission".into()
            })
        );
        assert_eq!(
            map_hook(&j(
                r#"{"hook_event_name":"Notification","message":"Claude is waiting for your input"}"#
            )),
            None
        );
    }
}
