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
    #[cfg(test)]
    return crate::test_profile::dir().join("run");
    #[cfg(not(test))]
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

/// A chat directory without a `pid` file is stale after this long.
const STALE_AFTER: std::time::Duration = std::time::Duration::from_secs(3600);

/// `root/chat-<uuid>` (0700) with `events/` and `approvals/` subdirectories
/// (0700) and a `pid` file (0600) naming this process and host, for
/// `sweep_stale`.
pub fn create_session_dir(root: &Path) -> anyhow::Result<PathBuf> {
    private_dir(root)?;
    let dir = root.join(format!("chat-{}", uuid::Uuid::new_v4()));
    private_dir(&dir)?;
    private_dir(&dir.join("events"))?;
    private_dir(&crate::chat::approvals::approvals_dir(&dir))?;
    let owner = format!("{}\n{}\n", std::process::id(), crate::auth::get_hostname());
    write_private(&dir.join("pid"), owner.as_bytes())?;
    Ok(dir)
}

/// Create or replace `path` (0600) with `body`.
fn write_private(path: &Path, body: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(body)?;
    Ok(())
}

/// Remove chat directories left by Atem processes that are gone (crash,
/// SIGKILL): `root/chat-*` whose `pid` file names a dead process on this host,
/// or that have no readable `pid` file and are older than an hour. A directory
/// owned by another host (a shared home) is never removed. Nothing else under
/// `root` is touched and no symlink is followed.
pub fn sweep_stale(root: &Path) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    let now = std::time::SystemTime::now();
    for entry in entries.flatten() {
        if !entry.file_name().to_string_lossy().starts_with("chat-") {
            continue;
        }
        let path = entry.path();
        // symlink_metadata: a symlink is not a directory here, so it is skipped.
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if !meta.is_dir() {
            continue;
        }
        let stale = match read_pid(&path.join("pid")) {
            Some((_, Some(host))) if host != crate::auth::get_hostname() => false,
            Some((pid, _)) => !process_alive(pid),
            None => meta
                .modified()
                .ok()
                .and_then(|t| now.duration_since(t).ok())
                .is_some_and(|age| age > STALE_AFTER),
        };
        if stale {
            // remove_dir_all does not follow symlinks inside the directory.
            let _ = std::fs::remove_dir_all(&path);
        }
    }
}

/// The pid and host in a regular `pid` file (never through a symlink).
fn read_pid(path: &Path) -> Option<(libc::pid_t, Option<String>)> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut text = String::new();
    file.by_ref().take(512).read_to_string(&mut text).ok()?;
    let mut lines = text.lines();
    let pid: libc::pid_t = lines.next()?.trim().parse().ok()?;
    let host = lines
        .next()
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty());
    (pid > 0).then_some((pid, host))
}

/// False only when the process is known to be gone (ESRCH).
fn process_alive(pid: libc::pid_t) -> bool {
    // SAFETY: signal 0 only checks that the process exists; nothing is sent.
    let rc = unsafe { libc::kill(pid, 0) };
    rc == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
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

/// Write `dir/settings.json` (0600) registering the hook for every event,
/// and with `approvals` the approval hook (`chat::approvals`, installed in
/// `dir`): the `PermissionRequest` hook (600 s) and, on `PostToolUse`, its
/// note that a tool ran (a prompt answered in the terminal). Without
/// (`[claude] approvals_hook = false`) Claude's prompts stay in its terminal.
pub fn write_settings(dir: &Path, approvals: bool) -> anyhow::Result<PathBuf> {
    use crate::chat::approvals;
    if approvals {
        approvals::install_script(&dir.join(approvals::SCRIPT_NAME))?;
    }
    let cmd = hook_command(dir);
    let mut hooks = serde_json::Map::new();
    for ev in HOOK_EVENTS {
        let mut entry = serde_json::Map::new();
        if ev == "PreToolUse" || ev == "PostToolUse" {
            entry.insert("matcher".into(), "".into());
        }
        let mut commands = vec![serde_json::json!({ "type": "command", "command": cmd })];
        if approvals && ev == "PostToolUse" {
            commands.push(serde_json::json!({
                "type": "command",
                "command": approvals::claude_post_command(dir),
            }));
        }
        entry.insert("hooks".into(), Value::Array(commands));
        hooks.insert(ev.into(), Value::Array(vec![Value::Object(entry)]));
    }
    if approvals {
        hooks.insert(
            "PermissionRequest".into(),
            serde_json::json!([{
                "matcher": "",
                "hooks": [{
                    "type": "command",
                    "command": approvals::claude_command(dir),
                    "timeout": approvals::CLAUDE_TIMEOUT,
                }]
            }]),
        );
    }
    let body = serde_json::to_string_pretty(&serde_json::json!({ "hooks": hooks }))?;
    let path = dir.join("settings.json");
    write_private(&path, body.as_bytes())?;
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
        for (mtime, _, path) in files {
            match std::fs::read_to_string(&path) {
                Ok(text) => {
                    let _ = std::fs::remove_file(&path);
                    if let Ok(v) = serde_json::from_str::<Value>(&text) {
                        let at = mtime
                            .duration_since(std::time::UNIX_EPOCH)
                            .map_or(0, |d| d.as_millis() as i64);
                        out.extend(map_hook(&v).map(|e| match e {
                            AgentEvent::PromptSubmitted { text, turn_id, .. } => {
                                AgentEvent::PromptSubmitted {
                                    text,
                                    turn_id,
                                    at_ms: Some(at),
                                }
                            }
                            e => e,
                        }));
                    }
                }
                Err(_) => {
                    // Unreadable: keep it for now, drop it once it is stale.
                    if now
                        .duration_since(mtime)
                        .is_ok_and(|age| age > std::time::Duration::from_secs(60))
                    {
                        let _ = std::fs::remove_file(&path);
                    }
                }
            }
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
            source: s("source").unwrap_or_default().to_string(),
            // The adapter decides; it knows which log it is reading.
            same_log: false,
        }),
        "UserPromptSubmit" => Some(AgentEvent::PromptSubmitted {
            text: s("prompt")?.to_string(),
            turn_id: None,
            at_ms: None,
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
        let path = write_settings(&dir, true).unwrap();
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
        assert_eq!(v["hooks"].as_object().unwrap().len(), 7);
        let post = &v["hooks"]["PostToolUse"][0]["hooks"][1];
        assert_eq!(
            post["command"],
            crate::chat::approvals::claude_post_command(&dir).as_str()
        );
        let perm = &v["hooks"]["PermissionRequest"][0];
        assert_eq!(perm["matcher"], "");
        assert_eq!(perm["hooks"][0]["timeout"], 600);
        assert_eq!(
            perm["hooks"][0]["command"],
            crate::chat::approvals::claude_command(&dir).as_str()
        );
        assert_eq!(
            fs::read_to_string(dir.join("approval-hook.sh")).unwrap(),
            crate::chat::approvals::SCRIPT
        );
        assert_eq!(mode(&dir.join("approvals")), 0o700);
    }

    fn dead_pid() -> u32 {
        let mut child = Command::new("true").spawn().unwrap();
        let pid = child.id();
        child.wait().unwrap();
        pid
    }

    fn age_dir(path: &Path, secs: u64) {
        let t = SystemTime::now() - Duration::from_secs(secs);
        fs::File::open(path).unwrap().set_modified(t).unwrap();
    }

    #[test]
    fn session_dir_records_this_process() {
        let root = tempfile::tempdir().unwrap();
        let dir = create_session_dir(root.path()).unwrap();
        let pid = dir.join("pid");
        assert_eq!(
            fs::read_to_string(&pid).unwrap(),
            format!("{}\n{}\n", std::process::id(), crate::auth::get_hostname())
        );
        assert_eq!(mode(&pid), 0o600);
    }

    #[test]
    fn sweep_keeps_dirs_owned_by_another_host() {
        let root = tempfile::tempdir().unwrap();
        let other = create_session_dir(root.path()).unwrap();
        let dead = dead_pid();
        fs::write(other.join("pid"), format!("{dead}\nsome-other-host\n")).unwrap();
        let here = create_session_dir(root.path()).unwrap();
        let host = crate::auth::get_hostname();
        fs::write(here.join("pid"), format!("{dead}\n{host}\n")).unwrap();
        sweep_stale(root.path());
        assert!(other.exists(), "another host's live atem may own it");
        assert!(!here.exists());
    }

    #[test]
    fn sweep_removes_only_stale_chat_dirs() {
        let root = tempfile::tempdir().unwrap();
        let r = root.path();
        let mine = create_session_dir(r).unwrap();
        let dead = create_session_dir(r).unwrap();
        fs::write(dead.join("pid"), dead_pid().to_string()).unwrap();
        // no pid file: removed only once older than an hour
        let old = r.join("chat-old");
        let young = r.join("chat-young");
        for d in [&old, &young] {
            fs::create_dir_all(d.join("events")).unwrap();
        }
        age_dir(&old, 2 * 3600);
        // not ours to touch
        let other = r.join("transcripts");
        fs::create_dir_all(&other).unwrap();
        fs::write(other.join("pid"), dead_pid().to_string()).unwrap();
        age_dir(&other, 2 * 3600);
        let file = r.join("chat-file");
        fs::write(&file, dead_pid().to_string()).unwrap();
        // a symlink named chat-* to a stale-looking dir is never followed
        let target = tempfile::tempdir().unwrap();
        fs::write(target.path().join("pid"), dead_pid().to_string()).unwrap();
        let link = r.join("chat-link");
        std::os::unix::fs::symlink(target.path(), &link).unwrap();
        // a pid file that is a symlink is not read either
        let linked_pid = r.join("chat-linkedpid");
        fs::create_dir_all(&linked_pid).unwrap();
        let pid_target = target.path().join("pidfile");
        fs::write(&pid_target, dead_pid().to_string()).unwrap();
        std::os::unix::fs::symlink(&pid_target, linked_pid.join("pid")).unwrap();

        sweep_stale(r);
        assert!(mine.exists());
        assert!(!dead.exists());
        assert!(!old.exists());
        assert!(young.exists());
        assert!(other.exists());
        assert!(file.exists());
        assert!(fs::symlink_metadata(&link).is_ok());
        assert!(target.path().join("pid").exists());
        assert!(linked_pid.exists());
        assert!(pid_target.exists());
        // a missing root is fine
        sweep_stale(&r.join("missing"));
    }

    #[test]
    fn settings_without_approvals_keep_only_the_chat_hooks() {
        let root = tempfile::tempdir().unwrap();
        let dir = create_session_dir(root.path()).unwrap();
        let path = write_settings(&dir, false).unwrap();
        let v: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let cmd = hook_command(&dir);
        assert_eq!(v["hooks"].as_object().unwrap().len(), 6);
        assert!(v["hooks"].get("PermissionRequest").is_none());
        for ev in HOOK_EVENTS {
            let hooks = v["hooks"][ev][0]["hooks"].as_array().unwrap();
            assert_eq!(hooks.len(), 1, "{ev}");
            assert_eq!(hooks[0]["command"], cmd.as_str(), "{ev}");
        }
        assert!(!dir.join("approval-hook.sh").exists());
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
        let s = write_settings(&dir, true).unwrap();
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
        let now_ms = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        let events = r.poll();
        // The prompt carries its file's time (written 3 s ago).
        let Some(AgentEvent::PromptSubmitted {
            at_ms: Some(at), ..
        }) = events.first()
        else {
            panic!("{events:?}")
        };
        assert!(
            (now_ms - 4000..=now_ms - 2000).contains(at),
            "{at} {now_ms}"
        );
        assert_eq!(
            events,
            vec![
                AgentEvent::PromptSubmitted {
                    text: "hi".into(),
                    turn_id: None,
                    at_ms: Some(*at),
                },
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
    fn unreadable_event_files_stay_until_stale() {
        let root = tempfile::tempdir().unwrap();
        let dir = create_session_dir(root.path()).unwrap();
        put(&dir, "ev.young.json", "{}", 1);
        put(&dir, "ev.old.json", "{}", 120);
        for n in ["ev.young.json", "ev.old.json"] {
            fs::set_permissions(
                dir.join("events").join(n),
                fs::Permissions::from_mode(0o000),
            )
            .unwrap();
        }
        if fs::read_to_string(dir.join("events/ev.young.json")).is_ok() {
            return; // running as root: cannot make a file unreadable
        }
        let mut r = EventReader::new(dir.clone());
        assert!(r.poll().is_empty());
        assert!(dir.join("events/ev.young.json").exists());
        assert!(!dir.join("events/ev.old.json").exists());
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
                source: "startup".into(),
                same_log: false,
            })
        );
        assert!(matches!(
            map_hook(&fixture("02-user-prompt-submit.json")),
            Some(AgentEvent::PromptSubmitted { text, turn_id: None, at_ms: None }) if !text.is_empty()
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
