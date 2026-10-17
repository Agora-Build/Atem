use super::*;
use std::fs;

const SCRIPT: &str = "/home/u/.config/atem/hooks/approval-hook.sh";

fn entry() -> Value {
    hook_entry(Path::new(SCRIPT))
}

fn entries() -> Vec<(&'static str, Value)> {
    hook_entries(Path::new(SCRIPT))
}

fn changed(m: Merge) -> String {
    match m {
        Merge::Changed(t) => t,
        Merge::Unchanged => panic!("expected a change"),
    }
}

fn groups(text: &str) -> Vec<Value> {
    groups_of(text, "PermissionRequest")
}

fn groups_of(text: &str, event: &str) -> Vec<Value> {
    let v: Value = serde_json::from_str(text).unwrap();
    v["hooks"][event].as_array().unwrap().clone()
}

/// Every event's list ends with exactly our entry, and ours appears once.
fn assert_complete(text: &str, script: &Path) {
    for (event, want) in hook_entries(script) {
        let g = groups_of(text, event);
        assert_eq!(g.last(), Some(&want), "{event}");
        let marked = g
            .iter()
            .filter(|g| {
                g["hooks"][0]["command"]
                    .as_str()
                    .unwrap_or("")
                    .starts_with(MARKER)
            })
            .count();
        assert_eq!(marked, 1, "{event}");
    }
}

fn fixture_hooks() -> String {
    fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("designs/fixtures/codex-hooks/hooks.json"),
    )
    .unwrap()
}

#[test]
fn the_permission_request_entry_is_unchanged_from_before_chat() {
    let e = entry();
    let cmd = e["hooks"][0]["command"].as_str().unwrap();
    // Byte for byte what Atem installed before (Codex's trust is a hash of it).
    assert_eq!(
        cmd,
        ": atem-approval-hook; [ -n \"${ATEM_APPROVAL_DIR:-}\" ] && [ -f '/home/u/.config/atem/hooks/approval-hook.sh' ] || exit 0; exec /bin/sh '/home/u/.config/atem/hooks/approval-hook.sh' codex 300"
    );
    assert_eq!(
        e,
        serde_json::json!({"matcher": "*", "hooks": [{"type": "command", "command": cmd, "timeout": 300}]})
    );
    assert_eq!(entry(), e, "the same for every session");
}

#[test]
fn one_marked_entry_per_event_async_but_permission_request_and_session_end() {
    let all = entries();
    assert_eq!(
        all.iter().map(|(e, _)| *e).collect::<Vec<_>>(),
        EVENTS.to_vec()
    );
    for (event, group) in &all {
        let hooks = group["hooks"].as_array().unwrap();
        assert_eq!(hooks.len(), 1, "{event}");
        let cmd = hooks[0]["command"].as_str().unwrap();
        assert!(cmd.starts_with(MARKER), "{event}");
        assert!(cmd.contains("\"${ATEM_APPROVAL_DIR:-}\""), "{event}");
        match *event {
            "PermissionRequest" => {
                assert!(cmd.ends_with(" codex 300"));
                assert!(hooks[0].get("async").is_none());
            }
            "SessionEnd" => {
                assert!(cmd.ends_with(" event SessionEnd"));
                assert!(hooks[0].get("async").is_none(), "SessionEnd is always sync");
                assert_eq!(hooks[0]["timeout"], EVENT_TIMEOUT);
            }
            other => {
                assert!(cmd.ends_with(&format!(" event {other}")), "{cmd}");
                assert_eq!(hooks[0]["async"], true, "{other}");
                assert_eq!(hooks[0]["timeout"], EVENT_TIMEOUT);
                assert!(group.get("matcher").is_none());
            }
        }
    }
    assert_eq!(entries(), all, "the same for every session");
}

#[test]
fn merge_into_nothing_creates_the_file() {
    for existing in [None, Some(""), Some("  \n")] {
        let text = changed(merge(existing, &entries()).unwrap());
        for (event, want) in entries() {
            assert_eq!(groups_of(&text, event), vec![want], "{event}");
        }
        assert_eq!(merge(Some(&text), &entries()).unwrap(), Merge::Unchanged);
    }
}

#[test]
fn merge_keeps_every_other_byte() {
    let existing = r#"{
  "zeta": {"keep": [1, 2.50, "x,{y"]},
  "hooks": {
    "PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "/a/check.sh"}]}],
    "PermissionRequest": [
      {"matcher": "Bash", "hooks": [{"type": "command", "command": "/a/deny-rm.sh"}]}
    ]
  },
  "a,b": true
}
"#;
    let only = [("PermissionRequest", entry())];
    let text = changed(merge(Some(existing), &only).unwrap());
    let g = groups(&text);
    assert_eq!(g.len(), 2);
    assert_eq!(g[0]["hooks"][0]["command"], "/a/deny-rm.sh", "theirs first");
    assert_eq!(g[1], entry());
    // Only our entry was inserted: removing it gives the original back.
    let inserted = format!(",\n      {}", serde_json::to_string(&entry()).unwrap());
    assert_eq!(text.replacen(&inserted, "", 1), existing);
    assert_eq!(merge(Some(&text), &only).unwrap(), Merge::Unchanged);

    // The full set: the user's groups keep their positions, ours come last.
    let text = changed(merge(Some(existing), &entries()).unwrap());
    assert_complete(&text, Path::new(SCRIPT));
    assert_eq!(
        groups_of(&text, "PreToolUse")[0]["hooks"][0]["command"],
        "/a/check.sh"
    );
    assert_eq!(groups(&text)[0]["hooks"][0]["command"], "/a/deny-rm.sh");
    let v: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["zeta"], serde_json::json!({"keep": [1, 2.50, "x,{y"]}));
    assert_eq!(v["a,b"], true);
    assert!(text.starts_with("{\n  \"zeta\": {\"keep\": [1, 2.50, \"x,{y\"]},\n  \"hooks\": {\n    \"PreToolUse\": [{\"matcher\": \"Bash\""));
    assert!(text.ends_with("  \"a,b\": true\n}\n"));
    assert_eq!(merge(Some(&text), &entries()).unwrap(), Merge::Unchanged);
}

#[test]
fn merge_appends_after_the_fixture_users_hooks() {
    // The spike's hooks.json: the user's own entries under all 12 events
    // (another marker, so not Atem's), two under Stop.
    let existing = fixture_hooks();
    let before: Value = serde_json::from_str(&existing).unwrap();
    let text = changed(merge(Some(&existing), &entries()).unwrap());
    assert_complete(&text, Path::new(SCRIPT));
    let after: Value = serde_json::from_str(&text).unwrap();
    for (event, theirs) in before["hooks"].as_object().unwrap() {
        let theirs = theirs.as_array().unwrap();
        let now = after["hooks"][event].as_array().unwrap();
        let ours = usize::from(EVENTS.contains(&event.as_str()));
        assert_eq!(now.len(), theirs.len() + ours, "{event}");
        assert_eq!(
            &now[..theirs.len()],
            &theirs[..],
            "{event}: theirs keep their positions"
        );
    }
    assert_eq!(merge(Some(&text), &entries()).unwrap(), Merge::Unchanged);
}

#[test]
fn a_partial_set_is_completed_by_appending_only_whats_missing() {
    // What Atem installed before chat: PermissionRequest only, after the
    // user's own Stop hook and PermissionRequest hook.
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("codex");
    fs::create_dir_all(&home).unwrap();
    fs::write(home.join("hooks.json"), MINE).unwrap();
    let only = [("PermissionRequest", entry())];
    let old = changed(merge(Some(MINE), &only).unwrap());
    fs::write(home.join("hooks.json"), &old).unwrap();
    let text = changed(merge(Some(&old), &entries()).unwrap());
    assert_complete(&text, Path::new(SCRIPT));
    // The PermissionRequest entry kept its position and bytes.
    assert_eq!(groups(&text), groups(&old));
    assert_eq!(
        text.matches(&serde_json::to_string(&entry()).unwrap())
            .count(),
        1,
        "the PermissionRequest entry's bytes are kept, never duplicated"
    );
    assert_eq!(
        groups_of(&text, "Stop")[0]["hooks"][0]["command"],
        "/stop.sh"
    );
    assert_eq!(groups_of(&text, "Stop").len(), 2);

    // A set missing two events gets exactly those two, appended.
    let mut some = entries();
    some.retain(|(e, _)| *e != "Interrupt" && *e != "PreCompact");
    let partial = changed(merge(Some(MINE), &some).unwrap());
    let full = changed(merge(Some(&partial), &entries()).unwrap());
    assert_complete(&full, Path::new(SCRIPT));
    let a: Value = serde_json::from_str(&partial).unwrap();
    let mut b: Value = serde_json::from_str(&full).unwrap();
    let hooks = b["hooks"].as_object_mut().unwrap();
    hooks.remove("Interrupt");
    hooks.remove("PreCompact");
    assert_eq!(a, b, "the rest unchanged");
    assert!(full.starts_with(&partial[..partial.rfind(']').unwrap()]));
}

#[test]
fn merge_adds_missing_levels() {
    let text = changed(merge(Some(r#"{"other": 1}"#), &entries()).unwrap());
    assert_complete(&text, Path::new(SCRIPT));
    assert_eq!(serde_json::from_str::<Value>(&text).unwrap()["other"], 1);
    let text = changed(merge(Some("{}"), &entries()).unwrap());
    assert_complete(&text, Path::new(SCRIPT));
    let text = changed(
        merge(
            Some(r#"{"hooks": {"Stop": [{"hooks": [{"type":"command","command":"x"}]}]}}"#),
            &entries(),
        )
        .unwrap(),
    );
    assert_complete(&text, Path::new(SCRIPT));
    let v: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["hooks"]["Stop"][0]["hooks"][0]["command"], "x");
    let text = changed(merge(Some(r#"{"hooks": {"PermissionRequest": []}}"#), &entries()).unwrap());
    assert_complete(&text, Path::new(SCRIPT));
}

#[test]
fn an_older_atem_entry_is_replaced_in_place() {
    let old = serde_json::json!({"matcher": "*", "hooks": [{"type": "command", "command": format!("{MARKER} old")}]});
    let old_stop = serde_json::json!({"hooks": [{"type": "command", "command": format!("{MARKER} old stop")}]});
    let theirs = serde_json::json!({"matcher": "Bash", "hooks": [{"type": "command", "command": "/a/x.sh"}]});
    let existing = serde_json::to_string_pretty(&serde_json::json!({
        "hooks": {"PermissionRequest": [old, theirs], "Stop": [old_stop, theirs]}
    }))
    .unwrap();
    let text = changed(merge(Some(&existing), &entries()).unwrap());
    assert_eq!(groups(&text), vec![entry(), theirs.clone()]);
    let stop = entry_for(Path::new(SCRIPT), "Stop");
    assert_eq!(groups_of(&text, "Stop"), vec![stop, theirs]);
}

#[test]
fn extra_atem_groups_of_an_event_are_dropped() {
    let marked = |c: &str| serde_json::json!({"hooks": [{"type": "command", "command": format!("{MARKER} {c}")}]});
    let theirs = serde_json::json!({"hooks": [{"type": "command", "command": "/a/x.sh"}]});
    let stop = entry_for(Path::new(SCRIPT), "Stop");
    // None equal: the first is replaced, the others go.
    let existing = serde_json::to_string_pretty(&serde_json::json!({
        "hooks": {"Stop": [marked("old1"), theirs, marked("old2"), marked("old3")]}
    }))
    .unwrap();
    let text = changed(merge(Some(&existing), &entries()).unwrap());
    assert_eq!(groups_of(&text, "Stop"), vec![stop.clone(), theirs.clone()]);
    // One equal: it stays where it is, the stale ones go.
    let existing = serde_json::to_string_pretty(&serde_json::json!({
        "hooks": {"Stop": [marked("old1"), theirs, stop]}
    }))
    .unwrap();
    let text = changed(
        merge(
            Some(&existing),
            &[("Stop", entry_for(Path::new(SCRIPT), "Stop"))],
        )
        .unwrap(),
    );
    assert_eq!(
        groups_of(&text, "Stop"),
        vec![theirs, entry_for(Path::new(SCRIPT), "Stop")]
    );
    assert_eq!(
        merge(
            Some(&text),
            &[("Stop", entry_for(Path::new(SCRIPT), "Stop"))]
        )
        .unwrap(),
        Merge::Unchanged
    );
}

#[test]
fn malformed_files_are_refused() {
    let marked = format!("{MARKER} x");
    for bad in [
        "{".to_string(),
        "[]".to_string(),
        "{\"hooks\": []}".to_string(),
        "{\"hooks\": {\"PermissionRequest\": {}}}".to_string(),
        "{\"hooks\": {\"Stop\": 1}}".to_string(),
        "// comment\n{}".to_string(),
        // Our marker outside a hook's command.
        serde_json::json!({"note": marked}).to_string(),
        // Our entry sharing its group with the user's hook.
        serde_json::json!({"hooks": {"Stop": [{"hooks": [
            {"type": "command", "command": marked},
            {"type": "command", "command": "/mine.sh"}
        ]}]}})
        .to_string(),
    ] {
        assert!(merge(Some(&bad), &entries()).is_err(), "{bad}");
    }
}

fn paths(root: &Path) -> Paths {
    Paths {
        codex_home: root.join("codex"),
        config: root.join("atem/config.toml"),
        script: root.join("atem/hooks/approval-hook.sh"),
    }
}

#[test]
fn install_backs_up_once_and_is_idempotent() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("codex");
    fs::create_dir_all(&home).unwrap();
    let original = r#"{"hooks": {"PermissionRequest": [{"matcher": "", "hooks": [{"type": "command", "command": "/mine.sh"}]}]}}"#;
    fs::write(home.join("hooks.json"), original).unwrap();
    let script = Path::new(SCRIPT);
    let bak = home.join(BACKUP);
    assert_eq!(
        install(&home, script).unwrap(),
        Installed::Changed {
            backup: Some(bak.clone())
        }
    );
    assert_eq!(fs::read_to_string(&bak).unwrap(), original);
    let after = fs::read_to_string(home.join("hooks.json")).unwrap();
    assert_eq!(groups(&after).len(), 2);
    assert_complete(&after, script);
    assert_eq!(install(&home, script).unwrap(), Installed::Unchanged);
    assert_eq!(fs::read_to_string(home.join("hooks.json")).unwrap(), after);
    // A later change (another script path) keeps the first backup.
    install(&home, Path::new("/other/approval-hook.sh")).unwrap();
    assert_eq!(fs::read_to_string(&bak).unwrap(), original);
    assert_eq!(
        groups(&fs::read_to_string(home.join("hooks.json")).unwrap()).len(),
        2
    );
}

#[test]
fn install_creates_a_missing_file_and_records_there_was_none() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("codex");
    assert_eq!(
        install(&home, Path::new(SCRIPT)).unwrap(),
        Installed::Changed { backup: None }
    );
    // An empty backup: "no file before Atem".
    assert_eq!(fs::read_to_string(home.join(BACKUP)).unwrap(), "");
    assert_eq!(mode(&home.join(BACKUP)), 0o600);
    let text = fs::read_to_string(home.join("hooks.json")).unwrap();
    assert_eq!(groups(&text), vec![entry()]);
    assert_complete(&text, Path::new(SCRIPT));
}

#[test]
fn a_malformed_file_is_never_overwritten() {
    let root = tempfile::tempdir().unwrap();
    let p = paths(root.path());
    fs::create_dir_all(&p.codex_home).unwrap();
    fs::write(p.codex_home.join("hooks.json"), "{ not json").unwrap();
    write_consent(&p.config, true).unwrap();
    let mut out = Vec::new();
    assert_eq!(setup(&p, |_| None, &mut out).unwrap(), Setup::Refused);
    let said = String::from_utf8(out).unwrap();
    assert!(
        said.contains("hooks.json") && said.contains("left as it is"),
        "{said}"
    );
    assert_eq!(
        fs::read_to_string(p.codex_home.join("hooks.json")).unwrap(),
        "{ not json"
    );
    assert!(!p.codex_home.join(BACKUP).exists());
}

#[test]
fn setup_asks_once_and_remembers() {
    let root = tempfile::tempdir().unwrap();
    let p = paths(root.path());
    fs::create_dir_all(p.config.parent().unwrap()).unwrap();
    fs::write(&p.config, "# mine\nterminal_prefix = \"Ctrl-a\"\n").unwrap();
    let mut out = Vec::new();
    let mut asked = 0;
    let r = setup(
        &p,
        |q| {
            asked += 1;
            assert!(q.contains("hooks.json") && q.contains("[y/N]"));
            assert!(q.contains("chat") && q.contains("approvals"), "{q}");
            Some(true)
        },
        &mut out,
    )
    .unwrap();
    assert_eq!(r, Setup::Ready);
    assert_eq!(asked, 1);
    let said = String::from_utf8(out).unwrap();
    assert!(said.contains("/hooks"), "{said}");
    assert_eq!(read_consent(&p.config).unwrap(), Some(true));
    let config = fs::read_to_string(&p.config).unwrap();
    assert!(
        config.starts_with("# mine\nterminal_prefix = \"Ctrl-a\"\n"),
        "{config}"
    );
    assert_eq!(
        fs::read_to_string(&p.script).unwrap(),
        crate::chat::approvals::SCRIPT
    );
    let text = fs::read_to_string(p.codex_home.join("hooks.json")).unwrap();
    assert_eq!(groups(&text), vec![hook_entry(&p.script)]);
    assert_complete(&text, &p.script);
    // Next launch: not asked, nothing said.
    let mut out = Vec::new();
    let r = setup(&p, |_| panic!("asked twice"), &mut out).unwrap();
    assert_eq!(r, Setup::Ready);
    assert!(out.is_empty());
}

#[test]
fn declined_consent_writes_no_hook() {
    let root = tempfile::tempdir().unwrap();
    let p = paths(root.path());
    let mut out = Vec::new();
    assert_eq!(
        setup(&p, |_| Some(false), &mut out).unwrap(),
        Setup::Declined
    );
    assert_eq!(read_consent(&p.config).unwrap(), Some(false));
    assert!(!p.codex_home.exists());
    assert!(!p.script.exists());
    let mut out = Vec::new();
    assert_eq!(
        setup(&p, |_| panic!("asked twice"), &mut out).unwrap(),
        Setup::Declined
    );
    assert!(out.is_empty());
    // No answer (no terminal): nothing remembered, nothing written.
    let root = tempfile::tempdir().unwrap();
    let p = paths(root.path());
    assert_eq!(
        setup(&p, |_| None, &mut Vec::new()).unwrap(),
        Setup::NotAsked
    );
    assert!(!p.config.exists() && !p.codex_home.exists());
}

#[test]
fn test_paths_never_reach_the_real_profile() {
    let (dir, _scope) = crate::test_profile::temp();
    assert!(codex_home().starts_with(dir.path()));
    assert!(script_path().starts_with(dir.path()));
}

// ── Modes, the consent write, and removal ([codex] hooks = false) ──

use std::os::unix::fs::PermissionsExt;

fn mode(p: &Path) -> u32 {
    fs::metadata(p).unwrap().permissions().mode() & 0o777
}

fn hooks_text(home: &Path) -> String {
    fs::read_to_string(home.join("hooks.json")).unwrap()
}

const MINE: &str = r#"{
  "hooks": {
    "Stop": [{"hooks": [{"type": "command", "command": "/stop.sh"}]}],
    "PermissionRequest": [
      {"matcher": "Bash", "hooks": [{"type": "command", "command": "/mine.sh"}]}
    ]
  }
}
"#;

#[test]
fn install_keeps_the_files_mode_and_the_backup_gets_it_too() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("codex");
    fs::create_dir_all(&home).unwrap();
    fs::write(home.join("hooks.json"), MINE).unwrap();
    fs::set_permissions(home.join("hooks.json"), fs::Permissions::from_mode(0o640)).unwrap();
    install(&home, Path::new(SCRIPT)).unwrap();
    assert_eq!(mode(&home.join("hooks.json")), 0o640);
    assert_eq!(mode(&home.join(BACKUP)), 0o640);
}

#[test]
fn the_consent_write_keeps_the_rest_and_the_mode() {
    let root = tempfile::tempdir().unwrap();
    let config = root.path().join("config.toml");
    fs::write(
        &config,
        "# mine\nterminal_prefix = \"Ctrl-a\"\n[memory]\nharvest_claude = false\n",
    )
    .unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o640)).unwrap();
    write_consent(&config, true).unwrap();
    write_consent(&config, false).unwrap();
    let text = fs::read_to_string(&config).unwrap();
    assert!(
        text.starts_with(
            "# mine\nterminal_prefix = \"Ctrl-a\"\n[memory]\nharvest_claude = false\n"
        ),
        "{text}"
    );
    assert_eq!(read_consent(&config).unwrap(), Some(false));
    assert_eq!(mode(&config), 0o640);
    // No temp or lock file left beside it but the lock.
    let names: Vec<String> = fs::read_dir(root.path())
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        names
            .iter()
            .all(|n| n == "config.toml" || n == "config.toml.lock"),
        "{names:?}"
    );
    // Malformed TOML: refused, untouched.
    fs::write(&config, "[[[").unwrap();
    assert!(write_consent(&config, true).is_err());
    assert_eq!(fs::read_to_string(&config).unwrap(), "[[[");
}

#[test]
fn removal_takes_out_only_our_entry_byte_for_byte() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("codex");
    fs::create_dir_all(&home).unwrap();
    fs::write(home.join("hooks.json"), MINE).unwrap();
    fs::set_permissions(home.join("hooks.json"), fs::Permissions::from_mode(0o640)).unwrap();
    install(&home, Path::new(SCRIPT)).unwrap();
    let installed = hooks_text(&home);
    let removed = uninstall(&home).unwrap();
    let Removed::Removed { backup } = removed else {
        panic!("{removed:?}")
    };
    assert_eq!(hooks_text(&home), MINE, "back to the user's file exactly");
    assert_eq!(mode(&home.join("hooks.json")), 0o640);
    // The first backup (the original) stays; this one holds what we changed.
    assert_eq!(fs::read_to_string(home.join(BACKUP)).unwrap(), MINE);
    assert_ne!(backup, home.join(BACKUP));
    assert!(
        backup
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("hooks.json.atem-removed.")
    );
    assert_eq!(fs::read_to_string(&backup).unwrap(), installed);
    assert_eq!(mode(&backup), 0o640);
    assert_eq!(uninstall(&home).unwrap(), Removed::Nothing);
}

#[test]
fn removal_drops_only_containers_atem_added() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("codex");
    fs::create_dir_all(&home).unwrap();
    let original = "{\"other\": 1}\n";
    fs::write(home.join("hooks.json"), original).unwrap();
    install(&home, Path::new(SCRIPT)).unwrap();
    uninstall(&home).unwrap();
    assert_eq!(hooks_text(&home), original);

    // An empty list the user had stays.
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("codex");
    fs::create_dir_all(&home).unwrap();
    let original = r#"{"hooks": {"PermissionRequest": []}}"#;
    fs::write(home.join("hooks.json"), original).unwrap();
    install(&home, Path::new(SCRIPT)).unwrap();
    uninstall(&home).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&hooks_text(&home)).unwrap(),
        serde_json::from_str::<Value>(original).unwrap()
    );

    // Atem created the file (empty backup): removal goes back to no file,
    // keeping its own copy of what it removed.
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("codex");
    install(&home, Path::new(SCRIPT)).unwrap();
    let installed = hooks_text(&home);
    let Removed::Removed { backup } = uninstall(&home).unwrap() else {
        panic!("nothing removed")
    };
    assert!(!home.join("hooks.json").exists());
    assert_eq!(fs::read_to_string(&backup).unwrap(), installed);
    assert_eq!(fs::read_to_string(home.join(BACKUP)).unwrap(), "");
    assert_eq!(uninstall(&home).unwrap(), Removed::Nothing);

    // Atem created the file and the user added a key since: only that stays.
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("codex");
    install(&home, Path::new(SCRIPT)).unwrap();
    let mut v: Value = serde_json::from_str(&hooks_text(&home)).unwrap();
    v["mine"] = Value::Bool(true);
    fs::write(home.join("hooks.json"), v.to_string()).unwrap();
    uninstall(&home).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&hooks_text(&home)).unwrap(),
        serde_json::json!({"mine": true})
    );

    // No backup at all (it was deleted): can't tell what was the user's,
    // so the empty containers stay.
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("codex");
    install(&home, Path::new(SCRIPT)).unwrap();
    fs::remove_file(home.join(BACKUP)).unwrap();
    uninstall(&home).unwrap();
    let empty: serde_json::Map<String, Value> = EVENTS
        .iter()
        .map(|e| (e.to_string(), Value::Array(Vec::new())))
        .collect();
    assert_eq!(
        serde_json::from_str::<Value>(&hooks_text(&home)).unwrap(),
        serde_json::json!({ "hooks": empty })
    );
    assert!(
        !home.join(BACKUP).exists(),
        "BACKUP is never the removal's copy"
    );
}

#[test]
fn removal_refuses_files_it_does_not_understand() {
    let marked = format!("{MARKER} x");
    let cases = [
        "{ not json".to_string(),
        "[]".to_string(),
        r#"{"hooks": {"PermissionRequest": {}}}"#.to_string(),
        // Our marker somewhere else.
        serde_json::json!({"note": marked}).to_string(),
        serde_json::json!({"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "/x", "statusMessage": marked}]}]}}).to_string(),
        serde_json::json!({"hooks": {"Stop": {"0": {"hooks": [{"type": "command", "command": marked}]}}}}).to_string(),
        // Our entry sharing its group with the user's hook.
        serde_json::json!({"hooks": {"PermissionRequest": [{"matcher": "*", "hooks": [
            {"type": "command", "command": marked},
            {"type": "command", "command": "/mine.sh"}
        ]}]}})
        .to_string(),
    ];
    for text in cases {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("codex");
        fs::create_dir_all(&home).unwrap();
        fs::write(home.join("hooks.json"), &text).unwrap();
        assert!(uninstall(&home).is_err(), "{text}");
        assert_eq!(hooks_text(&home), text);
        assert_eq!(
            fs::read_dir(&home).unwrap().count(),
            1,
            "no backup, no temp"
        );
    }
}

#[test]
fn a_removal_that_does_not_verify_is_restored() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("codex");
    fs::create_dir_all(&home).unwrap();
    fs::write(home.join("hooks.json"), MINE).unwrap();
    install(&home, Path::new(SCRIPT)).unwrap();
    let installed = hooks_text(&home);
    // A write that lands something else than intended.
    let bad = |path: &Path, bytes: &[u8], mode: u32| {
        let wrong = if path.ends_with("hooks.json") && !bytes.is_empty() {
            b"{}".to_vec()
        } else {
            bytes.to_vec()
        };
        write_keeping(path, &wrong, mode)
    };
    let error = uninstall_with(&home, &bad, &write_keeping).unwrap_err();
    assert!(format!("{error:#}").contains("restored"), "{error:#}");
    assert_eq!(hooks_text(&home), installed);
}

#[test]
fn an_install_that_does_not_verify_is_put_back() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("codex");
    fs::create_dir_all(&home).unwrap();
    let bad = |path: &Path, bytes: &[u8], mode: u32| {
        let wrong = if path.ends_with("hooks.json") {
            b"{}".to_vec()
        } else {
            bytes.to_vec()
        };
        write_keeping(path, &wrong, mode)
    };
    // there was a file: restored as it was
    fs::write(home.join("hooks.json"), MINE).unwrap();
    let error = install_with(&home, Path::new(SCRIPT), &bad, &write_keeping).unwrap_err();
    assert!(format!("{error:#}").contains("put back"), "{error:#}");
    assert_eq!(hooks_text(&home), MINE);
    // there was none: none again
    fs::remove_file(home.join("hooks.json")).unwrap();
    install_with(&home, Path::new(SCRIPT), &bad, &write_keeping).unwrap_err();
    assert!(!home.join("hooks.json").exists());
}

#[test]
fn declining_later_removes_our_hook_once() {
    let root = tempfile::tempdir().unwrap();
    let p = paths(root.path());
    fs::create_dir_all(&p.codex_home).unwrap();
    fs::write(p.codex_home.join("hooks.json"), MINE).unwrap();
    assert_eq!(
        setup(&p, |_| Some(true), &mut Vec::new()).unwrap(),
        Setup::Ready
    );
    write_consent(&p.config, false).unwrap();
    let mut out = Vec::new();
    assert_eq!(
        setup(&p, |_| panic!("asked"), &mut out).unwrap(),
        Setup::Declined
    );
    let said = String::from_utf8(out).unwrap();
    assert!(said.contains("Removed Atem's hooks"), "{said}");
    assert_eq!(hooks_text(&p.codex_home), MINE);
    let mut out = Vec::new();
    assert_eq!(
        setup(&p, |_| panic!("asked"), &mut out).unwrap(),
        Setup::Declined
    );
    assert!(out.is_empty(), "told once");
}

#[test]
fn removal_takes_out_every_marked_entry_and_gives_the_fixture_back() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("codex");
    fs::create_dir_all(&home).unwrap();
    let original = fixture_hooks();
    fs::write(home.join("hooks.json"), &original).unwrap();
    install(&home, Path::new(SCRIPT)).unwrap();
    assert_complete(&hooks_text(&home), Path::new(SCRIPT));
    assert!(matches!(uninstall(&home).unwrap(), Removed::Removed { .. }));
    assert_eq!(hooks_text(&home), original, "byte for byte");
    assert_eq!(uninstall(&home).unwrap(), Removed::Nothing);
}

#[test]
fn removal_takes_marked_entries_under_any_event() {
    // Ours under an event Atem doesn't install (any marked group goes), and
    // two of ours in one list.
    let marked = |c: &str| serde_json::json!({"hooks": [{"type": "command", "command": format!("{MARKER} {c}")}]});
    let theirs = serde_json::json!({"hooks": [{"type": "command", "command": "/mine.sh"}]});
    let text = serde_json::to_string_pretty(&serde_json::json!({"hooks": {
        "SubagentStop": [marked("a")],
        "Stop": [marked("b"), theirs, marked("c")],
    }}))
    .unwrap();
    let original = serde_json::json!({"hooks": {"Stop": []}}).to_string();
    let (out, want) = remove_ours(&text, Some(&original)).unwrap().unwrap();
    assert_eq!(want, serde_json::json!({"hooks": {"Stop": [theirs]}}));
    assert_eq!(serde_json::from_str::<Value>(&out).unwrap(), want);
}

// ── The script's event mode, with the spike's hook stdin files ──

mod script {
    use super::*;
    use crate::chat::approvals::{ENV, SCRIPT_NAME, install_script};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    fn hook_fixture(name: &str) -> String {
        fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("designs/fixtures/codex-hooks/hooks")
                .join(name),
        )
        .unwrap()
    }

    /// A Codex session directory (`approvals/`, `events/`) and the script.
    fn session() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("approvals")).unwrap();
        fs::create_dir(dir.path().join("events")).unwrap();
        let script = dir.path().join("hooks").join(SCRIPT_NAME);
        install_script(&script).unwrap();
        (dir, script)
    }

    /// Runs `command` as Codex does (`sh -c`, stdin then closed).
    fn run(command: &str, dir: Option<&Path>, stdin: &str) -> (bool, String, String) {
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c")
            .arg(command)
            .env_remove(ENV)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(dir) = dir {
            cmd.env(ENV, dir);
        }
        let mut child = cmd.spawn().unwrap();
        // A command that exits at once (outside Atem) may not read it.
        match child.stdin.take().unwrap().write_all(stdin.as_bytes()) {
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
            written => written.unwrap(),
        }
        let out = child.wait_with_output().unwrap();
        (
            out.status.success(),
            String::from_utf8(out.stdout).unwrap(),
            String::from_utf8(out.stderr).unwrap(),
        )
    }

    /// An event file's stdin, after its `$$ $PPID` line (checked); the
    /// parent pid.
    fn event_body(path: &Path) -> (String, u32) {
        let text = fs::read_to_string(path).unwrap();
        let (head, body) = text.split_once('\n').unwrap();
        let ids: Vec<u32> = head.split(' ').map(|n| n.parse().unwrap()).collect();
        assert_eq!(ids.len(), 2, "{head:?}");
        (body.to_string(), ids[1])
    }

    fn event_files(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir.join("events"))
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("ev-"))
            .collect();
        names.sort();
        names
    }

    /// What isn't an event or the counter (readers ignore these).
    fn leftovers(dir: &Path) -> Vec<String> {
        fs::read_dir(dir.join("events"))
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| !n.starts_with("ev-") && n != "seq")
            .collect()
    }

    #[test]
    fn every_event_of_the_spike_is_recorded_in_order() {
        let (s, script) = session();
        let mut want = Vec::new();
        let mut names: Vec<String> = fs::read_dir(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("designs/fixtures/codex-hooks/hooks"),
        )
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
        names.sort();
        for name in names {
            let input = hook_fixture(&name);
            let event = serde_json::from_str::<Value>(&input).unwrap()["hook_event_name"]
                .as_str()
                .unwrap()
                .to_string();
            let cmd = entry_for(&script, &event)["hooks"][0]["command"]
                .as_str()
                .unwrap()
                .to_string();
            if event == "PermissionRequest" {
                continue; // its own protocol (approvals tests)
            }
            let (ok, stdout, stderr) = run(&cmd, Some(s.path()), &input);
            assert!(ok, "{name}");
            assert!(
                stdout.is_empty() && stderr.is_empty(),
                "{name}: {stdout}{stderr}"
            );
            want.push((format!("ev-{:010}-{event}.json", want.len() + 1), input));
        }
        let got = event_files(s.path());
        assert_eq!(got, want.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>());
        use std::os::unix::fs::PermissionsExt;
        for (name, input) in &want {
            let p = s.path().join("events").join(name);
            let (body, parent) = event_body(&p);
            assert_eq!(&body, input, "{name}: stdin verbatim");
            // The command execs the script: its parent is whoever ran the
            // command (Codex; here the test).
            assert_eq!(parent, std::process::id(), "{name}");
            assert_eq!(
                fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert!(leftovers(s.path()).is_empty(), "{:?}", leftovers(s.path()));
        assert!(
            fs::read_dir(s.path().join("approvals"))
                .unwrap()
                .next()
                .is_none()
        );
    }

    #[test]
    fn the_event_name_comes_from_stdin_without_an_argument() {
        let (s, script) = session();
        let q = crate::chat::approvals::shell_quote(&script.to_string_lossy());
        let stop = hook_fixture("03-Stop.json");
        assert!(run(&format!("sh {q} event"), Some(s.path()), &stop).0);
        // A bad argument falls back to stdin, then to "unknown".
        assert!(run(&format!("sh {q} event 'x/../y'"), Some(s.path()), &stop).0);
        assert!(run(&format!("sh {q} event"), Some(s.path()), "{}").0);
        assert_eq!(
            event_files(s.path()),
            vec![
                "ev-0000000001-Stop.json",
                "ev-0000000002-Stop.json",
                "ev-0000000003-unknown.json"
            ]
        );
        // PermissionRequest is never recorded as an event.
        let pr = hook_fixture("06-PermissionRequest.json");
        let (ok, stdout, _) = run(&format!("sh {q} event"), Some(s.path()), &pr);
        assert!(ok && stdout.is_empty());
        assert_eq!(event_files(s.path()).len(), 3);
        assert!(leftovers(s.path()).is_empty());
    }

    #[test]
    fn outside_atem_the_commands_do_nothing() {
        let (s, script) = session();
        let input = hook_fixture("01-SessionStart-startup.json");
        for (event, group) in hook_entries(&script) {
            let cmd = group["hooks"][0]["command"].as_str().unwrap();
            let (ok, stdout, stderr) = run(cmd, None, &input);
            assert!(ok && stdout.is_empty() && stderr.is_empty(), "{event}");
        }
        // The script gone: nothing either, even inside a session.
        let gone = event_command(&s.path().join("gone.sh"), "SessionStart");
        let (ok, stdout, stderr) = run(&gone, Some(s.path()), &input);
        assert!(ok && stdout.is_empty() && stderr.is_empty());
        // A session directory without events/: nothing written, still silent.
        fs::remove_dir(s.path().join("events")).unwrap();
        let cmd = event_command(&script, "SessionStart");
        let (ok, stdout, stderr) = run(&cmd, Some(s.path()), &input);
        assert!(ok && stdout.is_empty() && stderr.is_empty());
        fs::create_dir(s.path().join("events")).unwrap();
        assert!(event_files(s.path()).is_empty());
    }

    #[test]
    fn concurrent_hooks_get_distinct_consecutive_seqs() {
        let (s, script) = session();
        let input = hook_fixture("05-PreToolUse-before-approval.json");
        let cmd = event_command(&script, "PreToolUse");
        let n = 12;
        let threads: Vec<_> = (0..n)
            .map(|_| {
                let (cmd, input, dir) = (cmd.clone(), input.clone(), s.path().to_path_buf());
                std::thread::spawn(move || run(&cmd, Some(&dir), &input))
            })
            .collect();
        for t in threads {
            let (ok, stdout, stderr) = t.join().unwrap();
            assert!(ok && stdout.is_empty() && stderr.is_empty());
        }
        let want: Vec<String> = (1..=n)
            .map(|i| format!("ev-{i:010}-PreToolUse.json"))
            .collect();
        assert_eq!(event_files(s.path()), want);
        assert!(leftovers(s.path()).is_empty(), "{:?}", leftovers(s.path()));
    }

    /// A pid that isn't running (a reaped child's).
    fn dead_pid() -> u32 {
        let mut child = Command::new("/bin/true").spawn().unwrap();
        let dead = child.id();
        child.wait().unwrap();
        dead
    }

    fn stop(s: &Path, script: &Path) -> (bool, String, String) {
        run(
            &event_command(script, "Stop"),
            Some(s),
            &hook_fixture("03-Stop.json"),
        )
    }

    #[test]
    fn a_lock_left_by_a_killed_hook_is_taken_over() {
        let (s, script) = session();
        let lock = s.path().join("events/seq.lock");
        std::os::unix::fs::symlink(dead_pid().to_string(), &lock).unwrap();
        fs::write(s.path().join("events/seq"), "41\n").unwrap();
        let started = Instant::now();
        let (ok, stdout, _) = stop(s.path(), &script);
        assert!(ok && stdout.is_empty());
        assert!(started.elapsed() < Duration::from_secs(3));
        assert_eq!(event_files(s.path()), vec!["ev-0000000042-Stop.json"]);
        assert!(fs::symlink_metadata(&lock).is_err(), "released");
    }

    /// A lock that names no pid (no hook makes one: `ln -s` writes the pid
    /// with the lock), or isn't a symlink at all, is taken over too.
    #[test]
    fn a_lock_without_a_pid_is_taken_over() {
        for make in ["empty-target", "word", "directory"] {
            let (s, script) = session();
            let lock = s.path().join("events/seq.lock");
            match make {
                "empty-target" => std::os::unix::fs::symlink("", &lock)
                    .or_else(|_| std::os::unix::fs::symlink("-", &lock))
                    .unwrap(),
                "word" => std::os::unix::fs::symlink("nobody", &lock).unwrap(),
                _ => fs::create_dir(&lock).unwrap(),
            }
            let (ok, stdout, _) = stop(s.path(), &script);
            assert!(ok && stdout.is_empty(), "{make}");
            assert_eq!(
                event_files(s.path()),
                vec!["ev-0000000001-Stop.json"],
                "{make}"
            );
            assert!(fs::symlink_metadata(&lock).is_err(), "{make}");
        }
    }

    /// A live holder: the event is dropped, the hook still exits 0 with no
    /// output within Codex's 3 s, and the holder's lock stays.
    #[test]
    fn a_live_holder_drops_the_event_in_time() {
        let (s, script) = session();
        let lock = s.path().join("events/seq.lock");
        std::os::unix::fs::symlink(std::process::id().to_string(), &lock).unwrap();
        let started = Instant::now();
        let (ok, stdout, stderr) = stop(s.path(), &script);
        let took = started.elapsed();
        assert!(ok && stdout.is_empty() && stderr.is_empty());
        assert!(took < Duration::from_secs(3), "{took:?}");
        assert!(took >= Duration::from_millis(1500), "it waited: {took:?}");
        assert!(event_files(s.path()).is_empty());
        assert_eq!(
            fs::read_link(&lock).unwrap(),
            PathBuf::from(std::process::id().to_string())
        );
        assert!(leftovers(s.path()).iter().all(|n| n == "seq.lock"));
    }

    /// A name already taken (as if another hook published that seq) is
    /// never overwritten: the event takes the next seq.
    #[test]
    fn a_taken_name_is_never_overwritten() {
        let (s, script) = session();
        let events = s.path().join("events");
        fs::write(events.join("seq"), "4\n").unwrap();
        fs::write(events.join("ev-0000000005-Stop.json"), "theirs").unwrap();
        fs::write(events.join("ev-0000000006-Stop.json"), "theirs too").unwrap();
        let (ok, stdout, _) = stop(s.path(), &script);
        assert!(ok && stdout.is_empty());
        assert_eq!(
            event_files(s.path()),
            vec![
                "ev-0000000005-Stop.json",
                "ev-0000000006-Stop.json",
                "ev-0000000007-Stop.json"
            ]
        );
        assert_eq!(
            fs::read_to_string(events.join("ev-0000000005-Stop.json")).unwrap(),
            "theirs"
        );
        assert_eq!(fs::read_to_string(events.join("seq")).unwrap(), "7\n");
        assert!(leftovers(s.path()).is_empty());
    }

    /// Two SessionEnd hooks at once (Codex quitting after /new), many
    /// times: never the same seq, never a lost event.
    #[test]
    fn simultaneous_session_ends_never_clobber() {
        for _ in 0..10 {
            let (s, script) = session();
            let cmd = event_command(&script, "SessionEnd");
            let a = hook_fixture("27-SessionEnd-old-session-at-exit.json");
            let b = hook_fixture("28-SessionEnd-current-session-at-exit.json");
            let threads: Vec<_> = [a.clone(), b.clone()]
                .into_iter()
                .map(|input| {
                    let (cmd, dir) = (cmd.clone(), s.path().to_path_buf());
                    std::thread::spawn(move || run(&cmd, Some(&dir), &input))
                })
                .collect();
            for t in threads {
                assert!(t.join().unwrap().0);
            }
            let files = event_files(s.path());
            assert_eq!(
                files,
                vec![
                    "ev-0000000001-SessionEnd.json",
                    "ev-0000000002-SessionEnd.json"
                ]
            );
            let mut got: Vec<String> = files
                .iter()
                .map(|f| event_body(&s.path().join("events").join(f)).0)
                .collect();
            got.sort();
            let mut want = vec![a, b];
            want.sort();
            assert_eq!(got, want);
        }
    }
}
