use super::*;
use std::fs;

const SCRIPT: &str = "/home/u/.config/atem/hooks/approval-hook.sh";

fn entry() -> Value {
    hook_entry(Path::new(SCRIPT))
}

fn changed(m: Merge) -> String {
    match m {
        Merge::Changed(t) => t,
        Merge::Unchanged => panic!("expected a change"),
    }
}

fn groups(text: &str) -> Vec<Value> {
    let v: Value = serde_json::from_str(text).unwrap();
    v["hooks"]["PermissionRequest"].as_array().unwrap().clone()
}

#[test]
fn the_entry_is_marked_stable_and_bounded() {
    let e = entry();
    let cmd = e["hooks"][0]["command"].as_str().unwrap();
    assert!(cmd.starts_with(MARKER));
    assert!(cmd.contains("ATEM_APPROVAL_DIR"));
    assert!(cmd.contains("codex 300"));
    assert_eq!(e["hooks"][0]["timeout"], 300);
    assert_eq!(e["matcher"], "*");
    assert_eq!(entry(), e, "the same for every session");
}

#[test]
fn merge_into_nothing_creates_the_file() {
    for existing in [None, Some(""), Some("  \n")] {
        let text = changed(merge(existing, &entry()).unwrap());
        assert_eq!(groups(&text), vec![entry()]);
        assert_eq!(merge(Some(&text), &entry()).unwrap(), Merge::Unchanged);
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
    let text = changed(merge(Some(existing), &entry()).unwrap());
    let g = groups(&text);
    assert_eq!(g.len(), 2);
    assert_eq!(g[0]["hooks"][0]["command"], "/a/deny-rm.sh", "theirs first");
    assert_eq!(g[1], entry());
    // Only our entry was inserted: removing it gives the original back.
    let inserted = format!(",\n      {}", serde_json::to_string(&entry()).unwrap());
    assert_eq!(text.replacen(&inserted, "", 1), existing);
    assert_eq!(merge(Some(&text), &entry()).unwrap(), Merge::Unchanged);
}

#[test]
fn merge_adds_missing_levels() {
    let text = changed(merge(Some(r#"{"other": 1}"#), &entry()).unwrap());
    assert_eq!(groups(&text), vec![entry()]);
    assert_eq!(serde_json::from_str::<Value>(&text).unwrap()["other"], 1);
    let text = changed(merge(Some("{}"), &entry()).unwrap());
    assert_eq!(groups(&text), vec![entry()]);
    let text = changed(
        merge(
            Some(r#"{"hooks": {"Stop": [{"hooks": [{"type":"command","command":"x"}]}]}}"#),
            &entry(),
        )
        .unwrap(),
    );
    assert_eq!(groups(&text), vec![entry()]);
    let v: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["hooks"]["Stop"][0]["hooks"][0]["command"], "x");
    let text = changed(merge(Some(r#"{"hooks": {"PermissionRequest": []}}"#), &entry()).unwrap());
    assert_eq!(groups(&text), vec![entry()]);
}

#[test]
fn an_older_atem_entry_is_replaced_in_place() {
    let old = serde_json::json!({"matcher": "*", "hooks": [{"type": "command", "command": format!("{MARKER} old")}]});
    let theirs = serde_json::json!({"matcher": "Bash", "hooks": [{"type": "command", "command": "/a/x.sh"}]});
    let existing = serde_json::to_string_pretty(&serde_json::json!({
        "hooks": {"PermissionRequest": [old, theirs]}
    }))
    .unwrap();
    let text = changed(merge(Some(&existing), &entry()).unwrap());
    assert_eq!(groups(&text), vec![entry(), theirs]);
}

#[test]
fn malformed_files_are_refused() {
    for bad in [
        "{",
        "[]",
        "{\"hooks\": []}",
        "{\"hooks\": {\"PermissionRequest\": {}}}",
        "// comment\n{}",
    ] {
        assert!(merge(Some(bad), &entry()).is_err(), "{bad}");
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
fn install_creates_a_missing_file_without_a_backup() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("codex");
    assert_eq!(
        install(&home, Path::new(SCRIPT)).unwrap(),
        Installed::Changed { backup: None }
    );
    assert!(!home.join(BACKUP).exists());
    assert_eq!(
        groups(&fs::read_to_string(home.join("hooks.json")).unwrap()),
        vec![entry()]
    );
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
    assert_eq!(
        groups(&fs::read_to_string(p.codex_home.join("hooks.json")).unwrap()),
        vec![hook_entry(&p.script)]
    );
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

// ── Modes, the consent write, and removal (approvals_hook = false) ──

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
            .starts_with("hooks.json.atem-bak.")
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

    // Atem created the file (no backup): can't tell what was the user's,
    // so the empty containers stay.
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("codex");
    install(&home, Path::new(SCRIPT)).unwrap();
    uninstall(&home).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&hooks_text(&home)).unwrap(),
        serde_json::json!({"hooks": {"PermissionRequest": []}})
    );
    assert!(home.join(BACKUP).exists(), "the removal's own backup");
}

#[test]
fn removal_refuses_files_it_does_not_understand() {
    let marked = format!("{MARKER} x");
    let cases = [
        "{ not json".to_string(),
        "[]".to_string(),
        r#"{"hooks": {"PermissionRequest": {}}}"#.to_string(),
        // Our marker somewhere else.
        serde_json::json!({"hooks": {"Stop": [{"hooks": [{"type": "command", "command": marked}]}]}}).to_string(),
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
    assert!(said.contains("Removed Atem's approval hook"), "{said}");
    assert_eq!(hooks_text(&p.codex_home), MINE);
    let mut out = Vec::new();
    assert_eq!(
        setup(&p, |_| panic!("asked"), &mut out).unwrap(),
        Setup::Declined
    );
    assert!(out.is_empty(), "told once");
}
