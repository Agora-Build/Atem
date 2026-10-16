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
    assert!(cmd.contains("codex 120"));
    assert_eq!(e["hooks"][0]["timeout"], 120);
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
