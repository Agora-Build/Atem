//! Codex hooks setup: one Atem entry per Codex hook event (`EVENTS`)
//! merged into `$CODEX_HOME/hooks.json` (default `~/.codex`), set up by
//! `atem agent launch codex` after asking once (remembered as
//! `[codex] hooks` in config.toml; one answer covers approvals and chat).
//!
//! - Merged, never overwritten: the user's hooks stay as they are (ours are
//!   appended after theirs, so their entries keep their positions and
//!   Codex's trust in them: Codex trusts each handler by its position
//!   `<event>:<group>:<handler>` plus a hash); the file is edited in place
//!   as text and checked to parse to exactly the intended JSON. A malformed
//!   or unexpected file is refused.
//! - `hooks.json.atem-bak` holds the original before the first change
//!   (empty: there was no file); a removal keeps its own copy of the file
//!   as `hooks.json.atem-removed.<seconds>`.
//! - Idempotent: an entry already there (equal) stays where it is, an older
//!   Atem entry of an event is replaced in place, a missing one is
//!   appended; so a partial set is completed by appending only what's
//!   missing. Ours are marked by their command (`: atem-approval-hook;`,
//!   kept from the first, PermissionRequest-only version so that entry's
//!   command, and Codex's trust in it, stay the same).
//! - Each command is the same for every session (the session comes from
//!   `ATEM_APPROVAL_DIR`, set by the worker), so Codex's one-time trust
//!   stays valid. Outside Atem the variable is absent and the command
//!   exits at once with no output: plain `codex` behaves as before.
//! - PermissionRequest is synchronous (it decides; Codex runs matching
//!   hooks concurrently and "any deny wins", so ours never overrides a deny
//!   from the user's own hooks); SessionEnd is always synchronous in Codex;
//!   every other event is `async: true` and only records the event
//!   (`approval_hook.sh event`, see its header for the `ev-<seq>-<Event>.json`
//!   files in the session's `events/` directory).

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::Value;

use crate::chat::approvals::{CODEX_TIMEOUT, ENV, shell_quote};
use crate::config::write_keeping;

// Wired into the worker by the next step (Codex chat plan, Task 3).
#[allow(dead_code)]
pub mod adapter;
#[allow(dead_code)]
pub mod rollout;

/// How our entries' commands start (their mark).
pub const MARKER: &str = ": atem-approval-hook;";
pub const BACKUP: &str = "hooks.json.atem-bak";

/// The Codex hook events Atem installs an entry for, in install order
/// (codex-cli 0.162.1; SubagentStart/SubagentStop are left out).
pub const EVENTS: [&str; 10] = [
    "SessionStart",
    "SessionEnd",
    "UserPromptSubmit",
    "PreToolUse",
    "PermissionRequest",
    "PostToolUse",
    "PreCompact",
    "PostCompact",
    "Stop",
    "Interrupt",
];

/// The timeout (seconds) of the event-recording entries: within Codex's
/// 3 s clamp for Interrupt and SessionEnd (so `/hooks` shows no clamping
/// warning); the script takes milliseconds, waiting at most ~2 s for the
/// event lock.
pub const EVENT_TIMEOUT: u64 = 3;

/// `$CODEX_HOME`, else `~/.codex`.
pub fn codex_home() -> PathBuf {
    #[cfg(test)]
    return crate::test_profile::dir().join("codex-home");
    #[cfg(not(test))]
    match std::env::var_os("CODEX_HOME") {
        Some(v) if !v.is_empty() => PathBuf::from(v),
        _ => dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".codex"),
    }
}

/// The stable script path: `<config>/hooks/approval-hook.sh`.
pub fn script_path() -> PathBuf {
    crate::config::AtemConfig::config_dir()
        .join("hooks")
        .join(crate::chat::approvals::SCRIPT_NAME)
}

/// The command's guard: outside Atem (or without the script) exit at once.
fn guard(script: &str) -> String {
    format!("{MARKER} [ -n \"${{{ENV}:-}}\" ] && [ -f {script} ] || exit 0;")
}

/// The PermissionRequest entry's command: the same for every session (and
/// byte for byte the one Atem installed before chat, so its trust stays).
pub fn hook_command(script: &Path) -> String {
    let script = shell_quote(&script.to_string_lossy());
    format!(
        "{} exec /bin/sh {script} codex {CODEX_TIMEOUT}",
        guard(&script)
    )
}

/// The command recording `event` (any event but PermissionRequest).
pub fn event_command(script: &Path, event: &str) -> String {
    let script = shell_quote(&script.to_string_lossy());
    format!("{} exec /bin/sh {script} event {event}", guard(&script))
}

/// Our matcher group for `hooks.PermissionRequest`.
pub fn hook_entry(script: &Path) -> Value {
    serde_json::json!({
        "matcher": "*",
        "hooks": [{
            "type": "command",
            "command": hook_command(script),
            "timeout": CODEX_TIMEOUT,
        }]
    })
}

/// Our group for `hooks.<event>`.
pub fn entry_for(script: &Path, event: &str) -> Value {
    if event == "PermissionRequest" {
        return hook_entry(script);
    }
    let mut hook = serde_json::json!({
        "type": "command",
        "command": event_command(script, event),
        "timeout": EVENT_TIMEOUT,
    });
    if event != "SessionEnd" {
        hook["async"] = Value::Bool(true);
    }
    serde_json::json!({ "hooks": [hook] })
}

/// Every event's entry, in `EVENTS` order.
pub fn hook_entries(script: &Path) -> Vec<(&'static str, Value)> {
    EVENTS.iter().map(|e| (*e, entry_for(script, e))).collect()
}

fn marked(hook: &Value) -> bool {
    hook.get("command")
        .and_then(Value::as_str)
        .is_some_and(|c| c.starts_with(MARKER))
}

/// JSON pointer token for `key`.
fn pointer_token(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
}

/// Where our groups are: event → group indices (sorted). `Err` for a
/// marker anywhere but a hook's `command` in `hooks.<event>[i].hooks[j]`,
/// or a marked group that also holds other hooks (never guessed at).
fn locate_ours(v: &Value) -> Result<BTreeMap<String, Vec<usize>>> {
    let mut found = Vec::new();
    marked_paths(v, &mut Vec::new(), &mut found);
    let mut ours: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for path in &found {
        let place = match path.iter().map(String::as_str).collect::<Vec<_>>()[..] {
            ["hooks", event, i, "hooks", _, "command"] => {
                let list = &v["hooks"][event];
                let i = i.parse::<usize>().ok().filter(|_| list.is_array());
                i.filter(|&i| list[i]["hooks"].is_array())
                    .map(|i| (event, i))
            }
            _ => None,
        };
        let Some((event, i)) = place else {
            bail!(
                "it has Atem's marker in an unexpected place ({})",
                path.join(".")
            );
        };
        let list = ours.entry(event.to_string()).or_default();
        if !list.contains(&i) {
            list.push(i);
        }
    }
    for (event, list) in &mut ours {
        list.sort_unstable();
        for &i in list.iter() {
            let all_ours = v["hooks"][event.as_str()][i]["hooks"]
                .as_array()
                .is_some_and(|hooks| hooks.iter().all(marked));
            if !all_ours {
                bail!("Atem's entry in hooks.{event} shares its group with other hooks");
            }
        }
    }
    Ok(ours)
}

// ── A small JSON scanner with byte spans (the input already parsed) ──

struct Node {
    start: usize,
    end: usize,
    kind: Kind,
}

enum Kind {
    /// (key, the key's start, value)
    Object(Vec<(String, usize, Node)>),
    Array(Vec<Node>),
    Other,
}

struct Scanner<'a> {
    text: &'a str,
    i: usize,
}

impl Scanner<'_> {
    fn byte(&self) -> Result<u8> {
        self.text
            .as_bytes()
            .get(self.i)
            .copied()
            .ok_or_else(|| anyhow!("unexpected end"))
    }

    fn ws(&mut self) {
        while self
            .text
            .as_bytes()
            .get(self.i)
            .is_some_and(|b| b.is_ascii_whitespace())
        {
            self.i += 1;
        }
    }

    fn expect(&mut self, b: u8) -> Result<()> {
        self.ws();
        if self.byte()? != b {
            bail!("expected {:?}", b as char);
        }
        self.i += 1;
        Ok(())
    }

    fn string(&mut self) -> Result<String> {
        self.ws();
        let start = self.i;
        self.expect(b'"')?;
        loop {
            match self.byte()? {
                b'\\' => self.i += 2,
                b'"' => {
                    self.i += 1;
                    break;
                }
                _ => self.i += 1,
            }
        }
        Ok(serde_json::from_str(&self.text[start..self.i])?)
    }

    fn value(&mut self) -> Result<Node> {
        self.ws();
        let start = self.i;
        let kind =
            match self.byte()? {
                b'{' => {
                    self.i += 1;
                    let mut members = Vec::new();
                    self.ws();
                    if self.byte()? == b'}' {
                        self.i += 1;
                    } else {
                        loop {
                            self.ws();
                            let key_start = self.i;
                            let key = self.string()?;
                            self.expect(b':')?;
                            members.push((key, key_start, self.value()?));
                            self.ws();
                            match self.byte()? {
                                b',' => self.i += 1,
                                b'}' => {
                                    self.i += 1;
                                    break;
                                }
                                _ => bail!("expected , or }}"),
                            }
                        }
                    }
                    Kind::Object(members)
                }
                b'[' => {
                    self.i += 1;
                    let mut items = Vec::new();
                    self.ws();
                    if self.byte()? == b']' {
                        self.i += 1;
                    } else {
                        loop {
                            items.push(self.value()?);
                            self.ws();
                            match self.byte()? {
                                b',' => self.i += 1,
                                b']' => {
                                    self.i += 1;
                                    break;
                                }
                                _ => bail!("expected , or ]"),
                            }
                        }
                    }
                    Kind::Array(items)
                }
                b'"' => {
                    self.string()?;
                    Kind::Other
                }
                _ => {
                    while self.text.as_bytes().get(self.i).is_some_and(|b| {
                        !b.is_ascii_whitespace() && !matches!(b, b',' | b'}' | b']')
                    }) {
                        self.i += 1;
                    }
                    Kind::Other
                }
            };
        Ok(Node {
            start,
            end: self.i,
            kind,
        })
    }
}

fn member<'a>(node: &'a Node, key: &str) -> Option<&'a Node> {
    match &node.kind {
        Kind::Object(members) => members
            .iter()
            .rev()
            .find(|(k, _, _)| k == key)
            .map(|(_, _, v)| v),
        _ => None,
    }
}

/// `insert` added to the object or array `node` (after its last item, with
/// the same leading whitespace, or right inside an empty one).
fn append(text: &str, node: &Node, insert: &str) -> String {
    let last = match &node.kind {
        Kind::Object(m) => m.last().map(|(_, key_start, v)| (*key_start, v)),
        Kind::Array(items) => items.last().map(|v| (v.start, v)),
        Kind::Other => None,
    };
    match last {
        Some((item_start, last)) => {
            let before = &text[..item_start];
            let lead = &before[before.trim_end().len()..];
            format!("{},{lead}{insert}{}", &text[..last.end], &text[last.end..])
        }
        None => format!(
            "{}{insert}{}",
            &text[..node.start + 1],
            &text[node.start + 1..]
        ),
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Merge {
    Unchanged,
    Changed(String),
}

/// What happens to one event's list.
enum Step {
    /// Our equal group stays (only extra Atem groups go).
    Keep,
    Append,
    Replace(usize),
}

/// `existing` (hooks.json's text, `None` when absent) with `entries`
/// (event, group) merged in: per event, an equal Atem group stays, else
/// the event's first Atem group is replaced in place, else the group is
/// appended after the user's (a missing list or `hooks` object is added).
/// Everything else is kept byte for byte. `Err` for a file that isn't the
/// hooks shape Codex reads (never rewritten).
pub fn merge(existing: Option<&str>, entries: &[(&str, Value)]) -> Result<Merge> {
    let text = match existing {
        Some(t) if !t.trim().is_empty() => t,
        _ => {
            let mut lists = Vec::new();
            for (event, entry) in entries {
                lists.push(format!(
                    "    {}: [\n      {}\n    ]",
                    Value::String(event.to_string()),
                    serde_json::to_string(entry)?
                ));
            }
            return Ok(Merge::Changed(format!(
                "{{\n  \"hooks\": {{\n{}\n  }}\n}}\n",
                lists.join(",\n")
            )));
        }
    };
    let mut want: Value = serde_json::from_str(text).context("it isn't valid JSON")?;
    if !want.is_object() {
        bail!("it isn't a JSON object");
    }
    if want.get("hooks").is_some_and(|h| !h.is_object()) {
        bail!("its \"hooks\" isn't an object");
    }
    for (event, _) in entries {
        if want
            .get("hooks")
            .and_then(|h| h.get(*event))
            .is_some_and(|l| !l.is_array())
        {
            bail!("its \"hooks.{event}\" isn't a list");
        }
    }
    let ours = locate_ours(&want)?;
    let hooks = want
        .as_object_mut()
        .unwrap()
        .entry("hooks")
        .or_insert_with(|| Value::Object(Default::default()))
        .as_object_mut()
        .unwrap();
    let mut steps = Vec::new();
    for (event, entry) in entries {
        let groups = hooks
            .entry(event.to_string())
            .or_insert_with(|| Value::Array(Vec::new()))
            .as_array_mut()
            .unwrap();
        let mine = ours.get(*event).map(Vec::as_slice).unwrap_or(&[]);
        // One Atem group per event: an equal one stays, else the first is
        // replaced; any other Atem group of the event goes (never left
        // running stale).
        let (step, keep) = match mine.iter().find(|&&i| groups[i] == *entry) {
            Some(&i) => (Step::Keep, Some(i)),
            None => match mine.first() {
                Some(&i) => {
                    groups[i] = entry.clone();
                    (Step::Replace(i), Some(i))
                }
                None => {
                    groups.push(entry.clone());
                    (Step::Append, None)
                }
            },
        };
        let mut extra: Vec<usize> = mine.iter().copied().filter(|&i| Some(i) != keep).collect();
        extra.sort_unstable_by(|a, b| b.cmp(a));
        if matches!(step, Step::Keep) && extra.is_empty() {
            continue;
        }
        for &i in &extra {
            groups.remove(i);
        }
        steps.push((*event, entry, step, extra));
    }
    if steps.is_empty() {
        return Ok(Merge::Unchanged);
    }

    let mut out = text.to_string();
    for (event, entry, step, extra) in steps {
        let entry_text = serde_json::to_string(entry)?;
        let key = Value::String(event.to_string());
        let tree = Scanner { text: &out, i: 0 }.value()?;
        out = match member(&tree, "hooks") {
            None => append(
                &out,
                &tree,
                &format!("\"hooks\": {{{key}: [{entry_text}]}}"),
            ),
            Some(hooks) => match member(hooks, event) {
                None => append(&out, hooks, &format!("{key}: [{entry_text}]")),
                Some(list) => match (&list.kind, step) {
                    (Kind::Array(items), Step::Replace(i)) => format!(
                        "{}{entry_text}{}",
                        &out[..items[i].start],
                        &out[items[i].end..]
                    ),
                    (_, Step::Keep) => out.clone(),
                    _ => append(&out, list, &entry_text),
                },
            },
        };
        // The extra Atem groups, highest index first.
        for i in extra {
            let tree = Scanner { text: &out, i: 0 }.value()?;
            let list = member(&tree, "hooks")
                .and_then(|h| member(h, event))
                .ok_or_else(|| anyhow!("hooks.{event} moved"))?;
            out = remove_item(&out, list, i);
        }
    }
    let check: Value = serde_json::from_str(&out).context("the merge went wrong")?;
    if check != want {
        bail!("it couldn't be merged safely");
    }
    Ok(Merge::Changed(out))
}

#[derive(Debug, PartialEq, Eq)]
pub enum Installed {
    Unchanged,
    /// Written; `backup` names the original's copy (none when there was no file).
    Changed {
        backup: Option<PathBuf>,
    },
}

/// Merges our entries for `script` into `codex_home/hooks.json`, writing
/// `hooks.json.atem-bak` before the first change of an existing file.
pub fn install(codex_home: &Path, script: &Path) -> Result<Installed> {
    let path = codex_home.join("hooks.json");
    let existing = match std::fs::symlink_metadata(&path) {
        Ok(meta) if !meta.is_file() => {
            bail!("{} isn't a regular file", path.display())
        }
        Ok(_) => Some(
            std::fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?,
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(anyhow!(e).context(format!("reading {}", path.display()))),
    };
    let merged = merge(existing.as_deref(), &hook_entries(script))
        .with_context(|| format!("{} was left as it is", path.display()))?;
    let Merge::Changed(text) = merged else {
        return Ok(Installed::Unchanged);
    };
    let mode = file_mode(&path).unwrap_or(0o600);
    // The original before Atem's first change; an empty one records that
    // there was no file (so removal can go back to none).
    std::fs::create_dir_all(codex_home)?;
    let bak = codex_home.join(BACKUP);
    if std::fs::symlink_metadata(&bak).is_err() {
        let original = existing.as_deref().unwrap_or("");
        write_keeping(&bak, original.as_bytes(), mode)
            .with_context(|| format!("writing {}", bak.display()))?;
    }
    let backup = existing.is_some().then_some(bak);
    write_keeping(&path, text.as_bytes(), mode)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(Installed::Changed { backup })
}

/// The permission bits of `path`, when it exists.
fn file_mode(path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .ok()
        .map(|m| m.permissions().mode() & 0o7777)
}

/// What `uninstall` did.
#[derive(Debug, PartialEq, Eq)]
pub enum Removed {
    /// No Atem entry (or no file): nothing written.
    Nothing,
    /// Our entries are gone; `backup` holds the file as it was.
    Removed { backup: PathBuf },
}

/// Paths of every string starting with our marker.
fn marked_paths(v: &Value, path: &mut Vec<String>, out: &mut Vec<Vec<String>>) {
    match v {
        Value::String(s) if s.starts_with(MARKER) => out.push(path.clone()),
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                path.push(i.to_string());
                marked_paths(item, path, out);
                path.pop();
            }
        }
        Value::Object(map) => {
            for (k, item) in map {
                path.push(k.clone());
                marked_paths(item, path, out);
                path.pop();
            }
        }
        _ => {}
    }
}

/// The item spans of an object (key start .. value end) or array.
fn spans(node: &Node) -> Vec<(usize, usize)> {
    match &node.kind {
        Kind::Object(m) => m.iter().map(|(_, k, v)| (*k, v.end)).collect(),
        Kind::Array(items) => items.iter().map(|v| (v.start, v.end)).collect(),
        Kind::Other => Vec::new(),
    }
}

/// `text` without item `k` of `node` (and the comma that separated it).
fn remove_item(text: &str, node: &Node, k: usize) -> String {
    let items = spans(node);
    let (from, to) = if items.len() == 1 {
        items[0]
    } else if k + 1 == items.len() {
        (items[k - 1].1, items[k].1)
    } else {
        (items[k].0, items[k + 1].0)
    };
    format!("{}{}", &text[..from], &text[to..])
}

/// The position of the last member `key` of object `node`.
fn key_position(node: &Node, key: &str) -> Option<usize> {
    match &node.kind {
        Kind::Object(m) => m.iter().rposition(|(k, _, _)| k == key),
        _ => None,
    }
}

/// `text` without Atem's groups (every marked one, under any event), and
/// without the containers left empty that `original` (the file before
/// Atem's first change; `None`: unknown) didn't have. `Ok(None)` when there
/// is nothing of ours; `Err` for anything unexpected (never guessed at).
pub fn remove_ours(text: &str, original: Option<&str>) -> Result<Option<(String, Value)>> {
    let mut want: Value = serde_json::from_str(text).context("it isn't valid JSON")?;
    if !want.is_object() {
        bail!("it isn't a JSON object");
    }
    if let Some(hooks) = want.get("hooks") {
        let hooks = hooks
            .as_object()
            .ok_or_else(|| anyhow!("its \"hooks\" isn't an object"))?;
        for event in EVENTS {
            if hooks.get(event).is_some_and(|l| !l.is_array()) {
                bail!("its \"hooks.{event}\" isn't a list");
            }
        }
    }
    let ours = locate_ours(&want)?;
    if ours.is_empty() {
        return Ok(None);
    }
    // What existed before Atem: nothing (a blank backup: no file) → drop
    // every container left empty; unknown → keep them all.
    let before: Option<Value> = match original {
        Some(t) if t.trim().is_empty() => Some(Value::Object(Default::default())),
        Some(t) => serde_json::from_str(t).ok(),
        None => None,
    };
    let had = |pointer: &str| before.as_ref().is_none_or(|b| b.pointer(pointer).is_some());

    let mut out = text.to_string();
    let hooks = want["hooks"].as_object_mut().unwrap();
    for (event, groups) in &ours {
        for &i in groups.iter().rev() {
            let tree = Scanner { text: &out, i: 0 }.value()?;
            let list = member(&tree, "hooks")
                .and_then(|h| member(h, event))
                .ok_or_else(|| anyhow!("hooks.{event} moved"))?;
            out = remove_item(&out, list, i);
        }
        let list = hooks[event.as_str()].as_array_mut().unwrap();
        for &i in groups.iter().rev() {
            list.remove(i);
        }
        if list.is_empty() && !had(&format!("/hooks/{}", pointer_token(event))) {
            hooks.remove(event.as_str());
            let tree = Scanner { text: &out, i: 0 }.value()?;
            let h = member(&tree, "hooks").ok_or_else(|| anyhow!("hooks moved"))?;
            let k = key_position(h, event).ok_or_else(|| anyhow!("hooks.{event} moved"))?;
            out = remove_item(&out, h, k);
        }
    }
    if hooks.is_empty() && !had("/hooks") {
        want.as_object_mut().unwrap().remove("hooks");
        let tree = Scanner { text: &out, i: 0 }.value()?;
        let k = key_position(&tree, "hooks").ok_or_else(|| anyhow!("hooks moved"))?;
        out = remove_item(&out, &tree, k);
    }
    let check: Value = serde_json::from_str(&out).context("the removal went wrong")?;
    if check != want {
        bail!("Atem's entries couldn't be removed safely");
    }
    Ok(Some((out, want)))
}

/// Where `uninstall` keeps the file as it was before a removal:
/// `hooks.json.atem-removed.<seconds>[-n]`, never `BACKUP` (the original
/// from before Atem, which removal reads).
pub const REMOVED: &str = "hooks.json.atem-removed";

fn removed_path(codex_home: &Path) -> PathBuf {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut n = 0;
    loop {
        let name = if n == 0 {
            format!("{REMOVED}.{secs}")
        } else {
            format!("{REMOVED}.{secs}-{n}")
        };
        let p = codex_home.join(name);
        if std::fs::symlink_metadata(&p).is_err() {
            return p;
        }
        n += 1;
    }
}

type Writer<'a> = &'a dyn Fn(&Path, &[u8], u32) -> std::io::Result<()>;

/// Removes Atem's entries from `codex_home/hooks.json` (`[codex] hooks =
/// false`): only groups made of hooks with our marker; a backup first; the
/// result read back and checked, else the file is restored. Codex's trust
/// state (in its config.toml) is never touched.
pub fn uninstall(codex_home: &Path) -> Result<Removed> {
    uninstall_with(codex_home, &write_keeping, &write_keeping)
}

pub fn uninstall_with(codex_home: &Path, write: Writer, restore: Writer) -> Result<Removed> {
    let path = codex_home.join("hooks.json");
    let text = match std::fs::symlink_metadata(&path) {
        Ok(meta) if !meta.is_file() => bail!("{} isn't a regular file", path.display()),
        Ok(_) => {
            std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Removed::Nothing),
        Err(e) => return Err(anyhow!(e).context(format!("reading {}", path.display()))),
    };
    let original = std::fs::read_to_string(codex_home.join(BACKUP)).ok();
    let Some((new, want)) = remove_ours(&text, original.as_deref())
        .with_context(|| format!("{} was left as it is", path.display()))?
    else {
        return Ok(Removed::Nothing);
    };
    let mode = file_mode(&path).unwrap_or(0o600);
    let backup = removed_path(codex_home);
    write(&backup, text.as_bytes(), mode)
        .with_context(|| format!("writing {}", backup.display()))?;
    // There was no file before Atem and nothing else is left: none again.
    let none_before = original.as_deref().is_some_and(|t| t.trim().is_empty());
    if none_before && want == Value::Object(Default::default()) {
        std::fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
        return Ok(Removed::Removed { backup });
    }
    write(&path, new.as_bytes(), mode).with_context(|| format!("writing {}", path.display()))?;
    let landed = std::fs::read_to_string(&path)
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok());
    if landed.as_ref() != Some(&want) {
        restore(&path, text.as_bytes(), mode)
            .with_context(|| format!("restoring {} from {}", path.display(), backup.display()))?;
        bail!(
            "{} didn't read back as intended; the original was restored (a copy is in {})",
            path.display(),
            backup.display()
        );
    }
    Ok(Removed::Removed { backup })
}

/// `[codex] hooks` in config.toml.
pub fn read_consent(config: &Path) -> Result<Option<bool>> {
    crate::chat::approvals::read_setting(config, crate::chat::approvals::Agent::Codex)
}

/// Records the answer, keeping the rest of config.toml (and its mode) as
/// it is (`config::edit_config_file`: locked, atomic, a symlink followed).
/// Malformed TOML is refused, never rewritten.
pub fn write_consent(config: &Path, allow: bool) -> Result<()> {
    crate::config::edit_config_file(config, |text| {
        let mut doc: toml_edit::DocumentMut = text
            .parse()
            .with_context(|| format!("{} isn't valid TOML", config.display()))?;
        if !doc.get("codex").is_some_and(|c| c.is_table_like()) {
            doc["codex"] = toml_edit::table();
        }
        doc["codex"]["hooks"] = toml_edit::value(allow);
        Ok(doc.to_string())
    })
}

pub struct Paths {
    pub codex_home: PathBuf,
    /// config.toml
    pub config: PathBuf,
    /// The stable hook script.
    pub script: PathBuf,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Setup {
    /// No answer (no terminal): nothing written, asked again next time.
    NotAsked,
    Declined,
    /// The hooks are in place (already, or written now).
    Ready,
    /// hooks.json couldn't be merged; the user was told.
    Refused,
}

fn question(hooks: &Path) -> String {
    format!(
        "Let Astation follow Codex sessions as chat and answer their approvals? This adds Atem's hooks (one per Codex event) to {}. [y/N] ",
        hooks.display()
    )
}

/// `atem agent launch codex`'s setup: asks once (`ask` gets the question;
/// `None` = no answer), remembers the answer, and when allowed installs the
/// script and merges the entries, telling `out` once that Codex will ask
/// to review them.
pub fn setup(
    paths: &Paths,
    ask: impl FnOnce(&str) -> Option<bool>,
    out: &mut dyn Write,
) -> Result<Setup> {
    let hooks = paths.codex_home.join("hooks.json");
    let allow = match read_consent(&paths.config)? {
        Some(allow) => allow,
        None => {
            let Some(allow) = ask(&question(&hooks)) else {
                return Ok(Setup::NotAsked);
            };
            write_consent(&paths.config, allow)?;
            if !allow {
                writeln!(
                    out,
                    "Codex stays in the terminal only (no chat or approvals from Astation). To change this, set [codex] hooks = true in {}.",
                    paths.config.display()
                )?;
            }
            allow
        }
    };
    if !allow {
        // Declined (now or earlier): an entry Atem added before goes.
        match uninstall(&paths.codex_home) {
            Ok(Removed::Nothing) => {}
            Ok(Removed::Removed { backup }) => writeln!(
                out,
                "Removed Atem's hooks from {} ([codex] hooks = false; the file as it was is in {}).",
                hooks.display(),
                backup.display()
            )?,
            Err(error) => writeln!(
                out,
                "Atem's hooks could not be removed: {error:#}. Remove the entries whose command starts with \"{MARKER}\" yourself."
            )?,
        }
        return Ok(Setup::Declined);
    }
    crate::chat::approvals::install_script(&paths.script)
        .with_context(|| format!("writing {}", paths.script.display()))?;
    match install(&paths.codex_home, &paths.script) {
        Ok(Installed::Unchanged) => Ok(Setup::Ready),
        Ok(Installed::Changed { backup }) => {
            let backup = backup
                .map(|b| format!(" (your previous file is in {})", b.display()))
                .unwrap_or_default();
            writeln!(
                out,
                "Added Atem's hooks to {}{backup}. Codex asks you to review them once: choose to trust them on its \"Hooks need review\" screen, or with /hooks.",
                hooks.display()
            )?;
            Ok(Setup::Ready)
        }
        Err(error) => {
            writeln!(
                out,
                "Codex chat and approvals from Astation are off for now: {error:#}. Fix the file and launch again; Codex stays in the terminal only meanwhile."
            )?;
            Ok(Setup::Refused)
        }
    }
}

/// `setup` for the real profile, asking on `/dev/tty`. Never blocks the
/// launch: a failure is printed and Codex stays in the terminal only.
pub fn setup_on_launch() {
    let paths = Paths {
        codex_home: codex_home(),
        config: crate::config::AtemConfig::config_path(),
        script: script_path(),
    };
    let ask = |q: &str| {
        crate::pair_verify::prompt_text(q)
            .ok()
            .map(|a| matches!(a.to_ascii_lowercase().as_str(), "y" | "yes"))
    };
    let mut out = std::io::stdout();
    if let Err(error) = setup(&paths, ask, &mut out) {
        eprintln!("Codex chat and approvals from Astation are off for now: {error:#}");
    }
}

#[cfg(test)]
mod tests;
