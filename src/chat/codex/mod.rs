//! Codex approvals setup: one Atem `PermissionRequest` entry merged into
//! `$CODEX_HOME/hooks.json` (default `~/.codex`), set up by `atem agent
//! launch codex` after asking once (remembered as `[codex] approvals_hook`
//! in config.toml).
//!
//! - Merged, never overwritten: the user's hooks stay as they are (ours is
//!   appended, so their entries keep their positions and Codex's trust in
//!   them); the file is edited in place as text and checked to parse to
//!   exactly the intended JSON. A malformed or unexpected file is refused.
//! - `hooks.json.atem-bak` holds the original before the first change.
//! - Idempotent; our entry is marked by its command (`: atem-approval-hook;`).
//! - The command is the same for every session (the session comes from
//!   `ATEM_APPROVAL_DIR`, set by the worker), so Codex's one-time trust (a
//!   hash of the entry) stays valid. Outside Atem the variable is absent and
//!   the command exits at once with no output: plain `codex` asks as before.
//! - Codex runs matching hooks concurrently and "any deny wins", so our
//!   entry never overrides a deny from the user's own hooks.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::Value;

use crate::chat::approvals::{CODEX_TIMEOUT, ENV, shell_quote};

/// How our entry's command starts (its mark).
pub const MARKER: &str = ": atem-approval-hook;";
pub const BACKUP: &str = "hooks.json.atem-bak";

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

/// The entry's command: the same for every session.
pub fn hook_command(script: &Path) -> String {
    let script = shell_quote(&script.to_string_lossy());
    format!(
        "{MARKER} [ -n \"${{{ENV}:-}}\" ] && [ -f {script} ] || exit 0; exec /bin/sh {script} codex {CODEX_TIMEOUT}"
    )
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

fn is_ours(group: &Value) -> bool {
    group
        .get("hooks")
        .and_then(Value::as_array)
        .is_some_and(|hooks| {
            hooks.iter().any(|h| {
                h.get("command")
                    .and_then(Value::as_str)
                    .is_some_and(|c| c.starts_with(MARKER))
            })
        })
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

/// `existing` (hooks.json's text, `None` when absent) with `entry` merged
/// in: appended to `hooks.PermissionRequest`, or replacing our older entry
/// in place. Everything else is kept byte for byte. `Err` for a file that
/// isn't the hooks shape Codex reads (never rewritten).
pub fn merge(existing: Option<&str>, entry: &Value) -> Result<Merge> {
    let entry_text = serde_json::to_string(entry)?;
    let text = match existing {
        Some(t) if !t.trim().is_empty() => t,
        _ => {
            return Ok(Merge::Changed(format!(
                "{{\n  \"hooks\": {{\n    \"PermissionRequest\": [\n      {entry_text}\n    ]\n  }}\n}}\n"
            )));
        }
    };
    let mut want: Value = serde_json::from_str(text).context("it isn't valid JSON")?;
    let root = want
        .as_object_mut()
        .ok_or_else(|| anyhow!("it isn't a JSON object"))?;
    let hooks = root
        .entry("hooks")
        .or_insert_with(|| Value::Object(Default::default()))
        .as_object_mut()
        .ok_or_else(|| anyhow!("its \"hooks\" isn't an object"))?;
    let groups = hooks
        .entry("PermissionRequest")
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut()
        .ok_or_else(|| anyhow!("its \"hooks.PermissionRequest\" isn't a list"))?;
    let ours = groups.iter().position(is_ours);
    match ours {
        Some(i) if groups[i] == *entry => return Ok(Merge::Unchanged),
        Some(i) => groups[i] = entry.clone(),
        None => groups.push(entry.clone()),
    }

    let tree = Scanner { text, i: 0 }.value()?;
    let merged = match member(&tree, "hooks") {
        None => append(
            text,
            &tree,
            &format!("\"hooks\": {{\"PermissionRequest\": [{entry_text}]}}"),
        ),
        Some(hooks) => match member(hooks, "PermissionRequest") {
            None => append(
                text,
                hooks,
                &format!("\"PermissionRequest\": [{entry_text}]"),
            ),
            Some(list) => match (&list.kind, ours) {
                (Kind::Array(items), Some(i)) => format!(
                    "{}{entry_text}{}",
                    &text[..items[i].start],
                    &text[items[i].end..]
                ),
                _ => append(text, list, &entry_text),
            },
        },
    };
    let check: Value = serde_json::from_str(&merged).context("the merge went wrong")?;
    if check != want {
        bail!("it couldn't be merged safely");
    }
    Ok(Merge::Changed(merged))
}

#[derive(Debug, PartialEq, Eq)]
pub enum Installed {
    Unchanged,
    /// Written; `backup` names the original's copy (none when there was no file).
    Changed {
        backup: Option<PathBuf>,
    },
}

/// Merges our entry for `script` into `codex_home/hooks.json`, writing
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
    let merged = merge(existing.as_deref(), &hook_entry(script))
        .with_context(|| format!("{} was left as it is", path.display()))?;
    let Merge::Changed(text) = merged else {
        return Ok(Installed::Unchanged);
    };
    let mode = file_mode(&path).unwrap_or(0o600);
    let mut backup = None;
    if let Some(original) = &existing {
        let bak = codex_home.join(BACKUP);
        if std::fs::symlink_metadata(&bak).is_err() {
            write_keeping(&bak, original.as_bytes(), mode)
                .with_context(|| format!("writing {}", bak.display()))?;
        }
        backup = Some(bak);
    }
    std::fs::create_dir_all(codex_home)?;
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

/// Replaces `path` with `bytes` (permission bits `mode`) through a temp
/// file in the same directory (unpredictable name, never through a
/// symlink), fsync and rename.
pub fn write_keeping(path: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let dir = path
        .parent()
        .ok_or_else(|| std::io::Error::other("no parent directory"))?;
    let name = path
        .file_name()
        .ok_or_else(|| std::io::Error::other("no file name"))?;
    let tmp = dir.join(format!(
        ".{}.atem-tmp-{}",
        name.to_string_lossy(),
        uuid::Uuid::new_v4().simple()
    ));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)?;
        file.set_permissions(std::fs::Permissions::from_mode(mode))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)?;
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
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

/// `text` without Atem's `PermissionRequest` groups, and without the
/// containers left empty that `original` (the file before Atem's first
/// change; `None`: unknown) didn't have. `Ok(None)` when there is nothing
/// of ours; `Err` for anything unexpected (never guessed at).
pub fn remove_ours(text: &str, original: Option<&str>) -> Result<Option<(String, Value)>> {
    let mut want: Value = serde_json::from_str(text).context("it isn't valid JSON")?;
    if !want.is_object() {
        bail!("it isn't a JSON object");
    }
    if let Some(hooks) = want.get("hooks") {
        let hooks = hooks
            .as_object()
            .ok_or_else(|| anyhow!("its \"hooks\" isn't an object"))?;
        if hooks
            .get("PermissionRequest")
            .is_some_and(|l| !l.is_array())
        {
            bail!("its \"hooks.PermissionRequest\" isn't a list");
        }
    }
    let mut found = Vec::new();
    marked_paths(&want, &mut Vec::new(), &mut found);
    if found.is_empty() {
        return Ok(None);
    }
    let groups = want
        .get("hooks")
        .and_then(|h| h.get("PermissionRequest"))
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("its Atem entry isn't in hooks.PermissionRequest"))?;
    let mut ours = Vec::new();
    for path in &found {
        let i = match path.iter().map(String::as_str).collect::<Vec<_>>()[..] {
            ["hooks", "PermissionRequest", i, "hooks", _, "command"] => i.parse::<usize>()?,
            _ => bail!(
                "it has Atem's marker in an unexpected place ({})",
                path.join(".")
            ),
        };
        if !ours.contains(&i) {
            ours.push(i);
        }
    }
    for &i in &ours {
        let all_ours = groups[i]
            .get("hooks")
            .and_then(Value::as_array)
            .is_some_and(|hooks| {
                hooks.iter().all(|h| {
                    h.get("command")
                        .and_then(Value::as_str)
                        .is_some_and(|c| c.starts_with(MARKER))
                })
            });
        if !all_ours {
            bail!("Atem's entry shares its group with other hooks");
        }
    }
    ours.sort_unstable();
    // What existed before Atem: unknown → keep every container.
    let before: Option<Value> = original.and_then(|t| serde_json::from_str(t).ok());
    let had = |pointer: &str| before.as_ref().is_none_or(|b| b.pointer(pointer).is_some());

    let mut out = text.to_string();
    for &i in ours.iter().rev() {
        let tree = Scanner { text: &out, i: 0 }.value()?;
        let list = member(&tree, "hooks")
            .and_then(|h| member(h, "PermissionRequest"))
            .ok_or_else(|| anyhow!("hooks.PermissionRequest moved"))?;
        out = remove_item(&out, list, i);
    }
    let hooks = want["hooks"].as_object_mut().unwrap();
    let list = hooks["PermissionRequest"].as_array_mut().unwrap();
    for &i in ours.iter().rev() {
        list.remove(i);
    }
    if list.is_empty() && !had("/hooks/PermissionRequest") {
        hooks.remove("PermissionRequest");
        let tree = Scanner { text: &out, i: 0 }.value()?;
        let h = member(&tree, "hooks").unwrap();
        let k = match &h.kind {
            Kind::Object(m) => m.iter().rposition(|(k, _, _)| k == "PermissionRequest"),
            _ => None,
        }
        .ok_or_else(|| anyhow!("hooks.PermissionRequest moved"))?;
        out = remove_item(&out, h, k);
        if hooks.is_empty() && !had("/hooks") {
            want.as_object_mut().unwrap().remove("hooks");
            let tree = Scanner { text: &out, i: 0 }.value()?;
            let k = match &tree.kind {
                Kind::Object(m) => m.iter().rposition(|(k, _, _)| k == "hooks"),
                _ => None,
            }
            .ok_or_else(|| anyhow!("hooks moved"))?;
            out = remove_item(&out, &tree, k);
        }
    }
    let check: Value = serde_json::from_str(&out).context("the removal went wrong")?;
    if check != want {
        bail!("Atem's entry couldn't be removed safely");
    }
    Ok(Some((out, want)))
}

/// A free backup name: `hooks.json.atem-bak`, else `….atem-bak.<seconds>`.
fn backup_path(codex_home: &Path) -> PathBuf {
    let first = codex_home.join(BACKUP);
    if std::fs::symlink_metadata(&first).is_err() {
        return first;
    }
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut n = 0;
    loop {
        let name = if n == 0 {
            format!("{BACKUP}.{secs}")
        } else {
            format!("{BACKUP}.{secs}-{n}")
        };
        let p = codex_home.join(name);
        if std::fs::symlink_metadata(&p).is_err() {
            return p;
        }
        n += 1;
    }
}

type Writer<'a> = &'a dyn Fn(&Path, &[u8], u32) -> std::io::Result<()>;

/// Removes Atem's entries from `codex_home/hooks.json` (`approvals_hook =
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
    let backup = backup_path(codex_home);
    write(&backup, text.as_bytes(), mode)
        .with_context(|| format!("writing {}", backup.display()))?;
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

/// `[codex] approvals_hook` in config.toml.
pub fn read_consent(config: &Path) -> Result<Option<bool>> {
    let text = match std::fs::read_to_string(config) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let value: toml::Value =
        toml::from_str(&text).with_context(|| format!("{} isn't valid TOML", config.display()))?;
    Ok(value
        .get("codex")
        .and_then(|c| c.get("approvals_hook"))
        .and_then(toml::Value::as_bool))
}

/// Records the answer, keeping the rest of config.toml (and its mode) as
/// it is: under an exclusive lock on `config.toml.lock`, written through a
/// temp file and rename. Malformed TOML is refused, never rewritten.
pub fn write_consent(config: &Path, allow: bool) -> Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    if let Some(dir) = config.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let lock_path = PathBuf::from(format!("{}.lock", config.display()));
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&lock_path)
        .with_context(|| format!("opening {}", lock_path.display()))?;
    // SAFETY: flock on a descriptor this function owns; released on close.
    while unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(anyhow!(error).context(format!("locking {}", lock_path.display())));
        }
    }
    let text = match std::fs::read_to_string(config) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e.into()),
    };
    let mut doc: toml_edit::DocumentMut = text
        .parse()
        .with_context(|| format!("{} isn't valid TOML", config.display()))?;
    if !doc.get("codex").is_some_and(|c| c.is_table_like()) {
        doc["codex"] = toml_edit::table();
    }
    doc["codex"]["approvals_hook"] = toml_edit::value(allow);
    let mode = file_mode(config).unwrap_or(0o600);
    write_keeping(config, doc.to_string().as_bytes(), mode)
        .with_context(|| format!("writing {}", config.display()))?;
    drop(lock);
    Ok(())
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
    /// The hook is in place (already, or written now).
    Ready,
    /// hooks.json couldn't be merged; the user was told.
    Refused,
}

fn question(hooks: &Path) -> String {
    format!(
        "Allow approvals from Astation for Codex? This adds one hook to {}. [y/N] ",
        hooks.display()
    )
}

/// `atem agent launch codex`'s setup: asks once (`ask` gets the question;
/// `None` = no answer), remembers the answer, and when allowed installs the
/// script and merges the entry, telling `out` once that Codex will ask to
/// review it.
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
                    "Codex approvals stay in the terminal. To change this, set [codex] approvals_hook = true in {}.",
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
                "Removed Atem's approval hook from {} (approvals_hook = false; the file as it was is in {}).",
                hooks.display(),
                backup.display()
            )?,
            Err(error) => writeln!(
                out,
                "Atem's approval hook could not be removed: {error:#}. Remove the entry whose command starts with \"{MARKER}\" yourself."
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
                "Added Atem's approval hook to {}{backup}. Codex asks you to review it once: choose to trust it on its \"Hooks need review\" screen, or with /hooks.",
                hooks.display()
            )?;
            Ok(Setup::Ready)
        }
        Err(error) => {
            writeln!(
                out,
                "Codex approvals from Astation are off for now: {error:#}. Fix the file and launch again; approvals stay in the terminal meanwhile."
            )?;
            Ok(Setup::Refused)
        }
    }
}

/// `setup` for the real profile, asking on `/dev/tty`. Never blocks the
/// launch: a failure is printed and Codex approvals stay in the terminal.
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
        eprintln!("Codex approvals from Astation are off for now: {error:#}");
    }
}

#[cfg(test)]
mod tests;
