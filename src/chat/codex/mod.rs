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
    let mut backup = None;
    if let Some(original) = &existing {
        let bak = codex_home.join(BACKUP);
        if std::fs::symlink_metadata(&bak).is_err() {
            crate::runtime::worker::write_atomic(&bak, original.as_bytes())
                .with_context(|| format!("writing {}", bak.display()))?;
        }
        backup = Some(bak);
    }
    std::fs::create_dir_all(codex_home)?;
    crate::runtime::worker::write_atomic(&path, text.as_bytes())
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(Installed::Changed { backup })
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

/// Records the answer, keeping the rest of config.toml as it is.
pub fn write_consent(config: &Path, allow: bool) -> Result<()> {
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
    if let Some(dir) = config.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(config, doc.to_string())?;
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
