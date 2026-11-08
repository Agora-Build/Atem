//! Skill wire v2: a skill row as the Station's `/api/skills/v2` routes carry
//! it (Astation `designs/protocol/skill-file-wire-v2.md`, Atem #130, F8).
//! A sealed skill file is already the ASCII text of its `e1.` envelope, so
//! it travels as that text (`e1-text`), not base64 of it a second time;
//! plain files travel as base64 (`base64`), only while the account's mode
//! permits plain text. Every row and every `rewrite` says which.
//!
//! Only the representation changes: the ciphertext, its associated data,
//! the hashes, versions and sequences are the same bytes as before. The
//! local store and queue keep `Skill`'s own serde (`model::b64map`), and
//! nothing here seals, opens or hashes. Values are never logged.

use crate::memory::crypto::valid_kid;
use crate::memory::model::{Scope, Skill};
use anyhow::{Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

/// The `wire_version` of every successful v2 response.
pub const WIRE_VERSION: u64 = 2;

/// Why a row's files are refused (the Station's own words for it).
pub const INVALID_ENCODING: &str = "invalid skill files encoding";

/// How a row's `files` values are carried.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FilesEncoding {
    /// Every path is an `e1.` envelope; every value is one too, or `""`
    /// (an empty file, never sealed).
    E1Text,
    /// Standard padded base64 of each file's bytes.
    Base64,
}

impl FilesEncoding {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::E1Text => "e1-text",
            Self::Base64 => "base64",
        }
    }

    fn parse(value: Option<&Value>) -> Result<Self> {
        match value {
            Some(Value::String(text)) if text == "e1-text" => Ok(Self::E1Text),
            Some(Value::String(text)) if text == "base64" => Ok(Self::Base64),
            Some(_) => bail!("{INVALID_ENCODING}: unknown files_encoding"),
            None => bail!("{INVALID_ENCODING}: no files_encoding"),
        }
    }
}

/// Whether `value` is structurally an `e1.` envelope (the Station's
/// `envelope_kid`): `e1`, an 8-hex-digit kid, and canonical standard base64
/// of at least a nonce and a tag (40 bytes). Whether it opens is checked
/// only when it is opened.
pub fn is_envelope(value: &str) -> bool {
    let mut parts = value.splitn(3, '.');
    parts.next() == Some("e1")
        && parts.next().is_some_and(valid_kid)
        && parts.next().is_some_and(|payload| {
            !payload.is_empty()
                && STANDARD
                    .decode(payload)
                    .is_ok_and(|bytes| bytes.len() >= 40)
        })
}

/// A sealed file's value: its envelope, or empty (an empty file).
fn sealed_value(value: &str) -> bool {
    value.is_empty() || is_envelope(value)
}

/// `files` as an `e1-text` row carries them. Files that aren't all sealed
/// (a path that isn't an envelope, a value neither an envelope nor empty)
/// are refused, never sent.
pub fn sealed_files(files: &BTreeMap<String, Vec<u8>>) -> Result<Value> {
    files
        .iter()
        .map(|(path, bytes)| {
            let value = std::str::from_utf8(bytes).ok().filter(|v| sealed_value(v));
            match value {
                Some(value) if is_envelope(path) => Ok((path.clone(), Value::from(value))),
                _ => bail!("{INVALID_ENCODING}: a file of a sealed skill isn't sealed"),
            }
        })
        .collect::<Result<Map<String, Value>>>()
        .map(Value::Object)
}

/// `files` as a `base64` row carries them.
pub fn plain_files(files: &BTreeMap<String, Vec<u8>>) -> Value {
    Value::Object(
        files
            .iter()
            .map(|(path, bytes)| (path.clone(), Value::from(STANDARD.encode(bytes))))
            .collect(),
    )
}

/// `skill` as a v2 row with `files` (`sealed_files` or `plain_files`).
fn row(skill: &Skill, encoding: FilesEncoding, files: Value) -> Value {
    // Every field named: a field added to `Skill` must be added here too.
    let Skill {
        scope,
        project,
        name,
        version,
        files: _,
        content_hash,
        source_agent,
        source_machine,
        created_at,
        deleted,
        seq,
    } = skill;
    json!({
        "scope": scope,
        "project": project,
        "name": name,
        "version": version,
        "files_encoding": encoding.as_str(),
        "files": files,
        "content_hash": content_hash,
        "source_agent": source_agent,
        "source_machine": source_machine,
        "created_at": created_at,
        "deleted": deleted,
        "seq": seq,
    })
}

/// A sealed skill (as `EncryptionContext::encrypt_skills` made it) as an
/// `e1-text` row.
pub fn sealed_skill(skill: &Skill) -> Result<Value> {
    Ok(row(
        skill,
        FilesEncoding::E1Text,
        sealed_files(&skill.files)?,
    ))
}

/// A plain skill as a `base64` row: only while the account's mode permits
/// plain text (the caller doesn't seal it).
pub fn plain_skill(skill: &Skill) -> Value {
    row(skill, FilesEncoding::Base64, plain_files(&skill.files))
}

/// The files of a v2 row or `rewrite` as bytes: an `e1-text` value is the
/// envelope's own text (`""` an empty file); a `base64` value is decoded.
/// Missing or unknown encodings, values that aren't strings, malformed
/// envelopes and plain entries in an `e1-text` row are refused.
pub fn files_from_wire(
    encoding: Option<&Value>,
    files: BTreeMap<String, Value>,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let encoding = FilesEncoding::parse(encoding)?;
    files
        .into_iter()
        .map(|(path, value)| {
            let Value::String(value) = value else {
                bail!("{INVALID_ENCODING}: a file value isn't a string");
            };
            let bytes = match encoding {
                FilesEncoding::E1Text if is_envelope(&path) && sealed_value(&value) => {
                    value.into_bytes()
                }
                FilesEncoding::E1Text => {
                    bail!("{INVALID_ENCODING}: an e1-text row has a file that isn't sealed")
                }
                FilesEncoding::Base64 => STANDARD
                    .decode(value)
                    .map_err(|_| anyhow!("{INVALID_ENCODING}: a base64 row has invalid base64"))?,
            };
            Ok((path, bytes))
        })
        .collect()
}

/// A skill row as a v2 response carries it (`skills[]`, `skill`).
#[derive(Debug, Deserialize)]
pub struct WireSkill {
    scope: Scope,
    #[serde(default)]
    project: String,
    name: String,
    version: i64,
    files: BTreeMap<String, Value>,
    #[serde(default)]
    files_encoding: Option<Value>,
    content_hash: String,
    source_agent: String,
    source_machine: String,
    created_at: i64,
    #[serde(default)]
    deleted: bool,
    #[serde(default)]
    seq: i64,
}

impl WireSkill {
    /// The row as a `Skill`: the same bytes the old wire carried.
    pub fn into_skill(self) -> Result<Skill> {
        let Self {
            scope,
            project,
            name,
            version,
            files,
            files_encoding,
            content_hash,
            source_agent,
            source_machine,
            created_at,
            deleted,
            seq,
        } = self;
        let files = files_from_wire(files_encoding.as_ref(), files)
            .map_err(|e| e.context(format!("skill {name} v{version}")))?;
        Ok(Skill {
            scope,
            project,
            name,
            version,
            files,
            content_hash,
            source_agent,
            source_machine,
            created_at,
            deleted,
            seq,
        })
    }
}

/// A successful v2 response must say `wire_version: 2`.
pub fn check_version(version: Option<u64>) -> Result<()> {
    match version {
        Some(WIRE_VERSION) => Ok(()),
        Some(other) => bail!("skill wire version {other}, where 2 was expected"),
        None => bail!("not a skill wire v2 response (no wire_version)"),
    }
}

#[cfg(test)]
#[path = "skill_wire_tests.rs"]
mod tests;
