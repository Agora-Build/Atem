//! Test only: the Station's skill file transport, as Astation's
//! `designs/protocol/skill-file-wire.md` (Astation PR #76 at 89a2d50)
//! defines it: in an `e1-text` row every path is a sealed envelope and
//! every value one or `""` (an empty file, never sealed); `base64` rows
//! carry the bytes. Fake relays keep their rows in the stored form
//! (`Skill`'s own serde: base64 files) and translate at the skill routes,
//! as the Station does. Written apart from the client's `skill_wire` (its
//! own envelope check), so each side checks the other.
//!
//! Versions (`Versioning::Kept`, the contract's compare-and-set): a push
//! carries `skill.version = base_version + 1` and is stored at exactly that
//! version only when its base is the skill's latest version, tombstones
//! and purged records included; otherwise the op answers
//! `version_conflict` with `current_version`, and nothing is stored.
//! `Versioning::Renumbered` models the Station before it, which stored
//! every push as `max(version) + 1` (the regression case).
//!
//! A batch is refused as the Station refuses it, in its order: `ops` not
//! an array (400 `invalid batch`), more than 16 ops (413), a missing,
//! unknown or non-string files encoding (400 `UNSUPPORTED`), malformed
//! files (400 `INVALID`), a normalized body over 16 MiB (413), then an
//! unknown op or one missing a field (400 `invalid batch`). Not modelled:
//! the 16 MiB bound on the body as received (the fake relays get it
//! parsed), and authentication.

use crate::memory::model::Skill;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Map, Value, json};

/// The Station's answers (HTTP 400) to a batch whose files encoding is
/// missing, unknown or not a string, or whose files are malformed.
pub(crate) const UNSUPPORTED: &str = "unsupported skill files encoding; update Atem";
pub(crate) const INVALID: &str = "invalid skill files encoding";

/// The Station's bounds on a skills batch (`SKILLS_BATCH_BODY_LIMIT`,
/// `SKILLS_BATCH_MAX_OPS`).
pub(crate) const BODY_LIMIT: usize = 16 * 1024 * 1024;
pub(crate) const MAX_OPS: usize = 16;

/// How the Station numbers a skill push.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Versioning {
    /// At exactly the version the push carries (sealed under), or a
    /// `version_conflict` when that version exists: nothing stored.
    #[default]
    Kept,
    /// As the Station deployed before Astation PR #76 (`knowledge_store.rs`
    /// on Astation main at d678e9c, both stores): `max(version) + 1` over
    /// every version, tombstones included, whatever the push carries, with
    /// `superseded_concurrent` when its base is below the latest live
    /// (non-deleted) version.
    Renumbered,
}

/// The largest version the Station accepts (JavaScript's safe integers).
pub(crate) const MAX_SKILL_VERSION: i64 = 9_007_199_254_740_991;

/// Where a push of the skill whose stored versions are `existing`
/// (`(version, deleted)`, tombstones and purged records included) goes:
/// `Ok((version, superseded_concurrent))`, or `Err` with the per-op answer
/// (`invalid skill version`, or `version_conflict` with `current_version`).
pub(crate) fn push_version(
    versioning: Versioning,
    push: &Value,
    existing: impl IntoIterator<Item = (i64, bool)>,
) -> Result<(i64, bool), Value> {
    let (mut current, mut live) = (0, 0);
    for (version, deleted) in existing {
        current = current.max(version);
        if !deleted {
            live = live.max(version);
        }
    }
    let (version, base) = (
        push["skill"]["version"].as_i64(),
        push["base_version"].as_i64(),
    );
    match versioning {
        Versioning::Kept => {
            let (Some(version), Some(base)) = (version, base) else {
                return Err(json!({"ok": false, "error": "invalid skill version"}));
            };
            if !(0..MAX_SKILL_VERSION).contains(&base) || version != base + 1 {
                return Err(json!({"ok": false, "error": "invalid skill version"}));
            }
            if base != current {
                return Err(json!({
                    "ok": false, "error": "version_conflict", "current_version": current,
                }));
            }
            Ok((version, false))
        }
        Versioning::Renumbered => Ok((current + 1, base.unwrap_or(0) < live)),
    }
}

/// The Station's `/api/skills/version` answer for `stored` (one stored
/// row, if any): the row as it serves it, 410 for a purged one, else 404.
pub(crate) fn version_answer(stored: Option<&Skill>, purged: bool) -> (u16, Value) {
    match stored {
        Some(_) if purged => (410, json!({"error": "skill version purged"})),
        Some(skill) => (200, json!({"skill": row(skill)})),
        None => (404, json!({"error": "no such skill version"})),
    }
}

/// Astation's `envelope_kid`: `e1`, a kid of 8 lowercase hex digits, and
/// standard base64 of at least a nonce and a tag (40 bytes).
pub(crate) fn envelope(text: &str) -> bool {
    let mut parts = text.splitn(3, '.');
    parts.next() == Some("e1")
        && parts.next().is_some_and(|kid| {
            kid.len() == 8
                && kid
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        && parts.next().is_some_and(|payload| {
            !payload.is_empty()
                && STANDARD
                    .decode(payload)
                    .is_ok_and(|bytes| bytes.len() >= 40)
        })
}

/// A `push.skill` or `rewrite` in its stored form: `files` as base64,
/// `files_encoding` gone. `Err` (`UNSUPPORTED` or `INVALID`) refuses the
/// whole batch.
pub(crate) fn normalize_files(row: &mut Value) -> Result<(), &'static str> {
    let sealed = match row.get("files_encoding").and_then(Value::as_str) {
        Some("e1-text") => true,
        Some("base64") => false,
        _ => return Err(UNSUPPORTED),
    };
    let files = row
        .get_mut("files")
        .and_then(Value::as_object_mut)
        .ok_or(INVALID)?;
    for (path, value) in files.iter_mut() {
        let text = value.as_str().ok_or(INVALID)?;
        if sealed {
            if !envelope(path) || !(text.is_empty() || envelope(text)) {
                return Err(INVALID);
            }
            *value = Value::String(STANDARD.encode(text));
        } else if STANDARD.decode(text).is_err() {
            return Err(INVALID);
        }
    }
    row.as_object_mut().ok_or(INVALID)?.remove("files_encoding");
    Ok(())
}

/// Every op of a batch in its stored form; one refusal refuses all.
pub(crate) fn normalize_ops(ops: &mut [Value]) -> Result<(), &'static str> {
    for op in ops {
        match op["op"].as_str() {
            Some("push") => normalize_files(op.get_mut("skill").ok_or(INVALID)?)?,
            Some("rewrite") => normalize_files(op)?,
            _ => {}
        }
    }
    Ok(())
}

/// A stored row as the Station serves it: `e1-text` when every path is an envelope
/// and every value one or empty, else `base64` (plain, binary, partly
/// migrated history).
pub(crate) fn encode_row(row: &mut Value) {
    let sealed: Option<Map<String, Value>> =
        row.get("files")
            .and_then(Value::as_object)
            .and_then(|files| {
                files
                    .iter()
                    .map(|(path, encoded)| {
                        let bytes = STANDARD.decode(encoded.as_str()?).ok()?;
                        let text = String::from_utf8(bytes).ok()?;
                        (envelope(path) && (text.is_empty() || envelope(&text)))
                            .then(|| (path.clone(), Value::String(text)))
                    })
                    .collect()
            });
    match sealed {
        Some(files) => {
            row["files"] = Value::Object(files);
            row["files_encoding"] = json!("e1-text");
        }
        None => row["files_encoding"] = json!("base64"),
    }
}

/// `skill` (stored form) as the Station serves it.
pub(crate) fn row(skill: &Skill) -> Value {
    let mut row = serde_json::to_value(skill).unwrap();
    encode_row(&mut row);
    row
}

/// A collection page of stored rows.
pub(crate) fn page<'a>(rows: impl IntoIterator<Item = &'a Skill>) -> Value {
    json!({"skills": rows.into_iter().map(row).collect::<Vec<_>>()})
}

/// Bytes written, none kept: a serialized size without the copy.
struct Counted(usize);

impl std::io::Write for Counted {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 += bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// An op the Station's `SkillOp` parses: a known `op` with its fields.
fn known_op(op: &Value) -> bool {
    let has = |fields: &[&str]| fields.iter().all(|field| op.get(*field).is_some());
    match op["op"].as_str() {
        Some("push") => op["skill"].is_object() && op["base_version"].is_i64(),
        Some("delete") | Some("purge") => has(&["scope", "name"]),
        Some("rewrite") => {
            has(&["scope", "name", "files", "content_hash"]) && op["version"].is_i64()
        }
        _ => false,
    }
}

/// A batch: every op is checked first, in the Station's order (a
/// refusal applies nothing), then `apply` gets each op in its stored form.
pub(crate) fn batch(body: &Value, mut apply: impl FnMut(&Value) -> Value) -> (u16, Value) {
    let refused = |status: u16, error: &str| (status, json!({"error": error}));
    let Some(ops) = body.get("ops").and_then(Value::as_array) else {
        return refused(400, "invalid batch");
    };
    if ops.len() > MAX_OPS {
        return refused(413, "too many ops");
    }
    let mut ops = ops.clone();
    if let Err(error) = normalize_ops(&mut ops) {
        return refused(400, error);
    }
    // Compact transport must not bypass the stored form's bound.
    let mut normalized = Counted(0);
    serde_json::to_writer(&mut normalized, &ops).unwrap();
    if normalized.0 + br#"{"ops":}"#.len() > BODY_LIMIT {
        return refused(413, "normalized request body too large");
    }
    if !ops.iter().all(known_op) {
        return refused(400, "invalid batch");
    }
    let results: Vec<Value> = ops.iter().map(&mut apply).collect();
    (200, json!({"results": results}))
}

/// `batch` for a fake relay that can't answer 400: a refusal panics.
pub(crate) fn batch_ok(body: &Value, apply: impl FnMut(&Value) -> Value) -> Value {
    match batch(body, apply) {
        (200, results) => results,
        (_, error) => panic!("the fake Station refused a batch: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope_of(marker: u8, bytes: usize) -> String {
        format!("e1.0123abcd.{}", STANDARD.encode(vec![marker; bytes]))
    }

    fn push(files: Value) -> Value {
        json!({"op": "push", "base_version": 0, "skill": {
            "scope": "global", "project": "", "name": "demo", "version": 1,
            "files_encoding": "e1-text", "files": files,
            "content_hash": format!("h1.0123abcd.{}", "a".repeat(64)),
            "source_agent": "test", "source_machine": "synthetic",
            "created_at": 1, "deleted": false, "seq": 0,
        }})
    }

    /// The Station's refusals, in its order, and nothing applied.
    #[test]
    fn a_batch_is_refused_as_the_station_refuses_it() {
        let valid = push(json!({envelope_of(1, 40): envelope_of(2, 40)}));
        let unsealed = push(json!({envelope_of(1, 40): "plaintext"}));
        let mut unencoded = valid.clone();
        unencoded["skill"]["files_encoding"] = json!("guess");
        let huge = push(json!({envelope_of(1, 40): envelope_of(2, 9_800_000)}));
        let cases = [
            (json!({}), 400, "invalid batch"),
            (json!({"ops": {}}), 400, "invalid batch"),
            (
                json!({"ops": vec![valid.clone(); MAX_OPS + 1]}),
                413,
                "too many ops",
            ),
            (json!({"ops": [valid.clone(), unsealed]}), 400, INVALID),
            (json!({"ops": [valid.clone(), unencoded]}), 400, UNSUPPORTED),
            // An unknown op is refused only after the encodings passed.
            (
                json!({"ops": [valid.clone(), {"op": "unknown"}]}),
                400,
                "invalid batch",
            ),
            (
                json!({"ops": [{"op": "delete", "scope": "global"}]}),
                400,
                "invalid batch",
            ),
            (
                json!({"ops": [huge]}),
                413,
                "normalized request body too large",
            ),
        ];
        for (body, status, error) in cases {
            let mut applied = 0;
            let answer = batch(&body, |_| {
                applied += 1;
                json!({"ok": true})
            });
            assert_eq!(answer, (status, json!({"error": error})), "{error}");
            assert_eq!(applied, 0, "{error}");
        }
        let answer = batch(&json!({"ops": vec![valid; MAX_OPS]}), |op| {
            assert_eq!(op["skill"].get("files_encoding"), None);
            json!({"ok": true})
        });
        assert_eq!(answer.0, 200);
        assert_eq!(answer.1["results"].as_array().unwrap().len(), MAX_OPS);
    }
}
