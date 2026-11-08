//! Test only: the Station's skill transport v2 adapter, as Astation's
//! `designs/protocol/skill-file-wire-v2.md` (commit 963c74b, Astation
//! PR #76) defines it, plus the empty-file rule that Astation's next pin
//! adds: in an `e1-text` row a value is a sealed envelope or `""` (an
//! empty file, never sealed). Fake relays keep their rows in the stored
//! form (`Skill`'s own serde: base64 files) and translate at the v2
//! routes, as the Station does. Written apart from the client's
//! `skill_wire` (its own envelope check), so each side checks the other.

use crate::memory::model::Skill;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Map, Value, json};

/// The Station's answer (HTTP 400) to a batch with a refused encoding.
pub(crate) const INVALID: &str = "invalid skill files encoding";

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

/// A v2 `push.skill` or `rewrite` in its stored form: `files` as base64,
/// `files_encoding` gone. `Err(INVALID)` refuses the whole batch.
pub(crate) fn normalize_files(row: &mut Value) -> Result<(), &'static str> {
    let sealed = match row.get("files_encoding").and_then(Value::as_str) {
        Some("e1-text") => true,
        Some("base64") => false,
        _ => return Err(INVALID),
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

/// Every op of a v2 batch in its stored form; one refusal refuses all.
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

/// A stored row as v2 serves it: `e1-text` when every path is an envelope
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

/// `skill` (stored form) as v2 serves it.
pub(crate) fn row(skill: &Skill) -> Value {
    let mut row = serde_json::to_value(skill).unwrap();
    encode_row(&mut row);
    row
}

/// A v2 collection page of stored rows.
pub(crate) fn page<'a>(rows: impl IntoIterator<Item = &'a Skill>) -> Value {
    json!({"wire_version": 2, "skills": rows.into_iter().map(row).collect::<Vec<_>>()})
}

/// A v2 batch: every op is checked first (400 and nothing applied on a
/// refusal), then `apply` gets each op in its stored form.
pub(crate) fn batch(body: &Value, mut apply: impl FnMut(&Value) -> Value) -> (u16, Value) {
    let mut ops = body["ops"].as_array().cloned().unwrap_or_default();
    if normalize_ops(&mut ops).is_err() {
        return (400, json!({"error": INVALID}));
    }
    let results: Vec<Value> = ops.iter().map(&mut apply).collect();
    (200, json!({"wire_version": 2, "results": results}))
}

/// `batch` for a fake relay that can't answer 400: a refusal panics.
pub(crate) fn batch_ok(body: &Value, apply: impl FnMut(&Value) -> Value) -> Value {
    match batch(body, apply) {
        (200, results) => results,
        (_, error) => panic!("the fake Station refused a batch: {error}"),
    }
}
