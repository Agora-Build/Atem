//! The prompt framing through the bindings' exports (delegated host-work
//! design III.2, acceptance test VII.C 40): the escaping, the marker check,
//! the Unicode version and the preflight size check give what the vectors
//! say, and (feature `test-vectors`) the rendering reproduces
//! `prompt-framing-v1.json` byte for byte. The Swift, Kotlin and JS suites
//! run the same vectors against the same exports.
//!
//! The vectors are `designs/protocol/fixtures/host-work/prompt-framing-v1.json`
//! (pinned in a cross-team agreement; this file never changes it) and
//! `framing-size-v1.json` (the preflight's complete-input cases).
use atem_client::session::framing as core;
use atem_client::session::host_work::{ContextKind, ContextSnapshot, digest};
use atem_client::session::wire::MAX_PROMPT_BYTES;
use atem_client_ffi::AtemError;
use atem_client_ffi::framing::{
    FramingEscaped, framing_checked_len, framing_escape, framing_folds_to_marker,
    framing_unicode_version,
};
use serde_json::{Value, json};

fn prompt_vectors() -> Value {
    serde_json::from_str(include_str!(
        "../../../designs/protocol/fixtures/host-work/prompt-framing-v1.json"
    ))
    .unwrap()
}

fn size_vectors() -> Value {
    serde_json::from_str(include_str!(
        "../../../designs/protocol/fixtures/host-work/framing-size-v1.json"
    ))
    .unwrap()
}

fn str_of<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key].as_str().unwrap_or_else(|| panic!("{key}: {v}"))
}

fn snapshot(kind: ContextKind, id: &str, version: u64, text: &str) -> ContextSnapshot {
    ContextSnapshot {
        kind,
        id: id.into(),
        version,
        digest: digest(text.as_bytes()),
        text: text.into(),
    }
}

fn context_json(context: &[ContextSnapshot]) -> String {
    serde_json::to_string(context).unwrap()
}

/// `framing_checked_len` of a text, an optional mark (JSON) and snapshots.
fn checked(text: &str, mark: Option<&Value>, context: &[ContextSnapshot]) -> u64 {
    framing_checked_len(
        text.into(),
        mark.map(Value::to_string),
        context_json(context),
    )
    .unwrap()
}

fn code_of(e: AtemError) -> String {
    match e {
        AtemError::Invalid { code, .. } => code,
        other => panic!("not an Invalid error: {other}"),
    }
}

#[test]
fn escape_cases_match_vectors() {
    let file = prompt_vectors();
    let cases = file["escape"].as_array().unwrap();
    assert_eq!(cases.len(), 57);
    for case in cases {
        let FramingEscaped {
            escaped,
            bars_added,
        } = framing_escape(str_of(case, "text").into());
        assert_eq!(escaped, str_of(case, "escaped"), "{}", case["name"]);
        assert_eq!(
            u64::from(bars_added),
            case["bars_added"].as_u64().unwrap(),
            "{}",
            case["name"]
        );
    }
}

/// The marker check on a line agrees with where the escaping puts a bar:
/// per line of each case (after the bars it already starts with), and in
/// total.
#[test]
fn folds_to_marker_agrees_with_the_escape_cases() {
    let file = prompt_vectors();
    for case in file["escape"].as_array().unwrap() {
        let text = str_of(case, "text");
        let folding = text
            .split(core::is_line_break)
            .filter(|line| framing_folds_to_marker(line.trim_start_matches('|').into()))
            .count();
        assert_eq!(
            folding as u64,
            case["bars_added"].as_u64().unwrap(),
            "{}",
            case["name"]
        );
    }
    for line in [
        "[atem]",
        "  [ATEM x",
        "[\u{410}\u{422}\u{415}\u{41c}]",
        "[a\u{fe0f}tem]",
    ] {
        assert!(framing_folds_to_marker(line.into()), "{line:?}");
    }
    for line in ["", "x[atem]", "[ atem]", "|[atem]", "[atom]"] {
        assert!(!framing_folds_to_marker(line.into()), "{line:?}");
    }
}

#[test]
fn unicode_version_is_pinned() {
    let file = prompt_vectors();
    assert_eq!(framing_unicode_version(), str_of(&file, "unicode_version"));
    assert_eq!(framing_unicode_version(), "18.0.0");
}

#[test]
fn checked_len_matches_size_section() {
    let file = prompt_vectors();
    let size = &file["size"];
    let vault = |id: &str, v: u64, n: usize| snapshot(ContextKind::Vault, id, v, &"c".repeat(n));
    // A typical task: 5,120 bytes of context, a 1,024-byte prompt.
    let (text, context) = ("t".repeat(1024), vec![vault("api-contract", 3, 5120)]);
    assert_eq!(
        checked(&text, None, &context) - 1024 - 5120,
        size["typical"]["checked_atem_bytes"].as_u64().unwrap()
    );
    // The worst: eight 1,000-byte contexts with 128-byte ids and 16-digit
    // versions, a 1,000-byte prompt.
    let worst: Vec<ContextSnapshot> = (0..8)
        .map(|i| {
            snapshot(
                ContextKind::Memory,
                &format!("{i}{}", "m".repeat(127)),
                9_007_199_254_740_991,
                &"c".repeat(1000),
            )
        })
        .collect();
    let text = "t".repeat(1000);
    assert_eq!(
        checked(&text, None, &worst) - 1000 - 8 * 1000,
        size["worst"]["checked_atem_bytes"].as_u64().unwrap()
    );
    // The same with a mark (the vectors' own, with a 128-byte mark id).
    let mut mark = file["prompts"]
        .as_array()
        .unwrap()
        .iter()
        .find_map(|p| p["input"].get("mark"))
        .unwrap()
        .clone();
    mark["mark_id"] = json!("k".repeat(128));
    assert_eq!(
        checked(&text, Some(&mark), &worst),
        size["worst_mark"]["checked_bytes"].as_u64().unwrap()
    );
    // At the bound: one byte more is over it.
    let n = size["at_bound"]["context_bytes"].as_u64().unwrap() as usize;
    let at = |n: usize| {
        checked(
            "x",
            None,
            &[snapshot(ContextKind::Vault, "c", 1, &"y".repeat(n))],
        )
    };
    assert_eq!(at(n), size["at_bound"]["checked_len"].as_u64().unwrap());
    assert_eq!(at(n), MAX_PROMPT_BYTES as u64);
    assert_eq!(at(n + 1), MAX_PROMPT_BYTES as u64 + 1);
}

#[test]
fn checked_len_matches_size_cases() {
    let file = size_vectors();
    assert_eq!(file["max_prompt_bytes"], MAX_PROMPT_BYTES);
    let cases = file["cases"].as_array().unwrap();
    assert!(cases.len() >= 10);
    for case in cases {
        let mark = case.get("mark").map(Value::to_string);
        let got = framing_checked_len(
            str_of(case, "text").into(),
            mark,
            case["context"].to_string(),
        )
        .unwrap_or_else(|e| panic!("{}: {e}", case["name"]));
        assert_eq!(
            got,
            case["checked_len"].as_u64().unwrap(),
            "{}",
            case["name"]
        );
    }
}

/// What the preflight takes is exactly the host-work shapes: anything else
/// is refused, never read loosely.
#[test]
fn checked_len_refuses_inputs_that_are_not_host_work_shapes() {
    let ok_context = context_json(&[snapshot(ContextKind::Vault, "a", 1, "x")]);
    let ok_mark = json!({"mark_id": "mark_1", "url": "u", "title": "t",
        "screenshot": {"attachment_id": "0b1c2d3e-4f50-4617-8829-3a4b5c6d7e8f",
            "digest": digest(b"png"), "size": 3, "media_type": "image/png"},
        "annotations": []});
    let run = |mark: Option<&str>, context: &str| {
        framing_checked_len("t".into(), mark.map(str::to_string), context.into())
    };
    assert!(run(None, "[]").is_ok());
    assert!(run(None, &ok_context).is_ok());
    assert!(run(Some(&ok_mark.to_string()), "[]").is_ok());
    // Not JSON, or not strict JSON (a duplicate key, a float).
    assert_eq!(code_of(run(None, "[").unwrap_err()), "not_strict_json");
    let dup = ok_context.replace("\"id\":\"a\"", "\"id\":\"a\",\"id\":\"b\"");
    assert_ne!(dup, ok_context);
    assert_eq!(code_of(run(None, &dup).unwrap_err()), "not_strict_json");
    let float = ok_context.replace("\"version\":1", "\"version\":1.5");
    assert_ne!(float, ok_context);
    assert_eq!(code_of(run(None, &float).unwrap_err()), "not_strict_json");
    // Over the 1 MiB the bindings parse is `not_strict_json` too (the strict
    // parser's size bound), for the context and for the mark.
    let big = format!("[\"{}\"]", "x".repeat(1 << 20));
    assert_eq!(code_of(run(None, &big).unwrap_err()), "not_strict_json");
    let big_mark = format!("\"{}\"", "x".repeat(1 << 20));
    assert_eq!(
        code_of(run(Some(&big_mark), "[]").unwrap_err()),
        "not_strict_json"
    );
    // Strict JSON of another shape: the context isn't an array, a snapshot
    // has an unknown field or lacks one or has an unknown kind, the mark
    // isn't a mark, `null` is no absent mark.
    for context in [
        "{}",
        "null",
        r#"[{"kind":"vault","id":"a","version":1,"digest":"d"}]"#,
        r#"[{"kind":"vault","id":"a","version":1,"digest":"d","text":"x","extra":1}]"#,
        r#"[{"kind":"notes","id":"a","version":1,"digest":"d","text":"x"}]"#,
    ] {
        assert_eq!(
            code_of(run(None, context).unwrap_err()),
            "malformed",
            "{context}"
        );
    }
    for mark in ["null", "{}", "[]", r#"{"mark_id":"m"}"#] {
        assert_eq!(
            code_of(run(Some(mark), "[]").unwrap_err()),
            "malformed",
            "{mark}"
        );
    }
    let mut extra = ok_mark.clone();
    extra["extra"] = json!(1);
    assert_eq!(
        code_of(run(Some(&extra.to_string()), "[]").unwrap_err()),
        "malformed"
    );
}

#[cfg(feature = "test-vectors")]
mod rendering {
    use super::*;
    use atem_client_ffi::framing::framing_render_for_vectors;

    /// The 60 bits of a tag as written (`XXXX-XXXX-XXXX`, Crockford base32).
    fn bits_of(tag: &str) -> u64 {
        const CROCKFORD: &str = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
        tag.chars()
            .filter(|c| *c != '-')
            .fold(0, |bits, c| bits << 5 | CROCKFORD.find(c).unwrap() as u64)
    }

    #[test]
    fn render_matches_vectors() {
        let file = prompt_vectors();
        let tag = str_of(&file, "tag");
        // The tag's bits give the tag back (the vectors' own rule).
        assert_eq!(core::Tag::from_bits(bits_of(tag)).as_str(), tag);
        let prompts = file["prompts"].as_array().unwrap();
        assert_eq!(prompts.len(), 9);
        for case in prompts {
            let rendered = framing_render_for_vectors(case["input"].to_string(), bits_of(tag))
                .unwrap_or_else(|e| panic!("{}: {e}", case["name"]));
            assert_eq!(rendered, str_of(case, "rendered"), "{}", case["name"]);
            assert_eq!(rendered.len() as u64, case["bytes"].as_u64().unwrap());
        }
    }

    /// Every tag of the vectors renders the prompt with that tag, and only
    /// on Atem's own lines (the sender's text is not touched, even where it
    /// holds the vectors' tag).
    #[test]
    fn render_takes_the_tag_from_its_bits() {
        let file = prompt_vectors();
        let case = &file["prompts"][0];
        let old = format!("[atem {}] ", str_of(&file, "tag"));
        let rendered = str_of(case, "rendered");
        for tag in file["tags"].as_array().unwrap() {
            let new = format!("[atem {}] ", str_of(tag, "tag"));
            let expected: Vec<String> = rendered
                .split('\n')
                .map(|line| match line.strip_prefix(&old) {
                    Some(rest) => format!("{new}{rest}"),
                    None => line.to_string(),
                })
                .collect();
            let bits = u64::from_str_radix(str_of(tag, "bits"), 16).unwrap();
            let got = framing_render_for_vectors(case["input"].to_string(), bits).unwrap();
            assert_eq!(got, expected.join("\n"), "{}", str_of(tag, "bits"));
        }
    }

    #[test]
    fn render_refuses_what_the_core_refuses_and_what_is_no_input() {
        let file = prompt_vectors();
        let input = file["prompts"][2]["input"].clone();
        let render = |input: &Value| framing_render_for_vectors(input.to_string(), 1);
        assert!(render(&input).is_ok());
        // A snapshot whose text doesn't match its digest is never rendered.
        let mut tampered = input.clone();
        tampered["context"][0]["text"] = json!("not what the digest says");
        assert_eq!(code_of(render(&tampered).unwrap_err()), "malformed");
        // An input that isn't the vectors' shape.
        for key in ["header", "text", "context", "snapshots"] {
            let mut missing = input.clone();
            missing.as_object_mut().unwrap().remove(key);
            assert_eq!(code_of(render(&missing).unwrap_err()), "malformed", "{key}");
        }
        let mut kind = input.clone();
        kind["header"]["kind"] = json!("notice");
        assert_eq!(code_of(render(&kind).unwrap_err()), "malformed");
        let mut snapshots = input.clone();
        snapshots["snapshots"] = json!("trusted");
        assert_eq!(code_of(render(&snapshots).unwrap_err()), "malformed");
        assert_eq!(
            code_of(framing_render_for_vectors("[".into(), 1).unwrap_err()),
            "not_strict_json"
        );
        // A sender longer than the longest one would break the size check.
        let mut sender = input.clone();
        sender["header"]["sender"] = json!("x".repeat(core::MAX_SENDER_BYTES + 1));
        assert_eq!(code_of(render(&sender).unwrap_err()), "malformed");
    }
}
