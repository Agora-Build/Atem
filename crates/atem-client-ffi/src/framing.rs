//! The prompt framing (delegated host-work design III.2) over
//! `atem_client::session::framing`: what an app needs of it, and nothing
//! the host decides.
//!
//! The host renders every prompt around sender text, with a tag drawn after
//! the sender's text is fixed; a client never renders one. What a client has
//! is:
//!
//! - [`framing_escape`] and [`framing_folds_to_marker`]: how the sender's
//!   text will be escaped (a `|` before each line that folds to Atem's
//!   marker `[atem`), for a preview or a check;
//! - [`framing_checked_len`]: a sender's preflight of a task's rendered
//!   size, from the task's complete inputs, before it enqueues it or
//!   publishes a message (a size-only check: the host is authoritative);
//! - [`framing_unicode_version`]: the Unicode version of all the folding
//!   data (a build with other data would escape other lines).
//!
//! With the `test-vectors` feature only (never in a shipped package),
//! [`framing_render_for_vectors`] renders a prompt with a chosen tag so the
//! conformance suites can check the shared vectors byte for byte.
use atem_client::session::framing;
use atem_client::session::host_work::ContextSnapshot;
use atem_client::session::mark::MarkTask;

use crate::encoding::strict;
use crate::error::{AtemError, Result};

record! {
    /// A sender's text as it goes into a counted block.
    pub struct FramingEscaped {
        /// The text with a `|` in front of every line that needs one.
        pub escaped: String,
        /// How many bars were added (`escaped` is that many bytes longer).
        pub bars_added: u32,
    }
}

/// The Unicode version (`major.minor.patch`) of all the folding data:
/// normalization, general categories, confusables, the default lowercase
/// mapping and White_Space. Other data would escape other lines, so the
/// shared vectors pin it.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn framing_unicode_version() -> String {
    let (major, minor, patch) = framing::UNICODE_VERSION;
    format!("{major}.{minor}.{patch}")
}

/// The sender's `text` as it goes into a counted block: a `|` in front of
/// every line (a line ends at LF, CR, VT, FF, NEL, U+2028 or U+2029) that,
/// after the `|`s it already starts with, folds to Atem's marker. Nothing
/// else changes.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn framing_escape(text: String) -> FramingEscaped {
    let escaped = framing::escape(&text);
    let bars_added = u32::try_from(escaped.len() - text.len()).unwrap_or(u32::MAX);
    FramingEscaped {
        escaped,
        bars_added,
    }
}

/// Whether one `line` folds to Atem's marker (III.2's folding: Cf dropped,
/// NFKC, lowercase, the UTS #39 skeleton, three forms; after leading white
/// space). The line is taken as it is: the escaping tests it after the
/// `|`s it starts with, so strip those first to mirror it.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn framing_folds_to_marker(line: String) -> bool {
    framing::folds_to_marker(&line)
}

/// A task's rendered size, for a sender's preflight before it enqueues
/// (`work_enqueue`) or publishes a message (`message_publish`): the exact
/// size of the framed `text`, `mark` and `context` blocks with the longest
/// first and last lines any sender, route or message gets, and no
/// screenshot lines. It calls the shared `framing::checked_len`, the
/// calculation the host makes.
///
/// **Size only.** It checks nothing but the size: not a snapshot's digest
/// against its text, an id, a kind's use or any other limit. The host stays
/// authoritative; this is a preflight.
///
/// The inputs are the complete task, not a byte count: each snapshot adds
/// its own block (its kind, id, version, digest and provenance lines) and
/// its own escaping, so equal text bytes in different snapshots render to
/// different sizes. `mark_json` is a host-work `MarkTask` (`None`: no mark),
/// `context_json` a JSON array of host-work `ContextSnapshot`s (`[]`: none);
/// both strict JSON of exactly those shapes (else `Invalid`:
/// `not_strict_json`, which includes input over 1 MiB, or `malformed`).
///
/// Compare the result with the task's bound: 32,768 bytes, or 28,672 (that
/// minus a 4,096-byte reserve for the screenshot lines added at dispatch)
/// when the task has attachments. **A message with a mark always has one,
/// its screenshot, so a mark's bound is 28,672, never 32,768.** The host
/// compares the same number in `work_enqueue` (the task's own attachments)
/// and in `message_publish`, where each agent recipient's task is the
/// message's text and context plus the mark, with the mark's screenshot as
/// its one attachment. `work_enqueue` measures its task with no mark. Above
/// 32,768 the value is only a lower bound: once the raw bytes alone are over
/// it, nothing is escaped.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn framing_checked_len(
    text: String,
    mark_json: Option<String>,
    context_json: String,
) -> Result<u64> {
    let mark = mark_json
        .map(|json| {
            serde_json::from_value::<MarkTask>(strict(&json)?)
                .map_err(|e| AtemError::malformed(&format!("mark: {e}")))
        })
        .transpose()?;
    let context = serde_json::from_value::<Vec<ContextSnapshot>>(strict(&context_json)?)
        .map_err(|e| AtemError::malformed(&format!("context: {e}")))?;
    Ok(framing::checked_len(&text, mark.as_ref(), &context) as u64)
}

#[cfg(feature = "test-vectors")]
mod vectors {
    use atem_client::session::attachments::Attachment;
    use atem_client::session::framing::{Closing, Header, Screenshot, Snapshots, Tag, TaskPrompt};
    use serde_json::Value;

    use super::*;

    fn bad(what: &str) -> AtemError {
        AtemError::malformed(what)
    }

    fn string<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
        v.get(key)
            .and_then(Value::as_str)
            .ok_or_else(|| bad(&format!("{key} is a string")))
    }

    fn optional<'a>(v: &'a Value, key: &str) -> Result<Option<&'a str>> {
        match v.get(key) {
            None => Ok(None),
            Some(Value::String(s)) => Ok(Some(s)),
            Some(_) => Err(bad(&format!("{key} is a string"))),
        }
    }

    fn required<'a>(v: &'a Value, key: &str) -> Result<&'a Value> {
        v.get(key).ok_or_else(|| bad(&format!("{key} is missing")))
    }

    /// Renders one prompt of the vectors' `prompts[].input` shape
    /// (`header`, `text`, `mark`?, `context`, `snapshots`, `screenshots`?,
    /// `closing`?) with the tag of `tag_bits` (its low 60 bits, most
    /// significant first, as 12 Crockford base32 characters): the exact
    /// bytes the host would render, for the conformance suites. Never in a
    /// shipped package: a client never renders a prompt itself (III.2).
    #[cfg_attr(feature = "uniffi", uniffi::export)]
    pub fn framing_render_for_vectors(input_json: String, tag_bits: u64) -> Result<String> {
        let input = strict(&input_json)?;
        let h = required(&input, "header")?;
        let header = match string(h, "kind")? {
            "task" => Header::Task {
                task_id: string(h, "task_id")?,
                workflow_id: string(h, "workflow_id")?,
                sender: string(h, "sender")?,
                session: optional(h, "session")?,
                route_id: string(h, "route_id")?,
                message_id: optional(h, "message_id")?,
            },
            "result" => Header::Result {
                task_id: string(h, "task_id")?,
                sender: string(h, "sender")?,
                session: string(h, "session")?,
            },
            _ => return Err(bad("header kind is task or result")),
        };
        let mark = input
            .get("mark")
            .map(|m| {
                serde_json::from_value::<MarkTask>(m.clone())
                    .map_err(|e| bad(&format!("mark: {e}")))
            })
            .transpose()?;
        let context =
            serde_json::from_value::<Vec<ContextSnapshot>>(required(&input, "context")?.clone())
                .map_err(|e| bad(&format!("context: {e}")))?;
        let shots = match input.get("screenshots") {
            None => Vec::new(),
            Some(Value::Array(items)) => items
                .iter()
                .map(|s| {
                    let attachment =
                        serde_json::from_value::<Attachment>(required(s, "attachment")?.clone())
                            .map_err(|e| bad(&format!("attachment: {e}")))?;
                    Ok((attachment, string(s, "path")?.to_string()))
                })
                .collect::<Result<Vec<_>>>()?,
            Some(_) => return Err(bad("screenshots is an array")),
        };
        let screenshots: Vec<Screenshot> = shots
            .iter()
            .map(|(attachment, path)| Screenshot { attachment, path })
            .collect();
        let closing = input
            .get("closing")
            .map(|c| match string(c, "kind")? {
                "answer" => Ok(Closing::Answer {
                    task_id: string(c, "task_id")?,
                }),
                "complete" => Ok(Closing::Complete {
                    task_id: string(c, "task_id")?,
                }),
                _ => Err(bad("closing kind is answer or complete")),
            })
            .transpose()?;
        let snapshots = match string(&input, "snapshots")? {
            "from_sender" => Snapshots::FromSender,
            "read_back" => Snapshots::ReadBack,
            _ => return Err(bad("snapshots is from_sender or read_back")),
        };
        let prompt = TaskPrompt {
            header,
            text: string(&input, "text")?,
            mark: mark.as_ref(),
            context: &context,
            snapshots,
            screenshots: &screenshots,
            closing,
        }
        .prompt()?;
        Ok(prompt.render(&Tag::from_bits(tag_bits))?)
    }
}

#[cfg(feature = "test-vectors")]
pub use vectors::framing_render_for_vectors;
