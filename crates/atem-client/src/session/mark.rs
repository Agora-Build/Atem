//! Chisel annotations become ordinary message tasks, with a screenshot reference.
use serde::{Deserialize, Serialize};

use super::{attachments::Attachment, wire::is_opaque_id};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Annotation {
    pub tool: String,
    pub text: String,
    pub x: u32,
    pub y: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MarkTask {
    pub mark_id: String,
    pub url: String,
    pub title: String,
    pub screenshot: Attachment,
    pub annotations: Vec<Annotation>,
}

impl MarkTask {
    /// The rendered mark (Atem's mark line and its counted block, delegated
    /// host-work design III.2) is at most 16 KiB, and its text has no
    /// control characters other than newline and tab.
    pub fn valid(&self) -> bool {
        let text = self.block_text();
        is_opaque_id(&self.mark_id)
            && self.url.len() <= 2048
            && self.title.len() <= 512
            && self.screenshot.valid()
            && self.annotations.len() <= 128
            && self
                .annotations
                .iter()
                .all(|a| a.tool.len() <= 32 && a.text.len() <= 1024 && a.x <= 16384 && a.y <= 16384)
            && !text
                .chars()
                .any(|c| c.is_control() && c != '\n' && c != '\t')
            && text.len() <= MAX_RENDERED_BYTES
            && super::framing::mark_len(self, &text) <= MAX_RENDERED_BYTES
    }

    /// The sender's part of a mark, the text of its counted block: its URL,
    /// title and annotations, one per line. Atem's line before the block
    /// names the mark (`framing::mark_line`); the screenshot is a line of
    /// Atem's once verified at dispatch.
    pub fn block_text(&self) -> String {
        let mut text = format!("Page URL: {}\nPage title: {}\n", self.url, self.title);
        for (i, a) in self.annotations.iter().enumerate() {
            text.push_str(&format!(
                "{}. [{}] at ({}, {}): {}\n",
                i + 1,
                a.tool,
                a.x,
                a.y,
                a.text
            ));
        }
        text
    }
}

/// The bound on a rendered mark.
pub const MAX_RENDERED_BYTES: usize = 16 * 1024;
