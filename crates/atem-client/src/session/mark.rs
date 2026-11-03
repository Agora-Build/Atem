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
    pub fn valid(&self) -> bool {
        is_opaque_id(&self.mark_id)
            && self.url.len() <= 2048
            && self.title.len() <= 512
            && self.screenshot.valid()
            && self.annotations.len() <= 128
            && self
                .annotations
                .iter()
                .all(|a| a.tool.len() <= 32 && a.text.len() <= 1024 && a.x <= 16384 && a.y <= 16384)
            && self.render().len() <= 16 * 1024
            && !self
                .render()
                .chars()
                .any(|c| c.is_control() && c != '\n' && c != '\t')
    }

    pub fn render(&self) -> String {
        let mut prompt = format!(
            "[Chisel/mark {}]\nImplement the UI changes indicated by the annotated screenshot.\nPage URL: {}\nPage title: {}\nScreenshot attachment: {} (sha256 {})\n",
            self.mark_id,
            self.url,
            self.title,
            self.screenshot.attachment_id,
            self.screenshot.digest
        );
        for (i, a) in self.annotations.iter().enumerate() {
            prompt.push_str(&format!(
                "{}. [{}] at ({}, {}): {}\n",
                i + 1,
                a.tool,
                a.x,
                a.y,
                a.text
            ));
        }
        prompt
    }
}
