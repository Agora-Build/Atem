//! Bounded screenshot transfer inside an admitted encrypted channel.
use serde::{Deserialize, Serialize};

use super::wire::{is_digest, is_uuid_v4};

pub const FEATURE: &str = "host.attachments";
pub const MAX_BYTES: u64 = 8 * 1024 * 1024;
pub const CHUNK_BYTES: usize = 96 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attachment {
    pub attachment_id: String,
    pub digest: String,
    pub size: u64,
    pub media_type: String,
}

impl Attachment {
    pub fn valid(&self) -> bool {
        is_uuid_v4(&self.attachment_id)
            && is_digest(&self.digest)
            && (33..=MAX_BYTES).contains(&self.size)
            && self.media_type == "image/png"
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachmentStatus {
    pub attachment: Attachment,
    pub received: u64,
    pub ready: bool,
}

impl AttachmentStatus {
    pub fn valid(&self) -> bool {
        self.attachment.valid()
            && self.received <= self.attachment.size
            && self.ready == (self.received == self.attachment.size)
    }
}
