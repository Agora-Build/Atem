//! Screenshot bytes share the durable work store; prompts receive verified local files.
use super::host_work::Store;
use atem_client::session::attachments::{Attachment, AttachmentStatus, CHUNK_BYTES};
use atem_client::session::host_work::digest;
use rusqlite::{OptionalExtension, params};
use std::io::Write;
use std::path::PathBuf;

const MAX_CACHE_BYTES: u64 = 128 * 1024 * 1024;

// Chisel emits PNGs. Check the signature and bounded IHDR dimensions before
// exposing a file to an agent; decoding image pixels remains the agent's job.
fn valid_png(bytes: &[u8]) -> bool {
    if bytes.len() < 33
        || &bytes[..8] != b"\x89PNG\r\n\x1a\n"
        || bytes[8..12] != 13_u32.to_be_bytes()
        || &bytes[12..16] != b"IHDR"
    {
        return false;
    }
    let width = u32::from_be_bytes(bytes[16..20].try_into().unwrap());
    let height = u32::from_be_bytes(bytes[20..24].try_into().unwrap());
    (1..=16384).contains(&width)
        && (1..=16384).contains(&height)
        && u64::from(width) * u64::from(height) <= 40_000_000
}

impl Store {
    pub fn put_attachment(
        &self,
        owner: &str,
        attachment: &Attachment,
        offset: u64,
        chunk: &[u8],
    ) -> Result<AttachmentStatus, &'static str> {
        if !attachment.valid()
            || chunk.is_empty()
            || chunk.len() > CHUNK_BYTES
            || offset
                .checked_add(chunk.len() as u64)
                .is_none_or(|end| end > attachment.size)
        {
            return Err("invalid_request");
        }
        let tx = self.db.unchecked_transaction().map_err(|_| "busy")?;
        let old: Option<(String, Vec<u8>)> = tx
            .query_row(
                "SELECT descriptor,bytes FROM attachments WHERE owner=?1 AND id=?2",
                params![owner, attachment.attachment_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|_| "busy")?;
        let descriptor = serde_json::to_string(attachment).map_err(|_| "invalid_request")?;
        let mut bytes = if let Some((old_descriptor, bytes)) = old {
            if old_descriptor != descriptor {
                return Err("request_id_reused");
            }
            bytes
        } else {
            if offset != 0 {
                return Err("invalid_request");
            }
            let (count, reserved): (u64, u64) = tx
                .query_row(
                    "SELECT count(*),coalesce(sum(size),0) FROM attachments",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(|_| "busy")?;
            if count >= 256 || reserved + attachment.size > MAX_CACHE_BYTES {
                return Err("busy");
            }
            Vec::new()
        };
        if offset > bytes.len() as u64 {
            return Err("invalid_request");
        }
        if offset < bytes.len() as u64 {
            let start = offset as usize;
            if bytes.get(start..start + chunk.len()) != Some(chunk) {
                return Err("request_id_reused");
            }
        } else {
            bytes.extend_from_slice(chunk);
        }
        let ready = bytes.len() as u64 == attachment.size;
        if ready && (digest(&bytes) != attachment.digest || !valid_png(&bytes)) {
            return Err("invalid_request");
        }
        tx.execute(
            "INSERT INTO attachments(owner,id,descriptor,size,bytes) VALUES(?1,?2,?3,?4,?5)
             ON CONFLICT(owner,id) DO UPDATE SET bytes=excluded.bytes",
            params![
                owner,
                attachment.attachment_id,
                descriptor,
                attachment.size,
                bytes
            ],
        )
        .map_err(|_| "busy")?;
        tx.commit().map_err(|_| "busy")?;
        Ok(AttachmentStatus {
            attachment: attachment.clone(),
            received: bytes.len() as u64,
            ready,
        })
    }

    /// Rebuild the cache from authoritative bytes, also repairing deleted or
    /// edited cache files. No URL or sender-supplied filesystem path is opened.
    pub fn attachment_paths(
        &self,
        owner: &str,
        attachments: &[Attachment],
    ) -> anyhow::Result<Vec<PathBuf>> {
        let mut paths = Vec::new();
        if attachments.is_empty() {
            return Ok(paths);
        }
        anyhow::ensure!(
            super::host_work::valid_owner(owner),
            "invalid attachment owner"
        );
        let root = self.state.join("attachments");
        super::worker::private_dir(&root)?;
        let dir = root.join(owner);
        super::worker::private_dir(&dir)?;
        for attachment in attachments {
            anyhow::ensure!(attachment.valid(), "invalid attachment");
            let (descriptor, bytes): (String, Vec<u8>) = self.db.query_row(
                "SELECT descriptor,bytes FROM attachments WHERE owner=?1 AND id=?2",
                params![owner, attachment.attachment_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            anyhow::ensure!(
                serde_json::from_str::<Attachment>(&descriptor)? == *attachment
                    && bytes.len() as u64 == attachment.size
                    && digest(&bytes) == attachment.digest
                    && valid_png(&bytes),
                "attachment is incomplete or invalid"
            );
            let path = dir.join(format!("{}.png", attachment.attachment_id));
            let mut file = tempfile::NamedTempFile::new_in(&dir)?;
            file.write_all(&bytes)?;
            file.as_file().sync_all()?;
            file.persist(&path)?;
            paths.push(path);
        }
        std::fs::File::open(dir)?.sync_all()?;
        Ok(paths)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn png() -> Vec<u8> {
        base64::engine::general_purpose::STANDARD.decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aS1kAAAAASUVORK5CYII="
        ).unwrap()
    }

    fn reference(bytes: &[u8]) -> Attachment {
        Attachment {
            attachment_id: uuid::Uuid::new_v4().to_string(),
            digest: digest(bytes),
            size: bytes.len() as u64,
            media_type: "image/png".into(),
        }
    }

    #[test]
    fn chunks_are_durable_idempotent_and_bound_to_the_sender_and_descriptor() {
        let dir = tempfile::tempdir().unwrap();
        let bytes = png();
        let a = reference(&bytes);
        let owner = digest(b"sender key");
        let store = Store::open(dir.path()).unwrap();
        let first = store.put_attachment(&owner, &a, 0, &bytes[..32]).unwrap();
        assert!(!first.ready);
        assert_eq!(
            first,
            store.put_attachment(&owner, &a, 0, &bytes[..32]).unwrap()
        );
        assert_eq!(
            store.put_attachment(&owner, &a, 0, &[0; 32]),
            Err("request_id_reused")
        );
        assert_eq!(
            store.put_attachment(&owner, &a, 40, &bytes[40..]),
            Err("invalid_request")
        );
        let mut changed = a.clone();
        changed.digest = digest(b"different");
        assert_eq!(
            store.put_attachment(&owner, &changed, 32, &bytes[32..]),
            Err("request_id_reused")
        );
        assert!(
            store
                .attachment_paths(&owner, std::slice::from_ref(&a))
                .is_err()
        );
        drop(store);
        let store = Store::open(dir.path()).unwrap();
        assert!(
            store
                .put_attachment(&owner, &a, 32, &bytes[32..])
                .unwrap()
                .ready
        );
        assert!(
            store
                .put_attachment(&owner, &a, 0, &bytes[..32])
                .unwrap()
                .ready
        );
        assert!(
            store
                .attachment_paths(&digest(b"other key"), std::slice::from_ref(&a))
                .is_err()
        );
        let paths = store
            .attachment_paths(&owner, std::slice::from_ref(&a))
            .unwrap();
        assert_eq!(std::fs::read(&paths[0]).unwrap(), bytes);
        // An agent's edits to a cache file cannot change a later prompt's artifact.
        std::fs::write(&paths[0], b"edited").unwrap();
        store.attachment_paths(&owner, &[a]).unwrap();
        assert_eq!(std::fs::read(&paths[0]).unwrap(), bytes);
    }

    #[test]
    fn screenshot_validation_refuses_corruption_paths_and_unbounded_dimensions() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let owner = digest(b"sender");
        let mut bytes = png();
        let a = reference(&bytes);
        bytes[40] ^= 1;
        assert_eq!(
            store.put_attachment(&owner, &a, 0, &bytes),
            Err("invalid_request")
        );
        bytes[16..20].copy_from_slice(&16385_u32.to_be_bytes());
        assert_eq!(
            store.put_attachment(&owner, &reference(&bytes), 0, &bytes),
            Err("invalid_request")
        );
        let mut bad = a.clone();
        bad.attachment_id = "../../evil".into();
        assert_eq!(
            store.put_attachment(&owner, &bad, 0, &png()),
            Err("invalid_request")
        );
        let mut bad = a.clone();
        bad.media_type = "image/svg+xml".into();
        assert_eq!(
            store.put_attachment(&owner, &bad, 0, &png()),
            Err("invalid_request")
        );
        let bytes = png();
        store.put_attachment(&owner, &a, 0, &bytes).unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(elsewhere.path(), dir.path().join("attachments")).unwrap();
        assert!(store.attachment_paths(&owner, &[a]).is_err());
        assert_eq!(std::fs::read_dir(elsewhere.path()).unwrap().count(), 0);
    }
}
