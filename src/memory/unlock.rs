//! The CLI side of unlock and storage-key rotation: carries the key agent's
//! requests to the home Astation and Astation's answers back. The storage
//! key never passes through here in plain form. Every agent call runs on a
//! blocking thread (`key_agent::blocking`): the client's socket I/O must not
//! stall the runtime.
//! See designs/e2e-encryption.md "Unlock policy" and "Keys on disk (atem)".
// Task 10 wires these into `atem cred unlock` and `atem pair`; remove then.
#![allow(dead_code)]
use anyhow::{Context, Result, anyhow, bail};
use std::sync::Arc;
use std::time::Duration;

use crate::memory::device_keys::UnlockAuthKey;
use crate::memory::key_agent::{KeyAgentApi, blocking, build_unlock_request};
use crate::memory::statements::SignedWire;
use crate::memory::storage_key::{SealedDeviceKeys, StorageRotation, UnlockGrantWire};
use crate::memory::trust::TrustStore;
use crate::memory::verification::KeyPaths;
use crate::websocket_client::{AstationClient, AstationMessage};

/// Touch ID may take a while: the user may have to walk to the Mac.
pub const UNLOCK_TIMEOUT: Duration = Duration::from_secs(300);
/// Rotation needs no prompt, only a device signature.
pub const ROTATION_TIMEOUT: Duration = Duration::from_secs(60);

/// What unlock and rotation need from an Astation connection.
pub(crate) trait AstationLink {
    async fn send(&mut self, message: AstationMessage) -> Result<()>;
    async fn recv(&mut self) -> Option<AstationMessage>;
}

impl AstationLink for AstationClient {
    async fn send(&mut self, message: AstationMessage) -> Result<()> {
        self.send_message(message).await
    }

    async fn recv(&mut self) -> Option<AstationMessage> {
        self.recv_message_async().await
    }
}

/// `/proc/sys/kernel/random/boot_id`; empty where the OS has none.
pub fn boot_id() -> String {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|id| id.trim().to_string())
        .unwrap_or_default()
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// The next message `wanted` accepts within `wait`, skipping unrelated traffic.
async fn next_reply<L: AstationLink>(
    link: &mut L,
    wait: Duration,
    waiting_for: &str,
    wanted: fn(&AstationMessage) -> bool,
) -> Result<AstationMessage> {
    let next = async {
        loop {
            match link.recv().await {
                Some(message) if wanted(&message) => return Ok(message),
                Some(_) => continue,
                None => bail!("Astation's connection closed before it answered"),
            }
        }
    };
    tokio::time::timeout(wait, next)
        .await
        .map_err(|_| anyhow!("timed out waiting for Astation {waiting_for}"))?
}

/// The agent's challenge as an `atem-unlock-request-v1` signed by the
/// unlock-auth key (blocking: agent call and file read).
fn signed_request(
    agent: &dyn KeyAgentApi,
    paths: &KeyPaths,
    astation_id: &str,
) -> Result<SignedWire> {
    let challenge = agent.begin_unlock(astation_id)?;
    let unlock_auth = UnlockAuthKey::load_from(&paths.unlock_auth_key)?.ok_or_else(|| {
        anyhow!("unlock_auth_key is missing; run `atem pair` to verify this device again")
    })?;
    Ok(build_unlock_request(
        &challenge,
        &boot_id(),
        now_secs(),
        &unlock_auth,
    ))
}

/// Unlocks the agent through `astation_id` (the home Astation): the agent's
/// single-use key goes out in a request signed by the unlock-auth key, and
/// Astation's sealed, signed answer goes straight back to the agent.
/// Returns the storage key id Astation released.
pub(crate) async fn unlock_via<L: AstationLink>(
    link: &mut L,
    agent: &Arc<dyn KeyAgentApi>,
    paths: &KeyPaths,
    astation_id: &str,
    wait: Duration,
) -> Result<String> {
    let request = {
        let (agent, paths, astation_id) = (agent.clone(), paths.clone(), astation_id.to_string());
        blocking(move || signed_request(agent.as_ref(), &paths, &astation_id)).await?
    };
    link.send(AstationMessage::UnlockRequest {
        request: request.statement.clone(),
        signature: request.signature,
    })
    .await?;
    let reply = next_reply(link, wait, "to approve the unlock", |message| {
        matches!(
            message,
            AstationMessage::UnlockGrant { .. } | AstationMessage::UnlockDenied { .. }
        )
    })
    .await?;
    match reply {
        AstationMessage::UnlockGrant {
            grant,
            encapped_key,
            ciphertext,
        } => {
            let (agent, astation_id) = (agent.clone(), astation_id.to_string());
            let grant = UnlockGrantWire {
                grant,
                encapped_key,
                ciphertext,
            };
            blocking(move || agent.finish_unlock(&astation_id, &request.statement, &grant)).await
        }
        AstationMessage::UnlockDenied { reason } => bail!("Astation denied the unlock: {reason}"),
        _ => unreachable!("filtered by next_reply"),
    }
}

/// Rotates the storage key with `astation_id` (the home Astation): a
/// rotation already pending in the agent is resent unchanged; otherwise a
/// stale `.next` file left by a rotation that died is abandoned first, then a
/// new rotation begins. Returns the new storage key id.
pub(crate) async fn rotate_via<L: AstationLink>(
    link: &mut L,
    agent: &Arc<dyn KeyAgentApi>,
    paths: &KeyPaths,
    astation_id: &str,
    wait: Duration,
) -> Result<String> {
    let (pending, stale_next) = {
        let (agent, paths) = (agent.clone(), paths.clone());
        blocking(move || match agent.pending_rotation()? {
            Some(rotation) => Ok((Some(rotation), None)),
            None => Ok((
                None,
                SealedDeviceKeys::load_from(&paths.device_keys_next)?.map(|next| next.storage_kid),
            )),
        })
        .await?
    };
    let rotation = match pending {
        Some(rotation) => rotation,
        None => {
            if let Some(stale) = stale_next {
                // The agent deletes the stale file before it signs.
                let abandon = abandon_via_agent(agent, astation_id, &stale).await?;
                link.send(AstationMessage::StorageKeyAbandon { abandon })
                    .await?;
            }
            let (agent, astation_id) = (agent.clone(), astation_id.to_string());
            blocking(move || agent.begin_rotation(&astation_id)).await?
        }
    };
    send_rotation(link, agent, astation_id, rotation, wait).await
}

async fn abandon_via_agent(
    agent: &Arc<dyn KeyAgentApi>,
    astation_id: &str,
    storage_kid: &str,
) -> Result<SignedWire> {
    let (agent, astation_id, kid) = (
        agent.clone(),
        astation_id.to_string(),
        storage_kid.to_string(),
    );
    blocking(move || agent.abandon_pending(&astation_id, &kid))
        .await
        .with_context(|| {
            format!("Astation holds a pending storage key {storage_kid} this device can't give up")
        })
}

/// Phases 2 and 3 for `rotation`: send it, and on Astation's ack let the
/// agent promote the new key and send its confirmation. When Astation is
/// committed to another pending key, the agent abandons that key (only if
/// no file of its own still needs it) and the same rotation is sent once more.
async fn send_rotation<L: AstationLink>(
    link: &mut L,
    agent: &Arc<dyn KeyAgentApi>,
    astation_id: &str,
    rotation: StorageRotation,
    wait: Duration,
) -> Result<String> {
    let mut abandoned = false;
    loop {
        link.send(AstationMessage::StorageKeyRotate {
            rotate: rotation.rotate.clone(),
            encapped_key: rotation.encapped_key.clone(),
            ciphertext: rotation.ciphertext.clone(),
        })
        .await?;
        let reply = next_reply(link, wait, "to store the new storage key", |message| {
            matches!(
                message,
                AstationMessage::StorageKeyAck { .. } | AstationMessage::StorageKeyRejected { .. }
            )
        })
        .await?;
        match reply {
            AstationMessage::StorageKeyAck { ack } => {
                let (agent, astation_id) = (agent.clone(), astation_id.to_string());
                let (storage_kid, confirm) =
                    blocking(move || agent.confirm_rotation(&astation_id, &ack)).await?;
                link.send(AstationMessage::StorageKeyConfirm { confirm })
                    .await?;
                return Ok(storage_kid);
            }
            AstationMessage::StorageKeyRejected {
                reason,
                pending_kid: Some(pending_kid),
            } if !abandoned => {
                let abandon = abandon_via_agent(agent, astation_id, &pending_kid)
                    .await
                    .with_context(|| format!("Astation refused the new storage key: {reason}"))?;
                link.send(AstationMessage::StorageKeyAbandon { abandon })
                    .await?;
                abandoned = true;
            }
            AstationMessage::StorageKeyRejected {
                reason,
                pending_kid,
            } => match pending_kid {
                Some(kid) => {
                    bail!("Astation refused the new storage key (pending key {kid}): {reason}")
                }
                None => bail!("Astation refused the new storage key: {reason}"),
            },
            _ => unreachable!("filtered by next_reply"),
        }
    }
}

/// Hands the storage key to the home Astation when the agent holds one
/// Astation doesn't have yet (after a first verification, or after the
/// agent sealed a plain step-1 file). A rotation already pending in the agent
/// (e.g. the verification's escrow whose ack was lost) is resent unchanged,
/// never begun again. `None` when there is nothing to send.
pub(crate) async fn escrow_if_needed<L: AstationLink>(
    link: &mut L,
    agent: &Arc<dyn KeyAgentApi>,
    paths: &KeyPaths,
    astation_id: &str,
) -> Result<Option<String>> {
    if TrustStore::load_from(&paths.trust)?.home() != Some(astation_id) {
        return Ok(None);
    }
    let (status, pending) = {
        let agent = agent.clone();
        blocking(move || Ok((agent.status()?, agent.pending_rotation()?))).await?
    };
    if pending.is_none() && (!status.unlocked || status.escrowed) {
        return Ok(None);
    }
    rotate_via(link, agent, paths, astation_id, ROTATION_TIMEOUT)
        .await
        .map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::fake_astation::{
        ASTATION_ID, DEVICE_ID, FakeKeyServer, captured_rotation, sealed_device,
    };
    use crate::memory::key_agent::{error_of, test_agent};
    use crate::memory::statements::SignedWire;
    use crate::memory::storage_key::{SealedDeviceKeys, StorageRotation, new_storage_key};
    use std::collections::VecDeque;

    const WAIT: Duration = Duration::from_secs(5);

    /// An Astation connection whose far end is a `FakeKeyServer`; unrelated
    /// traffic arrives before every answer, as it does on the real socket.
    struct ScriptedLink {
        server: FakeKeyServer,
        inbox: VecDeque<AstationMessage>,
        deny: Option<String>,
        /// Refuses the next rotate with this reason and pending kid.
        reject: Option<(String, Option<String>)>,
        silent: bool,
        abandons: usize,
        rotates: usize,
    }

    impl ScriptedLink {
        fn new(server: FakeKeyServer) -> Self {
            Self {
                server,
                inbox: VecDeque::new(),
                deny: None,
                reject: None,
                silent: false,
                abandons: 0,
                rotates: 0,
            }
        }
    }

    impl AstationLink for ScriptedLink {
        async fn send(&mut self, message: AstationMessage) -> Result<()> {
            if self.silent {
                return Ok(());
            }
            self.inbox.push_back(AstationMessage::EncryptionMode {
                account_state: None,
            });
            match message {
                AstationMessage::UnlockRequest { request, signature } => {
                    let reply = match &self.deny {
                        Some(reason) => AstationMessage::UnlockDenied {
                            reason: reason.clone(),
                        },
                        None => {
                            let grant = self.server.grant_unlock(&SignedWire {
                                statement: request,
                                signature,
                            })?;
                            AstationMessage::UnlockGrant {
                                grant: grant.grant,
                                encapped_key: grant.encapped_key,
                                ciphertext: grant.ciphertext,
                            }
                        }
                    };
                    self.inbox.push_back(reply);
                }
                AstationMessage::StorageKeyRotate {
                    rotate,
                    encapped_key,
                    ciphertext,
                } => {
                    self.rotates += 1;
                    let reply = if let Some((reason, pending_kid)) = self.reject.take() {
                        AstationMessage::StorageKeyRejected {
                            reason,
                            pending_kid,
                        }
                    } else {
                        match self.server.accept_rotation(&StorageRotation {
                            rotate,
                            encapped_key,
                            ciphertext,
                        }) {
                            Ok(ack) => AstationMessage::StorageKeyAck { ack },
                            // Astation names the pending key it is committed to.
                            Err(error) => AstationMessage::StorageKeyRejected {
                                reason: error.to_string(),
                                pending_kid: self
                                    .server
                                    .pending
                                    .as_ref()
                                    .map(|(kid, _)| kid.clone()),
                            },
                        }
                    };
                    self.inbox.push_back(reply);
                }
                AstationMessage::StorageKeyConfirm { confirm } => self.server.confirm(&confirm)?,
                AstationMessage::StorageKeyAbandon { abandon } => {
                    self.abandons += 1;
                    self.server.accept_abandon(&abandon)?;
                }
                _ => {}
            }
            Ok(())
        }

        async fn recv(&mut self) -> Option<AstationMessage> {
            self.inbox.pop_front()
        }
    }

    fn agent(paths: &KeyPaths) -> Arc<dyn KeyAgentApi> {
        Arc::new(test_agent(paths))
    }

    fn sealed_kid(path: &std::path::Path) -> String {
        SealedDeviceKeys::load_from(path)
            .unwrap()
            .unwrap()
            .storage_kid
    }

    #[tokio::test]
    async fn unlock_then_rotate_over_a_link() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, keys) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        let mut link = ScriptedLink::new(server);
        let kid = unlock_via(&mut link, &agent, &paths, ASTATION_ID, WAIT)
            .await
            .unwrap();
        assert_eq!(kid, "0a1b2c3d");
        assert_eq!(
            agent.public_keys().unwrap(),
            (keys.device_pub(), keys.device_sign_pub())
        );
        let new_kid = rotate_via(&mut link, &agent, &paths, ASTATION_ID, WAIT)
            .await
            .unwrap();
        assert_ne!(new_kid, "0a1b2c3d");
        assert_eq!(
            link.server.storage_keys.keys().cloned().collect::<Vec<_>>(),
            vec![new_kid.clone()]
        );
        assert!(link.server.pending.is_none());
        assert_eq!(sealed_kid(&paths.device_keys_sealed), new_kid);
        agent.lock_keys().unwrap();
        assert_eq!(
            unlock_via(&mut link, &agent, &paths, ASTATION_ID, WAIT)
                .await
                .unwrap(),
            new_kid
        );
    }

    #[tokio::test]
    async fn a_denied_unlock_leaves_the_keys_locked() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, _) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        let mut link = ScriptedLink::new(server);
        link.deny = Some("Denied on the Mac".into());
        let error = error_of(unlock_via(&mut link, &agent, &paths, ASTATION_ID, WAIT).await);
        assert!(error.contains("Denied on the Mac"), "{error}");
        assert!(!agent.status().unwrap().unlocked);
    }

    #[tokio::test]
    async fn a_silent_astation_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, _) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        let mut link = ScriptedLink::new(server);
        link.silent = true;
        let error = error_of(unlock_via(&mut link, &agent, &paths, ASTATION_ID, WAIT).await);
        assert!(error.contains("closed"), "{error}");
    }

    #[tokio::test]
    async fn a_pending_key_astation_is_committed_to_is_abandoned_then_the_rotation_retried() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, keys) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        let mut link = ScriptedLink::new(server);
        unlock_via(&mut link, &agent, &paths, ASTATION_ID, WAIT)
            .await
            .unwrap();
        // An earlier rotation this device has no file for left a pending key.
        let stale = captured_rotation(&link.server, &keys, "0a1b2c3d", "4e5f6a7b");
        link.server.accept_rotation(&stale).unwrap();

        let new_kid = rotate_via(&mut link, &agent, &paths, ASTATION_ID, WAIT)
            .await
            .unwrap();
        assert_eq!((link.abandons, link.rotates), (1, 2));
        assert_ne!(new_kid, "4e5f6a7b");
        assert_eq!(
            link.server.storage_keys.keys().cloned().collect::<Vec<_>>(),
            vec![new_kid.clone()]
        );
        assert!(link.server.pending.is_none());
        assert_eq!(sealed_kid(&paths.device_keys_sealed), new_kid);
    }

    #[tokio::test]
    async fn a_pending_key_the_agent_must_keep_is_not_abandoned() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, _) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        let mut link = ScriptedLink::new(server);
        unlock_via(&mut link, &agent, &paths, ASTATION_ID, WAIT)
            .await
            .unwrap();
        // Astation (or a relay) names the key the current file is sealed under.
        link.reject = Some(("a rotation is pending".into(), Some("0a1b2c3d".into())));
        let error = error_of(rotate_via(&mut link, &agent, &paths, ASTATION_ID, WAIT).await);
        assert!(error.contains("0a1b2c3d"), "{error}");
        assert_eq!(link.abandons, 0);
        assert_eq!(link.server.storage_keys.len(), 1);
    }

    #[tokio::test]
    async fn a_second_refusal_after_an_abandon_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, keys) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        let mut link = ScriptedLink::new(server);
        unlock_via(&mut link, &agent, &paths, ASTATION_ID, WAIT)
            .await
            .unwrap();
        // Astation holds 5f6a7b8c pending but first names another key: the
        // abandon of that one changes nothing, and the retry is refused too.
        let other = captured_rotation(&link.server, &keys, "0a1b2c3d", "5f6a7b8c");
        link.server.accept_rotation(&other).unwrap();
        link.reject = Some(("pending".into(), Some("4e5f6a7b".into())));
        let error = error_of(rotate_via(&mut link, &agent, &paths, ASTATION_ID, WAIT).await);
        assert!(error.contains("5f6a7b8c"), "{error}");
        assert_eq!((link.abandons, link.rotates), (1, 2));
    }

    #[tokio::test]
    async fn a_stale_next_file_is_abandoned_before_a_new_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, keys) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        let mut link = ScriptedLink::new(server);
        unlock_via(&mut link, &agent, &paths, ASTATION_ID, WAIT)
            .await
            .unwrap();
        // A rotation died after Astation stored its key, before the promote.
        SealedDeviceKeys::seal(&keys, DEVICE_ID, "4e5f6a7b", &new_storage_key())
            .unwrap()
            .save_to(&paths.device_keys_next)
            .unwrap();
        let stale = captured_rotation(&link.server, &keys, "0a1b2c3d", "4e5f6a7b");
        link.server.accept_rotation(&stale).unwrap();

        let new_kid = rotate_via(&mut link, &agent, &paths, ASTATION_ID, WAIT)
            .await
            .unwrap();
        assert_eq!((link.abandons, link.rotates), (1, 1));
        assert_ne!(new_kid, "4e5f6a7b");
        assert!(link.server.pending.is_none());
        assert_eq!(sealed_kid(&paths.device_keys_sealed), new_kid);
    }

    #[tokio::test]
    async fn keys_astation_does_not_hold_yet_are_escrowed_once() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, mut server, keys) = sealed_device(dir.path(), "0a1b2c3d");
        let storage_key = [9u8; 32];
        SealedDeviceKeys::seal(&keys, DEVICE_ID, "0a1b2c3d", &storage_key)
            .unwrap()
            .save_to(&paths.device_keys_sealed)
            .unwrap();
        server.storage_keys.clear();
        let agent = agent(&paths);
        agent
            .load_unlocked(DEVICE_ID, &keys, "0a1b2c3d", &storage_key)
            .unwrap();
        let mut link = ScriptedLink::new(server);
        assert_eq!(
            escrow_if_needed(&mut link, &agent, &paths, "astation-2")
                .await
                .unwrap(),
            None,
            "only the home Astation holds the storage key"
        );
        assert_eq!(
            escrow_if_needed(&mut link, &agent, &paths, ASTATION_ID)
                .await
                .unwrap()
                .as_deref(),
            Some("0a1b2c3d")
        );
        assert_eq!(link.server.storage_keys.get("0a1b2c3d"), Some(&storage_key));
        assert_eq!(
            escrow_if_needed(&mut link, &agent, &paths, ASTATION_ID)
                .await
                .unwrap(),
            None
        );
        assert_eq!(link.rotates, 1);
    }

    #[tokio::test]
    async fn an_escrow_already_begun_is_resent_not_begun_again() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, mut server, keys) = sealed_device(dir.path(), "0a1b2c3d");
        let storage_key = [9u8; 32];
        SealedDeviceKeys::seal(&keys, DEVICE_ID, "0a1b2c3d", &storage_key)
            .unwrap()
            .save_to(&paths.device_keys_sealed)
            .unwrap();
        server.storage_keys.clear();
        let agent = agent(&paths);
        agent
            .load_unlocked(DEVICE_ID, &keys, "0a1b2c3d", &storage_key)
            .unwrap();
        // The verification prepared the escrow (outcome.escrow); Astation
        // stored it, but its ack was lost.
        let escrow = agent.begin_rotation(ASTATION_ID).unwrap();
        server.accept_rotation(&escrow).unwrap();
        let mut link = ScriptedLink::new(server);
        assert_eq!(
            escrow_if_needed(&mut link, &agent, &paths, ASTATION_ID)
                .await
                .unwrap()
                .as_deref(),
            Some("0a1b2c3d")
        );
        assert_eq!(link.server.storage_keys.get("0a1b2c3d"), Some(&storage_key));
        assert!(link.server.pending.is_none());
        let status = agent.status().unwrap();
        assert!(status.escrowed);
        assert_eq!(agent.pending_rotation().unwrap(), None);
    }

    #[test]
    fn boot_id_is_trimmed_or_empty() {
        let id = boot_id();
        assert_eq!(id, id.trim());
    }
}
