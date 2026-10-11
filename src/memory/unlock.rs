//! The CLI side of unlock and storage-key rotation (`atem cred …`, and the
//! first escrow in `atem pair`): carries the key agent's requests to the home
//! Astation and Astation's answers back. The storage key never passes
//! through here in plain form. Every agent call runs on a blocking thread
//! (`key_agent::blocking`): the client's socket I/O must not stall the runtime.
//! See designs/e2e-encryption.md "Unlock policy" and "Keys on disk (atem)".
use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use std::sync::Arc;
use std::time::Duration;

use crate::memory::device_keys::UnlockAuthKey;
use crate::memory::encoding::dec;
use crate::memory::key_agent::{
    AgentStatus, KeyAgentApi, LOCKED, RESET, blocking, build_unlock_request, default_agent,
    running_agent,
};
use crate::memory::statements::{SignedWire, StorageRotate};
use crate::memory::storage_key::{
    SealedDeviceKeys, StorageRotation, UnlockGrantWire, check_storage_ack, check_unlock_grant,
};
use crate::memory::trust::{AstationTrust, TrustStore};
use crate::memory::verification::{KeyPaths, key_needed};
use crate::websocket_client::{AstationClient, AstationMessage};

/// Touch ID may take a while: the user may have to walk to the Mac.
pub const UNLOCK_TIMEOUT: Duration = Duration::from_secs(300);
/// Rotation needs no prompt, only a device signature.
pub const ROTATION_TIMEOUT: Duration = Duration::from_secs(60);
/// Handing the storage key to Astation outside an unlock: an Astation that
/// stores storage keys answers at once; one that doesn't never answers, so
/// don't keep the user waiting a full rotation timeout.
pub const ESCROW_TIMEOUT: Duration = Duration::from_secs(15);
/// Once Astation has already left a handover unanswered, retry only briefly.
pub const ESCROW_RETRY_TIMEOUT: Duration = Duration::from_secs(5);

/// How long to wait for Astation to store a handed-over storage key.
fn escrow_wait(paths: &KeyPaths) -> Duration {
    let unanswered = TrustStore::load_from(&paths.trust)
        .map(|trust| trust.escrow_unanswered())
        .unwrap_or(false);
    if unanswered { ESCROW_RETRY_TIMEOUT } else { ESCROW_TIMEOUT }
}

/// What unlock and rotation need from an Astation connection.
pub(crate) trait AstationLink {
    async fn send(&mut self, message: AstationMessage) -> Result<()>;
    async fn recv(&mut self) -> Option<AstationMessage>;
    /// Applies a signed `encryptionMode` or `keyGrant` (checked against the
    /// pinned keys) and returns its status line; `None` for other traffic.
    async fn apply_encryption(&mut self, message: &AstationMessage) -> Result<Option<String>>;
}

impl AstationLink for AstationClient {
    async fn send(&mut self, message: AstationMessage) -> Result<()> {
        self.send_message(message).await
    }

    async fn recv(&mut self) -> Option<AstationMessage> {
        self.recv_message_async().await
    }

    async fn apply_encryption(&mut self, message: &AstationMessage) -> Result<Option<String>> {
        self.handle_encryption_message(message).await
    }
}

/// `/proc/sys/kernel/random/boot_id`; empty where the OS has none (macOS
/// for now: `sysctl kern.bootsessionuuid` could fill it in a later step).
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

/// Astation-supplied text as it may be shown: without control characters
/// (a relay could otherwise rewrite the terminal) or invisible and bidi
/// format characters (which could reorder what the user reads), at most
/// 200 characters.
pub(crate) fn shown(text: &str) -> String {
    text.chars()
        .filter(|&c| {
            !c.is_control()
                && !matches!(
                    c,
                    '\u{061c}'
                        | '\u{200b}'..='\u{200f}'
                        | '\u{202a}'..='\u{202e}'
                        | '\u{2060}'..='\u{2069}'
                        | '\u{feff}'
                )
        })
        .take(200)
        .collect()
}

/// Applies an encryption message (`encryptionMode`, `keyGrant`) and prints
/// what it did. Astation sends them right after connect, so they arrive while
/// atem waits for something else; dropped, the device would keep a stale
/// mode. A grant that arrives while the keys are locked is ignored and asked
/// for again once they are unlocked (`request_missing_key`).
async fn apply_encryption_message<L: AstationLink>(link: &mut L, message: &AstationMessage) {
    match link.apply_encryption(message).await {
        // "…locked; run `atem cred unlock`" is noise here: this is the
        // unlock, and it asks for a missing key once the keys are unlocked.
        Ok(Some(status)) if status.contains(LOCKED) => {}
        Ok(Some(status)) => println!("{}", shown(&status)),
        Ok(None) => {}
        Err(error) => eprintln!(
            "⚠️  Ignored an encryption message: {}",
            shown(&format!("{error:#}"))
        ),
    }
}

/// The next message `wanted` accepts within `wait`, applying encryption
/// messages on the way and skipping other unrelated traffic and replies
/// `wanted` rejects (stale or forged ones).
///
/// Unsigned refusals (`unlockDenied`, `storageKeyRejected`) are accepted and
/// end the flow. They only cost liveness: a relay that can forge one can
/// as well drop every reply, and neither unlocks, rotates or abandons
/// anything by itself (an abandon is still the agent's decision).
async fn next_reply<L: AstationLink>(
    link: &mut L,
    wait: Duration,
    waiting_for: &str,
    mut wanted: impl FnMut(&AstationMessage) -> bool,
) -> Result<AstationMessage> {
    let next = async {
        loop {
            match link.recv().await {
                Some(message) if wanted(&message) => return Ok(message),
                Some(message) => apply_encryption_message(link, &message).await,
                None => bail!("Astation's connection closed before it answered"),
            }
        }
    };
    tokio::time::timeout(wait, next)
        .await
        .map_err(|_| anyhow!(NoAnswer(waiting_for.to_string())))?
}

/// Astation sent nothing `next_reply` accepts before the wait ran out. An
/// Astation without storage-key support drops these messages silently, so
/// that is all atem can see of it.
#[derive(Debug)]
pub struct NoAnswer(pub String);

impl std::fmt::Display for NoAnswer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "timed out waiting for Astation {}", self.0)
    }
}

impl std::error::Error for NoAnswer {}

/// The pins of `astation_id` (blocking: file read).
fn home_pins(paths: &KeyPaths, astation_id: &str) -> Result<AstationTrust> {
    TrustStore::load_from(&paths.trust)?
        .verified(astation_id)
        .cloned()
        .ok_or_else(|| anyhow!("this device isn't verified with Astation {astation_id}"))
}

/// Whether `grant` is the pinned Astation's answer to `request` (the
/// statement this run sent). Anything else is skipped, not handed to the
/// agent: its single-use key would be spent on a stale or forged reply.
/// The agent runs the same check (`check_unlock_grant`) again.
fn grant_answers(home: &AstationTrust, request: &str, grant: &UnlockGrantWire) -> bool {
    STANDARD
        .decode(request)
        .is_ok_and(|request| check_unlock_grant(home, &request, grant).is_ok())
}

/// The new storage key id a rotation carries.
fn rotation_kid(rotation: &StorageRotation) -> Result<String> {
    let statement = STANDARD.decode(&rotation.rotate.statement)?;
    Ok(StorageRotate::parse(&dec(&statement)?)?.new_storage_kid)
}

/// What is wrong with this device's key files, when it has a verified home
/// Astation and they can't be unlocked as they are (the fix is the reset).
/// A plain `device_keys` file is fine: the agent seals it when it starts.
pub fn key_file_problem(paths: &KeyPaths, trust: &TrustStore) -> Option<String> {
    trust.home()?;
    if paths.device_keys.exists() {
        return None;
    }
    let current = match SealedDeviceKeys::load_from(&paths.device_keys_sealed) {
        Ok(current) => current,
        Err(error) => return Some(format!("device_keys.sealed is unreadable ({error:#})")),
    };
    if current.is_none() {
        // Only when the current file is absent may a spare one stand in.
        let spares = [&paths.device_keys_next, &paths.device_keys_prev]
            .map(|path| SealedDeviceKeys::load_from(path));
        if !spares.iter().any(|spare| matches!(spare, Ok(Some(_)))) {
            return Some(match spares.into_iter().find_map(Result::err) {
                Some(error) => format!("the spare sealed key files are unreadable ({error:#})"),
                None => "no sealed keys on disk".into(),
            });
        }
    }
    match UnlockAuthKey::load_from(&paths.unlock_auth_key) {
        Ok(Some(_)) => None,
        Ok(None) => Some("unlock_auth_key is missing".into()),
        Err(error) => Some(format!("unlock_auth_key is unreadable ({error:#})")),
    }
}

/// The agent's challenge as an `atem-unlock-request-v1` signed by the
/// unlock-auth key (blocking: agent call and file read).
fn signed_request(
    agent: &dyn KeyAgentApi,
    paths: &KeyPaths,
    astation_id: &str,
) -> Result<SignedWire> {
    let challenge = agent.begin_unlock(astation_id)?;
    let unlock_auth = UnlockAuthKey::load_from(&paths.unlock_auth_key)?
        .ok_or_else(|| anyhow!("unlock_auth_key is missing. {RESET}"))?;
    Ok(build_unlock_request(
        &challenge,
        &boot_id(),
        now_secs(),
        &unlock_auth,
    ))
}

/// Whether an `unlockDenied` says the device was revoked: the `revoked`
/// flag, or, from an Astation that doesn't send it yet, a reason saying so.
/// An Astation that no longer knows the device (it forgets a revoked one)
/// says the request "does not belong to this verified device".
fn denial_revokes(reason: &str, revoked: bool) -> bool {
    let reason = reason.to_lowercase();
    revoked
        || reason.contains("revoked")
        || reason.contains("does not belong to this verified device")
}

/// Unlocks the agent through `astation_id` (the home Astation): the agent's
/// single-use key goes out in a request signed by the unlock-auth key, and
/// Astation's sealed, signed answer goes straight back to the agent. A grant
/// that doesn't answer this request is skipped (until `wait` runs out).
/// Returns the storage key id Astation released.
pub(crate) async fn unlock_via<L: AstationLink>(
    link: &mut L,
    agent: &Arc<dyn KeyAgentApi>,
    paths: &KeyPaths,
    astation_id: &str,
    wait: Duration,
) -> Result<String> {
    let (request, home) = {
        let (agent, paths, astation_id) = (agent.clone(), paths.clone(), astation_id.to_string());
        blocking(move || {
            let trust = TrustStore::load_from(&paths.trust)?;
            if let Some(problem) = key_file_problem(&paths, &trust) {
                bail!("this device's keys can't be unlocked: {problem}. {RESET}");
            }
            let home = home_pins(&paths, &astation_id)?;
            Ok((signed_request(agent.as_ref(), &paths, &astation_id)?, home))
        })
        .await?
    };
    link.send(AstationMessage::UnlockRequest {
        request: request.statement.clone(),
        signature: request.signature,
    })
    .await?;
    let reply = next_reply(
        link,
        wait,
        "to approve the unlock",
        |message| match message {
            AstationMessage::UnlockGrant {
                grant,
                encapped_key,
                ciphertext,
            } => grant_answers(
                &home,
                &request.statement,
                &UnlockGrantWire {
                    grant: grant.clone(),
                    encapped_key: encapped_key.clone(),
                    ciphertext: ciphertext.clone(),
                },
            ),
            AstationMessage::UnlockDenied { .. } => true,
            _ => false,
        },
    )
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
            // The grant is Astation's answer to this request: what fails now
            // is this device's key files.
            blocking(move || agent.finish_unlock(&astation_id, &request.statement, &grant))
                .await
                .map_err(|error| {
                    anyhow!(
                        "Astation released the storage key, but this device's keys didn't open: {error:#}. If this keeps happening: {RESET}"
                    )
                })
        }
        AstationMessage::UnlockDenied { reason, revoked } => {
            if !denial_revokes(&reason, revoked) {
                bail!("Astation denied the unlock: {}", shown(&reason));
            }
            // Unsigned (it came over the relay), so all it may cause is a
            // note in cred_state.json; `atem pair` then sets the old key files
            // aside (renamed, never deleted) and verifies with new keys and a
            // new safety code. A forged one costs a re-pair, never keys or trust.
            let (path, astation_id, at) =
                (paths.trust.clone(), astation_id.to_string(), now_secs());
            let recorded = blocking(move || {
                TrustStore::update(&path, |store| {
                    store.record_revoked(&astation_id, at);
                    Ok(())
                })
            })
            .await;
            let note = match recorded {
                Ok(()) => String::new(),
                Err(error) => format!(" (couldn't record it: {error:#})"),
            };
            bail!(
                "Astation denied the unlock: {}; this device was revoked; run `atem pair` to verify it again{note}",
                shown(&reason)
            )
        }
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
    let (home, pending, stale_next) = {
        let (agent, paths, astation_id) = (agent.clone(), paths.clone(), astation_id.to_string());
        blocking(move || {
            let home = home_pins(&paths, &astation_id)?;
            match agent.pending_rotation()? {
                Some(rotation) => Ok((home, Some(rotation), None)),
                None => Ok((
                    home,
                    None,
                    SealedDeviceKeys::load_from(&paths.device_keys_next)?
                        .map(|next| next.storage_kid),
                )),
            }
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
    send_rotation(link, agent, paths, astation_id, &home, rotation, wait).await
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
            format!(
                "Astation holds a pending storage key {} this device can't give up",
                shown(storage_kid)
            )
        })
}

/// Phases 2 and 3 for `rotation`: send it, and on Astation's ack let the
/// agent promote the new key and send its confirmation. An ack for another
/// key (stale or forged) is skipped. When Astation is committed to another
/// pending key, the agent abandons that key (only if no file of its own
/// still needs it) and the same rotation is sent once more.
async fn send_rotation<L: AstationLink>(
    link: &mut L,
    agent: &Arc<dyn KeyAgentApi>,
    paths: &KeyPaths,
    astation_id: &str,
    home: &AstationTrust,
    rotation: StorageRotation,
    wait: Duration,
) -> Result<String> {
    let new_kid = rotation_kid(&rotation)?;
    let mut abandoned = false;
    loop {
        link.send(AstationMessage::StorageKeyRotate {
            rotate: rotation.rotate.clone(),
            encapped_key: rotation.encapped_key.clone(),
            ciphertext: rotation.ciphertext.clone(),
        })
        .await?;
        let reply =
            match next_reply(
                link,
                wait,
                "to store the new storage key",
                |message| match message {
                    AstationMessage::StorageKeyAck { ack } => {
                        check_storage_ack(home, &new_kid, ack).is_ok()
                    }
                    AstationMessage::StorageKeyRejected { .. } => true,
                    _ => false,
                },
            )
            .await
            {
                Ok(reply) => reply,
                Err(error) => {
                    if error.downcast_ref::<NoAnswer>().is_some() {
                        // Before any escrow was confirmed, `atem cred status`
                        // says Astation may not take storage keys yet.
                        let path = paths.trust.clone();
                        let _ = blocking(move || {
                            TrustStore::update(&path, |store| {
                                store.record_escrow_unanswered();
                                Ok(())
                            })
                        })
                        .await;
                    }
                    return Err(error);
                }
            };
        match reply {
            AstationMessage::StorageKeyAck { ack } => {
                let (agent, astation_id) = (agent.clone(), astation_id.to_string());
                let (storage_kid, confirm) =
                    blocking(move || agent.confirm_rotation(&astation_id, &ack)).await?;
                // The new key is in place here and Astation holds it as
                // pending, which the next unlock (naming it) settles.
                if let Err(error) = link
                    .send(AstationMessage::StorageKeyConfirm { confirm })
                    .await
                {
                    eprintln!(
                        "⚠️  The storage key was rotated ({storage_kid}), but the confirmation didn't reach Astation ({error:#}); Astation settles it at the next unlock."
                    );
                }
                return Ok(storage_kid);
            }
            AstationMessage::StorageKeyRejected {
                reason,
                pending_kid: Some(pending_kid),
            } if !abandoned => {
                let abandon = abandon_via_agent(agent, astation_id, &pending_kid)
                    .await
                    .with_context(|| {
                        format!("Astation refused the new storage key: {}", shown(&reason))
                    })?;
                link.send(AstationMessage::StorageKeyAbandon { abandon })
                    .await?;
                abandoned = true;
            }
            AstationMessage::StorageKeyRejected {
                reason,
                pending_kid,
            } => match pending_kid {
                Some(kid) => bail!(
                    "Astation refused the new storage key (pending key {}): {}",
                    shown(&kid),
                    shown(&reason)
                ),
                None => bail!("Astation refused the new storage key: {}", shown(&reason)),
            },
            _ => unreachable!("filtered by next_reply"),
        }
    }
}

/// Hands the storage key to the home Astation when the agent holds one
/// Astation doesn't have yet (after a first verification, or after the
/// agent sealed a plain `device_keys` file). A rotation already pending in
/// the agent (e.g. the verification's escrow whose ack was lost) is resent
/// unchanged, never begun again. `None` when there is nothing to send.
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
    let wait = escrow_wait(paths);
    rotate_via(link, agent, paths, astation_id, wait)
        .await
        .map(Some)
}

/// What `atem pair` did about the storage key.
#[derive(Debug, PartialEq, Eq)]
pub enum PairEscrow {
    /// Astation now holds this storage key.
    Escrowed(String),
    /// The storage key belongs to this home Astation, not the one paired with.
    HeldByHome(String),
    /// Nothing to hand over.
    Nothing,
}

/// `atem pair`'s first escrow, in the same run: sends `escrow` (the
/// verification's `outcome.escrow`, already begun in the agent) and confirms
/// it; without one, hands over any storage key Astation doesn't hold yet.
pub(crate) async fn pair_escrow<L: AstationLink>(
    link: &mut L,
    agent: &Arc<dyn KeyAgentApi>,
    paths: &KeyPaths,
    astation_id: &str,
    escrow: Option<StorageRotation>,
) -> Result<PairEscrow> {
    let Some(rotation) = escrow else {
        // Only the home Astation holds the storage key: pairing with another
        // one has nothing to hand over, unless the home doesn't hold the
        // agent's key yet, which only the home Astation can fix.
        let trust = TrustStore::load_from(&paths.trust)?;
        if let Some(home) = trust.home().filter(|home| *home != astation_id) {
            let home = home.to_string();
            let (status, pending) = {
                let agent = agent.clone();
                blocking(move || Ok((agent.status()?, agent.pending_rotation()?))).await?
            };
            // A locked agent can't vouch for escrow itself: its sealed file's
            // kid must be the one Astation is known to hold.
            let held = status.escrowed
                || (!status.unlocked
                    && status.storage_kid.is_some()
                    && status.storage_kid.as_deref() == trust.escrowed_kid());
            if pending.is_some() || !held {
                bail!(
                    "this device's storage key goes only to its home Astation {home}, not to {astation_id}; run `atem cred unlock` to hand it to {home}"
                );
            }
            return Ok(PairEscrow::HeldByHome(home));
        }
        return Ok(
            match escrow_if_needed(link, agent, paths, astation_id).await? {
                Some(kid) => PairEscrow::Escrowed(kid),
                None => PairEscrow::Nothing,
            },
        );
    };
    let home = {
        let (paths, astation_id) = (paths.clone(), astation_id.to_string());
        blocking(move || home_pins(&paths, &astation_id)).await?
    };
    send_rotation(
        link,
        agent,
        paths,
        astation_id,
        &home,
        rotation,
        escrow_wait(paths),
    )
    .await
    .map(PairEscrow::Escrowed)
}

/// What `atem pair` prints when the first escrow didn't complete.
pub fn escrow_failure_message(error: &anyhow::Error) -> String {
    if error.downcast_ref::<NoAnswer>().is_some() {
        return format!(
            "Astation didn't answer the storage-key handover ({error:#}); it may not support storage keys yet. This device keeps its keys in the plain ~/.config/atem/device_keys file (re-sealed whenever the key agent starts) and hands the key over at the next `atem pair` or `atem cred unlock` once Astation does, which deletes that file."
        );
    }
    format!(
        "Astation doesn't hold this device's storage key yet ({error:#}). Until it does, this device keeps its keys in the plain ~/.config/atem/device_keys file (re-sealed whenever the key agent starts); run `atem cred unlock` to hand the key over, which deletes that file."
    )
}

/// `atem cred unlock` once connected to the home Astation: unlock (Touch ID
/// on the Mac) and rotate the storage key, or, when the agent is already
/// unlocked, hand Astation any storage key it doesn't hold yet.
pub(crate) async fn unlock_and_rotate<L: AstationLink>(
    link: &mut L,
    agent: &Arc<dyn KeyAgentApi>,
    paths: &KeyPaths,
    home: &str,
    wait: Duration,
) -> Result<()> {
    let status = {
        let agent = agent.clone();
        blocking(move || agent.status()).await?
    };
    if status.unlocked {
        match escrow_if_needed(link, agent, paths, home).await? {
            Some(kid) => println!("Astation now holds this device's storage key ({kid})."),
            None => println!(
                "Already unlocked (storage key {}).",
                status.storage_kid.unwrap_or_default()
            ),
        }
    } else {
        println!("Approve on your Mac with Touch ID…");
        let kid = unlock_via(link, agent, paths, home, wait).await?;
        println!("✅ Unlocked (storage key {kid}).");
        match rotate_via(link, agent, paths, home, ROTATION_TIMEOUT).await {
            Ok(kid) => println!("Storage key rotated ({kid})."),
            Err(error) => eprintln!(
                "⚠️  The storage key wasn't rotated ({error:#}); it rotates at the next unlock."
            ),
        }
    }
    request_missing_key(link, agent, paths, home).await
}

/// What `atem cred status` learned about the key agent.
pub enum AgentState {
    NotRunning,
    Running(AgentStatus),
    Unreachable(String),
}

/// The running agent's status. An agent that can't answer (an older one
/// speaking another protocol version, say) is reported, not an error: the
/// report carries its message and what to do about it.
pub fn agent_state(agent: Option<&dyn KeyAgentApi>) -> AgentState {
    match agent {
        None => AgentState::NotRunning,
        Some(agent) => match agent.status() {
            Ok(status) => AgentState::Running(status),
            Err(error) => AgentState::Unreachable(format!("{error:#}")),
        },
    }
}

/// `atem cred status`, for the paired Astation `astation_id`. `key_problem`
/// (from `key_file_problem`) adds the reset instructions.
pub fn status_report(
    trust: &TrustStore,
    astation_id: &str,
    agent: &AgentState,
    sealed_kid: Option<&str>,
    key_problem: Option<&str>,
) -> String {
    let (agent_line, storage_kid, waiting) = match agent {
        // Without the agent, only cred_state.json tells whether Astation
        // confirmed holding the sealed file's key (until it does, the plain
        // device_keys file stays and the next agent re-seals it).
        AgentState::NotRunning => (
            "not running (starts with 'atem cred unlock')".to_string(),
            sealed_kid.map(str::to_string),
            sealed_kid.is_some_and(|kid| trust.escrowed_kid() != Some(kid)),
        ),
        AgentState::Unreachable(error) => (
            format!("not answering ({error})"),
            sealed_kid.map(str::to_string),
            sealed_kid.is_some_and(|kid| trust.escrowed_kid() != Some(kid)),
        ),
        AgentState::Running(status) if status.unlocked => (
            "unlocked".to_string(),
            status.storage_kid.clone(),
            !status.escrowed,
        ),
        // A locked agent vouches for nothing: cred_state.json decides, as
        // when the agent isn't running.
        AgentState::Running(status) => (
            "locked (run 'atem cred unlock')".to_string(),
            status.storage_kid.clone(),
            status
                .storage_kid
                .as_deref()
                .is_some_and(|kid| trust.escrowed_kid() != Some(kid)),
        ),
    };
    let storage_line = match (storage_kid, waiting) {
        // The first escrow went unanswered: most likely an Astation without
        // storage-key support, where `atem cred unlock` can't help yet.
        (Some(kid), true) if trust.escrow_unanswered() => format!(
            "Storage key: {kid}  (not yet held by Astation: it hasn't answered storage-key requests, so it may not support them yet; the key is handed over at the next 'atem pair' or 'atem cred unlock' once it does, and until then this device keeps its plain device_keys file)"
        ),
        (Some(kid), true) => {
            format!("Storage key: {kid}  (not yet held by Astation; run 'atem cred unlock')")
        }
        (Some(kid), false) => format!("Storage key: {kid}"),
        (None, _) => "Storage key: none".to_string(),
    };
    let mut report = format!(
        "{}\nHome Astation: {}\nKey agent: {agent_line}\n{storage_line}\n",
        trust.verification_line(astation_id),
        trust.home().unwrap_or("none (verify with 'atem pair')"),
    );
    if let Some(problem) = key_problem {
        report.push_str(&format!("Key files: {problem}\n{RESET}\n"));
    }
    report
}

/// `atem cred lock`: what happened, or why the agent couldn't be reached.
pub fn lock_keys_message(agent: Option<&dyn KeyAgentApi>) -> Result<String> {
    match agent {
        None => Ok("The key agent isn't running; this device's keys are locked.".into()),
        Some(agent) => {
            agent
                .lock_keys()
                .map_err(|error| anyhow!("Not locked: {error:#}"))?;
            Ok("Locked: the key agent wiped this device's keys from memory.".into())
        }
    }
}

/// `atem cred …` (tier 2: needs a pairing with Astation).
pub async fn handle_cred(command: crate::cli::CredCommands) -> Result<()> {
    use crate::cli::CredCommands;
    let paired = crate::auth::require_pairing("atem cred")?;
    let paths = KeyPaths::default_paths();
    match command {
        CredCommands::Status => {
            let report = blocking(move || {
                let trust = TrustStore::load_from(&paths.trust)?;
                let sealed_kid = SealedDeviceKeys::load_from(&paths.device_keys_sealed)
                    .ok()
                    .flatten()
                    .map(|sealed| sealed.storage_kid);
                let problem = key_file_problem(&paths, &trust);
                let agent = agent_state(running_agent().as_deref());
                Ok(status_report(
                    &trust,
                    &paired.astation_id,
                    &agent,
                    sealed_kid.as_deref(),
                    problem.as_deref(),
                ))
            })
            .await?;
            print!("{report}");
            Ok(())
        }
        CredCommands::Unlock => unlock_command(&paths).await,
        CredCommands::Lock => {
            let message = blocking(|| lock_keys_message(running_agent().as_deref())).await?;
            println!("{message}");
            Ok(())
        }
    }
}

/// Connects to the home Astation without pairing: locally when the local
/// Astation is the home one, else through its relay identity room.
async fn connect_home(home: &str) -> Result<AstationClient> {
    let config = crate::config::AtemConfig::load()?;
    let mut local = AstationClient::new();
    if local
        .connect_without_pairing(config.astation_ws())
        .await
        .is_ok()
        && local.connected_astation_id() == Some(home)
    {
        return Ok(local);
    }
    drop(local);
    let mut client = AstationClient::new();
    client
        .connect_relay_identity_without_pairing(config.astation_relay_url(), home)
        .await
        .with_context(|| format!("couldn't reach this device's home Astation ({home})"))?;
    if client.connected_astation_id() != Some(home) {
        bail!("connected to a different Astation than this device's home ({home})");
    }
    Ok(client)
}

async fn unlock_command(paths: &KeyPaths) -> Result<()> {
    let trust = TrustStore::load_from(&paths.trust)?;
    let home = match (trust.home(), trust.recorded_home()) {
        (Some(home), _) => home.to_string(),
        (None, Some(stale)) => bail!(
            "This device's home Astation ({stale}) no longer verifies it, so its keys can't be unlocked. {RESET}"
        ),
        (None, None) => bail!("This device isn't verified yet. Run `atem pair` first."),
    };
    let agent: Arc<dyn KeyAgentApi> = Arc::from(default_agent());
    let nothing_to_do = {
        let (agent, paths, home) = (agent.clone(), paths.clone(), home.clone());
        blocking(move || already_unlocked(agent.as_ref(), &paths, &home)).await?
    };
    if let Some(message) = nothing_to_do {
        println!("{message}");
        if migration_pending(&TrustStore::load_from(&paths.trust)?, &home)? {
            // Astation sends the signed state on connect; applying it finishes
            // the migration and sends the signed completion report.
            println!("Finishing the encryption migration with Astation…");
            let mut client = connect_home(&home).await?;
            finish_migration(&mut client, MIGRATION_WAIT).await;
        }
        return Ok(());
    }
    let mut client = connect_home(&home).await?;
    unlock_and_rotate(&mut client, &agent, paths, &home, UNLOCK_TIMEOUT).await
}

/// How long an already unlocked `atem cred unlock` waits for Astation's
/// signed state when a migration is pending.
const MIGRATION_WAIT: Duration = Duration::from_secs(15);

/// The newest signed state for `home`'s account is `enabling` or
/// `disabling`: this device's part of the migration may not be reported yet.
fn migration_pending(trust: &TrustStore, home: &str) -> Result<bool> {
    Ok(matches!(
        crate::memory::verification::effective_state(trust, home)?,
        Some((_, Some(state)))
            if matches!(state.mode, crate::memory::crypto::EncryptionMode::Enabling | crate::memory::crypto::EncryptionMode::Disabling)
    ))
}

/// Applies the encryption messages Astation sends on connect until one
/// `encryptionMode` is handled (that runs the migration and reports it), at
/// most `wait`.
async fn finish_migration<L: AstationLink>(link: &mut L, wait: Duration) {
    // Only the wait for Astation's message is timed: applying an
    // `encryptionMode` runs the migration, which may take longer.
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        let Ok(Some(message)) = tokio::time::timeout_at(deadline, link.recv()).await else {
            eprintln!("⚠️  Astation didn't send the encryption state; try again in a moment.");
            return;
        };
        let is_mode = matches!(message, AstationMessage::EncryptionMode { .. });
        if is_mode || matches!(message, AstationMessage::KeyGrant { .. }) {
            apply_encryption_message(link, &message).await;
            if is_mode {
                return;
            }
        }
    }
}

/// "Already unlocked" when `atem cred unlock` needs no Touch ID:
/// the keys are unlocked, Astation holds their storage key, no rotation is
/// waiting to be resent and `K` isn't missing (blocking: agent call).
fn already_unlocked(
    agent: &dyn KeyAgentApi,
    paths: &KeyPaths,
    home: &str,
) -> Result<Option<String>> {
    let status = agent.status()?;
    if !status.unlocked
        || !status.escrowed
        || agent.pending_rotation()?.is_some()
        || key_needed(paths, agent, home)?
    {
        return Ok(None);
    }
    Ok(Some(format!(
        "Already unlocked (storage key {}).",
        status.storage_kid.unwrap_or_default()
    )))
}

/// How long to wait for `K` after a `keyRequest`.
const KEY_TIMEOUT: Duration = Duration::from_secs(15);

/// After an unlock: when the newest signed state needs `K` and the agent
/// doesn't hold it (a grant that arrived while the keys were locked was
/// ignored, or the state itself only arrived during the unlock), asks the
/// home Astation for it with the device key it pinned and installs the
/// grant. Nothing is asked when no signed state needs `K`.
async fn request_missing_key<L: AstationLink>(
    link: &mut L,
    agent: &Arc<dyn KeyAgentApi>,
    paths: &KeyPaths,
    home: &str,
) -> Result<()> {
    let public_key = {
        let (agent, paths, home) = (agent.clone(), paths.clone(), home.to_string());
        blocking(move || {
            if !key_needed(&paths, agent.as_ref(), &home)? {
                return Ok(None);
            }
            let trust = TrustStore::load_from(&paths.trust)?;
            Ok(Some(
                trust
                    .verified(&home)
                    .ok_or_else(|| anyhow!("this device isn't verified with its home Astation"))?
                    .device_pub
                    .clone(),
            ))
        })
        .await?
    };
    let Some(public_key) = public_key else {
        return Ok(());
    };
    link.send(AstationMessage::KeyRequest { public_key })
        .await?;
    println!("Encryption key requested from Astation…");
    let grant = next_reply(link, KEY_TIMEOUT, "to send the encryption key", |message| {
        matches!(message, AstationMessage::KeyGrant { .. })
    })
    .await;
    match grant {
        Ok(grant) => apply_encryption_message(link, &grant).await,
        Err(error) if error.downcast_ref::<NoAnswer>().is_some() => {
            eprintln!("⚠️  Astation didn't send the key yet; it arrives on a later connection.")
        }
        Err(error) => eprintln!("⚠️  {}", shown(&format!("{error:#}"))),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::crypto::EncryptionMode;
    use crate::memory::device_keys::DeviceKeys;
    use crate::memory::fake_astation::ACCOUNT;
    use crate::memory::fake_astation::{
        ASTATION_ID, DEVICE_ID, FakeKeyServer, captured_rotation, sealed_device, set_state,
    };
    use crate::memory::grant::seal_k_grant;
    use crate::memory::key_agent::{AgentStatus, RESET};
    use crate::memory::key_agent::{error_of, test_agent};
    use crate::memory::statements::AccountState;
    use crate::memory::statements::{FakeAstation, SignedWire, StorageAck};
    use crate::memory::storage_key::{SealedDeviceKeys, StorageRotation, new_storage_key};
    use crate::memory::verification::account_mode;
    use std::collections::VecDeque;

    #[test]
    fn escrow_waits_briefly_and_less_once_unanswered() {
        let dir = tempfile::tempdir().unwrap();
        let paths = KeyPaths::in_dir(dir.path());
        assert_eq!(escrow_wait(&paths), ESCROW_TIMEOUT);
        let mut trust = TrustStore::default();
        trust.record_escrow_unanswered();
        trust.save_to(&paths.trust).unwrap();
        assert_eq!(escrow_wait(&paths), ESCROW_RETRY_TIMEOUT);
        assert!(ESCROW_TIMEOUT < ROTATION_TIMEOUT);
    }

    const WAIT: Duration = Duration::from_secs(5);

    /// An Astation connection whose far end is a `FakeKeyServer`; unrelated
    /// traffic arrives before every answer, as it does on the real socket.
    struct ScriptedLink {
        server: FakeKeyServer,
        inbox: VecDeque<AstationMessage>,
        deny: Option<String>,
        /// The denial carries `revoked: true`.
        deny_revoked: bool,
        /// Refuses the next rotate with this reason and pending kid.
        reject: Option<(String, Option<String>)>,
        silent: bool,
        /// With nothing queued, `recv` waits forever (a link that never answers).
        hang: bool,
        /// Queued just before the next answer: a stale or replayed reply.
        stale: Option<AstationMessage>,
        /// Grants are signed by this impostor instead of the pinned Astation.
        forger: Option<FakeAstation>,
        /// Grants name this storage key id instead of the requested one.
        grant_kid: Option<String>,
        /// Sending the confirmation fails (the connection dropped).
        fail_confirm: bool,
        abandons: usize,
        rotates: usize,
        /// Encryption messages are applied to these paths and this agent.
        keys: Option<(KeyPaths, Arc<dyn KeyAgentApi>)>,
        /// What each applied encryption message did (`Applied`, as Debug).
        applied: Vec<String>,
        /// Queued just before the answer to the next rotate.
        on_rotate: Option<AstationMessage>,
        /// Answers a `keyRequest` with this.
        key_grant: Option<AstationMessage>,
        key_requests: usize,
    }

    impl ScriptedLink {
        fn new(server: FakeKeyServer) -> Self {
            Self {
                server,
                inbox: VecDeque::new(),
                deny: None,
                deny_revoked: false,
                reject: None,
                silent: false,
                hang: false,
                stale: None,
                forger: None,
                grant_kid: None,
                fail_confirm: false,
                abandons: 0,
                rotates: 0,
                keys: None,
                applied: Vec::new(),
                on_rotate: None,
                key_grant: None,
                key_requests: 0,
            }
        }

        fn with_keys(mut self, paths: &KeyPaths, agent: &Arc<dyn KeyAgentApi>) -> Self {
            self.keys = Some((paths.clone(), agent.clone()));
            self
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
            if let Some(stale) = self.stale.take() {
                self.inbox.push_back(stale);
            }
            match message {
                AstationMessage::UnlockRequest { request, signature } => {
                    let reply = match &self.deny {
                        Some(reason) => AstationMessage::UnlockDenied {
                            reason: reason.clone(),
                            revoked: self.deny_revoked,
                        },
                        None => {
                            let request = SignedWire {
                                statement: request,
                                signature,
                            };
                            let grant = match (&self.forger, &self.grant_kid) {
                                (Some(forger), _) => {
                                    self.server.unlock_grant(forger, &request, "0a1b2c3d")?
                                }
                                (None, Some(kid)) => self.server.unlock_grant(
                                    &self.server.astation,
                                    &request,
                                    kid,
                                )?,
                                // As Astation does: a request naming the
                                // pending key confirms it (implicit confirm).
                                (None, None) => self.server.grant_unlock_confirming(&request)?,
                            };
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
                    if let Some(message) = self.on_rotate.take() {
                        self.inbox.push_back(message);
                    }
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
                            // Astation names the pending key only when it is why.
                            Err(rejected) => AstationMessage::StorageKeyRejected {
                                reason: rejected.reason,
                                pending_kid: rejected.pending_kid,
                            },
                        }
                    };
                    self.inbox.push_back(reply);
                }
                AstationMessage::StorageKeyConfirm { .. } if self.fail_confirm => {
                    bail!("the connection dropped")
                }
                AstationMessage::StorageKeyConfirm { confirm } => self.server.confirm(&confirm)?,
                AstationMessage::StorageKeyAbandon { abandon } => {
                    self.abandons += 1;
                    self.server.accept_abandon(&abandon)?;
                }
                AstationMessage::KeyRequest { .. } => {
                    self.key_requests += 1;
                    if let Some(grant) = self.key_grant.take() {
                        self.inbox.push_back(grant);
                    }
                }
                _ => {}
            }
            Ok(())
        }

        async fn recv(&mut self) -> Option<AstationMessage> {
            match self.inbox.pop_front() {
                Some(message) => Some(message),
                None if self.hang => std::future::pending().await,
                None => None,
            }
        }

        async fn apply_encryption(&mut self, message: &AstationMessage) -> Result<Option<String>> {
            use crate::memory::verification::{apply_account_state, apply_grant};
            let Some((paths, agent)) = &self.keys else {
                return Ok(None);
            };
            let applied = match message {
                AstationMessage::EncryptionMode { account_state } => {
                    apply_account_state(paths, ASTATION_ID, account_state.as_ref())?
                }
                AstationMessage::KeyGrant { grant } => {
                    apply_grant(paths, agent.as_ref(), ASTATION_ID, grant.as_ref())?
                }
                _ => return Ok(None),
            };
            let applied = format!("{applied:?}");
            self.applied.push(applied.clone());
            Ok(Some(applied))
        }
    }

    const K_KID: &str = "0123abcd";

    /// `encryptionMode` signed by the pinned Astation.
    fn signed_mode(server: &FakeKeyServer, mode: EncryptionMode, epoch: u64) -> AstationMessage {
        let state = AccountState {
            account: ACCOUNT.into(),
            sign_gen: 1,
            mode,
            kid: mode.requires_key().then(|| K_KID.to_string()),
            epoch,
        };
        AstationMessage::EncryptionMode {
            account_state: Some(server.astation.sign(&state.encode())),
        }
    }

    /// `keyGrant` of `K` (kid `K_KID`) for this device.
    fn k_grant(server: &FakeKeyServer, keys: &DeviceKeys) -> AstationMessage {
        AstationMessage::KeyGrant {
            grant: Some(seal_k_grant(
                &server.astation,
                ACCOUNT,
                DEVICE_ID,
                keys.device_pub(),
                K_KID,
                [42; 32],
            )),
        }
    }

    #[tokio::test]
    async fn an_encryption_mode_that_arrives_during_the_unlock_is_applied() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, _) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        set_state(&paths, &server.astation, EncryptionMode::Off, None, 58);
        let mut link = ScriptedLink::new(server).with_keys(&paths, &agent);
        let mode = signed_mode(&link.server, EncryptionMode::On, 59);
        link.inbox.push_back(mode);
        unlock_via(&mut link, &agent, &paths, ASTATION_ID, WAIT)
            .await
            .unwrap();
        let state = account_mode(&paths.trust, ASTATION_ID).unwrap();
        assert_eq!(state.mode, EncryptionMode::On);
        assert_eq!(state.kid.as_deref(), Some(K_KID));
        assert!(
            link.applied.iter().any(|a| a.starts_with("ModeChanged")),
            "{:?}",
            link.applied
        );
    }

    #[test]
    fn a_migration_is_pending_only_while_enabling_or_disabling() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, _) = sealed_device(dir.path(), "0a1b2c3d");
        for (mode, pending) in [
            (EncryptionMode::Off, false),
            (EncryptionMode::Enabling, true),
            (EncryptionMode::On, false),
            (EncryptionMode::Disabling, true),
        ] {
            let kid = mode.requires_key().then_some(K_KID);
            set_state(&paths, &server.astation, mode, kid, 10 + mode as u64);
            let trust = TrustStore::load_from(&paths.trust).unwrap();
            assert_eq!(
                migration_pending(&trust, ASTATION_ID).unwrap(),
                pending,
                "{mode:?}"
            );
        }
    }

    #[tokio::test]
    async fn finishing_a_migration_applies_the_state_astation_sends_on_connect() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, _) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        set_state(&paths, &server.astation, EncryptionMode::Off, None, 58);
        let mut link = ScriptedLink::new(server).with_keys(&paths, &agent);
        let mode = signed_mode(&link.server, EncryptionMode::On, 59);
        // Unrelated traffic first, then the state.
        link.inbox.push_back(AstationMessage::Heartbeat {
            timestamp: "1".into(),
        });
        link.inbox.push_back(mode);
        finish_migration(&mut link, WAIT).await;
        assert_eq!(link.applied.len(), 1, "{:?}", link.applied);
        assert!(
            link.applied[0].starts_with("ModeChanged"),
            "{:?}",
            link.applied
        );
        assert_eq!(
            account_mode(&paths.trust, ASTATION_ID).unwrap().mode,
            EncryptionMode::On
        );
    }

    #[tokio::test]
    async fn a_key_grant_that_arrives_after_the_unlock_is_installed() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, keys) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        let mut link = ScriptedLink::new(server).with_keys(&paths, &agent);
        let (mode, grant) = (
            signed_mode(&link.server, EncryptionMode::On, 2),
            k_grant(&link.server, &keys),
        );
        // A grant before the unlock can't be opened yet; the same grant
        // during the rotation can.
        link.inbox.extend([mode, grant.clone()]);
        link.on_rotate = Some(grant);
        unlock_and_rotate(&mut link, &agent, &paths, ASTATION_ID, WAIT)
            .await
            .unwrap();
        assert_eq!(link.applied[1], "Locked", "{:?}", link.applied);
        assert_eq!(agent.held_kid(ASTATION_ID).unwrap().as_deref(), Some(K_KID));
        assert_eq!(link.key_requests, 0, "K arrived without asking");
    }

    #[tokio::test]
    async fn a_key_still_needed_after_the_unlock_is_requested() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, keys) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        let mut link = ScriptedLink::new(server).with_keys(&paths, &agent);
        let mode = signed_mode(&link.server, EncryptionMode::On, 2);
        link.key_grant = Some(k_grant(&link.server, &keys));
        link.inbox.push_back(mode);
        unlock_and_rotate(&mut link, &agent, &paths, ASTATION_ID, WAIT)
            .await
            .unwrap();
        assert_eq!(link.key_requests, 1);
        assert_eq!(agent.held_kid(ASTATION_ID).unwrap().as_deref(), Some(K_KID));
    }

    #[tokio::test]
    async fn an_unlock_without_an_encryption_mode_asks_for_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, _) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        set_state(&paths, &server.astation, EncryptionMode::Off, None, 58);
        let mut link = ScriptedLink::new(server).with_keys(&paths, &agent);
        unlock_and_rotate(&mut link, &agent, &paths, ASTATION_ID, WAIT)
            .await
            .unwrap();
        assert_eq!(link.key_requests, 0);
        let state = account_mode(&paths.trust, ASTATION_ID).unwrap();
        assert_eq!(state.mode, EncryptionMode::Off);
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
    async fn a_revoked_denial_is_recorded_and_says_to_pair_again() {
        // With the flag, and from an Astation that only says so in the reason.
        for (reason, flag) in [
            ("Denied on the Mac", true),
            (
                "Unlock was denied and this device's verification was REVOKED.",
                false,
            ),
            (
                "The request does not belong to this verified device and account.",
                false,
            ),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let (paths, server, _) = sealed_device(dir.path(), "0a1b2c3d");
            let agent = agent(&paths);
            let mut link = ScriptedLink::new(server);
            link.deny = Some(reason.into());
            link.deny_revoked = flag;
            let before = now_secs();
            let error = error_of(unlock_via(&mut link, &agent, &paths, ASTATION_ID, WAIT).await);
            assert!(error.contains(reason), "{error}");
            assert!(
                error.contains("this device was revoked; run `atem pair` to verify it again"),
                "{error}"
            );
            let trust = TrustStore::load_from(&paths.trust).unwrap();
            let revoked = trust.revoked().expect("the revocation is recorded");
            assert_eq!(revoked.astation_id, ASTATION_ID);
            assert!(revoked.at >= before && revoked.at <= now_secs());
            assert!(!agent.status().unwrap().unlocked);
        }
    }

    #[tokio::test]
    async fn a_plain_denial_records_no_revocation() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, _) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        let mut link = ScriptedLink::new(server);
        link.deny = Some("Denied on the Mac".into());
        let error = error_of(unlock_via(&mut link, &agent, &paths, ASTATION_ID, WAIT).await);
        assert!(!error.contains("revoked"), "{error}");
        assert!(
            TrustStore::load_from(&paths.trust)
                .unwrap()
                .revoked()
                .is_none()
        );
    }

    #[test]
    fn status_shows_a_recorded_revocation() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, _server, _) = sealed_device(dir.path(), "0a1b2c3d");
        let mut trust = TrustStore::load_from(&paths.trust).unwrap();
        // 2025-04-01 08:50 UTC
        trust.record_revoked(ASTATION_ID, 1743497400);
        let report = status_report(&trust, ASTATION_ID, &AgentState::NotRunning, None, None);
        assert!(
            report.starts_with(
                "Verified: revoked by Astation astation-1 (2025-04-01 08:50 UTC); run 'atem pair' to verify this device again\n"
            ),
            "{report}"
        );
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

    #[tokio::test]
    async fn an_astation_that_never_answers_times_out() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, _) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        let mut link = ScriptedLink::new(server);
        link.silent = true;
        link.hang = true;
        let wait = Duration::from_millis(50);
        let error = error_of(unlock_via(&mut link, &agent, &paths, ASTATION_ID, wait).await);
        assert!(
            error.contains("timed out waiting for Astation to approve the unlock"),
            "{error}"
        );
        assert!(!agent.status().unwrap().unlocked);
    }

    /// A device whose storage key no Astation ever confirmed holding (a
    /// fresh device or a migrated step-1 one before its first escrow),
    /// unlocked in its agent.
    fn never_escrowed(dir: &std::path::Path) -> (KeyPaths, FakeKeyServer, Arc<dyn KeyAgentApi>) {
        let (paths, mut server, keys) = sealed_device(dir, "0a1b2c3d");
        let mut raw: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&paths.trust).unwrap()).unwrap();
        raw.as_object_mut().unwrap().remove("escrowed_storage_kid");
        std::fs::write(&paths.trust, serde_json::to_vec(&raw).unwrap()).unwrap();
        assert_eq!(
            TrustStore::load_from(&paths.trust).unwrap().escrowed_kid(),
            None
        );
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
        (paths, server, agent)
    }

    /// `atem cred status` for `paths` with the agent as it is now.
    fn status_now(paths: &KeyPaths, agent: &Arc<dyn KeyAgentApi>) -> String {
        status_report(
            &TrustStore::load_from(&paths.trust).unwrap(),
            ASTATION_ID,
            &AgentState::Running(agent.status().unwrap()),
            None,
            None,
        )
    }

    #[tokio::test]
    async fn status_says_an_astation_that_never_answered_the_first_escrow_gets_it_later() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, agent) = never_escrowed(dir.path());
        // An Astation without storage-key support drops storageKeyRotate.
        let mut link = ScriptedLink::new(server);
        link.silent = true;
        link.hang = true;
        let wait = Duration::from_millis(50);
        let error = error_of(rotate_via(&mut link, &agent, &paths, ASTATION_ID, wait).await);
        assert!(error.contains("timed out"), "{error}");
        let report = status_now(&paths, &agent);
        assert!(
            report.contains("Storage key: 0a1b2c3d  (not yet held by Astation: it hasn't answered"),
            "{report}"
        );
        assert!(report.contains("once it does"), "{report}");
        assert!(!report.contains("run 'atem cred unlock'"), "{report}");
        // Once an Astation takes it, the note goes.
        link.silent = false;
        link.hang = false;
        rotate_via(&mut link, &agent, &paths, ASTATION_ID, WAIT)
            .await
            .unwrap();
        let report = status_now(&paths, &agent);
        assert!(!report.contains("not yet held"), "{report}");
        assert!(
            !TrustStore::load_from(&paths.trust)
                .unwrap()
                .escrow_unanswered()
        );
    }

    #[tokio::test]
    async fn a_rotation_timeout_after_the_first_escrow_still_says_run_unlock() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, keys) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        let storage_key = [9u8; 32];
        SealedDeviceKeys::seal(&keys, DEVICE_ID, "0a1b2c3d", &storage_key)
            .unwrap()
            .save_to(&paths.device_keys_sealed)
            .unwrap();
        agent
            .load_unlocked(DEVICE_ID, &keys, "0a1b2c3d", &storage_key)
            .unwrap();
        let mut link = ScriptedLink::new(server);
        link.silent = true;
        link.hang = true;
        let wait = Duration::from_millis(50);
        assert!(
            error_of(rotate_via(&mut link, &agent, &paths, ASTATION_ID, wait).await)
                .contains("timed out")
        );
        // This Astation took storage keys before: a lost answer isn't a sign
        // it can't.
        let trust = TrustStore::load_from(&paths.trust).unwrap();
        assert!(!trust.escrow_unanswered());
        let waiting = AgentState::Running(AgentStatus {
            unlocked: true,
            storage_kid: Some("4e5f6a7b".into()),
            escrowed: false,
        });
        let report = status_report(&trust, ASTATION_ID, &waiting, None, None);
        assert!(
            report.contains("(not yet held by Astation; run 'atem cred unlock')"),
            "{report}"
        );
    }

    #[test]
    fn a_first_escrow_nobody_answered_says_when_it_completes() {
        let message =
            escrow_failure_message(&anyhow!(NoAnswer("to store the new storage key".into())));
        assert!(message.contains("may not support"), "{message}");
        assert!(message.contains("plain"), "{message}");
        assert!(!message.contains(RESET), "{message}");
    }

    #[tokio::test]
    async fn a_grant_for_an_earlier_request_is_skipped_and_the_real_one_unlocks() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, _) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        let mut link = ScriptedLink::new(server);
        // Astation's answer to an earlier attempt, replayed by a relay.
        let earlier = signed_request(agent.as_ref(), &paths, ASTATION_ID).unwrap();
        let old = link.server.grant_unlock(&earlier).unwrap();
        link.stale = Some(AstationMessage::UnlockGrant {
            grant: old.grant,
            encapped_key: old.encapped_key,
            ciphertext: old.ciphertext,
        });
        let kid = unlock_via(&mut link, &agent, &paths, ASTATION_ID, WAIT)
            .await
            .unwrap();
        assert_eq!(kid, "0a1b2c3d");
        assert!(agent.status().unwrap().unlocked);
    }

    #[tokio::test]
    async fn a_grant_signed_by_anyone_else_is_skipped_until_the_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, _) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        let mut link = ScriptedLink::new(server);
        link.forger = Some(FakeAstation::new());
        link.hang = true;
        let wait = Duration::from_millis(200);
        let error = error_of(unlock_via(&mut link, &agent, &paths, ASTATION_ID, wait).await);
        assert!(error.contains("timed out"), "{error}");
        assert!(!agent.status().unwrap().unlocked);
    }

    #[tokio::test]
    async fn an_ack_for_another_key_is_skipped_and_the_real_one_confirms() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, _) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        let mut link = ScriptedLink::new(server);
        unlock_via(&mut link, &agent, &paths, ASTATION_ID, WAIT)
            .await
            .unwrap();
        // A genuine ack for an older rotation, replayed.
        let old = StorageAck {
            account: ACCOUNT.into(),
            sign_gen: 1,
            device_id: DEVICE_ID.into(),
            storage_kid: "ffffffff".into(),
        };
        link.stale = Some(AstationMessage::StorageKeyAck {
            ack: link.server.astation.sign(&old.encode()),
        });
        let new_kid = rotate_via(&mut link, &agent, &paths, ASTATION_ID, WAIT)
            .await
            .unwrap();
        assert_eq!(sealed_kid(&paths.device_keys_sealed), new_kid);
        assert!(link.server.pending.is_none());
        assert_eq!(agent.status().unwrap().storage_kid, Some(new_kid));
    }

    #[tokio::test]
    async fn astation_text_is_shown_without_control_characters() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, _) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        let mut link = ScriptedLink::new(server);
        unlock_via(&mut link, &agent, &paths, ASTATION_ID, WAIT)
            .await
            .unwrap();
        link.reject = Some(("busy\u{1b}[2J\u{7}\nnow".into(), None));
        let error = error_of(rotate_via(&mut link, &agent, &paths, ASTATION_ID, WAIT).await);
        assert!(!error.chars().any(char::is_control), "{error:?}");
        assert!(error.contains("busy[2Jnow"), "{error}");

        agent.lock_keys().unwrap();
        std::fs::remove_file(&paths.device_keys_next).unwrap();
        unlock_via(&mut link, &agent, &paths, ASTATION_ID, WAIT)
            .await
            .unwrap();
        link.reject = Some(("pending".into(), Some("\u{1b}]0;x\u{7}".into())));
        let error = error_of(rotate_via(&mut link, &agent, &paths, ASTATION_ID, WAIT).await);
        assert!(!error.chars().any(char::is_control), "{error:?}");

        let other = tempfile::tempdir().unwrap();
        let (paths, server, _) = sealed_device(other.path(), "0a1b2c3d");
        let agent = super::tests::agent(&paths);
        let mut link = ScriptedLink::new(server);
        link.deny = Some("no\u{1b}[31m\rway".into());
        let error = error_of(unlock_via(&mut link, &agent, &paths, ASTATION_ID, WAIT).await);
        assert!(!error.chars().any(char::is_control), "{error:?}");
        assert!(error.contains("no[31mway"), "{error}");
    }

    #[tokio::test]
    async fn a_lost_confirmation_after_the_promotion_is_only_a_warning() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, _) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        let mut link = ScriptedLink::new(server);
        unlock_via(&mut link, &agent, &paths, ASTATION_ID, WAIT)
            .await
            .unwrap();
        link.fail_confirm = true;
        let new_kid = rotate_via(&mut link, &agent, &paths, ASTATION_ID, WAIT)
            .await
            .unwrap();
        assert_eq!(sealed_kid(&paths.device_keys_sealed), new_kid);
        // Astation still holds it as pending: the next unlock settles it.
        assert_eq!(
            link.server.pending.as_ref().map(|(kid, _)| kid.clone()),
            Some(new_kid.clone())
        );
        agent.lock_keys().unwrap();
        link.fail_confirm = false;
        assert_eq!(
            unlock_via(&mut link, &agent, &paths, ASTATION_ID, WAIT)
                .await
                .unwrap(),
            new_kid
        );
        assert!(link.server.pending.is_none(), "the unlock confirmed it");
        assert_eq!(
            link.server.storage_keys.keys().cloned().collect::<Vec<_>>(),
            vec![new_kid.clone()]
        );
        // And the next rotation goes from it without a refusal.
        rotate_via(&mut link, &agent, &paths, ASTATION_ID, WAIT)
            .await
            .unwrap();
        assert_eq!(link.abandons, 0);
    }

    #[test]
    fn status_report_shows_each_agent_state() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, _server, _) = sealed_device(dir.path(), "0a1b2c3d");
        let trust = TrustStore::load_from(&paths.trust).unwrap();
        assert_eq!(
            status_report(
                &trust,
                ASTATION_ID,
                &AgentState::NotRunning,
                Some("0a1b2c3d"),
                None
            ),
            "Verified: yes  (safety code AAAA-BBBB-CCCC)\n\
             Home Astation: astation-1\n\
             Key agent: not running (starts with 'atem cred unlock')\n\
             Storage key: 0a1b2c3d\n"
        );
        let waiting = AgentState::Running(AgentStatus {
            unlocked: true,
            storage_kid: Some("4e5f6a7b".into()),
            escrowed: false,
        });
        let report = status_report(&trust, ASTATION_ID, &waiting, None, None);
        assert!(report.contains("Key agent: unlocked\n"), "{report}");
        assert!(
            report.contains(
                "Storage key: 4e5f6a7b  (not yet held by Astation; run 'atem cred unlock')"
            ),
            "{report}"
        );
        let locked = AgentState::Running(AgentStatus {
            unlocked: false,
            storage_kid: Some("0a1b2c3d".into()),
            escrowed: false,
        });
        let report = status_report(&trust, ASTATION_ID, &locked, None, None);
        assert!(
            report.contains("Key agent: locked (run 'atem cred unlock')"),
            "{report}"
        );
        assert!(report.contains("Storage key: 0a1b2c3d\n"), "{report}");
        // A locked agent's sealed file under a key Astation never confirmed
        // is flagged, as when the agent isn't running.
        let unconfirmed = AgentState::Running(AgentStatus {
            unlocked: false,
            storage_kid: Some("9a9b9c9d".into()),
            escrowed: false,
        });
        let report = status_report(&trust, ASTATION_ID, &unconfirmed, None, None);
        assert!(
            report.contains("Storage key: 9a9b9c9d  (not yet held by Astation"),
            "{report}"
        );
        let broken = AgentState::Unreachable("protocol v2".into());
        assert!(
            status_report(&trust, ASTATION_ID, &broken, Some("0a1b2c3d"), None)
                .contains("Key agent: not answering (protocol v2)")
        );
        let report = status_report(
            &TrustStore::default(),
            ASTATION_ID,
            &AgentState::NotRunning,
            None,
            None,
        );
        assert!(report.starts_with("Verified: no"), "{report}");
        assert!(report.contains("Home Astation: none (verify with 'atem pair')"));
        assert!(report.contains("Storage key: none"));
        let report = status_report(
            &trust,
            ASTATION_ID,
            &AgentState::NotRunning,
            None,
            Some("unlock_auth_key is missing"),
        );
        assert!(
            report.ends_with(&format!("Key files: unlock_auth_key is missing\n{RESET}\n")),
            "{report}"
        );
    }

    #[test]
    fn the_reset_names_every_key_file_and_the_trust_state() {
        assert_eq!(
            RESET,
            "To start over: delete ~/.config/atem/device_keys, device_keys.sealed, device_keys.sealed.next, device_keys.sealed.prev, unlock_auth_key and cred_state.json, then run `atem pair`. device_keys.sealed also holds the memory encryption key and its older keys: Astation grants the current key again, older keys may not come back."
        );
    }

    #[test]
    fn key_file_problems_are_found() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, _server, _) = sealed_device(dir.path(), "0a1b2c3d");
        let trust = TrustStore::load_from(&paths.trust).unwrap();
        assert_eq!(key_file_problem(&paths, &trust), None);
        std::fs::remove_file(&paths.unlock_auth_key).unwrap();
        let problem = key_file_problem(&paths, &trust).unwrap();
        assert!(problem.contains("unlock_auth_key"), "{problem}");
        std::fs::write(&paths.device_keys_sealed, b"junk").unwrap();
        let problem = key_file_problem(&paths, &trust).unwrap();
        assert!(problem.contains("device_keys.sealed"), "{problem}");
        std::fs::remove_file(&paths.device_keys_sealed).unwrap();
        let problem = key_file_problem(&paths, &trust).unwrap();
        assert!(problem.contains("no sealed keys"), "{problem}");
        // A device that was never verified has nothing to fix.
        let empty = tempfile::tempdir().unwrap();
        assert_eq!(
            key_file_problem(&KeyPaths::in_dir(empty.path()), &TrustStore::default()),
            None
        );
    }

    #[tokio::test]
    async fn an_unlock_failing_on_the_key_files_shows_the_reset() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, _) = sealed_device(dir.path(), "0a1b2c3d");
        std::fs::remove_file(&paths.unlock_auth_key).unwrap();
        let agent = agent(&paths);
        let mut link = ScriptedLink::new(server);
        let error = error_of(unlock_via(&mut link, &agent, &paths, ASTATION_ID, WAIT).await);
        assert!(error.contains(RESET), "{error}");
    }

    #[tokio::test]
    async fn the_unlock_command_unlocks_rotates_and_then_has_nothing_to_do() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, _) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        let mut link = ScriptedLink::new(server);
        unlock_and_rotate(&mut link, &agent, &paths, ASTATION_ID, WAIT)
            .await
            .unwrap();
        let status = agent.status().unwrap();
        assert!(status.unlocked && status.escrowed);
        assert_ne!(status.storage_kid.as_deref(), Some("0a1b2c3d"), "rotated");
        assert_eq!(link.rotates, 1);
        unlock_and_rotate(&mut link, &agent, &paths, ASTATION_ID, WAIT)
            .await
            .unwrap();
        assert_eq!(link.rotates, 1, "already unlocked and escrowed");
    }

    #[tokio::test]
    async fn a_refused_rotation_after_the_unlock_is_only_a_warning() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, _) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        let mut link = ScriptedLink::new(server);
        link.reject = Some(("not now".into(), None));
        unlock_and_rotate(&mut link, &agent, &paths, ASTATION_ID, WAIT)
            .await
            .unwrap();
        let status = agent.status().unwrap();
        assert!(status.unlocked);
        assert_eq!(status.storage_kid.as_deref(), Some("0a1b2c3d"));
    }

    /// A freshly verified device: unlocked, sealed under a key Astation
    /// doesn't hold yet, the first escrow begun (outcome.escrow).
    fn fresh_device(dir: &std::path::Path) -> (KeyPaths, FakeKeyServer, Arc<dyn KeyAgentApi>) {
        let (paths, mut server, keys) = sealed_device(dir, "0a1b2c3d");
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
        (paths, server, agent)
    }

    #[tokio::test]
    async fn pairing_sends_the_escrow_it_began_and_confirms_it() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, agent) = fresh_device(dir.path());
        let escrow = agent.begin_rotation(ASTATION_ID).unwrap();
        let mut link = ScriptedLink::new(server);
        assert_eq!(
            pair_escrow(&mut link, &agent, &paths, ASTATION_ID, Some(escrow))
                .await
                .unwrap(),
            PairEscrow::Escrowed("0a1b2c3d".into())
        );
        assert_eq!(link.rotates, 1);
        assert_eq!(link.server.storage_keys.get("0a1b2c3d"), Some(&[9u8; 32]));
        assert!(agent.status().unwrap().escrowed);
        assert_eq!(agent.pending_rotation().unwrap(), None);
        assert!(
            lock_keys_message(Some(agent.as_ref()))
                .unwrap()
                .contains("Locked")
        );
    }

    #[tokio::test]
    async fn pairing_without_a_prepared_escrow_still_hands_over_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, agent) = fresh_device(dir.path());
        let mut link = ScriptedLink::new(server);
        assert_eq!(
            pair_escrow(&mut link, &agent, &paths, ASTATION_ID, None)
                .await
                .unwrap(),
            PairEscrow::Escrowed("0a1b2c3d".into())
        );
        assert!(agent.status().unwrap().escrowed);
    }

    #[tokio::test]
    async fn a_grant_with_an_invalid_storage_kid_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, mut server, _) = sealed_device(dir.path(), "0a1b2c3d");
        server.storage_keys.insert("NOT-A-KID".into(), [1; 32]);
        let agent = agent(&paths);
        let mut link = ScriptedLink::new(server);
        link.grant_kid = Some("NOT-A-KID".into());
        link.hang = true;
        let wait = Duration::from_millis(200);
        let error = error_of(unlock_via(&mut link, &agent, &paths, ASTATION_ID, wait).await);
        assert!(error.contains("timed out"), "{error}");
        assert!(!agent.status().unwrap().unlocked);
    }

    #[tokio::test]
    async fn pairing_with_another_astation_leaves_the_escrow_to_the_home_one() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, _) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        let mut link = ScriptedLink::new(server);
        // Locked, nothing pending: the home Astation holds the key.
        let outcome = pair_escrow(&mut link, &agent, &paths, "astation-2", None)
            .await
            .unwrap();
        assert_eq!(outcome, PairEscrow::HeldByHome(ASTATION_ID.into()));
        // Unlocked through the home Astation, so escrowed: still nothing to do.
        unlock_via(&mut link, &agent, &paths, ASTATION_ID, WAIT)
            .await
            .unwrap();
        assert!(agent.status().unwrap().escrowed);
        let outcome = pair_escrow(&mut link, &agent, &paths, "astation-2", None)
            .await
            .unwrap();
        assert_eq!(outcome, PairEscrow::HeldByHome(ASTATION_ID.into()));
        assert_eq!(link.rotates, 0);
    }

    #[tokio::test]
    async fn pairing_with_another_astation_checks_a_locked_agent_against_the_escrowed_kid() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, _) = sealed_device(dir.path(), "0a1b2c3d");
        // The sealed file's key isn't the one Astation is known to hold.
        let mut trust = TrustStore::load_from(&paths.trust).unwrap();
        trust.set_escrowed_kid("ffffffff");
        trust.save_to(&paths.trust).unwrap();
        let agent = agent(&paths);
        assert!(!agent.status().unwrap().unlocked);
        let mut link = ScriptedLink::new(server);
        let error = error_of(pair_escrow(&mut link, &agent, &paths, "astation-2", None).await);
        assert!(error.contains("atem cred unlock"), "{error}");
        assert_eq!(link.rotates, 0);
    }

    #[tokio::test]
    async fn pairing_with_another_astation_while_the_home_lacks_the_key_says_to_unlock() {
        let dir = tempfile::tempdir().unwrap();
        // Unlocked with a storage key the home Astation doesn't hold yet.
        let (paths, server, agent) = fresh_device(dir.path());
        let mut link = ScriptedLink::new(server);
        let error = error_of(pair_escrow(&mut link, &agent, &paths, "astation-2", None).await);
        assert!(error.contains("atem cred unlock"), "{error}");
        assert!(error.contains(ASTATION_ID), "{error}");
        // A rotation pending in the agent needs the home Astation too.
        agent.begin_rotation(ASTATION_ID).unwrap();
        let error = error_of(pair_escrow(&mut link, &agent, &paths, "astation-2", None).await);
        assert!(error.contains("atem cred unlock"), "{error}");
        assert_eq!(link.rotates, 0);
    }

    #[test]
    fn shown_text_drops_bidi_and_format_characters() {
        let text = "a\u{200b}b\u{200f}c\u{202a}d\u{202e}e\u{2066}f\u{2069}g";
        assert_eq!(shown(text), "abcdefg");
        let text = "a\u{061c}b\u{2060}c\u{2064}d\u{2065}e\u{feff}f";
        assert_eq!(shown(text), "abcdef");
    }

    #[test]
    fn status_without_the_agent_flags_a_storage_key_astation_never_confirmed() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, _server, _) = sealed_device(dir.path(), "0a1b2c3d");
        let mut trust = TrustStore::load_from(&paths.trust).unwrap();
        trust.set_escrowed_kid("ffffffff");
        for agent in [AgentState::NotRunning, AgentState::Unreachable("v2".into())] {
            let report = status_report(&trust, ASTATION_ID, &agent, Some("0a1b2c3d"), None);
            assert!(
                report.contains(
                    "Storage key: 0a1b2c3d  (not yet held by Astation; run 'atem cred unlock')"
                ),
                "{report}"
            );
        }
    }

    #[tokio::test]
    async fn unlock_has_nothing_to_ask_only_when_unlocked_escrowed_and_settled() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, _) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        assert_eq!(
            already_unlocked(agent.as_ref(), &paths, ASTATION_ID).unwrap(),
            None
        );
        let mut link = ScriptedLink::new(server);
        unlock_via(&mut link, &agent, &paths, ASTATION_ID, WAIT)
            .await
            .unwrap();
        assert!(
            already_unlocked(agent.as_ref(), &paths, ASTATION_ID)
                .unwrap()
                .unwrap()
                .contains("Already unlocked (storage key 0a1b2c3d)")
        );
        // A rotation waiting to be resent needs Astation.
        agent.begin_rotation(ASTATION_ID).unwrap();
        assert_eq!(
            already_unlocked(agent.as_ref(), &paths, ASTATION_ID).unwrap(),
            None
        );
    }

    #[test]
    fn a_failed_escrow_says_what_to_do() {
        let message = escrow_failure_message(&anyhow!("timed out"));
        assert!(message.contains("timed out"), "{message}");
        assert!(message.contains("atem cred unlock"), "{message}");
        assert!(message.contains("plain"), "{message}");
        assert!(
            !message.contains("refused"),
            "locking is always allowed: {message}"
        );
        assert!(!message.contains(RESET), "nothing needs a reset: {message}");
    }

    #[test]
    fn lock_reports_what_it_did() {
        assert!(lock_keys_message(None).unwrap().contains("isn't running"));
        let dir = tempfile::tempdir().unwrap();
        let (paths, _server, _) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        assert!(
            lock_keys_message(Some(agent.as_ref()))
                .unwrap()
                .contains("Locked")
        );
    }

    #[test]
    fn boot_id_is_trimmed_or_empty() {
        let id = boot_id();
        assert_eq!(id, id.trim());
    }
}
