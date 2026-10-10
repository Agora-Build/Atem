//! Device verification: commit-then-reveal, a 12-character safety code both
//! sides show, then applying what a verified Astation sends.
//! See designs/e2e-encryption.md "Devices → Verification".
use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use std::path::{Path, PathBuf};

use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::memory::crypto::EncryptionMode;
use crate::memory::device_keys::{DeviceKeys, DevicePublics, PublicKeys, UnlockAuthKey};
use crate::memory::encoding::{base32_prefix, dec, enc};
use crate::memory::grant::{GrantWire, open_grant};
use crate::memory::key_agent::{KeyAgentApi, LOCKED};
use crate::memory::statements::{AccountState, SignedWire};
use crate::memory::storage_key::{
    SealedDeviceKeys, StorageRotation, new_storage_key, new_storage_kid,
};
use crate::memory::trust::{AstationTrust, TrustStore};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AstationKeys {
    /// SEC1-encoded P-256 public key of Astation's Secure Enclave signing key.
    pub sign_pub: Vec<u8>,
    pub enc_pub: [u8; 32],
    pub recovery_sign_pub: [u8; 32],
    pub nonce_s: [u8; 32],
}

fn decode_exact<const N: usize>(value: &str, what: &str) -> Result<[u8; N]> {
    STANDARD
        .decode(value)
        .with_context(|| format!("{what} is not base64"))?
        .try_into()
        .map_err(|_| anyhow!("{what} has the wrong length"))
}

impl AstationKeys {
    pub fn from_wire(
        sign_pub: &str,
        enc_pub: &str,
        recovery_sign_pub: &str,
        nonce: &str,
    ) -> Result<Self> {
        let sign_pub = STANDARD
            .decode(sign_pub)
            .context("Astation signing key is not base64")?;
        // CryptoKit's x963Representation: an uncompressed SEC1 point, 0x04 ‖ x ‖ y.
        if sign_pub.len() != 65
            || sign_pub[0] != 0x04
            || p256::ecdsa::VerifyingKey::from_sec1_bytes(&sign_pub).is_err()
        {
            return Err(anyhow!(
                "Astation signing key must be an uncompressed 65-byte P-256 point"
            ));
        }
        Ok(Self {
            sign_pub,
            enc_pub: decode_exact(enc_pub, "Astation encryption key")?,
            recovery_sign_pub: decode_exact(recovery_sign_pub, "recovery signing key")?,
            nonce_s: decode_exact(nonce, "Astation nonce")?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reveal {
    pub device_pub: [u8; 32],
    pub device_sign_pub: [u8; 32],
    pub unlock_auth_pub: [u8; 32],
    pub nonce_a: [u8; 32],
}

pub fn commitment_for(reveal: &Reveal) -> [u8; 32] {
    Sha256::digest(enc(&[
        b"atem-verify-commit-v1",
        &reveal.device_pub,
        &reveal.device_sign_pub,
        &reveal.unlock_auth_pub,
        &reveal.nonce_a,
    ]))
    .into()
}

pub fn safety_code(reveal: &Reveal, astation: &AstationKeys) -> String {
    let digest = Sha256::digest(enc(&[
        b"atem-safety-code-v1",
        &reveal.device_pub,
        &reveal.device_sign_pub,
        &reveal.unlock_auth_pub,
        &astation.sign_pub,
        &astation.enc_pub,
        &astation.recovery_sign_pub,
        &reveal.nonce_a,
        &astation.nonce_s,
    ]));
    let raw = base32_prefix(&digest, 12);
    format!("{}-{}-{}", &raw[..4], &raw[4..8], &raw[8..])
}

/// Binds a device certificate to one ceremony:
/// `SHA-256(enc("atem-verify-transcript-v1", commitment, nonce_a, nonce_s))`.
pub fn transcript_for(commitment: &[u8; 32], nonce_a: &[u8; 32], nonce_s: &[u8; 32]) -> [u8; 32] {
    Sha256::digest(enc(&[
        b"atem-verify-transcript-v1",
        commitment,
        nonce_a,
        nonce_s,
    ]))
    .into()
}

/// The keys a verification reveals: fresh ones (first verification, secrets
/// in hand), or this device's sealed keys, which only the key agent opens.
// One short-lived value per verification: boxing the larger variant buys nothing.
#[allow(clippy::large_enum_variant)]
pub enum VerificationKeys {
    Fresh(DeviceKeys),
    Sealed(DevicePublics),
}

impl From<DeviceKeys> for VerificationKeys {
    fn from(keys: DeviceKeys) -> Self {
        Self::Fresh(keys)
    }
}

impl PublicKeys for VerificationKeys {
    fn device_pub(&self) -> [u8; 32] {
        match self {
            Self::Fresh(keys) => keys.device_pub(),
            Self::Sealed(publics) => publics.device_pub,
        }
    }
    fn device_sign_pub(&self) -> [u8; 32] {
        match self {
            Self::Fresh(keys) => keys.device_sign_pub(),
            Self::Sealed(publics) => publics.device_sign_pub,
        }
    }
    fn unlock_auth_pub(&self) -> [u8; 32] {
        match self {
            Self::Fresh(keys) => keys.unlock_auth_pub(),
            Self::Sealed(publics) => publics.unlock_auth_pub,
        }
    }
}

pub struct Handshake {
    keys: VerificationKeys,
    nonce_a: [u8; 32],
}

impl Handshake {
    pub fn start(keys: impl Into<VerificationKeys>) -> Self {
        let mut nonce_a = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce_a);
        Self {
            keys: keys.into(),
            nonce_a,
        }
    }

    pub fn reveal(&self) -> Reveal {
        Reveal {
            device_pub: self.keys.device_pub(),
            device_sign_pub: self.keys.device_sign_pub(),
            unlock_auth_pub: self.keys.unlock_auth_pub(),
            nonce_a: self.nonce_a,
        }
    }

    pub fn commitment(&self) -> [u8; 32] {
        commitment_for(&self.reveal())
    }

    pub fn safety_code(&self, astation: &AstationKeys) -> String {
        safety_code(&self.reveal(), astation)
    }

    pub fn transcript(&self, astation: &AstationKeys) -> [u8; 32] {
        transcript_for(&self.commitment(), &self.nonce_a, &astation.nonce_s)
    }

    pub fn keys(&self) -> &VerificationKeys {
        &self.keys
    }

    pub fn into_keys(self) -> VerificationKeys {
        self.keys
    }
}

/// Every file verification and the key agent read or write. Tests point
/// these at a temp dir.
#[derive(Debug, Clone)]
pub struct KeyPaths {
    /// `data_keys.enc` from build steps 0–2a (`K`, project names, under the
    /// machine-bound key). The key agent moves it into `device_keys_sealed`
    /// and `project_names` at the first unlock and deletes it.
    pub data_keys: PathBuf,
    /// `project_names.json`: `h1.` project hash → readable project key.
    pub project_names: PathBuf,
    pub trust: PathBuf,
    /// The plain step-1 file; the key agent seals it into
    /// `device_keys_sealed` and deletes it.
    pub device_keys: PathBuf,
    pub device_keys_sealed: PathBuf,
    /// Written in rotation phase 1, renamed over `device_keys_sealed` in phase 3.
    pub device_keys_next: PathBuf,
    /// The sealed file a rotation replaced, kept until an unlock proves
    /// Astation holds the new storage key.
    pub device_keys_prev: PathBuf,
    pub unlock_auth_key: PathBuf,
    /// The plain X25519 key from #36; deleted once a device is verified.
    pub legacy_device_key: PathBuf,
    /// Held (flock) by the one key agent serving these files, for its life.
    pub agent_lock: PathBuf,
    /// The socket path that agent listens on, for clients whose runtime
    /// dir differs from the agent's.
    pub agent_socket: PathBuf,
}

impl KeyPaths {
    pub fn default_paths() -> Self {
        Self::in_dir(&crate::config::AtemConfig::config_dir())
    }

    pub fn in_dir(dir: &Path) -> Self {
        Self {
            data_keys: dir.join("data_keys.enc"),
            project_names: dir.join("project_names.json"),
            trust: dir.join("cred_state.json"),
            device_keys: dir.join("device_keys"),
            device_keys_sealed: dir.join("device_keys.sealed"),
            device_keys_next: dir.join("device_keys.sealed.next"),
            device_keys_prev: dir.join("device_keys.sealed.prev"),
            unlock_auth_key: dir.join("unlock_auth_key"),
            legacy_device_key: dir.join("device_key"),
            agent_lock: dir.join("key_agent.lock"),
            agent_socket: dir.join("agent.socket"),
        }
    }
}

#[derive(Debug)]
pub enum Applied {
    Ignored(&'static str),
    Unchanged,
    ModeChanged(AccountState),
    /// A repeated signed pending state resumes a failed or interrupted migration.
    MigrationPending(AccountState),
    KeyInstalled(String),
    /// A key grant arrived while the key agent is locked. After
    /// `atem cred unlock`, atem asks for the key again.
    Locked,
}

/// Applies a signed account state from a verified Astation. Unsigned states,
/// and any state for a device that isn't verified, are ignored.
pub fn apply_account_state(
    paths: &KeyPaths,
    astation_id: &str,
    signed: Option<&SignedWire>,
) -> Result<Applied> {
    let Some(signed) = signed else {
        return Ok(Applied::Ignored(
            "an unsigned encryption mode from the relay",
        ));
    };
    let _trust_lock = TrustStore::lock(&paths.trust)?;
    let mut trust = TrustStore::load_from(&paths.trust)?;
    if trust.verified(astation_id).is_none() {
        return Ok(Applied::Ignored(
            "an encryption mode for a device that isn't verified",
        ));
    }
    let Some(state) = trust.accept_account_state(astation_id, signed)? else {
        if let Some(state) = stored_state(trust.verified(astation_id).unwrap())?
            && matches!(state.mode, EncryptionMode::Enabling | EncryptionMode::Disabling)
        {
            return Ok(Applied::MigrationPending(state));
        }
        return Ok(Applied::Unchanged);
    };
    // Checked before anything is saved: a bad kid leaves the trust store
    // untouched. The signed state is the only record of mode and kid.
    check_state(&state)?;
    trust.save_to(&paths.trust)?;
    Ok(Applied::ModeChanged(state))
}

/// A signed state atem can apply: a well-formed kid, and one whenever the
/// mode needs `K`.
fn check_state(state: &AccountState) -> Result<()> {
    if let Some(kid) = state.kid.as_deref()
        && !crate::memory::crypto::valid_kid(kid)
    {
        bail!("signed account state has an invalid key id");
    }
    if state.mode.requires_key() && state.kid.is_none() {
        bail!("signed account state needs an encryption key but names no key id");
    }
    Ok(())
}

/// The account state stored for a verified Astation (already checked against
/// its signature when it was accepted).
pub(crate) fn stored_state(entry: &AstationTrust) -> Result<Option<AccountState>> {
    entry
        .account_state
        .as_ref()
        .map(|signed| {
            let bytes = STANDARD
                .decode(&signed.statement)
                .context("stored signed state is not base64")?;
            AccountState::parse(&dec(&bytes)?)
        })
        .transpose()
}

/// The newest signed state of every account a verified Astation names: the
/// highest epoch when two name one account (on equal epochs, the state of
/// the smallest Astation id), `None` while none of them has a signed state.
/// The one rule for which `K` an account needs, shared by the key agent
/// (which keys it keeps and uses) and `key_needed` (which it asks for);
/// `effective_state` reads it for one Astation.
pub(crate) fn newest_states(
    trust: &TrustStore,
) -> Result<std::collections::BTreeMap<String, Option<AccountState>>> {
    let mut newest = std::collections::BTreeMap::new();
    for entry in trust.verified_entries() {
        let state = stored_state(entry)?;
        let slot: &mut Option<AccountState> =
            newest.entry(entry.data_account.clone()).or_insert(None);
        // Entries come in Astation id order: strictly newer replaces, so the
        // smallest id keeps an equal epoch.
        if let Some(state) = state
            && slot.as_ref().is_none_or(|current| state.epoch > current.epoch)
        {
            *slot = Some(state);
        }
    }
    Ok(newest)
}

/// The state that governs `astation_id`'s account: `None` when this device
/// isn't verified with it, else its account and the newest signed state of
/// that account across every verified Astation naming it (`newest_states`),
/// `None` while none has sent one. Every caller that reads a mode or kid
/// (the agent's install and `Crypt`, `account_mode`, `key_needed`) uses this
/// one rule, so a stale Astation's older state can't demote a newer `K`.
pub(crate) fn effective_state(
    trust: &TrustStore,
    astation_id: &str,
) -> Result<Option<(String, Option<AccountState>)>> {
    let Some(entry) = trust.verified(astation_id) else {
        return Ok(None);
    };
    let account = entry.data_account.clone();
    let state = newest_states(trust)?.remove(&account).flatten();
    Ok(Some((account, state)))
}

/// What the latest signed account state says for this device and
/// `astation_id` (the newest across the verified Astations naming its
/// account, `effective_state`): the one source of the encryption mode and
/// kid (build step 2b). `data_account` is the Astation id when it isn't
/// verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountMode {
    pub mode: EncryptionMode,
    pub data_account: String,
    pub kid: Option<String>,
}

/// Unverified devices are `off`: they never obey stored state, which may
/// come from the old unauthenticated path. A verified device without a
/// signed state yet must not guess: that is an error.
pub fn account_mode(trust_path: &Path, astation_id: &str) -> Result<AccountMode> {
    let trust = TrustStore::load_from(trust_path)?;
    let Some((data_account, state)) = effective_state(&trust, astation_id)? else {
        return Ok(AccountMode {
            mode: EncryptionMode::Off,
            data_account: astation_id.into(),
            kid: None,
        });
    };
    let state = state.ok_or_else(|| {
        anyhow!("waiting for Astation's signed encryption state; reconnect to Astation")
    })?;
    Ok(AccountMode {
        mode: state.mode,
        data_account,
        kid: state.kid,
    })
}

/// Installs a signed `K` grant for this verified device. The key agent opens
/// it and keeps `K` sealed; nothing returns `K` to this process.
pub fn apply_grant(
    paths: &KeyPaths,
    agent: &dyn KeyAgentApi,
    astation_id: &str,
    grant: Option<&GrantWire>,
) -> Result<Applied> {
    let Some(grant) = grant else {
        return Ok(Applied::Ignored("an unsigned key grant from the relay"));
    };
    let trust = TrustStore::load_from(&paths.trust)?;
    if trust.verified(astation_id).is_none() {
        return Ok(Applied::Ignored(
            "a key grant for a device that isn't verified",
        ));
    }
    if !agent.status()?.unlocked {
        return Ok(Applied::Locked);
    }
    match agent.install_grant(astation_id, grant) {
        Ok(kid) => Ok(Applied::KeyInstalled(kid)),
        // Locked between the two calls.
        Err(error) if format!("{error:#}").contains(LOCKED) => Ok(Applied::Locked),
        Err(error) => Err(error),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationOutcome {
    /// The signed mode needs `K` and this device doesn't hold it yet.
    pub key_needed: bool,
    /// After the home Astation's first verification: the new storage key for
    /// Astation (`storageKeyRotate` from old kid `""`), which the CLI must
    /// send, then confirm with the agent once Astation acks it.
    pub escrow: Option<StorageRotation>,
    /// Something the user must act on although verification succeeded.
    pub warning: Option<String>,
}

/// Finishes verification once the user confirmed the code on this device and
/// Astation sent its signed certificate.
///
/// Everything is checked in memory first: the certificate, the signed state
/// and every grant, and that sealed keys are still the ones the unlocked key
/// agent holds. Fresh keys (a device's first verification) make this
/// Astation the home: they are sealed under a new storage key and handed to
/// the key agent before anything is written, so if the agent can't take
/// them nothing is saved. Then the sealed keys (and, for fresh keys, a
/// plain `device_keys` kept until the first escrow is confirmed), the state,
/// the pins and the home are written and the legacy plain key deleted. On
/// any failure before that point nothing is written. Then the key agent
/// installs the grants; a failure there is a warning (`K` is asked for again).
///
/// For fresh keys the outcome carries the storage key for the home Astation
/// (the first escrow), prepared by the agent once the home is saved.
pub fn complete_verification(
    paths: &KeyPaths,
    agent: &dyn KeyAgentApi,
    astation_id: &str,
    keys: VerificationKeys,
    device_verified: &SignedWire,
    account_state: &SignedWire,
    grants: &[GrantWire],
) -> Result<VerificationOutcome> {
    let mut staged = TrustStore::load_from(&paths.trust)?;
    // The account state epoch the certificate is checked against here.
    let checked_epoch = staged
        .verified(astation_id)
        .map_or(0, |previous| previous.account_epoch);
    staged.confirm(astation_id, device_verified)?;
    let changed = staged.accept_account_state(astation_id, account_state)?;
    let entry = staged
        .verified(astation_id)
        .expect("confirmed above")
        .clone();
    let state = match changed {
        Some(state) => state,
        None => stored_state(&entry)?.ok_or_else(|| anyhow!("no signed account state"))?,
    };
    check_state(&state)?;
    match &keys {
        // New keys become the home Astation's to hold: never under another
        // home (R12: the home never moves), which could never unlock them.
        VerificationKeys::Fresh(_) => {
            if has_device_keys(paths) {
                bail!(
                    "this device already has keys; verify with them (run `atem cred unlock`, then `atem pair` again)"
                );
            }
            if staged.home_is_set() && staged.home() != Some(astation_id) {
                bail!(
                    "this device's home Astation is {}; verify with it, or start over (delete ~/.config/atem/cred_state.json too)",
                    staged.recorded_home().unwrap_or_default()
                );
            }
        }
        // Sealed keys never leave the agent: it must hold exactly these.
        VerificationKeys::Sealed(publics) => {
            if !agent.status()?.unlocked {
                bail!("{LOCKED}, then `atem pair` again");
            }
            if agent.public_keys()? != (publics.device_pub, publics.device_sign_pub) {
                bail!("the key agent holds other device keys than this verification revealed");
            }
        }
    }
    // Every grant is checked before anything is written. Fresh keys are in
    // this process anyway, so their grants are opened here and `K` dropped at
    // once; sealed keys' grants are checked in the agent, which drops `K`.
    // The agent installs `K` below, once the pins it checks against are saved.
    let granted_kids = grants
        .iter()
        .map(|grant| match &keys {
            VerificationKeys::Fresh(fresh) => open_grant(&entry, fresh, grant).map(|opened| opened.kid),
            // The staged pins: they aren't saved until everything holds.
            VerificationKeys::Sealed(_) => agent.check_grant(grant, &entry),
        })
        .collect::<Result<Vec<_>>>()?;
    if granted_kids
        .iter()
        .any(|kid| Some(kid.as_str()) != state.kid.as_deref())
    {
        bail!("a key grant names a different key id than the signed account state");
    }

    let sealed = match &keys {
        VerificationKeys::Fresh(fresh) => {
            let storage_key = new_storage_key();
            let storage_kid = staged.pick_storage_kid("", new_storage_kid);
            let sealed =
                SealedDeviceKeys::seal(fresh, &entry.device_id, &storage_kid, &storage_key)?;
            agent.load_unlocked(&entry.device_id, fresh, &storage_kid, &storage_key)?;
            Some((sealed, fresh.unlock_auth_key()))
        }
        VerificationKeys::Sealed(_) => None,
    };
    // Returns the kid whose grants the agent installs afterwards.
    let write = || -> Result<Option<String>> {
        // Fresh keys: no key file exists (checked above). The plain file
        // stays until Astation confirms it holds the storage key (the agent
        // deletes it then), so an agent that stops before that re-seals the
        // keys from it instead of losing them.
        if let (Some((sealed, unlock_auth)), VerificationKeys::Fresh(fresh)) = (&sealed, &keys) {
            sealed.save_to(&paths.device_keys_sealed)?;
            unlock_auth.save_to(&paths.unlock_auth_key)?;
            fresh.save_to(&paths.device_keys)?;
        }
        // The staged changes again, on the store as it is now, under its
        // lock (never held across an agent call): another process's changes
        // since `staged` was loaded aren't lost, and a newer signed state it
        // applied meanwhile is kept, never rolled back.
        let _trust_lock = TrustStore::lock(&paths.trust)?;
        let mut current = TrustStore::load_from(&paths.trust)?;
        let first = current.verified(astation_id).is_none();
        // Accounts the Astations verified before this one name: what is
        // stored for them may be theirs, so a first verification keeps it.
        let named_elsewhere: std::collections::BTreeSet<String> =
            current.verified_entries().map(|entry| entry.data_account.clone()).collect();
        current.confirm_since(astation_id, device_verified, checked_epoch)?;
        let newer = current
            .verified(astation_id)
            .filter(|entry| entry.account_state.is_some() && entry.account_epoch > state.epoch)
            .map(stored_state)
            .transpose()?
            .flatten();
        if newer.is_none() {
            current.accept_account_state(astation_id, account_state)?;
        }
        if sealed.is_some() {
            if current.home_is_set() && current.recorded_home() != Some(astation_id) {
                bail!("another run made a different Astation this device's home");
            }
            current.set_home(astation_id);
        }
        if first {
            // Whatever the unauthenticated path stored for this Astation (K,
            // rotation history, project names) is dropped, not trusted, unless
            // another verified Astation names that account. Lock order:
            // cred_state.json's lock (held) before project_names.lock.
            crate::memory::legacy_keys::purge_unverified_at(&paths.data_keys, astation_id, &state.account, &named_elsewhere)?;
            if !named_elsewhere.contains(&state.account) {
                crate::memory::project_names::forget_account_at(&paths.project_names, &state.account)?;
            }
        }
        current.save_to(&paths.trust)?;
        // Grants are for this verification's state's kid: installed unless
        // the newer state moved to another key (its own grant brings that).
        Ok(newer.map_or(state.kid.clone(), |newer| newer.kid))
    };
    let install_kid = match write() {
        Ok(kid) => kid,
        Err(error) => {
            if let (Some((written, unlock_auth)), VerificationKeys::Fresh(fresh)) = (&sealed, &keys) {
                // Undo the fresh keys entirely: no sealed file without its
                // verification, and no agent holding keys that aren't on disk.
                // Only files this call wrote go: a concurrent pairing run's stay.
                // With the files gone the agent accepts the lock.
                if SealedDeviceKeys::load_from(&paths.device_keys_sealed)
                    .is_ok_and(|file| file.is_some_and(|file| file.storage_kid == written.storage_kid))
                {
                    let _ = remove_if_exists(&paths.device_keys_sealed);
                }
                if UnlockAuthKey::load_from(&paths.unlock_auth_key)
                    .is_ok_and(|file| file.is_some_and(|file| file.public() == unlock_auth.public()))
                {
                    let _ = remove_if_exists(&paths.unlock_auth_key);
                }
                if DeviceKeys::load_from(&paths.device_keys).is_ok_and(|file| {
                    file.is_some_and(|file| file.device_sign_pub() == fresh.device_sign_pub())
                }) {
                    let _ = remove_if_exists(&paths.device_keys);
                }
                if agent
                    .public_keys()
                    .is_ok_and(|held| held == (fresh.device_pub(), fresh.device_sign_pub()))
                {
                    let _ = agent.lock_keys();
                }
            }
            return Err(error);
        }
    };
    remove_if_exists(&paths.legacy_device_key)?;
    let mut warnings = Vec::new();
    // The verification is saved: a K that can't be stored now is asked for
    // again (key_needed below), never a reason to fail.
    for (grant, kid) in grants.iter().zip(&granted_kids) {
        if Some(kid) != install_kid.as_ref() {
            continue;
        }
        if let Err(error) = agent.install_grant(astation_id, grant) {
            warnings.push(format!(
                "the encryption key couldn't be stored in the key agent ({error:#}); atem asks Astation for it again"
            ));
        }
    }
    let escrow = match sealed {
        Some(_) => match agent.begin_rotation(astation_id) {
            Ok(rotation) => Some(rotation),
            Err(error) => {
                warnings.push(format!(
                    "this device's storage key couldn't be prepared for Astation ({error:#}); run `atem cred unlock` before this machine restarts"
                ));
                None
            }
        },
        None => None,
    };
    // Saved: an agent that can't answer means K is asked for, never an error.
    let key_needed = key_needed(paths, agent, astation_id).unwrap_or_else(|error| {
        warnings.push(format!(
            "couldn't check whether the key agent holds the encryption key ({error:#}); atem asks Astation for it"
        ));
        true
    });
    Ok(VerificationOutcome {
        key_needed,
        escrow,
        warning: (!warnings.is_empty()).then(|| warnings.join("; ")),
    })
}

fn remove_if_exists(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Whether this device is verified with `astation_id`, the newest signed
/// state of its account (from any verified Astation naming it, as the key
/// agent decides which keys to keep) needs `K`, and the key agent doesn't
/// hold that `K` (a locked agent counts as not holding it): then it should
/// send `keyRequest`. Blocking: from async code call it inside
/// `key_agent::blocking`.
pub fn key_needed(paths: &KeyPaths, agent: &dyn KeyAgentApi, astation_id: &str) -> Result<bool> {
    let trust = TrustStore::load_from(&paths.trust)?;
    let Some((_, Some(state))) = effective_state(&trust, astation_id)? else {
        return Ok(false);
    };
    if !state.mode.requires_key() {
        return Ok(false);
    }
    match agent.held_kid(astation_id) {
        Ok(held) => Ok(held != state.kid),
        Err(error) if format!("{error:#}").contains(LOCKED) => Ok(true),
        Err(error) => Err(error),
    }
}

/// Whether this device has keys on disk: a plain step-1 file, or any sealed
/// file (the current one, or a rotation's `.next` / `.prev`).
fn has_device_keys(paths: &KeyPaths) -> bool {
    [
        &paths.device_keys,
        &paths.device_keys_sealed,
        &paths.device_keys_next,
        &paths.device_keys_prev,
    ]
    .into_iter()
    .any(|path| path.symlink_metadata().is_ok())
}

/// When the home Astation revoked this device (recorded by `atem cred
/// unlock`) and the key agent is locked, its keys can never unlock again:
/// renames every key file to `<name>.revoked-<stamp>` (never deletes),
/// forgets that Astation's verification, the home and the escrow state, so
/// `device_keys_for_verification` then gives fresh keys. Returns the line to
/// print, or `None` when nothing was revoked (behaviour as before).
///
/// The revocation signal is unsigned (it arrives over the relay). Acting on
/// it only renames the old files aside and re-verifies with a fresh safety
/// code the user compares, so a forged "revoked" can cost a re-pair but
/// never keys (the files stay on disk) or trust (nothing new is trusted
/// without the ceremony). Blocking: call it inside `key_agent::blocking`.
pub fn set_aside_revoked_keys(paths: &KeyPaths, agent: &dyn KeyAgentApi) -> Result<Option<String>> {
    let trust = TrustStore::load_from(&paths.trust)?;
    let Some(revoked) = trust.revoked() else {
        return Ok(None);
    };
    if trust.recorded_home() != Some(revoked.astation_id.as_str()) || agent.status()?.unlocked {
        return Ok(None);
    }
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut moved = Vec::new();
    for path in [
        &paths.device_keys_sealed,
        &paths.device_keys_next,
        &paths.device_keys_prev,
        &paths.unlock_auth_key,
        &paths.device_keys,
    ] {
        if path.symlink_metadata().is_err() {
            continue;
        }
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        let aside = path.with_file_name(format!("{name}.revoked-{stamp}"));
        if aside.symlink_metadata().is_ok() {
            bail!("{} already exists; move it away and run `atem pair` again", aside.display());
        }
        std::fs::rename(path, &aside)
            .with_context(|| format!("couldn't move {} aside", path.display()))?;
        moved.push(name.into_owned());
    }
    let revoked = TrustStore::update(&paths.trust, |store| Ok(store.forget_revoked_keys()))?;
    let by = revoked.map_or_else(String::new, |revoked| format!(" by Astation {}", revoked.astation_id));
    let dir = paths.trust.parent().map(|dir| dir.display().to_string()).unwrap_or_default();
    Ok(Some(format!(
        "This device was revoked{by}: its old keys were moved aside ({} renamed to *.revoked-{stamp} in {dir}); verifying it with new keys.",
        if moved.is_empty() { "no key files".to_string() } else { moved.join(", ") }
    )))
}

/// The keys to verify with: this device's sealed keys when it has them (so
/// every Astation pins the same device key), fresh ones otherwise. Sealed
/// keys are revealed only while the key agent holds them unlocked; starting
/// the agent also seals a plain step-1 `device_keys` file.
pub fn device_keys_for_verification(
    paths: &KeyPaths,
    agent: &dyn KeyAgentApi,
) -> Result<VerificationKeys> {
    if !has_device_keys(paths) {
        return Ok(VerificationKeys::Fresh(DeviceKeys::generate()));
    }
    if !agent.status()?.unlocked {
        bail!("{LOCKED}, then `atem pair` again");
    }
    let (device_pub, device_sign_pub) = agent.public_keys()?;
    let unlock_auth = UnlockAuthKey::load_from(&paths.unlock_auth_key)?.ok_or_else(|| {
        anyhow!(
            "unlock_auth_key is missing. {}",
            crate::memory::key_agent::RESET
        )
    })?;
    Ok(VerificationKeys::Sealed(DevicePublics {
        device_pub,
        device_sign_pub,
        unlock_auth_pub: unlock_auth.public(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn astation() -> AstationKeys {
        AstationKeys {
            sign_pub: vec![4; 65],
            enc_pub: [5; 32],
            recovery_sign_pub: [6; 32],
            nonce_s: [7; 32],
        }
    }

    #[test]
    fn key_paths_name_every_key_file() {
        let paths = KeyPaths::in_dir(std::path::Path::new("/x"));
        assert_eq!(paths.device_keys, std::path::Path::new("/x/device_keys"));
        assert_eq!(paths.device_keys_sealed, std::path::Path::new("/x/device_keys.sealed"));
        assert_eq!(paths.device_keys_next, std::path::Path::new("/x/device_keys.sealed.next"));
        assert_eq!(paths.unlock_auth_key, std::path::Path::new("/x/unlock_auth_key"));
        assert_eq!(paths.project_names, std::path::Path::new("/x/project_names.json"));
    }

    #[test]
    fn verification_reuses_the_sealed_device_keys() {
        let empty = tempfile::tempdir().unwrap();
        let empty_paths = KeyPaths::in_dir(empty.path());
        let fresh_agent = test_agent(&empty_paths);
        assert!(matches!(
            device_keys_for_verification(&empty_paths, &fresh_agent).unwrap(),
            VerificationKeys::Fresh(_)
        ));

        let dir = tempfile::tempdir().unwrap();
        let (paths, agent, _, device_pub) = verify(dir.path(), EncryptionMode::Off);
        let keys = device_keys_for_verification(&paths, &agent).unwrap();
        assert!(matches!(keys, VerificationKeys::Sealed(_)));
        assert_eq!(keys.device_pub(), device_pub);
    }

    #[test]
    fn commitment_matches_the_reveal_and_hides_the_nonce() {
        let first = Handshake::start(DeviceKeys::generate());
        assert_eq!(commitment_for(&first.reveal()), first.commitment());
        let mut changed = first.reveal();
        changed.nonce_a[0] ^= 1;
        assert_ne!(commitment_for(&changed), first.commitment());
    }

    #[test]
    fn safety_code_is_stable_formatted_and_covers_every_key() {
        let handshake = Handshake::start(DeviceKeys::generate());
        let code = handshake.safety_code(&astation());
        assert_eq!(code, handshake.safety_code(&astation()));
        assert_eq!(code.len(), 14);
        assert!(code.chars().enumerate().all(|(i, c)| if i == 4 || i == 9 {
            c == '-'
        } else {
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".contains(c)
        }));

        let mut swapped = astation();
        swapped.recovery_sign_pub = [9; 32];
        assert_ne!(code, handshake.safety_code(&swapped));
        let mut nonce = astation();
        nonce.nonce_s = [8; 32];
        assert_ne!(code, handshake.safety_code(&nonce));
    }

    #[test]
    fn astation_keys_parse_from_base64() {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let keys = AstationKeys::from_wire(
            &STANDARD.encode(FakeAstation::new().sign_pub()),
            &STANDARD.encode([5u8; 32]),
            &STANDARD.encode([6u8; 32]),
            &STANDARD.encode([7u8; 32]),
        )
        .unwrap();
        assert_eq!(keys.enc_pub, [5; 32]);
        assert!(AstationKeys::from_wire("", &STANDARD.encode([5u8; 31]), "", "").is_err());
        let rest = |sign_pub: &[u8]| {
            AstationKeys::from_wire(
                &STANDARD.encode(sign_pub),
                &STANDARD.encode([5u8; 32]),
                &STANDARD.encode([6u8; 32]),
                &STANDARD.encode([7u8; 32]),
            )
        };
        // 65 bytes but not a point on the curve.
        assert!(rest(&[4u8; 65]).is_err());
        // A real key, but compressed (33 bytes): the wire carries x963 only.
        let fake = FakeAstation::new();
        let point = fake.sign_pub();
        let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&point).unwrap();
        assert!(rest(key.to_encoded_point(true).as_bytes()).is_err());
    }

    use crate::memory::crypto::EncryptionMode;
    use crate::memory::grant::seal_k_grant;
    use crate::memory::key_agent::{KeyAgent, holds_k, test_agent};
    use crate::memory::statements::{AccountState, DeviceVerified, FakeAstation};
    use crate::memory::trust::TrustStore;

    const ASTATION_ID: &str = "astation-1";

    fn signed_state(
        fake: &FakeAstation,
        mode: EncryptionMode,
        epoch: u64,
    ) -> crate::memory::statements::SignedWire {
        fake.sign(
            &AccountState {
                account: "acct".into(),
                sign_gen: 1,
                mode,
                kid: Some("0123abcd".into()),
                epoch,
            }
            .encode(),
        )
    }

    /// Runs the atem side of verification against a fake Astation and returns
    /// the paths, the (unlocked) key agent, the fake, and the device public key.
    fn verify(
        dir: &std::path::Path,
        mode: EncryptionMode,
    ) -> (KeyPaths, std::sync::Mutex<KeyAgent>, FakeAstation, [u8; 32]) {
        let paths = KeyPaths::in_dir(dir);
        let agent = test_agent(&paths);
        std::fs::write(&paths.legacy_device_key, [1u8; 32]).unwrap();
        let fake = FakeAstation::new();
        let handshake = Handshake::start(DeviceKeys::generate());
        let astation = AstationKeys {
            sign_pub: fake.sign_pub(),
            enc_pub: [5; 32],
            recovery_sign_pub: [6; 32],
            nonce_s: [7; 32],
        };
        let code = handshake.safety_code(&astation);
        let transcript = handshake.transcript(&astation);
        let mut trust = TrustStore::default();
        trust.set_pending(
            ASTATION_ID,
            "dev-1",
            handshake.keys(),
            &astation,
            &code,
            &transcript,
        );
        trust.save_to(&paths.trust).unwrap();
        let reveal = handshake.reveal();
        let certificate = DeviceVerified {
            account: "acct".into(),
            sign_gen: 1,
            device_id: "dev-1".into(),
            device_pub: reveal.device_pub,
            device_sign_pub: reveal.device_sign_pub,
            unlock_auth_pub: reveal.unlock_auth_pub,
            transcript,
            epoch: 1,
        };
        let grants = if mode.requires_key() {
            vec![seal_k_grant(
                &fake,
                "acct",
                "dev-1",
                reveal.device_pub,
                "0123abcd",
                [42; 32],
            )]
        } else {
            vec![]
        };
        complete_verification(
            &paths,
            &agent,
            ASTATION_ID,
            handshake.into_keys(),
            &fake.sign(&certificate.encode()),
            &signed_state(&fake, mode, 1),
            &grants,
        )
        .unwrap();
        (paths, agent, fake, reveal.device_pub)
    }

    #[test]
    fn the_mode_comes_from_the_signed_state_only() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, _, fake, _) = verify(dir.path(), EncryptionMode::On);
        assert_eq!(
            account_mode(&paths.trust, ASTATION_ID).unwrap(),
            AccountMode {
                mode: EncryptionMode::On,
                data_account: "acct".into(),
                kid: Some("0123abcd".into()),
            }
        );
        apply_account_state(
            &paths,
            ASTATION_ID,
            Some(&signed_state(&fake, EncryptionMode::Disabling, 2)),
        )
        .unwrap();
        assert_eq!(
            account_mode(&paths.trust, ASTATION_ID).unwrap().mode,
            EncryptionMode::Disabling
        );
        // Unverified: off, whatever any file says.
        assert_eq!(
            account_mode(&paths.trust, "astation-2").unwrap(),
            AccountMode {
                mode: EncryptionMode::Off,
                data_account: "astation-2".into(),
                kid: None,
            }
        );
        let trust = TrustStore::load_from(&paths.trust).unwrap();
        assert_eq!(trust.verified_entries().count(), 1);
    }

    #[test]
    fn a_verified_device_without_a_signed_state_has_no_mode() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, _, _, _) = verify(dir.path(), EncryptionMode::Off);
        let raw = std::fs::read_to_string(&paths.trust)
            .unwrap()
            .replace("\"account_state\": {", "\"account_state_was\": {");
        std::fs::write(&paths.trust, raw).unwrap();
        let error = format!("{:#}", account_mode(&paths.trust, ASTATION_ID).unwrap_err());
        assert!(error.contains("waiting for Astation's signed encryption state"), "{error}");
    }

    #[test]
    fn verification_installs_signed_state_and_key() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, agent, _, _) = verify(dir.path(), EncryptionMode::On);
        assert_eq!(account_mode(&paths.trust, ASTATION_ID).unwrap().mode, EncryptionMode::On);
        assert!(holds_k(&agent, ASTATION_ID));
        assert!(
            !paths.legacy_device_key.exists(),
            "old plain device_key must be deleted"
        );
        assert!(
            paths.device_keys.exists(),
            "fresh keys stay in plain until the first escrow is confirmed"
        );
        assert!(paths.device_keys_sealed.exists() && paths.unlock_auth_key.exists());
        assert!(agent.status().unwrap().unlocked);
    }

    #[test]
    fn unsigned_or_forged_mode_changes_are_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, agent, _, _) = verify(dir.path(), EncryptionMode::On);
        assert!(matches!(
            apply_account_state(&paths, ASTATION_ID, None).unwrap(),
            Applied::Ignored(_)
        ));
        let forged = signed_state(&FakeAstation::new(), EncryptionMode::Off, 9);
        assert!(apply_account_state(&paths, ASTATION_ID, Some(&forged)).is_err());
        assert_eq!(
            account_mode(&paths.trust, ASTATION_ID).unwrap().mode,
            EncryptionMode::On,
            "the mode must survive"
        );
        assert!(holds_k(&agent, ASTATION_ID), "K must survive");
    }

    #[test]
    fn signed_newer_state_is_applied() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, _, fake, _) = verify(dir.path(), EncryptionMode::On);
        let disabling = signed_state(&fake, EncryptionMode::Disabling, 2);
        assert!(matches!(
            apply_account_state(&paths, ASTATION_ID, Some(&disabling)).unwrap(),
            Applied::ModeChanged(_)
        ));
        assert_eq!(
            account_mode(&paths.trust, ASTATION_ID).unwrap().mode,
            EncryptionMode::Disabling
        );
    }

    #[test]
    fn signed_state_with_invalid_kid_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, _, fake, _) = verify(dir.path(), EncryptionMode::On);
        let bad = fake.sign(
            &AccountState {
                account: "acct".into(),
                sign_gen: 1,
                mode: EncryptionMode::Disabling,
                kid: Some("XYZ".into()),
                epoch: 2,
            }
            .encode(),
        );
        assert!(apply_account_state(&paths, ASTATION_ID, Some(&bad)).is_err());
        assert_eq!(
            account_mode(&paths.trust, ASTATION_ID).unwrap().mode,
            EncryptionMode::On
        );
        let trust = TrustStore::load_from(&paths.trust).unwrap();
        assert_eq!(trust.verified(ASTATION_ID).unwrap().account_epoch, 1);
    }

    #[test]
    fn signed_state_needing_a_key_without_kid_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, _, fake, _) = verify(dir.path(), EncryptionMode::On);
        let no_kid = fake.sign(
            &AccountState {
                account: "acct".into(),
                sign_gen: 1,
                mode: EncryptionMode::Disabling,
                kid: None,
                epoch: 2,
            }
            .encode(),
        );
        assert!(apply_account_state(&paths, ASTATION_ID, Some(&no_kid)).is_err());
        let trust = TrustStore::load_from(&paths.trust).unwrap();
        assert_eq!(trust.verified(ASTATION_ID).unwrap().account_epoch, 1);
        assert_eq!(
            account_mode(&paths.trust, ASTATION_ID).unwrap().mode,
            EncryptionMode::On
        );
    }

    #[test]
    fn unverified_devices_ignore_everything() {
        let dir = tempfile::tempdir().unwrap();
        let paths = KeyPaths::in_dir(dir.path());
        let fake = FakeAstation::new();
        assert!(matches!(
            apply_account_state(
                &paths,
                ASTATION_ID,
                Some(&signed_state(&fake, EncryptionMode::Off, 1))
            )
            .unwrap(),
            Applied::Ignored(_)
        ));
        let grant = seal_k_grant(&fake, "acct", "dev-1", [9; 32], "0123abcd", [42; 32]);
        let agent = test_agent(&paths);
        assert!(matches!(
            apply_grant(&paths, &agent, ASTATION_ID, Some(&grant)).unwrap(),
            Applied::Ignored(_)
        ));
        assert_eq!(
            account_mode(&paths.trust, ASTATION_ID).unwrap().mode,
            EncryptionMode::Off
        );
    }

    #[test]
    fn verified_device_without_a_state_refuses_to_build_a_context() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, _, _, _) = verify(dir.path(), EncryptionMode::Off);
        // Simulate a verified entry that never received a state: an Option
        // field missing from the JSON deserializes as None.
        let raw = std::fs::read_to_string(&paths.trust)
            .unwrap()
            .replace("\"account_state\": {", "\"account_state_was\": {");
        std::fs::write(&paths.trust, raw).unwrap();
        let trust = TrustStore::load_from(&paths.trust).unwrap();
        assert!(trust.verified(ASTATION_ID).unwrap().account_state.is_none());
        let error = account_mode(&paths.trust, ASTATION_ID)
            .unwrap_err()
            .to_string();
        assert!(error.contains("signed encryption state"), "{error}");
    }
}

#[cfg(test)]
mod ceremony_tests {
    use super::*;
    use crate::memory::crypto::EncryptionMode;
    use crate::memory::fake_astation::FakeKeyServer;
    use crate::memory::grant::seal_k_grant;
    use crate::memory::key_agent::{error_of, holds_k, test_agent};
    use crate::memory::statements::{DeviceVerified, FakeAstation, StorageRotate, verify_device};

    const ASTATION_ID: &str = "astation-1";

    fn state(
        fake: &FakeAstation,
        mode: EncryptionMode,
        kid: Option<&str>,
        epoch: u64,
    ) -> SignedWire {
        fake.sign(
            &AccountState {
                account: "acct".into(),
                sign_gen: 1,
                mode,
                kid: kid.map(str::to_string),
                epoch,
            }
            .encode(),
        )
    }

    /// Starts a ceremony with `keys` and leaves its pending pin in the trust
    /// store; returns the handshake and the certificate Astation would sign.
    fn start(
        paths: &KeyPaths,
        fake: &FakeAstation,
        keys: impl Into<VerificationKeys>,
        nonce_s: u8,
        epoch: u64,
    ) -> (Handshake, DeviceVerified) {
        let handshake = Handshake::start(keys);
        let astation = AstationKeys {
            sign_pub: fake.sign_pub(),
            enc_pub: fake.enc_pub(),
            recovery_sign_pub: [6; 32],
            nonce_s: [nonce_s; 32],
        };
        let code = handshake.safety_code(&astation);
        let transcript = handshake.transcript(&astation);
        let mut trust = TrustStore::load_from(&paths.trust).unwrap();
        trust.set_pending(
            ASTATION_ID,
            "dev-1",
            handshake.keys(),
            &astation,
            &code,
            &transcript,
        );
        trust.save_to(&paths.trust).unwrap();
        let reveal = handshake.reveal();
        let certificate = DeviceVerified {
            account: "acct".into(),
            sign_gen: 1,
            device_id: "dev-1".into(),
            device_pub: reveal.device_pub,
            device_sign_pub: reveal.device_sign_pub,
            unlock_auth_pub: reveal.unlock_auth_pub,
            transcript,
            epoch,
        };
        (handshake, certificate)
    }

    #[test]
    fn replayed_old_certificate_cannot_roll_a_verified_device_back() {
        let dir = tempfile::tempdir().unwrap();
        let paths = KeyPaths::in_dir(dir.path());
        let agent = test_agent(&paths);
        let fake = FakeAstation::new();
        let (handshake, certificate) = start(&paths, &fake, DeviceKeys::generate(), 7, 1);
        let old_certificate = fake.sign(&certificate.encode());
        let old_off = state(&fake, EncryptionMode::Off, None, 1);
        complete_verification(
            &paths,
            &agent,
            ASTATION_ID,
            handshake.into_keys(),
            &old_certificate,
            &old_off,
            &[],
        )
        .unwrap();
        // Later Astation turns encryption on and grants K.
        let device_pub = certificate.device_pub;
        let on = state(&fake, EncryptionMode::On, Some("0123abcd"), 2);
        apply_account_state(&paths, ASTATION_ID, Some(&on)).unwrap();
        let grant = seal_k_grant(&fake, "acct", "dev-1", device_pub, "0123abcd", [42; 32]);
        apply_grant(&paths, &agent, ASTATION_ID, Some(&grant)).unwrap();

        // Re-verification with the same saved keys; the relay withholds the
        // new certificate and replays the recorded old one with the old state.
        let keys = device_keys_for_verification(&paths, &agent).unwrap();
        let (handshake, _) = start(&paths, &fake, keys, 8, 3);
        let result = complete_verification(
            &paths,
            &agent,
            ASTATION_ID,
            handshake.into_keys(),
            &old_certificate,
            &old_off,
            &[],
        );
        assert!(result.is_err(), "a replayed certificate must be rejected");

        assert_eq!(account_mode(&paths.trust, ASTATION_ID).unwrap().mode, EncryptionMode::On);
        assert!(holds_k(&agent, ASTATION_ID), "K must survive");
        let trust = TrustStore::load_from(&paths.trust).unwrap();
        assert_eq!(trust.verified(ASTATION_ID).unwrap().account_epoch, 2);
    }

    #[test]
    fn legitimate_re_verification_keeps_mode_and_key() {
        let dir = tempfile::tempdir().unwrap();
        let paths = KeyPaths::in_dir(dir.path());
        let agent = test_agent(&paths);
        let fake = FakeAstation::new();
        let (handshake, certificate) = start(&paths, &fake, DeviceKeys::generate(), 7, 1);
        let device_pub = certificate.device_pub;
        let on = state(&fake, EncryptionMode::On, Some("0123abcd"), 2);
        let grant = seal_k_grant(&fake, "acct", "dev-1", device_pub, "0123abcd", [42; 32]);
        complete_verification(
            &paths,
            &agent,
            ASTATION_ID,
            handshake.into_keys(),
            &fake.sign(&certificate.encode()),
            &on,
            &[grant],
        )
        .unwrap();

        // Astation signs the new certificate at epoch 3 and re-signs the
        // current state at 4; it sends no grant this time.
        let keys = device_keys_for_verification(&paths, &agent).unwrap();
        let (handshake, certificate) = start(&paths, &fake, keys, 8, 3);
        let on_again = state(&fake, EncryptionMode::On, Some("0123abcd"), 4);
        complete_verification(
            &paths,
            &agent,
            ASTATION_ID,
            handshake.into_keys(),
            &fake.sign(&certificate.encode()),
            &on_again,
            &[],
        )
        .unwrap();

        assert_eq!(account_mode(&paths.trust, ASTATION_ID).unwrap().mode, EncryptionMode::On);
        assert!(holds_k(&agent, ASTATION_ID), "K must survive");
        let trust = TrustStore::load_from(&paths.trust).unwrap();
        let entry = trust.verified(ASTATION_ID).unwrap();
        assert_eq!((entry.epoch_floor, entry.account_epoch), (3, 4));
    }

    /// What a first verification attempt may have left on disk.
    fn assert_nothing_written(paths: &KeyPaths) {
        let trust = TrustStore::load_from(&paths.trust).unwrap();
        assert!(
            trust.verified(ASTATION_ID).is_none(),
            "no verified entry may be saved"
        );
        assert!(
            !paths.device_keys.exists() && !paths.device_keys_sealed.exists(),
            "device keys must not be written"
        );
        assert!(
            !paths.unlock_auth_key.exists(),
            "unlock_auth_key must not be written"
        );
        assert!(!paths.data_keys.exists(), "data_keys must not be written");
        assert!(!paths.project_names.exists(), "project_names.json must not be written");
        assert!(
            paths.legacy_device_key.exists(),
            "the old device_key must not be deleted"
        );
    }

    /// Runs a first verification with certificate epoch `cert_epoch`, the
    /// given signed state and grants (built for this device).
    fn first_verification(
        dir: &Path,
        cert_epoch: u64,
        make: impl FnOnce(&FakeAstation, [u8; 32]) -> (SignedWire, Vec<GrantWire>),
    ) -> (KeyPaths, Result<VerificationOutcome>) {
        first_verification_with(dir, cert_epoch, |_| {}, make)
    }

    /// [`first_verification`], with `setup` run once the agent has started
    /// (an agent of an unverified device deletes data_keys.enc at start).
    fn first_verification_with(
        dir: &Path,
        cert_epoch: u64,
        setup: impl FnOnce(&KeyPaths),
        make: impl FnOnce(&FakeAstation, [u8; 32]) -> (SignedWire, Vec<GrantWire>),
    ) -> (KeyPaths, Result<VerificationOutcome>) {
        let paths = KeyPaths::in_dir(dir);
        let agent = test_agent(&paths);
        setup(&paths);
        std::fs::write(&paths.legacy_device_key, [1u8; 32]).unwrap();
        let fake = FakeAstation::new();
        let (handshake, certificate) = start(&paths, &fake, DeviceKeys::generate(), 7, cert_epoch);
        let (account_state, grants) = make(&fake, certificate.device_pub);
        let result = complete_verification(
            &paths,
            &agent,
            ASTATION_ID,
            handshake.into_keys(),
            &fake.sign(&certificate.encode()),
            &account_state,
            &grants,
        );
        if result.is_err() {
            assert!(
                !agent.status().unwrap().unlocked,
                "a failed verification must not hand keys to the agent"
            );
        }
        (paths, result)
    }

    #[test]
    fn account_state_may_follow_the_certificate_epoch() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, result) = first_verification(dir.path(), 5, |fake, _| {
            (state(fake, EncryptionMode::Off, None, 6), vec![])
        });
        result.unwrap();
        let trust = TrustStore::load_from(&paths.trust).unwrap();
        let entry = trust.verified(ASTATION_ID).unwrap();
        assert_eq!((entry.epoch_floor, entry.account_epoch), (5, 6));
    }

    #[test]
    fn account_state_older_than_the_certificate_leaves_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, result) = first_verification(dir.path(), 5, |fake, _| {
            (state(fake, EncryptionMode::Off, None, 4), vec![])
        });
        assert!(result.is_err());
        assert_nothing_written(&paths);
    }

    #[test]
    fn invalid_kid_leaves_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, result) = first_verification(dir.path(), 1, |fake, _| {
            (state(fake, EncryptionMode::On, Some("XYZ"), 2), vec![])
        });
        assert!(result.is_err());
        assert_nothing_written(&paths);
    }

    #[test]
    fn key_mode_without_kid_leaves_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, result) = first_verification(dir.path(), 1, |fake, _| {
            (state(fake, EncryptionMode::On, None, 2), vec![])
        });
        assert!(result.is_err());
        assert_nothing_written(&paths);
    }

    #[test]
    fn bad_grant_leaves_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, result) = first_verification(dir.path(), 1, |fake, _| {
            let other_device = DeviceKeys::generate().device_pub();
            (
                state(fake, EncryptionMode::On, Some("0123abcd"), 2),
                vec![seal_k_grant(
                    fake,
                    "acct",
                    "dev-1",
                    other_device,
                    "0123abcd",
                    [42; 32],
                )],
            )
        });
        assert!(result.is_err());
        assert_nothing_written(&paths);
    }

    #[test]
    fn grant_for_another_kid_leaves_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, result) = first_verification(dir.path(), 1, |fake, device_pub| {
            (
                state(fake, EncryptionMode::On, Some("0123abcd"), 2),
                vec![seal_k_grant(
                    fake, "acct", "dev-1", device_pub, "89abcdef", [42; 32],
                )],
            )
        });
        assert!(result.is_err());
        assert_nothing_written(&paths);
    }

    #[test]
    fn first_verification_purges_legacy_keys() {
        use crate::memory::legacy_keys::{summary_at, write_for_test};
        let dir = tempfile::tempdir().unwrap();
        // K, its rotation history and a project name from the unauthenticated
        // #36 path, written once the agent runs (it deletes the file at start
        // on an unverified device), so the purge itself is what drops them.
        // Another account's entry stays.
        let (paths, result) = first_verification_with(dir.path(), 1, |legacy| {
            write_for_test(&legacy.data_keys, ASTATION_ID, "acct", &[("0123abcd", [1; 32]), ("11112222", [2; 32])], &[("h1.11112222.aa", "github.com/agora/atem")]);
            write_for_test(&legacy.data_keys, "astation-9", "other", &[("44445555", [3; 32])], &[("h1.44445555.bb", "p")]);
            crate::memory::project_names::remember(&legacy.project_names, "acct", [("h1.11112222.aa".to_string(), "github.com/agora/atem".to_string())]).unwrap();
        }, |fake, _| {
            (state(fake, EncryptionMode::On, Some("89abcdef"), 2), vec![])
        });
        result.unwrap();
        assert!(paths.data_keys.exists(), "purged, not deleted");
        assert_eq!(summary_at(&paths.data_keys, "acct"), (None, vec![], 0), "the old K and its history must be gone");
        assert_eq!(summary_at(&paths.data_keys, "other"), (Some("44445555".into()), vec![], 1));
        assert_eq!(crate::memory::project_names::ProjectNames::load_from(&paths.project_names).unwrap().len("acct"), 0);
    }

    #[test]
    fn outcome_says_when_k_is_still_needed() {
        let dir = tempfile::tempdir().unwrap();
        let (_, result) = first_verification(dir.path(), 1, |fake, _| {
            (state(fake, EncryptionMode::On, Some("0123abcd"), 2), vec![])
        });
        assert!(result.unwrap().key_needed);

        let dir = tempfile::tempdir().unwrap();
        let (_, result) = first_verification(dir.path(), 1, |fake, device_pub| {
            (
                state(fake, EncryptionMode::On, Some("0123abcd"), 2),
                vec![seal_k_grant(
                    fake, "acct", "dev-1", device_pub, "0123abcd", [42; 32],
                )],
            )
        });
        assert!(!result.unwrap().key_needed);

        let dir = tempfile::tempdir().unwrap();
        let (paths, result) = first_verification(dir.path(), 1, |fake, _| {
            (state(fake, EncryptionMode::Off, None, 2), vec![])
        });
        assert!(!result.unwrap().key_needed);
        let empty = tempfile::tempdir().unwrap();
        let locked = test_agent(&KeyPaths::in_dir(empty.path()));
        assert!(!key_needed(&paths, &locked, ASTATION_ID).unwrap(), "off needs no K");
        assert!(!key_needed(&paths, &locked, "never-verified").unwrap());
    }

    /// A first verification of fresh keys with `fake` (certificate epoch 1,
    /// state epoch 2, no grants); returns the certificate and the outcome.
    fn verified_device(
        paths: &KeyPaths,
        agent: &dyn KeyAgentApi,
        fake: &FakeAstation,
        mode: EncryptionMode,
        kid: Option<&str>,
    ) -> (DeviceVerified, VerificationOutcome) {
        let (handshake, certificate) = start(paths, fake, DeviceKeys::generate(), 7, 1);
        let outcome = complete_verification(
            paths,
            agent,
            ASTATION_ID,
            handshake.into_keys(),
            &fake.sign(&certificate.encode()),
            &state(fake, mode, kid, 2),
            &[],
        )
        .unwrap();
        (certificate, outcome)
    }

    #[test]
    fn first_verification_seals_the_keys_and_hands_them_to_the_agent() {
        let dir = tempfile::tempdir().unwrap();
        let paths = KeyPaths::in_dir(dir.path());
        let agent = test_agent(&paths);
        let fake = FakeAstation::new();
        let (certificate, outcome) =
            verified_device(&paths, &agent, &fake, EncryptionMode::Off, None);
        let sealed = SealedDeviceKeys::load_from(&paths.device_keys_sealed)
            .unwrap()
            .unwrap();
        assert_eq!(sealed.device_id, "dev-1");
        assert_eq!(
            UnlockAuthKey::load_from(&paths.unlock_auth_key)
                .unwrap()
                .unwrap()
                .public(),
            certificate.unlock_auth_pub
        );
        let status = agent.status().unwrap();
        assert!(
            status.unlocked && !status.escrowed,
            "Astation doesn't hold the storage key yet"
        );
        assert_eq!(status.storage_kid, Some(sealed.storage_kid.clone()));
        assert_eq!(
            agent.public_keys().unwrap(),
            (certificate.device_pub, certificate.device_sign_pub)
        );
        assert_eq!(
            TrustStore::load_from(&paths.trust).unwrap().home(),
            Some(ASTATION_ID)
        );

        // The initial escrow: the current storage key, from no old key.
        let escrow = outcome
            .escrow
            .expect("the first verification escrows the storage key");
        let rotate = StorageRotate::parse(
            &verify_device(&certificate.device_sign_pub, &escrow.rotate).unwrap(),
        )
        .unwrap();
        assert_eq!(rotate.old_storage_kid, "");
        assert_eq!(rotate.new_storage_kid, sealed.storage_kid);
        let mut server = FakeKeyServer {
            astation: fake,
            device_sign_pub: certificate.device_sign_pub,
            unlock_auth_pub: certificate.unlock_auth_pub,
            storage_keys: Default::default(),
            pending: None,
            pending_statement: None,
            acked: Default::default(),
        };
        let ack = server.accept_rotation(&escrow).unwrap();
        let (kid, confirm) = agent.confirm_rotation(ASTATION_ID, &ack).unwrap();
        server.confirm(&confirm).unwrap();
        assert_eq!(kid, sealed.storage_kid);
        assert!(server.storage_keys.contains_key(&kid));
        assert!(agent.status().unwrap().escrowed);
        assert!(
            !paths.device_keys.exists(),
            "the plain file goes once Astation holds the storage key"
        );
    }

    /// A key server that holds nothing yet for the device `certificate` names.
    fn empty_server(fake: FakeAstation, certificate: &DeviceVerified) -> FakeKeyServer {
        FakeKeyServer {
            astation: fake,
            device_sign_pub: certificate.device_sign_pub,
            unlock_auth_pub: certificate.unlock_auth_pub,
            storage_keys: Default::default(),
            pending: None,
            pending_statement: None,
            acked: Default::default(),
        }
    }

    /// The first escrow of a fresh verification, as `atem pair` completes
    /// it: Astation holds the storage key and the plain file goes, so a
    /// restarted agent starts locked.
    fn escrow_first(
        agent: &dyn KeyAgentApi,
        fake: &FakeAstation,
        certificate: &DeviceVerified,
        outcome: VerificationOutcome,
    ) {
        let mut server = empty_server(fake.clone(), certificate);
        let ack = server
            .accept_rotation(&outcome.escrow.expect("a fresh verification escrows"))
            .unwrap();
        agent.confirm_rotation(ASTATION_ID, &ack).unwrap();
    }

    #[test]
    fn a_fresh_device_whose_agent_stops_before_the_escrow_re_seals_from_the_plain_file() {
        let dir = tempfile::tempdir().unwrap();
        let paths = KeyPaths::in_dir(dir.path());
        let agent = test_agent(&paths);
        let fake = FakeAstation::new();
        let (certificate, _outcome) =
            verified_device(&paths, &agent, &fake, EncryptionMode::Off, None);
        let first_kid = SealedDeviceKeys::load_from(&paths.device_keys_sealed)
            .unwrap()
            .unwrap()
            .storage_kid;
        // The plain file holds exactly the verified keys, 0600.
        let plain = DeviceKeys::load_from(&paths.device_keys).unwrap().unwrap();
        assert_eq!(
            (plain.device_pub(), plain.device_sign_pub(), plain.unlock_auth_pub()),
            (
                certificate.device_pub,
                certificate.device_sign_pub,
                certificate.unlock_auth_pub
            )
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&paths.device_keys)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }

        // The agent exits (reboot, crash) before Astation holds the key: the
        // next agent re-seals the keys from the plain file, unlocked.
        drop(agent);
        let restarted = test_agent(&paths);
        let status = restarted.status().unwrap();
        assert!(status.unlocked && !status.escrowed, "{status:?}");
        assert_ne!(status.storage_kid.as_deref(), Some(first_kid.as_str()));
        assert_eq!(
            restarted.public_keys().unwrap(),
            (certificate.device_pub, certificate.device_sign_pub)
        );

        // The escrow then completes and the plain file goes.
        let mut server = empty_server(fake, &certificate);
        let ack = server
            .accept_rotation(&restarted.begin_rotation(ASTATION_ID).unwrap())
            .unwrap();
        let (kid, confirm) = restarted.confirm_rotation(ASTATION_ID, &ack).unwrap();
        server.confirm(&confirm).unwrap();
        assert_eq!(Some(kid.clone()), status.storage_kid);
        assert!(!paths.device_keys.exists());

        // From now on a restart starts locked, sealed under the escrowed key.
        drop(restarted);
        let rebooted = test_agent(&paths);
        assert!(!rebooted.status().unwrap().unlocked);
        assert_eq!(
            SealedDeviceKeys::load_from(&paths.device_keys_sealed)
                .unwrap()
                .unwrap()
                .storage_kid,
            kid
        );
    }

    #[test]
    fn re_verification_with_sealed_keys_opens_grants_in_the_agent() {
        let dir = tempfile::tempdir().unwrap();
        let paths = KeyPaths::in_dir(dir.path());
        let agent = test_agent(&paths);
        let fake = FakeAstation::new();
        verified_device(&paths, &agent, &fake, EncryptionMode::Off, None);

        let keys = device_keys_for_verification(&paths, &agent).unwrap();
        assert!(matches!(keys, VerificationKeys::Sealed(_)));
        let (handshake, certificate) = start(&paths, &fake, keys, 8, 3);
        let grant = seal_k_grant(
            &fake,
            "acct",
            "dev-1",
            certificate.device_pub,
            "0123abcd",
            [42; 32],
        );
        let outcome = complete_verification(
            &paths,
            &agent,
            ASTATION_ID,
            handshake.into_keys(),
            &fake.sign(&certificate.encode()),
            &state(&fake, EncryptionMode::On, Some("0123abcd"), 4),
            &[grant],
        )
        .unwrap();
        assert!(!outcome.key_needed);
        assert!(outcome.escrow.is_none(), "the storage key isn't new");
        assert!(holds_k(&agent, ASTATION_ID));
    }

    #[test]
    fn a_locked_agent_cannot_verify_existing_keys() {
        let dir = tempfile::tempdir().unwrap();
        let paths = KeyPaths::in_dir(dir.path());
        let agent = test_agent(&paths);
        let fake = FakeAstation::new();
        let (certificate, outcome) =
            verified_device(&paths, &agent, &fake, EncryptionMode::Off, None);
        escrow_first(&agent, &fake, &certificate, outcome);
        // After a reboot the agent starts locked.
        let rebooted = test_agent(&paths);
        let error = error_of(device_keys_for_verification(&paths, &rebooted));
        assert!(error.contains("atem cred unlock"), "{error}");

        // The agent restarted (locked) between the handshake and Astation's
        // certificate: nothing changes.
        let keys = device_keys_for_verification(&paths, &agent).unwrap();
        let (handshake, certificate) = start(&paths, &fake, keys, 8, 3);
        let before = std::fs::read(&paths.trust).unwrap();
        let error = error_of(complete_verification(
            &paths,
            &rebooted,
            ASTATION_ID,
            handshake.into_keys(),
            &fake.sign(&certificate.encode()),
            &state(&fake, EncryptionMode::Off, None, 4),
            &[],
        ));
        assert!(error.contains("atem cred unlock"), "{error}");
        assert_eq!(
            std::fs::read(&paths.trust).unwrap(),
            before,
            "nothing saved"
        );
    }

    /// The entries of `dir` named `<name>.revoked-<stamp>`.
    fn set_aside(dir: &std::path::Path, name: &str) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|file| {
                file.strip_prefix(&format!("{name}.revoked-"))
                    .is_some_and(|stamp| !stamp.is_empty() && stamp.chars().all(|c| c.is_ascii_digit()))
            })
            .collect()
    }

    #[test]
    fn a_revoked_device_sets_its_old_keys_aside_and_verifies_with_new_ones() {
        let dir = tempfile::tempdir().unwrap();
        let paths = KeyPaths::in_dir(dir.path());
        let agent = test_agent(&paths);
        let fake = FakeAstation::new();
        let (certificate, outcome) =
            verified_device(&paths, &agent, &fake, EncryptionMode::Off, None);
        escrow_first(&agent, &fake, &certificate, outcome);
        let sealed_before = std::fs::read(&paths.device_keys_sealed).unwrap();
        // Leftovers of a rotation and a plain file: all set aside too.
        for path in [&paths.device_keys_next, &paths.device_keys_prev, &paths.device_keys] {
            std::fs::write(path, b"old").unwrap();
        }
        std::fs::write(&paths.project_names, b"{}").unwrap();
        TrustStore::update(&paths.trust, |store| {
            store.record_abandoned("0f0f0f0f");
            store.record_escrow_unanswered();
            store.record_revoked(ASTATION_ID, 1_700_000_000);
            Ok(())
        })
        .unwrap();
        // After a reboot the agent is locked, and Astation won't unlock it.
        let rebooted = test_agent(&paths);
        let notice = set_aside_revoked_keys(&paths, &rebooted)
            .unwrap()
            .expect("the old keys are moved aside");
        assert!(notice.contains("moved aside"), "{notice}");
        for name in [
            "device_keys.sealed",
            "device_keys.sealed.next",
            "device_keys.sealed.prev",
            "unlock_auth_key",
            "device_keys",
        ] {
            assert!(!dir.path().join(name).exists(), "{name} is still there");
            let aside = set_aside(dir.path(), name);
            assert_eq!(aside.len(), 1, "{name}: {aside:?}");
        }
        let aside = set_aside(dir.path(), "device_keys.sealed");
        assert_eq!(std::fs::read(dir.path().join(&aside[0])).unwrap(), sealed_before, "renamed, not rewritten");
        assert_eq!(std::fs::read(&paths.project_names).unwrap(), b"{}");
        let trust = TrustStore::load_from(&paths.trust).unwrap();
        assert!(trust.verified(ASTATION_ID).is_none());
        assert!(!trust.home_is_set());
        assert_eq!(trust.escrowed_kid(), None);
        assert!(!trust.escrow_unanswered());
        assert!(trust.revoked().is_none());
        assert!(trust.was_abandoned("0f0f0f0f"), "abandoned kids are kept");

        let keys = device_keys_for_verification(&paths, &rebooted).unwrap();
        assert!(matches!(keys, VerificationKeys::Fresh(_)));
        let (handshake, certificate) = start(&paths, &fake, keys, 8, 3);
        let outcome = complete_verification(
            &paths,
            &rebooted,
            ASTATION_ID,
            handshake.into_keys(),
            &fake.sign(&certificate.encode()),
            &state(&fake, EncryptionMode::Off, None, 4),
            &[],
        )
        .unwrap();
        assert!(outcome.escrow.is_some(), "new keys go to Astation");
        let trust = TrustStore::load_from(&paths.trust).unwrap();
        assert_eq!(trust.home(), Some(ASTATION_ID));
        assert!(paths.device_keys_sealed.exists());
    }

    #[test]
    fn without_a_recorded_revocation_a_locked_agent_still_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let paths = KeyPaths::in_dir(dir.path());
        let agent = test_agent(&paths);
        let fake = FakeAstation::new();
        let (certificate, outcome) =
            verified_device(&paths, &agent, &fake, EncryptionMode::Off, None);
        escrow_first(&agent, &fake, &certificate, outcome);
        let rebooted = test_agent(&paths);
        assert_eq!(set_aside_revoked_keys(&paths, &rebooted).unwrap(), None);
        let error = error_of(device_keys_for_verification(&paths, &rebooted));
        assert!(error.contains("atem cred unlock"), "{error}");
        // Revoked by an Astation that isn't the home: nothing moves either.
        TrustStore::update(&paths.trust, |store| {
            store.record_revoked("astation-2", 1_700_000_000);
            Ok(())
        })
        .unwrap();
        assert_eq!(set_aside_revoked_keys(&paths, &rebooted).unwrap(), None);
        // An unlocked agent verifies with the keys it holds, as before.
        TrustStore::update(&paths.trust, |store| {
            store.record_revoked(ASTATION_ID, 1_700_000_000);
            Ok(())
        })
        .unwrap();
        assert_eq!(set_aside_revoked_keys(&paths, &agent).unwrap(), None);
        assert!(matches!(
            device_keys_for_verification(&paths, &agent).unwrap(),
            VerificationKeys::Sealed(_)
        ));
        assert!(paths.device_keys_sealed.exists());
        assert!(TrustStore::load_from(&paths.trust).unwrap().verified(ASTATION_ID).is_some());
    }

    #[test]
    fn a_second_astation_does_not_move_the_home() {
        let dir = tempfile::tempdir().unwrap();
        let paths = KeyPaths::in_dir(dir.path());
        let agent = test_agent(&paths);
        let fake = FakeAstation::new();
        let (certificate, _) = verified_device(&paths, &agent, &fake, EncryptionMode::Off, None);
        let sealed_before = std::fs::read(&paths.device_keys_sealed).unwrap();

        let other = FakeAstation::new();
        let handshake = Handshake::start(device_keys_for_verification(&paths, &agent).unwrap());
        let astation = AstationKeys {
            sign_pub: other.sign_pub(),
            enc_pub: [5; 32],
            recovery_sign_pub: [6; 32],
            nonce_s: [9; 32],
        };
        let transcript = handshake.transcript(&astation);
        let mut trust = TrustStore::load_from(&paths.trust).unwrap();
        trust.set_pending(
            "astation-2",
            "dev-1",
            handshake.keys(),
            &astation,
            &handshake.safety_code(&astation),
            &transcript,
        );
        trust.save_to(&paths.trust).unwrap();
        let reveal = handshake.reveal();
        let second = DeviceVerified {
            account: "acct".into(),
            sign_gen: 1,
            device_id: "dev-1".into(),
            device_pub: reveal.device_pub,
            device_sign_pub: reveal.device_sign_pub,
            unlock_auth_pub: reveal.unlock_auth_pub,
            transcript,
            epoch: 1,
        };
        let outcome = complete_verification(
            &paths,
            &agent,
            "astation-2",
            handshake.into_keys(),
            &other.sign(&second.encode()),
            &state(&other, EncryptionMode::Off, None, 2),
            &[],
        )
        .unwrap();
        assert!(
            outcome.escrow.is_none(),
            "only the home holds the storage key"
        );
        let trust = TrustStore::load_from(&paths.trust).unwrap();
        assert_eq!(trust.home(), Some(ASTATION_ID));
        assert!(trust.verified("astation-2").is_some());
        assert_eq!(
            second.device_pub, certificate.device_pub,
            "one device key for both"
        );
        assert_eq!(
            std::fs::read(&paths.device_keys_sealed).unwrap(),
            sealed_before,
            "the sealed keys are not re-sealed"
        );
    }

    #[test]
    fn a_second_astation_naming_a_verified_account_purges_nothing_of_it() {
        use crate::memory::legacy_keys::{summary_at, write_for_test};
        let dir = tempfile::tempdir().unwrap();
        let paths = KeyPaths::in_dir(dir.path());
        let agent = test_agent(&paths);
        let fake = FakeAstation::new();
        verified_device(&paths, &agent, &fake, EncryptionMode::Off, None);
        // Keys and names of "acct", which astation-1 (verified) names; and
        // the #36 path's entry for astation-2 naming "acct" and "stray".
        write_for_test(&paths.data_keys, ASTATION_ID, "acct", &[("0123abcd", [1; 32])], &[("h1.0123abcd.aa", "p")]);
        write_for_test(&paths.data_keys, "astation-2", "stray", &[("44445555", [3; 32])], &[]);
        crate::memory::project_names::remember(&paths.project_names, "acct", [("h1.0123abcd.aa".to_string(), "p".to_string())]).unwrap();

        let other = FakeAstation::new();
        let handshake = Handshake::start(device_keys_for_verification(&paths, &agent).unwrap());
        let astation = AstationKeys {
            sign_pub: other.sign_pub(),
            enc_pub: [5; 32],
            recovery_sign_pub: [6; 32],
            nonce_s: [9; 32],
        };
        let transcript = handshake.transcript(&astation);
        let mut trust = TrustStore::load_from(&paths.trust).unwrap();
        trust.set_pending("astation-2", "dev-1", handshake.keys(), &astation, &handshake.safety_code(&astation), &transcript);
        trust.save_to(&paths.trust).unwrap();
        let reveal = handshake.reveal();
        let second = DeviceVerified {
            account: "acct".into(),
            sign_gen: 1,
            device_id: "dev-1".into(),
            device_pub: reveal.device_pub,
            device_sign_pub: reveal.device_sign_pub,
            unlock_auth_pub: reveal.unlock_auth_pub,
            transcript,
            epoch: 1,
        };
        complete_verification(
            &paths,
            &agent,
            "astation-2",
            handshake.into_keys(),
            &other.sign(&second.encode()),
            &state(&other, EncryptionMode::Off, None, 2),
            &[],
        )
        .unwrap();
        assert_eq!(summary_at(&paths.data_keys, "acct"), (Some("0123abcd".into()), vec![], 1), "astation-1 still names it");
        assert_eq!(crate::memory::project_names::ProjectNames::load_from(&paths.project_names).unwrap().len("acct"), 1);
        assert_eq!(summary_at(&paths.data_keys, "stray"), (None, vec![], 0), "what only the unverified entry named goes");
    }

    #[test]
    fn fresh_keys_never_verify_under_another_home() {
        let dir = tempfile::tempdir().unwrap();
        let paths = KeyPaths::in_dir(dir.path());
        // The key files were deleted, but this device's home is another Astation.
        let mut trust = TrustStore::default();
        trust.set_home("astation-0");
        trust.save_to(&paths.trust).unwrap();
        let (paths, result) = first_verification(dir.path(), 1, |fake, _| {
            (state(fake, EncryptionMode::Off, None, 2), vec![])
        });
        let error = error_of(result);
        assert!(error.contains("astation-0"), "{error}");
        assert_nothing_written(&paths);
    }

    #[test]
    fn grants_wait_while_the_agent_is_locked() {
        let dir = tempfile::tempdir().unwrap();
        let paths = KeyPaths::in_dir(dir.path());
        let agent = test_agent(&paths);
        let fake = FakeAstation::new();
        let (certificate, outcome) =
            verified_device(&paths, &agent, &fake, EncryptionMode::On, Some("0123abcd"));
        escrow_first(&agent, &fake, &certificate, outcome);
        let grant = seal_k_grant(
            &fake,
            "acct",
            "dev-1",
            certificate.device_pub,
            "0123abcd",
            [42; 32],
        );
        let locked = test_agent(&paths);
        assert!(matches!(
            apply_grant(&paths, &locked, ASTATION_ID, Some(&grant)).unwrap(),
            Applied::Locked
        ));
        assert!(key_needed(&paths, &locked, ASTATION_ID).unwrap());
        assert!(matches!(
            apply_grant(&paths, &agent, ASTATION_ID, Some(&grant)).unwrap(),
            Applied::KeyInstalled(_)
        ));
        assert!(!key_needed(&paths, &agent, ASTATION_ID).unwrap());
        assert!(holds_k(&agent, ASTATION_ID));
    }

    /// Answers `Status` from one agent and everything else from another
    /// (e.g. a lock between the two calls), or fails `BeginRotation`.
    struct Scripted {
        status: std::sync::Mutex<crate::memory::key_agent::KeyAgent>,
        rest: std::sync::Mutex<crate::memory::key_agent::KeyAgent>,
        fail_rotation: bool,
    }

    impl KeyAgentApi for Scripted {
        fn call(
            &self,
            request: crate::memory::key_agent::Request,
        ) -> Result<crate::memory::key_agent::Reply> {
            use crate::memory::key_agent::Request;
            match request {
                Request::Status => self.status.call(request),
                Request::BeginRotation { .. } if self.fail_rotation => {
                    bail!("Astation's encryption key is unusable")
                }
                _ => self.rest.call(request),
            }
        }
    }

    /// Forwards to `agent`, failing `InstallGrant` and/or `HeldKid` with a
    /// non-lock error (a socket or protocol failure).
    struct FailingAfterWrite {
        agent: std::sync::Mutex<crate::memory::key_agent::KeyAgent>,
        fail_install: bool,
        fail_held_kid: bool,
    }

    impl KeyAgentApi for FailingAfterWrite {
        fn call(
            &self,
            request: crate::memory::key_agent::Request,
        ) -> Result<crate::memory::key_agent::Reply> {
            use crate::memory::key_agent::Request;
            match request {
                Request::InstallGrant { .. } if self.fail_install => {
                    bail!("the key agent closed the connection")
                }
                Request::HeldKid { .. } if self.fail_held_kid => {
                    bail!("the key agent sent an unreadable reply")
                }
                _ => self.agent.call(request),
            }
        }
    }

    /// A first verification (state on, kid 0123abcd, its grant) through
    /// `agent`.
    fn verify_on_with_grant(paths: &KeyPaths, agent: &dyn KeyAgentApi) -> Result<VerificationOutcome> {
        let fake = FakeAstation::new();
        let (handshake, certificate) = start(paths, &fake, DeviceKeys::generate(), 7, 1);
        let grant = seal_k_grant(
            &fake,
            "acct",
            "dev-1",
            certificate.device_pub,
            "0123abcd",
            [42; 32],
        );
        complete_verification(
            paths,
            agent,
            ASTATION_ID,
            handshake.into_keys(),
            &fake.sign(&certificate.encode()),
            &state(&fake, EncryptionMode::On, Some("0123abcd"), 2),
            &[grant],
        )
    }

    #[test]
    fn a_failed_install_after_a_saved_verification_is_a_warning() {
        let dir = tempfile::tempdir().unwrap();
        let paths = KeyPaths::in_dir(dir.path());
        let agent = FailingAfterWrite {
            agent: test_agent(&paths),
            fail_install: true,
            fail_held_kid: false,
        };
        let outcome = verify_on_with_grant(&paths, &agent).expect("the verification is saved");
        let warning = outcome.warning.expect("a warning");
        assert!(warning.contains("couldn't be stored in the key agent"), "{warning}");
        assert!(outcome.key_needed, "K is asked for again");
        assert!(TrustStore::load_from(&paths.trust).unwrap().verified(ASTATION_ID).is_some());
        assert!(!holds_k(&agent.agent, ASTATION_ID));
    }

    #[test]
    fn an_agent_error_after_a_saved_verification_means_k_is_needed() {
        let dir = tempfile::tempdir().unwrap();
        let paths = KeyPaths::in_dir(dir.path());
        let agent = FailingAfterWrite {
            agent: test_agent(&paths),
            fail_install: false,
            fail_held_kid: true,
        };
        let outcome = verify_on_with_grant(&paths, &agent).expect("the verification is saved");
        assert!(outcome.key_needed, "an unknown answer counts as K missing");
        let warning = outcome.warning.expect("a warning");
        assert!(warning.contains("unreadable reply"), "{warning}");
        assert!(TrustStore::load_from(&paths.trust).unwrap().verified(ASTATION_ID).is_some());
    }

    #[test]
    fn a_failed_write_on_a_fresh_device_leaves_no_sealed_keys() {
        let dir = tempfile::tempdir().unwrap();
        let paths = KeyPaths::in_dir(dir.path());
        let agent = test_agent(&paths);
        let fake = FakeAstation::new();
        let (handshake, certificate) = start(&paths, &fake, DeviceKeys::generate(), 7, 1);
        // cred_state.json can't be saved: the last write, after the key
        // files, fails.
        let _failing = crate::memory::crypto::fail_writes_to(&paths.trust);
        assert!(
            complete_verification(
                &paths,
                &agent,
                ASTATION_ID,
                handshake.into_keys(),
                &fake.sign(&certificate.encode()),
                &state(&fake, EncryptionMode::Off, None, 2),
                &[],
            )
            .is_err()
        );
        assert!(
            !agent.status().unwrap().unlocked,
            "the agent is left locked"
        );
        assert!(!paths.device_keys_sealed.exists(), "no sealed keys left");
        assert!(!paths.unlock_auth_key.exists(), "no unlock_auth_key left");
        assert!(!paths.device_keys.exists(), "no plain keys left");
        assert!(
            TrustStore::load_from(&paths.trust)
                .unwrap()
                .verified(ASTATION_ID)
                .is_none()
        );
        assert!(matches!(
            device_keys_for_verification(&paths, &agent).unwrap(),
            VerificationKeys::Fresh(_)
        ));
    }

    #[test]
    fn any_sealed_file_means_this_device_has_keys() {
        let dir = tempfile::tempdir().unwrap();
        let paths = KeyPaths::in_dir(dir.path());
        let keys = DeviceKeys::generate();
        let storage_key = new_storage_key();
        for (path, kid) in [
            (&paths.device_keys_next, "0a1b2c3d"),
            (&paths.device_keys_prev, "1a2b3c4d"),
        ] {
            SealedDeviceKeys::seal(&keys, "dev-1", kid, &storage_key)
                .unwrap()
                .save_to(path)
                .unwrap();
        }
        let agent = test_agent(&paths);
        let error = error_of(device_keys_for_verification(&paths, &agent));
        assert!(error.contains("atem cred unlock"), "{error}");

        let fake = FakeAstation::new();
        let (handshake, certificate) = start(&paths, &fake, DeviceKeys::generate(), 7, 1);
        let error = error_of(complete_verification(
            &paths,
            &agent,
            ASTATION_ID,
            handshake.into_keys(),
            &fake.sign(&certificate.encode()),
            &state(&fake, EncryptionMode::Off, None, 2),
            &[],
        ));
        assert!(error.contains("already has keys"), "{error}");
        assert!(!agent.status().unwrap().unlocked);
        assert!(!paths.device_keys_sealed.exists() && !paths.unlock_auth_key.exists());
        assert!(
            TrustStore::load_from(&paths.trust)
                .unwrap()
                .verified(ASTATION_ID)
                .is_none()
        );
    }

    #[test]
    fn a_failed_escrow_preparation_still_verifies_with_a_warning() {
        let dir = tempfile::tempdir().unwrap();
        let paths = KeyPaths::in_dir(dir.path());
        let agent = Scripted {
            status: test_agent(&paths),
            rest: test_agent(&paths),
            fail_rotation: true,
        };
        let fake = FakeAstation::new();
        let (handshake, certificate) = start(&paths, &fake, DeviceKeys::generate(), 7, 1);
        let outcome = complete_verification(
            &paths,
            &agent,
            ASTATION_ID,
            handshake.into_keys(),
            &fake.sign(&certificate.encode()),
            &state(&fake, EncryptionMode::On, Some("0123abcd"), 2),
            &[],
        )
        .unwrap();
        assert!(outcome.escrow.is_none());
        let warning = outcome.warning.expect("a warning about the escrow");
        assert!(warning.contains("atem cred unlock"), "{warning}");
        assert!(outcome.key_needed, "K is still asked for");
        assert!(
            TrustStore::load_from(&paths.trust)
                .unwrap()
                .verified(ASTATION_ID)
                .is_some()
        );
    }

    #[test]
    fn a_lock_between_status_and_open_is_reported_as_locked() {
        let dir = tempfile::tempdir().unwrap();
        let paths = KeyPaths::in_dir(dir.path());
        let unlocked = test_agent(&paths);
        let fake = FakeAstation::new();
        let (certificate, outcome) = verified_device(
            &paths,
            &unlocked,
            &fake,
            EncryptionMode::On,
            Some("0123abcd"),
        );
        escrow_first(&unlocked, &fake, &certificate, outcome);
        let grant = seal_k_grant(
            &fake,
            "acct",
            "dev-1",
            certificate.device_pub,
            "0123abcd",
            [42; 32],
        );
        let raced = Scripted {
            status: unlocked,
            rest: test_agent(&paths),
            fail_rotation: false,
        };
        assert!(matches!(
            apply_grant(&paths, &raced, ASTATION_ID, Some(&grant)).unwrap(),
            Applied::Locked
        ));
    }

    /// Forwards to `agent`. Right after the keys are loaded, a concurrent
    /// pairing run writes its own key files, and this run's write of the
    /// sealed file fails.
    struct RacedByAnotherRun {
        agent: std::sync::Mutex<crate::memory::key_agent::KeyAgent>,
        paths: KeyPaths,
        other: DeviceKeys,
        failing: std::sync::Mutex<Option<crate::memory::crypto::FailingWrite>>,
    }

    impl KeyAgentApi for RacedByAnotherRun {
        fn call(
            &self,
            request: crate::memory::key_agent::Request,
        ) -> Result<crate::memory::key_agent::Reply> {
            let load = matches!(request, crate::memory::key_agent::Request::LoadUnlocked { .. });
            let reply = self.agent.call(request)?;
            if load {
                SealedDeviceKeys::seal(&self.other, "dev-1", "7a7b7c7d", &new_storage_key())
                    .unwrap()
                    .save_to(&self.paths.device_keys_sealed)
                    .unwrap();
                self.other
                    .unlock_auth_key()
                    .save_to(&self.paths.unlock_auth_key)
                    .unwrap();
                self.other.save_to(&self.paths.device_keys).unwrap();
                // This run's own write of device_keys.sealed then fails.
                *self.failing.lock().unwrap() = Some(crate::memory::crypto::fail_writes_to(
                    &self.paths.device_keys_sealed,
                ));
            }
            Ok(reply)
        }
    }

    /// Forwards to `agent`; right after the keys are loaded, another atem
    /// process changes cred_state.json (here: records an abandoned kid).
    struct ChangedMeanwhile {
        agent: std::sync::Mutex<crate::memory::key_agent::KeyAgent>,
        paths: KeyPaths,
    }

    impl KeyAgentApi for ChangedMeanwhile {
        fn call(
            &self,
            request: crate::memory::key_agent::Request,
        ) -> Result<crate::memory::key_agent::Reply> {
            let load = matches!(request, crate::memory::key_agent::Request::LoadUnlocked { .. });
            let reply = self.agent.call(request)?;
            if load {
                TrustStore::update(&self.paths.trust, |store| {
                    store.record_abandoned("5a5b5c5d");
                    Ok(())
                })?;
            }
            Ok(reply)
        }
    }

    #[test]
    fn verification_keeps_changes_made_to_cred_state_meanwhile() {
        let dir = tempfile::tempdir().unwrap();
        let paths = KeyPaths::in_dir(dir.path());
        let agent = ChangedMeanwhile {
            agent: test_agent(&paths),
            paths: paths.clone(),
        };
        let fake = FakeAstation::new();
        verified_device(&paths, &agent, &fake, EncryptionMode::Off, None);
        let trust = TrustStore::load_from(&paths.trust).unwrap();
        assert!(trust.verified(ASTATION_ID).is_some());
        assert_eq!(trust.home(), Some(ASTATION_ID));
        assert!(trust.was_abandoned("5a5b5c5d"), "the other change survives");
    }

    #[test]
    fn a_failed_fresh_write_leaves_another_runs_key_files_alone() {
        let dir = tempfile::tempdir().unwrap();
        let paths = KeyPaths::in_dir(dir.path());
        let other = DeviceKeys::generate();
        let (other_unlock_auth, other_sign) = (other.unlock_auth_pub(), other.device_sign_pub());
        let agent = RacedByAnotherRun {
            agent: test_agent(&paths),
            paths: paths.clone(),
            other,
            failing: Default::default(),
        };
        let fake = FakeAstation::new();
        let (handshake, certificate) = start(&paths, &fake, DeviceKeys::generate(), 7, 1);
        assert!(
            complete_verification(
                &paths,
                &agent,
                ASTATION_ID,
                handshake.into_keys(),
                &fake.sign(&certificate.encode()),
                &state(&fake, EncryptionMode::Off, None, 2),
                &[],
            )
            .is_err()
        );
        assert_eq!(
            SealedDeviceKeys::load_from(&paths.device_keys_sealed)
                .unwrap()
                .expect("the other run's sealed file stays")
                .storage_kid,
            "7a7b7c7d"
        );
        assert_eq!(
            UnlockAuthKey::load_from(&paths.unlock_auth_key)
                .unwrap()
                .expect("the other run's unlock_auth_key stays")
                .public(),
            other_unlock_auth
        );
        assert_eq!(
            DeviceKeys::load_from(&paths.device_keys)
                .unwrap()
                .expect("the other run's plain keys stay")
                .device_sign_pub(),
            other_sign
        );
        assert!(!agent.status().unwrap().unlocked, "this run's keys are dropped");
    }

    /// Forwards to `agent`; right after it first opens a grant, another
    /// atem process (the TUI's Astation link) applies `newer`, a later
    /// signed account state, as `apply_account_state` does.
    struct NewerStateMeanwhile {
        agent: std::sync::Mutex<crate::memory::key_agent::KeyAgent>,
        paths: KeyPaths,
        newer: std::sync::Mutex<Option<SignedWire>>,
    }

    impl KeyAgentApi for NewerStateMeanwhile {
        fn call(
            &self,
            request: crate::memory::key_agent::Request,
        ) -> Result<crate::memory::key_agent::Reply> {
            let open = matches!(request, crate::memory::key_agent::Request::CheckGrant { .. });
            let reply = self.agent.call(request)?;
            if open && let Some(newer) = self.newer.lock().unwrap().take() {
                assert!(matches!(
                    apply_account_state(&self.paths, ASTATION_ID, Some(&newer))?,
                    Applied::ModeChanged(_)
                ));
            }
            Ok(reply)
        }
    }

    #[test]
    fn a_newer_state_applied_during_re_verification_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        let paths = KeyPaths::in_dir(dir.path());
        let fake = FakeAstation::new();
        let agent = NewerStateMeanwhile {
            agent: test_agent(&paths),
            paths: paths.clone(),
            newer: std::sync::Mutex::new(Some(state(
                &fake,
                EncryptionMode::On,
                Some("89abcdef"),
                5,
            ))),
        };
        verified_device(&paths, &agent, &fake, EncryptionMode::Off, None);

        // Re-verification with state epoch 4 (kid 0123abcd) and its grant;
        // while it runs, Astation's epoch-5 state (a rotated K) arrives.
        let keys = device_keys_for_verification(&paths, &agent).unwrap();
        let (handshake, certificate) = start(&paths, &fake, keys, 8, 3);
        let grant = seal_k_grant(
            &fake,
            "acct",
            "dev-1",
            certificate.device_pub,
            "0123abcd",
            [42; 32],
        );
        let outcome = complete_verification(
            &paths,
            &agent,
            ASTATION_ID,
            handshake.into_keys(),
            &fake.sign(&certificate.encode()),
            &state(&fake, EncryptionMode::On, Some("0123abcd"), 4),
            &[grant],
        )
        .expect("a newer state applied meanwhile doesn't fail the verification");

        let trust = TrustStore::load_from(&paths.trust).unwrap();
        let entry = trust.verified(ASTATION_ID).unwrap();
        assert_eq!(
            (entry.epoch_floor, entry.account_epoch),
            (5, 5),
            "the new certificate is recorded (the floor rises to the newer state) and that state kept"
        );
        assert!(outcome.key_needed, "K for the newer kid is still to come");
        // The signed state names the newer kid: its grant installs.
        let newer_grant = seal_k_grant(
            &fake,
            "acct",
            "dev-1",
            certificate.device_pub,
            "89abcdef",
            [43; 32],
        );
        assert!(matches!(
            apply_grant(&paths, &agent, ASTATION_ID, Some(&newer_grant)).unwrap(),
            Applied::KeyInstalled(_)
        ));
        let mode = account_mode(&paths.trust, ASTATION_ID).unwrap();
        assert_eq!(mode.mode, EncryptionMode::On);
        assert_eq!(mode.kid.as_deref(), Some("89abcdef"), "the older state isn't re-applied");
        assert_eq!(agent.held_kid(ASTATION_ID).unwrap().as_deref(), Some("89abcdef"));
    }
}
