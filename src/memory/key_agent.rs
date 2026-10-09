//! The key agent: this device's unlocked keys, in memory only, like
//! ssh-agent. It never talks to the network: the CLI carries its requests
//! to Astation and Astation's answers back. Keys are wiped on `Lock` and
//! when the process exits. See designs/e2e-encryption.md "Keys on disk (atem)".
use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::memory::account_keys::{AccountKeys, CryptOp, CryptOut, SignedModes};
use crate::memory::crypto::EncryptionMode;
use crate::memory::device_keys::{DeviceKeys, UnlockAuthKey, decode32};
use crate::memory::encoding::dec;
use crate::memory::grant::{GrantWire, hpke_open, hpke_seal, open_grant as open_sealed_grant};
use crate::memory::statements::{
    SignedWire, StorageAbandon, StorageConfirm, StorageRotate, UnlockRequest, sealed_hash,
    storage_key_info, unlock_info,
};
use crate::memory::storage_key::{
    CheckedGrant, SealedDeviceKeys, StorageKey, StorageRotation, UnlockGrantWire,
    check_storage_ack, check_unlock_grant, new_storage_key, new_storage_kid, promote_next,
};
use crate::memory::trust::{AstationTrust, TrustStore};
use crate::memory::verification::{KeyPaths, stored_state};

/// Every request carries `"v": PROTOCOL_VERSION`; the agent answers any
/// other version with an error, so an old agent and a newer CLI fail clearly.
pub const PROTOCOL_VERSION: u64 = 1;

pub const LOCKED: &str = "this device's keys are locked; run `atem cred unlock`";

/// Appended to key-file errors, which never stop the agent (it starts locked).
pub const RESET: &str = "To start over: delete ~/.config/atem/device_keys, device_keys.sealed, device_keys.sealed.next, device_keys.sealed.prev, unlock_auth_key and cred_state.json, then run `atem pair`.";

/// What the agent serves. Only the same user can reach it (agent_socket.rs).
/// Fields that carry secrets are `Zeroizing`.
#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
#[allow(
    clippy::large_enum_variant,
    reason = "one short-lived request per call; boxing the grant would only add an allocation"
)]
pub enum Request {
    Status,
    PublicKeys,
    /// Keys handed over at the first verification (same-user socket): the
    /// agent holds them unlocked until Astation has their storage key.
    LoadUnlocked {
        device_id: String,
        device: Zeroizing<String>,
        device_sign: Zeroizing<String>,
        unlock_auth: Zeroizing<String>,
        storage_kid: String,
        storage_key: Zeroizing<String>,
    },
    /// Opens a `K` grant from a verified Astation and stores `K` in the
    /// sealed file (it is never handed back). The grant must name the kid
    /// of the latest signed account state in cred_state.json.
    InstallGrant {
        astation_id: String,
        grant: GrantWire,
    },
    /// Verification only: opens a grant against pins not saved yet, to
    /// check it, and drops `K`.
    CheckGrant {
        grant: GrantWire,
        trust: AstationTrust,
    },
    /// Field operations with the account's `K` (account_keys.rs), in order.
    Crypt {
        astation_id: String,
        ops: Vec<CryptOp>,
    },
    /// The current kid held for `astation_id`'s account, once the keys a
    /// newer signed state retired are dropped.
    HeldKid {
        astation_id: String,
    },
    /// Starts an unlock through the home Astation: a single-use X25519 key.
    BeginUnlock {
        astation_id: String,
    },
    /// Astation's answer to the request built from the challenge.
    FinishUnlock {
        astation_id: String,
        request: String,
        grant: UnlockGrantWire,
    },
    /// Rotation phase 1: a new storage key for the home Astation.
    BeginRotation {
        astation_id: String,
    },
    /// The rotation in progress (phase 1 done, not yet confirmed), unchanged,
    /// so the CLI can resend it: Astation accepts an identical resend.
    PendingRotation,
    /// Rotation phase 3, after Astation's signed acknowledgement.
    ConfirmRotation {
        astation_id: String,
        ack: SignedWire,
    },
    /// Gives up a pending key Astation holds for a rotation this device no
    /// longer has a file for.
    AbandonPending {
        astation_id: String,
        storage_kid: String,
    },
    Lock,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Reply {
    Status {
        unlocked: bool,
        storage_kid: Option<String>,
        escrowed: bool,
    },
    PublicKeys {
        device_pub: String,
        device_sign_pub: String,
    },
    GrantInstalled {
        kid: String,
    },
    GrantChecked {
        kid: String,
    },
    Crypted {
        results: Vec<CryptOut>,
    },
    HeldKid {
        kid: Option<String>,
    },
    UnlockChallenge {
        e_pub: String,
        nonce: String,
        storage_kid: String,
        device_id: String,
        account: String,
    },
    Unlocked {
        storage_kid: String,
    },
    Rotation {
        rotation: StorageRotation,
    },
    PendingRotation {
        rotation: Option<StorageRotation>,
    },
    Confirmed {
        storage_kid: String,
        confirm: SignedWire,
    },
    Abandoned {
        abandon: SignedWire,
    },
    Done,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentStatus {
    pub unlocked: bool,
    /// The storage key the keys are sealed under (the file's, while locked).
    pub storage_kid: Option<String>,
    /// Whether the home Astation holds that storage key.
    pub escrowed: bool,
}

struct Unlocked {
    keys: DeviceKeys,
    /// `K` and the keys it replaced, per account (build step 2b), as sealed
    /// in the file this agent holds the storage key for.
    accounts: AccountKeys,
    device_id: String,
    storage_kid: String,
    storage_key: StorageKey,
    escrowed: bool,
    /// Opened with the `.prev` file: Astation may not hold the current key,
    /// so no rotation until an unlock opens the current file.
    via_prev: bool,
    /// `accounts` dropped retired keys the sealed file still carries (a
    /// best-effort re-seal failed): the next call writes the file again.
    unsaved: bool,
}

/// The single-use key of an unlock in progress. `StaticSecret` zeroizes on drop.
struct PendingUnlock {
    astation_id: String,
    /// The storage key the challenge named; the request must name the same.
    storage_kid: String,
    e_secret: StaticSecret,
    e_pub: [u8; 32],
    nonce: [u8; 32],
}

/// A storage key sent to Astation and not yet acknowledged.
struct PendingRotation {
    storage_kid: String,
    storage_key: StorageKey,
    /// The first escrow of the current key: nothing to rename.
    initial: bool,
    /// What phase 1 returned, for an identical resend.
    wire: StorageRotation,
}

/// What the CLI needs to build and sign an unlock request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnlockChallenge {
    pub e_pub: [u8; 32],
    pub nonce: [u8; 32],
    pub storage_kid: String,
    pub device_id: String,
    pub account: String,
}

/// The CLI's half: the `atem-unlock-request-v1` statement for `challenge`,
/// signed by the unlock-auth key. Auto-unlock tickets come in build step 7.
pub fn build_unlock_request(
    challenge: &UnlockChallenge,
    boot_id: &str,
    time: u64,
    unlock_auth: &UnlockAuthKey,
) -> SignedWire {
    let statement = UnlockRequest {
        account: challenge.account.clone(),
        device_id: challenge.device_id.clone(),
        boot_id: boot_id.into(),
        ticket: String::new(),
        e_pub: challenge.e_pub,
        nonce: challenge.nonce,
        time,
        storage_kid: challenge.storage_kid.clone(),
    }
    .encode();
    unlock_auth.sign_statement(&statement)
}

pub struct KeyAgent {
    paths: KeyPaths,
    unlocked: Option<Unlocked>,
    pending_unlock: Option<PendingUnlock>,
    pending_rotation: Option<PendingRotation>,
    /// How often a failed prune re-seal was logged.
    #[cfg(test)]
    pub(crate) prune_failures_logged: usize,
}

/// Opens a sealed device-keys file only when its header names the device and
/// the storage key the caller expects; anything else fails closed.
pub(crate) fn open_sealed_checked(
    sealed: &SealedDeviceKeys,
    device_id: &str,
    storage_kid: &str,
    storage_key: &[u8; 32],
    unlock_auth: UnlockAuthKey,
) -> Result<(DeviceKeys, AccountKeys)> {
    if sealed.device_id != device_id {
        bail!("device_keys.sealed belongs to another device");
    }
    if sealed.storage_kid != storage_kid {
        bail!(
            "device_keys.sealed is under storage key {}, not {storage_kid}",
            sealed.storage_kid
        );
    }
    sealed.open_with_accounts(storage_key, unlock_auth)
}

impl KeyAgent {
    /// An agent for the key files in `paths`: locked, unless a plain step-1
    /// `device_keys` file is migrated (then unlocked, not yet escrowed).
    /// First it sweeps the temps crashed writers left beside those files.
    /// A migration or key-file error never stops the agent: it starts locked
    /// and logs the error and how to start over.
    pub fn new(paths: KeyPaths) -> Result<Self> {
        // Temps a crashed writer left behind can hold key material.
        for path in [
            &paths.trust,
            &paths.device_keys,
            &paths.device_keys_sealed,
            &paths.device_keys_next,
            &paths.device_keys_prev,
            &paths.unlock_auth_key,
            &paths.agent_socket,
        ] {
            crate::memory::crypto::sweep_stale_temps(path);
        }
        let mut agent = Self {
            paths,
            unlocked: None,
            pending_unlock: None,
            pending_rotation: None,
            #[cfg(test)]
            prune_failures_logged: 0,
        };
        if let Err(error) = agent.migrate_plain_keys() {
            eprintln!("key agent: {error:#}");
            agent.wipe();
        }
        Ok(agent)
    }

    pub fn handle(&mut self, request: Request) -> Result<Reply> {
        match request {
            Request::Status => Ok(self.status()),
            Request::PublicKeys => {
                let unlocked = self.unlocked()?;
                Ok(Reply::PublicKeys {
                    device_pub: STANDARD.encode(unlocked.keys.device_pub()),
                    device_sign_pub: STANDARD.encode(unlocked.keys.device_sign_pub()),
                })
            }
            Request::LoadUnlocked {
                device_id,
                device,
                device_sign,
                unlock_auth,
                storage_kid,
                storage_key,
            } => self.load_unlocked(
                device_id,
                &device,
                &device_sign,
                &unlock_auth,
                storage_kid,
                &storage_key,
            ),
            Request::InstallGrant { astation_id, grant } => {
                self.install_grant(&astation_id, &grant)
            }
            Request::CheckGrant { grant, trust } => {
                let opened = open_sealed_grant(&trust, &self.unlocked()?.keys, &grant)?;
                Ok(Reply::GrantChecked { kid: opened.kid })
            }
            Request::Crypt { astation_id, ops } => self.crypt(&astation_id, ops),
            Request::HeldKid { astation_id } => self.held_kid(&astation_id),
            Request::BeginUnlock { astation_id } => self.begin_unlock(&astation_id),
            Request::FinishUnlock {
                astation_id,
                request,
                grant,
            } => self.finish_unlock(&astation_id, &request, &grant),
            Request::BeginRotation { astation_id } => self.begin_rotation(&astation_id),
            Request::PendingRotation => Ok(Reply::PendingRotation {
                rotation: self
                    .pending_rotation
                    .as_ref()
                    .map(|pending| pending.wire.clone()),
            }),
            Request::ConfirmRotation { astation_id, ack } => {
                self.confirm_rotation(&astation_id, &ack)
            }
            Request::AbandonPending {
                astation_id,
                storage_kid,
            } => self.abandon_pending(&astation_id, &storage_kid),
            // Always allowed: until Astation holds the storage key, the plain
            // device_keys file stays on disk and is re-sealed at the next start.
            Request::Lock => {
                self.wipe();
                Ok(Reply::Done)
            }
        }
    }

    /// Drops every secret; their types zeroize on drop.
    fn wipe(&mut self) {
        self.unlocked = None;
        self.pending_unlock = None;
        self.pending_rotation = None;
    }

    fn unlocked(&self) -> Result<&Unlocked> {
        self.unlocked.as_ref().ok_or_else(|| anyhow!(LOCKED))
    }

    fn status(&self) -> Reply {
        match &self.unlocked {
            Some(unlocked) => Reply::Status {
                unlocked: true,
                storage_kid: Some(unlocked.storage_kid.clone()),
                escrowed: unlocked.escrowed,
            },
            None => Reply::Status {
                unlocked: false,
                // The current file is missing only between a promotion's renames.
                storage_kid: [&self.paths.device_keys_sealed, &self.paths.device_keys_next]
                    .into_iter()
                    .find_map(|path| SealedDeviceKeys::load_from(path).ok().flatten())
                    .map(|sealed| sealed.storage_kid),
                escrowed: false,
            },
        }
    }

    fn load_unlocked(
        &mut self,
        device_id: String,
        device: &str,
        device_sign: &str,
        unlock_auth: &str,
        storage_kid: String,
        storage_key: &str,
    ) -> Result<Reply> {
        // A concurrent pairing run must not replace keys another one loaded.
        if self.unlocked.is_some() {
            bail!("the key agent already holds keys; run `atem cred lock` first");
        }
        if !crate::memory::crypto::valid_kid(&storage_kid) {
            bail!("storage key id must be 8 lowercase hex characters");
        }
        let keys = DeviceKeys::from_secrets(
            *decode32(device, "device key")?,
            *decode32(device_sign, "device signing key")?,
            *decode32(unlock_auth, "unlock-auth key")?,
        );
        let storage_key = decode32(storage_key, "storage key")?;
        self.pending_unlock = None;
        self.pending_rotation = None;
        self.unlocked = Some(Unlocked {
            keys,
            accounts: AccountKeys::default(),
            device_id,
            storage_kid,
            storage_key,
            escrowed: false,
            via_prev: false,
            unsaved: false,
        });
        Ok(Reply::Done)
    }

    fn install_grant(&mut self, astation_id: &str, grant: &GrantWire) -> Result<Reply> {
        let unlocked = self.unlocked()?;
        let trust = TrustStore::load_from(&self.paths.trust)?;
        let entry = trust
            .verified(astation_id)
            .ok_or_else(|| anyhow!("this device isn't verified with Astation {astation_id}"))?;
        let opened = open_sealed_grant(entry, &unlocked.keys, grant)?;
        if !crate::memory::crypto::valid_kid(&opened.kid) {
            bail!("encryption key id must be 8 lowercase hex characters");
        }
        let state = stored_state(entry)?
            .ok_or_else(|| anyhow!("received an encryption key before the account mode"))?;
        if state.kid.as_deref() != Some(opened.kid.as_str()) {
            bail!("encryption key grant does not match the announced account mode");
        }
        let kid = opened.kid.clone();
        let mut accounts = unlocked.accounts.clone();
        accounts.install(&entry.data_account, &kid, opened.key);
        accounts.reconcile(&self.signed_modes()?);
        // Another verified Astation naming this account may have signed a
        // newer state: a key it retires is never reported as installed.
        if accounts.current_kid(&entry.data_account) != Some(kid.as_str()) {
            bail!("a newer signed state retired this key");
        }
        // Saved before it is used: K is in memory only once it is on disk.
        self.persist(&accounts)?;
        let unlocked = self.unlocked.as_mut().expect("unlocked above");
        unlocked.accounts = accounts;
        unlocked.unsaved = false;
        Ok(Reply::GrantInstalled { kid })
    }

    fn crypt(&mut self, astation_id: &str, ops: Vec<CryptOp>) -> Result<Reply> {
        self.unlocked()?;
        self.prune_retired();
        let trust = TrustStore::load_from(&self.paths.trust)?;
        let entry = trust
            .verified(astation_id)
            .ok_or_else(|| anyhow!("this device isn't verified with Astation {astation_id}"))?;
        let state = stored_state(entry)?.ok_or_else(|| {
            anyhow!("waiting for Astation's signed encryption state; reconnect to Astation")
        })?;
        let results = self.unlocked()?.accounts.crypt(
            &entry.data_account,
            state.mode,
            state.kid.as_deref(),
            ops,
        )?;
        Ok(Reply::Crypted { results })
    }

    fn held_kid(&mut self, astation_id: &str) -> Result<Reply> {
        self.unlocked()?;
        self.prune_retired();
        let trust = TrustStore::load_from(&self.paths.trust)?;
        let kid = trust.verified(astation_id).and_then(|entry| {
            self.unlocked
                .as_ref()?
                .accounts
                .current_kid(&entry.data_account)
                .map(str::to_string)
        });
        Ok(Reply::HeldKid { kid })
    }

    /// The latest signed state of every account a verified Astation names
    /// (the highest epoch when two name one account).
    fn signed_modes(&self) -> Result<SignedModes> {
        let trust = TrustStore::load_from(&self.paths.trust)?;
        let mut latest: BTreeMap<String, Option<(u64, EncryptionMode, Option<String>)>> =
            BTreeMap::new();
        for entry in trust.verified_entries() {
            let state = stored_state(entry)?;
            let slot = latest.entry(entry.data_account.clone()).or_insert(None);
            if let Some(state) = state
                && slot
                    .as_ref()
                    .is_none_or(|(epoch, _, _)| state.epoch > *epoch)
            {
                *slot = Some((state.epoch, state.mode, state.kid));
            }
        }
        Ok(latest
            .into_iter()
            .map(|(account, state)| (account, state.map(|(_, mode, kid)| (mode, kid))))
            .collect())
    }

    /// Drops the account keys the signed states retired (`off`, or previous
    /// keys once `on` names the current kid). Best effort: they go from
    /// memory at once (the signed state already forbids them), and a failed
    /// re-seal is retried at the next call, never failing it. It is logged
    /// once, when the keys first go unsaved, not at every retry.
    fn prune_retired(&mut self) {
        let was_unsaved = self
            .unlocked
            .as_ref()
            .is_some_and(|unlocked| unlocked.unsaved);
        if let Err(error) = self.try_prune() {
            let unsaved = self
                .unlocked
                .as_ref()
                .is_some_and(|unlocked| unlocked.unsaved);
            if unsaved && !was_unsaved {
                eprintln!("key agent: could not re-seal the account keys: {error:#}");
                #[cfg(test)]
                {
                    self.prune_failures_logged += 1;
                }
            }
        }
    }

    fn try_prune(&mut self) -> Result<()> {
        let modes = self.signed_modes()?;
        let unlocked = self.unlocked.as_mut().ok_or_else(|| anyhow!(LOCKED))?;
        if unlocked.accounts.reconcile(&modes) {
            unlocked.unsaved = true;
        }
        if !unlocked.unsaved {
            return Ok(());
        }
        let unlocked = self.unlocked()?;
        self.persist(&unlocked.accounts)?;
        self.unlocked.as_mut().expect("unlocked above").unsaved = false;
        Ok(())
    }

    /// Writes the sealed file this agent holds the storage key for (and a
    /// pending rotation's `.next`) again, with `accounts`, under the storage
    /// keys they already use (temp file, fsync, rename). Only a file whose
    /// header names the storage kid the agent holds is ever rewritten:
    /// another kid there means another run changed it, and that file is
    /// left alone. A crash leaves the old or the new file, both opened by
    /// the same storage key; at worst a newly installed `K` is missing, and
    /// atem asks Astation for it again (a `K` always comes as a signed grant).
    fn persist(&self, accounts: &AccountKeys) -> Result<()> {
        let unlocked = self.unlocked()?;
        let held = if unlocked.via_prev {
            &self.paths.device_keys_prev
        } else {
            &self.paths.device_keys_sealed
        };
        let on_disk = SealedDeviceKeys::load_from(held)?.ok_or_else(|| {
            anyhow!(
                "{} is missing; the account keys can't be stored",
                held.display()
            )
        })?;
        if on_disk.device_id != unlocked.device_id || on_disk.storage_kid != unlocked.storage_kid {
            bail!(
                "{} is under storage key {}, not the one this agent holds ({}); run `atem cred lock`, then `atem cred unlock`",
                held.display(),
                on_disk.storage_kid,
                unlocked.storage_kid
            );
        }
        // A rotation in progress promotes .next: it must carry the same keys.
        // Written first, so a failure leaves the current file as it was.
        if let Some(pending) = &self.pending_rotation
            && !pending.initial
        {
            if let Some(next) = SealedDeviceKeys::load_from(&self.paths.device_keys_next)?
                && (next.device_id != unlocked.device_id || next.storage_kid != pending.storage_kid)
            {
                bail!(
                    "device_keys.sealed.next is under storage key {}, not the pending rotation's ({})",
                    next.storage_kid,
                    pending.storage_kid
                );
            }
            SealedDeviceKeys::seal_with(
                &unlocked.keys,
                accounts,
                &unlocked.device_id,
                &pending.storage_kid,
                &pending.storage_key,
            )?
            .save_to(&self.paths.device_keys_next)?;
        }
        SealedDeviceKeys::seal_with(
            &unlocked.keys,
            accounts,
            &unlocked.device_id,
            &unlocked.storage_kid,
            &unlocked.storage_key,
        )?
        .save_to(held)?;
        Ok(())
    }

    /// Once unlocked: drops account keys a signed state retired while the
    /// agent was locked. Never fatal: logged.
    fn after_unlock(&mut self) {
        self.prune_retired();
    }

    /// The pins of the home Astation, which must be `astation_id`.
    fn home(&self, astation_id: &str) -> Result<AstationTrust> {
        let store = TrustStore::load_from(&self.paths.trust)?;
        let home = store.home().ok_or_else(|| {
            anyhow!("this device has no home Astation yet; run `atem pair` to verify it")
        })?;
        if home != astation_id {
            bail!(
                "this device's keys unlock through its home Astation ({home}), not {astation_id}"
            );
        }
        store
            .verified(home)
            .cloned()
            .ok_or_else(|| anyhow!("the home Astation's pins are missing; run `atem pair`"))
    }

    fn begin_unlock(&mut self, astation_id: &str) -> Result<Reply> {
        if self.unlocked.is_some() {
            bail!("this device's keys are already unlocked");
        }
        let trust = self.home(astation_id)?;
        // The current file decides: only when it is absent (between a
        // promotion's renames) may a spare be named. Any error reading it
        // fails closed, so a transient error can't make a request name a
        // stale .next kid. A damaged spare doesn't matter if a later one reads.
        let mut sealed = SealedDeviceKeys::load_from(&self.paths.device_keys_sealed)?;
        let mut spare_error = None;
        for path in [&self.paths.device_keys_next, &self.paths.device_keys_prev] {
            if sealed.is_some() {
                break;
            }
            match SealedDeviceKeys::load_from(path) {
                Ok(file) => sealed = file,
                Err(error) => spare_error = spare_error.or(Some(error)),
            }
        }
        let sealed = match (sealed, spare_error) {
            (Some(file), _) => file,
            (None, Some(error)) => return Err(error),
            (None, None) => {
                bail!("this device has no sealed keys; run `atem pair` to verify it")
            }
        };
        if sealed.device_id != trust.device_id {
            bail!("device_keys.sealed belongs to another device id");
        }
        let e_secret = StaticSecret::random_from_rng(OsRng);
        let e_pub = PublicKey::from(&e_secret).to_bytes();
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        self.pending_unlock = Some(PendingUnlock {
            astation_id: astation_id.into(),
            storage_kid: sealed.storage_kid.clone(),
            e_secret,
            e_pub,
            nonce,
        });
        Ok(Reply::UnlockChallenge {
            e_pub: STANDARD.encode(e_pub),
            nonce: STANDARD.encode(nonce),
            storage_kid: sealed.storage_kid,
            device_id: trust.device_id,
            account: trust.data_account,
        })
    }

    fn finish_unlock(
        &mut self,
        astation_id: &str,
        request: &str,
        grant: &UnlockGrantWire,
    ) -> Result<Reply> {
        // Single use: E is gone after this call, whatever the outcome.
        let pending = self
            .pending_unlock
            .take()
            .ok_or_else(|| anyhow!("no unlock is in progress; run `atem cred unlock` again"))?;
        if self.unlocked.is_some() {
            bail!("this device's keys are already unlocked");
        }
        if pending.astation_id != astation_id {
            bail!("the unlock reply came from a different Astation");
        }
        let trust = self.home(astation_id)?;
        let request_bytes = STANDARD
            .decode(request)
            .context("unlock request is not base64")?;
        let sent = UnlockRequest::parse(&dec(&request_bytes)?)?;
        if sent.e_pub != pending.e_pub || sent.nonce != pending.nonce {
            bail!("the unlock reply answers a different request");
        }
        if sent.storage_kid != pending.storage_kid {
            bail!("the unlock request names a different storage key than the challenge");
        }
        if sent.account != trust.data_account || sent.device_id != trust.device_id {
            bail!("the unlock request names another account or device");
        }
        let CheckedGrant {
            grant: granted,
            request_hash,
            encapped,
            ciphertext,
        } = check_unlock_grant(&trust, &request_bytes, grant)?;
        let info = unlock_info(
            &granted.account,
            &granted.device_id,
            &granted.storage_kid,
            &request_hash,
        );
        // E's private key is dropped as soon as the storage key is open.
        let plain = {
            let e_secret = Zeroizing::new(pending.e_secret.to_bytes());
            drop(pending);
            hpke_open(&e_secret, &encapped, &ciphertext, &info)
                .context("the storage key could not be opened")?
        };
        let storage_key: StorageKey = Zeroizing::new(
            plain
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("storage key has the wrong length"))?,
        );
        drop(plain);
        let (sealed, source) = self.sealed_with_kid(&granted.storage_kid)?;
        let unlock_auth = UnlockAuthKey::load_from(&self.paths.unlock_auth_key)?
            .ok_or_else(|| anyhow!("unlock_auth_key is missing. {RESET}"))?;
        let (keys, accounts) = open_sealed_checked(
            &sealed,
            &trust.device_id,
            &granted.storage_kid,
            &storage_key,
            unlock_auth,
        )?;
        if STANDARD.encode(keys.device_pub()) != trust.device_pub
            || STANDARD.encode(keys.device_sign_pub()) != trust.device_sign_pub
        {
            bail!("the sealed keys aren't this device's pinned keys");
        }
        // A lone .prev that Astation just released becomes current again.
        let source = match source {
            SealedFile::Prev if !exists(&self.paths.device_keys_sealed)? => {
                promote_next(&self.paths.device_keys_prev, &self.paths.device_keys_sealed)?;
                SealedFile::Current
            }
            other => other,
        };
        match source {
            // Astation released the key a crashed rotation left pending.
            SealedFile::Next => promote_keeping_prev(&self.paths)?,
            // Astation holds the current key, so the file it replaced can go.
            SealedFile::Current => match std::fs::remove_file(&self.paths.device_keys_prev) {
                Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                    return Err(error.into());
                }
                _ => {}
            },
            SealedFile::Prev => {}
        }
        if source != SealedFile::Prev {
            // The unlock proves Astation holds the key the current file is
            // now sealed under: record it (`atem cred status` reads it).
            TrustStore::update(&self.paths.trust, |store| {
                store.set_escrowed_kid(&granted.storage_kid);
                Ok(())
            })?;
            // A pending first escrow is settled, so the plain file goes.
            if source == SealedFile::Current {
                remove_plain_keys(&self.paths)?;
            }
        }
        self.unlocked = Some(Unlocked {
            keys,
            accounts,
            device_id: trust.device_id,
            storage_kid: granted.storage_kid.clone(),
            storage_key,
            escrowed: true,
            via_prev: source == SealedFile::Prev,
            unsaved: false,
        });
        self.after_unlock();
        Ok(Reply::Unlocked {
            storage_kid: granted.storage_kid,
        })
    }

    fn begin_rotation(&mut self, astation_id: &str) -> Result<Reply> {
        if self.pending_rotation.is_some() {
            bail!(
                "a storage-key rotation is already in progress; `atem cred unlock` resends it to Astation"
            );
        }
        let unlocked = self.unlocked.as_ref().ok_or_else(|| anyhow!(LOCKED))?;
        let trust = self.home(astation_id)?;
        if unlocked.device_id != trust.device_id {
            bail!("the unlocked keys belong to another device id");
        }
        if unlocked.via_prev {
            bail!("unlocked with the previous storage key; lock and unlock again before rotating");
        }
        // A .next with no rotation in memory is a rotation that died after
        // Astation may have stored its key: that pending key must be abandoned first.
        if let Some(stale) = SealedDeviceKeys::load_from(&self.paths.device_keys_next)? {
            bail!(
                "device_keys.sealed.next (storage key {}) is left from an interrupted rotation that Astation may hold as pending; `atem cred unlock` abandons that key with Astation, then rotates",
                stale.storage_kid
            );
        }
        let initial = !unlocked.escrowed;
        let (old_kid, new_kid, new_key) = if initial {
            (
                String::new(),
                unlocked.storage_kid.clone(),
                unlocked.storage_key.clone(),
            )
        } else {
            // Never a kid this device abandoned: a replayed abandon could drop it.
            let kid = TrustStore::load_from(&self.paths.trust)?
                .pick_storage_kid(&unlocked.storage_kid, new_storage_kid);
            let key = new_storage_key();
            // Phase 1: the re-sealed file (with the account keys) waits
            // beside the current one.
            SealedDeviceKeys::seal_with(
                &unlocked.keys,
                &unlocked.accounts,
                &unlocked.device_id,
                &kid,
                &key,
            )?
            .save_to(&self.paths.device_keys_next)?;
            (unlocked.storage_kid.clone(), kid, key)
        };
        let enc_pub = decode32(&trust.astation_enc_pub, "Astation encryption key")?;
        let (encapped, ciphertext) = hpke_seal(
            &enc_pub,
            &storage_key_info(&trust.data_account, &unlocked.device_id, &new_kid),
            new_key.as_slice(),
        )?;
        let statement = StorageRotate {
            account: trust.data_account.clone(),
            device_id: unlocked.device_id.clone(),
            old_storage_kid: old_kid,
            new_storage_kid: new_kid.clone(),
            sealed_hash: sealed_hash(&encapped, &ciphertext),
        }
        .encode();
        let rotation = StorageRotation {
            rotate: unlocked.keys.sign_statement(&statement),
            encapped_key: STANDARD.encode(encapped),
            ciphertext: STANDARD.encode(ciphertext),
        };
        self.pending_rotation = Some(PendingRotation {
            storage_kid: new_kid,
            storage_key: new_key,
            initial,
            wire: rotation.clone(),
        });
        Ok(Reply::Rotation { rotation })
    }

    fn confirm_rotation(&mut self, astation_id: &str, ack: &SignedWire) -> Result<Reply> {
        let trust = self.home(astation_id)?;
        // Nothing is consumed until the ack checks out: a forged or stale ack
        // must not cancel the rotation Astation is really holding.
        let pending = self
            .pending_rotation
            .as_ref()
            .ok_or_else(|| anyhow!("no storage-key rotation is in progress"))?;
        check_storage_ack(&trust, &pending.storage_kid, ack)?;
        let unlocked = self.unlocked.as_ref().ok_or_else(|| anyhow!(LOCKED))?;
        if !pending.initial {
            let next = SealedDeviceKeys::load_from(&self.paths.device_keys_next)?
                .ok_or_else(|| anyhow!("device_keys.sealed.next is missing"))?;
            if next.storage_kid != pending.storage_kid || next.device_id != trust.device_id {
                bail!("device_keys.sealed.next is not the file this rotation wrote");
            }
        }
        // Astation holds the key now: record which one.
        TrustStore::update(&self.paths.trust, |store| {
            store.set_escrowed_kid(&pending.storage_kid);
            Ok(())
        })?;
        if pending.initial {
            // Only now does the plain step-1 file go.
            remove_plain_keys(&self.paths)?;
        } else {
            // Phase 3: the new file becomes current. The old one stays as
            // .prev until an unlock shows Astation really holds the new key.
            promote_keeping_prev(&self.paths)?;
        }
        let confirm = unlocked.keys.sign_statement(
            &StorageConfirm {
                account: trust.data_account,
                device_id: trust.device_id,
                storage_kid: pending.storage_kid.clone(),
            }
            .encode(),
        );
        let pending = self.pending_rotation.take().expect("checked above");
        let unlocked = self.unlocked.as_mut().expect("checked above");
        unlocked.storage_kid = pending.storage_kid.clone();
        unlocked.storage_key = pending.storage_key;
        unlocked.escrowed = true;
        Ok(Reply::Confirmed {
            storage_kid: pending.storage_kid,
            confirm,
        })
    }

    /// Signs `atem-storage-abandon-v1` for a pending key Astation may hold.
    /// Only when no rotation in memory and no sealed file carries that kid:
    /// otherwise the device could strand itself. A stale `.next` with that
    /// kid is deleted durably first.
    fn abandon_pending(&mut self, astation_id: &str, storage_kid: &str) -> Result<Reply> {
        let unlocked = self.unlocked.as_ref().ok_or_else(|| anyhow!(LOCKED))?;
        let trust = self.home(astation_id)?;
        if !crate::memory::crypto::valid_kid(storage_kid) {
            bail!("storage key id must be 8 lowercase hex characters");
        }
        if let Some(rotation) = &self.pending_rotation
            && rotation.storage_kid == storage_kid
        {
            bail!("a rotation to storage key {storage_kid} is in progress here");
        }
        let next = SealedDeviceKeys::load_from(&self.paths.device_keys_next)?;
        if let Some(next) = &next
            && next.storage_kid == storage_kid
            && self.pending_rotation.is_none()
        {
            std::fs::remove_file(&self.paths.device_keys_next)?;
            #[cfg(unix)]
            std::fs::File::open(
                self.paths
                    .device_keys_next
                    .parent()
                    .filter(|parent| !parent.as_os_str().is_empty())
                    .unwrap_or(std::path::Path::new(".")),
            )?
            .sync_all()?;
        }
        for path in [
            &self.paths.device_keys_sealed,
            &self.paths.device_keys_next,
            &self.paths.device_keys_prev,
        ] {
            if let Some(sealed) = SealedDeviceKeys::load_from(path)?
                && sealed.storage_kid == storage_kid
            {
                bail!("a sealed file still carries storage key {storage_kid}");
            }
        }
        // Recorded before it is signed, so the kid is never picked again.
        TrustStore::update(&self.paths.trust, |store| {
            store.record_abandoned(storage_kid);
            Ok(())
        })?;
        let abandon = unlocked.keys.sign_statement(
            &StorageAbandon {
                account: trust.data_account,
                device_id: trust.device_id,
                storage_kid: storage_kid.into(),
            }
            .encode(),
        );
        Ok(Reply::Abandoned { abandon })
    }

    /// The sealed file the released key belongs to: the current one, the
    /// `.next` a rotation left when it crashed after Astation stored the key,
    /// or the `.prev` a promotion kept when Astation turned out to hold only
    /// the older key.
    fn sealed_with_kid(&self, storage_kid: &str) -> Result<(SealedDeviceKeys, SealedFile)> {
        for (path, which) in [
            (&self.paths.device_keys_sealed, SealedFile::Current),
            (&self.paths.device_keys_next, SealedFile::Next),
            (&self.paths.device_keys_prev, SealedFile::Prev),
        ] {
            if let Some(sealed) = SealedDeviceKeys::load_from(path)?
                && sealed.storage_kid == storage_kid
            {
                return Ok((sealed, which));
            }
        }
        bail!("no sealed keys on disk match the storage key Astation released ({storage_kid})")
    }

    /// A plain `device_keys` file (a step-1 device's, or a fresh device's
    /// before its first escrow) is authoritative whenever it exists: it stays
    /// until Astation is known to hold the storage key. Seal it under a new
    /// storage key (overwriting any earlier sealed file, e.g. from a crashed
    /// migration or an agent that stopped before the escrow), split out the
    /// unlock-auth key, record the home Astation. The keys stay unlocked here
    /// until the CLI sends the storage key to the home Astation (`atem pair`
    /// or `atem cred unlock`).
    fn migrate_plain_keys(&mut self) -> Result<()> {
        self.migrate_inner()
            .map_err(|error| anyhow!("{error:#}. {RESET}"))
    }

    fn migrate_inner(&mut self) -> Result<()> {
        let Some(keys) = DeviceKeys::load_from(&self.paths.device_keys)? else {
            return Ok(());
        };
        // The whole migration reads and writes cred_state.json under its lock.
        let _trust_lock = TrustStore::lock(&self.paths.trust)?;
        let mut trust = TrustStore::load_from(&self.paths.trust)?;
        // A crash after the first escrow was recorded but before the plain
        // file went: the sealed file is already escrowed, so just delete it.
        if let Some(escrowed) = trust.escrowed_kid()
            && let Some(sealed) = SealedDeviceKeys::load_from(&self.paths.device_keys_sealed)?
            && sealed.storage_kid == escrowed
        {
            remove_plain_keys(&self.paths)?;
            return Ok(());
        }
        let Some(home) = trust.home_or_first_verified() else {
            if trust.home_is_set() {
                eprintln!(
                    "key agent: the home Astation is no longer verified; device_keys left as it is"
                );
            } else {
                eprintln!("key agent: device_keys belongs to no verified Astation; left as it is");
            }
            return Ok(());
        };
        let entry = trust
            .verified(&home)
            .cloned()
            .expect("home_or_first_verified names a verified Astation");
        if entry.device_pub != STANDARD.encode(keys.device_pub())
            || entry.device_sign_pub != STANDARD.encode(keys.device_sign_pub())
            || entry.unlock_auth_pub != STANDARD.encode(keys.unlock_auth_pub())
        {
            bail!("device_keys doesn't hold the keys pinned for Astation {home}");
        }
        let storage_key = new_storage_key();
        // The sealed file this overwrites may be from an earlier start whose
        // key went to Astation unsettled: never reuse its kid.
        let earlier = SealedDeviceKeys::load_from(&self.paths.device_keys_sealed)
            .ok()
            .flatten()
            .map(|sealed| sealed.storage_kid)
            .unwrap_or_default();
        let storage_kid = trust.pick_storage_kid(&earlier, new_storage_kid);
        // The sealed file this overwrites can't be opened (its storage key
        // went with the agent that wrote it): any `K` in it is asked for
        // again (a `K` always comes as a signed grant), so none is sealed.
        let accounts = AccountKeys::default();
        SealedDeviceKeys::seal_with(
            &keys,
            &accounts,
            &entry.device_id,
            &storage_kid,
            &storage_key,
        )?
        .save_to(&self.paths.device_keys_sealed)?;
        keys.unlock_auth_key()
            .save_to(&self.paths.unlock_auth_key)?;
        trust.set_home(&home);
        trust.save_to(&self.paths.trust)?;
        // The plain file stays until Astation confirms the first escrow (Task 6).
        eprintln!(
            "key agent: sealed device_keys under storage key {storage_kid}; run `atem cred unlock` to hand it to Astation {home}"
        );
        self.unlocked = Some(Unlocked {
            keys,
            accounts,
            device_id: entry.device_id,
            storage_kid,
            storage_key,
            escrowed: false,
            via_prev: false,
            unsaved: false,
        });
        Ok(())
    }
}

/// Which sealed file a released storage key opened.
#[derive(PartialEq, Eq)]
enum SealedFile {
    Current,
    Next,
    Prev,
}

/// Renames the current sealed file to `.prev`, then `.next` over it. A crash
/// between the renames leaves `.prev` + `.next`, which unlock also accepts.
fn promote_keeping_prev(paths: &KeyPaths) -> Result<()> {
    if paths.device_keys_sealed.exists() {
        std::fs::rename(&paths.device_keys_sealed, &paths.device_keys_prev)?;
    }
    promote_next(&paths.device_keys_next, &paths.device_keys_sealed)
}

/// Whether anything (even a dangling symlink) is at `path`.
fn exists(path: &std::path::Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

/// Deletes the plain step-1 `device_keys` file (absent is fine).
fn remove_plain_keys(paths: &KeyPaths) -> Result<()> {
    match std::fs::remove_file(&paths.device_keys) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error.into()),
        _ => Ok(()),
    }
}

/// How callers talk to the agent: over its socket (`KeyAgentClient`), or
/// in process (`Mutex<KeyAgent>`, used by tests and by the socket server).
pub trait KeyAgentApi: Send + Sync {
    fn call(&self, request: Request) -> Result<Reply>;

    fn status(&self) -> Result<AgentStatus> {
        match self.call(Request::Status)? {
            Reply::Status {
                unlocked,
                storage_kid,
                escrowed,
            } => Ok(AgentStatus {
                unlocked,
                storage_kid,
                escrowed,
            }),
            _ => unexpected(),
        }
    }

    /// The device key and device signing key (public halves).
    fn public_keys(&self) -> Result<([u8; 32], [u8; 32])> {
        match self.call(Request::PublicKeys)? {
            Reply::PublicKeys {
                device_pub,
                device_sign_pub,
            } => Ok((
                *decode32(&device_pub, "device key")?,
                *decode32(&device_sign_pub, "device signing key")?,
            )),
            _ => unexpected(),
        }
    }

    fn begin_unlock(&self, astation_id: &str) -> Result<UnlockChallenge> {
        match self.call(Request::BeginUnlock {
            astation_id: astation_id.into(),
        })? {
            Reply::UnlockChallenge {
                e_pub,
                nonce,
                storage_kid,
                device_id,
                account,
            } => Ok(UnlockChallenge {
                e_pub: *decode32(&e_pub, "unlock key")?,
                nonce: *decode32(&nonce, "unlock nonce")?,
                storage_kid,
                device_id,
                account,
            }),
            _ => unexpected(),
        }
    }

    /// Returns the storage key id Astation released.
    fn finish_unlock(
        &self,
        astation_id: &str,
        request: &str,
        grant: &UnlockGrantWire,
    ) -> Result<String> {
        match self.call(Request::FinishUnlock {
            astation_id: astation_id.into(),
            request: request.into(),
            grant: grant.clone(),
        })? {
            Reply::Unlocked { storage_kid } => Ok(storage_kid),
            _ => unexpected(),
        }
    }

    fn begin_rotation(&self, astation_id: &str) -> Result<StorageRotation> {
        match self.call(Request::BeginRotation {
            astation_id: astation_id.into(),
        })? {
            Reply::Rotation { rotation } => Ok(rotation),
            _ => unexpected(),
        }
    }

    /// The rotation in progress, to resend unchanged; `None` when there is none.
    fn pending_rotation(&self) -> Result<Option<StorageRotation>> {
        match self.call(Request::PendingRotation)? {
            Reply::PendingRotation { rotation } => Ok(rotation),
            _ => unexpected(),
        }
    }

    /// The signed abandon for a pending key id (see `KeyAgent::abandon_pending`).
    fn abandon_pending(&self, astation_id: &str, storage_kid: &str) -> Result<SignedWire> {
        match self.call(Request::AbandonPending {
            astation_id: astation_id.into(),
            storage_kid: storage_kid.into(),
        })? {
            Reply::Abandoned { abandon } => Ok(abandon),
            _ => unexpected(),
        }
    }

    /// Returns the new storage key id and the signed confirmation to send.
    fn confirm_rotation(
        &self,
        astation_id: &str,
        ack: &SignedWire,
    ) -> Result<(String, SignedWire)> {
        match self.call(Request::ConfirmRotation {
            astation_id: astation_id.into(),
            ack: ack.clone(),
        })? {
            Reply::Confirmed {
                storage_kid,
                confirm,
            } => Ok((storage_kid, confirm)),
            _ => unexpected(),
        }
    }

    fn load_unlocked(
        &self,
        device_id: &str,
        keys: &DeviceKeys,
        storage_kid: &str,
        storage_key: &[u8; 32],
    ) -> Result<()> {
        let (device, device_sign, unlock_auth) = keys.secret_parts();
        let request = Request::LoadUnlocked {
            device_id: device_id.into(),
            device: Zeroizing::new(STANDARD.encode(&device[..])),
            device_sign: Zeroizing::new(STANDARD.encode(&device_sign[..])),
            unlock_auth: Zeroizing::new(STANDARD.encode(&unlock_auth[..])),
            storage_kid: storage_kid.into(),
            storage_key: Zeroizing::new(STANDARD.encode(storage_key)),
        };
        match self.call(request)? {
            Reply::Done => Ok(()),
            _ => unexpected(),
        }
    }

    /// Installs a granted `K` in the agent; returns its kid.
    fn install_grant(&self, astation_id: &str, grant: &GrantWire) -> Result<String> {
        match self.call(Request::InstallGrant {
            astation_id: astation_id.into(),
            grant: grant.clone(),
        })? {
            Reply::GrantInstalled { kid } => Ok(kid),
            _ => unexpected(),
        }
    }

    /// Checks a grant against pins not saved yet (verification); its kid.
    fn check_grant(&self, grant: &GrantWire, trust: &AstationTrust) -> Result<String> {
        match self.call(Request::CheckGrant {
            grant: grant.clone(),
            trust: trust.clone(),
        })? {
            Reply::GrantChecked { kid } => Ok(kid),
            _ => unexpected(),
        }
    }

    /// Runs field operations with `astation_id`'s `K`, results in order.
    fn crypt(&self, astation_id: &str, ops: Vec<CryptOp>) -> Result<Vec<CryptOut>> {
        let count = ops.len();
        match self.call(Request::Crypt {
            astation_id: astation_id.into(),
            ops,
        })? {
            Reply::Crypted { results } if results.len() == count => Ok(results),
            Reply::Crypted { .. } => {
                bail!("the key agent answered a different number of operations")
            }
            _ => unexpected(),
        }
    }

    /// The current kid held for `astation_id`'s account.
    fn held_kid(&self, astation_id: &str) -> Result<Option<String>> {
        match self.call(Request::HeldKid {
            astation_id: astation_id.into(),
        })? {
            Reply::HeldKid { kid } => Ok(kid),
            _ => unexpected(),
        }
    }

    /// Wipes the unlocked keys. (Not `lock`: `Mutex::lock` would shadow it.)
    fn lock_keys(&self) -> Result<()> {
        match self.call(Request::Lock)? {
            Reply::Done => Ok(()),
            _ => unexpected(),
        }
    }
}

fn unexpected<T>() -> Result<T> {
    bail!("the key agent sent an unexpected reply")
}

impl KeyAgentApi for std::sync::Mutex<KeyAgent> {
    fn call(&self, request: Request) -> Result<Reply> {
        self.lock()
            .map_err(|_| anyhow!("the key agent's state is poisoned"))?
            .handle(request)
    }
}

/// A shared agent (`EncryptionContext` holds an `Arc<dyn KeyAgentApi>`).
impl<T: KeyAgentApi + ?Sized> KeyAgentApi for std::sync::Arc<T> {
    fn call(&self, request: Request) -> Result<Reply> {
        (**self).call(request)
    }
}

/// This user's agent, started on first use (lazily: nothing connects until
/// a request is made).
pub fn default_agent() -> Box<dyn KeyAgentApi> {
    #[cfg(unix)]
    {
        Box::new(crate::memory::agent_socket::KeyAgentClient::autostart())
    }
    #[cfg(not(unix))]
    {
        Box::new(NoAgent)
    }
}

/// Runs agent work from async code on a blocking thread: the client's
/// socket I/O and autostart wait must not stall the runtime (or the TUI).
pub async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|error| anyhow!("the key agent call didn't finish: {error}"))?
}

/// The running agent, without starting one.
pub fn running_agent() -> Option<Box<dyn KeyAgentApi>> {
    #[cfg(unix)]
    {
        let client = crate::memory::agent_socket::KeyAgentClient::existing();
        if client.is_running() {
            return Some(Box::new(client));
        }
    }
    None
}

#[cfg(not(unix))]
struct NoAgent;

#[cfg(not(unix))]
impl KeyAgentApi for NoAgent {
    fn call(&self, _request: Request) -> Result<Reply> {
        bail!("the key agent needs a Unix system")
    }
}

/// The error text of a result that must fail (works for any `T`, Debug or not).
#[cfg(test)]
pub(crate) fn error_of<T>(result: Result<T>) -> String {
    match result {
        Ok(_) => panic!("expected an error"),
        Err(error) => format!("{error:#}"),
    }
}

/// Whether `agent` holds `K` for `astation_id`'s account: it can seal.
#[cfg(test)]
pub(crate) fn holds_k(agent: &dyn KeyAgentApi, astation_id: &str) -> bool {
    agent
        .crypt(astation_id, vec![CryptOp::seal("mem", "content", b"x")])
        .is_ok()
}

/// The one in-process agent over `paths` that tests share.
#[cfg(test)]
pub(crate) fn test_agent(paths: &KeyPaths) -> std::sync::Mutex<KeyAgent> {
    std::sync::Mutex::new(KeyAgent::new(paths.clone()).unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::fake_astation::{ACCOUNT, ASTATION_ID, DEVICE_ID, pin, sealed_device};
    use crate::memory::grant::seal_k_grant;
    use crate::memory::statements::FakeAstation;
    use std::sync::Mutex;

    fn agent(paths: &KeyPaths) -> Mutex<KeyAgent> {
        test_agent(paths)
    }

    #[test]
    fn a_starting_agent_sweeps_temps_left_by_a_crashed_writer() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, _server, _keys) = sealed_device(dir.path(), "0a1b2c3d");
        // Left by a writer that died between creating its temp and renaming it.
        let stale: Vec<_> = [
            &paths.device_keys_sealed,
            &paths.device_keys_next,
            &paths.unlock_auth_key,
            &paths.trust,
            &paths.agent_socket,
        ]
        .iter()
        .map(|path| {
            let name = path.file_name().unwrap().to_string_lossy();
            let temp = path.with_file_name(format!(".{name}.999999999.0.0badf00d.tmp"));
            std::fs::write(&temp, b"half a secret").unwrap();
            temp
        })
        .collect();
        let agent = agent(&paths);
        assert!(!agent.status().unwrap().unlocked);
        for temp in stale {
            assert!(!temp.exists(), "{} was left", temp.display());
        }
    }

    #[test]
    fn a_new_agent_is_locked() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, keys) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        let status = agent.status().unwrap();
        assert!(!status.unlocked);
        assert_eq!(status.storage_kid.as_deref(), Some("0a1b2c3d"));
        assert!(error_of(agent.public_keys()).contains("locked"));
        let grant = seal_k_grant(
            &server.astation,
            ACCOUNT,
            DEVICE_ID,
            keys.device_pub(),
            "0123abcd",
            [42; 32],
        );
        assert!(error_of(agent.install_grant(ASTATION_ID, &grant)).contains("atem cred unlock"));
    }

    #[test]
    fn loaded_keys_install_grants_until_locked() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, keys) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        agent
            .load_unlocked(
                DEVICE_ID,
                &keys,
                "0a1b2c3d",
                &server.storage_keys["0a1b2c3d"],
            )
            .unwrap();
        let status = agent.status().unwrap();
        assert!(status.unlocked && !status.escrowed);
        assert_eq!(
            agent.public_keys().unwrap(),
            (keys.device_pub(), keys.device_sign_pub())
        );
        crate::memory::fake_astation::set_state(
            &paths,
            &server.astation,
            crate::memory::crypto::EncryptionMode::On,
            Some("0123abcd"),
            2,
        );
        let grant = seal_k_grant(
            &server.astation,
            ACCOUNT,
            DEVICE_ID,
            keys.device_pub(),
            "0123abcd",
            [42; 32],
        );
        assert_eq!(
            agent.install_grant(ASTATION_ID, &grant).unwrap(),
            "0123abcd"
        );
        assert!(holds_k(&agent, ASTATION_ID));
        agent.lock_keys().unwrap();
        assert!(!agent.status().unwrap().unlocked);
        assert!(error_of(agent.install_grant(ASTATION_ID, &grant)).contains("locked"));
    }

    #[test]
    fn loading_keys_is_refused_while_the_agent_already_holds_keys() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, _, keys) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        agent
            .load_unlocked(DEVICE_ID, &keys, "1a2b3c4d", &[9; 32])
            .unwrap();
        // A second pairing run with other fresh keys must not replace them.
        let other = DeviceKeys::generate();
        let error = error_of(agent.load_unlocked(DEVICE_ID, &other, "2a3b4c5d", &[8; 32]));
        assert!(error.contains("atem cred lock"), "{error}");
        assert_eq!(
            agent.public_keys().unwrap(),
            (keys.device_pub(), keys.device_sign_pub())
        );
        assert_eq!(
            agent.status().unwrap().storage_kid.as_deref(),
            Some("1a2b3c4d")
        );
    }

    #[test]
    fn lock_is_always_allowed_even_before_the_first_escrow() {
        // A fresh device keeps its plain device_keys file until the first
        // escrow is confirmed, so locking never loses the only copy.
        let dir = tempfile::tempdir().unwrap();
        let paths = KeyPaths::in_dir(dir.path());
        let keys = DeviceKeys::generate();
        pin(&paths, &FakeAstation::new(), &keys, true);
        let storage_key = new_storage_key();
        SealedDeviceKeys::seal(&keys, DEVICE_ID, "0a1b2c3d", &storage_key)
            .unwrap()
            .save_to(&paths.device_keys_sealed)
            .unwrap();
        let agent = agent(&paths);
        agent
            .load_unlocked(DEVICE_ID, &keys, "0a1b2c3d", &storage_key)
            .unwrap();
        assert!(!agent.status().unwrap().escrowed);
        agent.lock_keys().unwrap();
        assert!(!agent.status().unwrap().unlocked);
    }

    #[test]
    fn a_grant_from_an_unverified_astation_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, keys) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        agent
            .load_unlocked(DEVICE_ID, &keys, "0a1b2c3d", &[9; 32])
            .unwrap();
        let grant = seal_k_grant(
            &server.astation,
            ACCOUNT,
            DEVICE_ID,
            keys.device_pub(),
            "0123abcd",
            [42; 32],
        );
        assert!(error_of(agent.install_grant("astation-2", &grant)).contains("isn't verified"));
    }

    #[test]
    fn a_plain_step_one_file_is_sealed_when_the_agent_starts() {
        let dir = tempfile::tempdir().unwrap();
        let paths = KeyPaths::in_dir(dir.path());
        let keys = DeviceKeys::generate();
        keys.save_to(&paths.device_keys).unwrap();
        pin(&paths, &FakeAstation::new(), &keys, false);
        let agent = agent(&paths);
        let status = agent.status().unwrap();
        assert!(
            status.unlocked && !status.escrowed,
            "migrated keys wait for their first escrow"
        );
        assert!(
            paths.device_keys.exists(),
            "the plain file stays until the first escrow is confirmed"
        );
        let sealed = SealedDeviceKeys::load_from(&paths.device_keys_sealed)
            .unwrap()
            .unwrap();
        assert_eq!(sealed.device_id, DEVICE_ID);
        assert_eq!(Some(sealed.storage_kid), status.storage_kid);
        assert_eq!(
            UnlockAuthKey::load_from(&paths.unlock_auth_key)
                .unwrap()
                .unwrap()
                .public(),
            keys.unlock_auth_pub()
        );
        assert_eq!(
            TrustStore::load_from(&paths.trust).unwrap().home(),
            Some(ASTATION_ID)
        );
        assert_eq!(
            agent.public_keys().unwrap(),
            (keys.device_pub(), keys.device_sign_pub())
        );
    }

    #[test]
    fn migration_re_seals_over_a_stale_sealed_file() {
        let dir = tempfile::tempdir().unwrap();
        let paths = KeyPaths::in_dir(dir.path());
        let keys = DeviceKeys::generate();
        keys.save_to(&paths.device_keys).unwrap();
        pin(&paths, &FakeAstation::new(), &keys, false);
        // A crashed earlier migration left a sealed file under another key.
        SealedDeviceKeys::seal(&keys, DEVICE_ID, "deadbeef", &new_storage_key())
            .unwrap()
            .save_to(&paths.device_keys_sealed)
            .unwrap();
        let agent = agent(&paths);
        let status = agent.status().unwrap();
        assert!(status.unlocked);
        assert!(paths.device_keys.exists());
        let sealed = SealedDeviceKeys::load_from(&paths.device_keys_sealed)
            .unwrap()
            .unwrap();
        assert_ne!(sealed.storage_kid, "deadbeef");
        assert_eq!(Some(sealed.storage_kid.clone()), status.storage_kid);
        // The new file opens with the key the agent holds.
        let held = match agent.lock().unwrap().unlocked.as_ref() {
            Some(unlocked) => *unlocked.storage_key,
            None => panic!("expected unlocked"),
        };
        let unlock_auth = UnlockAuthKey::load_from(&paths.unlock_auth_key)
            .unwrap()
            .unwrap();
        let opened = sealed.open(&held, unlock_auth).unwrap();
        assert_eq!(opened.device_pub(), keys.device_pub());
    }

    #[test]
    fn migration_refuses_keys_that_are_not_the_pinned_ones() {
        let dir = tempfile::tempdir().unwrap();
        let paths = KeyPaths::in_dir(dir.path());
        DeviceKeys::generate().save_to(&paths.device_keys).unwrap();
        pin(&paths, &FakeAstation::new(), &DeviceKeys::generate(), true);
        // The error doesn't stop the agent: it starts locked and says how to start over.
        let message = error_of(KeyAgent::new(paths.clone()).unwrap().migrate_plain_keys());
        assert!(message.contains("pinned"), "{message}");
        assert!(message.contains("atem pair"), "{message}");
        let agent = agent(&paths);
        assert!(!agent.status().unwrap().unlocked);
        assert!(paths.device_keys.exists() && !paths.device_keys_sealed.exists());
    }

    #[test]
    fn an_unreadable_plain_file_leaves_the_agent_locked() {
        let dir = tempfile::tempdir().unwrap();
        let paths = KeyPaths::in_dir(dir.path());
        std::fs::write(&paths.device_keys, b"not json").unwrap();
        let agent = agent(&paths);
        assert!(!agent.status().unwrap().unlocked);
        assert!(paths.device_keys.exists());
    }

    #[test]
    fn an_unverified_plain_file_is_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let paths = KeyPaths::in_dir(dir.path());
        DeviceKeys::generate().save_to(&paths.device_keys).unwrap();
        let agent = agent(&paths);
        assert!(!agent.status().unwrap().unlocked);
        assert!(paths.device_keys.exists());
    }

    #[test]
    fn a_wrong_protocol_helper_input_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, _server, keys) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        let message = error_of(agent.load_unlocked(DEVICE_ID, &keys, "NOTAKID!", &[9; 32]));
        assert!(message.contains("8 lowercase hex"), "{message}");
        assert!(!agent.status().unwrap().unlocked);
    }

    #[test]
    fn a_sealed_file_for_another_device_or_key_is_refused() {
        let keys = DeviceKeys::generate();
        let key = new_storage_key();
        let sealed = SealedDeviceKeys::seal(&keys, DEVICE_ID, "0a1b2c3d", &key).unwrap();
        let auth = || keys.unlock_auth_key();
        assert!(open_sealed_checked(&sealed, DEVICE_ID, "0a1b2c3d", &key, auth()).is_ok());
        let message = error_of(open_sealed_checked(
            &sealed,
            "dev-2",
            "0a1b2c3d",
            &key,
            auth(),
        ));
        assert!(message.contains("another device"), "{message}");
        let message = error_of(open_sealed_checked(
            &sealed,
            DEVICE_ID,
            "ffffffff",
            &key,
            auth(),
        ));
        assert!(message.contains("storage key"), "{message}");
    }

    use crate::memory::encoding::dec;
    use crate::memory::fake_astation::FakeKeyServer;
    use crate::memory::statements::{SignedWire, UnlockGrant, UnlockRequest};

    /// What the CLI does: take a challenge, sign the request.
    fn request(
        agent: &Mutex<KeyAgent>,
        paths: &KeyPaths,
        time: u64,
    ) -> (UnlockChallenge, SignedWire) {
        let challenge = agent.begin_unlock(ASTATION_ID).unwrap();
        let unlock_auth = UnlockAuthKey::load_from(&paths.unlock_auth_key)
            .unwrap()
            .unwrap();
        let request = build_unlock_request(&challenge, "boot-1", time, &unlock_auth);
        (challenge, request)
    }

    /// A whole unlock against `server`: the one helper every test shares.
    use crate::memory::fake_astation::unlock_with as unlock;

    #[test]
    fn unlock_opens_the_sealed_keys() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, keys) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        assert_eq!(unlock(&agent, &server, &paths).unwrap(), "0a1b2c3d");
        let status = agent.status().unwrap();
        assert!(status.unlocked && status.escrowed);
        assert_eq!(
            agent.public_keys().unwrap(),
            (keys.device_pub(), keys.device_sign_pub())
        );
        assert!(error_of(agent.begin_unlock(ASTATION_ID)).contains("already unlocked"));
    }

    #[test]
    fn the_challenge_names_this_device_and_a_fresh_key() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, _server, _) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        let first = agent.begin_unlock(ASTATION_ID).unwrap();
        assert_eq!(
            (
                first.account.as_str(),
                first.device_id.as_str(),
                first.storage_kid.as_str()
            ),
            (ACCOUNT, DEVICE_ID, "0a1b2c3d")
        );
        let second = agent.begin_unlock(ASTATION_ID).unwrap();
        assert_ne!(first.e_pub, second.e_pub);
        assert_ne!(first.nonce, second.nonce);
        let (_, signed) = request(&agent, &paths, 7);
        let parsed =
            UnlockRequest::parse(&dec(&STANDARD.decode(&signed.statement).unwrap()).unwrap())
                .unwrap();
        assert_eq!(
            (parsed.boot_id.as_str(), parsed.ticket.as_str(), parsed.time),
            ("boot-1", "", 7)
        );
    }

    #[test]
    fn a_relay_swapped_e_pub_is_refused_on_both_sides() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, _) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        let (challenge, honest) = request(&agent, &paths, 1);
        let relay_key = x25519_dalek::PublicKey::from(
            &x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng),
        )
        .to_bytes();
        // The relay swaps in its own e_pub: Astation's unlock-auth check fails.
        let mut swapped =
            UnlockRequest::parse(&dec(&STANDARD.decode(&honest.statement).unwrap()).unwrap())
                .unwrap();
        swapped.e_pub = relay_key;
        let forged = SignedWire {
            statement: STANDARD.encode(swapped.encode()),
            signature: honest.signature.clone(),
        };
        assert!(server.grant_unlock(&forged).is_err());
        // Even a validly signed request for another e_pub doesn't unlock this agent.
        let unlock_auth = UnlockAuthKey::load_from(&paths.unlock_auth_key)
            .unwrap()
            .unwrap();
        let other = UnlockChallenge {
            e_pub: relay_key,
            ..challenge
        };
        let relay_request = build_unlock_request(&other, "boot-1", 1, &unlock_auth);
        let grant = server.grant_unlock(&relay_request).unwrap();
        assert!(
            error_of(agent.finish_unlock(ASTATION_ID, &relay_request.statement, &grant))
                .contains("different request")
        );
        assert!(!agent.status().unwrap().unlocked);
    }

    #[test]
    fn a_replayed_grant_for_an_old_request_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, _) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        let (_, old_request) = request(&agent, &paths, 1);
        let old_grant = server.grant_unlock(&old_request).unwrap();
        agent
            .finish_unlock(ASTATION_ID, &old_request.statement, &old_grant)
            .unwrap();
        agent.lock_keys().unwrap();

        // After a lock (or reboot) the relay replays the recorded exchange.
        let (_, new_request) = request(&agent, &paths, 2);
        assert!(
            error_of(agent.finish_unlock(ASTATION_ID, &old_request.statement, &old_grant))
                .contains("different request")
        );
        // E is single use: the failed attempt consumed it.
        let new_grant = server.grant_unlock(&new_request).unwrap();
        assert!(
            error_of(agent.finish_unlock(ASTATION_ID, &new_request.statement, &new_grant))
                .contains("no unlock is in progress")
        );
        // A fresh request paired with the old grant: the request hash differs.
        let (_, fresh) = request(&agent, &paths, 3);
        assert!(
            error_of(agent.finish_unlock(ASTATION_ID, &fresh.statement, &old_grant))
                .contains("different request")
        );
        assert!(!agent.status().unwrap().unlocked);
    }

    #[test]
    fn a_grant_signed_by_anyone_else_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, _) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        let (_, request) = request(&agent, &paths, 1);
        let forged = server
            .unlock_grant(&FakeAstation::new(), &request, "0a1b2c3d")
            .unwrap();
        assert!(
            error_of(agent.finish_unlock(ASTATION_ID, &request.statement, &forged))
                .contains("signature")
        );
        assert!(!agent.status().unwrap().unlocked);
    }

    #[test]
    fn a_tampered_seal_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, _) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        let (_, request) = request(&agent, &paths, 1);
        let mut grant = server.grant_unlock(&request).unwrap();
        let mut ciphertext = STANDARD.decode(&grant.ciphertext).unwrap();
        ciphertext[0] ^= 1;
        grant.ciphertext = STANDARD.encode(ciphertext);
        assert!(
            error_of(agent.finish_unlock(ASTATION_ID, &request.statement, &grant))
                .contains("does not match what Astation signed")
        );
    }

    #[test]
    fn only_the_home_astation_unlocks() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, _server, _) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        assert!(error_of(agent.begin_unlock("astation-2")).contains("home Astation"));
    }

    #[test]
    fn a_device_without_a_verified_home_cannot_unlock() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, _server, _) = sealed_device(dir.path(), "0a1b2c3d");
        std::fs::remove_file(&paths.trust).unwrap();
        let agent = agent(&paths);
        assert!(error_of(agent.begin_unlock(ASTATION_ID)).contains("no home Astation"));
    }

    /// Re-signs the honest grant with one statement field changed.
    fn tampered_grant(
        server: &FakeKeyServer,
        request: &SignedWire,
        change: impl Fn(&mut UnlockGrant),
    ) -> crate::memory::storage_key::UnlockGrantWire {
        let honest = server.grant_unlock(request).unwrap();
        let bytes = STANDARD.decode(&honest.grant.statement).unwrap();
        let mut statement = UnlockGrant::parse(&dec(&bytes).unwrap()).unwrap();
        change(&mut statement);
        crate::memory::storage_key::UnlockGrantWire {
            grant: server.astation.sign(&statement.encode()),
            ..honest
        }
    }

    #[test]
    fn a_grant_with_any_wrong_field_leaves_the_agent_locked() {
        type Change = Box<dyn Fn(&mut UnlockGrant)>;
        let cases: Vec<(&str, Change, &str)> = vec![
            (
                "account",
                Box::new(|g| g.account = "other".into()),
                "different account",
            ),
            (
                "sign_gen",
                Box::new(|g| g.sign_gen = 9),
                "signing-key generation",
            ),
            (
                "device_id",
                Box::new(|g| g.device_id = "dev-2".into()),
                "different device",
            ),
            (
                "storage_kid",
                Box::new(|g| g.storage_kid = "ffffffff".into()),
                "different storage key",
            ),
            (
                "bad storage_kid",
                Box::new(|g| g.storage_kid = "NOPE".into()),
                "invalid storage key id",
            ),
            (
                "request_hash",
                Box::new(|g| g.request_hash = [0; 32]),
                "different request",
            ),
        ];
        for (name, change, expected) in cases {
            let dir = tempfile::tempdir().unwrap();
            let (paths, server, _) = sealed_device(dir.path(), "0a1b2c3d");
            let agent = agent(&paths);
            let (_, request) = request(&agent, &paths, 1);
            let grant = tampered_grant(&server, &request, change);
            let message = error_of(agent.finish_unlock(ASTATION_ID, &request.statement, &grant));
            assert!(message.contains(expected), "{name}: {message}");
            assert!(!agent.status().unwrap().unlocked, "{name}");
            // E was consumed.
            assert!(
                error_of(agent.finish_unlock(ASTATION_ID, &request.statement, &grant))
                    .contains("no unlock is in progress"),
                "{name}"
            );
        }
    }

    #[test]
    fn a_sealed_file_for_another_device_is_refused_after_the_release() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, keys) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        let (_, request) = request(&agent, &paths, 1);
        let grant = server.grant_unlock(&request).unwrap();
        // The file is swapped for one naming another device, under the same key.
        let storage_key = server.storage_keys["0a1b2c3d"];
        SealedDeviceKeys::seal(&keys, "dev-2", "0a1b2c3d", &Zeroizing::new(storage_key))
            .unwrap()
            .save_to(&paths.device_keys_sealed)
            .unwrap();
        let message = error_of(agent.finish_unlock(ASTATION_ID, &request.statement, &grant));
        assert!(message.contains("another device"), "{message}");
        assert!(!agent.status().unwrap().unlocked);
    }

    use crate::memory::statements::{StorageAck, StorageRotate, verify_device};

    #[test]
    fn the_first_escrow_sends_the_current_storage_key() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, mut server, keys) = sealed_device(dir.path(), "0a1b2c3d");
        // As after a first verification: the agent has the key, Astation doesn't.
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

        let rotation = agent.begin_rotation(ASTATION_ID).unwrap();
        let statement = StorageRotate::parse(
            &verify_device(&keys.device_sign_pub(), &rotation.rotate).unwrap(),
        )
        .unwrap();
        assert_eq!(
            (
                statement.old_storage_kid.as_str(),
                statement.new_storage_kid.as_str()
            ),
            ("", "0a1b2c3d")
        );
        assert!(
            !paths.device_keys_next.exists(),
            "the first escrow re-seals nothing"
        );
        let ack = server.accept_rotation(&rotation).unwrap();
        assert_eq!(server.pending, Some(("0a1b2c3d".to_string(), storage_key)));
        let (kid, confirm) = agent.confirm_rotation(ASTATION_ID, &ack).unwrap();
        assert_eq!(kid, "0a1b2c3d");
        server.confirm(&confirm).unwrap();
        assert!(agent.status().unwrap().escrowed);

        agent.lock_keys().unwrap();
        assert_eq!(unlock(&agent, &server, &paths).unwrap(), "0a1b2c3d");
    }

    #[test]
    fn rotation_after_unlock_replaces_the_storage_key() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, mut server, _) = sealed_device(dir.path(), "0a1b2c3d");
        let old_key = server.storage_keys["0a1b2c3d"];
        let agent = agent(&paths);
        unlock(&agent, &server, &paths).unwrap();

        let rotation = agent.begin_rotation(ASTATION_ID).unwrap();
        let next = SealedDeviceKeys::load_from(&paths.device_keys_next)
            .unwrap()
            .expect("phase 1 writes .next");
        assert_ne!(next.storage_kid, "0a1b2c3d");
        assert_eq!(
            SealedDeviceKeys::load_from(&paths.device_keys_sealed)
                .unwrap()
                .unwrap()
                .storage_kid,
            "0a1b2c3d",
            "the current file stays until Astation acks"
        );
        let ack = server.accept_rotation(&rotation).unwrap();
        let (kid, confirm) = agent.confirm_rotation(ASTATION_ID, &ack).unwrap();
        assert_eq!(kid, next.storage_kid);
        assert!(!paths.device_keys_next.exists());
        let current = SealedDeviceKeys::load_from(&paths.device_keys_sealed)
            .unwrap()
            .unwrap();
        assert_eq!(current.storage_kid, kid);
        server.confirm(&confirm).unwrap();
        assert_eq!(server.storage_keys.keys().collect::<Vec<_>>(), vec![&kid]);
        assert_eq!(
            TrustStore::load_from(&paths.trust).unwrap().escrowed_kid(),
            Some(kid.as_str()),
            "every confirmed rotation updates the recorded kid"
        );

        // A stolen copy of the old storage key no longer opens the file.
        let unlock_auth = UnlockAuthKey::load_from(&paths.unlock_auth_key)
            .unwrap()
            .unwrap();
        assert!(current.open(&Zeroizing::new(old_key), unlock_auth).is_err());
        agent.lock_keys().unwrap();
        assert_eq!(unlock(&agent, &server, &paths).unwrap(), kid);
    }

    #[test]
    fn the_pending_rotation_is_returned_unchanged_for_a_resend() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, mut server, _) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        assert_eq!(agent.pending_rotation().unwrap(), None);
        unlock(&agent, &server, &paths).unwrap();
        assert_eq!(agent.pending_rotation().unwrap(), None);
        let rotation = agent.begin_rotation(ASTATION_ID).unwrap();
        // The same payload every time: Astation accepts an identical resend.
        assert_eq!(agent.pending_rotation().unwrap(), Some(rotation.clone()));
        assert_eq!(agent.pending_rotation().unwrap(), Some(rotation.clone()));
        server.accept_rotation(&rotation).unwrap();
        let resent = agent.pending_rotation().unwrap().unwrap();
        let ack = server.accept_rotation(&resent).unwrap();
        agent.confirm_rotation(ASTATION_ID, &ack).unwrap();
        assert_eq!(agent.pending_rotation().unwrap(), None);
    }

    #[test]
    fn a_crash_between_ack_and_confirm_unlocks_only_the_key_the_request_names() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, mut server, keys) = sealed_device(dir.path(), "0a1b2c3d");
        {
            let agent = agent(&paths);
            unlock(&agent, &server, &paths).unwrap();
            let rotation = agent.begin_rotation(ASTATION_ID).unwrap();
            server.accept_rotation(&rotation).unwrap();
            // The process dies here: no phase 3.
        }
        let new_kid = server.pending.as_ref().unwrap().0.clone();
        let agent = agent(&paths);
        assert!(!agent.status().unwrap().unlocked);
        // The request names the current file's key: a grant releasing the
        // pending key instead is refused, even though .next carries it.
        let (_, request) = request(&agent, &paths, 5);
        let grant = server
            .unlock_grant(&server.astation, &request, &new_kid)
            .unwrap();
        let error = error_of(agent.finish_unlock(ASTATION_ID, &request.statement, &grant));
        assert!(error.contains("different storage key"), "{error}");
        assert!(!agent.status().unwrap().unlocked);
        assert!(paths.device_keys_next.exists(), "nothing promoted");
        // Astation releases the key the request names: the current file opens.
        assert_eq!(unlock(&agent, &server, &paths).unwrap(), "0a1b2c3d");
        assert_eq!(
            agent.public_keys().unwrap(),
            (keys.device_pub(), keys.device_sign_pub())
        );
        assert_eq!(
            SealedDeviceKeys::load_from(&paths.device_keys_sealed)
                .unwrap()
                .unwrap()
                .storage_kid,
            "0a1b2c3d"
        );
    }

    #[test]
    fn a_forged_or_mismatched_ack_promotes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, _) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        unlock(&agent, &server, &paths).unwrap();
        agent.begin_rotation(ASTATION_ID).unwrap();
        let new_kid = SealedDeviceKeys::load_from(&paths.device_keys_next)
            .unwrap()
            .unwrap()
            .storage_kid;
        let ack = |kid: &str| StorageAck {
            account: ACCOUNT.into(),
            sign_gen: 1,
            device_id: DEVICE_ID.into(),
            storage_kid: kid.into(),
        };
        let forged = FakeAstation::new().sign(&ack(&new_kid).encode());
        assert!(error_of(agent.confirm_rotation(ASTATION_ID, &forged)).contains("signature"));

        let wrong = server.astation.sign(&ack("ffffffff").encode());
        assert!(
            error_of(agent.confirm_rotation(ASTATION_ID, &wrong)).contains("different storage key")
        );
        assert_eq!(
            SealedDeviceKeys::load_from(&paths.device_keys_sealed)
                .unwrap()
                .unwrap()
                .storage_kid,
            "0a1b2c3d"
        );
        assert!(paths.device_keys_next.exists());
        assert_eq!(
            agent.status().unwrap().storage_kid.as_deref(),
            Some("0a1b2c3d")
        );
    }

    #[test]
    fn rotation_needs_unlocked_keys_and_the_home_astation() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, _) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        assert!(error_of(agent.begin_rotation(ASTATION_ID)).contains("locked"));
        unlock(&agent, &server, &paths).unwrap();
        assert!(error_of(agent.begin_rotation("astation-2")).contains("home Astation"));
    }

    use crate::memory::fake_astation::migrated_device;

    #[test]
    fn the_plain_file_goes_only_after_astation_confirms_the_first_escrow() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, mut server, _, agent) = migrated_device(dir.path());
        let kid = agent.status().unwrap().storage_kid.unwrap();
        let rotation = agent.begin_rotation(ASTATION_ID).unwrap();
        assert!(
            paths.device_keys.exists(),
            "kept while the rotation is open"
        );
        let ack = server.accept_rotation(&rotation).unwrap();
        assert!(paths.device_keys.exists(), "kept until the ack is verified");
        assert_eq!(
            TrustStore::load_from(&paths.trust).unwrap().escrowed_kid(),
            None
        );
        let (confirmed, confirm) = agent.confirm_rotation(ASTATION_ID, &ack).unwrap();
        assert_eq!(confirmed, kid);
        server.confirm(&confirm).unwrap();
        assert_eq!(
            TrustStore::load_from(&paths.trust).unwrap().escrowed_kid(),
            Some(kid.as_str())
        );
        assert!(!paths.device_keys.exists());
        assert!(paths.device_keys_sealed.exists());
    }

    #[test]
    fn a_crash_after_the_escrow_is_recorded_keeps_the_sealed_file() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, mut server, keys, first) = migrated_device(dir.path());
        let kid = first.status().unwrap().storage_kid.unwrap();
        let sealed_before = std::fs::read(&paths.device_keys_sealed).unwrap();
        let rotation = first.begin_rotation(ASTATION_ID).unwrap();
        let ack = server.accept_rotation(&rotation).unwrap();
        first.confirm_rotation(ASTATION_ID, &ack).unwrap();
        // The crash: the kid is recorded, but the plain file is still there.
        keys.save_to(&paths.device_keys).unwrap();
        drop(first);

        let restarted = agent(&paths);
        assert!(!paths.device_keys.exists(), "the plain file is deleted");
        assert_eq!(
            std::fs::read(&paths.device_keys_sealed).unwrap(),
            sealed_before,
            "the sealed file is never re-sealed under a fresh key"
        );
        let status = restarted.status().unwrap();
        assert!(!status.unlocked, "it waits for a Touch ID unlock");
        assert_eq!(status.storage_kid.as_deref(), Some(kid.as_str()));
        assert_eq!(unlock(&restarted, &server, &paths).unwrap(), kid);
    }

    #[test]
    fn a_plain_file_with_a_different_sealed_kid_is_still_re_sealed() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, _, _, first) = migrated_device(dir.path());
        drop(first);
        let mut trust = TrustStore::load_from(&paths.trust).unwrap();
        trust.set_escrowed_kid("deadbeef");
        trust.save_to(&paths.trust).unwrap();
        let before = SealedDeviceKeys::load_from(&paths.device_keys_sealed)
            .unwrap()
            .unwrap()
            .storage_kid;
        let again = agent(&paths);
        assert!(again.status().unwrap().unlocked);
        assert!(paths.device_keys.exists());
        let after = SealedDeviceKeys::load_from(&paths.device_keys_sealed)
            .unwrap()
            .unwrap()
            .storage_kid;
        assert_ne!(
            after, before,
            "the sealed file was rewritten under a fresh key"
        );
        assert_eq!(
            again.status().unwrap().storage_kid.as_deref(),
            Some(after.as_str())
        );
    }

    #[test]
    fn a_second_begin_unlock_invalidates_the_first_request() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, _) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        let (_, first) = request(&agent, &paths, 1);
        let (_, _second) = request(&agent, &paths, 2);
        let grant = server.grant_unlock(&first).unwrap();
        let message = error_of(agent.finish_unlock(ASTATION_ID, &first.statement, &grant));
        assert!(message.contains("different request"), "{message}");
        assert!(!agent.status().unwrap().unlocked);
        // E was consumed by the failed attempt.
        assert!(
            error_of(agent.finish_unlock(ASTATION_ID, &first.statement, &grant))
                .contains("no unlock is in progress")
        );
    }

    #[test]
    fn loading_keys_cancels_a_pending_unlock() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, keys) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        let (_, signed) = request(&agent, &paths, 1);
        let grant = server.grant_unlock(&signed).unwrap();
        agent
            .load_unlocked(DEVICE_ID, &keys, "0a1b2c3d", &[9; 32])
            .unwrap();
        assert!(
            error_of(agent.finish_unlock(ASTATION_ID, &signed.statement, &grant))
                .contains("no unlock is in progress")
        );
    }

    #[test]
    fn finishing_an_unlock_refuses_when_already_unlocked() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, keys) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        let (_, signed) = request(&agent, &paths, 1);
        let grant = server.grant_unlock(&signed).unwrap();
        // Unlocked by some other path while the request was out.
        agent.lock().unwrap().unlocked = Some(Unlocked {
            keys,
            accounts: AccountKeys::default(),
            device_id: DEVICE_ID.into(),
            storage_kid: "0a1b2c3d".into(),
            storage_key: Zeroizing::new([9; 32]),
            escrowed: false,
            via_prev: false,
            unsaved: false,
        });
        let message = error_of(agent.finish_unlock(ASTATION_ID, &signed.statement, &grant));
        assert!(message.contains("already unlocked"), "{message}");
        assert!(
            agent.lock().unwrap().pending_unlock.is_none(),
            "E is consumed"
        );
        assert!(
            !agent.status().unwrap().escrowed,
            "the held keys are untouched"
        );
    }

    #[test]
    fn a_request_naming_another_storage_key_than_the_challenge_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, mut server, _) = sealed_device(dir.path(), "0a1b2c3d");
        server.storage_keys.insert("ffffffff".into(), [1; 32]);
        let agent = agent(&paths);
        let mut challenge = agent.begin_unlock(ASTATION_ID).unwrap();
        challenge.storage_kid = "ffffffff".into();
        let unlock_auth = UnlockAuthKey::load_from(&paths.unlock_auth_key)
            .unwrap()
            .unwrap();
        let signed = build_unlock_request(&challenge, "boot-1", 1, &unlock_auth);
        let grant = server.grant_unlock(&signed).unwrap();
        let message = error_of(agent.finish_unlock(ASTATION_ID, &signed.statement, &grant));
        assert!(message.contains("different storage key"), "{message}");
        assert!(!agent.status().unwrap().unlocked);
    }

    #[test]
    fn a_replayed_old_rotate_between_ack_and_confirm_cannot_strand_the_keys() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, mut server, keys) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        unlock(&agent, &server, &paths).unwrap();
        let rotation = agent.begin_rotation(ASTATION_ID).unwrap();
        let ack = server.accept_rotation(&rotation).unwrap();
        // A relay replays an older device-signed rotate from the same key.
        let old =
            crate::memory::fake_astation::captured_rotation(&server, &keys, "0a1b2c3d", "4e5f6a7b");
        assert!(
            server.accept_rotation(&old).is_err(),
            "a pending key is a commitment"
        );
        let (kid, confirm) = agent.confirm_rotation(ASTATION_ID, &ack).unwrap();
        server.confirm(&confirm).unwrap();
        drop(agent);
        let restarted = self::agent(&paths);
        assert_eq!(unlock(&restarted, &server, &paths).unwrap(), kid);
        assert_eq!(
            restarted.public_keys().unwrap(),
            (keys.device_pub(), keys.device_sign_pub())
        );
    }

    #[test]
    fn a_second_rotation_is_refused_while_one_is_pending() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, _) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        unlock(&agent, &server, &paths).unwrap();
        agent.begin_rotation(ASTATION_ID).unwrap();
        let next = std::fs::read(&paths.device_keys_next).unwrap();
        let message = error_of(agent.begin_rotation(ASTATION_ID));
        assert!(
            message.contains("in progress") && message.contains("atem cred unlock"),
            "{message}"
        );
        assert!(
            !message.contains("lock the agent"),
            "locking strands nothing it needs: {message}"
        );
        assert_eq!(std::fs::read(&paths.device_keys_next).unwrap(), next);
    }

    #[test]
    fn a_lost_confirm_is_settled_by_the_next_unlock() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, mut server, _) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        unlock(&agent, &server, &paths).unwrap();
        let rotation = agent.begin_rotation(ASTATION_ID).unwrap();
        let ack = server.accept_rotation(&rotation).unwrap();
        let (kid, _lost_confirm) = agent.confirm_rotation(ASTATION_ID, &ack).unwrap();
        drop(agent);

        let restarted = self::agent(&paths);
        let (_, request) = request(&restarted, &paths, 9);
        let grant = server.grant_unlock_confirming(&request).unwrap();
        assert_eq!(
            restarted
                .finish_unlock(ASTATION_ID, &request.statement, &grant)
                .unwrap(),
            kid
        );
        assert!(server.pending.is_none());
        assert_eq!(server.storage_keys.keys().collect::<Vec<_>>(), vec![&kid]);
        // A later rotation goes through.
        let rotation = restarted.begin_rotation(ASTATION_ID).unwrap();
        let ack = server.accept_rotation(&rotation).unwrap();
        let (newer, confirm) = restarted.confirm_rotation(ASTATION_ID, &ack).unwrap();
        server.confirm(&confirm).unwrap();
        assert_ne!(newer, kid);
    }

    #[test]
    fn a_forged_ack_does_not_consume_the_pending_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, mut server, _) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        unlock(&agent, &server, &paths).unwrap();
        let rotation = agent.begin_rotation(ASTATION_ID).unwrap();
        let kid = SealedDeviceKeys::load_from(&paths.device_keys_next)
            .unwrap()
            .unwrap()
            .storage_kid;
        let forged = FakeAstation::new().sign(
            &StorageAck {
                account: ACCOUNT.into(),
                sign_gen: 1,
                device_id: DEVICE_ID.into(),
                storage_kid: kid.clone(),
            }
            .encode(),
        );
        assert!(error_of(agent.confirm_rotation(ASTATION_ID, &forged)).contains("signature"));
        // The real ack still completes it.
        let ack = server.accept_rotation(&rotation).unwrap();
        assert_eq!(agent.confirm_rotation(ASTATION_ID, &ack).unwrap().0, kid);
    }

    #[test]
    fn the_next_file_must_match_the_pending_rotation_before_it_is_promoted() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, mut server, keys) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        unlock(&agent, &server, &paths).unwrap();
        let rotation = agent.begin_rotation(ASTATION_ID).unwrap();
        let ack = server.accept_rotation(&rotation).unwrap();
        SealedDeviceKeys::seal(&keys, DEVICE_ID, "ffffffff", &new_storage_key())
            .unwrap()
            .save_to(&paths.device_keys_next)
            .unwrap();
        assert!(error_of(agent.confirm_rotation(ASTATION_ID, &ack)).contains(".next"));
        assert_eq!(
            SealedDeviceKeys::load_from(&paths.device_keys_sealed)
                .unwrap()
                .unwrap()
                .storage_kid,
            "0a1b2c3d"
        );
        assert!(!paths.device_keys_prev.exists());
    }

    #[test]
    fn the_previous_file_goes_only_after_an_unlock_confirms_the_new_key() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, mut server, _) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        unlock(&agent, &server, &paths).unwrap();
        let rotation = agent.begin_rotation(ASTATION_ID).unwrap();
        let ack = server.accept_rotation(&rotation).unwrap();
        let (kid, _lost) = agent.confirm_rotation(ASTATION_ID, &ack).unwrap();
        assert_eq!(
            SealedDeviceKeys::load_from(&paths.device_keys_prev)
                .unwrap()
                .expect("promotion keeps the replaced file")
                .storage_kid,
            "0a1b2c3d"
        );
        drop(agent);

        // A release of the old key for a request naming the new one proves
        // nothing and opens nothing: the .prev stays.
        let restarted = self::agent(&paths);
        let (_, request) = request(&restarted, &paths, 1);
        let grant = server
            .unlock_grant(&server.astation, &request, "0a1b2c3d")
            .unwrap();
        let error = error_of(restarted.finish_unlock(ASTATION_ID, &request.statement, &grant));
        assert!(error.contains("different storage key"), "{error}");
        assert!(paths.device_keys_prev.exists());

        // An unlock that releases the current kid proves Astation holds it.
        let (_, request) = self::request(&restarted, &paths, 2);
        let grant = server.grant_unlock_confirming(&request).unwrap();
        assert_eq!(
            restarted
                .finish_unlock(ASTATION_ID, &request.statement, &grant)
                .unwrap(),
            kid
        );
        assert!(!paths.device_keys_prev.exists());
    }

    /// A device whose rotation C was acked by Astation and then lost: the
    /// agent restarted and unlocked on the still-current file A.
    fn device_with_a_stale_rotation(
        dir: &std::path::Path,
    ) -> (KeyPaths, FakeKeyServer, DeviceKeys, Mutex<KeyAgent>, String) {
        let (paths, mut server, keys) = sealed_device(dir, "0a1b2c3d");
        let stale = {
            let agent = agent(&paths);
            unlock(&agent, &server, &paths).unwrap();
            let rotation = agent.begin_rotation(ASTATION_ID).unwrap();
            server.accept_rotation(&rotation).unwrap();
            // The process dies here: Astation holds C pending, the agent never promoted.
            server.pending.as_ref().unwrap().0.clone()
        };
        let restarted = agent(&paths);
        unlock(&restarted, &server, &paths).unwrap();
        (paths, server, keys, restarted, stale)
    }

    #[test]
    fn an_abandon_clears_a_stale_pending_key_so_a_new_rotation_proceeds() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, mut server, _, agent, stale) = device_with_a_stale_rotation(dir.path());
        let message = error_of(agent.begin_rotation(ASTATION_ID));
        assert!(
            message.contains("abandon")
                && message.contains(&stale)
                && message.contains("atem cred unlock"),
            "{message}"
        );
        assert!(
            paths.device_keys_next.exists(),
            "begin_rotation deletes nothing"
        );

        let abandon = agent.abandon_pending(ASTATION_ID, &stale).unwrap();
        assert!(
            !paths.device_keys_next.exists(),
            "the stale .next is deleted first"
        );
        server.accept_abandon(&abandon).unwrap();
        assert!(server.pending.is_none());

        let rotation = agent.begin_rotation(ASTATION_ID).unwrap();
        let ack = server.accept_rotation(&rotation).unwrap();
        let (kid, confirm) = agent.confirm_rotation(ASTATION_ID, &ack).unwrap();
        assert_ne!(kid, stale);
        server.confirm(&confirm).unwrap();
        // A replayed abandon is a no-op, even against a later pending key.
        let again = agent.begin_rotation(ASTATION_ID).unwrap();
        server.accept_rotation(&again).unwrap();
        let pending = server.pending.clone();
        server.accept_abandon(&abandon).unwrap();
        assert_eq!(server.pending, pending);
        // The abandoned kid can never come back.
        assert!(server.acked.contains(&stale));
    }

    #[test]
    fn every_abandoned_kid_is_recorded_so_it_is_never_picked_again() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, _server, _, agent, stale) = device_with_a_stale_rotation(dir.path());
        agent.abandon_pending(ASTATION_ID, &stale).unwrap();
        agent.abandon_pending(ASTATION_ID, "ffffffff").unwrap();
        let trust = TrustStore::load_from(&paths.trust).unwrap();
        assert!(trust.was_abandoned(&stale));
        assert!(trust.was_abandoned("ffffffff"));
        // A refused abandon records nothing.
        let _ = agent.abandon_pending(ASTATION_ID, "0a1b2c3d");
        assert!(
            !TrustStore::load_from(&paths.trust)
                .unwrap()
                .was_abandoned("0a1b2c3d")
        );
    }

    #[test]
    fn the_agent_refuses_to_abandon_a_kid_it_still_has_a_file_for() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, mut server, _) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        unlock(&agent, &server, &paths).unwrap();
        // The current file.
        assert!(error_of(agent.abandon_pending(ASTATION_ID, "0a1b2c3d")).contains("sealed file"));
        // A rotation in memory.
        let rotation = agent.begin_rotation(ASTATION_ID).unwrap();
        let next = SealedDeviceKeys::load_from(&paths.device_keys_next)
            .unwrap()
            .unwrap()
            .storage_kid;
        assert!(error_of(agent.abandon_pending(ASTATION_ID, &next)).contains("in progress"));
        // The .prev a promotion kept.
        let ack = server.accept_rotation(&rotation).unwrap();
        agent.confirm_rotation(ASTATION_ID, &ack).unwrap();
        assert!(paths.device_keys_prev.exists());
        assert!(error_of(agent.abandon_pending(ASTATION_ID, "0a1b2c3d")).contains("sealed file"));
        assert!(error_of(agent.abandon_pending(ASTATION_ID, &next)).contains("sealed file"));
        assert!(error_of(agent.abandon_pending(ASTATION_ID, "NOPE")).contains("lowercase hex"));
        assert!(
            error_of(agent.abandon_pending("astation-2", "ffffffff")).contains("home Astation")
        );
    }

    #[test]
    fn an_unlock_on_the_current_file_settles_the_first_escrow() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, mut server, _, agent) = migrated_device(dir.path());
        let kid = agent.status().unwrap().storage_kid.unwrap();
        let rotation = agent.begin_rotation(ASTATION_ID).unwrap();
        server.accept_rotation(&rotation).unwrap();
        // The agent never sees the ack (a lost reply); Astation holds the key pending.
        agent.lock_keys().unwrap();
        assert!(paths.device_keys.exists());
        let (_, request) = request(&agent, &paths, 3);
        let grant = server.grant_unlock_confirming(&request).unwrap();
        assert_eq!(
            agent
                .finish_unlock(ASTATION_ID, &request.statement, &grant)
                .unwrap(),
            kid
        );
        assert_eq!(
            TrustStore::load_from(&paths.trust).unwrap().escrowed_kid(),
            Some(kid.as_str())
        );
        assert!(
            !paths.device_keys.exists(),
            "the unlock proves Astation holds the key"
        );
    }

    #[test]
    fn a_first_escrow_lost_before_the_trust_save_is_abandoned_and_redone() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, mut server, _, first) = migrated_device(dir.path());
        let k0 = first.status().unwrap().storage_kid.unwrap();
        let rotation = first.begin_rotation(ASTATION_ID).unwrap();
        server.accept_rotation(&rotation).unwrap();
        drop(first); // crash before the ack was handled: nothing recorded

        let restarted = agent(&paths);
        let k1 = restarted.status().unwrap().storage_kid.unwrap();
        assert_ne!(k0, k1, "the re-seal used a fresh key");
        let rotation = restarted.begin_rotation(ASTATION_ID).unwrap();
        assert!(
            server.accept_rotation(&rotation).is_err(),
            "k0 is still pending"
        );
        // No file carries k0 any more, so the agent can give it up (the
        // in-memory rotation is for k1).
        let abandon = restarted.abandon_pending(ASTATION_ID, &k0).unwrap();
        server.accept_abandon(&abandon).unwrap();
        let ack = server.accept_rotation(&rotation).unwrap();
        let (kid, confirm) = restarted.confirm_rotation(ASTATION_ID, &ack).unwrap();
        assert_eq!(kid, k1);
        server.confirm(&confirm).unwrap();
        assert!(!paths.device_keys.exists());
    }

    #[test]
    fn an_unlock_of_a_lone_previous_file_makes_it_current() {
        // Only .prev is left (e.g. the current file was lost): the request
        // names its kid, and once Astation releases that key the file is
        // current again, so the next start and rotation use it.
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, keys) = sealed_device(dir.path(), "0a1b2c3d");
        std::fs::rename(&paths.device_keys_sealed, &paths.device_keys_prev).unwrap();
        let agent = agent(&paths);
        assert_eq!(unlock(&agent, &server, &paths).unwrap(), "0a1b2c3d");
        assert_eq!(
            agent.public_keys().unwrap(),
            (keys.device_pub(), keys.device_sign_pub())
        );
        assert!(!paths.device_keys_prev.exists());
        assert_eq!(
            SealedDeviceKeys::load_from(&paths.device_keys_sealed)
                .unwrap()
                .expect("the previous file is current again")
                .storage_kid,
            "0a1b2c3d"
        );
        assert!(agent.begin_rotation(ASTATION_ID).is_ok());
    }

    #[test]
    fn an_unlock_that_opened_the_previous_file_blocks_rotation_until_the_current_opens() {
        // A current file that appears during an unlock naming .prev is kept,
        // and the keys unlocked from .prev may not rotate.
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, keys) = sealed_device(dir.path(), "0a1b2c3d");
        std::fs::rename(&paths.device_keys_sealed, &paths.device_keys_prev).unwrap();
        let agent = agent(&paths);
        let (_, request) = request(&agent, &paths, 1);
        SealedDeviceKeys::seal(&keys, DEVICE_ID, "4e5f6a7b", &new_storage_key())
            .unwrap()
            .save_to(&paths.device_keys_sealed)
            .unwrap();
        let grant = server.grant_unlock(&request).unwrap();
        agent
            .finish_unlock(ASTATION_ID, &request.statement, &grant)
            .unwrap();
        assert!(error_of(agent.begin_rotation(ASTATION_ID)).contains("previous"));
        assert_eq!(
            SealedDeviceKeys::load_from(&paths.device_keys_sealed)
                .unwrap()
                .unwrap()
                .storage_kid,
            "4e5f6a7b"
        );
    }

    #[test]
    fn a_missing_current_file_or_a_damaged_spare_does_not_stop_unlock_or_status() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, _) = sealed_device(dir.path(), "0a1b2c3d");
        std::fs::write(&paths.device_keys_next, b"not json").unwrap();
        std::fs::write(&paths.device_keys_prev, b"not json").unwrap();
        let agent = agent(&paths);
        assert!(
            agent.begin_unlock(ASTATION_ID).is_ok(),
            "stops at the readable current file"
        );
        assert_eq!(unlock(&agent, &server, &paths).unwrap(), "0a1b2c3d");

        // Between a promotion's two renames the current file is missing.
        let dir = tempfile::tempdir().unwrap();
        let (paths, _server, keys) = sealed_device(dir.path(), "0a1b2c3d");
        std::fs::remove_file(&paths.device_keys_sealed).unwrap();
        SealedDeviceKeys::seal(&keys, DEVICE_ID, "4e5f6a7b", &new_storage_key())
            .unwrap()
            .save_to(&paths.device_keys_next)
            .unwrap();
        let agent = self::agent(&paths);
        assert_eq!(
            agent.status().unwrap().storage_kid.as_deref(),
            Some("4e5f6a7b")
        );
    }

    #[test]
    fn an_unreadable_current_file_fails_the_unlock_instead_of_naming_a_spare() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, _server, keys) = sealed_device(dir.path(), "0a1b2c3d");
        SealedDeviceKeys::seal(&keys, DEVICE_ID, "4e5f6a7b", &new_storage_key())
            .unwrap()
            .save_to(&paths.device_keys_next)
            .unwrap();
        std::fs::write(&paths.device_keys_sealed, b"not json").unwrap();
        let agent = agent(&paths);
        let message = error_of(agent.begin_unlock(ASTATION_ID));
        assert!(message.contains("unreadable"), "{message}");
        assert!(agent.lock().unwrap().pending_unlock.is_none());
    }
}
