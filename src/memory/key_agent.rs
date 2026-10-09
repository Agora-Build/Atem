//! The key agent: this device's unlocked keys, in memory only, like
//! ssh-agent. It never talks to the network: the CLI carries its requests
//! to Astation and Astation's answers back. Keys are wiped on `Lock` and
//! when the process exits. See designs/e2e-encryption.md "Keys on disk (atem)".
use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::memory::device_keys::{DeviceKeys, UnlockAuthKey, decode32};
use crate::memory::grant::{GrantWire, OpenedGrant, open_grant as open_sealed_grant};
use crate::memory::storage_key::{SealedDeviceKeys, StorageKey, new_storage_key, new_storage_kid};
use crate::memory::trust::{AstationTrust, TrustStore};
use crate::memory::verification::KeyPaths;

/// Every request carries `"v": PROTOCOL_VERSION`; the agent answers any
/// other version with an error, so an old agent and a newer CLI fail clearly.
pub const PROTOCOL_VERSION: u64 = 1;

pub const LOCKED: &str = "this device's keys are locked; run `atem cred unlock`";

/// Appended to key-file errors, which never stop the agent (it starts locked).
pub const RESET: &str = "To start over: delete ~/.config/atem/device_keys (if present), device_keys.sealed and unlock_auth_key, then run `atem pair` to verify this device again.";

/// What the agent serves. Only the same user can reach it (agent_socket.rs).
/// Fields that carry secrets are `Zeroizing`.
#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
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
    /// Opens a key grant with the device key. `trust` is set only during
    /// verification, before the pins are saved; otherwise the agent uses the
    /// verified entry in cred_state.json.
    OpenGrant {
        astation_id: String,
        grant: GrantWire,
        #[serde(default)]
        trust: Option<AstationTrust>,
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
    /// `K` goes back to the caller until build step 2b moves data_keys.enc
    /// behind the agent.
    Grant {
        kid: String,
        key: Zeroizing<String>,
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
    #[allow(dead_code)] // used by unlock and rotation (Tasks 5-6)
    device_id: String,
    storage_kid: String,
    #[allow(dead_code)] // used by rotation (Task 6)
    storage_key: StorageKey,
    escrowed: bool,
}

pub struct KeyAgent {
    paths: KeyPaths,
    unlocked: Option<Unlocked>,
}

/// Opens a sealed device-keys file only when its header names the device and
/// the storage key the caller expects; anything else fails closed.
#[allow(dead_code)] // used by unlock and rotation (Tasks 5-6)
pub(crate) fn open_sealed_checked(
    sealed: &SealedDeviceKeys,
    device_id: &str,
    storage_kid: &str,
    storage_key: &[u8; 32],
    unlock_auth: UnlockAuthKey,
) -> Result<DeviceKeys> {
    if sealed.device_id != device_id {
        bail!("device_keys.sealed belongs to another device");
    }
    if sealed.storage_kid != storage_kid {
        bail!(
            "device_keys.sealed is under storage key {}, not {storage_kid}",
            sealed.storage_kid
        );
    }
    sealed.open(storage_key, unlock_auth)
}

impl KeyAgent {
    /// An agent for the key files in `paths`: locked, unless a plain step-1
    /// `device_keys` file is migrated (then unlocked, not yet escrowed).
    /// A migration or key-file error never stops the agent: it starts locked
    /// and logs the error and how to start over.
    pub fn new(paths: KeyPaths) -> Result<Self> {
        let mut agent = Self {
            paths,
            unlocked: None,
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
            Request::OpenGrant {
                astation_id,
                grant,
                trust,
            } => self.open_grant(&astation_id, &grant, trust),
            Request::Lock => {
                self.wipe();
                Ok(Reply::Done)
            }
        }
    }

    /// Drops every secret; their types zeroize on drop.
    fn wipe(&mut self) {
        self.unlocked = None;
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
                storage_kid: SealedDeviceKeys::load_from(&self.paths.device_keys_sealed)
                    .ok()
                    .flatten()
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
        if !crate::memory::crypto::valid_kid(&storage_kid) {
            bail!("storage key id must be 8 lowercase hex characters");
        }
        let keys = DeviceKeys::from_secrets(
            *decode32(device, "device key")?,
            *decode32(device_sign, "device signing key")?,
            *decode32(unlock_auth, "unlock-auth key")?,
        );
        let storage_key = decode32(storage_key, "storage key")?;
        self.unlocked = Some(Unlocked {
            keys,
            device_id,
            storage_kid,
            storage_key,
            escrowed: false,
        });
        Ok(Reply::Done)
    }

    fn open_grant(
        &self,
        astation_id: &str,
        grant: &GrantWire,
        trust: Option<AstationTrust>,
    ) -> Result<Reply> {
        let unlocked = self.unlocked()?;
        let entry = match trust {
            Some(entry) => entry,
            None => TrustStore::load_from(&self.paths.trust)?
                .verified(astation_id)
                .cloned()
                .ok_or_else(|| anyhow!("this device isn't verified with Astation {astation_id}"))?,
        };
        let opened = open_sealed_grant(&entry, &unlocked.keys, grant)?;
        let key = Zeroizing::new(STANDARD.encode(&opened.key[..]));
        Ok(Reply::Grant {
            kid: opened.kid,
            key,
        })
    }

    /// A plain step-1 `device_keys` is authoritative whenever it exists (it stays until the first escrow is confirmed): seal
    /// it under a new storage key (overwriting any earlier sealed file, e.g.
    /// from a crashed migration), split out the unlock-auth key, record the
    /// home Astation. The keys stay unlocked here until
    /// the CLI sends the storage key to the home Astation (`atem cred unlock`).
    fn migrate_plain_keys(&mut self) -> Result<()> {
        self.migrate_inner()
            .map_err(|error| anyhow!("{error:#}. {RESET}"))
    }

    fn migrate_inner(&mut self) -> Result<()> {
        let Some(keys) = DeviceKeys::load_from(&self.paths.device_keys)? else {
            return Ok(());
        };
        let mut trust = TrustStore::load_from(&self.paths.trust)?;
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
        let storage_kid = new_storage_kid();
        SealedDeviceKeys::seal(&keys, &entry.device_id, &storage_kid, &storage_key)?
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
            device_id: entry.device_id,
            storage_kid,
            storage_key,
            escrowed: false,
        });
        Ok(())
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

    fn open_grant(
        &self,
        astation_id: &str,
        grant: &GrantWire,
        trust: Option<&AstationTrust>,
    ) -> Result<OpenedGrant> {
        let request = Request::OpenGrant {
            astation_id: astation_id.into(),
            grant: grant.clone(),
            trust: trust.cloned(),
        };
        match self.call(request)? {
            Reply::Grant { kid, key } => Ok(OpenedGrant {
                kid,
                key: decode32(&key, "granted key")?,
            }),
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

/// The error text of a result that must fail (works for any `T`, Debug or not).
#[cfg(test)]
pub(crate) fn error_of<T>(result: Result<T>) -> String {
    match result {
        Ok(_) => panic!("expected an error"),
        Err(error) => format!("{error:#}"),
    }
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
        assert!(error_of(agent.open_grant(ASTATION_ID, &grant, None)).contains("atem cred unlock"));
    }

    #[test]
    fn loaded_keys_open_grants_until_locked() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, server, keys) = sealed_device(dir.path(), "0a1b2c3d");
        let agent = agent(&paths);
        agent
            .load_unlocked(DEVICE_ID, &keys, "0a1b2c3d", &[9; 32])
            .unwrap();
        let status = agent.status().unwrap();
        assert!(status.unlocked && !status.escrowed);
        assert_eq!(status.storage_kid.as_deref(), Some("0a1b2c3d"));
        assert_eq!(
            agent.public_keys().unwrap(),
            (keys.device_pub(), keys.device_sign_pub())
        );
        let grant = seal_k_grant(
            &server.astation,
            ACCOUNT,
            DEVICE_ID,
            keys.device_pub(),
            "0123abcd",
            [42; 32],
        );
        let opened = agent.open_grant(ASTATION_ID, &grant, None).unwrap();
        assert_eq!((opened.kid.as_str(), *opened.key), ("0123abcd", [42; 32]));
        agent.lock_keys().unwrap();
        assert!(!agent.status().unwrap().unlocked);
        assert!(error_of(agent.open_grant(ASTATION_ID, &grant, None)).contains("locked"));
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
        assert!(error_of(agent.open_grant("astation-2", &grant, None)).contains("isn't verified"));
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
}
