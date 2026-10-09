//! End-to-end encryption for relay-backed memory, skills, and vaults.
//! Local knowledge.db remains plaintext; transforms happen only at HTTP edges.

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, Payload},
    ChaCha20Poly1305, XChaCha20Poly1305,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::memory::model::{content_hash, skill_hash, Memory, Skill};

const WRAP_DOMAIN: &str = "astation-data-key-wrap-v1";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EncryptionMode {
    #[default]
    Off,
    Enabling,
    On,
    Disabling,
}

impl EncryptionMode {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "off" => Ok(Self::Off),
            "enabling" => Ok(Self::Enabling),
            "on" => Ok(Self::On),
            "disabling" => Ok(Self::Disabling),
            _ => bail!("unknown encryption mode {value:?}"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Enabling => "enabling",
            Self::On => "on",
            Self::Disabling => "disabling",
        }
    }

    pub fn requires_key(self) -> bool {
        self != Self::Off
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredMode {
    data_account: String,
    mode: EncryptionMode,
    kid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredKey {
    kid: String,
    key: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct StoredKeys {
    #[serde(default = "store_version")]
    version: u8,
    #[serde(default)]
    astations: HashMap<String, StoredMode>,
    #[serde(default)]
    accounts: HashMap<String, StoredKey>,
    #[serde(default)]
    previous_keys: HashMap<String, Vec<StoredKey>>,
    #[serde(default)]
    project_names: HashMap<String, HashMap<String, String>>,
}

fn store_version() -> u8 { 1 }

impl StoredKeys {
    fn load_from(path: &Path) -> Result<Self> {
        let raw = match fs::read(path) {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self { version: 1, ..Self::default() });
            }
            Err(error) => return Err(error.into()),
        };
        let plain = crate::credentials::decrypt_machine_bound(&raw)
            .context("data_keys.enc cannot be decrypted on this machine")?;
        let store: Self = serde_json::from_slice(&plain).context("data_keys.enc is unreadable")?;
        if store.version != 1 {
            bail!("unsupported data_keys.enc version {}", store.version);
        }
        Ok(store)
    }

    fn save_to(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() { fs::create_dir_all(parent)?; }
        let encrypted = crate::credentials::encrypt_machine_bound(&serde_json::to_vec(self)?)?;
        let temp = path.with_extension("enc.tmp");
        fs::write(&temp, encrypted)?;
        set_mode_600(&temp)?;
        fs::rename(temp, path)?;
        set_mode_600(path)
    }

    fn load_or_recover_from(path: &Path) -> Result<Self> {
        match Self::load_from(path) {
            Ok(store) => Ok(store),
            Err(load_error) if path.exists() => {
                let stamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos();
                let name = path.file_name().and_then(|name| name.to_str()).unwrap_or("data_keys.enc");
                let backup = path.with_file_name(format!("{name}.corrupt-{stamp}"));
                fs::rename(path, &backup).with_context(|| {
                    format!(
                        "data_keys.enc is unreadable ({load_error}) and could not be preserved as {}",
                        backup.display()
                    )
                })?;
                Ok(Self { version: 1, ..Self::default() })
            }
            Err(error) => Err(error),
        }
    }
}

fn key_store_path() -> PathBuf {
    crate::config::AtemConfig::config_dir().join("data_keys.enc")
}

fn device_key_path() -> PathBuf {
    crate::config::AtemConfig::config_dir().join("device_key")
}

#[cfg(unix)]
fn set_mode_600(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_mode_600(_path: &Path) -> Result<()> { Ok(()) }

/// Writes `bytes` to `path` as a 0600 file: temp file, fsync, rename.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    if let Some(parent) = path.parent() { fs::create_dir_all(parent)?; }
    let temp = path.with_extension("tmp");
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&temp, path)?;
    set_mode_600(path)
}

pub struct DeviceKey {
    secret: StaticSecret,
}

impl DeviceKey {
    pub fn load_or_create() -> Result<Self> {
        Self::load_or_create_at(&device_key_path())
    }

    fn load_or_create_at(path: &Path) -> Result<Self> {
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if let Some(parent) = path.parent() { fs::create_dir_all(parent)?; }
                let secret = StaticSecret::random_from_rng(OsRng);
                let bytes = secret.to_bytes();
                use std::io::Write;
                let mut options = fs::OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600);
                }
                match options.open(path) {
                    Ok(mut file) => {
                        file.write_all(&bytes)?;
                        file.sync_all()?;
                        bytes.to_vec()
                    }
                    Err(race) if race.kind() == std::io::ErrorKind::AlreadyExists => fs::read(path)?,
                    Err(error) => return Err(error.into()),
                }
            }
            Err(error) => return Err(error.into()),
        };
        if bytes.len() != 32 { bail!("device_key is unreadable; expected 32 bytes"); }
        set_mode_600(path)?;
        let mut raw = [0u8; 32];
        raw.copy_from_slice(&bytes);
        Ok(Self { secret: StaticSecret::from(raw) })
    }

    pub fn public_key_base64(&self) -> String {
        STANDARD.encode(PublicKey::from(&self.secret).as_bytes())
    }

    pub fn fingerprint(&self) -> String {
        let digest = Sha256::digest(PublicKey::from(&self.secret).as_bytes());
        let hex = digest[..8].iter().map(|byte| format!("{byte:02X}")).collect::<String>();
        (0..hex.len())
            .step_by(4)
            .map(|offset| &hex[offset..offset + 4])
            .collect::<Vec<_>>()
            .join("-")
    }

    pub fn open_grant(&self, data_account: &str, kid: &str, wrapped: &str) -> Result<[u8; 32]> {
        if !valid_kid(kid) { bail!("invalid encryption kid"); }
        let raw = STANDARD.decode(wrapped).context("invalid wrapped key encoding")?;
        if raw.len() < 32 + 12 + 16 { bail!("wrapped key is too short"); }
        let mut ephemeral = [0u8; 32];
        ephemeral.copy_from_slice(&raw[..32]);
        let shared = self.secret.diffie_hellman(&PublicKey::from(ephemeral));
        let aad = wrap_aad(data_account, kid);
        let hkdf = Hkdf::<Sha256>::new(None, shared.as_bytes());
        let mut wrapping_key = [0u8; 32];
        hkdf.expand(&aad, &mut wrapping_key).map_err(|_| anyhow!("key grant HKDF failed"))?;
        let plain = ChaCha20Poly1305::new((&wrapping_key).into())
            .decrypt((&raw[32..44]).into(), Payload { msg: &raw[44..], aad: &aad })
            .map_err(|_| anyhow!("key grant authentication failed"))?;
        if plain.len() != 32 { bail!("wrapped account key has the wrong length"); }
        let mut key = [0u8; 32];
        key.copy_from_slice(&plain);
        Ok(key)
    }
}

fn wrap_aad(data_account: &str, kid: &str) -> Vec<u8> {
    format!("{WRAP_DOMAIN}\n{data_account}\n{kid}").into_bytes()
}

pub(crate) fn valid_kid(kid: &str) -> bool {
    kid.len() == 8 && kid.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Debug, Clone)]
pub struct EncryptionContext {
    pub mode: EncryptionMode,
    pub data_account: String,
    pub kid: Option<String>,
    key: Option<[u8; 32]>,
    previous_keys: HashMap<String, [u8; 32]>,
    store_path: PathBuf,
}

impl EncryptionContext {
    pub fn for_astation(astation_id: &str) -> Result<Self> {
        Self::for_astation_at(astation_id, &key_store_path())
    }

    pub(crate) fn for_astation_at(astation_id: &str, path: &Path) -> Result<Self> {
        let store = StoredKeys::load_from(path)?;
        let Some(mode) = store.astations.get(astation_id) else {
            return Ok(Self {
                mode: EncryptionMode::Off,
                data_account: astation_id.into(),
                kid: None,
                key: None,
                previous_keys: HashMap::new(),
                store_path: path.to_path_buf(),
            });
        };
        let key = (mode.mode != EncryptionMode::Off).then(|| store.accounts.get(&mode.data_account)).flatten().map(|stored| {
            let bytes = STANDARD.decode(&stored.key).context("invalid stored account key")?;
            if bytes.len() != 32 { bail!("stored account key has the wrong length"); }
            if mode.kid.as_deref() != Some(&stored.kid) { bail!("stored account key id does not match relay mode"); }
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            Ok(key)
        }).transpose()?;
        if mode.mode.requires_key() && key.is_none() {
            bail!("this account requires encryption; connect to Astation to receive the encryption key");
        }
        let previous_keys = (mode.mode != EncryptionMode::Off)
            .then(|| store.previous_keys.get(&mode.data_account))
            .flatten()
            .into_iter()
            .flatten()
            .map(|stored| {
                let bytes = STANDARD.decode(&stored.key).context("invalid previous account key")?;
                if bytes.len() != 32 { bail!("previous account key has the wrong length"); }
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                Ok((stored.kid.clone(), key))
            })
            .collect::<Result<HashMap<_, _>>>()?;
        Ok(Self {
            mode: mode.mode,
            data_account: mode.data_account.clone(),
            kid: mode.kid.clone(),
            key,
            previous_keys,
            store_path: path.to_path_buf(),
        })
    }

    pub fn update_mode(astation_id: &str, data_account: &str, mode: EncryptionMode, kid: Option<&str>) -> Result<()> {
        let path = key_store_path();
        Self::update_mode_at(&path, astation_id, data_account, mode, kid)
    }

    pub(crate) fn update_mode_at(path: &Path, astation_id: &str, data_account: &str, mode: EncryptionMode, kid: Option<&str>) -> Result<()> {
        let mut store = StoredKeys::load_or_recover_from(path)?;
        if mode == EncryptionMode::Off {
            store.accounts.remove(data_account);
            store.previous_keys.remove(data_account);
            store.project_names.remove(data_account);
        } else if mode == EncryptionMode::On
            && store.accounts.get(data_account).is_some_and(|stored| Some(stored.kid.as_str()) == kid)
        {
            // Once the relay reports `on`, every stored field has the current
            // kid and rotation history is no longer needed for decryption.
            store.previous_keys.remove(data_account);
        }
        store.astations.insert(astation_id.into(), StoredMode {
            data_account: data_account.into(), mode, kid: kid.map(str::to_string),
        });
        store.save_to(path)
    }

    pub fn install_grant(astation_id: &str, data_account: &str, kid: &str, key: [u8; 32]) -> Result<()> {
        let path = key_store_path();
        Self::install_grant_at(&path, astation_id, data_account, kid, key)
    }

    pub(crate) fn install_grant_at(path: &Path, astation_id: &str, data_account: &str, kid: &str, key: [u8; 32]) -> Result<()> {
        let mut store = StoredKeys::load_from(&path)?;
        let mode = store.astations.get(astation_id)
            .ok_or_else(|| anyhow!("received an encryption key before the account mode"))?;
        if mode.data_account != data_account || mode.kid.as_deref() != Some(kid) {
            bail!("encryption key grant does not match the announced account mode");
        }
        let replacement = StoredKey { kid: kid.into(), key: STANDARD.encode(key) };
        if let Some(previous) = store.accounts.insert(data_account.into(), replacement)
            && previous.kid != kid {
            let history = store.previous_keys.entry(data_account.into()).or_default();
            history.retain(|item| item.kid != previous.kid);
            history.push(previous);
        }
        if mode.mode == EncryptionMode::On {
            store.previous_keys.remove(data_account);
        }
        store.save_to(path)
    }

    fn key(&self) -> Result<&[u8; 32]> {
        self.key.as_ref().ok_or_else(|| anyhow!(
            "this account requires encryption; connect to Astation to receive the encryption key"
        ))
    }

    pub fn should_encrypt(&self) -> bool {
        matches!(self.mode, EncryptionMode::Enabling | EncryptionMode::On)
    }

    pub fn wire_project(&self, project: &str) -> Result<String> {
        if project.is_empty() || !self.should_encrypt() { return Ok(project.to_string()); }
        remember_project(self, project)?;
        self.keyed_hash(project.as_bytes())
    }

    pub fn seal(&self, record: &str, field: &str, plain: &[u8]) -> Result<String> {
        if plain.is_empty() { return Ok(String::new()); }
        let kid = self.kid.as_deref().ok_or_else(|| anyhow!("encryption key id is missing"))?;
        let cipher = XChaCha20Poly1305::new(self.key()?.into());
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let aad = field_aad(record, field);
        let ciphertext = cipher.encrypt(&nonce, Payload { msg: plain, aad: &aad })
            .map_err(|_| anyhow!("field encryption failed"))?;
        let mut payload = nonce.to_vec();
        payload.extend_from_slice(&ciphertext);
        Ok(format!("e1.{kid}.{}", STANDARD.encode(payload)))
    }

    pub fn open(&self, record: &str, field: &str, value: &str) -> Result<Vec<u8>> {
        if value.is_empty() { return Ok(Vec::new()); }
        let rest = value.strip_prefix("e1.").ok_or_else(|| anyhow!("encrypted field is malformed"))?;
        let (kid, encoded) = rest.split_once('.').ok_or_else(|| anyhow!("encrypted field is malformed"))?;
        let key = if self.kid.as_deref() == Some(kid) {
            self.key()?
        } else {
            self.previous_keys.get(kid)
                .ok_or_else(|| anyhow!("encrypted field uses an unavailable key id"))?
        };
        let payload = STANDARD.decode(encoded).context("invalid encrypted field")?;
        if payload.len() < 40 { bail!("encrypted field is too short"); }
        let cipher = XChaCha20Poly1305::new(key.into());
        cipher.decrypt((&payload[..24]).into(), Payload { msg: &payload[24..], aad: &field_aad(record, field) })
            .map_err(|_| anyhow!("encrypted field authentication failed"))
    }

    pub fn keyed_hash(&self, value: &[u8]) -> Result<String> {
        let kid = self.kid.as_deref().ok_or_else(|| anyhow!("encryption key id is missing"))?;
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(self.key()?).expect("HMAC accepts 32 bytes");
        mac.update(value);
        let digest = mac.finalize().into_bytes().iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        Ok(format!("h1.{kid}.{digest}"))
    }

    pub fn encrypt_memory(&self, mut memory: Memory) -> Result<Memory> {
        if !self.should_encrypt() { return Ok(memory); }
        remember_project(self, &memory.project)?;
        memory.project = if memory.project.is_empty() { String::new() } else { self.keyed_hash(memory.project.as_bytes())? };
        memory.content_hash = if memory.content.is_empty() { String::new() } else { self.keyed_hash(memory.content.as_bytes())? };
        memory.content = self.seal(&memory.id, "content", memory.content.as_bytes())?;
        Ok(memory)
    }

    pub fn decrypt_memory(&self, mut memory: Memory) -> Result<Memory> {
        if self.mode == EncryptionMode::Off {
            return Ok(memory);
        }
        if memory.project.starts_with("h1.") {
            memory.project = resolve_project(self, &memory.project)?;
        }
        if memory.content.starts_with("e1.") {
            memory.content = String::from_utf8(self.open(&memory.id, "content", &memory.content)?)
                .context("memory content is not UTF-8")?;
        }
        if memory.content_hash.starts_with("h1.") {
            memory.content_hash = content_hash(&memory.content);
        }
        Ok(memory)
    }

    pub fn encrypt_skill(&self, mut skill: Skill) -> Result<Skill> {
        if !self.should_encrypt() { return Ok(skill); }
        remember_project(self, &skill.project)?;
        let record = skill_record(&skill);
        let mut encrypted = std::collections::BTreeMap::new();
        for (path, bytes) in &skill.files {
            let encrypted_path = self.seal(&record, "path", path.as_bytes())?;
            let encrypted_bytes = self.seal(&record, &format!("file:{encrypted_path}"), bytes)?;
            encrypted.insert(encrypted_path, encrypted_bytes.into_bytes());
        }
        skill.project = if skill.project.is_empty() { String::new() } else { self.keyed_hash(skill.project.as_bytes())? };
        skill.content_hash = self.keyed_hash(skill_hash(&skill.files).as_bytes())?;
        skill.files = encrypted;
        Ok(skill)
    }

    pub fn decrypt_skill(&self, mut skill: Skill) -> Result<Skill> {
        if self.mode == EncryptionMode::Off {
            return Ok(skill);
        }
        if skill.project.starts_with("h1.") {
            skill.project = resolve_project(self, &skill.project)?;
        }
        if skill.files.keys().any(|path| path.starts_with("e1.")) {
            let record = skill_record(&skill);
            let mut files = std::collections::BTreeMap::new();
            for (encrypted_path, encrypted_bytes) in &skill.files {
                let path = String::from_utf8(self.open(&record, "path", encrypted_path)?)
                    .context("skill path is not UTF-8")?;
                let envelope = std::str::from_utf8(encrypted_bytes).context("skill ciphertext is not UTF-8")?;
                let bytes = self.open(&record, &format!("file:{encrypted_path}"), envelope)?;
                files.insert(path, bytes);
            }
            skill.files = files;
        }
        if skill.content_hash.starts_with("h1.") {
            skill.content_hash = skill_hash(&skill.files);
        }
        Ok(skill)
    }
}

fn field_aad(record: &str, field: &str) -> Vec<u8> {
    format!("{record}\n{field}").into_bytes()
}

fn skill_record(skill: &Skill) -> String {
    format!("{}:{}:{}", skill.scope.as_str(), skill.name, skill.version)
}

fn remember_project(context: &EncryptionContext, project: &str) -> Result<()> {
    if project.is_empty() { return Ok(()); }
    let hash = context.keyed_hash(project.as_bytes())?;
    let mut store = StoredKeys::load_from(&context.store_path)?;
    store.project_names.entry(context.data_account.clone()).or_default().insert(hash, project.into());
    store.save_to(&context.store_path)
}

fn resolve_project(context: &EncryptionContext, project_hash: &str) -> Result<String> {
    if project_hash.is_empty() { return Ok(String::new()); }
    StoredKeys::load_from(&context.store_path)?
        .project_names
        .get(&context.data_account)
        .and_then(|projects| projects.get(project_hash))
        .cloned()
        .ok_or_else(|| anyhow!("encrypted project name is unknown on this Atem; sync from a device that used it first"))
}

pub async fn migrate_account(astation_id: &str) -> Result<Option<&'static str>> {
    let encryption = EncryptionContext::for_astation(astation_id)?;
    let target = match encryption.mode {
        EncryptionMode::Enabling => "on",
        EncryptionMode::Disabling => "off",
        _ => return Ok(None),
    };
    let paired = crate::auth::require_pairing("Encryption migration")?;
    if paired.astation_id != astation_id {
        bail!("the active pairing does not match the encryption account");
    }
    let client_id = crate::config::AtemConfig::ensure_instance_id();
    let knowledge = crate::memory::api::KnowledgeClient::new(
        paired.relay_base.clone(),
        client_id.clone(),
        paired.session_id.clone(),
        paired.astation_id.clone(),
    );
    let vault = crate::vault_client::VaultClient::new(
        paired.relay_base,
        client_id,
        paired.session_id,
        paired.astation_id,
    );
    knowledge.migrate_encryption().await
        .map_err(|error| anyhow!(error.to_string()))?;
    vault.migrate_encryption().await?;
    Ok(Some(target))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn context() -> EncryptionContext {
        EncryptionContext {
            mode: EncryptionMode::On,
            data_account: "account".into(),
            kid: Some("0123abcd".into()),
            key: Some([7; 32]),
            previous_keys: HashMap::new(),
            store_path: key_store_path(),
        }
    }

    #[test]
    fn device_key_is_stable_and_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("device_key");
        let first = DeviceKey::load_or_create_at(&path).unwrap();
        let second = DeviceKey::load_or_create_at(&path).unwrap();
        assert_eq!(first.public_key_base64(), second.public_key_base64());
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(path).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn envelope_round_trip_and_tamper_failure() {
        let context = context();
        let sealed = context.seal("mem-1", "content", b"hello").unwrap();
        assert_eq!(context.open("mem-1", "content", &sealed).unwrap(), b"hello");
        assert!(context.open("mem-2", "content", &sealed).is_err());
        let mut bad = sealed.into_bytes();
        *bad.last_mut().unwrap() = if *bad.last().unwrap() == b'A' { b'B' } else { b'A' };
        assert!(context.open("mem-1", "content", std::str::from_utf8(&bad).unwrap()).is_err());
    }

    #[test]
    fn fingerprint_is_stable() {
        let secret = StaticSecret::from([3u8; 32]);
        let key = DeviceKey { secret };
        assert_eq!(key.fingerprint(), key.fingerprint());
        assert_eq!(key.fingerprint().len(), 19);
    }

    #[test]
    fn wrapped_key_round_trip_matches_wire_format() {
        let device = DeviceKey { secret: StaticSecret::from([3u8; 32]) };
        let ephemeral = StaticSecret::from([4u8; 32]);
        let shared = ephemeral.diffie_hellman(&PublicKey::from(&device.secret));
        let aad = wrap_aad("account", "0123abcd");
        let hkdf = Hkdf::<Sha256>::new(None, shared.as_bytes());
        let mut wrapping_key = [0u8; 32];
        hkdf.expand(&aad, &mut wrapping_key).unwrap();
        let nonce = [9u8; 12];
        let account_key = [7u8; 32];
        let ciphertext = ChaCha20Poly1305::new((&wrapping_key).into())
            .encrypt((&nonce).into(), Payload { msg: &account_key, aad: &aad })
            .unwrap();
        let mut wrapped = PublicKey::from(&ephemeral).as_bytes().to_vec();
        wrapped.extend_from_slice(&nonce);
        wrapped.extend_from_slice(&ciphertext);
        assert_eq!(
            device
                .open_grant("account", "0123abcd", &STANDARD.encode(wrapped))
                .unwrap(),
            account_key
        );
    }

    #[test]
    fn memory_and_binary_skill_round_trip() {
        let context = context();
        let memory = Memory {
            id: "mem-1".into(),
            scope: crate::memory::model::Scope::Global,
            content: "use port 27183".into(),
            content_hash: content_hash("use port 27183"),
            confidence: "high".into(),
            source_agent: "test".into(),
            source_machine: "mac".into(),
            created_at: 1,
            ..Memory::default()
        };
        let encrypted = context.encrypt_memory(memory.clone()).unwrap();
        assert!(encrypted.content.starts_with("e1.0123abcd."));
        assert_eq!(context.decrypt_memory(encrypted).unwrap(), memory);

        let files = BTreeMap::from([
            ("SKILL.md".to_string(), b"hello".to_vec()),
            ("asset.bin".to_string(), vec![0, 159, 146, 150]),
        ]);
        let skill = Skill {
            scope: crate::memory::model::Scope::Global,
            project: String::new(),
            name: "sample".into(),
            version: 1,
            content_hash: skill_hash(&files),
            files,
            source_agent: "test".into(),
            source_machine: "mac".into(),
            created_at: 1,
            deleted: false,
            seq: 1,
        };
        let encrypted = context.encrypt_skill(skill.clone()).unwrap();
        assert!(encrypted.files.keys().all(|path| path.starts_with("e1.0123abcd.")));
        assert_eq!(context.decrypt_skill(encrypted).unwrap(), skill);
    }

    #[test]
    fn rotation_keeps_old_key_until_migration_and_off_removes_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data_keys.enc");
        EncryptionContext::update_mode_at(
            &path,
            "astation",
            "account",
            EncryptionMode::Enabling,
            Some("0123abcd"),
        )
        .unwrap();
        EncryptionContext::install_grant_at(
            &path,
            "astation",
            "account",
            "0123abcd",
            [7; 32],
        )
        .unwrap();
        let old = EncryptionContext::for_astation_at("astation", &path)
            .unwrap()
            .seal("mem", "content", b"old")
            .unwrap();

        EncryptionContext::update_mode_at(
            &path,
            "astation",
            "account",
            EncryptionMode::Enabling,
            Some("89abcdef"),
        )
        .unwrap();
        assert!(EncryptionContext::for_astation_at("astation", &path).is_err());
        EncryptionContext::install_grant_at(
            &path,
            "astation",
            "account",
            "89abcdef",
            [8; 32],
        )
        .unwrap();
        let rotated = EncryptionContext::for_astation_at("astation", &path).unwrap();
        assert_eq!(rotated.open("mem", "content", &old).unwrap(), b"old");

        EncryptionContext::update_mode_at(
            &path,
            "astation",
            "account",
            EncryptionMode::On,
            Some("89abcdef"),
        )
        .unwrap();
        let completed = EncryptionContext::for_astation_at("astation", &path).unwrap();
        assert!(completed.previous_keys.is_empty());
        assert!(completed.open("mem", "content", &old).is_err());

        EncryptionContext::update_mode_at(
            &path,
            "astation",
            "account",
            EncryptionMode::Off,
            None,
        )
        .unwrap();
        let off = EncryptionContext::for_astation_at("astation", &path).unwrap();
        assert_eq!(off.mode, EncryptionMode::Off);
        assert!(off.key.is_none());
        assert!(off.previous_keys.is_empty());
    }

    #[test]
    fn unreadable_key_store_is_preserved_before_requesting_a_new_grant() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data_keys.enc");
        fs::write(&path, b"not a machine-bound key store").unwrap();
        EncryptionContext::update_mode_at(
            &path,
            "astation",
            "account",
            EncryptionMode::On,
            Some("0123abcd"),
        )
        .unwrap();
        assert!(EncryptionContext::for_astation_at("astation", &path).is_err());
        let backups = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with("data_keys.enc.corrupt-"))
            .count();
        assert_eq!(backups, 1);
    }
}
