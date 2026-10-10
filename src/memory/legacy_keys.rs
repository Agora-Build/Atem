//! `data_keys.enc`, where build steps 0–2a kept `K`, its previous keys and
//! the project names, encrypted with the machine-bound key (which a copied
//! disk includes). Build step 2b only reads it: the key agent moves it into
//! `device_keys.sealed` and `project_names.json` and deletes it
//! (key_agent.rs), and a first verification still purges what the
//! unauthenticated #36 path stored in it.
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use zeroize::Zeroizing;

use crate::memory::crypto::EncryptionMode;

#[derive(Serialize, Deserialize)]
struct StoredMode {
    data_account: String,
    mode: EncryptionMode,
    kid: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct StoredKey {
    kid: String,
    key: Zeroizing<String>,
}

#[derive(Default, Serialize, Deserialize)]
pub struct LegacyKeys {
    #[serde(default = "version_one")]
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

fn version_one() -> u8 {
    1
}

pub enum Legacy {
    Missing,
    /// It can never be read on this machine (another machine id, damage).
    Unreadable(anyhow::Error),
    Keys(LegacyKeys),
}

/// Reads `data_keys.enc`. Only an I/O error other than "not found" is an
/// error: a file that can't be decrypted or parsed is `Unreadable`.
pub fn read(path: &Path) -> Result<Legacy> {
    let raw = match std::fs::read(path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Legacy::Missing),
        Err(error) => return Err(error.into()),
    };
    let parsed = crate::credentials::decrypt_machine_bound(&raw)
        .context("data_keys.enc cannot be decrypted on this machine")
        .and_then(|plain| {
            let plain = Zeroizing::new(plain);
            serde_json::from_slice::<LegacyKeys>(&plain).context("data_keys.enc is unreadable")
        })
        .and_then(|keys| {
            if keys.version != 1 {
                anyhow::bail!("unsupported data_keys.enc version {}", keys.version);
            }
            Ok(keys)
        });
    Ok(match parsed {
        Ok(keys) => Legacy::Keys(keys),
        Err(error) => Legacy::Unreadable(error),
    })
}

impl LegacyKeys {
    fn save_to(&self, path: &Path) -> Result<()> {
        let plain = Zeroizing::new(serde_json::to_vec(self)?);
        let encrypted = crate::credentials::encrypt_machine_bound(&plain)?;
        crate::memory::crypto::write_private(path, &encrypted)
    }
}

/// Removes what the unauthenticated #36 path may have stored for this
/// Astation: its mode entry, and the keys, rotation history and project
/// names of `data_account` and of the account that entry named. Called on a
/// device's first verification with this Astation. A missing file stays
/// missing; an unreadable one is moved aside (`move_aside`), never deleted.
pub fn purge_unverified_at(path: &Path, astation_id: &str, data_account: &str) -> Result<()> {
    let mut store = match read(path)? {
        Legacy::Missing => return Ok(()),
        Legacy::Unreadable(error) => return move_aside(path, &error),
        Legacy::Keys(store) => store,
    };
    let mut accounts = vec![data_account.to_string()];
    if let Some(legacy) = store.astations.remove(astation_id)
        && legacy.data_account != data_account
    {
        accounts.push(legacy.data_account);
    }
    for account in &accounts {
        store.accounts.remove(account);
        store.previous_keys.remove(account);
        store.project_names.remove(account);
    }
    store.save_to(path)
}

/// Renames an unreadable `data_keys.enc` to `data_keys.enc.corrupt-<stamp>`:
/// it may still hold keys another machine id could read, so it is kept.
pub fn move_aside(path: &Path, why: &anyhow::Error) -> Result<()> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut aside = path.as_os_str().to_owned();
    aside.push(format!(".corrupt-{stamp}"));
    std::fs::rename(path, &aside).with_context(|| {
        format!(
            "{} is unreadable ({why:#}) and could not be moved to {}",
            path.display(),
            Path::new(&aside).display()
        )
    })
}

/// Test stand-in for a step-2a store: `keys` oldest first (the last is
/// current), with a mode entry for `astation_id`.
#[cfg(test)]
pub(crate) fn write_for_test(
    path: &Path,
    astation_id: &str,
    account: &str,
    keys: &[(&str, [u8; 32])],
    names: &[(&str, &str)],
) {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let stored = |(kid, key): &(&str, [u8; 32])| StoredKey {
        kid: kid.to_string(),
        key: Zeroizing::new(STANDARD.encode(key)),
    };
    let (last, earlier) = keys.split_last().expect("at least one key");
    let mut store = LegacyKeys {
        version: 1,
        ..LegacyKeys::default()
    };
    store.astations.insert(
        astation_id.into(),
        StoredMode {
            data_account: account.into(),
            mode: EncryptionMode::Enabling,
            kid: Some(last.0.into()),
        },
    );
    store.accounts.insert(account.into(), stored(last));
    store
        .previous_keys
        .insert(account.into(), earlier.iter().map(stored).collect());
    store.project_names.insert(
        account.into(),
        names
            .iter()
            .map(|(hash, name)| (hash.to_string(), name.to_string()))
            .collect(),
    );
    store.save_to(path).unwrap();
}

/// Test view: (current kid, previous kids, number of project names).
#[cfg(test)]
pub(crate) fn summary_at(path: &Path, account: &str) -> (Option<String>, Vec<String>, usize) {
    let Legacy::Keys(store) = read(path).unwrap() else {
        return (None, Vec::new(), 0);
    };
    (
        store.accounts.get(account).map(|key| key.kid.clone()),
        store
            .previous_keys
            .get(account)
            .map(|keys| keys.iter().map(|key| key.kid.clone()).collect())
            .unwrap_or_default(),
        store.project_names.get(account).map_or(0, HashMap::len),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_written_store_reads_back_and_a_missing_one_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data_keys.enc");
        assert!(matches!(read(&path).unwrap(), Legacy::Missing));
        write_for_test(
            &path,
            "astation",
            "acct",
            &[("0123abcd", [1; 32]), ("11112222", [2; 32])],
            &[("h1.x.aa", "github.com/agora/atem")],
        );
        assert_eq!(
            summary_at(&path, "acct"),
            (Some("11112222".into()), vec!["0123abcd".into()], 1)
        );
        std::fs::write(&path, b"not machine-bound").unwrap();
        assert!(matches!(read(&path).unwrap(), Legacy::Unreadable(_)));
    }

    #[test]
    fn purge_removes_only_this_astations_legacy_state() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data_keys.enc");
        write_for_test(
            &path,
            "astation",
            "legacy",
            &[("0123abcd", [1; 32]), ("11112222", [2; 32])],
            &[("h1.x.aa", "p")],
        );
        purge_unverified_at(&path, "astation", "certified").unwrap();
        assert_eq!(
            summary_at(&path, "legacy"),
            (None, vec![], 0),
            "the account the mode entry named goes too"
        );
        // A missing store stays missing.
        let absent = dir.path().join("absent.enc");
        purge_unverified_at(&absent, "astation", "certified").unwrap();
        assert!(!absent.exists());
    }
    #[test]
    fn purge_moves_an_unreadable_store_aside() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data_keys.enc");
        std::fs::write(&path, b"not machine-bound").unwrap();
        purge_unverified_at(&path, "astation", "certified").unwrap();
        assert!(!path.exists());
        let aside: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|entry| {
                entry
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("data_keys.enc.corrupt-")
            })
            .collect();
        assert_eq!(aside.len(), 1, "kept, never deleted");
        assert_eq!(std::fs::read(&aside[0]).unwrap(), b"not machine-bound");
    }
}
