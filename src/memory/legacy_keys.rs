//! `data_keys.enc`, where build steps 0–2a kept `K`, its previous keys and
//! the project names, encrypted with the machine-bound key (which a copied
//! disk includes). Build step 2b never writes it (except the purge below):
//! at each unlock the key agent moves the keys and names of every verified
//! account into `device_keys.sealed` and `project_names.json`, and deletes
//! the file once the home Astation holds the storage key of the sealed file
//! (key_agent.rs `migrate_data_keys`). An agent on an unverified device
//! deletes it at start. An unreadable one is moved aside (`move_aside`),
//! never deleted. A first verification purges what the unauthenticated #36
//! path stored in it, except accounts another verified Astation names.
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::path::Path;
use zeroize::Zeroizing;

use crate::memory::account_keys::AccountKey;
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
    /// Each account in `accounts` (the verified ones) with its current key
    /// and the keys it replaced. Malformed entries are skipped: they could
    /// never open anything.
    pub fn keys_for(
        &self,
        accounts: &BTreeSet<String>,
    ) -> Vec<(String, AccountKey, Vec<AccountKey>)> {
        let parse = |stored: &StoredKey| -> Option<AccountKey> {
            if !crate::memory::crypto::valid_kid(&stored.kid) {
                return None;
            }
            Some(AccountKey {
                kid: stored.kid.clone(),
                key: crate::memory::device_keys::decode32(&stored.key, "account key").ok()?,
            })
        };
        let mut keys: Vec<_> = self
            .accounts
            .iter()
            .filter(|(account, _)| accounts.contains(*account))
            .filter_map(|(account, stored)| {
                let current = parse(stored)?;
                let previous = self
                    .previous_keys
                    .get(account)
                    .into_iter()
                    .flatten()
                    .filter_map(parse)
                    .collect();
                Some((account.clone(), current, previous))
            })
            .collect();
        keys.sort_by(|a, b| a.0.cmp(&b.0));
        keys
    }

    /// The project names (`h1.` hash → name) of each account in `accounts`.
    pub fn names_for(&self, accounts: &BTreeSet<String>) -> Vec<(String, Vec<(String, String)>)> {
        let mut names: Vec<_> = self
            .project_names
            .iter()
            .filter(|(account, _)| accounts.contains(*account))
            .map(|(account, names)| {
                let mut pairs: Vec<_> = names
                    .iter()
                    .map(|(hash, name)| (hash.clone(), name.clone()))
                    .collect();
                pairs.sort();
                (account.clone(), pairs)
            })
            .collect();
        names.sort();
        names
    }

    fn save_to(&self, path: &Path) -> Result<()> {
        let plain = Zeroizing::new(serde_json::to_vec(self)?);
        let encrypted = crate::credentials::encrypt_machine_bound(&plain)?;
        crate::memory::crypto::write_private(path, &encrypted)
    }
}

/// Removes what the unauthenticated #36 path may have stored for this
/// Astation: its mode entry, and the keys, rotation history and project
/// names of `data_account` and of the account that entry named, except an
/// account in `named_elsewhere` (one another verified Astation names: its
/// keys may be that Astation's). Called on a device's first verification
/// with this Astation. A missing file stays missing; an unreadable one is
/// moved aside (`move_aside`), never deleted.
pub fn purge_unverified_at(
    path: &Path,
    astation_id: &str,
    data_account: &str,
    named_elsewhere: &BTreeSet<String>,
) -> Result<()> {
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
    for account in accounts
        .iter()
        .filter(|account| !named_elsewhere.contains(*account))
    {
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
/// current), with a mode entry for `astation_id`. Added to the store already
/// at `path`, if one can be read.
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
    let mut store = match read(path).unwrap() {
        Legacy::Keys(store) => store,
        _ => LegacyKeys {
            version: 1,
            ..LegacyKeys::default()
        },
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
        write_for_test(
            &path,
            "astation-2",
            "bystander",
            &[("44445555", [3; 32]), ("66667777", [4; 32])],
            &[("h1.y.bb", "q"), ("h1.y.cc", "r")],
        );
        let before = summary_at(&path, "bystander");
        purge_unverified_at(&path, "astation", "certified", &BTreeSet::new()).unwrap();
        assert_eq!(
            summary_at(&path, "legacy"),
            (None, vec![], 0),
            "the account the mode entry named goes too"
        );
        assert_eq!(
            summary_at(&path, "bystander"),
            before,
            "another Astation's account is untouched"
        );
        assert_eq!(
            before,
            (Some("66667777".into()), vec!["44445555".into()], 2)
        );
        let Legacy::Keys(store) = read(&path).unwrap() else {
            panic!("still readable");
        };
        assert!(!store.astations.contains_key("astation"));
        assert_eq!(store.astations["astation-2"].data_account, "bystander");
        // A missing store stays missing.
        let absent = dir.path().join("absent.enc");
        purge_unverified_at(&absent, "astation", "certified", &BTreeSet::new()).unwrap();
        assert!(!absent.exists());
    }
    #[test]
    fn purge_moves_an_unreadable_store_aside() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data_keys.enc");
        std::fs::write(&path, b"not machine-bound").unwrap();
        purge_unverified_at(&path, "astation", "certified", &BTreeSet::new()).unwrap();
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

    #[test]
    fn purge_keeps_accounts_another_verified_astation_names() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data_keys.enc");
        write_for_test(
            &path,
            "astation",
            "shared",
            &[("0123abcd", [1; 32])],
            &[("h1.x.aa", "p")],
        );
        let named = BTreeSet::from(["shared".to_string()]);
        purge_unverified_at(&path, "astation", "shared", &named).unwrap();
        assert_eq!(
            summary_at(&path, "shared"),
            (Some("0123abcd".into()), vec![], 1)
        );
    }

    #[test]
    fn keys_and_names_are_read_for_the_given_accounts_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data_keys.enc");
        write_for_test(
            &path,
            "astation",
            "acct",
            &[("0123abcd", [1; 32]), ("11112222", [2; 32])],
            &[("h1.x.aa", "p")],
        );
        write_for_test(&path, "astation-2", "other", &[("44445555", [3; 32])], &[]);
        let Legacy::Keys(store) = read(&path).unwrap() else {
            panic!("readable");
        };
        let accounts = BTreeSet::from(["acct".to_string()]);
        let keys = store.keys_for(&accounts);
        assert_eq!(keys.len(), 1);
        let (account, current, previous) = &keys[0];
        assert_eq!(
            (account.as_str(), current.kid.as_str()),
            ("acct", "11112222")
        );
        assert_eq!(*current.key, [2; 32]);
        assert_eq!(previous.len(), 1);
        assert_eq!(
            (previous[0].kid.as_str(), *previous[0].key),
            ("0123abcd", [1; 32])
        );
        assert_eq!(
            store.names_for(&accounts),
            vec![(
                "acct".to_string(),
                vec![("h1.x.aa".to_string(), "p".to_string())]
            )]
        );
    }
}
