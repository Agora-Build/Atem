//! `~/.config/atem/project_names.json`: the readable project key each `h1.`
//! project hash on the relay stands for, per account. The relay sees only
//! the hash (keyed by `K`, which never leaves the key agent); atem keeps the
//! names locally to show and filter by them. No secrets, still 0600 and
//! written atomically. See designs/e2e-encryption.md "What each side stores".
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ProjectNames {
    #[serde(default = "version_one")]
    version: u8,
    #[serde(default)]
    accounts: BTreeMap<String, BTreeMap<String, String>>,
}

fn version_one() -> u8 {
    1
}

impl ProjectNames {
    pub fn load_from(path: &Path) -> Result<Self> {
        let raw = match std::fs::read(path) {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self {
                    version: 1,
                    ..Self::default()
                });
            }
            Err(error) => return Err(error.into()),
        };
        let names: Self = serde_json::from_slice(&raw)
            .with_context(|| format!("{} is unreadable", path.display()))?;
        if names.version != 1 {
            bail!("unsupported project_names.json version {}", names.version);
        }
        Ok(names)
    }

    fn save_to(&mut self, path: &Path) -> Result<()> {
        self.version = 1;
        crate::memory::crypto::write_private(path, &serde_json::to_vec_pretty(self)?)
    }

    pub fn name(&self, account: &str, hash: &str) -> Option<&str> {
        self.accounts
            .get(account)
            .and_then(|names| names.get(hash))
            .map(String::as_str)
    }

    #[cfg(test)]
    pub fn len(&self, account: &str) -> usize {
        self.accounts.get(account).map_or(0, BTreeMap::len)
    }
}

/// Records `hash → name` pairs for `account`: a read-modify-write under an
/// `flock` on `project_names.lock` (the helper cred_state.json uses), so the
/// key agent and other atem commands keep each other's names. Writes only
/// when something is new.
pub fn remember(
    path: &Path,
    account: &str,
    pairs: impl IntoIterator<Item = (String, String)>,
) -> Result<()> {
    let pairs: Vec<(String, String)> = pairs.into_iter().collect();
    if pairs.is_empty() {
        return Ok(());
    }
    let _lock = crate::memory::trust::TrustStore::lock(path)?;
    let mut names = ProjectNames::load_from(path)?;
    let entry = names.accounts.entry(account.into()).or_default();
    let mut changed = false;
    for (hash, name) in pairs {
        if entry.get(&hash) != Some(&name) {
            entry.insert(hash, name);
            changed = true;
        }
    }
    if changed {
        names.save_to(path)?;
    }
    Ok(())
}

/// Forgets every name of `account` (a first verification drops what the
/// unauthenticated path may have stored). A missing file stays missing.
pub fn forget_account_at(path: &Path, account: &str) -> Result<()> {
    if path.symlink_metadata().is_err() {
        return Ok(());
    }
    let _lock = crate::memory::trust::TrustStore::lock(path)?;
    let mut names = ProjectNames::load_from(path)?;
    if names.accounts.remove(account).is_some() {
        names.save_to(path)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(hash: &str, name: &str) -> (String, String) {
        (hash.to_string(), name.to_string())
    }

    #[test]
    fn names_round_trip_per_account_in_a_private_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("project_names.json");
        assert_eq!(ProjectNames::load_from(&path).unwrap().len("acct"), 0);
        remember(
            &path,
            "acct",
            [pair("h1.0123abcd.aa", "github.com/agora/atem")],
        )
        .unwrap();
        remember(
            &path,
            "other",
            [pair("h1.0123abcd.bb", "github.com/agora/dialf")],
        )
        .unwrap();
        let names = ProjectNames::load_from(&path).unwrap();
        assert_eq!(
            names.name("acct", "h1.0123abcd.aa"),
            Some("github.com/agora/atem")
        );
        assert_eq!(
            names.name("acct", "h1.0123abcd.bb"),
            None,
            "names are per account"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        forget_account_at(&path, "acct").unwrap();
        let names = ProjectNames::load_from(&path).unwrap();
        assert_eq!(names.len("acct"), 0);
        assert_eq!(names.len("other"), 1);
    }

    #[test]
    fn nothing_new_writes_nothing_and_nothing_is_created_by_a_forget() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("project_names.json");
        remember(&path, "acct", Vec::new()).unwrap();
        forget_account_at(&path, "acct").unwrap();
        assert!(!path.exists());
        remember(&path, "acct", [pair("h1.x.aa", "a")]).unwrap();
        let before = std::fs::read(&path).unwrap();
        remember(&path, "acct", [pair("h1.x.aa", "a")]).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[test]
    fn an_unreadable_file_is_an_error_naming_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("project_names.json");
        std::fs::write(&path, b"not json").unwrap();
        let error = format!("{:#}", ProjectNames::load_from(&path).err().unwrap());
        assert!(error.contains("project_names.json"), "{error}");
    }

    #[test]
    fn concurrent_writers_keep_each_others_names() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("project_names.json");
        let writers: Vec<_> = (0..4)
            .map(|writer| {
                let path = path.clone();
                std::thread::spawn(move || {
                    for n in 0..25 {
                        remember(&path, "acct", [pair(&format!("h1.x.{writer}-{n}"), "p")])
                            .unwrap();
                    }
                })
            })
            .collect();
        for writer in writers {
            writer.join().unwrap();
        }
        assert_eq!(ProjectNames::load_from(&path).unwrap().len("acct"), 100);
    }
}
