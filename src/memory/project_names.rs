//! `~/.config/atem/cred/project_names.json`: the readable project key each `h1.`
//! project hash on the relay stands for, per account. The relay sees only
//! the hash (keyed by `K`, which never leaves the cred agent); atem keeps the
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
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    labels: BTreeMap<String, BTreeMap<String, String>>,
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

    /// For the writers: a file that doesn't parse holds only names (no
    /// secrets), so it is moved aside and the writer starts empty. A version
    /// other than 1 stays an error (downgrade guard).
    fn load_for_write(path: &Path) -> Result<Self> {
        match Self::load_from(path) {
            Ok(names) => Ok(names),
            Err(error) if error.to_string().contains("is unreadable") => {
                let stamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs());
                let mut aside = path.as_os_str().to_owned();
                aside.push(format!(".corrupt-{stamp}"));
                std::fs::rename(path, &aside)
                    .with_context(|| format!("moving {} aside", path.display()))?;
                eprintln!(
                    "{} was unreadable; moved it to {}",
                    path.display(),
                    Path::new(&aside).display()
                );
                Ok(Self {
                    version: 1,
                    ..Self::default()
                })
            }
            Err(error) => Err(error),
        }
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

    pub fn projects(&self, account: &str) -> Vec<String> {
        self.accounts.get(account).map(|names| names.values().cloned().collect()).unwrap_or_default()
    }

    pub fn project_labels(&self, account: &str) -> Vec<String> {
        let mut projects: BTreeMap<_, _> = self.projects(account).into_iter().map(|key| (key.clone(), key)).collect();
        if let Some(labels) = self.labels.get(account) {
            for (key, label) in labels {
                if super::credential_projects::canonical_project(label).as_ref() == Some(key) {
                    projects.insert(key.clone(), label.clone());
                }
            }
        }
        projects.into_values().collect()
    }

    #[cfg(test)]
    pub fn len(&self, account: &str) -> usize {
        self.accounts.get(account).map_or(0, BTreeMap::len)
    }
}

/// Records `hash → name` pairs for `account`: a read-modify-write under an
/// `flock` on `project_names.lock` (the helper cred/state.json uses), so the
/// cred agent and other atem commands keep each other's names. Writes only
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
    let mut names = ProjectNames::load_for_write(path)?;
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
    let _lock = crate::memory::trust::TrustStore::lock(path)?;
    match path.symlink_metadata() {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    }
    let mut names = ProjectNames::load_for_write(path)?;
    let removed = names.accounts.remove(account).is_some();
    if names.labels.remove(account).is_some() || removed {
        names.save_to(path)?;
    }
    Ok(())
}

/// Display spelling is account scoped; hash-to-key identity stays unchanged.
pub fn remember_label(path: &Path, account: &str, label: &str) -> Result<()> {
    let Some(key) = super::credential_projects::canonical_project(label) else { return Ok(()); };
    let _lock = crate::memory::trust::TrustStore::lock(path)?;
    let mut names = ProjectNames::load_for_write(path)?;
    let labels = names.labels.entry(account.to_string()).or_default();
    let label = label.trim();
    if labels.get(&key).map(String::as_str) != Some(label) {
        labels.insert(key, label.to_string());
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
        let path = crate::paths::CredPaths::in_dir(dir.path()).project_names;
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
    fn display_labels_survive_name_writes_and_remain_account_scoped() {
        let dir = tempfile::tempdir().unwrap();
        let path = crate::paths::CredPaths::in_dir(dir.path()).project_names;
        remember(&path, "acct", [pair("h1.x.aa", "github.com/org/repo")]).unwrap();
        remember_label(&path, "acct", "github.com/Org/Repo").unwrap();
        remember_label(&path, "other", "github.com/Private/Other").unwrap();
        remember(&path, "acct", [pair("h1.x.bb", "github.com/org/second")]).unwrap();
        let names = ProjectNames::load_from(&path).unwrap();
        assert_eq!(names.name("acct", "h1.x.aa"), Some("github.com/org/repo"));
        assert_eq!(names.project_labels("acct"), ["github.com/Org/Repo", "github.com/org/second"]);
        assert_eq!(names.project_labels("other"), ["github.com/Private/Other"]);
        let before = std::fs::read(&path).unwrap();
        remember_label(&path, "acct", "github.com/Org/Repo").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), before);
        forget_account_at(&path, "acct").unwrap();
        let names = ProjectNames::load_from(&path).unwrap();
        assert!(names.project_labels("acct").is_empty());
        assert_eq!(names.project_labels("other"), ["github.com/Private/Other"]);
    }

    #[test]
    fn nothing_new_writes_nothing_and_nothing_is_created_by_a_forget() {
        let dir = tempfile::tempdir().unwrap();
        let path = crate::paths::CredPaths::in_dir(dir.path()).project_names;
        remember(&path, "acct", Vec::new()).unwrap();
        forget_account_at(&path, "acct").unwrap();
        assert!(!path.exists());
        remember(&path, "acct", [pair("h1.x.aa", "a")]).unwrap();
        let before = std::fs::read(&path).unwrap();
        remember(&path, "acct", [pair("h1.x.aa", "a")]).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[test]
    fn an_unreadable_file_is_an_error_naming_it_for_direct_readers() {
        let dir = tempfile::tempdir().unwrap();
        let path = crate::paths::CredPaths::in_dir(dir.path()).project_names;
        crate::paths::write_test_file(&path, b"not json");
        let error = format!("{:#}", ProjectNames::load_from(&path).err().unwrap());
        assert!(error.contains("project_names.json"), "{error}");
    }

    #[test]
    fn a_corrupt_file_is_moved_aside_by_the_writers() {
        let dir = tempfile::tempdir().unwrap();
        let path = crate::paths::CredPaths::in_dir(dir.path()).project_names;
        crate::paths::write_test_file(&path, b"not json");
        remember(&path, "acct", [pair("h1.x.aa", "a")]).unwrap();
        let names = ProjectNames::load_from(&path).unwrap();
        assert_eq!(names.len("acct"), 1);
        assert_eq!(names.name("acct", "h1.x.aa"), Some("a"));
        let prefix = format!("{}.corrupt-", path.file_name().unwrap().to_string_lossy());
        let aside: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(&prefix))
            .collect();
        assert_eq!(aside.len(), 1, "{aside:?}");
        crate::paths::write_test_file(&path, b"not json");
        forget_account_at(&path, "acct").unwrap();
        assert!(ProjectNames::load_from(&path).is_ok());
    }

    #[test]
    fn a_newer_version_stays_an_error_for_writers() {
        let dir = tempfile::tempdir().unwrap();
        let path = crate::paths::CredPaths::in_dir(dir.path()).project_names;
        crate::paths::write_test_file(&path, br#"{"version":2,"accounts":{}}"#);
        assert!(remember(&path, "acct", [pair("h1.x.aa", "a")]).is_err());
        assert!(path.exists());
    }

    #[test]
    fn concurrent_writers_keep_each_others_names() {
        let dir = tempfile::tempdir().unwrap();
        let path = crate::paths::CredPaths::in_dir(dir.path()).project_names;
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
