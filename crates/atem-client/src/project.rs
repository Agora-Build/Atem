//! Service `projects` scopes (§R9.6): the launch project key and its
//! `h1.<kid>.<hash>` keyed hash, sans-I/O.
//!
//! A session's launch project key is its working directory's repository,
//! named by the normalized `origin` remote (`github.com/agora-build/atem`,
//! lowercase, credentials, port and `.git` dropped), else
//! `local:<folder name>` (the repository root's folder, or the working
//! directory's when it isn't in a repository; case kept). Atem records it
//! at launch and compares `h1.<kid>.<hex HMAC-SHA256(K, project key)>`
//! under the `K` generation each scope entry names; the cred agent makes
//! that hash on the host. These are the same functions the host uses
//! (`memory::project` calls [`remote_label`] and [`project_key_of_remote`]),
//! so a manager computes exactly the value the host compares.
//!
//! `K` stays where the app keeps it: [`project_hash_from_mac`] formats an
//! HMAC the platform computed over [`project_hash_input`] under the key
//! `kid` names; [`project_hash`] is the software form over a
//! [`BackupKey`] (the K-backup flows' key handle).
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::backup::{BackupKey, kid_ok};
use crate::error::{Error, Result};

/// The remote as `<host>/<path>` with its own capitalization
/// (`github.com/Agora-Build/Atem`); credentials, port and `.git` dropped.
/// `None` for a remote that names no host and path (`file:///…`, a bare
/// name).
pub fn remote_label(url: &str) -> Option<String> {
    let u = url.trim();
    if u.is_empty() {
        return None;
    }
    let (host, path) = if let Some(idx) = u.find("://") {
        let rest = &u[idx + 3..];
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i + 1..]),
            None => (rest, ""),
        };
        let host = authority.rsplit('@').next().unwrap_or(authority);
        let host = match host.rsplit_once(':') {
            Some((h, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => h,
            _ => host,
        };
        (host.to_string(), path.to_string())
    } else if let Some((left, path)) = u.split_once(':') {
        let host = left.rsplit('@').next().unwrap_or(left);
        (host.to_string(), path.to_string())
    } else {
        return None;
    };
    let path = path.trim_matches('/');
    let path = path.strip_suffix(".git").unwrap_or(path);
    if host.is_empty() || path.is_empty() {
        return None;
    }
    Some(format!("{host}/{path}"))
}

/// The project key of a repository whose `origin` is `url`:
/// `git@github.com:Agora-Build/Atem.git` and
/// `https://github.com/Agora-Build/Atem` both become
/// `github.com/agora-build/atem`.
pub fn project_key_of_remote(url: &str) -> Option<String> {
    remote_label(url).map(|s| s.to_lowercase())
}

/// The project key of a folder with no usable `origin` remote:
/// `local:<folder name>`, its case kept (the repository root's folder name,
/// or the working directory's outside a repository; `root` for `/`).
pub fn local_project_key(folder_name: &str) -> String {
    format!("local:{folder_name}")
}

/// The bytes the keyed hash covers: the project key's UTF-8, nothing else
/// (no length prefix or label).
pub fn project_hash_input(project_key: &str) -> &[u8] {
    project_key.as_bytes()
}

/// `h1.<kid>.<64 lowercase hex>` of a 32-byte HMAC-SHA256 the platform
/// computed under the `K` generation `kid` over
/// [`project_hash_input`]. `kid` is 1–64 bytes of `[A-Za-z0-9_:-]` (no `.`:
/// it is the hash's separator).
pub fn project_hash_from_mac(kid: &str, mac: &[u8]) -> Result<String> {
    if !kid_ok(kid) || kid.contains('.') {
        return Err(Error::Malformed("kid"));
    }
    if mac.len() != 32 {
        return Err(Error::Malformed("mac"));
    }
    Ok(format!("h1.{kid}.{}", crate::encoding::hex(mac)))
}

/// The software form: `h1.<kid>.<hex HMAC-SHA256(k, project key)>` under
/// `key` (a `K` generation and its kid).
pub fn project_hash(key: &BackupKey, project_key: &str) -> Result<String> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key.k[..]).expect("HMAC accepts 32 bytes");
    mac.update(project_hash_input(project_key));
    project_hash_from_mac(&key.kid, &mac.finalize().into_bytes())
}

/// Whether `text` is a scope's project entry (`h1.<kid>.<64 lowercase
/// hex>`): the verifier's own syntax check.
pub fn is_project_hash(text: &str) -> bool {
    crate::membership::entry::project_hash_ok(text)
}

/// The kid a project entry names (`None` if it isn't one).
pub fn kid_of_project_hash(text: &str) -> Option<&str> {
    is_project_hash(text)
        .then(|| text.split('.').nth(1))
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    /// The host's own vector (`memory::account_keys` `H1_VECTOR`): `h1.`
    /// of "github.com/agora/atem" under K = [7; 32], kid 0123abcd.
    const H1_VECTOR: &str =
        "h1.0123abcd.777eda018c9c9736a84728e10308571167773f209924bf052477a1283cfd7cb6";

    fn key(kid: &str, byte: u8) -> BackupKey {
        BackupKey {
            kid: kid.into(),
            k: Zeroizing::new([byte; 32]),
        }
    }

    #[test]
    fn the_hash_matches_the_hosts_vector() {
        let hash = project_hash(&key("0123abcd", 7), "github.com/agora/atem").unwrap();
        assert_eq!(hash, H1_VECTOR);
        assert!(is_project_hash(&hash));
        assert_eq!(kid_of_project_hash(&hash), Some("0123abcd"));
        // Another generation is another hash.
        assert_ne!(
            project_hash(&key("4567cdef", 8), "github.com/agora/atem").unwrap(),
            hash
        );
    }

    #[test]
    fn a_platform_mac_formats_the_same_value() {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&[7; 32]).unwrap();
        mac.update(project_hash_input("github.com/agora/atem"));
        let bytes = mac.finalize().into_bytes();
        assert_eq!(
            project_hash_from_mac("0123abcd", &bytes).unwrap(),
            H1_VECTOR
        );
        assert_eq!(
            project_hash_from_mac("01.23", &bytes),
            Err(Error::Malformed("kid"))
        );
        assert_eq!(
            project_hash_from_mac("", &bytes),
            Err(Error::Malformed("kid"))
        );
        assert_eq!(
            project_hash_from_mac("0123abcd", &bytes[..31]),
            Err(Error::Malformed("mac"))
        );
    }

    #[test]
    fn remotes_normalize_as_the_host_does() {
        let want = Some("github.com/agora-build/atem".to_string());
        for url in [
            "git@github.com:Agora-Build/Atem.git",
            "https://github.com/Agora-Build/Atem",
            "https://github.com/Agora-Build/Atem.git/",
            "ssh://git@github.com:22/Agora-Build/Atem.git",
            "  https://user:tok@github.com/Agora-Build/Atem.git  ",
        ] {
            assert_eq!(project_key_of_remote(url), want, "{url}");
        }
        assert_eq!(
            remote_label("git@github.com:Agora-Build/Atem.git").as_deref(),
            Some("github.com/Agora-Build/Atem")
        );
        for bad in ["", "file:///srv/repo.git", "justaname", "https://host/"] {
            assert_eq!(project_key_of_remote(bad), None, "{bad}");
        }
        assert_eq!(local_project_key("Scratch"), "local:Scratch");
        assert!(!is_project_hash("h1.0123abcd.ZZ"));
        assert_eq!(kid_of_project_hash("local:x"), None);
    }
}
