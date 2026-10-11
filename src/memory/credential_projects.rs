//! Encrypted project suggestions for Astation's credential editor.
use anyhow::{Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::time::{SystemTime, UNIX_EPOCH};

use super::device_keys::DeviceKeys;
use super::encoding::{enc, u64_field};
use super::grant::hpke_seal;
use super::statements::{SignedWire, sealed_hash};

pub const MAX_PROJECTS: usize = 256;
pub const MAX_BYTES: usize = 65_536;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectReportWire {
    pub signed: SignedWire,
    pub encapped_key: String,
    pub ciphertext: String,
}

pub fn canonical_project(raw: &str) -> Option<String> {
    let key = raw.trim().to_lowercase();
    if key.is_empty() || key.len() > 1024 || key.ends_with(".git")
        || key.chars().any(|c| c.is_whitespace() || c.is_control() || "@?#\\:".contains(c)) {
        return None;
    }
    let parts: Vec<_> = key.split('/').collect();
    if parts.len() < 2 || !parts[0].contains('.')
        || parts.iter().any(|part| part.is_empty() || *part == "." || *part == "..") {
        return None;
    }
    Some(key)
}

pub fn seal_report(
    keys: &DeviceKeys, account: &str, device_id: &str, recipient: &[u8; 32],
    remembered: impl IntoIterator<Item = String>, current: Option<&str>,
) -> Result<ProjectReportWire> {
    let mut projects: BTreeSet<String> = remembered.into_iter().filter_map(|key| canonical_project(&key)).collect();
    let current = current.and_then(canonical_project);
    if let Some(key) = &current { projects.insert(key.clone()); }
    let mut selected = Vec::new();
    if let Some(key) = current { selected.push(key); }
    for key in projects {
        if selected.len() == MAX_PROJECTS { break; }
        if !selected.contains(&key) { selected.push(key); }
    }
    // Bound the encoded payload too; long names must not exceed the wire budget.
    while serde_json::to_vec(&selected)?.len() > MAX_BYTES { selected.pop(); }
    selected.sort();
    let time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let generation = u64_field(1);
    let time_field = u64_field(time);
    let info = enc(&[b"atem-credential-projects-info-v1", account.as_bytes(), device_id.as_bytes(), &generation, &time_field]);
    let (encapped, ciphertext) = hpke_seal(recipient, &info, &serde_json::to_vec(&selected)?)?;
    let hash = sealed_hash(&encapped, &ciphertext);
    let statement = enc(&[b"atem-credential-projects-v1", account.as_bytes(), device_id.as_bytes(), &generation, &time_field, &hash]);
    if account.is_empty() || device_id.is_empty() { bail!("project report identity is missing"); }
    Ok(ProjectReportWire {
        signed: keys.sign_statement(&statement),
        encapped_key: STANDARD.encode(encapped),
        ciphertext: STANDARD.encode(ciphertext),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::encoding::dec;
    use super::super::grant::hpke_open;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use super::super::device_keys::PublicKeys;
    use x25519_dalek::{PublicKey, StaticSecret};

    #[test]
    fn reports_are_signed_encrypted_deduplicated_and_bounded() {
        let keys = DeviceKeys::generate();
        let secret = StaticSecret::from([7u8; 32]);
        let recipient = PublicKey::from(&secret).to_bytes();
        let projects = (0..300).map(|i| format!("github.com/org/repo{i:03}"))
            .chain(["github.com/Org/Repo000".into(), "local:scratch".into(), "github.com/user@token/repo".into()]);
        let report = seal_report(&keys, "account", "device", &recipient, projects, Some("github.com/org/current")).unwrap();
        let statement = STANDARD.decode(&report.signed.statement).unwrap();
        VerifyingKey::from_bytes(&keys.device_sign_pub()).unwrap().verify(&statement,
            &Signature::from_slice(&STANDARD.decode(&report.signed.signature).unwrap()).unwrap()).unwrap();
        let fields = dec(&statement).unwrap();
        let encapped = STANDARD.decode(&report.encapped_key).unwrap();
        let ciphertext = STANDARD.decode(&report.ciphertext).unwrap();
        assert_eq!(fields[5], sealed_hash(&encapped, &ciphertext));
        let info = enc(&[b"atem-credential-projects-info-v1", &fields[1], &fields[2], &fields[3], &fields[4]]);
        let plain = hpke_open(&secret.to_bytes(), &encapped, &ciphertext, &info).unwrap();
        assert!(plain.len() <= MAX_BYTES);
        let names: Vec<String> = serde_json::from_slice(&plain).unwrap();
        assert_eq!(names.len(), MAX_PROJECTS);
        assert!(names.contains(&"github.com/org/current".into()));
        assert_eq!(names.iter().collect::<BTreeSet<_>>().len(), names.len());
        assert!(!serde_json::to_string(&report).unwrap().contains("github.com"));
        assert!(hpke_open(&[8u8; 32], &encapped, &ciphertext, &info).is_err());
    }

    #[test]
    fn excludes_local_paths_credentials_and_invalid_project_keys() {
        for key in ["local:scratch", "/Users/test/repo", "github.com/a/../b", "github.com/a/repo?token=x", "github.com/a/repo.git", "github.com//repo"] {
            assert!(canonical_project(key).is_none(), "{key}");
        }
        assert_eq!(canonical_project("github.com/Owner/Repo"), Some("github.com/owner/repo".into()));
    }
}
