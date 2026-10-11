//! Encrypted project suggestions for Astation's credential editor.
use anyhow::{Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels: Option<ProjectLabelsWire>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectLabelsWire {
    pub signed: SignedWire,
    pub encapped_key: String,
    pub ciphertext: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectLabel {
    pub key: String,
    pub label: String,
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
    let mut projects = BTreeMap::new();
    for label in remembered {
        if let Some(key) = canonical_project(&label) {
            projects.entry(key).or_insert_with(|| label.trim().to_string());
        }
    }
    let current = current.and_then(|label| canonical_project(label).map(|key| (key, label.trim().to_string())));
    if let Some((key, label)) = &current { projects.insert(key.clone(), label.clone()); }
    let mut selected = Vec::new();
    if let Some((key, label)) = current { selected.push(ProjectLabel { key, label }); }
    for (key, label) in projects {
        if selected.len() == MAX_PROJECTS { break; }
        if !selected.iter().any(|entry| entry.key == key) { selected.push(ProjectLabel { key, label }); }
    }
    // Keep the current repo while bounding both encrypted payloads together.
    let canonical = |entries: &[ProjectLabel]| entries.iter().map(|entry| entry.key.clone()).collect::<Vec<_>>();
    while serde_json::to_vec(&canonical(&selected))?.len() + serde_json::to_vec(&selected)?.len() > MAX_BYTES { selected.pop(); }
    selected.sort_by(|a, b| a.key.cmp(&b.key));
    let time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let generation = u64_field(1);
    let time_field = u64_field(time);
    let info = enc(&[b"atem-credential-projects-info-v1", account.as_bytes(), device_id.as_bytes(), &generation, &time_field]);
    let (encapped, ciphertext) = hpke_seal(recipient, &info, &serde_json::to_vec(&canonical(&selected))?)?;
    let hash = sealed_hash(&encapped, &ciphertext);
    let statement = enc(&[b"atem-credential-projects-v1", account.as_bytes(), device_id.as_bytes(), &generation, &time_field, &hash]);
    if account.is_empty() || device_id.is_empty() { bail!("project report identity is missing"); }
    let label_info = enc(&[b"atem-credential-project-labels-info-v1", account.as_bytes(), device_id.as_bytes(), &generation, &time_field]);
    let (label_encapped, label_ciphertext) = hpke_seal(recipient, &label_info, &serde_json::to_vec(&selected)?)?;
    let label_hash = sealed_hash(&label_encapped, &label_ciphertext);
    let label_statement = enc(&[b"atem-credential-project-labels-v1", account.as_bytes(), device_id.as_bytes(), &generation, &time_field, &label_hash]);
    Ok(ProjectReportWire {
        signed: keys.sign_statement(&statement),
        encapped_key: STANDARD.encode(encapped),
        ciphertext: STANDARD.encode(ciphertext),
        labels: Some(ProjectLabelsWire {
            signed: keys.sign_statement(&label_statement),
            encapped_key: STANDARD.encode(label_encapped),
            ciphertext: STANDARD.encode(label_ciphertext),
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::encoding::dec;
    use super::super::grant::hpke_open;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use x25519_dalek::{PublicKey, StaticSecret};
    use std::collections::BTreeSet;

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

    fn open_labels(report: &ProjectReportWire, secret: &StaticSecret, keys: &DeviceKeys) -> Vec<ProjectLabel> {
        let labels = report.labels.as_ref().unwrap();
        let statement = STANDARD.decode(&labels.signed.statement).unwrap();
        VerifyingKey::from_bytes(&keys.device_sign_pub()).unwrap().verify(&statement,
            &Signature::from_slice(&STANDARD.decode(&labels.signed.signature).unwrap()).unwrap()).unwrap();
        let fields = dec(&statement).unwrap();
        assert_eq!(fields[0], b"atem-credential-project-labels-v1");
        let legacy_fields = dec(&STANDARD.decode(&report.signed.statement).unwrap()).unwrap();
        assert_eq!(fields[1..5], legacy_fields[1..5]);
        let encapped = STANDARD.decode(&labels.encapped_key).unwrap();
        let ciphertext = STANDARD.decode(&labels.ciphertext).unwrap();
        assert_eq!(fields[5], sealed_hash(&encapped, &ciphertext));
        let info = enc(&[b"atem-credential-project-labels-info-v1", &fields[1], &fields[2], &fields[3], &fields[4]]);
        let plain = hpke_open(&secret.to_bytes(), &encapped, &ciphertext, &info).unwrap();
        let legacy_info = enc(&[b"atem-credential-projects-info-v1", &fields[1], &fields[2], &fields[3], &fields[4]]);
        let legacy_plain = hpke_open(&secret.to_bytes(), &STANDARD.decode(&report.encapped_key).unwrap(),
            &STANDARD.decode(&report.ciphertext).unwrap(), &legacy_info).unwrap();
        assert!(plain.len() + legacy_plain.len() <= MAX_BYTES);
        let entries: Vec<ProjectLabel> = serde_json::from_slice(&plain).unwrap();
        let canonical: Vec<String> = serde_json::from_slice(&legacy_plain).unwrap();
        assert_eq!(entries.iter().map(|entry| entry.key.clone()).collect::<Vec<_>>(), canonical);
        for entry in &entries { assert_eq!(canonical_project(&entry.label).as_ref(), Some(&entry.key)); }
        entries
    }

    #[test]
    fn labels_preserve_current_spelling_without_changing_legacy_keys() {
        let keys = DeviceKeys::generate();
        let secret = StaticSecret::from([7u8; 32]);
        let report = seal_report(&keys, "account", "device", &PublicKey::from(&secret).to_bytes(),
            ["github.com/org/repo".into(), "github.com/Org/Repo".into(), "github.com/Other/Project".into()],
            Some("github.com/ORG/Repo")).unwrap();
        let entries = open_labels(&report, &secret, &keys);
        assert_eq!(entries, [
            ProjectLabel { key: "github.com/org/repo".into(), label: "github.com/ORG/Repo".into() },
            ProjectLabel { key: "github.com/other/project".into(), label: "github.com/Other/Project".into() },
        ]);
        let mut legacy = serde_json::to_value(&report).unwrap();
        legacy.as_object_mut().unwrap().remove("labels");
        assert!(serde_json::from_value::<ProjectReportWire>(legacy).unwrap().labels.is_none());
        assert!(!serde_json::to_string(&report).unwrap().contains("github.com"));
    }

    #[test]
    fn combined_payload_budget_retains_current_repo_and_empty_reports_work() {
        let keys = DeviceKeys::generate();
        let secret = StaticSecret::from([7u8; 32]);
        let recipient = PublicKey::from(&secret).to_bytes();
        let report = seal_report(&keys, "account", "device", &recipient,
            (0..300).map(|i| format!("github.com/Org/Repo{i:03}{}", "x".repeat(900))), Some("github.com/Org/Current")).unwrap();
        let entries = open_labels(&report, &secret, &keys);
        assert!(entries.len() < MAX_PROJECTS);
        assert!(entries.iter().any(|entry| entry.label == "github.com/Org/Current"));
        let empty = seal_report(&keys, "account", "device", &recipient, [], None).unwrap();
        assert!(open_labels(&empty, &secret, &keys).is_empty());
    }
}
