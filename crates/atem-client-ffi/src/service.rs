//! Service member builders and the project-hash helper (§R9.6) over
//! `atem_client::membership::service` and `atem_client::project`: the
//! builders return the action JSON `MembershipLog::draft_entry` and
//! `check_change` take, already checked by the verifier's structural
//! parse; nothing here is a second wire form.
use atem_client::backup::BackupKey;
use atem_client::membership::{Action, Scope, ServiceChangeError, ServiceScope};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::encoding::{canonical, safe_int};
use crate::error::{AtemError, Result};
use crate::log::MembershipLog;
use crate::types::{AccountKey, PublicKeyData, ServiceGrantInfo, ServiceScopeInfo};

impl From<&ServiceScopeInfo> for ServiceScope {
    fn from(s: &ServiceScopeInfo) -> Self {
        ServiceScope::new(s.hosts.iter().cloned())
            .ops(s.ops.iter().cloned())
            .projects(s.projects.clone())
            .sessions(s.sessions.clone())
    }
}

pub(crate) fn scope_info(scope: &Scope) -> ServiceScopeInfo {
    ServiceScopeInfo {
        hosts: scope.hosts.clone(),
        projects: scope.projects.clone(),
        sessions: scope.sessions.clone(),
        ops: scope.ops.clone(),
    }
}

/// `{"action": …, …its fields}` in canonical JSON (what `draft_entry`
/// takes).
fn action_json(action: &Action) -> Result<String> {
    let mut object = action.fields();
    object.insert("action".into(), Value::from(action.name()));
    canonical(&Value::Object(object))
}

fn change_error(e: ServiceChangeError) -> AtemError {
    match e {
        ServiceChangeError::Invalid(i) => AtemError::from(i),
        other => AtemError::Invalid {
            code: other.code().into(),
            detail: match other {
                ServiceChangeError::NotAService => "no service of that id is in effect",
                ServiceChangeError::NotARenewal => "expires_at isn't later than the current one",
                _ => "the scope or expiry grants something new, or changes nothing",
            }
            .into(),
        },
    }
}

/// The `add` of a service member (§R9.2): `auth_key` P-256 or Ed25519,
/// `expires_at` at most 90 days after `signed_at`. Returns the action JSON
/// (`{"action":"add","member":{…}}`) for `draft_entry`/`check_change`; a
/// shape the verifier refuses throws `Membership` with its code
/// (`bad_scope`, `service_expiry`, `wrong_alg`, …).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn service_add_action(
    device_id: String,
    auth_key: PublicKeyData,
    scope: ServiceScopeInfo,
    expires_at: u64,
    signed_at: u64,
) -> Result<String> {
    let action = atem_client::membership::service_add(
        &device_id,
        auth_key.to_key()?,
        &ServiceScope::from(&scope),
        safe_int(expires_at, "expires_at")?,
        safe_int(signed_at, "signed_at")?,
    )?;
    action_json(&action)
}

/// A service `set_roles` (roles `["service"]`, scope, `expires_at` ≤ 90
/// days after `signed_at`): the action JSON. Any `set_roles` fences the
/// service's live channels; it reconnects under the new grant.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn service_set_roles_action(
    device_id: String,
    scope: ServiceScopeInfo,
    expires_at: u64,
    signed_at: u64,
) -> Result<String> {
    let action = atem_client::membership::service_set_roles(
        &device_id,
        &ServiceScope::from(&scope),
        safe_int(expires_at, "expires_at")?,
        safe_int(signed_at, "signed_at")?,
    )?;
    action_json(&action)
}

/// `r9_svc` of a service's `auth_key`: lowercase hex SHA-256 of the raw
/// public key bytes (P-256: 65-byte SEC1 uncompressed; Ed25519: 32 bytes),
/// nothing else hashed. The key is checked first (`bad_key`, `weak_key`;
/// X25519 is `wrong_alg`).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn service_key_fingerprint(auth_key: PublicKeyData) -> Result<String> {
    Ok(atem_client::membership::service_key_fingerprint(
        &auth_key.to_key()?,
    )?)
}

/// A launch project key from a repository's `origin` remote
/// (`github.com/agora-build/atem`); `None` for a remote with no host and
/// path.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn project_key_of_remote(url: String) -> Option<String> {
    atem_client::project::project_key_of_remote(&url)
}

/// The launch project key of a folder without a usable remote:
/// `local:<folder name>`.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn local_project_key(folder_name: String) -> String {
    atem_client::project::local_project_key(&folder_name)
}

/// The bytes to HMAC-SHA256 under `K` (the project key's UTF-8).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn project_hash_input(project_key: String) -> Vec<u8> {
    atem_client::project::project_hash_input(&project_key).to_vec()
}

/// `h1.<kid>.<hex>` of a 32-byte HMAC-SHA256 the platform computed under
/// the `K` generation `kid` over `project_hash_input` (the key stays in
/// the platform key store).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn project_hash_from_mac(kid: String, mac: Vec<u8>) -> Result<String> {
    Ok(atem_client::project::project_hash_from_mac(&kid, &mac)?)
}

/// The software form: `h1.<kid>.<hex HMAC-SHA256(k, project key)>` under
/// an account key (as `seal_k_backup` takes it). Only for an app that
/// already holds `K` bytes in memory (restore, K backups); otherwise use
/// `project_hash_from_mac` with the key in the platform key store.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn project_hash(key: AccountKey, project_key: String) -> Result<String> {
    let AccountKey { kid, k } = key;
    let k = Zeroizing::new(k);
    let bytes: [u8; 32] = k
        .as_slice()
        .try_into()
        .map_err(|_| AtemError::malformed("a K is 32 bytes"))?;
    let key = BackupKey {
        kid,
        k: Zeroizing::new(bytes),
    };
    Ok(atem_client::project::project_hash(&key, &project_key)?)
}

/// Whether `text` is a scope's project entry (`h1.<kid>.<64 hex>`).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn is_project_hash(text: String) -> bool {
    atem_client::project::is_project_hash(&text)
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl MembershipLog {
    /// The scope and expiry of the active service member `device_id`
    /// (its membership status only: an expired service is still returned;
    /// compare `expires_at` with the time yourself).
    pub fn service_grant(&self, device_id: String) -> Option<ServiceGrantInfo> {
        let log = self.lock();
        atem_client::membership::service_grant(&log, &device_id).map(|(scope, expires_at)| {
            ServiceGrantInfo {
                scope: scope_info(scope),
                expires_at,
            }
        })
    }

    /// `r9_svc` of the active service member `device_id` (its `add`
    /// entry's `auth_key`), else `None`. Status only: expiry is the
    /// caller's check.
    pub fn service_key_fingerprint(&self, device_id: String) -> Option<String> {
        atem_client::membership::service_key_fingerprint_of(&self.lock(), &device_id)
    }

    /// A renewal of the service `device_id`: its current scope with a
    /// later `expires_at` (≤ 90 days after `signed_at`), as action JSON.
    /// `not_a_service` / `not_a_renewal` are `Invalid`. Check it with
    /// `check_change` first (paced 24 h after the service's last grant).
    pub fn service_renewal_action(
        &self,
        device_id: String,
        expires_at: u64,
        signed_at: u64,
    ) -> Result<String> {
        let log = self.lock();
        let action = atem_client::membership::service_renewal(
            &log,
            &device_id,
            safe_int(expires_at, "expires_at")?,
            safe_int(signed_at, "signed_at")?,
        )
        .map_err(change_error)?;
        action_json(&action)
    }

    /// A narrowing of the service `device_id` to `scope` and `expires_at`
    /// (`None`: unchanged): nothing new granted and something changed, else
    /// `not_a_narrowing` (`Invalid`). Never paced by `check_change`.
    pub fn service_narrowing_action(
        &self,
        device_id: String,
        scope: ServiceScopeInfo,
        expires_at: Option<u64>,
        signed_at: u64,
    ) -> Result<String> {
        let log = self.lock();
        let expires_at = expires_at.map(|e| safe_int(e, "expires_at")).transpose()?;
        let action = atem_client::membership::service_narrowing(
            &log,
            &device_id,
            &ServiceScope::from(&scope),
            expires_at,
            safe_int(signed_at, "signed_at")?,
        )
        .map_err(change_error)?;
        action_json(&action)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(ops: &[&str]) -> ServiceScopeInfo {
        ServiceScopeInfo {
            hosts: vec!["host-a".into()],
            projects: None,
            sessions: Some(vec!["ses-bbbbbbbbbbbb".into(), "ses-aaaaaaaaaaaa".into()]),
            ops: ops.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn the_action_json_is_canonical_and_draftable() {
        let key = PublicKeyData {
            alg: crate::types::KeyAlg::Ed25519,
            raw: atem_client::kit::recovery_key_of_seed(&[3; 32])
                .as_bytes()
                .to_vec(),
        };
        let json =
            service_add_action("svc-x".into(), key, scope(&["prompt"]), 2_000, 1_000).unwrap();
        assert!(
            json.starts_with(r#"{"action":"add","member":{"auth_key":"#),
            "{json}"
        );
        assert!(
            json.contains(
                r#""ops":["prompt","view"],"sessions":["ses-aaaaaaaaaaaa","ses-bbbbbbbbbbbb"]"#
            ),
            "{json}"
        );
        let roles =
            service_set_roles_action("svc-x".into(), scope(&["view"]), 2_000, 1_000).unwrap();
        assert_eq!(
            roles,
            r#"{"action":"set_roles","device_id":"svc-x","expires_at":2000,"roles":["service"],"scope":{"hosts":["host-a"],"ops":["view"],"sessions":["ses-aaaaaaaaaaaa","ses-bbbbbbbbbbbb"]}}"#
        );
        let mut bad = scope(&["fly"]);
        bad.hosts.clear();
        assert!(matches!(
            service_set_roles_action("svc-x".into(), bad, 2_000, 1_000),
            Err(AtemError::Membership { detail, .. }) if detail == "bad_scope"
        ));
        assert!(matches!(
            service_set_roles_action("svc-x".into(), scope(&[]), 1_000 + 7_776_000_001, 1_000),
            Err(AtemError::Membership { detail, .. }) if detail == "service_expiry"
        ));
    }

    #[test]
    fn project_hash_matches_the_hosts_vector() {
        let key = AccountKey {
            kid: "0123abcd".into(),
            k: vec![7; 32],
        };
        assert_eq!(
            project_hash(key, "github.com/agora/atem".into()).unwrap(),
            "h1.0123abcd.777eda018c9c9736a84728e10308571167773f209924bf052477a1283cfd7cb6"
        );
        assert!(matches!(
            project_hash(
                AccountKey {
                    kid: "k".into(),
                    k: vec![7; 31]
                },
                "x".into()
            ),
            Err(AtemError::Invalid { .. })
        ));
        assert!(matches!(
            project_hash_from_mac("a.b".into(), vec![0; 32]),
            Err(AtemError::Invalid { code, .. }) if code == "malformed"
        ));
    }
}
