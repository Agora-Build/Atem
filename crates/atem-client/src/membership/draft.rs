//! Building and signing entries (§R9.4 client rules 1–4): a body is drafted
//! on a head the signer verified, stored, then signed. Signing re-parses the
//! result as a verifier would, so a signer can't produce an entry its own
//! verifier refuses for its shape.
use serde_json::{Map, Value, json};

use crate::encoding::Hash32;
use crate::provider::{KeyId, KeyProvider};
use crate::signed::SignedObject;

use super::entry::{Action, HostRecord, KBackupRecord, KitMode, Member, MemberKind, Scope};
use super::{Entry, Invalid, Membership};

impl Scope {
    pub fn to_json(&self) -> Value {
        let mut object = Map::new();
        object.insert("hosts".into(), json!(self.hosts));
        if let Some(projects) = &self.projects {
            object.insert("projects".into(), json!(projects));
        }
        if let Some(sessions) = &self.sessions {
            object.insert("sessions".into(), json!(sessions));
        }
        object.insert("ops".into(), json!(self.ops));
        Value::Object(object)
    }
}

impl Member {
    /// The `member` object (sets in canonical order).
    pub fn to_json(&self) -> Value {
        match &self.kind {
            MemberKind::Native { enc_key, roles } => json!({
                "device_id": self.device_id,
                "kind": "native",
                "auth_key": self.auth_key.to_json(),
                "enc_key": enc_key.to_json(),
                "roles": roles.iter().map(|r| r.as_str()).collect::<Vec<_>>(),
            }),
            MemberKind::Service { scope, expires_at } => json!({
                "device_id": self.device_id,
                "kind": "service",
                "auth_key": self.auth_key.to_json(),
                "roles": ["service"],
                "scope": scope.to_json(),
                "expires_at": expires_at,
            }),
        }
    }
}

impl KBackupRecord {
    pub fn to_json(&self) -> Value {
        json!({
            "blob_version": self.blob_version,
            "kids": self.kids,
            "recovery_key": self.recovery_key.to_json(),
            "backup_hash": self.backup_hash.to_hex(),
        })
    }
}

impl HostRecord {
    pub fn to_json(&self) -> Value {
        json!({
            "host_id": self.host_id,
            "host_trust_gen": self.host_trust_gen,
            "host_key": self.host_key.to_json(),
        })
    }
}

impl Action {
    /// The action's own fields.
    pub fn fields(&self) -> Map<String, Value> {
        let value = match self {
            Action::Genesis {
                member,
                recovery_key,
            } => json!({"member": member.to_json(), "recovery_key": recovery_key.to_json()}),
            Action::Add { member } | Action::RecoveryAdd { member } => {
                json!({"member": member.to_json()})
            }
            Action::Remove { device_id } => json!({"device_id": device_id}),
            Action::SetRoles { device_id, change } => match change {
                super::RolesChange::Native(roles) => json!({
                    "device_id": device_id,
                    "roles": roles.iter().map(|r| r.as_str()).collect::<Vec<_>>(),
                }),
                super::RolesChange::Service { scope, expires_at } => json!({
                    "device_id": device_id,
                    "roles": ["service"],
                    "scope": scope.to_json(),
                    "expires_at": expires_at,
                }),
            },
            Action::AddHost { host } => json!({"host": host.to_json()}),
            Action::RemoveHost { host_id } => json!({"host_id": host_id}),
            Action::SetRecoveryKey { recovery_key, kit } => json!({
                "recovery_key": recovery_key.to_json(),
                "kit": match kit { KitMode::Current => "current", KitMode::Lost => "lost" },
            }),
            Action::RecoveryApprove { target } | Action::RecoveryVeto { target } => {
                json!({"target": target.to_hex()})
            }
            Action::KBackup(record) => json!({"k_backup": record.to_json()}),
        };
        match value {
            Value::Object(map) => map,
            _ => unreachable!(),
        }
    }
}

impl Membership {
    /// The body of the entry after this head, signed by `signer` (a device
    /// id, or `"recovery"` for a `recovery_add`). `signed_at` is display only.
    pub fn draft(&self, signer: &str, signed_at: u64, action: &Action) -> Value {
        draft_on(
            self.account_id(),
            &self.genesis_hash(),
            self.head().seq + 1,
            &self.head().hash,
            signer,
            signed_at,
            action,
        )
    }
}

/// A body at `seq` after `prev_hash` (a genesis: `seq` 1, zero `prev_hash`,
/// no `genesis_hash`).
pub fn draft_on(
    account_id: &str,
    genesis_hash: &Hash32,
    seq: u64,
    prev_hash: &Hash32,
    signer: &str,
    signed_at: u64,
    action: &Action,
) -> Value {
    let mut body = Map::new();
    body.insert("type".into(), json!("atem-membership-entry"));
    body.insert("v".into(), json!(1));
    body.insert("account_id".into(), json!(account_id));
    if !matches!(action, Action::Genesis { .. }) {
        body.insert("genesis_hash".into(), json!(genesis_hash.to_hex()));
    }
    body.insert("seq".into(), json!(seq));
    body.insert("prev_hash".into(), json!(prev_hash.to_hex()));
    body.insert("action".into(), json!(action.name()));
    body.insert("signer".into(), json!(signer));
    body.insert("signed_at".into(), json!(signed_at));
    body.extend(action.fields());
    Value::Object(body)
}

/// Signs a drafted body with `key` (the signer's `auth_key`, or a kit's
/// recovery key for `recovery_add`).
pub fn sign_entry(provider: &dyn KeyProvider, key: &KeyId, body: Value) -> Result<Entry, Invalid> {
    Entry::parse(SignedObject::sign(provider, key, body)?)
}

/// Signs a `set_recovery_key` with `kit: "current"`: the manager's `sig`,
/// then the current kit's `kit_sig` (§R9.5).
pub fn sign_entry_cosigned(
    provider: &dyn KeyProvider,
    key: &KeyId,
    kit: &dyn KeyProvider,
    kit_key: &KeyId,
    body: Value,
) -> Result<Entry, Invalid> {
    let mut object = SignedObject::sign(provider, key, body)?;
    object.cosign(kit, kit_key)?;
    Entry::parse(object)
}
