//! Membership entries (§R9.2): the typed, schema-checked form of a signed
//! `atem-membership-entry`.
//!
//! [`Entry::parse`] applies every rule that depends on the entry alone:
//! exactly the fields of its action (no unknown field anywhere in the body,
//! §R9.1), the fixed algorithm of every key inside it (`auth_key` P-256 or
//! Ed25519, `enc_key` X25519, `host_key` and `recovery_key` Ed25519), id
//! syntax, roles, scope and service expiry, and who may sign which action.
//! Rules that need the chain (signer authority, ids never reused, version
//! floors) are [`super::Membership`]'s.
use std::collections::BTreeSet;

use serde_json::{Map, Value};

use crate::backup::kid_ok;
use crate::canonical::StrictValue;
use crate::encoding::Hash32;
use crate::error::Error;
use crate::keys::{Alg, PublicKey};
use crate::signed::SignedObject;

use super::Invalid;

/// The reserved signer of `recovery_add` (no device id may equal it).
pub const RECOVERY_SIGNER: &str = "recovery";
/// A service's `expires_at` is at most this long after `signed_at` (90 days).
pub const SERVICE_MAX_LIFETIME_MS: u64 = 7_776_000_000;
/// `scope.hosts`: 1 to 16 hosts.
pub const MAX_SCOPE_HOSTS: usize = 16;
/// `scope.projects` and `scope.sessions`: at most 64 each.
pub const MAX_SCOPE_ITEMS: usize = 64;

/// The ops of a service scope or a grant (§R9.6). `view` is always required.
pub const OPS: [&str; 7] = [
    "approval",
    "interrupt",
    "prompt",
    "rule_revoke",
    "stop",
    "terminal",
    "view",
];

/// An opaque id (`device_id`, `host_id`): 1–128 bytes of `[A-Za-z0-9._:-]`.
pub fn id_ok(id: &str) -> bool {
    (1..=128).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

/// Native roles (a set, §R9.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Role {
    Control,
    Manage,
    View,
}

impl Role {
    pub fn parse(name: &str) -> Option<Role> {
        match name {
            "control" => Some(Role::Control),
            "manage" => Some(Role::Manage),
            "view" => Some(Role::View),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Role::Control => "control",
            Role::Manage => "manage",
            Role::View => "view",
        }
    }
}

/// A service's scope (§R9.6). Absent lists don't restrict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    pub hosts: Vec<String>,
    pub projects: Option<Vec<String>>,
    pub sessions: Option<Vec<String>>,
    pub ops: Vec<String>,
}

/// What a member is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberKind {
    /// A native device: its `enc_key` (push hints are sealed to it) and roles
    /// (always with `view`).
    Native {
        enc_key: PublicKey,
        roles: BTreeSet<Role>,
    },
    /// A scoped bot: roles exactly `["service"]`.
    Service { scope: Scope, expires_at: u64 },
}

/// The `member` object of `genesis`, `add` and `recovery_add`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub device_id: String,
    pub auth_key: PublicKey,
    pub kind: MemberKind,
}

impl Member {
    pub fn is_native(&self) -> bool {
        matches!(self.kind, MemberKind::Native { .. })
    }

    /// A native member holding `manage`.
    pub fn is_manager(&self) -> bool {
        matches!(&self.kind, MemberKind::Native { roles, .. } if roles.contains(&Role::Manage))
    }

    pub fn has_role(&self, role: Role) -> bool {
        matches!(&self.kind, MemberKind::Native { roles, .. } if roles.contains(&role))
    }
}

/// `set_recovery_key`'s mode (§R9.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KitMode {
    /// Co-signed by the current kit (`kit_sig`): in effect at once.
    Current,
    /// No `kit_sig`: pending for 24 h, approve or veto.
    Lost,
}

/// The newest K backup record (§R9.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KBackupRecord {
    pub blob_version: u64,
    /// A sequence: current kid first.
    pub kids: Vec<String>,
    pub recovery_key: PublicKey,
    pub backup_hash: Hash32,
}

/// A host's key (`add_host`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostRecord {
    pub host_id: String,
    pub host_trust_gen: u64,
    pub host_key: PublicKey,
}

/// What a `set_roles` sets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RolesChange {
    Native(BTreeSet<Role>),
    Service { scope: Scope, expires_at: u64 },
}

/// An entry's action and its own fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Genesis {
        member: Member,
        recovery_key: PublicKey,
    },
    Add {
        member: Member,
    },
    Remove {
        device_id: String,
    },
    SetRoles {
        device_id: String,
        change: RolesChange,
    },
    AddHost {
        host: HostRecord,
    },
    RemoveHost {
        host_id: String,
    },
    RecoveryAdd {
        member: Member,
    },
    SetRecoveryKey {
        recovery_key: PublicKey,
        kit: KitMode,
    },
    RecoveryApprove {
        target: Hash32,
    },
    RecoveryVeto {
        target: Hash32,
    },
    KBackup(KBackupRecord),
}

impl Action {
    pub fn name(&self) -> &'static str {
        match self {
            Action::Genesis { .. } => "genesis",
            Action::Add { .. } => "add",
            Action::Remove { .. } => "remove",
            Action::SetRoles { .. } => "set_roles",
            Action::AddHost { .. } => "add_host",
            Action::RemoveHost { .. } => "remove_host",
            Action::RecoveryAdd { .. } => "recovery_add",
            Action::SetRecoveryKey { .. } => "set_recovery_key",
            Action::RecoveryApprove { .. } => "recovery_approve",
            Action::RecoveryVeto { .. } => "recovery_veto",
            Action::KBackup(_) => "k_backup",
        }
    }

    /// A `recovery_add` or a `kit: "lost"` `set_recovery_key`: the entries
    /// that wait 24 h and take approve and veto (§R9.5).
    pub fn is_pending_type(&self) -> bool {
        matches!(
            self,
            Action::RecoveryAdd { .. }
                | Action::SetRecoveryKey {
                    kit: KitMode::Lost,
                    ..
                }
        )
    }
}

/// A parsed membership entry: its signed object, `entry_hash` and fields.
#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    object: SignedObject,
    hash: Hash32,
    pub account_id: String,
    /// Absent only in `genesis`.
    pub genesis_hash: Option<Hash32>,
    pub seq: u64,
    pub prev_hash: Hash32,
    pub signer: String,
    /// Display only, never authority (§R9.2).
    pub signed_at: u64,
    pub action: Action,
}

impl Entry {
    /// Strict parse of an entry's wire bytes.
    pub fn parse_bytes(bytes: &[u8]) -> Result<Entry, Invalid> {
        Entry::parse(SignedObject::parse(bytes)?)
    }

    /// From a part of a strictly parsed message (a carriage's `entries`).
    pub fn from_strict(value: &StrictValue) -> Result<Entry, Invalid> {
        Entry::parse(SignedObject::from_strict(value)?)
    }

    /// Checks the body against its action's schema. The signature is not
    /// checked here (it needs the chain to know the key).
    pub fn parse(object: SignedObject) -> Result<Entry, Invalid> {
        if object.body_type() != "atem-membership-entry" {
            return Err(Invalid::Malformed("not a membership entry"));
        }
        let body = object
            .body()
            .as_object()
            .ok_or(Invalid::Malformed("body"))?;
        let action_name = str_field(body, "action")?;
        let action_fields: &[&str] = match action_name {
            "genesis" => &["member", "recovery_key"],
            "add" | "recovery_add" => &["member"],
            "remove" => &["device_id"],
            "set_roles" => &["device_id", "roles", "scope", "expires_at"],
            "add_host" => &["host"],
            "remove_host" => &["host_id"],
            "set_recovery_key" => &["recovery_key", "kit"],
            "recovery_approve" | "recovery_veto" => &["target"],
            "k_backup" => &["k_backup"],
            _ => return Err(Invalid::Malformed("unknown action")),
        };
        const COMMON: [&str; 9] = [
            "type",
            "v",
            "account_id",
            "genesis_hash",
            "seq",
            "prev_hash",
            "action",
            "signer",
            "signed_at",
        ];
        only_fields(body, &[&COMMON[..], action_fields].concat())?;

        let account_id = str_field(body, "account_id")?;
        if account_id.is_empty() || account_id.len() > 128 {
            return Err(Invalid::Malformed("account_id"));
        }
        let genesis_hash = body
            .get("genesis_hash")
            .map(|v| hash_value(v, "genesis_hash"))
            .transpose()?;
        let seq = u64_field(body, "seq")?;
        if seq == 0 {
            return Err(Invalid::Malformed("seq starts at 1"));
        }
        let prev_hash = hash_value(field(body, "prev_hash")?, "prev_hash")?;
        let signer = str_field(body, "signer")?;
        if signer != RECOVERY_SIGNER && !id_ok(signer) {
            return Err(Invalid::Malformed("signer"));
        }
        let signed_at = u64_field(body, "signed_at")?;

        let action = match action_name {
            "genesis" => {
                let member = member(field(body, "member")?, signed_at)?;
                if !exactly_all_roles(&member) {
                    return Err(Invalid::BadRoles);
                }
                if seq != 1 || prev_hash != Hash32([0u8; 32]) || genesis_hash.is_some() {
                    return Err(Invalid::BadGenesis);
                }
                if signer != member.device_id {
                    return Err(Invalid::BadGenesis);
                }
                Action::Genesis {
                    member,
                    recovery_key: key(field(body, "recovery_key")?, &[Alg::Ed25519])?,
                }
            }
            "add" => Action::Add {
                member: member(field(body, "member")?, signed_at)?,
            },
            "recovery_add" => {
                let member = member(field(body, "member")?, signed_at)?;
                if !exactly_all_roles(&member) {
                    return Err(Invalid::BadRoles);
                }
                Action::RecoveryAdd { member }
            }
            "remove" => Action::Remove {
                device_id: device_id(field(body, "device_id")?)?,
            },
            "set_roles" => {
                let roles = string_set(field(body, "roles")?, "roles")?;
                let change = if roles == ["service"] {
                    let scope = scope(body.get("scope").ok_or(Invalid::BadScope)?)?;
                    let expires_at = body
                        .get("expires_at")
                        .ok_or(Invalid::Malformed("expires_at"))
                        .and_then(|v| v.as_u64().ok_or(Invalid::Malformed("expires_at")))?;
                    service_expiry(signed_at, expires_at)?;
                    RolesChange::Service { scope, expires_at }
                } else {
                    if body.contains_key("scope") || body.contains_key("expires_at") {
                        return Err(Invalid::BadRoles);
                    }
                    RolesChange::Native(native_roles(&roles)?)
                };
                Action::SetRoles {
                    device_id: device_id(field(body, "device_id")?)?,
                    change,
                }
            }
            "add_host" => {
                let host = field(body, "host")?
                    .as_object()
                    .ok_or(Invalid::Malformed("host"))?;
                only_fields(host, &["host_id", "host_trust_gen", "host_key"])?;
                let host_id = str_field(host, "host_id")?;
                if !id_ok(host_id) {
                    return Err(Invalid::Malformed("host_id"));
                }
                let host_trust_gen = u64_field(host, "host_trust_gen")?;
                if host_trust_gen == 0 {
                    return Err(Invalid::Malformed("host_trust_gen"));
                }
                Action::AddHost {
                    host: HostRecord {
                        host_id: host_id.to_owned(),
                        host_trust_gen,
                        host_key: key(field(host, "host_key")?, &[Alg::Ed25519])?,
                    },
                }
            }
            "remove_host" => {
                let host_id = str_field(body, "host_id")?;
                if !id_ok(host_id) {
                    return Err(Invalid::Malformed("host_id"));
                }
                Action::RemoveHost {
                    host_id: host_id.to_owned(),
                }
            }
            "set_recovery_key" => Action::SetRecoveryKey {
                recovery_key: key(field(body, "recovery_key")?, &[Alg::Ed25519])?,
                kit: match str_field(body, "kit")? {
                    "current" => KitMode::Current,
                    "lost" => KitMode::Lost,
                    _ => return Err(Invalid::Malformed("kit")),
                },
            },
            "recovery_approve" => Action::RecoveryApprove {
                target: hash_value(field(body, "target")?, "target")?,
            },
            "recovery_veto" => Action::RecoveryVeto {
                target: hash_value(field(body, "target")?, "target")?,
            },
            "k_backup" => {
                let record = field(body, "k_backup")?
                    .as_object()
                    .ok_or(Invalid::Malformed("k_backup"))?;
                only_fields(
                    record,
                    &["blob_version", "kids", "recovery_key", "backup_hash"],
                )?;
                let blob_version = u64_field(record, "blob_version")?;
                if blob_version == 0 {
                    return Err(Invalid::Malformed("blob_version"));
                }
                // The array rules (a sequence, 1–8, unique) were checked by
                // the signed-object parse; the kids' syntax is the envelope's.
                let kids: Vec<String> = field(record, "kids")?
                    .as_array()
                    .ok_or(Invalid::Malformed("kids"))?
                    .iter()
                    .map(|kid| kid.as_str().filter(|k| kid_ok(k)).map(str::to_owned))
                    .collect::<Option<_>>()
                    .ok_or(Invalid::Malformed("kids"))?;
                Action::KBackup(KBackupRecord {
                    blob_version,
                    kids,
                    recovery_key: key(field(record, "recovery_key")?, &[Alg::Ed25519])?,
                    backup_hash: hash_value(field(record, "backup_hash")?, "backup_hash")?,
                })
            }
            _ => unreachable!("matched above"),
        };

        // Who may sign what: the recovery key only `recovery_add`, and a
        // `recovery_add` only the recovery key (§R9.5).
        let by_recovery = signer == RECOVERY_SIGNER;
        if by_recovery != matches!(action, Action::RecoveryAdd { .. }) {
            return Err(Invalid::RecoverySignerAction);
        }
        if genesis_hash.is_none() && !matches!(action, Action::Genesis { .. }) {
            return Err(Invalid::Malformed("genesis_hash"));
        }

        // The body names its mode, so a `kit: "current"` entry without its
        // `kit_sig` is invalid, never another entry (§R9.5).
        if object.cosign_input().is_some() && object.kit_sig().is_none() {
            return Err(Invalid::KitSigMissing);
        }
        let hash = object.entry_hash().expect("a membership entry has a hash");
        Ok(Entry {
            hash,
            account_id: account_id.to_owned(),
            genesis_hash,
            seq,
            prev_hash,
            signer: signer.to_owned(),
            signed_at,
            action,
            object,
        })
    }

    /// `entry_hash` (the body only; a re-signed body is the same entry).
    pub fn hash(&self) -> Hash32 {
        self.hash
    }

    pub fn object(&self) -> &SignedObject {
        &self.object
    }

    /// The device this entry is about: the member it adds or the device
    /// whose roles or membership it changes.
    pub fn subject(&self) -> Option<&str> {
        match &self.action {
            Action::Genesis { member, .. }
            | Action::Add { member }
            | Action::RecoveryAdd { member } => Some(&member.device_id),
            Action::Remove { device_id } | Action::SetRoles { device_id, .. } => Some(device_id),
            _ => None,
        }
    }
}

fn field<'a>(object: &'a Map<String, Value>, name: &'static str) -> Result<&'a Value, Invalid> {
    object.get(name).ok_or(Invalid::Malformed(name))
}

fn str_field<'a>(object: &'a Map<String, Value>, name: &'static str) -> Result<&'a str, Invalid> {
    field(object, name)?
        .as_str()
        .ok_or(Invalid::Malformed(name))
}

fn u64_field(object: &Map<String, Value>, name: &'static str) -> Result<u64, Invalid> {
    field(object, name)?
        .as_u64()
        .ok_or(Invalid::Malformed(name))
}

fn hash_value(value: &Value, name: &'static str) -> Result<Hash32, Invalid> {
    value
        .as_str()
        .and_then(|text| Hash32::from_hex(text).ok())
        .ok_or(Invalid::Malformed(name))
}

/// Every key of `object` is in `allowed` (§R9.1: no unknown fields in a
/// signed body). Required fields are checked where they are read.
fn only_fields(object: &Map<String, Value>, allowed: &[&str]) -> Result<(), Invalid> {
    if object.keys().all(|key| allowed.contains(&key.as_str())) {
        Ok(())
    } else {
        Err(Invalid::UnknownField)
    }
}

/// A key object whose algorithm is one of `algs` (the field's pin).
fn key(value: &Value, algs: &[Alg]) -> Result<PublicKey, Invalid> {
    let key = PublicKey::from_json(value)?;
    if !algs.contains(&key.alg()) {
        return Err(Invalid::from(Error::WrongAlg));
    }
    Ok(key)
}

fn device_id(value: &Value) -> Result<String, Invalid> {
    let id = value.as_str().ok_or(Invalid::Malformed("device_id"))?;
    if !id_ok(id) || id == RECOVERY_SIGNER {
        return Err(Invalid::Malformed("device_id"));
    }
    Ok(id.to_owned())
}

/// A set of strings (the signed-object parse already checked order and
/// uniqueness).
fn string_set(value: &Value, name: &'static str) -> Result<Vec<String>, Invalid> {
    value
        .as_array()
        .ok_or(Invalid::Malformed(name))?
        .iter()
        .map(|item| item.as_str().map(str::to_owned))
        .collect::<Option<_>>()
        .ok_or(Invalid::Malformed(name))
}

fn native_roles(roles: &[String]) -> Result<BTreeSet<Role>, Invalid> {
    let set: BTreeSet<Role> = roles
        .iter()
        .map(|r| Role::parse(r))
        .collect::<Option<_>>()
        .ok_or(Invalid::BadRoles)?;
    if set.len() != roles.len() || !set.contains(&Role::View) {
        return Err(Invalid::BadRoles);
    }
    Ok(set)
}

fn exactly_all_roles(member: &Member) -> bool {
    matches!(&member.kind, MemberKind::Native { roles, .. }
        if *roles == BTreeSet::from([Role::Control, Role::Manage, Role::View]))
}

fn service_expiry(signed_at: u64, expires_at: u64) -> Result<(), Invalid> {
    if expires_at > signed_at.saturating_add(SERVICE_MAX_LIFETIME_MS) {
        return Err(Invalid::ServiceExpiry);
    }
    Ok(())
}

fn scope(value: &Value) -> Result<Scope, Invalid> {
    let object = value.as_object().ok_or(Invalid::BadScope)?;
    only_fields(object, &["hosts", "projects", "sessions", "ops"])?;
    let list = |name: &'static str, max: usize, ok: &dyn Fn(&str) -> bool| {
        object
            .get(name)
            .map(|v| {
                let items = string_set(v, name).map_err(|_| Invalid::BadScope)?;
                if items.is_empty() || items.len() > max || !items.iter().all(|i| ok(i)) {
                    return Err(Invalid::BadScope);
                }
                Ok(items)
            })
            .transpose()
    };
    let hosts = list("hosts", MAX_SCOPE_HOSTS, &id_ok)?.ok_or(Invalid::BadScope)?;
    let projects = list("projects", MAX_SCOPE_ITEMS, &project_hash_ok)?;
    let sessions = list("sessions", MAX_SCOPE_ITEMS, &session_id_ok)?;
    let ops = list("ops", OPS.len(), &|op| OPS.contains(&op))?.ok_or(Invalid::BadScope)?;
    if !ops.iter().any(|op| op == "view") {
        return Err(Invalid::BadScope);
    }
    Ok(Scope {
        hosts,
        projects,
        sessions,
        ops,
    })
}

/// `h1.<kid>.<64 lowercase hex>` (memory sync's keyed project hash).
fn project_hash_ok(text: &str) -> bool {
    let mut parts = text.splitn(3, '.');
    matches!(
        (parts.next(), parts.next(), parts.next()),
        (Some("h1"), Some(kid), Some(hash))
            if kid_ok(kid) && !kid.contains('.')
                && hash.len() == 64
                && hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    )
}

/// `ses-` + 12 lowercase base32 characters (atem's session ids).
fn session_id_ok(text: &str) -> bool {
    text.strip_prefix("ses-").is_some_and(|rest| {
        rest.len() == 12 && rest.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7'))
    })
}

fn member(value: &Value, signed_at: u64) -> Result<Member, Invalid> {
    let object = value.as_object().ok_or(Invalid::Malformed("member"))?;
    let device_id = device_id(field(object, "device_id")?)?;
    let auth_key = key(field(object, "auth_key")?, &[Alg::P256, Alg::Ed25519])?;
    let roles = string_set(field(object, "roles")?, "roles")?;
    let kind = match str_field(object, "kind")? {
        "native" => {
            only_fields(
                object,
                &["device_id", "kind", "auth_key", "enc_key", "roles"],
            )?;
            MemberKind::Native {
                enc_key: key(field(object, "enc_key")?, &[Alg::X25519])?,
                roles: native_roles(&roles)?,
            }
        }
        "service" => {
            only_fields(
                object,
                &[
                    "device_id",
                    "kind",
                    "auth_key",
                    "roles",
                    "scope",
                    "expires_at",
                ],
            )?;
            if roles != ["service"] {
                return Err(Invalid::BadRoles);
            }
            let expires_at = u64_field(object, "expires_at")?;
            service_expiry(signed_at, expires_at)?;
            MemberKind::Service {
                scope: scope(field(object, "scope")?)?,
                expires_at,
            }
        }
        _ => return Err(Invalid::Malformed("member kind")),
    };
    Ok(Member {
        device_id,
        auth_key,
        kind,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::b64u;
    use serde_json::json;

    fn p256_pub() -> String {
        // The P-256 generator point, uncompressed.
        let mut bytes = vec![4u8];
        bytes.extend(
            crate::encoding::hex_decode_array::<32>(
                "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
            )
            .unwrap(),
        );
        bytes.extend(
            crate::encoding::hex_decode_array::<32>(
                "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
            )
            .unwrap(),
        );
        b64u(&bytes)
    }

    fn body(extra: Value) -> Value {
        let mut body = json!({
            "type": "atem-membership-entry", "v": 1, "account_id": "acct",
            "genesis_hash": "ab".repeat(32), "seq": 2, "prev_hash": "cd".repeat(32),
            "signer": "dev-mac", "signed_at": 1000,
        });
        body.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        body
    }

    fn parse(body: Value) -> Result<Entry, Invalid> {
        let wire = json!({"body": body, "sig": "AA"});
        Entry::parse_bytes(wire.to_string().as_bytes())
    }

    fn native(roles: Value) -> Value {
        json!({"device_id": "dev-x", "kind": "native",
               "auth_key": {"alg": "p256", "pub": p256_pub()},
               "enc_key": {"alg": "x25519", "pub": b64u(&[9u8; 32])}, "roles": roles})
    }

    #[test]
    fn unknown_fields_are_refused_anywhere_in_the_body() {
        assert!(
            parse(body(
                json!({"action": "add", "member": native(json!(["view"]))})
            ))
            .is_ok()
        );
        assert_eq!(
            parse(body(
                json!({"action": "remove", "device_id": "a", "note": "x"})
            )),
            Err(Invalid::UnknownField)
        );
        let mut member = native(json!(["view"]));
        member["label"] = json!("phone");
        assert_eq!(
            parse(body(json!({"action": "add", "member": member}))),
            Err(Invalid::UnknownField)
        );
        // A field of another action is unknown here.
        assert_eq!(
            parse(body(
                json!({"action": "remove", "device_id": "a", "target": "00".repeat(32)})
            )),
            Err(Invalid::UnknownField)
        );
    }

    #[test]
    fn in_body_keys_have_fixed_algorithms() {
        let mut member = native(json!(["view"]));
        member["enc_key"] = json!({"alg": "ed25519", "pub": b64u(&[9u8; 32])});
        assert_eq!(
            parse(body(json!({"action": "add", "member": member}))),
            Err(Invalid::WrongAlg)
        );
        let mut member = native(json!(["view"]));
        member["auth_key"] = json!({"alg": "x25519", "pub": b64u(&[9u8; 32])});
        assert_eq!(
            parse(body(json!({"action": "add", "member": member}))),
            Err(Invalid::WrongAlg)
        );
        assert_eq!(
            parse(body(json!({"action": "set_recovery_key", "kit": "lost",
                               "recovery_key": {"alg": "p256", "pub": p256_pub()}}))),
            Err(Invalid::WrongAlg)
        );
        assert_eq!(
            parse(body(json!({"action": "add_host", "host": {"host_id": "h",
                "host_trust_gen": 1, "host_key": {"alg": "p256", "pub": p256_pub()}}}))),
            Err(Invalid::WrongAlg)
        );
    }

    #[test]
    fn roles_scope_and_ids_follow_their_rules() {
        for bad in [
            json!(["control"]),
            json!(["service"]),
            json!(["admin", "view"]),
        ] {
            assert_eq!(
                parse(body(json!({"action": "add", "member": native(bad)}))),
                Err(Invalid::BadRoles)
            );
        }
        let mut member = native(json!(["view"]));
        member["device_id"] = json!("recovery");
        assert!(parse(body(json!({"action": "add", "member": member}))).is_err());
        let service = |scope: Value, expires_at: u64| {
            json!({"device_id": "svc", "kind": "service",
                   "auth_key": {"alg": "p256", "pub": p256_pub()},
                   "roles": ["service"], "scope": scope, "expires_at": expires_at})
        };
        let ok_scope = json!({"hosts": ["host-a"], "ops": ["prompt", "view"]});
        assert!(
            parse(body(
                json!({"action": "add", "member": service(ok_scope.clone(), 1000)})
            ))
            .is_ok()
        );
        assert_eq!(
            parse(body(json!({"action": "add",
                "member": service(ok_scope.clone(), 1000 + SERVICE_MAX_LIFETIME_MS + 1)}))),
            Err(Invalid::ServiceExpiry)
        );
        for bad in [
            json!({"hosts": [], "ops": ["view"]}),
            json!({"hosts": ["h"], "ops": ["prompt"]}),
            json!({"hosts": ["h"], "ops": ["fly", "view"]}),
            json!({"hosts": ["h"], "ops": ["view"], "sessions": ["ses-x"]}),
            json!({"hosts": ["h"], "ops": ["view"], "projects": ["h1.k.zz"]}),
        ] {
            assert_eq!(
                parse(body(json!({"action": "add", "member": service(bad, 1000)}))),
                Err(Invalid::BadScope)
            );
        }
    }

    #[test]
    fn only_the_recovery_key_signs_recovery_add_and_nothing_else() {
        let mut b = body(json!({"action": "remove", "device_id": "dev-mac"}));
        b["signer"] = json!("recovery");
        assert_eq!(parse(b), Err(Invalid::RecoverySignerAction));
        let all = json!(["control", "manage", "view"]);
        assert_eq!(
            parse(body(
                json!({"action": "recovery_add", "member": native(all)})
            )),
            Err(Invalid::RecoverySignerAction)
        );
    }

    #[test]
    fn genesis_has_its_own_shape() {
        let all = json!(["control", "manage", "view"]);
        let recovery = crate::kit::recovery_key_of_seed(&[1u8; 32]).to_json();
        let mut b = body(json!({"action": "genesis", "member": native(all),
            "recovery_key": recovery}));
        b.as_object_mut().unwrap().remove("genesis_hash");
        b["seq"] = json!(1);
        b["prev_hash"] = json!("00".repeat(32));
        b["signer"] = json!("dev-x");
        assert_eq!(parse(b.clone()).unwrap().action.name(), "genesis");
        let mut at_two = b.clone();
        at_two["seq"] = json!(2);
        assert_eq!(parse(at_two), Err(Invalid::BadGenesis));
        b["signer"] = json!("dev-y");
        assert_eq!(parse(b), Err(Invalid::BadGenesis));
    }
}
