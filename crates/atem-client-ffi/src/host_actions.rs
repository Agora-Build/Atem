//! The five device-list actions of delegated host work (design II.2.2,
//! II.3.1, II.4.1) and what they derive, through the bindings:
//!
//! - **Builders** (`project_set_action`, `project_remove_action`,
//!   `host_sender_revoke_action`, `host_sender_readmit_action`,
//!   `host_enc_key_action`) return the action JSON `MembershipLog::
//!   check_change` and `draft_entry` take, already checked by the
//!   verifier's own structural parse (as `service_add_action` does): a shape
//!   the verifier refuses on its own is its refusal here (`Membership`
//!   `bad_project`, `malformed`, `wrong_alg`). Whether the entry is valid
//!   on a chain (hosts current, a project in effect, a host's state, its
//!   key binding) is the verifier's, after signing; `check_change` advises
//!   on a redundant revoke or readmit.
//! - **`verify_host_enc_sig`**: a host's `enc_sig` over its `enc_key`,
//!   checked with its `host_key` as the manager receives the pair from the
//!   host, before it signs `host_enc_key_action`.
//! - **Queries** on the verified log: a host's sending state and membership
//!   epoch, the projects in effect, and a host's encryption keys.
//!
//! The host signs its own `enc_sig` in Rust (it has no binding label); a
//! manager's signature over the entry asks its key store under the
//! purposes `Project`, `HostSender` and `HostEncKey` (a fresh confirmation
//! of the exact body, R9.6 rule 4). Atem itself never signs these entries;
//! Astation signs them only once every strict verifier of the account knows
//! the actions (the signing gate, II.2.2).
use atem_client::encoding::b64u_decode;
use atem_client::membership::{
    self, HostEncKeys, HostSenderState, Invalid, Project, ProjectOp, verify_host_enc_sig as verify,
};

use crate::encoding::{hash_of, safe_int};
use crate::error::{AtemError, Result};
use crate::log::MembershipLog;
use crate::service::action_json;
use crate::types::{
    HostEncKeyInfo, HostEncKeysInfo, HostSenderStateInfo, PreviousHostEncKeyInfo, ProjectInfo,
    PublicKeyData,
};

/// A `project_set` (the project's whole new state: every listed host a
/// member, replacing any earlier state of that name). `name` is 1 to 32
/// characters of `[a-z0-9-]`, `hosts` 2 to 64 host ids and `ops` from
/// `launch`, `message`, `notify`, `prompt` (`notify` needs `message` and
/// `prompt` with it); both lists in any order, duplicates dropped. Returns
/// the action JSON `{"action":"project_set","project":{…}}`; a shape the
/// verifier refuses is `Membership` `bad_project`. That each host is
/// current is checked against the chain.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn project_set_action(
    name: String,
    hosts: Vec<String>,
    ops: Vec<String>,
    signed_at: u64,
) -> Result<String> {
    let ops = ops
        .iter()
        .map(|op| ProjectOp::parse(op).ok_or(Invalid::BadProject))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let action = membership::project_set(&name, hosts, ops, safe_int(signed_at, "signed_at")?)?;
    action_json(&action)
}

/// A `project_remove` of the project `name` (it must be in effect: the
/// verifier refuses another with `not_a_project`).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn project_remove_action(name: String, signed_at: u64) -> Result<String> {
    action_json(&membership::project_remove(
        &name,
        safe_int(signed_at, "signed_at")?,
    )?)
}

/// A `host_sender_revoke` of `host_id` (a host an `add_host` named, current
/// or removed, and authorized: `unknown_host` / `already_revoked` are the
/// verifier's). `interrupt_running` asks each receiving host for an
/// interrupt intent for the tasks it already started from that host.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn host_sender_revoke_action(
    host_id: String,
    interrupt_running: bool,
    signed_at: u64,
) -> Result<String> {
    action_json(&membership::host_sender_revoke(
        &host_id,
        interrupt_running,
        safe_int(signed_at, "signed_at")?,
    )?)
}

/// A `host_sender_readmit` of `host_id` (it must be revoked: the verifier
/// refuses another with `not_revoked`).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn host_sender_readmit_action(host_id: String, signed_at: u64) -> Result<String> {
    action_json(&membership::host_sender_readmit(
        &host_id,
        safe_int(signed_at, "signed_at")?,
    )?)
}

/// A `host_enc_key` for `host_id` at its `host_trust_gen`: `enc_key` is
/// X25519 (`wrong_alg` otherwise) and `enc_sig_b64u` the host's own
/// signature over it (64 bytes of strict base64url; check it with
/// `verify_host_enc_sig` first). `retire_previous` retires the key this one
/// replaces at once (after a suspected compromise); false is omitted from
/// the body (its only form). That the host is current, the generation its
/// newest, `enc_sig` valid and the key another than its current one is the
/// verifier's to judge.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn host_enc_key_action(
    host_id: String,
    host_trust_gen: u64,
    enc_key: PublicKeyData,
    enc_sig_b64u: String,
    retire_previous: bool,
    signed_at: u64,
) -> Result<String> {
    let enc_sig = b64u_decode(&enc_sig_b64u).map_err(|_| AtemError::malformed("enc_sig"))?;
    let action = membership::host_enc_key(
        &host_id,
        safe_int(host_trust_gen, "host_trust_gen")?,
        &enc_key.to_key()?,
        &enc_sig,
        retire_previous,
        safe_int(signed_at, "signed_at")?,
    )?;
    action_json(&action)
}

/// Whether `enc_sig_b64u` is `host_key`'s signature (Ed25519, strict) over
/// `enc_key` for this account, genesis, host and trust generation: the
/// binding a `host_enc_key` entry carries, which the verifier checks again
/// against the host's `add_host`. `false` for anything else, a value that
/// isn't a key, a hash or a signature included.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn verify_host_enc_sig(
    host_key: PublicKeyData,
    account_id: String,
    genesis_hash: String,
    host_id: String,
    host_trust_gen: u64,
    enc_key: PublicKeyData,
    enc_sig_b64u: String,
) -> bool {
    let check = || -> Result<()> {
        let host_key = host_key.to_key()?;
        let enc_key = enc_key.to_key()?;
        let enc_pub = enc_key
            .as_32()
            .filter(|_| enc_key.alg() == atem_client::keys::Alg::X25519)
            .ok_or_else(|| AtemError::malformed("enc_key is an X25519 key"))?;
        let sig = b64u_decode(&enc_sig_b64u)?;
        Ok(verify(
            &host_key,
            &account_id,
            &hash_of(&genesis_hash)?,
            &host_id,
            host_trust_gen,
            enc_pub,
            &sig,
        )?)
    };
    check().is_ok()
}

fn project_info(project: &Project, members: Vec<&str>) -> ProjectInfo {
    ProjectInfo {
        name: project.name.clone(),
        hosts: project.hosts.clone(),
        members: members.into_iter().map(str::to_owned).collect(),
        ops: project
            .ops
            .iter()
            .map(|op| op.as_str().to_owned())
            .collect(),
    }
}

fn enc_key_info(key: &membership::EncKey) -> HostEncKeyInfo {
    HostEncKeyInfo {
        enc_kid: key.kid.iter().map(|b| format!("{b:02x}")).collect(),
        key: (&key.key).into(),
        seq: key.seq,
        host_trust_gen: key.host_trust_gen,
    }
}

fn enc_keys_info(keys: &HostEncKeys) -> HostEncKeysInfo {
    HostEncKeysInfo {
        current: enc_key_info(&keys.current),
        previous: keys.previous.as_ref().map(|p| PreviousHostEncKeyInfo {
            key: enc_key_info(&p.key),
            retired: p.retired,
            replaced_at_seq: p.replaced_at_seq,
        }),
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl MembershipLog {
    /// `host_id`'s sending authorization (II.3.1): `None` for a host no
    /// `add_host` ever named. A removed host keeps its state (it can't send
    /// while it isn't a current host, `host`); a re-verification, a removal
    /// and a re-add never change it, only a revoke or readmit does.
    pub fn host_sender_state(&self, host_id: String) -> Option<HostSenderStateInfo> {
        self.lock()
            .host_sender_state(&host_id)
            .map(|state| match state {
                HostSenderState::Authorized { generation } => {
                    HostSenderStateInfo::Authorized { generation }
                }
                HostSenderState::Revoked { seq } => HostSenderStateInfo::Revoked { seq },
            })
    }

    /// `host_id`'s membership epoch: the `seq` of its first `add_host` after
    /// its last `remove_host`; `None` for a host never added, or removed and
    /// not added again.
    pub fn host_membership_epoch(&self, host_id: String) -> Option<u64> {
        self.lock().host_membership_epoch(&host_id)
    }

    /// The projects in effect (set and not removed), by name. A project
    /// whose hosts were all removed stays (with no `members`) until a
    /// `project_remove`.
    pub fn projects(&self) -> Vec<ProjectInfo> {
        let log = self.lock();
        log.projects()
            .map(|project| project_info(project, log.project_hosts(&project.name)))
            .collect()
    }

    /// The names of the projects `host_id`'s membership of is in effect, in
    /// order.
    pub fn host_projects(&self, host_id: String) -> Vec<String> {
        self.lock()
            .host_projects(&host_id)
            .into_iter()
            .map(str::to_owned)
            .collect()
    }

    /// What `a` and `b` may send each other: the union of the ops of every
    /// project in effect that both are members of, sorted. Empty when `a`
    /// is `b` (a project lets a host reach the other hosts it lists).
    pub fn project_ops_between(&self, a: String, b: String) -> Vec<String> {
        self.lock()
            .project_ops_between(&a, &b)
            .into_iter()
            .map(|op| op.as_str().to_owned())
            .collect()
    }

    /// `host_id`'s encryption keys for its current trust generation (II.4.1),
    /// as its `host_enc_key` entries set them; `None` for a host that isn't
    /// current, or has no entry for its newest `add_host` (a re-verification
    /// and a removal void the keys).
    pub fn host_enc_key(&self, host_id: String) -> Option<HostEncKeysInfo> {
        self.lock().host_enc_key(&host_id).map(enc_keys_info)
    }
}
