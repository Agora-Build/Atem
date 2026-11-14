//! Verifying a control record against the device list (delegated host-work
//! design I.5.4): which key may sign which action, with the key and its
//! algorithm taken from the device-list entry of the signer the body
//! names, never from the object (R9.1, III.1).
//!
//! **Who signs.**
//! - **The principal's own key** signs every action of a service
//!   (`signer` equal to `principal`): any `auth_key` the service had in the
//!   account's device-list history ([`Membership::keys_ever`]), even after
//!   its grant expired or it was removed, and the one whose SHA-256 the
//!   body's `principal_key` names. That value is the integration's `r9Svc`
//!   ([`principal_key_of`]), so a Station can cross-check records against
//!   the Portal feed.
//! - **A current native manager** (`member:<device_id>`) signs `revoke`
//!   and `interrupt_running` only, for any principal: a `native` member
//!   holding `manage` at this list's head, under its pinned algorithm
//!   ([`Membership::current_manager_key`]). It never signs `cover`, `hold`
//!   or `release`. A service record it signs still names the principal's
//!   key.
//! - **Removed managers** (the strict rule): a record whose native signer
//!   was removed or lost `manage` in the list it is checked against is
//!   refused; Astation re-signs it with a current manager.
//! - **Host principals** (`host:<host_id>`): the only record is a native
//!   manager's `interrupt_running`; the host's own key signs nothing. The
//!   host must have an `add_host` in the log, current or removed, and the
//!   record's `revoke_seq` must name this list's `host_sender_revoke` of
//!   that host: beyond the head it is pending, any other entry is
//!   refused. A readmit since changes nothing: the interrupt is for
//!   the tasks admitted before that revoke (II.3.1). Whether the host
//!   applied that revoke (its applied device-list `seq` reached it) is the
//!   application's (I.5.5). A host principal's `release` (or `cover`,
//!   `hold`, `revoke`) never gets here: [`ControlRecord::parse`] refuses it
//!   (`not_for_host_principal`).
//!
//! **Pending** (I.5.4, "Verification"): a principal or native signer the
//! list doesn't hold yet (a `recovery_add` still waiting holds nothing), or
//! a host principal's `revoke_seq` beyond its head, to be verified again
//! after every device-list advance.
//!
//! **The verdict is relative to the list given.** It is a pure function of
//! the record and that list, and another list can give another verdict: a
//! native without `manage` signs validly once a `set_roles` gives it
//! `manage`, a demoted manager once it is promoted again. What is final is
//! what the host does with a refused record (kept as evidence, the scan
//! cursor moves past it, I.5.4), which is the application's.
//!
//! **Order.** Nothing the list doesn't hold yet is refused for the signer's
//! current roles:
//! 1. the account;
//! 2. what no later entry can make valid: a host's own key, a manager's
//!    `cover`, `hold` or `release`, and a `member:` signer that is removed,
//!    cancelled (ids are never reused) or a service (a member's kind never
//!    changes);
//! 3. the principal: one the list doesn't hold yet waits; then a native
//!    principal, the principal's key, a host's `revoke_seq` naming another
//!    entry (a committed entry never changes) or beyond the head (waits);
//! 4. the signer: one the list doesn't hold yet waits; an active native
//!    without `manage` is refused;
//! 5. the signature.
//!
//! The verdict holds for the list it was checked against: a host verifies
//! a record against the head of the transaction that applies it, never a
//! verdict from before (a manager removed in between is caught).
use crate::keys::PublicKey;
use crate::membership::{Action, Head, MemberKind, MemberStatus, Membership};

use super::record::{
    ControlAction, ControlPrincipal, ControlRecord, ControlSigner, principal_key_of,
};

/// The verdict on a record, against one device list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlCheck {
    /// Signed by a key allowed to sign it: the host applies it per I.5.5,
    /// never while its device list is frozen or held.
    Valid(VerifiedControl),
    /// Stored, and verified again after every device-list advance.
    Pending(PendingReason),
    /// Refused against this list. The host keeps it as evidence, skips it
    /// and reports it `refused` (I.5.4).
    Refused(RefusalReason),
}

/// What a valid record was verified with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedControl {
    /// Whose key verified it.
    pub signer: VerifiedSigner,
    /// The head of the list it was verified against.
    pub head: Head,
}

/// Whose key verified a valid record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifiedSigner {
    /// The service's own key, from the entry at `key_seq` (its `add`).
    Principal { key_seq: u64 },
    /// A current native manager.
    Manager { device_id: String },
}

/// Why a record waits. [`verify_control`] gives the first three;
/// [`ControlState::apply`](super::state::ControlState::apply) the others,
/// for a record that verified (or one it never verifies, on a frozen list).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingReason {
    /// The list has no member `service:<id>` names, or no `add_host` of the
    /// host `host:<host_id>` names, yet.
    PrincipalUnknown,
    /// The list has no native member `member:<device_id>` names yet, or one
    /// whose `recovery_add` is still waiting.
    SignerUnknown,
    /// A host principal's `revoke_seq` is beyond the list's head.
    RevokeNotInList,
    /// The device list is frozen (R9.4): nothing new applies until it is
    /// reconciled.
    ListFrozen,
    /// A service's `interrupt_running`: the service isn't revoked on this
    /// host yet (I.5.5 step 3).
    NotRevoked,
    /// A host principal's `interrupt_running`: host-work's applied
    /// device-list `seq` hasn't reached its `revoke_seq` (II.3.1).
    RevokeNotApplied,
}

impl PendingReason {
    /// A stable name.
    pub fn code(self) -> &'static str {
        match self {
            PendingReason::PrincipalUnknown => "principal_unknown",
            PendingReason::SignerUnknown => "signer_unknown",
            PendingReason::RevokeNotInList => "revoke_not_in_list",
            PendingReason::ListFrozen => "list_frozen",
            PendingReason::NotRevoked => "not_revoked",
            PendingReason::RevokeNotApplied => "revoke_not_applied",
        }
    }

    /// Every reason, in declaration order.
    pub const ALL: [PendingReason; 6] = [
        PendingReason::PrincipalUnknown,
        PendingReason::SignerUnknown,
        PendingReason::RevokeNotInList,
        PendingReason::ListFrozen,
        PendingReason::NotRevoked,
        PendingReason::RevokeNotApplied,
    ];
}

/// Why a record is refused. A host principal's record other than
/// `interrupt_running` is refused at parse
/// (`ControlError::NotForHostPrincipal`), so it has no reason here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalReason {
    /// Its `account_id` or `genesis_hash` isn't this list's.
    WrongAccount,
    /// The signature doesn't verify under the named signer's key.
    BadSignature,
    /// A service record's `principal_key` names no key the principal ever
    /// had.
    KeyMismatch,
    /// A native manager's `cover`, `hold` or `release`, or a `member:`
    /// signer that never was a native manager in this list (a native
    /// without `manage`, a service, a `recovery_add` that was cancelled).
    SignerNotAllowed,
    /// Its native signer was a manager in this list and was removed or lost
    /// `manage` since (its signature verified under its key).
    RemovedManager,
    /// A host principal's record naming the host as its signer: a host's
    /// own key signs nothing.
    HostKeySigned,
    /// `service:<id>` names a native member, which is never a control
    /// record's principal.
    NotAService,
    /// A host principal's `revoke_seq` names an entry that isn't a
    /// `host_sender_revoke` of that host.
    NotARevoke,
}

impl RefusalReason {
    /// A stable name.
    pub fn code(self) -> &'static str {
        match self {
            RefusalReason::WrongAccount => "wrong_account",
            RefusalReason::BadSignature => "bad_signature",
            RefusalReason::KeyMismatch => "key_mismatch",
            RefusalReason::SignerNotAllowed => "signer_not_allowed",
            RefusalReason::RemovedManager => "removed_manager",
            RefusalReason::HostKeySigned => "host_key_signed",
            RefusalReason::NotAService => "not_a_service",
            RefusalReason::NotARevoke => "not_a_revoke",
        }
    }

    /// Every reason, in declaration order.
    pub const ALL: [RefusalReason; 8] = [
        RefusalReason::WrongAccount,
        RefusalReason::BadSignature,
        RefusalReason::KeyMismatch,
        RefusalReason::SignerNotAllowed,
        RefusalReason::RemovedManager,
        RefusalReason::HostKeySigned,
        RefusalReason::NotAService,
        RefusalReason::NotARevoke,
    ];
}

/// Verifies `rec` against `list`, the device list at the head the host
/// applies it on (I.5.4; the module docs give the rules and their order).
///
/// `Valid` means the record is signed by a key allowed to sign it, nothing
/// more: the host never applies a record while its device list is frozen
/// (R9.4) or the host is held after a write fault (R9.3), whatever this
/// says; it applies it per I.5.5.
pub fn verify_control(rec: &ControlRecord, list: &Membership) -> ControlCheck {
    if rec.account_id() != list.account_id() || rec.genesis_hash() != list.genesis_hash() {
        return ControlCheck::Refused(RefusalReason::WrongAccount);
    }
    let verdict = match rec.signer() {
        ControlSigner::Principal => by_principal(rec, list),
        ControlSigner::Member(device_id) => by_manager(rec, list, device_id),
    };
    match verdict {
        Ok(signer) => ControlCheck::Valid(VerifiedControl {
            signer,
            head: list.head(),
        }),
        Err(check) => check,
    }
}

type Verdict<T> = Result<T, ControlCheck>;

fn refused(reason: RefusalReason) -> ControlCheck {
    ControlCheck::Refused(reason)
}

fn pending(reason: PendingReason) -> ControlCheck {
    ControlCheck::Pending(reason)
}

/// Signed by the principal itself: a service's key from the history.
fn by_principal(rec: &ControlRecord, list: &Membership) -> Verdict<VerifiedSigner> {
    let ControlPrincipal::Service(id) = rec.principal() else {
        return Err(refused(RefusalReason::HostKeySigned));
    };
    let (key_seq, key) = service_key(rec, list, id)?;
    signed_by(rec, &key)?;
    Ok(VerifiedSigner::Principal { key_seq })
}

/// Signed by `member:<device_id>`: a current native manager, `revoke` and
/// `interrupt_running` only.
fn by_manager(rec: &ControlRecord, list: &Membership, device_id: &str) -> Verdict<VerifiedSigner> {
    if !matches!(
        rec.action(),
        ControlAction::Revoke { .. } | ControlAction::InterruptRunning { .. }
    ) {
        return Err(refused(RefusalReason::SignerNotAllowed));
    }
    let standing = standing(rec, list, device_id)?;
    match rec.principal() {
        ControlPrincipal::Service(id) => {
            service_key(rec, list, id)?;
        }
        ControlPrincipal::Host(host_id) => host_revoke(rec, list, host_id)?,
    }
    let key = match standing {
        Standing::Manager(key) => key,
        Standing::Unknown => return Err(pending(PendingReason::SignerUnknown)),
        Standing::NotManager => return Err(refused(not_a_manager(rec, list, device_id))),
    };
    signed_by(rec, &key)?;
    Ok(VerifiedSigner::Manager {
        device_id: device_id.to_owned(),
    })
}

/// A `member:` signer's standing on this list.
enum Standing {
    /// A current native manager, with its key.
    Manager(PublicKey),
    /// Not in the list yet, or a `recovery_add` still waiting.
    Unknown,
    /// An active native without `manage` (never given it, or demoted): a
    /// later `set_roles` can give it `manage`, so it is refused only after
    /// what the list doesn't hold yet waited.
    NotManager,
}

/// The signer's standing, or its refusal when no later entry can make it a
/// manager: removed, or its `recovery_add` cancelled (ids are never
/// reused), or a service (a member's kind never changes).
fn standing(rec: &ControlRecord, list: &Membership, device_id: &str) -> Verdict<Standing> {
    if let Some(key) = list.current_manager_key(device_id) {
        return Ok(Standing::Manager(key));
    }
    let Some(state) = list.member(device_id) else {
        return Ok(Standing::Unknown);
    };
    match (&state.member.kind, state.status) {
        (_, MemberStatus::Pending { .. }) => Ok(Standing::Unknown),
        (MemberKind::Native { .. }, MemberStatus::Active) => Ok(Standing::NotManager),
        _ => Err(refused(not_a_manager(rec, list, device_id))),
    }
}

/// Why a signer that isn't a current manager is refused: one that was a
/// manager (removed, or lost `manage`) is `RemovedManager` once its key
/// from the history verifies the record, else `BadSignature` (a forgery in
/// its name); any other is `SignerNotAllowed`.
fn not_a_manager(rec: &ControlRecord, list: &Membership, device_id: &str) -> RefusalReason {
    if !list.was_manager(device_id) {
        return RefusalReason::SignerNotAllowed;
    }
    let signed = list
        .keys_ever(device_id)
        .iter()
        .any(|(_, key)| signed_by(rec, key).is_ok());
    if signed {
        RefusalReason::RemovedManager
    } else {
        RefusalReason::BadSignature
    }
}

/// The service `id`'s key the record's `principal_key` names, with the
/// `seq` of the entry that gave it.
fn service_key(rec: &ControlRecord, list: &Membership, id: &str) -> Verdict<(u64, PublicKey)> {
    let state = list
        .member(id)
        .ok_or(pending(PendingReason::PrincipalUnknown))?;
    if !matches!(state.member.kind, MemberKind::Service { .. }) {
        return Err(refused(RefusalReason::NotAService));
    }
    let named = rec
        .principal_key()
        .ok_or(refused(RefusalReason::KeyMismatch))?;
    list.keys_ever(id)
        .into_iter()
        .find(|(_, key)| principal_key_of(key).is_ok_and(|hash| hash == named))
        .ok_or(refused(RefusalReason::KeyMismatch))
}

/// A host principal's `revoke_seq` names this list's `host_sender_revoke`
/// of `host_id`. An entry there that isn't one is refused,
/// whatever the list holds later (a committed entry never changes); beyond
/// the head, the record waits (after an unknown host, which can't have a
/// revoke in the list yet).
fn host_revoke(rec: &ControlRecord, list: &Membership, host_id: &str) -> Verdict<()> {
    // The parse gives a host principal's record exactly this form.
    let ControlAction::InterruptRunning {
        revoke_seq: Some(seq),
    } = rec.action()
    else {
        return Err(refused(RefusalReason::NotARevoke));
    };
    match list.entry(seq).map(|entry| &entry.action) {
        Some(Action::HostSenderRevoke {
            host_id: revoked, ..
        }) if revoked == host_id => Ok(()),
        Some(_) => Err(refused(RefusalReason::NotARevoke)),
        None if list.host_sender_state(host_id).is_none() => {
            Err(pending(PendingReason::PrincipalUnknown))
        }
        None => Err(pending(PendingReason::RevokeNotInList)),
    }
}

fn signed_by(rec: &ControlRecord, key: &PublicKey) -> Verdict<()> {
    rec.object()
        .verify(key)
        .map_err(|_| refused(RefusalReason::BadSignature))
}

#[cfg(test)]
mod verify_control_tests {
    use super::*;
    use crate::control::record::{
        ControlAbout, ControlAction, ControlBody, ControlError, ControlFeed, ControlPrincipal,
        ControlSigner, build_control, principal_key_of,
    };
    use crate::encoding::{Hash32, hex};
    use crate::keys::PublicKey;
    use crate::membership::entry::{
        Action, HostRecord, Member, MemberKind, RECOVERY_SIGNER, Role, RolesChange,
    };
    use crate::membership::{
        Check, HostNow, Invalid, ServiceScope, draft_on, host_sender_readmit, host_sender_revoke,
        service_add, service_key_fingerprint, service_renewal, sign_entry,
    };
    use crate::provider::{KeyId, KeyProvider};
    use crate::signed::SignedObject;
    use crate::software::SoftwareKeys;
    use serde_json::json;

    const ACCOUNT: &str = "acct-test-1";
    const T0: u64 = 1_800_000_000_000;
    const HOUR: u64 = 3_600_000;
    const ORIGIN: &str = "https://station-dev.agora.build";
    const FEED: &str = "6f1c2b3a-4d5e-4f60-8a7b-9c0d1e2f3a4b";
    const RECORD: &str = "0b9a8c7d-6e5f-4a3b-9c2d-1e0f2a3b4c5d";
    const INTEGRATION: &str = "i-01jc5zq9x8w7v6t5s4r3q2p1n0";
    const ALL: [Role; 3] = [Role::Control, Role::Manage, Role::View];
    /// `account()`'s entries: the services' `add` and the host's `add_host`.
    const SVC_1_SEQ: u64 = 4;
    const SVC_ED_SEQ: u64 = 5;
    const HOST_A_SEQ: u64 = 6;

    const SERVICE_ACTIONS: [ControlAction; 6] = [
        ControlAction::Cover,
        ControlAction::Revoke {
            interrupt_running: false,
        },
        ControlAction::Revoke {
            interrupt_running: true,
        },
        ControlAction::Hold,
        ControlAction::Release,
        ControlAction::InterruptRunning { revoke_seq: None },
    ];
    const MANAGER_ACTIONS: [ControlAction; 3] = [
        ControlAction::Revoke {
            interrupt_running: false,
        },
        ControlAction::Revoke {
            interrupt_running: true,
        },
        ControlAction::InterruptRunning { revoke_seq: None },
    ];

    /// Every signing key, named by the id it signs as: natives `mac` (P-256,
    /// as Astation's Secure Enclave key), `phone` (Ed25519), `ipad`,
    /// `dev-new` and `dev-kit`; services `svc-1` (P-256), `svc-ed` (Ed25519)
    /// and `svc-new`; the host `host-a`; the Recovery Kit `kit`. Natives'
    /// encryption keys are `enc-<id>`.
    fn keys() -> SoftwareKeys {
        let mut keys = SoftwareKeys::new();
        keys.insert_p256(KeyId::new("mac"), &[1; 32]).unwrap();
        keys.insert_ed25519(KeyId::new("phone"), &[2; 32]);
        keys.insert_p256(KeyId::new("ipad"), &[3; 32]).unwrap();
        keys.insert_ed25519(KeyId::new("dev-new"), &[4; 32]);
        keys.insert_p256(KeyId::new("dev-kit"), &[5; 32]).unwrap();
        keys.insert_p256(KeyId::new("svc-1"), &[6; 32]).unwrap();
        keys.insert_ed25519(KeyId::new("svc-ed"), &[7; 32]);
        keys.insert_ed25519(KeyId::new("svc-new"), &[8; 32]);
        keys.insert_ed25519(KeyId::new("host-a"), &[9; 32]);
        keys.insert_ed25519(KeyId::new("host-b"), &[11; 32]);
        keys.insert_ed25519(KeyId::new("kit"), &[10; 32]);
        for (i, id) in ["mac", "phone", "ipad", "dev-new", "dev-kit"]
            .into_iter()
            .enumerate()
        {
            keys.insert_x25519(KeyId::new(format!("enc-{id}")), &[20 + i as u8; 32]);
        }
        keys
    }

    fn key(keys: &SoftwareKeys, id: &str) -> PublicKey {
        keys.public_key(&KeyId::new(id)).unwrap()
    }

    fn native(keys: &SoftwareKeys, id: &str, roles: &[Role]) -> Member {
        Member {
            device_id: id.into(),
            auth_key: key(keys, id),
            kind: MemberKind::Native {
                enc_key: key(keys, &format!("enc-{id}")),
                roles: roles.iter().copied().collect(),
            },
        }
    }

    fn now(at: u64) -> HostNow {
        HostNow {
            wall_ms: at,
            mono_ms: at,
            boot_id: "b".into(),
        }
    }

    /// `action` signed by `signer` (its key, or the kit's for a
    /// `recovery_add`), carried to the list as a verifier takes it. Returns
    /// its `seq`.
    fn append(list: &mut Membership, keys: &SoftwareKeys, signer: &str, action: Action) -> u64 {
        let at = T0 + list.head().seq;
        let key_id = if signer == RECOVERY_SIGNER {
            "kit"
        } else {
            signer
        };
        let body = list.draft(signer, at, &action);
        let entry = sign_entry(keys, &KeyId::new(key_id), body).unwrap();
        let eval = list.evaluate_objects(&[entry.object().clone()], &now(at));
        assert_eq!(eval.stop, None, "{action:?}");
        *list = eval.next;
        list.head().seq
    }

    /// The account: managers `mac` (P-256) and `phone` (Ed25519), `ipad`
    /// (control and view, never manage), the services `svc-1` (P-256) and
    /// `svc-ed` (Ed25519), whose grants end at `T0 + HOUR`, and the host
    /// `host-a`.
    fn account(keys: &SoftwareKeys) -> Membership {
        let body = draft_on(
            ACCOUNT,
            &Hash32([0; 32]),
            1,
            &Hash32([0; 32]),
            "mac",
            T0,
            &Action::Genesis {
                member: native(keys, "mac", &ALL),
                recovery_key: key(keys, "kit"),
            },
        );
        let genesis = sign_entry(keys, &KeyId::new("mac"), body).unwrap();
        let mut list = Membership::from_genesis(ACCOUNT, &genesis.hash(), genesis).unwrap();
        for (id, roles) in [("phone", &ALL[..]), ("ipad", &[Role::Control, Role::View])] {
            let member = native(keys, id, roles);
            append(&mut list, keys, "mac", Action::Add { member });
        }
        for (id, seq) in [("svc-1", SVC_1_SEQ), ("svc-ed", SVC_ED_SEQ)] {
            let scope = ServiceScope::new(["host-a"]);
            let action = service_add(id, key(keys, id), &scope, T0 + HOUR, T0).unwrap();
            assert_eq!(append(&mut list, keys, "mac", action), seq);
        }
        let host = HostRecord {
            host_id: "host-a".into(),
            host_trust_gen: 1,
            host_key: key(keys, "host-a"),
        };
        let seq = append(&mut list, keys, "mac", Action::AddHost { host });
        assert_eq!(seq, HOST_A_SEQ);
        list
    }

    /// `host-a`'s `host_sender_revoke`, signed by `mac`; returns its `seq`.
    fn revoke_host(list: &mut Membership, keys: &SoftwareKeys, host_id: &str) -> u64 {
        let action = host_sender_revoke(host_id, false, T0).unwrap();
        append(list, keys, "mac", action)
    }

    /// A record about the service `principal`, signed as `signer` (the
    /// principal itself, or `member:<signer>`), issued after the grant
    /// ended.
    fn service_body(
        list: &Membership,
        keys: &SoftwareKeys,
        principal: &str,
        signer: &str,
        action: ControlAction,
    ) -> ControlBody {
        ControlBody {
            account_id: list.account_id().into(),
            genesis_hash: list.genesis_hash(),
            feed: Some(ControlFeed {
                origin: ORIGIN.into(),
                feed_id: FEED.into(),
            }),
            principal: ControlPrincipal::Service(principal.into()),
            principal_key: Some(principal_key_of(&key(keys, principal)).unwrap()),
            signer: if signer == principal {
                ControlSigner::Principal
            } else {
                ControlSigner::Member(signer.into())
            },
            action,
            record_id: RECORD.into(),
            issued_at: T0 + 2 * HOUR,
            about: ControlAbout {
                integration_id: Some(INTEGRATION.into()),
                by: "owner".into(),
            },
        }
    }

    /// A host principal's `interrupt_running` after the revoke at
    /// `revoke_seq`.
    fn host_body(
        list: &Membership,
        host_id: &str,
        signer: ControlSigner,
        revoke_seq: u64,
    ) -> ControlBody {
        ControlBody {
            account_id: list.account_id().into(),
            genesis_hash: list.genesis_hash(),
            feed: None,
            principal: ControlPrincipal::Host(host_id.into()),
            principal_key: None,
            signer,
            action: ControlAction::InterruptRunning {
                revoke_seq: Some(revoke_seq),
            },
            record_id: RECORD.into(),
            issued_at: T0 + 2 * HOUR,
            about: ControlAbout {
                integration_id: None,
                by: "owner".into(),
            },
        }
    }

    fn manager(id: &str) -> ControlSigner {
        ControlSigner::Member(id.into())
    }

    /// `body` signed with the key `key_id`, verified against `list`.
    fn check(
        list: &Membership,
        keys: &SoftwareKeys,
        key_id: &str,
        body: &ControlBody,
    ) -> ControlCheck {
        let object = build_control(keys, &KeyId::new(key_id), body).unwrap();
        verify_control(&ControlRecord::from_signed(object).unwrap(), list)
    }

    fn valid(list: &Membership, signer: VerifiedSigner) -> ControlCheck {
        ControlCheck::Valid(VerifiedControl {
            signer,
            head: list.head(),
        })
    }

    fn by_principal(key_seq: u64) -> VerifiedSigner {
        VerifiedSigner::Principal { key_seq }
    }

    fn by_manager(id: &str) -> VerifiedSigner {
        VerifiedSigner::Manager {
            device_id: id.into(),
        }
    }

    fn refused(reason: RefusalReason) -> ControlCheck {
        ControlCheck::Refused(reason)
    }

    fn pending(reason: PendingReason) -> ControlCheck {
        ControlCheck::Pending(reason)
    }

    #[test]
    fn service_self_signed_all_actions_valid() {
        let keys = keys();
        let list = account(&keys);
        for (principal, seq) in [("svc-1", SVC_1_SEQ), ("svc-ed", SVC_ED_SEQ)] {
            for action in SERVICE_ACTIONS {
                let body = service_body(&list, &keys, principal, principal, action);
                assert_eq!(
                    check(&list, &keys, principal, &body),
                    valid(&list, by_principal(seq)),
                    "{principal} {action:?}"
                );
            }
            // The key and its algorithm are the list's: any other key fails,
            // a manager's included.
            let body = service_body(&list, &keys, principal, principal, ControlAction::Hold);
            for other in ["svc-1", "svc-ed", "mac", "phone"] {
                if other != principal {
                    assert_eq!(
                        check(&list, &keys, other, &body),
                        refused(RefusalReason::BadSignature),
                        "{principal} signed by {other}"
                    );
                }
            }
        }
    }

    #[test]
    fn expired_and_removed_service_key_still_valid() {
        let keys = keys();
        let mut list = account(&keys);
        // Its grant ended at T0 + HOUR and the record is issued after it:
        // expiry is no stop, and the verifier reads no clock.
        let revoke = ControlAction::Revoke {
            interrupt_running: true,
        };
        let body = service_body(&list, &keys, "svc-1", "svc-1", revoke);
        assert_eq!(
            check(&list, &keys, "svc-1", &body),
            valid(&list, by_principal(SVC_1_SEQ))
        );
        // A renewal changes the grant, never the key.
        let renewal = service_renewal(&list, "svc-ed", T0 + 3 * HOUR, T0 + 2 * HOUR).unwrap();
        append(&mut list, &keys, "mac", renewal);
        assert_eq!(
            list.keys_ever("svc-ed"),
            [(SVC_ED_SEQ, key(&keys, "svc-ed"))]
        );
        // Removed: its key, from the history, still signs every action.
        for id in ["svc-1", "svc-ed"] {
            let remove = Action::Remove {
                device_id: id.into(),
            };
            append(&mut list, &keys, "mac", remove);
        }
        for (principal, seq) in [("svc-1", SVC_1_SEQ), ("svc-ed", SVC_ED_SEQ)] {
            for action in SERVICE_ACTIONS {
                let body = service_body(&list, &keys, principal, principal, action);
                assert_eq!(
                    check(&list, &keys, principal, &body),
                    valid(&list, by_principal(seq)),
                    "{principal} {action:?}"
                );
            }
            assert_eq!(list.keys_ever(principal), [(seq, key(&keys, principal))]);
        }
        // Ids are never reused, so a removed service never gets another key.
        let readd = service_add(
            "svc-1",
            key(&keys, "svc-new"),
            &ServiceScope::new(["host-a"]),
            T0 + HOUR,
            T0,
        )
        .unwrap();
        let body = list.draft("mac", T0, &readd);
        let entry = sign_entry(&keys, &KeyId::new("mac"), body).unwrap();
        assert_eq!(
            list.check_next(&entry),
            Check::Invalid(Invalid::DeviceIdReused)
        );
    }

    #[test]
    fn manager_revoke_and_interrupt_valid() {
        let keys = keys();
        let mut list = account(&keys);
        for removed in [false, true] {
            if removed {
                let remove = Action::Remove {
                    device_id: "svc-1".into(),
                };
                append(&mut list, &keys, "mac", remove);
            }
            // Each manager under its own algorithm (`mac` P-256, `phone`
            // Ed25519), for any service, removed or not.
            for signer in ["mac", "phone"] {
                for principal in ["svc-1", "svc-ed"] {
                    for action in MANAGER_ACTIONS {
                        let body = service_body(&list, &keys, principal, signer, action);
                        assert_eq!(
                            check(&list, &keys, signer, &body),
                            valid(&list, by_manager(signer)),
                            "{signer} {principal} {action:?} (removed: {removed})"
                        );
                    }
                }
            }
        }
        // The key is the named manager's: another manager's fails.
        let body = service_body(&list, &keys, "svc-ed", "phone", MANAGER_ACTIONS[0]);
        assert_eq!(
            check(&list, &keys, "mac", &body),
            refused(RefusalReason::BadSignature)
        );
    }

    #[test]
    fn manager_cover_hold_release_refused() {
        let keys = keys();
        let list = account(&keys);
        // Never, whoever the member is: a current manager, a member that
        // isn't one, or one the list doesn't know yet.
        for signer in ["mac", "phone", "ipad", "dev-new"] {
            for action in [
                ControlAction::Cover,
                ControlAction::Hold,
                ControlAction::Release,
            ] {
                let body = service_body(&list, &keys, "svc-1", signer, action);
                assert_eq!(
                    check(&list, &keys, signer, &body),
                    refused(RefusalReason::SignerNotAllowed),
                    "{signer} {action:?}"
                );
            }
        }
    }

    #[test]
    fn removed_manager_refused() {
        let keys = keys();
        let mut list = account(&keys);
        let revoke = ControlAction::Revoke {
            interrupt_running: false,
        };
        let svc = service_body(&list, &keys, "svc-1", "phone", revoke);
        let r = revoke_host(&mut list, &keys, "host-a");
        let host = host_body(&list, "host-a", manager("phone"), r);
        assert_eq!(
            check(&list, &keys, "phone", &svc),
            valid(&list, by_manager("phone"))
        );
        assert_eq!(
            check(&list, &keys, "phone", &host),
            valid(&list, by_manager("phone"))
        );

        // Removed before the host applies them: refused (the strict rule),
        // for a service and for a host principal alike.
        let remove = Action::Remove {
            device_id: "phone".into(),
        };
        append(&mut list, &keys, "mac", remove);
        for body in [&svc, &host] {
            assert_eq!(
                check(&list, &keys, "phone", body),
                refused(RefusalReason::RemovedManager)
            );
            // One forged in its name: the signature, under its key from the
            // history, fails first.
            assert_eq!(
                check(&list, &keys, "mac", body),
                refused(RefusalReason::BadSignature)
            );
        }
        // Refused whatever the principal: it can never become valid.
        let unknown = service_body(&list, &keys, "svc-new", "phone", revoke);
        assert_eq!(
            check(&list, &keys, "phone", &unknown),
            refused(RefusalReason::RemovedManager)
        );

        // A manager that lost `manage` is refused the same way, and is a
        // current manager again only once it holds `manage` again.
        let add = Action::Add {
            member: native(&keys, "dev-new", &ALL),
        };
        append(&mut list, &keys, "mac", add);
        let body = service_body(&list, &keys, "svc-1", "dev-new", revoke);
        assert_eq!(
            check(&list, &keys, "dev-new", &body),
            valid(&list, by_manager("dev-new"))
        );
        let demote = |roles: &[Role]| Action::SetRoles {
            device_id: "dev-new".into(),
            change: RolesChange::Native(roles.iter().copied().collect()),
        };
        append(
            &mut list,
            &keys,
            "mac",
            demote(&[Role::Control, Role::View]),
        );
        assert_eq!(
            check(&list, &keys, "dev-new", &body),
            refused(RefusalReason::RemovedManager)
        );
        append(&mut list, &keys, "mac", demote(&ALL));
        assert_eq!(
            check(&list, &keys, "dev-new", &body),
            valid(&list, by_manager("dev-new"))
        );

        // Never a manager: a native without `manage`, or a service.
        for signer in ["ipad", "svc-ed"] {
            let body = service_body(&list, &keys, "svc-1", signer, revoke);
            assert_eq!(
                check(&list, &keys, signer, &body),
                refused(RefusalReason::SignerNotAllowed),
                "{signer}"
            );
        }
    }

    #[test]
    fn unknown_signer_pending() {
        let keys = keys();
        let mut list = account(&keys);
        let revoke = ControlAction::Revoke {
            interrupt_running: true,
        };
        let r = revoke_host(&mut list, &keys, "host-a");
        let svc = service_body(&list, &keys, "svc-1", "dev-new", revoke);
        let host = host_body(&list, "host-a", manager("dev-new"), r);
        for body in [&svc, &host] {
            assert_eq!(
                check(&list, &keys, "dev-new", body),
                pending(PendingReason::SignerUnknown)
            );
        }
        // Verified again after the list advances.
        let add = Action::Add {
            member: native(&keys, "dev-new", &ALL),
        };
        append(&mut list, &keys, "mac", add);
        for body in [&svc, &host] {
            assert_eq!(
                check(&list, &keys, "dev-new", body),
                valid(&list, by_manager("dev-new"))
            );
        }

        // A principal the list doesn't know yet, whoever signs.
        let hold = service_body(&list, &keys, "svc-new", "svc-new", ControlAction::Hold);
        let stop = service_body(&list, &keys, "svc-new", "mac", revoke);
        let host_b = host_body(&list, "host-b", manager("mac"), list.head().seq + 1);
        assert_eq!(
            check(&list, &keys, "svc-new", &hold),
            pending(PendingReason::PrincipalUnknown)
        );
        assert_eq!(
            check(&list, &keys, "mac", &stop),
            pending(PendingReason::PrincipalUnknown)
        );
        assert_eq!(
            check(&list, &keys, "mac", &host_b),
            pending(PendingReason::PrincipalUnknown)
        );
        let scope = ServiceScope::new(["host-a"]);
        let add = service_add("svc-new", key(&keys, "svc-new"), &scope, T0 + HOUR, T0).unwrap();
        let seq = append(&mut list, &keys, "mac", add);
        assert_eq!(
            check(&list, &keys, "svc-new", &hold),
            valid(&list, by_principal(seq))
        );
        assert_eq!(
            check(&list, &keys, "mac", &stop),
            valid(&list, by_manager("mac"))
        );

        // A `recovery_add` still waiting holds nothing yet: its member signs
        // as one the list doesn't know.
        let recovery = Action::RecoveryAdd {
            member: native(&keys, "dev-kit", &ALL),
        };
        append(&mut list, &keys, RECOVERY_SIGNER, recovery);
        let body = service_body(&list, &keys, "svc-1", "dev-kit", revoke);
        assert_eq!(
            check(&list, &keys, "dev-kit", &body),
            pending(PendingReason::SignerUnknown)
        );
        assert_eq!(list.keys_ever("dev-kit"), []);
        assert_eq!(list.current_manager_key("dev-kit"), None);
    }

    #[test]
    fn principal_key_mismatch_refused() {
        let keys = keys();
        let list = account(&keys);
        let revoke = ControlAction::Revoke {
            interrupt_running: false,
        };
        // Another key's fingerprint, by the principal or by a manager.
        for (signer, action) in [("svc-1", ControlAction::Hold), ("mac", revoke)] {
            let mut body = service_body(&list, &keys, "svc-1", signer, action);
            body.principal_key = Some(principal_key_of(&key(&keys, "svc-ed")).unwrap());
            assert_eq!(
                check(&list, &keys, signer, &body),
                refused(RefusalReason::KeyMismatch),
                "{signer}"
            );
        }
        // A native's id is no service principal, whatever key it names.
        for signer in ["ipad", "mac"] {
            let mut body = service_body(&list, &keys, "ipad", signer, revoke);
            body.principal_key = Some(principal_key_of(&key(&keys, "ipad")).unwrap());
            assert_eq!(
                check(&list, &keys, signer, &body),
                refused(RefusalReason::NotAService),
                "{signer}"
            );
        }
    }

    /// A service record's `principal_key` is the integration's `r9Svc`
    /// (decision 8): the vectors' keys, through the verifier.
    #[test]
    fn principal_key_equals_r9_svc() {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../../vectors/r9-svc-fingerprint.json")).unwrap();
        let keys = keys();
        let mut list = account(&keys);
        for (i, case) in v["valid"].as_array().unwrap().iter().enumerate() {
            let auth_key = PublicKey::from_json(&case["auth_key"]).unwrap();
            let r9_svc = case["fingerprint"].as_str().unwrap();
            let principal_key = principal_key_of(&auth_key).unwrap();
            assert_eq!(principal_key.to_hex(), r9_svc, "{}", case["case"]);
            assert_eq!(service_key_fingerprint(&auth_key).unwrap(), r9_svc);

            // A service enrolled with that key: a record naming its r9Svc
            // reaches the signature (the vectors hold no private key, so
            // it fails there); one naming anything else doesn't.
            let id = format!("svc-v{i}");
            let scope = ServiceScope::new(["host-a"]);
            let add = service_add(&id, auth_key, &scope, T0 + HOUR, T0).unwrap();
            append(&mut list, &keys, "mac", add);
            let mut body = service_body(&list, &keys, "svc-1", "svc-1", ControlAction::Hold);
            body.principal = ControlPrincipal::Service(id);
            body.principal_key = Some(Hash32::from_hex(r9_svc).unwrap());
            assert_eq!(
                check(&list, &keys, "svc-1", &body),
                refused(RefusalReason::BadSignature),
                "{}",
                case["case"]
            );
            let mut other = principal_key.0;
            other[0] ^= 1;
            body.principal_key = Some(Hash32(other));
            assert_eq!(
                check(&list, &keys, "svc-1", &body),
                refused(RefusalReason::KeyMismatch),
                "{}",
                case["case"]
            );
        }
        // An X25519 key is no auth_key.
        let bad = PublicKey::from_json(&v["invalid"][0]["auth_key"]).unwrap();
        assert_eq!(principal_key_of(&bad).unwrap_err().code(), "wrong_alg");
        // The keys this test holds: valid, under each algorithm.
        for (id, seq) in [("svc-1", SVC_1_SEQ), ("svc-ed", SVC_ED_SEQ)] {
            let body = service_body(&list, &keys, id, id, ControlAction::Cover);
            assert_eq!(
                body.principal_key.unwrap().to_hex(),
                hex(&crate::encoding::Hash32::of(key(&keys, id).as_bytes()).0)
            );
            assert_eq!(
                check(&list, &keys, id, &body),
                valid(&list, by_principal(seq))
            );
        }
    }

    #[test]
    fn wrong_account_refused() {
        let keys = keys();
        let mut list = account(&keys);
        let r = revoke_host(&mut list, &keys, "host-a");
        let bodies = [
            service_body(&list, &keys, "svc-1", "svc-1", ControlAction::Hold),
            service_body(&list, &keys, "svc-1", "mac", MANAGER_ACTIONS[0]),
            host_body(&list, "host-a", manager("mac"), r),
        ];
        for body in bodies {
            let key_id = match &body.signer {
                ControlSigner::Principal => "svc-1",
                ControlSigner::Member(id) => id.as_str(),
            };
            let mut other_account = body.clone();
            other_account.account_id = "acct-other".into();
            let mut other_list = body.clone();
            other_list.genesis_hash = Hash32([0x11; 32]);
            for wrong in [other_account, other_list] {
                assert_eq!(
                    check(&list, &keys, key_id, &wrong),
                    refused(RefusalReason::WrongAccount)
                );
            }
        }
    }

    #[test]
    fn host_principal_interrupt_by_manager_valid() {
        let keys = keys();
        let mut list = account(&keys);
        let r = revoke_host(&mut list, &keys, "host-a");
        for signer in ["mac", "phone"] {
            let body = host_body(&list, "host-a", manager(signer), r);
            assert_eq!(
                check(&list, &keys, signer, &body),
                valid(&list, by_manager(signer))
            );
        }
        // A removed host is still a principal: a later interrupt reaches the
        // tasks it sent before its revoke.
        let remove = Action::RemoveHost {
            host_id: "host-a".into(),
        };
        append(&mut list, &keys, "mac", remove);
        let body = host_body(&list, "host-a", manager("mac"), r);
        assert_eq!(
            check(&list, &keys, "mac", &body),
            valid(&list, by_manager("mac"))
        );
    }

    #[test]
    fn host_principal_signed_by_host_key_refused() {
        let keys = keys();
        let mut list = account(&keys);
        let r = revoke_host(&mut list, &keys, "host-a");
        // Signed by the host's own key, or by any other key naming the host
        // as its signer; a host the list doesn't know too.
        for (host_id, key_id) in [
            ("host-a", "host-a"),
            ("host-a", "mac"),
            ("host-b", "host-a"),
        ] {
            let body = host_body(&list, host_id, ControlSigner::Principal, r);
            assert_eq!(
                check(&list, &keys, key_id, &body),
                refused(RefusalReason::HostKeySigned),
                "{host_id} {key_id}"
            );
        }
    }

    /// A host principal's `release` (or `cover`,
    /// `hold`, `revoke`) is refused at parse, as `NotForHostPrincipal`, so
    /// it never reaches `verify_control`; the caller keeps the bytes as
    /// evidence (I.5.4).
    #[test]
    fn host_principal_release_refused() {
        let keys = keys();
        let list = account(&keys);
        for action in ["release", "cover", "hold", "revoke"] {
            // A current manager's valid signature over the body.
            let mut body = host_body(&list, "host-a", manager("mac"), 7).to_json();
            body["action"] = json!(action);
            body.as_object_mut().unwrap().remove("revoke_seq");
            let object = SignedObject::sign(&keys, &KeyId::new("mac"), body).unwrap();
            object.verify(&key(&keys, "mac")).unwrap();
            assert_eq!(
                ControlRecord::from_signed(object.clone()),
                Err(ControlError::NotForHostPrincipal),
                "{action}"
            );
            let wire = object.to_json().to_string();
            assert_eq!(
                ControlRecord::parse(wire.as_bytes()),
                Err(ControlError::NotForHostPrincipal),
                "{action}"
            );
        }
        // Nor is one built.
        let mut body = host_body(&list, "host-a", manager("mac"), 7);
        body.action = ControlAction::Release;
        assert!(build_control(&keys, &KeyId::new("mac"), &body).is_err());
    }

    /// Review fix 1: a native member without `manage` can still be given
    /// it, so a principal or revoke the list doesn't hold yet waits before
    /// that signer is refused (I.5.4, "Verification").
    #[test]
    fn unknown_principal_pending_before_non_manager_refused() {
        let keys = keys();
        let mut list = account(&keys);
        let revoke = ControlAction::Revoke {
            interrupt_running: false,
        };
        let next = list.head().seq + 1;
        let svc = service_body(&list, &keys, "svc-new", "ipad", revoke);
        let host_b = host_body(&list, "host-b", manager("ipad"), next + 10);
        let host_a = host_body(&list, "host-a", manager("ipad"), next);
        for body in [&svc, &host_b] {
            assert_eq!(
                check(&list, &keys, "ipad", body),
                pending(PendingReason::PrincipalUnknown)
            );
        }
        assert_eq!(
            check(&list, &keys, "ipad", &host_a),
            pending(PendingReason::RevokeNotInList)
        );
        // In the list, the signer still without `manage`: refused against
        // this list.
        assert_eq!(revoke_host(&mut list, &keys, "host-a"), next);
        let scope = ServiceScope::new(["host-a"]);
        let add = service_add("svc-new", key(&keys, "svc-new"), &scope, T0 + HOUR, T0).unwrap();
        append(&mut list, &keys, "mac", add);
        for body in [&svc, &host_a] {
            assert_eq!(
                check(&list, &keys, "ipad", body),
                refused(RefusalReason::SignerNotAllowed)
            );
        }
        // Given `manage`: valid.
        let promote = Action::SetRoles {
            device_id: "ipad".into(),
            change: RolesChange::Native(ALL.into_iter().collect()),
        };
        append(&mut list, &keys, "mac", promote);
        for body in [&svc, &host_a] {
            assert_eq!(
                check(&list, &keys, "ipad", body),
                valid(&list, by_manager("ipad"))
            );
        }
    }

    /// Review fix 1: the same for a manager that lost `manage`.
    #[test]
    fn unknown_principal_pending_before_demoted_manager_refused() {
        let keys = keys();
        let mut list = account(&keys);
        let roles = |roles: &[Role]| Action::SetRoles {
            device_id: "dev-new".into(),
            change: RolesChange::Native(roles.iter().copied().collect()),
        };
        let add = Action::Add {
            member: native(&keys, "dev-new", &ALL),
        };
        append(&mut list, &keys, "mac", add);
        append(&mut list, &keys, "mac", roles(&[Role::Control, Role::View]));
        let revoke = ControlAction::Revoke {
            interrupt_running: true,
        };
        // svc-new's add, host-b's add_host, then host-b's revoke follow.
        let r_b = list.head().seq + 3;
        let svc = service_body(&list, &keys, "svc-new", "dev-new", revoke);
        let host_b = host_body(&list, "host-b", manager("dev-new"), r_b);
        for body in [&svc, &host_b] {
            assert_eq!(
                check(&list, &keys, "dev-new", body),
                pending(PendingReason::PrincipalUnknown)
            );
        }
        let scope = ServiceScope::new(["host-a"]);
        let add = service_add("svc-new", key(&keys, "svc-new"), &scope, T0 + HOUR, T0).unwrap();
        append(&mut list, &keys, "mac", add);
        add_host_b(&mut list, &keys);
        assert_eq!(revoke_host(&mut list, &keys, "host-b"), r_b);
        for body in [&svc, &host_b] {
            assert_eq!(
                check(&list, &keys, "dev-new", body),
                refused(RefusalReason::RemovedManager)
            );
            // One forged in its name.
            assert_eq!(
                check(&list, &keys, "mac", body),
                refused(RefusalReason::BadSignature)
            );
        }
        append(&mut list, &keys, "mac", roles(&ALL));
        for body in [&svc, &host_b] {
            assert_eq!(
                check(&list, &keys, "dev-new", body),
                valid(&list, by_manager("dev-new"))
            );
        }
    }

    /// What no later entry changes is refused even while the principal is
    /// unknown: a removed manager (`removed_manager_refused`), a service as
    /// signer, a member whose `recovery_add` was cancelled (ids are never
    /// reused and a member's kind never changes).
    #[test]
    fn permanent_signer_refusals_before_unknown_principal() {
        let keys = keys();
        let mut list = account(&keys);
        let recovery = Action::RecoveryAdd {
            member: native(&keys, "dev-kit", &ALL),
        };
        let seq = append(&mut list, &keys, RECOVERY_SIGNER, recovery);
        let target = list.entry(seq).unwrap().hash();
        append(&mut list, &keys, "mac", Action::RecoveryVeto { target });
        let revoke = ControlAction::Revoke {
            interrupt_running: false,
        };
        for signer in ["svc-ed", "dev-kit"] {
            let body = service_body(&list, &keys, "svc-new", signer, revoke);
            assert_eq!(
                check(&list, &keys, signer, &body),
                refused(RefusalReason::SignerNotAllowed),
                "{signer}"
            );
        }
    }

    /// Adds the host `host-b` (signed by `mac`); returns its `seq`.
    fn add_host_b(list: &mut Membership, keys: &SoftwareKeys) -> u64 {
        let host = HostRecord {
            host_id: "host-b".into(),
            host_trust_gen: 1,
            host_key: key(keys, "host-b"),
        };
        append(list, keys, "mac", Action::AddHost { host })
    }

    /// `revoke_seq` names that host's `host_sender_revoke`.
    #[test]
    fn host_interrupt_matching_revoke_valid() {
        let keys = keys();
        let mut list = account(&keys);
        add_host_b(&mut list, &keys);
        let r_a = revoke_host(&mut list, &keys, "host-a");
        let r_b = revoke_host(&mut list, &keys, "host-b");
        for (host_id, r) in [("host-a", r_a), ("host-b", r_b)] {
            let body = host_body(&list, host_id, manager("phone"), r);
            assert_eq!(
                check(&list, &keys, "phone", &body),
                valid(&list, by_manager("phone")),
                "{host_id}"
            );
        }
        // A readmit since changes nothing: the interrupt is for the tasks
        // admitted before that revoke (II.3.1).
        let readmit = host_sender_readmit("host-a", T0).unwrap();
        append(&mut list, &keys, "mac", readmit);
        let body = host_body(&list, "host-a", manager("mac"), r_a);
        assert_eq!(
            check(&list, &keys, "mac", &body),
            valid(&list, by_manager("mac"))
        );
    }

    /// A `revoke_seq` beyond the head waits, and verifies once
    /// the list holds that host's revoke there.
    #[test]
    fn host_interrupt_revoke_beyond_head_pending() {
        let keys = keys();
        let mut list = account(&keys);
        let next = list.head().seq + 1;
        let body = host_body(&list, "host-a", manager("mac"), next);
        assert_eq!(
            check(&list, &keys, "mac", &body),
            pending(PendingReason::RevokeNotInList)
        );
        // Far beyond too.
        let far = host_body(&list, "host-a", manager("mac"), next + 100);
        assert_eq!(
            check(&list, &keys, "mac", &far),
            pending(PendingReason::RevokeNotInList)
        );
        assert_eq!(revoke_host(&mut list, &keys, "host-a"), next);
        assert_eq!(
            check(&list, &keys, "mac", &body),
            valid(&list, by_manager("mac"))
        );
    }

    /// Another host's revoke is no revoke of this host.
    #[test]
    fn host_interrupt_other_hosts_revoke_refused() {
        let keys = keys();
        let mut list = account(&keys);
        add_host_b(&mut list, &keys);
        let r_b = revoke_host(&mut list, &keys, "host-b");
        // host-a is still authorized; host-c was never added.
        for host_id in ["host-a", "host-c"] {
            let body = host_body(&list, host_id, manager("mac"), r_b);
            assert_eq!(
                check(&list, &keys, "mac", &body),
                refused(RefusalReason::NotARevoke),
                "{host_id}"
            );
        }
        // Once host-a is revoked as well, r_b still names host-b's.
        revoke_host(&mut list, &keys, "host-a");
        let body = host_body(&list, "host-a", manager("mac"), r_b);
        assert_eq!(
            check(&list, &keys, "mac", &body),
            refused(RefusalReason::NotARevoke)
        );
    }

    /// An entry that isn't a `host_sender_revoke` at all: the
    /// genesis, the host's own `add_host`, a service `add`, and a readmit
    /// of the host.
    #[test]
    fn host_interrupt_not_a_revoke_refused() {
        let keys = keys();
        let mut list = account(&keys);
        revoke_host(&mut list, &keys, "host-a");
        let readmit = host_sender_readmit("host-a", T0).unwrap();
        let readmit_seq = append(&mut list, &keys, "mac", readmit);
        for seq in [1, HOST_A_SEQ, SVC_1_SEQ, readmit_seq] {
            let body = host_body(&list, "host-a", manager("mac"), seq);
            assert_eq!(
                check(&list, &keys, "mac", &body),
                refused(RefusalReason::NotARevoke),
                "seq {seq}"
            );
        }
    }

    #[test]
    fn keys_ever_and_current_manager_key() {
        let keys = keys();
        let mut list = account(&keys);
        assert_eq!(list.keys_ever("mac"), [(1, key(&keys, "mac"))]);
        assert_eq!(list.keys_ever("svc-1"), [(SVC_1_SEQ, key(&keys, "svc-1"))]);
        assert_eq!(list.keys_ever("host-a"), [], "a host is no member");
        assert_eq!(list.keys_ever("nobody"), []);
        assert_eq!(list.current_manager_key("mac"), Some(key(&keys, "mac")));
        assert_eq!(list.current_manager_key("phone"), Some(key(&keys, "phone")));
        for id in ["ipad", "svc-1", "host-a", "nobody"] {
            assert_eq!(list.current_manager_key(id), None, "{id}");
        }
        assert!(list.was_manager("phone"));
        assert!(!list.was_manager("ipad"));
        assert!(!list.was_manager("svc-1"));
        let remove = Action::Remove {
            device_id: "phone".into(),
        };
        append(&mut list, &keys, "mac", remove);
        assert_eq!(list.current_manager_key("phone"), None);
        assert_eq!(list.keys_ever("phone"), [(2, key(&keys, "phone"))]);
        assert!(list.was_manager("phone"));
        // `ipad` given `manage`, then demoted: it was one.
        let set = |roles: &[Role]| Action::SetRoles {
            device_id: "ipad".into(),
            change: RolesChange::Native(roles.iter().copied().collect()),
        };
        append(&mut list, &keys, "mac", set(&ALL));
        assert_eq!(list.current_manager_key("ipad"), Some(key(&keys, "ipad")));
        append(&mut list, &keys, "mac", set(&[Role::View]));
        assert_eq!(list.current_manager_key("ipad"), None);
        assert!(list.was_manager("ipad"));
    }

    #[test]
    fn reasons_have_distinct_codes() {
        let codes = [
            PendingReason::PrincipalUnknown.code(),
            PendingReason::SignerUnknown.code(),
            PendingReason::RevokeNotInList.code(),
            RefusalReason::WrongAccount.code(),
            RefusalReason::BadSignature.code(),
            RefusalReason::KeyMismatch.code(),
            RefusalReason::SignerNotAllowed.code(),
            RefusalReason::RemovedManager.code(),
            RefusalReason::HostKeySigned.code(),
            RefusalReason::NotAService.code(),
            RefusalReason::NotARevoke.code(),
        ];
        let distinct: std::collections::BTreeSet<_> = codes.iter().collect();
        assert_eq!(distinct.len(), codes.len());
    }
}
