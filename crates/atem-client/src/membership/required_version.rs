//! The signing gate's compatibility requirement for one unsigned entry body
//! (session-v1 R9.2 "How the signing gate uses it"; the shared helper the
//! gate's adoption waited on, built as **Atem's proposal, for Astation's
//! agreement**).
//!
//! An entry needs a requirement when some released verifier refuses it:
//! the requirement names the first verifier version
//! ([`VERIFIER_VERSION`](super::VERIFIER_VERSION)) that accepts it. Today
//! those are the five delegated host-work actions (version 2) and a service
//! `add` or `set_roles` whose scope carries `launch`, `message` or `notify`
//! (version 1; v0.8.0 and v0.8.1 lack those ops). Every other entry is
//! accepted by every release from v0.8.0 to v0.8.5 and needs none.
//! The actions are classified by an exhaustive match, the scope ops by
//! `OP_SINCE`, one entry per op of [`OPS`] in its order: a new action or
//! op doesn't build, or fails `the_op_table_classifies_every_op`, until it
//! is classified here. A new rule for an existing action has no such guard
//! (see [`VERIFIER_VERSION`](super::VERIFIER_VERSION)).
use super::entry::OPS;
use super::{Action, Invalid, MemberKind, RolesChange, Scope, check_body};
use crate::canonical::StrictValue;
use crate::signed::MAX_OBJECT_BYTES;

/// What a verifier must report before a signer signs the entry: the
/// entry's `action` and the first version that accepts it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierRequirement {
    pub action: &'static str,
    pub minimum_version: u32,
}

/// The first version that accepts `project_set`, `project_remove`,
/// `host_sender_revoke`, `host_sender_readmit` and `host_enc_key`.
const DELEGATED_ACTIONS_SINCE: u32 = 2;

/// Each scope op of [`OPS`], in its order, with the first version that
/// accepts a service scope carrying it: `None` for R9.6's seven, which
/// every release from v0.8.0 accepts, `Some(1)` for the three v0.8.2 added
/// (host-work-v1 §2 "Ops"). Its length is `OPS`'s, so an op added there
/// doesn't build until it is classified here, and
/// `the_op_table_classifies_every_op` checks the names.
const OP_SINCE: [(&str, Option<u32>); OPS.len()] = [
    ("approval", None),
    ("interrupt", None),
    ("launch", Some(1)),
    ("message", Some(1)),
    ("notify", Some(1)),
    ("prompt", None),
    ("rule_revoke", None),
    ("stop", None),
    ("terminal", None),
    ("view", None),
];

/// The requirement of one unsigned membership-entry body, for R9.2's
/// all-verifier signing gate: `None` for an entry every release from
/// v0.8.0 to v0.8.5 accepts, else the action and the first version that
/// accepts it.
///
/// `body_json` is the body as JSON text (not the `{body, sig}` object). It
/// is read strictly (strict I-JSON, at most 16 KiB, no duplicate key at any
/// depth, integers only), then given the same `SignedObject`/`Entry` parse
/// as a received entry, after JCS ([`check_body`]): the body bound, the
/// canonical sets, every key's algorithm and the action's own fields and
/// rules. A body that doesn't parse is refused, never `None`.
///
/// This checks neither the signature nor the chain (a body of the right
/// shape may still be refused on its chain), authenticates no verifier and
/// grants no signing authority. The caller still needs those checks and
/// current, authenticated support from every verifier of the account for a
/// returned requirement.
///
/// # Errors
///
/// The [`Invalid`] the verifier gives an entry of that shape: `malformed`
/// for text that isn't strict JSON (more than 16 KiB of it included) or a
/// missing or mistyped field, `too_large` for a body over 4,096 bytes of
/// JCS, `unknown_field`, `array_not_canonical`, `wrong_alg`, `bad_key`,
/// `bad_scope`, `bad_roles`, `bad_project`, …. An action this build doesn't
/// know is `Invalid::Malformed("unknown action")`, code `malformed` like
/// any other malformed field: to tell a newer action from a damaged body,
/// compare the body's `action` with [`known_actions`](super::known_actions).
/// The bindings throw it as `Membership{code: "membership_invalid", detail:
/// <the code>}`.
pub fn required_version(body_json: &[u8]) -> Result<Option<VerifierRequirement>, Invalid> {
    let body = StrictValue::parse(body_json, MAX_OBJECT_BYTES).map_err(crate::Error::from)?;
    let entry = check_body(body.value())?;
    let minimum_version = match &entry.action {
        Action::ProjectSet { .. }
        | Action::ProjectRemove { .. }
        | Action::HostSenderRevoke { .. }
        | Action::HostSenderReadmit { .. }
        | Action::HostEncKey { .. } => Some(DELEGATED_ACTIONS_SINCE),
        Action::Add { member } => match &member.kind {
            MemberKind::Service { scope, .. } => scope_version(scope)?,
            MemberKind::Native { .. } => None,
        },
        Action::SetRoles { change, .. } => match change {
            RolesChange::Service { scope, .. } => scope_version(scope)?,
            RolesChange::Native(_) => None,
        },
        Action::Genesis { .. }
        | Action::Remove { .. }
        | Action::AddHost { .. }
        | Action::RemoveHost { .. }
        | Action::RecoveryAdd { .. }
        | Action::SetRecoveryKey { .. }
        | Action::RecoveryApprove { .. }
        | Action::RecoveryVeto { .. }
        | Action::KBackup(_) => None,
    };
    Ok(minimum_version.map(|minimum_version| VerifierRequirement {
        action: entry.action.name(),
        minimum_version,
    }))
}

/// The highest first version of the scope's ops. An op [`OP_SINCE`] doesn't
/// list can't get here (`Entry::parse` refuses an op outside [`OPS`]), and
/// is refused rather than read as needing nothing.
fn scope_version(scope: &Scope) -> Result<Option<u32>, Invalid> {
    let mut version = None;
    for op in &scope.ops {
        let (_, since) = OP_SINCE
            .iter()
            .find(|(name, _)| name == op)
            .ok_or(Invalid::BadScope)?;
        version = version.max(*since);
    }
    Ok(version)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::membership::VERIFIER_VERSION;

    fn scope(ops: &[&str]) -> Scope {
        Scope {
            hosts: vec!["host-a".into()],
            projects: None,
            sessions: None,
            ops: ops.iter().map(|op| (*op).to_owned()).collect(),
        }
    }

    /// The table names exactly the verifier's ops, in their order: an op
    /// renamed in [`OPS`] fails here (one added there doesn't build) until
    /// the table gives it a version.
    #[test]
    fn the_op_table_classifies_every_op() {
        let names: Vec<&str> = OP_SINCE.iter().map(|(name, _)| *name).collect();
        assert_eq!(names, OPS);
    }

    /// The ops that need no version are exactly the seven v0.8.0 shipped
    /// (its `OPS`): a new op given `None` by mistake fails here, so it can't
    /// be read as one every verifier knows, even with the vectors
    /// regenerated.
    #[test]
    fn only_v0_8_0s_seven_ops_need_no_version() {
        let none: Vec<&str> = OP_SINCE
            .iter()
            .filter(|(_, since)| since.is_none())
            .map(|(name, _)| *name)
            .collect();
        assert_eq!(
            none,
            [
                "approval",
                "interrupt",
                "prompt",
                "rule_revoke",
                "stop",
                "terminal",
                "view"
            ]
        );
    }

    /// No entry asks for more than this verifier reports, and a requirement
    /// is a version (1 or more).
    #[test]
    fn no_requirement_is_above_this_verifier() {
        let versions = OP_SINCE
            .iter()
            .filter_map(|(_, since)| *since)
            .chain([DELEGATED_ACTIONS_SINCE]);
        for version in versions {
            assert!((1..=VERIFIER_VERSION).contains(&version), "{version}");
        }
    }

    /// A scope needs its highest op's version; an op outside the table is
    /// refused, never read as needing none.
    #[test]
    fn a_scope_needs_its_highest_op() {
        assert_eq!(scope_version(&scope(&["view"])), Ok(None));
        assert_eq!(scope_version(&scope(&OPS[..2])), Ok(None));
        assert_eq!(scope_version(&scope(&OPS)), Ok(Some(1)));
        assert_eq!(
            scope_version(&scope(&["interrupt", "notify", "view"])),
            Ok(Some(1))
        );
        assert_eq!(
            scope_version(&scope(&["task", "view"])),
            Err(Invalid::BadScope)
        );
    }
}
