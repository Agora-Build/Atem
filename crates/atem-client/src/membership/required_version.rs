//! The signing gate's compatibility requirement for one unsigned entry body.
use super::{Action, Invalid, MemberKind, RolesChange, Scope, check_body};
use crate::canonical::StrictValue;
use crate::signed::MAX_OBJECT_BYTES;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierRequirement {
    pub action: &'static str,
    pub minimum_version: u32,
}

/// Strictly check the unsigned membership body before classifying it for
/// R9.2's all-verifier signing gate. `None` means a known, structurally valid
/// entry whose action and rules predate reported inventories. Unknown or
/// malformed bodies are errors, never universal support.
///
/// This checks neither the signature nor the chain, authenticates no verifier
/// and grants no signing authority. The caller still needs those checks and
/// fresh support from every required participant for a returned requirement.
pub fn required_version(body_json: &[u8]) -> Result<Option<VerifierRequirement>, Invalid> {
    let body = StrictValue::parse(body_json, MAX_OBJECT_BYTES).map_err(crate::Error::from)?;
    let entry = check_body(body.value())?;
    let minimum_version = match &entry.action {
        Action::ProjectSet { .. }
        | Action::ProjectRemove { .. }
        | Action::HostSenderRevoke { .. }
        | Action::HostSenderReadmit { .. }
        | Action::HostEncKey { .. } => Some(2),
        Action::Add { member } => match &member.kind {
            MemberKind::Service { scope, .. } => scope_version(scope),
            MemberKind::Native { .. } => None,
        },
        Action::SetRoles { change, .. } => match change {
            RolesChange::Service { scope, .. } => scope_version(scope),
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

fn scope_version(scope: &Scope) -> Option<u32> {
    scope
        .ops
        .iter()
        .any(|op| matches!(op.as_str(), "launch" | "message" | "notify"))
        .then_some(1)
}
