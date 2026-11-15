//! Host senders on the receiving host (the delegated host-work design
//! II.2, II.3, II.7, II.8; host-work-v1 §11.5, §11.6): another Atem host of
//! the account, `host:<host_id>`, sending work through the Station
//! mailbox. Everything here is behind `host.senders` (the debug-only hook,
//! only with `host.delegated`).
//!
//! - **Who it is** ([`classify_host`], design I.1.3, II.2.1): a current host
//!   of the device list (an `add_host`, no `remove_host` since), authorized
//!   as a sender (II.3.1), with the authorization generation and the
//!   membership epoch it has now (II.2.2), which its tasks record at
//!   admission. Otherwise refused: it has no v1 path.
use super::{DelegatedSender, SenderClass};
use crate::runtime::test_hooks::HostFeatures;
use atem_client::host_principal::parse_host_principal;
use atem_client::membership::{HostSenderState, Membership};
use atem_client::session::wire::is_delegated_sender;

/// [`super::classify`] of a `host:` principal (see there).
pub fn classify_host(principal: &str, list: &Membership, features: HostFeatures) -> SenderClass {
    if !(features.delegated && features.senders) || !is_delegated_sender(principal) {
        return SenderClass::Refused;
    }
    let Some(host_id) = parse_host_principal(principal) else {
        return SenderClass::Refused;
    };
    match standing(list, host_id) {
        Some((generation, epoch)) => SenderClass::Delegated(DelegatedSender::Host {
            host_id: host_id.to_owned(),
            generation,
            epoch,
        }),
        None => SenderClass::Refused,
    }
}

/// `host_id`'s authorization generation and membership epoch on `list`
/// while it may send: a current host (its epoch), authorized (its
/// generation). None when it is removed, revoked or unknown.
fn standing(list: &Membership, host_id: &str) -> Option<(u64, u64)> {
    list.host(host_id)?;
    let epoch = list.host_membership_epoch(host_id)?;
    match list.host_sender_state(host_id)? {
        HostSenderState::Authorized { generation } => Some((generation, epoch)),
        HostSenderState::Revoked { .. } => None,
    }
}
