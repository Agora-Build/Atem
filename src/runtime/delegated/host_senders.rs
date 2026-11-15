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
//! - **Route consent** ([`Consent`], II.2.3): `runtime.toml`'s route
//!   `principals` take `project:<name>` (every host the signed project
//!   lists, when this host is in it too) and `host:<host_id>` (that host),
//!   only with `host.senders` on (`host_work::Config::validate_for`): with
//!   it off the file refuses them, as main does any unknown principal.
use super::{DelegatedSender, SenderClass};
use crate::runtime::test_hooks::HostFeatures;
use atem_client::host_principal::parse_host_principal;
use atem_client::membership::{HostSenderState, Membership, project_name_ok};
use atem_client::session::wire::is_delegated_sender;

/// The prefix of a route principal naming a signed project (II.2.3).
const PROJECT_PREFIX: &str = "project:";

/// A route principal that consents to host senders (design II.2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Consent<'a> {
    /// `project:<name>`: every host the signed project `name` lists, when
    /// this host is in it too, within that project's ops.
    Project(&'a str),
    /// `host:<host_id>`: that host only, within the ops of every project in
    /// effect that lists both hosts.
    Host(&'a str),
}

impl Consent<'_> {
    /// The consent `principal` names: `None` when it is neither form
    /// (another principal, or none), `Some(Err(why))` for one of the forms
    /// outside its grammar (a project name by the shared core's
    /// `project_name_ok`, a host id by the device list's).
    pub fn parse(principal: &str) -> Option<Result<Consent<'_>, &'static str>> {
        if let Some(name) = principal.strip_prefix(PROJECT_PREFIX) {
            return Some(if project_name_ok(name) {
                Ok(Consent::Project(name))
            } else {
                Err("a project name is 1-32 of a-z, 0-9 and -")
            });
        }
        if principal.starts_with("host:") {
            return Some(match parse_host_principal(principal) {
                Some(host_id) => Ok(Consent::Host(host_id)),
                None => Err("a host id is 1-128 letters, digits, `.`, `_`, `:` or `-`"),
            });
        }
        None
    }
}

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
