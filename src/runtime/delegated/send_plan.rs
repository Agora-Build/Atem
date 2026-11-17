//! The sending host's plan of a message to other hosts (the delegated
//! host-work design II.6, as amended 2026-11-15; host-work-v1 §11.5,
//! "`select` from host senders"), behind the debug-only hook's
//! `host.senders`. Pure: it reads only this host's committed device list.
//!
//! - **`atem:<atem_id>[/<route_id>]`** names one host: this host when the
//!   id is its own (stage 1's local match), else the current host of the
//!   list whose `host_id` is that `atem_id` (a host's `host_id` is its
//!   `atem_id`). An id no current host has is refused.
//! - **`project:<name>` terms** reach the hosts every named signed project
//!   lists, other than this host, when each of those projects lists this
//!   host too (a project lets a host reach the *other* hosts it lists,
//!   II.2.2); one that doesn't (or isn't in effect) reaches no other host,
//!   and the selector stays a local one. `tag:` and `self:` terms ride
//!   along for each receiver to expand against its own labels.
//! - **Who can be a target:** a current host with a current `host_enc_key`
//!   whose shared projects grant `message`, `notify` and `prompt` (and
//!   `launch` for a launch on message, II.2.3). A planned host that isn't
//!   one refuses the send with the reason (Atem's reading: a send never
//!   leaves part of its audience out silently).
//! - **This host signs only while its own list shows it** a current host
//!   at its trust generation and `authorized` (§11.5's sender rule).
//! - **One budget of 32 agents** across every part, local and remote: the
//!   local part (when a selector can reach this host's agents) first, then
//!   each planned host by `host_id`, each the same share, the remainder one
//!   each to the first.
use atem_client::PublicKey;
use atem_client::membership::{HostSenderState, Membership, ProjectOp};
use atem_client::session::select::{Label, MAX_AGENTS, Selector};
use std::collections::BTreeMap;

/// This host as the plan reads it.
#[derive(Debug, Clone, Copy)]
pub struct Me<'a> {
    /// Its `host_id` in the device list (its `atem_device_id`).
    pub host_id: &'a str,
    /// Its `atem_id`, what stage 1's `atem:` selectors match (the same id
    /// on a verified host).
    pub atem_id: &'a str,
    /// Its own trust generation, from its pairing.
    pub host_trust_gen: u64,
}

impl Me<'_> {
    fn is(&self, id: &str) -> bool {
        id == self.host_id || id == self.atem_id
    }
}

/// One planned host: where the message's `select` recipient goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub host_id: String,
    /// Its newest `add_host`'s generation.
    pub host_trust_gen: u64,
    /// Its current encryption key, and that key's `enc_kid`.
    pub enc_key: PublicKey,
    pub enc_kid: String,
    /// The selectors that planned it, in the send's order.
    pub selectors: Vec<String>,
    /// Its share of the message's 32 agents.
    pub budget: u32,
    /// The send's `--launch`, where a selector names this host and a route.
    pub launch: bool,
}

/// A send's plan: the local part's budget (none: no selector can reach
/// this host's agents) and the other hosts' recipients.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub local: Option<u32>,
    pub remote: Vec<Target>,
}

/// The stage-1 refusal of `--launch` without a route to start one on.
pub const LAUNCH_NEEDS_ROUTE: &str =
    "use --launch with atem:<atem_id>/<route_id>; the route must allow launch = on_message";

/// The ops a message task needs from a host sender's project (II.2.3).
const TASK_OPS: [ProjectOp; 3] = [ProjectOp::Message, ProjectOp::Notify, ProjectOp::Prompt];

/// The plan of `to` (already valid selectors) from `me` on `list`, with
/// the send's `launch`; why it can't be sent otherwise.
pub fn plan(list: &Membership, me: Me<'_>, to: &[String], launch: bool) -> Result<Plan, String> {
    let selectors: Vec<Selector> = to
        .iter()
        .map(|s| s.parse::<Selector>())
        .collect::<Result<_, _>>()
        .map_err(str::to_owned)?;
    let mut local = false;
    let mut hosts: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (i, selector) in selectors.iter().enumerate() {
        match selector {
            Selector::Instance { atem_id, .. } if me.is(atem_id) => local = true,
            Selector::Instance { atem_id, .. } => {
                if list.host(atem_id).is_none() {
                    return Err(format!(
                        "atem:{atem_id}: no current host of this account's device list has that id"
                    ));
                }
                hosts.entry(atem_id.clone()).or_default().push(i);
            }
            Selector::All(labels) => {
                local = true;
                for host in project_hosts(list, me.host_id, labels) {
                    hosts.entry(host).or_default().push(i);
                }
            }
        }
    }
    let route_named = |host: &str| {
        selectors.iter().any(
            |s| matches!(s, Selector::Instance { atem_id, route_id: Some(_) } if atem_id == host),
        )
    };
    if launch && !route_named(me.atem_id) && !hosts.keys().any(|h| route_named(h)) {
        return Err(LAUNCH_NEEDS_ROUTE.into());
    }
    if hosts.is_empty() {
        return Ok(Plan {
            local: Some(MAX_AGENTS),
            remote: Vec::new(),
        });
    }
    signs(list, me)?;
    let parts = usize::from(local) + hosts.len();
    if parts > MAX_AGENTS as usize {
        return Err(format!(
            "a message reaches the agents of at most {MAX_AGENTS} hosts; this one plans {parts}"
        ));
    }
    let mut shares = (0..parts)
        .map(|i| MAX_AGENTS / parts as u32 + u32::from((i as u32) < MAX_AGENTS % parts as u32));
    let local = local.then(|| shares.next().unwrap());
    let mut remote = Vec::new();
    for ((host_id, picked), budget) in hosts.into_iter().zip(shares) {
        let launch = launch && route_named(&host_id);
        remote.push(
            target(list, me, &host_id, launch)?
                .with(picked.iter().map(|&i| to[i].clone()).collect(), budget),
        );
    }
    Ok(Plan { local, remote })
}

/// The hosts a label selector's `project:` terms reach: those every named
/// project lists, other than `me`, when each lists `me` too.
fn project_hosts(list: &Membership, me: &str, labels: &[Label]) -> Vec<String> {
    let mut names = labels.iter().filter_map(|l| match l {
        Label::Project(p) => p.strip_prefix("project:"),
        _ => None,
    });
    let Some(first) = names.next() else {
        return Vec::new();
    };
    let lists_me = |name: &str| list.project_hosts(name).contains(&me);
    if !lists_me(first) {
        return Vec::new();
    }
    let mut hosts: Vec<String> = list
        .project_hosts(first)
        .into_iter()
        .filter(|h| *h != me)
        .map(str::to_owned)
        .collect();
    for name in names {
        if !lists_me(name) {
            return Vec::new();
        }
        let theirs = list.project_hosts(name);
        hosts.retain(|h| theirs.contains(&h.as_str()));
    }
    hosts
}

/// This host may sign envelopes: a current host at its own trust
/// generation, `authorized` (§11.5's sender rule).
fn signs(list: &Membership, me: Me<'_>) -> Result<(), String> {
    if list
        .host(me.host_id)
        .is_none_or(|h| h.host_trust_gen != me.host_trust_gen)
    {
        return Err(format!(
            "this host isn't a current host of its device list at trust generation {}; it can't send to other hosts",
            me.host_trust_gen
        ));
    }
    match list.host_sender_state(me.host_id) {
        Some(HostSenderState::Authorized { .. }) => Ok(()),
        _ => Err(
            "this host is revoked as a host sender (host_sender_revoke); a native manager readmits it"
                .into(),
        ),
    }
}

/// `host_id` as a target: a current host with a current key whose shared
/// projects grant a task's ops (and `launch` with `launch`).
fn target(list: &Membership, me: Me<'_>, host_id: &str, launch: bool) -> Result<Target, String> {
    let host = list.host(host_id).ok_or_else(|| {
        format!("{host_id}: no current host of this account's device list has that id")
    })?;
    let key = list.host_enc_key(host_id).ok_or_else(|| {
        format!(
            "host {host_id} has no encryption key in the device list yet; it can't receive messages from other hosts"
        )
    })?;
    let ops = list.project_ops_between(me.host_id, host_id);
    if !TASK_OPS.iter().all(|op| ops.contains(op)) {
        return Err(format!(
            "no signed project of this host and {host_id} grants message, notify and prompt"
        ));
    }
    if launch && !ops.contains(&ProjectOp::Launch) {
        return Err(format!(
            "no signed project of this host and {host_id} grants launch"
        ));
    }
    Ok(Target {
        host_id: host_id.to_owned(),
        host_trust_gen: host.host_trust_gen,
        enc_key: key.current.key.clone(),
        enc_kid: atem_client::encoding::hex(&key.current.kid),
        selectors: Vec::new(),
        budget: 0,
        launch,
    })
}

impl Target {
    fn with(mut self, selectors: Vec<String>, budget: u32) -> Target {
        self.selectors = selectors;
        self.budget = budget;
        self
    }
}

#[cfg(test)]
#[path = "send_plan_tests.rs"]
mod tests;
