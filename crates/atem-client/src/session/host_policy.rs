//! The host policy of §R9.8a: relay only, set and read inside the channel.
//!
//! A native member with `manage` sends [`set`] or [`get`]; the host answers
//! one [`HostPolicyResult`] per request, built for the channel it is sent
//! on (`re` = the request's `id`, a fresh `id`). There is no plaintext form:
//! the outer `transportPolicy`/`transportPolicyAck` are removed.
//!
//! [`HostPolicyTracker`] is the client's side: relay only is confirmed only
//! by a durable `committed`/`unchanged`/`current` result answering one of
//! its own outstanding requests on this attachment, bound to the host it was
//! welcomed by, with the value it wants.
use std::collections::HashSet;

use serde_json::{Value, json};

use crate::membership::Head;
use crate::session::r9::Welcome;
use crate::session::wire::is_uuid_v4;

/// The feature a host with the policy lists in `welcome.features`.
pub const FEATURE: &str = "host.policy";

/// How a request ended (§R9.8a's table; `current` answers a `get`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Committed,
    Unchanged,
    Superseded,
    Conflict,
    SaveFailed,
    Uncertain,
    Current,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Committed => "committed",
            Outcome::Unchanged => "unchanged",
            Outcome::Superseded => "superseded",
            Outcome::Conflict => "conflict",
            Outcome::SaveFailed => "save_failed",
            Outcome::Uncertain => "uncertain",
            Outcome::Current => "current",
        }
    }

    pub fn parse(s: &str) -> Option<Outcome> {
        Some(match s {
            "committed" => Outcome::Committed,
            "unchanged" => Outcome::Unchanged,
            "superseded" => Outcome::Superseded,
            "conflict" => Outcome::Conflict,
            "save_failed" => Outcome::SaveFailed,
            "uncertain" => Outcome::Uncertain,
            "current" => Outcome::Current,
            _ => return None,
        })
    }

    /// The outcomes that can confirm a policy (with a durable state).
    pub fn confirms(self) -> bool {
        matches!(
            self,
            Outcome::Committed | Outcome::Unchanged | Outcome::Current
        )
    }
}

/// Whether the host knows its policy file survives a crash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyState {
    Durable,
    /// Replaced, but the directory sync failed: no local or direct link
    /// until it succeeds.
    Uncertain,
}

impl PolicyState {
    pub fn as_str(self) -> &'static str {
        match self {
            PolicyState::Durable => "durable",
            PolicyState::Uncertain => "uncertain",
        }
    }

    pub fn parse(s: &str) -> Option<PolicyState> {
        match s {
            "durable" => Some(PolicyState::Durable),
            "uncertain" => Some(PolicyState::Uncertain),
            _ => None,
        }
    }
}

/// The host's current policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    pub relay_only: bool,
    pub revision: u64,
    pub state: PolicyState,
}

impl Policy {
    pub fn to_json(&self) -> Value {
        json!({"relay_only": self.relay_only, "revision": self.revision,
            "state": self.state.as_str()})
    }

    /// Exactly `{relay_only, revision, state}`.
    pub fn from_json(value: &Value) -> Option<Policy> {
        let o = value.as_object()?;
        if o.len() != 3 {
            return None;
        }
        Some(Policy {
            relay_only: o.get("relay_only")?.as_bool()?,
            revision: o.get("revision")?.as_u64()?,
            state: PolicyState::parse(o.get("state")?.as_str()?)?,
        })
    }
}

fn session(data: Value) -> Value {
    json!({"type": "session", "data": data})
}

/// `host_policy_set` (C→H). `request_id` is the change's durable identity
/// (a retry sends the same one with the same body); `expected_revision` the
/// revision the client believes current.
pub fn set(id: &str, request_id: &str, relay_only: bool, expected_revision: u64) -> Value {
    session(
        json!({"v": 1, "op": "host_policy_set", "id": id, "request_id": request_id,
        "relay_only": relay_only, "expected_revision": expected_revision}),
    )
}

/// `host_policy_get` (C→H).
pub fn get(id: &str) -> Value {
    session(json!({"v": 1, "op": "host_policy_get", "id": id}))
}

/// A request the host read (§R9.8a).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    Set {
        id: String,
        request_id: String,
        relay_only: bool,
        expected_revision: u64,
    },
    Get {
        id: String,
    },
}

impl Request {
    pub fn id(&self) -> &str {
        match self {
            Request::Set { id, .. } | Request::Get { id } => id,
        }
    }

    /// Reads a `host_policy_set`/`host_policy_get`'s `data`: exactly its
    /// fields, `v: 1`, UUID v4 ids. `Err` names the field at fault
    /// (`invalid_request`).
    pub fn from_data(data: &Value) -> Result<Request, &'static str> {
        let o = data.as_object().ok_or("data")?;
        if o.get("v").and_then(Value::as_u64) != Some(1) {
            return Err("v");
        }
        let id = o
            .get("id")
            .and_then(Value::as_str)
            .filter(|s| is_uuid_v4(s))
            .ok_or("id")?
            .to_owned();
        match o.get("op").and_then(Value::as_str) {
            Some("host_policy_get") => {
                if o.len() != 3 {
                    return Err("fields");
                }
                Ok(Request::Get { id })
            }
            Some("host_policy_set") => {
                if o.len() != 6 {
                    return Err("fields");
                }
                Ok(Request::Set {
                    id,
                    request_id: o
                        .get("request_id")
                        .and_then(Value::as_str)
                        .filter(|s| is_uuid_v4(s))
                        .ok_or("request_id")?
                        .to_owned(),
                    relay_only: o
                        .get("relay_only")
                        .and_then(Value::as_bool)
                        .ok_or("relay_only")?,
                    expected_revision: o
                        .get("expected_revision")
                        .and_then(Value::as_u64)
                        .ok_or("expected_revision")?,
                })
            }
            _ => Err("op"),
        }
    }
}

/// `host_policy_result` (H→C): built when it is sent, for the channel and
/// attachment it is sent on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPolicyResult {
    pub id: String,
    pub re: String,
    /// A set's `request_id`; none for a get.
    pub request_id: Option<String>,
    pub outcome: Outcome,
    /// The host's current policy when the result was built.
    pub policy: Policy,
    pub account_id: String,
    pub atem_device_id: String,
    pub host_trust_gen: u64,
    pub head: Head,
    pub channel_id: String,
    pub attachment_gen: String,
}

impl HostPolicyResult {
    pub fn to_json(&self) -> Value {
        let mut data = json!({"v": 1, "op": "host_policy_result", "id": self.id, "re": self.re,
            "outcome": self.outcome.as_str(), "policy": self.policy.to_json(),
            "account_id": self.account_id, "atem_device_id": self.atem_device_id,
            "host_trust_gen": self.host_trust_gen, "head": self.head.to_json(),
            "channel_id": self.channel_id, "attachment_gen": self.attachment_gen});
        if let Some(r) = &self.request_id {
            data["request_id"] = json!(r);
        }
        session(data)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_json().to_string().into_bytes()
    }

    /// Reads a result's `data`: exactly its fields (`request_id` only on a
    /// set's outcomes, never on `current`).
    pub fn from_data(data: &Value) -> Result<HostPolicyResult, &'static str> {
        let o = data.as_object().ok_or("data")?;
        if o.get("op").and_then(Value::as_str) != Some("host_policy_result") {
            return Err("op");
        }
        if o.get("v").and_then(Value::as_u64) != Some(1) {
            return Err("v");
        }
        let s = |k: &'static str| -> Result<String, &'static str> {
            o.get(k).and_then(Value::as_str).map(str::to_owned).ok_or(k)
        };
        let outcome = Outcome::parse(&s("outcome")?).ok_or("outcome")?;
        let request_id = match o.get("request_id") {
            None => None,
            Some(v) => Some(
                v.as_str()
                    .filter(|r| is_uuid_v4(r))
                    .ok_or("request_id")?
                    .to_owned(),
            ),
        };
        if (outcome == Outcome::Current) != request_id.is_none() {
            return Err("request_id");
        }
        if o.len() != 12 + usize::from(request_id.is_some()) {
            return Err("fields");
        }
        Ok(HostPolicyResult {
            id: s("id")?,
            re: s("re")?,
            request_id,
            outcome,
            policy: o
                .get("policy")
                .and_then(Policy::from_json)
                .ok_or("policy")?,
            account_id: s("account_id")?,
            atem_device_id: s("atem_device_id")?,
            host_trust_gen: o
                .get("host_trust_gen")
                .and_then(Value::as_u64)
                .ok_or("host_trust_gen")?,
            head: o.get("head").and_then(Head::from_json).ok_or("head")?,
            channel_id: s("channel_id")?,
            attachment_gen: s("attachment_gen")?,
        })
    }
}

/// `host_policy_changed` (H→C, an event): another manager's change
/// committed; the host's current policy, bound like a result. It never
/// confirms anything (it answers no request of this attachment); it ends
/// readiness when it contradicts the wanted value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPolicyChanged {
    pub id: String,
    pub policy: Policy,
    pub account_id: String,
    pub atem_device_id: String,
    pub host_trust_gen: u64,
    pub head: Head,
    pub channel_id: String,
    pub attachment_gen: String,
}

impl HostPolicyChanged {
    pub fn to_json(&self) -> Value {
        session(json!({"v": 1, "op": "host_policy_changed", "id": self.id,
            "policy": self.policy.to_json(),
            "account_id": self.account_id, "atem_device_id": self.atem_device_id,
            "host_trust_gen": self.host_trust_gen, "head": self.head.to_json(),
            "channel_id": self.channel_id, "attachment_gen": self.attachment_gen}))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_json().to_string().into_bytes()
    }

    /// Exactly its fields.
    pub fn from_data(data: &Value) -> Result<HostPolicyChanged, &'static str> {
        let o = data.as_object().ok_or("data")?;
        if o.get("op").and_then(Value::as_str) != Some("host_policy_changed") {
            return Err("op");
        }
        if o.get("v").and_then(Value::as_u64) != Some(1) {
            return Err("v");
        }
        if o.len() != 10 {
            return Err("fields");
        }
        let s = |k: &'static str| -> Result<String, &'static str> {
            o.get(k).and_then(Value::as_str).map(str::to_owned).ok_or(k)
        };
        Ok(HostPolicyChanged {
            id: s("id")?,
            policy: o
                .get("policy")
                .and_then(Policy::from_json)
                .ok_or("policy")?,
            account_id: s("account_id")?,
            atem_device_id: s("atem_device_id")?,
            host_trust_gen: o
                .get("host_trust_gen")
                .and_then(Value::as_u64)
                .ok_or("host_trust_gen")?,
            head: o.get("head").and_then(Head::from_json).ok_or("head")?,
            channel_id: s("channel_id")?,
            attachment_gen: s("attachment_gen")?,
        })
    }
}

/// What a result did to the tracker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observed {
    /// Not one of this attachment's outstanding requests, or bound to
    /// another host, trust generation, channel or attachment: ignored.
    Foreign,
    /// Ours, and the policy is confirmed as wanted.
    Ready,
    /// Ours, and not ready after it (it reported an uncertain state or
    /// another value, or never confirmed and nothing did before).
    NotReady,
}

/// The client's readiness for relay only, bound to one admitted attachment
/// (a new attachment starts a new tracker: not ready).
#[derive(Debug, Clone)]
pub struct HostPolicyTracker {
    account_id: String,
    atem_device_id: String,
    host_trust_gen: u64,
    channel_id: String,
    attachment_gen: String,
    supported: bool,
    desired: bool,
    outstanding: HashSet<String>,
    /// The newest policy a bound result reported (for `expected_revision`).
    known: Option<Policy>,
    ready: bool,
}

impl HostPolicyTracker {
    /// For the attachment `welcome` admitted; `desired` is the value the
    /// app wants confirmed.
    pub fn new(welcome: &Welcome, desired: bool) -> HostPolicyTracker {
        HostPolicyTracker {
            account_id: welcome.account_id.clone(),
            atem_device_id: welcome.atem_device_id.clone(),
            host_trust_gen: welcome.host_trust_gen,
            channel_id: welcome.channel_id.clone(),
            attachment_gen: welcome.attachment_gen.clone(),
            supported: welcome.features.iter().any(|f| f == FEATURE),
            desired,
            outstanding: HashSet::new(),
            known: None,
            ready: false,
        }
    }

    /// Whether the host advertised `host.policy` (without it: never ready).
    pub fn supported(&self) -> bool {
        self.supported
    }

    pub fn ready(&self) -> bool {
        self.ready
    }

    /// The newest policy a bound result of this attachment reported.
    pub fn known(&self) -> Option<Policy> {
        self.known
    }

    /// Changes the wanted value: not ready until a result confirms it.
    pub fn set_desired(&mut self, desired: bool) {
        if desired != self.desired {
            self.desired = desired;
            self.ready = false;
        }
    }

    /// A `host_policy_get` to send; its `id` becomes outstanding.
    pub fn get(&mut self) -> Value {
        let id = crate::session::new_id();
        self.outstanding.insert(id.clone());
        get(&id)
    }

    /// A `host_policy_set` of the wanted value against the newest known
    /// revision (0 before any result); `request_id` is the caller's (kept
    /// for retries, see [`HostPolicyTracker::retry`]).
    pub fn set(&mut self, request_id: &str) -> Value {
        let expected = self.known.map_or(0, |p| p.revision);
        self.retry(request_id, expected)
    }

    /// The same change again (same `request_id`, the same body) under a
    /// fresh `id`.
    pub fn retry(&mut self, request_id: &str, expected_revision: u64) -> Value {
        let id = crate::session::new_id();
        self.outstanding.insert(id.clone());
        set(&id, request_id, self.desired, expected_revision)
    }

    fn bound(
        &self,
        account_id: &str,
        atem_device_id: &str,
        host_trust_gen: u64,
        channel_id: &str,
        attachment_gen: &str,
    ) -> bool {
        account_id == self.account_id
            && atem_device_id == self.atem_device_id
            && host_trust_gen == self.host_trust_gen
            && channel_id == self.channel_id
            && attachment_gen == self.attachment_gen
    }

    /// Applies another manager's change (`host_policy_changed`): it never
    /// confirms; a policy other than the wanted durable one ends readiness.
    pub fn observe_change(&mut self, change: &HostPolicyChanged) -> Observed {
        if !self.bound(
            &change.account_id,
            &change.atem_device_id,
            change.host_trust_gen,
            &change.channel_id,
            &change.attachment_gen,
        ) {
            return Observed::Foreign;
        }
        if self
            .known
            .is_none_or(|k| change.policy.revision >= k.revision)
        {
            self.known = Some(change.policy);
        }
        if change.policy.state != PolicyState::Durable || change.policy.relay_only != self.desired {
            self.ready = false;
        }
        if self.ready {
            Observed::Ready
        } else {
            Observed::NotReady
        }
    }

    /// Applies a result received on this attachment's channel.
    pub fn observe(&mut self, result: &HostPolicyResult) -> Observed {
        let bound = self.bound(
            &result.account_id,
            &result.atem_device_id,
            result.host_trust_gen,
            &result.channel_id,
            &result.attachment_gen,
        );
        if !bound || !self.outstanding.remove(&result.re) {
            return Observed::Foreign;
        }
        if self
            .known
            .is_none_or(|k| result.policy.revision >= k.revision)
        {
            self.known = Some(result.policy);
        }
        // The result's policy is the host's current one: a contradicting
        // policy ends readiness whatever the outcome; only a confirming
        // outcome starts it.
        let matches =
            result.policy.state == PolicyState::Durable && result.policy.relay_only == self.desired;
        if !matches {
            self.ready = false;
        } else if self.supported && result.outcome.confirms() {
            self.ready = true;
        }
        if self.ready {
            Observed::Ready
        } else {
            Observed::NotReady
        }
    }
}

#[cfg(test)]
#[path = "host_policy_tests.rs"]
mod tests;
