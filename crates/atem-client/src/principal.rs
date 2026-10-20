//! Principals, scope, expiry and grants (§R9.6), as pure checks the host
//! runs at admission and on every request, and a client runs before it
//! connects or issues a grant.
//!
//! | kind | proof | principal | permissions |
//! |---|---|---|---|
//! | native | member of kind `native` at the head; `sig_c` by its `auth_key` | `member:<id>` | `view`; `control` with the `control` role |
//! | service | member of kind `service`, not expired, host in `scope.hosts` | `service:<id>` | `view`; `control` if `scope.ops` has a control op; each op checked |
//! | browser | a grant whose issuer is a native member with `control` | `browser:<grant_id>` | `view`; `control` if the grant's `ops` have a control op |
//!
//! [`Authority::resolve`] (or [`Authority::of_member`] after a carriage was
//! judged) gives the key `sig_c` must verify with, the permissions, the
//! scope and the expiry; [`Authority::allows`] checks one request's op and
//! [`Authority::session_in_scope`] one session. Refusals are `unauthorized`
//! with the detail the fixtures name (`not a member`, `removed`, `expired`,
//! `grant revoked`, `invalid grant`, `issuer fenced`, `out of scope`).
//!
//! [`BrowserGrant`] parses a grant strictly (§R9.1: exact fields, the
//! browser key pinned to P-256) and checks it against the head and the
//! clock; [`BrowserGrant::issue`] is what a phone signs for a QR code.
use std::collections::BTreeSet;

use serde_json::{Map, Value, json};

use crate::SignedObject;
use crate::channel::{NATIVE_LIFETIME_MS, Principal};
use crate::encoding::Hash32;
use crate::error::{Error, Result};
use crate::keys::{Alg, PublicKey};
use crate::membership::{
    Admission, HostNow, Member, MemberKind, MemberStatus, Membership, Role, Scope,
};
use crate::provider::{KeyId, KeyProvider};
use crate::session::wire::{is_session_id, is_uuid_v4};

/// A grant lives at most an hour (`expires_at − issued_at`).
pub const GRANT_MAX_LIFETIME_MS: u64 = 3_600_000;
/// A grant's `issued_at` may be at most this far ahead of Atem's clock.
pub const GRANT_ISSUED_AHEAD_MS: u64 = 300_000;
/// Atem journals at most this many revoked grant ids (until their expiry).
pub const MAX_REVOKED_GRANTS: usize = 256;

/// The ops of §R9.6 (service `scope.ops`, grant `ops`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Op {
    /// Registry, chat open/history, terminal subscribe, `receipt_query`.
    View,
    /// Prompt submits (with or without §F acquire).
    Prompt,
    Interrupt,
    Stop,
    /// Terminal input and resize.
    Terminal,
    /// §G approval answers.
    Approval,
    RuleRevoke,
}

impl Op {
    pub const ALL: [Op; 7] = [
        Op::View,
        Op::Prompt,
        Op::Interrupt,
        Op::Stop,
        Op::Terminal,
        Op::Approval,
        Op::RuleRevoke,
    ];

    pub fn parse(name: &str) -> Option<Op> {
        Op::ALL.into_iter().find(|op| op.as_str() == name)
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Op::View => "view",
            Op::Prompt => "prompt",
            Op::Interrupt => "interrupt",
            Op::Stop => "stop",
            Op::Terminal => "terminal",
            Op::Approval => "approval",
            Op::RuleRevoke => "rule_revoke",
        }
    }

    /// Every op but `view` is a control op.
    pub const fn is_control(self) -> bool {
        !matches!(self, Op::View)
    }
}

/// Op names as a wire set: sorted by bytes (§R9.2), whatever the enum
/// order.
pub fn op_names(ops: &BTreeSet<Op>) -> Vec<&'static str> {
    let mut names: Vec<&'static str> = ops.iter().map(|o| o.as_str()).collect();
    names.sort_unstable();
    names
}

/// What a request needs (§R9.6 "Ops"; r8's ops map onto these).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Need {
    Op(Op),
    /// `acquire`/`renew`/`release`: one of `prompt`, `interrupt`, `stop`,
    /// `terminal`.
    Lease,
    /// An attachment with `control`.
    Control,
    /// `approval_seen` (R9.9): an attachment with `control`, and for a
    /// scoped principal the `approval` op (§R9.6: "approvals only with
    /// `approval` in `ops`").
    Seen,
    /// `revoke_grant`: the grant's issuer or any member with `control`
    /// (§R9.6, services included; a browser never revokes: it holds a
    /// grant, it isn't a member).
    RevokeGrant,
}

impl Need {
    /// What one request needs, from its family and `data` as received
    /// (before the strict field decode, so a principal outside its ops gets
    /// `forbidden` and learns nothing from field validation). `None` for a
    /// message a client may always send (`hello`) or one that isn't a
    /// request (the host's own messages); the caller refuses those as before.
    pub fn of_request(family: &str, data: &Value) -> Option<Need> {
        let op = data.get("op").and_then(Value::as_str)?;
        Some(match (family, op) {
            ("session", "list" | "receipt_query") => Need::Op(Op::View),
            ("session", "acquire" | "renew" | "release") => Need::Lease,
            ("session", "submit") => Need::Op(match data.get("kind").and_then(Value::as_str)? {
                "prompt" => Op::Prompt,
                "interrupt" => Op::Interrupt,
                "stop" => Op::Stop,
                "approval" => Op::Approval,
                "approval_rule_revoke" => Op::RuleRevoke,
                _ => return None,
            }),
            ("session", "approval_seen") => Need::Seen,
            ("session", "revoke_grant") => Need::RevokeGrant,
            ("session", "membership") => Need::Op(Op::View),
            ("terminal", "input" | "resize") => Need::Op(Op::Terminal),
            ("terminal", "stop") => Need::Op(Op::Stop),
            ("terminal", _) => Need::Op(Op::View),
            ("agentChat", "submit") => {
                if data.get("approval").is_some() {
                    Need::Op(Op::Approval)
                } else if data.get("approval_rule_revoke").is_some() {
                    Need::Op(Op::RuleRevoke)
                } else {
                    Need::Op(Op::Prompt)
                }
            }
            ("agentChat", _) => Need::Op(Op::View),
            _ => return None,
        })
    }

    /// The session a request names (`binding.target.session_id`), if any.
    pub fn session_of(data: &Value) -> Option<&str> {
        data.get("binding")?
            .get("target")?
            .get("session_id")?
            .as_str()
    }
}

/// Why [`Authority::authorize`] refused a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denied {
    /// The op is outside the principal's ops or permissions.
    Forbidden,
    /// The session is outside its scope (or doesn't exist): the same answer
    /// in registry, chat, terminal and receipts alike (§R9.6).
    UnknownSession,
}

impl Denied {
    pub const fn code(self) -> &'static str {
        match self {
            Denied::Forbidden => "forbidden",
            Denied::UnknownSession => "unknown_session",
        }
    }
}

/// The session a request names, as the host knows it: `None` when the
/// host has no such session; else its host id and how its recorded launch
/// project matches a scope entry (see [`Authority::session_in_scope`]).
pub struct SessionRef<'a> {
    pub host_id: &'a str,
    pub session_id: &'a str,
    pub project_matches: &'a dyn Fn(&str) -> Option<bool>,
}

/// `view` and `control`, as `welcome.permissions` lists them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Permission {
    Control,
    View,
}

impl Permission {
    pub const fn as_str(self) -> &'static str {
        match self {
            Permission::Control => "control",
            Permission::View => "view",
        }
    }
}

/// `welcome.client_kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientKind {
    Native,
    Service,
    Browser,
}

impl ClientKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            ClientKind::Native => "native",
            ClientKind::Service => "service",
            ClientKind::Browser => "browser",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "native" => ClientKind::Native,
            "service" => ClientKind::Service,
            "browser" => ClientKind::Browser,
            _ => return None,
        })
    }

    pub fn of(principal: &Principal) -> Self {
        match principal {
            Principal::Native { .. } => ClientKind::Native,
            Principal::Service { .. } => ClientKind::Service,
            Principal::Browser { .. } => ClientKind::Browser,
        }
    }
}

/// Why a principal isn't admitted (or is fenced).
#[derive(Debug, Clone, PartialEq)]
pub enum Refusal {
    /// `unauthorized` with this detail.
    Unauthorized(&'static str),
    /// The membership side refused first (`account_frozen`,
    /// `recovery_pending`, …): the host answers with the admission's error.
    Membership(Box<Admission>),
}

impl Refusal {
    pub fn detail(&self) -> Option<&'static str> {
        match self {
            Refusal::Unauthorized(d) => Some(d),
            Refusal::Membership(_) => None,
        }
    }
}

// ------------------------------------------------------------------ grant

/// A strictly parsed `atem-browser-grant` (§R9.6). Its signature and
/// authority are checked by [`BrowserGrant::verify`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserGrant {
    pub object: SignedObject,
    pub grant_id: String,
    pub account_id: String,
    pub genesis_hash: Hash32,
    pub issuer: String,
    pub browser_key: PublicKey,
    pub host_id: String,
    pub host_trust_gen: u64,
    pub session_id: Option<String>,
    pub ops: BTreeSet<Op>,
    pub issued_at: u64,
    pub expires_at: u64,
}

/// The fields a grant body may have (§R9.1: no unknown fields).
const GRANT_FIELDS: &[&str] = &[
    "type",
    "v",
    "grant_id",
    "account_id",
    "genesis_hash",
    "issuer",
    "browser_key",
    "target",
    "ops",
    "issued_at",
    "expires_at",
];

fn field<'a>(object: &'a Map<String, Value>, name: &'static str) -> Result<&'a Value> {
    object.get(name).ok_or(Error::Malformed(name))
}

fn string(object: &Map<String, Value>, name: &'static str) -> Result<String> {
    Ok(field(object, name)?
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or(Error::Malformed(name))?
        .to_owned())
}

fn integer(object: &Map<String, Value>, name: &'static str) -> Result<u64> {
    field(object, name)?.as_u64().ok_or(Error::Malformed(name))
}

/// Parses an `ops` set (sorted, unique by the signed-object rules; known
/// names; `view` included). Absent: `["view"]`.
fn ops(value: Option<&Value>) -> Result<BTreeSet<Op>> {
    let Some(value) = value else {
        return Ok(BTreeSet::from([Op::View]));
    };
    let items = value.as_array().ok_or(Error::Malformed("ops"))?;
    let mut set = BTreeSet::new();
    for item in items {
        let op = item
            .as_str()
            .and_then(Op::parse)
            .ok_or(Error::Malformed("ops: unknown op"))?;
        set.insert(op);
    }
    if !set.contains(&Op::View) {
        return Err(Error::Malformed("ops must contain view"));
    }
    Ok(set)
}

impl BrowserGrant {
    /// Strict parse of a signed grant: exactly the grant's fields (and the
    /// target's), `grant_id` a UUID v4, `browser_key` P-256 only.
    pub fn parse(object: SignedObject) -> Result<Self> {
        if object.body_type() != "atem-browser-grant" {
            return Err(Error::UnknownType);
        }
        let body = object
            .body()
            .as_object()
            .ok_or(Error::Malformed("body"))?
            .clone();
        if let Some(extra) = body.keys().find(|k| !GRANT_FIELDS.contains(&k.as_str())) {
            let _ = extra;
            return Err(Error::Malformed("unknown field in a grant"));
        }
        let grant_id = string(&body, "grant_id")?;
        if !is_uuid_v4(&grant_id) {
            return Err(Error::Malformed("grant_id"));
        }
        let genesis_hash = Hash32::from_hex(
            field(&body, "genesis_hash")?
                .as_str()
                .ok_or(Error::Malformed("genesis_hash"))?,
        )?;
        let browser_key = PublicKey::from_json_as(field(&body, "browser_key")?, Alg::P256)?;
        let target = field(&body, "target")?
            .as_object()
            .ok_or(Error::Malformed("target"))?;
        if target
            .keys()
            .any(|k| !matches!(k.as_str(), "host_id" | "host_trust_gen" | "session_id"))
        {
            return Err(Error::Malformed("unknown field in a grant target"));
        }
        let session_id = match target.get("session_id") {
            None => None,
            Some(v) => {
                let id = v.as_str().ok_or(Error::Malformed("target.session_id"))?;
                if !is_session_id(id) {
                    return Err(Error::Malformed("target.session_id"));
                }
                Some(id.to_owned())
            }
        };
        let host_trust_gen = integer(target, "host_trust_gen")?;
        if host_trust_gen == 0 {
            return Err(Error::Malformed("target.host_trust_gen"));
        }
        Ok(BrowserGrant {
            grant_id,
            account_id: string(&body, "account_id")?,
            genesis_hash,
            issuer: string(&body, "issuer")?,
            browser_key,
            host_id: string(target, "host_id")?,
            host_trust_gen,
            session_id,
            ops: ops(body.get("ops"))?,
            issued_at: integer(&body, "issued_at")?,
            expires_at: integer(&body, "expires_at")?,
            object,
        })
    }

    /// The grant's body for a phone to sign ([`BrowserGrant::issue`]).
    #[allow(clippy::too_many_arguments)]
    pub fn body(
        log: &Membership,
        grant_id: &str,
        issuer: &str,
        browser_key: &PublicKey,
        host_id: &str,
        host_trust_gen: u64,
        session_id: Option<&str>,
        ops: &BTreeSet<Op>,
        issued_at: u64,
        expires_at: u64,
    ) -> Value {
        let mut target = json!({"host_id": host_id, "host_trust_gen": host_trust_gen});
        if let Some(session) = session_id {
            target["session_id"] = json!(session);
        }
        json!({
            "type": "atem-browser-grant", "v": 1, "grant_id": grant_id,
            "account_id": log.account_id(), "genesis_hash": log.genesis_hash().to_hex(),
            "issuer": issuer, "browser_key": browser_key.to_json(), "target": target,
            "ops": op_names(ops),
            "issued_at": issued_at, "expires_at": expires_at,
        })
    }

    /// Signs a grant with the issuer's `auth_key` (a native member with
    /// `control`; §R9.6 requires a fresh owner confirmation for it). Checks
    /// the issuer's standing and the lifetime first, so a phone never hands
    /// out a grant Atem would refuse.
    pub fn issue(
        log: &Membership,
        provider: &dyn KeyProvider,
        key: &KeyId,
        body: Value,
    ) -> Result<BrowserGrant> {
        let grant = BrowserGrant::parse(SignedObject::sign(provider, key, body)?)?;
        grant
            .check_static(log)
            .map_err(|_| Error::Malformed("not a valid grant"))?;
        Ok(grant)
    }

    /// `grant_hash` (bound into `th3`).
    pub fn grant_hash(&self) -> Hash32 {
        self.object.grant_hash().expect("a grant has a grant hash")
    }

    /// The browser principal it names.
    pub fn principal(&self) -> Principal {
        Principal::Browser {
            grant_id: self.grant_id.clone(),
            grant_hash: self.grant_hash(),
        }
    }

    /// Everything but the clock and revocation: account and genesis,
    /// lifetime ≤ 1 h, the issuer a native member with `control` at the
    /// head, and the issuer's signature. `Unauthorized("invalid grant")`
    /// when it never was valid, `"issuer fenced"` when its issuer was
    /// removed or lost `control`.
    fn check_static<'l>(&self, log: &'l Membership) -> std::result::Result<&'l Member, Refusal> {
        let invalid = Refusal::Unauthorized("invalid grant");
        if self.account_id != log.account_id() || self.genesis_hash != log.genesis_hash() {
            return Err(invalid);
        }
        if self.expires_at <= self.issued_at
            || self.expires_at - self.issued_at > GRANT_MAX_LIFETIME_MS
        {
            return Err(invalid);
        }
        let issuer = log.member(&self.issuer).ok_or(invalid.clone())?;
        if !issuer.member.is_native() {
            return Err(invalid);
        }
        if self.object.verify(&issuer.member.auth_key).is_err() {
            return Err(invalid);
        }
        if issuer.status != MemberStatus::Active || !issuer.member.has_role(Role::Control) {
            return Err(Refusal::Unauthorized("issuer fenced"));
        }
        Ok(&issuer.member)
    }

    /// The whole §R9.6 check at a host (`host_id` at `host_trust_gen`):
    /// static validity, the target, `issued_at ≤ now + 300 s`, `now <
    /// expires_at`, and not revoked.
    pub fn verify(
        &self,
        log: &Membership,
        host_id: &str,
        host_trust_gen: u64,
        now_wall_ms: u64,
        revoked: &dyn Fn(&str) -> bool,
    ) -> std::result::Result<(), Refusal> {
        self.check_static(log)?;
        if self.host_id != host_id || self.host_trust_gen != host_trust_gen {
            return Err(Refusal::Unauthorized("invalid grant"));
        }
        if revoked(&self.grant_id) {
            return Err(Refusal::Unauthorized("grant revoked"));
        }
        if self.issued_at > now_wall_ms.saturating_add(GRANT_ISSUED_AHEAD_MS) {
            return Err(Refusal::Unauthorized("invalid grant"));
        }
        if now_wall_ms >= self.expires_at {
            return Err(Refusal::Unauthorized("expired"));
        }
        Ok(())
    }
}

// -------------------------------------------------------------- authority

/// A service's or browser's restriction, as `welcome.scope` shows it:
/// `{ops, sessions?, projects?}` (and the hosts, for the host's checks).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeView {
    pub ops: BTreeSet<Op>,
    pub hosts: Option<Vec<String>>,
    pub sessions: Option<Vec<String>>,
    pub projects: Option<Vec<String>>,
}

impl ScopeView {
    /// `welcome.scope`.
    pub fn to_json(&self) -> Value {
        let mut out = json!({ "ops": op_names(&self.ops) });
        if let Some(sessions) = &self.sessions {
            out["sessions"] = json!(sessions);
        }
        if let Some(projects) = &self.projects {
            out["projects"] = json!(projects);
        }
        out
    }

    /// `welcome.scope` as received.
    pub fn from_json(value: &Value) -> Option<ScopeView> {
        let object = value.as_object()?;
        let list = |k: &str| -> Option<Option<Vec<String>>> {
            match object.get(k) {
                None => Some(None),
                Some(v) => Some(Some(
                    v.as_array()?
                        .iter()
                        .map(|s| s.as_str().map(str::to_owned))
                        .collect::<Option<Vec<_>>>()?,
                )),
            }
        };
        Some(ScopeView {
            ops: ops(Some(object.get("ops")?)).ok()?,
            hosts: None,
            sessions: list("sessions")?,
            projects: list("projects")?,
        })
    }

    fn of_service(scope: &Scope) -> Option<ScopeView> {
        Some(ScopeView {
            ops: ops(Some(&json!(scope.ops))).ok()?,
            hosts: Some(scope.hosts.clone()),
            sessions: scope.sessions.clone(),
            projects: scope.projects.clone(),
        })
    }
}

/// What a principal may do on this host, resolved against the committed
/// head (§R9.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authority {
    pub principal: Principal,
    pub client_kind: ClientKind,
    /// The key `sig_c` must verify with.
    pub key: PublicKey,
    /// `view`, and `control` when allowed.
    pub permissions: BTreeSet<Permission>,
    /// Service and browser: their ops and scope. Native: none (roles).
    pub scope: Option<ScopeView>,
    /// Service and browser: the wall-clock expiry. Native members never
    /// expire (they are removed).
    pub expires_at: Option<u64>,
    /// Browser: the issuer (recorded).
    pub issuer: Option<String>,
}

impl Authority {
    /// `member:<id>`, `service:<id>` or `browser:<grant_id>`.
    pub fn name(&self) -> String {
        self.principal.name()
    }

    /// A native or service member admitted by the membership side (an
    /// [`Admission::Member`] from `Membership::admit` or
    /// `Evaluation::admission`): checks the principal's kind against the
    /// member's, a service's expiry and host.
    pub fn of_member(
        principal: &Principal,
        member: &Member,
        host_id: &str,
        now_wall_ms: u64,
    ) -> std::result::Result<Authority, Refusal> {
        match (principal, &member.kind) {
            (Principal::Native { .. }, MemberKind::Native { roles, .. }) => {
                let mut permissions = BTreeSet::from([Permission::View]);
                if roles.contains(&Role::Control) {
                    permissions.insert(Permission::Control);
                }
                Ok(Authority {
                    principal: principal.clone(),
                    client_kind: ClientKind::Native,
                    key: member.auth_key.clone(),
                    permissions,
                    scope: None,
                    expires_at: None,
                    issuer: None,
                })
            }
            (Principal::Service { .. }, MemberKind::Service { scope, expires_at }) => {
                if now_wall_ms >= *expires_at {
                    return Err(Refusal::Unauthorized("expired"));
                }
                if !scope.hosts.iter().any(|h| h == host_id) {
                    return Err(Refusal::Unauthorized("out of scope"));
                }
                let view =
                    ScopeView::of_service(scope).ok_or(Refusal::Unauthorized("not a member"))?;
                let mut permissions = BTreeSet::from([Permission::View]);
                if view.ops.iter().any(|o| o.is_control()) {
                    permissions.insert(Permission::Control);
                }
                Ok(Authority {
                    principal: principal.clone(),
                    client_kind: ClientKind::Service,
                    key: member.auth_key.clone(),
                    permissions,
                    scope: Some(view),
                    expires_at: Some(*expires_at),
                    issuer: None,
                })
            }
            // A device claiming another kind than its entry's.
            _ => Err(Refusal::Unauthorized("not a member")),
        }
    }

    /// A browser with its grant (checked with [`BrowserGrant::verify`]).
    pub fn of_grant(
        grant: &BrowserGrant,
        log: &Membership,
        host_id: &str,
        host_trust_gen: u64,
        now_wall_ms: u64,
        revoked: &dyn Fn(&str) -> bool,
    ) -> std::result::Result<Authority, Refusal> {
        grant.verify(log, host_id, host_trust_gen, now_wall_ms, revoked)?;
        let mut permissions = BTreeSet::from([Permission::View]);
        if grant.ops.iter().any(|o| o.is_control()) {
            permissions.insert(Permission::Control);
        }
        Ok(Authority {
            principal: grant.principal(),
            client_kind: ClientKind::Browser,
            key: grant.browser_key.clone(),
            permissions,
            scope: Some(ScopeView {
                ops: grant.ops.clone(),
                hosts: Some(vec![grant.host_id.clone()]),
                sessions: grant.session_id.clone().map(|s| vec![s]),
                projects: None,
            }),
            expires_at: Some(grant.expires_at),
            issuer: Some(grant.issuer.clone()),
        })
    }

    /// The whole resolution for a `hello` with no carriage (or after the
    /// carriage committed): the membership side (`Membership::admit`:
    /// frozen, removed, recovery pending, …) for native and service
    /// principals, the grant for a browser. `grant` is the hello's.
    pub fn resolve(
        log: &Membership,
        principal: &Principal,
        grant: Option<&SignedObject>,
        host_id: &str,
        host_trust_gen: u64,
        now: &HostNow,
        revoked: &dyn Fn(&str) -> bool,
    ) -> std::result::Result<Authority, Refusal> {
        match principal {
            Principal::Native { device_id } | Principal::Service { device_id } => {
                match log.admit(device_id, now) {
                    Admission::Member { state, .. } => {
                        Authority::of_member(principal, &state.member, host_id, now.wall_ms)
                    }
                    Admission::Unauthorized(detail) => Err(Refusal::Unauthorized(detail)),
                    other => Err(Refusal::Membership(Box::new(other))),
                }
            }
            Principal::Browser { grant_hash, .. } => {
                let grant = grant.ok_or(Refusal::Unauthorized("invalid grant"))?;
                let grant = BrowserGrant::parse(grant.clone())
                    .map_err(|_| Refusal::Unauthorized("invalid grant"))?;
                if grant.grant_hash() != *grant_hash {
                    return Err(Refusal::Unauthorized("invalid grant"));
                }
                if log.frozen().is_some() {
                    return Err(Refusal::Membership(Box::new(Admission::Frozen)));
                }
                Authority::of_grant(&grant, log, host_id, host_trust_gen, now.wall_ms, revoked)
            }
        }
    }

    /// Whether a request needing `need` is allowed (`forbidden` otherwise).
    pub fn allows(&self, need: Need) -> bool {
        let control = self.permissions.contains(&Permission::Control);
        match (&self.scope, need) {
            (_, Need::Control) => control,
            (_, Need::RevokeGrant) => self.client_kind != ClientKind::Browser && control,
            (None, Need::Seen) => control,
            (Some(scope), Need::Seen) => control && scope.ops.contains(&Op::Approval),
            (None, Need::Op(Op::View)) => true,
            (None, Need::Op(_) | Need::Lease) => control,
            (Some(scope), Need::Op(op)) => scope.ops.contains(&op),
            (Some(scope), Need::Lease) => [Op::Prompt, Op::Interrupt, Op::Stop, Op::Terminal]
                .iter()
                .any(|op| scope.ops.contains(op)),
        }
    }

    /// The one check a host runs per request (§R9.6): the session first —
    /// a request naming a session outside the scope, or one the host
    /// doesn't have (`session: Some(None)`), is `unknown_session`, so a
    /// principal learns nothing of sessions it can't see — then the op.
    /// `session: None` for a request that names no session (`list`,
    /// `revoke_grant`, `membership`). Results a request returns (the
    /// receipts of `receipt_query`, the registry of `list`) must be
    /// filtered with [`Authority::session_in_scope`] as well.
    pub fn authorize(
        &self,
        need: Need,
        session: Option<Option<&SessionRef<'_>>>,
    ) -> std::result::Result<(), Denied> {
        match session {
            Some(None) => return Err(Denied::UnknownSession),
            Some(Some(s)) if !self.session_in_scope(s.host_id, s.session_id, s.project_matches) => {
                return Err(Denied::UnknownSession);
            }
            _ => {}
        }
        if self.allows(need) {
            Ok(())
        } else {
            Err(Denied::Forbidden)
        }
    }

    /// Whether a session is in scope (`unknown_session` otherwise): its host
    /// is listed, its id (when `sessions` is present), and its launch
    /// project (when `projects` is present). `project_matches(entry)` tells
    /// whether the session's recorded project matches a scope entry
    /// (`h1.<kid>.<hash>` under that entry's `kid`); `None` while it can't
    /// be computed (a locked cred agent), which leaves the session out.
    pub fn session_in_scope(
        &self,
        host_id: &str,
        session_id: &str,
        project_matches: &dyn Fn(&str) -> Option<bool>,
    ) -> bool {
        let Some(scope) = &self.scope else {
            return true;
        };
        if let Some(hosts) = &scope.hosts
            && !hosts.iter().any(|h| h == host_id)
        {
            return false;
        }
        if let Some(sessions) = &scope.sessions
            && !sessions.iter().any(|s| s == session_id)
        {
            return false;
        }
        if let Some(projects) = &scope.projects {
            return projects.iter().any(|p| project_matches(p) == Some(true));
        }
        true
    }

    /// Expired at `now_wall_ms` (a service or browser; the host's timer
    /// fences it then).
    pub fn expired(&self, now_wall_ms: u64) -> bool {
        self.expires_at.is_some_and(|e| now_wall_ms >= e)
    }

    /// `welcome.authorization_ms_left`: min(expiry − now, the channel's
    /// remaining lifetime).
    pub fn authorization_ms_left(&self, now_wall_ms: u64, channel_ms_left: u64) -> u64 {
        match self.expires_at {
            Some(e) => e.saturating_sub(now_wall_ms).min(channel_ms_left),
            None => channel_ms_left,
        }
    }

    /// The channel deadline for [`crate::channel::Keyed::admit`] (monotonic):
    /// 24 h, or the expiry if sooner.
    pub fn channel_deadline_ms(&self, now: &HostNow) -> u64 {
        now.mono_ms + self.authorization_ms_left(now.wall_ms, NATIVE_LIFETIME_MS)
    }
}

/// The session `error` a host sends for a membership-side refusal (§R9.3
/// step 5, §R9.11); `None` for `Admission::Member`.
pub fn admission_error(
    admission: &Admission,
    re: Option<&str>,
) -> Option<crate::session::r9::SessionError> {
    use crate::session::r9::{SessionError, code};
    let mut e = match admission {
        Admission::Member { .. } => return None,
        Admission::Frozen => SessionError::new(code::ACCOUNT_FROZEN),
        Admission::Invalid {
            head,
            index,
            reason,
            need_before,
        } => SessionError {
            head: Some(*head),
            index: Some(*index as u64),
            detail: Some(reason.code().to_owned()),
            need_before: *need_before,
            ..SessionError::new(code::MEMBERSHIP_INVALID)
        },
        Admission::Incomplete { head } => SessionError {
            head: Some(*head),
            ..SessionError::new(code::MEMBERSHIP_INCOMPLETE)
        },
        Admission::RecoveryPending {
            entry_hash,
            effective_at,
        } => SessionError {
            entry_hash: Some(*entry_hash),
            effective_at: Some(*effective_at),
            ..SessionError::new(code::RECOVERY_PENDING)
        },
        Admission::Unauthorized(detail) => SessionError {
            detail: Some((*detail).to_owned()),
            ..SessionError::new(code::UNAUTHORIZED)
        },
    };
    e.re = re.map(str::to_owned);
    Some(e)
}

impl Refusal {
    /// The session `error` for this refusal.
    pub fn to_error(&self, re: Option<&str>) -> crate::session::r9::SessionError {
        match self {
            Refusal::Unauthorized(detail) => crate::session::r9::SessionError {
                re: re.map(str::to_owned),
                detail: Some((*detail).to_owned()),
                ..crate::session::r9::SessionError::new(crate::session::r9::code::UNAUTHORIZED)
            },
            Refusal::Membership(admission) => {
                admission_error(admission, re).expect("a refusal is never a member")
            }
        }
    }
}
