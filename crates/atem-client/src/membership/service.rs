//! Typed builders for service members (§R9.2 `add` and `set_roles`, §R9.6
//! scopes): what a manager drafts to enroll, renew or narrow a bot (a
//! Station agent module, a Discord bridge, a custom app).
//!
//! There is no second wire form here. A [`ServiceScope`] keeps every list
//! as a set (sorted by bytes, no duplicates, §R9.2's canonical order) and
//! always holds `view`; each builder makes the crate's own [`Action`],
//! drafts it with the crate's drafter and runs the verifier's structural
//! parse over the body ([`check_body`]), so a builder returns only an
//! action whose entry the verifier accepts for its shape (bounds, id and
//! hash syntax, ops, the 90-day expiry), or the verifier's own
//! [`Invalid`].
//!
//! The renewal and narrowing helpers start from the service's current
//! grant in a verified log. Pair them with [`super::check_change`] before
//! drafting: a renewal is paced (24 h after the service's last grant, D23),
//! a narrowing never is.
use std::collections::BTreeSet;

use crate::encoding::Hash32;
use crate::keys::PublicKey;

use super::capacity::narrows;
use super::draft::{check_body, draft_on};
use super::entry::{Action, Member, MemberKind, RolesChange, Scope};
use super::{Invalid, MemberStatus, Membership};

/// A service scope (§R9.6) in canonical form: `hosts` and `ops` always,
/// `projects` and `sessions` when they restrict. `view` is always in `ops`
/// (§R9.6 requires it). Setters replace a list; duplicates collapse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceScope {
    hosts: BTreeSet<String>,
    projects: Option<BTreeSet<String>>,
    sessions: Option<BTreeSet<String>>,
    ops: BTreeSet<String>,
}

fn set<I, S>(items: I) -> BTreeSet<String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    items.into_iter().map(Into::into).collect()
}

impl ServiceScope {
    /// A scope on `hosts` with only `view`, no project or session
    /// restriction.
    pub fn new<I, S>(hosts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        ServiceScope {
            hosts: set(hosts),
            projects: None,
            sessions: None,
            ops: BTreeSet::from(["view".to_owned()]),
        }
    }

    /// The scope a verified entry holds (to narrow it).
    pub fn of(scope: &Scope) -> Self {
        ServiceScope {
            hosts: set(scope.hosts.iter().cloned()),
            projects: scope.projects.as_ref().map(|p| set(p.iter().cloned())),
            sessions: scope.sessions.as_ref().map(|s| set(s.iter().cloned())),
            ops: set(scope.ops.iter().cloned()),
        }
        .ops_kept_with_view()
    }

    pub fn hosts<I, S>(mut self, hosts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.hosts = set(hosts);
        self
    }

    /// The ops (§R9.6 `OPS`); `view` is added.
    pub fn ops<I, S>(mut self, ops: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.ops = set(ops);
        self.ops_kept_with_view()
    }

    /// `h1.<kid>.<hash>` launch project hashes ([`crate::project`]);
    /// `None` doesn't restrict.
    pub fn projects<I, S>(mut self, projects: Option<I>) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.projects = projects.map(set);
        self
    }

    /// Session ids (`ses-…`); `None` doesn't restrict.
    pub fn sessions<I, S>(mut self, sessions: Option<I>) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.sessions = sessions.map(set);
        self
    }

    fn ops_kept_with_view(mut self) -> Self {
        self.ops.insert("view".to_owned());
        self
    }

    /// The crate's [`Scope`], lists in canonical order (not yet checked:
    /// the builders below check it with the verifier).
    pub fn scope(&self) -> Scope {
        Scope {
            hosts: self.hosts.iter().cloned().collect(),
            projects: self.projects.as_ref().map(|p| p.iter().cloned().collect()),
            sessions: self.sessions.as_ref().map(|s| s.iter().cloned().collect()),
            ops: self.ops.iter().cloned().collect(),
        }
    }
}

/// Why a renewal or narrowing helper made no action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceChangeError {
    /// The verifier refuses the entry's shape (its own code).
    Invalid(Invalid),
    /// No service member of that id is in effect in the log.
    NotAService,
    /// A renewal's `expires_at` isn't later than the current one.
    NotARenewal,
    /// The scope or expiry grants something the service doesn't hold, or
    /// changes nothing (renew or re-enroll instead).
    NotANarrowing,
}

impl ServiceChangeError {
    pub fn code(&self) -> &'static str {
        match self {
            ServiceChangeError::Invalid(i) => i.code(),
            ServiceChangeError::NotAService => "not_a_service",
            ServiceChangeError::NotARenewal => "not_a_renewal",
            ServiceChangeError::NotANarrowing => "not_a_narrowing",
        }
    }
}

impl std::fmt::Display for ServiceChangeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for ServiceChangeError {}

impl From<Invalid> for ServiceChangeError {
    fn from(i: Invalid) -> Self {
        ServiceChangeError::Invalid(i)
    }
}

/// The action as the verifier parses it: drafted on a placeholder chain
/// position (account, `seq`, hashes and signer don't affect the action's
/// own rules) at `signed_at` (the expiry bound counts from it), then
/// [`check_body`].
fn verified(action: Action, signed_at: u64) -> Result<Action, Invalid> {
    let body = draft_on(
        "service-check",
        &Hash32([0; 32]),
        2,
        &Hash32([0; 32]),
        "service-check",
        signed_at,
        &action,
    );
    Ok(check_body(&body)?.action)
}

/// The `add` of a service member: `auth_key` (P-256 or Ed25519, the bot's
/// own software key, §R9.6 rule 5), `scope`, and `expires_at` at most 90
/// days after `signed_at` (the time the manager signs it).
pub fn service_add(
    device_id: &str,
    auth_key: PublicKey,
    scope: &ServiceScope,
    expires_at: u64,
    signed_at: u64,
) -> Result<Action, Invalid> {
    verified(
        Action::Add {
            member: Member {
                device_id: device_id.to_owned(),
                auth_key,
                kind: MemberKind::Service {
                    scope: scope.scope(),
                    expires_at,
                },
            },
        },
        signed_at,
    )
}

/// A service `set_roles` (roles exactly `["service"]`, `scope`,
/// `expires_at` ≤ 90 days after `signed_at`). Any `set_roles` fences the
/// service's live channels at once; it reconnects under the new grant
/// (§R9.3 step 4).
pub fn service_set_roles(
    device_id: &str,
    scope: &ServiceScope,
    expires_at: u64,
    signed_at: u64,
) -> Result<Action, Invalid> {
    verified(
        Action::SetRoles {
            device_id: device_id.to_owned(),
            change: RolesChange::Service {
                scope: scope.scope(),
                expires_at,
            },
        },
        signed_at,
    )
}

/// The scope and expiry of the service member `device_id` in effect in
/// `log`.
pub fn service_grant<'a>(log: &'a Membership, device_id: &str) -> Option<(&'a Scope, u64)> {
    let state = log.member(device_id)?;
    match (&state.member.kind, &state.status) {
        (MemberKind::Service { scope, expires_at }, MemberStatus::Active) => {
            Some((scope, *expires_at))
        }
        _ => None,
    }
}

/// A renewal: the service's current scope with a later `expires_at`.
/// Paced by [`super::check_change`] (24 h after the last grant).
pub fn service_renewal(
    log: &Membership,
    device_id: &str,
    expires_at: u64,
    signed_at: u64,
) -> Result<Action, ServiceChangeError> {
    let (scope, current) = service_grant(log, device_id).ok_or(ServiceChangeError::NotAService)?;
    if expires_at <= current {
        return Err(ServiceChangeError::NotARenewal);
    }
    Ok(service_set_roles(
        device_id,
        &ServiceScope::of(scope),
        expires_at,
        signed_at,
    )?)
}

/// A narrowing: `scope` and `expires_at` (`None`: the current expiry) grant
/// nothing the service doesn't hold (no new host, op, project or session,
/// no restriction dropped, no later expiry) and change something. Never
/// paced by [`super::check_change`], and it doesn't restart the 24 h.
pub fn service_narrowing(
    log: &Membership,
    device_id: &str,
    scope: &ServiceScope,
    expires_at: Option<u64>,
    signed_at: u64,
) -> Result<Action, ServiceChangeError> {
    let (current, current_expiry) =
        service_grant(log, device_id).ok_or(ServiceChangeError::NotAService)?;
    let expires_at = expires_at.unwrap_or(current_expiry);
    let action = service_set_roles(device_id, scope, expires_at, signed_at)?;
    let Action::SetRoles {
        change: RolesChange::Service { scope: new, .. },
        ..
    } = &action
    else {
        unreachable!("service_set_roles makes a service set_roles");
    };
    if !narrows(current, current_expiry, new, expires_at) {
        return Err(ServiceChangeError::NotANarrowing);
    }
    Ok(action)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Alg;
    use crate::membership::entry::SERVICE_MAX_LIFETIME_MS;
    use crate::membership::{ChangeRefusal, check_change};

    const T0: u64 = 1_800_000_000_000;
    const HASH_A: &str =
        "h1.0123abcd.1111111111111111111111111111111111111111111111111111111111111111";
    const HASH_B: &str =
        "h1.0123abcd.2222222222222222222222222222222222222222222222222222222222222222";

    fn ed_key() -> PublicKey {
        crate::kit::recovery_key_of_seed(&[3; 32])
    }

    /// A log whose genesis manager `mac` signs every entry, each checked
    /// as a verifier would before it is appended.
    fn signed_log() -> (Membership, impl FnMut(&mut Membership, Action, u64)) {
        use crate::kit::RecoveryKit;
        use crate::membership::entry::Role;
        use crate::membership::{Check, HostNow, sign_entry};
        use crate::provider::KeyProvider;
        let mac = RecoveryKit::make(&[1; 32], "acct", Hash32([0; 32]));
        let member = Member {
            device_id: "mac".into(),
            auth_key: mac.recovery_key(),
            kind: MemberKind::Native {
                enc_key: mac.public_key(&RecoveryKit::x25519_id()).unwrap(),
                roles: [Role::Control, Role::Manage, Role::View].into(),
            },
        };
        let body = draft_on(
            "acct",
            &Hash32([0; 32]),
            1,
            &Hash32([0; 32]),
            "mac",
            T0,
            &Action::Genesis {
                member,
                recovery_key: crate::kit::recovery_key_of_seed(&[9; 32]),
            },
        );
        let genesis = sign_entry(&mac, &RecoveryKit::sign_id(), body).unwrap();
        let log = Membership::from_genesis("acct", &genesis.hash(), genesis).unwrap();
        let append = move |log: &mut Membership, action: Action, at: u64| {
            let body = log.draft("mac", at, &action);
            let entry = sign_entry(&mac, &RecoveryKit::sign_id(), body).unwrap();
            assert_eq!(log.check_next(&entry), Check::Valid);
            let now = HostNow {
                wall_ms: at,
                mono_ms: 0,
                boot_id: "b".into(),
            };
            log.append(entry, &now, &mut Vec::new());
        };
        (log, append)
    }

    #[test]
    fn the_scope_is_canonical_and_always_has_view() {
        let scope = ServiceScope::new(["host-b", "host-a", "host-b"])
            .ops(["prompt", "approval", "prompt"])
            .sessions(Some(["ses-bbbbbbbbbbbb", "ses-aaaaaaaaaaaa"]))
            .scope();
        assert_eq!(scope.hosts, ["host-a", "host-b"]);
        assert_eq!(scope.ops, ["approval", "prompt", "view"]);
        assert_eq!(
            scope.sessions.as_deref(),
            Some(&["ses-aaaaaaaaaaaa".to_owned(), "ses-bbbbbbbbbbbb".to_owned()][..])
        );
        assert_eq!(scope.projects, None);
        assert_eq!(
            crate::canonical::jcs(&scope.to_json()).unwrap(),
            r#"{"hosts":["host-a","host-b"],"ops":["approval","prompt","view"],"sessions":["ses-aaaaaaaaaaaa","ses-bbbbbbbbbbbb"]}"#
        );
    }

    #[test]
    fn builders_return_what_the_verifier_parses_or_its_refusal() {
        let scope = ServiceScope::new(["host-a"])
            .ops(["prompt"])
            .projects(Some([HASH_B, HASH_A]));
        let add = service_add("svc-bot", ed_key(), &scope, T0 + 3_600_000, T0).unwrap();
        let Action::Add { member } = &add else {
            panic!("an add")
        };
        assert!(matches!(&member.kind, MemberKind::Service { scope: s, .. }
            if s.projects.as_deref() == Some(&[HASH_A.to_owned(), HASH_B.to_owned()][..])));
        // The verifier's own rules, never the builder's.
        let cases: Vec<(ServiceScope, u64, Invalid)> = vec![
            (
                ServiceScope::new(Vec::<String>::new()),
                T0,
                Invalid::BadScope,
            ),
            (
                ServiceScope::new(["host-a"]).ops(["fly"]),
                T0,
                Invalid::BadScope,
            ),
            (
                ServiceScope::new(["host-a"]).sessions(Some(["ses-x"])),
                T0,
                Invalid::BadScope,
            ),
            (
                ServiceScope::new(["host-a"]).projects(Some(["h1.k.zz"])),
                T0,
                Invalid::BadScope,
            ),
            (
                ServiceScope::new((0..17).map(|i| format!("host-{i}"))),
                T0,
                Invalid::BadScope,
            ),
            (ServiceScope::new(["host a"]), T0, Invalid::BadScope),
            (
                ServiceScope::new(["host-a"]),
                T0 + SERVICE_MAX_LIFETIME_MS + 1,
                Invalid::ServiceExpiry,
            ),
        ];
        for (scope, expires_at, want) in cases {
            assert_eq!(
                service_add("svc-bot", ed_key(), &scope, expires_at, T0),
                Err(want.clone()),
                "{scope:?}"
            );
            assert_eq!(
                service_set_roles("svc-bot", &scope, expires_at, T0),
                Err(want),
                "{scope:?}"
            );
        }
        assert_eq!(
            service_add("recovery", ed_key(), &ServiceScope::new(["host-a"]), T0, T0),
            Err(Invalid::Malformed("device_id"))
        );
        let x25519 = PublicKey::new(Alg::X25519, &[9; 32]).unwrap();
        assert_eq!(
            service_add("svc-bot", x25519, &ServiceScope::new(["host-a"]), T0, T0),
            Err(Invalid::WrongAlg)
        );
        // At the bound exactly: valid.
        assert!(
            service_set_roles(
                "svc-bot",
                &ServiceScope::new(["host-a"]),
                T0 + SERVICE_MAX_LIFETIME_MS,
                T0
            )
            .is_ok()
        );
    }

    /// The helpers on a real log, with `check_change` beside them.
    #[test]
    fn renewal_and_narrowing_pair_with_check_change() {
        let (mut log, mut append) = signed_log();
        let scope = ServiceScope::new(["host-a", "host-b"])
            .ops(["prompt", "interrupt"])
            .projects(Some([HASH_A, HASH_B]));
        let add = service_add("svc-bot", ed_key(), &scope, T0 + 3_600_000, T0).unwrap();
        append(&mut log, add, T0);
        assert_eq!(
            service_grant(&log, "svc-bot").map(|(_, e)| e),
            Some(T0 + 3_600_000)
        );

        // Renewal: same scope, later expiry; paced for 24 h.
        let renew = service_renewal(&log, "svc-bot", T0 + 7_200_000, T0 + 60_000).unwrap();
        assert!(
            matches!(&renew, Action::SetRoles { change: RolesChange::Service { scope: s, expires_at }, .. }
            if *s == scope.scope() && *expires_at == T0 + 7_200_000)
        );
        assert!(matches!(
            check_change(&log, &renew, T0 + 60_000),
            Err(ChangeRefusal::ServiceChangeTooSoon { .. })
        ));
        assert_eq!(
            check_change(
                &log,
                &renew,
                T0 + super::super::SERVICE_CHANGE_MIN_INTERVAL_MS
            ),
            Ok(())
        );
        assert_eq!(
            service_renewal(&log, "svc-bot", T0 + 3_600_000, T0),
            Err(ServiceChangeError::NotARenewal)
        );
        assert_eq!(
            service_renewal(&log, "svc-other", T0 + 7_200_000, T0),
            Err(ServiceChangeError::NotAService)
        );
        assert_eq!(
            service_renewal(&log, "svc-bot", T0 + SERVICE_MAX_LIFETIME_MS * 2, T0),
            Err(ServiceChangeError::Invalid(Invalid::ServiceExpiry))
        );

        // Narrowing: from the current grant, never paced.
        let current = ServiceScope::of(service_grant(&log, "svc-bot").unwrap().0);
        let narrower = current
            .clone()
            .hosts(["host-a"])
            .ops(["prompt"])
            .projects(Some([HASH_A]))
            .sessions(Some(["ses-aaaaaaaaaaaa"]));
        let narrow = service_narrowing(&log, "svc-bot", &narrower, None, T0 + 60_000).unwrap();
        assert_eq!(check_change(&log, &narrow, T0 + 60_000), Ok(()));
        let earlier =
            service_narrowing(&log, "svc-bot", &current, Some(T0 + 1_000), T0 + 60_000).unwrap();
        assert_eq!(check_change(&log, &earlier, T0 + 60_000), Ok(()));
        for widening in [
            current.clone().hosts(["host-a", "host-c"]),
            current.clone().ops(["prompt", "interrupt", "stop"]),
            current.clone().projects(None::<Vec<String>>),
            current.clone(),
        ] {
            assert_eq!(
                service_narrowing(&log, "svc-bot", &widening, None, T0 + 60_000),
                Err(ServiceChangeError::NotANarrowing),
                "{widening:?}"
            );
        }
        assert_eq!(
            service_narrowing(&log, "svc-bot", &current, Some(T0 + 9_000_000), T0),
            Err(ServiceChangeError::NotANarrowing)
        );
        assert_eq!(
            service_narrowing(&log, "dev-mac", &current, None, T0),
            Err(ServiceChangeError::NotAService)
        );
        // Applied, the narrowing is the grant the next helper starts from.
        append(&mut log, narrow, T0 + 60_000);
        let (s, _) = service_grant(&log, "svc-bot").unwrap();
        assert_eq!(*s, narrower.scope());
    }
}
