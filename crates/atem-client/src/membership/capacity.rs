//! How full a verified log is, and the signer-side guard on service changes
//! (decision D23: no log compaction). The log holds at most
//! [`MAX_ENTRIES`] entries, [`MAX_MEMBERS`] current members and
//! [`MAX_HOSTS`] current hosts (§R9.2); ids
//! are never reused, every renewal and removal takes one entry, and a full
//! log means re-pairing.
//!
//! Advisory only: nothing here changes what a verifier accepts (a valid
//! signed entry stays valid on every host). [`Membership::capacity`] reads
//! the verifier's own counters against its own limits, so the two can't
//! drift; [`check_change`] is what a managing device asks before it drafts
//! an entry, so a bot's renewals can't use up the list.
use super::entry::{Action, MemberKind, RolesChange, Scope};
use super::{MAX_ENTRIES, MAX_HOSTS, MAX_MEMBERS, MemberStatus, Membership};

/// A limit counts as nearly full from this share of it (%), for each
/// limit: 922 of 1024 entries, 231 of 256 members, 58 of 64 hosts.
pub const NEARLY_FULL_PERCENT: u64 = 90;

/// A product default, not a protocol rule: a signer doesn't widen or renew
/// a service (a `set_roles` that grants anything new, e.g. a later
/// `expires_at`) within 24 h of that service's last grant (its `add`, or a
/// `set_roles` that granted something new; a narrowing doesn't restart the
/// clock, so a mistaken narrowing can be undone at once), measured on the entries' `signed_at` (the signers' own
/// clocks: display only for a verifier, so a host never applies it; the
/// guard is advisory by design). Narrowing and removal are never
/// rate-limited.
pub const SERVICE_CHANGE_MIN_INTERVAL_MS: u64 = 86_400_000;

/// How close a log (or one of its limits) is to full.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CapacityLevel {
    Ok,
    /// At or above [`NEARLY_FULL_PERCENT`] of a limit.
    NearlyFull,
    /// A limit reached: no entry at all (entries), no `add` (members), or
    /// no `add_host` of a new host (hosts).
    Full,
}

impl CapacityLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            CapacityLevel::Ok => "ok",
            CapacityLevel::NearlyFull => "nearly_full",
            CapacityLevel::Full => "full",
        }
    }

    fn of(used: u64, max: u64) -> CapacityLevel {
        if used >= max {
            CapacityLevel::Full
        } else if used * 100 >= max * NEARLY_FULL_PERCENT {
            CapacityLevel::NearlyFull
        } else {
            CapacityLevel::Ok
        }
    }
}

/// A verified log's use of its limits (§R9.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capacity {
    /// Entries in the log (the head's `seq`).
    pub entries: u64,
    pub max_entries: u64,
    /// Members the verifier's member limit counts: in effect, or the
    /// subject of a `recovery_add` still pending here. Removed and
    /// cancelled ones aren't counted (their ids stay used).
    pub members: u64,
    pub max_members: u64,
    /// Hosts the verifier's host limit counts: current ones (a removed
    /// host frees its place).
    pub hosts: u64,
    pub max_hosts: u64,
    /// The highest of the three limits' levels.
    pub level: CapacityLevel,
}

impl Capacity {
    /// `entries`, `members` and `hosts` against the verifier's limits.
    pub fn of(entries: u64, members: u64, hosts: u64) -> Capacity {
        let mut capacity = Capacity {
            entries,
            max_entries: MAX_ENTRIES,
            members,
            max_members: MAX_MEMBERS as u64,
            hosts,
            max_hosts: MAX_HOSTS as u64,
            level: CapacityLevel::Ok,
        };
        capacity.level = capacity
            .entries_level()
            .max(capacity.members_level())
            .max(capacity.hosts_level());
        capacity
    }

    pub fn entries_level(&self) -> CapacityLevel {
        CapacityLevel::of(self.entries, self.max_entries)
    }

    pub fn members_level(&self) -> CapacityLevel {
        CapacityLevel::of(self.members, self.max_members)
    }

    pub fn hosts_level(&self) -> CapacityLevel {
        CapacityLevel::of(self.hosts, self.max_hosts)
    }
}

impl Membership {
    /// How full this log is, by the verifier's own counts and limits.
    pub fn capacity(&self) -> Capacity {
        Capacity::of(
            self.head().seq,
            self.derived.current_member_count() as u64,
            self.derived.current_hosts() as u64,
        )
    }
}

impl Membership {
    /// Appends `entry` with no verification at all: filler for tests of
    /// long logs (a debug build signs and verifies a thousand entries too
    /// slowly). Never in a shipped build (feature `test-vectors`).
    #[cfg(any(test, feature = "test-vectors"))]
    #[doc(hidden)]
    pub fn append_unchecked_for_tests(&mut self, entry: super::Entry, now: &super::HostNow) {
        self.append(entry, now, &mut Vec::new());
    }
}

/// Why a signer shouldn't draft a change now ([`check_change`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeRefusal {
    /// The log holds [`MAX_ENTRIES`]: no verifier takes another entry, a
    /// removal included; the account needs re-pairing.
    LogFull,
    /// [`MAX_MEMBERS`] members: no `add`, and no `recovery_add` either (a
    /// Recovery Kit can't bring the account back), until one is removed.
    MembersFull,
    /// [`MAX_HOSTS`] current hosts: no `add_host` of a new host until one
    /// is removed (a current host's new key still fits).
    HostsFull,
    /// The service's last grant was signed at `last_signed_at`; a change
    /// that grants anything new waits until `retry_at`
    /// ([`SERVICE_CHANGE_MIN_INTERVAL_MS`]).
    ServiceChangeTooSoon { last_signed_at: u64, retry_at: u64 },
}

impl ChangeRefusal {
    pub fn code(&self) -> &'static str {
        match self {
            ChangeRefusal::LogFull => "log_full",
            ChangeRefusal::MembersFull => "members_full",
            ChangeRefusal::HostsFull => "hosts_full",
            ChangeRefusal::ServiceChangeTooSoon { .. } => "service_change_too_soon",
        }
    }
}

impl std::fmt::Display for ChangeRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for ChangeRefusal {}

/// Whether a signer should draft `action` as the next entry of `log` at
/// `now_ms` (the signer's clock, as its `signed_at` would be). Advisory
/// and deterministic; it judges capacity and pace only (the verifier still
/// judges the entry itself):
///
/// - a full log ([`MAX_ENTRIES`]) refuses every action;
/// - full members refuse `add` and `recovery_add`;
/// - full hosts refuse an `add_host` of a host that isn't current;
/// - a service's `set_roles` that grants anything new (a later
///   `expires_at`, a host, op, project or session it didn't have, or a
///   list it was restricted by dropped) within
///   [`SERVICE_CHANGE_MIN_INTERVAL_MS`] of that service's last grant (its
///   `add` or a `set_roles` that granted something new) is refused; one
///   that only narrows is never rate-limited, nor is `remove`. A last grant
///   signed after `now_ms` counts as within the interval.
///
/// Scope lists are compared as the verifier holds them: canonical (sorted,
/// unique), as every parsed entry and the bindings' `action_json` are. A
/// Rust caller building an [`Action`] by hand must sort them too, or an
/// identical re-grant reads as a narrowing and isn't paced.
pub fn check_change(log: &Membership, action: &Action, now_ms: u64) -> Result<(), ChangeRefusal> {
    let capacity = log.capacity();
    if capacity.entries_level() == CapacityLevel::Full {
        return Err(ChangeRefusal::LogFull);
    }
    match action {
        Action::Add { .. } | Action::RecoveryAdd { .. }
            if capacity.members_level() == CapacityLevel::Full =>
        {
            Err(ChangeRefusal::MembersFull)
        }
        Action::AddHost { host }
            if capacity.hosts_level() == CapacityLevel::Full
                && log.host(&host.host_id).is_none() =>
        {
            Err(ChangeRefusal::HostsFull)
        }
        Action::SetRoles {
            device_id,
            change:
                RolesChange::Service {
                    scope: new_scope,
                    expires_at: new_expiry,
                },
        } => {
            let Some(state) = log.member(device_id) else {
                return Ok(());
            };
            let MemberKind::Service { scope, expires_at } = &state.member.kind else {
                return Ok(());
            };
            if matches!(
                state.status,
                MemberStatus::Removed | MemberStatus::Cancelled
            ) || narrows(scope, *expires_at, new_scope, *new_expiry)
            {
                return Ok(());
            }
            match last_grant(log, device_id) {
                Some(at) if now_ms < at.saturating_add(SERVICE_CHANGE_MIN_INTERVAL_MS) => {
                    Err(ChangeRefusal::ServiceChangeTooSoon {
                        last_signed_at: at,
                        retry_at: at.saturating_add(SERVICE_CHANGE_MIN_INTERVAL_MS),
                    })
                }
                _ => Ok(()),
            }
        }
        _ => Ok(()),
    }
}

/// `signed_at` of the service's last entry that granted something: its
/// `add`, or a `set_roles` that didn't only narrow what it had then.
fn last_grant(log: &Membership, device_id: &str) -> Option<u64> {
    let mut held: Option<(&Scope, u64)> = None;
    let mut last = None;
    for entry in log.entries() {
        if entry.subject() != Some(device_id) {
            continue;
        }
        match &entry.action {
            Action::Add { member } => {
                if let MemberKind::Service { scope, expires_at } = &member.kind {
                    held = Some((scope, *expires_at));
                    last = Some(entry.signed_at);
                }
            }
            Action::SetRoles {
                change: RolesChange::Service { scope, expires_at },
                ..
            } => {
                let narrowed = held.is_some_and(|(cur, exp)| narrows(cur, exp, scope, *expires_at));
                if !narrowed {
                    last = Some(entry.signed_at);
                }
                held = Some((scope, *expires_at));
            }
            _ => {}
        }
    }
    last
}

/// The new scope and expiry grant nothing the current ones don't, and
/// differ from them (the same grant again would only use an entry).
pub(crate) fn narrows(scope: &Scope, expires_at: u64, new: &Scope, new_expiry: u64) -> bool {
    let within = |new: &[String], cur: &[String]| new.iter().all(|i| cur.contains(i));
    let list_within = |new: &Option<Vec<String>>, cur: &Option<Vec<String>>| match (new, cur) {
        (_, None) => true,
        (None, Some(_)) => false,
        (Some(n), Some(c)) => within(n, c),
    };
    let grants_nothing_new = new_expiry <= expires_at
        && within(&new.hosts, &scope.hosts)
        && within(&new.ops, &scope.ops)
        && list_within(&new.projects, &scope.projects)
        && list_within(&new.sessions, &scope.sessions);
    grants_nothing_new && (new != scope || new_expiry != expires_at)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::Hash32;
    use crate::kit::RecoveryKit;
    use crate::membership::Entry;
    use crate::membership::entry::{HostRecord, Member, Role};
    use crate::membership::{HostNow, RECOVERY_SIGNER, draft, sign_entry};
    use crate::provider::KeyProvider;

    const ALL: [Role; 3] = [Role::Control, Role::Manage, Role::View];
    const DAY: u64 = SERVICE_CHANGE_MIN_INTERVAL_MS;
    const T0: u64 = 1_800_000_000_000;

    fn keys(seed: u8) -> RecoveryKit {
        RecoveryKit::make(&[seed; 32], "acct", Hash32([0; 32]))
    }

    fn native(id: &str, keys: &RecoveryKit, roles: &[Role]) -> Member {
        Member {
            device_id: id.into(),
            auth_key: keys.recovery_key(),
            kind: MemberKind::Native {
                enc_key: keys.public_key(&RecoveryKit::x25519_id()).unwrap(),
                roles: roles.iter().copied().collect(),
            },
        }
    }

    fn scope(ops: &[&str], projects: Option<&[&str]>) -> Scope {
        Scope {
            hosts: vec!["host-a".into()],
            projects: projects.map(|p| p.iter().map(|s| s.to_string()).collect()),
            sessions: None,
            ops: ops.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn service(id: &str, keys: &RecoveryKit, expires_at: u64) -> Member {
        Member {
            device_id: id.into(),
            auth_key: keys.recovery_key(),
            kind: MemberKind::Service {
                scope: scope(&["prompt", "view"], None),
                expires_at,
            },
        }
    }

    fn now(wall: u64) -> HostNow {
        HostNow {
            wall_ms: wall,
            mono_ms: 0,
            boot_id: "b".into(),
        }
    }

    /// A log whose genesis member `mac` signs everything.
    struct Log {
        m: Membership,
        mac: RecoveryKit,
    }

    impl Log {
        fn new() -> Log {
            let mac = keys(1);
            let body = draft::draft_on(
                "acct",
                &Hash32([0; 32]),
                1,
                &Hash32([0; 32]),
                "mac",
                T0,
                &Action::Genesis {
                    member: native("mac", &mac, &ALL),
                    recovery_key: keys(9).recovery_key(),
                },
            );
            let genesis = sign_entry(&mac, &RecoveryKit::sign_id(), body).unwrap();
            let m = Membership::from_genesis("acct", &genesis.hash(), genesis).unwrap();
            Log { m, mac }
        }

        /// Signed and checked as a verifier would; appended in place (a
        /// long log without cloning it per entry).
        fn push(&mut self, action: Action, at: u64) {
            let body = self.m.draft("mac", at, &action);
            let entry = sign_entry(&self.mac, &RecoveryKit::sign_id(), body).unwrap();
            assert_eq!(self.m.check_next(&entry), super::super::Check::Valid);
            self.m.append(entry, &now(at), &mut Vec::new());
        }

        /// Filler: parsed as a verifier would, appended unsigned (a debug
        /// build signs and verifies a thousand entries too slowly; `push`
        /// and `sign_check` keep the real checks where they matter).
        fn push_unsigned(&mut self, action: Action, at: u64) {
            let body = self.m.draft("mac", at, &action);
            let wire = serde_json::json!({"body": body, "sig": crate::encoding::b64u(&[0u8; 64])});
            let entry = Entry::parse_bytes(wire.to_string().as_bytes()).unwrap();
            assert_eq!(entry.seq, self.m.head().seq + 1);
            self.m.append(entry, &now(at), &mut Vec::new());
        }

        fn sign_check(&self, action: &Action, at: u64) -> super::super::Check {
            let body = self.m.draft("mac", at, action);
            let entry = sign_entry(&self.mac, &RecoveryKit::sign_id(), body).unwrap();
            self.m.check_next(&entry)
        }

        /// `n` more entries, toggling a native member's roles.
        fn fill(&mut self, n: u64) {
            let phone = keys(2);
            if self.m.member("phone").is_none() {
                self.push(
                    Action::Add {
                        member: native("phone", &phone, &[Role::View]),
                    },
                    T0,
                );
                return self.fill(n - 1);
            }
            for i in 0..n {
                let roles = if i % 2 == 0 {
                    [Role::Control, Role::View].into()
                } else {
                    [Role::View].into()
                };
                self.push_unsigned(
                    Action::SetRoles {
                        device_id: "phone".into(),
                        change: RolesChange::Native(roles),
                    },
                    T0,
                );
            }
        }
    }

    fn renew(id: &str, expires_at: u64) -> Action {
        Action::SetRoles {
            device_id: id.into(),
            change: RolesChange::Service {
                scope: scope(&["prompt", "view"], None),
                expires_at,
            },
        }
    }

    fn add_service(id: &str) -> Action {
        Action::Add {
            member: service(id, &keys(3), T0 + 30 * DAY),
        }
    }

    #[test]
    fn a_genesis_log_is_far_from_full() {
        let log = Log::new();
        let c = log.m.capacity();
        assert_eq!(
            c,
            Capacity {
                entries: 1,
                max_entries: 1024,
                members: 1,
                max_members: 256,
                hosts: 0,
                max_hosts: 64,
                level: CapacityLevel::Ok,
            }
        );
    }

    #[test]
    fn entries_are_nearly_full_from_90_percent_and_full_at_the_verifiers_limit() {
        let mut log = Log::new();
        // 921 entries: 89.9 %.
        log.fill(920);
        assert_eq!(log.m.capacity().entries, 921);
        assert_eq!(log.m.capacity().level, CapacityLevel::Ok);
        log.fill(1);
        assert_eq!(log.m.capacity().level, CapacityLevel::NearlyFull);
        assert_eq!(check_change(&log.m, &add_service("svc"), T0), Ok(()));
        log.fill(MAX_ENTRIES - 922);
        let c = log.m.capacity();
        assert_eq!((c.entries, c.level), (MAX_ENTRIES, CapacityLevel::Full));
        // The verifier agrees: nothing more, a removal included.
        let remove = Action::Remove {
            device_id: "phone".into(),
        };
        assert_eq!(
            log.sign_check(&remove, T0),
            super::super::Check::Invalid(super::super::Invalid::LogFull)
        );
        for action in [remove, add_service("svc"), renew("svc", T0)] {
            assert_eq!(
                check_change(&log.m, &action, T0 + 9 * DAY),
                Err(ChangeRefusal::LogFull)
            );
        }
    }

    #[test]
    fn members_count_as_the_verifiers_member_limit_does() {
        let mut log = Log::new();
        let k = keys(4);
        for i in 1..MAX_MEMBERS {
            log.push_unsigned(
                Action::Add {
                    member: native(&format!("dev-{i}"), &k, &[Role::View]),
                },
                T0,
            );
            if i == 229 {
                // 230 of 256: 89.8 %.
                assert_eq!(log.m.capacity().members_level(), CapacityLevel::Ok);
            }
            if i == 230 {
                assert_eq!(log.m.capacity().level, CapacityLevel::NearlyFull);
            }
        }
        let c = log.m.capacity();
        assert_eq!((c.members, c.level), (256, CapacityLevel::Full));
        assert_eq!(c.entries_level(), CapacityLevel::Ok);
        let add = Action::Add {
            member: native("one-more", &k, &[Role::View]),
        };
        assert_eq!(
            log.sign_check(&add, T0),
            super::super::Check::Invalid(super::super::Invalid::LogFull)
        );
        assert_eq!(
            check_change(&log.m, &add, T0),
            Err(ChangeRefusal::MembersFull)
        );
        let recovery_add = Action::RecoveryAdd {
            member: native("rec", &k, &ALL),
        };
        assert_eq!(
            check_change(&log.m, &recovery_add, T0),
            Err(ChangeRefusal::MembersFull)
        );
        // A removed member frees its place (its id stays used); entries and
        // other changes go on.
        let remove = Action::Remove {
            device_id: "dev-1".into(),
        };
        assert_eq!(check_change(&log.m, &remove, T0), Ok(()));
        log.push(remove, T0);
        assert_eq!(log.m.capacity().members, 255);
        assert_eq!(check_change(&log.m, &add, T0), Ok(()));
        assert_eq!(log.sign_check(&add, T0), super::super::Check::Valid);
    }

    #[test]
    fn hosts_count_as_the_verifiers_host_limit_does() {
        let mut log = Log::new();
        let add_host = |id: &str, trust_gen: u64| Action::AddHost {
            host: HostRecord {
                host_id: id.into(),
                host_trust_gen: trust_gen,
                host_key: keys(7).recovery_key(),
            },
        };
        for i in 0..MAX_HOSTS {
            log.push_unsigned(add_host(&format!("host-{i}"), 1), T0);
            if i == 56 {
                // 57 of 64: 89.1 %.
                assert_eq!(log.m.capacity().hosts_level(), CapacityLevel::Ok);
            }
            if i == 57 {
                assert_eq!(log.m.capacity().level, CapacityLevel::NearlyFull);
            }
        }
        let c = log.m.capacity();
        assert_eq!((c.hosts, c.level), (64, CapacityLevel::Full));
        assert_eq!(
            (c.entries_level(), c.members_level()),
            (CapacityLevel::Ok, CapacityLevel::Ok)
        );
        // A new host: the verifier and the guard refuse it.
        let new_host = add_host("host-new", 1);
        assert_eq!(
            log.sign_check(&new_host, T0),
            super::super::Check::Invalid(super::super::Invalid::LogFull)
        );
        assert_eq!(
            check_change(&log.m, &new_host, T0),
            Err(ChangeRefusal::HostsFull)
        );
        // A current host's new key still fits; members and other entries go on.
        let rekey = add_host("host-3", 2);
        assert_eq!(log.sign_check(&rekey, T0), super::super::Check::Valid);
        assert_eq!(check_change(&log.m, &rekey, T0), Ok(()));
        assert_eq!(check_change(&log.m, &add_service("svc"), T0), Ok(()));
        // A removed host frees its place.
        log.push(
            Action::RemoveHost {
                host_id: "host-0".into(),
            },
            T0,
        );
        assert_eq!(log.m.capacity().hosts, 63);
        assert_eq!(check_change(&log.m, &new_host, T0), Ok(()));
        assert_eq!(log.sign_check(&new_host, T0), super::super::Check::Valid);
    }

    #[test]
    fn a_pending_recovery_add_counts_as_a_member() {
        let mut log = Log::new();
        let kit = keys(9);
        let body = log.m.draft(
            RECOVERY_SIGNER,
            T0,
            &Action::RecoveryAdd {
                member: native("newmac", &keys(5), &ALL),
            },
        );
        let entry = sign_entry(&kit, &RecoveryKit::sign_id(), body).unwrap();
        log.m.append(entry, &now(T0), &mut Vec::new());
        assert!(matches!(
            log.m.member("newmac").unwrap().status,
            MemberStatus::Pending { .. }
        ));
        assert_eq!(log.m.capacity().members, 2);
    }

    #[test]
    fn a_service_renewal_waits_24_h_after_its_last_entry() {
        let mut log = Log::new();
        log.push(add_service("svc"), T0);
        let renewal = renew("svc", T0 + 40 * DAY);
        let too_soon = Err(ChangeRefusal::ServiceChangeTooSoon {
            last_signed_at: T0,
            retry_at: T0 + DAY,
        });
        assert_eq!(check_change(&log.m, &renewal, T0 + DAY - 1), too_soon);
        // A clock behind the last entry is within the interval too.
        assert_eq!(check_change(&log.m, &renewal, T0 - 5), too_soon);
        assert_eq!(check_change(&log.m, &renewal, T0 + DAY), Ok(()));
        log.push(renewal, T0 + DAY);
        // The renewal is the last entry now: a second one waits again.
        let again = renew("svc", T0 + 50 * DAY);
        assert_eq!(
            check_change(&log.m, &again, T0 + DAY + 3_600_000),
            Err(ChangeRefusal::ServiceChangeTooSoon {
                last_signed_at: T0 + DAY,
                retry_at: T0 + 2 * DAY,
            })
        );
        // Another service's entries don't count.
        log.push(add_service("svc-2"), T0 + DAY + 1);
        assert_eq!(check_change(&log.m, &again, T0 + 2 * DAY), Ok(()));
        // The same grant again only uses an entry: rate-limited too.
        assert!(check_change(&log.m, &renew("svc-2", T0 + 30 * DAY), T0 + DAY + 2).is_err());
    }

    #[test]
    fn a_narrowing_doesnt_restart_the_clock() {
        let mut log = Log::new();
        log.push(add_service("svc"), T0);
        // Narrowed by mistake two hours later...
        let narrow = Action::SetRoles {
            device_id: "svc".into(),
            change: RolesChange::Service {
                scope: scope(&["view"], None),
                expires_at: T0 + 30 * DAY,
            },
        };
        log.push(narrow, T0 + 2 * 3_600_000);
        // ...restored within 24 h of the narrowing, a day after the add.
        let restore = renew("svc", T0 + 30 * DAY);
        assert_eq!(check_change(&log.m, &restore, T0 + DAY), Ok(()));
        // Before a day since the add (the last grant), it waits for that.
        assert_eq!(
            check_change(&log.m, &restore, T0 + DAY - 1),
            Err(ChangeRefusal::ServiceChangeTooSoon {
                last_signed_at: T0,
                retry_at: T0 + DAY,
            })
        );
        // The restore is a grant: the clock runs from it.
        log.push(restore, T0 + DAY);
        assert!(check_change(&log.m, &renew("svc", T0 + 40 * DAY), T0 + DAY + 1).is_err());
    }

    #[test]
    fn narrowing_and_removal_are_never_rate_limited() {
        let mut log = Log::new();
        log.push(add_service("svc"), T0);
        let soon = T0 + 60_000;
        let narrow = |ops: &[&str], projects: Option<&[&str]>, expires_at: u64| Action::SetRoles {
            device_id: "svc".into(),
            change: RolesChange::Service {
                scope: scope(ops, projects),
                expires_at,
            },
        };
        let project = "h1.k1.".to_string() + &"ab".repeat(32);
        for action in [
            narrow(&["view"], None, T0 + 30 * DAY),
            narrow(&["prompt", "view"], None, T0 + DAY),
            narrow(
                &["prompt", "view"],
                Some(&[project.as_str()]),
                T0 + 30 * DAY,
            ),
            Action::Remove {
                device_id: "svc".into(),
            },
        ] {
            assert_eq!(check_change(&log.m, &action, soon), Ok(()), "{action:?}");
        }
        // Widening is a change like a renewal.
        assert!(
            check_change(&log.m, &narrow(&["prompt", "stop", "view"], None, T0), soon).is_err()
        );
        // Once restricted to a project, dropping the restriction widens.
        log.push(
            narrow(
                &["prompt", "view"],
                Some(&[project.as_str()]),
                T0 + 30 * DAY,
            ),
            soon,
        );
        assert!(check_change(&log.m, &narrow(&["prompt", "view"], None, T0), soon + 1).is_err());
        // Native role changes and other actions aren't paced.
        let phone = Action::Add {
            member: native("phone", &keys(2), &[Role::View]),
        };
        assert_eq!(check_change(&log.m, &phone, soon), Ok(()));
    }
}
