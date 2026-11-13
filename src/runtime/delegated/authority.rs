//! Interaction authority (design I.3.1, I.4.5; host-work-v1 §11.2
//! "Authority"; step 4's Decision 15): who may query, cancel or complete a
//! delegated sender's task once it was admitted, and read its reply.
//!
//! - **The sender** ([`Caller::Sender`]): the principal and key that
//!   enqueued it (the admission record's), with its current authority on
//!   the host's device list: still a member under that key (a new key is a
//!   new member, R9.2), no `revoke` record, its grant unexpired, `notify`
//!   and `prompt` in that grant, and the grant still covering the task's
//!   target (design I.3.3: "readable within the new grant"; a `projects`
//!   entry the task's project matched at admission covers it with no hash,
//!   `Admission::project_matches`). A changed
//!   `control_gen` doesn't forbid anything (a renewal, any `set_roles`),
//!   and neither does a route change (I.4.5).
//! - **The owner** ([`Caller::Owner`]): a native member holding `control`
//!   at the host's current head, under its own key. It reads any delegated
//!   task, a revoked or removed sender's included (Decision 15); what it may
//!   do beyond reading is the bridge's (`work_query`, `reply_query` and
//!   `work_resolve` here; `work_interrupt` comes with its task).
//!
//! v1 tasks never come here: they keep host-work v1's caller rule.
//! Anything refused is `forbidden`, with no detail (host-work-v1 §7: §11.6
//! names none for it); [`Refused`] says why, for tests and logs only.
use super::{Admission, DelegatedSender, SenderStanding};
use atem_client::channel::Principal;
use atem_client::membership::entry::{MemberKind, Role};
use atem_client::membership::{MemberStatus, Membership};
use atem_client::principal::{Authority, Need, Op, Refusal};
use atem_client::session::host_work::digest;

/// Who asks about a delegated task (design I.4.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Caller {
    /// The task's sender, with its current authority.
    Sender,
    /// The owner's voice: a native member holding `control` at the head.
    Owner,
}

/// Why [`interaction`] refused a caller. The wire says `forbidden` only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// The host's device list isn't open and serving (frozen, held,
    /// faulted, or none): queries are refused (design I.3.3).
    NoList,
    /// Neither the sender (another principal, or the same one under another
    /// key) nor the owner.
    NotTheSender,
    /// The sender, removed from the device list, or another key in its
    /// place.
    Removed,
    /// The sender, revoked by a `revoke` record.
    Revoked,
    /// The sender, its grant expired.
    Expired,
    /// The sender, its current grant without `notify` and `prompt`, or no
    /// longer covering the task's target (host, session, project).
    NotCovered,
    /// The sender, a service, while the host's control state can't be read
    /// (damaged or not loaded): its revocation and hold can't be checked,
    /// so it is answered `busy`, never let through (ruling T32b). The owner
    /// still reads.
    Unchecked,
    /// The sender, whose current grant covers the task's target only if a
    /// `projects` comparison that can't be made yet matches (a locked cred
    /// agent, a hash just asked for: Task 32 review m1): `busy`, never a
    /// `forbidden` that might not stand.
    ProjectPending,
}

impl Refused {
    /// The error code it is answered with (host-work-v1 §7): `busy` while
    /// what decides can't be read yet, else `forbidden`.
    pub fn code(self) -> &'static str {
        match self {
            Refused::Unchecked | Refused::ProjectPending => "busy",
            _ => "forbidden",
        }
    }
}

/// What [`interaction`] reads besides the caller and the task.
pub struct Grounds<'a> {
    /// The host's device list at its head, open and serving.
    pub list: &'a Membership,
    /// The sender's control standing (revoked, held, coverage).
    pub standing: &'a SenderStanding,
    /// The control state couldn't be read (`Feeds` damaged or not loaded):
    /// `standing` says nothing, so a service sender is [`Refused::Unchecked`]
    /// (a native's authority comes from the device list alone).
    pub unchecked: bool,
    /// This host's id (a service grant's `hosts`).
    pub host_id: &'a str,
    /// The time a grant's expiry is compared with: the host's wall clock,
    /// or the delegated clock's `D` when that is later.
    pub now_ms: u64,
    /// Whether the task's session is in a `projects` scope entry, for a
    /// kid the admission didn't see (an entry it matched at admission
    /// decides without it, `Admission::project_matches`): none while that
    /// can't be compared (a locked cred agent, a hash not made yet), which
    /// leaves it out of scope, as [`Refused::ProjectPending`] when that
    /// comparison alone decides.
    pub projects: &'a dyn Fn(&str) -> Option<bool>,
}

/// Who `caller_principal`, under the raw auth key `caller_key`, is to the
/// delegated task admitted as `task` on session `session_id` (see the
/// module doc): the sender when its current authority holds, else the owner
/// when it is one, else refused, with the sender's own reason when it is the
/// sender.
pub fn interaction(
    caller_principal: &str,
    caller_key: &[u8],
    task: &Admission,
    session_id: &str,
    at: &Grounds<'_>,
) -> Result<Caller, Refused> {
    let refused = if caller_principal == task.principal && digest(caller_key) == task.principal_key
    {
        let service = matches!(task.sender, DelegatedSender::Service { .. });
        if service && at.unchecked {
            Refused::Unchecked
        } else {
            match sender_authority(caller_key, task, session_id, at) {
                Ok(()) => return Ok(Caller::Sender),
                Err(why) => why,
            }
        }
    } else {
        Refused::NotTheSender
    };
    if owner(caller_principal, caller_key, at.list) {
        return Ok(Caller::Owner);
    }
    Err(refused)
}

/// The sender's current authority over its task (design I.4.5).
fn sender_authority(
    caller_key: &[u8],
    task: &Admission,
    session_id: &str,
    at: &Grounds<'_>,
) -> Result<(), Refused> {
    let (device_id, principal) = match &task.sender {
        DelegatedSender::Native { device_id } => (
            device_id,
            Principal::Native {
                device_id: device_id.clone(),
            },
        ),
        DelegatedSender::Service { device_id, .. } => (
            device_id,
            Principal::Service {
                device_id: device_id.clone(),
            },
        ),
    };
    let member = at
        .list
        .member(device_id)
        .filter(|m| m.status == MemberStatus::Active)
        .filter(|m| m.member.auth_key.as_bytes() == caller_key)
        .ok_or(Refused::Removed)?;
    if at.standing.revoked.is_some() {
        return Err(Refused::Revoked);
    }
    let grant = Authority::of_member(&principal, &member.member, at.host_id, at.now_ms).map_err(
        |refusal| match refusal {
            Refusal::Unauthorized("expired") => Refused::Expired,
            // A device claiming another kind than its entry's: not the
            // member it was admitted as.
            Refusal::Unauthorized("not a member") => Refused::Removed,
            _ => Refused::NotCovered,
        },
    )?;
    // A `projects` entry the task's project matched at admission covers it
    // without a hash (I1): the live comparison only for a kid it didn't see.
    let projects = |entry: &str| task.project_matches(entry, at.projects);
    if !grant.allows(Need::Op(Op::Notify)) || !grant.allows(Need::Op(Op::Prompt)) {
        return Err(Refused::NotCovered);
    }
    if !grant.session_in_scope(at.host_id, session_id, &projects) {
        // In scope if every comparison still pending matched: not yet
        // decided, never narrowed (as the start check's `waiting for
        // unlock`); out of it whatever they say: not covered.
        let pending_in =
            grant.session_in_scope(at.host_id, session_id, &|e| projects(e).or(Some(true)));
        return Err(if pending_in {
            Refused::ProjectPending
        } else {
            Refused::NotCovered
        });
    }
    Ok(())
}

/// Who a caller is to a message's delegated tasks together (`message_query`
/// and a `message_publish` retry), from what [`interaction`] said of each:
/// every task must let it through; a refusal that stands (`forbidden`) is
/// answered whatever the recipients' order, before one that can't be
/// decided yet (`busy`), so a caller that would be refused anyway isn't
/// told to retry (Task 32 re-review N3). With none refused: the owner when
/// any task saw the owner in it.
pub fn every_caller(
    each: impl IntoIterator<Item = Result<Caller, Refused>>,
) -> Result<Caller, Refused> {
    let mut caller = Caller::Sender;
    let mut undecided = None;
    for one in each {
        match one {
            Ok(Caller::Owner) => caller = Caller::Owner,
            Ok(Caller::Sender) => {}
            Err(refused) if refused.code() == "busy" => {
                undecided.get_or_insert(refused);
            }
            Err(refused) => return Err(refused),
        }
    }
    match undecided {
        Some(refused) => Err(refused),
        None => Ok(caller),
    }
}

/// A native member holding `control` at the head, under its own key.
fn owner(caller_principal: &str, caller_key: &[u8], list: &Membership) -> bool {
    let Some(device_id) = caller_principal.strip_prefix("member:") else {
        return false;
    };
    list.member(device_id).is_some_and(|m| {
        m.status == MemberStatus::Active
            && m.member.auth_key.as_bytes() == caller_key
            && matches!(&m.member.kind,
                MemberKind::Native { roles, .. } if roles.contains(&Role::Control))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::delegated::{FeedRef, SenderClass, classify};
    use crate::runtime::test_hooks::HostFeatures;
    use crate::session_protocol::membership::r9log::{TestLog, auth, host_now, secret};
    use atem_client::KeyProvider;

    const HOST: &str = "host-i";
    const S1: &str = "ses-aaaaaaaaaaaa";
    const S2: &str = "ses-bbbbbbbbbbbb";

    struct Covers;

    impl crate::runtime::delegated::ControlView for Covers {
        fn standing(&self, _: &str) -> SenderStanding {
            SenderStanding {
                coverage: Some(FeedRef {
                    origin: "https://station-dev.agora.build".into(),
                    feed_id: "feed-1".into(),
                }),
                ..SenderStanding::default()
            }
        }
    }

    /// Task 32 re-review N3: a message's tasks answer as one: a definitive
    /// refusal (`forbidden`) wins over one that can't be decided yet
    /// (`busy`) whatever the order of the recipients; otherwise the first
    /// `busy`; with none, the owner when any task saw one.
    #[test]
    fn a_definitive_refusal_wins_over_busy_in_either_order() {
        use Refused::*;
        let both = |a: Result<Caller, Refused>, b| {
            (
                every_caller([a, b]).map_err(Refused::code),
                every_caller([b, a]).map_err(Refused::code),
            )
        };
        assert_eq!(
            both(Err(ProjectPending), Err(NotCovered)),
            (Err("forbidden"), Err("forbidden"))
        );
        assert_eq!(
            both(Err(Unchecked), Err(Revoked)),
            (Err("forbidden"), Err("forbidden"))
        );
        assert_eq!(
            both(Ok(Caller::Sender), Err(ProjectPending)),
            (Err("busy"), Err("busy"))
        );
        assert_eq!(
            both(Ok(Caller::Sender), Ok(Caller::Owner)),
            (Ok(Caller::Owner), Ok(Caller::Owner))
        );
        assert_eq!(every_caller([]), Ok(Caller::Sender));
    }

    /// A bot expiry a day ahead (the verifier's limit is 90 days).
    fn later() -> u64 {
        host_now().wall_ms + 86_400_000
    }

    /// The Mac, this host, the phone (`control`), a viewer (`view` only)
    /// and a bot (a service on this host, sessions S1 and S2, expiring at
    /// `bot_expiry`).
    fn log(bot_expiry: u64) -> TestLog {
        let mut log = TestLog::genesis("acct-i", &secret("interaction astation"));
        log.add_host(HOST, 1, &secret("interaction host"));
        log.add_native("dev-phone", &["control", "view"]);
        log.add_native("dev-viewer", &["view"]);
        log.add_service(
            "svc-bot",
            &[HOST],
            Some(&[S1, S2]),
            &["message", "notify", "prompt", "view"],
            bot_expiry,
        );
        log
    }

    fn key(log: &TestLog, device: &str) -> Vec<u8> {
        log.keys
            .public_key(&auth(device))
            .unwrap()
            .as_bytes()
            .to_vec()
    }

    /// `principal`'s task as admitted on `log`'s head.
    fn admitted(log: &TestLog, principal: &str) -> Admission {
        let (who, sender) = match principal.strip_prefix("member:") {
            Some(id) => (
                Principal::Native {
                    device_id: id.into(),
                },
                classify(principal, &log.log, &Covers, on()),
            ),
            None => (
                Principal::Service {
                    device_id: principal.strip_prefix("service:").unwrap().into(),
                },
                classify(principal, &log.log, &Covers, on()),
            ),
        };
        let mut now = host_now();
        now.wall_ms = 0;
        let authority =
            Authority::resolve(&log.log, &who, None, HOST, 1, &now, &|_| false).unwrap();
        let SenderClass::Delegated(sender) = sender else {
            panic!("{principal} is delegated");
        };
        Admission::freeze(&authority, sender, "r", 1, log.log.head().seq)
    }

    fn on() -> HostFeatures {
        HostFeatures::parse("host.delegated").unwrap()
    }

    fn ask(
        log: &TestLog,
        who: &str,
        device: &str,
        task: &Admission,
        standing: &SenderStanding,
        now_ms: u64,
    ) -> Result<Caller, Refused> {
        interaction(
            who,
            &key(log, device),
            task,
            S1,
            &Grounds {
                list: &log.log,
                standing,
                unchecked: false,
                host_id: HOST,
                now_ms,
                projects: &|_| Some(false),
            },
        )
    }

    /// Design I.4.5: the sender is the principal and key that enqueued the
    /// task, with its current authority; nothing compares a control
    /// generation. Another principal, or the same id under another key, is
    /// not the sender; a native member with `control` is the owner.
    #[test]
    fn the_sender_is_the_principal_and_key_that_enqueued_it() {
        let log = log(later());
        let none = SenderStanding::default();
        let bot = admitted(&log, "service:svc-bot");
        let phone = admitted(&log, "member:dev-phone");
        assert_eq!(
            ask(&log, "service:svc-bot", "svc-bot", &bot, &none, 0),
            Ok(Caller::Sender)
        );
        assert_eq!(
            ask(&log, "member:dev-phone", "dev-phone", &phone, &none, 0),
            Ok(Caller::Sender)
        );
        // The phone holds `control`: the bot's task's owner.
        assert_eq!(
            ask(&log, "member:dev-phone", "dev-phone", &bot, &none, 0),
            Ok(Caller::Owner)
        );
        // A viewer is neither.
        assert_eq!(
            ask(&log, "member:dev-viewer", "dev-viewer", &bot, &none, 0),
            Err(Refused::NotTheSender)
        );
        // The bot's id under another key (the phone's): not the sender.
        assert_eq!(
            ask(&log, "service:svc-bot", "dev-phone", &bot, &none, 0),
            Err(Refused::NotTheSender)
        );
        // The owner's id under another key: not the owner.
        assert_eq!(
            ask(&log, "member:dev-phone", "dev-viewer", &bot, &none, 0),
            Err(Refused::NotTheSender)
        );
    }

    /// Ruling T32b (Task 32 review I1): while the control state can't be
    /// read, a service sender is refused `Unchecked` (`busy`), its standing
    /// unknown, never let through on an empty one; the owner still reads,
    /// and a native sender (its authority is the device list's) is
    /// unchanged.
    #[test]
    fn an_unchecked_control_state_refuses_a_service_sender_only() {
        let log = log(later());
        let none = SenderStanding::default();
        let bot = admitted(&log, "service:svc-bot");
        let phone = admitted(&log, "member:dev-phone");
        let unchecked = |who: &str, device: &str, task: &Admission| {
            interaction(
                who,
                &key(&log, device),
                task,
                S1,
                &Grounds {
                    list: &log.log,
                    standing: &none,
                    unchecked: true,
                    host_id: HOST,
                    now_ms: 0,
                    projects: &|_| Some(false),
                },
            )
        };
        assert_eq!(
            unchecked("service:svc-bot", "svc-bot", &bot),
            Err(Refused::Unchecked)
        );
        assert_eq!(
            unchecked("member:dev-phone", "dev-phone", &bot),
            Ok(Caller::Owner)
        );
        assert_eq!(
            unchecked("member:dev-phone", "dev-phone", &phone),
            Ok(Caller::Sender)
        );
        assert_eq!(
            unchecked("member:dev-viewer", "dev-viewer", &bot),
            Err(Refused::NotTheSender)
        );
    }

    /// Design I.2, I.3.3: expiry refuses the sender's queries, and a
    /// renewal (a later expiry, the same key) makes them work again; the
    /// owner reads throughout.
    #[test]
    fn an_expired_grant_reads_nothing_until_renewed() {
        let expiry = host_now().wall_ms + 3_600_000;
        let mut log = log(expiry);
        let bot = admitted(&log, "service:svc-bot");
        let none = SenderStanding::default();
        assert_eq!(
            ask(&log, "service:svc-bot", "svc-bot", &bot, &none, expiry - 1),
            Ok(Caller::Sender)
        );
        assert_eq!(
            ask(&log, "service:svc-bot", "svc-bot", &bot, &none, expiry),
            Err(Refused::Expired)
        );
        assert_eq!(
            ask(&log, "member:dev-phone", "dev-phone", &bot, &none, expiry),
            Ok(Caller::Owner)
        );
        log.renew_service("svc-bot", expiry + 3_600_000);
        assert_eq!(
            ask(&log, "service:svc-bot", "svc-bot", &bot, &none, expiry),
            Ok(Caller::Sender)
        );
    }

    /// Design I.3.3: a revoked or removed sender reads nothing; the owner
    /// reads its tasks. A native removed, or demoted below `control`, is no
    /// owner either.
    #[test]
    fn revoked_and_removed_senders_read_nothing_the_owner_reads() {
        let mut log = log(later());
        let bot = admitted(&log, "service:svc-bot");
        let phone = admitted(&log, "member:dev-phone");
        let revoked = SenderStanding {
            revoked: Some("rec-1".into()),
            ..SenderStanding::default()
        };
        let none = SenderStanding::default();
        assert_eq!(
            ask(&log, "service:svc-bot", "svc-bot", &bot, &revoked, 0),
            Err(Refused::Revoked)
        );
        assert_eq!(
            ask(&log, "member:dev-phone", "dev-phone", &bot, &revoked, 0),
            Ok(Caller::Owner)
        );
        log.remove("svc-bot");
        assert_eq!(
            ask(&log, "service:svc-bot", "svc-bot", &bot, &none, 0),
            Err(Refused::Removed)
        );
        assert_eq!(
            ask(&log, "member:dev-phone", "dev-phone", &bot, &none, 0),
            Ok(Caller::Owner)
        );
        log.set_native_roles("dev-phone", &["view"]);
        // Its own task: no `notify` or `prompt` without `control`.
        assert_eq!(
            ask(&log, "member:dev-phone", "dev-phone", &phone, &none, 0),
            Err(Refused::NotCovered)
        );
        assert_eq!(
            ask(&log, "member:dev-phone", "dev-phone", &bot, &none, 0),
            Err(Refused::NotTheSender)
        );
        log.remove("dev-phone");
        assert_eq!(
            ask(&log, "member:dev-phone", "dev-phone", &phone, &none, 0),
            Err(Refused::Removed)
        );
    }

    /// Design I.3.3 (narrowing: "readable within the new grant"): the
    /// sender's current grant must still hold `notify` and `prompt` and
    /// cover the task's session; a pending project comparison (a locked
    /// cred agent) leaves it out.
    #[test]
    fn the_current_grant_must_cover_the_task() {
        use atem_client::membership::ServiceScope;
        let mut log = log(later());
        let bot = admitted(&log, "service:svc-bot");
        let none = SenderStanding::default();
        let narrowed = |sessions: &[&str], ops: &[&str]| {
            ServiceScope::new([HOST])
                .sessions(Some(sessions.iter().copied()))
                .ops(ops.iter().copied())
        };
        // Narrowed, still covering S1 (`message` dropped): the sender.
        log.narrow_service(
            "svc-bot",
            &narrowed(&[S1, S2], &["notify", "prompt", "view"]),
            None,
        );
        assert_eq!(
            ask(&log, "service:svc-bot", "svc-bot", &bot, &none, 0),
            Ok(Caller::Sender)
        );
        // S1 left out: not covered.
        log.narrow_service(
            "svc-bot",
            &narrowed(&[S2], &["notify", "prompt", "view"]),
            None,
        );
        assert_eq!(
            ask(&log, "service:svc-bot", "svc-bot", &bot, &none, 0),
            Err(Refused::NotCovered)
        );
        let s2 = interaction(
            "service:svc-bot",
            &key(&log, "svc-bot"),
            &bot,
            S2,
            &Grounds {
                list: &log.log,
                standing: &none,
                unchecked: false,
                host_id: HOST,
                now_ms: 0,
                projects: &|_| None,
            },
        );
        assert_eq!(s2, Ok(Caller::Sender), "a task on S2 still is");
        // `prompt` dropped: not covered.
        log.narrow_service("svc-bot", &narrowed(&[S2], &["notify", "view"]), None);
        let s2 = interaction(
            "service:svc-bot",
            &key(&log, "svc-bot"),
            &bot,
            S2,
            &Grounds {
                list: &log.log,
                standing: &none,
                unchecked: false,
                host_id: HOST,
                now_ms: 0,
                projects: &|_| None,
            },
        );
        assert_eq!(s2, Err(Refused::NotCovered));
    }

    /// Task 20 review I1: the `projects` entries the task's project matched
    /// at admission cover it with no hash (its session gone, the cred agent
    /// locked or its hashes dropped); a narrowing to another project under
    /// that kid doesn't, whatever a live comparison says; only under a kid
    /// the admission didn't see does the live comparison decide. An
    /// admission without frozen entries keeps the live rule.
    #[test]
    fn frozen_project_entries_cover_without_a_hash() {
        use atem_client::membership::ServiceScope;
        const PA: &str =
            "h1.0a0b0c0d.1111111111111111111111111111111111111111111111111111111111111111";
        const PB: &str =
            "h1.0a0b0c0d.2222222222222222222222222222222222222222222222222222222222222222";
        const PC: &str =
            "h1.0b0b0b0b.3333333333333333333333333333333333333333333333333333333333333333";
        let mut log = log(later());
        log.add_service_projects(
            "svc-proj",
            &[HOST],
            Some(&[PA, PB]),
            None,
            &["notify", "prompt", "view"],
            later(),
        );
        let frozen = admitted(&log, "service:svc-proj").with_projects(vec![PA.into()]);
        let live = admitted(&log, "service:svc-proj");
        assert!(live.projects_matched.is_empty());
        let none = SenderStanding::default();
        let at = |log: &TestLog, task: &Admission, projects: &dyn Fn(&str) -> Option<bool>| {
            interaction(
                "service:svc-proj",
                &key(log, "svc-proj"),
                task,
                S1,
                &Grounds {
                    list: &log.log,
                    standing: &none,
                    unchecked: false,
                    host_id: HOST,
                    now_ms: 0,
                    projects,
                },
            )
        };
        assert_eq!(at(&log, &frozen, &|_| None), Ok(Caller::Sender));
        assert_eq!(at(&log, &frozen, &|_| Some(false)), Ok(Caller::Sender));
        // Without frozen entries, a comparison not made yet decides nothing
        // (`busy`, never a `forbidden` that might not stand: Task 32 review
        // m1); one made decides.
        assert_eq!(at(&log, &live, &|_| None), Err(Refused::ProjectPending));
        assert_eq!(at(&log, &live, &|_| Some(false)), Err(Refused::NotCovered));
        assert_eq!(at(&log, &live, &|e| Some(e == PA)), Ok(Caller::Sender));
        // Narrowed to the other project under that kid.
        log.narrow_service(
            "svc-proj",
            &ServiceScope::new([HOST])
                .projects(Some([PB]))
                .ops(["notify", "prompt"]),
            None,
        );
        assert_eq!(at(&log, &frozen, &|_| Some(true)), Err(Refused::NotCovered));
        // Scoped under a kid the admission didn't see: the live comparison.
        log.set_service(
            "svc-proj",
            &ServiceScope::new([HOST])
                .projects(Some([PC]))
                .ops(["notify", "prompt"]),
            later(),
        );
        assert_eq!(at(&log, &frozen, &|e| Some(e == PC)), Ok(Caller::Sender));
        assert_eq!(
            at(&log, &frozen, &|_| Some(false)),
            Err(Refused::NotCovered)
        );
        // Its hash not made yet (a locked agent, a project just asked for):
        // `busy` (m1).
        assert_eq!(at(&log, &frozen, &|_| None), Err(Refused::ProjectPending));
    }
}
