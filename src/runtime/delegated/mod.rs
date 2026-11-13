//! Delegated host work (the delegated host-work design, Part I;
//! host-work-v1 §11 and §11.6, session-v1 R9.14): the lifecycle a delegated
//! sender's task has, behind `host.delegated` and `host.alerts`. Nothing of
//! it runs unless the debug-only hook turns the features on
//! (`test_hooks::host_features`, read once when the runtime starts: step
//! 4's Decision 10); a release build never does.
//!
//! Here so far: who is delegated ([`classify`]: design I.1.3, Decision 13),
//! the admission record a delegated sender's task gets ([`Admission`],
//! I.4.1), its attempts ([`attempts`], I.6.4), the start check and the
//! gates ([`start`], [`gate`], I.4.3, I.5.8), who may query, cancel or
//! complete it ([`authority`], I.4.5, Decision 15), what the bridge answers
//! the delegated ops ([`request`]), §11.6's detail texts ([`details`]), and
//! the host's Station link with its own device-list fetch ([`station`],
//! [`fetch`], I.5.8).
pub mod attempts;
pub mod authority;
pub mod details;
pub mod fetch;
pub mod gate;
pub mod start;
pub mod station;

use crate::runtime::test_hooks::HostFeatures;
use crate::session_protocol::r9::HostWorkError;
use atem_client::membership::entry::MemberKind;
use atem_client::membership::{MemberStatus, Membership, service_key_fingerprint};
use atem_client::principal::{Authority, Need, Op, op_names};
use atem_client::session::host_work::{ALERTS_FEATURE, DELEGATED_FEATURE, Request, ResultBody};
use atem_client::session::wire::is_delegated_sender;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// The detail of a `host.delegated` op the host advertises but doesn't
/// serve yet (`busy`, host-work-v1 §7: a request it can't take now). Not a
/// §11.6 detail: it names no task's state.
pub const DELEGATED_NOT_SERVED: &str = "host.delegated is not served yet";
/// [`DELEGATED_NOT_SERVED`] for `host.alerts` (`alert_list`).
pub const ALERTS_NOT_SERVED: &str = "host.alerts is not served yet";

/// The Station feed that covers a service (design I.5.2): the Station's
/// origin and the feed's id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeedRef {
    pub origin: String,
    pub feed_id: String,
}

/// A sender whose every stop the host learns from signed data (design
/// I.1.3), so its tasks run while it is offline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DelegatedSender {
    /// A native member (`member:<id>`): its stops come from the device list.
    Native { device_id: String },
    /// A service (`service:<id>`) the feed covers: its stops come from that
    /// feed's control records and the device list.
    Service { device_id: String, feed: FeedRef },
}

/// Which lifecycle a sender's tasks get, decided when a task is admitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SenderClass {
    Delegated(DelegatedSender),
    /// Host-work v1's (§4): browser grants, services no feed covers,
    /// `local`, and everyone while `host.delegated` is off.
    V1,
}

/// What the host's control state says of a principal: revoked (by which
/// record), held, and the feed that covers it. The host's own view, so the
/// lifecycle doesn't wait for the shared feed state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SenderStanding {
    pub revoked: Option<String>,
    pub held: bool,
    pub coverage: Option<FeedRef>,
}

/// The host's control state, read by principal.
pub trait ControlView {
    fn standing(&self, principal: &str) -> SenderStanding;
}

/// The view while the host syncs no feed (until the feeds exist): nobody is
/// revoked, held or covered.
pub struct NoFeeds;

impl ControlView for NoFeeds {
    fn standing(&self, _principal: &str) -> SenderStanding {
        SenderStanding::default()
    }
}

/// A delegated sender's task's admission record (design I.4.1): what its
/// execution depends on, stored with the task before the enqueue is
/// answered and never changed. The task's own fields hold the rest of
/// I.4.1's record: `task_id`, `workflow_id`, the deadline, the target
/// triple with `session_id` and `process_gen`, the inputs and their
/// digest, the profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Admission {
    /// `member:<id>` or `service:<id>`.
    pub principal: String,
    /// Hex SHA-256 of the principal's `auth_key` (its raw bytes), as
    /// `r9_svc` is computed.
    pub principal_key: String,
    pub sender: DelegatedSender,
    /// The feed whose control records apply to it: a covered service's.
    /// None for a native member, whose gate is the host's own Station's
    /// (design I.5.8), not a feed of its own.
    pub feed: Option<FeedRef>,
    pub route_id: String,
    pub route_revision: u64,
    /// The ops it held (`notify` and `prompt` among them), sorted: a
    /// service's grant's, every op for a native member holding `control`.
    pub ops_at_admission: Vec<String>,
    /// A service's grant scope (`ops`, `hosts`, and `sessions` and
    /// `projects` when it has them); null for a native member (roles, no
    /// scope).
    pub scope_at_admission: Value,
    /// A service's grant expiry; none for a native member.
    pub grant_expires_at: Option<u64>,
    /// The device list's head `seq` at admission.
    pub device_list_seq: u64,
    /// A service's `projects` scope entries the task's launch project
    /// matched at admission, sorted (`h1.<kid>.<hash>`; Task 20 review I1):
    /// a current grant covers the task's project when one of its entries
    /// equals one of these, with no hash from the cred agent, whatever
    /// became of the session ([`Admission::project_matches`]). Empty
    /// without a `projects` scope, and in records written before it was
    /// kept: the live comparison is the rule then.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub projects_matched: Vec<String>,
}

impl Admission {
    /// The record of a task `authority` enqueued through `route_id` at
    /// `route_revision`, its sender classified `sender` ([`classify`]) on
    /// the device list whose head is `device_list_seq`.
    pub fn freeze(
        authority: &Authority,
        sender: DelegatedSender,
        route_id: &str,
        route_revision: u64,
        device_list_seq: u64,
    ) -> Admission {
        let feed = match &sender {
            DelegatedSender::Service { feed, .. } => Some(feed.clone()),
            DelegatedSender::Native { .. } => None,
        };
        let ops = Op::ALL
            .into_iter()
            .filter(|op| authority.allows(Need::Op(*op)))
            .collect();
        let scope_at_admission = authority.scope.as_ref().map_or(Value::Null, |scope| {
            let mut out = json!({"ops": op_names(&scope.ops)});
            for (key, list) in [
                ("hosts", &scope.hosts),
                ("sessions", &scope.sessions),
                ("projects", &scope.projects),
            ] {
                if let Some(list) = list {
                    out[key] = json!(list);
                }
            }
            out
        });
        Admission {
            principal: authority.name(),
            // `r9_svc`'s one definition. An auth key is P-256 or Ed25519
            // (the device list's verifier); any other gives no fingerprint,
            // which no caller's key ever matches (fail closed).
            principal_key: service_key_fingerprint(&authority.key).unwrap_or_default(),
            sender,
            feed,
            route_id: route_id.to_owned(),
            route_revision,
            ops_at_admission: op_names(&ops).into_iter().map(String::from).collect(),
            scope_at_admission,
            grant_expires_at: authority.expires_at,
            device_list_seq,
            projects_matched: Vec::new(),
        }
    }

    /// Whether the task's session is in the current grant's `projects`
    /// entry `entry` (Task 20 review I1): yes when it equals an entry the
    /// task's project matched at admission; no when another of those has
    /// its kid (the project's hash under that kid is the frozen one); else,
    /// for a kid the admission didn't see, the live comparison (`live`:
    /// none while it can't be made). Without frozen entries, `live` alone,
    /// as before they were kept.
    pub fn project_matches(
        &self,
        entry: &str,
        live: &dyn Fn(&str) -> Option<bool>,
    ) -> Option<bool> {
        use crate::runtime::project_scope::kid_of;
        if self.projects_matched.iter().any(|m| m == entry) {
            return Some(true);
        }
        let kid = kid_of(entry);
        if kid.is_some() && self.projects_matched.iter().any(|m| kid_of(m) == kid) {
            return Some(false);
        }
        live(entry)
    }

    /// With the `projects` scope entries the task's project matched at
    /// admission (sorted, once each).
    pub fn with_projects(mut self, mut matched: Vec<String>) -> Admission {
        matched.sort();
        matched.dedup();
        self.projects_matched = matched;
        self
    }
}

/// Who is delegated (design I.1.3, step 4's Decision 13), with
/// `host.delegated` on: a native member in effect on the host's pinned
/// device list (`list`), and a service in effect there that a feed this
/// host syncs covers (`controls`). Everyone else keeps v1: browser grants,
/// services no feed covers, `local`, host senders (`host.senders` is never
/// on in step 4) and anything that isn't a principal of the list.
///
/// The caller passes the host's device list only while it is open and
/// serving (pinned, not held, frozen or faulted): otherwise a native member
/// is v1, never delegated (`HostBridge::sender_class`).
pub fn classify(
    principal: &str,
    list: &Membership,
    controls: &dyn ControlView,
    features: HostFeatures,
) -> SenderClass {
    if !features.delegated || !is_delegated_sender(principal) {
        return SenderClass::V1;
    }
    let kind = |device_id: &str| {
        list.member(device_id)
            .filter(|m| m.status == MemberStatus::Active)
            .map(|m| &m.member.kind)
    };
    if let Some(device_id) = principal.strip_prefix("member:")
        && matches!(kind(device_id), Some(MemberKind::Native { .. }))
    {
        return SenderClass::Delegated(DelegatedSender::Native {
            device_id: device_id.to_owned(),
        });
    }
    if let Some(device_id) = principal.strip_prefix("service:")
        && matches!(kind(device_id), Some(MemberKind::Service { .. }))
        && let Some(feed) = controls.standing(principal).coverage
    {
        return SenderClass::Delegated(DelegatedSender::Service {
            device_id: device_id.to_owned(),
            feed,
        });
    }
    SenderClass::V1
}

/// What the bridge answers a `host.delegated` or `host.alerts` op that
/// reached it (`work_interrupt`, `work_resolve`, `alert_list`), after the
/// checks every host-work request has. With its feature off: `busy` and
/// nothing else, as before the hook existed (the channel refuses the op
/// while the feature isn't listed, so none gets here then; one that did is
/// never half-served). With it on: `busy`, saying the feature isn't served
/// yet, until its handlers exist.
pub fn request(features: HostFeatures, req: &Request) -> Result<ResultBody, HostWorkError> {
    let feature = req.feature();
    let detail = if feature == DELEGATED_FEATURE && features.delegated {
        Some(DELEGATED_NOT_SERVED)
    } else if feature == ALERTS_FEATURE && features.delegated && features.alerts {
        Some(ALERTS_NOT_SERVED)
    } else {
        None
    };
    Err(HostWorkError {
        code: "busy",
        detail,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session_protocol::membership::r9log::{TestLog, host_now, secret};
    use atem_client::session::host_work::{self as hw, HostTarget};

    const HOST: &str = "host-d";

    /// The Mac (genesis), this host, a phone (native, `control`), a native
    /// removed since, and a bot (a service on this host).
    fn list() -> TestLog {
        let mut log = TestLog::genesis("acct-d", &secret("astation"));
        log.add_host(HOST, 1, &secret("host seed"));
        log.add_native("dev-phone", &["control", "view"]);
        log.add_native("dev-old", &["control", "view"]);
        log.remove("dev-old");
        log.add_service(
            "svc-bot",
            &[HOST],
            None,
            &["notify", "prompt", "view"],
            host_now().wall_ms + 3_600_000,
        );
        log
    }

    /// The hook's value with `host.delegated` on.
    fn on() -> HostFeatures {
        HostFeatures::parse("host.delegated").unwrap()
    }

    fn feed() -> FeedRef {
        FeedRef {
            origin: "https://station-dev.agora.build".into(),
            feed_id: "feed-1".into(),
        }
    }

    /// A control view whose feeds cover these principals (as the feeds
    /// will, PR 10; until then the host's view is [`NoFeeds`]).
    struct Covers(Vec<&'static str>);

    impl ControlView for Covers {
        fn standing(&self, principal: &str) -> SenderStanding {
            SenderStanding {
                coverage: self.0.contains(&principal).then(feed),
                ..SenderStanding::default()
            }
        }
    }

    fn native(id: &str) -> SenderClass {
        SenderClass::Delegated(DelegatedSender::Native {
            device_id: id.into(),
        })
    }

    /// The three delegated ops, as a channel hands them to the runtime.
    fn ops() -> [hw::Request; 3] {
        let host = HostTarget {
            account_id: "acct-d".into(),
            atem_device_id: HOST.into(),
            host_trust_gen: 1,
        };
        let id = || uuid::Uuid::new_v4().to_string();
        [
            hw::Request::WorkInterrupt {
                v: 1,
                id: id(),
                host: host.clone(),
                task_id: id(),
            },
            hw::Request::WorkResolve {
                v: 1,
                id: id(),
                host: host.clone(),
                task_id: id(),
                resolution: hw::Resolution::Failed {
                    detail: "agent exited".into(),
                },
            },
            hw::Request::AlertList {
                v: 1,
                id: id(),
                host,
                after: None,
            },
        ]
    }

    /// `busy` with no detail: what the bridge answered before the hook
    /// existed.
    fn busy() -> Result<hw::ResultBody, HostWorkError> {
        Err(HostWorkError {
            code: "busy",
            detail: None,
        })
    }

    /// Design I.1.3, Decision 13: a native member on a host with a pinned
    /// device list is delegated (its stops come from the device list, so no
    /// feed is needed), once the hook turns `host.delegated` on. Only a
    /// native member in effect on the list is.
    #[test]
    fn native_member_tasks_are_delegated() {
        let log = list();
        assert_eq!(
            classify("member:dev-phone", &log.log, &NoFeeds, on()),
            native("dev-phone")
        );
        assert_eq!(
            classify("member:dev-mac", &log.log, &NoFeeds, on()),
            native("dev-mac")
        );
        // A feed's standing changes nothing for a native.
        assert_eq!(
            classify(
                "member:dev-phone",
                &log.log,
                &Covers(vec!["member:dev-phone"]),
                on()
            ),
            native("dev-phone")
        );
        // Without the hook nobody is delegated.
        assert_eq!(
            classify(
                "member:dev-phone",
                &log.log,
                &NoFeeds,
                HostFeatures::default()
            ),
            SenderClass::V1
        );
        // Removed, unknown, or a service named as a member: not a native
        // member in effect.
        for principal in ["member:dev-old", "member:dev-unknown", "member:svc-bot"] {
            assert_eq!(
                classify(principal, &log.log, &NoFeeds, on()),
                SenderClass::V1,
                "{principal}"
            );
        }
    }

    /// Design I.1.3: a service is delegated only while a feed this host
    /// syncs covers it (none until the feeds exist: [`NoFeeds`]); browser
    /// grants, `local`, host senders (`host.senders` is never on in step 4)
    /// and anything else keep v1, covered or not.
    #[test]
    fn uncovered_service_browser_and_local_keep_v1() {
        let log = list();
        assert_eq!(
            classify("service:svc-bot", &log.log, &NoFeeds, on()),
            SenderClass::V1
        );
        let covers = Covers(vec![
            "service:svc-bot",
            "service:dev-phone",
            "service:svc-gone",
            "browser:grant-1",
            "local",
            "host:host-other",
            "host-work",
        ]);
        assert_eq!(
            classify("service:svc-bot", &log.log, &covers, on()),
            SenderClass::Delegated(DelegatedSender::Service {
                device_id: "svc-bot".into(),
                feed: feed(),
            })
        );
        assert_eq!(
            classify(
                "service:svc-bot",
                &log.log,
                &covers,
                HostFeatures::default()
            ),
            SenderClass::V1,
            "not without the hook"
        );
        for principal in [
            // Covered, but not a service in effect on the list.
            "service:dev-phone",
            "service:svc-gone",
            "browser:grant-1",
            "local",
            "host:host-other",
            "host-work",
            "",
            "member:",
            "service:",
            "member:dev phone",
        ] {
            assert_eq!(
                classify(principal, &log.log, &covers, on()),
                SenderClass::V1,
                "{principal:?}"
            );
        }
    }

    /// Design I.4.1: what a delegated sender held at admission, frozen:
    /// its principal and key fingerprint (hex SHA-256 of its `auth_key`, as
    /// `r9_svc` is computed), its kind and feed, the route, the ops it
    /// held, its scope, its grant's expiry and the device list's head.
    #[test]
    fn admission_freezes_what_the_sender_held() {
        use atem_client::channel::Principal;
        use atem_client::membership::service_key_fingerprint;
        use atem_client::principal::{Authority, Op, op_names};
        let log = list();
        let now = host_now();
        let resolve = |principal: Principal| {
            Authority::resolve(&log.log, &principal, None, HOST, 1, &now, &|_| false).unwrap()
        };
        let head = log.log.head().seq;

        let phone = resolve(Principal::Native {
            device_id: "dev-phone".into(),
        });
        let SenderClass::Delegated(sender) = classify(&phone.name(), &log.log, &NoFeeds, on())
        else {
            panic!("a native member is delegated");
        };
        let a = Admission::freeze(&phone, sender.clone(), "r", 3, head);
        assert_eq!(
            a,
            Admission {
                principal: "member:dev-phone".into(),
                principal_key: service_key_fingerprint(&phone.key).unwrap(),
                sender,
                feed: None,
                route_id: "r".into(),
                route_revision: 3,
                // A native member holding `control` holds every op.
                ops_at_admission: op_names(&Op::ALL.into_iter().collect())
                    .into_iter()
                    .map(String::from)
                    .collect(),
                scope_at_admission: serde_json::Value::Null,
                grant_expires_at: None,
                device_list_seq: head,
                projects_matched: vec![],
            }
        );

        let bot = resolve(Principal::Service {
            device_id: "svc-bot".into(),
        });
        let covers = Covers(vec!["service:svc-bot"]);
        let SenderClass::Delegated(sender) = classify(&bot.name(), &log.log, &covers, on()) else {
            panic!("a covered service is delegated");
        };
        let a = Admission::freeze(&bot, sender, "r", 1, head);
        assert_eq!(a.principal, "service:svc-bot");
        assert_eq!(a.principal_key, service_key_fingerprint(&bot.key).unwrap());
        assert_eq!(a.feed, Some(feed()));
        assert_eq!(a.ops_at_admission, ["notify", "prompt", "view"]);
        assert_eq!(
            a.scope_at_admission,
            serde_json::json!({"ops": ["notify", "prompt", "view"], "hosts": [HOST]})
        );
        assert_eq!(a.grant_expires_at, bot.expires_at);
        assert!(a.grant_expires_at.is_some());
        // Stored with the task, and read back the same.
        let text = serde_json::to_string(&a).unwrap();
        assert_eq!(serde_json::from_str::<Admission>(&text).unwrap(), a);
        // The sender check (`authority::interaction`) compares the raw
        // key's digest with it: the same value.
        assert_eq!(
            hw::digest(bot.key.as_bytes()),
            a.principal_key,
            "one definition of the key's fingerprint"
        );
    }

    /// An admission stored before `projects_matched` existed (as e1bb860
    /// wrote it) reads with none, and one with none is written as before
    /// (no field): records of either build read the same.
    #[test]
    fn an_admission_without_projects_matched_reads_and_writes_as_before() {
        let old = serde_json::json!({
            "principal": "service:svc-bot",
            "principal_key": "ab".repeat(32),
            "sender": {"kind": "service", "device_id": "svc-bot",
                "feed": {"origin": "https://station-dev.agora.build", "feed_id": "feed-1"}},
            "feed": {"origin": "https://station-dev.agora.build", "feed_id": "feed-1"},
            "route_id": "r",
            "route_revision": 1,
            "ops_at_admission": ["notify", "prompt", "view"],
            "scope_at_admission": {"ops": ["notify", "prompt", "view"], "hosts": [HOST]},
            "grant_expires_at": 1_800_000_000_000_u64,
            "device_list_seq": 6,
        });
        let a: Admission = serde_json::from_value(old.clone()).unwrap();
        assert!(a.projects_matched.is_empty());
        assert_eq!(
            a.sender,
            DelegatedSender::Service {
                device_id: "svc-bot".into(),
                feed: feed(),
            }
        );
        assert_eq!(serde_json::to_value(&a).unwrap(), old);
    }

    /// With the hook off the delegated ops that reach the bridge are
    /// answered as before it existed: `busy`, no detail, nothing else.
    /// `host.alerts` without `host.delegated` turns nothing on, and
    /// `alert_list` needs `host.alerts`.
    #[test]
    fn delegated_ops_stay_busy_without_the_hook() {
        let alerts_only = HostFeatures {
            delegated: false,
            alerts: true,
        };
        for req in &ops() {
            assert_eq!(request(HostFeatures::default(), req), busy(), "{req:?}");
            assert_eq!(request(alerts_only, req), busy(), "{req:?}");
        }
        assert_eq!(
            request(on(), &ops()[2]),
            busy(),
            "alert_list needs host.alerts"
        );
    }

    /// With the hook on, the ops reach `delegated` and are `busy` (§7: a
    /// request the host can't take now), saying their feature isn't served
    /// yet: the handlers come with later tasks.
    #[test]
    fn hooked_delegated_ops_are_busy_until_served() {
        let both = HostFeatures::parse("host.delegated,host.alerts").unwrap();
        let [interrupt, resolve, alerts] = ops();
        for (req, detail) in [
            (&interrupt, DELEGATED_NOT_SERVED),
            (&resolve, DELEGATED_NOT_SERVED),
            (&alerts, ALERTS_NOT_SERVED),
        ] {
            assert_eq!(
                request(both, req),
                Err(HostWorkError {
                    code: "busy",
                    detail: Some(detail),
                }),
                "{req:?}"
            );
        }
        assert!(DELEGATED_NOT_SERVED.starts_with(hw::DELEGATED_FEATURE));
        assert!(ALERTS_NOT_SERVED.starts_with(hw::ALERTS_FEATURE));
        // Not a detail of §11.6's table: it says nothing about a task.
        assert!(!details::ALL.contains(&DELEGATED_NOT_SERVED));
        assert!(!details::ALL.contains(&ALERTS_NOT_SERVED));
    }

    /// Release builds compile the hook out (step 4, Decision 10): with the
    /// variable set, the runtime reads no features, the engine lists none of
    /// `host.delegated`, `host.alerts` and `host.senders` with hosting on,
    /// nobody is delegated and the ops are answered as before. Run by every
    /// release test job (`.github/workflows/test.yml`).
    #[cfg(not(debug_assertions))]
    #[test]
    fn release_builds_never_turn_on_host_features() {
        use crate::session_protocol::r9::R9Host;
        // SAFETY: the tests that write this variable (this one and
        // `test_hooks::tests::host_features_are_off_in_release`) write this
        // one value, and release builds never read it at all.
        unsafe { std::env::set_var("ATEM_TEST_HOST_FEATURES", "host.delegated,host.alerts") };
        let features = crate::runtime::test_hooks::host_features();
        assert_eq!(features, HostFeatures::default());
        let mut r9 = R9Host::default();
        r9.enable_host_work(true);
        r9.set_delegated_features(features.delegated, features.alerts);
        let advertised = r9.advertised_features();
        assert!(
            advertised.iter().any(|f| f == hw::WORK_FEATURE),
            "hosting is on: {advertised:?}"
        );
        for feature in [
            hw::DELEGATED_FEATURE,
            hw::ALERTS_FEATURE,
            hw::SENDERS_FEATURE,
        ] {
            assert!(!advertised.iter().any(|f| f == feature), "{feature}");
        }
        let log = list();
        assert_eq!(
            classify("member:dev-phone", &log.log, &NoFeeds, features),
            SenderClass::V1
        );
        for req in &ops() {
            assert_eq!(request(features, req), busy(), "{req:?}");
        }
    }
}
