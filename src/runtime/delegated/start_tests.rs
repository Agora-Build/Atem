//! The start check: `may_start`'s conditions and their order, and
//! `DelegatedStart` in the session host's `accepted` → `executing` step.
use super::*;
use crate::runtime::delegated::{FeedRef, SenderClass, classify};
use crate::runtime::test_hooks::HostFeatures;
use crate::session_protocol::fake_runtime::{AUTHORIZATION_MS, FakeRuntime};
use crate::session_protocol::host::{DETAIL_WITHDRAWN_BY_HOST, DispatchReport, Effect, HostConfig};
use crate::session_protocol::journal::Provenance;
use crate::session_protocol::membership::DeferredStop;
use crate::session_protocol::membership::r9log::{TestLog, host_now, secret};
use crate::session_protocol::wire::{self, Permission, ReceiptState};
use serde_json::json;

const HOST: &str = "host-a";
const S1: &str = "ses-aaaaaaaaaaaa";
const P1: &str = "22222222-2222-4222-8222-222222222222";
const TASK: &str = "5ba7b810-9dad-41d1-80b4-00c04fd430c8";
const HW: &str = "abababab-abab-4bab-8bab-abababababab";
const PHONE: &str = "member:dev-phone";
const BOT: &str = "service:svc-bot";
const ORIGIN: &str = "https://station-dev.agora.build";
/// A project entry of the bot's scope (`h1.<kid>.<hash>`, R9.6).
const PROJECT: &str =
    "h1.0a0b0c0d.1111111111111111111111111111111111111111111111111111111111111111";
/// Its kid.
const KID: &str = "0a0b0c0d";
/// Another project under that kid.
const OTHER: &str = "h1.0a0b0c0d.2222222222222222222222222222222222222222222222222222222222222222";

/// The list: the Mac, this host, the phone (`control`) and a bot scoped to
/// projects; `change` edits it after (a removal, a demotion).
fn log_with(change: impl FnOnce(&mut TestLog)) -> TestLog {
    log_of(&["notify", "prompt", "view"], change)
}

/// [`log_with`], the bot holding `bot_ops`.
fn log_of(bot_ops: &[&str], change: impl FnOnce(&mut TestLog)) -> TestLog {
    let mut log = TestLog::genesis("account-a", &secret("start astation"));
    log.add_host(HOST, 1, &secret("start host"));
    log.add_native("dev-phone", &["control", "view"]);
    log.add_service_projects(
        "svc-bot",
        &[HOST],
        Some(&[PROJECT]),
        None,
        bot_ops,
        host_now().wall_ms + 3_600_000,
    );
    change(&mut log);
    log
}

fn state(log: &TestLog) -> ListState {
    ListState {
        membership: Arc::new(log.log.clone()),
        frozen: false,
        held: false,
        faulted: false,
        unpaired: false,
        deferred: None,
    }
}

fn config(route_revision: u64) -> Config {
    toml::from_str(&format!(
        r#"
version = 1
enabled = true
[[profiles]]
id = "p"
revision = 1
label = "p"
provider = "claude"
cwd = "/tmp/start-check"
project = "local:project"
principals = ["{PHONE}", "{BOT}"]
[[routes]]
id = "rm"
revision = {route_revision}
profile_id = "p"
principals = ["{PHONE}", "{BOT}"]
"#
    ))
    .unwrap()
}

fn feed() -> FeedRef {
    FeedRef {
        origin: ORIGIN.into(),
        feed_id: "feed-1".into(),
    }
}

/// `principal`'s task, admitted on `log`'s head through route `rm`.
fn task(log: &TestLog, principal: &str, deadline: u64) -> StartTask {
    let (who, controls): (Principal, Covers) = match principal.strip_prefix("member:") {
        Some(id) => (
            Principal::Native {
                device_id: id.into(),
            },
            Covers(None),
        ),
        None => (
            Principal::Service {
                device_id: principal.strip_prefix("service:").unwrap().into(),
            },
            Covers(Some(feed())),
        ),
    };
    let mut now = host_now();
    now.wall_ms = 0;
    let authority = Authority::resolve(&log.log, &who, None, HOST, 1, &now, &|_| false).unwrap();
    let on = HostFeatures::parse("host.delegated").unwrap();
    let SenderClass::Delegated(sender) = classify(principal, &log.log, &controls, on) else {
        panic!("{principal} is delegated");
    };
    let admission = Admission::freeze(&authority, sender, "rm", 1, log.log.head().seq);
    StartTask {
        task_id: TASK.into(),
        admission,
        deadline,
        target: Target {
            account_id: "account-a".into(),
            atem_device_id: HOST.into(),
            host_trust_gen: 1,
            session_id: S1.into(),
            process_gen: P1.into(),
        },
        accepted: Accepted {
            principal: principal.into(),
            control_gen: 1,
            authorization_expires_at: None,
            route_id: "rm".into(),
            route_revision: 1,
            profile_id: "p".into(),
            profile_revision: 1,
            project: "local:project".into(),
        },
    }
}

/// A control view whose feed covers the bot (as PR 10's will).
struct Covers(Option<FeedRef>);

impl super::super::ControlView for Covers {
    fn standing(&self, principal: &str) -> SenderStanding {
        SenderStanding {
            coverage: (principal == BOT).then(|| self.0.clone()).flatten(),
            ..SenderStanding::default()
        }
    }
}

/// A view where the phone's and the bot's tasks may start: the list as
/// `log` is, the route at revision 1, the phone's channel caught up, the
/// bot covered by an open Station gate and its project's hash known.
fn view(log: &TestLog) -> StartView {
    let mut view = StartView::new(HOST);
    view.list = Some(state(log));
    view.config = config(1);
    view.gates
        .set_caught_up(BTreeSet::from([PHONE.to_string()]));
    view.gates.open_own_station(ORIGIN);
    view.standings.insert(
        BOT.into(),
        SenderStanding {
            coverage: Some(feed()),
            ..SenderStanding::default()
        },
    );
    view.scopes
        .hashes
        .insert((S1.into(), KID.into()), PROJECT.into());
    view.now_d_ms = Some(0);
    view
}

const LATER: u64 = u64::MAX / 2;

/// Condition 2a, owner-agreed Q4 (design I.4.3): a frozen, held or faulted
/// device list (or none) fails the task `sender's authority changed`, before
/// any other event (here the phone is also held and its gate closed).
#[test]
fn frozen_held_or_faulted_list_fails_sender_authority_changed() {
    let log = log_with(|_| {});
    let phone = task(&log, PHONE, LATER);
    assert_eq!(may_start(&view(&log), &phone, Some(0)), Ok(()));
    type Break = (&'static str, fn(&mut ListState));
    let breaks: [Break; 4] = [
        ("frozen", |l| l.frozen = true),
        ("held", |l| l.held = true),
        ("faulted", |l| l.faulted = true),
        ("unpaired", |l| l.unpaired = true),
    ];
    for (what, make) in breaks {
        let mut v = view(&log);
        make(v.list.as_mut().unwrap());
        v.standings.insert(
            PHONE.into(),
            SenderStanding {
                held: true,
                ..SenderStanding::default()
            },
        );
        v.gates.set_caught_up(BTreeSet::new());
        v.halted = true;
        assert_eq!(
            may_start(&v, &phone, Some(0)),
            Err(Event::AuthorityChanged),
            "{what}"
        );
    }
    let mut none = view(&log);
    none.list = None;
    assert_eq!(
        may_start(&none, &phone, Some(0)),
        Err(Event::AuthorityChanged)
    );
    assert_eq!(
        Event::AuthorityChanged.outcome(),
        (WorkState::Failed, "sender's authority changed")
    );
    assert!(Event::AuthorityChanged.holds_session());
}

/// Condition 2a: a halted session journal alone (the list usable) leaves
/// the task `blocked` until the restart, never failed; a halt beside a
/// faulted list fails it.
#[test]
fn a_halted_journal_alone_blocks_in_the_check() {
    let log = log_with(|_| {});
    let phone = task(&log, PHONE, LATER);
    let mut v = view(&log);
    v.halted = true;
    assert_eq!(may_start(&v, &phone, Some(0)), Err(Event::Halted));
    assert_eq!(
        Event::Halted.outcome(),
        (WorkState::Blocked, "journal halted; restart Atem")
    );
    v.list.as_mut().unwrap().faulted = true;
    assert_eq!(may_start(&v, &phone, Some(0)), Err(Event::AuthorityChanged));
}

/// Design I.4.3, "Locked credentials": a service whose `projects` scope
/// can't be compared (the cred agent locked: no hash under the kid, which
/// `ProjectScopes::pending_for` reports) waits, `waiting for unlock`, and
/// holds its session; it is never failed as narrowed. Once the hash is
/// known it starts, or, when it doesn't match, is narrowed.
#[test]
fn locked_credentials_block_waiting_for_unlock_never_narrowed() {
    let log = log_with(|_| {});
    let bot = task(&log, BOT, LATER);
    let mut v = view(&log);
    assert_eq!(may_start(&v, &bot, Some(0)), Ok(()));
    v.scopes.hashes.clear();
    v.scopes.pending.insert(KID.into());
    assert_eq!(may_start(&v, &bot, Some(0)), Err(Event::ScopePending));
    assert_eq!(
        Event::ScopePending.outcome(),
        (WorkState::Blocked, "waiting for unlock")
    );
    assert!(Event::ScopePending.holds_session());
    // A removal or a deadline still settles it while it waits.
    assert_eq!(may_start(&v, &bot, Some(LATER)), Err(Event::Expired));
    // A pending comparison never hides a narrowing of the rest: the bot's
    // ops lose `prompt`.
    let narrowed = log_of(&["notify", "view"], |_| {});
    let mut n = view(&narrowed);
    n.scopes.hashes.clear();
    n.scopes.pending.insert(KID.into());
    assert_eq!(may_start(&n, &bot, Some(0)), Err(Event::Narrowed));
    // Known, and another project: narrowed.
    v.scopes.pending.clear();
    v.scopes
        .hashes
        .insert((S1.into(), KID.into()), OTHER.into());
    assert_eq!(may_start(&v, &bot, Some(0)), Err(Event::Narrowed));
    // No launch project recorded for the session (nothing pending): never
    // in a `projects` scope.
    v.scopes.hashes.clear();
    assert_eq!(may_start(&v, &bot, Some(0)), Err(Event::Narrowed));
}

/// The deadline is compared with the delegated clock's `D` only (§11.6,
/// "Deadline comparisons"): at or past it the task expires (v1's text), and
/// without a reading it isn't compared (the dispatch waits for one).
#[test]
fn the_check_compares_the_deadline_with_d() {
    let log = log_with(|_| {});
    let phone = task(&log, PHONE, 1_000);
    let v = view(&log);
    assert_eq!(may_start(&v, &phone, Some(999)), Ok(()));
    assert_eq!(may_start(&v, &phone, Some(1_000)), Err(Event::Expired));
    assert_eq!(may_start(&v, &phone, None), Ok(()));
    assert_eq!(
        Event::Expired.outcome(),
        (WorkState::Expired, "expired before submission")
    );
}

/// Which waits hold their session (§11.6, "Waiting doesn't hold the
/// session"): `paused`, `revocations not yet checked` and `device list
/// update pending` don't; every other event does or settles the task.
#[test]
fn only_holds_gates_and_deferrals_let_the_session_go() {
    for (event, holds) in [
        (Event::Held, false),
        (Event::GateClosed, false),
        (Event::Deferred, false),
        (Event::ScopePending, true),
        (Event::Halted, true),
    ] {
        assert_eq!(event.holds_session(), holds, "{event:?}");
        assert_eq!(event.outcome().0, WorkState::Blocked, "{event:?}");
    }
    for event in [
        Event::Revoked,
        Event::Removed,
        Event::Narrowed,
        Event::RouteChanged,
        Event::AuthorityChanged,
        Event::Expired,
    ] {
        assert!(event.outcome().0.terminal(), "{event:?}");
    }
}

/// Task 20 review I1: a bot's task whose project matched an entry at
/// admission (frozen there) is judged by that entry: no hash (the kid
/// pending after its hashes went, or the session's project gone) starts
/// it; a grant re-scoped to another project under that kid narrows it,
/// never pending; under a kid the admission didn't see, the live comparison
/// decides (pending waits, a known hash starts it).
#[test]
fn frozen_project_entries_decide_without_a_hash() {
    use atem_client::membership::ServiceScope;
    const THIRD: &str =
        "h1.0b0b0b0b.3333333333333333333333333333333333333333333333333333333333333333";
    let rescoped = |entry: &'static str| {
        log_with(move |log| {
            log.set_service(
                "svc-bot",
                &ServiceScope::new([HOST])
                    .projects(Some([entry]))
                    .ops(["notify", "prompt"]),
                host_now().wall_ms + 3_600_000,
            );
        })
    };
    let log = log_with(|_| {});
    let mut bot = task(&log, BOT, LATER);
    bot.admission = bot.admission.clone().with_projects(vec![PROJECT.into()]);
    let mut v = view(&log);
    v.scopes.hashes.clear();
    v.scopes.pending.insert(KID.into());
    assert_eq!(may_start(&v, &bot, Some(0)), Ok(()));
    v.scopes.pending.clear();
    assert_eq!(may_start(&v, &bot, Some(0)), Ok(()));
    let other = rescoped(OTHER);
    let mut o = view(&other);
    o.scopes.hashes.clear();
    o.scopes.pending.insert(KID.into());
    assert_eq!(may_start(&o, &bot, Some(0)), Err(Event::Narrowed));
    let third = rescoped(THIRD);
    let mut t = view(&third);
    t.scopes.hashes.clear();
    t.scopes.pending.insert("0b0b0b0b".into());
    assert_eq!(may_start(&t, &bot, Some(0)), Err(Event::ScopePending));
    t.scopes.pending.clear();
    t.scopes
        .hashes
        .insert((S1.into(), "0b0b0b0b".into()), THIRD.into());
    assert_eq!(may_start(&t, &bot, Some(0)), Ok(()));
}

// ── At the start (the session host's `accepted` → `executing` step) ──

fn rid(n: u64) -> String {
    format!("44444444-4444-4444-8444-{n:012}")
}

fn setup() -> FakeRuntime {
    let setup = json!({
        "host": {"account_id": "account-a", "atem_device_id": HOST, "host_trust_gen": 1,
                 "runtime_gen": "55555555-5555-4555-8555-555555555555", "runtime_epoch": 7},
        "sessions": [{"session_id": S1, "process_gen": P1, "chat": true}],
        "clients": [],
    });
    let mut rt = FakeRuntime::from_json(setup, HostConfig::default());
    rt.connect_only(
        wire::HOST_WORK_PRINCIPAL,
        HW,
        vec![Permission::View, Permission::Control],
        AUTHORIZATION_MS,
    );
    let now = rt.now();
    rt.host.welcome_r9(HW, now).unwrap();
    let fx = rt.host.take_effects();
    rt.apply(fx);
    rt
}

/// Host-work submits attempt `n` of the phone's task (registered first, as
/// the dispatch does after the attempt's row committed).
fn submit(rt: &mut FakeRuntime, view: &Arc<Mutex<StartView>>, t: &StartTask, n: u64) {
    view.lock().unwrap().register(&rid(n), t.clone());
    let data = json!({"v": 1, "op": "submit", "id": uuid::Uuid::new_v4().to_string(),
        "binding": {"target": serde_json::to_value(&t.target).unwrap(), "attachment_gen": HW},
        "request_id": rid(n), "kind": "prompt", "payload": {"text": "run the tests"},
        "acquire": true});
    let fx = rt.host.submit_host_work(
        HW,
        data,
        Provenance {
            task_id: t.task_id.clone(),
            sender: t.admission.principal.clone(),
        },
    );
    rt.apply(fx);
}

fn state_of(rt: &FakeRuntime, n: u64) -> (ReceiptState, Option<String>) {
    let r = rt.host.receipt(&rid(n)).unwrap();
    (r.state, r.detail)
}

fn done() -> DispatchReport {
    DispatchReport::Completed {
        detail: Some("done".into()),
        turn_id: Some("turn-1".into()),
        user_message_id: Some("turn-1-u".into()),
    }
}

/// Design I.4.3 ("The same check runs at the start"), session-v1 R9.14
/// item 3, VII.A test 6: an attempt that waits `accepted` behind another
/// turn is checked again in the step that would make it `executing`, against
/// the view as it is then. Each change of conditions 2 to 5 (and 2a's
/// freeze) made while it waits withdraws it (`rejected`, `withdrawn by the
/// host`) before any effect, and the check keeps the event, which the task
/// then takes (a hold's withdrawal isn't counted). Unchanged, it starts.
#[test]
fn conditions_2_to_5_withdraw_at_executing() {
    let log = log_with(|_| {});
    let removed = log_with(|log| {
        log.remove("dev-phone");
    });
    let demoted = log_with(|log| {
        log.set_native_roles("dev-phone", &["view"]);
    });
    let phone = task(&log, PHONE, LATER);
    type Change = Box<dyn Fn(&mut StartView)>;
    let cases: Vec<(&str, Change, Event)> = vec![
        (
            "a revoke record (2)",
            Box::new(|v| {
                v.standings.insert(
                    PHONE.into(),
                    SenderStanding {
                        revoked: Some("rec-1".into()),
                        ..SenderStanding::default()
                    },
                );
            }),
            Event::Revoked,
        ),
        (
            "an R9 removal (2)",
            Box::new(move |v| v.list = Some(state(&removed))),
            Event::Removed,
        ),
        (
            "a hold (2)",
            Box::new(|v| {
                v.standings.insert(
                    PHONE.into(),
                    SenderStanding {
                        held: true,
                        ..SenderStanding::default()
                    },
                );
            }),
            Event::Held,
        ),
        (
            "a deferred entry (2)",
            Box::new(|v| {
                v.list.as_mut().unwrap().deferred = Some(DeferredStop {
                    seq: 9,
                    until_ms: LATER,
                    on: None,
                });
            }),
            Event::Deferred,
        ),
        (
            "a freeze (2a)",
            Box::new(|v| v.list.as_mut().unwrap().frozen = true),
            Event::AuthorityChanged,
        ),
        (
            "a narrowing (3)",
            Box::new(move |v| v.list = Some(state(&demoted))),
            Event::Narrowed,
        ),
        (
            "a route change (4)",
            Box::new(|v| v.config = config(2)),
            Event::RouteChanged,
        ),
        (
            "the gate closed (5)",
            // The phone's channel closed, no Station gate open (this
            // version's gates).
            Box::new(|v| v.gates = Gates::closed_until_feeds()),
            Event::GateClosed,
        ),
    ];
    let mut rt = setup();
    let shared = Arc::new(Mutex::new(view(&log)));
    rt.host
        .set_start_check(Box::new(DelegatedStart(shared.clone())));
    let mut n = 0;
    for (what, change, event) in &cases {
        // A turn runs: its attempt started, the view as at dispatch.
        *shared.lock().unwrap() = view(&log);
        n += 1;
        let running = n;
        submit(&mut rt, &shared, &phone, running);
        assert_eq!(state_of(&rt, running).0, ReceiptState::Executing, "{what}");
        // The next attempt waits `accepted` behind it.
        n += 1;
        submit(&mut rt, &shared, &phone, n);
        assert_eq!(state_of(&rt, n).0, ReceiptState::Accepted, "{what}");
        change(&mut shared.lock().unwrap());
        let fx = rt.host.dispatch_report(&rid(running), done());
        assert!(
            !fx.iter()
                .any(|e| matches!(e, Effect::Dispatch { request_id, .. } if *request_id == rid(n))),
            "{what}: nothing dispatched"
        );
        rt.apply(fx);
        assert_eq!(
            state_of(&rt, n),
            (
                ReceiptState::Rejected,
                Some(DETAIL_WITHDRAWN_BY_HOST.to_string())
            ),
            "{what}"
        );
        assert_eq!(
            shared.lock().unwrap().refused(&rid(n)),
            Some(*event),
            "{what}"
        );
    }
    // Unchanged, the waiting attempt starts in that step.
    *shared.lock().unwrap() = view(&log);
    n += 1;
    let running = n;
    submit(&mut rt, &shared, &phone, running);
    n += 1;
    submit(&mut rt, &shared, &phone, n);
    let fx = rt.host.dispatch_report(&rid(running), done());
    rt.apply(fx);
    assert_eq!(state_of(&rt, n).0, ReceiptState::Executing);
    assert_eq!(shared.lock().unwrap().refused(&rid(n)), None);
    // An attempt the view doesn't know (or another task's) never starts.
    let fx = rt.host.dispatch_report(&rid(n), done());
    rt.apply(fx);
    let data = json!({"v": 1, "op": "submit", "id": uuid::Uuid::new_v4().to_string(),
        "binding": {"target": serde_json::to_value(&phone.target).unwrap(), "attachment_gen": HW},
        "request_id": rid(99), "kind": "prompt", "payload": {"text": "unknown"},
        "acquire": true});
    let fx = rt.host.submit_host_work(
        HW,
        data,
        Provenance {
            task_id: TASK.into(),
            sender: PHONE.into(),
        },
    );
    rt.apply(fx);
    assert_eq!(
        state_of(&rt, 99),
        (
            ReceiptState::Rejected,
            Some(DETAIL_WITHDRAWN_BY_HOST.to_string())
        )
    );
    assert_eq!(shared.lock().unwrap().refused(&rid(99)), None);
}

/// Task 19 review M3: without a reading of the delegated clock the start
/// check can't compare the deadline, so it withdraws the attempt (fail
/// closed), naming no event; with one, the same attempt starts.
#[test]
fn the_start_check_withdraws_without_a_reading() {
    let log = log_with(|_| {});
    let phone = task(&log, PHONE, LATER);
    let mut rt = setup();
    let shared = Arc::new(Mutex::new(view(&log)));
    shared.lock().unwrap().now_d_ms = None;
    rt.host
        .set_start_check(Box::new(DelegatedStart(shared.clone())));
    submit(&mut rt, &shared, &phone, 1);
    assert_eq!(
        state_of(&rt, 1),
        (
            ReceiptState::Rejected,
            Some(DETAIL_WITHDRAWN_BY_HOST.to_string())
        )
    );
    assert_eq!(shared.lock().unwrap().refused(&rid(1)), None);
    shared.lock().unwrap().now_d_ms = Some(0);
    submit(&mut rt, &shared, &phone, 2);
    assert_eq!(state_of(&rt, 2).0, ReceiptState::Executing);
}

/// Design I.4.3, "Launches": the spawn-boundary check of a launch is
/// [`may_start`]'s events in their order, with `launch` for `notify` and
/// `prompt`, the profile for the route and the launch's expiry for the
/// deadline: what settles a task fails the launch with the event's detail,
/// what blocks one makes it wait, and an expiry passed is `expired before
/// the spawn`. A service's `projects` scope is compared on the profile's
/// scope key: pending, it waits for unlock, never narrowed.
#[test]
fn the_launch_check_gives_may_starts_events_for_a_launch() {
    use crate::runtime::delegated::details;
    let log = log_of(&["launch", "notify", "prompt", "view"], |_| {});
    let profile = config(1).profile("p").unwrap().clone();
    let key = profile.scope_key();
    let launch = |principal: &str| StartLaunch {
        admission: task(&log, principal, LATER).admission,
        profile: profile.clone(),
        expires_at: 1_000,
    };
    let (phone, bot) = (launch(PHONE), launch(BOT));
    let ready = || {
        let mut v = view(&log);
        v.scopes
            .hashes
            .insert((key.clone(), KID.into()), PROJECT.into());
        v
    };
    let v = ready();
    assert_eq!(launch_check(&v, &phone, 0), LaunchVerdict::Go);
    assert_eq!(launch_check(&v, &bot, 999), LaunchVerdict::Go);
    assert_eq!(
        launch_check(&v, &bot, 1_000),
        LaunchVerdict::Fail(details::EXPIRED_BEFORE_THE_SPAWN)
    );
    // The bot's project: pending, then another one.
    let mut v = ready();
    v.scopes.hashes.clear();
    v.scopes.pending.insert(KID.into());
    assert_eq!(
        launch_check(&v, &bot, 0),
        LaunchVerdict::Wait(details::WAITING_FOR_UNLOCK)
    );
    v.scopes.pending.clear();
    v.scopes.hashes.insert((key.clone(), KID.into()), OTHER.into());
    assert_eq!(
        launch_check(&v, &bot, 0),
        LaunchVerdict::Fail(details::AUTHORIZATION_NARROWED)
    );
    // A grant without `launch` (the bot of `log_with`) is narrowed.
    let no_launch = log_with(|_| {});
    let mut v = view(&no_launch);
    v.scopes
        .hashes
        .insert((key.clone(), KID.into()), PROJECT.into());
    let bot_without = StartLaunch {
        admission: task(&no_launch, BOT, LATER).admission,
        profile: profile.clone(),
        expires_at: 1_000,
    };
    assert_eq!(
        launch_check(&v, &bot_without, 0),
        LaunchVerdict::Fail(details::AUTHORIZATION_NARROWED)
    );
    // The profile changed: the route of condition 4.
    let mut v = ready();
    v.config.profiles[0].revision = 2;
    assert_eq!(
        launch_check(&v, &phone, 0),
        LaunchVerdict::Fail(details::ROUTE_CHANGED)
    );
    // Settling events first: held and revoked is revoked; held, frozen.
    let mut v = ready();
    v.standings.insert(
        PHONE.into(),
        SenderStanding {
            held: true,
            ..SenderStanding::default()
        },
    );
    assert_eq!(
        launch_check(&v, &phone, 0),
        LaunchVerdict::Wait(details::PAUSED)
    );
    v.list.as_mut().unwrap().frozen = true;
    assert_eq!(
        launch_check(&v, &phone, 0),
        LaunchVerdict::Fail(details::AUTHORITY_CHANGED)
    );
    v.list.as_mut().unwrap().frozen = false;
    v.standings.get_mut(PHONE).unwrap().revoked = Some("rec-1".into());
    assert_eq!(
        launch_check(&v, &phone, 0),
        LaunchVerdict::Fail(details::SENDER_REVOKED)
    );
    // The journal halted alone: the check says wait (its callers fence a
    // launch on a halt first, hosting §5); beside a faulted list, failed.
    let mut v = ready();
    v.halted = true;
    assert_eq!(
        launch_check(&v, &phone, 0),
        LaunchVerdict::Wait(details::JOURNAL_HALTED)
    );
    v.list.as_mut().unwrap().faulted = true;
    assert_eq!(
        launch_check(&v, &phone, 0),
        LaunchVerdict::Fail(details::AUTHORITY_CHANGED)
    );
    // The gate closed and a deferred entry wait.
    let mut v = ready();
    v.gates.set_caught_up(BTreeSet::new());
    v.gates.close_stations();
    assert_eq!(
        launch_check(&v, &phone, 0),
        LaunchVerdict::Wait(details::REVOCATIONS_NOT_YET_CHECKED)
    );
    let mut v = ready();
    v.list.as_mut().unwrap().deferred = Some(DeferredStop {
        seq: 9,
        until_ms: u64::MAX,
        on: None,
    });
    assert_eq!(
        launch_check(&v, &bot, 0),
        LaunchVerdict::Wait(details::DEVICE_LIST_UPDATE_PENDING)
    );
}
