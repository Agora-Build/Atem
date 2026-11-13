// Interaction authority and the event rules of delegated tasks (design
// I.2, I.3, I.4.5; host-work-v1 §11.6; step 4's Decisions 13 and 15), in
// the bridge: the rig's host with a pinned device list, the phone (a native
// member holding `control`) and a bot (a service on this host, classified
// on a control view whose feed of the host's own Station covers it, as PR
// 10's feeds will), the fake agent, and the delegated clock on a manual OS.
// Included beside the dispatch's tests (`dispatch_tests.rs`), whose helpers
// and imports it shares.

use crate::runtime::delegated::gate::Gates;
use crate::runtime::delegated::{ControlView, FeedRef};
use crate::runtime::host_work::AUTHORIZATION_EXPIRED;
use crate::runtime::project_scope::{CredAgentHasher, ProjectScopes, TableAgent};
use atem_client::canonical::StrictValue;
use atem_client::membership::ServiceScope;

const BOT: &str = "service:svc-bot";
/// A session a bot's scope may name besides the rig's (never launched).
const OTHER_SESSION: &str = "ses-zzzzzzzzzzzz";
const HOUR: u64 = 3_600_000;
/// The kid of the bot's `projects` entries, and the rig's launch project's
/// hash under it (`h1.<kid>.<hash>`, R9.6), as the test cred agent makes it.
const KID: &str = "0a0b0c0d";
const PROJECT: &str =
    "h1.0a0b0c0d.1111111111111111111111111111111111111111111111111111111111111111";
/// Another project under that kid.
const OTHER_PROJECT: &str =
    "h1.0a0b0c0d.2222222222222222222222222222222222222222222222222222222222222222";
/// The rig's launch project key.
const RIG_PROJECT: &str = "local:project";

/// The phone, the bot, the Mac (a native member holding `control`: an
/// owner), a viewer (`view` only), and the list behind them.
struct Senders {
    phone: Authority,
    bot: Authority,
    mac: Authority,
    viewer: Authority,
    log: TestLog,
}

/// `principal` of `log`, as its channel resolves it now.
fn resolve(log: &TestLog, principal: atem_client::channel::Principal) -> Authority {
    use crate::session_protocol::membership::r9log::host_now as now;
    Authority::resolve(&log.log, &principal, None, "host", 1, &now(), &|_| false).unwrap()
}

/// A control view whose feed (of the host's own Station) covers the bot.
struct CoversBot;

impl ControlView for CoversBot {
    fn standing(&self, principal: &str) -> SenderStanding {
        SenderStanding {
            coverage: (principal == BOT).then(bot_feed),
            ..SenderStanding::default()
        }
    }
}

/// How the bot's grant is scoped: the rig's session and [`OTHER_SESSION`],
/// or these `projects` entries.
enum BotScope<'a> {
    Sessions,
    Projects(&'a [&'a str]),
}

/// The rig as a delegated host (`host.delegated` on, the delegated clock on
/// `os`, the host's own Station's gate open): its list the Mac, this host,
/// the phone, a viewer and the bot (scoped to the rig's session and
/// [`OTHER_SESSION`], `message`, `notify`, `prompt`, `stop` and `view`,
/// expiring at `bot_expiry`), routes `rm` (the phone) and `rs` (the bot),
/// and the bot covered by a feed of the host's own Station.
fn with_bot(rig: &mut LocalRig, root: &Path, os: &ManualOs, bot_expiry: u64) -> Senders {
    delegated_host(rig, root, os, bot_expiry, BotScope::Sessions, &BOT_OPS)
}

/// The bot's ops in [`with_bot`]: no `interrupt`.
const BOT_OPS: [&str; 5] = ["message", "notify", "prompt", "stop", "view"];

/// [`with_bot`], the bot's grant holding `ops` instead.
fn with_bot_ops(
    rig: &mut LocalRig,
    root: &Path,
    os: &ManualOs,
    bot_expiry: u64,
    ops: &[&str],
) -> Senders {
    delegated_host(rig, root, os, bot_expiry, BotScope::Sessions, ops)
}

/// [`with_bot`], the bot's grant scoped to `projects` entries instead, and
/// the rig's project hashed by `agent` (a test cred agent that makes
/// [`PROJECT`] under [`KID`]); once both the session's and the profile's
/// hashes are known (what an enqueue compares).
async fn with_project_bot(
    rig: &mut LocalRig,
    root: &Path,
    os: &ManualOs,
    bot_expiry: u64,
    projects: &[&str],
    agent: &Arc<TableAgent>,
) -> Senders {
    agent
        .table
        .lock()
        .unwrap()
        .insert((RIG_PROJECT.into(), KID.into()), PROJECT.into());
    rig.bridge.projects = ProjectScopes::new(Arc::new(CredAgentHasher {
        agent: agent.clone(),
        astation_id: "astation-test".into(),
    }));
    let profile = rig.bridge.work.config.profile("p").unwrap().scope_key();
    rig.bridge
        .projects
        .session(rig.sid.as_str(), Some(RIG_PROJECT.into()));
    rig.bridge
        .projects
        .session(&profile, Some(RIG_PROJECT.into()));
    let s = delegated_host(
        rig,
        root,
        os,
        bot_expiry,
        BotScope::Projects(projects),
        &BOT_OPS,
    );
    rig.until(|r| {
        r.bridge.projects.matches(r.sid.as_str(), PROJECT) == Some(true)
            && r.bridge.projects.matches(&profile, PROJECT) == Some(true)
    })
    .await;
    s
}

fn delegated_host(
    rig: &mut LocalRig,
    root: &Path,
    os: &ManualOs,
    bot_expiry: u64,
    scope: BotScope<'_>,
    ops: &[&str],
) -> Senders {
    use crate::session_protocol::membership::r9log::secret;
    use crate::session_protocol::membership::{HostPin, MembershipHost};
    use atem_client::channel::Principal;
    rig.bridge.features = HostFeatures::parse("host.delegated").unwrap();
    rig.bridge.work.controls = Some(Box::new(CoversBot));
    let mut log = TestLog::genesis("acct", &secret("delegated astation"));
    log.add_host("host", 1, &secret("delegated host"));
    log.add_native("dev-phone", &["control", "view"]);
    log.add_native("dev-viewer", &["view"]);
    match scope {
        BotScope::Sessions => log.add_service(
            "svc-bot",
            &["host"],
            Some(&[rig.sid.as_str(), OTHER_SESSION]),
            ops,
            bot_expiry,
        ),
        BotScope::Projects(projects) => {
            log.add_service_projects("svc-bot", &["host"], Some(projects), None, ops, bot_expiry)
        }
    };
    let pairing = crate::profile::Sources::in_dir(&root.join("profile"))
        .paths
        .pairing;
    let pin = HostPin {
        host_id: "host".into(),
        host_trust_gen: 1,
    };
    MembershipHost::pin(
        &pairing,
        &rig.bridge.dir,
        &pin,
        &log.log,
        &secret("delegated host"),
    )
    .unwrap();
    rig.bridge.pairing = Some(pairing);
    rig.bridge.reopen_list_if_changed(&mut Cx {
        client: &rig.app.astation_client,
        sessions: &mut rig.sessions,
    });
    rig.bridge.pairing = None;
    assert!(rig.bridge.membership.is_some() && rig.bridge.host_key.is_some());
    for (id, principal) in [("rm", PHONE), ("rs", BOT)] {
        rig.bridge
            .work
            .config
            .routes
            .push(crate::runtime::host_work::Route {
                id: id.into(),
                revision: 1,
                profile_id: "p".into(),
                principals: vec![principal.into()],
                labels: vec![],
                launch: Default::default(),
                results: false,
                auto_report: Default::default(),
            });
    }
    manual_clock(rig, os);
    // The control feeds load as at a runtime's first pass (the tests'
    // control view stands in for them).
    rig.bridge.ensure_feeds();
    rig.bridge.start_view().gates.open_own_station(ORIGIN);
    rig.bridge.start_view().standings.insert(
        BOT.into(),
        SenderStanding {
            coverage: Some(bot_feed()),
            ..SenderStanding::default()
        },
    );
    let native = |id: &str| Principal::Native {
        device_id: id.into(),
    };
    Senders {
        phone: resolve(&log, native("dev-phone")),
        bot: resolve(
            &log,
            Principal::Service {
                device_id: "svc-bot".into(),
            },
        ),
        mac: resolve(&log, native(MAC)),
        viewer: resolve(&log, native("dev-viewer")),
        log,
    }
}

/// The feed covering the bot (its gate is the host's own Station's).
fn bot_feed() -> FeedRef {
    FeedRef {
        origin: ORIGIN.into(),
        feed_id: "feed-1".into(),
    }
}

/// A request about a task (or a message), built when it is asked.
enum Q<'a> {
    Query(&'a str),
    Reply(&'a str),
    Cancel(&'a str),
    /// `work_complete` with a result of this text.
    Complete(&'a str, &'a str),
    /// `message_query` of a `message_publish` request's message.
    Message(&'a hw::Request),
    /// `work_interrupt` (`host.delegated`, host-work-v1 §11.2).
    Interrupt(&'a str),
}

impl Q<'_> {
    fn request(&self, host: HostTarget) -> hw::Request {
        let id = uuid::Uuid::new_v4().to_string();
        match *self {
            Q::Query(task) => hw::Request::WorkQuery {
                v: 1,
                id,
                host,
                task_id: task.into(),
            },
            Q::Reply(task) => hw::Request::ReplyQuery {
                v: 1,
                id,
                host,
                task_id: task.into(),
            },
            Q::Cancel(task) => hw::Request::Cancel {
                v: 1,
                id,
                host,
                task_id: task.into(),
            },
            Q::Complete(task, text) => hw::Request::Complete {
                v: 1,
                id,
                host,
                task_id: task.into(),
                result: hw::ContextSnapshot {
                    kind: hw::ContextKind::Vault,
                    id: "v-result:1".into(),
                    version: 1,
                    digest: hw::digest(text.as_bytes()),
                    text: text.into(),
                },
            },
            Q::Interrupt(task) => hw::Request::WorkInterrupt {
                v: 1,
                id,
                host,
                task_id: task.into(),
            },
            Q::Message(publish) => {
                let hw::Request::Publish { message, .. } = publish else {
                    unreachable!()
                };
                hw::Request::MessageQuery {
                    v: 1,
                    id,
                    host,
                    message_id: message.message_id.clone(),
                }
            }
        }
    }
}

/// `who` asks `q`, as its channel hands the request to the bridge.
fn ask(rig: &mut LocalRig, who: &Authority, q: Q<'_>) -> Result<ResultBody, HostWorkError> {
    let req = q.request(rig.bridge.work_host());
    ask_req(rig, who, &req)
}

/// `who` sends `req`.
fn ask_req(
    rig: &mut LocalRig,
    who: &Authority,
    req: &hw::Request,
) -> Result<ResultBody, HostWorkError> {
    rig.bridge.work_request_as(
        "att-asker",
        req,
        Sender::Remote(Box::new(who.clone())),
        &mut Cx {
            client: &rig.app.astation_client,
            sessions: &mut rig.sessions,
        },
    )
}

fn forbidden() -> Result<ResultBody, HostWorkError> {
    Err(HostWorkError {
        code: "forbidden",
        detail: None,
    })
}

fn busy() -> Result<ResultBody, HostWorkError> {
    Err(HostWorkError {
        code: "busy",
        detail: None,
    })
}

/// The status a `work` result carries.
fn status(reply: Result<ResultBody, HostWorkError>) -> WorkStatus {
    match reply {
        Ok(ResultBody::Work { work }) => work,
        other => panic!("a work result: {other:?}"),
    }
}

/// The text of the reply a `reply_query` result carries.
fn reply_text(reply: Result<ResultBody, HostWorkError>) -> String {
    match reply {
        Ok(ResultBody::Reply { reply: Some(r) }) => r.text,
        other => panic!("a reply: {other:?}"),
    }
}

/// The bot enqueues `prompt` through route `rs`, its deadline
/// `expires_at`: the task's id. A feed covers it (`CoversBot`), so the task
/// is delegated, its admission frozen by the bridge.
fn bot_task(rig: &mut LocalRig, s: &Senders, prompt: &str, expires_at: u64) -> String {
    let mut req = phone_enqueue(rig, prompt);
    if let hw::Request::Enqueue { route_id, task, .. } = &mut req {
        *route_id = "rs".into();
        task.expires_at = expires_at;
    }
    ask_req(rig, &s.bot, &req).unwrap();
    let id = enqueued(&req);
    let admission = stored_record(rig, &id)
        .delegated
        .expect("a covered bot's task");
    assert_eq!(admission.principal, BOT);
    id
}

/// The phone enqueues `prompt` with its deadline at `expires_at`.
fn phone_task(rig: &mut LocalRig, phone: &Authority, prompt: &str, expires_at: u64) -> String {
    let mut req = phone_enqueue(rig, prompt);
    if let hw::Request::Enqueue { task, .. } = &mut req {
        task.expires_at = expires_at;
    }
    as_phone(rig, phone, &req).unwrap();
    enqueued(&req)
}

/// `entry` (signed into `log`) is carried to the host, as a route or the
/// host's own fetch carries it; the host's head is `log`'s then.
fn carry(rig: &mut LocalRig, log: &TestLog, entry: Value) {
    let entry = StrictValue::parse(entry.to_string().as_bytes(), usize::MAX).unwrap();
    rig.bridge
        .carry(
            &[entry],
            &mut Cx {
                client: &rig.app.astation_client,
                sessions: &mut rig.sessions,
            },
        )
        .unwrap();
    assert_eq!(
        rig.bridge.membership.as_ref().unwrap().head().seq,
        log.log.head().seq
    );
}

/// The task's prompt is written and its turn ends: `awaiting_result`.
async fn run(rig: &mut LocalRig, task: &str, prompt: &str) {
    rig.until(|r| input(r).contains(prompt)).await;
    complete(rig, task).await;
}

/// `task` waits `blocked` with `detail`.
async fn blocked(rig: &mut LocalRig, task: &str, detail: &str) {
    rig.until(|r| {
        let s = stored_record(r, task).status;
        s.state == WorkState::Blocked && s.detail == detail
    })
    .await;
}

/// `task`'s state and detail as stored.
fn settled(rig: &LocalRig, task: &str) -> (WorkState, String) {
    let s = stored_record(rig, task).status;
    (s.state, s.detail)
}

fn outcome(event: Event) -> (WorkState, String) {
    let (state, detail) = event.outcome();
    (state, detail.to_string())
}

/// A new attempt of `task` is made, committed and submitted as the
/// dispatch makes one (a dispatch racing a turn would leave it so): with a
/// turn of host-work's running on the session, it waits `accepted` behind
/// it. Its id.
fn attempt_behind_the_turn(rig: &mut LocalRig, task: &str, prompt: &str) -> String {
    let store = rig.bridge.work.store.as_ref().unwrap();
    let tx = store.immediate().unwrap();
    let attempt = store.new_attempt(&tx, task).unwrap();
    let mut record = store.work(task).unwrap().unwrap();
    record.status.state = WorkState::Submitting;
    record.status.detail = "dispatch intent persisted".into();
    store.save_work(&record).unwrap();
    tx.commit().unwrap();
    rig.bridge.start_view().register(
        &attempt.attempt_id,
        crate::runtime::delegated::start::StartTask::of(&record).unwrap(),
    );
    let att = rig.bridge.host_work_attachment().unwrap().to_string();
    let (mut binding, _) = rig
        .bridge
        .host
        .binding_for_work(&att, &record.task.target)
        .unwrap();
    // Sent with `acquire` (its own lease, unchanged), as host-work submits.
    binding.lease_epoch = None;
    let data = json!({"v": 1, "op": "submit", "id": uuid::Uuid::new_v4().to_string(),
        "binding": binding, "request_id": attempt.attempt_id, "kind": "prompt",
        "payload": {"text": prompt}, "acquire": true});
    let effects = rig.bridge.host.submit_host_work(
        &att,
        data,
        crate::session_protocol::host::Provenance {
            task_id: task.to_string(),
            sender: record.principal.clone(),
        },
    );
    rig.bridge.exec(
        effects,
        &mut Cx {
            client: &rig.app.astation_client,
            sessions: &mut rig.sessions,
        },
    );
    let receipt = rig
        .bridge
        .host
        .attempt_receipt(&attempt.attempt_id, task)
        .expect("admitted");
    assert_eq!(receipt.state, wire::ReceiptState::Accepted);
    attempt.attempt_id
}

/// VII.A test 2, design I.2 and I.3.3 ("Grant or integration expires"):
/// the bot's grant expires on the delegated clock with one task awaiting
/// its result and another waiting (behind a closed gate). Neither fails:
/// the awaiting one isn't `sender's authorization expired`, and the waiting
/// one runs after the expiry, before its deadline. Nothing ran twice, and
/// the expiry issued no control record.
#[test]
fn expiry_neither_fails_nor_stops_accepted_tasks() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = with_bot(&mut rig, root, &os, start + HOUR);
        let first = bot_task(&mut rig, &s, "EXPIRY_FIRST", start + 3 * HOUR);
        run(&mut rig, &first, "EXPIRY_FIRST").await;
        // Its authorization recorded as already past on the wall clock too
        // (v1's arm would fail it, by the wall clock, at once).
        let mut record = stored_record(&rig, &first);
        record.authorization_expires_at = Some(start - 1);
        rig.bridge
            .work
            .store
            .as_ref()
            .unwrap()
            .save_work(&record)
            .unwrap();
        rig.bridge.start_view().gates = Gates::default();
        let second = bot_task(&mut rig, &s, "EXPIRY_SECOND", start + 3 * HOUR);
        blocked(&mut rig, &second, details::REVOCATIONS_NOT_YET_CHECKED).await;
        // The grant expires: `D` passes it.
        os.pass(HOUR + 1_000);
        passes(&mut rig, 5);
        let (state, detail) = settled(&rig, &first);
        assert_eq!(state, WorkState::AwaitingResult, "{detail}");
        assert_ne!(detail, AUTHORIZATION_EXPIRED);
        assert_eq!(
            settled(&rig, &second),
            (
                WorkState::Blocked,
                details::REVOCATIONS_NOT_YET_CHECKED.into()
            )
        );
        // Its gate opens: it runs, past the grant's expiry.
        rig.bridge.start_view().gates.open_own_station(ORIGIN);
        run(&mut rig, &second, "EXPIRY_SECOND").await;
        passes(&mut rig, 3);
        assert_eq!(settled(&rig, &first).0, WorkState::AwaitingResult);
        let text = input(&rig);
        assert_eq!(text.matches("EXPIRY_FIRST").count(), 1);
        assert_eq!(text.matches("EXPIRY_SECOND").count(), 1);
        assert_eq!(attempts(&rig, &second).len(), 1);
        assert_eq!(
            rig.bridge.start_view().standings[BOT].revoked,
            None,
            "an expiry is no revocation"
        );
    });
}

/// VII.A test 2 (its queries), design I.4.5: once the bot's grant expired
/// on the delegated clock, its `work_query`, `reply_query`, `work_cancel`
/// and `work_complete` are `forbidden`; the owner still reads. A renewal
/// (the same key, a later expiry), which moves its control generation,
/// makes the task and its reply readable again, and completable; the
/// prompt ran once.
#[test]
fn queries_refused_after_expiry_readable_after_renewal() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let mut s = with_bot(&mut rig, root, &os, start + HOUR);
        let task = bot_task(&mut rig, &s, "RENEWAL_PROMPT", start + 3 * HOUR);
        run(&mut rig, &task, "RENEWAL_PROMPT").await;
        reply(&mut rig, &task, "RENEWAL_REPLY", &[]).unwrap();
        let bot = s.bot.clone();
        assert_eq!(
            status(ask(&mut rig, &bot, Q::Query(&task))).state,
            WorkState::AwaitingResult
        );
        assert_eq!(
            reply_text(ask(&mut rig, &bot, Q::Reply(&task))),
            "RENEWAL_REPLY"
        );
        os.pass(HOUR + 1_000);
        passes(&mut rig, 2);
        for q in [
            Q::Query(&task),
            Q::Reply(&task),
            Q::Cancel(&task),
            Q::Complete(&task, "too late"),
        ] {
            assert_eq!(ask(&mut rig, &bot, q), forbidden());
        }
        let mac = s.mac.clone();
        assert_eq!(
            reply_text(ask(&mut rig, &mac, Q::Reply(&task))),
            "RENEWAL_REPLY",
            "the owner reads it"
        );
        // A renewal: the same key, a later expiry.
        let fenced_at = rig.bridge.host.control_gen(BOT);
        let renewal = s.log.renew_service("svc-bot", start + 4 * HOUR);
        carry(&mut rig, &s.log, renewal);
        assert!(
            rig.bridge.host.control_gen(BOT) > fenced_at,
            "the renewal fenced"
        );
        assert_eq!(
            status(ask(&mut rig, &bot, Q::Query(&task))).state,
            WorkState::AwaitingResult
        );
        assert_eq!(
            reply_text(ask(&mut rig, &bot, Q::Reply(&task))),
            "RENEWAL_REPLY"
        );
        assert_eq!(
            status(ask(&mut rig, &bot, Q::Complete(&task, "done"))).state,
            WorkState::Completed
        );
        assert_eq!(input(&rig).matches("RENEWAL_PROMPT").count(), 1);
    });
}

/// Design I.4.5 ("A changed `control_gen` no longer forbids these calls"),
/// I.3.3: the phone's principal is fenced (its control generation moves
/// on). Its delegated tasks are neither failed nor hidden: the one awaiting
/// its result and its reply stay readable, the waiting one runs. Its v1
/// task (enqueued with the hook off) keeps v1's rules: failed, `sender's
/// authority changed`, and `forbidden` to read.
#[test]
fn control_gen_change_doesnt_forbid_reads() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let (phone, _) = delegated(&mut rig, root, &os, true);
        let first = phone_task(&mut rig, &phone, "GEN_FIRST", start + HOUR);
        run(&mut rig, &first, "GEN_FIRST").await;
        reply(&mut rig, &first, "GEN_REPLY", &[]).unwrap();
        rig.bridge.start_view().gates = Gates::default();
        let second = phone_task(&mut rig, &phone, "GEN_SECOND", start + HOUR);
        blocked(&mut rig, &second, details::REVOCATIONS_NOT_YET_CHECKED).await;
        rig.bridge.features = HostFeatures::default();
        let v1 = phone_task(&mut rig, &phone, "GEN_V1", start + HOUR);
        rig.bridge.features = HostFeatures::parse("host.delegated").unwrap();
        assert_eq!(stored_record(&rig, &v1).delegated, None);
        let effects = rig.bridge.host.fence_principal(PHONE, 0);
        rig.bridge.exec(
            effects,
            &mut Cx {
                client: &rig.app.astation_client,
                sessions: &mut rig.sessions,
            },
        );
        rig.until(|r| stored_record(r, &v1).status.state == WorkState::Failed)
            .await;
        assert_eq!(settled(&rig, &v1).1, "sender's authority changed");
        assert_eq!(ask(&mut rig, &phone, Q::Query(&v1)), forbidden());
        passes(&mut rig, 3);
        assert_eq!(settled(&rig, &first).0, WorkState::AwaitingResult);
        assert_eq!(settled(&rig, &second).0, WorkState::Blocked);
        assert_eq!(
            status(ask(&mut rig, &phone, Q::Query(&first))).state,
            WorkState::AwaitingResult
        );
        assert_eq!(
            reply_text(ask(&mut rig, &phone, Q::Reply(&first))),
            "GEN_REPLY"
        );
        rig.bridge.start_view().gates.open_own_station(ORIGIN);
        run(&mut rig, &second, "GEN_SECOND").await;
        assert_eq!(
            status(ask(&mut rig, &phone, Q::Query(&second))).state,
            WorkState::AwaitingResult
        );
    });
}

/// VII.A test 8, design I.3.3 ("Narrowing"): a narrowing that still covers
/// the session changes nothing; one that leaves it out fails only the
/// bot's unstarted task there (`sender's authorization narrowed`, the
/// dispatch's own text). Its task awaiting a result is kept, readable by
/// the owner but no longer by the bot (outside its new grant); another
/// sender's task on the session runs.
#[test]
fn narrowing_fails_only_uncovered_unstarted_tasks() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let mut s = with_bot(&mut rig, root, &os, start + 3 * HOUR);
        let first = bot_task(&mut rig, &s, "NARROW_FIRST", start + HOUR);
        run(&mut rig, &first, "NARROW_FIRST").await;
        rig.bridge.start_view().gates = Gates::default();
        let second = bot_task(&mut rig, &s, "NARROW_SECOND", start + HOUR);
        let bot = s.bot.clone();
        let (message, message_task) = message_from(&rig, BOT, "rs", "NARROW_MESSAGE", None);
        ask_req(&mut rig, &bot, &message).unwrap();
        let phone = s.phone.clone();
        let phones = phone_task(&mut rig, &phone, "NARROW_PHONE", start + HOUR);
        blocked(&mut rig, &second, details::REVOCATIONS_NOT_YET_CHECKED).await;
        blocked(&mut rig, &phones, details::REVOCATIONS_NOT_YET_CHECKED).await;
        let sid = rig.sid.to_string();
        let scope = |sessions: &[&str]| {
            ServiceScope::new(["host"])
                .sessions(Some(sessions.iter().copied()))
                .ops(["message", "notify", "prompt"])
        };
        // Narrowed (`stop` dropped), the session still covered.
        let kept = s
            .log
            .narrow_service("svc-bot", &scope(&[sid.as_str(), OTHER_SESSION]), None);
        carry(&mut rig, &s.log, kept);
        passes(&mut rig, 5);
        assert_eq!(
            settled(&rig, &second),
            (
                WorkState::Blocked,
                details::REVOCATIONS_NOT_YET_CHECKED.into()
            )
        );
        assert_eq!(
            status(ask(&mut rig, &bot, Q::Query(&first))).state,
            WorkState::AwaitingResult
        );
        assert!(matches!(
            ask(&mut rig, &bot, Q::Message(&message)),
            Ok(ResultBody::Message { .. })
        ));
        // The session left out.
        let out = s
            .log
            .narrow_service("svc-bot", &scope(&[OTHER_SESSION]), None);
        carry(&mut rig, &s.log, out);
        rig.until(|r| settled(r, &second).0 == WorkState::Failed)
            .await;
        assert_eq!(settled(&rig, &second), outcome(Event::Narrowed));
        assert_eq!(settled(&rig, &second).1, details::AUTHORIZATION_NARROWED);
        assert_eq!(settled(&rig, &first).0, WorkState::AwaitingResult);
        assert_eq!(ask(&mut rig, &bot, Q::Query(&first)), forbidden());
        assert_eq!(settled(&rig, &message_task), outcome(Event::Narrowed));
        assert_eq!(ask(&mut rig, &bot, Q::Message(&message)), forbidden());
        let mac = s.mac.clone();
        assert_eq!(
            status(ask(&mut rig, &mac, Q::Query(&first))).state,
            WorkState::AwaitingResult
        );
        assert!(matches!(
            ask(&mut rig, &mac, Q::Message(&message)),
            Ok(ResultBody::Message { .. })
        ));
        // A message's tasks decide all or nothing: one on a session the
        // grant still covers and one off it, and the message isn't the
        // bot's to read.
        let mut covered = stored_record(&rig, &message_task);
        covered.task.target.session_id = OTHER_SESSION.into();
        let left_out = stored_record(&rig, &message_task);
        let as_bot = Sender::Remote(Box::new(bot.clone()));
        assert_eq!(
            rig.bridge
                .delegated_message_caller(&as_bot, std::slice::from_ref(&covered)),
            Ok(Caller::Sender)
        );
        assert_eq!(
            rig.bridge
                .delegated_message_caller(&as_bot, &[covered, left_out]),
            Err(crate::runtime::delegated::authority::Refused::NotCovered)
        );
        assert_eq!(settled(&rig, &phones).0, WorkState::Blocked);
        rig.bridge.start_view().gates.open_own_station(ORIGIN);
        run(&mut rig, &phones, "NARROW_PHONE").await;
        assert!(!input(&rig).contains("NARROW_SECOND"));
        assert!(attempts(&rig, &second).is_empty());
    });
}

/// VII.A test 8 ("A widening or a pure renewal changes nothing"), design
/// I.3.3: a widening and then a renewal of the bot's grant (each moving its
/// control generation) fail none of its tasks and hide none: the one
/// awaiting its result stays readable, the waiting one runs.
#[test]
fn widening_and_renewal_change_nothing() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let mut s = with_bot(&mut rig, root, &os, start + 3 * HOUR);
        let first = bot_task(&mut rig, &s, "WIDEN_FIRST", start + HOUR);
        run(&mut rig, &first, "WIDEN_FIRST").await;
        rig.bridge.start_view().gates = Gates::default();
        let second = bot_task(&mut rig, &s, "WIDEN_SECOND", start + HOUR);
        blocked(&mut rig, &second, details::REVOCATIONS_NOT_YET_CHECKED).await;
        let bot = s.bot.clone();
        let fenced_at = rig.bridge.host.control_gen(BOT);
        let wider = ServiceScope::new(["host"])
            .sessions(Some([rig.sid.as_str(), OTHER_SESSION]))
            .ops(["interrupt", "message", "notify", "prompt", "stop"]);
        let widening = s.log.set_service("svc-bot", &wider, start + 3 * HOUR);
        carry(&mut rig, &s.log, widening);
        let renewal = s.log.renew_service("svc-bot", start + 5 * HOUR);
        carry(&mut rig, &s.log, renewal);
        assert!(
            rig.bridge.host.control_gen(BOT) > fenced_at,
            "each one fenced"
        );
        passes(&mut rig, 5);
        assert_eq!(
            settled(&rig, &second),
            (
                WorkState::Blocked,
                details::REVOCATIONS_NOT_YET_CHECKED.into()
            )
        );
        assert_eq!(
            status(ask(&mut rig, &bot, Q::Query(&first))).state,
            WorkState::AwaitingResult
        );
        rig.bridge.start_view().gates.open_own_station(ORIGIN);
        run(&mut rig, &second, "WIDEN_SECOND").await;
        assert_eq!(
            status(ask(&mut rig, &bot, Q::Query(&second))).state,
            WorkState::AwaitingResult
        );
    });
}

/// VII.A test 8 ("A route change fails unstarted tasks and keeps awaiting
/// ones"), design I.3.3, I.4.5: a new revision of the phone's route fails
/// its unstarted task (`route changed`, the dispatch's own text) and keeps
/// the one awaiting its result and the one of unknown outcome, which the
/// phone still reads (a route change hides nothing from its sender), with
/// the reply, and completes.
#[test]
fn route_change_fails_unstarted_keeps_awaiting_and_unknown() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let (phone, _) = delegated(&mut rig, root, &os, true);
        let first = phone_task(&mut rig, &phone, "ROUTE_FIRST", start + HOUR);
        run(&mut rig, &first, "ROUTE_FIRST").await;
        reply(&mut rig, &first, "ROUTE_REPLY", &[]).unwrap();
        rig.bridge.start_view().gates = Gates::default();
        // Of unknown outcome (its agent exited mid-turn, say).
        let unknown = phone_task(&mut rig, &phone, "ROUTE_UNKNOWN", start + HOUR);
        let mut record = stored_record(&rig, &unknown);
        record.status.state = WorkState::OutcomeUnknown;
        record.status.detail = "agent exited".into();
        rig.bridge
            .work
            .store
            .as_ref()
            .unwrap()
            .save_work(&record)
            .unwrap();
        let second = phone_task(&mut rig, &phone, "ROUTE_SECOND", start + HOUR);
        blocked(&mut rig, &second, details::REVOCATIONS_NOT_YET_CHECKED).await;
        // The owner approves a new revision of the route.
        let route = rig
            .bridge
            .work
            .config
            .routes
            .iter_mut()
            .find(|r| r.id == "rm")
            .unwrap();
        route.revision = 2;
        rig.until(|r| settled(r, &second).0 == WorkState::Failed)
            .await;
        assert_eq!(settled(&rig, &second), outcome(Event::RouteChanged));
        assert_eq!(settled(&rig, &second).1, details::ROUTE_CHANGED);
        passes(&mut rig, 3);
        assert_eq!(settled(&rig, &first).0, WorkState::AwaitingResult);
        assert_eq!(
            settled(&rig, &unknown),
            (WorkState::OutcomeUnknown, "agent exited".into())
        );
        assert_eq!(
            status(ask(&mut rig, &phone, Q::Query(&unknown))).state,
            WorkState::OutcomeUnknown
        );
        assert_eq!(
            reply_text(ask(&mut rig, &phone, Q::Reply(&first))),
            "ROUTE_REPLY"
        );
        assert_eq!(
            status(ask(&mut rig, &phone, Q::Complete(&first, "done"))).state,
            WorkState::Completed
        );
        assert!(!input(&rig).contains("ROUTE_SECOND"));
    });
}

/// Design I.3.3 ("R9 removal of the sender"), I.5.5, VII.A test 6: the
/// phone removed from the device list, its unstarted tasks are cancelled,
/// `sender revoked` (the dispatch's own text): a queued one, and one whose
/// attempt waits `accepted` behind the running turn, which is withdrawn in
/// the session host first (`withdrawn by the host`), never written. The
/// running turn goes on, and its task awaits its result. The removed phone
/// reads nothing; the owner (the Mac) reads its tasks.
#[test]
fn removal_cancels_unstarted_sender_revoked() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let mut s = with_bot(&mut rig, root, &os, start + 3 * HOUR);
        let phone = s.phone.clone();
        let running = phone_task(&mut rig, &phone, "REMOVAL_RUNNING", start + HOUR);
        rig.until(|r| input(r).contains("REMOVAL_RUNNING")).await;
        let waiting = phone_task(&mut rig, &phone, "REMOVAL_WAITING", start + HOUR);
        blocked(
            &mut rig,
            &waiting,
            "waiting for an earlier task on this session",
        )
        .await;
        let attempt = attempt_behind_the_turn(&mut rig, &waiting, "REMOVAL_WAITING");
        let queued = phone_task(&mut rig, &phone, "REMOVAL_QUEUED", start + HOUR);
        blocked(
            &mut rig,
            &queued,
            "waiting for an earlier task on this session",
        )
        .await;
        let removal = s.log.remove("dev-phone");
        carry(&mut rig, &s.log, removal);
        // While the turn still runs.
        rig.until(|r| {
            settled(r, &waiting).0 == WorkState::Cancelled
                && settled(r, &queued).0 == WorkState::Cancelled
        })
        .await;
        assert_eq!(settled(&rig, &running).0, WorkState::Submitted);
        for task in [&waiting, &queued] {
            assert_eq!(settled(&rig, task), outcome(Event::Removed));
            assert_eq!(settled(&rig, task).1, details::SENDER_REVOKED);
        }
        let receipt = rig.bridge.host.attempt_receipt(&attempt, &waiting).unwrap();
        assert_eq!(
            (receipt.state, receipt.detail.as_deref()),
            (
                wire::ReceiptState::Rejected,
                Some(details::WITHDRAWN_BY_THE_HOST)
            )
        );
        assert_eq!(
            attempts(&rig, &waiting),
            [(attempt.clone(), Some("withdrawn".into()), true)]
        );
        assert!(!rig.bridge.start_view().is_live(&attempt));
        complete(&mut rig, &running).await;
        passes(&mut rig, 5);
        assert_eq!(settled(&rig, &running).0, WorkState::AwaitingResult);
        let text = input(&rig);
        assert!(!text.contains("REMOVAL_WAITING") && !text.contains("REMOVAL_QUEUED"));
        assert_eq!(ask(&mut rig, &phone, Q::Query(&running)), forbidden());
        let mac = s.mac.clone();
        for (task, state) in [
            (&running, WorkState::AwaitingResult),
            (&waiting, WorkState::Cancelled),
        ] {
            assert_eq!(status(ask(&mut rig, &mac, Q::Query(task))).state, state);
        }
    });
}

/// VII.A test 6 ("The same holds for … a narrowing and a route change
/// while an attempt waits `accepted`"), design I.5.5: with the bot's turn
/// running, an attempt of the phone's and one of the bot's wait `accepted`
/// behind it. The phone's route changes and the bot's grant is narrowed
/// off the session: each attempt is withdrawn (`withdrawn by the host`) and
/// its task fails with the dispatch's own detail, while the turn runs; the
/// running task goes on and awaits its result.
#[test]
fn attempts_waiting_accepted_settle_from_their_withdrawal() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let mut s = with_bot(&mut rig, root, &os, start + 3 * HOUR);
        let running = bot_task(&mut rig, &s, "WAITING_RUNNING", start + HOUR);
        rig.until(|r| input(r).contains("WAITING_RUNNING")).await;
        let phone = s.phone.clone();
        let routed = phone_task(&mut rig, &phone, "WAITING_ROUTED", start + HOUR);
        let narrowed = bot_task(&mut rig, &s, "WAITING_NARROWED", start + HOUR);
        for task in [&routed, &narrowed] {
            blocked(
                &mut rig,
                task,
                "waiting for an earlier task on this session",
            )
            .await;
        }
        let routed_attempt = attempt_behind_the_turn(&mut rig, &routed, "WAITING_ROUTED");
        let narrowed_attempt = attempt_behind_the_turn(&mut rig, &narrowed, "WAITING_NARROWED");
        passes(&mut rig, 3);
        assert_eq!(settled(&rig, &routed).0, WorkState::Submitted, "still live");
        rig.bridge
            .work
            .config
            .routes
            .iter_mut()
            .find(|r| r.id == "rm")
            .unwrap()
            .revision = 2;
        let out = s.log.narrow_service(
            "svc-bot",
            &ServiceScope::new(["host"])
                .sessions(Some([OTHER_SESSION]))
                .ops(["message", "notify", "prompt"]),
            None,
        );
        carry(&mut rig, &s.log, out);
        rig.until(|r| {
            settled(r, &routed).0 == WorkState::Failed
                && settled(r, &narrowed).0 == WorkState::Failed
        })
        .await;
        assert_eq!(settled(&rig, &running).0, WorkState::Submitted);
        assert_eq!(settled(&rig, &routed), outcome(Event::RouteChanged));
        assert_eq!(settled(&rig, &narrowed), outcome(Event::Narrowed));
        for (task, attempt) in [(&routed, &routed_attempt), (&narrowed, &narrowed_attempt)] {
            let receipt = rig.bridge.host.attempt_receipt(attempt, task).unwrap();
            assert_eq!(
                (receipt.state, receipt.detail.as_deref()),
                (
                    wire::ReceiptState::Rejected,
                    Some(details::WITHDRAWN_BY_THE_HOST)
                )
            );
            assert_eq!(
                attempts(&rig, task),
                [(attempt.clone(), Some("withdrawn".into()), true)]
            );
        }
        complete(&mut rig, &running).await;
        passes(&mut rig, 5);
        assert_eq!(settled(&rig, &running).0, WorkState::AwaitingResult);
        let text = input(&rig);
        assert!(!text.contains("WAITING_ROUTED") && !text.contains("WAITING_NARROWED"));
    });
}

/// Step 4's Decision 15, design I.4.5 ("The owner"): a native member
/// holding `control` at the head reads any delegated task, another
/// sender's included, and its reply, but neither cancels nor completes it;
/// it reads no v1 task, whose rule is v1's. A native without `control`
/// reads nothing of another sender's.
#[test]
fn owner_reads_any_delegated_task_not_v1_ones() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = with_bot(&mut rig, root, &os, start + 3 * HOUR);
        let task = bot_task(&mut rig, &s, "OWNER_DELEGATED", start + HOUR);
        run(&mut rig, &task, "OWNER_DELEGATED").await;
        reply(&mut rig, &task, "OWNER_REPLY", &[]).unwrap();
        let (bot, phone, mac, viewer) = (
            s.bot.clone(),
            s.phone.clone(),
            s.mac.clone(),
            s.viewer.clone(),
        );
        // The bot's message, delegated too.
        let (message, _) = message_from(&rig, BOT, "rs", "OWNER_MESSAGE", None);
        ask_req(&mut rig, &bot, &message).unwrap();
        // The bot's v1 task and message (the hook off): no admission.
        rig.bridge.features = HostFeatures::default();
        let mut req = phone_enqueue(&rig, "OWNER_V1");
        if let hw::Request::Enqueue { route_id, .. } = &mut req {
            *route_id = "rs".into();
        }
        ask_req(&mut rig, &bot, &req).unwrap();
        let (v1_message, v1_message_task) = message_from(&rig, BOT, "rs", "OWNER_V1_MESSAGE", None);
        ask_req(&mut rig, &bot, &v1_message).unwrap();
        rig.bridge.features = HostFeatures::parse("host.delegated").unwrap();
        let v1 = enqueued(&req);
        assert_eq!(stored_record(&rig, &v1).delegated, None);
        assert_eq!(stored_record(&rig, &v1_message_task).delegated, None);
        for owner in [&phone, &mac] {
            assert!(matches!(
                ask(&mut rig, owner, Q::Message(&message)),
                Ok(ResultBody::Message { .. })
            ));
            assert_eq!(ask(&mut rig, owner, Q::Message(&v1_message)), forbidden());
            assert_eq!(
                status(ask(&mut rig, owner, Q::Query(&task))).state,
                WorkState::AwaitingResult
            );
            assert_eq!(
                reply_text(ask(&mut rig, owner, Q::Reply(&task))),
                "OWNER_REPLY"
            );
            assert_eq!(ask(&mut rig, owner, Q::Cancel(&task)), forbidden());
            assert_eq!(ask(&mut rig, owner, Q::Complete(&task, "x")), forbidden());
            assert_eq!(ask(&mut rig, owner, Q::Query(&v1)), forbidden());
            assert_eq!(ask(&mut rig, owner, Q::Reply(&v1)), forbidden());
        }
        assert_eq!(ask(&mut rig, &viewer, Q::Query(&task)), forbidden());
        // Its sender reads them all, as before.
        assert_eq!(status(ask(&mut rig, &bot, Q::Query(&v1))).task_id, v1);
        for m in [&message, &v1_message] {
            assert!(matches!(
                ask(&mut rig, &bot, Q::Message(m)),
                Ok(ResultBody::Message { .. })
            ));
        }
        assert_eq!(
            status(ask(&mut rig, &bot, Q::Complete(&task, "done"))).state,
            WorkState::Completed
        );
    });
}

/// Design I.3.3 ("Revocation"): once a `revoke` record applies to the bot
/// (as the feeds will apply one), its waiting task is cancelled (`sender
/// revoked`) and the one awaiting its result is kept; neither it nor its
/// reply is readable by the bot any more, and both are by the owner.
#[test]
fn revoked_senders_reply_readable_by_the_owner_not_the_sender() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = with_bot(&mut rig, root, &os, start + 3 * HOUR);
        let first = bot_task(&mut rig, &s, "REVOKED_FIRST", start + HOUR);
        run(&mut rig, &first, "REVOKED_FIRST").await;
        reply(&mut rig, &first, "REVOKED_REPLY", &[]).unwrap();
        rig.bridge.start_view().gates = Gates::default();
        let second = bot_task(&mut rig, &s, "REVOKED_SECOND", start + HOUR);
        blocked(&mut rig, &second, details::REVOCATIONS_NOT_YET_CHECKED).await;
        rig.bridge
            .start_view()
            .standings
            .get_mut(BOT)
            .unwrap()
            .revoked = Some("rec-1".into());
        rig.until(|r| settled(r, &second).0 == WorkState::Cancelled)
            .await;
        assert_eq!(settled(&rig, &second), outcome(Event::Revoked));
        assert_eq!(settled(&rig, &first).0, WorkState::AwaitingResult);
        let (bot, phone) = (s.bot.clone(), s.phone.clone());
        for q in [
            Q::Query(&first),
            Q::Reply(&first),
            Q::Complete(&first, "x"),
            Q::Query(&second),
        ] {
            assert_eq!(ask(&mut rig, &bot, q), forbidden());
        }
        assert_eq!(
            reply_text(ask(&mut rig, &phone, Q::Reply(&first))),
            "REVOKED_REPLY"
        );
        assert_eq!(
            status(ask(&mut rig, &phone, Q::Query(&second))).detail,
            details::SENDER_REVOKED
        );
    });
}

/// The phone's `message_publish` with an agent recipient on this host, its
/// text `text` (and `mark` when given): its request and the recipient's
/// task id.
fn phone_message(
    rig: &LocalRig,
    text: &str,
    mark: Option<atem_client::session::mark::MarkTask>,
) -> (hw::Request, String) {
    message_from(rig, PHONE, "rm", text, mark)
}

/// `sender`'s `message_publish` with an agent recipient on this host
/// through `route`, its text `text` (and `mark` when given): its request and
/// the recipient's task id.
fn message_from(
    rig: &LocalRig,
    sender: &str,
    route: &str,
    text: &str,
    mark: Option<atem_client::session::mark::MarkTask>,
) -> (hw::Request, String) {
    let mut message = rig.message();
    message.sender = sender.into();
    message.from_session = None;
    message.text = text.into();
    message.mark = mark;
    if let Destination::Agent { route_id, .. } = &mut message.recipients[0].destination {
        *route_id = route.into();
    }
    let task = message.recipients[0].recipient_id.clone();
    let req = hw::Request::Publish {
        v: 1,
        id: uuid::Uuid::new_v4().to_string(),
        host: rig.bridge.work_host(),
        message,
    };
    (req, task)
}

/// Step 4's Decision 13: a delegated sender's `message_publish` tasks (a
/// mark task's too) are delegated, classified when the message is
/// accepted: they get an admission record, wait behind the sender's earlier
/// task (one sender's tasks keep their order) without holding the session,
/// and run under `host-work` with no channel of the phone's. Their message
/// stays readable with `message_query` under the same caller rule (a route
/// change hides nothing), unlike a v1 message (the hook off), whose tasks
/// have no admission.
#[test]
fn message_tasks_of_delegated_senders_are_delegated() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let (phone, _) = delegated(&mut rig, root, &os, false);
        let earlier = phone_task(&mut rig, &phone, "MESSAGE_EARLIER", start + HOUR);
        blocked(&mut rig, &earlier, details::REVOCATIONS_NOT_YET_CHECKED).await;
        let (mut publish, task) = phone_message(&rig, "MESSAGE_TASK", None);
        // A notice to the route's project too (a stored recipient).
        if let hw::Request::Publish { message, .. } = &mut publish {
            message.recipients.push(Recipient {
                recipient_id: uuid::Uuid::new_v4().to_string(),
                host: rig.bridge.work_host(),
                destination: Destination::Project {
                    route_id: "rm".into(),
                    route_revision: 1,
                },
            });
        }
        let Ok(ResultBody::Message { message: receipt }) = as_phone(&mut rig, &phone, &publish)
        else {
            panic!("a message result");
        };
        assert!(matches!(receipt.recipients[1].delivery, Delivery::Stored));
        let admission = stored_record(&rig, &task)
            .delegated
            .expect("a delegated sender's message task");
        assert_eq!(admission.principal, PHONE);
        assert_eq!(
            (admission.route_id.as_str(), admission.route_revision),
            ("rm", 1)
        );
        blocked(&mut rig, &task, details::REVOCATIONS_NOT_YET_CHECKED).await;
        local_task_runs(&mut rig, "LOCAL_PAST_THE_MESSAGE").await;
        // A mark task, the same way.
        let mark = atem_client::session::mark::MarkTask {
            mark_id: "mark_1".into(),
            url: "http://localhost:3000/".into(),
            title: "Page".into(),
            screenshot: atem_client::session::attachments::Attachment {
                attachment_id: uuid::Uuid::new_v4().to_string(),
                digest: hw::digest(b"png"),
                size: 68,
                media_type: "image/png".into(),
            },
            annotations: vec![],
        };
        let (marked, mark_task) = phone_message(&rig, "", Some(mark));
        as_phone(&mut rig, &phone, &marked).unwrap();
        assert!(stored_record(&rig, &mark_task).delegated.is_some());
        let mut record = stored_record(&rig, &mark_task);
        record.status.state = WorkState::Cancelled;
        rig.bridge
            .work
            .store
            .as_ref()
            .unwrap()
            .save_work(&record)
            .unwrap();
        // The hook off: v1.
        rig.bridge.features = HostFeatures::default();
        let (v1_publish, v1_task) = phone_message(&rig, "MESSAGE_V1", None);
        as_phone(&mut rig, &phone, &v1_publish).unwrap();
        rig.bridge.features = HostFeatures::parse("host.delegated").unwrap();
        assert_eq!(stored_record(&rig, &v1_task).delegated, None);
        let mut record = stored_record(&rig, &v1_task);
        record.status.state = WorkState::Cancelled;
        rig.bridge
            .work
            .store
            .as_ref()
            .unwrap()
            .save_work(&record)
            .unwrap();
        // The gate opens: the earlier task, then the message's.
        rig.bridge.start_view().gates.open_own_station(ORIGIN);
        rig.until(|r| input(r).contains("MESSAGE_EARLIER")).await;
        assert!(!input(&rig).contains("MESSAGE_TASK"));
        complete(&mut rig, &earlier).await;
        run(&mut rig, &task, "MESSAGE_TASK").await;
        let text = input(&rig);
        assert!(text.find("MESSAGE_EARLIER") < text.find("MESSAGE_TASK"));
        let attempt = stored_record(&rig, &task).status.receipt_id;
        let receipt = rig.bridge.host.attempt_receipt(&attempt, &task).unwrap();
        assert_eq!(receipt.sender.as_deref(), Some(PHONE));
        // A route change hides the v1 message from its sender, not the
        // delegated one (its notice included: judged by its tasks' rule).
        rig.bridge
            .work
            .config
            .routes
            .iter_mut()
            .find(|r| r.id == "rm")
            .unwrap()
            .revision = 2;
        assert!(matches!(
            ask(&mut rig, &phone, Q::Message(&publish)),
            Ok(ResultBody::Message { .. })
        ));
        assert_eq!(ask(&mut rig, &phone, Q::Message(&v1_publish)), forbidden());
    });
}

/// Design I.4.5, I.5.5 ("A task with a live attempt"), task 19's review:
/// the phone cancels a task whose attempt waits `accepted` behind the
/// running turn: the attempt is withdrawn in the session host first
/// (`withdrawn by the host`) and forgotten by the start check, the task is
/// `cancelled`, and its prompt is never written. A cancel of the running
/// task is `busy`, and it goes on; a repeated cancel returns the status.
#[test]
fn a_cancel_withdraws_a_live_attempt_first() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let (phone, _) = delegated(&mut rig, root, &os, true);
        let running = phone_task(&mut rig, &phone, "CANCEL_RUNNING", start + HOUR);
        rig.until(|r| input(r).contains("CANCEL_RUNNING")).await;
        let waiting = phone_task(&mut rig, &phone, "CANCEL_WAITING", start + HOUR);
        blocked(
            &mut rig,
            &waiting,
            "waiting for an earlier task on this session",
        )
        .await;
        let attempt = attempt_behind_the_turn(&mut rig, &waiting, "CANCEL_WAITING");
        assert_eq!(ask(&mut rig, &phone, Q::Cancel(&running)), busy());
        let cancelled = status(ask(&mut rig, &phone, Q::Cancel(&waiting)));
        assert_eq!(cancelled.state, WorkState::Cancelled);
        assert_eq!(cancelled.detail, "cancelled before submission");
        let receipt = rig.bridge.host.attempt_receipt(&attempt, &waiting).unwrap();
        assert_eq!(
            (receipt.state, receipt.detail.as_deref()),
            (
                wire::ReceiptState::Rejected,
                Some(details::WITHDRAWN_BY_THE_HOST)
            )
        );
        assert_eq!(
            attempts(&rig, &waiting),
            [(attempt.clone(), Some("withdrawn".into()), true)]
        );
        assert!(!rig.bridge.start_view().is_live(&attempt));
        assert_eq!(
            status(ask(&mut rig, &phone, Q::Cancel(&waiting))),
            cancelled
        );
        complete(&mut rig, &running).await;
        passes(&mut rig, 5);
        assert!(!input(&rig).contains("CANCEL_WAITING"));
        assert_eq!(settled(&rig, &waiting).0, WorkState::Cancelled);
    });
}

/// Design I.4.5, I.5.6: with the session journal halted the withdrawal
/// can't be confirmed, so a cancel of a task whose attempt waits `accepted`
/// is `busy` and changes nothing: never a cancelled task with a live
/// attempt.
#[test]
fn a_cancel_that_cant_withdraw_leaves_the_task_and_its_attempt() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let (phone, _) = delegated(&mut rig, root, &os, true);
        phone_task(&mut rig, &phone, "HALT_RUNNING", start + HOUR);
        rig.until(|r| input(r).contains("HALT_RUNNING")).await;
        let waiting = phone_task(&mut rig, &phone, "HALT_WAITING", start + HOUR);
        blocked(
            &mut rig,
            &waiting,
            "waiting for an earlier task on this session",
        )
        .await;
        let attempt = attempt_behind_the_turn(&mut rig, &waiting, "HALT_WAITING");
        rig.bridge.host.journal_mut().fail_append_of(1, false);
        let effects = rig.bridge.host.fence_principal("service:other", 0);
        rig.bridge.exec(
            effects,
            &mut Cx {
                client: &rig.app.astation_client,
                sessions: &mut rig.sessions,
            },
        );
        assert!(rig.bridge.host.journal_halted());
        let before = settled(&rig, &waiting);
        assert_eq!(ask(&mut rig, &phone, Q::Cancel(&waiting)), busy());
        assert_eq!(settled(&rig, &waiting), before);
        assert_ne!(before.0, WorkState::Cancelled);
        assert_eq!(attempts(&rig, &waiting), [(attempt.clone(), None, true)]);
        assert_eq!(
            rig.bridge
                .host
                .attempt_receipt(&attempt, &waiting)
                .unwrap()
                .state,
            wire::ReceiptState::Accepted
        );
    });
}

/// Task 19's review ("Guard `end_attempt`"): an attempt ending after its
/// task settled (a cancel, an event) ends, and the task keeps its stored
/// terminal state.
#[test]
fn end_attempt_keeps_a_terminal_stored_state() {
    use crate::runtime::delegated::attempts::AttemptEnd;
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let (phone, _) = delegated(&mut rig, root, &os, false);
        let task = enqueue(&mut rig, &phone, "GUARDED_PROMPT");
        let a = {
            let store = rig.bridge.work.store.as_ref().unwrap();
            let tx = store.immediate().unwrap();
            let a = store.new_attempt(&tx, &task).unwrap();
            tx.commit().unwrap();
            a
        };
        let mut record = stored_record(&rig, &task);
        record.status.state = WorkState::Cancelled;
        record.status.detail = "cancelled before submission".into();
        rig.bridge
            .work
            .store
            .as_ref()
            .unwrap()
            .save_work(&record)
            .unwrap();
        rig.bridge
            .end_attempt(
                &mut record,
                &a,
                AttemptEnd::NotAdmitted,
                (WorkState::Queued, "waiting for a ready agent"),
            )
            .unwrap();
        assert_eq!(
            settled(&rig, &task),
            (WorkState::Cancelled, "cancelled before submission".into())
        );
        assert_eq!(record.status.state, WorkState::Cancelled);
        assert_eq!(
            attempts(&rig, &task),
            [(a.attempt_id.clone(), Some("not_admitted".into()), true)]
        );
    });
}

/// Task 20 review m1, design I.5.6: the withdrawal's own write fails (the
/// journal halts in it), so it can't be confirmed: the cancel is `busy`, the
/// task and its live attempt are as they were, and the request is on the
/// refusal list, so the restart rejects it.
#[test]
fn a_cancel_whose_withdrawal_halts_the_journal_is_busy() {
    use crate::session_protocol::journal::Journal as _;
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let (phone, _) = delegated(&mut rig, root, &os, true);
        phone_task(&mut rig, &phone, "WITHDRAWAL_RUNNING", start + HOUR);
        rig.until(|r| input(r).contains("WITHDRAWAL_RUNNING")).await;
        let waiting = phone_task(&mut rig, &phone, "WITHDRAWAL_WAITING", start + HOUR);
        blocked(
            &mut rig,
            &waiting,
            "waiting for an earlier task on this session",
        )
        .await;
        let attempt = attempt_behind_the_turn(&mut rig, &waiting, "WITHDRAWAL_WAITING");
        let before = settled(&rig, &waiting);
        assert!(!rig.bridge.host.journal_halted());
        // The next journal write, the withdrawal's `rejected`, fails.
        rig.bridge.host.journal_mut().fail_append_of(1, false);
        assert_eq!(ask(&mut rig, &phone, Q::Cancel(&waiting)), busy());
        assert!(rig.bridge.host.journal_halted());
        assert_eq!(settled(&rig, &waiting), before);
        assert_ne!(before.0, WorkState::Cancelled);
        assert_eq!(attempts(&rig, &waiting), [(attempt.clone(), None, true)]);
        let listed = rig.bridge.host.journal().refusals().unwrap();
        assert!(listed.iter().any(|r| r.request_id == attempt), "{listed:?}");
    });
}

// ── A `projects`-scoped bot (Task 20 review I1) ──

/// The cred agent can no longer make the bot's project hashes: they are
/// dropped and the agent is locked, so they aren't made again. This is
/// what the host has once the last service naming the kid expired (its
/// kid unused, `ProjectScopes::pass`) with the agent locked; simulated, as
/// that pass reads the real wall clock.
fn hashes_gone(rig: &mut LocalRig, agent: &TableAgent) {
    *agent.unlocked.lock().unwrap() = false;
    rig.bridge
        .projects
        .pass(&std::collections::BTreeSet::new(), Instant::now());
    passes(rig, 3);
    assert_eq!(rig.bridge.projects.matches(rig.sid.as_str(), PROJECT), None);
}

/// VII.A test 2 with a `projects`-scoped bot (Task 20 review I1, face b):
/// its grant expires with a task queued, and the hashes of its project go
/// with the agent locked. The task matched the project at admission (its
/// entry frozen there), so it runs before its deadline: never `waiting for
/// unlock`.
#[test]
fn a_projects_scoped_grant_expiring_with_a_task_queued_still_runs() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let agent = TableAgent::new(true);
        let s = with_project_bot(&mut rig, root, &os, start + HOUR, &[PROJECT], &agent).await;
        rig.bridge.start_view().gates = Gates::default();
        let task = bot_task(&mut rig, &s, "PROJECTS_EXPIRY", start + 3 * HOUR);
        assert_eq!(
            stored_record(&rig, &task)
                .delegated
                .unwrap()
                .projects_matched,
            [PROJECT]
        );
        blocked(&mut rig, &task, details::REVOCATIONS_NOT_YET_CHECKED).await;
        os.pass(HOUR + 1_000);
        hashes_gone(&mut rig, &agent);
        assert!(rig.bridge.start_view().scopes.pending.contains(KID));
        rig.bridge.start_view().gates.open_own_station(ORIGIN);
        run(&mut rig, &task, "PROJECTS_EXPIRY").await;
        assert_eq!(input(&rig).matches("PROJECTS_EXPIRY").count(), 1);
    });
}

/// Task 20 review I1, face a: the bot's task awaits its result, and its
/// session stops (its hashes leave with it). The task stays readable and
/// completable by the bot: its project matched at admission, and no
/// narrowing happened.
#[test]
fn a_projects_scoped_awaiting_task_stays_readable_after_its_session_stops() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let agent = TableAgent::new(true);
        let s = with_project_bot(&mut rig, root, &os, start + 3 * HOUR, &[PROJECT], &agent).await;
        let task = bot_task(&mut rig, &s, "PROJECTS_STOPPED", start + HOUR);
        run(&mut rig, &task, "PROJECTS_STOPPED").await;
        reply(&mut rig, &task, "PROJECTS_REPLY", &[]).unwrap();
        // The session stops.
        let session = rig.sessions.remove(&rig.sid).unwrap();
        let _ = session.stop();
        passes(&mut rig, 3);
        assert_eq!(rig.bridge.projects.matches(rig.sid.as_str(), PROJECT), None);
        let bot = s.bot.clone();
        assert_eq!(
            status(ask(&mut rig, &bot, Q::Query(&task))).state,
            WorkState::AwaitingResult
        );
        assert_eq!(
            reply_text(ask(&mut rig, &bot, Q::Reply(&task))),
            "PROJECTS_REPLY"
        );
        assert_eq!(
            status(ask(&mut rig, &bot, Q::Complete(&task, "done"))).state,
            WorkState::Completed
        );
    });
}

/// VII.A test 2 with a `projects`-scoped bot, the agent locked (Task 20
/// review I1, question 6): after the expiry the bot reads nothing; a
/// renewal (the same entries, a later expiry) makes its task and reply
/// readable at once, though no hash can be made.
#[test]
fn a_projects_scoped_renewal_while_the_agent_is_locked_restores_reads() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let agent = TableAgent::new(true);
        let mut s = with_project_bot(&mut rig, root, &os, start + HOUR, &[PROJECT], &agent).await;
        let task = bot_task(&mut rig, &s, "PROJECTS_RENEWED", start + 3 * HOUR);
        run(&mut rig, &task, "PROJECTS_RENEWED").await;
        reply(&mut rig, &task, "PROJECTS_RENEWED_REPLY", &[]).unwrap();
        os.pass(HOUR + 1_000);
        hashes_gone(&mut rig, &agent);
        let bot = s.bot.clone();
        assert_eq!(ask(&mut rig, &bot, Q::Query(&task)), forbidden());
        let renewal = s.log.renew_service("svc-bot", start + 4 * HOUR);
        carry(&mut rig, &s.log, renewal);
        passes(&mut rig, 3);
        assert_eq!(rig.bridge.projects.matches(rig.sid.as_str(), PROJECT), None);
        assert_eq!(
            status(ask(&mut rig, &bot, Q::Query(&task))).state,
            WorkState::AwaitingResult
        );
        assert_eq!(
            reply_text(ask(&mut rig, &bot, Q::Reply(&task))),
            "PROJECTS_RENEWED_REPLY"
        );
        assert_eq!(
            status(ask(&mut rig, &bot, Q::Complete(&task, "done"))).state,
            WorkState::Completed
        );
    });
}

/// Design I.3.3 ("Narrowing") with a `projects`-scoped bot: a narrowing
/// that drops the task's project (another entry under the same kid stays)
/// is no longer the bot's grant covering it: its task awaiting a result is
/// `forbidden` to it, the owner reads it, and its unstarted task fails
/// `sender's authorization narrowed`. The frozen entry never covers more
/// than the grant does.
#[test]
fn a_narrowing_that_drops_the_project_is_forbidden() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let agent = TableAgent::new(true);
        let mut s = with_project_bot(
            &mut rig,
            root,
            &os,
            start + 3 * HOUR,
            &[PROJECT, OTHER_PROJECT],
            &agent,
        )
        .await;
        let first = bot_task(&mut rig, &s, "PROJECTS_FIRST", start + HOUR);
        run(&mut rig, &first, "PROJECTS_FIRST").await;
        rig.bridge.start_view().gates = Gates::default();
        let second = bot_task(&mut rig, &s, "PROJECTS_SECOND", start + HOUR);
        blocked(&mut rig, &second, details::REVOCATIONS_NOT_YET_CHECKED).await;
        let out = s.log.narrow_service(
            "svc-bot",
            &ServiceScope::new(["host"])
                .projects(Some([OTHER_PROJECT]))
                .ops(["message", "notify", "prompt", "stop"]),
            None,
        );
        carry(&mut rig, &s.log, out);
        rig.until(|r| settled(r, &second).0 == WorkState::Failed)
            .await;
        assert_eq!(settled(&rig, &second), outcome(Event::Narrowed));
        assert_eq!(settled(&rig, &first).0, WorkState::AwaitingResult);
        let (bot, mac) = (s.bot.clone(), s.mac.clone());
        for q in [Q::Query(&first), Q::Reply(&first), Q::Complete(&first, "x")] {
            assert_eq!(ask(&mut rig, &bot, q), forbidden());
        }
        assert_eq!(
            status(ask(&mut rig, &mac, Q::Query(&first))).state,
            WorkState::AwaitingResult
        );
    });
}

/// The feed the control feeds' tests sign records in: the host's own
/// Station's.
const FEED_ID: &str = "22222222-2222-4222-8222-222222222222";

/// The bot's records with `actions`, signed with its key as its Station
/// issues them, applied by a feed store over the rig's store (as a sync
/// applies them) in one transaction, at positions 1, 2, …, and committed.
/// The bridge's own feed store doesn't see them until it loads again.
fn commit_bot_records(
    rig: &LocalRig,
    log: &TestLog,
    actions: &[atem_client::control::ControlAction],
) {
    use crate::runtime::delegated::feeds::{FeedStore, signed_record};
    let store = rig.bridge.work.store.as_ref().unwrap();
    let mut feeds = FeedStore::load(store, &log.log).unwrap();
    feeds.set_own_origin(Some(ORIGIN.into()));
    let list = rig.bridge.membership.as_ref().unwrap().list_state();
    let tx = feeds.begin(store).unwrap();
    for (i, action) in actions.iter().enumerate() {
        let rec = signed_record(
            log,
            "svc-bot",
            "svc-bot",
            *action,
            uuid::Uuid::new_v4().to_string(),
            (ORIGIN, FEED_ID),
            host_now().wall_ms + i as u64,
        );
        let pos = feeds.position(FEED_ID, i as u64 + 1).unwrap();
        feeds.apply(&tx, &rec, &list, pos, 0).unwrap();
    }
    feeds.commit(tx).unwrap();
}

/// Decisions 13 and 16 with the control feeds (PR 10): the bridge's feed
/// store loads with the device list; a service is delegated once a cover
/// record covers it (`sender_class` reads the feeds, not `NoFeeds`); and
/// what a record commits is in the start view at its commit, with no pass
/// of host-work's in between (a pause included).
#[test]
fn the_feeds_cover_a_service_and_reach_the_start_view_at_commit() {
    use crate::runtime::delegated::feeds::{Feeds, signed_record};
    use atem_client::control::ControlAction;
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = with_bot(&mut rig, root, &os, start + 3 * HOUR);
        // The feeds, not the tests' stand-in.
        rig.bridge.work.controls = None;
        rig.bridge.start_view().standings.clear();
        passes(&mut rig, 1);
        assert!(matches!(rig.bridge.work.feeds, Feeds::Loaded(_)));
        assert_eq!(rig.bridge.sender_class(BOT), SenderClass::V1, "not covered");
        let list = rig.bridge.membership.as_ref().unwrap().list_state();
        let apply = |rig: &mut LocalRig, action: ControlAction, seq: u64| {
            let rec = signed_record(
                &s.log,
                "svc-bot",
                "svc-bot",
                action,
                uuid::Uuid::new_v4().to_string(),
                (ORIGIN, FEED_ID),
                start + seq,
            );
            let State { feeds, store, .. } = &mut rig.bridge.work;
            let (Feeds::Loaded(feeds), Some(store)) = (feeds, store.as_ref()) else {
                panic!("the feeds loaded");
            };
            feeds.set_own_origin(Some(ORIGIN.into()));
            let tx = feeds.begin(store).unwrap();
            let pos = feeds.position(FEED_ID, seq).unwrap();
            feeds.apply(&tx, &rec, &list, pos, 0).unwrap();
            feeds.commit(tx).unwrap();
        };
        apply(&mut rig, ControlAction::Cover, 1);
        let feed = FeedRef {
            origin: ORIGIN.into(),
            feed_id: FEED_ID.into(),
        };
        assert_eq!(
            rig.bridge.start_view().standings[BOT].coverage,
            Some(feed.clone()),
            "at the commit"
        );
        assert_eq!(
            rig.bridge.sender_class(BOT),
            SenderClass::Delegated(crate::runtime::delegated::DelegatedSender::Service {
                device_id: "svc-bot".into(),
                feed,
            })
        );
        let task = bot_task(&mut rig, &s, "COVERED_BY_A_RECORD", start + HOUR);
        run(&mut rig, &task, "COVERED_BY_A_RECORD").await;
        apply(&mut rig, ControlAction::Hold, 2);
        assert!(rig.bridge.start_view().standings[BOT].held);

        // A store whose state doesn't read, loaded as after a new identity
        // (Task 32 review m5, I1): the standings shown so far go, the bot
        // is unchecked (never v1), and nothing delegated starts.
        rig.bridge
            .work
            .store
            .as_ref()
            .unwrap()
            .db
            .execute(
                "INSERT INTO control_principals(principal,part) VALUES('service:svc-x','{damaged')",
                [],
            )
            .unwrap();
        rig.bridge.work.feeds = Feeds::Unloaded;
        rig.bridge.ensure_feeds();
        assert!(matches!(rig.bridge.work.feeds, Feeds::Damaged));
        assert!(rig.bridge.start_view().standings.is_empty());
        assert!(rig.bridge.start_view().controls_damaged);
        assert_eq!(rig.bridge.sender_class(BOT), SenderClass::Unchecked);
        assert!(matches!(
            rig.bridge.sender_class(PHONE),
            SenderClass::Delegated(crate::runtime::delegated::DelegatedSender::Native { .. })
        ));
    });
}

/// Task 32 review m1 (ruling T20c): a task whose launch project was never
/// hashed in this run (its record closed before a restart: only open
/// records are registered at the start) is registered when its sender asks
/// about it; while that hash isn't made the sender gets `busy`, never a
/// `forbidden` that would stand, and then reads it.
#[test]
fn a_task_whose_project_isnt_hashed_yet_is_busy_until_it_is() {
    const NEW_KID: &str = "0e0f0a0c";
    const NEW_PROJECT: &str =
        "h1.0e0f0a0c.4444444444444444444444444444444444444444444444444444444444444444";
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let agent = TableAgent::new(true);
        let mut s =
            with_project_bot(&mut rig, root, &os, start + 3 * HOUR, &[PROJECT], &agent).await;
        let task = bot_task(&mut rig, &s, "PROJECTS_NOT_HASHED", start + HOUR);
        run(&mut rig, &task, "PROJECTS_NOT_HASHED").await;
        // As a restart finds it once its record closed: not registered.
        rig.bridge
            .projects
            .forget(&crate::runtime::project_scope::task_project_key(
                RIG_PROJECT,
            ));
        let session = rig.sessions.remove(&rig.sid).unwrap();
        let _ = session.stop();
        passes(&mut rig, 3);
        agent
            .table
            .lock()
            .unwrap()
            .insert((RIG_PROJECT.into(), NEW_KID.into()), NEW_PROJECT.into());
        let change = s.log.set_service(
            "svc-bot",
            &ServiceScope::new(["host"])
                .projects(Some([NEW_PROJECT]))
                .ops(["message", "notify", "prompt", "stop"]),
            start + 3 * HOUR,
        );
        carry(&mut rig, &s.log, change);
        let bot = s.bot.clone();
        assert_eq!(
            ask(&mut rig, &bot, Q::Query(&task)),
            busy(),
            "not yet hashed"
        );
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut asked = ask(&mut rig, &bot, Q::Query(&task));
        while asked.is_err() && Instant::now() < deadline {
            assert_eq!(asked, busy(), "busy until hashed, never forbidden");
            passes(&mut rig, 1);
            tokio::time::sleep(Duration::from_millis(10)).await;
            asked = ask(&mut rig, &bot, Q::Query(&task));
        }
        assert_eq!(status(asked).state, WorkState::AwaitingResult);
    });
}

/// Task 32 re-review N1: the same for a `message_query` of the bot's
/// message whose delegated task closed before a restart (its project not
/// registered then) and whose session is gone: `busy` while its project
/// isn't hashed under the grant's new kid, never for good: the query
/// registers the task's project, which is then hashed.
#[test]
fn a_message_whose_tasks_project_isnt_hashed_yet_is_busy_until_it_is() {
    const NEW_KID: &str = "0e0f0a0d";
    const NEW_PROJECT: &str =
        "h1.0e0f0a0d.5555555555555555555555555555555555555555555555555555555555555555";
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let agent = TableAgent::new(true);
        let mut s =
            with_project_bot(&mut rig, root, &os, start + 3 * HOUR, &[PROJECT], &agent).await;
        let (publish, task) = message_from(&rig, BOT, "rs", "PROJECTS_MESSAGE", None);
        let bot = s.bot.clone();
        ask_req(&mut rig, &bot, &publish).unwrap();
        assert!(stored_record(&rig, &task).delegated.is_some());
        run(&mut rig, &task, "PROJECTS_MESSAGE").await;
        // As a restart finds it once its record closed: not registered.
        rig.bridge
            .projects
            .forget(&crate::runtime::project_scope::task_project_key(
                RIG_PROJECT,
            ));
        let session = rig.sessions.remove(&rig.sid).unwrap();
        let _ = session.stop();
        passes(&mut rig, 3);
        agent
            .table
            .lock()
            .unwrap()
            .insert((RIG_PROJECT.into(), NEW_KID.into()), NEW_PROJECT.into());
        let change = s.log.set_service(
            "svc-bot",
            &ServiceScope::new(["host"])
                .projects(Some([NEW_PROJECT]))
                .ops(["message", "notify", "prompt", "stop"]),
            start + 3 * HOUR,
        );
        carry(&mut rig, &s.log, change);
        assert_eq!(
            ask(&mut rig, &bot, Q::Message(&publish)),
            busy(),
            "not yet hashed"
        );
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut asked = ask(&mut rig, &bot, Q::Message(&publish));
        while asked.is_err() && Instant::now() < deadline {
            assert_eq!(asked, busy(), "busy until hashed, never forbidden");
            passes(&mut rig, 1);
            tokio::time::sleep(Duration::from_millis(10)).await;
            asked = ask(&mut rig, &bot, Q::Message(&publish));
        }
        assert!(matches!(asked, Ok(ResultBody::Message { .. })), "{asked:?}");
    });
}

/// Task 20 re-review M1, ruling T20c (the first PR that covers services):
/// the bot's grant is re-issued under a kid its task's admission didn't
/// see (a K rotation) after the task's session stopped. Its task stays
/// readable and completable by the bot: the task's launch project
/// (host-private, kept with its record) is hashed under the new kid through
/// the cred agent, without the session.
#[test]
fn a_projects_scoped_task_is_compared_under_a_new_kid_without_its_session() {
    const NEW_KID: &str = "0e0f0a0b";
    const NEW_PROJECT: &str =
        "h1.0e0f0a0b.3333333333333333333333333333333333333333333333333333333333333333";
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let agent = TableAgent::new(true);
        let mut s =
            with_project_bot(&mut rig, root, &os, start + 3 * HOUR, &[PROJECT], &agent).await;
        let task = bot_task(&mut rig, &s, "PROJECTS_NEW_KID", start + HOUR);
        run(&mut rig, &task, "PROJECTS_NEW_KID").await;
        // The session stops: its hashes leave with it.
        let session = rig.sessions.remove(&rig.sid).unwrap();
        let _ = session.stop();
        passes(&mut rig, 3);
        assert_eq!(rig.bridge.projects.matches(rig.sid.as_str(), PROJECT), None);
        // A K rotation: the grant re-issued under the new kid.
        agent
            .table
            .lock()
            .unwrap()
            .insert((RIG_PROJECT.into(), NEW_KID.into()), NEW_PROJECT.into());
        let change = s.log.set_service(
            "svc-bot",
            &ServiceScope::new(["host"])
                .projects(Some([NEW_PROJECT]))
                .ops(["message", "notify", "prompt", "stop"]),
            start + 3 * HOUR,
        );
        carry(&mut rig, &s.log, change);
        let bot = s.bot.clone();
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut asked = ask(&mut rig, &bot, Q::Query(&task));
        while asked.is_err() && Instant::now() < deadline {
            passes(&mut rig, 1);
            tokio::time::sleep(Duration::from_millis(10)).await;
            asked = ask(&mut rig, &bot, Q::Query(&task));
        }
        assert_eq!(status(asked).state, WorkState::AwaitingResult);
        assert_eq!(
            status(ask(&mut rig, &bot, Q::Complete(&task, "done"))).state,
            WorkState::Completed
        );
    });
}
