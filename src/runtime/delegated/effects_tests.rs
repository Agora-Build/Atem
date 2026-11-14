// What control records do to delegated tasks, in the bridge (Task 35;
// design I.5.5 to I.5.7, I.5.9; host-work-v1 §11.1, §11.6): the rig's host
// with the phone and the bot (`with_bot`), the bot's records served by the
// host's own Station's feed and read through the bridge's sync (`feed`: the
// page's records and their effects in one transaction), the fake agent and
// the delegated clock on a manual OS. Included beside the dispatch's, the
// lifecycle's, the feed pass's and the intents' tests, whose helpers and
// imports it shares.

use crate::runtime::delegated::feeds::Feeds;
use atem_client::control::{ControlAction, ControlRecord};

/// The bot's record of `action`, the `n`th of the test (its `issued_at`
/// rises with it: a release comes after the holds before it, O1).
fn bot_record(log: &TestLog, action: ControlAction, n: u64) -> ControlRecord {
    own_record(log, "svc-bot", action, n)
}

/// `records`, served by the host's own Station ([`ORIGIN`]) at its feed's
/// next positions and read through the bridge's sync as a page is: its
/// `heads`, the call the sync asks, the page (its records applied with
/// their effects in the page's transaction, the standings published at
/// its commit). The rig has no Station link: one is set up for the page and
/// gone after it, the gates as the test left them (a pass on the rig's own
/// link would close them). What the records ask of the bridge after their
/// commit (withdrawals, fences) waits for the next pass.
fn feed(rig: &mut LocalRig, log: &TestLog, records: &[&ControlRecord]) {
    use crate::runtime::delegated::station::{Call, LinkKind, Station};
    let gates = rig.bridge.start_view().gates.clone();
    let mut station = Station::new();
    station.sync_link(Some(1), 1, || LinkKind::Routed, || Some(ORIGIN.to_string()));
    rig.bridge.station = Some(station);
    rig.bridge.feed_advance(clocks_after(0));
    let after = match &rig.bridge.work.feeds {
        Feeds::Loaded(feeds) => feeds.current_feed(ORIGIN).map_or(0, |(_, cursor)| cursor),
        _ => panic!("the feeds loaded"),
    };
    let head = after + records.len() as u64;
    let calls = bridge_heads(rig, head, log.log.head());
    assert!(matches!(calls.as_slice(), [Call::Sync(_)]), "{calls:?}");
    let entries: Vec<(u64, &ControlRecord)> = records
        .iter()
        .enumerate()
        .map(|(i, record)| (after + 1 + i as u64, *record))
        .collect();
    bridge_page(rig, head, &entries);
    let cursor = match &rig.bridge.work.feeds {
        Feeds::Loaded(feeds) => feeds.cursor(ORIGIN, OWN_FEED),
        _ => None,
    };
    assert_eq!(cursor, Some(head), "the page applied");
    rig.bridge.station = None;
    rig.bridge.start_view().gates = gates;
}

/// The bot covered by the host's own Station's feed (its first record), on
/// [`with_bot`]'s rig.
fn covered_bot(rig: &mut LocalRig, root: &Path, os: &ManualOs, start: u64) -> Senders {
    let s = with_bot(rig, root, os, start + 3 * HOUR);
    feed(rig, &s.log, &[&bot_record(&s.log, ControlAction::Cover, 1)]);
    assert!(rig.bridge.start_view().standings[BOT].coverage.is_some());
    s
}

fn revoke(interrupt_running: bool) -> ControlAction {
    ControlAction::Revoke { interrupt_running }
}

/// The phone's task of `prompt` runs on the rig's session (its turn
/// journaled): its id.
async fn phone_running(rig: &mut LocalRig, s: &Senders, prompt: &str, start: u64) -> String {
    let phone = s.phone.clone();
    let task = phone_task(rig, &phone, prompt, start + HOUR);
    turn_journaled(rig, &task, prompt).await;
    task
}

/// The bot's task of `prompt` runs on the rig's session (its turn
/// journaled): its id.
async fn bot_running(rig: &mut LocalRig, s: &Senders, prompt: &str, start: u64) -> String {
    let task = bot_task(rig, s, prompt, start + HOUR);
    turn_journaled(rig, &task, prompt).await;
    task
}

const BEHIND: &str = "waiting for an earlier task on this session";

/// `n` broker ticks as they come: host-work's scheduling passes only when
/// due (held by [`hold_host_work`], they don't run).
fn ticks(rig: &mut LocalRig, n: usize) {
    for _ in 0..n {
        for s in rig.sessions.values_mut() {
            s.pump();
        }
        rig.bridge.tick(&mut rig.app, &mut rig.sessions, false);
    }
}

/// Design I.5.5 step 2, I.5.6 (VII.A test 3, 6): a revoke cancels the
/// bot's unstarted task in the record's own transaction (`cancelled`,
/// `sender revoked`), before any pass; a task whose attempt waits
/// `accepted` behind another sender's turn isn't settled there: its
/// attempt is withdrawn after the commit (`withdrawn by the host`), and the
/// task is cancelled from that withdrawal. The other sender's turn goes on;
/// nothing of the bot's ran.
#[test]
fn revoke_cancels_unstarted_and_withdraws_an_accepted_attempt() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = covered_bot(&mut rig, root, &os, start);
        let running = phone_running(&mut rig, &s, "REVOKE_PHONE_RUNNING", start).await;
        let queued = bot_task(&mut rig, &s, "REVOKE_QUEUED", start + HOUR);
        let accepted = bot_task(&mut rig, &s, "REVOKE_ACCEPTED", start + HOUR);
        for task in [&queued, &accepted] {
            blocked(&mut rig, task, BEHIND).await;
        }
        let attempt = attempt_behind_the_turn(&mut rig, &accepted, "REVOKE_ACCEPTED");
        feed(&mut rig, &s.log, &[&bot_record(&s.log, revoke(false), 2)]);
        // The record's transaction: the unstarted task cancelled; the one
        // with a live attempt not settled.
        assert_eq!(settled(&rig, &queued), outcome(Event::Revoked));
        assert_eq!(settled(&rig, &accepted).0, WorkState::Submitting);
        assert_eq!(attempts(&rig, &accepted), [(attempt.clone(), None, true)]);
        // After the commit: the attempt withdrawn, the task cancelled from
        // its withdrawal.
        passes(&mut rig, 1);
        assert_eq!(settled(&rig, &accepted), outcome(Event::Revoked));
        let receipt = rig
            .bridge
            .host
            .attempt_receipt(&attempt, &accepted)
            .unwrap();
        assert_eq!(
            (receipt.state, receipt.detail.as_deref()),
            (
                wire::ReceiptState::Rejected,
                Some(details::WITHDRAWN_BY_THE_HOST)
            )
        );
        assert_eq!(
            attempts(&rig, &accepted),
            [(attempt, Some("withdrawn".into()), true)]
        );
        assert_eq!(settled(&rig, &running).0, WorkState::Submitted);
        complete(&mut rig, &running).await;
        passes(&mut rig, 3);
        let text = input(&rig);
        assert!(!text.contains("REVOKE_QUEUED") && !text.contains("REVOKE_ACCEPTED"));
        assert!(attempts(&rig, &queued).is_empty());
    });
}

/// VII.A test 21 (design I.5.5, "A task with a live attempt"): the bot's
/// attempt waits `accepted` behind the phone's turn; the turn ends and the
/// session host starts it (`executing`, its start check passing) before
/// host-work's scheduling has seen it, and the revoke lands then. The
/// record's transaction leaves the task alone (its attempt is live); the
/// withdrawal after the commit finds it started, and the task runs: it
/// never shows `cancelled` while its turn runs, and its turn ends as any.
#[test]
fn a_task_never_shows_cancelled_while_its_turn_runs() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = covered_bot(&mut rig, root, &os, start);
        let running = phone_running(&mut rig, &s, "LIVE_PHONE_RUNNING", start).await;
        let task = bot_task(&mut rig, &s, "LIVE_BOT_STARTS", start + HOUR);
        blocked(&mut rig, &task, BEHIND).await;
        let attempt = attempt_behind_the_turn(&mut rig, &task, "LIVE_BOT_STARTS");
        // Host-work's scheduling held: the phone's turn ends, and the
        // session host starts the bot's attempt on its own.
        hold_host_work(&mut rig);
        std::fs::write(rig.fake.join("complete"), "").unwrap();
        rig.until(|r| {
            r.bridge
                .host
                .attempt_receipt(&attempt, &task)
                .is_some_and(|rc| rc.state == wire::ReceiptState::Executing)
        })
        .await;
        let never_cancelled = |rig: &LocalRig| {
            assert_ne!(settled(rig, &task).0, WorkState::Cancelled);
        };
        feed(&mut rig, &s.log, &[&bot_record(&s.log, revoke(false), 2)]);
        never_cancelled(&rig);
        assert_eq!(attempts(&rig, &task), [(attempt.clone(), None, true)]);
        // The withdrawal finds it started: nothing ends.
        ticks(&mut rig, 3);
        never_cancelled(&rig);
        assert_eq!(attempts(&rig, &task), [(attempt.clone(), None, true)]);
        // Host-work's scheduling back: the task follows its receipt.
        rig.bridge.work.scheduled = Instant::now();
        rig.until(|r| {
            never_cancelled(r);
            settled(r, &task) == (WorkState::Submitted, "in the agent's turn".into())
        })
        .await;
        assert_eq!(
            attempts(&rig, &task),
            [(attempt, Some("started".into()), true)]
        );
        assert!(input(&rig).contains("LIVE_BOT_STARTS"));
        assert_eq!(settled(&rig, &running).0, WorkState::AwaitingResult);
        complete(&mut rig, &task).await;
    });
}

/// Design I.5.5 step 3, I.5.7 (VII.A test 3): a revoke with
/// `interrupt_running` writes, in its own transaction, an interrupt intent
/// for the bot's started task (reason `revoke`, the revocation's record
/// id), none for a task awaiting its result (its turn ended) nor for an
/// unstarted one (cancelled); the next passes interrupt the turn with host
/// authority, once, and the turn it ended reads `turn interrupted` (not
/// the deadline's text).
#[test]
fn revoke_with_interrupt_writes_intents() {
    use crate::runtime::delegated::intents::IntentReason;
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = covered_bot(&mut rig, root, &os, start);
        let done = bot_running(&mut rig, &s, "INTERRUPT_DONE", start).await;
        complete(&mut rig, &done).await;
        let running = bot_running(&mut rig, &s, "INTERRUPT_RUNNING", start).await;
        let queued = bot_task(&mut rig, &s, "INTERRUPT_QUEUED", start + HOUR);
        blocked(&mut rig, &queued, BEHIND).await;
        let record = bot_record(&s.log, revoke(true), 2);
        feed(&mut rig, &s.log, &[&record]);
        let stored = intents(&rig, &running);
        let [intent] = stored.as_slice() else {
            panic!("one intent: {stored:?}");
        };
        assert_eq!(
            (
                intent.attempt_id.as_str(),
                &intent.reason,
                intent.done_ms.is_some()
            ),
            (
                stored_record(&rig, &running).status.receipt_id.as_str(),
                &IntentReason::Revoke {
                    revocation: record.record_id().to_string()
                },
                false
            )
        );
        assert!(intents(&rig, &done).is_empty(), "its turn ended");
        assert!(intents(&rig, &queued).is_empty());
        assert_eq!(settled(&rig, &queued), outcome(Event::Revoked));
        assert_eq!(escs(&rig), 0, "nothing acted before the commit's followups");
        passes(&mut rig, 2);
        escs_reach(&rig, 1).await;
        settle(&mut rig).await;
        passes(&mut rig, 3);
        assert_eq!(escs(&rig), 1, "once per turn");
        turn_interrupted(&mut rig, &running).await;
        rig.until(|r| settled(r, &running).0 == WorkState::AwaitingResult)
            .await;
        assert_eq!(settled(&rig, &running).1, "turn interrupted");
        rig.until(|r| intents(r, &running)[0].done_ms.is_some())
            .await;
        assert_eq!(escs(&rig), 1);
    });
}

/// Design I.5.5 step 3 (I.5.8: one interrupt per revocation): a revoke
/// without `interrupt_running` leaves the bot's running turn alone; a
/// later `interrupt_running` record writes the intent in its own
/// transaction, and the turn gets one Esc. The same record served again,
/// and another `interrupt_running` record for the same revocation, add no
/// intent and no Esc.
#[test]
fn a_later_interrupt_record_writes_intents_once() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = covered_bot(&mut rig, root, &os, start);
        let running = bot_running(&mut rig, &s, "LATER_INTERRUPT", start).await;
        feed(&mut rig, &s.log, &[&bot_record(&s.log, revoke(false), 2)]);
        passes(&mut rig, 3);
        assert!(intents(&rig, &running).is_empty());
        assert_eq!(escs(&rig), 0);
        assert_eq!(settled(&rig, &running).0, WorkState::Submitted);
        let interrupt = ControlAction::InterruptRunning { revoke_seq: None };
        let first = bot_record(&s.log, interrupt, 3);
        feed(&mut rig, &s.log, &[&first]);
        assert_eq!(
            intents(&rig, &running).len(),
            1,
            "in the record's transaction"
        );
        passes(&mut rig, 2);
        escs_reach(&rig, 1).await;
        settle(&mut rig).await;
        // Served again, and another record for the same revocation.
        feed(&mut rig, &s.log, &[&first]);
        feed(&mut rig, &s.log, &[&bot_record(&s.log, interrupt, 4)]);
        assert_eq!(intents(&rig, &running).len(), 1);
        passes(&mut rig, 3);
        settle(&mut rig).await;
        assert_eq!(escs(&rig), 1);
        turn_interrupted(&mut rig, &running).await;
        rig.until(|r| settled(r, &running).0 == WorkState::AwaitingResult)
            .await;
        assert_eq!(escs(&rig), 1);
    });
}

/// Design I.5.5 step 4, I.6.4 (VII.A test 5): a hold puts the bot's
/// unstarted task in `blocked`, `paused`, in the record's transaction; one
/// whose attempt waits `accepted` behind the phone's turn is withdrawn
/// after the commit, not counted, and paused too. A release lets both run
/// again (`queued` at its commit), before their deadline, each in turn.
#[test]
fn hold_blocks_paused_and_release_resumes() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = covered_bot(&mut rig, root, &os, start);
        let running = phone_running(&mut rig, &s, "HOLD_PHONE_RUNNING", start).await;
        let first = bot_task(&mut rig, &s, "HOLD_FIRST", start + HOUR);
        let second = bot_task(&mut rig, &s, "HOLD_SECOND", start + HOUR);
        for task in [&first, &second] {
            blocked(&mut rig, task, BEHIND).await;
        }
        let withdrawn = attempt_behind_the_turn(&mut rig, &second, "HOLD_SECOND");
        feed(
            &mut rig,
            &s.log,
            &[&bot_record(&s.log, ControlAction::Hold, 2)],
        );
        assert_eq!(settled(&rig, &first), outcome(Event::Held));
        assert_eq!(settled(&rig, &second).0, WorkState::Submitting);
        passes(&mut rig, 1);
        assert_eq!(settled(&rig, &second), outcome(Event::Held));
        assert_eq!(
            attempts(&rig, &second),
            [(withdrawn.clone(), Some("withdrawn".into()), false)],
            "a hold's withdrawal isn't counted"
        );
        feed(
            &mut rig,
            &s.log,
            &[&bot_record(&s.log, ControlAction::Release, 3)],
        );
        for task in [&first, &second] {
            assert_eq!(
                settled(&rig, task),
                (WorkState::Queued, "waiting for a ready agent".into()),
                "released at its commit"
            );
        }
        complete(&mut rig, &running).await;
        run(&mut rig, &first, "HOLD_FIRST").await;
        run(&mut rig, &second, "HOLD_SECOND").await;
        let ends = attempts(&rig, &second);
        assert_eq!(ends.len(), 2);
        assert_eq!(ends[0], (withdrawn, Some("withdrawn".into()), false));
        assert_eq!((ends[1].1.as_deref(), ends[1].2), (Some("started"), true));
    });
}

/// Design I.5.5 step 4, host-work-v1 §11.1 rule 6 (VII.A test 5): hold,
/// release, a later hold; the first release served again at a later
/// position is a replay: it lifts nothing (its record already counted), so
/// the bot's task stays `paused` and never runs, the phone's turn ended.
#[test]
fn a_replayed_release_after_a_later_hold_is_ignored() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = covered_bot(&mut rig, root, &os, start);
        let running = phone_running(&mut rig, &s, "REPLAY_PHONE_RUNNING", start).await;
        let task = bot_task(&mut rig, &s, "REPLAY_BOT", start + HOUR);
        blocked(&mut rig, &task, BEHIND).await;
        feed(
            &mut rig,
            &s.log,
            &[&bot_record(&s.log, ControlAction::Hold, 2)],
        );
        assert_eq!(settled(&rig, &task), outcome(Event::Held));
        // Issued after the hold (O1), kept to be served again.
        let release = bot_record(&s.log, ControlAction::Release, 3);
        feed(&mut rig, &s.log, &[&release]);
        assert_eq!(settled(&rig, &task).0, WorkState::Queued);
        feed(
            &mut rig,
            &s.log,
            &[&bot_record(&s.log, ControlAction::Hold, 4)],
        );
        assert_eq!(settled(&rig, &task), outcome(Event::Held));
        feed(&mut rig, &s.log, &[&release]);
        assert_eq!(settled(&rig, &task), outcome(Event::Held), "a replay");
        assert!(rig.bridge.start_view().standings[BOT].held);
        complete(&mut rig, &running).await;
        passes(&mut rig, 5);
        assert_eq!(settled(&rig, &task), outcome(Event::Held));
        assert!(attempts(&rig, &task).is_empty());
        assert!(!input(&rig).contains("REPLAY_BOT"));
    });
}

/// Design I.5.5 step 4, §11.6 "Waiting doesn't hold the session" (VII.A
/// test 5): the bot's attempt waits `accepted` behind the phone's turn when
/// the hold lands; it is withdrawn at once and the task paused, so it holds
/// the session no longer: once the turn ends, the phone's next task and a
/// local task run on it, the bot's task still paused.
#[test]
fn a_held_task_doesnt_hold_another_senders_or_a_local_task() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = covered_bot(&mut rig, root, &os, start);
        let running = phone_running(&mut rig, &s, "HELD_PHONE_RUNNING", start).await;
        let held = bot_task(&mut rig, &s, "HELD_BOT", start + HOUR);
        blocked(&mut rig, &held, BEHIND).await;
        let attempt = attempt_behind_the_turn(&mut rig, &held, "HELD_BOT");
        let phone = s.phone.clone();
        let next = phone_task(&mut rig, &phone, "HELD_PHONE_NEXT", start + HOUR);
        feed(
            &mut rig,
            &s.log,
            &[&bot_record(&s.log, ControlAction::Hold, 2)],
        );
        passes(&mut rig, 1);
        assert_eq!(settled(&rig, &held), outcome(Event::Held));
        assert_eq!(
            attempts(&rig, &held),
            [(attempt, Some("withdrawn".into()), false)]
        );
        complete(&mut rig, &running).await;
        run(&mut rig, &next, "HELD_PHONE_NEXT").await;
        local_task_runs(&mut rig, "LOCAL_PAST_THE_HELD_TASK").await;
        assert_eq!(settled(&rig, &held), outcome(Event::Held));
        assert!(!input(&rig).contains("HELD_BOT"));
    });
}

/// Design I.5.5 step 5, I.1.3 (Decision 13): a `cover` makes the bot's
/// future tasks delegated, from its feed; a task it had already keeps the
/// rules it was admitted under (v1: no admission record).
#[test]
fn cover_makes_a_service_delegated_for_future_tasks_only() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = with_bot(&mut rig, root, &os, start + 3 * HOUR);
        // The feeds alone decide (no control view standing in), read in
        // full once (an empty feed: ruling T35d, B), the bot uncovered.
        rig.bridge.work.controls = None;
        rig.bridge.start_view().standings.clear();
        feed(&mut rig, &s.log, &[]);
        assert_eq!(rig.bridge.sender_class(BOT), SenderClass::V1);
        let mut before = phone_enqueue(&rig, "COVER_BEFORE");
        if let hw::Request::Enqueue { route_id, .. } = &mut before {
            *route_id = "rs".into();
        }
        let bot = s.bot.clone();
        ask_req(&mut rig, &bot, &before).unwrap();
        let before = enqueued(&before);
        assert!(stored_record(&rig, &before).delegated.is_none(), "v1");
        feed(
            &mut rig,
            &s.log,
            &[&bot_record(&s.log, ControlAction::Cover, 1)],
        );
        let after = bot_task(&mut rig, &s, "COVER_AFTER", start + HOUR);
        let admission = stored_record(&rig, &after).delegated.unwrap();
        assert_eq!(
            admission.feed,
            Some(FeedRef {
                origin: ORIGIN.into(),
                feed_id: OWN_FEED.into()
            })
        );
        assert!(
            stored_record(&rig, &before).delegated.is_none(),
            "admitted under v1, it stays v1"
        );
    });
}

/// A service's `hello` on the bridge's r9 engine (channel `handle`, its
/// carriage `log`'s suffix): the attached client, or what refused it.
fn service_hello(
    rig: &mut LocalRig,
    log: &TestLog,
    handle: &str,
    device: &str,
) -> Result<atem_client::connect::Attached, atem_client::connect::ConnectError> {
    hello_as(rig, log, handle, Identity::service(device, auth(device)))
}

/// `identity`'s `hello` on the bridge's r9 engine (channel `handle`, its
/// carriage `log`'s suffix): the attached client, or what refused it.
fn hello_as(
    rig: &mut LocalRig,
    log: &TestLog,
    handle: &str,
    identity: Identity,
) -> Result<atem_client::connect::Attached, atem_client::connect::ConnectError> {
    hello_at(rig, log, handle, identity, 1)
}

/// [`hello_as`] to the host at trust generation `trust_gen`.
fn hello_at(
    rig: &mut LocalRig,
    log: &TestLog,
    handle: &str,
    identity: Identity,
    trust_gen: u64,
) -> Result<atem_client::connect::Attached, atem_client::connect::ConnectError> {
    rig.bridge.r9.reset_init_limiter();
    envelope_in(rig, &envelope::open(handle, Transport::Relay));
    let (connecting, init) = Connector::new("host").start(&log.log, trust_gen).unwrap();
    envelope_in(rig, &envelope::frame(handle, &init));
    let accept = frames_for(rig, handle).remove(0);
    let (welcoming, finish) = connecting
        .on_accept(&accept, &log.log, &log.keys, &identity, 1)
        .unwrap();
    envelope_in(rig, &envelope::frame(handle, &finish));
    let welcome = frames_for(rig, handle).remove(0);
    welcoming.on_frame(&welcome, &log.log, 1)
}

/// What refused a `hello`: its code and detail.
fn refusal(
    hello: Result<atem_client::connect::Attached, atem_client::connect::ConnectError>,
) -> (String, Option<String>) {
    match hello {
        Err(atem_client::connect::ConnectError::Refused { error, .. }) => {
            (error.code, error.detail)
        }
        other => panic!("a refusal: {:?}", other.map(|_| ())),
    }
}

/// The engine's frames and closes for `handle` since the last call.
fn flushed(rig: &mut LocalRig, handle: &str) -> (Vec<Vec<u8>>, Vec<Option<String>>) {
    let mut out = Vec::new();
    rig.bridge.r9.flush(&mut |text, _| {
        out.push(text);
        true
    });
    let (mut frames, mut closes) = (Vec::new(), Vec::new());
    for text in out {
        match envelope::parse(&text).unwrap() {
            Envelope9::Frame { channel, frame } if channel == handle => frames.push(frame),
            Envelope9::Close { channel, reason } if channel == handle => closes.push(reason),
            _ => {}
        }
    }
    (frames, closes)
}

/// Every kind of request a service sends, now: `work_enqueue`,
/// `work_query` of `task`, a notice-only `message_publish`,
/// `attachment_put`, `host_profiles`, `host_launch` and
/// `host_launch_query`, by kind.
fn every_request(rig: &LocalRig, task: &str) -> Vec<(&'static str, hw::Request)> {
    let host = rig.bridge.work_host();
    let id = || uuid::Uuid::new_v4().to_string();
    let mut enqueue = phone_enqueue(rig, "REVOKED_SENDERS_NEW_TASK");
    if let hw::Request::Enqueue { route_id, .. } = &mut enqueue {
        *route_id = "rs".into();
    }
    let (mut notice, _) = message_from(rig, BOT, "rs", "REVOKED_SENDERS_NOTICE", None);
    if let hw::Request::Publish { message, .. } = &mut notice {
        message.recipients = vec![Recipient {
            recipient_id: id(),
            host: host.clone(),
            destination: Destination::Project {
                route_id: "rs".into(),
                route_revision: 1,
            },
        }];
    }
    let png = b"\x89PNG\r\n\x1a\nREVOKED_SENDERS_ATTACHMENT_BYTES_0123456789";
    vec![
        ("work_enqueue", enqueue),
        (
            "work_query",
            hw::Request::WorkQuery {
                v: 1,
                id: id(),
                host: host.clone(),
                task_id: task.into(),
            },
        ),
        ("message_publish", notice),
        (
            "attachment_put",
            hw::Request::AttachmentPut {
                v: 1,
                id: id(),
                host: host.clone(),
                attachment: atem_client::session::attachments::Attachment {
                    attachment_id: id(),
                    digest: hw::digest(png),
                    size: png.len() as u64,
                    media_type: "image/png".into(),
                },
                offset: 0,
                data: {
                    use base64::Engine;
                    base64::engine::general_purpose::STANDARD.encode(png)
                },
            },
        ),
        (
            "host_profiles",
            hw::Request::Profiles {
                v: 1,
                id: id(),
                host: host.clone(),
            },
        ),
        (
            "host_launch",
            hw::Request::Launch {
                v: 1,
                id: id(),
                host: host.clone(),
                request_id: id(),
                profile_id: "p".into(),
                profile_revision: 1,
                expires_at: host_now().wall_ms + HOUR,
            },
        ),
        (
            "host_launch_query",
            hw::Request::LaunchQuery {
                v: 1,
                id: id(),
                host,
                request_id: id(),
            },
        ),
    ]
}

/// Design I.5.5 step 2: once the revoke commits, every request of the bot
/// is refused (`forbidden`), whatever it asks, nothing stored, while the
/// owner still reads its task; and after the commit its attachments are
/// fenced through §H (its `control_gen` raised, its channel closed after
/// `unauthorized`, `revoked`), and a new `hello` of it is refused the same
/// way.
#[test]
fn a_revoked_senders_requests_are_refused_and_its_attachments_fenced() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = covered_bot(&mut rig, root, &os, start);
        r9_link_up(&mut rig);
        let mut channel = service_hello(&mut rig, &s.log, "bot-1", "svc-bot").unwrap();
        assert!(
            rig.bridge
                .r9
                .attachments()
                .iter()
                .any(|(_, p)| p.as_str() == BOT)
        );
        let control_gen = rig.bridge.host.control_gen(BOT);
        let task = bot_task(&mut rig, &s, "REVOKED_SENDERS_TASK", start + HOUR);
        let mac = s.mac.clone();
        assert!(ask(&mut rig, &mac, Q::Query(&task)).is_ok());
        feed(&mut rig, &s.log, &[&bot_record(&s.log, revoke(false), 2)]);
        let bot = s.bot.clone();
        let requests = every_request(&rig, &task);
        for (kind, req) in &requests {
            assert_eq!(ask_req(&mut rig, &bot, req), forbidden(), "{kind}");
        }
        let store = rig.bridge.work.store.as_ref().unwrap();
        assert!(
            store.work(&enqueued(&requests[0].1)).unwrap().is_none(),
            "nothing stored"
        );
        assert!(rig.bridge.work.pending.is_empty(), "no launch reserved");
        assert_eq!(
            status(ask(&mut rig, &mac, Q::Query(&task))).state,
            WorkState::Cancelled,
            "the owner reads it"
        );
        // After the commit: the §H fence, its channel closed after
        // `unauthorized`, `revoked`.
        let _ = flushed(&mut rig, "bot-1");
        passes(&mut rig, 1);
        assert!(rig.bridge.host.control_gen(BOT) > control_gen);
        let (frames, closes) = flushed(&mut rig, "bot-1");
        assert_eq!(closes.len(), 1, "{closes:?}");
        let fenced: Vec<_> = frames
            .iter()
            .flat_map(|f| channel.on_frame(f, 1).unwrap())
            .filter_map(|e| match e {
                atem_client::connect::Event::Fenced(e) => Some((e.code, e.detail)),
                _ => None,
            })
            .collect();
        assert_eq!(
            fenced,
            [("unauthorized".to_string(), Some("revoked".to_string()))]
        );
        assert!(
            !rig.bridge
                .r9
                .attachments()
                .iter()
                .any(|(_, p)| p.as_str() == BOT),
            "fenced"
        );
        match service_hello(&mut rig, &s.log, "bot-2", "svc-bot") {
            Err(atem_client::connect::ConnectError::Refused { error, .. }) => assert_eq!(
                (error.code.as_str(), error.detail.as_deref()),
                ("unauthorized", Some("revoked"))
            ),
            other => panic!("a refusal: {:?}", other.map(|_| ())),
        }
    });
}

/// Ruling T32b, PR 11 setup review note 2 (I1's remaining paths): while
/// the control state doesn't read, every request of a service is `busy`
/// and stores nothing (its revocation and hold can't be checked): a
/// notice-only `message_publish`, `attachment_put`, `host_profiles`,
/// `host_launch` and its query too; the phone, a native, is unaffected.
#[test]
fn a_damaged_control_state_answers_every_service_request_busy() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = covered_bot(&mut rig, root, &os, start);
        let task = bot_task(&mut rig, &s, "DAMAGED_TASK", start + HOUR);
        rig.bridge.work.controls = None;
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
        let bot = s.bot.clone();
        let requests = every_request(&rig, &task);
        for (kind, req) in &requests {
            assert_eq!(ask_req(&mut rig, &bot, req), busy(), "{kind}");
        }
        let store = rig.bridge.work.store.as_ref().unwrap();
        assert!(
            store.work(&enqueued(&requests[0].1)).unwrap().is_none(),
            "nothing stored"
        );
        assert!(rig.bridge.work.pending.is_empty(), "no launch reserved");
        let phone = s.phone.clone();
        let profiles = hw::Request::Profiles {
            v: 1,
            id: uuid::Uuid::new_v4().to_string(),
            host: rig.bridge.work_host(),
        };
        let reply = ask_req(&mut rig, &phone, &profiles);
        assert!(
            matches!(reply, Ok(ResultBody::Profiles { .. })),
            "{reply:?}"
        );
    });
}

/// Ledger carry (attribution): a revoke's intent and a deadline's share an
/// attempt; the Esc is the first pending one's (the revoke's), and only it
/// records the turn it reached, so the turn it ended reads `turn
/// interrupted`, never the deadline's `interrupted at deadline`.
#[test]
fn a_turn_a_revoke_interrupted_reads_turn_interrupted_beside_a_deadline_intent() {
    use crate::runtime::delegated::intents::IntentReason;
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = covered_bot(&mut rig, root, &os, start);
        let running = bot_running(&mut rig, &s, "SHARED_TURN", start).await;
        commit_intent(
            &rig,
            &running,
            IntentReason::Revoke {
                revocation: "rec-1".into(),
            },
        );
        commit_intent(&rig, &running, IntentReason::Deadline);
        passes(&mut rig, 2);
        escs_reach(&rig, 1).await;
        settle(&mut rig).await;
        passes(&mut rig, 2);
        let stored = intents(&rig, &running);
        assert_eq!(stored.len(), 2);
        assert!(stored[0].delivered_turn.is_some(), "the revoke's Esc");
        assert_eq!(stored[1].delivered_turn, None, "not the deadline's");
        turn_interrupted(&mut rig, &running).await;
        rig.until(|r| settled(r, &running).0 == WorkState::AwaitingResult)
            .await;
        assert_eq!(settled(&rig, &running).1, "turn interrupted");
        assert_eq!(escs(&rig), 1);
    });
}

/// Ruling T26a, ledger carry "standings at commit, pause included": a
/// record's effects reach the tasks while hosting is paused (`runtime.toml`
/// stopped loading; a stop always wins): a hold pauses the bot's unstarted
/// task in its transaction and withdraws its attempt waiting `accepted`
/// right after (no scheduling pass runs while paused), not counted; a later
/// revoke cancels both. The phone's turn goes on.
#[test]
fn records_take_effect_while_hosting_is_paused() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = covered_bot(&mut rig, root, &os, start);
        let running = phone_running(&mut rig, &s, "PAUSED_PHONE_RUNNING", start).await;
        let queued = bot_task(&mut rig, &s, "PAUSED_QUEUED", start + HOUR);
        let accepted = bot_task(&mut rig, &s, "PAUSED_ACCEPTED", start + HOUR);
        for task in [&queued, &accepted] {
            blocked(&mut rig, task, BEHIND).await;
        }
        let attempt = attempt_behind_the_turn(&mut rig, &accepted, "PAUSED_ACCEPTED");
        rig.bridge.work.config = Config::default();
        rig.bridge.work.config_problem = Some("expected a table".into());
        assert!(!rig.bridge.hosting_enabled());
        passes(&mut rig, 1);
        feed(
            &mut rig,
            &s.log,
            &[&bot_record(&s.log, ControlAction::Hold, 2)],
        );
        assert_eq!(settled(&rig, &queued), outcome(Event::Held));
        passes(&mut rig, 1);
        assert_eq!(settled(&rig, &accepted), outcome(Event::Held));
        assert_eq!(
            attempts(&rig, &accepted),
            [(attempt, Some("withdrawn".into()), false)]
        );
        feed(&mut rig, &s.log, &[&bot_record(&s.log, revoke(false), 3)]);
        for task in [&queued, &accepted] {
            assert_eq!(settled(&rig, task), outcome(Event::Revoked));
        }
        assert_eq!(settled(&rig, &running).0, WorkState::Submitted);
        let text = input(&rig);
        assert!(!text.contains("PAUSED_QUEUED") && !text.contains("PAUSED_ACCEPTED"));
    });
}

/// Task 33 re-review N4: a new host identity moves the store aside, and
/// with it what its records applied and asked of the bridge: the records a
/// re-verification kept and the followups not carried out yet go, and the
/// r9 engine's revoked services (they were that pairing's).
#[test]
fn a_new_identity_drops_what_the_old_stores_records_asked() {
    use crate::runtime::delegated::effects::Followup;
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = covered_bot(&mut rig, root, &os, start);
        let record = bot_record(&s.log, ControlAction::Hold, 2);
        rig.bridge
            .work
            .reapplied
            .push(crate::runtime::delegated::feeds::Reapplied {
                record,
                pos: None,
                applied: atem_client::control::Applied {
                    record_result: atem_client::control::ApplicationResult::Applied,
                    effects: Vec::new(),
                    actions: Vec::new(),
                    evidence: false,
                    why: None,
                },
            });
        rig.bridge.work.followups.push(Followup::Withdraw {
            task_id: "t".into(),
            attempt_id: "a".into(),
            then: Event::Held,
        });
        rig.bridge
            .r9
            .set_revoked_services(HashSet::from([BOT.to_string()]));
        let other = HostTarget {
            account_id: "acct".into(),
            atem_device_id: "host".into(),
            host_trust_gen: 2,
        };
        assert!(rig.bridge.work_store_ready(&other));
        assert!(rig.bridge.work.reapplied.is_empty());
        assert!(rig.bridge.work.followups.is_empty());
        assert!(rig.bridge.r9.revoked_services().is_empty());
    });
}

/// Hook off = main (step 4's Decision 10): with `host.delegated` off, no
/// service request is refused for its control standing (one the start
/// view says is revoked included: nothing reads it), and a pass carries
/// out nothing of the records' (no feeds, no followups, no revoked
/// services in the r9 engine).
#[test]
fn the_hook_off_refuses_and_carries_out_nothing() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = with_bot(&mut rig, root, &os, start + 3 * HOUR);
        rig.bridge.features = HostFeatures::default();
        rig.bridge.start_view().standings.insert(
            BOT.into(),
            SenderStanding {
                revoked: Some("rec-1".into()),
                ..SenderStanding::default()
            },
        );
        let bot = s.bot.clone();
        let profiles = hw::Request::Profiles {
            v: 1,
            id: uuid::Uuid::new_v4().to_string(),
            host: rig.bridge.work_host(),
        };
        let reply = ask_req(&mut rig, &bot, &profiles);
        assert!(
            matches!(reply, Ok(ResultBody::Profiles { .. })),
            "{reply:?}"
        );
        passes(&mut rig, 2);
        assert!(rig.bridge.work.followups.is_empty());
        assert!(rig.bridge.r9.revoked_services().is_empty());
    });
}

/// PR 11 setup review note 4 (design I.3.3's "awaiting_result,
/// outcome_unknown" column): a revoke with `interrupt_running` leaves the
/// bot's task awaiting its result and its task of unknown outcome as they
/// are, writing no intent for either (their turn ended, or none can be tied
/// to them), so no acknowledgment can count one; the owner still reads
/// both, the bot neither.
#[test]
fn a_revoke_leaves_awaiting_and_unknown_outcomes_alone() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = covered_bot(&mut rig, root, &os, start);
        let awaiting = bot_running(&mut rig, &s, "REVOKE_LEAVES_AWAITING", start).await;
        complete(&mut rig, &awaiting).await;
        let template = stored_record(&rig, &awaiting);
        let [unknown] = unknown_outcomes(&rig, &template, BOT, 1)
            .try_into()
            .unwrap();
        feed(&mut rig, &s.log, &[&bot_record(&s.log, revoke(true), 2)]);
        passes(&mut rig, 3);
        assert!(intents(&rig, &awaiting).is_empty());
        assert!(intents(&rig, &unknown).is_empty());
        assert_eq!(settled(&rig, &awaiting).0, WorkState::AwaitingResult);
        assert_eq!(
            settled(&rig, &unknown),
            (WorkState::OutcomeUnknown, details::AGENT_EXITED.into())
        );
        let (mac, bot) = (s.mac.clone(), s.bot.clone());
        for task in [&awaiting, &unknown] {
            assert!(ask(&mut rig, &mac, Q::Query(task)).is_ok(), "the owner");
            assert_eq!(ask(&mut rig, &bot, Q::Query(task)), forbidden());
        }
    });
}

/// The feeds alone decide (no control view standing in), the bot covered by
/// the host's own Station's feed: [`with_bot`]'s rig as a runtime has it.
fn fed_bot(rig: &mut LocalRig, root: &Path, os: &ManualOs, start: u64) -> Senders {
    let s = with_bot(rig, root, os, start + 3 * HOUR);
    rig.bridge.work.controls = None;
    rig.bridge.start_view().standings.clear();
    feed(rig, &s.log, &[&bot_record(&s.log, ControlAction::Cover, 1)]);
    assert!(matches!(
        rig.bridge.sender_class(BOT),
        SenderClass::Delegated(_)
    ));
    s
}

/// The stored control state stops reading (a damaged part, found when the
/// feeds load again).
fn damage(rig: &mut LocalRig) {
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
}

/// The phone, a native member.
fn phone_identity() -> Identity {
    Identity::native("dev-phone", auth("dev-phone"))
}

/// What a service's `hello` and its closed attachments get while the
/// control state is unchecked.
fn unchecked() -> (String, Option<String>) {
    (
        "busy".into(),
        Some(details::REVOCATIONS_NOT_YET_CHECKED.into()),
    )
}

fn revoked_refusal() -> (String, Option<String>) {
    ("unauthorized".into(), Some("revoked".into()))
}

/// Whether a principal holds a live r9 attachment.
fn attached(rig: &LocalRig, principal: &str) -> bool {
    rig.bridge
        .r9
        .attachments()
        .iter()
        .any(|(_, p)| p.as_str() == principal)
}

/// Ruling T35c (review I1): while the control state can't be checked, no
/// service holds session-v1, as host-work answers it `busy`. A state found
/// damaged closes every live service attachment (§H, after `busy`,
/// `revocations not yet checked`) and refuses every service's `hello` the
/// same way. Natives are admitted throughout. Repaired, with hosting
/// paused, the state loads anyway (ruling T35d, A), and the bot, not
/// revoked, is admitted again.
#[test]
fn every_services_hello_is_busy_while_the_control_state_is_unchecked() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = fed_bot(&mut rig, root, &os, start);
        r9_link_up(&mut rig);
        let mut bot = service_hello(&mut rig, &s.log, "bot-1", "svc-bot").unwrap();
        hello_as(&mut rig, &s.log, "phone-1", phone_identity()).unwrap();
        let before = rig.bridge.host.control_gen(BOT);
        damage(&mut rig);
        let _ = flushed(&mut rig, "bot-1");
        passes(&mut rig, 1);
        assert!(!attached(&rig, BOT), "closed");
        assert!(attached(&rig, PHONE), "a native stays");
        assert!(rig.bridge.host.control_gen(BOT) > before);
        let (frames, closes) = flushed(&mut rig, "bot-1");
        assert_eq!(closes.len(), 1, "{closes:?}");
        // A `busy` with no `re` (not a fence the client takes as final).
        let errors: Vec<_> = frames
            .iter()
            .flat_map(|f| bot.on_frame(f, 1).unwrap())
            .filter_map(|e| match e {
                atem_client::connect::Event::Error(e) => Some((e.code, e.detail)),
                _ => None,
            })
            .collect();
        assert_eq!(errors, [unchecked()]);
        assert_eq!(
            refusal(service_hello(&mut rig, &s.log, "bot-2", "svc-bot")),
            unchecked()
        );
        hello_as(&mut rig, &s.log, "phone-2", phone_identity()).unwrap();
        // Repaired with hosting paused: the store, bound to this host's
        // identity, keeps a control state, which loads whatever hosting
        // does (ruling T35d, A): the bot, not revoked, is admitted.
        rig.bridge
            .work
            .store
            .as_ref()
            .unwrap()
            .db
            .execute(
                "DELETE FROM control_principals WHERE principal='service:svc-x'",
                [],
            )
            .unwrap();
        rig.bridge.work.feeds = Feeds::Unloaded;
        rig.bridge.work.config = Config::default();
        rig.bridge.work.config_problem = Some("expected a table".into());
        passes(&mut rig, 2);
        assert!(matches!(rig.bridge.work.feeds, Feeds::Loaded(_)));
        service_hello(&mut rig, &s.log, "bot-3", "svc-bot").unwrap();
        hello_as(&mut rig, &s.log, "phone-3", phone_identity()).unwrap();
    });
}

/// A receipt-database fault fails closed for services too (host-work-v1
/// §11.1): with it, no control page applies until `atem runtime restart`,
/// so the committed standings may be stale (a revoke stored at the Station
/// meanwhile never reaches them). With the hook on, the control state is
/// unchecked then: the bot's live attachment is closed through the §H
/// fence after `busy`, `revocations not yet checked`, and its `hello` is
/// refused so, never kept on those standings. Natives are admitted
/// throughout. With the hook off, nothing is refused for it (as on main).
#[test]
fn a_receipt_database_fault_leaves_every_service_unchecked() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = fed_bot(&mut rig, root, &os, start);
        r9_link_up(&mut rig);
        let mut bot = service_hello(&mut rig, &s.log, "bot-1", "svc-bot").unwrap();
        hello_as(&mut rig, &s.log, "phone-1", phone_identity()).unwrap();
        assert!(!rig.bridge.controls_unchecked());
        let before = rig.bridge.host.control_gen(BOT);
        rig.bridge.work_fail();
        assert!(rig.bridge.controls_unchecked());
        let _ = flushed(&mut rig, "bot-1");
        passes(&mut rig, 1);
        assert!(rig.bridge.r9.services_unchecked());
        assert!(!attached(&rig, BOT), "closed");
        assert!(attached(&rig, PHONE), "a native stays");
        assert!(rig.bridge.host.control_gen(BOT) > before);
        let (frames, closes) = flushed(&mut rig, "bot-1");
        assert_eq!(closes.len(), 1, "{closes:?}");
        let errors: Vec<_> = frames
            .iter()
            .flat_map(|f| bot.on_frame(f, 1).unwrap())
            .filter_map(|e| match e {
                atem_client::connect::Event::Error(e) => Some((e.code, e.detail)),
                _ => None,
            })
            .collect();
        assert_eq!(errors, [unchecked()]);
        assert_eq!(
            refusal(service_hello(&mut rig, &s.log, "bot-2", "svc-bot")),
            unchecked()
        );
        hello_as(&mut rig, &s.log, "phone-2", phone_identity()).unwrap();
        let line = rig.bridge.feeds_status().unwrap_or_default();
        assert!(
            line.ends_with(
                "; services are refused (busy) until `atem runtime restart` (the receipt database failed)"
            ),
            "{line}"
        );
        // The hook off (as on main): nothing is refused for the fault.
        rig.bridge.features = HostFeatures::default();
        passes(&mut rig, 1);
        assert!(!rig.bridge.r9.services_unchecked());
        service_hello(&mut rig, &s.log, "bot-3", "svc-bot").unwrap();
    });
}

/// Review I2 (D9, ruling T35c): the r9 engine's revoked services come back
/// from the stored control state, never from memory. After a restart with
/// hosting paused (probe B), the stored state loads anyway (ruling T35d,
/// A), and the revoked bot's `hello` is refused `unauthorized`, `revoked`;
/// so it is with hosting back. A channel of it live when the loaded state
/// is first read (as one admitted before it) is fenced then, its
/// `control_gen` raised once.
#[test]
fn a_revoked_services_hello_stays_refused_across_a_restart() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = fed_bot(&mut rig, root, &os, start);
        feed(&mut rig, &s.log, &[&bot_record(&s.log, revoke(false), 2)]);
        r9_link_up(&mut rig);
        assert_eq!(
            refusal(service_hello(&mut rig, &s.log, "bot-1", "svc-bot")),
            revoked_refusal()
        );
        restart(&mut rig, root, &os, false, true);
        r9_link_up(&mut rig);
        // As the restart finds them while hosting is paused: the feeds not
        // loaded, nothing of the last run's in memory. The store keeps a
        // control state of this identity: it loads anyway (ruling T35d, A).
        let config = rig.bridge.work.config.clone();
        rig.bridge.work.feeds = Feeds::Unloaded;
        rig.bridge
            .r9
            .set_revoked_services(std::collections::HashSet::new());
        rig.bridge.work.config = Config::default();
        rig.bridge.work.config_problem = Some("expected a table".into());
        passes(&mut rig, 2);
        assert!(matches!(rig.bridge.work.feeds, Feeds::Loaded(_)));
        assert_eq!(
            refusal(service_hello(&mut rig, &s.log, "bot-2", "svc-bot")),
            revoked_refusal()
        );
        hello_as(&mut rig, &s.log, "phone-1", phone_identity()).unwrap();
        rig.bridge.work.config = config;
        rig.bridge.work.config_problem = None;
        passes(&mut rig, 2);
        assert!(matches!(rig.bridge.work.feeds, Feeds::Loaded(_)));
        assert_eq!(
            refusal(service_hello(&mut rig, &s.log, "bot-3", "svc-bot")),
            revoked_refusal()
        );
        // A channel of it live when the loaded state is read: as one
        // admitted before (the engine's set empty, its gate open).
        rig.bridge
            .r9
            .set_revoked_services(std::collections::HashSet::new());
        let _live = service_hello(&mut rig, &s.log, "bot-4", "svc-bot").unwrap();
        let before = rig.bridge.host.control_gen(BOT);
        passes(&mut rig, 2);
        assert!(!attached(&rig, BOT), "fenced at the read");
        assert_eq!(rig.bridge.host.control_gen(BOT), before + 1);
        assert_eq!(
            refusal(service_hello(&mut rig, &s.log, "bot-5", "svc-bot")),
            revoked_refusal()
        );
    });
}

/// Review m1: a revoke fences the service's live attachment once: its
/// `control_gen` raised by one, whatever reads the revoke first (the
/// record's followup, or the engine's revoked services).
#[test]
fn a_revoke_fences_a_live_service_once() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = fed_bot(&mut rig, root, &os, start);
        r9_link_up(&mut rig);
        let _live = service_hello(&mut rig, &s.log, "bot-1", "svc-bot").unwrap();
        let before = rig.bridge.host.control_gen(BOT);
        feed(&mut rig, &s.log, &[&bot_record(&s.log, revoke(false), 2)]);
        passes(&mut rig, 3);
        assert!(!attached(&rig, BOT));
        assert_eq!(rig.bridge.host.control_gen(BOT), before + 1);
    });
}

/// Review m2 (ruling T35c): with `host.delegated` off the r9 engine refuses
/// no service's `hello` for the control state, delegated rows in the store
/// or not (their feeds still load: hook off = main for session-v1): the
/// revoked bot is admitted, and so is it while the state doesn't read.
#[test]
fn with_the_hook_off_no_services_hello_is_refused_for_the_control_state() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = fed_bot(&mut rig, root, &os, start);
        let task = bot_task(&mut rig, &s, "HOOK_OFF_ROW", start + HOUR);
        assert!(stored_record(&rig, &task).delegated.is_some());
        feed(&mut rig, &s.log, &[&bot_record(&s.log, revoke(false), 2)]);
        // The hook removed: a restart's fresh engine, the feeds loaded again
        // for the delegated rows.
        rig.bridge.features = HostFeatures::default();
        rig.bridge
            .r9
            .set_revoked_services(std::collections::HashSet::new());
        rig.bridge.work.feeds = Feeds::Unloaded;
        r9_link_up(&mut rig);
        passes(&mut rig, 2);
        assert!(matches!(rig.bridge.work.feeds, Feeds::Loaded(_)));
        service_hello(&mut rig, &s.log, "bot-1", "svc-bot").unwrap();
        damage(&mut rig);
        passes(&mut rig, 2);
        service_hello(&mut rig, &s.log, "bot-2", "svc-bot").unwrap();
    });
}

/// Review m5 (design I.5.5 step 4, I.6.4): the runtime dies after a hold's
/// record committed and before the bridge withdrew the bot's attempt
/// waiting `accepted`. The restart withdraws it (`withdrawn at recovery`),
/// and it still isn't counted: the hold's cause was written with the
/// record. The task waits `paused`.
#[test]
fn a_holds_withdrawal_stays_uncounted_across_a_crash() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = covered_bot(&mut rig, root, &os, start);
        phone_running(&mut rig, &s, "CRASH_PHONE_RUNNING", start).await;
        let task = bot_task(&mut rig, &s, "CRASH_HELD", start + HOUR);
        blocked(&mut rig, &task, BEHIND).await;
        let attempt = attempt_behind_the_turn(&mut rig, &task, "CRASH_HELD");
        feed(
            &mut rig,
            &s.log,
            &[&bot_record(&s.log, ControlAction::Hold, 2)],
        );
        // The crash: the record committed, its followups never ran.
        rig.bridge.work.followups.clear();
        restart(&mut rig, root, &os, false, true);
        passes(&mut rig, 2);
        assert_eq!(
            attempts(&rig, &task),
            [(attempt, Some("withdrawn".into()), false)]
        );
        assert_eq!(settled(&rig, &task), outcome(Event::Held));
        assert!(!input(&rig).contains("CRASH_HELD"));
    });
}

/// The bot's task with its attempt waiting `accepted` behind the phone's
/// turn, then a hold and a release in one page (the hold's withdrawal asks
/// nothing: it was lifted at once): the task and its attempt.
async fn held_and_released(
    rig: &mut LocalRig,
    s: &Senders,
    prompt: &str,
    start: u64,
) -> (String, String) {
    phone_running(rig, s, &format!("{prompt}_PHONE"), start).await;
    let task = bot_task(rig, s, prompt, start + HOUR);
    blocked(rig, &task, BEHIND).await;
    let attempt = attempt_behind_the_turn(rig, &task, prompt);
    let hold = bot_record(&s.log, ControlAction::Hold, 2);
    let release = bot_record(&s.log, ControlAction::Release, 3);
    feed(rig, &s.log, &[&hold, &release]);
    (task, attempt)
}

/// Review N2 (ruling T35d): a release lifts the hold's not-counted mark on
/// the principal's live attempts in its transaction, so a later withdrawal
/// of one of them, for another cause (here its route changed), is counted.
#[test]
fn a_release_makes_a_later_withdrawal_count_again() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = covered_bot(&mut rig, root, &os, start);
        let (task, attempt) = held_and_released(&mut rig, &s, "RELEASED_ROUTE", start).await;
        passes(&mut rig, 1);
        assert_eq!(attempts(&rig, &task), [(attempt.clone(), None, true)]);
        rig.bridge
            .work
            .config
            .routes
            .iter_mut()
            .find(|r| r.id == "rs")
            .unwrap()
            .revision = 2;
        rig.until(|r| settled(r, &task).0 == WorkState::Failed)
            .await;
        assert_eq!(
            attempts(&rig, &task),
            [(attempt, Some("withdrawn".into()), true)]
        );
    });
}

/// Review N2 across a restart: after a hold and its release, the runtime
/// dies before the bridge saw the attempt again; the restart's withdrawal
/// (`withdrawn at recovery`) is counted.
#[test]
fn a_release_makes_a_withdrawal_at_recovery_count() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = covered_bot(&mut rig, root, &os, start);
        let (task, attempt) = held_and_released(&mut rig, &s, "RELEASED_CRASH", start).await;
        rig.bridge.work.followups.clear();
        restart(&mut rig, root, &os, false, true);
        passes(&mut rig, 2);
        assert_eq!(
            attempts(&rig, &task),
            [(attempt, Some("withdrawn".into()), true)]
        );
    });
}

/// Ruling T35d, A: hosting enabled, then switched off on purpose (and the
/// runtime started again so): the store, bound to this host's identity,
/// keeps a control state, which loads whatever hosting does. The revoked
/// bot stays refused (`unauthorized`, `revoked`); another service, not
/// revoked, is admitted.
#[test]
fn a_host_with_hosting_off_still_refuses_a_revoked_service_and_admits_another() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let mut s = fed_bot(&mut rig, root, &os, start);
        let entry = s.log.add_service(
            "svc-two",
            &["host"],
            None,
            &["notify", "prompt", "view"],
            start + 3 * HOUR,
        );
        carry(&mut rig, &s.log, entry);
        feed(&mut rig, &s.log, &[&bot_record(&s.log, revoke(false), 2)]);
        rig.bridge.work.config.enabled = false;
        assert!(!rig.bridge.hosting_enabled());
        r9_link_up(&mut rig);
        passes(&mut rig, 2);
        assert_eq!(
            refusal(service_hello(&mut rig, &s.log, "bot-1", "svc-bot")),
            revoked_refusal()
        );
        service_hello(&mut rig, &s.log, "two-1", "svc-two").unwrap();
        // A start with hosting off: nothing of the last run in memory.
        restart(&mut rig, root, &os, false, true);
        rig.bridge.work.config.enabled = false;
        r9_link_up(&mut rig);
        passes(&mut rig, 2);
        assert!(matches!(rig.bridge.work.feeds, Feeds::Loaded(_)));
        assert_eq!(
            refusal(service_hello(&mut rig, &s.log, "bot-2", "svc-bot")),
            revoked_refusal()
        );
        service_hello(&mut rig, &s.log, "two-2", "svc-two").unwrap();
    });
}

/// Ruling T35d, B: a fresh store (a first pairing) keeps its control state
/// unread until its first complete read of the host's own Station's feed:
/// services are `busy` until then (their `hello`s and their host-work
/// requests), and served once that read reached the announced head.
#[test]
fn services_are_busy_until_a_fresh_stores_first_complete_read() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = with_bot(&mut rig, root, &os, start + 3 * HOUR);
        rig.bridge.work.controls = None;
        rig.bridge.start_view().standings.clear();
        r9_link_up(&mut rig);
        passes(&mut rig, 1);
        assert_eq!(
            refusal(service_hello(&mut rig, &s.log, "bot-1", "svc-bot")),
            unchecked()
        );
        let bot = s.bot.clone();
        let profiles = hw::Request::Profiles {
            v: 1,
            id: uuid::Uuid::new_v4().to_string(),
            host: rig.bridge.work_host(),
        };
        assert_eq!(ask_req(&mut rig, &bot, &profiles), busy());
        hello_as(&mut rig, &s.log, "phone-1", phone_identity()).unwrap();
        // The first complete read (the cover, up to the announced head).
        feed(
            &mut rig,
            &s.log,
            &[&bot_record(&s.log, ControlAction::Cover, 1)],
        );
        passes(&mut rig, 1);
        service_hello(&mut rig, &s.log, "bot-2", "svc-bot").unwrap();
        assert!(matches!(
            ask_req(&mut rig, &bot, &profiles),
            Ok(ResultBody::Profiles { .. })
        ));
    });
}

/// Ruling T35d, A and B: on a hosting host (the hook on, hosting enabled) a
/// fresh store keeps a control state, never read, from the moment a pass's
/// `work_config` opens it, so no service's `hello` of that pass is admitted
/// before the pass's first load makes the control tables.
#[test]
fn a_hosting_hosts_fresh_store_keeps_a_control_state_from_its_open() {
    use std::os::unix::fs::PermissionsExt;
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let _s = with_bot(&mut rig, root, &os, start + 3 * HOUR);
        rig.bridge.work.controls = None;
        rig.bridge.start_view().standings.clear();
        // A first pairing's store: none yet, hosting enabled on disk.
        rig.bridge.work.store = None;
        for name in [
            "host-work.sqlite",
            "host-work.sqlite-wal",
            "host-work.sqlite-shm",
        ] {
            let _ = std::fs::remove_file(root.join("runtime").join(name));
        }
        rig.bridge.work.feeds = Feeds::Unloaded;
        rig.bridge.work.kept = None;
        let path = root.join("runtime.toml");
        std::fs::write(&path, "version = 1\nenabled = true\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        rig.bridge.work.available = true;
        rig.bridge.work.refresh = Instant::now();
        rig.bridge.work_config();
        assert!(rig.bridge.hosting_enabled());
        // As the pass's `hello`s see it, before its `work_pass` loads.
        rig.bridge.sync_services(&mut Cx {
            client: &rig.app.astation_client,
            sessions: &mut rig.sessions,
        });
        assert!(rig.bridge.controls_unchecked());
        assert!(rig.bridge.r9.services_unchecked());
    });
}

/// Ruling T35d, B: a re-verification (the next trust generation, the same
/// device list) starts a new store, unread: the revoked bot is never
/// admitted in between. Refused as revoked under the old store until it
/// is moved aside, `busy` while the new one is unread, and refused as
/// revoked again once the new store read its Station's feed from 0.
#[test]
fn a_reverify_never_admits_a_revoked_service_in_between() {
    use crate::session_protocol::membership::r9log::secret;
    use crate::session_protocol::membership::{HostPin, MembershipHost};
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let mut s = fed_bot(&mut rig, root, &os, start);
        let cover = bot_record(&s.log, ControlAction::Cover, 1);
        let revoked = bot_record(&s.log, revoke(false), 2);
        feed(&mut rig, &s.log, &[&revoked]);
        r9_link_up(&mut rig);
        assert_eq!(
            refusal(service_hello(&mut rig, &s.log, "bot-1", "svc-bot")),
            revoked_refusal()
        );
        // `atem pair verify`: the host's next trust generation on the same
        // list, pinned, and the session host rebound to it.
        s.log.add_host("host", 2, &secret("delegated host"));
        let pairing = crate::profile::Sources::in_dir(&root.join("profile"))
            .paths
            .pairing;
        MembershipHost::pin(
            &pairing,
            &rig.bridge.dir,
            &HostPin {
                host_id: "host".into(),
                host_trust_gen: 2,
            },
            &s.log.log,
            &secret("delegated host"),
        )
        .unwrap();
        let identity = crate::runtime::host_bridge::Identity {
            account_id: "acct".into(),
            atem_device_id: "host".into(),
            host_trust_gen: 2,
        };
        {
            let mut cx = Cx {
                client: &rig.app.astation_client,
                sessions: &mut rig.sessions,
            };
            rig.bridge.pairing = Some(pairing);
            rig.bridge.reopen_list_if_changed(&mut cx);
            rig.bridge.pairing = None;
            assert!(rig.bridge.adopt_identity(&identity, &mut cx));
        }
        let bot_hello = |rig: &mut LocalRig, handle: &str| {
            refusal(hello_at(
                rig,
                &s.log,
                handle,
                Identity::service("svc-bot", auth("svc-bot")),
                2,
            ))
        };
        for n in 0..3 {
            let refused = bot_hello(&mut rig, &format!("bot-a{n}"));
            assert!(
                refused == revoked_refusal() || refused == unchecked(),
                "{refused:?}"
            );
            passes(&mut rig, 1);
        }
        assert_eq!(
            bot_hello(&mut rig, "bot-b"),
            unchecked(),
            "the new store, unread"
        );
        hello_at(&mut rig, &s.log, "phone-1", phone_identity(), 2).unwrap();
        // The Station's feed read from 0 into the new store.
        feed(&mut rig, &s.log, &[&cover, &revoked]);
        passes(&mut rig, 1);
        assert_eq!(bot_hello(&mut rig, "bot-c"), revoked_refusal());
    });
}

/// Ruling T35e: hosting paused across a re-verify. The store, bound to the
/// old identity, keeps a control state at every hosting state, and the new
/// identity never read its feed: every service's `hello` is `busy` (the
/// revoked bot's and an unrevoked one's), a native's admitted, in the
/// running process and as a start finds it. Once hosting resumes and the
/// new store's first read completes, the unrevoked service is admitted and
/// the revoked one refused.
#[test]
fn a_reverify_while_hosting_is_paused_keeps_every_service_busy() {
    use crate::session_protocol::membership::r9log::secret;
    use crate::session_protocol::membership::{HostPin, MembershipHost};
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let mut s = fed_bot(&mut rig, root, &os, start);
        let entry = s.log.add_service(
            "svc-two",
            &["host"],
            None,
            &["notify", "prompt", "view"],
            start + 3 * HOUR,
        );
        carry(&mut rig, &s.log, entry);
        let cover = bot_record(&s.log, ControlAction::Cover, 1);
        let revoked = bot_record(&s.log, revoke(false), 2);
        feed(&mut rig, &s.log, &[&revoked]);
        r9_link_up(&mut rig);
        assert_eq!(
            refusal(service_hello(&mut rig, &s.log, "bot-1", "svc-bot")),
            revoked_refusal()
        );
        service_hello(&mut rig, &s.log, "two-1", "svc-two").unwrap();
        // Hosting paused, then `atem pair verify`: the host's next trust
        // generation on the same list, pinned, the session host rebound.
        rig.bridge.work.config.enabled = false;
        passes(&mut rig, 1);
        s.log.add_host("host", 2, &secret("delegated host"));
        let pairing = crate::profile::Sources::in_dir(&root.join("profile"))
            .paths
            .pairing;
        MembershipHost::pin(
            &pairing,
            &rig.bridge.dir,
            &HostPin {
                host_id: "host".into(),
                host_trust_gen: 2,
            },
            &s.log.log,
            &secret("delegated host"),
        )
        .unwrap();
        let identity = crate::runtime::host_bridge::Identity {
            account_id: "acct".into(),
            atem_device_id: "host".into(),
            host_trust_gen: 2,
        };
        {
            let mut cx = Cx {
                client: &rig.app.astation_client,
                sessions: &mut rig.sessions,
            };
            rig.bridge.pairing = Some(pairing);
            rig.bridge.reopen_list_if_changed(&mut cx);
            rig.bridge.pairing = None;
            assert!(rig.bridge.adopt_identity(&identity, &mut cx));
        }
        let hello = |rig: &mut LocalRig, handle: &str, device: &str| {
            refusal(hello_at(
                rig,
                &s.log,
                handle,
                Identity::service(device, auth(device)),
                2,
            ))
        };
        passes(&mut rig, 2);
        assert_eq!(hello(&mut rig, "bot-a", "svc-bot"), unchecked());
        assert_eq!(hello(&mut rig, "two-a", "svc-two"), unchecked());
        assert!(!attached(&rig, "service:svc-two"), "fenced");
        hello_at(&mut rig, &s.log, "phone-1", phone_identity(), 2).unwrap();
        // As a start finds it, hosting still paused: nothing of the run in
        // memory, the old identity's store on disk.
        rig.bridge.work.feeds = Feeds::Unloaded;
        rig.bridge.work.kept = None;
        rig.bridge.r9.set_revoked_services(Default::default());
        passes(&mut rig, 2);
        assert!(matches!(rig.bridge.work.feeds, Feeds::Unloaded));
        // `atem status` says why, with the way out.
        let link = rig
            .bridge
            .station
            .replace(crate::runtime::delegated::station::Station::new());
        let line = rig.bridge.feeds_status().unwrap_or_default();
        assert!(
            line.contains("until this host identity's own store is made"),
            "{line}"
        );
        rig.bridge.station = link;
        assert_eq!(hello(&mut rig, "bot-b", "svc-bot"), unchecked());
        assert_eq!(hello(&mut rig, "two-b", "svc-two"), unchecked());
        hello_at(&mut rig, &s.log, "phone-2", phone_identity(), 2).unwrap();
        // Hosting resumes: this identity's store, unread until the
        // Station's feed is read from 0 into it.
        rig.bridge.work.config.enabled = true;
        passes(&mut rig, 1);
        assert_eq!(
            hello(&mut rig, "two-c", "svc-two"),
            unchecked(),
            "the new store, unread"
        );
        feed(&mut rig, &s.log, &[&cover, &revoked]);
        passes(&mut rig, 1);
        hello_at(
            &mut rig,
            &s.log,
            "two-d",
            Identity::service("svc-two", auth("svc-two")),
            2,
        )
        .unwrap();
        assert_eq!(hello(&mut rig, "bot-d", "svc-bot"), revoked_refusal());
    });
}

/// Ruling T35f, m1: a new identity's store replaces the old one in one
/// step. A failure at any step of the swap (or a crash there: nothing is
/// undone, so the disk is as a crash just before that step leaves it)
/// leaves `host-work.sqlite` either the old identity's store, its control
/// state whole, or the new identity's, bound, with its control tables and
/// its unread mark; never no store, never one without control tables. A
/// start with hosting off then finds a control state kept: the revoked bot
/// stays refused (revoked, or every service `busy`).
#[test]
fn a_failed_store_swap_never_leaves_the_host_without_its_control_state() {
    for step in [
        "build", "bind", "prepare", "close", "link", "journal", "rename", "sync", "reopen",
    ] {
        local_test(async |root| {
            let mut rig = LocalRig::new(root).await;
            let start = host_now().wall_ms;
            let os = ManualOs::at(start);
            let s = fed_bot(&mut rig, root, &os, start);
            feed(&mut rig, &s.log, &[&bot_record(&s.log, revoke(false), 2)]);
            let old = rig.bridge.work_host();
            let new = HostTarget {
                host_trust_gen: old.host_trust_gen + 1,
                ..old.clone()
            };
            crate::runtime::host_work::fail_replace_at(Some(step));
            let swapped = rig.bridge.work_store_ready(&new);
            crate::runtime::host_work::fail_replace_at(None);
            assert!(!swapped, "{step}: the swap failed");
            // On disk, as a start finds it.
            let state = root.join("runtime");
            assert!(state.join("host-work.sqlite").exists(), "{step}: a store");
            let store = Store::open(&state).unwrap();
            assert!(
                FeedStore::kept_in(&store).unwrap(),
                "{step}: control tables"
            );
            let bound = store.bound().unwrap();
            let unread: bool = store
                .db
                .query_row("SELECT EXISTS(SELECT 1 FROM control_unread)", [], |r| {
                    r.get(0)
                })
                .unwrap();
            if bound.as_ref() == Some(&old) {
                let part: Option<String> = store
                    .db
                    .query_row(
                        "SELECT part FROM control_principals WHERE principal=?1",
                        [BOT],
                        |r| r.get(0),
                    )
                    .ok();
                assert!(part.is_some(), "{step}: the old state whole");
                assert!(!unread, "{step}");
            } else {
                assert_eq!(bound.as_ref(), Some(&new), "{step}: bound");
                assert!(unread, "{step}: the new store unread");
            }
            // A start with hosting off: the store opened, its control state
            // kept, and the revoked bot refused either way.
            rig.bridge.work.store = Some(store);
            rig.bridge.work.kept = None;
            rig.bridge.work.feeds = Feeds::Unloaded;
            rig.bridge.start_view().standings.clear();
            rig.bridge.read_kept();
            assert!(rig.bridge.keeps_controls(), "{step}");
            if rig.bridge.kept_here() {
                rig.bridge.ensure_feeds();
                assert!(!rig.bridge.controls_unchecked(), "{step}");
                assert!(
                    rig.bridge.start_view().standings[BOT].revoked.is_some(),
                    "{step}"
                );
            } else {
                assert!(rig.bridge.controls_unchecked(), "{step}: busy");
            }
        });
    }
}

/// The host's next trust generation on the same device list, pinned, and
/// the session host rebound to it (`atem pair verify`, as a runtime sees
/// it).
fn reverify(rig: &mut LocalRig, root: &Path, s: &mut Senders) {
    use crate::session_protocol::membership::r9log::secret;
    use crate::session_protocol::membership::{HostPin, MembershipHost};
    s.log.add_host("host", 2, &secret("delegated host"));
    let pairing = crate::profile::Sources::in_dir(&root.join("profile"))
        .paths
        .pairing;
    MembershipHost::pin(
        &pairing,
        &rig.bridge.dir,
        &HostPin {
            host_id: "host".into(),
            host_trust_gen: 2,
        },
        &s.log.log,
        &secret("delegated host"),
    )
    .unwrap();
    let identity = crate::runtime::host_bridge::Identity {
        account_id: "acct".into(),
        atem_device_id: "host".into(),
        host_trust_gen: 2,
    };
    let mut cx = Cx {
        client: &rig.app.astation_client,
        sessions: &mut rig.sessions,
    };
    rig.bridge.pairing = Some(pairing);
    rig.bridge.reopen_list_if_changed(&mut cx);
    rig.bridge.pairing = None;
    assert!(rig.bridge.adopt_identity(&identity, &mut cx));
}

/// Ruling T35f, m3: a fresh store (made with its control tables, never
/// bound) loads while hosting is paused, the host is verified again, and
/// hosting resumes: the store's first use binds it to the new identity,
/// whose control state it then keeps, so services are `busy` only until
/// its first complete read, then served (not `busy` until a restart).
#[test]
fn a_fresh_store_loaded_while_paused_then_reverified_serves_services_after_its_read() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let mut s = with_bot(&mut rig, root, &os, start + 3 * HOUR);
        rig.bridge.work.controls = None;
        rig.bridge.start_view().standings.clear();
        // A first pairing's store, made with its tables, never bound.
        let state = root.join("runtime");
        rig.bridge.work.store = None;
        let _ = std::fs::remove_file(state.join("host-work.sqlite"));
        let store = Store::open(&state).unwrap();
        FeedStore::prepare(&store).unwrap();
        assert_eq!(store.bound().unwrap(), None);
        rig.bridge.work.store = Some(store);
        rig.bridge.work.kept = None;
        rig.bridge.work.feeds = Feeds::Unloaded;
        // Hosting paused before its first pass: the store loads.
        rig.bridge.work.config.enabled = false;
        passes(&mut rig, 1);
        assert!(matches!(rig.bridge.work.feeds, Feeds::Loaded(_)));
        reverify(&mut rig, root, &mut s);
        r9_link_up(&mut rig);
        let hello = |rig: &mut LocalRig, handle: &str| {
            hello_at(
                rig,
                &s.log,
                handle,
                Identity::service("svc-bot", auth("svc-bot")),
                2,
            )
        };
        assert_eq!(refusal(hello(&mut rig, "bot-a")), unchecked());
        // Hosting resumes: the store's first use binds it to this identity.
        rig.bridge.work.config.enabled = true;
        passes(&mut rig, 1);
        let bound = rig.bridge.work.store.as_ref().unwrap().bound().unwrap();
        assert_eq!(bound, Some(rig.bridge.work_host()));
        assert_eq!(
            refusal(hello(&mut rig, "bot-b")),
            unchecked(),
            "unread until its first complete read"
        );
        feed(
            &mut rig,
            &s.log,
            &[&bot_record(&s.log, ControlAction::Cover, 1)],
        );
        passes(&mut rig, 1);
        hello(&mut rig, "bot-c").unwrap();
    });
}

/// Ruling T35f, m4 (§11.1 corrected): while hosting is paused across a
/// re-verify, an owner's command that opens the store (`atem task list
/// --unknown` here) moves the old identity's store aside and makes this
/// identity's, as hosting does; `atem status` names that way out. The new
/// store is this identity's, so it loads while paused, its first complete
/// read is made then, and services are served, hosting still paused.
#[test]
fn an_owner_command_while_paused_makes_this_identitys_store() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let mut s = fed_bot(&mut rig, root, &os, start);
        rig.bridge.work.config.enabled = false;
        passes(&mut rig, 1);
        reverify(&mut rig, root, &mut s);
        passes(&mut rig, 1);
        assert!(rig.bridge.kept_elsewhere());
        let link = rig
            .bridge
            .station
            .replace(crate::runtime::delegated::station::Station::new());
        let line = rig.bridge.feeds_status().unwrap_or_default();
        assert!(
            line.contains(
                "an owner command that opens the store, such as `atem task list --unknown`"
            ),
            "{line}"
        );
        rig.bridge.station = link;
        assert!(rig.bridge.owner_unknown_tasks().unwrap().is_empty());
        let bound = rig.bridge.work.store.as_ref().unwrap().bound().unwrap();
        assert_eq!(bound, Some(rig.bridge.work_host()));
        assert!(rig.bridge.kept_here());
        passes(&mut rig, 1);
        assert!(matches!(rig.bridge.work.feeds, Feeds::Loaded(_)));
        r9_link_up(&mut rig);
        let hello = |rig: &mut LocalRig, handle: &str| {
            hello_at(
                rig,
                &s.log,
                handle,
                Identity::service("svc-bot", auth("svc-bot")),
                2,
            )
        };
        assert_eq!(refusal(hello(&mut rig, "bot-a")), unchecked());
        feed(
            &mut rig,
            &s.log,
            &[&bot_record(&s.log, ControlAction::Cover, 1)],
        );
        passes(&mut rig, 1);
        assert!(!rig.bridge.hosting_enabled(), "still paused");
        hello(&mut rig, "bot-b").unwrap();
    });
}

/// The host's Station link up (generation `n`, the rig's r9 link with it)
/// and the link's sends kept: what the bridge's Station step hands it.
fn station_up(rig: &mut LocalRig, n: u64) -> crate::websocket_client::SentForTest {
    use crate::runtime::delegated::station::{LinkKind, Station};
    let mut station = Station::new();
    station.sync_link(Some(n), n, || LinkKind::Routed, || Some(ORIGIN.to_string()));
    rig.bridge.station = Some(station);
    rig.bridge.r9_link = Some(n);
    rig.app.astation_client.capture_sent_for_test()
}

/// Task 35 re-review 2, notes for Task 36 (1 to 3): while hosting is paused
/// across a re-verify, the store is the previous identity's: it takes no
/// page (nothing is asked for it, nothing applies into it) and sends no
/// ack, its unsent results included (never under the new identity's
/// claim). Hosting resumes: the new identity's store reads the feed from
/// 0 and acknowledges what it applied itself, under its own claim: the
/// cover applied before is `applied` again (Atem's reading: results per
/// identity; the Station counts per host, so nothing counts twice).
#[test]
fn another_identitys_store_takes_no_page_and_sends_no_ack() {
    use atem_client::control::{AckResult, ApplicationResult};
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let mut s = with_bot(&mut rig, root, &os, start + 3 * HOUR);
        rig.bridge.work.controls = None;
        rig.bridge.start_view().standings.clear();
        let cover = bot_record(&s.log, ControlAction::Cover, 1);
        // Read with no send loop: its result is owed, unsent.
        feed(&mut rig, &s.log, &[&cover]);
        let unsent = |rig: &LocalRig| -> i64 {
            rig.bridge
                .work
                .store
                .as_ref()
                .unwrap()
                .db
                .query_row(
                    "SELECT count(*) FROM control_acks WHERE sent_gen IS NULL",
                    [],
                    |r| r.get(0),
                )
                .unwrap()
        };
        assert_eq!(unsent(&rig), 1);
        rig.bridge.work.config.enabled = false;
        passes(&mut rig, 1);
        reverify(&mut rig, root, &mut s);
        passes(&mut rig, 1);
        assert!(rig.bridge.kept_elsewhere());
        let mut sent = station_up(&mut rig, 1);
        let heads = heads_text(&[(ORIGIN, OWN_FEED, 2)], s.log.log.head());
        station_pass(&mut rig, 0, vec![heads.clone()]);
        let page = page_text(&rig, 2, &[(2, &bot_record(&s.log, revoke(false), 2))]);
        station_pass(&mut rig, 100, vec![page]);
        assert!(
            sent.texts().is_empty(),
            "nothing asked, nothing acknowledged"
        );
        assert_eq!(unsent(&rig), 1, "still owed, never sent under gen 2");
        let cursor = match &rig.bridge.work.feeds {
            Feeds::Loaded(feeds) => feeds.cursor(ORIGIN, OWN_FEED),
            _ => None,
        };
        assert_eq!(cursor, Some(1), "nothing applied into it");
        // Hosting resumes: this identity's store, read from 0.
        rig.bridge.work.config.enabled = true;
        passes(&mut rig, 1);
        assert_eq!(
            unsent(&rig),
            0,
            "the old store's results went aside with it"
        );
        let mut sent = station_up(&mut rig, 2);
        station_pass(
            &mut rig,
            1_000,
            vec![heads_text(&[(ORIGIN, OWN_FEED, 1)], s.log.log.head())],
        );
        let page = page_text(&rig, 1, &[(1, &cover)]);
        station_pass(&mut rig, 1_100, vec![page]);
        let acks = acks_in(&sent.texts());
        assert_eq!(acks.len(), 1, "{acks:?}");
        assert_eq!(acks[0].host_trust_gen, 2);
        let AckResult::Record { record_id, effects } = &acks[0].results[0] else {
            panic!("a record's result");
        };
        assert_eq!(record_id, cover.record_id());
        assert_eq!(effects[0].result, ApplicationResult::Applied);
    });
}

/// Review m3 (ruling T36a; carry: "send a record's result only after the
/// revoke's session-v1 fence has run"): in the Station step that commits a
/// revoke of the bot, whose channel is live, the bot's attachments are
/// fenced before the revoke's ack is handed to the link.
#[test]
fn a_revokes_ack_goes_after_its_fence() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = fed_bot(&mut rig, root, &os, start);
        r9_link_up(&mut rig);
        service_hello(&mut rig, &s.log, "bot-1", "svc-bot").unwrap();
        assert!(attached(&rig, BOT));
        let mut sent = station_up(&mut rig, 7);
        let revoked = bot_record(&s.log, revoke(false), 2);
        let heads = heads_text(&[(ORIGIN, OWN_FEED, 2)], s.log.log.head());
        station_pass(&mut rig, 0, vec![heads]);
        let page = page_text(&rig, 2, &[(2, &revoked)]);
        station_pass(&mut rig, 100, vec![page]);
        let id = revoked.record_id().to_string();
        let (_, attached_then) = rig
            .bridge
            .work
            .acks_handed
            .iter()
            .find(|(ids, _)| ids.contains(&id))
            .expect("the revoke's ack handed to the link")
            .clone();
        assert!(
            !attached_then.iter().any(|p| p == BOT),
            "fenced before its ack: {attached_then:?}"
        );
        assert!(!attached(&rig, BOT));
        assert!(
            acks_in(&sent.texts())
                .iter()
                .any(|ack| ack.results.iter().any(|r| matches!(
                    r,
                    atem_client::control::AckResult::Record { record_id, .. } if *record_id == id
                )))
        );
    });
}

/// Ruling T35d, B (hook off = main): with `host.delegated` off a store
/// gets no control table and no unread mark, a pass and a new identity's
/// store included.
#[test]
fn with_the_hook_off_a_store_gets_no_control_table() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let (_phone, _log) = pin_phone_log(&mut rig, root);
        passes(&mut rig, 2);
        let tables = |rig: &LocalRig| -> Vec<String> {
            let db = &rig.bridge.work.store.as_ref().unwrap().db;
            let mut q = db
                .prepare("SELECT name FROM sqlite_master WHERE name LIKE 'control%'")
                .unwrap();
            q.query_map([], |r| r.get(0))
                .unwrap()
                .map(Result::unwrap)
                .collect()
        };
        assert!(tables(&rig).is_empty(), "{:?}", tables(&rig));
        let other = HostTarget {
            account_id: "acct".into(),
            atem_device_id: "host".into(),
            host_trust_gen: 9,
        };
        assert!(rig.bridge.work_store_ready(&other));
        assert!(tables(&rig).is_empty(), "{:?}", tables(&rig));
    });
}

/// Ruling T35d (re-review out-of-scope note 1): `atem status`'s `Control
/// feeds:` line says why services are refused, with the way out: a store
/// never read, a control state that doesn't read.
#[test]
fn atem_status_says_why_services_are_refused() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = with_bot(&mut rig, root, &os, start + 3 * HOUR);
        rig.bridge.work.controls = None;
        let line = |rig: &LocalRig| rig.bridge.feeds_status().unwrap_or_default();
        rig.bridge.station = Some(crate::runtime::delegated::station::Station::new());
        passes(&mut rig, 1);
        assert!(
            line(&rig).contains(
                "services are refused (busy) until this host's first complete read of its Station's control feed"
            ),
            "{}",
            line(&rig)
        );
        feed(
            &mut rig,
            &s.log,
            &[&bot_record(&s.log, ControlAction::Cover, 1)],
        );
        rig.bridge.station = Some(crate::runtime::delegated::station::Station::new());
        assert!(
            !line(&rig).contains("services are refused"),
            "{}",
            line(&rig)
        );
        damage(&mut rig);
        assert!(
            line(&rig).contains("services are refused (busy) until it reads"),
            "{}",
            line(&rig)
        );
    });
}

/// Ruling T35f, m2 (hook off = main): with `host.delegated` off (the hook
/// removed with delegated tasks left, so the feeds still load) a damaged
/// control state's status line says nothing of services, which are refused
/// nothing for it then; with it on, the line says they are.
#[test]
fn with_the_hook_off_the_damaged_line_says_nothing_of_services() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let _s = fed_bot(&mut rig, root, &os, start);
        damage(&mut rig);
        let line = rig.bridge.feeds_status().unwrap_or_default();
        assert!(line.contains("services are refused"), "{line}");
        rig.bridge.features = HostFeatures::default();
        let line = rig.bridge.feeds_status().unwrap_or_default();
        assert!(
            line.starts_with("the stored control state doesn't read"),
            "{line}"
        );
        assert!(!line.contains("services"), "{line}");
    });
}

/// Re-review out-of-scope note 2: a bridge opened with `host.delegated` on
/// starts refusing every service's `hello`, before any pass (fail closed
/// from the start); with it off it doesn't.
#[test]
fn a_bridge_opened_with_the_hook_starts_refusing_services() {
    local_test(async |root| {
        let on = HostBridge::open_with_features(
            &root.join("on/runtime/journal"),
            None,
            Clock::default(),
            HostFeatures::parse("host.delegated").unwrap(),
        )
        .unwrap();
        assert!(on.r9.services_unchecked());
        let off = HostBridge::open_with_features(
            &root.join("off/runtime/journal"),
            None,
            Clock::default(),
            HostFeatures::default(),
        )
        .unwrap();
        assert!(!off.r9.services_unchecked());
    });
}

/// The bot enqueues `prompt` through route `rs` while no feed covers it:
/// a v1 task (no admission record), its deadline `expires_at`.
fn bot_v1_task(rig: &mut LocalRig, s: &Senders, prompt: &str, expires_at: u64) -> String {
    let mut req = phone_enqueue(rig, prompt);
    if let hw::Request::Enqueue { route_id, task, .. } = &mut req {
        *route_id = "rs".into();
        task.expires_at = expires_at;
    }
    ask_req(rig, &s.bot, &req).unwrap();
    let id = enqueued(&req);
    assert!(stored_record(rig, &id).delegated.is_none(), "a v1 task");
    id
}

/// The bot, no feed covering it yet (the feeds alone decide, read once),
/// welcomed on channel `bot-1` (its control state granted), its v1 task of
/// `V1_BEHIND` queued behind the phone's turn, then its channel gone: the
/// phone's running task and the v1 task.
async fn a_v1_task_behind_the_phones_turn(
    rig: &mut LocalRig,
    s: &Senders,
    start: u64,
) -> (String, String) {
    rig.bridge.work.controls = None;
    rig.bridge.start_view().standings.clear();
    feed(rig, &s.log, &[]);
    assert!(matches!(rig.bridge.sender_class(BOT), SenderClass::V1));
    r9_link_up(rig);
    service_hello(rig, &s.log, "bot-1", "svc-bot").unwrap();
    let busy = phone_running(rig, s, "PHONE_BUSY", start).await;
    let v1 = bot_v1_task(rig, s, "V1_BEHIND", start + HOUR);
    blocked(rig, &v1, BEHIND).await;
    envelope_in(rig, &envelope::close("bot-1", Some("client_gone")));
    passes(rig, 1);
    assert!(!attached(rig, BOT));
    (busy, v1)
}

/// The v1 task ended `failed`, `sender's authority changed` (host-work-v1
/// §11.1: a v1 task the service had follows v1's rules, which the revoke's
/// fence ends), never run, and the session isn't held: the phone's turn
/// ends and a later task of the phone's runs on it.
async fn ended_by_the_fence(rig: &mut LocalRig, s: &Senders, busy: &str, v1: &str, start: u64) {
    rig.until(|r| settled(r, v1) == (WorkState::Failed, details::AUTHORITY_CHANGED.to_string()))
        .await;
    complete(rig, busy).await;
    let later = phone_task(rig, &s.phone, "PHONE_LATER", start + HOUR);
    run(rig, &later, "PHONE_LATER").await;
    assert!(!input(rig).contains("V1_BEHIND"));
}

/// Host-work-v1 §11.1 ("The effects on tasks, as built in step 4"; Task 37
/// review I1): a revoke of a service with no live channel still runs its
/// §H fence (`control_gen` raised), which ends the v1 task it had from
/// before its cover: `failed`, `sender's authority changed`; a later task
/// on that session then runs.
#[test]
fn a_revoke_ends_a_channelless_services_pre_cover_v1_task() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = with_bot(&mut rig, root, &os, start + 3 * HOUR);
        let (busy, v1) = a_v1_task_behind_the_phones_turn(&mut rig, &s, start).await;
        let before = rig.bridge.host.control_gen(BOT);
        feed(
            &mut rig,
            &s.log,
            &[
                &bot_record(&s.log, ControlAction::Cover, 1),
                &bot_record(&s.log, revoke(false), 2),
            ],
        );
        passes(&mut rig, 2);
        assert_eq!(rig.bridge.host.control_gen(BOT), before + 1);
        ended_by_the_fence(&mut rig, &s, &busy, &v1, start).await;
    });
}

/// Task 37 review I1 (ruling T37a), the crash between a revoke's commit and
/// its followups: the fence, a followup in memory, is lost with the run.
/// At the next start the loaded control state shows the service revoked
/// while the session host still grants it `control`: the fence is written
/// then, once, and the service's pre-cover v1 task ends as without the
/// crash (`failed`, `sender's authority changed`), not held until its
/// deadline; a later task on that session runs.
#[test]
fn a_revokes_fence_lost_to_a_crash_is_written_at_the_next_load() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = with_bot(&mut rig, root, &os, start + 3 * HOUR);
        let (busy, v1) = a_v1_task_behind_the_phones_turn(&mut rig, &s, start).await;
        let before = rig.bridge.host.control_gen(BOT);
        feed(
            &mut rig,
            &s.log,
            &[
                &bot_record(&s.log, ControlAction::Cover, 1),
                &bot_record(&s.log, revoke(false), 2),
            ],
        );
        // The run ends before the followups (the fence among them).
        assert!(
            rig.bridge.work.followups.iter().any(|f| matches!(
                f,
                crate::runtime::delegated::effects::Followup::Fence { .. }
            )),
            "{:?}",
            rig.bridge.work.followups
        );
        rig.bridge.work.followups.clear();
        assert_eq!(rig.bridge.host.control_gen(BOT), before);
        restart(&mut rig, root, &os, false, true);
        passes(&mut rig, 2);
        assert_eq!(rig.bridge.host.control_gen(BOT), before + 1);
        // The Station's feed read again: the gate open (for the phone's
        // later task).
        rig.bridge.start_view().gates.open_own_station(ORIGIN);
        ended_by_the_fence(&mut rig, &s, &busy, &v1, start).await;
        // Once: another start writes no fence more.
        restart(&mut rig, root, &os, false, true);
        passes(&mut rig, 2);
        assert_eq!(rig.bridge.host.control_gen(BOT), before + 1);
    });
}
