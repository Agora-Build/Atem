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
        // The feeds alone decide (no control view standing in).
        rig.bridge.work.controls = None;
        rig.bridge.start_view().standings.clear();
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
    rig.bridge.r9.reset_init_limiter();
    envelope_in(rig, &envelope::open(handle, Transport::Relay));
    let identity = Identity::service(device, auth(device));
    let (connecting, init) = Connector::new("host").start(&log.log, 1).unwrap();
    envelope_in(rig, &envelope::frame(handle, &init));
    let accept = frames_for(rig, handle).remove(0);
    let (welcoming, finish) = connecting
        .on_accept(&accept, &log.log, &log.keys, &identity, 1)
        .unwrap();
    envelope_in(rig, &envelope::frame(handle, &finish));
    let welcome = frames_for(rig, handle).remove(0);
    welcoming.on_frame(&welcome, &log.log, 1)
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
