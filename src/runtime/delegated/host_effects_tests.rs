// Host senders' tasks and the device list's entries, in the bridge (design
// II.2.2, II.3.1, II.8; host-work-v1 §11.6): the rig's host with
// `host.delegated` and `host.senders` on, its list naming this host, host
// B and the phone, and a project `build` listing this host and B with a
// task's ops; route `rh` consents to `project:build`. These tests don't
// go through the mailbox: a host sender's task is the phone's task
// rewritten as B's (its admission frozen by `Admission::for_host`), as
// admission stores it. Included beside the other delegated tests, whose
// helpers and imports it shares.

use crate::runtime::delegated::DelegatedSender;
use crate::runtime::delegated::host_senders::{self, HostOp, HostSender, host_sender_permits};
use atem_client::membership::entry::Action as ListAction;
use atem_client::membership::{
    ProjectOp, host_sender_readmit, host_sender_revoke, project_remove, project_set,
};

const HOST_B: &str = "host:host-b";

/// The rig as a host-sender host (see the file's head): the list behind
/// it and the phone (whose tasks are rewritten as B's).
struct HostSenders {
    log: TestLog,
    phone: Authority,
}

fn host_senders_host(rig: &mut LocalRig, root: &Path, os: &ManualOs) -> HostSenders {
    use crate::session_protocol::membership::r9log::secret;
    use crate::session_protocol::membership::{HostPin, MembershipHost};
    rig.bridge.features = HostFeatures::parse("host.delegated,host.senders").unwrap();
    let mut log = TestLog::genesis("acct", &secret("delegated astation"));
    log.add_host("host", 1, &secret("delegated host"));
    log.add_native("dev-phone", &["control", "view"]);
    log.add_host("host-b", 1, &secret("host b"));
    log.append(
        MAC,
        project_set("build", ["host", "host-b"], task_ops(), 0).unwrap(),
    );
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
    for (id, principal) in [("rm", PHONE), ("rh", "project:build")] {
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
    rig.bridge.ensure_feeds();
    rig.bridge.start_view().gates.open_own_station(ORIGIN);
    let phone = resolve(
        &log,
        atem_client::channel::Principal::Native {
            device_id: "dev-phone".into(),
        },
    );
    HostSenders { log, phone }
}

fn task_ops() -> [ProjectOp; 3] {
    [ProjectOp::Message, ProjectOp::Notify, ProjectOp::Prompt]
}

/// Host B's task of `prompt` through route `rh`, its deadline
/// `expires_at`, admitted on the host's committed list now: its id.
fn host_task(rig: &mut LocalRig, s: &HostSenders, prompt: &str, expires_at: u64) -> String {
    let id = phone_task(rig, &s.phone, prompt, expires_at);
    let list = rig.bridge.membership.as_ref().unwrap().membership();
    let route = rig.bridge.work.config.route("rh").unwrap().clone();
    let sender = HostSender {
        host_id: "host-b",
        admitted: None,
    };
    let permit = host_sender_permits(list, "host", &sender, &route, HostOp::Task).unwrap();
    let admission = Admission::for_host(list, "host-b", &permit, "rh", 1).unwrap();
    let store = rig.bridge.work.store.as_ref().unwrap();
    let mut r = store.work(&id).unwrap().unwrap();
    r.principal = HOST_B.into();
    r.route_id = "rh".into();
    r.delegated = Some(admission);
    store.save_work(&r).unwrap();
    id
}

/// Host B's task runs (its turn journaled): its id.
async fn host_running(rig: &mut LocalRig, s: &HostSenders, prompt: &str, start: u64) -> String {
    let task = host_task(rig, s, prompt, start + HOUR);
    turn_journaled(rig, &task, prompt).await;
    task
}

/// `action`, signed into `s.log` by the Mac (a native manager), carried to
/// the host.
fn sign_and_carry(rig: &mut LocalRig, s: &mut HostSenders, action: ListAction) {
    let entry = s.log.append(MAC, action);
    carry(rig, &s.log, entry);
}

/// Host-work's applied device-list `seq`.
fn applied(rig: &LocalRig) -> u64 {
    let genesis = rig
        .bridge
        .membership
        .as_ref()
        .unwrap()
        .membership()
        .genesis_hash();
    host_senders::applied_seq(&rig.bridge.work.store.as_ref().unwrap().db, &genesis).unwrap()
}

/// Design II.3.1, II.8 (VII.B test 27): a `host_sender_revoke` of B
/// without `interrupt_running`, applied while B's tasks are queued, waiting
/// `accepted` and executing: host-work's own pass (its scheduling held, so
/// nothing else acts) cancels the queued one, `sender revoked`, in the
/// transaction that moves its applied `seq` to the entry; the one waiting
/// `accepted` is withdrawn after the commit and cancelled from that; the
/// executing one runs on, with no intent, and is kept awaiting its result.
#[test]
fn a_host_sender_revoke_cancels_unstarted_tasks_and_running_turns_go_on() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let mut s = host_senders_host(&mut rig, root, &os);
        let running = host_running(&mut rig, &s, "HS_REVOKE_RUNNING", start).await;
        let queued = host_task(&mut rig, &s, "HS_REVOKE_QUEUED", start + HOUR);
        let accepted = host_task(&mut rig, &s, "HS_REVOKE_ACCEPTED", start + HOUR);
        for task in [&queued, &accepted] {
            blocked(&mut rig, task, BEHIND).await;
        }
        let attempt = attempt_behind_the_turn(&mut rig, &accepted, "HS_REVOKE_ACCEPTED");
        let before = applied(&rig);
        hold_host_work(&mut rig);
        sign_and_carry(
            &mut rig,
            &mut s,
            host_sender_revoke("host-b", false, 0).unwrap(),
        );
        assert_eq!(applied(&rig), before, "the commit alone writes nothing");
        ticks(&mut rig, 1);
        assert_eq!(applied(&rig), s.log.log.head().seq);
        assert_eq!(settled(&rig, &queued), outcome(Event::Revoked));
        ticks(&mut rig, 1);
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
        assert_eq!(settled(&rig, &running).0, WorkState::Submitted);
        assert!(intents(&rig, &running).is_empty(), "no interrupt asked");
        rig.bridge.work.scheduled = Instant::now();
        complete(&mut rig, &running).await;
        passes(&mut rig, 3);
        assert_eq!(settled(&rig, &running).0, WorkState::AwaitingResult);
        let text = input(&rig);
        assert!(!text.contains("HS_REVOKE_QUEUED") && !text.contains("HS_REVOKE_ACCEPTED"));
        assert_eq!(escs(&rig), 0);
    });
}

/// Design II.3.1, I.5.7: a revoke with `interrupt_running` writes, in the
/// same transaction, an interrupt intent for B's started task (reason
/// `revoke`, the revoke's `seq`), none for its cancelled one; the turn is
/// interrupted once with host authority and reads `turn interrupted`.
#[test]
fn a_revoke_with_interrupt_running_interrupts_started_tasks() {
    use crate::runtime::delegated::intents::IntentReason;
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let mut s = host_senders_host(&mut rig, root, &os);
        let running = host_running(&mut rig, &s, "HS_INTERRUPT_RUNNING", start).await;
        let queued = host_task(&mut rig, &s, "HS_INTERRUPT_QUEUED", start + HOUR);
        blocked(&mut rig, &queued, BEHIND).await;
        hold_host_work(&mut rig);
        sign_and_carry(
            &mut rig,
            &mut s,
            host_sender_revoke("host-b", true, 0).unwrap(),
        );
        let revoke_seq = s.log.log.head().seq;
        ticks(&mut rig, 1);
        let stored = intents(&rig, &running);
        let [intent] = stored.as_slice() else {
            panic!("one intent: {stored:?}");
        };
        assert_eq!(
            (intent.attempt_id.as_str(), &intent.reason),
            (
                stored_record(&rig, &running).status.receipt_id.as_str(),
                &IntentReason::Revoke {
                    revocation: revoke_seq.to_string()
                }
            )
        );
        assert!(intents(&rig, &queued).is_empty());
        assert_eq!(settled(&rig, &queued), outcome(Event::Revoked));
        rig.bridge.work.scheduled = Instant::now();
        passes(&mut rig, 2);
        escs_delivered(&mut rig, 1).await;
        settle(&mut rig).await;
        passes(&mut rig, 3);
        assert_eq!(escs(&rig), 1, "once per turn");
        turn_interrupted(&mut rig, &running).await;
        rig.until(|r| settled(r, &running).0 == WorkState::AwaitingResult)
            .await;
        assert_eq!(settled(&rig, &running).1, "turn interrupted");
    });
}

/// Design II.2.2, II.8: `remove_host` of B cancels its unstarted task
/// (`sender revoked`) and leaves its running turn alone; a re-add (a new
/// epoch) doesn't bring the cancelled task back.
#[test]
fn a_remove_host_cancels_unstarted_tasks() {
    use crate::session_protocol::membership::r9log::secret;
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let mut s = host_senders_host(&mut rig, root, &os);
        let running = host_running(&mut rig, &s, "HS_REMOVE_RUNNING", start).await;
        let queued = host_task(&mut rig, &s, "HS_REMOVE_QUEUED", start + HOUR);
        blocked(&mut rig, &queued, BEHIND).await;
        hold_host_work(&mut rig);
        sign_and_carry(
            &mut rig,
            &mut s,
            ListAction::RemoveHost {
                host_id: "host-b".into(),
            },
        );
        ticks(&mut rig, 1);
        assert_eq!(settled(&rig, &queued), outcome(Event::Removed));
        assert_eq!(settled(&rig, &running).0, WorkState::Submitted);
        assert!(intents(&rig, &running).is_empty());
        s.log.add_host("host-b", 2, &secret("host b again"));
        let entry = s.log.entries.last().unwrap().object().to_json();
        carry(&mut rig, &s.log, entry);
        ticks(&mut rig, 1);
        assert_eq!(settled(&rig, &queued), outcome(Event::Removed));
        assert_eq!(applied(&rig), s.log.log.head().seq);
    });
}

/// Design II.2.2, II.8 (VII.B test 25): narrowing `build` to `message`
/// fails B's unstarted task (`sender's authorization narrowed`) and keeps
/// its task awaiting a result; a widening changes nothing; a
/// `project_remove` fails the next unstarted one the same way.
#[test]
fn a_narrowing_fails_unstarted_tasks_and_keeps_awaiting_ones() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let mut s = host_senders_host(&mut rig, root, &os);
        let awaiting = host_running(&mut rig, &s, "HS_NARROW_AWAITING", start).await;
        complete(&mut rig, &awaiting).await;
        let running = host_running(&mut rig, &s, "HS_NARROW_RUNNING", start).await;
        let queued = host_task(&mut rig, &s, "HS_NARROW_QUEUED", start + HOUR);
        blocked(&mut rig, &queued, BEHIND).await;
        hold_host_work(&mut rig);
        sign_and_carry(
            &mut rig,
            &mut s,
            project_set("build", ["host", "host-b"], [ProjectOp::Message], 0).unwrap(),
        );
        ticks(&mut rig, 1);
        assert_eq!(settled(&rig, &queued), outcome(Event::Narrowed));
        assert_eq!(settled(&rig, &awaiting).0, WorkState::AwaitingResult);
        assert_eq!(settled(&rig, &running).0, WorkState::Submitted);
        // Widened again: what failed stays failed, a new task is covered.
        sign_and_carry(
            &mut rig,
            &mut s,
            project_set("build", ["host", "host-b"], task_ops(), 0).unwrap(),
        );
        let next = host_task(&mut rig, &s, "HS_NARROW_NEXT", start + HOUR);
        ticks(&mut rig, 1);
        assert_eq!(settled(&rig, &queued), outcome(Event::Narrowed));
        assert_eq!(settled(&rig, &next).0, WorkState::Queued);
        sign_and_carry(&mut rig, &mut s, project_remove("build", 0).unwrap());
        ticks(&mut rig, 1);
        assert_eq!(settled(&rig, &next), outcome(Event::Narrowed));
        assert_eq!(settled(&rig, &awaiting).0, WorkState::AwaitingResult);
        assert_eq!(applied(&rig), s.log.log.head().seq);
    });
}

/// Design II.3.1, II.8, VII.B tests 29 and 32: a readmit leaves the
/// revoke's cancelled task cancelled, and a task admitted after it runs; a
/// newer `add_host` of B (re-verification) changes nothing: B's queued task
/// stays queued and runs.
#[test]
fn a_readmit_and_a_new_key_change_nothing() {
    use crate::session_protocol::membership::r9log::secret;
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let mut s = host_senders_host(&mut rig, root, &os);
        let running = host_running(&mut rig, &s, "HS_READMIT_RUNNING", start).await;
        let revoked = host_task(&mut rig, &s, "HS_READMIT_REVOKED", start + HOUR);
        blocked(&mut rig, &revoked, BEHIND).await;
        sign_and_carry(
            &mut rig,
            &mut s,
            host_sender_revoke("host-b", false, 0).unwrap(),
        );
        sign_and_carry(&mut rig, &mut s, host_sender_readmit("host-b", 0).unwrap());
        passes(&mut rig, 2);
        assert_eq!(settled(&rig, &revoked), outcome(Event::Revoked));
        // Admitted after the readmit, at its generation.
        let after = host_task(&mut rig, &s, "HS_READMIT_AFTER", start + HOUR);
        assert_eq!(
            stored_record(&rig, &after).delegated.unwrap().sender,
            DelegatedSender::Host {
                host_id: "host-b".into(),
                generation: s.log.log.head().seq,
                epoch: s.log.log.host_membership_epoch("host-b").unwrap(),
            }
        );
        // Re-verification: a newer `add_host`, no removal.
        s.log.add_host("host-b", 2, &secret("host b re-verified"));
        let entry = s.log.entries.last().unwrap().object().to_json();
        carry(&mut rig, &s.log, entry);
        passes(&mut rig, 2);
        assert_eq!(settled(&rig, &revoked), outcome(Event::Revoked));
        complete(&mut rig, &running).await;
        rig.until(|r| input(r).contains("HS_READMIT_AFTER")).await;
        complete(&mut rig, &after).await;
        assert!(!input(&rig).contains("HS_READMIT_REVOKED"));
        assert_eq!(applied(&rig), s.log.log.head().seq);
    });
}

/// Design II.3.1, "Crash safety": a revoke with `interrupt_running`
/// committed in the device list, and the runtime killed before host-work
/// wrote its effects. The next start replays them from host-work's applied
/// `seq` before its recovery: the queued task is cancelled, and the
/// running one's intent is written in time for the recovery's
/// interrupt-intent step, which carries it out. Nothing is written twice.
#[test]
fn a_crash_between_an_entry_and_its_effects_is_replayed_at_the_start() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let mut s = host_senders_host(&mut rig, root, &os);
        let running = host_running(&mut rig, &s, "HS_CRASH_RUNNING", start).await;
        let queued = host_task(&mut rig, &s, "HS_CRASH_QUEUED", start + HOUR);
        blocked(&mut rig, &queued, BEHIND).await;
        let before = applied(&rig);
        // Committed in the device list; no pass of host-work's runs.
        sign_and_carry(
            &mut rig,
            &mut s,
            host_sender_revoke("host-b", true, 0).unwrap(),
        );
        assert_eq!(applied(&rig), before);
        assert!(intents(&rig, &running).is_empty());
        let steps = restart(&mut rig, root, &os, false, true);
        assert_eq!(applied(&rig), s.log.log.head().seq);
        assert_eq!(settled(&rig, &queued), outcome(Event::Revoked));
        assert_eq!(intents(&rig, &running).len(), 1);
        let carried = steps.iter().find_map(|step| match step {
            RecoveryStep::PendingIntents(tasks) => Some(tasks.clone()),
            _ => None,
        });
        assert_eq!(carried, Some(vec![running.clone()]));
        // Applied again from the same `seq`: nothing new.
        let store = rig.bridge.work.store.as_ref().unwrap();
        let list = rig.bridge.membership.as_ref().unwrap().membership();
        let tx = store.immediate().unwrap();
        let again = host_senders::list_effects(store, &tx, list, "host", before).unwrap();
        tx.commit().unwrap();
        assert!(
            again.iter().all(|f| !matches!(
                f,
                crate::runtime::delegated::effects::Followup::Intents { .. }
            )),
            "{again:?}"
        );
        assert_eq!(intents(&rig, &running).len(), 1);
        assert_eq!(settled(&rig, &queued), outcome(Event::Revoked));
    });
}

/// A transaction that doesn't commit leaves nothing: neither the effects
/// nor the applied `seq` (they commit together).
#[test]
fn the_effects_and_the_applied_seq_commit_together() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let mut s = host_senders_host(&mut rig, root, &os);
        let queued = host_task(&mut rig, &s, "HS_TX_QUEUED", start + HOUR);
        hold_host_work(&mut rig);
        ticks(&mut rig, 1);
        let before = applied(&rig);
        let genesis = s.log.log.genesis_hash();
        sign_and_carry(
            &mut rig,
            &mut s,
            host_sender_revoke("host-b", false, 0).unwrap(),
        );
        {
            let store = rig.bridge.work.store.as_ref().unwrap();
            let list = rig.bridge.membership.as_ref().unwrap().membership();
            let tx = store.immediate().unwrap();
            host_senders::list_effects(store, &tx, list, "host", before).unwrap();
            host_senders::set_applied_seq(&tx, &genesis, list.head().seq).unwrap();
            drop(tx);
        }
        assert_eq!(applied(&rig), before);
        assert_ne!(settled(&rig, &queued), outcome(Event::Revoked));
        ticks(&mut rig, 1);
        assert_eq!(applied(&rig), s.log.log.head().seq);
        assert_eq!(settled(&rig, &queued), outcome(Event::Revoked));
    });
}

/// Hook off = main: with `host.delegated` alone no pass of host senders'
/// runs and its table is never made, whatever the device list carries.
#[test]
fn without_host_senders_no_effects_table_is_made() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let mut s = host_senders_host(&mut rig, root, &os);
        rig.bridge.features = HostFeatures::parse("host.delegated").unwrap();
        sign_and_carry(
            &mut rig,
            &mut s,
            host_sender_revoke("host-b", true, 0).unwrap(),
        );
        passes(&mut rig, 3);
        let made: bool = rig
            .bridge
            .work
            .store
            .as_ref()
            .unwrap()
            .db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='host_senders_applied')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(!made);
        assert_eq!(applied(&rig), 0);
    });
}

// ── A native manager's later `interrupt_running` about a host sender ──

/// A native manager's (the Mac's) `interrupt_running` record about host B,
/// for its revoke at `revoke_seq` (design II.3.1, "A later interrupt"):
/// bound to no feed, no principal key.
fn host_interrupt(log: &TestLog, revoke_seq: u64) -> atem_client::control::ControlRecord {
    use atem_client::control::{
        ControlAbout, ControlAction, ControlBody, ControlPrincipal, ControlRecord, ControlSigner,
        build_control,
    };
    let body = ControlBody {
        account_id: log.account.clone(),
        genesis_hash: log.genesis_hash(),
        feed: None,
        principal: ControlPrincipal::Host("host-b".into()),
        principal_key: None,
        signer: ControlSigner::Member(MAC.into()),
        action: ControlAction::InterruptRunning {
            revoke_seq: Some(revoke_seq),
        },
        record_id: uuid::Uuid::new_v4().to_string(),
        issued_at: host_now().wall_ms,
        about: ControlAbout {
            integration_id: None,
            by: "owner".into(),
        },
    };
    ControlRecord::from_signed(build_control(&log.keys, &auth(MAC), &body).unwrap()).unwrap()
}

/// What the host answered `records`, carried on the phone's channel: each
/// record's result and its interrupt effect's.
fn interrupt_results(
    results: &[atem_client::session::r9::RecordResult],
) -> Vec<(
    atem_client::control::ApplicationResult,
    atem_client::control::ApplicationResult,
)> {
    results
        .iter()
        .map(|r| {
            assert_eq!(r.effects.len(), 1, "{r:?}");
            (r.result, r.effects[0].result)
        })
        .collect()
}

/// Design II.3.1 ("A later interrupt"), I.5.7, VII.B test 27: after a
/// revoke without `interrupt_running` and a readmit, a native manager's
/// `interrupt_running` for that revoke, carried over a channel, writes an
/// intent for B's started task admitted before the revoke, and none for its
/// task admitted after the readmit (whose attempt waits `accepted`): the
/// first turn is interrupted once, then the later task runs. The same
/// record again, and another for the same revoke, are duplicates: nothing
/// more is written.
#[test]
fn a_later_interrupt_record_interrupts_only_tasks_admitted_before_the_revoke() {
    use crate::runtime::delegated::intents::IntentReason;
    use atem_client::control::ApplicationResult::{Applied, Duplicate};
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let mut s = host_senders_host(&mut rig, root, &os);
        let running = host_running(&mut rig, &s, "HS_LATER_RUNNING", start).await;
        sign_and_carry(
            &mut rig,
            &mut s,
            host_sender_revoke("host-b", false, 0).unwrap(),
        );
        let revoke_seq = s.log.log.head().seq;
        sign_and_carry(&mut rig, &mut s, host_sender_readmit("host-b", 0).unwrap());
        passes(&mut rig, 1);
        assert_eq!(settled(&rig, &running).0, WorkState::Submitted);
        let after = host_task(&mut rig, &s, "HS_LATER_AFTER", start + HOUR);
        blocked(&mut rig, &after, BEHIND).await;
        let attempt = attempt_behind_the_turn(&mut rig, &after, "HS_LATER_AFTER");
        let record = host_interrupt(&s.log, revoke_seq);
        let results = rig
            .bridge
            .apply_carried_records("member:dev-phone", std::slice::from_ref(&record))
            .unwrap();
        assert_eq!(results[0].record_id, record.record_id());
        assert_eq!(interrupt_results(&results), [(Applied, Applied)]);
        let stored = intents(&rig, &running);
        assert_eq!(
            stored.iter().map(|i| &i.reason).collect::<Vec<_>>(),
            [&IntentReason::Revoke {
                revocation: revoke_seq.to_string()
            }]
        );
        assert!(
            intents(&rig, &after).is_empty(),
            "admitted after the readmit"
        );
        passes(&mut rig, 2);
        escs_delivered(&mut rig, 1).await;
        settle(&mut rig).await;
        turn_interrupted(&mut rig, &running).await;
        rig.until(|r| settled(r, &running).0 == WorkState::AwaitingResult)
            .await;
        assert_eq!(settled(&rig, &running).1, "turn interrupted");
        let again = rig
            .bridge
            .apply_carried_records(
                "member:dev-phone",
                &[record, host_interrupt(&s.log, revoke_seq)],
            )
            .unwrap();
        assert_eq!(
            interrupt_results(&again),
            [(Duplicate, Duplicate), (Duplicate, Duplicate)]
        );
        assert_eq!(intents(&rig, &running).len(), 1);
        // The later task's attempt starts once the turn ended: it runs.
        rig.until(|r| input(r).contains("HS_LATER_AFTER")).await;
        assert_eq!(
            attempts(&rig, &after)[0].0,
            attempt,
            "its own attempt, never withdrawn"
        );
        assert_eq!(escs(&rig), 1);
    });
}

/// Host-work-v1 §11.1 rule 4 (design II.3.1): a host principal's interrupt
/// waits until host-work's applied device-list `seq` reaches its revoke,
/// whose cancellations are durable then: carried before the revoke's
/// effects were written, it is `pending`, and applies (its intent written)
/// in the pass that writes them. A revoke that carried `interrupt_running`
/// itself makes a later record for it a duplicate.
#[test]
fn an_interrupt_record_waits_for_its_revokes_effects() {
    use atem_client::control::ApplicationResult::{Duplicate, Pending};
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let mut s = host_senders_host(&mut rig, root, &os);
        let running = host_running(&mut rig, &s, "HS_WAIT_RUNNING", start).await;
        hold_host_work(&mut rig);
        sign_and_carry(
            &mut rig,
            &mut s,
            host_sender_revoke("host-b", false, 0).unwrap(),
        );
        let revoke_seq = s.log.log.head().seq;
        assert!(applied(&rig) < revoke_seq);
        let results = rig
            .bridge
            .apply_carried_records("member:dev-phone", &[host_interrupt(&s.log, revoke_seq)])
            .unwrap();
        assert_eq!(interrupt_results(&results), [(Pending, Pending)]);
        assert!(intents(&rig, &running).is_empty());
        ticks(&mut rig, 1);
        assert_eq!(applied(&rig), revoke_seq);
        assert_eq!(intents(&rig, &running).len(), 1, "applied once it may");
        // A revoke that asked for the interrupt itself.
        sign_and_carry(&mut rig, &mut s, host_sender_readmit("host-b", 0).unwrap());
        sign_and_carry(
            &mut rig,
            &mut s,
            host_sender_revoke("host-b", true, 0).unwrap(),
        );
        let second = s.log.log.head().seq;
        ticks(&mut rig, 1);
        let results = rig
            .bridge
            .apply_carried_records("member:dev-phone", &[host_interrupt(&s.log, second)])
            .unwrap();
        assert_eq!(interrupt_results(&results), [(Duplicate, Duplicate)]);
    });
}

/// Session-v1 R9.8, host-work-v1 §11.1 ("Carriage"): with `host.senders`
/// on, a native member's `control_records` reaches the runtime over its
/// channel and is answered there, `control_records_result` with one result
/// per record, after the records applied (the intent written).
#[test]
fn control_records_on_a_natives_channel_are_answered() {
    use atem_client::connect::Event as CEvent;
    use atem_client::control::ApplicationResult::Applied;
    use atem_client::session::r9::ControlRecordsResult;
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let mut s = host_senders_host(&mut rig, root, &os);
        rig.bridge.r9.set_delegated_features(true, false);
        rig.bridge.r9.set_senders_feature(true);
        rig.bridge.r9.enable_host_work(true);
        r9_link_up(&mut rig);
        let running = host_running(&mut rig, &s, "HS_CHANNEL_RUNNING", start).await;
        sign_and_carry(
            &mut rig,
            &mut s,
            host_sender_revoke("host-b", false, 0).unwrap(),
        );
        passes(&mut rig, 1);
        let mut ch = channel(&mut rig, &s.log, "ph-1", "dev-phone");
        assert!(
            ch.welcome()
                .features
                .iter()
                .any(|f| f == atem_client::session::host_work::SENDERS_FEATURE)
        );
        let record = host_interrupt(&s.log, s.log.log.head().seq);
        let (id, frame) = ch
            .send_control_records(std::slice::from_ref(&record), 2)
            .unwrap();
        envelope_in(&mut rig, &envelope::frame("ph-1", &frame));
        passes(&mut rig, 1);
        let mut answers = Vec::new();
        for frame in frames_for(&mut rig, "ph-1") {
            for event in ch.on_frame(&frame, 3).unwrap() {
                if let CEvent::Family(message) = event
                    && let Some(data) = message.data
                    && let Ok(result) = ControlRecordsResult::from_data(&data)
                {
                    answers.push(result);
                }
            }
        }
        let [answer] = answers.as_slice() else {
            panic!("one answer: {answers:?}");
        };
        assert_eq!(answer.re, id);
        assert_eq!(interrupt_results(&answer.results), [(Applied, Applied)]);
        assert_eq!(intents(&rig, &running).len(), 1);
    });
}

/// Design I.1.3, II.2.1 (never v1): with no device list open (none pinned
/// here; a frozen, held or faulted one isn't open either), a host sender is
/// refused, not v1, whatever the hook says; every other principal is v1
/// there, as on main.
#[test]
fn a_host_sender_is_refused_without_an_open_list() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        for features in ["", "host.delegated", "host.delegated,host.senders"] {
            rig.bridge.features = HostFeatures::parse(features).unwrap();
            assert!(rig.bridge.open_list().is_none());
            assert_eq!(rig.bridge.sender_class(HOST_B), SenderClass::Refused);
            assert_eq!(rig.bridge.sender_class("member:dev-phone"), SenderClass::V1);
        }
        let os = ManualOs::at(host_now().wall_ms);
        let _s = host_senders_host(&mut rig, root, &os);
        assert!(matches!(
            rig.bridge.sender_class(HOST_B),
            SenderClass::Delegated(DelegatedSender::Host { .. })
        ));
    });
}

/// Host B's results owed the Station (`control_acks`): none may be, by
/// host-work-v1 §11.4's acknowledgments (what the host's own Station's feed
/// delivered) and this rule: a record carried on a channel is answered on
/// its channel only.
fn acks_owed_for_host_b(rig: &LocalRig) -> i64 {
    rig.bridge
        .work
        .store
        .as_ref()
        .unwrap()
        .db
        .query_row(
            "SELECT count(*) FROM control_acks WHERE principal=?1",
            [HOST_B],
            |r| r.get(0),
        )
        .unwrap()
}

/// One rule for a record carried on a native's channel (design II.3.1,
/// host-work-v1 §11.4): its result is reported on that channel only, never
/// acknowledged to the Station, whether it applied at once or was pending
/// and applied at a later re-verification (the Station's own delivery of
/// the same record, if any, is acknowledged by that delivery).
#[test]
fn a_carried_records_result_goes_to_its_channel_only() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let mut s = host_senders_host(&mut rig, root, &os);
        let _running = host_running(&mut rig, &s, "HS_ACK_RUNNING", start).await;
        hold_host_work(&mut rig);
        sign_and_carry(
            &mut rig,
            &mut s,
            host_sender_revoke("host-b", false, 0).unwrap(),
        );
        let revoke_seq = s.log.log.head().seq;
        // Pending (the revoke's effects not written yet), then applied by
        // the pass's re-verification.
        let pending = host_interrupt(&s.log, revoke_seq);
        rig.bridge
            .apply_carried_records("member:dev-phone", std::slice::from_ref(&pending))
            .unwrap();
        ticks(&mut rig, 1);
        assert_eq!(applied(&rig), revoke_seq);
        assert!(
            rig.bridge
                .work
                .reapplied
                .iter()
                .any(|r| r.record.record_id() == pending.record_id()),
            "applied at the re-verification"
        );
        // Applied at once.
        rig.bridge
            .apply_carried_records("member:dev-phone", &[host_interrupt(&s.log, revoke_seq)])
            .unwrap();
        assert_eq!(acks_owed_for_host_b(&rig), 0);
    });
}

thread_local! {
    /// The statements this thread ran on a traced store.
    static HS_TRACED: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
}

fn hs_traced(sql: &str) {
    HS_TRACED.with(|t| t.borrow_mut().push(sql.to_string()));
}

/// Host-work's applied device-list `seq` is kept in memory once a pass
/// wrote (or read) it: a pass where the device list didn't move, and the
/// sync's and re-verification's reads of it, run no statement on its row.
#[test]
fn the_applied_seq_is_read_from_memory() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let mut s = host_senders_host(&mut rig, root, &os);
        hold_host_work(&mut rig);
        sign_and_carry(
            &mut rig,
            &mut s,
            host_sender_revoke("host-b", false, 0).unwrap(),
        );
        ticks(&mut rig, 1);
        assert_eq!(applied(&rig), s.log.log.head().seq);
        rig.bridge
            .work
            .store
            .as_mut()
            .unwrap()
            .db
            .trace(Some(hs_traced));
        HS_TRACED.with(|t| t.borrow_mut().clear());
        ticks(&mut rig, 3);
        let list = rig.bridge.start_view().list.clone().unwrap();
        assert_eq!(rig.bridge.host_applied_seq(&list), s.log.log.head().seq);
        let reads: Vec<String> = HS_TRACED.with(|t| {
            t.borrow()
                .iter()
                .filter(|sql| sql.contains("host_senders_applied"))
                .cloned()
                .collect()
        });
        assert!(reads.is_empty(), "{reads:?}");
    });
}

// ── Project entries judged per entry; the effects while paused; replay ──

/// `build` narrowed to `message` alone: a task's `notify` and `prompt` gone.
fn hs_narrowing() -> ListAction {
    project_set("build", ["host", "host-b"], [ProjectOp::Message], 0).unwrap()
}

/// `build` with a task's ops again, as before [`hs_narrowing`].
fn hs_restoring() -> ListAction {
    project_set("build", ["host", "host-b"], task_ops(), 0).unwrap()
}

/// `build` with every op: a widening of a task's.
fn hs_widening() -> ListAction {
    project_set(
        "build",
        ["host", "host-b"],
        [
            ProjectOp::Launch,
            ProjectOp::Message,
            ProjectOp::Notify,
            ProjectOp::Prompt,
        ],
        0,
    )
    .unwrap()
}

/// The owner's decision (2026-11-22; Astation's integration requirement,
/// #120 comment 7028723996, final readings item 9; host-work-v1 §11.6):
/// project entries are judged per entry, each on the device list as of
/// its `seq`. A narrowing and a restore that reach host-work's pass
/// together fail B's queued task at the narrowing, `sender's authorization
/// narrowed`, and it stays failed: neither the restore nor a later
/// widening revives it, and it never runs.
#[test]
fn a_narrowing_then_a_restore_in_one_catch_up_fails_the_task() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let mut s = host_senders_host(&mut rig, root, &os);
        let queued = host_task(&mut rig, &s, "HS_RESTORED_QUEUED", start + HOUR);
        hold_host_work(&mut rig);
        ticks(&mut rig, 1);
        sign_and_carry(&mut rig, &mut s, hs_narrowing());
        sign_and_carry(&mut rig, &mut s, hs_restoring());
        ticks(&mut rig, 1);
        assert_eq!(applied(&rig), s.log.log.head().seq);
        assert_eq!(settled(&rig, &queued), outcome(Event::Narrowed));
        sign_and_carry(&mut rig, &mut s, hs_widening());
        ticks(&mut rig, 1);
        assert_eq!(settled(&rig, &queued), outcome(Event::Narrowed));
        rig.bridge.work.scheduled = Instant::now();
        passes(&mut rig, 3);
        assert_eq!(settled(&rig, &queued), outcome(Event::Narrowed));
        assert!(!input(&rig).contains("HS_RESTORED_QUEUED"));
    });
}

/// As [`a_narrowing_then_a_restore_in_one_catch_up_fails_the_task`], for a
/// `project_remove` and a `project_set` that sets the project again.
#[test]
fn a_removal_then_a_re_set_in_one_catch_up_fails_the_task() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let mut s = host_senders_host(&mut rig, root, &os);
        let queued = host_task(&mut rig, &s, "HS_RESET_QUEUED", start + HOUR);
        hold_host_work(&mut rig);
        ticks(&mut rig, 1);
        sign_and_carry(&mut rig, &mut s, project_remove("build", 0).unwrap());
        sign_and_carry(&mut rig, &mut s, hs_restoring());
        ticks(&mut rig, 1);
        assert_eq!(applied(&rig), s.log.log.head().seq);
        assert_eq!(settled(&rig, &queued), outcome(Event::Narrowed));
        sign_and_carry(&mut rig, &mut s, hs_widening());
        ticks(&mut rig, 1);
        assert_eq!(settled(&rig, &queued), outcome(Event::Narrowed));
    });
}

/// Per entry, a widening alone stops nothing, and neither does a narrowing
/// that still covers the task (`build` widened, then back to a task's ops,
/// in one catch-up): B's task runs.
#[test]
fn a_widening_or_a_narrowing_that_still_covers_stops_nothing() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let mut s = host_senders_host(&mut rig, root, &os);
        let queued = host_task(&mut rig, &s, "HS_STILL_COVERED", start + HOUR);
        hold_host_work(&mut rig);
        ticks(&mut rig, 1);
        sign_and_carry(&mut rig, &mut s, hs_widening());
        ticks(&mut rig, 1);
        assert_eq!(applied(&rig), s.log.log.head().seq);
        assert_eq!(settled(&rig, &queued).0, WorkState::Queued, "a widening");
        sign_and_carry(&mut rig, &mut s, hs_widening());
        sign_and_carry(&mut rig, &mut s, hs_restoring());
        ticks(&mut rig, 1);
        assert_eq!(applied(&rig), s.log.log.head().seq);
        assert_eq!(
            settled(&rig, &queued).0,
            WorkState::Queued,
            "a narrowing that still covers it"
        );
        rig.bridge.work.scheduled = Instant::now();
        rig.until(|r| input(r).contains("HS_STILL_COVERED")).await;
    });
}

/// Per entry, a task is judged only on the entries after the device list
/// it was admitted on (`Admission::device_list_seq`): one admitted after a
/// narrowing and its restore committed, before host-work's pass wrote
/// their effects, was judged on a list that had both, and runs.
#[test]
fn a_task_admitted_after_the_entries_is_not_judged_on_them() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let mut s = host_senders_host(&mut rig, root, &os);
        hold_host_work(&mut rig);
        ticks(&mut rig, 1);
        let before = applied(&rig);
        sign_and_carry(&mut rig, &mut s, hs_narrowing());
        sign_and_carry(&mut rig, &mut s, hs_restoring());
        assert_eq!(applied(&rig), before);
        let after = host_task(&mut rig, &s, "HS_ADMITTED_AFTER", start + HOUR);
        ticks(&mut rig, 1);
        assert_eq!(applied(&rig), s.log.log.head().seq);
        assert_eq!(settled(&rig, &after).0, WorkState::Queued);
        rig.bridge.work.scheduled = Instant::now();
        rig.until(|r| input(r).contains("HS_ADMITTED_AFTER")).await;
    });
}

/// No start crosses an entry whose effects aren't written (the owner's
/// decision, 2026-11-22: no start may cross a missing stop): once a
/// narrowing and its restore committed, the start check (the dispatch's,
/// and the session host's at `executing`) holds B's task, `device list
/// update pending`, until host-work's pass wrote their effects, which fail
/// it; the committed head alone, which covers it again, never lets it
/// start.
#[test]
fn no_start_crosses_an_entry_whose_effects_arent_written() {
    use crate::runtime::delegated::start::{StartTask, may_start};
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let mut s = host_senders_host(&mut rig, root, &os);
        let queued = host_task(&mut rig, &s, "HS_NO_CROSSING", start + HOUR);
        hold_host_work(&mut rig);
        ticks(&mut rig, 1);
        // The view as a scheduling pass leaves it (`runtime.toml`'s routes).
        rig.bridge.refresh_start_view();
        let check = |rig: &LocalRig| {
            let task = StartTask::of(&stored_record(rig, &queued)).unwrap();
            let view = rig.bridge.start_view();
            may_start(&view, &task, view.now_d_ms)
        };
        assert_eq!(check(&rig), Ok(()));
        sign_and_carry(&mut rig, &mut s, hs_narrowing());
        sign_and_carry(&mut rig, &mut s, hs_restoring());
        assert_eq!(check(&rig), Err(Event::Deferred));
        ticks(&mut rig, 1);
        assert_eq!(settled(&rig, &queued), outcome(Event::Narrowed));
        // Written: a task admitted now starts.
        let next = host_task(&mut rig, &s, "HS_AFTER_CROSSING", start + HOUR);
        let task = StartTask::of(&stored_record(&rig, &next)).unwrap();
        let view = rig.bridge.start_view();
        assert_eq!(may_start(&view, &task, view.now_d_ms), Ok(()));
    });
}

/// Per entry, a live attempt is withdrawn as before: B's task whose
/// attempt waits `accepted` behind a turn, reached by a narrowing that a
/// restore follows in the same catch-up, is withdrawn after the commit and
/// fails from that; the running turn goes on.
#[test]
fn a_live_attempt_is_withdrawn_at_a_narrowing_a_restore_follows() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let mut s = host_senders_host(&mut rig, root, &os);
        let running = host_running(&mut rig, &s, "HS_LIVE_RUNNING", start).await;
        let accepted = host_task(&mut rig, &s, "HS_LIVE_ACCEPTED", start + HOUR);
        blocked(&mut rig, &accepted, BEHIND).await;
        let attempt = attempt_behind_the_turn(&mut rig, &accepted, "HS_LIVE_ACCEPTED");
        hold_host_work(&mut rig);
        sign_and_carry(&mut rig, &mut s, hs_narrowing());
        sign_and_carry(&mut rig, &mut s, hs_restoring());
        ticks(&mut rig, 1);
        assert_eq!(applied(&rig), s.log.log.head().seq);
        ticks(&mut rig, 1);
        assert_eq!(settled(&rig, &accepted), outcome(Event::Narrowed));
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
        assert_eq!(settled(&rig, &running).0, WorkState::Submitted);
        rig.bridge.work.scheduled = Instant::now();
        complete(&mut rig, &running).await;
        passes(&mut rig, 3);
        assert_eq!(settled(&rig, &accepted), outcome(Event::Narrowed));
        assert!(!input(&rig).contains("HS_LIVE_ACCEPTED"));
    });
}

/// A narrowing and a revoke of the same sender in one catch-up, in both
/// orders (the owner's decision, 2026-11-22): a task's first stop, in
/// `seq` order, is its outcome. B's queued task and its task whose attempt
/// waits `accepted` (withdrawn after the commit, settled from that) take
/// the first entry's; the running turn goes on.
#[test]
fn a_narrowing_and_a_revoke_in_one_catch_up_the_first_stop_wins() {
    let cases: [(&str, bool, Event); 2] = [
        ("the narrowing first", true, Event::Narrowed),
        ("the revoke first", false, Event::Revoked),
    ];
    for (what, narrowing_first, event) in cases {
        local_test(async |root| {
            let mut rig = LocalRig::new(root).await;
            let start = host_now().wall_ms;
            let os = ManualOs::at(start);
            let mut s = host_senders_host(&mut rig, root, &os);
            let running = host_running(&mut rig, &s, "HS_BOTH_RUNNING", start).await;
            let queued = host_task(&mut rig, &s, "HS_BOTH_QUEUED", start + HOUR);
            let accepted = host_task(&mut rig, &s, "HS_BOTH_ACCEPTED", start + HOUR);
            for task in [&queued, &accepted] {
                blocked(&mut rig, task, BEHIND).await;
            }
            let attempt = attempt_behind_the_turn(&mut rig, &accepted, "HS_BOTH_ACCEPTED");
            hold_host_work(&mut rig);
            let revoke = host_sender_revoke("host-b", false, 0).unwrap();
            if narrowing_first {
                sign_and_carry(&mut rig, &mut s, hs_narrowing());
                sign_and_carry(&mut rig, &mut s, revoke);
            } else {
                sign_and_carry(&mut rig, &mut s, revoke);
                sign_and_carry(&mut rig, &mut s, hs_narrowing());
            }
            ticks(&mut rig, 1);
            assert_eq!(applied(&rig), s.log.log.head().seq, "{what}");
            assert_eq!(settled(&rig, &queued), outcome(event), "{what}");
            ticks(&mut rig, 1);
            assert_eq!(settled(&rig, &accepted), outcome(event), "{what}");
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
                ),
                "{what}"
            );
            assert_eq!(settled(&rig, &running).0, WorkState::Submitted, "{what}");
        });
    }
}

/// Per entry, at a bounded cost: a catch-up of several project entries
/// reads the active tasks once (at its first project entry), the device
/// list as of each entry built on one pass over the log, nothing verified
/// again; each entry stops what the list as of it no longer covers (here
/// the first narrowing, so the later ones reach nothing).
#[test]
fn a_catch_up_of_project_entries_reads_the_active_tasks_once() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let mut s = host_senders_host(&mut rig, root, &os);
        let queued = host_task(&mut rig, &s, "HS_ONE_READ", start + HOUR);
        hold_host_work(&mut rig);
        ticks(&mut rig, 1);
        let before = applied(&rig);
        for _ in 0..3 {
            sign_and_carry(&mut rig, &mut s, hs_narrowing());
            sign_and_carry(&mut rig, &mut s, hs_restoring());
        }
        rig.bridge
            .work
            .store
            .as_mut()
            .unwrap()
            .db
            .trace(Some(hs_traced));
        HS_TRACED.with(|t| t.borrow_mut().clear());
        {
            let store = rig.bridge.work.store.as_ref().unwrap();
            let list = rig.bridge.membership.as_ref().unwrap().membership();
            let tx = store.immediate().unwrap();
            host_senders::list_effects(store, &tx, list, "host", before).unwrap();
            tx.commit().unwrap();
        }
        rig.bridge.work.store.as_mut().unwrap().db.trace(None);
        let reads = HS_TRACED.with(|t| {
            t.borrow()
                .iter()
                .filter(|sql| {
                    sql.contains("SELECT id,record FROM work WHERE state IN")
                        && !sql.contains("json_extract")
                })
                .count()
        });
        assert_eq!(reads, 1);
        assert_eq!(settled(&rig, &queued), outcome(Event::Narrowed));
    });
}

/// Design II.3.1, "Crash safety", per entry: a narrowing and its restore
/// committed in the device list, the runtime killed before host-work wrote
/// their effects. The next start replays them from host-work's applied
/// `seq`, entry by entry, before the recovery: B's queued task fails at
/// the narrowing. Applied again from the same `seq`, nothing is written to
/// it and nothing is asked; a later restore doesn't revive it.
#[test]
fn a_narrowing_and_its_restore_replayed_after_a_crash_stop_the_task_once() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let mut s = host_senders_host(&mut rig, root, &os);
        let queued = host_task(&mut rig, &s, "HS_REPLAY_RESTORED", start + HOUR);
        hold_host_work(&mut rig);
        ticks(&mut rig, 1);
        let before = applied(&rig);
        sign_and_carry(&mut rig, &mut s, hs_narrowing());
        sign_and_carry(&mut rig, &mut s, hs_restoring());
        assert_eq!(applied(&rig), before);
        let steps = restart(&mut rig, root, &os, false, true);
        assert_eq!(applied(&rig), s.log.log.head().seq);
        assert_eq!(settled(&rig, &queued), outcome(Event::Narrowed));
        assert!(
            !reconciled_at_recovery(&steps, &queued),
            "settled by the replay, before the recovery"
        );
        let stored = serde_json::to_value(stored_record(&rig, &queued)).unwrap();
        rig.bridge
            .work
            .store
            .as_mut()
            .unwrap()
            .db
            .trace(Some(hs_traced));
        HS_TRACED.with(|t| t.borrow_mut().clear());
        let again = {
            let store = rig.bridge.work.store.as_ref().unwrap();
            let list = rig.bridge.membership.as_ref().unwrap().membership();
            let tx = store.immediate().unwrap();
            let again = host_senders::list_effects(store, &tx, list, "host", before).unwrap();
            tx.commit().unwrap();
            again
        };
        rig.bridge.work.store.as_mut().unwrap().db.trace(None);
        assert!(again.is_empty(), "{again:?}");
        let writes: Vec<String> = HS_TRACED.with(|t| {
            t.borrow()
                .iter()
                .filter(|sql| sql.contains("UPDATE work") || sql.contains("INSERT INTO work"))
                .cloned()
                .collect()
        });
        assert!(writes.is_empty(), "{writes:?}");
        assert_eq!(
            serde_json::to_value(stored_record(&rig, &queued)).unwrap(),
            stored
        );
        sign_and_carry(&mut rig, &mut s, hs_widening());
        ticks(&mut rig, 1);
        assert_eq!(applied(&rig), s.log.log.head().seq);
        assert_eq!(settled(&rig, &queued), outcome(Event::Narrowed));
    });
}

/// Design II.3.1, I.4.4 ("a stop always wins"): with hosting paused
/// (`enabled = false`), host senders' device-list effects are still
/// written and their stops carried out: a revoke with `interrupt_running`
/// cancels a queued task and interrupts the running turn.
#[test]
fn device_list_effects_run_while_hosting_is_paused() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let mut s = host_senders_host(&mut rig, root, &os);
        let running = host_running(&mut rig, &s, "HS_PAUSED_RUNNING", start).await;
        let queued = host_task(&mut rig, &s, "HS_PAUSED_QUEUED", start + HOUR);
        blocked(&mut rig, &queued, BEHIND).await;
        rig.bridge.work.config.enabled = false;
        passes(&mut rig, 1);
        assert!(!rig.bridge.hosting_enabled());
        sign_and_carry(
            &mut rig,
            &mut s,
            host_sender_revoke("host-b", true, 0).unwrap(),
        );
        passes(&mut rig, 1);
        assert_eq!(applied(&rig), s.log.log.head().seq);
        assert_eq!(settled(&rig, &queued), outcome(Event::Revoked));
        assert_eq!(intents(&rig, &running).len(), 1);
        passes(&mut rig, 2);
        escs_delivered(&mut rig, 1).await;
        settle(&mut rig).await;
        turn_interrupted(&mut rig, &running).await;
        assert_eq!(escs(&rig), 1);
    });
}

/// A `control_records` call taken from a native's channel before hosting
/// paused is applied and answered while it is paused (a stop always wins).
#[test]
fn a_carried_record_is_answered_while_hosting_is_paused() {
    use atem_client::connect::Event as CEvent;
    use atem_client::control::ApplicationResult::Applied;
    use atem_client::session::r9::ControlRecordsResult;
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let mut s = host_senders_host(&mut rig, root, &os);
        rig.bridge.r9.set_delegated_features(true, false);
        rig.bridge.r9.set_senders_feature(true);
        rig.bridge.r9.enable_host_work(true);
        r9_link_up(&mut rig);
        let running = host_running(&mut rig, &s, "HS_PAUSED_CARRIED", start).await;
        sign_and_carry(
            &mut rig,
            &mut s,
            host_sender_revoke("host-b", false, 0).unwrap(),
        );
        passes(&mut rig, 1);
        let mut ch = channel(&mut rig, &s.log, "ph-1", "dev-phone");
        let record = host_interrupt(&s.log, s.log.log.head().seq);
        let (id, frame) = ch
            .send_control_records(std::slice::from_ref(&record), 2)
            .unwrap();
        envelope_in(&mut rig, &envelope::frame("ph-1", &frame));
        rig.bridge.work.config.enabled = false;
        passes(&mut rig, 1);
        assert!(!rig.bridge.hosting_enabled());
        let mut answers = Vec::new();
        for frame in frames_for(&mut rig, "ph-1") {
            for event in ch.on_frame(&frame, 3).unwrap() {
                if let CEvent::Family(message) = event
                    && let Some(data) = message.data
                    && let Ok(result) = ControlRecordsResult::from_data(&data)
                {
                    answers.push(result);
                }
            }
        }
        let [answer] = answers.as_slice() else {
            panic!("one answer: {answers:?}");
        };
        assert_eq!(answer.re, id);
        assert_eq!(interrupt_results(&answer.results), [(Applied, Applied)]);
        assert_eq!(intents(&rig, &running).len(), 1);
    });
}

/// The recovery step a task was settled in, if any (its `Reconcile` list).
fn reconciled_at_recovery(steps: &[RecoveryStep], task: &str) -> bool {
    steps.iter().any(|step| match step {
        RecoveryStep::Reconcile(tasks) => tasks.iter().any(|t| t.task_id == task),
        _ => false,
    })
}

/// Design II.3.1, "Crash safety", for every entry kind: a narrowing, a
/// `remove_host`, and a revoke with its readmit, each committed in the
/// device list with the runtime killed before host-work wrote its effects:
/// the next start replays them from host-work's applied `seq`, before the
/// recovery (which then finds the tasks settled already).
#[test]
fn every_entry_kind_is_replayed_after_a_crash() {
    type Change = fn(&mut HostSenders, &mut LocalRig);
    let cases: [(&str, Change, Event); 3] = [
        (
            "a narrowing",
            |s, rig| {
                sign_and_carry(
                    rig,
                    s,
                    project_set("build", ["host", "host-b"], [ProjectOp::Message], 0).unwrap(),
                )
            },
            Event::Narrowed,
        ),
        (
            "a removal",
            |s, rig| {
                sign_and_carry(
                    rig,
                    s,
                    ListAction::RemoveHost {
                        host_id: "host-b".into(),
                    },
                )
            },
            Event::Removed,
        ),
        (
            "a revoke and a readmit",
            |s, rig| {
                sign_and_carry(rig, s, host_sender_revoke("host-b", false, 0).unwrap());
                sign_and_carry(rig, s, host_sender_readmit("host-b", 0).unwrap());
            },
            Event::Revoked,
        ),
    ];
    for (what, change, event) in cases {
        local_test(async |root| {
            let mut rig = LocalRig::new(root).await;
            let start = host_now().wall_ms;
            let os = ManualOs::at(start);
            let mut s = host_senders_host(&mut rig, root, &os);
            let queued = host_task(&mut rig, &s, "HS_REPLAY_QUEUED", start + HOUR);
            hold_host_work(&mut rig);
            ticks(&mut rig, 1);
            let before = applied(&rig);
            change(&mut s, &mut rig);
            assert_eq!(applied(&rig), before, "{what}");
            let steps = restart(&mut rig, root, &os, false, true);
            assert_eq!(applied(&rig), s.log.log.head().seq, "{what}");
            assert_eq!(settled(&rig, &queued), outcome(event), "{what}");
            assert!(
                !reconciled_at_recovery(&steps, &queued),
                "{what}: settled by the replay, before the recovery"
            );
        });
    }
}

/// Design II.3.1 ("admitted before"): replaying an older revoke or removal
/// leaves the sender's tasks admitted after its readmit or re-add alone.
#[test]
fn a_replay_leaves_tasks_admitted_after_a_readmit_or_a_re_add() {
    use crate::session_protocol::membership::r9log::secret;
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let mut s = host_senders_host(&mut rig, root, &os);
        hold_host_work(&mut rig);
        ticks(&mut rig, 1);
        // A revoke and its readmit committed, host-work's pass not run yet:
        // a task admitted after the readmit, then the pass.
        sign_and_carry(
            &mut rig,
            &mut s,
            host_sender_revoke("host-b", true, 0).unwrap(),
        );
        sign_and_carry(&mut rig, &mut s, host_sender_readmit("host-b", 0).unwrap());
        let after_readmit = host_task(&mut rig, &s, "HS_AFTER_READMIT", start + HOUR);
        ticks(&mut rig, 1);
        assert_eq!(applied(&rig), s.log.log.head().seq);
        assert_eq!(settled(&rig, &after_readmit).0, WorkState::Queued);
        assert!(intents(&rig, &after_readmit).is_empty());
        // A removal and a re-add (with a project listing it again).
        sign_and_carry(
            &mut rig,
            &mut s,
            ListAction::RemoveHost {
                host_id: "host-b".into(),
            },
        );
        s.log.add_host("host-b", 2, &secret("host b re-added"));
        let entry = s.log.entries.last().unwrap().object().to_json();
        carry(&mut rig, &s.log, entry);
        sign_and_carry(
            &mut rig,
            &mut s,
            project_set("build", ["host", "host-b"], task_ops(), 0).unwrap(),
        );
        let after_re_add = host_task(&mut rig, &s, "HS_AFTER_RE_ADD", start + HOUR);
        ticks(&mut rig, 1);
        assert_eq!(applied(&rig), s.log.log.head().seq);
        assert_eq!(settled(&rig, &after_re_add).0, WorkState::Queued);
        // The earlier one, admitted before the removal, is cancelled.
        assert_eq!(settled(&rig, &after_readmit), outcome(Event::Removed));
        // Host-work's scheduling back: the task admitted after the re-add
        // runs.
        rig.bridge.work.scheduled = Instant::now();
        rig.until(|r| input(r).contains("HS_AFTER_RE_ADD")).await;
    });
}

/// A `host_senders_applied` row naming another device list is damage (a
/// store is one identity's, its list's): host senders' pass refuses it as
/// a receipt-database fault, writing nothing, never restarting the count.
#[test]
fn another_lists_applied_seq_is_a_fault() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let mut s = host_senders_host(&mut rig, root, &os);
        let queued = host_task(&mut rig, &s, "HS_OTHER_LIST", start + HOUR);
        {
            let store = rig.bridge.work.store.as_ref().unwrap();
            let tx = store.immediate().unwrap();
            let other = atem_client::encoding::Hash32([9; 32]);
            host_senders::set_applied_seq(&tx, &other, 1).unwrap();
            tx.commit().unwrap();
        }
        sign_and_carry(
            &mut rig,
            &mut s,
            host_sender_revoke("host-b", false, 0).unwrap(),
        );
        hold_host_work(&mut rig);
        ticks(&mut rig, 1);
        assert!(rig.bridge.work.error, "a receipt-database fault");
        assert_ne!(settled(&rig, &queued), outcome(Event::Revoked));
        let genesis = s.log.log.genesis_hash();
        assert!(
            host_senders::applied_seq(&rig.bridge.work.store.as_ref().unwrap().db, &genesis)
                .is_err()
        );
    });
}

/// A stop always wins (as `work_interrupt`'s): while hosting is paused, a
/// native's `interrupt_running` about host B, sent during the pause on its
/// channel welcomed with `host.senders` before it, is answered and its
/// intent written.
#[test]
fn a_carried_record_sent_during_the_pause_is_answered() {
    use atem_client::connect::Event as CEvent;
    use atem_client::control::ApplicationResult::Applied;
    use atem_client::session::r9::ControlRecordsResult;
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let mut s = host_senders_host(&mut rig, root, &os);
        rig.bridge.r9.set_delegated_features(true, false);
        rig.bridge.r9.set_senders_feature(true);
        rig.bridge.r9.enable_host_work(true);
        r9_link_up(&mut rig);
        let running = host_running(&mut rig, &s, "HS_DURING_PAUSE", start).await;
        sign_and_carry(
            &mut rig,
            &mut s,
            host_sender_revoke("host-b", false, 0).unwrap(),
        );
        passes(&mut rig, 1);
        let mut ch = channel(&mut rig, &s.log, "ph-1", "dev-phone");
        // Hosting paused (the runtime's `work_config` does both).
        rig.bridge.work.config.enabled = false;
        rig.bridge.r9.enable_host_work(false);
        passes(&mut rig, 1);
        assert!(!rig.bridge.hosting_enabled());
        let record = host_interrupt(&s.log, s.log.log.head().seq);
        let (id, frame) = ch
            .send_control_records(std::slice::from_ref(&record), 2)
            .unwrap();
        envelope_in(&mut rig, &envelope::frame("ph-1", &frame));
        passes(&mut rig, 1);
        let mut answers = Vec::new();
        for frame in frames_for(&mut rig, "ph-1") {
            for event in ch.on_frame(&frame, 3).unwrap() {
                if let CEvent::Family(message) = event
                    && let Some(data) = message.data
                    && let Ok(result) = ControlRecordsResult::from_data(&data)
                {
                    answers.push(result);
                }
            }
        }
        let [answer] = answers.as_slice() else {
            panic!("one answer: {answers:?}");
        };
        assert_eq!(answer.re, id);
        assert_eq!(interrupt_results(&answer.results), [(Applied, Applied)]);
        assert_eq!(intents(&rig, &running).len(), 1);
    });
}

/// Host B's results owed the host's own Station: each row's `effects` as
/// the book keeps them.
fn acks_for_host_b(rig: &LocalRig) -> Vec<String> {
    let db = &rig.bridge.work.store.as_ref().unwrap().db;
    let mut q = db
        .prepare("SELECT effects FROM control_acks WHERE principal=?1")
        .unwrap();
    q.query_map([HOST_B], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

/// Host-work-v1 §11.1 "Carriage": the host's own Station's feed delivering
/// a record a channel carried. While that record is still `pending` from
/// the carrier, the feed's delivery adopts it (its source and position are
/// the feed's from then on), so its final result is acknowledged to the
/// Station as any feed record's is; once it is final, the feed's delivery
/// is acknowledged at that delivery (a `duplicate`). The channel had its
/// answer either way.
#[test]
fn a_feed_delivery_of_a_carried_record_is_acknowledged() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let mut s = host_senders_host(&mut rig, root, &os);
        let running = host_running(&mut rig, &s, "HS_FEED_ADOPTS", start).await;
        hold_host_work(&mut rig);
        sign_and_carry(
            &mut rig,
            &mut s,
            host_sender_revoke("host-b", false, 0).unwrap(),
        );
        let revoke_seq = s.log.log.head().seq;
        // Carried while its revoke's effects aren't written: pending.
        let record = host_interrupt(&s.log, revoke_seq);
        rig.bridge
            .apply_carried_records("member:dev-phone", std::slice::from_ref(&record))
            .unwrap();
        assert!(acks_for_host_b(&rig).is_empty());
        // The Station's feed delivers it, still pending: that delivery's
        // ack says so.
        feed(&mut rig, &s.log, &[&record]);
        let acks = acks_for_host_b(&rig);
        assert_eq!(acks.len(), 1, "{acks:?}");
        assert!(acks[0].contains("pending"), "{acks:?}");
        // It applies at the re-verification: its final result is owed the
        // Station.
        ticks(&mut rig, 1);
        assert_eq!(intents(&rig, &running).len(), 1);
        let acks = acks_for_host_b(&rig);
        assert_eq!(acks.len(), 1, "{acks:?}");
        assert!(
            acks[0].contains("\"applied\"") && !acks[0].contains("pending"),
            "{acks:?}"
        );
        // Carried once final (applied at once: a duplicate), then delivered
        // by the feed: acknowledged at that delivery.
        let later = host_interrupt(&s.log, revoke_seq);
        let results = rig
            .bridge
            .apply_carried_records("member:dev-phone", std::slice::from_ref(&later))
            .unwrap();
        assert_eq!(
            interrupt_results(&results),
            [(
                atem_client::control::ApplicationResult::Duplicate,
                atem_client::control::ApplicationResult::Duplicate
            )]
        );
        assert_eq!(acks_for_host_b(&rig).len(), 1, "not for the channel's");
        feed(&mut rig, &s.log, &[&later]);
        let acks = acks_for_host_b(&rig);
        assert_eq!(acks.len(), 2, "{acks:?}");
        assert!(acks.iter().any(|a| a.contains("duplicate")), "{acks:?}");
    });
}
