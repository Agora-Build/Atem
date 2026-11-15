// Host senders' tasks and the device list's entries, in the bridge (design
// II.2.2, II.3.1, II.8; host-work-v1 §11.6): the rig's host with
// `host.delegated` and `host.senders` on, its list naming this host, host
// B and the phone, and a project `build` listing this host and B with a
// task's ops; route `rh` consents to `project:build`. Mailbox admission
// isn't built: a host sender's task is the phone's task rewritten as B's
// (its admission frozen by `Admission::for_host`), as admission will store
// it. Included beside the other delegated tests, whose helpers and imports
// it shares.

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
        escs_reach(&rig, 1).await;
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
