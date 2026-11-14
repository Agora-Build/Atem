// The owner's own commands on the host (host-work-v1 §11.6 "On the host";
// design I.4.6; step 4's open question 2, ruling T23a), in the bridge: `atem
// task list --unknown` and `atem task resolve` as the local server hands
// them over (the caller is the owner: the server's check), and `atem
// status`'s `Delegated:` data. The rig's host with a pinned device list,
// the phone, the bot, the Mac (the owner) and a viewer. Included beside the
// resolutions' tests, whose helpers and imports it shares.

use crate::runtime::collab_context::{ContextPublisher, VaultRef};
use crate::runtime::delegated::details::RESOLVED_AS_FAILED_ON_THE_HOST;
use crate::runtime::host_bridge::OwnerDone;
use crate::runtime::protocol::{DelegatedStatus, UnknownTask};

/// Publishes a memory as the relay reads it back: its own text.
struct AsItIs;

impl ContextPublisher for AsItIs {
    async fn memory(
        &self,
        memory: &crate::memory::model::Memory,
    ) -> anyhow::Result<hw::ContextSnapshot> {
        Ok(hw::ContextSnapshot {
            kind: hw::ContextKind::Memory,
            id: memory.id.clone(),
            version: 1,
            digest: hw::digest(memory.content.as_bytes()),
            text: memory.content.clone(),
        })
    }
    async fn vault(&self, _: &VaultRef) -> anyhow::Result<hw::ContextSnapshot> {
        unreachable!("no vault context here")
    }
}

/// A memory of `content` in the rig's profile (`knowledge.db`), as `atem
/// memory add` stores one.
fn remembered(root: &Path, id: &str, content: &str) {
    crate::memory::store::Store::open(&root.join("knowledge.db"))
        .unwrap()
        .upsert_memory(&crate::memory::model::Memory {
            id: id.into(),
            content: content.into(),
            ..Default::default()
        })
        .unwrap();
}

/// `atem task resolve <task> failed --detail <detail>`, as the server
/// hands it over.
fn owner_fails(rig: &mut LocalRig, task: &str, detail: &str) -> anyhow::Result<WorkStatus> {
    rig.bridge.owner_resolve(
        task,
        &Resolution::Failed {
            detail: detail.into(),
        },
    )
}

/// `atem task resolve <task> done --memory <memory>`: captured, published
/// (as the relay reads it back), then resolved, as the server runs it.
async fn owner_done_with(
    rig: &mut LocalRig,
    task: &str,
    memory: &str,
) -> anyhow::Result<WorkStatus> {
    let publication = match rig.bridge.owner_done(task, Some(memory), None)? {
        OwnerDone::Recorded(status) => return Ok(status),
        OwnerDone::Publish(publication) => publication,
    };
    let mut snapshots =
        crate::runtime::collab_context::publish(&AsItIs, &publication.specs).await?;
    assert_eq!(snapshots.len(), 1);
    rig.bridge.owner_resolve(
        task,
        &Resolution::Done {
            result: snapshots.remove(0),
        },
    )
}

/// The listed tasks as (task, session, sender, reason).
fn listed(tasks: &[UnknownTask]) -> Vec<(String, String, String, String)> {
    tasks
        .iter()
        .map(|t| {
            (
                t.task_id.clone(),
                t.session_id.clone(),
                t.sender.clone(),
                t.reason.clone(),
            )
        })
        .collect()
}

/// Host-work-v1 §11.6 "On the host" ("`atem task list --unknown` lists the
/// unresolved outcomes: the task, session, sender, reason and when"),
/// design I.4.6: one row per delegated task of unknown outcome nobody
/// resolved, in the host's order, each naming its session, its sender, why
/// its outcome is unknown (the reason its alert was raised with, kept past
/// the deadline) and when it became unknown; the line the CLI prints shows
/// them in that order. A v1 task of unknown outcome isn't one. A resolved
/// task leaves the list, the rest keep their order; the list is the same
/// with the hook off.
#[test]
fn task_list_unknown_lists_task_session_sender_reason_and_when() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = with_bot(&mut rig, root, &os, start + 3 * HOUR);
        alerts_on(&mut rig);
        assert_eq!(rig.bridge.owner_unknown_tasks().unwrap(), vec![]);
        let before = host_now().wall_ms;
        let phone = phone_unknowns(&mut rig, &s, 2, start + HOUR);
        // The bot's task, its write interrupted.
        let bot = bot_task(&mut rig, &s, "BOT_UNKNOWN", start + HOUR);
        make_unknown(&rig, &bot, details::WRITE_INTERRUPTED);
        let after = host_now().wall_ms;
        // A v1 task of unknown outcome (accepted with the hook off).
        rig.bridge.features = HostFeatures::default();
        let v1 = phone_task(&mut rig, &s.phone, "V1_UNKNOWN", start + HOUR);
        alerts_on(&mut rig);
        make_unknown(&rig, &v1, details::AGENT_EXITED);
        let sid = rig.sid.to_string();
        let row = |task: &str, sender: &str, reason: &str| {
            (
                task.to_string(),
                sid.clone(),
                sender.to_string(),
                reason.to_string(),
            )
        };
        let tasks = rig.bridge.owner_unknown_tasks().unwrap();
        assert_eq!(
            listed(&tasks),
            [
                row(&phone[0], PHONE, details::AGENT_EXITED),
                row(&phone[1], PHONE, details::AGENT_EXITED),
                row(&bot, BOT, details::WRITE_INTERRUPTED),
            ]
        );
        for t in &tasks {
            assert!((before..=after).contains(&t.at_ms), "{t:?}");
        }
        // The line `atem task list --unknown` prints.
        assert_eq!(
            crate::runtime::commands::unknown_line(&tasks[2], |ms| format!("<{ms}>")),
            format!(
                "{bot}  {sid}  {BOT}  {}  <{}>",
                details::WRITE_INTERRUPTED,
                tasks[2].at_ms
            )
        );
        // Past their deadline (on the delegated clock): listed as before,
        // with the reasons they were raised with.
        os.pass(HOUR);
        passes(&mut rig, 2);
        assert_eq!(
            settled(&rig, &phone[0]).1,
            details::DEADLINE_PASSED_OUTCOME_UNKNOWN
        );
        assert_eq!(rig.bridge.owner_unknown_tasks().unwrap(), tasks);
        // One resolved: the others stay, in order.
        owner_fails(&mut rig, &phone[1], "checked").unwrap();
        let rest = rig.bridge.owner_unknown_tasks().unwrap();
        assert_eq!(rest, vec![tasks[0].clone(), tasks[2].clone()]);
        // The hook off (a restart without it): the same list.
        rig.bridge.features = HostFeatures::default();
        assert_eq!(rig.bridge.owner_unknown_tasks().unwrap(), rest);
    });
}

/// Host-work-v1 §11.2 ("`by` … is the literal `local`, for the host's own
/// command"), §11.6 "On the host", step 4's open question 2: the owner
/// resolves a task `failed` with the default detail, another with its own
/// (kept byte for byte), and a third `done` with a Memory fact taken
/// through collaboration's context capture and publication (exactly that
/// snapshot). Each records `resolved{by: local, at}` (the host's wall clock
/// then), ends its alert, and its sender reads it so. The same resolution
/// again returns the recorded status; another, or a detail no reader takes,
/// is refused with nothing changed. `done` takes one snapshot, as `message
/// reply` does: a memory that isn't there, an entryless vault reference,
/// or vault context while the account's encryption isn't `on` are refused
/// before anything is published.
#[test]
fn task_resolve_failed_and_done_as_local() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = with_bot(&mut rig, root, &os, start + 3 * HOUR);
        alerts_on(&mut rig);
        let tasks = phone_unknowns(&mut rig, &s, 3, start + HOUR);
        let unknown = (WorkState::OutcomeUnknown, details::AGENT_EXITED.to_string());
        // Details no reader takes: nothing changes.
        for bad in ["", "   ", "two\nlines", "a\u{200B}b", &"x".repeat(1025)] {
            let error = owner_fails(&mut rig, &tasks[0], bad).unwrap_err();
            assert_eq!(
                error.to_string(),
                "a failed task's detail is 1-1024 bytes on one line, not blank, with no control or format character",
                "{bad:?}"
            );
            assert_eq!(settled(&rig, &tasks[0]), unknown);
        }
        let before = host_now().wall_ms;
        let failed = owner_fails(&mut rig, &tasks[0], RESOLVED_AS_FAILED_ON_THE_HOST).unwrap();
        let own = owner_fails(&mut rig, &tasks[1], "  checked: nothing ran ").unwrap();
        remembered(root, "mem_f00dbabe", "the change landed in main");
        let done = owner_done_with(&mut rig, &tasks[2], "mem_f00dbabe")
            .await
            .unwrap();
        let after = host_now().wall_ms;
        assert_eq!(
            (failed.state, failed.detail.as_str()),
            (WorkState::Failed, "resolved as failed on the host")
        );
        assert_eq!(
            (own.state, own.detail.as_str()),
            (WorkState::Failed, "  checked: nothing ran ")
        );
        let result = done.result.clone().unwrap();
        assert_eq!(
            (
                done.state,
                result.kind,
                result.id.as_str(),
                result.text.as_str()
            ),
            (
                WorkState::Completed,
                hw::ContextKind::Memory,
                "mem_f00dbabe",
                "the change landed in main"
            )
        );
        for (task, st) in tasks.iter().zip([&failed, &own, &done]) {
            let by = st.resolved.as_ref().unwrap();
            assert_eq!(by.by, "local");
            assert!((before..=after).contains(&by.at), "{by:?}");
            assert!(st.valid());
            assert_eq!(&stored_record(&rig, task).status, st);
            // Its sender reads it so (`resolved` on the wire: the hook is on).
            assert_eq!(&status(ask(&mut rig, &s.phone, Q::Query(task))), st);
        }
        assert_eq!(rig.bridge.owner_unknown_tasks().unwrap(), vec![]);
        let store = rig.bridge.work.store.as_ref().unwrap();
        assert_eq!(store.unresolved().unwrap().0, 0);
        // The same again: the recorded status. Another: refused.
        let again = owner_fails(&mut rig, &tasks[0], RESOLVED_AS_FAILED_ON_THE_HOST).unwrap();
        assert_eq!(again, failed);
        let again = owner_done_with(&mut rig, &tasks[2], "mem_f00dbabe")
            .await
            .unwrap();
        assert_eq!(again, done);
        let refused = owner_fails(&mut rig, &tasks[1], "checked: nothing ran").unwrap_err();
        assert_eq!(
            refused.to_string(),
            format!(
                "task {} was already resolved (failed, by local); another resolution is refused",
                tasks[1]
            )
        );
        let refused = owner_fails(&mut rig, &tasks[2], "no").unwrap_err();
        assert_eq!(
            refused.to_string(),
            format!(
                "task {} was already resolved (completed, by local); another resolution is refused",
                tasks[2]
            )
        );
        assert_eq!(stored_record(&rig, &tasks[1]).status, own);
        // `done`'s snapshot is taken as a reply's.
        let more = phone_unknowns(&mut rig, &s, 1, start + HOUR).remove(0);
        for (memory, vault, error) in [
            (Some("mem_0bad0bad"), None, "No memory mem_0bad0bad"),
            (
                None,
                Some("v-result@1"),
                "ambiguous vault reference v-result@1: a resolution names the entry, ID:ENTRY@VERSION",
            ),
            (
                None,
                Some("v-result:1@1"),
                crate::runtime::collab_context::VAULT_NEEDS_E2E,
            ),
            (None, None, "done needs one --memory or --vault"),
            (
                Some("mem_f00dbabe"),
                Some("v-result:1@1"),
                "done needs one --memory or --vault",
            ),
        ] {
            let refused = rig.bridge.owner_done(&more, memory, vault).err().unwrap();
            assert!(
                refused.to_string().contains(error),
                "{memory:?} {vault:?}: {refused:#}"
            );
        }
        assert_eq!(settled(&rig, &more), unknown);
    });
}

/// Host-work-v1 §11.6 "On the host" ("Like `work_resolve`, it resolves
/// only a delegated task: a task of `local`, a browser grant or a service
/// no feed covers keeps v1, and its unknown outcome expires"), §11.2: a v1
/// task of unknown outcome is refused, `failed` and `done` alike (`done`
/// before any capture), and keeps v1: it expires at its deadline on the
/// wall clock. So are a task the host doesn't have and a delegated task
/// that isn't of unknown outcome, each with its own reason.
#[test]
fn task_resolve_refuses_a_v1_task() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = with_bot(&mut rig, root, &os, start + 3 * HOUR);
        alerts_on(&mut rig);
        rig.bridge.start_view().gates = Gates::default();
        rig.bridge.features = HostFeatures::default();
        let v1 = phone_task(&mut rig, &s.phone, "V1_UNKNOWN", start + HOUR);
        alerts_on(&mut rig);
        assert_eq!(stored_record(&rig, &v1).delegated, None);
        make_unknown(&rig, &v1, details::AGENT_EXITED);
        let waiting = phone_task(&mut rig, &s.phone, "DELEGATED_WAITING", start + HOUR);
        let never = uuid::Uuid::new_v4().to_string();
        remembered(root, "mem_f00dbabe", "a result");
        for (task, error) in [
            (
                &v1,
                format!(
                    "task {v1} is not a delegated sender's task; only those are resolved (a v1 task's unknown outcome expires at its deadline)"
                ),
            ),
            (
                &waiting,
                format!("task {waiting} is queued; only a task of unknown outcome is resolved"),
            ),
            (&never, format!("no task {never} in this runtime")),
        ] {
            let failed = owner_fails(&mut rig, task, "no").unwrap_err();
            assert_eq!(failed.to_string(), error);
            let done = rig
                .bridge
                .owner_done(task, Some("mem_f00dbabe"), None)
                .err()
                .unwrap();
            assert_eq!(done.to_string(), error);
        }
        assert_eq!(
            settled(&rig, &v1),
            (WorkState::OutcomeUnknown, details::AGENT_EXITED.into())
        );
        assert_eq!(stored_record(&rig, &v1).status.resolved, None);
        assert_eq!(settled(&rig, &waiting).0, WorkState::Queued);
        // The v1 one expires at its deadline, on the wall clock.
        let mut record = stored_record(&rig, &v1);
        record.task.expires_at = host_now().wall_ms - 1;
        let store = rig.bridge.work.store.as_ref().unwrap();
        store.save_work(&record).unwrap();
        passes(&mut rig, 1);
        assert_eq!(
            settled(&rig, &v1),
            (
                WorkState::Expired,
                crate::runtime::host_work::EXPIRED_UNKNOWN.into()
            )
        );
    });
}

/// Ruling T23a, step 4's Decision 10 ("started ones follow their
/// receipts"): with the hook off (a restart without it), remote
/// `work_resolve` isn't served, so the owner's command is the only way to
/// settle a delegated task of unknown outcome, and it works: listed,
/// resolved `failed` and `done` by `local`, its alert ended. The store keeps
/// `resolved`; the wire doesn't carry it while the hook is off (§11.2,
/// "Compatibility"), and remote `work_resolve` stays `busy`.
#[test]
fn task_resolve_works_with_the_hook_off() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = with_bot(&mut rig, root, &os, start + 3 * HOUR);
        alerts_on(&mut rig);
        let tasks = phone_unknowns(&mut rig, &s, 2, start + HOUR);
        // A restart without the hook.
        rig.bridge.features = HostFeatures::default();
        rig.bridge.r9.set_delegated_features(false, false);
        assert_eq!(
            resolve_by(&mut rig, &s.phone, &tasks[0], &failure("remote")).1,
            busy()
        );
        assert_eq!(rig.bridge.owner_unknown_tasks().unwrap().len(), 2);
        let failed = owner_fails(&mut rig, &tasks[0], RESOLVED_AS_FAILED_ON_THE_HOST).unwrap();
        remembered(root, "mem_f00dbabe", "done while the hook was off");
        let done = owner_done_with(&mut rig, &tasks[1], "mem_f00dbabe")
            .await
            .unwrap();
        assert_eq!(
            (failed.state, failed.resolved.as_ref().unwrap().by.as_str()),
            (WorkState::Failed, "local")
        );
        assert_eq!(
            (done.state, done.resolved.as_ref().unwrap().by.as_str()),
            (WorkState::Completed, "local")
        );
        assert_eq!(rig.bridge.owner_unknown_tasks().unwrap(), vec![]);
        let store = rig.bridge.work.store.as_ref().unwrap();
        assert_eq!(store.unresolved().unwrap().0, 0);
        for (task, st) in tasks.iter().zip([&failed, &done]) {
            assert_eq!(&stored_record(&rig, task).status, st);
            let body = ask(&mut rig, &s.phone, Q::Query(task)).unwrap();
            let wire = serde_json::to_string(&body).unwrap();
            assert!(!wire.contains("\"resolved\""), "{wire}");
            let mut shown = st.clone();
            shown.resolved = None;
            assert_eq!(status(Ok(body)), shown);
        }
    });
}

/// `atem status`'s `Delegated:` data (host-work-v1 §11.6 "On the host"):
/// none while nothing is delegated (the hook off, no delegated task, none
/// unresolved: main's status); with the hook on, the count, zero included;
/// with the hook off, while a delegated task of unknown outcome is
/// unresolved (ruling T23a), its count, and none again once it was
/// resolved and its task closed.
#[test]
fn delegated_status_only_while_something_is_delegated() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        assert_eq!(rig.bridge.delegated_status(), None);
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = with_bot(&mut rig, root, &os, start + 3 * HOUR);
        alerts_on(&mut rig);
        let on = |n| Some(DelegatedStatus { unresolved: n });
        assert_eq!(rig.bridge.delegated_status(), on(0));
        let tasks = phone_unknowns(&mut rig, &s, 2, start + HOUR);
        assert_eq!(rig.bridge.delegated_status(), on(2));
        // The hook off: shown while one is unresolved.
        rig.bridge.features = HostFeatures::default();
        assert_eq!(rig.bridge.delegated_status(), on(2));
        owner_fails(&mut rig, &tasks[0], "checked").unwrap();
        assert_eq!(rig.bridge.delegated_status(), on(1));
        owner_fails(&mut rig, &tasks[1], "checked").unwrap();
        // Resolved, their tasks still open: still delegated work.
        assert_eq!(rig.bridge.delegated_status(), on(0));
        // Closed a day after their deadline, with the phone's template
        // (cancelled): nothing delegated is left.
        let store = rig.bridge.work.store.as_ref().unwrap();
        for mut open in store.open_tasks().unwrap() {
            if open.status.state == WorkState::Queued {
                open.status.state = WorkState::Cancelled;
                store.save_work(&open).unwrap();
            }
        }
        store
            .drop_payloads(start + HOUR + crate::runtime::host_work::PAYLOAD_RETENTION_MS)
            .unwrap();
        assert!(!store.has_delegated().unwrap());
        assert_eq!(rig.bridge.delegated_status(), None);
    });
}

/// Step 4's open question 3: when kept replies go before their 30 days (the
/// kept replies' 64 MiB budget full), one runtime.log line says how many.
#[test]
fn kept_replies_dropped_early_say_so_in_one_line() {
    assert_eq!(
        kept_early_line(1),
        "the replies kept for delegated tasks are over their 64 MiB budget: dropped the text and context of 1 reply before its 30 days, oldest first (records kept)"
    );
    assert_eq!(
        kept_early_line(3),
        "the replies kept for delegated tasks are over their 64 MiB budget: dropped the text and context of 3 replies before their 30 days, oldest first (records kept)"
    );
}

/// Ruling T25a (review I1): a missing kept-replies total (a crash right
/// after its table was made) never fails a cleanup, so it never fences
/// hosting: the pass runs its cleanup and hosting goes on.
#[test]
fn a_missing_kept_total_never_fences_hosting() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let store = rig.bridge.work.store.as_ref().unwrap();
        store.db.execute("DELETE FROM kept_replies", []).unwrap();
        rig.bridge.work.cleanup = Instant::now();
        passes(&mut rig, 2);
        assert!(rig.bridge.work.cleanup > Instant::now(), "the cleanup ran");
        assert!(!rig.bridge.work.error, "hosting was fenced");
    });
}

/// Review M2: `done` checks a resolved task before it captures or
/// publishes anything. The same snapshot again (the same memory, its text
/// unchanged; the same vault entry and version, which never changes) is the
/// same resolution: its recorded status, nothing published. Another memory,
/// the memory's text changed, another version or a task resolved `failed`
/// are refused at once, as another resolution.
#[test]
fn a_repeated_done_publishes_nothing() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = with_bot(&mut rig, root, &os, start + 3 * HOUR);
        alerts_on(&mut rig);
        let tasks = phone_unknowns(&mut rig, &s, 3, start + HOUR);
        remembered(root, "mem_f00dbabe", "the change landed");
        let done = owner_done_with(&mut rig, &tasks[0], "mem_f00dbabe")
            .await
            .unwrap();
        let recorded = |rig: &mut LocalRig, task: &str, memory, vault| match rig
            .bridge
            .owner_done(task, memory, vault)
        {
            Ok(OwnerDone::Recorded(status)) => Ok(status),
            Ok(OwnerDone::Publish(_)) => panic!("{task}: published again"),
            Err(error) => Err(error.to_string()),
        };
        assert_eq!(
            recorded(&mut rig, &tasks[0], Some("mem_f00dbabe"), None),
            Ok(done.clone())
        );
        let completed = format!(
            "task {} was already resolved (completed, by local); another resolution is refused",
            tasks[0]
        );
        remembered(root, "mem_0abcdef0", "another fact");
        for (memory, vault) in [(Some("mem_0abcdef0"), None), (None, Some("v-result:1@1"))] {
            assert_eq!(
                recorded(&mut rig, &tasks[0], memory, vault),
                Err(completed.clone())
            );
        }
        remembered(root, "mem_f00dbabe", "the change landed, then was reverted");
        assert_eq!(
            recorded(&mut rig, &tasks[0], Some("mem_f00dbabe"), None),
            Err(completed)
        );
        // Resolved with a vault entry: the same entry and version again.
        let by_vault = rig
            .bridge
            .owner_resolve(&tasks[1], &done_with("the vault's result", 1))
            .unwrap();
        assert_eq!(
            recorded(&mut rig, &tasks[1], None, Some("v-result:1@1")),
            Ok(by_vault)
        );
        assert_eq!(
            recorded(&mut rig, &tasks[1], None, Some("v-result:1@2")),
            Err(format!(
                "task {} was already resolved (completed, by local); another resolution is refused",
                tasks[1]
            ))
        );
        // Resolved `failed`: refused before anything is captured.
        owner_fails(&mut rig, &tasks[2], "gave up").unwrap();
        assert_eq!(
            recorded(&mut rig, &tasks[2], Some("mem_f00dbabe"), None),
            Err(format!(
                "task {} was already resolved (failed, by local); another resolution is refused",
                tasks[2]
            ))
        );
        assert_eq!(stored_record(&rig, &tasks[0]).status, done);
    });
}
