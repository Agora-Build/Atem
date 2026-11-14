// Delegated launches at the spawn boundary (design I.4.3, "Launches";
// host-work-v1 §3 and §11.6, "Launches"): the phone (a native member, a
// delegated sender) launches the rig's profile `p` with `host_launch`. Its
// launch is checked before the spawn: a reason that can clear makes it
// wait, one that can't fails it at once, an expiry passed while it waits
// fails it `expired before the spawn`, and none is ever `outcome_unknown`;
// hosting §5's fences stay as they are. Included into the host-work
// bridge's local tests (`include!`), beside the dispatch tests' helpers
// (`delegated`, `ManualOs`, `passes`).

use crate::runtime::adopt::{self, NotSpawned, PreSpawn, WorkerPaths};
use crate::runtime::delegated::start::{LaunchVerdict, StartView, launch_check};
use crate::session_protocol::membership::ListState;

const HOUR_MS: u64 = 3_600_000;

/// `runtime.toml`: the rig's profile `p` (at `revision`), which the phone
/// may launch too, its routes `r` (`local`) and `rm` (the phone).
fn phone_toml(root: &Path, revision: u64) -> String {
    format!(
        r#"
version = 1
enabled = true
[collab]
send = true
[[profiles]]
id = "p"
revision = {revision}
label = "p"
provider = "claude"
cwd = {cwd:?}
project = "local:project"
principals = ["member:owner", "{PHONE}"]
[[routes]]
id = "r"
revision = 1
profile_id = "p"
principals = ["local"]
[[routes]]
id = "rm"
revision = 1
profile_id = "p"
principals = ["{PHONE}"]
"#,
        cwd = root.join("project")
    )
}

/// `text` as the rig's `runtime.toml`: on disk (what the spawn boundary
/// re-reads) and as the bridge loaded it (what the start view gets at the
/// next pass).
fn configure(rig: &mut LocalRig, root: &Path, text: &str) {
    use std::os::unix::fs::PermissionsExt;
    let path = root.join("runtime.toml");
    std::fs::write(&path, text).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    rig.bridge.work.config = Config::load(root).unwrap();
}

/// The rig as a delegated host the phone may launch on (see `delegated`),
/// one pass taken (the start view has the file and a reading of `D`).
fn launch_host(rig: &mut LocalRig, root: &Path, os: &ManualOs, gate: bool) -> (Authority, TestLog) {
    let (phone, log) = delegated(rig, root, os, gate);
    configure(rig, root, &phone_toml(root, 1));
    passes(rig, 1);
    (phone, log)
}

/// The phone's `host_launch` of profile `p`, expiring `ms` from now: its
/// request id (the reply says `starting`).
fn phone_launch(rig: &mut LocalRig, phone: &Authority, ms: u64) -> String {
    let request_id = uuid::Uuid::new_v4().to_string();
    let req = hw::Request::Launch {
        v: 1,
        id: uuid::Uuid::new_v4().to_string(),
        host: rig.bridge.work_host(),
        request_id: request_id.clone(),
        profile_id: "p".into(),
        profile_revision: 1,
        expires_at: host_now().wall_ms + ms,
    };
    let ResultBody::Launch { launch } = as_phone(rig, phone, &req).unwrap() else {
        panic!("a launch result");
    };
    assert_eq!(launch.state, LaunchState::Starting);
    request_id
}

/// Launch `id`'s state as stored (what `host_launch_query` answers).
fn launch_state(rig: &LocalRig, id: &str) -> LaunchState {
    rig.bridge
        .work
        .store
        .as_ref()
        .unwrap()
        .launch(id)
        .unwrap()
        .unwrap()
        .status
        .state
}

/// One pass, then what the bridge hands to the launcher (as the runtime's
/// pass takes it, `take_remote_launches`).
fn handed(rig: &mut LocalRig) -> Vec<RemoteLaunch> {
    passes(rig, 1);
    rig.bridge.take_remote_launches()
}

/// What the check says of pending launch `id` now, at the view's `D`.
fn verdict(rig: &LocalRig, id: &str) -> LaunchVerdict {
    let view = rig.bridge.start_view();
    let launch = &rig.bridge.work.pending[id]
        .delegated
        .as_ref()
        .unwrap()
        .launch;
    launch_check(&view, launch, view.now_d_ms.unwrap())
}

/// The worker request a launch is spawned with.
fn spawn_request(launch: &RemoteLaunch) -> SpawnRequest {
    SpawnRequest {
        session_id: SessionId::parse(&launch.session_id).unwrap(),
        process_gen: launch.process_gen.clone(),
        provider: crate::session::Provider::Claude,
        args: vec![],
        cwd: launch.profile.cwd.clone(),
        rows: 24,
        cols: 80,
    }
}

/// `launch` handed to the launcher as the runtime's pass hands it
/// (`server.rs`): spawned in process through its guard and its check, its
/// end reported (`launch_finished`); the error, if it didn't start.
async fn spawn(rig: &mut LocalRig, root: &Path, launch: &RemoteLaunch) -> Option<anyhow::Error> {
    let launcher = Launcher::InProcess(InProcess {
        state: root.join("runtime"),
        socket_dir: root.join("ws"),
        chat_root: root.join("chat"),
    });
    let fake = root.join("fake-launched");
    std::fs::create_dir_all(&fake).unwrap();
    let bin =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/approvals/fake-agent.py");
    let request = spawn_request(launch);
    let result = launcher
        .spawn_guarded(
            request.clone(),
            LaunchEnv(vec![
                ("PATH".into(), "/usr/bin:/bin".into()),
                ("HOME".into(), root.display().to_string()),
                ("CLAUDE_CLI_BIN".into(), bin.display().to_string()),
                ("FAKE_DIR".into(), fake.display().to_string()),
            ]),
            launch.guard.clone(),
            launch.check.clone(),
        )
        .await;
    rig.bridge
        .launch_finished(&launch.request_id, result.as_ref().map(|_| ()), false);
    match result {
        Ok((handle, created)) => {
            rig.sessions.insert(
                request.session_id.clone(),
                BrokerSession::launched(handle, &request, created),
            );
            None
        }
        Err(error) => Some(error),
    }
}

/// Launch `id` ended `failed` before its spawn with `detail` (the reason
/// logged; never among the local tasks' reasons), forgotten, never
/// `outcome_unknown`.
fn failed_with(rig: &LocalRig, id: &str, detail: &str) {
    assert_eq!(launch_state(rig, id), LaunchState::Failed, "{detail}");
    assert_eq!(
        rig.bridge.work.failed_before_spawn.get(id).copied(),
        Some(detail)
    );
    assert!(!rig.bridge.work.refused.contains_key(id));
    assert!(!rig.bridge.work.pending.contains_key(id));
    assert!(
        !rig.bridge.work.launches.iter().any(|l| l.request_id == id),
        "not queued"
    );
}

/// Launch `id` waits at the spawn boundary for `detail`: still `starting`,
/// never handed out, never fenced.
fn waits_for(rig: &mut LocalRig, id: &str, detail: &'static str) {
    for _ in 0..3 {
        assert!(handed(rig).is_empty(), "{detail}: never handed out");
    }
    assert_eq!(launch_state(rig, id), LaunchState::Starting, "{detail}");
    assert!(
        rig.bridge.work.pending[id].permit.load(Ordering::SeqCst),
        "{detail}: never fenced"
    );
    assert_eq!(verdict(rig, id), LaunchVerdict::Wait(detail));
}

/// Design I.4.3, "Launches": a delegated sender's `host_launch` is checked
/// at the spawn boundary, before its worker is spawned. With its gate
/// closed (no feeds, no channel of the phone's: the sender's channel is no
/// condition, so nothing fences it as v1 would) it waits in the queue,
/// never handed out. Handed out once the gate opens, it carries its check;
/// the gate closing again before the spawn makes that check wait, and the
/// process launcher refuses it before writing or spawning anything; the
/// runtime hands it back to the queue, still `starting`. Once the gate is
/// open again it starts.
#[test]
fn a_delegated_launch_is_checked_before_the_spawn() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let (phone, _) = launch_host(&mut rig, root, &os, false);
        let id = phone_launch(&mut rig, &phone, 60_000);
        assert!(
            rig.bridge.work.pending[&id].delegated.is_some(),
            "a delegated sender's launch"
        );
        waits_for(&mut rig, &id, details::REVOCATIONS_NOT_YET_CHECKED);
        // The gate opens: handed out, with its check.
        rig.bridge.start_view().gates.open_own_station(ORIGIN);
        let launches = handed(&mut rig);
        assert_eq!(launches.len(), 1);
        assert_eq!(launches[0].request_id, id);
        let check = launches[0].check.clone().expect("its check");
        assert_eq!(check(), PreSpawn::Go);
        // Before the spawn the gate closed again: the check waits.
        rig.bridge.start_view().gates.close_stations();
        assert_eq!(check(), PreSpawn::Wait);
        // The process launcher asks it before anything is written or
        // spawned.
        let paths = WorkerPaths {
            exe: root.join("no-atem-here"),
            state: root.join("runtime"),
            socket_dir: root.join("ws"),
        };
        let error = adopt::spawn_guarded(
            &paths,
            &spawn_request(&launches[0]),
            None,
            Some(launches[0].guard.clone()),
            Some(check.clone()),
        )
        .await
        .unwrap_err();
        assert_eq!(error.downcast_ref::<NotSpawned>(), Some(&NotSpawned::Wait));
        assert!(
            !crate::runtime::worker::spec_path(&paths.state, &launches[0].session_id).exists(),
            "nothing written"
        );
        // The runtime reports it: back in the queue, waiting, `starting`.
        rig.bridge.launch_finished(&id, Err(&error), false);
        waits_for(&mut rig, &id, details::REVOCATIONS_NOT_YET_CHECKED);
        // Open again: it starts.
        rig.bridge.start_view().gates.open_own_station(ORIGIN);
        let launches = handed(&mut rig);
        assert_eq!(launches.len(), 1);
        assert!(spawn(&mut rig, root, &launches[0]).await.is_none());
        assert_eq!(launch_state(&rig, &id), LaunchState::Started);
        assert!(rig.bridge.work.pending.is_empty());
    });
}

/// Design I.4.3, "Launches" (VII.A test 19's launch half): a reason that
/// can clear (the sender held, the gate closed, a deferred device-list
/// entry, a project scope pending) makes a delegated launch wait at the
/// spawn boundary while its expiry holds; once it clears, the launch is
/// handed out to start. One still waiting when its expiry passes on the
/// delegated clock ends `failed`, `expired before the spawn`: nothing
/// spawned, never `outcome_unknown`. A hold handed out meanwhile waits at
/// the boundary too.
#[test]
fn a_clearable_reason_waits_then_expired_before_the_spawn() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let (phone, _) = launch_host(&mut rig, root, &os, true);
        let held = SenderStanding {
            held: true,
            ..SenderStanding::default()
        };
        let id = phone_launch(&mut rig, &phone, 60_000);
        type Change = fn(&mut StartView, &SenderStanding);
        let reasons: [(&str, Change, Change); 3] = [
            (
                details::PAUSED,
                |v, held| {
                    v.standings.insert(PHONE.into(), held.clone());
                },
                |v, _| {
                    v.standings.remove(PHONE);
                },
            ),
            (
                details::REVOCATIONS_NOT_YET_CHECKED,
                |v, _| v.gates.close_stations(),
                |v, _| v.gates.open_own_station(ORIGIN),
            ),
            (
                details::DEVICE_LIST_UPDATE_PENDING,
                |v, _| {
                    v.list.as_mut().unwrap().deferred =
                        Some(crate::session_protocol::membership::DeferredStop {
                            seq: 99,
                            until_ms: u64::MAX,
                            on: None,
                        })
                },
                |v, _| v.list.as_mut().unwrap().deferred = None,
            ),
        ];
        for (detail, make, clear) in reasons {
            make(&mut rig.bridge.start_view(), &held);
            waits_for(&mut rig, &id, detail);
            clear(&mut rig.bridge.start_view(), &held);
        }
        // Cleared: handed out. A hold arriving before its spawn makes it
        // wait there, and it is handed back.
        let launches = handed(&mut rig);
        assert_eq!(launches.len(), 1);
        rig.bridge
            .start_view()
            .standings
            .insert(PHONE.into(), held.clone());
        let error = spawn(&mut rig, root, &launches[0])
            .await
            .expect("not spawned");
        assert_eq!(error.downcast_ref::<NotSpawned>(), Some(&NotSpawned::Wait));
        waits_for(&mut rig, &id, details::PAUSED);
        // Still held at its expiry on the delegated clock: `failed`,
        // `expired before the spawn`.
        os.pass(120_000);
        assert!(handed(&mut rig).is_empty());
        failed_with(&rig, &id, details::EXPIRED_BEFORE_THE_SPAWN);
        assert_eq!(rig.sessions.len(), 1, "nothing spawned");
        // A release lets the next one start.
        rig.bridge.start_view().standings.remove(PHONE);
        let next = phone_launch(&mut rig, &phone, HOUR_MS);
        let launches = handed(&mut rig);
        assert_eq!(launches.len(), 1);
        assert!(spawn(&mut rig, root, &launches[0]).await.is_none());
        assert_eq!(launch_state(&rig, &next), LaunchState::Started);
    });
}

/// Design I.4.3, "Launches": a reason that can't clear ends a delegated
/// launch `failed` at once with the event's detail, nothing spawned: the
/// sender revoked or removed (`sender revoked`), narrowed off `launch`
/// (`sender's authorization narrowed`), its profile changed (`route
/// changed`). Never `outcome_unknown`, also when the reason arrives after
/// the launch was handed out: its check at the spawn boundary fails it.
#[test]
fn an_unclearable_reason_fails_at_once_never_outcome_unknown() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let (phone, mut log) = launch_host(&mut rig, root, &os, true);
        let revoked = SenderStanding {
            revoked: Some("rec-revoke".into()),
            ..SenderStanding::default()
        };
        // Revoked.
        let id = phone_launch(&mut rig, &phone, 60_000);
        rig.bridge
            .start_view()
            .standings
            .insert(PHONE.into(), revoked.clone());
        assert!(handed(&mut rig).is_empty());
        failed_with(&rig, &id, details::SENDER_REVOKED);
        rig.bridge.start_view().standings.remove(PHONE);
        // Narrowed (no longer `control`: no `launch`), then removed from
        // the device list, as the view has the list at commit.
        let current = rig.bridge.start_view().list.clone().unwrap();
        for (detail, demote) in [
            (details::AUTHORIZATION_NARROWED, true),
            (details::SENDER_REVOKED, false),
        ] {
            let id = phone_launch(&mut rig, &phone, 60_000);
            if demote {
                log.set_native_roles("dev-phone", &["view"]);
            } else {
                log.remove("dev-phone");
            }
            rig.bridge.start_view().list.as_mut().unwrap().membership = Arc::new(log.log.clone());
            assert!(handed(&mut rig).is_empty());
            failed_with(&rig, &id, detail);
            rig.bridge.start_view().list = Some(current.clone());
        }
        // Its profile changed (a new revision of `p`).
        let id = phone_launch(&mut rig, &phone, 60_000);
        configure(&mut rig, root, &phone_toml(root, 2));
        assert!(handed(&mut rig).is_empty());
        failed_with(&rig, &id, details::ROUTE_CHANGED);
        configure(&mut rig, root, &phone_toml(root, 1));
        // Handed out, then revoked before its spawn: the check fails it
        // there, nothing spawned, and the launch is `failed`.
        let id = phone_launch(&mut rig, &phone, 60_000);
        let launches = handed(&mut rig);
        assert_eq!(launches.len(), 1);
        rig.bridge
            .start_view()
            .standings
            .insert(PHONE.into(), revoked);
        let error = spawn(&mut rig, root, &launches[0])
            .await
            .expect("not spawned");
        assert_eq!(
            error.downcast_ref::<NotSpawned>(),
            Some(&NotSpawned::Fail(details::SENDER_REVOKED))
        );
        failed_with(&rig, &id, details::SENDER_REVOKED);
        // So does a profile changed in the file the spawn boundary re-reads
        // (before the bridge loaded it).
        rig.bridge.start_view().standings.remove(PHONE);
        let id = phone_launch(&mut rig, &phone, 60_000);
        let launches = handed(&mut rig);
        assert_eq!(launches.len(), 1);
        std::fs::write(root.join("runtime.toml"), phone_toml(root, 2)).unwrap();
        assert_eq!(
            launches[0].check.as_ref().unwrap()(),
            PreSpawn::Fail(details::ROUTE_CHANGED)
        );
        assert!(spawn(&mut rig, root, &launches[0]).await.is_some());
        failed_with(&rig, &id, details::ROUTE_CHANGED);
        assert_eq!(rig.sessions.len(), 1, "nothing spawned");
    });
}

/// Design I.4.3, "Launches", condition 2a and owner-agreed Q4: a frozen,
/// held or faulted device list fails a delegated launch `sender's
/// authority changed` at once, before any other event (here its gate is
/// also closed), nothing spawned and never `outcome_unknown`; a halted
/// journal beside a faulted list fails it too (a halt alone fences: see
/// below).
#[test]
fn a_frozen_list_fails_the_launch_sender_authority_changed() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let (phone, _) = launch_host(&mut rig, root, &os, false);
        let usable = rig.bridge.start_view().list.clone().unwrap();
        type Break = (&'static str, fn(&mut ListState));
        let breaks: [Break; 3] = [
            ("frozen", |l| l.frozen = true),
            ("held", |l| l.held = true),
            ("faulted", |l| l.faulted = true),
        ];
        for (what, make) in breaks {
            let id = phone_launch(&mut rig, &phone, 60_000);
            waits_for(&mut rig, &id, details::REVOCATIONS_NOT_YET_CHECKED);
            make(rig.bridge.start_view().list.as_mut().unwrap());
            assert!(handed(&mut rig).is_empty(), "{what}");
            failed_with(&rig, &id, details::AUTHORITY_CHANGED);
            rig.bridge.start_view().list = Some(usable.clone());
        }
        // A fault halts the journal too: the list's fault decides.
        let id = phone_launch(&mut rig, &phone, 60_000);
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
        rig.bridge.start_view().list.as_mut().unwrap().faulted = true;
        assert!(handed(&mut rig).is_empty());
        failed_with(&rig, &id, details::AUTHORITY_CHANGED);
    });
}

/// Design I.4.3, "Launches" ("Unchanged from Atem's spec"): a
/// receipt-database fault fences a delegated launch not yet started at
/// once, as every launch: handed out to fail at its spawn boundary
/// (`Fence`), its outcome unknown (`outcome_unknown`), never waiting.
#[test]
fn a_receipt_database_fault_still_fences_outcome_unknown() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let (phone, _) = launch_host(&mut rig, root, &os, false);
        let id = phone_launch(&mut rig, &phone, 60_000);
        waits_for(&mut rig, &id, details::REVOCATIONS_NOT_YET_CHECKED);
        rig.bridge.work_fail();
        let launches = rig.bridge.take_remote_launches();
        assert_eq!(launches.len(), 1, "released to fail, never held");
        assert!(!rig.bridge.work.pending[&id].permit.load(Ordering::SeqCst));
        assert_eq!(launches[0].check.as_ref().unwrap()(), PreSpawn::Fence);
        assert!(!(launches[0].guard)());
        let error = spawn(&mut rig, root, &launches[0]).await.expect("fenced");
        assert!(error.downcast_ref::<NotSpawned>().is_none());
        assert_eq!(launch_state(&rig, &id), LaunchState::OutcomeUnknown);
    });
}

/// Hosting §5, unchanged for delegated launches: hosting switched off
/// (`enabled = false` in a file that loads) and a halted session journal
/// alone (the device list usable) fence a delegated launch not yet started
/// (`outcome_unknown`), and hosting on again doesn't revive it; a file that
/// doesn't load is waited out, in the queue and at the spawn boundary
/// (nothing spawned yet), the launch starting once it loads.
#[test]
fn hosting_off_and_a_halted_journal_alone_still_fence_a_delegated_launch() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let (phone, _) = launch_host(&mut rig, root, &os, true);
        // A file that doesn't load: it waits, never fenced.
        let id = phone_launch(&mut rig, &phone, 60_000);
        let good = rig.bridge.work.config.clone();
        rig.bridge.work.config = Config::default();
        rig.bridge.work.config_problem = Some("expected a table".into());
        for _ in 0..3 {
            assert!(rig.bridge.take_remote_launches().is_empty(), "held");
        }
        assert!(rig.bridge.work.pending[&id].permit.load(Ordering::SeqCst));
        rig.bridge.work.config = good.clone();
        rig.bridge.work.config_problem = None;
        let launches = handed(&mut rig);
        assert_eq!(launches.len(), 1);
        // Handed out, the file stops loading before the spawn: nothing is
        // spawned yet, so it waits there too, handed back.
        std::fs::write(root.join("runtime.toml"), "not = [valid").unwrap();
        let error = spawn(&mut rig, root, &launches[0])
            .await
            .expect("not spawned");
        assert_eq!(error.downcast_ref::<NotSpawned>(), Some(&NotSpawned::Wait));
        assert_eq!(launch_state(&rig, &id), LaunchState::Starting);
        configure(&mut rig, root, &phone_toml(root, 1));
        let launches = handed(&mut rig);
        assert_eq!(launches.len(), 1);
        assert!(spawn(&mut rig, root, &launches[0]).await.is_none());
        assert_eq!(launch_state(&rig, &id), LaunchState::Started);
        // Hosting switched off: fenced, never revived.
        let id = phone_launch(&mut rig, &phone, 60_000);
        rig.bridge.work.config.enabled = false;
        let launches = rig.bridge.take_remote_launches();
        assert_eq!(launches.len(), 1, "released to fail, never held");
        assert!(!rig.bridge.work.pending[&id].permit.load(Ordering::SeqCst));
        rig.bridge.work.config = good;
        assert_eq!(launches[0].check.as_ref().unwrap()(), PreSpawn::Fence);
        assert!(spawn(&mut rig, root, &launches[0]).await.is_some());
        assert_eq!(launch_state(&rig, &id), LaunchState::OutcomeUnknown);
        // A halted journal alone.
        let id = phone_launch(&mut rig, &phone, 60_000);
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
        let launches = handed(&mut rig);
        assert_eq!(launches.len(), 1, "released to fail, never held");
        assert_eq!(launches[0].check.as_ref().unwrap()(), PreSpawn::Fence);
        assert!(spawn(&mut rig, root, &launches[0]).await.is_some());
        assert_eq!(launch_state(&rig, &id), LaunchState::OutcomeUnknown);
    });
}

/// Hook off = main, and v1 senders keep hosting §5's rules: with
/// `host.delegated` off the phone's `host_launch` is v1's (no check, no
/// delegated record), so its sender's absent channel fences it at once
/// and it is handed out to fail at its guard, `outcome_unknown`, as
/// before; its stored record has v1's fields only. With the hook on, a
/// `local` launch on message has no check either and its guard decides at
/// the spawn boundary, as before.
#[test]
fn v1_launches_unchanged() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let (_, phone) = pin_phone(&mut rig, root);
        configure(&mut rig, root, &phone_toml(root, 1));
        assert!(!rig.bridge.features.delegated);
        let id = phone_launch(&mut rig, &phone, 60_000);
        assert!(rig.bridge.work.pending[&id].delegated.is_none());
        let launches = rig.bridge.take_remote_launches();
        assert_eq!(launches.len(), 1, "fenced: no channel of its sender");
        assert!(launches[0].check.is_none());
        assert!(!rig.bridge.work.pending[&id].permit.load(Ordering::SeqCst));
        assert!(!(launches[0].guard)());
        let error = spawn(&mut rig, root, &launches[0]).await.expect("fenced");
        assert_eq!(
            error.to_string(),
            "remote launch authorization changed",
            "v1's refusal"
        );
        assert_eq!(launch_state(&rig, &id), LaunchState::OutcomeUnknown);
        let stored: serde_json::Value = serde_json::from_str(
            &rig.bridge
                .work
                .store
                .as_ref()
                .unwrap()
                .db
                .query_row("SELECT record FROM launches WHERE id=?1", [&id], |r| {
                    r.get::<_, String>(0)
                })
                .unwrap(),
        )
        .unwrap();
        let mut keys: Vec<_> = stored.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "digest",
                "expires_at",
                "principal",
                "profile_id",
                "profile_revision",
                "status"
            ]
        );
        // The hook on: a local launch on message keeps its guard alone.
        rig.bridge.features =
            crate::runtime::test_hooks::HostFeatures::parse("host.delegated").unwrap();
        launch_route(&mut rig, root);
        send_q(&mut rig, true);
        let local = launch_records(&rig)
            .into_iter()
            .find(|l| l.principal == "local")
            .unwrap();
        assert!(
            rig.bridge.work.pending[&local.status.request_id]
                .delegated
                .is_none()
        );
        let launches = rig.bridge.take_remote_launches();
        assert_eq!(launches.len(), 1);
        assert!(launches[0].check.is_none());
        // Its guard re-reads a file without its route: v1's fence.
        assert!(!(launches[0].guard)());
        assert!(spawn(&mut rig, root, &launches[0]).await.is_some());
        assert_eq!(
            launch_state(&rig, &local.status.request_id),
            LaunchState::OutcomeUnknown
        );
    });
}

/// The delegated clock, as one that reads nothing: no OS reading and no
/// record (a store of its own, never written).
fn no_reading(rig: &mut LocalRig, root: &Path) {
    let dir = root.join("no-reading");
    std::fs::create_dir_all(&dir).unwrap();
    let store = Store::open(&dir).unwrap();
    rig.bridge.work.clock = Some(HostClock::with_readings(&store, || None));
}

/// Design I.4.3 "As built" (Task 28 review m2(a)): with no reading of the
/// delegated clock a launch's expiry can't be compared, so it waits, in
/// the queue and at the spawn boundary (one already handed out is handed
/// back), still `starting`, never fenced; once a reading comes back, both
/// are handed out.
#[test]
fn a_launch_waits_without_a_reading_of_the_delegated_clock() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let (phone, _) = launch_host(&mut rig, root, &os, true);
        let first = phone_launch(&mut rig, &phone, HOUR_MS);
        let launches = handed(&mut rig);
        assert_eq!(launches.len(), 1);
        no_reading(&mut rig, root);
        passes(&mut rig, 1);
        assert_eq!(rig.bridge.start_view().now_d_ms, None, "no reading");
        assert_eq!(launches[0].check.as_ref().unwrap()(), PreSpawn::Wait);
        let error = spawn(&mut rig, root, &launches[0])
            .await
            .expect("not spawned");
        assert_eq!(error.downcast_ref::<NotSpawned>(), Some(&NotSpawned::Wait));
        let second = phone_launch(&mut rig, &phone, HOUR_MS);
        for _ in 0..3 {
            assert!(handed(&mut rig).is_empty(), "waits for a reading");
        }
        for id in [&first, &second] {
            assert_eq!(launch_state(&rig, id), LaunchState::Starting);
            assert!(rig.bridge.work.pending[id].permit.load(Ordering::SeqCst));
        }
        assert_eq!(rig.sessions.len(), 1, "nothing spawned");
        // A reading again.
        manual_clock(&mut rig, &os);
        let mut ids: Vec<String> = handed(&mut rig).into_iter().map(|l| l.request_id).collect();
        ids.sort();
        let mut both = vec![first, second];
        both.sort();
        assert_eq!(ids, both);
    });
}

/// Design I.4.3 "As built" (Task 28 review m2(b)): a launch waiting out a
/// `runtime.toml` that doesn't load still fails at its expiry on the
/// delegated clock, `expired before the spawn`: nothing spawned, never
/// `outcome_unknown`.
#[test]
fn the_expiry_fails_a_launch_waiting_out_an_invalid_file() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let (phone, _) = launch_host(&mut rig, root, &os, true);
        let id = phone_launch(&mut rig, &phone, 60_000);
        rig.bridge.work.config = Config::default();
        rig.bridge.work.config_problem = Some("expected a table".into());
        for _ in 0..3 {
            assert!(handed(&mut rig).is_empty(), "waits out the file");
        }
        assert_eq!(launch_state(&rig, &id), LaunchState::Starting);
        os.pass(120_000);
        assert!(handed(&mut rig).is_empty());
        failed_with(&rig, &id, details::EXPIRED_BEFORE_THE_SPAWN);
        assert_eq!(rig.sessions.len(), 1, "nothing spawned");
    });
}

/// Task 28 review m4: a delegated launch's failure is only logged (its
/// query reads `failed`). It never goes into `work.refused`, the reasons of
/// local launch-on-message tasks, so a burst of them can't evict one there
/// (that map clears itself when full).
#[test]
fn delegated_launch_failures_leave_local_reasons_alone() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let (phone, _) = launch_host(&mut rig, root, &os, true);
        // One short of full: the next reason would clear the map.
        for n in 0..255 {
            rig.bridge.work.refused.insert(
                format!("local-launch-{n}"),
                "at most 16 sessions can run at once".into(),
            );
        }
        let before = rig.bridge.work.refused.clone();
        for _ in 0..3 {
            let id = phone_launch(&mut rig, &phone, HOUR_MS);
            rig.bridge.start_view().standings.insert(
                PHONE.into(),
                SenderStanding {
                    revoked: Some("rec-revoke".into()),
                    ..SenderStanding::default()
                },
            );
            assert!(handed(&mut rig).is_empty());
            failed_with(&rig, &id, details::SENDER_REVOKED);
            rig.bridge.start_view().standings.remove(PHONE);
        }
        assert_eq!(rig.bridge.work.refused, before, "local reasons untouched");
    });
}
