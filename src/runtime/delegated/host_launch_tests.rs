// Launch on message on the receiving host (design II.6; host-work-v1
// §11.5, "`select` from host senders"; collaboration §5, "When no agent
// runs"): a host sender's `select` with `launch` starts a session only on a
// route an `atem:<this host>/<route_id>` selector names, that launches on
// message, consents to the sender, and whose project grants `launch` as
// well as a task's ops. The launch is reserved in the admission
// transaction and checked at the spawn boundary as a delegated sender's;
// its tasks wait for it. Shares the admission tests' rig (`sp_host`,
// `ad_*`); every name here starts with `hl_`.

/// The rig as a receiving host with a launch route: `sp_host`, and profile
/// `pl` (a directory no agent runs in), route `rl` launching it on message
/// for `project:pl`, a project listing this host and B with `launch` and a
/// task's ops.
fn hl_host(rig: &mut LocalRig, root: &Path, os: &ManualOs) -> MbHost {
    let mut host = sp_host(rig, root, os);
    let cwd = root.join("launched");
    std::fs::create_dir_all(&cwd).unwrap();
    let mut profile = rig.bridge.work.config.profile("p").unwrap().clone();
    profile.id = "pl".into();
    profile.cwd = cwd;
    profile.project = "local:launched".into();
    rig.bridge.work.config.profiles.push(profile);
    rig.bridge
        .work
        .config
        .routes
        .push(crate::runtime::host_work::Route {
            id: "rl".into(),
            revision: 1,
            profile_id: "pl".into(),
            principals: vec!["project:pl".into()],
            labels: vec![],
            launch: crate::runtime::host_work::RouteLaunch::OnMessage,
            results: false,
            auto_report: Default::default(),
        });
    hl_project(rig, &mut host, true);
    host
}

/// Project `pl` signed and carried: this host and B, a task's ops, and
/// `launch` when `launch`.
fn hl_project(rig: &mut LocalRig, host: &mut MbHost, launch: bool) {
    let mut ops = task_ops().to_vec();
    if launch {
        ops.push(ProjectOp::Launch);
    }
    sign_and_carry(
        rig,
        &mut host.s,
        atem_client::membership::project_set("pl", ["host", "host-b"], ops, 0).unwrap(),
    );
    mb_tick(rig, host, 0);
}

/// B's message to this host with one `select` recipient.
fn hl_message(rig: &LocalRig, selectors: &[&str], launch: bool) -> Message {
    ad_message(
        rig,
        vec![Destination::Select {
            selectors: selectors.iter().map(|s| s.to_string()).collect(),
            budget: 1,
            launch,
        }],
    )
}

/// The launches host senders' requests reserved: their records.
fn hl_launches(db: &rusqlite::Connection) -> Vec<LaunchRecord> {
    let mut q = db
        .prepare(
            "SELECT record FROM launches WHERE json_extract(record,'$.principal') GLOB 'host:*'",
        )
        .unwrap();
    q.query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .map(|r| serde_json::from_str(&r.unwrap()).unwrap())
        .collect()
}

/// [`verdict`] on the start view as the pass refreshes it.
fn hl_verdict(rig: &mut LocalRig, id: &str) -> LaunchVerdict {
    rig.bridge.refresh_start_view();
    verdict(rig, id)
}

/// B's request, admitted: its tasks.
fn hl_admit(rig: &mut LocalRig, message: &Message) -> Vec<WorkRecord> {
    ad_inbox_request(rig, message);
    ad_admit(rig);
    ad_tasks(rig, message)
}

/// Item 2: a `select` with `launch` naming the launch route reserves its
/// launch in the admission transaction (another connection reads the
/// launch, the task targeting its session and their link together), hands
/// it to the launcher with its spawn-boundary check, and reports the task
/// in its resolution. A second request naming the route while that launch
/// starts shares it.
#[test]
fn a_select_with_launch_reserves_its_launch_with_its_admission() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let _host = hl_host(&mut rig, root, &os);
        let message = hl_message(&rig, &["atem:host/rl"], true);
        let tasks = hl_admit(&mut rig, &message);
        assert_eq!(tasks.len(), 1);
        let other = Store::open(&root.join("runtime")).unwrap();
        let launches = hl_launches(&other.db);
        assert_eq!(launches.len(), 1, "reserved with the task");
        let launch = &launches[0];
        assert_eq!(
            (
                launch.principal.as_str(),
                launch.profile_id.as_str(),
                launch.status.state
            ),
            ("host:host-b", "pl", LaunchState::Starting)
        );
        let task = &tasks[0];
        assert_eq!(
            (
                task.task.target.session_id.as_str(),
                task.task.target.process_gen.as_str(),
                task.route_id.as_str()
            ),
            (
                launch.status.session_id.as_str(),
                launch.status.process_gen.as_str(),
                "rl"
            )
        );
        assert_eq!(
            crate::runtime::delegated::admit::launch_of(&other.db, &task.task.task_id).unwrap(),
            Some(launch.status.request_id.clone())
        );
        let id = &launch.status.request_id;
        let queued: Vec<_> = rig.bridge.work.launches.iter().collect();
        assert_eq!(queued.len(), 1);
        assert_eq!(&queued[0].request_id, id);
        assert!(queued[0].check.is_some(), "checked at the spawn boundary");
        assert!(rig.bridge.work.pending[id].delegated.is_some());
        let receipts = ad_receipts(&rig, &message);
        assert_eq!(ad_resolved(&receipts[0]).len(), 1);
        // A second request naming the route shares the launch under way.
        let second = hl_message(&rig, &["atem:host/rl"], true);
        let shared = hl_admit(&mut rig, &second);
        assert_eq!(shared[0].task.target.session_id, launch.status.session_id);
        assert_eq!(hl_launches(&other.db).len(), 1, "no second launch");
        assert_eq!(rig.bridge.work.launches.len(), 1);
    });
}

/// Without every condition a `select` launches nothing and resolves to the
/// running agents only (none on these routes: `no_match`): no `launch`;
/// no selector naming the launch route (another route named); the route
/// not launching on message; a project without `launch`; a route not
/// consenting to the sender.
#[test]
fn without_every_condition_a_select_launches_nothing() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = hl_host(&mut rig, root, &os);
        fn route(rig: &mut LocalRig) -> &mut crate::runtime::host_work::Route {
            rig.bridge
                .work
                .config
                .routes
                .iter_mut()
                .find(|r| r.id == "rl")
                .unwrap()
        }
        let no_launch = |rig: &mut LocalRig, selectors: &[&str], launch: bool| {
            let message = hl_message(rig, selectors, launch);
            assert!(hl_admit(rig, &message).is_empty(), "{selectors:?}");
            let receipts = ad_receipts(rig, &message);
            assert_eq!(receipts[0].delivery, Delivery::NoMatch {}, "{selectors:?}");
            let db = &rig.bridge.work.store.as_ref().unwrap().db;
            assert!(hl_launches(db).is_empty(), "{selectors:?}");
            assert!(rig.bridge.work.launches.is_empty());
        };
        no_launch(&mut rig, &["atem:host/rl"], false);
        no_launch(&mut rig, &["atem:host/r"], true);
        route(&mut rig).launch = crate::runtime::host_work::RouteLaunch::Off;
        no_launch(&mut rig, &["atem:host/rl"], true);
        route(&mut rig).launch = crate::runtime::host_work::RouteLaunch::OnMessage;
        route(&mut rig).principals = vec!["project:other".into()];
        no_launch(&mut rig, &["atem:host/rl"], true);
        route(&mut rig).principals = vec!["project:pl".into()];
        hl_project(&mut rig, &mut host, false);
        no_launch(&mut rig, &["atem:host/rl"], true);
    });
}

/// The tasks wait for their launch: one that failed (refused at its
/// spawn, or of unknown outcome after a restart) fails them, never runs
/// them, and never makes them `outcome_unknown`.
#[test]
fn a_task_whose_launch_failed_fails() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let _host = hl_host(&mut rig, root, &os);
        for (state, detail) in [
            (
                LaunchState::Failed,
                "approved route launch failed; check its cwd and environment",
            ),
            (
                LaunchState::OutcomeUnknown,
                "launch outcome unknown; the reserved launch will not be repeated",
            ),
        ] {
            let message = hl_message(&rig, &["atem:host/rl"], true);
            let task = hl_admit(&mut rig, &message).remove(0);
            let id = rig.bridge.work.launches.pop_front().unwrap().request_id;
            rig.bridge.remote_launched(&id, state);
            rig.until(|r| ad_tasks(r, &message)[0].status.state == WorkState::Failed)
                .await;
            assert_eq!(ad_tasks(&rig, &message)[0].status.detail, detail);
            assert!(
                attempts(&rig, &task.task.task_id).is_empty(),
                "never attempted"
            );
        }
    });
}

/// The launch is a delegated sender's at the spawn boundary
/// (`launch_check`): its sender revoked, the route no longer launching on
/// message, or its project no longer granting `launch` each fail it there.
#[test]
fn a_host_senders_launch_is_checked_at_the_spawn_boundary() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = hl_host(&mut rig, root, &os);
        let launch = |rig: &mut LocalRig| {
            let message = hl_message(rig, &["atem:host/rl"], true);
            hl_admit(rig, &message);
            rig.bridge.work.launches.back().unwrap().request_id.clone()
        };
        let id = launch(&mut rig);
        let first = hl_verdict(&mut rig, &id);
        assert!(!matches!(first, LaunchVerdict::Fail(_)), "{first:?}");
        hl_project(&mut rig, &mut host, false);
        assert_eq!(
            hl_verdict(&mut rig, &id),
            LaunchVerdict::Fail(details::AUTHORIZATION_NARROWED)
        );
        hl_project(&mut rig, &mut host, true);
        rig.bridge
            .work
            .config
            .routes
            .iter_mut()
            .find(|r| r.id == "rl")
            .unwrap()
            .launch = crate::runtime::host_work::RouteLaunch::Off;
        assert_eq!(
            hl_verdict(&mut rig, &id),
            LaunchVerdict::Fail(details::ROUTE_CHANGED)
        );
        sign_and_carry(
            &mut rig,
            &mut host.s,
            atem_client::membership::host_sender_revoke("host-b", false, 0).unwrap(),
        );
        mb_tick(&mut rig, &mut host, 0);
        assert_eq!(
            hl_verdict(&mut rig, &id),
            LaunchVerdict::Fail(details::SENDER_REVOKED)
        );
        // Handed out, it fails before its spawn, never `outcome_unknown`.
        assert!(rig.bridge.take_remote_launches().is_empty());
        failed_with(&rig, &id, details::SENDER_REVOKED);
    });
}

/// Review L5: a launch refused at its spawn check (here its route no longer
/// launching on message) fails its tasks with that reason, as stage 1
/// fails them with the launcher's (`approved route launch not started:
/// <why>`), never the cwd and environment guess.
#[test]
fn a_launch_refused_at_its_spawn_check_fails_its_tasks_with_why() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let _host = hl_host(&mut rig, root, &os);
        let message = hl_message(&rig, &["atem:host/rl"], true);
        hl_admit(&mut rig, &message);
        let id = rig.bridge.work.launches.back().unwrap().request_id.clone();
        rig.bridge
            .work
            .config
            .routes
            .iter_mut()
            .find(|r| r.id == "rl")
            .unwrap()
            .launch = crate::runtime::host_work::RouteLaunch::Off;
        rig.bridge.refresh_start_view();
        assert!(rig.bridge.take_remote_launches().is_empty());
        failed_with(&rig, &id, details::ROUTE_CHANGED);
        rig.until(|r| ad_tasks(r, &message)[0].status.state == WorkState::Failed)
            .await;
        assert_eq!(
            ad_tasks(&rig, &message)[0].status.detail,
            "approved route launch not started: route changed"
        );
    });
}

/// Review L6: a launch under way is shared as stage 1 shares one, and only
/// a launch of the same sender: (a) a started launch only while its
/// session's launch project isn't known yet; (b) one launch per profile
/// per request, across its recipients; (c) another sender's launch is
/// never shared (its admission and expiry are its own).
#[test]
fn a_launch_is_shared_only_as_stage_1_shares_one() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let _host = hl_host(&mut rig, root, &os);
        let launches = |rig: &LocalRig| hl_launches(&rig.bridge.work.store.as_ref().unwrap().db);
        // (c) A launch under way that another sender's request reserved.
        let first = hl_message(&rig, &["atem:host/rl"], true);
        hl_admit(&mut rig, &first);
        let theirs = launches(&rig).remove(0);
        let store = rig.bridge.work.store.as_ref().unwrap();
        let mut other = theirs.clone();
        other.principal = "host:host-c".into();
        store.save_launch(&other).unwrap();
        let second = hl_message(&rig, &["atem:host/rl"], true);
        let tasks = hl_admit(&mut rig, &second);
        assert_ne!(
            tasks[0].task.target.session_id, theirs.status.session_id,
            "not another sender's"
        );
        assert_eq!(launches(&rig).len(), 2);
        // Nothing under way from here: each part starts afresh.
        let afresh = |rig: &mut LocalRig| {
            rig.bridge.work.launches.clear();
            rig.bridge.work.pending.clear();
            let store = rig.bridge.work.store.as_ref().unwrap();
            for mut record in launches(rig) {
                record.status.state = LaunchState::Failed;
                store.save_launch(&record).unwrap();
            }
        };
        // (a) A started launch whose session's project is known (the rig's
        // own session stands for it) isn't shared.
        afresh(&mut rig);
        let store = rig.bridge.work.store.as_ref().unwrap();
        let mut known = launches(&rig).remove(0);
        known.principal = "host:host-b".into();
        known.status.request_id = uuid::Uuid::new_v4().to_string();
        known.status.session_id = rig.sid.to_string();
        known.status.process_gen = rig.sessions[&rig.sid].process_gen.clone();
        known.status.state = LaunchState::Started;
        store
            .db
            .execute(
                "INSERT INTO launches(id,record) VALUES(?1,?2)",
                rusqlite::params![
                    known.status.request_id,
                    serde_json::to_string(&known).unwrap()
                ],
            )
            .unwrap();
        store
            .db
            .execute(
                "INSERT INTO mail_launches(task_id, request_id, route_id, route_revision)
                VALUES('t-known', ?1, 'rl', 1)",
                [&known.status.request_id],
            )
            .unwrap();
        let third = hl_message(&rig, &["atem:host/rl"], true);
        let tasks = hl_admit(&mut rig, &third);
        assert_ne!(tasks[0].task.target.session_id, rig.sid.to_string());
        assert_eq!(rig.bridge.work.launches.len(), 1, "a launch of its own");
        // (b) Two recipients naming two routes of one profile: one launch.
        afresh(&mut rig);
        let mut twin = rig.bridge.work.config.route("rl").unwrap().clone();
        twin.id = "rl2".into();
        rig.bridge.work.config.routes.push(twin);
        let pair = ad_message(
            &rig,
            vec![
                Destination::Select {
                    selectors: vec!["atem:host/rl2".into()],
                    budget: 1,
                    launch: true,
                },
                Destination::Select {
                    selectors: vec!["atem:host/rl".into()],
                    budget: 1,
                    launch: true,
                },
            ],
        );
        hl_admit(&mut rig, &pair);
        assert_eq!(rig.bridge.work.launches.len(), 1, "one per profile");
    });
}

// ── Ruling R51: a spawn is a start, so a launch is judged per entry ──

/// What B's task says once its launch was stopped by a narrowing.
const HL_NOT_STARTED: &str = "approved route launch not started: sender's authorization narrowed";

/// Project `pl` signed and carried with no pass after it (the entries
/// reach host-work's pass together): `launch` when `launch`.
fn hl_entry(rig: &mut LocalRig, host: &mut MbHost, launch: bool) {
    let mut ops = task_ops().to_vec();
    if launch {
        ops.push(ProjectOp::Launch);
    }
    sign_and_carry(
        rig,
        &mut host.s,
        atem_client::membership::project_set("pl", ["host", "host-b"], ops, 0).unwrap(),
    );
}

/// B's request naming the launch route, admitted, its sender's gate open
/// (the mailbox read: its part open), and host-work's device-list effects
/// written up to the head: the message and its launch's request id
/// (queued, not handed out).
fn hl_queued(rig: &mut LocalRig) -> (Message, String) {
    let message = hl_message(rig, &["atem:host/rl"], true);
    hl_admit(rig, &message);
    rig.bridge.start_view().gates.set_mailbox(true);
    rig.bridge.host_senders_pass();
    let id = rig.bridge.work.launches.back().unwrap().request_id.clone();
    (message, id)
}

/// Profile `pl` as the rig's `runtime.toml` on disk (what the spawn check
/// re-reads), the same as the bridge has it.
fn hl_configure(rig: &LocalRig, root: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let p = rig.bridge.work.config.profile("pl").unwrap();
    let mut text = format!(
        "version = 1\nenabled = true\n[[profiles]]\nid = {:?}\nrevision = {}\nlabel = {:?}\n\
         provider = {:?}\ncwd = {:?}\nproject = {:?}\nargs = {:?}\nprincipals = {:?}\n\
         env_names = {:?}\n",
        p.id, p.revision, p.label, p.provider, p.cwd, p.project, p.args, p.principals, p.env_names
    );
    if let Some(env) = &p.env_file {
        text += &format!("env_file = {env:?}\n");
    }
    let path = root.join("runtime.toml");
    std::fs::write(&path, text).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let loaded = Config::load_for(root, rig.bridge.features).unwrap();
    assert!(
        loaded.profile("pl") == Some(p),
        "the file has the bridge's profile"
    );
}

/// Ruling R51 (a spawn is a start), per entry: B's task waits for its
/// launch, queued with no agent running, and `launch` is taken out of
/// project `pl`, then given back, in entries host-work's pass reads
/// together. The spawn boundary waits until their effects are written;
/// then the launch fails at the narrowing (`sender's authorization
/// narrowed`: its record `failed`, why kept) and its task with it
/// (`approved route launch not started: …`), in the effects' transaction.
/// It leaves the queue, never spawns, and neither the restore nor a later
/// entry revives it or its task.
#[test]
fn a_launch_narrowed_then_restored_in_one_catch_up_never_spawns() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = hl_host(&mut rig, root, &os);
        let (message, id) = hl_queued(&mut rig);
        assert_eq!(hl_verdict(&mut rig, &id), LaunchVerdict::Go);
        hl_entry(&mut rig, &mut host, false);
        hl_entry(&mut rig, &mut host, true);
        assert_eq!(
            hl_verdict(&mut rig, &id),
            LaunchVerdict::Wait(details::DEVICE_LIST_UPDATE_PENDING),
            "the spawn boundary waits for the entries' effects"
        );
        rig.bridge.host_senders_pass();
        let db = &rig.bridge.work.store.as_ref().unwrap().db;
        assert_eq!(launch_state(&rig, &id), LaunchState::Failed);
        assert_eq!(
            crate::runtime::delegated::admit::launch_failure(db, &id)
                .unwrap()
                .as_deref(),
            Some(details::AUTHORIZATION_NARROWED)
        );
        let task = ad_tasks(&rig, &message).remove(0);
        assert_eq!(
            (task.status.state, task.status.detail.as_str()),
            (WorkState::Failed, HL_NOT_STARTED)
        );
        assert!(!rig.bridge.work.pending.contains_key(&id));
        assert!(
            rig.bridge.take_remote_launches().is_empty(),
            "never handed out"
        );
        hl_project(&mut rig, &mut host, true);
        rig.bridge.host_senders_pass();
        passes(&mut rig, 2);
        assert_eq!(launch_state(&rig, &id), LaunchState::Failed);
        assert_eq!(ad_tasks(&rig, &message)[0].status.detail, HL_NOT_STARTED);
        assert!(rig.bridge.take_remote_launches().is_empty());
        assert!(
            attempts(&rig, &task.task.task_id).is_empty(),
            "never attempted"
        );
    });
}

/// Ruling R51 at the spawn boundary: a launch already handed to the
/// launcher, its check not run yet, when `launch` is narrowed then
/// restored. The check waits until host-work wrote the entries' effects,
/// then refuses it (`sender's authorization narrowed`), nothing spawned;
/// the launcher's report changes nothing. A launch whose check let it go
/// before the entries committed had started then: they don't reach it.
#[test]
fn the_spawn_check_refuses_a_launch_an_entry_stopped() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = hl_host(&mut rig, root, &os);
        hl_configure(&rig, root);
        let (message, id) = hl_queued(&mut rig);
        rig.bridge.refresh_start_view();
        let handed = rig.bridge.take_remote_launches();
        assert_eq!(handed.len(), 1, "handed to the launcher");
        let check = handed[0].check.clone().unwrap();
        hl_entry(&mut rig, &mut host, false);
        hl_entry(&mut rig, &mut host, true);
        assert_eq!(check(), PreSpawn::Wait, "waits for the entries' effects");
        rig.bridge.host_senders_pass();
        assert_eq!(check(), PreSpawn::Fail(details::AUTHORIZATION_NARROWED));
        let refused = anyhow::Error::from(NotSpawned::Fail(details::AUTHORIZATION_NARROWED));
        rig.bridge.launch_finished(&id, Err(&refused), true);
        assert_eq!(launch_state(&rig, &id), LaunchState::Failed);
        assert_eq!(ad_tasks(&rig, &message)[0].status.detail, HL_NOT_STARTED);
        // Let go before the entries: it started then.
        let (_, gone) = hl_queued(&mut rig);
        assert_ne!(gone, id);
        rig.bridge.refresh_start_view();
        let handed = rig.bridge.take_remote_launches();
        let check = handed[0].check.clone().unwrap();
        assert_eq!(check(), PreSpawn::Go);
        hl_entry(&mut rig, &mut host, false);
        hl_entry(&mut rig, &mut host, true);
        rig.bridge.host_senders_pass();
        assert_eq!(launch_state(&rig, &gone), LaunchState::Starting);
        assert!(rig.bridge.work.pending.contains_key(&gone));
        rig.bridge.launch_finished(&gone, Ok(()), false);
        assert_eq!(launch_state(&rig, &gone), LaunchState::Started);
    });
}

/// Ruling R51 across a crash, after the commit: the entries' effects
/// committed (the launch `failed`, why kept, its task failed) and the
/// runtime killed before the bridge let go of the launch. At the start
/// nothing of it is queued and nothing spawns; the record and the task
/// stay as committed (the start's recovery takes only launches still
/// `starting`); applied again from the same `seq`, nothing is written.
#[test]
fn a_launchs_stop_committed_before_a_crash_stays() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = hl_host(&mut rig, root, &os);
        let (message, id) = hl_queued(&mut rig);
        let before = applied(&rig);
        hl_entry(&mut rig, &mut host, false);
        hl_entry(&mut rig, &mut host, true);
        let queued = vec![host_senders::QueuedLaunch {
            request_id: id.clone(),
            admission: rig.bridge.work.pending[&id]
                .delegated
                .as_ref()
                .unwrap()
                .launch
                .admission
                .clone(),
        }];
        let apply = |rig: &LocalRig| {
            let store = rig.bridge.work.store.as_ref().unwrap();
            let list = rig.bridge.membership.as_ref().unwrap().membership();
            let tx = store.immediate().unwrap();
            let effects =
                host_senders::list_effects(store, &tx, list, "host", before, &queued).unwrap();
            host_senders::set_applied_seq(&tx, &list.genesis_hash(), list.head().seq).unwrap();
            tx.commit().unwrap();
            effects
        };
        let effects = apply(&rig);
        assert_eq!(
            effects.launches,
            [(id.clone(), details::AUTHORIZATION_NARROWED)]
        );
        restart(&mut rig, root, &os, false, true);
        passes(&mut rig, 2);
        assert_eq!(launch_state(&rig, &id), LaunchState::Failed);
        assert_eq!(ad_tasks(&rig, &message)[0].status.detail, HL_NOT_STARTED);
        assert!(rig.bridge.work.pending.is_empty());
        assert!(
            rig.bridge.take_remote_launches().is_empty(),
            "never spawned"
        );
        let again = apply(&rig);
        assert!(
            again.launches.is_empty() && again.followups.is_empty(),
            "{again:?}"
        );
        assert_eq!(ad_tasks(&rig, &message)[0].status.detail, HL_NOT_STARTED);
    });
}

/// Ruling R51 across a crash, before the commit: `launch` narrowed then
/// restored committed in the device list, the runtime killed before
/// host-work wrote their effects. The launch was in that run's memory
/// only: at the start, as every launch not started at a restart, its
/// record `starting` is of unknown outcome, so it is never spawned again,
/// and its task fails; the start's replay of the entries reaches no launch
/// of the run before (Atem's reading: it may have spawned before them).
#[test]
fn a_launch_narrowed_then_restored_across_a_crash_never_spawns() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = hl_host(&mut rig, root, &os);
        let (message, id) = hl_queued(&mut rig);
        hl_entry(&mut rig, &mut host, false);
        hl_entry(&mut rig, &mut host, true);
        restart(&mut rig, root, &os, false, true);
        passes(&mut rig, 2);
        assert_eq!(launch_state(&rig, &id), LaunchState::OutcomeUnknown);
        assert!(
            rig.bridge.take_remote_launches().is_empty(),
            "never spawned"
        );
        rig.until(|r| ad_tasks(r, &message)[0].status.state == WorkState::Failed)
            .await;
        assert_eq!(
            ad_tasks(&rig, &message)[0].status.detail,
            "launch outcome unknown; the reserved launch will not be repeated"
        );
    });
}
