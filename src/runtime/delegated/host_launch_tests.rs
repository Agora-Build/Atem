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
