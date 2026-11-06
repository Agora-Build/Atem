//! Local launch-on-message reserves identities before invoking the worker launcher.
use super::*;
use crate::runtime::{
    collab::{self, Candidate, ResolvedTask},
    host_work::{Route, RouteLaunch},
};
use anyhow::{Result, anyhow, bail};
use atem_client::session::{
    messages::{Destination, Message},
    select::{MAX_AGENTS, Selector},
};
use rusqlite::{OptionalExtension, Transaction, params};

/// The detail of a local task whose launch a plain session-journal halt
/// fenced before it started (`halted_launches`).
const HALTED_LAUNCH: &str =
    "launch not started: the session journal halted; run `atem runtime restart`";

pub(super) struct LocalLaunch {
    record: LaunchRecord,
    route: Route,
}
pub(super) struct Resolution {
    pub(super) tasks: Vec<ResolvedTask>,
    launches: Vec<LocalLaunch>,
}

impl HostBridge {
    pub(super) fn collab_resolve(
        &self,
        atem_id: &str,
        message: &Message,
        launch: bool,
        sessions: &BTreeMap<SessionId, BrokerSession>,
    ) -> Result<Resolution> {
        let Destination::Select { selectors, budget } = &message.recipients[0].destination else {
            bail!("invalid local destination");
        };
        let selectors: Vec<Selector> = selectors
            .iter()
            .map(|s| s.parse().map_err(|e| anyhow!("{e}")))
            .collect::<Result<_>>()?;
        let mut candidates = self.collab_candidates(sessions);
        let mut pending_ids = HashMap::new();
        let mut profiles = HashSet::new();
        for (id, pending) in &self.work.pending {
            let Some(route) = pending.local_route.as_ref() else {
                continue;
            };
            let Some(record) = self.work.store.as_ref().unwrap().launch(id)? else {
                continue;
            };
            if !pending.permit.load(Ordering::SeqCst)
                || self.work.config.route(&route.id) != Some(route)
            {
                continue;
            }
            candidates.push(self.launch_candidate(route, &record, message.created_at));
            profiles.insert(pending.profile.id.clone());
            pending_ids.insert(record.status.session_id.clone(), id.clone());
        }
        // A session this runtime started for a route stays that route's
        // candidate until its launch project is known (its worker's record
        // is read a pass after it starts): a message in that window must not
        // start a second one.
        let store = self.work.store.as_ref().unwrap();
        for session in sessions
            .values()
            .filter(|s| s.is_live() && self.projects.key_of(s.id.as_str()).is_none())
        {
            let Some(reserved) = collab::launched_by(store, session.id.as_str())? else {
                continue;
            };
            let Some(launch_id) = reserved.launch_request_id.clone() else {
                continue;
            };
            let Some(route) = self.work.config.route(&reserved.route_id).filter(|route| {
                route.revision == reserved.route_revision
                    && route.principals.iter().any(|p| p == "local")
            }) else {
                continue;
            };
            let Some(profile) = self.work.config.profile(&route.profile_id) else {
                continue;
            };
            if session.process_gen != reserved.process_gen
                || session.cwd != profile.cwd
                || session.provider != profile.provider
                || !store
                    .launch(&launch_id)?
                    .is_some_and(|l| l.status.state == LaunchState::Started)
            {
                continue;
            }
            let labels = self
                .work
                .config
                .instance
                .labels
                .iter()
                .chain(&route.labels)
                .chain(session.self_tags())
                .filter_map(|s| s.parse().ok())
                .collect();
            candidates.push(Candidate {
                route_id: route.id.clone(),
                route_revision: route.revision,
                session_id: session.id.to_string(),
                process_gen: session.process_gen.clone(),
                started_ms: session.created_at_ms,
                labels,
            });
            profiles.insert(profile.id.clone());
            pending_ids.insert(session.id.to_string(), launch_id);
        }
        let mut launches = Vec::new();
        let mut routes: Vec<_> = self.work.config.routes.iter().collect();
        routes.sort_by(|a, b| a.id.cmp(&b.id));
        for route in routes {
            // Only a send that asked for it starts a session, and only on a
            // route one of its `atem:<atem_id>/<route_id>` selectors names
            // (spec section 5): never one that a label or the bare instance
            // matches. The route's own `launch` setting says it may.
            let named = selectors.iter().any(|s| {
                matches!(s, Selector::Instance { atem_id: id, route_id: Some(r) }
                    if id == atem_id && *r == route.id)
            });
            if !launch
                || !named
                || route.launch != RouteLaunch::OnMessage
                || !route.principals.iter().any(|p| p == "local")
                || candidates.iter().any(|c| c.route_id == route.id)
            {
                continue;
            }
            let profile = self
                .work
                .config
                .profile(&route.profile_id)
                .ok_or_else(|| anyhow!("missing profile"))?;
            if !profiles.insert(profile.id.clone()) {
                continue;
            }
            let record = LaunchRecord {
                principal: "local".into(),
                profile_id: profile.id.clone(),
                profile_revision: profile.revision,
                expires_at: message.expires_at,
                digest: hw::digest(&serde_json::to_vec(&(
                    &message.message_id,
                    &route.id,
                    route.revision,
                ))?),
                status: LaunchStatus {
                    request_id: uuid::Uuid::new_v4().to_string(),
                    session_id: SessionId::new().to_string(),
                    process_gen: uuid::Uuid::new_v4().to_string(),
                    state: LaunchState::Starting,
                },
            };
            candidates.push(self.launch_candidate(route, &record, message.created_at));
            pending_ids.insert(
                record.status.session_id.clone(),
                record.status.request_id.clone(),
            );
            launches.push(LocalLaunch {
                record,
                route: route.clone(),
            });
        }
        let mut tasks = collab::resolve(
            atem_id,
            &candidates,
            &selectors,
            (*budget).min(MAX_AGENTS),
            message.from_session.as_deref().unwrap(),
            &message.message_id,
            &message.recipients[0].recipient_id,
        );
        for task in &mut tasks {
            task.launch_request_id = pending_ids.get(&task.session_id).cloned();
        }
        launches.retain(|l| {
            tasks.iter().any(|t| {
                t.launch_request_id.as_deref() == Some(l.record.status.request_id.as_str())
            })
        });
        Ok(Resolution { tasks, launches })
    }

    fn launch_candidate(&self, route: &Route, record: &LaunchRecord, now: u64) -> Candidate {
        Candidate {
            route_id: route.id.clone(),
            route_revision: route.revision,
            session_id: record.status.session_id.clone(),
            process_gen: record.status.process_gen.clone(),
            started_ms: now,
            labels: self
                .work
                .config
                .instance
                .labels
                .iter()
                .chain(&route.labels)
                .filter_map(|s| s.parse().ok())
                .collect(),
        }
    }

    pub(super) fn collab_reserve_launches(
        &self,
        tx: &Transaction<'_>,
        plan: &Resolution,
    ) -> Result<()> {
        let count: usize = tx.query_row("SELECT count(*) FROM launches", [], |r| r.get(0))?;
        if count + plan.launches.len() > crate::runtime::host_work::MAX_RECORDS {
            bail!("launch receipt capacity reached");
        }
        for launch in &plan.launches {
            tx.execute(
                "INSERT INTO launches(id,record) VALUES(?1,?2)",
                params![
                    launch.record.status.request_id,
                    serde_json::to_string(&launch.record)?
                ],
            )?;
        }
        Ok(())
    }

    pub(super) fn collab_start_launches(&mut self, plan: Resolution, expires_at: u64) {
        for launch in plan.launches {
            let route = launch.route;
            let profile = self.work.config.profile(&route.profile_id).unwrap().clone();
            let permit = Arc::new(AtomicBool::new(true));
            let (flag, approved, approved_route, dir) = (
                permit.clone(),
                profile.clone(),
                route.clone(),
                self.work.dir.clone(),
            );
            let guard = Arc::new(move || {
                flag.load(Ordering::SeqCst)
                    && host_now().wall_ms < expires_at
                    // A pause (a file that doesn't load, hosting off) is no
                    // change: a launch that is already under way isn't
                    // failed by it (`take_remote_launches` holds the ones
                    // not started). A changed approval is.
                    && match Config::load(&dir) {
                        Ok(c) if c.enabled => {
                            c.profile(&approved.id) == Some(&approved)
                                && c.route(&approved_route.id) == Some(&approved_route)
                        }
                        _ => true,
                    }
                    && crate::memory::project::project_key_for(&approved.cwd) == approved.project
            });
            let status = launch.record.status;
            self.work.pending.insert(
                status.request_id.clone(),
                PendingLaunch {
                    attachment: self.local_attachment().into(),
                    principal: "local".into(),
                    control_gen: self.host.control_gen("local"),
                    profile: profile.clone(),
                    expires_at,
                    permit,
                    local_route: Some(route),
                },
            );
            self.work.launches.push_back(RemoteLaunch {
                request_id: status.request_id,
                profile,
                session_id: status.session_id,
                process_gen: status.process_gen,
                guard,
            });
        }
    }

    pub(super) fn collab_wait_for_launch(&self, task: &mut WorkRecord) -> Result<bool> {
        let store = self.work.store.as_ref().unwrap();
        let id: Option<String> = store
            .db
            .query_row(
                "SELECT launch_request_id FROM resolutions WHERE task_id=?1",
                [&task.task.task_id],
                |r| r.get(0),
            )
            .optional()?
            .flatten();
        let Some(id) = id else {
            return Ok(false);
        };
        let record = store
            .launch(&id)?
            .ok_or_else(|| anyhow!("missing reserved launch"))?;
        let (state, detail) = match record.status.state {
            LaunchState::Started => return Ok(false),
            LaunchState::Starting => (WorkState::Blocked, "launching the approved route"),
            LaunchState::Failed if self.work.halted_launches.contains(&id) => {
                (WorkState::Failed, HALTED_LAUNCH)
            }
            LaunchState::Failed => (
                WorkState::Failed,
                "approved route launch failed; check its cwd and environment",
            ),
            LaunchState::OutcomeUnknown => (
                WorkState::OutcomeUnknown,
                "launch outcome unknown; the reserved launch will not be repeated",
            ),
        };
        if task.status.state != state || task.status.detail != detail {
            task.status.state = state;
            task.status.detail = detail.into();
            store.save_work(task)?;
        }
        Ok(true)
    }
}
