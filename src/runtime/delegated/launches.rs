//! Delegated launches at the spawn boundary (design I.4.3, "Launches";
//! host-work-v1 §11.6, "Launches"): a delegated sender's `host_launch` is
//! checked against conditions 2, 2a, 3 (with `launch`), 4 and 5, and its
//! expiry on the delegated clock, before its worker is spawned
//! ([`launch_check`]), so a refusal there proves that nothing ran.
//!
//! - **A reason that can clear** (the sender held, the gate closed, a
//!   deferred entry, a scope waiting for unlock) makes it wait in the
//!   bridge's queue, never handed to the launcher, while its expiry holds;
//!   one still waiting at its expiry ends `failed` (`expired before the
//!   spawn`).
//! - **A reason that can't clear** (revoked or removed, narrowed, its
//!   profile changed, the device list frozen, held or faulted) ends it
//!   `failed` at once.
//! - **Neither is `outcome_unknown`.** The launch's record is written
//!   `failed` before anything says so (its query reads it); the detail goes
//!   to `runtime.log` (the launch result has no `detail`, §3).
//! - **Hosting §5's fences are unchanged** and come first: a
//!   receipt-database fault, a halted session journal alone (the list
//!   usable) and hosting switched off fence it (`outcome_unknown`), as every
//!   other launch; a `runtime.toml` that doesn't load is waited out, its
//!   expiry still ending it `failed`. Its sender's channel, control
//!   generation and online state are not conditions, so they never fence it
//!   (`work_fence_launches` leaves those to the check).
//! - **At the spawn boundary** ([`PreSpawnCheck`], before anything is
//!   written or spawned) the check runs again, with the fences, the file
//!   re-read (one that doesn't load is waited out there too; a profile it
//!   no longer approves, or a directory now of another project, is `route
//!   changed`) and the pass's `D` from the start view: a wait hands the
//!   launch back to the queue, a refusal fails it. That is the launch's
//!   linearization point: after the spawn, up to the worker's `start`, its
//!   guard only fences (`outcome_unknown`, the worker may run), as every
//!   launch's, so an event after the check doesn't stop it.
//! - **At a restart** a launch still waiting is lost with the runtime's
//!   memory, as every launch not started: `starting` becomes
//!   `outcome_unknown` (§3), the restart can't tell it never reached the
//!   launcher.
//!
//! Only a delegated sender's (`host.delegated` on, the sender classified
//! delegated, Decision 13): every other launch, local ones included, keeps
//! its guard and hosting §5's rules, unchanged.
use super::*;
use crate::runtime::adopt::{NotSpawned, PreSpawn, PreSpawnCheck, SpawnGuard};
use crate::runtime::delegated::start::{LaunchVerdict, StartLaunch, StartView, launch_check};

/// A delegated sender's launch while it hasn't started.
pub(in crate::runtime) struct DelegatedLaunch {
    /// What the check reads of it.
    pub(in crate::runtime) launch: StartLaunch,
    /// The launch as it is handed to the launcher, to queue again when the
    /// check at the spawn boundary makes it wait.
    handout: RemoteLaunch,
    /// The reason it last waited for, as logged.
    waiting: Option<&'static str>,
}

/// What a pass does with a delegated launch that isn't fenced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Handout {
    /// To the launcher.
    Now,
    /// It waits in the queue (the reason, for `runtime.log` only).
    Wait(&'static str),
    /// It fails, with §11.6's detail.
    Fail(&'static str),
}

/// The device list as the start view has it is usable: a halted journal
/// beside it is a halt alone, which fences (with the list frozen, held,
/// faulted or gone, the check fails the launch instead).
fn list_usable(view: &StartView) -> bool {
    view.list
        .as_ref()
        .is_some_and(|l| !(l.frozen || l.held || l.faulted || l.unpaired))
}

impl HostBridge {
    /// The launch of `profile` by `a`, expiring at `expires_at`, with its
    /// permit `permit`: none unless `a` is a delegated sender (its
    /// admission record, [`HostBridge::admission`], against the profile's
    /// scope key); else its record, the guard that fences it after the
    /// spawn and its check at the spawn boundary.
    pub(super) fn delegated_launch(
        &self,
        a: &Sender,
        profile: &Profile,
        expires_at: u64,
        permit: &Arc<AtomicBool>,
    ) -> Option<(StartLaunch, SpawnGuard, PreSpawnCheck)> {
        // With the hook off nobody is delegated: every launch is v1's.
        if !self.features.delegated {
            return None;
        }
        // A launch has no route: the profile stands for it.
        let admission = self.admission(a, "", 0, &profile.scope_key())?;
        let launch = StartLaunch {
            admission,
            profile: profile.clone(),
            expires_at,
        };
        let (flag, dir, view, approved) = (
            permit.clone(),
            self.work.dir.clone(),
            self.start_view.clone(),
            profile.clone(),
        );
        // After the spawn, up to `start`: the fences, as a v1 launch's
        // guard, its expiry on the delegated clock.
        let guard: SpawnGuard = Arc::new(move || {
            flag.load(Ordering::SeqCst)
                && Config::load(&dir)
                    .is_ok_and(|c| c.enabled && c.profile(&approved.id) == Some(&approved))
                && view
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .now_d_ms
                    .is_some_and(|d| d < expires_at)
                && crate::memory::project::project_key_for(&approved.cwd) == approved.project
        });
        let (flag, dir, view, start) = (
            permit.clone(),
            self.work.dir.clone(),
            self.start_view.clone(),
            launch.clone(),
        );
        let check: PreSpawnCheck = Arc::new(move || {
            // Hosting §5's fences first: a receipt-database fault, hosting
            // switched off or a halted journal (the pass's, `permit`), the
            // file re-read here switching hosting off. One that doesn't
            // load is waited out (nothing is spawned yet; its approval is
            // compared once it loads), as in the queue.
            if !flag.load(Ordering::SeqCst) {
                return PreSpawn::Fence;
            }
            let Ok(config) = Config::load(&dir) else {
                return PreSpawn::Wait;
            };
            if !config.enabled {
                return PreSpawn::Fence;
            }
            let verdict = {
                let view = view
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if view.halted && list_usable(&view) {
                    return PreSpawn::Fence;
                }
                // No reading of the delegated clock: its expiry can't be
                // compared, so it waits (as a task's dispatch does).
                let Some(now_d) = view.now_d_ms else {
                    return PreSpawn::Wait;
                };
                launch_check(&view, &start, now_d)
            };
            match verdict {
                LaunchVerdict::Wait(_) => PreSpawn::Wait,
                LaunchVerdict::Fail(detail) => PreSpawn::Fail(detail),
                // The file as re-read here, and the project its directory
                // is now: the profile it was approved under (condition 4).
                LaunchVerdict::Go
                    if config.profile(&start.profile.id) != Some(&start.profile)
                        || crate::memory::project::project_key_for(&start.profile.cwd)
                            != start.profile.project =>
                {
                    PreSpawn::Fail(details::ROUTE_CHANGED)
                }
                LaunchVerdict::Go => PreSpawn::Go,
            }
        });
        Some((launch, guard, check))
    }

    /// `handout` is a delegated sender's launch, its record `launch`:
    /// remembered while it hasn't started.
    pub(super) fn delegated_pending(
        launch: StartLaunch,
        handout: &RemoteLaunch,
    ) -> DelegatedLaunch {
        DelegatedLaunch {
            launch,
            handout: handout.clone(),
            waiting: None,
        }
    }

    /// Whether hosting §5's fences apply to a delegated launch not yet
    /// started (`work_fence_launches`): hosting switched off (a file that
    /// loads, `enabled = false`), a receipt-database fault, or a halted
    /// session journal alone (the device list usable). A file that doesn't
    /// load (`paused`) is waited out. Nothing of its sender fences it.
    pub(super) fn delegated_launch_fenced(&self, paused: bool) -> bool {
        (!paused && !self.hosting_enabled())
            || (self.host.journal_halted() && list_usable(&self.start_view()))
    }

    /// What this pass does with each queued delegated launch that isn't
    /// fenced (its permit holds), by request id: the check at the spawn
    /// boundary against the start view and its `D` (the pass's reading,
    /// `take_reading`). While the file doesn't load (`paused`) it waits, as
    /// every launch does, but its expiry still fails it; with no reading of
    /// the delegated clock it waits. One already in the launcher's hands is
    /// its check's there.
    pub(super) fn delegated_handouts(&mut self, paused: bool) -> HashMap<String, Handout> {
        let mut out = HashMap::new();
        if self.work.pending.values().all(|p| p.delegated.is_none()) {
            return out;
        }
        {
            let view = self.start_view();
            for launch in &self.work.launches {
                let id = &launch.request_id;
                let Some(p) = self.work.pending.get(id) else {
                    continue;
                };
                let Some(d) = &p.delegated else {
                    continue;
                };
                if !p.permit.load(Ordering::SeqCst) {
                    continue;
                }
                let handout = match view.now_d_ms {
                    Some(now_d) if now_d >= d.launch.expires_at => {
                        Handout::Fail(details::EXPIRED_BEFORE_THE_SPAWN)
                    }
                    _ if paused => Handout::Wait("runtime.toml doesn't load"),
                    None => Handout::Wait("no reading of the delegated clock"),
                    Some(now_d) => match launch_check(&view, &d.launch, now_d) {
                        LaunchVerdict::Go => Handout::Now,
                        LaunchVerdict::Wait(detail) => Handout::Wait(detail),
                        LaunchVerdict::Fail(detail) => Handout::Fail(detail),
                    },
                };
                out.insert(id.clone(), handout);
            }
        }
        for (id, handout) in &out {
            let reason = match handout {
                Handout::Wait(reason) => Some(*reason),
                _ => None,
            };
            let Some(d) = self
                .work
                .pending
                .get_mut(id)
                .and_then(|p| p.delegated.as_mut())
            else {
                continue;
            };
            if let Some(reason) = reason
                && d.waiting != Some(reason)
            {
                eprintln!("atem runtime: launch {id} waits at the spawn boundary: {reason}");
            }
            d.waiting = reason;
        }
        out
    }

    /// A launch handed to the launcher ended: started; failed in its
    /// preparation (`no_start`: nothing started); refused by a delegated
    /// launch's check before the spawn ([`NotSpawned`]); or anything else,
    /// whose outcome is unknown (it may have started).
    pub fn launch_finished(
        &mut self,
        request_id: &str,
        result: std::result::Result<(), &anyhow::Error>,
        no_start: bool,
    ) {
        match result {
            Ok(()) => self.remote_launched(request_id, LaunchState::Started),
            Err(error) => match error.downcast_ref::<NotSpawned>() {
                Some(refused) => self.launch_not_spawned(request_id, *refused),
                None if no_start => self.remote_launched(request_id, LaunchState::Failed),
                None => self.remote_launched(request_id, LaunchState::OutcomeUnknown),
            },
        }
    }

    /// A delegated launch's check refused it at the spawn boundary, before
    /// anything was spawned: it waits in the queue again (checked again
    /// each pass), or fails.
    pub(super) fn launch_not_spawned(&mut self, request_id: &str, refused: NotSpawned) {
        match refused {
            NotSpawned::Fail(detail) => self.launch_failed_before_spawn(request_id, detail),
            NotSpawned::Wait => {
                // Gone: fenced when the host's identity changed (its record
                // went aside with the old database).
                let Some(p) = self.work.pending.get(request_id) else {
                    return;
                };
                match &p.delegated {
                    Some(d) => self.work.launches.push_back(d.handout.clone()),
                    // Only a delegated launch has a check: never here.
                    None => self.remote_launched(request_id, LaunchState::OutcomeUnknown),
                }
            }
        }
    }

    /// A delegated launch failed before its spawn, nothing started
    /// (`detail`, §11.6): its record is `failed` (written before anything
    /// says so), and the reason logged. It has no local task, so it never
    /// goes into `work.refused`, whose eviction would wipe a local task's
    /// reason (PR 8 review, T28 m4).
    pub(super) fn launch_failed_before_spawn(&mut self, request_id: &str, detail: &'static str) {
        // Gone: fenced when the host's identity changed.
        if !self.work.pending.contains_key(request_id) {
            return;
        }
        self.remote_launched(request_id, LaunchState::Failed);
        if self.work.error {
            return;
        }
        #[cfg(test)]
        self.work
            .failed_before_spawn
            .insert(request_id.to_string(), detail);
        eprintln!("atem runtime: launch {request_id} failed before its spawn: {detail}");
    }
}
