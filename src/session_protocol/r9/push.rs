//! Sealed push hints and seen on the host (atem-session-v1.md §R9.9).
//!
//! An r9 host never sends tool or summary in clear (the r8 `push_approval`
//! and `push_resolved` are gone). For each approval it signs, with its
//! `host_channel_key`, one **open** hint per recipient (every native
//! member with `control` at its head, `push::recipients`), the tool and
//! summary HPKE-sealed to that member's `enc_key`, and later one
//! **resolved** hint; a native device that saw the card makes it sign one
//! **seen**. Everything goes to the relay over Atem's link as
//! `{"type":"relay","op":"push_hint","hints":[…]}` /
//! `{"type":"relay","op":"push_seen","seen":{body, sig}}`, kept in memory
//! and resent (the same bytes) every 10 s and at each link reconnect until
//! the relay's `push_ack` names it, the approval's resolved hint is
//! acknowledged, or `expires_at + 300 s` passes (`atem_client::push::
//! Outbox`). A broker restart ends the approvals and their resends.
//!
//! Sans-I/O, on the device list's host clock (§R9.5: `created_at`,
//! `expires_at`, resends and the guard are its wall ms). What it adds to
//! the crate's `HostApproval`/`Outbox`:
//!
//! - **suppression**: nothing is signed or sent while the device list is
//!   held, frozen or faulted, or the session journal halted; what was
//!   queued is dropped then (fail closed: the relay's own guard bounds
//!   what it still sends);
//! - **the guard on Atem's side**: no open hint and no seen is sent (or
//!   resent) at or after `expires_at − 15 s`, when no provider send could
//!   follow; the resolved hint still goes (it only cancels);
//! - a resolved hint ends the resends of its approval's opens and seens
//!   (it dominates them at the relay);
//! - recipients follow the head: an open hint not yet acknowledged whose
//!   device is no longer a recipient (removed, or lost `control`) is never
//!   sent again (its resolved hint still goes: it carries nothing sealed);
//! - bounds: at most [`MAX_APPROVALS`] approvals tracked. A published
//!   lifecycle is never evicted: an approval whose open hints went out
//!   keeps them until it resolves, and its resolved hint until the relay
//!   acknowledges it (or `expires_at + 300 s`). To make room only an
//!   approval with nothing left to send, then one whose opens were never
//!   published, is forgotten; when nothing can go, the new approval gets
//!   no hint (a counted runtime.log line) and works on the host as
//!   always (§R9.9). Each `push_hint` at most [`MAX_MESSAGE_BYTES`]
//!   (hints due together are split, never one frame the link or relay
//!   refuses forever); at most [`MAX_RELAY_OUT_BYTES`] waiting for the
//!   link (the rest go at the next resend).
use super::HostKey;
use atem_client::membership::Membership;
use atem_client::push::{
    self, ApprovalKey, GUARD_MARGIN_MS, Hint, HintPlain, HostApproval, Identity, Outbox,
    SeenOutcome, Verifier,
};
use std::collections::{BTreeMap, VecDeque};

/// Approvals whose hints are tracked at most (see the module docs for
/// what makes room).
pub const MAX_APPROVALS: usize = 64;
/// Bytes of relay messages waiting for the link at most (the rest are
/// resent at the next tick).
pub const MAX_RELAY_OUT_BYTES: usize = 16 << 20;
/// One `push_hint` message at most (well under the link's 2 MiB bound;
/// one open hint is about 1.5 KiB).
pub const MAX_MESSAGE_BYTES: usize = 256 << 10;
/// The suppression reason of a host without a device list.
pub const NO_LIST: &str = "no device list";
/// How long after `expires_at` the outbox still resends (§R9.9).
const RESEND_AFTER_EXPIRY_MS: u64 = push::CLIENT_SKEW_MS;

fn log(line: &str) {
    eprintln!("atem runtime: r9: push: {line}");
}

struct Tracked {
    approval: HostApproval,
    /// The devices its open hints went to (fixed at the open): only their
    /// seen is signed (§R9.9).
    recipients: std::collections::BTreeSet<String>,
    /// Each unacknowledged hint or seen and when it was first queued.
    unacked: BTreeMap<Identity, u64>,
    /// Its open hints were handed to the link (or acknowledged): the
    /// relay may hold them, so its lifecycle is kept to the end.
    published: bool,
}

impl Tracked {
    fn guard_passed(&self, now: u64) -> bool {
        now >= push::guard(self.approval.expires_at)
    }

    /// The opens and seens still waiting (never the resolved).
    fn opens_and_seens(&self) -> Vec<Identity> {
        self.unacked
            .keys()
            .filter(|id| !matches!(id, Identity::Resolved { .. }))
            .cloned()
            .collect()
    }
}

/// What `atem status` shows of the relay delivery.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PushStatus {
    /// Hints and seens not yet acknowledged by the relay.
    pub pending: usize,
    /// How long the oldest of them has waited (ms).
    pub oldest_ms: Option<u64>,
    /// Why nothing is sent now, if nothing is.
    pub suppressed: Option<&'static str>,
}

/// The host's push state (see the module docs).
#[derive(Default)]
pub struct HostPush {
    approvals: BTreeMap<String, Tracked>,
    order: VecDeque<String>,
    outbox: Outbox,
    out: VecDeque<String>,
    out_bytes: usize,
    link: bool,
    suppressed: Option<&'static str>,
    /// New approvals that got no hint because every tracked one holds a
    /// published lifecycle.
    unhinted: u64,
}

/// What signing needs: the verified log, the host's key.
pub struct Signer<'a> {
    pub log: &'a Membership,
    pub key: &'a HostKey,
}

impl HostPush {
    /// A new approval (`created_at` its creation, the `approval_request`'s
    /// `created_at`; `expires_at` = `created_at` + the hook's wait; `now`
    /// the host clock): its open hints, one per recipient, queued and sent
    /// while the link is up.
    #[allow(clippy::too_many_arguments)]
    pub fn opened(
        &mut self,
        key: ApprovalKey,
        created_at: u64,
        expires_at: u64,
        plain: &HintPlain,
        signer: Option<Signer<'_>>,
        now: u64,
    ) {
        let Some(signer) = self.usable(signer) else {
            log(&format!(
                "approval {}: no hint ({})",
                key.approval_id,
                self.suppressed.unwrap_or(NO_LIST)
            ));
            return;
        };
        if now.max(created_at) >= push::guard(expires_at) {
            log(&format!(
                "approval {}: no hint (opened within {} s of its expiry)",
                key.approval_id,
                GUARD_MARGIN_MS / 1000
            ));
            return;
        }
        let approval_id = key.approval_id.clone();
        let approval = HostApproval::new(key, created_at, expires_at);
        let objects = match approval.open_hints(&signer.key.keys, &signer.key.id, signer.log, plain)
        {
            Ok(objects) => objects,
            Err(e) => {
                log(&format!("approval {approval_id}: no hint ({e})"));
                return;
            }
        };
        let hints: Vec<Hint> = objects
            .iter()
            .filter_map(|o| {
                match Hint::verify(o, signer.log, now.max(created_at), Verifier::Client) {
                    Ok(h) => Some(h),
                    Err(r) => {
                        log(&format!(
                            "approval {approval_id}: a hint failed its own check ({})",
                            r.code()
                        ));
                        None
                    }
                }
            })
            .collect();
        if hints.is_empty() {
            // No native member with control: nobody to notify, nothing to
            // resolve or see.
            log(&format!("approval {approval_id}: no recipient"));
            return;
        }
        if self.approvals.len() >= MAX_APPROVALS && !self.make_room() {
            // Every tracked approval holds a published lifecycle: the new
            // one goes unhinted (its card and answers work as always).
            self.unhinted += 1;
            if self.unhinted.is_power_of_two() {
                log(&format!(
                    "approval {approval_id}: no hint ({MAX_APPROVALS} published approvals pending or resolving; {} unhinted so far)",
                    self.unhinted
                ));
            }
            return;
        }
        let mut tracked = Tracked {
            approval,
            recipients: hints
                .iter()
                .filter_map(|h| match h.identity() {
                    Identity::Open { device_id, .. } => Some(device_id),
                    _ => None,
                })
                .collect(),
            unacked: BTreeMap::new(),
            published: self.link,
        };
        for h in &hints {
            tracked.unacked.insert(h.identity(), now);
        }
        let message = self.outbox.send_hints(&hints, now);
        self.queue(message);
        log(&format!(
            "approval {approval_id}: {} sealed hint(s)",
            hints.len()
        ));
        self.order.push_back(approval_id.clone());
        self.approvals.insert(approval_id, tracked);
    }

    /// The approval is no longer pending (`reason` the `approval_closed`
    /// reason): its resolved hint replaces the opens and seens still
    /// waiting, and is sent until acknowledged.
    pub fn resolved(
        &mut self,
        approval_id: &str,
        reason: &str,
        signer: Option<Signer<'_>>,
        now: u64,
    ) {
        if !self.approvals.contains_key(approval_id) {
            return;
        }
        let Some(signer) = self.usable(signer) else {
            self.forget(approval_id);
            return;
        };
        let t = self.approvals.get_mut(approval_id).expect("tracked");
        if t.approval.is_closed() {
            return;
        }
        let object = match t
            .approval
            .close(&signer.key.keys, &signer.key.id, reason, now)
        {
            Ok(object) => object,
            Err(e) => {
                log(&format!("approval {approval_id}: no resolved hint ({e})"));
                self.forget(approval_id);
                return;
            }
        };
        let hint = match Hint::verify(&object, signer.log, now, Verifier::Client) {
            Ok(hint) => hint,
            Err(r) => {
                // Stale (past `expires_at + 300 s`): nothing to cancel.
                log(&format!(
                    "approval {approval_id}: no resolved hint ({})",
                    r.code()
                ));
                self.forget(approval_id);
                return;
            }
        };
        let done = t.opens_and_seens();
        self.outbox.on_ack(&done);
        for id in &done {
            t.unacked.remove(id);
        }
        t.unacked.insert(hint.identity(), now);
        let message = self.outbox.send_hints(&[hint], now);
        self.queue(message);
    }

    /// A native device's first `approval_seen` for a pending approval of
    /// exactly that session and process (the caller checked `control`
    /// and that it is pending): the signed seen, sent until acknowledged.
    /// A later seen of the same device is never re-signed.
    #[allow(clippy::too_many_arguments)]
    pub fn seen(
        &mut self,
        approval_id: &str,
        session_id: &str,
        process_gen: &str,
        device_id: &str,
        signer: Option<Signer<'_>>,
        now: u64,
    ) {
        let Some(signer) = self.usable(signer) else {
            return;
        };
        let Some(t) = self.approvals.get_mut(approval_id) else {
            return;
        };
        if t.guard_passed(now) {
            return;
        }
        if !t.recipients.contains(device_id) {
            // Added or given `control` after the open: no hint went to it,
            // so its seen could only wait as pending at the relay.
            log(&format!(
                "approval {approval_id}: {device_id} is not a recipient; its seen is not signed"
            ));
            return;
        }
        let outcome = t.approval.seen(
            &signer.key.keys,
            &signer.key.id,
            device_id,
            true,
            session_id,
            process_gen,
            now,
        );
        let object = match outcome {
            Ok(SeenOutcome::Signed(object)) => object,
            Ok(_) => return,
            Err(e) => {
                log(&format!("approval {approval_id}: no seen ({e})"));
                return;
            }
        };
        let seen = match push::Seen::verify(&object, signer.log) {
            Ok(seen) => seen,
            Err(r) => {
                log(&format!(
                    "approval {approval_id}: a seen failed its own check ({})",
                    r.code()
                ));
                return;
            }
        };
        t.unacked.insert(seen.identity(), now);
        let expires_at = t.approval.expires_at;
        let message = self.outbox.send_seen(&seen, expires_at, now);
        self.queue(message);
    }

    /// The relay's `push_ack` (any other relay message is ignored): each
    /// identity it names is done; an acknowledged resolved hint ends its
    /// approval. Returns how many tracked identities it acknowledged.
    pub fn ack(&mut self, message: &serde_json::Value) -> usize {
        let acks = push::parse_push_ack(message);
        if acks.is_empty() {
            return 0;
        }
        self.outbox.on_ack(&acks);
        let mut matched = 0;
        let mut ended = Vec::new();
        for ack in &acks {
            for (id, t) in self.approvals.iter_mut() {
                if t.unacked.remove(ack).is_some() {
                    matched += 1;
                    t.published = true;
                }
                if matches!(ack, Identity::Resolved { key } if *key == t.approval.key) {
                    ended.push(id.clone());
                }
            }
        }
        for id in ended {
            self.forget(&id);
        }
        matched
    }

    /// The head moved (or the pass): open hints not yet acknowledged whose
    /// device is no longer a recipient at the head (removed, or lost
    /// `control`) are never sent again; what waits for the link is
    /// rebuilt without them. Returns how many were dropped.
    pub fn sync_recipients(&mut self, membership: &Membership, now: u64) -> usize {
        let current: std::collections::BTreeSet<String> = push::recipients(membership)
            .into_iter()
            .map(|(device, _)| device)
            .collect();
        let mut gone = Vec::new();
        for (id, t) in self.approvals.iter_mut() {
            let stale: Vec<Identity> = t
                .unacked
                .keys()
                .filter(|i| matches!(i, Identity::Open { device_id, .. } if !current.contains(device_id)))
                .cloned()
                .collect();
            for i in stale {
                if let Identity::Open { device_id, .. } = &i {
                    log(&format!(
                        "approval {id}: {device_id} is no longer a recipient; its hint is not sent again"
                    ));
                }
                if let Identity::Open { device_id, .. } = &i {
                    t.recipients.remove(device_id);
                }
                t.unacked.remove(&i);
                gone.push(i);
            }
        }
        if gone.is_empty() {
            return 0;
        }
        self.outbox.on_ack(&gone);
        if self.link && !self.out.is_empty() {
            // Messages already waiting may hold them: rebuilt from what is
            // still pending (a resend now is idempotent at the relay).
            self.out.clear();
            self.out_bytes = 0;
            for m in self.outbox.reconnect(now) {
                self.queue(m);
            }
        }
        gone.len()
    }

    /// The pass: suppression drops everything; the guard ends the opens
    /// and seens of approvals within 15 s of their expiry; what is due for
    /// a resend (every 10 s) is queued while the link is up.
    pub fn tick(&mut self, suppressed: Option<&'static str>, now: u64) {
        if self.suppress(suppressed) {
            return;
        }
        self.prune(now);
        let messages = self.outbox.tick(now);
        if self.link {
            for m in messages {
                self.queue(m);
            }
        }
    }

    /// Atem's link came up (a new generation): everything unacknowledged
    /// goes now, the same bytes.
    pub fn link_up(&mut self, suppressed: Option<&'static str>, now: u64) {
        self.link = true;
        if self.suppress(suppressed) {
            return;
        }
        self.prune(now);
        // Everything still pending goes now: published from here on.
        for t in self.approvals.values_mut() {
            if !t.unacked.is_empty() {
                t.published = true;
            }
        }
        for m in self.outbox.reconnect(now) {
            self.queue(m);
        }
    }

    /// Atem's link dropped: what waited for it goes at the reconnect.
    pub fn link_down(&mut self) {
        self.link = false;
        self.out.clear();
        self.out_bytes = 0;
    }

    /// The device list was pinned again or removed: every approval's
    /// hints belong to the old identity and are dropped.
    pub fn reset(&mut self) {
        if !self.approvals.is_empty() {
            log(&format!(
                "{} approval(s) dropped (the device list changed)",
                self.approvals.len()
            ));
        }
        let link = self.link;
        *self = HostPush::default();
        self.link = link;
    }

    /// Hands the queued relay messages to `send`; one it refuses (the link
    /// is full or gone) and the rest wait for the next resend.
    pub fn flush(&mut self, send: &mut dyn FnMut(String) -> bool) {
        while let Some(text) = self.out.pop_front() {
            self.out_bytes -= text.len();
            if !send(text) {
                self.out.clear();
                self.out_bytes = 0;
                return;
            }
        }
    }

    pub fn status(&self, now: u64) -> PushStatus {
        let oldest = self
            .approvals
            .values()
            .flat_map(|t| t.unacked.values())
            .min()
            .copied();
        PushStatus {
            pending: self.outbox.len(),
            oldest_ms: oldest.map(|at| now.saturating_sub(at)),
            suppressed: self.suppressed,
        }
    }

    /// New approvals that got no hint for want of room (tests).
    #[cfg(test)]
    pub fn unhinted(&self) -> u64 {
        self.unhinted
    }

    /// Whether `approval_id` has push state (tests).
    #[cfg(test)]
    pub fn tracks(&self, approval_id: &str) -> bool {
        self.approvals.contains_key(approval_id)
    }

    // ── Internal ──

    fn usable<'a>(&mut self, signer: Option<Signer<'a>>) -> Option<Signer<'a>> {
        if self.suppressed.is_some() {
            return None;
        }
        signer
    }

    /// Records the suppression state (the caller's, before each call);
    /// when it starts, everything queued is dropped. True while suppressed.
    pub fn suppress(&mut self, suppressed: Option<&'static str>) -> bool {
        match (self.suppressed, suppressed) {
            (None, Some(why)) => {
                let n = self.outbox.len();
                // A host without a device list (r8) has nothing to say.
                if n > 0 || why != NO_LIST {
                    log(&format!(
                        "suppressed ({why}); {n} unacknowledged hint(s)/seen(s) dropped"
                    ));
                }
                let link = self.link;
                *self = HostPush::default();
                self.link = link;
                self.suppressed = Some(why);
            }
            (Some(was), None) => {
                if was != NO_LIST {
                    log("no longer suppressed");
                }
                self.suppressed = None;
            }
            (Some(_), Some(why)) => self.suppressed = Some(why),
            (None, None) => {}
        }
        self.suppressed.is_some()
    }

    /// The guard (opens and seens end at `expires_at − 15 s`) and expiry
    /// (an approval is forgotten at `expires_at + 300 s`).
    fn prune(&mut self, now: u64) {
        let mut gone = Vec::new();
        for (id, t) in self.approvals.iter_mut() {
            if now >= t.approval.expires_at.saturating_add(RESEND_AFTER_EXPIRY_MS) {
                gone.push(id.clone());
                continue;
            }
            if t.guard_passed(now) {
                let done = t.opens_and_seens();
                if !done.is_empty() {
                    log(&format!(
                        "approval {id}: {} open hint(s)/seen(s) no longer sent (within {} s of its expiry)",
                        done.len(),
                        GUARD_MARGIN_MS / 1000
                    ));
                    self.outbox.on_ack(&done);
                    for d in &done {
                        t.unacked.remove(d);
                    }
                }
            }
        }
        for id in gone {
            self.forget(&id);
        }
    }

    /// Forgets one tracked approval to make room, never a published
    /// lifecycle: first one with nothing left to send (its resolution
    /// acknowledged, or none ever owed), then one whose opens were never
    /// published, pending or closed (the relay holds nothing of it, so its
    /// resolution is owed to nobody). False when there is none.
    fn make_room(&mut self) -> bool {
        let pick = |want: &dyn Fn(&Tracked) -> bool| {
            self.order
                .iter()
                .find(|id| self.approvals.get(*id).is_some_and(want))
                .cloned()
        };
        let victim =
            pick(&|t: &Tracked| t.unacked.is_empty() && (t.approval.is_closed() || !t.published))
                .or_else(|| pick(&|t: &Tracked| !t.published));
        let Some(victim) = victim else {
            return false;
        };
        log(&format!(
            "approval {victim}: forgotten to make room (nothing published left to finish)"
        ));
        self.forget(&victim);
        true
    }

    /// Drops an approval and everything of it still waiting.
    fn forget(&mut self, approval_id: &str) {
        if let Some(t) = self.approvals.remove(approval_id) {
            // An acknowledged resolved ends every pending entry of its key.
            self.outbox.on_ack(&[Identity::Resolved {
                key: t.approval.key.clone(),
            }]);
        }
        self.order.retain(|a| a != approval_id);
    }

    fn queue(&mut self, message: serde_json::Value) {
        if !self.link {
            return;
        }
        for text in split(message) {
            if self.out_bytes + text.len() > MAX_RELAY_OUT_BYTES {
                // Resent at the next tick (every 10 s).
                log("the link is backed up; the rest waits for the next resend");
                return;
            }
            self.out_bytes += text.len();
            self.out.push_back(text);
        }
    }
}

/// A `push_hint` whose hints don't fit [`MAX_MESSAGE_BYTES`] as several,
/// in order (one hint always fits); anything else as is.
pub(super) fn split(message: serde_json::Value) -> Vec<String> {
    let text = message.to_string();
    if text.len() <= MAX_MESSAGE_BYTES || message["op"] != "push_hint" {
        return vec![text];
    }
    let Some(hints) = message["hints"].as_array() else {
        return vec![text];
    };
    // The message's own bytes around the array, with margin.
    const FRAME: usize = 64;
    let message_of = |batch: &[serde_json::Value]| {
        serde_json::json!({"type": "relay", "op": "push_hint", "hints": batch}).to_string()
    };
    let mut out = Vec::new();
    let mut batch: Vec<serde_json::Value> = Vec::new();
    let mut bytes = 0;
    for h in hints {
        let n = h.to_string().len() + 1;
        if !batch.is_empty() && FRAME + bytes + n > MAX_MESSAGE_BYTES {
            out.push(message_of(&batch));
            batch.clear();
            bytes = 0;
        }
        bytes += n;
        batch.push(h.clone());
    }
    if !batch.is_empty() {
        out.push(message_of(&batch));
    }
    out
}
