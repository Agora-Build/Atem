//! r9 admission on the host (atem-session-v1.md Appendix r9: §R9.6–§R9.8,
//! §R9.7a): the `atem-ch1` responder for every client channel the router
//! opens on Atem's link, carry before admission (§R9.3), principals with
//! scope and expiry (§R9.6, the `atem_client::principal` helpers), the
//! r9 `welcome`, `membership`/`membership_head`, `revoke_grant`,
//! `approval_seen`, and the fences: each attachment is fenced on its own
//! (its `attachment_gen`), a principal's attachments together (its §H
//! `control_gen`).
//!
//! Sans-I/O. The transport seam is the channel envelope ([`envelope`]):
//! [`R9Host::link_up`]/[`R9Host::link_down`] for Atem's link, every
//! received envelope through [`R9Host::on_envelope`], and what Atem sends
//! drained with [`R9Host::flush`] (a `try_send` of envelope text that may
//! refuse when the link is full). What the transport must provide:
//!
//! - one ordered, reliable stream of JSON text messages per link
//!   generation, in both directions (Atem's existing outbound WebSocket);
//! - the router's `open` before a channel's first frame, and its `close`
//!   when the client goes away;
//! - a new link generation on every (re)authentication, and the drop of
//!   the old one (every channel on it closes);
//! - a bounded `try_send` (Atem queues per channel, bounded, and closes a
//!   channel that falls behind rather than dropping records).
//!
//! The session host (`SessionHost`) serves each admitted channel as an
//! attachment like any other: the runtime runs its effects, and hands the
//! messages for an r9 attachment back here ([`R9Host::deliver`]) to be
//! filtered by scope, sealed and queued.
pub mod envelope;
#[cfg(test)]
mod fixtures_tests;
pub mod push;
#[cfg(test)]
mod push_tests;
#[cfg(test)]
mod tests;

use super::host::{Attach, Effect, SessionHost};
use super::journal::Journal;
use super::membership::{
    self, Carried, DETAIL_NOT_RECONCILED, DETAIL_NOT_RECORDED, Fence, FenceReason, Hello as MHello,
    HostFences, Init as MInit, MembershipHost,
};
use super::wire::{self as r8, Envelope as R8Envelope, Op as R8Op};
use atem_client::canonical::StrictValue;
use atem_client::channel::responder::{AwaitFinish, HostContext, InitLimiter, Responder};
use atem_client::channel::wire::{self as chwire, Frame};
use atem_client::channel::{Channel, ClearCode, Principal};
use atem_client::membership::{Admission, HostNow};
use atem_client::principal::{
    Authority, ClientKind, Denied, GRANT_ISSUED_AHEAD_MS, GRANT_MAX_LIFETIME_MS, Need, Op,
    Permission, Refusal, RevokedGrants, SessionRef, admission_error,
};
use atem_client::session::r9::{
    self, Hello, PendingRecovery, R9_FEATURES, REVISION, SessionError, Welcome, code,
};
use atem_client::{KeyId, SoftwareKeys};
use envelope::{Event, Transport, reason};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};

/// §R9.7a "Bounds".
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub open_channels: usize,
    pub handshakes: usize,
    pub queued_bytes: usize,
    pub unknown_handles: usize,
    /// `close`s refusing an `open` or a frame for an unknown handle, a
    /// second (together).
    pub unknown_closes_per_second: u32,
    /// `close`s queued outside any channel, at most.
    pub global_closes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            open_channels: 64,
            handshakes: 16,
            queued_bytes: 4 << 20,
            unknown_handles: 1024,
            unknown_closes_per_second: 16,
            global_closes: 1024,
        }
    }
}

/// The largest legal inner frame (a `finish`; a `rec` is 3 bytes shorter)
/// and `ct` (1 MiB + the 16-byte tag, base64url), §R9.7a.
pub const MAX_INNER_FRAME: usize = 1_398_162;
pub const MAX_CT_CHARS: usize = 1_398_123;
/// Approval ids remembered with their session (scope checks of
/// `approval_closed`).
const MAX_APPROVAL_SESSIONS: usize = 1024;

/// An opened channel waits this long for its `init` (as `accept` → `finish`).
const INIT_WAIT_MS: u64 = atem_client::channel::HANDSHAKE_STEP_MS;
/// `busy` detail when the device list was removed while the runtime ran.
const DETAIL_UNPAIRED: &str = "device list removed";
/// `busy` detail when the journal halted (r8 §I).
const DETAIL_JOURNAL_HALTED: &str = "journal halted; restart Atem";
/// `busy` when the session host runs under another identity than the list.
const DETAIL_IDENTITY: &str = "host identity differs from the device list";
/// The revoked grants journal (§R9.6), in the session journal's directory.
pub const REVOKED_GRANTS_FILE: &str = "revoked_grants";

/// The host's `host_channel_key` behind a provider (plain, §R9.3).
pub struct HostKey {
    keys: SoftwareKeys,
    id: KeyId,
}

impl HostKey {
    pub fn new(seed: &[u8; 32]) -> Self {
        let mut keys = SoftwareKeys::new();
        let id = KeyId::new("host_channel_key");
        keys.insert_ed25519(id.clone(), seed);
        HostKey { keys, id }
    }
}

impl std::fmt::Debug for HostKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HostKey")
    }
}

/// The runtime's device list, as admission sees it.
pub enum DeviceList<'a> {
    /// Not paired for r9: r9 is refused (`stale_target` at `init`).
    None,
    /// It exists but can't serve (damaged, unsynced, no host key): r9 is
    /// refused (`busy`), with why.
    Failed(&'a str),
    Open {
        m: &'a mut MembershipHost,
        key: &'a HostKey,
    },
}

/// The clocks: the session host's monotonic ms, and the host clock of
/// §R9.5 (wall time for expiry; its monotonic ms for channel timers).
#[derive(Debug, Clone)]
pub struct Now {
    pub mono: u64,
    pub host: HostNow,
}

/// How a session's recorded launch project matches a service scope's
/// `projects` entry (`h1.<kid>.<hash>`, §R9.6). `None` while it can't be
/// told (no project recorded, a locked cred agent): the session is then
/// out of scope (fail closed).
pub trait ProjectScope {
    fn matches(&self, session_id: &str, entry: &str) -> Option<bool>;
}

/// No launch project is recorded: every `projects` scope leaves sessions
/// out (pending), never in.
pub struct NoProjects;

impl ProjectScope for NoProjects {
    fn matches(&self, _: &str, _: &str) -> Option<bool> {
        None
    }
}

/// What one call works on.
pub struct Parts<'a, J: Journal> {
    pub host: &'a mut SessionHost<J>,
    pub list: DeviceList<'a>,
    pub now: Now,
    pub projects: &'a dyn ProjectScope,
}

struct Attached {
    channel: Channel,
    attachment: String,
    authority: Authority,
}

enum Phase {
    /// Opened; waiting for `init` until `deadline`.
    AwaitInit {
        deadline: u64,
    },
    AwaitFinish(AwaitFinish),
    Open(Box<Attached>),
    /// Atem closed it: what is queued goes, then the `close`.
    Closing,
}

struct Chan {
    transport: Transport,
    phase: Phase,
    queue: VecDeque<String>,
    queued: usize,
    /// Atem's `close` reason, sent once the queue drained.
    close: Option<&'static str>,
}

impl Chan {
    fn handshaking(&self) -> bool {
        matches!(self.phase, Phase::AwaitInit { .. } | Phase::AwaitFinish(_))
    }
}

/// What `atem status` shows of r9 admission.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct R9Status {
    pub link: bool,
    pub channels: usize,
    pub attachments: usize,
}

/// The r9 admission engine for one runtime (see the module docs).
pub struct R9Host {
    limits: Limits,
    /// The live link generation.
    link: Option<u64>,
    chans: BTreeMap<String, Chan>,
    by_attachment: HashMap<String, String>,
    /// One `init` a second per link (§R9.7a: "per transport" is the link).
    limiter: InitLimiter,
    unknown: HashSet<String>,
    unknown_order: VecDeque<String>,
    /// (second, closes sent in it) for `unknown_channel`.
    unknown_rate: (u64, u32),
    unknown_dropped: u64,
    /// approval id → its session, from the requests delivered (in order).
    approval_sessions: HashMap<String, String>,
    approval_order: VecDeque<String>,
    /// `close`s queued outside any channel, in order: refusals (bounded by
    /// `global_closes` and the rate) and the `close{closed}`s of a restart
    /// (lifecycle closes, counted in `lifecycle`).
    global: VecDeque<(String, bool)>,
    /// Lifecycle closes in `global` (flagged `true` there): each holds its channel's slot until it
    /// is sent, so open channels plus these never pass `open_channels`.
    lifecycle: usize,
    revoked: RevokedGrants,
    revoked_until: BTreeMap<String, u64>,
    revoked_path: Option<PathBuf>,
    /// (approval id, device) pairs whose first `approval_seen` was taken.
    seen: HashSet<(String, String)>,
    /// The error a fenced principal's attachments get before their close.
    fence_errors: HashMap<String, SessionError>,
    /// Attachments whose channel Atem closed (overflow), for the session
    /// host to forget.
    dead: Vec<String>,
    /// The channel the link last refused (the next round starts after it).
    flush_cursor: Option<String>,
    /// Sealed push hints and seen for the relay (§R9.9).
    push: push::HostPush,
}

fn log(line: &str) {
    eprintln!("atem runtime: r9: {line}");
}

fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn error(code: &str, re: Option<&str>, detail: Option<&str>) -> SessionError {
    SessionError {
        re: re.map(str::to_owned),
        detail: detail.map(str::to_owned),
        ..SessionError::new(code)
    }
}

/// The session `error` a fence reason gives the fenced principal's
/// attachments (sent without `re`: the client closes, §R9.8).
fn fence_error(reason: FenceReason) -> SessionError {
    match reason {
        FenceReason::Removed => error(code::UNAUTHORIZED, None, Some("removed")),
        FenceReason::Revoked => error(code::UNAUTHORIZED, None, Some("roles changed")),
        FenceReason::HostRemoved => error(code::UNAUTHORIZED, None, Some("host removed")),
        FenceReason::Frozen => error(code::ACCOUNT_FROZEN, None, None),
        FenceReason::NotRecorded => error(code::BUSY, None, Some(DETAIL_NOT_RECORDED)),
    }
}

/// The family error of a terminal-v1 or chat-v1 request (their r8 shapes).
fn family_error(family: &str, data: &Value, code: &str) -> Vec<u8> {
    let body = if family == "agentChat" {
        serde_json::json!({"v": 1, "op": "error", "conversationId": data.get("conversationId"),
               "agentId": data.get("agentId"), "code": code, "text": code})
    } else {
        serde_json::json!({"v": 1, "op": "error", "terminal_id": data.get("terminal_id"),
               "code": code, "message": code})
    };
    serde_json::json!({"type": family, "data": body})
        .to_string()
        .into_bytes()
}

impl Default for R9Host {
    fn default() -> Self {
        Self::new(Limits::default(), None)
    }
}

impl R9Host {
    /// An engine with these bounds; revoked grants are journaled in
    /// `journal_dir/revoked_grants` (none: memory only, tests).
    pub fn new(limits: Limits, journal_dir: Option<&Path>) -> Self {
        let revoked_path = journal_dir.map(|d| d.join(REVOKED_GRANTS_FILE));
        let mut host = R9Host {
            limits,
            link: None,
            chans: BTreeMap::new(),
            by_attachment: HashMap::new(),
            limiter: InitLimiter::new(),
            unknown: HashSet::new(),
            unknown_order: VecDeque::new(),
            unknown_rate: (0, 0),
            unknown_dropped: 0,
            approval_sessions: HashMap::new(),
            approval_order: VecDeque::new(),
            global: VecDeque::new(),
            lifecycle: 0,
            revoked: RevokedGrants::new(),
            revoked_until: BTreeMap::new(),
            revoked_path,
            seen: HashSet::new(),
            fence_errors: HashMap::new(),
            dead: Vec::new(),
            flush_cursor: None,
            push: push::HostPush::default(),
        };
        host.load_revoked();
        host
    }

    pub fn status(&self) -> R9Status {
        R9Status {
            link: self.link.is_some(),
            channels: self.chans.len(),
            attachments: self.by_attachment.len(),
        }
    }

    /// The r9 attachments (debug builds: the fixture state dump).
    #[cfg(any(test, debug_assertions))]
    pub fn attachment_ids(&self) -> Vec<String> {
        self.by_attachment.keys().cloned().collect()
    }

    /// Whether `att` is an r9 attachment (its messages go back here).
    pub fn owns(&self, att: &str) -> bool {
        self.by_attachment.contains_key(att)
    }

    /// The r9 attachments, with their principals.
    pub fn attachments(&self) -> Vec<(String, String)> {
        self.chans
            .values()
            .filter_map(|c| match &c.phase {
                Phase::Open(a) => Some((a.attachment.clone(), a.authority.name())),
                _ => None,
            })
            .collect()
    }

    // ── The link ──

    /// Atem's link authenticated (generation `link_gen`): channels may
    /// open. Anything of an earlier link is gone already
    /// ([`R9Host::link_down`]).
    pub fn link_up<J: Journal>(&mut self, link_gen: u64, parts: &mut Parts<'_, J>) -> Vec<Effect> {
        let mut effects = Vec::new();
        if self.link.is_some_and(|g| g != link_gen) {
            effects = self.link_down(parts);
        }
        if self.link.is_none() {
            self.link = Some(link_gen);
            self.limiter = InitLimiter::new();
            self.unknown.clear();
            self.unknown_order.clear();
            // §R9.9: everything unacknowledged goes again at a reconnect
            // (to the recipients at the head).
            self.push_recipients(parts);
            self.push
                .link_up(push_suppressed(parts), parts.now.host.wall_ms);
        }
        effects
    }

    /// Atem's link dropped: every channel on it closes and its attachment
    /// is fenced (no lease is carried; §R9.7a 6). Nothing is sent.
    pub fn link_down<J: Journal>(&mut self, parts: &mut Parts<'_, J>) -> Vec<Effect> {
        let had_link = self.link.is_some();
        let effects = self.end_channels(parts);
        self.global.clear();
        self.lifecycle = 0;
        if had_link {
            log("the link dropped; every channel on it closed");
        }
        effects
    }

    /// Every channel ends and its attachment is fenced; the link is no
    /// longer up. What is queued outside a channel is the caller's.
    fn end_channels<J: Journal>(&mut self, parts: &mut Parts<'_, J>) -> Vec<Effect> {
        let mut effects = Vec::new();
        for (_, chan) in std::mem::take(&mut self.chans) {
            if let Phase::Open(a) = chan.phase {
                effects.extend(parts.host.disconnect(&a.attachment));
            }
        }
        self.by_attachment.clear();
        self.unknown.clear();
        self.unknown_order.clear();
        self.link = None;
        self.push.link_down();
        effects
    }

    /// The link generation ends while the socket stays up (a
    /// re-authentication, or a link no longer authenticated): every
    /// channel ends as in [`R9Host::restart`], and its closes (with those
    /// already queued) are handed to `send` now, before anything of a new
    /// generation. Whatever the socket doesn't take now is dropped and
    /// counted: a handle is scoped to its generation (§R9.7a "Scope of a
    /// handle"), so a late close could end a new channel that reused it.
    /// The caller brings the new generation up ([`R9Host::link_up`]).
    pub fn end_generation<J: Journal>(
        &mut self,
        parts: &mut Parts<'_, J>,
        send: &mut dyn FnMut(String) -> bool,
    ) -> Vec<Effect> {
        let effects = self.restart(parts);
        self.flush_closes(send);
        let left = std::mem::take(&mut self.global).len();
        self.lifecycle = 0;
        if left > 0 {
            self.unknown_dropped += left as u64;
            log(&format!(
                "{left} close(s) of an ended link generation dropped (the link was backed up)"
            ));
        }
        effects
    }

    // ── Envelopes in ──

    /// One envelope from the router (§R9.7a).
    pub fn on_envelope<J: Journal>(&mut self, text: &str, parts: &mut Parts<'_, J>) -> Vec<Effect> {
        if self.link.is_none() {
            return Vec::new();
        }
        let event = match envelope::parse(text) {
            Ok(event) => event,
            Err(refused) => {
                log(&format!("refused an envelope ({})", refused.reason()));
                if let Some(handle) = refused.channel().map(str::to_owned) {
                    return self.fail(&handle, refused.reason(), parts);
                }
                return Vec::new();
            }
        };
        match event {
            Event::Open { channel, transport } => {
                self.open(channel, transport, parts);
                Vec::new()
            }
            Event::Close { channel, .. } => self.router_closed(&channel, parts),
            Event::Frame { channel, frame } => {
                if !self.chans.contains_key(&channel) {
                    self.unknown_frame(&channel, parts.now.host.mono_ms);
                    return Vec::new();
                }
                self.on_frame(&channel, &frame, parts)
            }
        }
    }

    fn open<J: Journal>(&mut self, handle: String, transport: Transport, parts: &Parts<'_, J>) {
        if self.chans.contains_key(&handle) {
            // Never replaces a live handshake, keys or attachment.
            log(&format!(
                "ignored a duplicate open of a live channel ({})",
                transport.as_str()
            ));
            return;
        }
        let handshakes = self.chans.values().filter(|c| c.handshaking()).count();
        // A restart's pending `close{closed}` still holds its channel's
        // slot (§R9.7a "Overload"): opens wait for the link to take it.
        if self.chans.len() + self.lifecycle >= self.limits.open_channels
            || handshakes >= self.limits.handshakes
        {
            self.refuse_outside(&handle, reason::BUSY, parts.now.host.mono_ms);
            return;
        }
        if self.unknown.remove(&handle) {
            self.unknown_order.retain(|h| *h != handle);
        }
        self.chans.insert(
            handle,
            Chan {
                transport,
                phase: Phase::AwaitInit {
                    deadline: parts.now.host.mono_ms + INIT_WAIT_MS,
                },
                queue: VecDeque::new(),
                queued: 0,
                close: None,
            },
        );
    }

    /// The router closed `handle`: that channel ends (its attachment is
    /// fenced); nothing answers a close.
    fn router_closed<J: Journal>(&mut self, handle: &str, parts: &mut Parts<'_, J>) -> Vec<Effect> {
        let Some(chan) = self.chans.remove(handle) else {
            return Vec::new();
        };
        match chan.phase {
            Phase::Open(a) => {
                self.by_attachment.remove(&a.attachment);
                parts.host.disconnect(&a.attachment)
            }
            _ => Vec::new(),
        }
    }

    /// A frame for a handle Atem doesn't hold: one `unknown_channel` close
    /// per handle per link, at most 16 a second (§R9.7a 3).
    fn unknown_frame(&mut self, handle: &str, now_mono: u64) {
        if self.unknown.contains(handle) {
            return;
        }
        if self.unknown_order.len() >= self.limits.unknown_handles {
            // Remembers no more: dropped, never a second close (§R9.7a 3).
            self.dropped("frames for unknown channels");
            return;
        }
        if self.refuse_outside(handle, reason::UNKNOWN_CHANNEL, now_mono) {
            self.unknown.insert(handle.to_string());
            self.unknown_order.push_back(handle.to_string());
        }
    }

    /// A `close` outside any channel (a refused `open`, an unknown handle):
    /// at most 16 a second and 1024 queued (§R9.7a "Bounds"); beyond either
    /// dropped and counted. Whether it was queued.
    fn refuse_outside(&mut self, handle: &str, why: &'static str, now_mono: u64) -> bool {
        let second = now_mono / 1000;
        if self.unknown_rate.0 != second {
            self.unknown_rate = (second, 0);
        }
        if self.unknown_rate.1 >= self.limits.unknown_closes_per_second
            || self.global.len() - self.lifecycle >= self.limits.global_closes
        {
            self.dropped("refusals outside a channel");
            return false;
        }
        self.unknown_rate.1 += 1;
        self.global
            .push_back((envelope::close(handle, Some(why)), false));
        true
    }

    fn dropped(&mut self, what: &str) {
        self.unknown_dropped += 1;
        if self.unknown_dropped.is_power_of_two() {
            log(&format!("{} {what} dropped so far", self.unknown_dropped));
        }
    }

    /// Tests: the fixture runners connect clients back to back; the
    /// per-link `init` rate is checked by the engine tests and the envelope
    /// fixtures. Debug builds: the real runtime's fixture hook
    /// (`ATEM_TEST_NO_INIT_LIMIT`).
    #[cfg(any(test, debug_assertions))]
    pub fn reset_init_limiter(&mut self) {
        self.limiter = InitLimiter::new();
    }

    /// `close`s queued outside any channel (tests: the bound holds).
    pub fn queued_closes(&self) -> usize {
        self.global.len()
    }

    /// Bytes of the `close`s queued outside any channel (tests: the bound
    /// holds).
    pub fn queued_close_bytes(&self) -> usize {
        self.global.iter().map(|(t, _)| t.len()).sum()
    }

    /// Restart closes not yet taken by the link (tests).
    pub fn pending_lifecycle_closes(&self) -> usize {
        self.lifecycle
    }

    /// Hands the closes queued outside a channel to `send`, in order;
    /// false when it refused one (the rest waits).
    fn flush_closes(&mut self, send: &mut dyn FnMut(String) -> bool) -> bool {
        while let Some((text, lifecycle)) = self.global.pop_front() {
            if !send(text.clone()) {
                self.global.push_front((text, lifecycle));
                return false;
            }
            if lifecycle {
                self.lifecycle -= 1;
            }
        }
        true
    }

    /// Ends every channel while the socket stays up (a re-pin, an unpair, a
    /// re-authentication): as [`R9Host::link_down`], but the closes already
    /// queued stay and a `close{closed}` is queued for each live handle
    /// (past the outside-channel bounds: they end channels the router holds
    /// open), all sent on the same socket (§R9.7a 6). Each such close holds
    /// its channel's slot until the link takes it, so across any number of
    /// restarts at most 64 are pending (opens are refused `busy` while the
    /// slots are taken). The caller brings the link up again.
    pub fn restart<J: Journal>(&mut self, parts: &mut Parts<'_, J>) -> Vec<Effect> {
        let live: Vec<String> = self.chans.keys().cloned().collect();
        let effects = self.end_channels(parts);
        if !live.is_empty() {
            log(&format!(
                "every channel ended ({}); the link stays up",
                live.len()
            ));
        }
        // Each holds its channel's slot until sent (see `open`): at most
        // `open_channels` are ever pending, however many restarts come.
        self.lifecycle += live.len();
        self.global.extend(
            live.iter()
                .map(|h| (envelope::close(h, Some(reason::CLOSED)), true)),
        );
        effects
    }

    /// Closes `handle` now with `reason` (no record first); its attachment,
    /// if any, is fenced.
    fn fail<J: Journal>(
        &mut self,
        handle: &str,
        why: &'static str,
        parts: &mut Parts<'_, J>,
    ) -> Vec<Effect> {
        let Some(chan) = self.chans.get_mut(handle) else {
            return Vec::new();
        };
        let phase = std::mem::replace(&mut chan.phase, Phase::Closing);
        chan.queue.clear();
        chan.queued = 0;
        chan.close.get_or_insert(why);
        match phase {
            Phase::Open(mut a) => {
                a.channel.close();
                self.by_attachment.remove(&a.attachment);
                parts.host.disconnect(&a.attachment)
            }
            _ => Vec::new(),
        }
    }

    /// An envelope of `handle` was refused unread (the broker's inbox was
    /// full: `busy`; over its bound: `too_large`): that channel closes,
    /// never short of a frame.
    pub fn refuse_unread<J: Journal>(
        &mut self,
        handle: &str,
        why: &'static str,
        parts: &mut Parts<'_, J>,
    ) -> Vec<Effect> {
        if self.chans.contains_key(handle) {
            return self.fail(handle, why, parts);
        }
        self.refuse_outside(handle, why, parts.now.host.mono_ms);
        Vec::new()
    }

    /// Sends `frame` (an `atem-ch1` frame's bytes) on `handle`, then closes
    /// it with `why`.
    fn reply_and_close(&mut self, handle: &str, frame: Option<Vec<u8>>, why: &'static str) {
        if let Some(chan) = self.chans.get_mut(handle) {
            chan.phase = Phase::Closing;
            if let Some(frame) = frame {
                let text = envelope::frame(handle, &frame);
                chan.queued += text.len();
                chan.queue.push_back(text);
            }
            chan.close.get_or_insert(why);
        }
    }

    fn on_frame<J: Journal>(
        &mut self,
        handle: &str,
        frame: &[u8],
        parts: &mut Parts<'_, J>,
    ) -> Vec<Effect> {
        if inner_too_large(frame) {
            log("a channel's frame is over the inner-frame bound; closed (too_large)");
            return self.fail(handle, reason::TOO_LARGE, parts);
        }
        let chan = self.chans.get_mut(handle).expect("checked");
        let phase = std::mem::replace(&mut chan.phase, Phase::Closing);
        match phase {
            Phase::Closing => {
                // Atem is closing it: anything more is dropped.
                chan.phase = Phase::Closing;
                Vec::new()
            }
            Phase::AwaitInit { .. } => {
                self.on_init(handle, frame, parts);
                Vec::new()
            }
            Phase::AwaitFinish(await_finish) => self.on_finish(handle, await_finish, frame, parts),
            Phase::Open(mut a) => {
                let plain = match a.channel.open(frame, parts.now.host.mono_ms) {
                    Ok(plain) => plain,
                    Err(e) => {
                        // A gap, replay, failed tag or wrong direction: that
                        // channel closes without a reply (§R9.7 "Records").
                        log(&format!("a channel closed: {}", e.code()));
                        let chan = self.chans.get_mut(handle).expect("checked");
                        chan.phase = Phase::Open(a);
                        return self.fail(handle, reason::CLOSED, parts);
                    }
                };
                let attachment = a.attachment.clone();
                let authority = a.authority.clone();
                self.chans.get_mut(handle).expect("checked").phase = Phase::Open(a);
                self.on_record(&attachment, &authority, &plain, parts)
            }
        }
    }

    // ── The handshake ──

    fn on_init<J: Journal>(&mut self, handle: &str, frame: &[u8], parts: &mut Parts<'_, J>) {
        let clear = |code: ClearCode| Some(chwire::clear_error(code));
        let init = match chwire::parse_frame(frame) {
            Ok(Frame::Init(init)) => init,
            Ok(Frame::Error { .. }) => {
                // The client gave up (advisory): close quietly.
                self.reply_and_close(handle, None, reason::CLOSED);
                return;
            }
            _ => {
                self.reply_and_close(
                    handle,
                    clear(ClearCode::HandshakeFailed),
                    reason::HANDSHAKE_FAILED,
                );
                return;
            }
        };
        if !self.limiter.admit(parts.now.host.mono_ms) {
            self.reply_and_close(handle, InitLimiter::busy().reply, reason::BUSY);
            return;
        }
        let ctx = parts.host.context().clone();
        let (m, key) = match &mut parts.list {
            DeviceList::None => {
                // No device list: nothing of this host is pinned.
                self.reply_and_close(handle, clear(ClearCode::StaleTarget), reason::CLOSED);
                return;
            }
            DeviceList::Failed(why) => {
                log(&format!(
                    "refused an init: the device list failed to open ({why})"
                ));
                self.reply_and_close(handle, clear(ClearCode::Busy), reason::BUSY);
                return;
            }
            DeviceList::Open { m, key } => (m, key),
        };
        let pin = m.pin_of().clone();
        // §R9.7 step 2: the target first (stale_target), then frozen.
        if init.genesis_hash != m.membership().genesis_hash()
            || init.host_id != pin.host_id
            || init.host_trust_gen != pin.host_trust_gen
        {
            self.reply_and_close(handle, clear(ClearCode::StaleTarget), reason::CLOSED);
            return;
        }
        match m.init() {
            MInit::Frozen => {
                self.reply_and_close(handle, clear(ClearCode::AccountFrozen), reason::CLOSED);
                return;
            }
            MInit::Busy => {
                self.reply_and_close(handle, clear(ClearCode::Busy), reason::BUSY);
                return;
            }
            MInit::Accept => {}
        }
        if ctx.account_id != m.membership().account_id()
            || ctx.atem_device_id != pin.host_id
            || ctx.host_trust_gen != pin.host_trust_gen
        {
            log(DETAIL_IDENTITY);
            self.reply_and_close(handle, clear(ClearCode::Busy), reason::BUSY);
            return;
        }
        let hctx = HostContext {
            log: m.membership(),
            host_id: &pin.host_id,
            host_trust_gen: pin.host_trust_gen,
            provider: &key.keys,
            key: &key.id,
        };
        match Responder::on_init(&hctx, frame, parts.now.host.mono_ms) {
            Ok((next, accept)) => {
                let chan = self.chans.get_mut(handle).expect("checked");
                chan.phase = Phase::AwaitFinish(next);
                let text = envelope::frame(handle, &accept);
                chan.queued += text.len();
                chan.queue.push_back(text);
            }
            Err(refused) => {
                let why = match refused.reply.is_some() {
                    true => reason::HANDSHAKE_FAILED,
                    false => reason::CLOSED,
                };
                self.reply_and_close(handle, refused.reply, why);
            }
        }
    }

    fn on_finish<J: Journal>(
        &mut self,
        handle: &str,
        await_finish: AwaitFinish,
        frame: &[u8],
        parts: &mut Parts<'_, J>,
    ) -> Vec<Effect> {
        let mono = parts.now.host.mono_ms;
        let opened = match await_finish.on_finish(frame, mono) {
            Ok(opened) => opened,
            Err(refused) => {
                self.reply_and_close(handle, refused.reply, reason::HANDSHAKE_FAILED);
                return Vec::new();
            }
        };
        let Some(hello) = Hello::parse(opened.hello()) else {
            let refused = opened.malformed();
            self.reply_and_close(handle, refused.reply, reason::HANDSHAKE_FAILED);
            return Vec::new();
        };
        let keyed = opened.key(&hello.proof);
        let re = hello.id.clone();
        let mut effects = Vec::new();
        let refuse =
            |me: &mut Self, keyed: atem_client::channel::responder::Keyed, e: SessionError| {
                log(&format!(
                    "refused a hello: {}{}",
                    e.code,
                    e.detail
                        .as_deref()
                        .map(|d| format!(" ({d})"))
                        .unwrap_or_default()
                ));
                let frame = keyed.refuse(&e.to_bytes(), mono).ok();
                me.reply_and_close(handle, frame, reason::CLOSED);
            };
        let membership = match hello.check() {
            Ok(m) => m.clone(),
            Err(r) => {
                refuse(self, keyed, r.to_error(re.as_deref()));
                return effects;
            }
        };
        let DeviceList::Open { m, .. } = &mut parts.list else {
            refuse(
                self,
                keyed,
                error(code::BUSY, re.as_deref(), Some(DETAIL_UNPAIRED)),
            );
            return effects;
        };
        // §R9.7 step 6: the carriage before judging the sender (§R9.3).
        let carriage = if membership.entries.is_empty() {
            None
        } else {
            let mut fences = HostFences::new(parts.host);
            let result = m.apply_carriage(&membership.entries, &parts.now.host, &mut fences);
            effects.extend(fences.effects);
            Some(result)
        };
        if let Some(result) = &carriage {
            self.note_fences(&result.fences);
            // §R9.9: a removed or demoted device's hints stop at once.
            self.push
                .sync_recipients(m.membership(), parts.now.host.wall_ms);
            if result.announce {
                // Every live attachment learns the new head now, whatever
                // the carrier's own admission (its welcome names it).
                let pending: Vec<PendingRecovery> = m
                    .membership()
                    .pending_recovery(&parts.now.host)
                    .iter()
                    .map(PendingRecovery::of)
                    .collect();
                let message = r9::membership_head(&new_id(), None, m.head(), &pending)
                    .to_string()
                    .into_bytes();
                self.announce_to_all(&message, None, parts.now.host.mono_ms);
            }
            let refused = match result.carried {
                Carried::NotRecorded | Carried::Refused | Carried::Crashed => {
                    Some(error(code::BUSY, re.as_deref(), Some(DETAIL_NOT_RECORDED)))
                }
                Carried::Unpaired => Some(error(code::BUSY, re.as_deref(), Some(DETAIL_UNPAIRED))),
                Carried::Frozen => Some(error(code::ACCOUNT_FROZEN, re.as_deref(), None)),
                Carried::Committed | Carried::Unchanged => None,
            };
            if let Some(e) = refused {
                refuse(self, keyed, e);
                return effects;
            }
        }
        let pin = m.pin_of().clone();
        let now = parts.now.host.clone();
        let wall = now.wall_ms;
        let resolved: Result<Authority, SessionError> = match &hello.proof.principal {
            Principal::Native { device_id } | Principal::Service { device_id } => {
                match m.hello(
                    device_id,
                    Some(membership.head),
                    carriage.as_ref(),
                    membership.more,
                    &now,
                ) {
                    MHello::Frozen => Err(error(code::ACCOUNT_FROZEN, re.as_deref(), None)),
                    MHello::NotRecorded => {
                        Err(error(code::BUSY, re.as_deref(), Some(DETAIL_NOT_RECORDED)))
                    }
                    MHello::NotReconciled => Err(error(
                        code::BUSY,
                        re.as_deref(),
                        Some(DETAIL_NOT_RECONCILED),
                    )),
                    MHello::Admit(Admission::Member { state, .. }) => Authority::of_member(
                        &hello.proof.principal,
                        &state.member,
                        &pin.host_id,
                        wall,
                    )
                    .map_err(|r| r.to_error(re.as_deref())),
                    MHello::Admit(other) => Err(admission_error(&other, re.as_deref())
                        .unwrap_or_else(|| error(code::UNAUTHORIZED, re.as_deref(), None))),
                }
            }
            Principal::Browser { .. } => {
                if m.is_frozen() {
                    Err(error(code::ACCOUNT_FROZEN, re.as_deref(), None))
                } else if m.faulted().is_some() {
                    Err(error(code::BUSY, re.as_deref(), Some(DETAIL_NOT_RECORDED)))
                } else if m.held().is_some() {
                    Err(error(
                        code::BUSY,
                        re.as_deref(),
                        Some(DETAIL_NOT_RECONCILED),
                    ))
                } else {
                    let revoked = &self.revoked;
                    Authority::resolve(
                        m.membership(),
                        &hello.proof.principal,
                        hello.grant.as_ref(),
                        &pin.host_id,
                        pin.host_trust_gen,
                        &now,
                        &|id| revoked.contains(id, wall),
                    )
                    .map_err(|r| match r {
                        Refusal::Membership(a) => admission_error(&a, re.as_deref())
                            .unwrap_or_else(|| error(code::UNAUTHORIZED, re.as_deref(), None)),
                        r => r.to_error(re.as_deref()),
                    })
                }
            }
        };
        let authority = match resolved {
            Ok(a) => a,
            Err(e) => {
                refuse(self, keyed, e);
                return effects;
            }
        };
        let mut channel = match keyed.admit(&authority.key, authority.channel_deadline_ms(&now)) {
            Ok(channel) => channel,
            Err(refusal) => {
                log("refused a hello: handshake_failed (sig_c)");
                let e = error(code::HANDSHAKE_FAILED, re.as_deref(), None);
                let frame = refusal.reply(&e.to_bytes(), mono).ok();
                self.reply_and_close(handle, frame, reason::CLOSED);
                return effects;
            }
        };
        // The session host's attachment: one per channel (its own client),
        // speaking for the principal (r8 §H).
        let attachment = new_id();
        let permissions: Vec<r8::Permission> = authority
            .permissions
            .iter()
            .map(|p| match p {
                Permission::Control => r8::Permission::Control,
                Permission::View => r8::Permission::View,
            })
            .collect();
        let channel_ms_left = channel.deadline_ms().saturating_sub(mono);
        let ms_left = authority.authorization_ms_left(wall, channel_ms_left);
        let attach = Attach {
            client: attachment.clone(),
            principal: authority.name(),
            attachment_gen: attachment.clone(),
            permissions,
            client_kind: match authority.client_kind {
                ClientKind::Browser => r8::ClientKind::Browser,
                ClientKind::Native | ClientKind::Service => r8::ClientKind::Native,
            },
            authorization_ms: ms_left,
        };
        if let Err(why) = parts.host.connect(attach) {
            log(&format!(
                "refused a hello: the session host refused the attachment ({why})"
            ));
            let e = error(code::BUSY, re.as_deref(), None);
            let frame = channel.seal(&e.to_bytes(), mono).ok();
            channel.close();
            self.reply_and_close(handle, frame, reason::CLOSED);
            return effects;
        }
        let (controller_session, _) = match parts.host.welcome_r9(&attachment, parts.now.mono) {
            Ok(welcomed) => welcomed,
            Err(code) => {
                effects.extend(parts.host.disconnect(&attachment));
                let detail = (code == r8::ErrorCode::Busy).then_some(DETAIL_JOURNAL_HALTED);
                let e = error(&super::host::code_name(code), re.as_deref(), detail);
                let frame = channel.seal(&e.to_bytes(), mono).ok();
                channel.close();
                self.reply_and_close(handle, frame, reason::CLOSED);
                return effects;
            }
        };
        effects.extend(parts.host.take_effects());
        let ctx = parts.host.context().clone();
        let mut features: Vec<String> = crate::session_protocol::revision::FEATURES
            .iter()
            .map(|f| f.to_string())
            .collect();
        features.extend(R9_FEATURES.iter().map(|f| f.to_string()));
        let welcome = Welcome {
            id: new_id(),
            re: re.clone(),
            account_id: ctx.account_id.clone(),
            atem_device_id: ctx.atem_device_id.clone(),
            host_trust_gen: ctx.host_trust_gen,
            runtime_gen: ctx.runtime_gen.clone(),
            controller_session,
            attachment_gen: attachment.clone(),
            client_kind: authority.client_kind,
            permissions: authority.permissions.iter().copied().collect(),
            authorization_ms_left: ms_left,
            server_time: wall,
            revision: REVISION,
            features,
            principal: authority.name(),
            scope: authority.scope.clone(),
            head: m.head(),
            pending_recovery: m
                .membership()
                .pending_recovery(&now)
                .iter()
                .map(PendingRecovery::of)
                .collect(),
            channel_id: channel.channel_id().to_owned(),
        };
        let frame = match channel.seal(&welcome.to_bytes(), mono) {
            Ok(frame) => frame,
            Err(_) => {
                effects.extend(parts.host.disconnect(&attachment));
                self.reply_and_close(handle, None, reason::CLOSED);
                return effects;
            }
        };
        let transport = self.chans.get(handle).map(|c| c.transport);
        log(&format!(
            "welcomed {} ({}, {})",
            authority.name(),
            authority.client_kind.as_str(),
            transport.map_or("?", Transport::as_str)
        ));
        let chan = self.chans.get_mut(handle).expect("checked");
        let text = envelope::frame(handle, &frame);
        chan.queued += text.len();
        chan.queue.push_back(text);
        chan.phase = Phase::Open(Box::new(Attached {
            channel,
            attachment: attachment.clone(),
            authority,
        }));
        self.by_attachment.insert(attachment, handle.to_string());
        effects
    }

    /// The fences a carriage made: each fenced principal's attachments get
    /// its error before their close; browsers whose issuer was removed or
    /// lost its roles are fenced with them (§R9.6 "issuer fenced").
    pub fn note_fences(&mut self, fences: &[Fence]) {
        for f in fences {
            self.fence_errors
                .entry(f.principal.clone())
                .or_insert_with(|| fence_error(f.reason));
        }
    }

    /// The browsers whose issuer `fences` fenced (removed or roles
    /// changed): fenced too, through §H.
    pub fn fence_issued<J: Journal>(
        &mut self,
        fences: &[Fence],
        parts: &mut Parts<'_, J>,
    ) -> Vec<Effect> {
        let issuers: HashSet<&str> = fences
            .iter()
            .filter(|f| matches!(f.reason, FenceReason::Removed | FenceReason::Revoked))
            .filter_map(|f| f.principal.strip_prefix("member:"))
            .collect();
        let browsers: Vec<String> = self
            .chans
            .values()
            .filter_map(|c| match &c.phase {
                Phase::Open(a)
                    if a.authority
                        .issuer
                        .as_deref()
                        .is_some_and(|i| issuers.contains(i)) =>
                {
                    Some(a.authority.name())
                }
                _ => None,
            })
            .collect();
        let mut effects = Vec::new();
        for b in browsers {
            self.fence_errors
                .entry(b.clone())
                .or_insert_with(|| error(code::UNAUTHORIZED, None, Some("issuer fenced")));
            effects.extend(parts.host.fence_principal(&b, 0));
        }
        effects
    }

    /// The end of a pass: fence errors don't outlive the effects they were
    /// noted for.
    pub fn end_pass(&mut self) {
        self.fence_errors.clear();
    }

    /// Every r9 attachment gets `membership_head` (the head moved, or a
    /// pending entry changed state).
    pub fn announce<J: Journal>(&mut self, parts: &mut Parts<'_, J>) {
        let DeviceList::Open { m, .. } = &parts.list else {
            return;
        };
        let pending: Vec<PendingRecovery> = m
            .membership()
            .pending_recovery(&parts.now.host)
            .iter()
            .map(PendingRecovery::of)
            .collect();
        let message = r9::membership_head(&new_id(), None, m.head(), &pending)
            .to_string()
            .into_bytes();
        self.announce_to_all(&message, None, parts.now.host.mono_ms);
    }

    fn announce_to_all(&mut self, message: &[u8], except: Option<&str>, now_mono: u64) {
        let atts: Vec<String> = self
            .chans
            .values()
            .filter_map(|c| match &c.phase {
                Phase::Open(a)
                    if Some(a.attachment.as_str()) != except
                        && !self.fence_errors.contains_key(&a.authority.name()) =>
                {
                    Some(a.attachment.clone())
                }
                _ => None,
            })
            .collect();
        for att in atts {
            self.seal_to(&att, message, now_mono);
        }
    }

    // ── Records ──

    fn on_record<J: Journal>(
        &mut self,
        att: &str,
        authority: &Authority,
        plain: &[u8],
        parts: &mut Parts<'_, J>,
    ) -> Vec<Effect> {
        let mono = parts.now.host.mono_ms;
        let value: Value = serde_json::from_slice(plain).unwrap_or(Value::Null);
        let family = value
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let data = value.get("data").cloned().unwrap_or(Value::Null);
        let re = data.get("id").and_then(Value::as_str).map(str::to_owned);
        let refuse = |me: &mut Self, code: &str, detail: Option<&str>| {
            let bytes = match family.as_str() {
                "session" | "" => error(code, re.as_deref(), detail).to_bytes(),
                _ => family_error(&family, &data, code),
            };
            me.seal_to(att, &bytes, mono);
        };
        // The one authority check for every request (§R9.6), before any
        // field is decoded: the named session first, then the op.
        let need = match Need::of_request(&family, &data) {
            Ok(need) => need,
            Err(denied) => {
                refuse(self, denied.code(), None);
                return Vec::new();
            }
        };
        let verdict = match Need::session_of(&data) {
            None => authority.authorize(need, None),
            Some(sid) => {
                // Out of scope and nonexistent take the same path: the
                // scope is evaluated either way, then existence decides.
                let host_id = parts.host.context().atem_device_id.clone();
                let projects = parts.projects;
                let matches = |entry: &str| projects.matches(sid, entry);
                let r = SessionRef {
                    host_id: &host_id,
                    session_id: sid,
                    project_matches: &matches,
                };
                let in_scope =
                    authority.session_in_scope(r.host_id, r.session_id, r.project_matches);
                let exists = parts.host.descriptor_of(sid).is_some();
                if exists && in_scope {
                    authority.authorize(need, Some(Some(&r)))
                } else {
                    Err(Denied::UnknownSession)
                }
            }
        };
        if let Err(denied) = verdict {
            refuse(self, denied.code(), None);
            return Vec::new();
        }
        if family == "session" {
            match data.get("op").and_then(Value::as_str) {
                Some("membership") => return self.membership_op(att, &data, re.as_deref(), parts),
                Some("revoke_grant") => {
                    return self.revoke_grant(att, authority, &data, re.as_deref(), parts);
                }
                Some("approval_seen") => {
                    self.approval_seen(att, authority, &data, re.as_deref(), parts);
                    return Vec::new();
                }
                _ => {}
            }
        }
        parts.host.receive(att, plain, parts.now.mono)
    }

    /// `membership{entries}` → `membership_head{re}` (§R9.8): the entries
    /// carried on an open channel, applied as any carriage (§R9.3).
    fn membership_op<J: Journal>(
        &mut self,
        att: &str,
        data: &Value,
        re: Option<&str>,
        parts: &mut Parts<'_, J>,
    ) -> Vec<Effect> {
        let mono = parts.now.host.mono_ms;
        let entries: Option<Vec<StrictValue>> = data
            .get("entries")
            .and_then(Value::as_array)
            .and_then(|list| {
                list.iter()
                    .map(|e| StrictValue::parse(e.to_string().as_bytes(), usize::MAX).ok())
                    .collect()
            });
        let Some(entries) = entries else {
            self.seal_to(
                att,
                &error(code::INVALID_REQUEST, re, None).to_bytes(),
                mono,
            );
            return Vec::new();
        };
        let DeviceList::Open { m, .. } = &mut parts.list else {
            self.seal_to(
                att,
                &error(code::BUSY, re, Some(DETAIL_UNPAIRED)).to_bytes(),
                mono,
            );
            return Vec::new();
        };
        let mut fences = HostFences::new(parts.host);
        let result = m.apply_carriage(&entries, &parts.now.host, &mut fences);
        let mut effects = fences.effects;
        self.note_fences(&result.fences);
        // §R9.9: a removed or demoted device's hints stop at once.
        self.push
            .sync_recipients(m.membership(), parts.now.host.wall_ms);
        let reply = match result.carried {
            Carried::NotRecorded | Carried::Refused | Carried::Crashed => {
                error(code::BUSY, re, Some(DETAIL_NOT_RECORDED)).to_bytes()
            }
            Carried::Unpaired => error(code::BUSY, re, Some(DETAIL_UNPAIRED)).to_bytes(),
            Carried::Frozen => error(code::ACCOUNT_FROZEN, re, None).to_bytes(),
            Carried::Committed | Carried::Unchanged => {
                match result.evaluation.as_ref().and_then(|e| invalid_of(e, re)) {
                    Some(e) => e.to_bytes(),
                    None => {
                        let pending: Vec<PendingRecovery> = m
                            .membership()
                            .pending_recovery(&parts.now.host)
                            .iter()
                            .map(PendingRecovery::of)
                            .collect();
                        r9::membership_head(&new_id(), re, m.head(), &pending)
                            .to_string()
                            .into_bytes()
                    }
                }
            }
        };
        self.seal_to(att, &reply, mono);
        effects.extend(self.fence_issued(&result.fences, parts));
        if result.announce {
            // The carrier got its reply; everyone else the event.
            self.announce_except(att, parts);
        }
        effects
    }

    fn announce_except<J: Journal>(&mut self, except: &str, parts: &mut Parts<'_, J>) {
        let DeviceList::Open { m, .. } = &parts.list else {
            return;
        };
        let pending: Vec<PendingRecovery> = m
            .membership()
            .pending_recovery(&parts.now.host)
            .iter()
            .map(PendingRecovery::of)
            .collect();
        let message = r9::membership_head(&new_id(), None, m.head(), &pending)
            .to_string()
            .into_bytes();
        // Not to principals being fenced in this pass: their fence error
        // is their last record.
        let atts: Vec<String> = self
            .chans
            .values()
            .filter_map(|c| match &c.phase {
                Phase::Open(a)
                    if a.attachment != except
                        && !self.fence_errors.contains_key(&a.authority.name()) =>
                {
                    Some(a.attachment.clone())
                }
                _ => None,
            })
            .collect();
        for att in atts {
            self.seal_to(&att, &message, parts.now.host.mono_ms);
        }
    }

    /// `revoke_grant{grant_id}` → `grant_revoked{re}` (§R9.6, §R9.8): the
    /// grant id is journaled until its grant's expiry (≤ 256), then the
    /// browser's attachments are fenced through §H.
    fn revoke_grant<J: Journal>(
        &mut self,
        att: &str,
        _authority: &Authority,
        data: &Value,
        re: Option<&str>,
        parts: &mut Parts<'_, J>,
    ) -> Vec<Effect> {
        let mono = parts.now.host.mono_ms;
        let wall = parts.now.host.wall_ms;
        let Some(grant_id) = data
            .get("grant_id")
            .and_then(Value::as_str)
            .filter(|g| atem_client::session::wire::is_uuid_v4(g))
            .map(str::to_owned)
        else {
            self.seal_to(
                att,
                &error(code::INVALID_REQUEST, re, None).to_bytes(),
                mono,
            );
            return Vec::new();
        };
        let principal = format!("browser:{grant_id}");
        let until = self
            .chans
            .values()
            .find_map(|c| match &c.phase {
                Phase::Open(a) if a.authority.name() == principal => a.authority.expires_at,
                _ => None,
            })
            .unwrap_or(wall + GRANT_MAX_LIFETIME_MS + GRANT_ISSUED_AHEAD_MS);
        if self.revoked.revoke(&grant_id, until, wall).is_err() {
            self.seal_to(
                att,
                &error(code::BUSY, re, Some("revoked grants journal full")).to_bytes(),
                mono,
            );
            return Vec::new();
        }
        self.revoked_until.retain(|_, t| wall < *t);
        let t = self.revoked_until.entry(grant_id.clone()).or_insert(until);
        *t = (*t).max(until);
        let recorded = self.save_revoked();
        // In effect at once, recorded or not (fail closed).
        self.fence_errors.insert(
            principal.clone(),
            error(code::UNAUTHORIZED, None, Some("grant revoked")),
        );
        let effects = parts.host.fence_principal(&principal, 0);
        let reply = match recorded {
            Ok(()) => r9::grant_revoked(&new_id(), re.unwrap_or_default())
                .to_string()
                .into_bytes(),
            Err(e) => {
                log(&format!("cannot record a revoked grant: {e}"));
                error(code::BUSY, re, Some("revocation not recorded")).to_bytes()
            }
        };
        self.seal_to(att, &reply, mono);
        effects
    }

    /// `approval_seen{binding, approval_id}` → `seen{re}` (§R9.9): the
    /// attachment has `control` (and `approval` for a scoped principal,
    /// checked by the authority), the approval is pending for exactly that
    /// session and process. Only the first seen of a device counts; later
    /// ones are answered `seen` too. A native device's first one is signed
    /// and sent to the relay (`push_seen`) until acknowledged; services and
    /// browsers are never hint recipients, so their seen suppresses
    /// nothing and nothing is signed.
    fn approval_seen<J: Journal>(
        &mut self,
        att: &str,
        authority: &Authority,
        data: &Value,
        re: Option<&str>,
        parts: &mut Parts<'_, J>,
    ) {
        let mono = parts.now.host.mono_ms;
        let target = data.get("binding").and_then(|b| b.get("target"));
        let session = target
            .and_then(|t| t.get("session_id"))
            .and_then(Value::as_str);
        let process = target
            .and_then(|t| t.get("process_gen"))
            .and_then(Value::as_str);
        let approval = data.get("approval_id").and_then(Value::as_str);
        let (Some(session), Some(process), Some(approval)) = (session, process, approval) else {
            self.seal_to(
                att,
                &error(code::INVALID_REQUEST, re, None).to_bytes(),
                mono,
            );
            return;
        };
        let current = parts
            .host
            .descriptor_of(session)
            .is_some_and(|d| d.process_gen == process);
        let pending = current
            && parts
                .host
                .pending_approvals(session)
                .iter()
                .any(|a| a == approval);
        if !pending {
            self.seal_to(att, &error(code::STALE_TARGET, re, None).to_bytes(), mono);
            return;
        }
        let device = match &authority.principal {
            Principal::Native { device_id } | Principal::Service { device_id } => device_id.clone(),
            Principal::Browser { grant_id, .. } => grant_id.clone(),
        };
        if self.seen.insert((approval.to_string(), device)) {
            log(&format!("{} saw approval {approval}", authority.name()));
        }
        if let Principal::Native { device_id } = &authority.principal {
            self.push.suppress(push_suppressed(parts));
            let wall = parts.now.host.wall_ms;
            self.push.seen(
                approval,
                session,
                process,
                device_id,
                signer_of(&parts.list),
                wall,
            );
        }
        let reply = r9::seen(&new_id(), re.unwrap_or_default())
            .to_string()
            .into_bytes();
        self.seal_to(att, &reply, mono);
    }

    // ── Push (§R9.9) ──

    /// An approval opened (`Effect::PushApproval`): its open hints, sealed
    /// per recipient. `created_at` is the `approval_request`'s (one clock
    /// for the card and the hint), `expires_at` = `created_at` + `wait_ms`
    /// (the hook's wait: Claude 600 s, Codex 300 s).
    pub fn approval_opened<J: Journal>(
        &mut self,
        request: &r8::ApprovalRequest,
        wait_ms: u64,
        parts: &mut Parts<'_, J>,
    ) {
        self.push.suppress(push_suppressed(parts));
        let wall = parts.now.host.wall_ms;
        let Some(key) = approval_key(&parts.list, request) else {
            return;
        };
        let plain = atem_client::push::HintPlain {
            tool: request.tool.clone(),
            summary: request.summary.clone(),
        };
        self.push.opened(
            key,
            request.created_at,
            request.created_at.saturating_add(wait_ms),
            &plain,
            signer_of(&parts.list),
            wall,
        );
    }

    /// An approval stopped being pending (`Effect::PushResolved`): its
    /// resolved hint.
    pub fn approval_resolved<J: Journal>(
        &mut self,
        approval_id: &str,
        reason: r8::ApprovalCloseReason,
        parts: &mut Parts<'_, J>,
    ) {
        self.push.suppress(push_suppressed(parts));
        let reason = serde_json::to_value(reason)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default();
        let wall = parts.now.host.wall_ms;
        self.push
            .resolved(approval_id, &reason, signer_of(&parts.list), wall);
    }

    /// A relay message on Atem's link (`{"type":"relay",…}`): a `push_ack`
    /// ends the resends of what it names.
    pub fn relay_message(&mut self, text: &str) {
        let Ok(value) = serde_json::from_str::<Value>(text) else {
            return;
        };
        let matched = self.push.ack(&value);
        if matched == 0 && value.get("op").and_then(Value::as_str) == Some("push_ack") {
            log("a push_ack acknowledged nothing pending");
        }
    }

    /// The head may have moved: open hints of devices no longer recipients
    /// (removed, or lost `control`) are never sent again (§R9.9, §R9.6).
    fn push_recipients<J: Journal>(&mut self, parts: &Parts<'_, J>) {
        let wall = parts.now.host.wall_ms;
        if let Some(signer) = signer_of(&parts.list) {
            self.push.sync_recipients(signer.log, wall);
        }
    }

    /// Hands the relay messages due now to `send` (Atem's link).
    pub fn flush_relay(&mut self, send: &mut dyn FnMut(String) -> bool) {
        self.push.flush(send);
    }

    /// The relay delivery's health for `atem status`.
    pub fn push_status(&self, now_wall: u64) -> push::PushStatus {
        self.push.status(now_wall)
    }

    /// The device list changed (a re-pin or unpair): the old identity's
    /// hints are dropped.
    pub fn reset_push(&mut self) {
        self.push.reset();
    }

    // ── Out ──

    /// A session-host message for the r9 attachment `att`: what its scope
    /// doesn't cover is left out (§R9.6: out-of-scope sessions don't
    /// exist for it), the rest sealed and queued.
    pub fn deliver(
        &mut self,
        att: &str,
        message: &R8Envelope,
        projects: &dyn ProjectScope,
        host_id: &str,
        now_mono: u64,
    ) {
        if let R8Envelope::Session(m) = message
            && let R8Op::ApprovalRequest(r) = &m.op
            && !self.approval_sessions.contains_key(&r.approval_id)
        {
            if self.approval_order.len() >= MAX_APPROVAL_SESSIONS
                && let Some(old) = self.approval_order.pop_front()
            {
                self.approval_sessions.remove(&old);
            }
            self.approval_order.push_back(r.approval_id.clone());
            self.approval_sessions
                .insert(r.approval_id.clone(), r.session_id.clone());
        }
        let Some(authority) = self.authority_of(att).cloned() else {
            return;
        };
        let approvals = &self.approval_sessions;
        let session_of = |id: &str| approvals.get(id).cloned();
        let Some(message) = scoped(&authority, message, projects, host_id, &session_of) else {
            return;
        };
        let bytes = r8::encode(&message);
        self.seal_to(att, &bytes, now_mono);
    }

    /// A terminal-v1 or chat-v1 message (raw JSON) for the r9 attachment
    /// `att`, about session `sid` (left out when out of its scope).
    pub fn deliver_family(
        &mut self,
        att: &str,
        sid: &str,
        text: &str,
        projects: &dyn ProjectScope,
        host_id: &str,
        now_mono: u64,
    ) {
        let Some(authority) = self.authority_of(att) else {
            return;
        };
        if !authority.session_in_scope(host_id, sid, &|e| projects.matches(sid, e)) {
            return;
        }
        self.seal_to(att, text.as_bytes(), now_mono);
    }

    /// Bytes queued for `att`'s channel (terminal frames hold back while
    /// they wait).
    pub fn backlog(&self, att: &str) -> usize {
        self.by_attachment
            .get(att)
            .and_then(|h| self.chans.get(h))
            .map_or(0, |c| c.queued)
    }

    /// The kids the live attachments' service `projects` scopes name
    /// (`h1.<kid>.<hash>`): the keyed hashes the runtime must know.
    pub fn scope_project_kids(&self) -> std::collections::BTreeSet<String> {
        self.chans
            .values()
            .filter_map(|c| match &c.phase {
                Phase::Open(a) => a.authority.scope.as_ref()?.projects.clone(),
                _ => None,
            })
            .flatten()
            .filter_map(|e| {
                e.strip_prefix("h1.")
                    .and_then(|r| r.split_once('.'))
                    .map(|(kid, _)| kid.to_string())
            })
            .collect()
    }

    /// Whether the r9 attachment `att` may see approvals (cards, rules):
    /// unscoped principals may; a scoped one only with the `approval` op.
    pub fn sees_approvals(&self, att: &str) -> bool {
        self.authority_of(att).is_some_and(|a| {
            a.scope
                .as_ref()
                .is_none_or(|scope| scope.ops.contains(&Op::Approval))
        })
    }

    fn authority_of(&self, att: &str) -> Option<&Authority> {
        let handle = self.by_attachment.get(att)?;
        match &self.chans.get(handle)?.phase {
            Phase::Open(a) => Some(&a.authority),
            _ => None,
        }
    }

    /// The session host closed the r9 attachment `att` (a fence): its
    /// error (a fence's, if one was noted for its principal) is the last
    /// record, then the channel closes.
    pub fn close_attachment(&mut self, att: &str, now_mono: u64) {
        let Some(handle) = self.by_attachment.remove(att) else {
            return;
        };
        let Some(chan) = self.chans.get_mut(&handle) else {
            return;
        };
        let Phase::Open(mut a) = std::mem::replace(&mut chan.phase, Phase::Closing) else {
            return;
        };
        if let Some(e) = self.fence_errors.get(&a.authority.name())
            && let Ok(frame) = a.channel.seal(&e.to_bytes(), now_mono)
        {
            let text = envelope::frame(&handle, &frame);
            chan.queued += text.len();
            chan.queue.push_back(text);
        }
        a.channel.close();
        chan.close.get_or_insert(reason::CLOSED);
    }

    fn seal_to(&mut self, att: &str, plain: &[u8], now_mono: u64) {
        let Some(handle) = self.by_attachment.get(att).cloned() else {
            return;
        };
        let limit = self.limits.queued_bytes;
        let Some(chan) = self.chans.get_mut(&handle) else {
            return;
        };
        let Phase::Open(a) = &mut chan.phase else {
            return;
        };
        match a.channel.seal(plain, now_mono) {
            Ok(frame) => {
                let text = envelope::frame(&handle, &frame);
                chan.queued += text.len();
                chan.queue.push_back(text);
                if chan.queued > limit {
                    // Fallen behind: closed explicitly, never a silent drop.
                    log("a channel's output passed its bound; closed (busy)");
                    self.overflow(&handle);
                }
            }
            Err(e) => {
                log(&format!(
                    "a channel can't take a record ({}); closed",
                    e.code()
                ));
                self.overflow(&handle);
            }
        }
    }

    /// Closes `handle` at once with `busy` (its queue goes); the attachment
    /// is gone from the session host by the next pass ([`R9Host::reap`]).
    fn overflow(&mut self, handle: &str) {
        if let Some(chan) = self.chans.get_mut(handle) {
            chan.queue.clear();
            chan.queued = 0;
            chan.close = Some(reason::BUSY);
            if let Phase::Open(a) = std::mem::replace(&mut chan.phase, Phase::Closing) {
                self.dead.push(a.attachment.clone());
                self.by_attachment.remove(&a.attachment);
            }
        }
    }

    /// Attachments whose channel closed on Atem's side (overflow): the
    /// session host forgets them.
    pub fn reap<J: Journal>(&mut self, parts: &mut Parts<'_, J>) -> Vec<Effect> {
        let mut effects = Vec::new();
        for att in std::mem::take(&mut self.dead) {
            effects.extend(parts.host.disconnect(&att));
        }
        effects
    }

    /// Hands what is queued to the link: the `unknown_channel` closes, then
    /// each channel's queue in turn, and each closing channel's `close`
    /// once its queue drained. `send` refuses when the link is full; the
    /// rest waits.
    pub fn flush(&mut self, send: &mut dyn FnMut(String) -> bool) {
        if !self.flush_closes(send) {
            return;
        }
        // Fair service: one message per channel per round, the rounds
        // starting with the channel the link last refused, so a busy
        // channel can't hold the others back (§R9.7a "Bounds").
        let mut handles: Vec<String> = self.chans.keys().cloned().collect();
        if let Some(cursor) = &self.flush_cursor {
            // Resume at the refused channel (it goes first next time).
            let at = handles.partition_point(|h| h < cursor);
            handles.rotate_left(at);
        }
        loop {
            let mut progressed = false;
            for handle in &handles {
                let Some(chan) = self.chans.get_mut(handle) else {
                    continue;
                };
                if let Some(text) = chan.queue.pop_front() {
                    let len = text.len();
                    if !send(text.clone()) {
                        chan.queue.push_front(text);
                        self.flush_cursor = Some(handle.clone());
                        return;
                    }
                    chan.queued = chan.queued.saturating_sub(len);
                    progressed = true;
                } else if let Some(why) = chan.close {
                    if !send(envelope::close(handle, Some(why))) {
                        self.flush_cursor = Some(handle.clone());
                        return;
                    }
                    self.chans.remove(handle);
                    progressed = true;
                }
            }
            if !progressed {
                return;
            }
        }
    }

    // ── Time ──

    /// The pass: handshakes past their step (10 s), channels past their
    /// lifetime (24 h, or the expiry), and principals whose expiry passed
    /// (fenced through §H: a revocation, §R9.6).
    pub fn tick<J: Journal>(&mut self, parts: &mut Parts<'_, J>) -> Vec<Effect> {
        let mono = parts.now.host.mono_ms;
        let wall = parts.now.host.wall_ms;
        let mut effects = self.reap(parts);
        let mut timeouts = Vec::new();
        let mut ended = Vec::new();
        let mut expired = Vec::new();
        for (handle, chan) in &self.chans {
            match &chan.phase {
                Phase::AwaitInit { deadline } if mono > *deadline => timeouts.push(handle.clone()),
                Phase::AwaitFinish(f) if mono > f.deadline_ms() => timeouts.push(handle.clone()),
                Phase::Open(a) if a.authority.expired(wall) => expired.push(a.authority.name()),
                Phase::Open(a) if mono >= a.channel.deadline_ms() => ended.push(handle.clone()),
                _ => {}
            }
        }
        for handle in timeouts {
            let frame = Some(chwire::clear_error(ClearCode::HandshakeFailed));
            self.reply_and_close(&handle, frame, reason::HANDSHAKE_FAILED);
        }
        for handle in ended {
            effects.extend(self.fail(&handle, reason::EXPIRED, parts));
        }
        expired.sort();
        expired.dedup();
        for principal in expired {
            log(&format!("{principal} expired; fenced"));
            self.fence_errors.insert(
                principal.clone(),
                error(code::UNAUTHORIZED, None, Some("expired")),
            );
            effects.extend(parts.host.fence_principal(&principal, 0));
        }
        self.revoked.prune(wall);
        self.push_recipients(parts);
        self.push.tick(push_suppressed(parts), wall);
        effects
    }

    // ── Revoked grants journal ──

    fn load_revoked(&mut self) {
        let Some(path) = &self.revoked_path else {
            return;
        };
        let Ok(Some(bytes)) = membership::store::read_private(path) else {
            return;
        };
        let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
            log("revoked_grants is damaged; ignored (grants still expire within an hour)");
            return;
        };
        if let Some(map) = value.get("revoked").and_then(Value::as_object) {
            for (id, until) in map {
                if let Some(until) = until.as_u64() {
                    self.revoked_until.insert(id.clone(), until);
                    let _ = self.revoked.revoke(id, until, 0);
                }
            }
        }
    }

    fn save_revoked(&self) -> std::io::Result<()> {
        let Some(path) = &self.revoked_path else {
            return Ok(());
        };
        let body = serde_json::json!({"v": 1, "revoked": self.revoked_until}).to_string();
        write_private_atomic(path, body.as_bytes())
    }
}

/// Why no push hint or seen may be signed or sent now (§R9.9 with §R9.3,
/// §R9.4 and r8 §I): no device list, a held, frozen or faulted one, or a
/// halted session journal.
fn push_suppressed<J: Journal>(parts: &Parts<'_, J>) -> Option<&'static str> {
    if parts.host.journal_halted() {
        return Some("journal halted");
    }
    match &parts.list {
        DeviceList::Open { m, .. } if m.is_frozen() => Some("device list frozen"),
        DeviceList::Open { m, .. } if m.faulted().is_some() => Some("device list faulted"),
        DeviceList::Open { m, .. } if m.held().is_some() => Some("device list held"),
        DeviceList::Open { .. } => None,
        DeviceList::Failed(_) => Some("device list failed"),
        DeviceList::None => Some(push::NO_LIST),
    }
}

/// The verified log and the host key that sign hints and seens.
fn signer_of<'a>(list: &'a DeviceList<'_>) -> Option<push::Signer<'a>> {
    match list {
        DeviceList::Open { m, key } => Some(push::Signer {
            log: m.membership(),
            key,
        }),
        _ => None,
    }
}

/// An approval's push identity on this host (§R9.9).
fn approval_key(
    list: &DeviceList<'_>,
    request: &r8::ApprovalRequest,
) -> Option<atem_client::push::ApprovalKey> {
    let DeviceList::Open { m, .. } = list else {
        return None;
    };
    let pin = m.pin_of();
    Some(atem_client::push::ApprovalKey::new(
        m.membership(),
        &pin.host_id,
        pin.host_trust_gen,
        &request.session_id,
        &request.process_gen,
        &request.approval_id,
    ))
}

/// §R9.7a: the compact inner frame, or its `ct`, over the bound.
fn inner_too_large(frame: &[u8]) -> bool {
    #[derive(serde::Deserialize)]
    struct Peek<'a> {
        #[serde(borrow, default)]
        ct: Option<&'a str>,
    }
    if frame.len() > MAX_INNER_FRAME {
        return true;
    }
    serde_json::from_slice::<Peek>(frame)
        .ok()
        .and_then(|p| p.ct)
        .is_some_and(|ct| ct.len() > MAX_CT_CHARS)
}

/// `membership_invalid`/`membership_incomplete` of a `membership` op's
/// evaluation (its stop), if any.
fn invalid_of(
    eval: &atem_client::membership::Evaluation,
    re: Option<&str>,
) -> Option<SessionError> {
    use atem_client::membership::Stop;
    match &eval.stop {
        Some(Stop::Invalid { .. }) | Some(Stop::NeedBefore { .. }) => admission_error(
            &eval.admission(
                "",
                false,
                &HostNow {
                    wall_ms: 0,
                    mono_ms: 0,
                    boot_id: String::new(),
                },
            ),
            re,
        ),
        _ => None,
    }
}

/// `message` as `authority` may see it: sessions out of its scope left out
/// of snapshots, events about them dropped; approvals only with the
/// `approval` op (§R9.6). Unscoped (native) principals see everything.
fn scoped(
    authority: &Authority,
    message: &R8Envelope,
    projects: &dyn ProjectScope,
    host_id: &str,
    approval_session: &dyn Fn(&str) -> Option<String>,
) -> Option<R8Envelope> {
    let Some(scope) = &authority.scope else {
        return Some(message.clone());
    };
    let in_scope =
        |sid: &str| authority.session_in_scope(host_id, sid, &|e| projects.matches(sid, e));
    let approvals = scope.ops.contains(&Op::Approval);
    let R8Envelope::Session(m) = message else {
        return Some(message.clone());
    };
    let mut m = m.clone();
    match &mut m.op {
        R8Op::Sessions { sessions, .. } => sessions.retain(|d| in_scope(&d.session_id)),
        R8Op::SessionChanged { descriptor, .. } if !in_scope(&descriptor.session_id) => {
            return None;
        }
        R8Op::LeaseChanged { session_id, .. } if !in_scope(session_id) => return None,
        R8Op::ApprovalRules { session_id, .. } if !approvals || !in_scope(session_id) => {
            return None;
        }
        R8Op::ApprovalRequest(r) if !approvals || !in_scope(&r.session_id) => return None,
        // Its session from the request it closes; unknown: left out.
        R8Op::ApprovalClosed { approval_id, .. }
            if !approvals || !approval_session(approval_id).is_some_and(|s| in_scope(&s)) =>
        {
            return None;
        }
        R8Op::Receipt(r) if !in_scope(&r.target.session_id) => return None,
        R8Op::Receipts { receipts } => receipts.retain(|r| in_scope(&r.target.session_id)),
        _ => {}
    }
    Some(R8Envelope::Session(m))
}

/// A private file replaced whole: temp (0600, `O_EXCL`), write, fsync,
/// rename, directory fsync.
fn write_private_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let dir = path
        .parent()
        .ok_or_else(|| std::io::Error::other("no directory"))?;
    let tmp = path.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)?;
    std::fs::File::open(dir)?.sync_all()
}
