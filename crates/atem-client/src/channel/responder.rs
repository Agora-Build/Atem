//! The host's side of `atem-ch1` (§R9.7 steps 2, 4, 6, 7).
//!
//! [`Responder::on_init`] → [`AwaitFinish::on_finish`] → [`Opened`] (the
//! `hello` bytes) → [`Opened::key`] with the hello's proof → [`Keyed`]. The
//! caller then applies the carriage, resolves the principal against the
//! committed head and either [`Keyed::admit`]s it with the principal's key
//! (verifying `sig_c`) or [`Keyed::refuse`]s it; a bad `sig_c` is a
//! [`Refusal`] whose reply is the encrypted first record. The host keeps
//! nothing for an `init` but its handshake secret; classify transport
//! frames with [`super::wire::parse`] first (a plain session message is the
//! caller's to answer).
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use super::record::{Channel, Role};
use super::transcript::{
    HostAccept, Schedule, channel_id, client_signing_input, shared_secret, th3, th4,
};
use super::wire::{Accept, Frame, clear_error, parse_frame};
use super::{
    ChannelError, ClearCode, ClientProof, Failure, HANDSHAKE_STEP_MS, INIT_INTERVAL_MS,
    NATIVE_LIFETIME_MS, Principal,
};
use crate::keys::PublicKey;
use crate::membership::Membership;
use crate::provider::{KeyId, KeyProvider, sign};

/// What the host answers with: its committed log (genesis, head, frozen),
/// its identity, and its `host_channel_key` behind a provider.
pub struct HostContext<'a> {
    pub log: &'a Membership,
    pub host_id: &'a str,
    pub host_trust_gen: u64,
    pub provider: &'a dyn KeyProvider,
    pub key: &'a KeyId,
}

/// A refused handshake step: send `reply` if there is one, then close.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    pub error: ChannelError,
    pub reply: Option<Vec<u8>>,
}

impl Refused {
    fn clear(error: ChannelError, code: ClearCode) -> Self {
        Refused {
            error,
            reply: Some(clear_error(code)),
        }
    }

    fn silent(error: ChannelError) -> Self {
        Refused { error, reply: None }
    }
}

/// At most one `init` a second per transport (§R9.7 "Limits"); one per
/// transport connection.
#[derive(Debug, Default)]
pub struct InitLimiter {
    last_ms: Option<u64>,
}

impl InitLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// `true` when an `init` arriving at `now_ms` may be answered; else the
    /// caller answers `busy` ([`InitLimiter::busy`]) and closes.
    pub fn admit(&mut self, now_ms: u64) -> bool {
        match self.last_ms {
            Some(last) if now_ms < last + INIT_INTERVAL_MS => false,
            _ => {
                self.last_ms = Some(now_ms);
                true
            }
        }
    }

    /// The clear `busy` refusal.
    pub fn busy() -> Refused {
        Refused::clear(ChannelError::Busy, ClearCode::Busy)
    }
}

/// Answers `init`s.
pub struct Responder;

impl Responder {
    /// Step 2: checks the target, signs the head, derives `hs`. Returns the
    /// state and the `accept` frame, or the clear refusal.
    pub fn on_init(
        ctx: &HostContext<'_>,
        frame: &[u8],
        now_ms: u64,
    ) -> Result<(AwaitFinish, Vec<u8>), Refused> {
        let mut n = [0u8; 32];
        OsRng.fill_bytes(&mut n);
        let secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        Self::on_init_inner(ctx, frame, secret, n, now_ms)
    }

    /// `on_init` with a fixed ephemeral secret and nonce (known-answer
    /// vectors only).
    #[cfg(any(test, feature = "test-vectors"))]
    pub fn on_init_with(
        ctx: &HostContext<'_>,
        frame: &[u8],
        e_secret: [u8; 32],
        n: [u8; 32],
        now_ms: u64,
    ) -> Result<(AwaitFinish, Vec<u8>), Refused> {
        Self::on_init_inner(
            ctx,
            frame,
            x25519_dalek::StaticSecret::from(e_secret),
            n,
            now_ms,
        )
    }

    fn on_init_inner(
        ctx: &HostContext<'_>,
        frame: &[u8],
        secret: x25519_dalek::StaticSecret,
        n: [u8; 32],
        now_ms: u64,
    ) -> Result<(AwaitFinish, Vec<u8>), Refused> {
        let failed = |why| {
            Refused::clear(
                ChannelError::HandshakeFailed(why),
                ClearCode::HandshakeFailed,
            )
        };
        let init = match parse_frame(frame) {
            Ok(Frame::Init(init)) => init,
            Ok(Frame::Error { code }) => {
                return Err(Refused::silent(ChannelError::Advisory { code }));
            }
            _ => return Err(failed(Failure::Malformed)),
        };
        let ours = init.genesis_hash == ctx.log.genesis_hash()
            && init.host_id == ctx.host_id
            && init.host_trust_gen == ctx.host_trust_gen;
        if !ours {
            return Err(Refused::clear(
                ChannelError::StaleTarget,
                ClearCode::StaleTarget,
            ));
        }
        if ctx.log.frozen().is_some() {
            return Err(Refused::clear(
                ChannelError::AccountFrozen,
                ClearCode::AccountFrozen,
            ));
        }
        let ss = shared_secret(&secret, &init.e).map_err(|_| failed(Failure::ZeroSharedSecret))?;
        let mut accept = Accept {
            e: x25519_dalek::PublicKey::from(&secret).to_bytes(),
            n,
            head: ctx.log.head(),
            sig: Vec::new(),
        };
        drop(secret);
        let pair = HostAccept::new(&init, &accept);
        accept.sig = sign(ctx.provider, ctx.key, &pair.signing_input())
            .map_err(|_| Refused::clear(ChannelError::Busy, ClearCode::Busy))?;
        let schedule = Schedule::new(pair.th2(), &ss);
        Ok((
            AwaitFinish {
                schedule,
                sig_h: accept.sig.clone(),
                accepted_ms: now_ms,
            },
            Frame::Accept(accept).to_bytes(),
        ))
    }
}

/// `accept` sent; waiting for `finish`.
pub struct AwaitFinish {
    schedule: Schedule,
    sig_h: Vec<u8>,
    accepted_ms: u64,
}

impl AwaitFinish {
    /// The host closes at this time without a `finish` (10 s after
    /// `accept`), answering [`AwaitFinish::timeout`].
    pub fn deadline_ms(&self) -> u64 {
        self.accepted_ms + HANDSHAKE_STEP_MS
    }

    /// The clear refusal when the deadline passed.
    pub fn timeout(self) -> Refused {
        Refused::clear(
            ChannelError::HandshakeFailed(Failure::Timeout),
            ClearCode::HandshakeFailed,
        )
    }

    /// Step 6's first part: opens the `finish`. A failed tag (a tampered or
    /// replayed `finish`) is a clear `handshake_failed`.
    pub fn on_finish(self, frame: &[u8], now_ms: u64) -> Result<Opened, Refused> {
        if now_ms > self.deadline_ms() {
            return Err(self.timeout());
        }
        let failed = |why| {
            Refused::clear(
                ChannelError::HandshakeFailed(why),
                ClearCode::HandshakeFailed,
            )
        };
        let ct = match parse_frame(frame) {
            Ok(Frame::Finish { ct }) => ct,
            Ok(Frame::Error { code }) => {
                return Err(Refused::silent(ChannelError::Advisory { code }));
            }
            _ => return Err(failed(Failure::Malformed)),
        };
        let hello = self
            .schedule
            .open_finish(&ct)
            .ok_or_else(|| failed(Failure::FinishTag))?;
        Ok(Opened {
            schedule: self.schedule,
            sig_h: self.sig_h,
            hello,
            opened_ms: now_ms,
        })
    }
}

/// `finish` opened: the host holds the `hello` bytes.
pub struct Opened {
    schedule: Schedule,
    sig_h: Vec<u8>,
    hello: Zeroizing<Vec<u8>>,
    opened_ms: u64,
}

impl Opened {
    /// The `hello` plaintext, exactly as hashed into `th4`.
    pub fn hello(&self) -> &[u8] {
        &self.hello
    }

    /// A `hello` the host can't read a proof from (not JSON, no principal or
    /// `sig`): the host can't derive `th4` without them, so it answers a
    /// clear `handshake_failed` and closes (an Atem decision; §R9.7 lists
    /// the malformed handshake message among the clear errors).
    pub fn malformed(self) -> Refused {
        Refused::clear(
            ChannelError::HandshakeFailed(Failure::Malformed),
            ClearCode::HandshakeFailed,
        )
    }

    /// Step 7 with the proof the `hello` carries: `th3`, `th4` and the
    /// record keys, whatever `sig_c` is worth (so any refusal from here on
    /// is the encrypted first record). `hs` is wiped.
    pub fn key(self, proof: &ClientProof) -> Keyed {
        let th3 = th3(&self.schedule.th2(), &self.sig_h, &proof.principal);
        let th4 = th4(&th3, &proof.sig_c, &self.hello);
        let channel = Channel::new(
            Role::Host,
            self.schedule.record_keys(&th4),
            channel_id(&th4),
            self.opened_ms + NATIVE_LIFETIME_MS,
        );
        Keyed {
            channel,
            th3,
            sig_c: proof.sig_c.clone(),
            principal: proof.principal.clone(),
        }
    }
}

/// Keys derived; the client isn't authenticated yet.
pub struct Keyed {
    channel: Channel,
    th3: crate::encoding::Hash32,
    sig_c: Vec<u8>,
    principal: Principal,
}

impl Keyed {
    pub fn channel_id(&self) -> &str {
        self.channel.channel_id()
    }

    /// The principal the `hello` claims (not yet proven).
    pub fn principal(&self) -> &Principal {
        &self.principal
    }

    /// Verifies `sig_c` with the key the committed head gives the principal
    /// (a member's `auth_key`, a grant's `browser_key`). On success the
    /// channel is open and its first record must be the `welcome`.
    ///
    /// `deadline_ms` (monotonic) is when the channel ends, required so a
    /// service's or browser's expiry can't be forgotten (§R9.7 "Limits": 24 h
    /// for a native principal, the expiry for service/browser):
    /// [`crate::principal::Authority::channel_deadline_ms`] computes it. It
    /// only shortens the 24 h the channel started with.
    pub fn admit(self, key: &PublicKey, deadline_ms: u64) -> Result<Channel, Refusal> {
        match key.verify(&client_signing_input(&self.th3), &self.sig_c) {
            Ok(()) => {
                let mut channel = self.channel;
                channel.limit_lifetime(deadline_ms);
                Ok(channel)
            }
            Err(_) => Err(Refusal {
                channel: Box::new(self.channel),
            }),
        }
    }

    /// Refuses before (or instead of) checking `sig_c` — `unauthorized`,
    /// `membership_invalid`, `recovery_pending`, `unsupported_version`, … —
    /// with `error` (a session `error` message) as the first record. Returns
    /// that frame; the channel is closed and its keys wiped.
    pub fn refuse(self, error: &[u8], now_ms: u64) -> Result<Vec<u8>, ChannelError> {
        Refusal {
            channel: Box::new(self.channel),
        }
        .reply(error, now_ms)
    }
}

/// A bad `sig_c` (`handshake_failed`, sent encrypted, §R9.11).
pub struct Refusal {
    channel: Box<Channel>,
}

impl Refusal {
    pub fn error(&self) -> ChannelError {
        ChannelError::HandshakeFailed(Failure::BadClientSignature)
    }

    /// Seals `error` (the session `error` message) as the first record and
    /// closes. Returns the frame to send before closing the transport.
    pub fn reply(mut self, error: &[u8], now_ms: u64) -> Result<Vec<u8>, ChannelError> {
        let frame = self.channel.seal(error, now_ms);
        self.channel.close();
        frame
    }
}

impl std::fmt::Debug for AwaitFinish {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Secrets are never printed.
        f.debug_struct("AwaitFinish").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for Opened {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Secrets are never printed.
        f.debug_struct("Opened").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for Keyed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Secrets are never printed.
        f.debug_struct("Keyed").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Secrets are never printed.
        f.debug_struct("Refusal").finish_non_exhaustive()
    }
}
