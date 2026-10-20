//! The client's side of `atem-ch1` (§R9.7 steps 1, 3, 4, 5, 7).
//!
//! [`Initiator::start`] → [`AwaitAccept::on_frame`] → [`Accepted::sign`] →
//! [`Signed::finish`] → [`Channel`]. The host key and its trust generation
//! come only from the client's verified log; the host's head is verified
//! (`sig_h`, bound into `th2`) and reported, never adopted. On a bad `sig_h`
//! (or any other refusal) the client sends nothing more.
use rand_core::{OsRng, RngCore};

use super::carriage::{Carriage, HeadRelation};
use super::record::{Channel, Role};
use super::transcript::{
    HeadError, HostAccept, HostHead, Schedule, channel_id, client_signing_input, shared_secret,
    th3, th4,
};
use super::wire::{Frame, Init, parse_frame};
use super::{
    ChannelError, Failure, HANDSHAKE_STEP_MS, MAX_PLAINTEXT, NATIVE_LIFETIME_MS, Principal,
};
use crate::SignedObject;
use crate::domain::SigningInput;
use crate::encoding::Hash32;
use crate::keys::{Alg, PublicKey, normalize_signature};
use crate::membership::Membership;
use crate::membership::entry::HostRecord;
use crate::provider::{KeyId, KeyProvider, sign};
use crate::session::r9::hello_bytes;

/// Starts a handshake.
pub struct Initiator;

impl Initiator {
    /// Step 1: refuses unless `host_id` is a current host of the client's
    /// verified `log` (its newest `add_host` gives the trust generation and
    /// key). Returns the state and the `init` frame to send.
    pub fn start(
        log: &Membership,
        host_id: &str,
        now_ms: u64,
    ) -> Result<(AwaitAccept, Vec<u8>), ChannelError> {
        let mut n = [0u8; 32];
        OsRng.fill_bytes(&mut n);
        let secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        Self::start_inner(log, host_id, secret, n, now_ms)
    }

    /// `start` with a fixed ephemeral secret and nonce (known-answer
    /// vectors only).
    #[cfg(any(test, feature = "test-vectors"))]
    pub fn start_with(
        log: &Membership,
        host_id: &str,
        e_secret: [u8; 32],
        n: [u8; 32],
        now_ms: u64,
    ) -> Result<(AwaitAccept, Vec<u8>), ChannelError> {
        Self::start_inner(
            log,
            host_id,
            x25519_dalek::StaticSecret::from(e_secret),
            n,
            now_ms,
        )
    }

    fn start_inner(
        log: &Membership,
        host_id: &str,
        secret: x25519_dalek::StaticSecret,
        n: [u8; 32],
        now_ms: u64,
    ) -> Result<(AwaitAccept, Vec<u8>), ChannelError> {
        let host = log.host(host_id).ok_or(ChannelError::UnknownHost)?.clone();
        let init = Init {
            e: x25519_dalek::PublicKey::from(&secret).to_bytes(),
            n,
            genesis_hash: log.genesis_hash(),
            host_id: host.host_id.clone(),
            host_trust_gen: host.host_trust_gen,
        };
        let frame = Frame::Init(init.clone()).to_bytes();
        Ok((
            AwaitAccept {
                secret,
                init,
                host,
                started_ms: now_ms,
            },
            frame,
        ))
    }
}

/// `init` sent; waiting for `accept`.
pub struct AwaitAccept {
    secret: x25519_dalek::StaticSecret,
    init: Init,
    host: HostRecord,
    started_ms: u64,
}

impl AwaitAccept {
    /// The client gives up on `accept` at this time (§R9.7: within 10 s).
    pub fn deadline_ms(&self) -> u64 {
        self.started_ms + HANDSHAKE_STEP_MS
    }

    /// The `init` this state sent (`genesis_hash`, `host_id`,
    /// `host_trust_gen`).
    pub fn init(&self) -> &Init {
        &self.init
    }

    /// Step 3 and 4. `log` is the client's verified log now (for the head
    /// relation; the host key is the one pinned at `start`). A clear `error`
    /// is returned as [`ChannelError::Advisory`]; anything else that fails
    /// is `handshake_failed` and the client sends nothing more.
    pub fn on_frame(
        self,
        frame: &[u8],
        log: &Membership,
        now_ms: u64,
    ) -> Result<Accepted, ChannelError> {
        let failed = ChannelError::HandshakeFailed;
        if now_ms > self.deadline_ms() {
            return Err(failed(Failure::Timeout));
        }
        let accept = match parse_frame(frame) {
            Ok(Frame::Accept(accept)) => accept,
            Ok(Frame::Error { code }) => return Err(ChannelError::Advisory { code }),
            _ => return Err(failed(Failure::Malformed)),
        };
        let pair = HostAccept::new(&self.init, &accept);
        // `sig_h` over th2 with the key pinned from the verified log: a
        // rewritten head, nonce or ephemeral fails here.
        let host_head = pair.verify_with(&self.host).map_err(|e| match e {
            HeadError::BadSignature | HeadError::Malformed => failed(Failure::BadHostSignature),
            HeadError::OtherGenesis | HeadError::UnknownHost => ChannelError::UnknownHost,
        })?;
        let ss = shared_secret(&self.secret, &accept.e)
            .map_err(|_| failed(Failure::ZeroSharedSecret))?;
        let schedule = Schedule::new(pair.th2(), &ss);
        // The relation is judged on the log the client holds now, but only
        // if it is still the log the host key came from.
        let relation = if log.genesis_hash() == self.init.genesis_hash {
            HeadRelation::of(log, host_head.head())
        } else {
            return Err(ChannelError::UnknownHost);
        };
        Ok(Accepted {
            schedule,
            sig_h: accept.sig,
            host_head,
            relation,
            accepted_ms: now_ms,
        })
    }
}

/// `accept` verified: `hs` derived, the host's head known.
pub struct Accepted {
    schedule: Schedule,
    sig_h: Vec<u8>,
    host_head: HostHead,
    relation: HeadRelation,
    accepted_ms: u64,
}

impl Accepted {
    /// The host's head, verified with its key (`sig_h`).
    pub fn host_head(&self) -> &HostHead {
        &self.host_head
    }

    /// How the client's log relates to it (what the `hello` carries).
    pub fn relation(&self) -> HeadRelation {
        self.relation
    }

    /// `th2` (diagnostics and vectors).
    pub fn th2(&self) -> Hash32 {
        self.schedule.th2()
    }

    /// Step 5's signature: `sig_c` over `th3` with the principal's key
    /// (`auth_key`, or a browser's `browser_key`) through the platform.
    pub fn sign(
        self,
        principal: Principal,
        provider: &dyn KeyProvider,
        key: &KeyId,
    ) -> Result<Signed, ChannelError> {
        let th3 = th3(&self.schedule.th2(), &self.sig_h, &principal);
        // A provider failure (a cancelled confirmation) ends the handshake
        // locally: nothing is sent.
        let sig_c =
            sign(provider, key, &client_signing_input(&th3)).map_err(ChannelError::Signing)?;
        Ok(self.into_signed(principal, th3, sig_c))
    }

    /// The input `sig_c` signs for `principal`: what an asynchronous
    /// platform signer (WebCrypto, an owner-auth prompt answered later)
    /// signs before [`Accepted::signed_with`].
    pub fn signing_input(&self, principal: &Principal) -> SigningInput {
        client_signing_input(&th3(&self.schedule.th2(), &self.sig_h, principal))
    }

    /// Step 5 with a signature made outside the crate over
    /// [`Accepted::signing_input`]: a P-256 signature is normalized to low S,
    /// then it must verify with `public` (the principal's key) before it is
    /// used; anything else is `ChannelError::Signing` and nothing is sent.
    pub fn signed_with(
        self,
        principal: Principal,
        public: &PublicKey,
        sig: &[u8],
    ) -> Result<Signed, ChannelError> {
        let th3 = th3(&self.schedule.th2(), &self.sig_h, &principal);
        if public.alg() == Alg::X25519 {
            return Err(ChannelError::Signing(crate::Error::WrongAlg));
        }
        let sig_c =
            normalize_signature(public.alg(), sig.to_vec()).map_err(ChannelError::Signing)?;
        public
            .verify(&client_signing_input(&th3), &sig_c)
            .map_err(ChannelError::Signing)?;
        Ok(self.into_signed(principal, th3, sig_c))
    }

    fn into_signed(self, principal: Principal, th3: Hash32, sig_c: Vec<u8>) -> Signed {
        Signed {
            schedule: self.schedule,
            th3,
            sig_c,
            principal,
            host_head: self.host_head,
            relation: self.relation,
            accepted_ms: self.accepted_ms,
        }
    }
}

/// `sig_c` made; the caller builds the `hello` around it.
pub struct Signed {
    schedule: Schedule,
    th3: Hash32,
    sig_c: Vec<u8>,
    principal: Principal,
    host_head: HostHead,
    relation: HeadRelation,
    accepted_ms: u64,
}

impl Signed {
    /// `sig_c` (`hello.proof.sig`, b64u).
    pub fn sig_c(&self) -> &[u8] {
        &self.sig_c
    }

    pub fn principal(&self) -> &Principal {
        &self.principal
    }

    pub fn host_head(&self) -> &HostHead {
        &self.host_head
    }

    pub fn relation(&self) -> HeadRelation {
        self.relation
    }

    pub fn th3(&self) -> Hash32 {
        self.th3
    }

    /// Steps 5 and 7 with the crate's own `hello` (§R9.8): `revision: 9`,
    /// `proof{principal, sig}` with exactly the principal and `sig_c` of this
    /// handshake, the `membership` carriage, and the grant for a browser (its
    /// `grant_hash` must be the one bound into `th3`). Seals it under `k_fin`
    /// and derives the record keys. Returns the channel (native lifetime
    /// until the `welcome` shortens it to `authorization_ms_left`) and the
    /// `finish` frame. `hs` and `k_fin` are wiped when this returns.
    pub fn finish_hello(
        self,
        id: &str,
        carriage: &Carriage,
        grant: Option<&SignedObject>,
        now_ms: u64,
    ) -> Result<(Channel, Vec<u8>), ChannelError> {
        let grant_hash = grant.map(|g| g.grant_hash());
        match (self.principal.grant_hash(), grant_hash) {
            (None, None) => {}
            (Some(bound), Some(Some(given))) if bound == given => {}
            _ => {
                return Err(ChannelError::InvalidHello(
                    "the grant is not the principal's",
                ));
            }
        }
        let hello = hello_bytes(id, &self.principal, &self.sig_c, carriage, grant);
        self.seal(&hello, now_ms)
    }

    /// Seals arbitrary `hello` bytes (known-answer vectors and fixtures that
    /// send a malformed or mismatched hello on purpose). Apps use
    /// [`Signed::finish_hello`].
    #[cfg(any(test, feature = "test-vectors"))]
    pub fn finish(self, hello: &[u8], now_ms: u64) -> Result<(Channel, Vec<u8>), ChannelError> {
        self.seal(hello, now_ms)
    }

    fn seal(self, hello: &[u8], now_ms: u64) -> Result<(Channel, Vec<u8>), ChannelError> {
        if hello.len() > MAX_PLAINTEXT {
            return Err(ChannelError::TooLarge);
        }
        if now_ms > self.accepted_ms + HANDSHAKE_STEP_MS {
            return Err(ChannelError::HandshakeFailed(Failure::Timeout));
        }
        let ct = self.schedule.seal_finish(hello);
        let th4 = th4(&self.th3, &self.sig_c, hello);
        let keys = self.schedule.record_keys(&th4);
        let channel = Channel::new(
            Role::Client,
            keys,
            channel_id(&th4),
            now_ms + NATIVE_LIFETIME_MS,
        );
        Ok((channel, Frame::Finish { ct }.to_bytes()))
    }
}

impl std::fmt::Debug for AwaitAccept {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Secrets are never printed.
        f.debug_struct("AwaitAccept").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for Accepted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Secrets are never printed.
        f.debug_struct("Accepted").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for Signed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Secrets are never printed.
        f.debug_struct("Signed").finish_non_exhaustive()
    }
}
