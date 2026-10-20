//! The `atem-ch1` transcript and key schedule (§R9.7 steps 2–7). Every
//! input is `enc`; `H` is SHA-256. This module is the one implementation
//! of each formula: the state machines, the restore's host-signed heads and
//! the vector runner all call these.
//!
//! ```text
//! th2   = H(enc(["atem-ch1-th2", e_c, n_c, genesis_hash, host_id,
//!                u64(host_trust_gen), e_h, n_h, u64(head.seq), head.hash]))
//! sig_h = Sign_ed25519(host_channel_key, enc(["atem-ch1-host-sig-v1", th2]))
//! hs    = HKDF-Extract(salt = th2, ikm = ss)
//! k_fin = HKDF-Expand(hs, enc(["atem-ch1 finish c2h", th2]), 32)
//! th3   = H(enc(["atem-ch1-th3", th2, sig_h, jcs(principal), grant_hash or empty]))
//! sig_c = Sign(auth_key or browser_key, enc(["atem-ch1-client-sig-v1", th3]))
//! finish.ct = ChaCha20-Poly1305(k_fin, 12 zero bytes, enc(["atem-ch1-finish", th2]), hello)
//! th4   = H(enc(["atem-ch1-th4", th3, sig_c, H(hello)]))
//! k_c2h = HKDF-Expand(hs, enc(["atem-ch1 ap c2h", th4]), 32)
//! k_h2c = HKDF-Expand(hs, enc(["atem-ch1 ap h2c", th4]), 32)
//! channel_id = hex(th4[0..16])
//! ```
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use super::Principal;
use super::wire::{Accept, Frame, Init, frame_of_value};
use crate::canonical::StrictValue;
use crate::domain::{self, SignLabel, SigningInput};
use crate::encoding::{Hash32, enc, hex, u64_field};
use crate::membership::entry::HostRecord;
use crate::membership::{Head, Membership};

/// One host's answer to an `init` (§R9.7 messages 1 and 2): what the client
/// sent and what the host signed. The client checks it with
/// [`HostAccept::verify`] (in the handshake, and for each head a restore
/// relies on, §R9.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostAccept {
    /// `init`: the client's ephemeral and nonce, and the target it named.
    pub e_c: [u8; 32],
    pub n_c: [u8; 32],
    pub genesis_hash: Hash32,
    pub host_id: String,
    pub host_trust_gen: u64,
    /// `accept`: the host's ephemeral and nonce, its head and `sig_h`.
    pub e_h: [u8; 32],
    pub n_h: [u8; 32],
    pub head: Head,
    pub sig: Vec<u8>,
}

/// Why a host's `accept` doesn't confirm a head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeadError {
    /// Not the `init`/`accept` shape of §R9.7.
    Malformed,
    /// The `init` named another log (another account or genesis).
    OtherGenesis,
    /// No current host by that id in the verified chain, or not its newest
    /// trust generation.
    UnknownHost,
    /// `sig_h` doesn't verify with that host's key.
    BadSignature,
}

/// A head a host signed, verified: only [`HostAccept::verify`] makes one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostHead {
    host_id: String,
    head: Head,
}

impl HostHead {
    pub fn host_id(&self) -> &str {
        &self.host_id
    }

    pub fn head(&self) -> Head {
        self.head
    }

    /// `log` holds this head's entry at its `seq` (the client reached it,
    /// e.g. after fetching and verifying the suffix it lacked).
    pub fn reached_by(&self, log: &Membership) -> bool {
        log.entry(self.head.seq)
            .is_some_and(|e| e.hash() == self.head.hash)
    }
}

impl HostAccept {
    /// From the two frames.
    pub fn new(init: &Init, accept: &Accept) -> Self {
        HostAccept {
            e_c: init.e,
            n_c: init.n,
            genesis_hash: init.genesis_hash,
            host_id: init.host_id.clone(),
            host_trust_gen: init.host_trust_gen,
            e_h: accept.e,
            n_h: accept.n,
            head: accept.head,
            sig: accept.sig.clone(),
        }
    }

    /// From the two wire messages, parsed strictly (exactly the fields of
    /// §R9.7).
    pub fn from_messages(init: &StrictValue, accept: &StrictValue) -> Result<Self, HeadError> {
        match (frame_of_value(init), frame_of_value(accept)) {
            (Ok(Frame::Init(init)), Ok(Frame::Accept(accept))) => Ok(Self::new(&init, &accept)),
            _ => Err(HeadError::Malformed),
        }
    }

    /// `th2`.
    pub fn th2(&self) -> Hash32 {
        Hash32::of_enc(&[
            domain::CH1_TH2.as_bytes(),
            &self.e_c,
            &self.n_c,
            self.genesis_hash.as_bytes(),
            self.host_id.as_bytes(),
            &u64_field(self.host_trust_gen),
            &self.e_h,
            &self.n_h,
            &u64_field(self.head.seq),
            self.head.hash.as_bytes(),
        ])
    }

    /// `enc(["atem-ch1-host-sig-v1", th2])`: what the host signs.
    pub fn signing_input(&self) -> SigningInput {
        host_signing_input(&self.th2())
    }

    /// Checks `sig_h` with the host key `log` records for `host_id` at
    /// `host_trust_gen` (its newest `add_host`, the host still current), and
    /// that the `init` named `log`'s genesis.
    pub fn verify(&self, log: &Membership) -> Result<HostHead, HeadError> {
        if self.genesis_hash != log.genesis_hash() {
            return Err(HeadError::OtherGenesis);
        }
        let host = log.host(&self.host_id).ok_or(HeadError::UnknownHost)?;
        self.verify_with(host)
    }

    /// `verify` against one host record (the client pinned it at `init`).
    pub fn verify_with(&self, host: &HostRecord) -> Result<HostHead, HeadError> {
        if host.host_id != self.host_id || host.host_trust_gen != self.host_trust_gen {
            return Err(HeadError::UnknownHost);
        }
        host.host_key
            .verify(&self.signing_input(), &self.sig)
            .map_err(|_| HeadError::BadSignature)?;
        Ok(HostHead {
            host_id: self.host_id.clone(),
            head: self.head,
        })
    }
}

/// `enc(["atem-ch1-host-sig-v1", th2])`.
pub fn host_signing_input(th2: &Hash32) -> SigningInput {
    SigningInput::new(SignLabel::ChannelHost, th2.as_bytes())
}

/// `th3`; `grant_hash` is an empty field unless the principal is a browser.
pub fn th3(th2: &Hash32, sig_h: &[u8], principal: &Principal) -> Hash32 {
    let grant_hash = principal.grant_hash();
    let grant: &[u8] = match &grant_hash {
        Some(hash) => hash.as_bytes(),
        None => &[],
    };
    Hash32::of_enc(&[
        domain::CH1_TH3.as_bytes(),
        th2.as_bytes(),
        sig_h,
        principal.jcs().as_bytes(),
        grant,
    ])
}

/// `enc(["atem-ch1-client-sig-v1", th3])`: what the client signs.
pub fn client_signing_input(th3: &Hash32) -> SigningInput {
    SigningInput::new(SignLabel::ChannelClient, th3.as_bytes())
}

/// `th4`.
pub fn th4(th3: &Hash32, sig_c: &[u8], hello: &[u8]) -> Hash32 {
    Hash32::of_enc(&[
        domain::CH1_TH4.as_bytes(),
        th3.as_bytes(),
        sig_c,
        Hash32::of(hello).as_bytes(),
    ])
}

/// `hex(th4[0..16])`.
pub fn channel_id(th4: &Hash32) -> String {
    hex(&th4.as_bytes()[..16])
}

/// The all-zero shared secret (a low-order peer ephemeral, §R9.7 step 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZeroSharedSecret;

/// `ss = X25519(own, peer)`, refusing the all-zero output (checked in
/// constant time, before any HKDF).
pub fn shared_secret(
    own: &x25519_dalek::StaticSecret,
    peer: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, ZeroSharedSecret> {
    let shared = own.diffie_hellman(&x25519_dalek::PublicKey::from(*peer));
    let ss = Zeroizing::new(shared.to_bytes());
    if bool::from(ss.ct_eq(&[0u8; 32])) || !shared.was_contributory() {
        return Err(ZeroSharedSecret);
    }
    Ok(ss)
}

/// The handshake secret `hs` and `th2`: `k_fin` and the record keys come
/// from here. Wiped on drop.
pub struct Schedule {
    hs: Zeroizing<[u8; 32]>,
    th2: Hash32,
}

impl Schedule {
    /// `hs = HKDF-Extract(salt = th2, ikm = ss)`.
    pub fn new(th2: Hash32, ss: &[u8; 32]) -> Self {
        let (mut prk, _) = Hkdf::<Sha256>::extract(Some(th2.as_bytes()), ss);
        let mut hs = Zeroizing::new([0u8; 32]);
        hs.copy_from_slice(&prk);
        prk.as_mut_slice().zeroize();
        Schedule { hs, th2 }
    }

    pub fn th2(&self) -> Hash32 {
        self.th2
    }

    /// `hs` (the vectors check it).
    pub fn hs(&self) -> &[u8; 32] {
        &self.hs
    }

    fn expand(&self, label: &str, th: &Hash32) -> Zeroizing<[u8; 32]> {
        let hkdf = Hkdf::<Sha256>::from_prk(&*self.hs).expect("hs is 32 bytes");
        let mut out = Zeroizing::new([0u8; 32]);
        hkdf.expand(&enc(&[label.as_bytes(), th.as_bytes()]), &mut *out)
            .expect("32 bytes is a valid HKDF length");
        out
    }

    /// `k_fin`.
    pub fn finish_key(&self) -> Zeroizing<[u8; 32]> {
        self.expand(domain::CH1_FINISH_KEY, &self.th2)
    }

    /// `(k_c2h, k_h2c)` for `th4`.
    pub fn record_keys(&self, th4: &Hash32) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
        (
            self.expand(domain::CH1_AP_C2H, th4),
            self.expand(domain::CH1_AP_H2C, th4),
        )
    }

    /// `enc(["atem-ch1-finish", th2])`.
    pub fn finish_aad(&self) -> Vec<u8> {
        enc(&[domain::CH1_FINISH_AAD.as_bytes(), self.th2.as_bytes()])
    }

    /// `finish.ct`.
    pub fn seal_finish(&self, hello: &[u8]) -> Vec<u8> {
        aead_seal(&self.finish_key(), &[0u8; 12], &self.finish_aad(), hello)
    }

    /// Opens `finish.ct`; `None` when the tag fails.
    pub fn open_finish(&self, ct: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        aead_open(&self.finish_key(), &[0u8; 12], &self.finish_aad(), ct)
    }
}

/// ChaCha20-Poly1305 seal.
pub(crate) fn aead_seal(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], plain: &[u8]) -> Vec<u8> {
    ChaCha20Poly1305::new(Key::from_slice(key))
        .encrypt(Nonce::from_slice(nonce), Payload { msg: plain, aad })
        .expect("ChaCha20-Poly1305 seals any plaintext under 256 GiB")
}

/// ChaCha20-Poly1305 open (the tag is checked in constant time by the
/// crate); `None` when it fails.
pub(crate) fn aead_open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ct: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    ChaCha20Poly1305::new(Key::from_slice(key))
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad })
        .ok()
        .map(Zeroizing::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_low_order_peer_gives_a_refused_zero_secret() {
        let own = x25519_dalek::StaticSecret::from([7u8; 32]);
        assert_eq!(shared_secret(&own, &[0u8; 32]), Err(ZeroSharedSecret));
        // The order-2 point (u = 1) is low order too.
        let mut one = [0u8; 32];
        one[0] = 1;
        assert_eq!(shared_secret(&own, &one), Err(ZeroSharedSecret));
        assert!(shared_secret(&own, &[9u8; 32]).is_ok());
    }

    #[test]
    fn th3_binds_the_grant_only_for_a_browser() {
        let th2 = Hash32([1; 32]);
        let native = Principal::Native {
            device_id: "dev-a".into(),
        };
        let browser = Principal::Browser {
            grant_id: "dev-a".into(),
            grant_hash: Hash32([2; 32]),
        };
        let other_grant = Principal::Browser {
            grant_id: "dev-a".into(),
            grant_hash: Hash32([3; 32]),
        };
        let all = [
            th3(&th2, &[5; 64], &native),
            th3(&th2, &[5; 64], &browser),
            th3(&th2, &[5; 64], &other_grant),
            th3(&th2, &[6; 64], &native),
        ];
        for i in 0..all.len() {
            for j in i + 1..all.len() {
                assert_ne!(all[i], all[j]);
            }
        }
    }

    #[test]
    fn finish_opens_only_under_its_own_transcript() {
        let a = Schedule::new(Hash32([1; 32]), &[2; 32]);
        let b = Schedule::new(Hash32([3; 32]), &[2; 32]);
        let ct = a.seal_finish(b"hello");
        assert_eq!(&**a.open_finish(&ct).unwrap(), b"hello");
        assert!(b.open_finish(&ct).is_none());
        let mut flipped = ct.clone();
        flipped[0] ^= 1;
        assert!(a.open_finish(&flipped).is_none());
    }
}
