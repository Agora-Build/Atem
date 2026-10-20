//! The app's key store. Native members' keys live in the Secure Enclave or
//! Android Keystore and never enter Rust: the core asks the app to sign, to
//! agree an X25519 secret or to open an HPKE seal through
//! [`AppKeyProvider`], a foreign trait Swift and Kotlin implement.
//!
//! Every signature request carries its [`SigningPurpose`] (derived here
//! from the signing label and, for membership entries, the entry's
//! `action`) and the body being signed, so the app applies R9.6: up to
//! 5 minutes of reuse for the channel signature, a fresh owner
//! confirmation bound to the shown body for everything else.
//!
//! Calls into the provider are synchronous and happen on the thread that
//! called the binding: call the binding off the main thread (a provider may
//! block on a biometric prompt). Never call back into the same binding
//! object from inside a provider callback (it holds its lock).
//!
//! A signer that can only answer asynchronously (WebCrypto) uses the
//! deferred handshake instead: `ClientConnection::on_accept_deferred`
//! returns the [`SignRequest`], `finish_with_signature` takes the answer.
#[cfg_attr(
    not(any(feature = "uniffi", feature = "software-keys")),
    allow(unused_imports)
)]
use std::sync::Arc;

use atem_client::domain::{SignLabel, SigningInput};
use atem_client::encoding::dec;
use atem_client::keys::{Alg, PublicKey};
#[cfg_attr(
    not(any(feature = "uniffi", feature = "software-keys")),
    allow(unused_imports)
)]
use atem_client::provider::{KeyId, KeyProvider};
#[cfg_attr(
    not(any(feature = "uniffi", feature = "software-keys")),
    allow(unused_imports)
)]
use zeroize::Zeroizing;

use crate::error::AtemError;
use crate::types::{KeyAlg, PublicKeyData, SignLabelKind, SignRequest, SigningPurpose};

/// Why a provider call failed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum ProviderError {
    /// The owner declined or the confirmation timed out (nothing is sent).
    Cancelled { reason: String },
    /// No key by that id.
    UnknownKey,
    /// Any other platform failure.
    Failed { reason: String },
}

impl std::fmt::Display for ProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProviderError::Cancelled { reason } => write!(f, "cancelled: {reason}"),
            ProviderError::UnknownKey => f.write_str("unknown key"),
            ProviderError::Failed { reason } => write!(f, "failed: {reason}"),
        }
    }
}

impl std::error::Error for ProviderError {}

#[cfg(feature = "uniffi")]
impl From<uniffi::UnexpectedUniFFICallbackError> for ProviderError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        ProviderError::Failed { reason: e.reason }
    }
}

/// What the core needs from the platform key store (implemented in Swift or
/// Kotlin). Each key has one algorithm, fixed when it was created.
#[cfg_attr(feature = "uniffi", uniffi::export(with_foreign))]
pub trait AppKeyProvider: Send + Sync {
    /// The public half of a key, with its algorithm.
    fn public_key(&self, key_id: String) -> Result<PublicKeyData, ProviderError>;

    /// Signs `request.input` with a P-256 (ECDSA/SHA-256, 64-byte `r‖s`,
    /// either S) or Ed25519 key, after the owner confirmation its
    /// `purpose` asks for.
    fn sign(&self, request: SignRequest) -> Result<Vec<u8>, ProviderError>;

    /// X25519 of an X25519 key with `peer` (32 bytes).
    fn x25519(&self, key_id: String, peer: Vec<u8>) -> Result<Vec<u8>, ProviderError>;

    /// RFC 9180 base-mode open with an X25519 key: DHKEM(X25519,
    /// HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305 (CryptoKit `HPKE`,
    /// Tink).
    fn hpke_open(
        &self,
        key_id: String,
        enc: Vec<u8>,
        ct: Vec<u8>,
        info: Vec<u8>,
        aad: Vec<u8>,
    ) -> Result<Vec<u8>, ProviderError>;
}

impl From<Alg> for KeyAlg {
    fn from(alg: Alg) -> Self {
        match alg {
            Alg::P256 => KeyAlg::P256,
            Alg::Ed25519 => KeyAlg::Ed25519,
            Alg::X25519 => KeyAlg::X25519,
        }
    }
}

impl From<KeyAlg> for Alg {
    fn from(alg: KeyAlg) -> Self {
        match alg {
            KeyAlg::P256 => Alg::P256,
            KeyAlg::Ed25519 => Alg::Ed25519,
            KeyAlg::X25519 => Alg::X25519,
        }
    }
}

impl From<&PublicKey> for PublicKeyData {
    fn from(key: &PublicKey) -> Self {
        PublicKeyData {
            alg: key.alg().into(),
            raw: key.as_bytes().to_vec(),
        }
    }
}

impl PublicKeyData {
    /// Validated (length, curve, weak keys).
    pub(crate) fn to_key(&self) -> Result<PublicKey, AtemError> {
        Ok(PublicKey::new(self.alg.into(), &self.raw)?)
    }
}

impl From<SignLabel> for SignLabelKind {
    fn from(label: SignLabel) -> Self {
        match label {
            SignLabel::MembershipEntry => SignLabelKind::MembershipEntry,
            SignLabel::RecoveryCosign => SignLabelKind::RecoveryCosign,
            SignLabel::BrowserGrant => SignLabelKind::BrowserGrant,
            SignLabel::PushHint => SignLabelKind::PushHint,
            SignLabel::Seen => SignLabelKind::Seen,
            SignLabel::ChannelHost => SignLabelKind::ChannelHost,
            SignLabel::ChannelClient => SignLabelKind::ChannelClient,
        }
    }
}

impl From<SignLabelKind> for SignLabel {
    fn from(label: SignLabelKind) -> Self {
        match label {
            SignLabelKind::MembershipEntry => SignLabel::MembershipEntry,
            SignLabelKind::RecoveryCosign => SignLabel::RecoveryCosign,
            SignLabelKind::BrowserGrant => SignLabel::BrowserGrant,
            SignLabelKind::PushHint => SignLabel::PushHint,
            SignLabelKind::Seen => SignLabel::Seen,
            SignLabelKind::ChannelHost => SignLabel::ChannelHost,
            SignLabelKind::ChannelClient => SignLabel::ChannelClient,
        }
    }
}

/// The purpose of a signing input, and the canonical body it signs (none
/// for the channel signatures, which sign a transcript hash).
pub fn describe(input: &SigningInput) -> (SigningPurpose, Option<String>) {
    let body = || {
        dec(input.as_bytes())
            .ok()
            .and_then(|fields| fields.get(1).map(|b| b.to_vec()))
            .and_then(|b| String::from_utf8(b).ok())
    };
    match input.label() {
        SignLabel::ChannelClient => (SigningPurpose::Channel, None),
        SignLabel::ChannelHost => (SigningPurpose::HostSigning, None),
        SignLabel::PushHint | SignLabel::Seen => (SigningPurpose::HostSigning, body()),
        SignLabel::BrowserGrant => (SigningPurpose::BrowserGrant, body()),
        SignLabel::RecoveryCosign => (SigningPurpose::Kit, body()),
        SignLabel::MembershipEntry => {
            let body = body();
            let action = body
                .as_deref()
                .and_then(|b| serde_json::from_str::<serde_json::Value>(b).ok())
                .and_then(|v| v["action"].as_str().map(str::to_owned));
            let purpose = match action.as_deref() {
                Some("genesis") => SigningPurpose::Genesis,
                Some("remove") => SigningPurpose::Remove,
                Some("set_roles") => SigningPurpose::Roles,
                Some("add_host" | "remove_host") => SigningPurpose::Host,
                Some("recovery_add" | "recovery_approve" | "recovery_veto") => {
                    SigningPurpose::Recovery
                }
                Some("set_recovery_key") => SigningPurpose::Kit,
                Some("k_backup") => SigningPurpose::KeyBackup,
                // `add`, and anything else (which the verifier refuses after
                // signing): a fresh confirmation either way.
                _ => SigningPurpose::Enroll,
            };
            (purpose, body)
        }
    }
}

/// The request the app sees for `input` signed by `key`.
pub fn sign_request(key: &KeyId, input: &SigningInput) -> SignRequest {
    let (purpose, body_json) = describe(input);
    SignRequest {
        key_id: key.0.clone(),
        purpose,
        fresh_confirmation: purpose.needs_fresh_confirmation(),
        label: input.label().as_str().into(),
        input: input.as_bytes().to_vec(),
        body_json,
    }
}

#[cfg(feature = "uniffi")]
fn provider_error(e: ProviderError) -> atem_client::Error {
    match e {
        ProviderError::UnknownKey => atem_client::Error::UnknownKey,
        other => atem_client::Error::Provider(other.to_string()),
    }
}

/// The app's provider as the core's `KeyProvider`.
#[cfg(feature = "uniffi")]
pub(crate) struct Platform(pub Arc<dyn AppKeyProvider>);

#[cfg(feature = "uniffi")]
impl KeyProvider for Platform {
    fn public_key(&self, key: &KeyId) -> atem_client::Result<PublicKey> {
        let data = self.0.public_key(key.0.clone()).map_err(provider_error)?;
        PublicKey::new(data.alg.into(), &data.raw)
    }

    fn sign(&self, key: &KeyId, input: &SigningInput) -> atem_client::Result<Vec<u8>> {
        self.0
            .sign(sign_request(key, input))
            .map_err(provider_error)
    }

    fn x25519(&self, key: &KeyId, peer: &[u8; 32]) -> atem_client::Result<Zeroizing<[u8; 32]>> {
        let out = Zeroizing::new(
            self.0
                .x25519(key.0.clone(), peer.to_vec())
                .map_err(provider_error)?,
        );
        let shared: [u8; 32] = out
            .as_slice()
            .try_into()
            .map_err(|_| atem_client::Error::Provider("x25519 must return 32 bytes".into()))?;
        let shared = Zeroizing::new(shared);
        if atem_client::encoding::ct_eq(&*shared, &[0u8; 32]) {
            return Err(atem_client::Error::ZeroSharedSecret);
        }
        Ok(shared)
    }

    fn hpke_open(
        &self,
        key: &KeyId,
        enc: &[u8],
        ct: &[u8],
        info: &[u8],
        aad: &[u8],
    ) -> atem_client::Result<Zeroizing<Vec<u8>>> {
        self.0
            .hpke_open(
                key.0.clone(),
                enc.to_vec(),
                ct.to_vec(),
                info.to_vec(),
                aad.to_vec(),
            )
            .map(Zeroizing::new)
            .map_err(provider_error)
    }
}

/// An in-memory key store (feature `software-keys`): for bots, whose
/// `service` key comes from their own secret store (R9.6 rule 5), and for
/// the conformance tests. Never for a native member's keys.
#[cfg(feature = "software-keys")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct SoftwareKeyStore {
    keys: std::sync::Mutex<atem_client::SoftwareKeys>,
}

#[cfg(feature = "software-keys")]
fn secret32(secret: &[u8]) -> Result<Zeroizing<[u8; 32]>, AtemError> {
    let bytes: [u8; 32] = secret
        .try_into()
        .map_err(|_| AtemError::malformed("a secret is 32 bytes"))?;
    Ok(Zeroizing::new(bytes))
}

#[cfg(feature = "software-keys")]
#[cfg_attr(feature = "uniffi", uniffi::export)]
impl SoftwareKeyStore {
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn new() -> Arc<Self> {
        Arc::new(SoftwareKeyStore {
            keys: std::sync::Mutex::new(atem_client::SoftwareKeys::new()),
        })
    }

    /// A P-256 key from its 32-byte scalar.
    pub fn insert_p256(&self, key_id: String, secret: Vec<u8>) -> Result<(), AtemError> {
        let secret = Zeroizing::new(secret);
        self.lock()
            .insert_p256(KeyId(key_id), &*secret32(&secret)?)?;
        Ok(())
    }

    /// An Ed25519 key from its 32-byte seed.
    pub fn insert_ed25519(&self, key_id: String, seed: Vec<u8>) -> Result<(), AtemError> {
        let seed = Zeroizing::new(seed);
        self.lock()
            .insert_ed25519(KeyId(key_id), &*secret32(&seed)?);
        Ok(())
    }

    /// An X25519 key from its 32 secret bytes.
    pub fn insert_x25519(&self, key_id: String, secret: Vec<u8>) -> Result<(), AtemError> {
        let secret = Zeroizing::new(secret);
        self.lock()
            .insert_x25519(KeyId(key_id), &*secret32(&secret)?);
        Ok(())
    }

    /// A new random key; returns its public half.
    pub fn generate(&self, key_id: String, alg: KeyAlg) -> Result<PublicKeyData, AtemError> {
        let key = self.lock().generate(KeyId(key_id), alg.into())?;
        Ok((&key).into())
    }

    pub fn public_key_of(&self, key_id: String) -> Result<PublicKeyData, AtemError> {
        let key = self.lock().public_key(&KeyId(key_id))?;
        Ok((&key).into())
    }

    /// This store as an `AppKeyProvider` (pass it wherever one is asked).
    #[cfg(feature = "uniffi")]
    pub fn provider(self: Arc<Self>) -> Arc<dyn AppKeyProvider> {
        self
    }
}

#[cfg(feature = "software-keys")]
impl SoftwareKeyStore {
    pub(crate) fn lock(&self) -> std::sync::MutexGuard<'_, atem_client::SoftwareKeys> {
        self.keys.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(feature = "software-keys")]
impl KeyProvider for SoftwareKeyStore {
    fn public_key(&self, key: &KeyId) -> atem_client::Result<PublicKey> {
        self.lock().public_key(key)
    }
    fn sign(&self, key: &KeyId, input: &SigningInput) -> atem_client::Result<Vec<u8>> {
        self.lock().sign(key, input)
    }
    fn x25519(&self, key: &KeyId, peer: &[u8; 32]) -> atem_client::Result<Zeroizing<[u8; 32]>> {
        self.lock().x25519(key, peer)
    }
    fn hpke_open(
        &self,
        key: &KeyId,
        enc: &[u8],
        ct: &[u8],
        info: &[u8],
        aad: &[u8],
    ) -> atem_client::Result<Zeroizing<Vec<u8>>> {
        self.lock().hpke_open(key, enc, ct, info, aad)
    }
}

#[cfg(all(feature = "software-keys", feature = "uniffi"))]
impl AppKeyProvider for SoftwareKeyStore {
    fn public_key(&self, key_id: String) -> Result<PublicKeyData, ProviderError> {
        KeyProvider::public_key(self, &KeyId(key_id))
            .map(|k| (&k).into())
            .map_err(|e| match e {
                atem_client::Error::UnknownKey => ProviderError::UnknownKey,
                other => ProviderError::Failed {
                    reason: other.to_string(),
                },
            })
    }

    fn sign(&self, request: SignRequest) -> Result<Vec<u8>, ProviderError> {
        // The software store signs exactly the bytes it is handed; the label
        // is the first field of `input`, so the request can't lie about it
        // to a verifier.
        let fields = dec(&request.input).map_err(|_| ProviderError::Failed {
            reason: "not a signing input".into(),
        })?;
        let label = match fields.first().copied() {
            Some(l) => l,
            None => {
                return Err(ProviderError::Failed {
                    reason: "not a signing input".into(),
                });
            }
        };
        let label = [
            SignLabel::MembershipEntry,
            SignLabel::RecoveryCosign,
            SignLabel::BrowserGrant,
            SignLabel::PushHint,
            SignLabel::Seen,
            SignLabel::ChannelHost,
            SignLabel::ChannelClient,
        ]
        .into_iter()
        .find(|l| l.as_str().as_bytes() == label)
        .ok_or(ProviderError::Failed {
            reason: "unknown label".into(),
        })?;
        let payload = fields.get(1).copied().unwrap_or_default();
        let input = SigningInput::new(label, payload);
        if input.as_bytes() != request.input.as_slice() {
            return Err(ProviderError::Failed {
                reason: "not a signing input".into(),
            });
        }
        KeyProvider::sign(self, &KeyId(request.key_id), &input).map_err(|e| ProviderError::Failed {
            reason: e.to_string(),
        })
    }

    fn x25519(&self, key_id: String, peer: Vec<u8>) -> Result<Vec<u8>, ProviderError> {
        let peer: [u8; 32] = peer
            .as_slice()
            .try_into()
            .map_err(|_| ProviderError::Failed {
                reason: "peer is 32 bytes".into(),
            })?;
        KeyProvider::x25519(self, &KeyId(key_id), &peer)
            .map(|s| s.to_vec())
            .map_err(|e| ProviderError::Failed {
                reason: e.to_string(),
            })
    }

    fn hpke_open(
        &self,
        key_id: String,
        enc: Vec<u8>,
        ct: Vec<u8>,
        info: Vec<u8>,
        aad: Vec<u8>,
    ) -> Result<Vec<u8>, ProviderError> {
        KeyProvider::hpke_open(self, &KeyId(key_id), &enc, &ct, &info, &aad)
            .map(|p| p.to_vec())
            .map_err(|e| ProviderError::Failed {
                reason: e.to_string(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry_input(action: &str) -> SigningInput {
        let body = format!(r#"{{"action":"{action}","type":"atem-membership-entry"}}"#);
        SigningInput::new(SignLabel::MembershipEntry, body.as_bytes())
    }

    /// R9.6 rules 3–4: only the channel signature may reuse a confirmation;
    /// every entry, the kit and grants ask afresh and show the body.
    #[test]
    fn every_signing_input_names_its_purpose() {
        let cases = [
            ("genesis", SigningPurpose::Genesis),
            ("add", SigningPurpose::Enroll),
            ("remove", SigningPurpose::Remove),
            ("set_roles", SigningPurpose::Roles),
            ("add_host", SigningPurpose::Host),
            ("remove_host", SigningPurpose::Host),
            ("recovery_add", SigningPurpose::Recovery),
            ("recovery_approve", SigningPurpose::Recovery),
            ("recovery_veto", SigningPurpose::Recovery),
            ("set_recovery_key", SigningPurpose::Kit),
            ("k_backup", SigningPurpose::KeyBackup),
            ("unknown", SigningPurpose::Enroll),
        ];
        for (action, purpose) in cases {
            let request = sign_request(&KeyId::new("k"), &entry_input(action));
            assert_eq!(request.purpose, purpose, "{action}");
            assert!(request.fresh_confirmation, "{action}");
            assert!(request.body_json.unwrap().contains(action));
            assert_eq!(request.label, "atem-membership-entry-v1");
        }
        let channel = sign_request(
            &KeyId::new("k"),
            &SigningInput::new(SignLabel::ChannelClient, &[7u8; 32]),
        );
        assert_eq!(channel.purpose, SigningPurpose::Channel);
        assert!(!channel.fresh_confirmation);
        assert_eq!(channel.body_json, None);
        for (label, purpose) in [
            (SignLabel::RecoveryCosign, SigningPurpose::Kit),
            (SignLabel::BrowserGrant, SigningPurpose::BrowserGrant),
            (SignLabel::PushHint, SigningPurpose::HostSigning),
            (SignLabel::Seen, SigningPurpose::HostSigning),
            (SignLabel::ChannelHost, SigningPurpose::HostSigning),
        ] {
            let request = sign_request(&KeyId::new("k"), &SigningInput::new(label, b"{}"));
            assert_eq!(request.purpose, purpose, "{label:?}");
            assert_eq!(
                request.fresh_confirmation,
                purpose != SigningPurpose::HostSigning
            );
        }
    }

    /// The software store signs only a well-formed signing input, so a
    /// caller can't make it sign bytes outside a domain.
    #[cfg(all(feature = "software-keys", feature = "uniffi"))]
    #[test]
    fn the_software_store_signs_only_signing_inputs() {
        let store = SoftwareKeyStore::new();
        store.insert_ed25519("k".into(), vec![7u8; 32]).unwrap();
        let good = sign_request(&KeyId::new("k"), &entry_input("remove"));
        assert_eq!(
            AppKeyProvider::sign(&*store, good.clone()).unwrap().len(),
            64
        );
        let mut raw = good.clone();
        raw.input = b"just some bytes".to_vec();
        assert!(AppKeyProvider::sign(&*store, raw).is_err());
        let mut unlabelled = good;
        unlabelled.input = atem_client::encoding::enc(&[b"not-a-label", b"{}"]);
        assert!(AppKeyProvider::sign(&*store, unlabelled).is_err());
    }
}
