//! The WASM surface (wasm-bindgen; feature `wasm`): the same objects and
//! functions as the UniFFI surface, for browsers and Node bots.
//!
//! - Times are JS numbers (milliseconds; all r9 times are below 2^53).
//! - Bytes are `Uint8Array`; records come back as plain objects (camelCase
//!   fields; enums with data as `{type, …}`, unit enums as strings).
//! - Errors are thrown as `Error` objects with `kind` (the `AtemError`
//!   variant), `code` (stable) and the variant's other fields.
//! - A browser signs with its non-extractable WebCrypto P-256 key through
//!   the deferred handshake: `onAcceptDeferred` returns the request,
//!   `crypto.subtle.sign({name:"ECDSA", hash:"SHA-256"}, key, input)` makes
//!   the 64-byte `r‖s`, `finishWithSignature` takes it.
//! - Bots (feature `software-keys`) hold their service key in a
//!   `SoftwareKeyStore` loaded from their own secret store.
//!
//! What browsers never do (R9.6: only native members sign entries and
//! receive push hints) is left out unless `software-keys` gives a bot or a
//! test a key store to do it with.
use std::sync::Arc;

use serde::Deserialize;
use wasm_bindgen::prelude::*;

use crate::error::AtemError;
use crate::types::{
    ApprovalChoice, ClientIdentity, ControlFeedPos, ControlRecordBody, DeviceKind, HostClock,
    KeyAlg, PrincipalKind, PublicKeyData, PushRecipient, PushStage, PushVerifier, SignLabelKind,
};

type JsResult<T> = Result<T, JsValue>;

fn js_error(e: AtemError) -> JsValue {
    let error = js_sys::Error::new(&e.to_string());
    let set = |k: &str, v: JsValue| {
        let _ = js_sys::Reflect::set(&error, &JsValue::from_str(k), &v);
    };
    let kind = match &e {
        AtemError::Invalid { .. } => "invalid",
        AtemError::Membership { .. } => "membership",
        AtemError::Channel { .. } => "channel",
        AtemError::Refused { .. } => "refused",
        AtemError::BadWelcome { .. } => "bad_welcome",
        AtemError::Request { .. } => "request",
        AtemError::Restore { .. } => "restore",
        AtemError::Publish { .. } => "publish",
        AtemError::Push { .. } => "push",
        AtemError::Stored { .. } => "stored",
        AtemError::State { .. } => "state",
    };
    set("kind", kind.into());
    set("code", e.code().into());
    match &e {
        AtemError::Membership {
            detail,
            index: Some(i),
            ..
        } => {
            set("detail", detail.as_str().into());
            set("index", (*i as f64).into());
        }
        AtemError::Refused {
            detail,
            error_json,
            next,
            ..
        } => {
            if let Some(d) = detail {
                set("detail", d.as_str().into());
            }
            set("errorJson", error_json.as_str().into());
            set("next", to_js(next).unwrap_or(JsValue::NULL));
        }
        AtemError::BadWelcome { check } => set("detail", check.as_str().into()),
        AtemError::Invalid { detail, .. }
        | AtemError::Membership { detail, .. }
        | AtemError::Channel { detail, .. }
        | AtemError::Request { detail }
        | AtemError::Restore { detail, .. }
        | AtemError::Publish { detail, .. }
        | AtemError::Push { detail, .. }
        | AtemError::Stored { detail, .. }
        | AtemError::State { detail } => set("detail", detail.as_str().into()),
    }
    error.into()
}

fn to_js<T: serde::Serialize>(value: &T) -> JsResult<JsValue> {
    value
        .serialize(
            &serde_wasm_bindgen::Serializer::json_compatible().serialize_bytes_as_arrays(false),
        )
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

fn ok<T: serde::Serialize>(r: Result<T, AtemError>) -> JsResult<JsValue> {
    to_js(&r.map_err(js_error)?)
}

fn err<T>(r: Result<T, AtemError>) -> JsResult<T> {
    r.map_err(js_error)
}

fn bad(what: &str) -> JsValue {
    js_error(AtemError::malformed(what))
}

fn ms(v: f64) -> JsResult<u64> {
    if v.is_finite() && v >= 0.0 && v.fract() == 0.0 && v <= 9_007_199_254_740_991.0 {
        Ok(v as u64)
    } else {
        Err(bad("a time is a non-negative safe integer (ms)"))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsClock {
    wall_ms: f64,
    mono_ms: f64,
    boot_id: String,
}

fn clock(v: JsValue) -> JsResult<HostClock> {
    let c: JsClock =
        serde_wasm_bindgen::from_value(v).map_err(|_| bad("clock {wallMs, monoMs, bootId}"))?;
    Ok(HostClock {
        wall_ms: ms(c.wall_ms)?,
        mono_ms: ms(c.mono_ms)?,
        boot_id: c.boot_id,
    })
}

fn alg(name: &str) -> JsResult<KeyAlg> {
    match name {
        "p256" => Ok(KeyAlg::P256),
        "ed25519" => Ok(KeyAlg::Ed25519),
        "x25519" => Ok(KeyAlg::X25519),
        _ => Err(bad("alg is p256, ed25519 or x25519")),
    }
}

fn key(alg_name: &str, raw: Vec<u8>) -> JsResult<PublicKeyData> {
    Ok(PublicKeyData {
        alg: alg(alg_name)?,
        raw,
    })
}

fn label(name: &str) -> JsResult<SignLabelKind> {
    Ok(match name {
        "membership_entry" => SignLabelKind::MembershipEntry,
        "recovery_cosign" => SignLabelKind::RecoveryCosign,
        "browser_grant" => SignLabelKind::BrowserGrant,
        "push_hint" => SignLabelKind::PushHint,
        "seen" => SignLabelKind::Seen,
        "channel_host" => SignLabelKind::ChannelHost,
        "channel_client" => SignLabelKind::ChannelClient,
        "host_work_control" => SignLabelKind::HostWorkControl,
        _ => return Err(bad("unknown label")),
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsRecipient {
    device_class: String,
    connected: bool,
    immediate_mobile: bool,
}

fn recipient(v: JsValue) -> JsResult<PushRecipient> {
    let r: JsRecipient = serde_wasm_bindgen::from_value(v)
        .map_err(|_| bad("recipient {deviceClass, connected, immediateMobile}"))?;
    Ok(PushRecipient {
        device_class: match r.device_class.as_str() {
            "desktop" => DeviceKind::Desktop,
            "mobile" => DeviceKind::Mobile,
            _ => return Err(bad("deviceClass is desktop or mobile")),
        },
        connected: r.connected,
        immediate_mobile: r.immediate_mobile,
    })
}

fn stage(name: &str) -> JsResult<PushStage> {
    Ok(match name {
        "in_app" => PushStage::InApp,
        "desktop_os" => PushStage::DesktopOs,
        "mobile_immediate" => PushStage::MobileImmediate,
        "mobile" => PushStage::Mobile,
        _ => return Err(bad("unknown stage")),
    })
}

fn approval_ref(v: JsValue) -> JsResult<crate::types::ApprovalRef> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct R {
        account_id: String,
        genesis_hash: String,
        host_id: String,
        host_trust_gen: f64,
        session_id: String,
        process_gen: String,
        approval_id: String,
    }
    let r: R = serde_wasm_bindgen::from_value(v).map_err(|_| bad("approval ref"))?;
    Ok(crate::types::ApprovalRef {
        account_id: r.account_id,
        genesis_hash: r.genesis_hash,
        host_id: r.host_id,
        host_trust_gen: ms(r.host_trust_gen)?,
        session_id: r.session_id,
        process_gen: r.process_gen,
        approval_id: r.approval_id,
    })
}

fn head(v: JsValue) -> JsResult<crate::types::LogHead> {
    #[derive(Deserialize)]
    struct H {
        seq: f64,
        hash: String,
    }
    let h: H = serde_wasm_bindgen::from_value(v).map_err(|_| bad("head {seq, hash}"))?;
    Ok(crate::types::LogHead {
        seq: ms(h.seq)?,
        hash: h.hash,
    })
}

// ------------------------------------------------------------ encoding

#[wasm_bindgen(js_name = encodeFields)]
pub fn encode_fields(fields: Vec<js_sys::Uint8Array>) -> Vec<u8> {
    crate::encoding::encode_fields(fields.iter().map(|f| f.to_vec()).collect())
}

#[wasm_bindgen(js_name = hashFields)]
pub fn hash_fields(fields: Vec<js_sys::Uint8Array>) -> String {
    crate::encoding::hash_fields(fields.iter().map(|f| f.to_vec()).collect())
}

#[wasm_bindgen(js_name = canonicalJson)]
pub fn canonical_json(json: String) -> JsResult<String> {
    err(crate::encoding::canonical_json(json))
}

/// `verifyCommit.host_trust_gen` (§R9.2), as a JS number (always a safe
/// integer).
#[wasm_bindgen(js_name = verifyCommitHostTrustGen)]
pub fn verify_commit_host_trust_gen(message_json: String) -> JsResult<f64> {
    err(crate::encoding::verify_commit_host_trust_gen(message_json)).map(|n| n as f64)
}

#[wasm_bindgen(js_name = signingInput)]
pub fn signing_input(label_name: &str, payload: Vec<u8>) -> JsResult<Vec<u8>> {
    Ok(crate::encoding::signing_input(label(label_name)?, payload))
}

#[wasm_bindgen(js_name = verifySignature)]
pub fn verify_signature(
    alg_name: &str,
    raw: Vec<u8>,
    label_name: &str,
    payload: Vec<u8>,
    signature: Vec<u8>,
) -> JsResult<()> {
    err(crate::encoding::verify_signature(
        key(alg_name, raw)?,
        label(label_name)?,
        payload,
        signature,
    ))
}

#[cfg(feature = "test-vectors")]
#[wasm_bindgen(js_name = verifyRawSignature)]
pub fn verify_raw_signature(
    alg_name: &str,
    raw: Vec<u8>,
    message: Vec<u8>,
    signature: Vec<u8>,
) -> JsResult<()> {
    err(crate::encoding::verify_raw_signature(
        key(alg_name, raw)?,
        message,
        signature,
    ))
}

#[wasm_bindgen(js_name = checkPublicKey)]
pub fn check_public_key(alg_name: &str, raw: Vec<u8>) -> JsResult<()> {
    err(crate::encoding::check_public_key(key(alg_name, raw)?))
}

#[wasm_bindgen(js_name = signedObjectInfo)]
pub fn signed_object_info(json: String) -> JsResult<JsValue> {
    ok(crate::encoding::signed_object_info(json))
}

#[wasm_bindgen(js_name = verifySignedObject)]
pub fn verify_signed_object(json: String, alg_name: &str, raw: Vec<u8>) -> JsResult<()> {
    err(crate::encoding::verify_signed_object(
        json,
        key(alg_name, raw)?,
    ))
}

#[wasm_bindgen(js_name = encKid)]
pub fn enc_kid(x25519_raw: Vec<u8>) -> JsResult<String> {
    err(crate::encoding::enc_kid(key("x25519", x25519_raw)?))
}

#[wasm_bindgen(js_name = ed25519PublicToX25519)]
pub fn ed25519_public_to_x25519(raw: Vec<u8>) -> JsResult<Vec<u8>> {
    err(crate::encoding::ed25519_public_to_x25519(key(
        "ed25519", raw,
    )?))
}

// ------------------------------------------------------------ the log

#[wasm_bindgen]
pub struct MembershipLog(Arc<crate::log::MembershipLog>);

#[wasm_bindgen]
impl MembershipLog {
    pub fn verify(
        account_id: String,
        genesis_hash: String,
        entries: Vec<String>,
        now: JsValue,
    ) -> JsResult<MembershipLog> {
        Ok(MembershipLog(err(crate::log::MembershipLog::verify(
            account_id,
            genesis_hash,
            entries,
            clock(now)?,
        ))?))
    }
    /// The log from its durable snapshot, against the app's anchors.
    #[wasm_bindgen(js_name = fromStored)]
    pub fn from_stored(
        account_id: String,
        genesis_hash: String,
        stored_json: String,
        now: JsValue,
    ) -> JsResult<MembershipLog> {
        Ok(MembershipLog(err(crate::log::MembershipLog::from_stored(
            account_id,
            genesis_hash,
            stored_json,
            clock(now)?,
        ))?))
    }
    #[wasm_bindgen(js_name = storedJson)]
    pub fn stored_json(&self) -> JsResult<String> {
        err(self.0.stored_json())
    }
    pub fn snapshot(&self) -> MembershipLog {
        MembershipLog(self.0.snapshot())
    }
    #[wasm_bindgen(js_name = accountId)]
    pub fn account_id(&self) -> String {
        self.0.account_id()
    }
    #[wasm_bindgen(js_name = genesisHash)]
    pub fn genesis_hash(&self) -> String {
        self.0.genesis_hash()
    }
    pub fn head(&self) -> JsResult<JsValue> {
        to_js(&self.0.head())
    }
    pub fn entries(&self) -> Vec<String> {
        self.0.entries()
    }
    #[wasm_bindgen(js_name = entriesAfter)]
    pub fn entries_after(&self, seq: f64) -> JsResult<Vec<String>> {
        Ok(self.0.entries_after(ms(seq)?))
    }
    pub fn members(&self) -> JsResult<JsValue> {
        to_js(&self.0.members())
    }
    pub fn member(&self, device_id: String) -> JsResult<JsValue> {
        to_js(&self.0.member(device_id))
    }
    pub fn host(&self, host_id: String) -> JsResult<JsValue> {
        to_js(&self.0.host(host_id))
    }
    #[wasm_bindgen(js_name = recoveryKey)]
    pub fn recovery_key(&self) -> JsResult<JsValue> {
        to_js(&self.0.recovery_key())
    }
    #[wasm_bindgen(js_name = kBackup)]
    pub fn k_backup(&self) -> JsResult<JsValue> {
        to_js(&self.0.k_backup())
    }
    pub fn frozen(&self) -> JsResult<JsValue> {
        to_js(&self.0.frozen())
    }
    #[wasm_bindgen(js_name = pendingRecovery)]
    pub fn pending_recovery(&self, now: JsValue) -> JsResult<JsValue> {
        ok(self.0.pending_recovery(clock(now)?))
    }
    pub fn relation(&self, h: JsValue) -> JsResult<JsValue> {
        ok(self.0.relation(head(h)?))
    }
    pub fn evaluate(&self, entries: Vec<String>, now: JsValue) -> JsResult<JsValue> {
        ok(self.0.evaluate(entries, clock(now)?))
    }
    pub fn extend(&self, entries: Vec<String>, now: JsValue) -> JsResult<JsValue> {
        ok(self.0.extend(entries, clock(now)?))
    }
    pub fn advance(&self, now: JsValue) -> JsResult<JsValue> {
        ok(self.0.advance(clock(now)?))
    }
    /// Host role: the membership side of admitting `deviceId` after its
    /// carriage (commits the evaluation).
    #[cfg(feature = "host")]
    #[wasm_bindgen(js_name = admitCarrier)]
    pub fn admit_carrier(
        &self,
        device_id: String,
        entries: Vec<String>,
        more: bool,
        now: JsValue,
    ) -> JsResult<JsValue> {
        ok(self.0.admit_carrier(device_id, entries, more, clock(now)?))
    }
    #[wasm_bindgen(js_name = draftEntry)]
    pub fn draft_entry(
        &self,
        signer: String,
        signed_at: f64,
        action_json: String,
    ) -> JsResult<String> {
        err(self.0.draft_entry(signer, ms(signed_at)?, action_json))
    }
    /// How full the log is: `{entries, maxEntries, members, maxMembers,
    /// hosts, maxHosts, level, entriesLevel, membersLevel, hostsLevel}`
    /// (levels `ok`, `nearly_full`, `full`).
    pub fn capacity(&self) -> JsResult<JsValue> {
        to_js(&self.0.capacity())
    }
    /// `null` to go ahead, else `{type: "log_full" | "members_full" |
    /// "hosts_full" | "service_change_too_soon" | "already_revoked" |
    /// "not_revoked" | "enc_key_reused", lastSignedAt?, retryAt?}`
    /// (advisory, for signers: `service_change_too_soon` carries
    /// `lastSignedAt` and `retryAt`; `already_revoked` is a
    /// `host_sender_revoke` of a host already revoked, `not_revoked` a
    /// `host_sender_readmit` of one that isn't revoked, a host never added
    /// included; `enc_key_reused` a `host_enc_key` of a key already set for
    /// that host since its newest `add_host`).
    #[wasm_bindgen(js_name = checkChange)]
    pub fn check_change(&self, action_json: String, now_ms: f64) -> JsResult<JsValue> {
        ok(self.0.check_change(action_json, ms(now_ms)?))
    }
    #[wasm_bindgen(js_name = checkMember)]
    pub fn check_member(&self, member_json: String) -> JsResult<String> {
        err(self.0.check_member(member_json))
    }
    /// `{scope: {hosts, projects?, sessions?, ops}, expiresAt}` of the
    /// active service member, or `null` (status only: an expired service is
    /// still returned; compare `expiresAt` with the time yourself).
    #[wasm_bindgen(js_name = serviceGrant)]
    pub fn service_grant(&self, device_id: String) -> JsResult<JsValue> {
        to_js(&self.0.service_grant(device_id))
    }
    /// `r9_svc` of the active service member, or `null`.
    #[wasm_bindgen(js_name = serviceKeyFingerprint)]
    pub fn service_key_fingerprint(&self, device_id: String) -> Option<String> {
        self.0.service_key_fingerprint(device_id)
    }
    /// `{type: "authorized", generation}` or `{type: "revoked", seq}` (a
    /// host's sending authorization, delegated host-work II.3.1), or `null`
    /// for a host no `add_host` named.
    #[wasm_bindgen(js_name = hostSenderState)]
    pub fn host_sender_state(&self, host_id: String) -> JsResult<JsValue> {
        to_js(&self.0.host_sender_state(host_id))
    }
    /// The `seq` of the host's first `add_host` after its last
    /// `remove_host`, or `null`.
    #[wasm_bindgen(js_name = hostMembershipEpoch)]
    pub fn host_membership_epoch(&self, host_id: String) -> JsResult<JsValue> {
        to_js(&self.0.host_membership_epoch(host_id))
    }
    /// The projects in effect: `[{name, hosts, members, ops}]` (`hosts` as
    /// signed, `members` those whose membership is in effect).
    pub fn projects(&self) -> JsResult<JsValue> {
        to_js(&self.0.projects())
    }
    /// The names of the projects the host's membership of is in effect.
    #[wasm_bindgen(js_name = hostProjects)]
    pub fn host_projects(&self, host_id: String) -> Vec<String> {
        self.0.host_projects(host_id)
    }
    /// The ops the two hosts may send each other (the union over the
    /// projects both are members of; empty for one host with itself).
    #[wasm_bindgen(js_name = projectOpsBetween)]
    pub fn project_ops_between(&self, a: String, b: String) -> Vec<String> {
        self.0.project_ops_between(a, b)
    }
    /// `{current, previous}` of a host's encryption keys, each `{encKid,
    /// key, seq, hostTrustGen}` (`previous` adds `retired` and
    /// `replacedAtSeq`: `{key, retired, replacedAtSeq}`), or `null`.
    #[wasm_bindgen(js_name = hostEncKey)]
    pub fn host_enc_key(&self, host_id: String) -> JsResult<JsValue> {
        to_js(&self.0.host_enc_key(host_id))
    }
    /// A renewal's action JSON (current scope, later `expiresAt`).
    #[wasm_bindgen(js_name = serviceRenewalAction)]
    pub fn service_renewal_action(
        &self,
        device_id: String,
        expires_at: f64,
        signed_at: f64,
    ) -> JsResult<String> {
        err(self
            .0
            .service_renewal_action(device_id, ms(expires_at)?, ms(signed_at)?))
    }
    /// A narrowing's action JSON (`expiresAt` `null`: unchanged).
    #[wasm_bindgen(js_name = serviceNarrowingAction)]
    pub fn service_narrowing_action(
        &self,
        device_id: String,
        scope: JsValue,
        expires_at: Option<f64>,
        signed_at: f64,
    ) -> JsResult<String> {
        err(self.0.service_narrowing_action(
            device_id,
            service_scope(scope)?,
            expires_at.map(ms).transpose()?,
            ms(signed_at)?,
        ))
    }
}

// ------------------------------------------- service builders, projects

/// `{hosts, projects?, sessions?, ops}` (any order; `view` is added).
fn service_scope(v: JsValue) -> JsResult<crate::types::ServiceScopeInfo> {
    #[derive(Deserialize)]
    struct S {
        hosts: Vec<String>,
        #[serde(default)]
        projects: Option<Vec<String>>,
        #[serde(default)]
        sessions: Option<Vec<String>>,
        ops: Vec<String>,
    }
    let s: S = serde_wasm_bindgen::from_value(v)
        .map_err(|_| bad("scope {hosts, projects?, sessions?, ops}"))?;
    Ok(crate::types::ServiceScopeInfo {
        hosts: s.hosts,
        projects: s.projects,
        sessions: s.sessions,
        ops: s.ops,
    })
}

/// The action JSON of a service `add` (for `draftEntry`/`checkChange`).
#[wasm_bindgen(js_name = serviceAddAction)]
pub fn service_add_action(
    device_id: String,
    auth_alg: &str,
    auth_raw: Vec<u8>,
    scope: JsValue,
    expires_at: f64,
    signed_at: f64,
) -> JsResult<String> {
    err(crate::service::service_add_action(
        device_id,
        key(auth_alg, auth_raw)?,
        service_scope(scope)?,
        ms(expires_at)?,
        ms(signed_at)?,
    ))
}

/// The action JSON of a service `set_roles`.
#[wasm_bindgen(js_name = serviceSetRolesAction)]
pub fn service_set_roles_action(
    device_id: String,
    scope: JsValue,
    expires_at: f64,
    signed_at: f64,
) -> JsResult<String> {
    err(crate::service::service_set_roles_action(
        device_id,
        service_scope(scope)?,
        ms(expires_at)?,
        ms(signed_at)?,
    ))
}

/// The action JSON of a `project_set` (ops: `launch`, `message`, `notify`,
/// `prompt`; any order).
#[wasm_bindgen(js_name = projectSetAction)]
pub fn project_set_action(
    name: String,
    hosts: Vec<String>,
    ops: Vec<String>,
    signed_at: f64,
) -> JsResult<String> {
    err(crate::host_actions::project_set_action(
        name,
        hosts,
        ops,
        ms(signed_at)?,
    ))
}

/// The action JSON of a `project_remove`.
#[wasm_bindgen(js_name = projectRemoveAction)]
pub fn project_remove_action(name: String, signed_at: f64) -> JsResult<String> {
    err(crate::host_actions::project_remove_action(
        name,
        ms(signed_at)?,
    ))
}

/// The action JSON of a `host_sender_revoke`.
#[wasm_bindgen(js_name = hostSenderRevokeAction)]
pub fn host_sender_revoke_action(
    host_id: String,
    interrupt_running: bool,
    signed_at: f64,
) -> JsResult<String> {
    err(crate::host_actions::host_sender_revoke_action(
        host_id,
        interrupt_running,
        ms(signed_at)?,
    ))
}

/// The action JSON of a `host_sender_readmit`.
#[wasm_bindgen(js_name = hostSenderReadmitAction)]
pub fn host_sender_readmit_action(host_id: String, signed_at: f64) -> JsResult<String> {
    err(crate::host_actions::host_sender_readmit_action(
        host_id,
        ms(signed_at)?,
    ))
}

/// The action JSON of a `host_enc_key` (`encAlg` `x25519`; `encSigB64u` the
/// host's own signature over the key, 64 bytes of base64url).
#[wasm_bindgen(js_name = hostEncKeyAction)]
pub fn host_enc_key_action(
    host_id: String,
    host_trust_gen: f64,
    enc_alg: &str,
    enc_raw: Vec<u8>,
    enc_sig_b64u: String,
    retire_previous: bool,
    signed_at: f64,
) -> JsResult<String> {
    err(crate::host_actions::host_enc_key_action(
        host_id,
        ms(host_trust_gen)?,
        key(enc_alg, enc_raw)?,
        enc_sig_b64u,
        retire_previous,
        ms(signed_at)?,
    ))
}

/// Whether the host's `enc_sig` over its `enc_key` verifies: `false` for
/// anything else, never a throw, as the UniFFI `verify_host_enc_sig`
/// (malformed values included: an unknown `hostAlg` or `encAlg`, and a
/// `hostTrustGen` that isn't a non-negative safe integer, which UniFFI's
/// `u64` can't carry).
#[wasm_bindgen(js_name = verifyHostEncSig)]
#[allow(clippy::too_many_arguments)]
pub fn verify_host_enc_sig(
    host_alg: &str,
    host_raw: Vec<u8>,
    account_id: String,
    genesis_hash: String,
    host_id: String,
    host_trust_gen: f64,
    enc_alg: &str,
    enc_raw: Vec<u8>,
    enc_sig_b64u: String,
) -> bool {
    let (Ok(host_key), Ok(host_trust_gen), Ok(enc_key)) = (
        key(host_alg, host_raw),
        ms(host_trust_gen),
        key(enc_alg, enc_raw),
    ) else {
        return false;
    };
    crate::host_actions::verify_host_enc_sig(
        host_key,
        account_id,
        genesis_hash,
        host_id,
        host_trust_gen,
        enc_key,
        enc_sig_b64u,
    )
}

/// `r9_svc` of a service `auth_key` (`alg` `p256` or `ed25519`, raw bytes).
#[wasm_bindgen(js_name = serviceKeyFingerprint)]
pub fn service_key_fingerprint(auth_alg: &str, auth_raw: Vec<u8>) -> JsResult<String> {
    err(crate::service::service_key_fingerprint(key(
        auth_alg, auth_raw,
    )?))
}

#[wasm_bindgen(js_name = projectKeyOfRemote)]
pub fn project_key_of_remote(url: String) -> Option<String> {
    crate::service::project_key_of_remote(url)
}

#[wasm_bindgen(js_name = localProjectKey)]
pub fn local_project_key(folder_name: String) -> String {
    crate::service::local_project_key(folder_name)
}

/// The bytes to HMAC (WebCrypto: `crypto.subtle.sign("HMAC", key, …)`).
#[wasm_bindgen(js_name = projectHashInput)]
pub fn project_hash_input(project_key: String) -> Vec<u8> {
    crate::service::project_hash_input(project_key)
}

#[wasm_bindgen(js_name = projectHashFromMac)]
pub fn project_hash_from_mac(kid: String, mac: Vec<u8>) -> JsResult<String> {
    err(crate::service::project_hash_from_mac(kid, mac))
}

#[wasm_bindgen(js_name = isProjectHash)]
pub fn is_project_hash(text: String) -> bool {
    crate::service::is_project_hash(text)
}

/// The software form over `{kid, k}` (bots and tests: `K` in JS memory).
#[cfg(feature = "software-keys")]
#[wasm_bindgen(js_name = projectHash)]
pub fn project_hash(account_key: JsValue, project_key: String) -> JsResult<String> {
    #[derive(Deserialize)]
    struct K {
        kid: String,
        #[serde(with = "serde_bytes")]
        k: Vec<u8>,
    }
    let k: K = serde_wasm_bindgen::from_value(account_key).map_err(|_| bad("key {kid, k}"))?;
    err(crate::service::project_hash(
        crate::types::AccountKey { kid: k.kid, k: k.k },
        project_key,
    ))
}

// --------------------------------------- control records (Station builders)

/// A control record's body as JS passes it: `ControlRecordBody`'s fields
/// in camelCase, absent ones omitted, `undefined` or `null`; no other field.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct JsControlBody {
    account_id: String,
    genesis_hash: String,
    #[serde(default)]
    origin: Option<String>,
    #[serde(default)]
    feed_id: Option<String>,
    principal: String,
    #[serde(default)]
    principal_key: Option<String>,
    signer: String,
    action: String,
    #[serde(default)]
    interrupt_running: Option<bool>,
    #[serde(default)]
    revoke_seq: Option<f64>,
    record_id: String,
    issued_at: f64,
    #[serde(default)]
    integration_id: Option<String>,
    by: String,
}

/// `v` is a plain object with no key outside `fields` (serde-wasm-bindgen
/// reads only the fields a struct names, so `deny_unknown_fields` alone
/// would let a misspelled one through unread).
fn only_fields(v: &JsValue, fields: &[&str], what: &str) -> JsResult<()> {
    use wasm_bindgen::JsCast;
    let object = v
        .dyn_ref::<js_sys::Object>()
        .ok_or_else(|| bad(&format!("{what} is an object")))?;
    for key in js_sys::Object::keys(object).iter() {
        let key = key.as_string().unwrap_or_default();
        if !fields.contains(&key.as_str()) {
            return Err(bad(&format!("{what}: unknown field {key}")));
        }
    }
    Ok(())
}

fn control_body(v: JsValue) -> JsResult<ControlRecordBody> {
    only_fields(
        &v,
        &[
            "accountId",
            "genesisHash",
            "origin",
            "feedId",
            "principal",
            "principalKey",
            "signer",
            "action",
            "interruptRunning",
            "revokeSeq",
            "recordId",
            "issuedAt",
            "integrationId",
            "by",
        ],
        "a control record body",
    )?;
    let b: JsControlBody = serde_wasm_bindgen::from_value(v).map_err(|e| {
        bad(&format!(
            "a control record body {{accountId, genesisHash, origin?, feedId?, principal, principalKey?, signer, action, interruptRunning?, revokeSeq?, recordId, issuedAt, integrationId?, by}}: {e}"
        ))
    })?;
    Ok(ControlRecordBody {
        account_id: b.account_id,
        genesis_hash: b.genesis_hash,
        origin: b.origin,
        feed_id: b.feed_id,
        principal: b.principal,
        principal_key: b.principal_key,
        signer: b.signer,
        action: b.action,
        interrupt_running: b.interrupt_running,
        revoke_seq: b.revoke_seq.map(ms).transpose()?,
        record_id: b.record_id,
        issued_at: ms(b.issued_at)?,
        integration_id: b.integration_id,
        by: b.by,
    })
}

/// A record's body, field by field (`parse_control_record`).
#[wasm_bindgen(js_name = parseControlRecord)]
pub fn parse_control_record(record_json: String) -> JsResult<JsValue> {
    ok(crate::control::parse_control_record(record_json))
}

/// The verdict on a record against `log` (`verify_control_record`):
/// `{type: "valid", signer, keySeq, head}`, `{type: "pending", reason}` or
/// `{type: "refused", reason}`.
#[wasm_bindgen(js_name = verifyControlRecord)]
pub fn verify_control_record(log: &MembershipLog, record_json: String) -> JsResult<JsValue> {
    ok(crate::control::verify_control_record(
        log.0.clone(),
        record_json,
    ))
}

/// The bytes a key signs for `body` (`control_record_signing_input`): a
/// Station's key in WebCrypto or a KMS signs them, then
/// `controlRecordWithSignature` makes the record.
#[wasm_bindgen(js_name = controlRecordSigningInput)]
pub fn control_record_signing_input(body: JsValue) -> JsResult<Vec<u8>> {
    err(crate::control::control_record_signing_input(control_body(
        body,
    )?))
}

/// The record of `body` with `signature` by the key `signerAlg`/`signerRaw`
/// (`control_record_with_signature`; verified before it is returned).
#[wasm_bindgen(js_name = controlRecordWithSignature)]
pub fn control_record_with_signature(
    body: JsValue,
    signer_alg: &str,
    signer_raw: Vec<u8>,
    signature: Vec<u8>,
) -> JsResult<String> {
    err(crate::control::control_record_with_signature(
        control_body(body)?,
        key(signer_alg, signer_raw)?,
        signature,
    ))
}

/// A record signed with a key of a software store (bots and tests; a
/// Station keeps its keys in its own key store and uses
/// `controlRecordSigningInput`).
#[cfg(feature = "software-keys")]
#[wasm_bindgen(js_name = buildControlRecord)]
pub fn build_control_record(
    store: &SoftwareKeyStore,
    key_id: String,
    body: JsValue,
) -> JsResult<String> {
    err(crate::control::build_control_record_with(
        &*store.0,
        &key_id,
        &control_body(body)?,
    ))
}

/// The reference control state of one device list (`ControlStateHandle`).
#[wasm_bindgen]
pub struct ControlStateHandle(Arc<crate::control::ControlStateHandle>);

#[wasm_bindgen]
impl ControlStateHandle {
    #[wasm_bindgen(constructor)]
    pub fn new(log: &MembershipLog) -> ControlStateHandle {
        ControlStateHandle(crate::control::ControlStateHandle::new(log.0.clone()))
    }
    /// A state `toJson()` wrote, for `log`'s device list.
    #[wasm_bindgen(js_name = fromJson)]
    pub fn from_json(log: &MembershipLog, state_json: String) -> JsResult<ControlStateHandle> {
        Ok(ControlStateHandle(err(
            crate::control::ControlStateHandle::from_json(log.0.clone(), state_json),
        )?))
    }
    /// The durable state (canonical JSON): store the next state's after
    /// every `apply`.
    #[wasm_bindgen(js_name = toJson)]
    pub fn to_json(&self) -> String {
        self.0.to_json()
    }
    /// Applies a record to this state (`pos`: `{origin, feedId, feedSeq}`,
    /// or `null`/`undefined` over a channel) and returns a
    /// `ControlTransition`: `applied` (`{result, effects: [{effect,
    /// result}], actions: [{type, principal, …}], evidence}`) and `next`,
    /// the state after it. This handle doesn't change: use `next` once
    /// your transaction storing `next.toJson()` committed.
    pub fn apply(
        &self,
        record_json: String,
        log: &MembershipLog,
        pos: JsValue,
        host_applied_seq: f64,
    ) -> JsResult<ControlTransition> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct P {
            origin: String,
            feed_id: String,
            feed_seq: f64,
        }
        let pos = if pos.is_null() || pos.is_undefined() {
            None
        } else {
            only_fields(&pos, &["origin", "feedId", "feedSeq"], "pos")?;
            let p: P = serde_wasm_bindgen::from_value(pos)
                .map_err(|_| bad("pos {origin, feedId, feedSeq}, or null"))?;
            Some(ControlFeedPos {
                origin: p.origin,
                feed_id: p.feed_id,
                feed_seq: ms(p.feed_seq)?,
            })
        };
        let transition = err(self
            .0
            .apply(record_json, log.0.clone(), pos, ms(host_applied_seq)?))?;
        Ok(ControlTransition {
            applied: to_js(&transition.applied)?,
            next: transition.next,
        })
    }
}

/// What `ControlStateHandle.apply` gives (`crate::control::ControlTransition`).
#[wasm_bindgen]
pub struct ControlTransition {
    applied: JsValue,
    next: Arc<crate::control::ControlStateHandle>,
}

#[wasm_bindgen]
impl ControlTransition {
    /// What the record did: `{result, effects, actions, evidence}`.
    #[wasm_bindgen(getter)]
    pub fn applied(&self) -> JsValue {
        self.applied.clone()
    }
    /// The state after the record: use it once the transaction storing
    /// `next.toJson()` committed (until then the handle applied on is the
    /// current state).
    #[wasm_bindgen(getter)]
    pub fn next(&self) -> ControlStateHandle {
        ControlStateHandle(self.next.clone())
    }
}

// ----------------------- Station calls and acknowledgments (Station builders)

/// The objects of the array `v`, each with no key outside `fields`, read
/// as `T`.
fn items<T: serde::de::DeserializeOwned>(
    v: &JsValue,
    fields: &[&str],
    what: &str,
) -> JsResult<Vec<T>> {
    use wasm_bindgen::JsCast;
    let array = v
        .dyn_ref::<js_sys::Array>()
        .ok_or_else(|| bad(&format!("{what} is an array")))?;
    array
        .iter()
        .map(|item| {
            only_fields(&item, fields, what)?;
            serde_wasm_bindgen::from_value(item).map_err(|e| bad(&format!("{what}: {e}")))
        })
        .collect()
}

/// `[{effect, result}]`, by their wire names.
fn effect_results(v: &JsValue) -> JsResult<Vec<crate::types::ControlEffectResult>> {
    #[derive(Deserialize)]
    struct E {
        effect: String,
        result: String,
    }
    items::<E>(v, &["effect", "result"], "effects [{effect, result}]")?
        .into_iter()
        .map(|e| {
            Ok(crate::types::ControlEffectResult {
                effect: crate::station::effect_kind_of(&e.effect)
                    .ok_or_else(|| bad("effect: revocation, interrupt, hold, release or cover"))?,
                result: crate::station::result_kind_of(&e.result)
                    .ok_or_else(|| bad("result: applied, duplicate, pending or refused"))?,
            })
        })
        .collect()
}

fn strict_head(v: JsValue) -> JsResult<crate::types::LogHead> {
    only_fields(&v, &["seq", "hash"], "head {seq, hash}")?;
    head(v)
}

/// A host's call to its Station, read strictly (`relay_decode_to_station`):
/// `{type: "control_sync", origin, feedId?, after}`, `{type:
/// "control_ack", ack: {…}}` or `{type: "membership_fetch", after}`.
#[wasm_bindgen(js_name = relayDecodeToStation)]
pub fn relay_decode_to_station(message: String) -> JsResult<JsValue> {
    ok(crate::station::relay_decode_to_station(message))
}

/// A Station's message to a host, read strictly (`relay_decode_to_host`).
#[wasm_bindgen(js_name = relayDecodeToHost)]
pub fn relay_decode_to_host(message: String) -> JsResult<JsValue> {
    ok(crate::station::relay_decode_to_host(message))
}

/// `control_sync{origin, feed_id?, after}` (`relay_control_sync`).
#[wasm_bindgen(js_name = relayControlSync)]
pub fn relay_control_sync(origin: String, feed_id: Option<String>, after: f64) -> JsResult<String> {
    err(crate::station::relay_control_sync(
        origin,
        feed_id,
        ms(after)?,
    ))
}

/// `control_sync_result` (`relay_control_sync_result`): `records` is
/// `[{feedSeq, recordJson}]`, each record one the control parser accepts.
#[wasm_bindgen(js_name = relayControlSyncResult)]
pub fn relay_control_sync_result(
    origin: String,
    feed_id: String,
    head: f64,
    station_time: f64,
    records: JsValue,
) -> JsResult<String> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct R {
        feed_seq: f64,
        record_json: String,
    }
    let records = items::<R>(&records, &["feedSeq", "recordJson"], "records")?
        .into_iter()
        .map(|r| {
            Ok(crate::types::RelayFeedRecord {
                feed_seq: ms(r.feed_seq)?,
                record_json: r.record_json,
            })
        })
        .collect::<JsResult<Vec<_>>>()?;
    err(crate::station::relay_control_sync_result(
        origin,
        feed_id,
        ms(head)?,
        ms(station_time)?,
        records,
    ))
}

/// `heads{feeds, membership}` (`relay_heads`): `feeds` is `[{origin,
/// feedId, head, stationTime}]`, `membership` `{seq, hash}`.
#[wasm_bindgen(js_name = relayHeads)]
pub fn relay_heads(feeds: JsValue, membership: JsValue) -> JsResult<String> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct F {
        origin: String,
        feed_id: String,
        head: f64,
        station_time: f64,
    }
    let feeds = items::<F>(
        &feeds,
        &["origin", "feedId", "head", "stationTime"],
        "feeds",
    )?
    .into_iter()
    .map(|f| {
        Ok(crate::types::RelayFeedHead {
            origin: f.origin,
            feed_id: f.feed_id,
            head: ms(f.head)?,
            station_time: ms(f.station_time)?,
        })
    })
    .collect::<JsResult<Vec<_>>>()?;
    err(crate::station::relay_heads(feeds, strict_head(membership)?))
}

/// `control_ack` (`relay_control_ack`): `{accountId, genesisHash, hostId,
/// hostTrustGen, origin, feedId, cursor, results}`, each result `{type:
/// "record", recordId, effects}` or `{type: "entry", seq, entryHash,
/// appliedSeq, effects}`.
#[wasm_bindgen(js_name = relayControlAck)]
pub fn relay_control_ack(ack: JsValue) -> JsResult<String> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct A {
        account_id: String,
        genesis_hash: String,
        host_id: String,
        host_trust_gen: f64,
        origin: String,
        feed_id: String,
        cursor: f64,
        #[serde(with = "serde_wasm_bindgen::preserve")]
        results: JsValue,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct R {
        #[serde(rename = "type")]
        kind: String,
        #[serde(default)]
        record_id: Option<String>,
        #[serde(default)]
        seq: Option<f64>,
        #[serde(default)]
        entry_hash: Option<String>,
        #[serde(default)]
        applied_seq: Option<f64>,
        #[serde(with = "serde_wasm_bindgen::preserve")]
        effects: JsValue,
    }
    let fields = [
        "accountId",
        "genesisHash",
        "hostId",
        "hostTrustGen",
        "origin",
        "feedId",
        "cursor",
        "results",
    ];
    only_fields(&ack, &fields, "control_ack")?;
    let a: A =
        serde_wasm_bindgen::from_value(ack).map_err(|e| bad(&format!("control_ack: {e}")))?;
    let results = items::<R>(
        &a.results,
        &["type", "recordId", "seq", "entryHash", "appliedSeq", "effects"],
        "results",
    )?
    .into_iter()
    .map(|r| {
        let effects = effect_results(&r.effects)?;
        match (r.kind.as_str(), r.record_id, r.seq, r.entry_hash, r.applied_seq) {
            ("record", Some(record_id), None, None, None) => {
                Ok(crate::types::RelayAckResult::Record { record_id, effects })
            }
            ("entry", None, Some(seq), Some(entry_hash), Some(applied_seq)) => {
                Ok(crate::types::RelayAckResult::Entry {
                    seq: ms(seq)?,
                    entry_hash,
                    applied_seq: ms(applied_seq)?,
                    effects,
                })
            }
            _ => Err(bad(
                "a result is {type: \"record\", recordId, effects} or {type: \"entry\", seq, entryHash, appliedSeq, effects}",
            )),
        }
    })
    .collect::<JsResult<Vec<_>>>()?;
    err(crate::station::relay_control_ack(
        crate::types::ControlAckInfo {
            account_id: a.account_id,
            genesis_hash: a.genesis_hash,
            host_id: a.host_id,
            host_trust_gen: ms(a.host_trust_gen)?,
            origin: a.origin,
            feed_id: a.feed_id,
            cursor: ms(a.cursor)?,
            results,
        },
    ))
}

/// `membership_fetch{after}` (`relay_membership_fetch`).
#[wasm_bindgen(js_name = relayMembershipFetch)]
pub fn relay_membership_fetch(after: f64) -> JsResult<String> {
    err(crate::station::relay_membership_fetch(ms(after)?))
}

/// `membership_fetch_result{head, entries}`
/// (`relay_membership_fetch_result`): `head` `{seq, hash}`, `entries` the
/// signed objects' JSON.
#[wasm_bindgen(js_name = relayMembershipFetchResult)]
pub fn relay_membership_fetch_result(head: JsValue, entries: Vec<String>) -> JsResult<String> {
    err(crate::station::relay_membership_fetch_result(
        strict_head(head)?,
        entries,
    ))
}

/// The class of the Portal's HTTP status for a report: `"confirm"`,
/// `"retry"`, `"refuse"` or `"stop_reporting"` (`report_answer`).
#[wasm_bindgen(js_name = reportAnswer)]
pub fn report_answer(status: f64) -> JsResult<JsValue> {
    if !(status.is_finite() && status.fract() == 0.0 && (0.0..=65535.0).contains(&status)) {
        return Err(bad("an HTTP status is an integer from 0 to 65535"));
    }
    to_js(&crate::station::report_answer(status as u16))
}

/// The Station's reference acknowledgment ledger (`AckLedgerHandle`).
#[wasm_bindgen]
pub struct AckLedgerHandle(Arc<crate::station::AckLedgerHandle>);

fn ack_transition(t: crate::station::AckTransition) -> JsResult<AckTransition> {
    Ok(AckTransition {
        intents: to_js(&t.intents)?,
        alerts: to_js(&t.alerts)?,
        next: t.next,
    })
}

#[wasm_bindgen]
impl AckLedgerHandle {
    /// The empty ledger of the device list `accountId`/`genesisHash` at
    /// the Station `origin`.
    #[wasm_bindgen(constructor)]
    pub fn new(
        origin: String,
        account_id: String,
        genesis_hash: String,
    ) -> JsResult<AckLedgerHandle> {
        Ok(AckLedgerHandle(err(crate::station::AckLedgerHandle::new(
            origin,
            account_id,
            genesis_hash,
        ))?))
    }
    /// A state `toJson()` wrote.
    #[wasm_bindgen(js_name = fromJson)]
    pub fn from_json(state_json: String) -> JsResult<AckLedgerHandle> {
        Ok(AckLedgerHandle(err(
            crate::station::AckLedgerHandle::from_json(state_json),
        )?))
    }
    /// The durable state (canonical JSON): store the next state's after
    /// every call that returns a transition.
    #[wasm_bindgen(js_name = toJson)]
    pub fn to_json(&self) -> String {
        self.0.to_json()
    }
    pub fn origin(&self) -> String {
        self.0.origin()
    }
    #[wasm_bindgen(js_name = accountId)]
    pub fn account_id(&self) -> String {
        self.0.account_id()
    }
    #[wasm_bindgen(js_name = genesisHash)]
    pub fn genesis_hash(&self) -> String {
        self.0.genesis_hash()
    }
    /// A record the Station stored in its feed (`record`).
    pub fn record(
        &self,
        record_json: String,
        revoked_at_ms: f64,
        covered_hosts: Vec<String>,
        now_ms: f64,
    ) -> JsResult<AckTransition> {
        ack_transition(err(self.0.record(
            record_json,
            ms(revoked_at_ms)?,
            covered_hosts,
            ms(now_ms)?,
        ))?)
    }
    /// A host's `control_ack` on the link `link` (`{accountId, genesisHash,
    /// hostId, hostTrustGen, connectionId}`, the link's verified
    /// association), at `nowMs` (`ack`).
    pub fn ack(&self, link: JsValue, ack_json: String, now_ms: f64) -> JsResult<AckTransition> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct L {
            account_id: String,
            genesis_hash: String,
            host_id: String,
            host_trust_gen: f64,
            connection_id: String,
        }
        only_fields(
            &link,
            &[
                "accountId",
                "genesisHash",
                "hostId",
                "hostTrustGen",
                "connectionId",
            ],
            "link",
        )?;
        let l: L = serde_wasm_bindgen::from_value(link).map_err(|e| {
            bad(&format!(
                "link {{accountId, genesisHash, hostId, hostTrustGen, connectionId}}: {e}"
            ))
        })?;
        let link = crate::types::LinkAssociationInfo {
            account_id: l.account_id,
            genesis_hash: l.genesis_hash,
            host_id: l.host_id,
            host_trust_gen: ms(l.host_trust_gen)?,
            connection_id: l.connection_id,
        };
        ack_transition(err(self.0.ack(link, ack_json, ms(now_ms)?))?)
    }
    /// The Station's timer (`tick`).
    pub fn tick(&self, now_ms: f64) -> JsResult<AckTransition> {
        ack_transition(self.0.tick(ms(now_ms)?))
    }
    /// The Portal answered `200` (`confirm`).
    pub fn confirm(&self, report_id: String) -> JsResult<AckTransition> {
        ack_transition(self.0.confirm(report_id))
    }
    /// The Portal refused the report for good (`refuse`).
    pub fn refuse(&self, report_id: String) -> JsResult<AckTransition> {
        ack_transition(self.0.refuse(report_id))
    }
    /// The Portal answered `403` to the report client `clientId`
    /// (`stop_reporting`): every report held until a resume.
    #[wasm_bindgen(js_name = stopReporting)]
    pub fn stop_reporting(&self, client_id: String) -> JsResult<AckTransition> {
        ack_transition(err(self.0.stop_reporting(client_id))?)
    }
    /// The Station reports again as the report client `clientId`
    /// (`resume_reporting`): the stop's own ID keeps every report, another
    /// drops them.
    #[wasm_bindgen(js_name = resumeReporting)]
    pub fn resume_reporting(&self, client_id: String) -> JsResult<AckTransition> {
        ack_transition(err(self.0.resume_reporting(client_id))?)
    }
    /// The report client ID reporting is stopped under, or `undefined`.
    #[wasm_bindgen(js_name = stoppedClientId)]
    pub fn stopped_client_id(&self) -> Option<String> {
        self.0.stopped_client_id()
    }
    /// What to send now, in order: `[{reportId, report: {type, …},
    /// notBefore}]`.
    #[wasm_bindgen(js_name = pendingReports)]
    pub fn pending_reports(&self) -> JsResult<JsValue> {
        to_js(&self.0.pending_reports())
    }
    /// The native-signed records still to re-sign (`record_id`s, sorted).
    #[wasm_bindgen(js_name = resignAlerts)]
    pub fn resign_alerts(&self) -> Vec<String> {
        self.0.resign_alerts()
    }
    /// The reports refused for good, and those a resume under another
    /// report client ID dropped.
    #[wasm_bindgen(js_name = refusedReports)]
    pub fn refused_reports(&self) -> Vec<String> {
        self.0.refused_reports()
    }
    /// The Portal refused this Station's reports (`403`).
    #[wasm_bindgen(js_name = reportingStopped)]
    pub fn reporting_stopped(&self) -> bool {
        self.0.reporting_stopped()
    }
}

/// What a ledger call gives (`crate::station::AckTransition`).
#[wasm_bindgen]
pub struct AckTransition {
    intents: JsValue,
    alerts: JsValue,
    next: Arc<crate::station::AckLedgerHandle>,
}

#[wasm_bindgen]
impl AckTransition {
    /// The reports the call made: `[{reportId, report, notBefore}]`.
    #[wasm_bindgen(getter)]
    pub fn intents(&self) -> JsValue {
        self.intents.clone()
    }
    /// The operator alerts it raised: `{type: "report_refused", reportId}`,
    /// `{type: "reporting_stopped", clientId}` or `{type:
    /// "reports_dropped", clientId, dropped}`.
    #[wasm_bindgen(getter)]
    pub fn alerts(&self) -> JsValue {
        self.alerts.clone()
    }
    /// The state after the call: use it once the transaction storing
    /// `next.toJson()` committed.
    #[wasm_bindgen(getter)]
    pub fn next(&self) -> AckLedgerHandle {
        AckLedgerHandle(self.next.clone())
    }
}

// ------------------------------------------------------- kit and backup

#[wasm_bindgen]
pub struct RecoveryKit(Arc<crate::kit::RecoveryKitHandle>);

#[wasm_bindgen]
impl RecoveryKit {
    pub fn generate(account_id: String, genesis_hash: String) -> JsResult<RecoveryKit> {
        Ok(RecoveryKit(err(crate::kit::RecoveryKitHandle::generate(
            account_id,
            genesis_hash,
        ))?))
    }
    pub fn make(r: Vec<u8>, account_id: String, genesis_hash: String) -> JsResult<RecoveryKit> {
        Ok(RecoveryKit(err(crate::kit::RecoveryKitHandle::make(
            r,
            account_id,
            genesis_hash,
        ))?))
    }
    pub fn read(
        r: Vec<u8>,
        account_id: String,
        genesis_hash: String,
        kit_tag: Vec<u8>,
    ) -> JsResult<RecoveryKit> {
        Ok(RecoveryKit(err(crate::kit::RecoveryKitHandle::read(
            r,
            account_id,
            genesis_hash,
            kit_tag,
        ))?))
    }
    #[wasm_bindgen(js_name = secretR)]
    pub fn secret_r(&self) -> Vec<u8> {
        self.0.secret_r()
    }
    #[wasm_bindgen(js_name = kitTag)]
    pub fn kit_tag(&self) -> Vec<u8> {
        self.0.kit_tag()
    }
    #[wasm_bindgen(js_name = recoveryKey)]
    pub fn recovery_key(&self) -> JsResult<JsValue> {
        to_js(&self.0.recovery_key())
    }
    #[wasm_bindgen(js_name = x25519Public)]
    pub fn x25519_public(&self) -> JsResult<Vec<u8>> {
        err(self.0.x25519_public())
    }
}

#[wasm_bindgen(js_name = parseKBackup)]
pub fn parse_k_backup(envelope_json: String) -> JsResult<JsValue> {
    ok(crate::kit::parse_k_backup(envelope_json))
}

#[wasm_bindgen(js_name = openKBackup)]
pub fn open_k_backup(envelope_json: String, kit: &RecoveryKit) -> JsResult<JsValue> {
    ok(crate::kit::open_k_backup(envelope_json, kit.0.clone()))
}

#[wasm_bindgen(js_name = hostAcceptTh2)]
pub fn host_accept_th2(init_json: String, accept_json: String) -> JsResult<String> {
    err(crate::kit::host_accept_th2(init_json, accept_json))
}

#[wasm_bindgen(js_name = verifyHostAccept)]
pub fn verify_host_accept(
    init_json: String,
    accept_json: String,
    log: &MembershipLog,
) -> JsResult<JsValue> {
    ok(crate::kit::verify_host_accept(
        init_json,
        accept_json,
        log.0.clone(),
    ))
}

#[wasm_bindgen]
pub struct RestoreSession(Arc<crate::kit::RestoreSession>);

#[wasm_bindgen]
impl RestoreSession {
    pub fn read(
        r: Vec<u8>,
        account_id: String,
        genesis_hash: String,
        kit_tag: Vec<u8>,
    ) -> JsResult<RestoreSession> {
        Ok(RestoreSession(err(crate::kit::RestoreSession::read(
            r,
            account_id,
            genesis_hash,
            kit_tag,
        ))?))
    }
    /// `hostAccepts`: an array of `{initJson, acceptJson}`.
    pub fn attempt(
        &self,
        relay_entries: Vec<String>,
        envelope_json: String,
        host_accepts: JsValue,
        now: JsValue,
    ) -> JsResult<JsValue> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Pair {
            init_json: String,
            accept_json: String,
        }
        let pairs: Vec<Pair> =
            serde_wasm_bindgen::from_value(host_accepts).map_err(|_| bad("host accepts"))?;
        let pairs = pairs
            .into_iter()
            .map(|p| crate::types::HostAcceptPair {
                init_json: p.init_json,
                accept_json: p.accept_json,
            })
            .collect();
        ok(self
            .0
            .attempt(relay_entries, envelope_json, pairs, clock(now)?))
    }
    /// After a restart with an enrollment in flight (its `preparedJson()`).
    pub fn resume(
        r: Vec<u8>,
        account_id: String,
        genesis_hash: String,
        kit_tag: Vec<u8>,
        prepared_json: String,
    ) -> JsResult<RestoreSession> {
        Ok(RestoreSession(err(crate::kit::RestoreSession::resume(
            r,
            account_id,
            genesis_hash,
            kit_tag,
            prepared_json,
        ))?))
    }
    /// The signed `recovery_add` to (re)send.
    pub fn outstanding(&self) -> JsResult<JsValue> {
        to_js(&self.0.outstanding())
    }
    pub fn log(&self) -> Option<MembershipLog> {
        self.0.log().map(MembershipLog)
    }
    #[wasm_bindgen(js_name = kStored)]
    pub fn k_stored(&self) -> bool {
        self.0.k_stored()
    }
    #[wasm_bindgen(js_name = mayRotateK)]
    pub fn may_rotate_k(&self, device_id: String) -> bool {
        self.0.may_rotate_k(device_id)
    }
    #[wasm_bindgen(js_name = waitingForHosts)]
    pub fn waiting_for_hosts(&self) -> Option<Vec<String>> {
        self.0.waiting_for_hosts()
    }
    #[wasm_bindgen(js_name = lastErrorCode)]
    pub fn last_error_code(&self) -> Option<String> {
        self.0.last_error_code()
    }
    pub fn enroll(&self, member_json: String, signed_at: f64) -> JsResult<JsValue> {
        ok(self.0.enroll(member_json, ms(signed_at)?))
    }
    #[wasm_bindgen(js_name = preparedJson)]
    pub fn prepared_json(&self) -> Option<String> {
        self.0.prepared_json()
    }
    #[wasm_bindgen(js_name = appendStored)]
    pub fn append_stored(&self, now: JsValue) -> JsResult<JsValue> {
        ok(self.0.append_stored(clock(now)?))
    }
    #[wasm_bindgen(js_name = appendConflict)]
    pub fn append_conflict(
        &self,
        h: JsValue,
        entries: Vec<String>,
        more: bool,
        now: JsValue,
    ) -> JsResult<JsValue> {
        ok(self.0.append_conflict(head(h)?, entries, more, clock(now)?))
    }
}

// --------------------------------------------------------- push, grants

#[wasm_bindgen]
pub struct PushHint(Arc<crate::push::PushHint>);

#[wasm_bindgen(js_name = verifyPushHint)]
pub fn verify_push_hint(
    hint_json: String,
    log: &MembershipLog,
    now_ms: f64,
    verifier: &str,
) -> JsResult<PushHint> {
    let verifier = match verifier {
        "client" => PushVerifier::Client,
        "relay" => PushVerifier::Relay,
        _ => return Err(bad("verifier is client or relay")),
    };
    Ok(PushHint(err(crate::push::verify_push_hint(
        hint_json,
        log.0.clone(),
        ms(now_ms)?,
        verifier,
    ))?))
}

#[wasm_bindgen]
impl PushHint {
    pub fn approval(&self) -> JsResult<JsValue> {
        to_js(&self.0.approval())
    }
    pub fn state(&self) -> JsResult<JsValue> {
        to_js(&self.0.state())
    }
    #[wasm_bindgen(js_name = createdAt)]
    pub fn created_at(&self) -> f64 {
        self.0.created_at() as f64
    }
    #[wasm_bindgen(js_name = expiresAt)]
    pub fn expires_at(&self) -> f64 {
        self.0.expires_at() as f64
    }
    #[wasm_bindgen(js_name = ackJson)]
    pub fn ack_json(&self) -> String {
        self.0.ack_json()
    }
    pub fn json(&self) -> String {
        self.0.json()
    }
    #[wasm_bindgen(js_name = checkSealed)]
    pub fn check_sealed(&self) -> JsResult<()> {
        err(self.0.check_sealed())
    }
    #[cfg(feature = "software-keys")]
    pub fn open(
        &self,
        store: &SoftwareKeyStore,
        enc_key_id: String,
        device_id: String,
    ) -> JsResult<JsValue> {
        ok(self.0.open_with(&*store.0, &enc_key_id, &device_id))
    }
}

#[wasm_bindgen]
pub struct PushHintBook(Arc<crate::push::PushHintBook>);

impl Default for PushHintBook {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
impl PushHintBook {
    #[wasm_bindgen(constructor)]
    pub fn new() -> PushHintBook {
        PushHintBook(crate::push::PushHintBook::new())
    }
    pub fn offer(&self, hint: &PushHint) -> JsResult<JsValue> {
        ok(self.0.offer(hint.0.clone()))
    }
    #[wasm_bindgen(js_name = isResolved)]
    pub fn is_resolved(&self, approval: JsValue) -> JsResult<bool> {
        err(self.0.is_resolved(approval_ref(approval)?))
    }
    pub fn prune(&self, now_ms: f64) -> JsResult<()> {
        self.0.prune(ms(now_ms)?);
        Ok(())
    }
}

#[wasm_bindgen(js_name = pushStages)]
pub fn push_stages(created_at: f64, r: JsValue) -> JsResult<JsValue> {
    to_js(&crate::push::push_stages(ms(created_at)?, recipient(r)?))
}

#[wasm_bindgen(js_name = pushSendNow)]
pub fn push_send_now(
    stage_name: &str,
    due: f64,
    now: f64,
    expires_at: f64,
    resolved: bool,
    seen: bool,
) -> JsResult<bool> {
    Ok(crate::push::push_send_now(
        stage(stage_name)?,
        ms(due)?,
        ms(now)?,
        ms(expires_at)?,
        resolved,
        seen,
    ))
}

#[wasm_bindgen(js_name = pushGuard)]
pub fn push_guard(expires_at: f64) -> JsResult<f64> {
    Ok(crate::push::push_guard(ms(expires_at)?) as f64)
}

#[wasm_bindgen(js_name = pushNextDue)]
pub fn push_next_due(
    created_at: f64,
    expires_at: f64,
    r: JsValue,
    sent: Vec<String>,
    now: f64,
) -> JsResult<Option<f64>> {
    let sent = sent
        .iter()
        .map(|s| stage(s))
        .collect::<JsResult<Vec<_>>>()?;
    Ok(crate::push::push_next_due(
        ms(created_at)?,
        ms(expires_at)?,
        recipient(r)?,
        sent,
        ms(now)?,
    )
    .map(|v| v as f64))
}

#[wasm_bindgen(js_name = verifySeen)]
pub fn verify_seen(seen_json: String, log: &MembershipLog) -> JsResult<JsValue> {
    ok(crate::push::verify_seen(seen_json, log.0.clone()))
}

#[wasm_bindgen(js_name = seenInWindow)]
pub fn seen_in_window(
    seen_json: String,
    log: &MembershipLog,
    open_created_at: f64,
) -> JsResult<bool> {
    err(crate::push::seen_in_window(
        seen_json,
        log.0.clone(),
        ms(open_created_at)?,
    ))
}

#[wasm_bindgen(js_name = seenAckJson)]
pub fn seen_ack_json(seen_json: String, log: &MembershipLog) -> JsResult<String> {
    err(crate::push::seen_ack_json(seen_json, log.0.clone()))
}

#[wasm_bindgen(js_name = pushAckMessage)]
pub fn push_ack_message(acks: Vec<String>) -> JsResult<String> {
    err(crate::push::push_ack_message(acks))
}

#[wasm_bindgen(js_name = parsePushAck)]
pub fn parse_push_ack(message_json: String) -> JsResult<Vec<String>> {
    err(crate::push::parse_push_ack(message_json))
}

#[wasm_bindgen(js_name = parseBrowserGrant)]
pub fn parse_browser_grant(grant_json: String) -> JsResult<JsValue> {
    ok(crate::push::parse_browser_grant(grant_json))
}

// ---------------------------------------------------------- connection

#[wasm_bindgen]
pub struct ClientConnection(Arc<crate::connection::ClientConnection>);

#[wasm_bindgen]
impl ClientConnection {
    /// `kind`: `native`, `service` or `browser`; a browser passes its
    /// grant (JSON) and the id of its WebCrypto key.
    #[wasm_bindgen(constructor)]
    pub fn new(
        host_id: String,
        kind: &str,
        device_id: Option<String>,
        key_id: String,
        grant_json: Option<String>,
        need_before: Option<f64>,
    ) -> JsResult<ClientConnection> {
        let kind = match kind {
            "native" => PrincipalKind::Native,
            "service" => PrincipalKind::Service,
            "browser" => PrincipalKind::Browser,
            _ => return Err(bad("kind is native, service or browser")),
        };
        let identity = ClientIdentity {
            kind,
            device_id,
            key_id,
            grant_json,
        };
        let need_before = need_before.map(ms).transpose()?;
        Ok(ClientConnection(err(
            crate::connection::ClientConnection::new(host_id, identity, need_before),
        )?))
    }
    pub fn state(&self) -> JsResult<JsValue> {
        to_js(&self.0.state())
    }
    pub fn start(&self, log: &MembershipLog, now_ms: f64) -> JsResult<Vec<u8>> {
        err(self.0.start(log.0.clone(), ms(now_ms)?))
    }
    #[wasm_bindgen(js_name = onAcceptDeferred)]
    pub fn on_accept_deferred(
        &self,
        frame: Vec<u8>,
        log: &MembershipLog,
        now_ms: f64,
    ) -> JsResult<JsValue> {
        ok(self.0.on_accept_deferred(frame, log.0.clone(), ms(now_ms)?))
    }
    #[wasm_bindgen(js_name = finishWithSignature)]
    /// The WebCrypto signature (`r‖s`) over the request's `input`; it must
    /// verify with the identity's own key (the grant's `browser_key`).
    pub fn finish_with_signature(&self, signature: Vec<u8>, now_ms: f64) -> JsResult<Vec<u8>> {
        err(self.0.finish_with_signature(signature, ms(now_ms)?))
    }
    #[cfg(feature = "software-keys")]
    #[wasm_bindgen(js_name = onAccept)]
    pub fn on_accept(
        &self,
        frame: Vec<u8>,
        log: &MembershipLog,
        store: &SoftwareKeyStore,
        now_ms: f64,
    ) -> JsResult<Vec<u8>> {
        err(self
            .0
            .on_accept_with(&frame, &log.0, &*store.0, ms(now_ms)?))
    }
    #[wasm_bindgen(js_name = onWelcome)]
    pub fn on_welcome(
        &self,
        frame: Vec<u8>,
        log: &MembershipLog,
        now_ms: f64,
    ) -> JsResult<JsValue> {
        ok(self.0.on_welcome(frame, log.0.clone(), ms(now_ms)?))
    }
    pub fn welcome(&self) -> JsResult<JsValue> {
        to_js(&self.0.welcome())
    }
    pub fn head(&self) -> JsResult<JsValue> {
        to_js(&self.0.head())
    }
    #[wasm_bindgen(js_name = pendingRecovery)]
    pub fn pending_recovery(&self) -> JsResult<JsValue> {
        to_js(&self.0.pending_recovery())
    }
    #[wasm_bindgen(js_name = fetchTo)]
    pub fn fetch_to(&self, log: &MembershipLog) -> JsResult<JsValue> {
        to_js(&self.0.fetch_to(log.0.clone()))
    }
    #[wasm_bindgen(js_name = isClosed)]
    pub fn is_closed(&self) -> bool {
        self.0.is_closed()
    }
    pub fn disconnect(&self) {
        self.0.disconnect()
    }
    #[wasm_bindgen(js_name = onFrame)]
    pub fn on_frame(&self, frame: Vec<u8>, now_ms: f64) -> JsResult<JsValue> {
        ok(self.0.on_frame(frame, ms(now_ms)?))
    }
    pub fn sessions(&self) -> JsResult<JsValue> {
        to_js(&self.0.sessions())
    }
    pub fn lease(&self, session_id: String, now_ms: f64) -> JsResult<JsValue> {
        to_js(&self.0.lease(session_id, ms(now_ms)?))
    }
    #[wasm_bindgen(js_name = bindingJson)]
    pub fn binding_json(
        &self,
        session_id: String,
        mutation: bool,
        now_ms: f64,
    ) -> JsResult<Option<String>> {
        Ok(self.0.binding_json(session_id, mutation, ms(now_ms)?))
    }
    pub fn list(&self, now_ms: f64) -> JsResult<JsValue> {
        ok(self.0.list(ms(now_ms)?))
    }
    pub fn acquire(&self, session_id: String, takeover: bool, now_ms: f64) -> JsResult<JsValue> {
        ok(self.0.acquire(session_id, takeover, ms(now_ms)?))
    }
    pub fn renew(&self, session_id: String, now_ms: f64) -> JsResult<JsValue> {
        ok(self.0.renew(session_id, ms(now_ms)?))
    }
    pub fn release(&self, session_id: String, now_ms: f64) -> JsResult<JsValue> {
        ok(self.0.release(session_id, ms(now_ms)?))
    }
    #[wasm_bindgen(js_name = submitPrompt)]
    pub fn submit_prompt(
        &self,
        session_id: String,
        request_id: String,
        text: String,
        now_ms: f64,
    ) -> JsResult<JsValue> {
        ok(self
            .0
            .submit_prompt(session_id, request_id, text, ms(now_ms)?))
    }
    #[wasm_bindgen(js_name = submitInterrupt)]
    pub fn submit_interrupt(
        &self,
        session_id: String,
        request_id: String,
        now_ms: f64,
    ) -> JsResult<JsValue> {
        ok(self.0.submit_interrupt(session_id, request_id, ms(now_ms)?))
    }
    #[wasm_bindgen(js_name = submitStop)]
    pub fn submit_stop(
        &self,
        session_id: String,
        request_id: String,
        now_ms: f64,
    ) -> JsResult<JsValue> {
        ok(self.0.submit_stop(session_id, request_id, ms(now_ms)?))
    }
    /// `decision`: `allow_once`, `allow_always` (with `ruleId`) or `deny`.
    #[wasm_bindgen(js_name = submitApproval)]
    #[allow(clippy::too_many_arguments)]
    pub fn submit_approval(
        &self,
        session_id: String,
        request_id: String,
        approval_id: String,
        decision: &str,
        rule_id: Option<String>,
        message: Option<String>,
        now_ms: f64,
    ) -> JsResult<JsValue> {
        let decision = match decision {
            "allow_once" => ApprovalChoice::AllowOnce,
            "allow_always" => ApprovalChoice::AllowAlways,
            "deny" => ApprovalChoice::Deny,
            _ => return Err(bad("decision is allow_once, allow_always or deny")),
        };
        ok(self.0.submit_approval(
            session_id,
            request_id,
            approval_id,
            decision,
            rule_id,
            message,
            ms(now_ms)?,
        ))
    }
    #[wasm_bindgen(js_name = submitRuleRevoke)]
    pub fn submit_rule_revoke(
        &self,
        session_id: String,
        request_id: String,
        rule_id: String,
        now_ms: f64,
    ) -> JsResult<JsValue> {
        ok(self
            .0
            .submit_rule_revoke(session_id, request_id, rule_id, ms(now_ms)?))
    }
    #[wasm_bindgen(js_name = receiptQuery)]
    pub fn receipt_query(
        &self,
        session_id: String,
        request_ids: Vec<String>,
        now_ms: f64,
    ) -> JsResult<JsValue> {
        ok(self.0.receipt_query(session_id, request_ids, ms(now_ms)?))
    }
    #[wasm_bindgen(js_name = approvalSeen)]
    pub fn approval_seen(
        &self,
        session_id: String,
        approval_id: String,
        now_ms: f64,
    ) -> JsResult<JsValue> {
        ok(self.0.approval_seen(session_id, approval_id, ms(now_ms)?))
    }
    #[wasm_bindgen(js_name = revokeGrant)]
    pub fn revoke_grant(&self, grant_id: String, now_ms: f64) -> JsResult<JsValue> {
        ok(self.0.revoke_grant(grant_id, ms(now_ms)?))
    }
    #[wasm_bindgen(js_name = hostPolicySet)]
    pub fn host_policy_set(
        &self,
        relay_only: bool,
        request_id: String,
        now_ms: f64,
    ) -> JsResult<JsValue> {
        ok(self.0.host_policy_set(relay_only, request_id, ms(now_ms)?))
    }
    #[wasm_bindgen(js_name = hostPolicyRetry)]
    pub fn host_policy_retry(
        &self,
        relay_only: bool,
        request_id: String,
        expected_revision: f64,
        now_ms: f64,
    ) -> JsResult<JsValue> {
        ok(self
            .0
            .host_policy_retry(relay_only, request_id, ms(expected_revision)?, ms(now_ms)?))
    }
    #[wasm_bindgen(js_name = hostPolicyGet)]
    pub fn host_policy_get(&self, desired: bool, now_ms: f64) -> JsResult<JsValue> {
        ok(self.0.host_policy_get(desired, ms(now_ms)?))
    }
    #[wasm_bindgen(js_name = hostPolicyReady)]
    pub fn host_policy_ready(&self) -> bool {
        self.0.host_policy_ready()
    }
    #[wasm_bindgen(js_name = sendMembership)]
    pub fn send_membership(&self, entries: Vec<String>, now_ms: f64) -> JsResult<JsValue> {
        ok(self.0.send_membership(entries, ms(now_ms)?))
    }
    #[wasm_bindgen(js_name = terminalSubscribe)]
    pub fn terminal_subscribe(&self, session_id: String, now_ms: f64) -> JsResult<JsValue> {
        ok(self.0.terminal_subscribe(session_id, ms(now_ms)?))
    }
    #[wasm_bindgen(js_name = chatOpen)]
    pub fn chat_open(
        &self,
        session_id: String,
        conversation_id: String,
        now_ms: f64,
    ) -> JsResult<JsValue> {
        ok(self.0.chat_open(session_id, conversation_id, ms(now_ms)?))
    }
    #[wasm_bindgen(js_name = sendJson)]
    pub fn send_json(&self, message_json: String, now_ms: f64) -> JsResult<Vec<u8>> {
        err(self.0.send_json(message_json, ms(now_ms)?))
    }
}

// ------------------------------------------------ software keys (bots)

#[cfg(feature = "software-keys")]
#[wasm_bindgen]
pub struct SoftwareKeyStore(Arc<crate::provider::SoftwareKeyStore>);

#[cfg(feature = "software-keys")]
impl Default for SoftwareKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "software-keys")]
#[wasm_bindgen]
impl SoftwareKeyStore {
    #[wasm_bindgen(constructor)]
    pub fn new() -> SoftwareKeyStore {
        SoftwareKeyStore(crate::provider::SoftwareKeyStore::new())
    }
    #[wasm_bindgen(js_name = insertP256)]
    pub fn insert_p256(&self, key_id: String, secret: Vec<u8>) -> JsResult<()> {
        err(self.0.insert_p256(key_id, secret))
    }
    #[wasm_bindgen(js_name = insertEd25519)]
    pub fn insert_ed25519(&self, key_id: String, seed: Vec<u8>) -> JsResult<()> {
        err(self.0.insert_ed25519(key_id, seed))
    }
    #[wasm_bindgen(js_name = insertX25519)]
    pub fn insert_x25519(&self, key_id: String, secret: Vec<u8>) -> JsResult<()> {
        err(self.0.insert_x25519(key_id, secret))
    }
    pub fn generate(&self, key_id: String, alg_name: &str) -> JsResult<JsValue> {
        ok(self.0.generate(key_id, alg(alg_name)?))
    }
    #[wasm_bindgen(js_name = publicKey)]
    pub fn public_key(&self, key_id: String) -> JsResult<JsValue> {
        ok(self.0.public_key_of(key_id))
    }
}

#[cfg(feature = "software-keys")]
#[wasm_bindgen(js_name = sealKBackup)]
pub fn seal_k_backup(
    account_id: String,
    genesis_hash: String,
    blob_version: f64,
    recovery_alg: &str,
    recovery_raw: Vec<u8>,
    keys: JsValue,
) -> JsResult<String> {
    #[derive(Deserialize)]
    struct K {
        kid: String,
        #[serde(with = "serde_bytes")]
        k: Vec<u8>,
    }
    let keys: Vec<K> = serde_wasm_bindgen::from_value(keys).map_err(|_| bad("keys [{kid, k}]"))?;
    let keys = keys
        .into_iter()
        .map(|k| crate::types::AccountKey { kid: k.kid, k: k.k })
        .collect();
    err(crate::kit::seal_k_backup(
        account_id,
        genesis_hash,
        ms(blob_version)?,
        key(recovery_alg, recovery_raw)?,
        keys,
    ))
}

// ------------------------------------------- publishing (bots, tests)

#[wasm_bindgen]
pub struct EntryPublisher(Arc<crate::publish::EntryPublisher>);

impl Default for EntryPublisher {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
impl EntryPublisher {
    #[wasm_bindgen(constructor)]
    pub fn new() -> EntryPublisher {
        EntryPublisher(crate::publish::EntryPublisher::new())
    }
    pub fn resume(prepared_json: String) -> JsResult<EntryPublisher> {
        Ok(EntryPublisher(err(
            crate::publish::EntryPublisher::resume(prepared_json),
        )?))
    }
    pub fn prepare(&self, log: &MembershipLog, body_json: String) -> JsResult<()> {
        err(self.0.prepare(log.0.clone(), body_json))
    }
    #[wasm_bindgen(js_name = preparedJson)]
    pub fn prepared_json(&self) -> Option<String> {
        self.0.prepared_json()
    }
    pub fn outstanding(&self) -> JsResult<JsValue> {
        to_js(&self.0.outstanding())
    }
    #[cfg(feature = "software-keys")]
    pub fn sign(
        &self,
        store: &SoftwareKeyStore,
        key_id: String,
        cosign_kit: Option<RecoveryKit>,
    ) -> JsResult<JsValue> {
        ok(self
            .0
            .sign_with(&*store.0, &key_id, cosign_kit.as_ref().map(|k| &*k.0)))
    }
    #[wasm_bindgen(js_name = replyStored)]
    pub fn reply_stored(&self, log: &MembershipLog, now: JsValue) -> JsResult<JsValue> {
        ok(self.0.reply_stored(log.0.clone(), clock(now)?))
    }
    #[wasm_bindgen(js_name = replyConflict)]
    pub fn reply_conflict(
        &self,
        log: &MembershipLog,
        h: JsValue,
        entries: Vec<String>,
        more: bool,
        now: JsValue,
    ) -> JsResult<JsValue> {
        ok(self
            .0
            .reply_conflict(log.0.clone(), head(h)?, entries, more, clock(now)?))
    }
}

#[wasm_bindgen]
pub struct KBackupWriter(Arc<crate::publish::KBackupWriter>);

#[wasm_bindgen]
impl KBackupWriter {
    pub fn start(
        log: &MembershipLog,
        kids: Vec<String>,
        recovery_alg: &str,
        recovery_raw: Vec<u8>,
        signer: String,
    ) -> JsResult<KBackupWriter> {
        Ok(KBackupWriter(err(crate::publish::KBackupWriter::start(
            log.0.clone(),
            kids,
            key(recovery_alg, recovery_raw)?,
            signer,
        ))?))
    }
    /// A writer resumed from its persisted `preparedJson()`.
    pub fn resume(saved_json: String) -> JsResult<KBackupWriter> {
        Ok(KBackupWriter(err(crate::publish::KBackupWriter::resume(
            saved_json,
        ))?))
    }
    /// The durable state: persist it after every call, before the step.
    #[wasm_bindgen(js_name = preparedJson)]
    pub fn prepared_json(&self) -> Option<String> {
        self.0.prepared_json()
    }
    pub fn step(&self) -> JsResult<JsValue> {
        to_js(&self.0.step())
    }
    pub fn sealed(
        &self,
        log: &MembershipLog,
        envelope_json: String,
        signed_at: f64,
    ) -> JsResult<JsValue> {
        ok(self.0.sealed(log.0.clone(), envelope_json, ms(signed_at)?))
    }
    #[cfg(feature = "software-keys")]
    pub fn sign(&self, store: &SoftwareKeyStore, key_id: String) -> JsResult<JsValue> {
        ok(self.0.sign_with(&*store.0, &key_id))
    }
    #[wasm_bindgen(js_name = putReply)]
    pub fn put_reply(&self, log: &MembershipLog, max_occupied: Option<f64>) -> JsResult<JsValue> {
        let max = max_occupied.map(ms).transpose()?;
        ok(self.0.put_reply(log.0.clone(), max))
    }
    #[wasm_bindgen(js_name = appendStored)]
    pub fn append_stored(
        &self,
        log: &MembershipLog,
        now: JsValue,
        signed_at: f64,
    ) -> JsResult<JsValue> {
        ok(self
            .0
            .append_stored(log.0.clone(), clock(now)?, ms(signed_at)?))
    }
    #[wasm_bindgen(js_name = appendConflict)]
    pub fn append_conflict(
        &self,
        log: &MembershipLog,
        h: JsValue,
        entries: Vec<String>,
        more: bool,
        now: JsValue,
        signed_at: f64,
    ) -> JsResult<JsValue> {
        ok(self.0.append_conflict(
            log.0.clone(),
            head(h)?,
            entries,
            more,
            clock(now)?,
            ms(signed_at)?,
        ))
    }
    pub fn fetched(
        &self,
        log: &MembershipLog,
        entries: Vec<String>,
        more: bool,
        now: JsValue,
        signed_at: f64,
    ) -> JsResult<JsValue> {
        ok(self
            .0
            .fetched(log.0.clone(), entries, more, clock(now)?, ms(signed_at)?))
    }
    pub fn restart(&self) -> JsResult<JsValue> {
        ok(self.0.restart())
    }
}

/// A phone's grant for a browser key (a bot or a test holding the issuer's
/// key in a software store; a real phone uses the native binding).
#[cfg(feature = "software-keys")]
#[wasm_bindgen(js_name = issueBrowserGrant)]
#[allow(clippy::too_many_arguments)]
pub fn issue_browser_grant(
    log: &MembershipLog,
    store: &SoftwareKeyStore,
    issuer_key_id: String,
    issuer: String,
    browser_key_raw: Vec<u8>,
    host_id: String,
    host_trust_gen: f64,
    session_id: Option<String>,
    ops: Vec<String>,
    issued_at: f64,
    expires_at: f64,
) -> JsResult<String> {
    err(crate::push::issue_browser_grant_with(
        &log.0,
        &*store.0,
        &issuer_key_id,
        &issuer,
        &key("p256", browser_key_raw)?,
        &host_id,
        ms(host_trust_gen)?,
        session_id.as_deref(),
        &ops,
        ms(issued_at)?,
        ms(expires_at)?,
    ))
}

/// Host role: a seen signed with `host_channel_key` from a software store.
#[cfg(all(feature = "software-keys", feature = "host"))]
#[wasm_bindgen(js_name = signSeen)]
pub fn sign_seen(
    store: &SoftwareKeyStore,
    host_key_id: String,
    approval: JsValue,
    created_at: f64,
    device_id: String,
    seen_at: f64,
) -> JsResult<String> {
    err(crate::push::sign_seen_with(
        &*store.0,
        &host_key_id,
        &approval_ref(approval)?,
        ms(created_at)?,
        &device_id,
        ms(seen_at)?,
    ))
}
