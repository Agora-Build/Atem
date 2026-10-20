//! The plain data the bindings pass: records (structs of values) and enums.
//! Swift/Kotlin get them as generated value types; JS as plain objects
//! (camelCase fields; enums with data as `{type, …}`, unit enums as
//! strings). Hashes and genesis hashes are lowercase hex; keys are raw
//! bytes with their algorithm; JSON values are canonical JSON text.

unit_enum! {
    /// §R9.1's algorithms. `X25519` keys encrypt and never sign.
    pub enum KeyAlg {
        P256,
        Ed25519,
        X25519,
    }
}

record! {
    /// A public key: SEC1 uncompressed (65 bytes) for P-256, 32 bytes
    /// otherwise.
    pub struct PublicKeyData {
        pub alg: KeyAlg,
        #[cfg_attr(feature = "wasm", serde(with = "serde_bytes"))]
        pub raw: Vec<u8>,
    }
}

unit_enum! {
    /// Why a key signs (R9.6 "Keys and owner confirmation"). `Channel` may
    /// reuse one owner confirmation for at most 5 minutes (cleared on lock
    /// and background); every other client purpose needs a fresh
    /// confirmation bound to the exact body shown (`SignRequest.body_json`)
    /// and is never given in the background or a notification extension.
    pub enum SigningPurpose {
        /// `sig_c`: the routine channel signature (every connection).
        Channel,
        /// The account's first entry (account setup).
        Genesis,
        /// `add` (a device or service joins).
        Enroll,
        /// `remove`.
        Remove,
        /// `set_roles`.
        Roles,
        /// `add_host` / `remove_host`.
        Host,
        /// `recovery_add`, `recovery_approve`, `recovery_veto`.
        Recovery,
        /// `set_recovery_key` and the current kit's co-signature.
        Kit,
        /// `k_backup` (naming a new K backup envelope).
        KeyBackup,
        /// A browser grant (a QR handed to a browser).
        BrowserGrant,
        /// Host-only signatures (`sig_h`, push hints, seens): never asked
        /// of a phone or a desktop client.
        HostSigning,
    }
}

impl SigningPurpose {
    /// Whether R9.6 rule 4 asks for a fresh confirmation (everything but the
    /// channel signature and host signing).
    pub fn needs_fresh_confirmation(self) -> bool {
        !matches!(self, SigningPurpose::Channel | SigningPurpose::HostSigning)
    }
}

unit_enum! {
    /// The signing labels of §R9.1 (domain separation).
    pub enum SignLabelKind {
        MembershipEntry,
        RecoveryCosign,
        BrowserGrant,
        PushHint,
        Seen,
        ChannelHost,
        ChannelClient,
    }
}

record! {
    /// One signature the core needs. `input` is exactly the bytes to sign
    /// (P-256: ECDSA over SHA-256 of `input`, 64-byte `r‖s`, either S;
    /// Ed25519: over `input`). `body_json` is the canonical body being
    /// signed, to show the owner (absent for the channel signature, whose
    /// input is a transcript hash).
    pub struct SignRequest {
        pub key_id: String,
        pub purpose: SigningPurpose,
        pub fresh_confirmation: bool,
        pub label: String,
        #[cfg_attr(feature = "wasm", serde(with = "serde_bytes"))]
        pub input: Vec<u8>,
        pub body_json: Option<String>,
    }
}

record! {
    /// The verifier's clock: wall time (ms since the epoch), a monotonic
    /// reading (ms) and the boot it belongs to. Pending recoveries wait 24 h
    /// of both (§R9.5).
    pub struct HostClock {
        pub wall_ms: u64,
        pub mono_ms: u64,
        pub boot_id: String,
    }
}

record! {
    /// A chain position.
    pub struct LogHead {
        pub seq: u64,
        pub hash: String,
    }
}

data_enum! {
    /// What a client does after the host refused its hello.
    pub enum NextStep {
        /// Reconnect with a new `ClientConnection` (pass `need_before` to
        /// it: the next hello carries the earlier window).
        Reconnect { need_before: Option<u64> },
        /// This device is behind a pending recovery: show it, retry after
        /// `effective_at`.
        WaitForRecovery { entry_hash: String, effective_at: u64 },
        /// `busy`: retry later.
        RetryLater,
        /// Show the error; don't loop.
        Stop,
    }
}

unit_enum! {
    pub enum MemberStatusKind {
        Active,
        /// The subject of a pending `recovery_add`: holds nothing yet.
        Pending,
        Cancelled,
        Removed,
    }
}

record! {
    /// A member as the verified log says.
    pub struct MemberInfo {
        pub device_id: String,
        /// `native` or `service`.
        pub kind: String,
        /// Native roles (`control`, `manage`, `view`), or `["service"]`.
        pub roles: Vec<String>,
        pub status: MemberStatusKind,
        pub pending_entry_hash: Option<String>,
        pub auth_key: PublicKeyData,
        /// A native member's push key.
        pub enc_key: Option<PublicKeyData>,
        /// A service's scope (canonical JSON).
        pub scope_json: Option<String>,
        pub expires_at: Option<u64>,
        /// The member object as signed (canonical JSON).
        pub member_json: String,
    }
}

record! {
    pub struct HostInfo {
        pub host_id: String,
        pub host_trust_gen: u64,
        pub host_key: PublicKeyData,
    }
}

record! {
    /// The newest `k_backup` record.
    pub struct KBackupInfo {
        pub blob_version: u64,
        pub kids: Vec<String>,
        pub recovery_key: PublicKeyData,
        pub backup_hash: String,
    }
}

record! {
    /// A pending recovery entry (show it: "Recovery of <subject> pending,
    /// takes effect <effective_at>: approve or cancel").
    pub struct PendingRecoveryInfo {
        pub entry_hash: String,
        pub seq: u64,
        pub action: String,
        pub subject: String,
        pub effective_at: u64,
    }
}

record! {
    /// The log is frozen (two current managers signed conflicting entries;
    /// §R9.4): both are kept for a manager to look at.
    pub struct FreezeInfo {
        pub seq: u64,
        pub ours_json: String,
        pub theirs_json: String,
        pub at: u64,
    }
}

data_enum! {
    /// A state change the verifier committed (or would commit).
    pub enum MembershipEffect {
        Appended { head: LogHead },
        MemberAdded { device_id: String },
        MemberRemoved { device_id: String },
        RolesChanged { device_id: String },
        HostKeyChanged { host_id: String },
        HostRemoved { host_id: String },
        RecoveryPending { entry_hash: String },
        RecoveryActive { entry_hash: String, reason: String },
        RecoveryCancelled { entry_hash: String, reason: String },
        RecoveryKeyReplaced,
        KBackupRecorded { blob_version: u64 },
        VetoReplaced { head: LogHead },
        Evidence { reason: String },
        Frozen,
    }
}

data_enum! {
    /// Where an evaluation of entries stopped (the valid prefix applies).
    pub enum CarriageStop {
        Frozen,
        /// `membership_invalid` at `index` (`code` the detail).
        Invalid { index: u64, code: String },
        /// The divergence is before the window: carry from before `seq`.
        NeedBefore { index: u64, seq: u64 },
        /// Depends on the pending entry `on`: stopped without an error.
        Deferred { index: u64, on: String },
        /// A conflicting entry: `freeze`, `ignored:<reason>` or
        /// `replaced_veto`.
        Conflict { index: u64, outcome: String },
    }
}

record! {
    /// The result of evaluating entries against a log.
    pub struct CarriageResult {
        pub appended: u64,
        /// The head after the valid prefix.
        pub head: LogHead,
        pub stop: Option<CarriageStop>,
        pub effects: Vec<MembershipEffect>,
        /// Whether the log object now holds this state.
        pub committed: bool,
    }
}

unit_enum! {
    /// How a log relates to a head another party signed.
    pub enum HeadRelationKind {
        Same,
        /// The log holds that head and more.
        HostBehind,
        /// The head is beyond the log: fetch and verify up to it.
        HostAhead,
        Diverged,
    }
}

data_enum! {
    /// The membership side of admitting a carrier (host role, feature
    /// `host`).
    #[cfg(feature = "host")]
    pub enum AdmissionInfo {
        Frozen,
        Invalid { head: LogHead, index: u64, code: String, need_before: Option<u64> },
        Incomplete { head: LogHead },
        RecoveryPending { entry_hash: String, effective_at: u64 },
        Unauthorized { detail: String },
        Member { head: LogHead, device_id: String },
    }
}

record! {
    /// An append to send: `POST …/entries {"entry": <entry_json>,
    /// "expected": {"seq", "hash"}}`. Resend exactly this after an
    /// uncertain outcome.
    pub struct AppendRequest {
        pub entry_json: String,
        pub entry_hash: String,
        pub expected: LogHead,
    }
}

data_enum! {
    /// What an append came to (§R9.4 rules 2–3).
    pub enum PublishOutcome {
        /// In the relay's log and in ours.
        Committed { head: LogHead },
        /// Stored at the relay; joins our log when the pending entry `on`
        /// takes effect here.
        StoredPending { head: LogHead, on: String },
        /// `409`: our body was discarded; the log moved to `head`. A new
        /// body needs a new owner confirmation.
        LostRace { head: LogHead },
        /// `409` with more: discarded; fetch entries after `after`, extend,
        /// decide again.
        FetchMore { after: u64 },
        /// The relay showed conflicting signed history: stop signing
        /// entries; carry the window to hosts.
        Diverged,
        /// The relay's log goes beyond the pending entry `on`: wait.
        Waiting { on: String },
        /// The relay's answer didn't move our log to its head: refetch
        /// later; never rebuild on the unchanged head.
        RelayInconsistent { head: LogHead },
        /// The relay returned entries that don't verify.
        RelayInvalid { index: u64, code: String },
    }
}

data_enum! {
    /// The K-backup writer's next step (the app performs it and feeds the
    /// answer back).
    pub enum BackupStep {
        /// Seal the job's keys at this version (`seal_k_backup`), then call
        /// `sealed`.
        Seal { blob_version: u64 },
        /// The body to sign is stored: ask the manager's key (`sign`).
        Sign { body_json: String },
        /// Upload these envelope bytes (put-if-absent at this version).
        Put { blob_version: u64, bytes: String },
        /// Append this entry with the log CAS.
        Append { request: AppendRequest },
        /// Fetch entries after `after`, then call `fetched`.
        Fetch { after: u64 },
        /// The newest committed backup covers the job.
        Done { committed: u64 },
        Failed { code: String, detail: String },
    }
}

record! {
    /// An account key `K` (secret: store it in the platform key store at
    /// once and drop this value).
    pub struct AccountKey {
        pub kid: String,
        #[cfg_attr(feature = "wasm", serde(with = "serde_bytes"))]
        pub k: Vec<u8>,
    }
}

record! {
    /// A restore that passed (§R9.5 steps 1–5): store `keys`, then enroll.
    pub struct RestoredInfo {
        pub head: LogHead,
        pub keys: Vec<AccountKey>,
    }
}

data_enum! {
    pub enum EnrollmentOutcome {
        /// Stored: takes effect after the 24 h wait unless approved or
        /// vetoed.
        Published { head: LogHead },
        /// `409`: run `attempt` again on the new head, then enroll again.
        Rebuild,
        /// The relay misbehaved: stop; nothing was published.
        Stopped { detail: String },
    }
}

record! {
    /// A host's `init`/`accept` pair (its signed head), for the restore.
    pub struct HostAcceptPair {
        pub init_json: String,
        pub accept_json: String,
    }
}

unit_enum! {
    /// Who verifies a push hint (the clock rules differ, §R9.9).
    pub enum PushVerifier {
        Client,
        Relay,
    }
}

record! {
    /// The approval a hint or seen is about.
    pub struct ApprovalRef {
        pub account_id: String,
        pub genesis_hash: String,
        pub host_id: String,
        pub host_trust_gen: u64,
        pub session_id: String,
        pub process_gen: String,
        pub approval_id: String,
    }
}

data_enum! {
    pub enum HintStateInfo {
        Open { device_id: String, enc_kid: String, sealed_hash: String },
        Resolved { reason: String, resolved_at: u64 },
    }
}

record! {
    /// A hint's sealed content (the redacted tool and summary).
    pub struct HintContent {
        pub tool: String,
        pub summary: String,
    }
}

unit_enum! {
    pub enum HintOffer {
        /// New: show it (client) / schedule it (relay).
        Accepted,
        /// The same bytes again.
        Idempotent,
        /// An open for an approval already resolved.
        IgnoredAfterResolved,
    }
}

unit_enum! {
    pub enum DeviceKind {
        Desktop,
        Mobile,
    }
}

record! {
    /// A recipient as the relay's schedule sees it.
    pub struct PushRecipient {
        pub device_class: DeviceKind,
        /// A desktop Astation of this device is connected.
        pub connected: bool,
        /// A mobile device that opted in to immediate pushes.
        pub immediate_mobile: bool,
    }
}

unit_enum! {
    pub enum PushStage {
        InApp,
        DesktopOs,
        MobileImmediate,
        Mobile,
    }
}

record! {
    pub struct PushStageDue {
        pub stage: PushStage,
        pub due: u64,
        pub provider_push: bool,
    }
}

record! {
    pub struct SeenInfo {
        pub approval: ApprovalRef,
        pub created_at: u64,
        pub device_id: String,
        pub seen_at: u64,
    }
}

record! {
    pub struct BrowserGrantInfo {
        pub grant_id: String,
        pub account_id: String,
        pub genesis_hash: String,
        pub issuer: String,
        pub browser_key: PublicKeyData,
        pub host_id: String,
        pub host_trust_gen: u64,
        pub session_id: Option<String>,
        pub ops: Vec<String>,
        pub issued_at: u64,
        pub expires_at: u64,
        pub grant_hash: String,
    }
}

unit_enum! {
    pub enum PrincipalKind {
        Native,
        Service,
        Browser,
    }
}

record! {
    /// Who connects: a native member or a service by `device_id`, or a
    /// browser with its grant; `key_id` names its key in the provider (a
    /// browser's WebCrypto key).
    pub struct ClientIdentity {
        pub kind: PrincipalKind,
        pub device_id: Option<String>,
        pub key_id: String,
        pub grant_json: Option<String>,
    }
}

record! {
    /// A request to send: its message `id` (replies carry it as `re`) and
    /// the channel frame.
    pub struct Outgoing {
        pub id: String,
        #[cfg_attr(feature = "wasm", serde(with = "serde_bytes"))]
        pub frame: Vec<u8>,
    }
}

record! {
    pub struct WelcomeInfo {
        pub principal: String,
        pub client_kind: String,
        pub permissions: Vec<String>,
        pub revision: u64,
        pub features: Vec<String>,
        pub account_id: String,
        pub atem_device_id: String,
        pub host_trust_gen: u64,
        pub attachment_gen: String,
        pub controller_session: String,
        pub runtime_gen: String,
        pub authorization_ms_left: u64,
        pub server_time: u64,
        pub head: LogHead,
        pub pending_recovery: Vec<PendingRecoveryInfo>,
        pub channel_id: String,
        pub scope_json: Option<String>,
        /// The whole welcome (canonical JSON).
        pub json: String,
    }
}

record! {
    /// A session as the registry holds it.
    pub struct SessionInfo {
        pub session_id: String,
        pub process_gen: String,
        pub provider: String,
        pub cwd_label: String,
        pub state: String,
        pub activity: String,
        pub controller_session: Option<String>,
        pub lease_epoch: Option<u64>,
        pub capabilities: Vec<String>,
        pub json: String,
    }
}

record! {
    /// This attachment's lease on a session.
    pub struct LeaseInfo {
        pub controls: bool,
        pub input_enabled: bool,
        pub lease_epoch: Option<u64>,
        pub deadline_ms: Option<u64>,
    }
}

unit_enum! {
    pub enum ConnectionState {
        New,
        AwaitAccept,
        AwaitSignature,
        AwaitWelcome,
        Attached,
        Closed,
    }
}

unit_enum! {
    pub enum ApprovalChoice {
        AllowOnce,
        AllowAlways,
        Deny,
    }
}

data_enum! {
    /// Something that happened on an attachment.
    pub enum ClientEvent {
        /// A session-v1 message (receipts, `lease_changed`, `sessions`,
        /// approvals, errors with `re`, …): `op`, its `id`/`re`, the JSON.
        Session { op: String, id: String, re: Option<String>, json: String },
        /// What the registry did with a `sessions`/`session_changed`/
        /// approval message (`applied`, `stale_epoch`, …).
        Registry { outcome: String },
        /// What a session's lease client did with a reply (`applied`,
        /// `applied_expired`, `unknown_re`, `deadline_passed`, `mismatch`,
        /// `stale_epoch`, …).
        Lease { session_id: String, outcome: String },
        /// terminal-v1 or chat-v1 (`family` `terminal` / `agentChat`).
        Family { family: String, op: Option<String>, json: String },
        /// Send this frame now (a chat resync `open`).
        Outgoing {
            #[cfg_attr(feature = "wasm", serde(with = "serde_bytes"))]
            frame: Vec<u8>,
        },
        /// The host's head moved or pending entries changed: fetch and
        /// verify up to `head` when it is beyond the log (`fetch_to`).
        MembershipHead { re: Option<String>, head: LogHead, pending_recovery: Vec<PendingRecoveryInfo> },
        GrantRevoked { re: String },
        Seen { re: String },
        /// A session error.
        Error { code: String, re: Option<String>, detail: Option<String>, json: String },
        /// The attachment is over (`unauthorized`/`account_frozen` without
        /// `re`): the channel is closed; reconnect to learn more.
        Fenced { code: String, detail: Option<String>, json: String },
    }
}
