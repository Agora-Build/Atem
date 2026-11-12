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
        /// `project_set` / `project_remove`: a project grant, which hosts of
        /// the account may send each other which operations (show the
        /// project's name, its hosts and ops, or that it is removed).
        Project,
        /// `host_sender_revoke` / `host_sender_readmit`: stop (and with
        /// `interrupt_running`, also interrupt what it already started) or
        /// resume accepting one host as a sender of host work (show the host
        /// and which of the two).
        HostSender,
        /// `host_enc_key`: install a host's encryption key, the one it
        /// vouched for itself (`enc_sig`), which other hosts seal mail to
        /// (show the host, its trust generation, the key's `enc_kid`, and
        /// `retire_previous`: the key it replaces stops opening mail at
        /// once). Not the host's own `enc_sig`, which is `HostSigning`.
        HostEncKey,
        /// A native manager's control record (`atem-host-work-control`,
        /// delegated host-work I.5.3, `signer` `member:<device_id>`): a
        /// signed stop of a service or a host sender, `revoke` or
        /// `interrupt_running` only. A fresh confirmation of the exact body:
        /// show the principal, the action and `interrupt_running`; for a
        /// host principal (`host:<host_id>`), the host and the `revoke_seq`
        /// of the device-list revoke it follows.
        ControlRecord,
        /// A control record signed with the principal's own service key
        /// (`signer` equal to `principal`, `service:<id>`): the Station that
        /// hosts the integration signs it on its own, from the Portal's
        /// feed (`cover`, `hold`, `release`, `revoke`,
        /// `interrupt_running`). No owner confirmation; never asked of a
        /// native member's key (a native app's provider refuses it: such a
        /// signature would never verify).
        ServiceControl,
        /// `recovery_add`, `recovery_approve`, `recovery_veto`.
        Recovery,
        /// `set_recovery_key` and the current kit's co-signature.
        Kit,
        /// `k_backup` (naming a new K backup envelope).
        KeyBackup,
        /// A browser grant (a QR handed to a browser).
        BrowserGrant,
        /// Host-only signatures (`sig_h`, push hints, seens, a host's
        /// `enc_sig`): never asked of a phone or a desktop client.
        HostSigning,
    }
}

impl SigningPurpose {
    /// Whether R9.6 rule 4 asks for a fresh confirmation (everything but the
    /// channel signature, host signing and a service key's own control
    /// records).
    pub fn needs_fresh_confirmation(self) -> bool {
        !matches!(
            self,
            SigningPurpose::Channel | SigningPurpose::HostSigning | SigningPurpose::ServiceControl
        )
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
        /// `atem-host-work-control-v1`: control records (delegated host
        /// work I.5.3).
        HostWorkControl,
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

unit_enum! {
    /// How close the log (or one of its limits) is to full (D23).
    pub enum CapacityLevelKind {
        Ok,
        /// At or above 90 % of a limit: renewals use one entry each.
        NearlyFull,
        /// A limit reached: no entry at all (entries; the account needs
        /// re-pairing), no `add` (members), or no `add_host` of a new host
        /// (hosts).
        Full,
    }
}

record! {
    /// The log's use of its limits (§R9.2), by the verifier's own counts.
    /// `members` counts members in effect and the subjects of pending
    /// `recovery_add`s (removed ones free their place; ids stay used),
    /// `hosts` current hosts. `level` is the highest of the three limits'
    /// levels.
    pub struct CapacityInfo {
        pub entries: u64,
        pub max_entries: u64,
        pub members: u64,
        pub max_members: u64,
        pub hosts: u64,
        pub max_hosts: u64,
        pub level: CapacityLevelKind,
        pub entries_level: CapacityLevelKind,
        pub members_level: CapacityLevelKind,
        pub hosts_level: CapacityLevelKind,
    }
}

record! {
    /// What a device-list verifier reports about itself (session-v1 R9.2
    /// "How a verifier reports itself"; Atem's proposal, for Astation's
    /// agreement, Decision 23): `version` (from 1) names its action set,
    /// `actions` are the actions it knows, sorted by bytes, each once.
    /// `verifier_inventory()` is this binding's own verifier;
    /// `WelcomeInfo.verifier` is the host's, when its welcome carried one.
    /// It is a claim, not a proof: an unknown, offline or unconfirmed
    /// verifier still keeps the signing gate closed.
    pub struct VerifierInventory {
        pub version: u32,
        pub actions: Vec<String>,
    }
}

impl From<&atem_client::membership::VerifierInventory> for VerifierInventory {
    fn from(v: &atem_client::membership::VerifierInventory) -> Self {
        VerifierInventory {
            version: v.version,
            actions: v.actions.clone(),
        }
    }
}

data_enum! {
    /// Why a signer shouldn't draft a change now
    /// (`MembershipLog::check_change`; advisory, the verifier still accepts
    /// any valid entry).
    pub enum ChangeRefusalInfo {
        /// 1024 entries: no verifier takes another, a removal included.
        LogFull,
        /// 256 members: no `add`, and no `recovery_add` either (a Recovery
        /// Kit can't bring the account back), until one is removed: keep
        /// expired or unused services removed so a place stays free.
        MembersFull,
        /// 64 current hosts: no `add_host` of a new host until one is
        /// removed (a current host's new key still fits).
        HostsFull,
        /// A service change that grants anything new within 24 h of that
        /// service's last grant (its add, or a change that granted
        /// something new; signed at `last_signed_at`): retry at `retry_at`.
        ServiceChangeTooSoon { last_signed_at: u64, retry_at: u64 },
        /// A `host_sender_revoke` of a host already revoked.
        AlreadyRevoked,
        /// A `host_sender_readmit` of a host that isn't revoked.
        NotRevoked,
        /// A `host_enc_key` of a key already set for that host since its
        /// newest `add_host` (current, previous, retired or no longer
        /// kept): ask the host for a new key.
        EncKeyReused,
    }
}

record! {
    /// A service scope (§R9.6) to build an `add` or `set_roles` from: the
    /// lists in any order (the builder sorts them and drops duplicates);
    /// `view` is added to `ops`; `projects`/`sessions` absent don't
    /// restrict. Also what `MembershipLog::service_grant` returns
    /// (canonical order).
    pub struct ServiceScopeInfo {
        pub hosts: Vec<String>,
        /// `h1.<kid>.<64 hex>` launch project hashes (`project_hash`).
        pub projects: Option<Vec<String>>,
        /// `ses-…` session ids.
        pub sessions: Option<Vec<String>>,
        pub ops: Vec<String>,
    }
}

record! {
    /// A service member's grant in effect: its scope and expiry.
    pub struct ServiceGrantInfo {
        pub scope: ServiceScopeInfo,
        pub expires_at: u64,
    }
}

data_enum! {
    /// A host's sending authorization (delegated host-work II.3.1), from its
    /// `add_host` and the `host_sender_revoke` / `host_sender_readmit`
    /// entries after it.
    pub enum HostSenderStateInfo {
        /// Its envelopes signed at or after `generation` are accepted: the
        /// `seq` of its first `add_host`, or of its latest readmit.
        Authorized { generation: u64 },
        /// Revoked by the entry at `seq`: none are accepted.
        Revoked { seq: u64 },
    }
}

record! {
    /// A project in effect (II.2.2): the hosts it lets send each other the
    /// `ops` (`launch`, `message`, `notify`, `prompt`).
    pub struct ProjectInfo {
        pub name: String,
        /// The hosts as the latest `project_set` signed them (sorted).
        pub hosts: Vec<String>,
        /// The hosts of `hosts` whose membership is still in effect (no
        /// `remove_host` of them since; sorted).
        pub members: Vec<String>,
        /// Sorted.
        pub ops: Vec<String>,
    }
}

record! {
    /// A host encryption key as a `host_enc_key` entry set it (II.4.1).
    pub struct HostEncKeyInfo {
        /// R9.9's `enc_kid` of `key` (16 hex characters).
        pub enc_kid: String,
        /// X25519.
        pub key: PublicKeyData,
        /// The `seq` of the entry that set it.
        pub seq: u64,
        /// The host's trust generation it is bound to.
        pub host_trust_gen: u64,
    }
}

record! {
    /// The key a rotation replaced.
    pub struct PreviousHostEncKeyInfo {
        pub key: HostEncKeyInfo,
        /// Retired at once (`retire_previous`): it opens nothing. Otherwise
        /// the host keeps it for 24 h on its own clock from when it applied
        /// the entry at `replaced_at_seq`.
        pub retired: bool,
        /// The `seq` of the entry that replaced it.
        pub replaced_at_seq: u64,
    }
}

record! {
    /// A host's encryption keys for its current trust generation.
    pub struct HostEncKeysInfo {
        pub current: HostEncKeyInfo,
        pub previous: Option<PreviousHostEncKeyInfo>,
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
        ProjectSet { name: String },
        ProjectRemoved { name: String },
        HostSenderRevoked { host_id: String, seq: u64, interrupt_running: bool },
        HostSenderReadmitted { host_id: String, seq: u64 },
        HostEncKeySet { host_id: String, retire_previous: bool },
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

record! {
    /// The alert an `outcome_unknown` hint is about.
    pub struct AlertRef {
        pub account_id: String,
        pub genesis_hash: String,
        pub host_id: String,
        pub host_trust_gen: u64,
        pub alert_id: String,
    }
}

data_enum! {
    /// Where a hint stands: an approval's `open` or `resolved`, or an
    /// `outcome_unknown` hint (delegated host work, I.4.6), which like an
    /// open hint names its recipient and sealed part.
    pub enum HintStateInfo {
        Open { device_id: String, enc_kid: String, sealed_hash: String },
        Resolved { reason: String, resolved_at: u64 },
        OutcomeUnknown { device_id: String, enc_kid: String, sealed_hash: String },
    }
}

data_enum! {
    /// A hint's sealed content: an approval's redacted tool and summary, or
    /// an `outcome_unknown` hint's task, session, sender and reason.
    pub enum HintContent {
        Approval { tool: String, summary: String },
        OutcomeUnknown { task_id: String, session_id: String, sender: String, reason: String },
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
        /// The host verifier's report, absent when the host sent none
        /// (Atem's proposal, for Astation's agreement; Decision 23).
        pub verifier: Option<VerifierInventory>,
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
        /// A `host_policy_result` (§R9.8a): the host's current policy and
        /// what it did to this attachment's relay-only readiness
        /// (`observed`: `ready`, `not_ready`, or `foreign` — not one of
        /// this attachment's requests, or bound elsewhere: confirms
        /// nothing). `outcome`: `committed`, `unchanged`, `superseded`,
        /// `conflict`, `save_failed`, `uncertain`, `current`; `state`:
        /// `durable` or `uncertain`.
        HostPolicy {
            re: String,
            request_id: Option<String>,
            outcome: String,
            relay_only: bool,
            revision: u64,
            state: String,
            observed: String,
            json: String,
        },
        /// `host_policy_changed`: another manager's committed change (the
        /// host's current policy). Never a confirmation; `observed`
        /// `not_ready` when it contradicts the wanted value.
        HostPolicyChanged {
            relay_only: bool,
            revision: u64,
            state: String,
            observed: String,
            json: String,
        },
        /// A session error.
        Error { code: String, re: Option<String>, detail: Option<String>, json: String },
        /// The attachment is over (`unauthorized`/`account_frozen` without
        /// `re`): the channel is closed; reconnect to learn more.
        Fenced { code: String, detail: Option<String>, json: String },
    }
}

// ------------------------------------- control records (delegated host work)

record! {
    /// A control record's body (`atem-host-work-control`, delegated host
    /// work I.5.3; host-work-v1 §11.1), field by field. Absent fields are
    /// `None` and omitted from the body. A service's record (`principal`
    /// `service:<id>`) has `origin`, `feed_id`, `principal_key` (the
    /// integration's `r9Svc`: `service_key_fingerprint` of its `auth_key`)
    /// and `integration_id`; a host principal's (`host:<host_id>`) is
    /// `interrupt_running` only, with `revoke_seq` and none of those.
    /// `interrupt_running` is present exactly on `revoke`.
    pub struct ControlRecordBody {
        pub account_id: String,
        /// Lowercase hex.
        pub genesis_hash: String,
        /// The Station's exact origin (`https://…`).
        pub origin: Option<String>,
        /// The Station feed's UUID v4.
        pub feed_id: Option<String>,
        /// `service:<device_id>` or `host:<host_id>`.
        pub principal: String,
        /// Lowercase hex SHA-256 of the principal's `auth_key` bytes.
        pub principal_key: Option<String>,
        /// The principal itself, or `member:<device_id>` (a native manager).
        pub signer: String,
        /// `cover`, `revoke`, `hold`, `release` or `interrupt_running`.
        pub action: String,
        pub interrupt_running: Option<bool>,
        /// A host principal's: the `seq` of its `host_sender_revoke`.
        pub revoke_seq: Option<u64>,
        /// A fresh UUID v4: the record's identity, kept before it is sent.
        pub record_id: String,
        /// Milliseconds since the epoch (orders covers by `(issued_at,
        /// record_id)`).
        pub issued_at: u64,
        /// `about.integration_id`: Auth's client id (`i-…`).
        pub integration_id: Option<String>,
        /// `about.by`: a label of 1 to 32 characters of `[a-z_]`; display
        /// only (an unknown value is accepted).
        pub by: String,
    }
}

data_enum! {
    /// A record against a device list (`verify_control_record`, I.5.4).
    pub enum ControlCheckInfo {
        /// Signed by a key allowed to sign it: the verified `signer`
        /// (`service:<id>` for the principal's own key, from the entry at
        /// `key_seq`; `member:<device_id>` for a current native manager), at
        /// the list's `head`.
        Valid {
            signer: String,
            key_seq: Option<u64>,
            head: LogHead,
        },
        /// Not verifiable yet (`principal_unknown`, `signer_unknown`,
        /// `revoke_not_in_list`): keep it and verify again after every
        /// device-list advance.
        Pending { reason: String },
        /// Refused against this list (`wrong_account`, `bad_signature`,
        /// `key_mismatch`, `signer_not_allowed`, `removed_manager`,
        /// `host_key_signed`, `not_a_service`, `not_a_revoke`): keep it as
        /// evidence.
        Refused { reason: String },
    }
}

unit_enum! {
    /// An application result (I.5.8): of a record, or of one effect.
    pub enum ControlResultKind {
        /// This record put the effect in force on this host.
        Applied,
        /// The host already had it in force (for the revocation: "already
        /// in force on this host", decision 8).
        Duplicate,
        /// Not in force yet; apply the record again later.
        Pending,
        /// Not in force, and never from this record.
        Refused,
    }
}

unit_enum! {
    /// One effect a record carries (I.5.8).
    pub enum ControlEffectKind {
        /// The principal's revocation.
        Revocation,
        /// The interrupt for that revocation.
        Interrupt,
        Hold,
        Release,
        Cover,
    }
}

record! {
    /// One effect's result.
    pub struct ControlEffectResult {
        pub effect: ControlEffectKind,
        pub result: ControlResultKind,
    }
}

data_enum! {
    /// What the host does in the transaction that applies a record (I.5.5).
    /// Principals are named in full (`service:<id>`, `host:<host_id>`).
    pub enum ControlHostAction {
        /// Refuse the service's requests, fence it, cancel its unstarted
        /// tasks.
        Revoke { principal: String },
        /// An interrupt intent for each started task of `principal`
        /// admitted before `revocation` (the revoking record's `record_id`,
        /// or a host principal's `revoke_seq` in decimal).
        Interrupt {
            principal: String,
            revocation: String,
        },
        /// Hold its unstarted tasks.
        Hold { principal: String },
        /// Let them run again.
        Release { principal: String },
        /// Its future tasks are delegated under `origin`'s gate, from the
        /// feed `feed_id`.
        Cover {
            principal: String,
            origin: String,
            feed_id: String,
        },
    }
}

record! {
    /// What `ControlStateHandle::apply` did with one record.
    pub struct ControlApplied {
        /// The record's result: `applied` when any effect is, `duplicate`
        /// when every effect is, else `pending` or `refused`. Read
        /// `effects`, not only this.
        pub result: ControlResultKind,
        /// Every effect the record carries, with its result.
        pub effects: Vec<ControlEffectResult>,
        /// What the host does, in the same transaction.
        pub actions: Vec<ControlHostAction>,
        /// Keep the record as evidence and alert (I.5.4): it failed
        /// verification, or it reuses a `record_id` of the same principal
        /// with another body (a stop still applies then; see `effects`).
        pub evidence: bool,
    }
}

record! {
    /// Where a record was read: its feed's Station `origin` and `feed_id`,
    /// and its position (`feed_seq`). None over a channel. A record counts
    /// as read at its own feed's position only when its body names the
    /// same `origin` and `feed_id`.
    pub struct ControlFeedPos {
        pub origin: String,
        pub feed_id: String,
        pub feed_seq: u64,
    }
}

// ---------------------------------------- Station calls and acknowledgments

record! {
    /// The verified association of the link a host's call arrived on
    /// (I.5.8, "Which host is calling"): the account and its root
    /// (`genesis_hash`, lowercase hex), the host and its trust generation,
    /// and the Station's id of the authenticated connection (1 to 128
    /// characters of `[A-Za-z0-9._:-]`). The Station takes it from its
    /// authenticated link, never from the call.
    pub struct LinkAssociationInfo {
        pub account_id: String,
        pub genesis_hash: String,
        pub host_id: String,
        pub host_trust_gen: u64,
        pub connection_id: String,
    }
}

data_enum! {
    /// A report the Station owes the Portal, keyed by integration. The
    /// Portal's HTTP body is Auth/Portal's (`platform.md`: `state` is the
    /// variant's name, with `host` and `recordId`, or `outcome` and
    /// `pendingHosts`, and `reportId`).
    pub enum StationReport {
        /// The revocation is in force on `host`, as the result for
        /// `record_id` said first.
        RevocationApplied {
            integration_id: String,
            host: String,
            record_id: String,
        },
        /// The revocation is done: `outcome` `all_applied` (no pending
        /// host) or `deadline_passed` (the hosts that didn't confirm,
        /// sorted, never none).
        Revoked {
            integration_id: String,
            outcome: String,
            pending_hosts: Vec<String>,
        },
    }
}

record! {
    /// A report, with its `report_id` (the Portal's `reportId`). Send it
    /// only as the committed state's `pending_reports()` offers it (in the
    /// order its principal's reports were made, never while reporting is
    /// stopped), until it is settled: confirmed, refused, or dropped by a
    /// resume under another report client ID.
    pub struct ReportIntentInfo {
        pub report_id: String,
        pub report: StationReport,
        /// Sorted.
        pub not_before: Vec<String>,
    }
}

data_enum! {
    /// An operator alert a ledger transition raises, once (the ledger keeps
    /// what it is about: raise it again from `refused_reports`,
    /// `stopped_client_id` and `dropped_reports` after a restart if you may
    /// have lost it).
    pub enum LedgerAlertInfo {
        /// The Portal refused this report for good: done, never sent again.
        ReportRefused { report_id: String },
        /// The Portal refused the reports of the report client `client_id`
        /// (`403`): every report is held, none sent, until a resume.
        ReportingStopped { client_id: String },
        /// Reporting resumed under another report client ID than
        /// `client_id`, the stopped one (another Station at Auth): each
        /// report pending then, `dropped`, is done unsent; every revocation
        /// reports on as usual.
        ReportsDropped {
            client_id: String,
            dropped: Vec<String>,
        },
    }
}

unit_enum! {
    /// What a Station does with the Portal's answer to a report
    /// (`report_answer`; the classes are Auth/Portal's).
    pub enum ReportAnswerKind {
        /// `200` (a repeat's recorded `200` too): `confirm`.
        Confirm,
        /// Send the same report again later, with backoff: a network error
        /// or timeout, a 5xx, `408`, `429` (after `Retry-After`), `401`
        /// (after refreshing the `station.report` token).
        Retry,
        /// Final, with an operator alert: `refuse`. Never follow a 3xx.
        Refuse,
        /// `403`: `stop_reporting` under the Station's report client ID (one
        /// alert; every report held until `resume_reporting`).
        StopReporting,
    }
}

record! {
    /// One record of a control feed at its position. `record_json` is the
    /// record's JSON text: for a builder, a record the control parser
    /// accepts (a Station serves only what it validated at intake); as
    /// decoded, the value the Station sent, of any JSON type (judge it with
    /// `parse_control_record`, and keep one it refuses as evidence).
    pub struct RelayFeedRecord {
        pub feed_seq: u64,
        pub record_json: String,
    }
}

record! {
    /// One feed's head announcement (I.5.2).
    pub struct RelayFeedHead {
        pub origin: String,
        pub feed_id: String,
        pub head: u64,
        /// The Station's clock, ms since the epoch (I.6.5).
        pub station_time: u64,
    }
}

data_enum! {
    /// One result of a `control_ack` (I.5.8): a record's, or a host
    /// sender's device-list revoke entry's, per effect.
    pub enum RelayAckResult {
        Record {
            record_id: String,
            effects: Vec<ControlEffectResult>,
        },
        Entry {
            seq: u64,
            entry_hash: String,
            applied_seq: u64,
            effects: Vec<ControlEffectResult>,
        },
    }
}

record! {
    /// A `control_ack`: the host's scan `cursor` in the feed
    /// `(origin, feed_id)` and its durable per-effect results. The account,
    /// root, host and trust generation are the host's claim, refused when
    /// they aren't its link's.
    pub struct ControlAckInfo {
        pub account_id: String,
        pub genesis_hash: String,
        pub host_id: String,
        pub host_trust_gen: u64,
        pub origin: String,
        pub feed_id: String,
        pub cursor: u64,
        pub results: Vec<RelayAckResult>,
    }
}

data_enum! {
    /// A host's call to its Station, as `relay_decode_to_station` reads it.
    pub enum RelayToStation {
        ControlSync {
            origin: String,
            feed_id: Option<String>,
            after: u64,
        },
        ControlAck { ack: ControlAckInfo },
        MembershipFetch { after: u64 },
    }
}

unit_enum! {
    /// Why a Station refused a host's call on the link (`code`): exactly
    /// `forbidden` in this version.
    pub enum RelayRefusalCode {
        /// Not authorized on this link: another account's feed or device
        /// list, or an ack whose claimed association isn't the link's.
        Forbidden,
    }
}

data_enum! {
    /// A Station's message to a host, as `relay_decode_to_host` reads it.
    /// A refusal is an authorization failure on the link, never a page or
    /// an acknowledgment: advance nothing on it, open no gate, complete or
    /// correlate no request, and keep the link's synchronization gates
    /// closed while the association is repaired and resynchronized.
    pub enum RelayToHost {
        ControlSyncResult {
            origin: String,
            feed_id: String,
            head: u64,
            station_time: u64,
            records: Vec<RelayFeedRecord>,
        },
        Heads {
            feeds: Vec<RelayFeedHead>,
            membership: LogHead,
        },
        MembershipFetchResult {
            head: LogHead,
            entries: Vec<String>,
        },
        /// `control_sync_refused`: the Station refused this link's
        /// `control_sync`.
        ControlSyncRefused { code: RelayRefusalCode },
        /// `membership_fetch_refused`.
        MembershipFetchRefused { code: RelayRefusalCode },
        /// `control_ack_refused`.
        ControlAckRefused { code: RelayRefusalCode },
    }
}
