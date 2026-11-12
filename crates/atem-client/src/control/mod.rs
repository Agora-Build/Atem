//! Control records (delegated host-work design I.5): signed stops of a
//! principal that a host applies to the delegated work it holds for it.
//!
//! A record is a signed object in R9.1's one form, `{"body":{…},"sig"}`,
//! signed over `enc(["atem-host-work-control-v1", jcs(body)])`
//! ([`record`]). It is about a **service** (`service:<id>`), carried by the
//! control feed of the Station that holds its key (`origin`, `feed_id`), or
//! about a **host** sender (`host:<host_id>`), where the only record is a
//! native manager's later `interrupt_running` after a device-list revoke,
//! bound to no feed (II.3.1).
//!
//! [`record`] parses and builds the object: what holds for the record
//! alone. [`verify`] checks who may sign which action, against which key of
//! the device list (I.5.4). [`state`] applies it to a host's control state
//! and gives its per-effect application results (I.5.5, I.5.8); carrying
//! out the actions is the host's. [`relay`] is the wire of a host's calls to
//! its Station (I.5.8): the feed, its heads, the host's acknowledgments of
//! per-effect results, and its own device-list fetch. [`ledger`] is the
//! Station's reference side of those acknowledgments: what each covered host
//! has in force, the durable, retryable reports it owes the Portal, and the
//! re-sign alerts (I.5.4, I.5.8).
pub mod ledger;
pub mod record;
pub mod relay;
pub mod state;
pub mod verify;

pub use ledger::{
    AckLedger, AckRefusal, LedgerAlert, LedgerTransition, LinkAssociation, REVOCATION_DEADLINE_MS,
    REVOCATION_START_SLACK_MS, RecordRefusal, Report, ReportAnswer, ReportIntent, RevokedOutcome,
};
pub use record::{
    CONTROL_TYPE, ControlAbout, ControlAction, ControlBody, ControlError, ControlFeed,
    ControlPrincipal, ControlRecord, ControlSigner, KNOWN_BY, MAX_BY_CHARS, build_control,
    control_signing_input, control_with_signature, principal_key_of,
};
pub use relay::{
    AckResult, CallRefused, ControlAck, ControlSync, ControlSyncResult, EntryRef, FeedEntry,
    FeedHead, Heads, MembershipFetch, MembershipFetchResult, RefusalCode, RefusedCall, RelayError,
    ToHost, ToStation,
};
pub use state::{
    ApplicationResult, Applied, ControlState, EffectKind, EffectResult, FeedPos, HostAction,
    Transition,
};
pub use verify::{
    ControlCheck, PendingReason, RefusalReason, VerifiedControl, VerifiedSigner, verify_control,
};
