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
//! This module parses and builds the object only: what holds for the record
//! alone. Who may sign which action, against which key of the device list,
//! is the verifier's (I.5.4); applying it is the host's (I.5.5).
pub mod record;

pub use record::{
    CONTROL_TYPE, ControlAbout, ControlAction, ControlBody, ControlError, ControlFeed,
    ControlPrincipal, ControlRecord, ControlSigner, KNOWN_BY, MAX_BY_CHARS, build_control,
};
