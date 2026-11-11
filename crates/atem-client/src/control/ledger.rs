//! The Station's reference acknowledgment ledger (delegated host-work design
//! I.5.8, "Acknowledgment" and "Delivery progress is not application"; I.5.4,
//! the re-sign alerts; the contract is `designs/protocol/atem-host-work-v1.md`
//! §11.4, "Acknowledgments" and "Reports").
//!
//! [`AckLedger`] is a Station's side of its hosts' [`ControlAck`]s, for one
//! device list (an account and its root) at one Station (its exact `origin`):
//! which covered hosts have each revocation in force, the per-host and final
//! reports the Station owes the Portal, and the native-signed records not yet
//! in force on every host they cover. Like [`crate::push::RelayLedger`] it is
//! sans-I/O, pure and deterministic: no clock (`now_ms` is a parameter), no
//! storage and no HTTP. The Station owns those; the ledger makes the boundary
//! between them safe.
//!
//! **A transition never changes the ledger it is called on.**
//! [`AckLedger::record`], [`AckLedger::ack`], [`AckLedger::tick`],
//! [`AckLedger::confirm`], [`AckLedger::refuse`],
//! [`AckLedger::stop_reporting`] and [`AckLedger::resume_reporting`] return
//! a [`LedgerTransition`]: the next ledger, the report intents the
//! transition made and the operator alerts it raised. The next ledger holds
//! every intent not yet settled (confirmed, refused or dropped), so the
//! Station persists `next`'s [`AckLedger::to_json`] in one transaction,
//! before any HTTP, and adopts `next` only once that committed. What to send
//! is always [`AckLedger::pending_reports`] of the adopted ledger, never the
//! transition's intents: those are what the call made, sent or held (while
//! reporting is stopped they are held, and nothing is sent), never an
//! outbox. A crash or a failed save before the commit loses nothing: the
//! host resends its ack, and the same transition on the same ledger gives
//! the same next ledger and the same intents, their `report_id`s included. Transitions of one ledger are
//! serialized, each from the latest committed state (two replicas may load
//! the same state; one commits, and the other starts again from the new one).
//!
//! **Delivery.** After a commit the Station sends
//! [`AckLedger::pending_reports`], in order, to the Portal
//! (`POST /api/v1/stations/reports`, the `report_id` as `reportId`), and
//! acts on each answer by its class ([`ReportAnswer::of_status`],
//! Auth/Portal's): `200` (a repeated `reportId`'s recorded `200` included)
//! is [`AckLedger::confirm`]; a network error, a timeout, a 5xx, a `408`, a
//! `429` (after its `Retry-After`) or a `401` (after refreshing the token)
//! is sent again later with the same `report_id` and body, after a restart
//! too (`pending_reports` offers every report until it is settled); a final
//! refusal (`400`, `404`, `409`, `413`, `415`, any other 4xx) is
//! [`AckLedger::refuse`]: done, never sent again, and an operator alert; a
//! `403` is [`AckLedger::stop_reporting`] under the Station's report client
//! ID: every report held, none sent, one alert, until
//! [`AckLedger::resume_reporting`] (the same ID keeps every report; another
//! ID than the stop's, another Station at Auth as Atem reads "start fresh",
//! drops the reports pending then, and every revocation reports on as
//! usual). Each of those is a transition the Station commits like any
//! other.
//!
//! **Order.** Reports of one principal go to the Portal in the order they
//! were made: [`AckLedger::pending_reports`] offers a report only once every
//! report of the same principal made before it is settled (confirmed,
//! refused or dropped), so one at a time per principal. As a consequence a
//! `revoked` report goes after the per-host reports made before it (those
//! its `not_before` names), so the Portal never sees `all_applied` ahead of
//! a covered host's `revocation_applied` (but one dropped by a resume under
//! another report client ID, which is settled unsent), and a host's report
//! made after the final never goes before it.
//!
//! **What counts** (I.5.8; plan decision 8).
//! - Only an effect result of `applied` or `duplicate` counts: both say the
//!   effect is in force on that host. The scan cursor never counts, nor do
//!   `pending` and `refused`.
//! - Counts are per host and per effect of a principal: its revocation, and
//!   the interrupt for that revocation (for a host principal, per
//!   `revoke_seq`), each once per host, through whichever record first said
//!   so. An interrupt never counts as the revocation.
//! - Only `revoke` and `interrupt_running` records are tracked. A `cover`,
//!   `hold` or `release` makes no report and no alert, so results about
//!   them, and about a host sender's device-list revoke (an entry, which
//!   needs no re-signing), are accepted and count nothing.
//! - Counts come from the link's verified host, never from the ack's claim,
//!   and only a covered host is reported.
//!
//! **Reports** (keyed by integration, as the Portal's report API is). A
//! service's revocation starts at the Station's own `revoke` (signed with the
//! service key: the Portal revoked the integration), whose `record` fixes the
//! integration (`about.integration_id`), the covered hosts and the
//! revocation's time; a later revoke of the same principal (a re-signed copy,
//! a snapshot after a reset) changes none of them. A native revoke appended to
//! the feed is counted, and reported once the Station's own revoke is
//! recorded.
//! - `revocation_applied{integration_id, host, record_id}`: once per covered
//!   host, at its first `applied` or `duplicate` for the revocation, naming the
//!   record whose result said so. A host that applied it after the deadline
//!   is still reported: the report is true.
//! - `revoked{integration_id, outcome, pending_hosts}`: once per revocation:
//!   `all_applied`, with no pending host, when every covered host has it in
//!   force; else `deadline_passed`, with the hosts that didn't confirm (never
//!   none), [`REVOCATION_DEADLINE_MS`] after the revocation's own time
//!   (`revoked_at_ms`, persisted), never after a restart's. An ack or a
//!   record is applied after any deadline its `now_ms` has passed, so the
//!   outcome depends on time, never on when the Station ticked; an own
//!   revoke recorded after its own deadline is final at once.
//!
//! **Report ids** come from the report's identity, never from time, order
//! or a counter: `<kind>:<hex SHA-256 of enc([STATION_REPORT_ID, kind,
//! account_id, genesis_hash (32 bytes), principal, integration_id,
//! host])>`, without the host for `revoked`, so a retry, a restart or a
//! replica gives the same id with the same body. Each fits the Portal's 1 to
//! 128 characters of `[A-Za-z0-9._:-]`. Neither the record a
//! `revocation_applied` names nor a `revoked`'s outcome is part of its id: a
//! revocation has one `revoked` and one `revocation_applied` per host, so if
//! two Station histories ever diverged (transitions not serialized), the
//! Portal's `report_id_reused` keeps the first and nothing counts twice.
//!
//! **Which host acknowledges** (I.5.8, "Which host is calling").
//! [`AckLedger::ack`] takes the complete verified association of the link the
//! ack arrived on ([`LinkAssociation`]: account, root, host, trust generation
//! and connection), never a host id alone, and refuses an ack whose claims
//! (account, root, host, trust generation) differ from it, or that belongs to
//! another device list or Station. The ack names no connection (no call
//! can), so the connection is the Station's to verify; an association
//! without one is refused as incomplete.
//!
//! **Re-sign alerts** (I.5.4). [`AckLedger::resign_alerts`] lists the
//! native-signed records not yet in force, for every effect they carry, on
//! every host they cover. Astation alerts the owner to re-sign those whose
//! signer was removed. A host that has an effect in force through another
//! record (the original of a re-signed copy) is done for it.
use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value, json};

use crate::canonical::MAX_SAFE_INTEGER;
use crate::domain::STATION_REPORT_ID;
use crate::encoding::Hash32;
use crate::error::{Error, Result};
use crate::membership::MAX_HOSTS;
use crate::membership::entry::id_ok;
use crate::session::wire::is_uuid_v4;
use crate::station_route::normalize_relay;

use super::record::{ControlAction, ControlPrincipal, ControlRecord, ControlSigner};
use super::relay::{AckResult, ControlAck, RelayError};
use super::state::{ApplicationResult, EffectKind};

/// How long after a revocation the Station reports it `deadline_passed`:
/// 24 hours, by which time every task has passed its deadline (I.4.4).
pub const REVOCATION_DEADLINE_MS: u64 = 24 * 60 * 60 * 1000;

/// `account_id`: 1 to this many bytes, as the device list's (§R9.2).
const MAX_ACCOUNT_ID_BYTES: usize = 128;

/// The report kinds, as the Portal names them (`state`).
const APPLIED: &str = "revocation_applied";
const REVOKED: &str = "revoked";

/// The verified association of the link an ack arrived on: the account and
/// its root, the host and its trust generation, and the connection (I.5.8,
/// "Which host is calling"). The Station takes it from the authenticated
/// link (for a call through Astation's `:8080` or a carrier-A link, the
/// authenticated transport's), never from the ack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkAssociation {
    pub account_id: String,
    pub genesis_hash: Hash32,
    pub host_id: String,
    pub host_trust_gen: u64,
    /// The Station's id of the authenticated connection: 1 to 128
    /// characters of `[A-Za-z0-9._:-]`.
    pub connection_id: String,
}

impl LinkAssociation {
    /// Every part present and in its grammar.
    fn complete(&self) -> bool {
        account_ok(&self.account_id)
            && id_ok(&self.host_id)
            && (1..=MAX_SAFE_INTEGER).contains(&self.host_trust_gen)
            && id_ok(&self.connection_id)
    }
}

/// A `revoked` report's outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokedOutcome {
    /// Every covered host has the revocation in force.
    AllApplied,
    /// The deadline passed with hosts that didn't confirm.
    DeadlinePassed,
}

impl RevokedOutcome {
    /// The wire name.
    pub fn code(self) -> &'static str {
        match self {
            RevokedOutcome::AllApplied => "all_applied",
            RevokedOutcome::DeadlinePassed => "deadline_passed",
        }
    }

    /// From the wire name, exactly.
    pub fn from_code(code: &str) -> Option<Self> {
        [RevokedOutcome::AllApplied, RevokedOutcome::DeadlinePassed]
            .into_iter()
            .find(|outcome| outcome.code() == code)
    }
}

/// What the Station does with the Portal's answer to a report
/// (`POST /api/v1/stations/reports`; the classes are Auth/Portal's,
/// 2026-11-10). A network error or a timeout has no status: it is
/// [`ReportAnswer::Retry`] (never pass a "no response" sentinel such as 0
/// to [`ReportAnswer::of_status`]: it is no status the Portal answers
/// with, so it is final). A 3xx is never followed: following it would
/// carry the `station.report` bearer wherever it points.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportAnswer {
    /// `200`, the recorded `200` of a repeated `reportId` included:
    /// [`AckLedger::confirm`].
    Confirm,
    /// Send the same report (the same `report_id` and body) again later,
    /// with backoff: a 5xx (`503` and unknown ones too); `408`, like a
    /// timeout; `429`, after its `Retry-After`; `401`, after refreshing the
    /// `station.report` token.
    Retry,
    /// Final, with an operator alert: [`AckLedger::refuse`]. `400`, `404`,
    /// `409` (`report_id_reused`, `invalid_state`), `413`, `415`, every
    /// other 4xx but `401`, `403`, `408` and `429`, and a status the Portal
    /// never answers with (1xx, 3xx, a 2xx other than `200`).
    Refuse,
    /// `403`: stop reporting under this report client ID, one alert:
    /// [`AckLedger::stop_reporting`] (every report held until a resume).
    StopReporting,
}

impl ReportAnswer {
    /// The class of an HTTP status.
    pub fn of_status(status: u16) -> Self {
        match status {
            200 => ReportAnswer::Confirm,
            401 | 408 | 429 | 500..=599 => ReportAnswer::Retry,
            403 => ReportAnswer::StopReporting,
            _ => ReportAnswer::Refuse,
        }
    }

    /// `confirm`, `retry`, `refuse` or `stop_reporting`.
    pub fn code(self) -> &'static str {
        match self {
            ReportAnswer::Confirm => "confirm",
            ReportAnswer::Retry => "retry",
            ReportAnswer::Refuse => "refuse",
            ReportAnswer::StopReporting => "stop_reporting",
        }
    }
}

/// An operator alert a transition raises, once. The ledger keeps what it
/// is about ([`AckLedger::refused_reports`],
/// [`AckLedger::stopped_client_id`], [`AckLedger::dropped_reports`] with
/// [`AckLedger::dropped_client_ids`]), so a
/// Station that died between the commit and the alert raises it again from
/// the state at start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerAlert {
    /// The Portal refused this report for good: it is done, never sent
    /// again.
    ReportRefused { report_id: String },
    /// The Portal refused the reports of the report client `client_id`
    /// (`403`): every report is held, none is sent, until a resume.
    ReportingStopped { client_id: String },
    /// Reporting resumed under another report client ID than `client_id`,
    /// the one that was stopped (another Station at Auth): each report
    /// pending then, `dropped` (in delivery order), is done unsent; every
    /// revocation reports on as usual.
    ReportsDropped {
        client_id: String,
        dropped: Vec<String>,
    },
}

impl LedgerAlert {
    /// `{"kind":"report_refused","report_id":"…"}`,
    /// `{"kind":"reporting_stopped","client_id":"…"}` or
    /// `{"kind":"reports_dropped","client_id":"…","dropped":[…]}`.
    pub fn to_json(&self) -> Value {
        match self {
            LedgerAlert::ReportRefused { report_id } => {
                json!({"kind": "report_refused", "report_id": report_id})
            }
            LedgerAlert::ReportingStopped { client_id } => {
                json!({"kind": "reporting_stopped", "client_id": client_id})
            }
            LedgerAlert::ReportsDropped { client_id, dropped } => {
                json!({"kind": "reports_dropped", "client_id": client_id, "dropped": dropped})
            }
        }
    }
}

/// A report to the Portal, keyed by integration (the HTTP shape is Auth/
/// Portal's, `platform.md`: `state` is [`Report::kind`], with `host` and
/// `recordId`, or `outcome` and `pendingHosts`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Report {
    /// The revocation is in force on `host`, as the result for `record_id`
    /// said first.
    RevocationApplied {
        integration_id: String,
        host: String,
        record_id: String,
    },
    /// The revocation is done: `pending_hosts` (sorted) is empty for
    /// `all_applied` and not for `deadline_passed`.
    Revoked {
        integration_id: String,
        outcome: RevokedOutcome,
        pending_hosts: Vec<String>,
    },
}

impl Report {
    /// `revocation_applied` or `revoked`.
    pub fn kind(&self) -> &'static str {
        match self {
            Report::RevocationApplied { .. } => APPLIED,
            Report::Revoked { .. } => REVOKED,
        }
    }

    pub fn integration_id(&self) -> &str {
        match self {
            Report::RevocationApplied { integration_id, .. }
            | Report::Revoked { integration_id, .. } => integration_id,
        }
    }

    /// `{"kind":"revocation_applied","integration_id","host","record_id"}`
    /// or `{"kind":"revoked","integration_id","outcome","pending_hosts"}`.
    pub fn to_json(&self) -> Value {
        // Keys in sorted order, whatever `serde_json::Map` preserves.
        let mut o = Map::new();
        match self {
            Report::RevocationApplied {
                integration_id,
                host,
                record_id,
            } => {
                o.insert("host".into(), json!(host));
                o.insert("integration_id".into(), json!(integration_id));
                o.insert("kind".into(), json!(APPLIED));
                o.insert("record_id".into(), json!(record_id));
            }
            Report::Revoked {
                integration_id,
                outcome,
                pending_hosts,
            } => {
                o.insert("integration_id".into(), json!(integration_id));
                o.insert("kind".into(), json!(REVOKED));
                o.insert("outcome".into(), json!(outcome.code()));
                o.insert("pending_hosts".into(), json!(pending_hosts));
            }
        }
        Value::Object(o)
    }

    /// A report as [`Report::to_json`] writes it: its fields, their
    /// grammars, and the outcome's rule on `pending_hosts`.
    fn read(value: &Value) -> Result<Self> {
        let what = "ack ledger report";
        let kind = value
            .get("kind")
            .and_then(Value::as_str)
            .ok_or(Error::Malformed(what))?;
        let integration = |o: &Map<String, Value>| {
            o["integration_id"]
                .as_str()
                .filter(|id| id_ok(id))
                .map(str::to_owned)
                .ok_or(Error::Malformed("ack ledger report integration_id"))
        };
        match kind {
            APPLIED => {
                let o = fields(
                    value,
                    &["kind", "integration_id", "host", "record_id"],
                    &[],
                    what,
                )?;
                Ok(Report::RevocationApplied {
                    integration_id: integration(o)?,
                    host: host(&o["host"], "ack ledger report host")?,
                    record_id: record_id(&o["record_id"], "ack ledger report record_id")?,
                })
            }
            REVOKED => {
                let o = fields(
                    value,
                    &["kind", "integration_id", "outcome", "pending_hosts"],
                    &[],
                    what,
                )?;
                let outcome = o["outcome"]
                    .as_str()
                    .and_then(RevokedOutcome::from_code)
                    .ok_or(Error::Malformed("ack ledger report outcome"))?;
                let pending_hosts: Vec<String> =
                    host_set(&o["pending_hosts"], "ack ledger report pending_hosts")?
                        .into_iter()
                        .collect();
                if pending_hosts.is_empty() != (outcome == RevokedOutcome::AllApplied) {
                    return Err(Error::Malformed("ack ledger report pending_hosts"));
                }
                Ok(Report::Revoked {
                    integration_id: integration(o)?,
                    outcome,
                    pending_hosts,
                })
            }
            _ => Err(Error::Malformed("ack ledger report kind")),
        }
    }
}

/// A report the Station owes the Portal, with its `report_id`. Send it only
/// as [`AckLedger::pending_reports`] of the committed state offers it (in
/// the order its principal's reports were made, never while reporting is
/// stopped), until it is settled: [`AckLedger::confirm`]ed,
/// [`AckLedger::refuse`]d or dropped by a resume under another report
/// client ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportIntent {
    pub report_id: String,
    pub report: Report,
    /// Sorted.
    pub not_before: Vec<String>,
}

impl ReportIntent {
    /// `{"not_before":[…],"report":{…},"report_id":"…"}`: the same bytes
    /// (as `jcs`) for the same `report_id`, however often it is made.
    pub fn to_json(&self) -> Value {
        let mut o = Map::new();
        o.insert("not_before".into(), json!(self.not_before));
        o.insert("report".into(), self.report.to_json());
        o.insert("report_id".into(), json!(self.report_id));
        Value::Object(o)
    }
}

/// What a transition gives: the next ledger (persist its
/// [`AckLedger::to_json`] and adopt it once committed), `made`, what the
/// call made (`next` holds each until it is settled), and the operator
/// alerts it raised (raise them once it committed). Send the committed
/// state's [`AckLedger::pending_reports`], never `made`: a report made
/// while reporting is stopped is held, and one made after an earlier report
/// of its principal waits for it. After a restart, send the committed
/// state's `pending_reports`, never stored transitions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerTransition {
    pub next: AckLedger,
    pub made: Vec<ReportIntent>,
    pub alerts: Vec<LedgerAlert>,
}

/// Why [`AckLedger::record`] refuses a record. `code()` is a stable name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordRefusal {
    /// The record's account or root isn't this ledger's.
    OtherAccount,
    /// A service's record of another Station's feed.
    OtherStation,
    /// Another body under a `record_id` this ledger tracks: a result naming
    /// that id would be ambiguous, so the Station doesn't serve it.
    RecordIdReused,
    /// `revoked_at_ms` out of range, or the covered hosts out of their
    /// grammar or more than [`MAX_HOSTS`].
    Malformed(&'static str),
}

impl RecordRefusal {
    pub fn code(&self) -> &'static str {
        match self {
            RecordRefusal::OtherAccount => "other_account",
            RecordRefusal::OtherStation => "other_station",
            RecordRefusal::RecordIdReused => "record_id_reused",
            RecordRefusal::Malformed(_) => "malformed",
        }
    }
}

impl std::fmt::Display for RecordRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecordRefusal::Malformed(what) => write!(f, "malformed: {what}"),
            other => f.write_str(other.code()),
        }
    }
}

impl std::error::Error for RecordRefusal {}

/// Why [`AckLedger::ack`] refuses an ack: refused whole, nothing of it
/// counted. `code()` is a stable name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AckRefusal {
    /// The link's association is incomplete: an account, host or connection
    /// missing or out of grammar, or no trust generation.
    IncompleteLink,
    /// Not an ack the relay reader accepts (one built in memory).
    Malformed(RelayError),
    /// The ack's account, root, host or trust generation isn't its link's.
    NotTheLink,
    /// The link belongs to another device list than this ledger's.
    OtherAccount,
    /// The ack is about another Station's feed.
    OtherStation,
    /// A result names a record this ledger tracks with effects that record
    /// doesn't carry.
    NotTheRecord(String),
}

impl AckRefusal {
    pub fn code(&self) -> &'static str {
        match self {
            AckRefusal::IncompleteLink => "incomplete_link",
            AckRefusal::Malformed(_) => "malformed",
            AckRefusal::NotTheLink => "not_the_link",
            AckRefusal::OtherAccount => "other_account",
            AckRefusal::OtherStation => "other_station",
            AckRefusal::NotTheRecord(_) => "not_the_record",
        }
    }
}

impl std::fmt::Display for AckRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AckRefusal::Malformed(e) => write!(f, "malformed: {e}"),
            AckRefusal::NotTheRecord(id) => write!(f, "not the record: {id}"),
            other => f.write_str(other.code()),
        }
    }
}

impl std::error::Error for AckRefusal {}

/// The ledger (the module docs give the rules).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckLedger {
    /// This Station's exact origin.
    origin: String,
    /// The device list it belongs to.
    account_id: String,
    genesis_hash: Hash32,
    /// The `revoke` and `interrupt_running` records recorded, by
    /// `record_id`.
    records: BTreeMap<String, Tracked>,
    /// Service revocations, by principal (`service:<id>`): from the
    /// Station's own first revoke.
    revocations: BTreeMap<String, Revocation>,
    /// Each effect in force on a host, with the record whose result first
    /// said so.
    done: BTreeMap<Done, String>,
    /// The intents not yet settled, in the order they were made (the
    /// delivery order).
    pending: Vec<Pending>,
    /// The reports the Portal refused for good.
    refused: BTreeSet<String>,
    /// The reports a resume under another report client ID than the
    /// stop's dropped unsent, each with the report client ID it was dropped
    /// under (the stopped one).
    dropped: BTreeMap<String, String>,
    /// The report client ID the Portal refused (`403`): every report is
    /// held until a resume.
    stopped: Option<String>,
}

/// A tracked record.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Tracked {
    /// `service:<id>` or `host:<host_id>`.
    principal: String,
    /// A host principal's interrupt: the revocation it follows.
    revoke_seq: Option<u64>,
    /// The effects it carries, in `EffectKind::of`'s order.
    effects: Vec<EffectKind>,
    /// Signed by a native member (`member:<device_id>`): alerted until in
    /// force on every covered host.
    native: bool,
    /// The hosts it covers, as recorded.
    covered: BTreeSet<String>,
    /// SHA-256 of its body's `jcs`.
    digest: Hash32,
}

/// A service's revocation, as its first own revoke fixed it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Revocation {
    integration_id: String,
    revoked_at_ms: u64,
    covered: BTreeSet<String>,
    /// The `revoked` report made.
    outcome: Option<RevokedOutcome>,
}

/// An effect of a principal in force on a host.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Done {
    principal: String,
    effect: Counted,
    host: String,
}

impl Done {
    fn revocation(principal: &str, host: &str) -> Self {
        Done {
            principal: principal.to_owned(),
            effect: Counted::Revocation,
            host: host.to_owned(),
        }
    }
}

/// What is counted: a principal's revocation, or the interrupt for its
/// revocation (a host principal's at its `revoke_seq`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Counted {
    Revocation,
    Interrupt(Option<u64>),
}

/// An intent not yet settled, with the principal whose revocation it
/// reports.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Pending {
    principal: String,
    intent: ReportIntent,
}

impl AckLedger {
    /// The empty ledger of the device list `account_id`/`genesis_hash` at
    /// the Station `origin` (exact, as `normalize_relay` writes it).
    pub fn new(origin: &str, account_id: &str, genesis_hash: Hash32) -> Result<Self> {
        if normalize_relay(origin).as_deref() != Ok(origin) {
            return Err(Error::Malformed("ack ledger origin"));
        }
        if !account_ok(account_id) {
            return Err(Error::Malformed("ack ledger account_id"));
        }
        Ok(AckLedger {
            origin: origin.to_owned(),
            account_id: account_id.to_owned(),
            genesis_hash,
            records: BTreeMap::new(),
            revocations: BTreeMap::new(),
            done: BTreeMap::new(),
            pending: Vec::new(),
            refused: BTreeSet::new(),
            dropped: BTreeMap::new(),
            stopped: None,
        })
    }

    pub fn origin(&self) -> &str {
        &self.origin
    }

    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    pub fn genesis_hash(&self) -> Hash32 {
        self.genesis_hash
    }

    /// A record the Station stored in its feed, before it serves it, at
    /// `now_ms` (deadlines `now_ms` passed are applied first, as
    /// [`AckLedger::tick`] would). For the Station's own `revoke` (signed
    /// with the service key), the first of its principal starts the
    /// revocation: `revoked_at_ms` is when the Portal revoked the
    /// integration (the deadline's start) and `covered_hosts` the hosts its
    /// grant covered (a set); the hosts that have it in force already
    /// (through a native revoke) are reported at once, and a revocation
    /// recorded after its own deadline is final at once. For any other
    /// record `revoked_at_ms` is unused, and `covered_hosts` are the hosts
    /// its alert waits for. The same record again (a retried intake, a
    /// snapshot's re-issue) changes nothing; a `cover`, `hold` or `release`
    /// is not tracked.
    pub fn record(
        &self,
        rec: &ControlRecord,
        revoked_at_ms: u64,
        covered_hosts: &[String],
        now_ms: u64,
    ) -> std::result::Result<LedgerTransition, RecordRefusal> {
        if rec.account_id() != self.account_id || rec.genesis_hash() != self.genesis_hash {
            return Err(RecordRefusal::OtherAccount);
        }
        if rec.feed().is_some_and(|(origin, _)| origin != self.origin) {
            return Err(RecordRefusal::OtherStation);
        }
        if revoked_at_ms > MAX_SAFE_INTEGER {
            return Err(RecordRefusal::Malformed("revoked_at_ms"));
        }
        let covered: BTreeSet<String> = covered_hosts.iter().cloned().collect();
        if covered.len() > MAX_HOSTS || !covered.iter().all(|h| id_ok(h)) {
            return Err(RecordRefusal::Malformed("covered_hosts"));
        }
        let digest = Hash32::of(rec.object().jcs().as_bytes());
        if let Some(held) = self.records.get(rec.record_id())
            && held.digest != digest
        {
            return Err(RecordRefusal::RecordIdReused);
        }
        let mut next = self.clone();
        let mut intents = Vec::new();
        next.pass_deadlines(now_ms, &mut intents);
        if self.records.contains_key(rec.record_id()) {
            return Ok(next.with(intents));
        }
        let effects = EffectKind::of(rec.action());
        if !effects
            .iter()
            .any(|e| matches!(e, EffectKind::Revocation | EffectKind::Interrupt))
        {
            return Ok(next.with(intents));
        }

        let principal = rec.principal().name();
        let native = matches!(rec.signer(), ControlSigner::Member(_));
        let revoke_seq = match rec.action() {
            ControlAction::InterruptRunning { revoke_seq } => revoke_seq,
            _ => None,
        };
        let starts = !native
            && effects.contains(&EffectKind::Revocation)
            && !self.revocations.contains_key(&principal);
        next.records.insert(
            rec.record_id().to_owned(),
            Tracked {
                principal: principal.clone(),
                revoke_seq,
                effects,
                native,
                covered: covered.clone(),
                digest,
            },
        );
        if starts {
            // A service's record always names its integration (`record`).
            let integration_id = rec
                .about()
                .integration_id
                .clone()
                .ok_or(RecordRefusal::Malformed("about.integration_id"))?;
            next.revocations.insert(
                principal.clone(),
                Revocation {
                    integration_id,
                    revoked_at_ms,
                    covered: covered.clone(),
                    outcome: None,
                },
            );
            // Hosts that have it in force already, through a native revoke.
            for host in &covered {
                let first = next.done.get(&Done::revocation(&principal, host)).cloned();
                if let Some(record_id) = first {
                    next.report_applied(&principal, host, &record_id, &mut intents);
                }
            }
            next.finish_when_all_applied(&principal, &mut intents);
            // Recorded after its own deadline: final at once.
            next.pass_deadlines(now_ms, &mut intents);
        }
        Ok(next.with(intents))
    }

    /// An ack that arrived on the link whose verified association is
    /// `link`, at `now_ms` (deadlines `now_ms` passed are applied first, as
    /// [`AckLedger::tick`] would). Refused whole when its claims aren't the
    /// link's, it is another device list's or Station's, or a result names
    /// a tracked record with other effects than the record's.
    pub fn ack(
        &self,
        link: &LinkAssociation,
        ack: &ControlAck,
        now_ms: u64,
    ) -> std::result::Result<LedgerTransition, AckRefusal> {
        if !link.complete() {
            return Err(AckRefusal::IncompleteLink);
        }
        ack.check().map_err(AckRefusal::Malformed)?;
        if ack.account_id != link.account_id
            || ack.genesis_hash != link.genesis_hash
            || ack.host_id != link.host_id
            || ack.host_trust_gen != link.host_trust_gen
        {
            return Err(AckRefusal::NotTheLink);
        }
        if link.account_id != self.account_id || link.genesis_hash != self.genesis_hash {
            return Err(AckRefusal::OtherAccount);
        }
        if ack.origin != self.origin {
            return Err(AckRefusal::OtherStation);
        }

        // Every result checked before anything counts.
        let mut counts = Vec::new();
        for result in &ack.results {
            // A host sender's device-list revoke is no record.
            let AckResult::Record { record_id, effects } = result else {
                continue;
            };
            // Not tracked: a cover, hold or release, or no record of ours.
            let Some(tracked) = self.records.get(record_id) else {
                continue;
            };
            if !effects
                .iter()
                .map(|e| e.effect)
                .eq(tracked.effects.iter().copied())
            {
                return Err(AckRefusal::NotTheRecord(record_id.clone()));
            }
            for e in effects {
                if matches!(
                    e.result,
                    ApplicationResult::Applied | ApplicationResult::Duplicate
                ) {
                    counts.push((record_id.as_str(), tracked, e.effect));
                }
            }
        }

        let mut next = self.clone();
        let mut intents = Vec::new();
        next.pass_deadlines(now_ms, &mut intents);
        for (record_id, tracked, effect) in counts {
            next.count(tracked, effect, &link.host_id, record_id, &mut intents);
        }
        Ok(next.with(intents))
    }

    /// The time is `now_ms`: every revocation whose deadline passed gets
    /// its `revoked` report.
    pub fn tick(&self, now_ms: u64) -> LedgerTransition {
        let mut next = self.clone();
        let mut intents = Vec::new();
        next.pass_deadlines(now_ms, &mut intents);
        next.with(intents)
    }

    /// The Portal accepted the report `report_id` (`200`, or the recorded
    /// `200` of a repeat: [`ReportAnswer::Confirm`]). An id not pending
    /// changes nothing.
    pub fn confirm(&self, report_id: &str) -> LedgerTransition {
        let mut next = self.clone();
        next.pending.retain(|p| p.intent.report_id != report_id);
        next.with(Vec::new())
    }

    /// The Portal refused the report `report_id` for good
    /// ([`ReportAnswer::Refuse`]): it is done and never sent again (the
    /// reports waiting for it go once the others they wait for are
    /// settled), and the transition raises [`LedgerAlert::ReportRefused`]
    /// for the operator. An id not pending changes nothing and alerts
    /// nothing.
    pub fn refuse(&self, report_id: &str) -> LedgerTransition {
        if !self.pending.iter().any(|p| p.intent.report_id == report_id) {
            return self.unchanged();
        }
        let mut next = self.clone();
        next.pending.retain(|p| p.intent.report_id != report_id);
        next.refused.insert(report_id.to_owned());
        let mut t = next.with(Vec::new());
        t.alerts.push(LedgerAlert::ReportRefused {
            report_id: report_id.to_owned(),
        });
        t
    }

    /// The Portal refused the reports of the report client `client_id`,
    /// this Station's client at Auth (`403`,
    /// [`ReportAnswer::StopReporting`]): the ledger records the ID and holds
    /// every report, none sent ([`AckLedger::pending_reports`] is empty),
    /// until [`AckLedger::resume_reporting`]; counting and reports go on
    /// meanwhile. The transition raises [`LedgerAlert::ReportingStopped`]
    /// once. A ledger already stopped changes nothing, whatever the ID. A
    /// `client_id` out of grammar (1 to 128 characters of
    /// `[A-Za-z0-9._:-]`) is refused.
    pub fn stop_reporting(&self, client_id: &str) -> Result<LedgerTransition> {
        client(client_id)?;
        if self.stopped.is_some() {
            return Ok(self.unchanged());
        }
        let mut next = self.clone();
        next.stopped = Some(client_id.to_owned());
        let mut t = next.with(Vec::new());
        t.alerts.push(LedgerAlert::ReportingStopped {
            client_id: client_id.to_owned(),
        });
        Ok(t)
    }

    /// The Station reports again as the report client `client_id` (after a
    /// restart, say once an operator fixed its token; the built-in Station
    /// takes its ID from its configuration and always resumes). The ID is
    /// compared only here, at a resume after a `403` stop: a ledger not
    /// stopped changes nothing, whatever the ID (a change of report client
    /// without a stop changes nothing either). The same ID as the stop's
    /// clears the stop and keeps every report. Another ID than the stop's
    /// is, as Atem reads Auth/Portal's "start fresh", another Station at
    /// Auth (a removed Station registered again): the reports pending at
    /// this moment are dropped, done unsent ([`AckLedger::dropped_reports`]),
    /// and the transition raises [`LedgerAlert::ReportsDropped`] naming
    /// each; nothing else changes, so every revocation reports on as usual
    /// (a late host, its final), under the new ID. A `client_id` out of
    /// grammar is refused.
    pub fn resume_reporting(&self, client_id: &str) -> Result<LedgerTransition> {
        client(client_id)?;
        let Some(stopped) = &self.stopped else {
            return Ok(self.unchanged());
        };
        let mut next = self.clone();
        next.stopped = None;
        if stopped == client_id {
            return Ok(next.with(Vec::new()));
        }
        let dropped: Vec<String> = next.pending.drain(..).map(|p| p.intent.report_id).collect();
        next.dropped
            .extend(dropped.iter().map(|id| (id.clone(), stopped.clone())));
        let mut t = next.with(Vec::new());
        t.alerts.push(LedgerAlert::ReportsDropped {
            client_id: stopped.clone(),
            dropped,
        });
        Ok(t)
    }

    /// The reports the Portal refused for good (sorted).
    pub fn refused_reports(&self) -> Vec<String> {
        self.refused.iter().cloned().collect()
    }

    /// The reports a resume under another report client ID than the stop's
    /// dropped unsent (sorted): kept, like the refusals, so a Station that
    /// may have lost the alert raises it again.
    pub fn dropped_reports(&self) -> Vec<String> {
        self.dropped.keys().cloned().collect()
    }

    /// The report client ID each report of [`AckLedger::dropped_reports`]
    /// was dropped under (the stopped one), in the same order: one per
    /// dropped report, so an alert raised again at start names it.
    pub fn dropped_client_ids(&self) -> Vec<String> {
        self.dropped.values().cloned().collect()
    }

    /// The Portal refused this Station's reports: every report is held.
    pub fn reporting_stopped(&self) -> bool {
        self.stopped.is_some()
    }

    /// The report client ID the Portal refused, while reporting is stopped.
    pub fn stopped_client_id(&self) -> Option<&str> {
        self.stopped.as_deref()
    }

    /// What to send now, after a commit, a restart or a failed POST: for
    /// each principal, its earliest report not yet settled (confirmed,
    /// refused or dropped), when every report its `not_before` names is
    /// settled too, in delivery order. Reports of one principal thus go in
    /// the order they were made, one at a time. Nothing while reporting is
    /// stopped.
    pub fn pending_reports(&self) -> Vec<ReportIntent> {
        if self.stopped.is_some() {
            return Vec::new();
        }
        let waiting: BTreeSet<&str> = self
            .pending
            .iter()
            .map(|p| p.intent.report_id.as_str())
            .collect();
        // Reports of one principal go in the order they were made: only
        // the earliest unsettled one of each principal is offered. That
        // `not_before` is settled follows (those reports were made before),
        // and is checked as well.
        let mut ahead: BTreeSet<&str> = BTreeSet::new();
        let mut offered = Vec::new();
        for p in &self.pending {
            if !ahead.insert(p.principal.as_str()) {
                continue;
            }
            let ready = p
                .intent
                .not_before
                .iter()
                .all(|id| !waiting.contains(id.as_str()));
            if ready {
                offered.push(p.intent.clone());
            }
        }
        offered
    }

    /// The native-signed records not yet in force, for every effect they
    /// carry, on every host they cover (by `record_id`, sorted).
    pub fn resign_alerts(&self) -> Vec<String> {
        self.records
            .iter()
            .filter(|(_, t)| {
                t.native
                    && t.covered.iter().any(|host| {
                        t.effects.iter().any(|effect| {
                            Self::counted(t, *effect).is_some_and(|counted| {
                                !self.done.contains_key(&Done {
                                    principal: t.principal.clone(),
                                    effect: counted,
                                    host: host.clone(),
                                })
                            })
                        })
                    })
            })
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// The ledger's state: deterministic (keys sorted, sets sorted), read
    /// back exactly by [`AckLedger::from_json`].
    ///
    /// ```json
    /// {"v":1,"origin":"https://…","account_id":"…","genesis_hash":"<hex>",
    ///  "records":{"<record_id>":{"principal":"service:svc-1",
    ///    "effects":["revocation","interrupt"],"native":true,
    ///    "covered":["host-a"],"digest":"<hex>","revoke_seq"?:5}},
    ///  "revocations":{"service:svc-1":{"integration_id":"i-…",
    ///    "revoked_at_ms":…,"covered":[…],"outcome"?:"all_applied"}},
    ///  "done":[{"principal","effect","revoke_seq"?,"host","record_id"}],
    ///  "pending":[{"principal","report_id","report":{…},"not_before":[…]}],
    ///  "refused":["<report_id>"],"dropped":{"<report_id>":"<client id>"},
    ///  "stopped"?:"<report client id>"}
    /// ```
    pub fn to_json(&self) -> Value {
        let records: Map<String, Value> = self
            .records
            .iter()
            .map(|(id, t)| (id.clone(), t.to_json()))
            .collect();
        let revocations: Map<String, Value> = self
            .revocations
            .iter()
            .map(|(principal, r)| (principal.clone(), r.to_json()))
            .collect();
        let done: Vec<Value> = self
            .done
            .iter()
            .map(|(key, record_id)| key.to_json(record_id))
            .collect();
        let pending: Vec<Value> = self.pending.iter().map(Pending::to_json).collect();
        // Keys in sorted order, whatever `serde_json::Map` preserves.
        let mut o = Map::new();
        o.insert("account_id".into(), json!(self.account_id));
        o.insert("done".into(), Value::Array(done));
        o.insert("dropped".into(), json!(self.dropped));
        o.insert("genesis_hash".into(), json!(self.genesis_hash.to_hex()));
        o.insert("origin".into(), json!(self.origin));
        o.insert("pending".into(), Value::Array(pending));
        o.insert("records".into(), Value::Object(records));
        o.insert("refused".into(), json!(self.refused));
        o.insert("revocations".into(), Value::Object(revocations));
        if let Some(client_id) = &self.stopped {
            o.insert("stopped".into(), json!(client_id));
        }
        o.insert("v".into(), json!(1));
        Value::Object(o)
    }

    /// A ledger from [`AckLedger::to_json`], read strictly: exactly its
    /// fields, their types and grammars, sets sorted and unique, and its
    /// invariants: a revocation for exactly the principals with an own
    /// revoke recorded, every count of a tracked record and an effect it
    /// carries, `all_applied` exactly when every covered host has the
    /// revocation in force, each pending intent's `report_id` its
    /// report's, consistent with what it reports, and each refused or
    /// dropped report one the ledger made, no longer pending, and settled
    /// once (never both refused and dropped).
    pub fn from_json(value: &Value) -> Result<Self> {
        let o = fields(
            value,
            &[
                "v",
                "origin",
                "account_id",
                "genesis_hash",
                "records",
                "revocations",
                "done",
                "pending",
                "refused",
                "dropped",
            ],
            &["stopped"],
            "ack ledger",
        )?;
        if o["v"].as_u64() != Some(1) {
            return Err(Error::Malformed("ack ledger v"));
        }
        let origin = o["origin"]
            .as_str()
            .ok_or(Error::Malformed("ack ledger origin"))?;
        let account_id = o["account_id"]
            .as_str()
            .ok_or(Error::Malformed("ack ledger account_id"))?;
        let genesis_hash = hash(&o["genesis_hash"], "ack ledger genesis_hash")?;
        let mut ledger = AckLedger::new(origin, account_id, genesis_hash)?;

        for (id, t) in object(&o["records"], "ack ledger records")? {
            if !is_uuid_v4(id) {
                return Err(Error::Malformed("ack ledger record_id"));
            }
            ledger.records.insert(id.clone(), Tracked::read(t)?);
        }
        let own_revoke = |t: &Tracked| !t.native && t.effects.contains(&EffectKind::Revocation);
        for (principal, r) in object(&o["revocations"], "ack ledger revocations")? {
            let service = matches!(
                ControlPrincipal::parse(principal),
                Some(p @ ControlPrincipal::Service(_)) if p.name() == *principal
            );
            let recorded = ledger
                .records
                .values()
                .any(|t| t.principal == *principal && own_revoke(t));
            if !service || !recorded {
                return Err(Error::Malformed("ack ledger revocation"));
            }
            ledger
                .revocations
                .insert(principal.clone(), Revocation::read(r)?);
        }
        if ledger
            .records
            .values()
            .any(|t| own_revoke(t) && !ledger.revocations.contains_key(&t.principal))
        {
            return Err(Error::Malformed("ack ledger revocation"));
        }

        for d in array(&o["done"], "ack ledger done")? {
            let (key, record_id) = Done::read(d, &ledger.records)?;
            // Strictly increasing: sorted, no repeat.
            if ledger
                .done
                .last_key_value()
                .is_some_and(|(last, _)| *last >= key)
            {
                return Err(Error::Malformed("ack ledger done"));
            }
            ledger.done.insert(key, record_id);
        }
        for (principal, r) in &ledger.revocations {
            let all = ledger.all_applied(principal, r);
            match r.outcome {
                None if all => return Err(Error::Malformed("ack ledger revocation outcome")),
                Some(RevokedOutcome::AllApplied) if !all => {
                    return Err(Error::Malformed("ack ledger revocation outcome"));
                }
                _ => {}
            }
        }

        let mut ids = BTreeSet::new();
        for p in array(&o["pending"], "ack ledger pending")? {
            let pending = ledger.read_pending(p)?;
            if !ids.insert(pending.intent.report_id.clone()) {
                return Err(Error::Malformed("ack ledger pending"));
            }
            ledger.pending.push(pending);
        }
        let made = ledger.made_ids();
        for id in id_list(&o["refused"], "ack ledger refused")? {
            if !made.contains(&id) || ids.contains(&id) {
                return Err(Error::Malformed("ack ledger refused"));
            }
            ledger.refused.insert(id);
        }
        for (id, client_id) in object(&o["dropped"], "ack ledger dropped")? {
            let settled_once =
                made.contains(id) && !ids.contains(id) && !ledger.refused.contains(id);
            let by = client_id.as_str().filter(|c| id_ok(c));
            match (settled_once, by) {
                (true, Some(by)) => {
                    ledger.dropped.insert(id.clone(), by.to_owned());
                }
                _ => return Err(Error::Malformed("ack ledger dropped")),
            }
        }
        ledger.stopped = match o.get("stopped") {
            None => None,
            Some(id) => Some(
                id.as_str()
                    .filter(|id| id_ok(id))
                    .ok_or(Error::Malformed("ack ledger stopped"))?
                    .to_owned(),
            ),
        };
        Ok(ledger)
    }

    // ---------------------------------------------------------- internal

    fn unchanged(&self) -> LedgerTransition {
        self.clone().with(Vec::new())
    }

    /// This ledger as a transition's next, with the intents it made.
    fn with(self, intents: Vec<ReportIntent>) -> LedgerTransition {
        LedgerTransition {
            next: self,
            made: intents,
            alerts: Vec::new(),
        }
    }

    /// The id of every report this ledger has made: each revocation's
    /// final once it has an outcome, and the per-host report of each
    /// covered host that has it in force.
    fn made_ids(&self) -> BTreeSet<String> {
        let mut ids = BTreeSet::new();
        for (principal, r) in &self.revocations {
            if r.outcome.is_some() {
                ids.insert(self.report_id(REVOKED, principal, &r.integration_id, None));
            }
            for host in &r.covered {
                if self.done.contains_key(&Done::revocation(principal, host)) {
                    ids.insert(self.report_id(APPLIED, principal, &r.integration_id, Some(host)));
                }
            }
        }
        ids
    }

    /// What `effect` of `tracked` counts as; `None` for an effect the
    /// ledger doesn't count (it tracks none).
    fn counted(tracked: &Tracked, effect: EffectKind) -> Option<Counted> {
        match effect {
            EffectKind::Revocation => Some(Counted::Revocation),
            EffectKind::Interrupt => Some(Counted::Interrupt(tracked.revoke_seq)),
            _ => None,
        }
    }

    /// `host` has `effect` of `tracked` in force, as the result for
    /// `record_id` says: counted once, and reported when it is a covered
    /// host's revocation.
    fn count(
        &mut self,
        tracked: &Tracked,
        effect: EffectKind,
        host: &str,
        record_id: &str,
        intents: &mut Vec<ReportIntent>,
    ) {
        let Some(counted) = Self::counted(tracked, effect) else {
            return;
        };
        let key = Done {
            principal: tracked.principal.clone(),
            effect: counted,
            host: host.to_owned(),
        };
        if self.done.contains_key(&key) {
            return;
        }
        self.done.insert(key, record_id.to_owned());
        let covered = self
            .revocations
            .get(&tracked.principal)
            .is_some_and(|r| r.covered.contains(host));
        if counted == Counted::Revocation && covered {
            self.report_applied(&tracked.principal, host, record_id, intents);
            self.finish_when_all_applied(&tracked.principal, intents);
        }
    }

    fn report_applied(
        &mut self,
        principal: &str,
        host: &str,
        record_id: &str,
        intents: &mut Vec<ReportIntent>,
    ) {
        let integration_id = self.revocations[principal].integration_id.clone();
        let intent = ReportIntent {
            report_id: self.report_id(APPLIED, principal, &integration_id, Some(host)),
            report: Report::RevocationApplied {
                integration_id,
                host: host.to_owned(),
                record_id: record_id.to_owned(),
            },
            not_before: Vec::new(),
        };
        self.make(principal, intent, intents);
    }

    fn all_applied(&self, principal: &str, r: &Revocation) -> bool {
        r.covered
            .iter()
            .all(|host| self.done.contains_key(&Done::revocation(principal, host)))
    }

    fn finish_when_all_applied(&mut self, principal: &str, intents: &mut Vec<ReportIntent>) {
        let r = &self.revocations[principal];
        if r.outcome.is_none() && self.all_applied(principal, r) {
            self.finish(principal, intents);
        }
    }

    fn pass_deadlines(&mut self, now_ms: u64, intents: &mut Vec<ReportIntent>) {
        let due: Vec<String> = self
            .revocations
            .iter()
            .filter(|(_, r)| {
                r.outcome.is_none()
                    && now_ms >= r.revoked_at_ms.saturating_add(REVOCATION_DEADLINE_MS)
            })
            .map(|(principal, _)| principal.clone())
            .collect();
        for principal in due {
            self.finish(&principal, intents);
        }
    }

    /// The revocation's `revoked` report: `all_applied` when no covered
    /// host is pending, else `deadline_passed` with them; after the
    /// per-host reports made so far.
    fn finish(&mut self, principal: &str, intents: &mut Vec<ReportIntent>) {
        let r = &self.revocations[principal];
        let integration_id = r.integration_id.clone();
        let mut not_before = Vec::new();
        let mut pending_hosts = Vec::new();
        for host in &r.covered {
            if self.done.contains_key(&Done::revocation(principal, host)) {
                not_before.push(self.report_id(APPLIED, principal, &integration_id, Some(host)));
            } else {
                pending_hosts.push(host.clone());
            }
        }
        not_before.sort();
        let outcome = if pending_hosts.is_empty() {
            RevokedOutcome::AllApplied
        } else {
            RevokedOutcome::DeadlinePassed
        };
        if let Some(r) = self.revocations.get_mut(principal) {
            r.outcome = Some(outcome);
        }
        let intent = ReportIntent {
            report_id: self.report_id(REVOKED, principal, &integration_id, None),
            report: Report::Revoked {
                integration_id,
                outcome,
                pending_hosts,
            },
            not_before,
        };
        self.make(principal, intent, intents);
    }

    /// An intent made: kept until settled.
    fn make(&mut self, principal: &str, intent: ReportIntent, intents: &mut Vec<ReportIntent>) {
        intents.push(intent.clone());
        self.pending.push(Pending {
            principal: principal.to_owned(),
            intent,
        });
    }

    /// `<kind>:<hex SHA-256 of enc([STATION_REPORT_ID, kind, account_id,
    /// genesis_hash, principal, integration_id, host?])>`.
    fn report_id(
        &self,
        kind: &str,
        principal: &str,
        integration_id: &str,
        host: Option<&str>,
    ) -> String {
        let mut parts: Vec<&[u8]> = vec![
            STATION_REPORT_ID.as_bytes(),
            kind.as_bytes(),
            self.account_id.as_bytes(),
            self.genesis_hash.as_bytes().as_slice(),
            principal.as_bytes(),
            integration_id.as_bytes(),
        ];
        parts.extend(host.map(str::as_bytes));
        format!("{kind}:{}", Hash32::of_enc(&parts).to_hex())
    }

    /// A pending intent: its revocation's, with the `report_id` of its
    /// report, consistent with what the ledger counted.
    fn read_pending(&self, value: &Value) -> Result<Pending> {
        let what = "ack ledger pending";
        let o = fields(
            value,
            &["principal", "report_id", "report", "not_before"],
            &[],
            what,
        )?;
        let principal = o["principal"].as_str().ok_or(Error::Malformed(what))?;
        let r = self
            .revocations
            .get(principal)
            .ok_or(Error::Malformed(what))?;
        let report = Report::read(&o["report"])?;
        let report_id = o["report_id"].as_str().ok_or(Error::Malformed(what))?;
        let not_before = id_list(&o["not_before"], what)?;
        if report.integration_id() != r.integration_id {
            return Err(Error::Malformed(what));
        }
        let host_id =
            |host: &str| self.report_id(APPLIED, principal, &r.integration_id, Some(host));
        let consistent = match &report {
            Report::RevocationApplied {
                host, record_id, ..
            } => {
                r.covered.contains(host)
                    && self.done.get(&Done::revocation(principal, host)) == Some(record_id)
                    && not_before.is_empty()
                    && report_id == host_id(host)
            }
            Report::Revoked {
                outcome,
                pending_hosts,
                ..
            } => {
                // `not_before` names the reports of the hosts that had it
                // in force, `pending_hosts` the others: together, the
                // covered hosts, once each.
                let by_id: BTreeMap<String, &String> =
                    r.covered.iter().map(|h| (host_id(h), h)).collect();
                let confirmed: Option<BTreeSet<&String>> =
                    not_before.iter().map(|id| by_id.get(id).copied()).collect();
                let mut all: BTreeSet<&String> = BTreeSet::new();
                let partition = pending_hosts.iter().all(|h| r.covered.contains(h))
                    && confirmed.is_some_and(|confirmed| {
                        confirmed
                            .iter()
                            .all(|h| self.done.contains_key(&Done::revocation(principal, h)))
                            && confirmed
                                .into_iter()
                                .chain(pending_hosts)
                                .all(|h| all.insert(h))
                            && all.len() == r.covered.len()
                    });
                partition
                    && r.outcome == Some(*outcome)
                    && report_id == self.report_id(REVOKED, principal, &r.integration_id, None)
            }
        };
        if !consistent {
            return Err(Error::Malformed(what));
        }
        Ok(Pending {
            principal: principal.to_owned(),
            intent: ReportIntent {
                report_id: report_id.to_owned(),
                report,
                not_before,
            },
        })
    }
}

impl Tracked {
    fn to_json(&self) -> Value {
        let effects: Vec<&str> = self.effects.iter().map(|e| e.code()).collect();
        let mut o = Map::new();
        o.insert("covered".into(), json!(self.covered));
        o.insert("digest".into(), json!(self.digest.to_hex()));
        o.insert("effects".into(), json!(effects));
        o.insert("native".into(), json!(self.native));
        o.insert("principal".into(), json!(self.principal));
        if let Some(seq) = self.revoke_seq {
            o.insert("revoke_seq".into(), json!(seq));
        }
        Value::Object(o)
    }

    /// A service's record carries the revocation, the revocation and its
    /// interrupt, or the interrupt; a host principal's the interrupt at its
    /// `revoke_seq`.
    fn read(value: &Value) -> Result<Self> {
        let what = "ack ledger record";
        let o = fields(
            value,
            &["principal", "effects", "native", "covered", "digest"],
            &["revoke_seq"],
            what,
        )?;
        let name = o["principal"].as_str().ok_or(Error::Malformed(what))?;
        let principal = ControlPrincipal::parse(name)
            .filter(|p| p.name() == name)
            .ok_or(Error::Malformed("ack ledger record principal"))?;
        let effects = o["effects"]
            .as_array()
            .ok_or(Error::Malformed(what))?
            .iter()
            .map(|e| e.as_str().and_then(EffectKind::from_code))
            .collect::<Option<Vec<_>>>()
            .ok_or(Error::Malformed("ack ledger record effects"))?;
        let revoke_seq = match o.get("revoke_seq") {
            None => None,
            Some(seq) => Some(
                seq.as_u64()
                    .filter(|seq| (1..=MAX_SAFE_INTEGER).contains(seq))
                    .ok_or(Error::Malformed("ack ledger record revoke_seq"))?,
            ),
        };
        use EffectKind::{Interrupt, Revocation};
        let fits = match principal {
            ControlPrincipal::Service(_) => {
                revoke_seq.is_none()
                    && [
                        &[Revocation][..],
                        &[Revocation, Interrupt][..],
                        &[Interrupt][..],
                    ]
                    .contains(&effects.as_slice())
            }
            ControlPrincipal::Host(_) => revoke_seq.is_some() && effects == [Interrupt],
        };
        if !fits {
            return Err(Error::Malformed("ack ledger record effects"));
        }
        Ok(Tracked {
            principal: name.to_owned(),
            revoke_seq,
            effects,
            native: o["native"].as_bool().ok_or(Error::Malformed(what))?,
            covered: host_set(&o["covered"], "ack ledger record covered")?,
            digest: hash(&o["digest"], "ack ledger record digest")?,
        })
    }
}

impl Revocation {
    fn to_json(&self) -> Value {
        let mut o = Map::new();
        o.insert("covered".into(), json!(self.covered));
        o.insert("integration_id".into(), json!(self.integration_id));
        if let Some(outcome) = self.outcome {
            o.insert("outcome".into(), json!(outcome.code()));
        }
        o.insert("revoked_at_ms".into(), json!(self.revoked_at_ms));
        Value::Object(o)
    }

    fn read(value: &Value) -> Result<Self> {
        let what = "ack ledger revocation";
        let o = fields(
            value,
            &["integration_id", "revoked_at_ms", "covered"],
            &["outcome"],
            what,
        )?;
        let outcome = match o.get("outcome") {
            None => None,
            Some(code) => Some(
                code.as_str()
                    .and_then(RevokedOutcome::from_code)
                    .ok_or(Error::Malformed("ack ledger revocation outcome"))?,
            ),
        };
        Ok(Revocation {
            integration_id: o["integration_id"]
                .as_str()
                .filter(|id| id_ok(id))
                .ok_or(Error::Malformed("ack ledger revocation integration_id"))?
                .to_owned(),
            revoked_at_ms: o["revoked_at_ms"]
                .as_u64()
                .filter(|at| *at <= MAX_SAFE_INTEGER)
                .ok_or(Error::Malformed("ack ledger revocation revoked_at_ms"))?,
            covered: host_set(&o["covered"], "ack ledger revocation covered")?,
            outcome,
        })
    }
}

impl Done {
    fn to_json(&self, record_id: &str) -> Value {
        let (effect, revoke_seq) = match self.effect {
            Counted::Revocation => (EffectKind::Revocation, None),
            Counted::Interrupt(seq) => (EffectKind::Interrupt, seq),
        };
        let mut o = Map::new();
        o.insert("effect".into(), json!(effect.code()));
        o.insert("host".into(), json!(self.host));
        o.insert("principal".into(), json!(self.principal));
        o.insert("record_id".into(), json!(record_id));
        if let Some(seq) = revoke_seq {
            o.insert("revoke_seq".into(), json!(seq));
        }
        Value::Object(o)
    }

    /// A count: of a tracked record, its principal and an effect it
    /// carries (an interrupt at the record's `revoke_seq`).
    fn read(value: &Value, records: &BTreeMap<String, Tracked>) -> Result<(Self, String)> {
        let what = "ack ledger done";
        let o = fields(
            value,
            &["principal", "effect", "host", "record_id"],
            &["revoke_seq"],
            what,
        )?;
        let record_id = o["record_id"].as_str().ok_or(Error::Malformed(what))?;
        let tracked = records.get(record_id).ok_or(Error::Malformed(what))?;
        let effect = o["effect"]
            .as_str()
            .and_then(EffectKind::from_code)
            .filter(|e| tracked.effects.contains(e))
            .ok_or(Error::Malformed(what))?;
        let revoke_seq = match o.get("revoke_seq") {
            None => None,
            Some(seq) => Some(seq.as_u64().ok_or(Error::Malformed(what))?),
        };
        let counted = match effect {
            EffectKind::Revocation if revoke_seq.is_none() => Counted::Revocation,
            EffectKind::Interrupt if revoke_seq == tracked.revoke_seq => {
                Counted::Interrupt(revoke_seq)
            }
            _ => return Err(Error::Malformed(what)),
        };
        if o["principal"].as_str() != Some(tracked.principal.as_str()) {
            return Err(Error::Malformed(what));
        }
        let key = Done {
            principal: tracked.principal.clone(),
            effect: counted,
            host: host(&o["host"], what)?,
        };
        Ok((key, record_id.to_owned()))
    }
}

impl Pending {
    /// The intent's [`ReportIntent::to_json`], with its principal.
    fn to_json(&self) -> Value {
        let mut o = Map::new();
        o.insert("not_before".into(), json!(self.intent.not_before));
        o.insert("principal".into(), json!(self.principal));
        o.insert("report".into(), self.intent.report.to_json());
        o.insert("report_id".into(), json!(self.intent.report_id));
        Value::Object(o)
    }
}

// ------------------------------------------------------------- readers

/// A report client ID: 1 to 128 characters of `[A-Za-z0-9._:-]`.
fn client(client_id: &str) -> Result<()> {
    if id_ok(client_id) {
        Ok(())
    } else {
        Err(Error::Malformed("report client_id"))
    }
}

/// `account_id`: 1 to 128 bytes, as the device list's.
fn account_ok(id: &str) -> bool {
    (1..=MAX_ACCOUNT_ID_BYTES).contains(&id.len())
}

/// Exactly `required` and at most `optional` fields.
fn fields<'a>(
    value: &'a Value,
    required: &[&str],
    optional: &[&str],
    what: &'static str,
) -> Result<&'a Map<String, Value>> {
    let o = value.as_object().ok_or(Error::Malformed(what))?;
    let known = |key: &str| required.contains(&key) || optional.contains(&key);
    if !o.keys().all(|key| known(key)) || !required.iter().all(|key| o.contains_key(*key)) {
        return Err(Error::Malformed(what));
    }
    Ok(o)
}

fn object<'a>(value: &'a Value, what: &'static str) -> Result<&'a Map<String, Value>> {
    value.as_object().ok_or(Error::Malformed(what))
}

fn array<'a>(value: &'a Value, what: &'static str) -> Result<&'a Vec<Value>> {
    value.as_array().ok_or(Error::Malformed(what))
}

fn hash(value: &Value, what: &'static str) -> Result<Hash32> {
    value
        .as_str()
        .and_then(|text| Hash32::from_hex(text).ok())
        .ok_or(Error::Malformed(what))
}

fn host(value: &Value, what: &'static str) -> Result<String> {
    value
        .as_str()
        .filter(|h| id_ok(h))
        .map(str::to_owned)
        .ok_or(Error::Malformed(what))
}

fn record_id(value: &Value, what: &'static str) -> Result<String> {
    value
        .as_str()
        .filter(|id| is_uuid_v4(id))
        .map(str::to_owned)
        .ok_or(Error::Malformed(what))
}

/// Strings, strictly increasing (sorted, no repeat).
fn id_list(value: &Value, what: &'static str) -> Result<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    for item in array(value, what)? {
        let item = item.as_str().ok_or(Error::Malformed(what))?;
        if out.last().is_some_and(|last| last.as_str() >= item) {
            return Err(Error::Malformed(what));
        }
        out.push(item.to_owned());
    }
    Ok(out)
}

/// Host ids, sorted and unique, at most [`MAX_HOSTS`].
fn host_set(value: &Value, what: &'static str) -> Result<BTreeSet<String>> {
    let list = id_list(value, what)?;
    if list.len() > MAX_HOSTS || !list.iter().all(|h| id_ok(h)) {
        return Err(Error::Malformed(what));
    }
    Ok(list.into_iter().collect())
}

#[cfg(test)]
mod ack_ledger_tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;
    use crate::canonical::jcs;
    use crate::control::record::{
        ControlAbout, ControlAction, ControlBody, ControlFeed, ControlPrincipal, ControlSigner,
        build_control,
    };
    use crate::control::relay::{AckResult, ControlAck, EntryRef, RelayError};
    use crate::control::state::{ApplicationResult, EffectKind, EffectResult};
    use crate::membership::entry::id_ok;
    use crate::provider::KeyId;
    use crate::software::SoftwareKeys;
    use serde_json::{Value, json};

    use ApplicationResult as R;
    use EffectKind as E;

    const ORIGIN: &str = "https://station-dev.agora.build";
    const FEED: &str = "6f1c2b3a-4d5e-4f60-8a7b-9c0d1e2f3a4b";
    /// The same Station's feed after a reset.
    const FEED2: &str = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d";
    const ACCOUNT: &str = "acct-test-1";
    const INTEGRATION: &str = "i-01jc5zq9x8w7v6t5s4r3q2p1n0";
    const T0: u64 = 1_800_000_000_000;
    const HOUR: u64 = 3_600_000;
    const DAY: u64 = 24 * HOUR;

    fn genesis() -> Hash32 {
        Hash32([7; 32])
    }

    /// The `n`th record id (a UUID v4).
    fn rid(n: u32) -> String {
        format!("00000000-0000-4000-8000-{n:012x}")
    }

    /// Who signs: the principal itself (the Station's service key), or the
    /// native manager `mac`.
    #[derive(Clone, Copy)]
    enum By {
        Own,
        Native,
    }

    /// A record of `svc-1` (or of the host principal `host:host-z` when
    /// `action` carries a `revoke_seq`), record id `n`. The ledger never
    /// verifies a signature, so one key signs everything.
    fn rec(by: By, action: ControlAction, n: u32) -> ControlRecord {
        rec_of(ACCOUNT, ORIGIN, by, action, n)
    }

    fn rec_of(account: &str, origin: &str, by: By, action: ControlAction, n: u32) -> ControlRecord {
        rec_for(account, origin, "svc-1", by, action, n)
    }

    /// [`rec_of`] for the service `service` (an integration of its own).
    fn rec_for(
        account: &str,
        origin: &str,
        service: &str,
        by: By,
        action: ControlAction,
        n: u32,
    ) -> ControlRecord {
        let host_principal = matches!(
            action,
            ControlAction::InterruptRunning {
                revoke_seq: Some(_)
            }
        );
        let principal = if host_principal {
            ControlPrincipal::Host("host-z".into())
        } else {
            ControlPrincipal::Service(service.into())
        };
        let body = ControlBody {
            account_id: account.into(),
            genesis_hash: genesis(),
            feed: (!host_principal).then(|| ControlFeed {
                origin: origin.into(),
                feed_id: FEED.into(),
            }),
            principal,
            principal_key: (!host_principal).then_some(Hash32([1; 32])),
            signer: match by {
                By::Own => ControlSigner::Principal,
                By::Native => ControlSigner::Member("mac".into()),
            },
            action,
            record_id: rid(n),
            issued_at: T0 + u64::from(n),
            about: ControlAbout {
                integration_id: (!host_principal).then(|| {
                    if service == "svc-1" {
                        INTEGRATION.into()
                    } else {
                        format!("i-{service}")
                    }
                }),
                by: "owner".into(),
            },
        };
        let mut keys = SoftwareKeys::new();
        keys.insert_ed25519(KeyId::new("k"), &[9; 32]);
        let object = build_control(&keys, &KeyId::new("k"), &body).unwrap();
        ControlRecord::from_signed(object).unwrap()
    }

    fn revoke(by: By, interrupt_running: bool, n: u32) -> ControlRecord {
        rec(by, ControlAction::Revoke { interrupt_running }, n)
    }

    fn interrupt(by: By, n: u32) -> ControlRecord {
        rec(by, ControlAction::InterruptRunning { revoke_seq: None }, n)
    }

    /// A native manager's later interrupt of the host principal `host-z`.
    fn host_interrupt(revoke_seq: u64, n: u32) -> ControlRecord {
        rec(
            By::Native,
            ControlAction::InterruptRunning {
                revoke_seq: Some(revoke_seq),
            },
            n,
        )
    }

    fn hosts(names: &[&str]) -> Vec<String> {
        names.iter().map(|h| h.to_string()).collect()
    }

    fn link(host: &str) -> LinkAssociation {
        LinkAssociation {
            account_id: ACCOUNT.into(),
            genesis_hash: genesis(),
            host_id: host.into(),
            host_trust_gen: 1,
            connection_id: format!("conn-{host}"),
        }
    }

    fn ack(host: &str, results: Vec<AckResult>) -> ControlAck {
        ControlAck {
            account_id: ACCOUNT.into(),
            genesis_hash: genesis(),
            host_id: host.into(),
            host_trust_gen: 1,
            origin: ORIGIN.into(),
            feed_id: FEED.into(),
            cursor: 10,
            results,
        }
    }

    /// A record's result, per effect.
    fn res(record: &ControlRecord, effects: &[(EffectKind, ApplicationResult)]) -> AckResult {
        AckResult::Record {
            record_id: record.record_id().into(),
            effects: effects
                .iter()
                .map(|&(effect, result)| EffectResult { effect, result })
                .collect(),
        }
    }

    fn ledger() -> AckLedger {
        AckLedger::new(ORIGIN, ACCOUNT, genesis()).unwrap()
    }

    /// The Station's side in the tests: apply, commit (adopt), keep the
    /// intents.
    trait Adopt {
        fn rec(&mut self, r: &ControlRecord, at: u64, covered: &[&str]) -> Vec<ReportIntent>;
        fn ack_by(&mut self, host: &str, results: Vec<AckResult>, now: u64) -> Vec<ReportIntent>;
        fn tick_at(&mut self, now: u64) -> Vec<ReportIntent>;
        fn confirm_id(&mut self, id: &str);
    }

    impl Adopt for AckLedger {
        fn rec(&mut self, r: &ControlRecord, at: u64, covered: &[&str]) -> Vec<ReportIntent> {
            let t = self.record(r, at, &hosts(covered), at).unwrap();
            *self = t.next;
            t.made
        }

        fn ack_by(&mut self, host: &str, results: Vec<AckResult>, now: u64) -> Vec<ReportIntent> {
            let t = self.ack(&link(host), &ack(host, results), now).unwrap();
            *self = t.next;
            t.made
        }

        fn tick_at(&mut self, now: u64) -> Vec<ReportIntent> {
            let t = self.tick(now);
            *self = t.next;
            t.made
        }

        fn confirm_id(&mut self, id: &str) {
            *self = self.confirm(id).next;
        }
    }

    fn applied(host: &str, record: &ControlRecord) -> Report {
        Report::RevocationApplied {
            integration_id: INTEGRATION.into(),
            host: host.into(),
            record_id: record.record_id().into(),
        }
    }

    fn revoked(outcome: RevokedOutcome, pending: &[&str]) -> Report {
        Report::Revoked {
            integration_id: INTEGRATION.into(),
            outcome,
            pending_hosts: hosts(pending),
        }
    }

    fn reports(intents: &[ReportIntent]) -> Vec<Report> {
        intents.iter().map(|i| i.report.clone()).collect()
    }

    fn ids(intents: &[ReportIntent]) -> Vec<String> {
        intents.iter().map(|i| i.report_id.clone()).collect()
    }

    fn bytes(intent: &ReportIntent) -> String {
        jcs(&intent.to_json()).unwrap()
    }

    /// The Station's own revoke `S` (record 1) of `svc-1`, at `T0`,
    /// covering hosts `a` and `b`.
    fn revoked_ledger() -> (AckLedger, ControlRecord) {
        let mut l = ledger();
        let s = revoke(By::Own, false, 1);
        assert_eq!(l.rec(&s, T0, &["a", "b"]), vec![]);
        (l, s)
    }

    // ------------------------------------------------------------ counting

    #[test]
    fn one_revocation_applied_per_host_and_integration() {
        let (mut l, s) = revoked_ledger();
        let a = l.ack_by("a", vec![res(&s, &[(E::Revocation, R::Applied)])], T0 + 1);
        assert_eq!(reports(&a), vec![applied("a", &s)]);
        assert_eq!(a[0].not_before, Vec::<String>::new());
        // The same result again, and a later duplicate: nothing more.
        for result in [R::Applied, R::Duplicate] {
            let again = l.ack_by("a", vec![res(&s, &[(E::Revocation, result)])], T0 + 2);
            assert_eq!(again, vec![]);
        }
        let b = l.ack_by("b", vec![res(&s, &[(E::Revocation, R::Applied)])], T0 + 3);
        assert_eq!(
            reports(&b),
            vec![applied("b", &s), revoked(RevokedOutcome::AllApplied, &[])]
        );
        let mut want = vec![a[0].report_id.clone(), b[0].report_id.clone()];
        want.sort();
        assert_eq!(b[1].not_before, want);
        // Nothing more, ever: not from acks, not from the deadline.
        assert_eq!(
            l.ack_by("b", vec![res(&s, &[(E::Revocation, R::Duplicate)])], T0 + 4),
            vec![]
        );
        assert_eq!(l.tick_at(T0 + 2 * DAY), vec![]);
    }

    #[test]
    fn the_cursor_pending_and_refused_never_count() {
        let (mut l, s) = revoked_ledger();
        let before = l.clone();
        // A cursor past the record, with no result for it.
        let mut far = ack("a", vec![]);
        far.cursor = 1_000;
        let t = l.ack(&link("a"), &far, T0 + 1).unwrap();
        assert_eq!((t.next, t.made), (before.clone(), vec![]));
        for result in [R::Pending, R::Refused] {
            let t = l
                .ack(
                    &link("a"),
                    &ack("a", vec![res(&s, &[(E::Revocation, result)])]),
                    T0 + 1,
                )
                .unwrap();
            assert_eq!((t.next, t.made), (before.clone(), vec![]));
        }
        assert_eq!(l.pending_reports(), vec![]);
        // Only `applied` or `duplicate` counts.
        let a = l.ack_by("a", vec![res(&s, &[(E::Revocation, R::Duplicate)])], T0 + 2);
        assert_eq!(reports(&a), vec![applied("a", &s)]);
    }

    /// Decision 8: a host that applied the revocation through another
    /// record first (a native revoke from another Station's feed) reports
    /// the Station's revoke `duplicate`, and `revocation_applied` names the
    /// Station's record; `all_applied` follows every covered host's report.
    #[test]
    fn a_duplicate_counts_and_names_its_record() {
        let (mut l, s) = revoked_ledger();
        let a = l.ack_by("a", vec![res(&s, &[(E::Revocation, R::Duplicate)])], T0 + 1);
        assert_eq!(reports(&a), vec![applied("a", &s)]);
        let b = l.ack_by("b", vec![res(&s, &[(E::Revocation, R::Applied)])], T0 + 2);
        assert_eq!(
            reports(&b),
            vec![applied("b", &s), revoked(RevokedOutcome::AllApplied, &[])]
        );
    }

    /// A native revoke in this feed before the Station's own: hosts that
    /// applied it are counted once the Station revokes the integration,
    /// naming the native record, the first that applied it there.
    #[test]
    fn a_native_revoke_applied_first_is_named_once_the_integration_is_revoked() {
        let mut l = ledger();
        let n = revoke(By::Native, false, 1);
        assert_eq!(l.rec(&n, T0, &["a", "b"]), vec![]);
        let a = l.ack_by("a", vec![res(&n, &[(E::Revocation, R::Applied)])], T0 + 1);
        assert_eq!(a, vec![], "the Portal hasn't revoked the integration yet");
        assert_eq!(l.resign_alerts(), vec![rid(1)]);

        let s = revoke(By::Own, false, 2);
        let at_revoke = l.rec(&s, T0 + HOUR, &["a", "b"]);
        assert_eq!(reports(&at_revoke), vec![applied("a", &n)]);
        // `a`'s later duplicate for the Station's record names nothing new.
        assert_eq!(
            l.ack_by(
                "a",
                vec![res(&s, &[(E::Revocation, R::Duplicate)])],
                T0 + HOUR
            ),
            vec![]
        );
        let b = l.ack_by(
            "b",
            vec![res(&s, &[(E::Revocation, R::Applied)])],
            T0 + HOUR,
        );
        assert_eq!(
            reports(&b),
            vec![applied("b", &s), revoked(RevokedOutcome::AllApplied, &[])]
        );
        // `b` has the revocation in force, so the native record is done.
        assert_eq!(l.resign_alerts(), Vec::<String>::new());
        // The deadline runs from the Station's own revoke.
        let mut d = ledger();
        d.rec(&n, T0, &["a", "b"]);
        d.rec(&s, T0 + HOUR, &["a", "b"]);
        assert_eq!(d.tick_at(T0 + DAY), vec![]);
        assert_eq!(
            reports(&d.tick_at(T0 + HOUR + DAY)),
            vec![revoked(RevokedOutcome::DeadlinePassed, &["a", "b"])]
        );
    }

    #[test]
    fn interrupt_effects_never_count_as_revocation() {
        let (mut l, s) = revoked_ledger();
        let i = interrupt(By::Native, 2);
        assert_eq!(l.rec(&i, T0, &["a", "b"]), vec![]);
        let s2 = revoke(By::Native, true, 3);
        assert_eq!(l.rec(&s2, T0, &["a", "b"]), vec![]);
        for host in ["a", "b"] {
            let got = l.ack_by(
                host,
                vec![
                    res(&i, &[(E::Interrupt, R::Applied)]),
                    res(
                        &s2,
                        &[(E::Revocation, R::Pending), (E::Interrupt, R::Duplicate)],
                    ),
                    res(&s, &[(E::Revocation, R::Refused)]),
                ],
                T0 + 1,
            );
            assert_eq!(got, vec![], "{host}");
        }
        assert_eq!(l.pending_reports(), vec![]);
        // The interrupts are counted, apart: `s2`'s revocation isn't.
        assert_eq!(l.resign_alerts(), vec![rid(3)]);
        // A host principal's interrupt, too.
        let h = host_interrupt(5, 4);
        l.rec(&h, T0, &["a"]);
        assert_eq!(
            l.ack_by("a", vec![res(&h, &[(E::Interrupt, R::Applied)])], T0 + 2),
            vec![]
        );
        // The revocation still waits for both hosts, and its deadline.
        assert_eq!(
            reports(&l.tick_at(T0 + DAY)),
            vec![revoked(RevokedOutcome::DeadlinePassed, &["a", "b"])]
        );
    }

    #[test]
    fn untracked_records_and_device_list_entries_are_ignored() {
        let (mut l, s) = revoked_ledger();
        let before = l.clone();
        // Cover, hold and release records carry nothing the ledger counts.
        for (n, action) in [
            (10, ControlAction::Cover),
            (11, ControlAction::Hold),
            (12, ControlAction::Release),
        ] {
            let r = rec(By::Own, action, n);
            let t = l.record(&r, T0, &hosts(&["a"]), T0).unwrap();
            assert_eq!((t.next, t.made), (before.clone(), vec![]));
            let kind = match action {
                ControlAction::Cover => E::Cover,
                ControlAction::Hold => E::Hold,
                _ => E::Release,
            };
            let t = l
                .ack(
                    &link("a"),
                    &ack("a", vec![res(&r, &[(kind, R::Applied)])]),
                    T0,
                )
                .unwrap();
            assert_eq!((t.next, t.made), (before.clone(), vec![]));
        }
        // A record the ledger never saw, and a host sender's revoke entry.
        let unknown = revoke(By::Own, false, 99);
        let entry = AckResult::Entry {
            entry: EntryRef {
                seq: 5,
                entry_hash: Hash32([3; 32]),
            },
            applied_seq: 5,
            effects: vec![EffectResult {
                effect: E::Revocation,
                result: R::Applied,
            }],
        };
        let t = l
            .ack(
                &link("a"),
                &ack(
                    "a",
                    vec![res(&unknown, &[(E::Revocation, R::Applied)]), entry.clone()],
                ),
                T0,
            )
            .unwrap();
        assert_eq!((t.next, t.made), (before.clone(), vec![]));
        // Beside them, a tracked record's result counts as usual.
        let mixed = l.ack(
            &link("a"),
            &ack("a", vec![entry, res(&s, &[(E::Revocation, R::Applied)])]),
            T0,
        );
        assert_eq!(reports(&mixed.unwrap().made), vec![applied("a", &s)]);
        // A host the revocation doesn't cover is never reported.
        let c = l.ack_by("c", vec![res(&s, &[(E::Revocation, R::Applied)])], T0);
        assert_eq!(c, vec![]);
        assert_eq!(
            reports(&l.tick_at(T0 + DAY)),
            vec![revoked(RevokedOutcome::DeadlinePassed, &["a", "b"])]
        );
    }

    #[test]
    fn a_revocation_covering_no_host_is_all_applied_at_once() {
        // host-work-v1 §11.4 "Reports": nothing could apply it, so the
        // revocation is complete when recorded: `revoked{all_applied,
        // pending_hosts: []}` at once, with no per-host report.
        let mut l = ledger();
        let s = revoke(By::Own, false, 1);
        let got = l.rec(&s, T0, &[]);
        assert_eq!(
            reports(&got),
            vec![revoked(RevokedOutcome::AllApplied, &[])]
        );
        assert_eq!(
            got[0].report.to_json(),
            json!({"integration_id": INTEGRATION, "kind": "revoked",
                "outcome": "all_applied", "pending_hosts": []})
        );
        assert_eq!(got[0].not_before, Vec::<String>::new());
        assert_eq!(l.pending_reports(), got);
        assert_eq!(l.tick_at(T0 + DAY), vec![]);
    }

    // ----------------------------------------------------------- re-signing

    /// Test 48: a native interrupt refused on `b` (its signer was removed)
    /// keeps its alert; the re-signed copy is applied on `b`, and `a`,
    /// which applied the original, reports the copy `duplicate`.
    #[test]
    fn a_resign_alert_stays_until_every_covered_host_applied() {
        let mut l = ledger();
        let n1 = interrupt(By::Native, 1);
        l.rec(&n1, T0, &["a", "b"]);
        assert_eq!(l.resign_alerts(), vec![rid(1)]);
        l.ack_by("a", vec![res(&n1, &[(E::Interrupt, R::Applied)])], T0);
        l.ack_by("b", vec![res(&n1, &[(E::Interrupt, R::Refused)])], T0);
        assert_eq!(l.resign_alerts(), vec![rid(1)], "refused never counts");
        l.ack_by("b", vec![res(&n1, &[(E::Interrupt, R::Pending)])], T0);
        assert_eq!(l.resign_alerts(), vec![rid(1)], "pending never counts");

        // The re-signed copy: the same body, a new record id.
        let n2 = interrupt(By::Native, 2);
        l.rec(&n2, T0 + HOUR, &["a", "b"]);
        assert_eq!(l.resign_alerts(), vec![rid(1), rid(2)]);
        l.ack_by(
            "a",
            vec![res(&n2, &[(E::Interrupt, R::Duplicate)])],
            T0 + HOUR,
        );
        assert_eq!(l.resign_alerts(), vec![rid(1), rid(2)]);
        l.ack_by(
            "b",
            vec![res(&n2, &[(E::Interrupt, R::Applied)])],
            T0 + HOUR,
        );
        // Per effect: both records are done on every covered host.
        assert_eq!(l.resign_alerts(), Vec::<String>::new());
        assert_eq!(
            l.pending_reports(),
            vec![],
            "an interrupt is never reported"
        );

        // A host principal's interrupt likewise, per `revoke_seq`.
        let h5 = host_interrupt(5, 3);
        let h6 = host_interrupt(6, 4);
        l.rec(&h5, T0, &["a"]);
        l.rec(&h6, T0, &["a"]);
        l.ack_by("a", vec![res(&h5, &[(E::Interrupt, R::Applied)])], T0);
        assert_eq!(l.resign_alerts(), vec![rid(4)], "another revocation's");
        // Only native-signed records are alerted.
        let own = interrupt(By::Own, 5);
        l.rec(&own, T0, &["a", "b"]);
        assert_eq!(l.resign_alerts(), vec![rid(4)]);
    }

    /// A re-signed `revoke` that adds `interrupt_running: true` to a revoke
    /// the hosts applied: `duplicate` for the revocation (nothing new to
    /// report), `applied` for the interrupt.
    #[test]
    fn a_resigned_revoke_that_adds_an_interrupt() {
        let (mut l, s) = revoked_ledger();
        for host in ["a", "b"] {
            l.ack_by(host, vec![res(&s, &[(E::Revocation, R::Applied)])], T0);
        }
        // Three made (two per-host reports and the final), one offered at a
        // time.
        assert_eq!((l.pending.len(), l.pending_reports().len()), (3, 1));
        let n = revoke(By::Native, true, 2);
        assert_eq!(l.rec(&n, T0 + HOUR, &["a", "b"]), vec![]);
        assert_eq!(l.resign_alerts(), vec![rid(2)]);
        let both = [(E::Revocation, R::Duplicate), (E::Interrupt, R::Applied)];
        assert_eq!(l.ack_by("a", vec![res(&n, &both)], T0 + HOUR), vec![]);
        assert_eq!(l.resign_alerts(), vec![rid(2)]);
        assert_eq!(l.ack_by("b", vec![res(&n, &both)], T0 + HOUR), vec![]);
        assert_eq!(l.resign_alerts(), Vec::<String>::new());
        // Still exactly the three reports.
        let all: Vec<Report> = l.pending.iter().map(|p| p.intent.report.clone()).collect();
        assert_eq!(
            all,
            vec![
                applied("a", &s),
                applied("b", &s),
                revoked(RevokedOutcome::AllApplied, &[])
            ]
        );
    }

    // ------------------------------------------------------------- deadline

    #[test]
    fn deadline_passed_names_the_pending_hosts() {
        let (mut l, s) = revoked_ledger();
        let a = l.ack_by("a", vec![res(&s, &[(E::Revocation, R::Applied)])], T0 + 1);
        assert_eq!(l.tick_at(T0 + DAY - 1), vec![]);
        let d = l.tick_at(T0 + DAY);
        assert_eq!(
            reports(&d),
            vec![revoked(RevokedOutcome::DeadlinePassed, &["b"])]
        );
        assert_eq!(d[0].not_before, ids(&a));
        assert_eq!(l.tick_at(T0 + 2 * DAY), vec![], "sent once");
        // `b` applies it later: its report is still true, and sent; no second
        // `revoked`.
        let b = l.ack_by(
            "b",
            vec![res(&s, &[(E::Revocation, R::Applied)])],
            T0 + 2 * DAY,
        );
        assert_eq!(reports(&b), vec![applied("b", &s)]);
    }

    /// An ack that arrives after the deadline, with no tick in between,
    /// sees the deadline first: the outcome depends on time, never on when
    /// the Station ticked.
    #[test]
    fn an_ack_after_the_deadline_sees_the_deadline_first() {
        let (mut l, s) = revoked_ledger();
        l.ack_by("a", vec![res(&s, &[(E::Revocation, R::Applied)])], T0 + 1);
        let got = l.ack_by(
            "b",
            vec![res(&s, &[(E::Revocation, R::Applied)])],
            T0 + DAY + HOUR,
        );
        assert_eq!(
            reports(&got),
            vec![
                revoked(RevokedOutcome::DeadlinePassed, &["b"]),
                applied("b", &s)
            ]
        );
        // The same ack before the deadline: all applied.
        let (mut l, s) = revoked_ledger();
        l.ack_by("a", vec![res(&s, &[(E::Revocation, R::Applied)])], T0 + 1);
        let got = l.ack_by(
            "b",
            vec![res(&s, &[(E::Revocation, R::Applied)])],
            T0 + DAY - 1,
        );
        assert_eq!(
            reports(&got),
            vec![applied("b", &s), revoked(RevokedOutcome::AllApplied, &[])]
        );
    }

    #[test]
    fn deadline_keeps_the_original_revocation_time_after_restart() {
        let (mut l, s) = revoked_ledger();
        // A later revoke of the same principal (a re-signed copy, a
        // snapshot after a reset) never moves the revocation's time or
        // its hosts.
        let s2 = revoke(By::Own, true, 2);
        assert_eq!(l.rec(&s2, T0 + 20 * HOUR, &["a", "b", "c"]), vec![]);
        l.ack_by(
            "a",
            vec![res(&s, &[(E::Revocation, R::Applied)])],
            T0 + HOUR,
        );
        // The Station restarts (and restarts again) 23 hours later: the
        // state it persisted is all it has.
        let mut restarted = AckLedger::from_json(&l.to_json()).unwrap();
        assert_eq!(restarted, l);
        assert_eq!(restarted.tick_at(T0 + DAY - 1), vec![]);
        let mut restarted = AckLedger::from_json(&restarted.to_json()).unwrap();
        assert_eq!(
            reports(&restarted.tick_at(T0 + DAY)),
            vec![revoked(RevokedOutcome::DeadlinePassed, &["b"])]
        );
    }

    #[test]
    fn all_applied_has_empty_pending_hosts_and_deadline_passed_does_not() {
        let (mut l, s) = revoked_ledger();
        for host in ["a", "b"] {
            l.ack_by(host, vec![res(&s, &[(E::Revocation, R::Applied)])], T0);
        }
        let finals: Vec<Report> = l
            .pending
            .iter()
            .map(|p| p.intent.report.clone())
            .filter(|r| matches!(r, Report::Revoked { .. }))
            .collect();
        assert_eq!(finals, vec![revoked(RevokedOutcome::AllApplied, &[])]);

        let (mut l, _) = revoked_ledger();
        let d = l.tick_at(T0 + DAY);
        assert_eq!(
            reports(&d),
            vec![revoked(RevokedOutcome::DeadlinePassed, &["a", "b"])]
        );

        // A state that says otherwise is refused.
        let mut v = l.to_json();
        let at = v["pending"].as_array().unwrap().len() - 1;
        v["pending"][at]["report"]["pending_hosts"] = json!([]);
        assert!(AckLedger::from_json(&v).is_err());
        let (mut l, s) = revoked_ledger();
        for host in ["a", "b"] {
            l.ack_by(host, vec![res(&s, &[(E::Revocation, R::Applied)])], T0);
        }
        let mut v = l.to_json();
        v["pending"][2]["report"]["pending_hosts"] = json!(["a"]);
        assert!(AckLedger::from_json(&v).is_err());
    }

    // --------------------------------------------------- report delivery

    #[test]
    fn all_applied_waits_for_per_host_confirmations() {
        let (mut l, s) = revoked_ledger();
        let a = l.ack_by("a", vec![res(&s, &[(E::Revocation, R::Applied)])], T0);
        let b = l.ack_by("b", vec![res(&s, &[(E::Revocation, R::Applied)])], T0);
        let (ra, rb, fin) = (a[0].clone(), b[0].clone(), b[1].clone());
        // The final's intent exists (persisted with the state), but is not
        // delivered before the per-host reports it requires: reports of one
        // principal go in the order they were made, one at a time.
        assert_eq!(l.pending_reports(), vec![ra.clone()]);
        l.confirm_id(&ra.report_id);
        assert_eq!(l.pending_reports(), vec![rb.clone()]);
        l.confirm_id(&rb.report_id);
        assert_eq!(l.pending_reports(), vec![fin.clone()]);
        l.confirm_id(&fin.report_id);
        assert_eq!(l.pending_reports(), vec![]);
        // A confirmation repeated, or of an id never made, changes nothing.
        let before = l.clone();
        for id in [&fin.report_id, &ra.report_id, &"revoked:nope".to_owned()] {
            let t = l.confirm(id);
            assert_eq!((t.next, t.made), (before.clone(), vec![]));
        }
        // `deadline_passed` waits for the per-host reports made before it.
        let (mut l, s) = revoked_ledger();
        let a = l.ack_by("a", vec![res(&s, &[(E::Revocation, R::Applied)])], T0);
        let d = l.tick_at(T0 + DAY);
        assert_eq!(l.pending_reports(), a);
        l.confirm_id(&a[0].report_id);
        assert_eq!(l.pending_reports(), d);
    }

    /// Reports of one principal go to the Portal in the order they were
    /// made: a late host's report waits for the revocation's final made
    /// before it (a Portal outage across the deadline, or a 403 stop across
    /// it, must never let it overtake).
    #[test]
    fn reports_of_one_principal_go_in_the_order_they_were_made() {
        // A Portal outage across the deadline.
        let mut l = ledger();
        let s = revoke(By::Own, false, 1);
        l.rec(&s, T0, &["a", "b", "c"]);
        let a1 = l.ack_by("a", vec![res(&s, &[(E::Revocation, R::Applied)])], T0);
        // a1 is not confirmed: the Portal is down.
        let f = l.tick_at(T0 + DAY);
        assert_eq!(
            reports(&f),
            vec![revoked(RevokedOutcome::DeadlinePassed, &["b", "c"])]
        );
        let b1 = l.ack_by(
            "b",
            vec![res(&s, &[(E::Revocation, R::Applied)])],
            T0 + DAY + 1,
        );
        assert_eq!(reports(&b1), vec![applied("b", &s)]);
        assert_eq!(b1[0].not_before, Vec::<String>::new());
        // Only the earliest: b's report never goes before the final.
        assert_eq!(l.pending_reports(), a1);
        l.confirm_id(&a1[0].report_id);
        assert_eq!(l.pending_reports(), f);
        l.confirm_id(&f[0].report_id);
        assert_eq!(l.pending_reports(), b1);
        // A refused report settles its place in the order too.
        let mut r = l.clone();
        r = r.refuse(&b1[0].report_id).next;
        assert_eq!(r.pending_reports(), vec![]);

        // A 403 stop across the deadline, then a resume under the same ID.
        let mut l = ledger();
        l.rec(&s, T0, &["a", "b", "c"]);
        let a1 = l.ack_by("a", vec![res(&s, &[(E::Revocation, R::Applied)])], T0);
        l = l.stop_reporting(CLIENT).unwrap().next;
        let f = l.tick_at(T0 + DAY);
        let b1 = l.ack_by(
            "b",
            vec![res(&s, &[(E::Revocation, R::Applied)])],
            T0 + DAY + 1,
        );
        l = l.resume_reporting(CLIENT).unwrap().next;
        assert_eq!(l.pending_reports(), a1);
        l.confirm_id(&a1[0].report_id);
        assert_eq!(l.pending_reports(), f);
        l.confirm_id(&f[0].report_id);
        assert_eq!(l.pending_reports(), b1);

        // Another principal's reports don't wait: the order is per
        // principal.
        let mut l = ledger();
        l.rec(&s, T0, &["a", "b"]);
        let s2 = rec_for(
            ACCOUNT,
            ORIGIN,
            "svc-2",
            By::Own,
            ControlAction::Revoke {
                interrupt_running: false,
            },
            2,
        );
        l.rec(&s2, T0, &["a"]);
        let a1 = l.ack_by(
            "a",
            vec![
                res(&s, &[(E::Revocation, R::Applied)]),
                res(&s2, &[(E::Revocation, R::Applied)]),
            ],
            T0,
        );
        assert_eq!(a1.len(), 3, "svc-1's report, svc-2's report and its final");
        assert_eq!(l.pending_reports(), a1[..2].to_vec());
    }

    /// A Station in the tests: its committed state (the JSON it persisted)
    /// and a Portal that keeps the first body per `report_id`, and answers
    /// a repeat with the same body as accepted.
    struct Station {
        committed: Value,
        portal: BTreeMap<String, String>,
        posts: usize,
    }

    impl Station {
        fn new(l: &AckLedger) -> Self {
            Station {
                committed: l.to_json(),
                portal: BTreeMap::new(),
                posts: 0,
            }
        }

        fn load(&self) -> AckLedger {
            AckLedger::from_json(&self.committed).unwrap()
        }

        fn commit(&mut self, t: LedgerTransition) {
            self.committed = t.next.to_json();
        }

        /// POSTs each pending report in order; `lost` loses the answers
        /// (the Portal got them), `fail` makes the Portal refuse them
        /// (nothing recorded). Confirms what was answered.
        fn deliver(&mut self, lost: bool, fail: bool) {
            for intent in self.load().pending_reports() {
                self.posts += 1;
                if fail {
                    return;
                }
                let body = bytes(&intent);
                let first = self
                    .portal
                    .entry(intent.report_id.clone())
                    .or_insert(body.clone());
                assert_eq!(*first, body, "one report_id, one body");
                if lost {
                    return;
                }
                let t = self.load().confirm(&intent.report_id);
                self.commit(t);
            }
        }
    }

    /// Fixture `r9-control-ack-durable`'s cases: a crash before the
    /// commit, after it, and after delivery but before the confirmation;
    /// a Portal failure; a lost first ack; replicas. Exactly one body per
    /// `report_id`, and every report delivered.
    #[test]
    fn restarts_around_the_report_boundary_deliver_one_report_per_id() {
        let (l, s) = revoked_ledger();
        let mut st = Station::new(&l);
        let ack_a = || ack("a", vec![res(&s, &[(E::Revocation, R::Applied)])]);
        let ack_b = || ack("b", vec![res(&s, &[(E::Revocation, R::Applied)])]);

        // A crash before the commit: the transition is lost, the host
        // resends its ack, and the same transition comes again.
        let lost = st.load().ack(&link("a"), &ack_a(), T0).unwrap();
        let again = st.load().ack(&link("a"), &ack_a(), T0).unwrap();
        assert_eq!(lost, again);
        st.commit(again);
        // A crash after the commit, before delivery: a restart delivers.
        // The Portal fails the first time; the retry carries the same id.
        st.deliver(false, true);
        assert!(st.portal.is_empty());
        // Delivered, but the answer is lost before the confirmation.
        st.deliver(true, false);
        assert_eq!(st.portal.len(), 1);
        // A restart sends it again: the same id and body.
        st.deliver(false, false);
        assert_eq!(st.portal.len(), 1);
        assert_eq!(st.load().pending_reports(), vec![]);

        // The host resends its first ack after all (its answer was lost):
        // nothing is counted twice.
        let t = st.load().ack(&link("a"), &ack_a(), T0 + 1).unwrap();
        assert_eq!(t.made, vec![]);
        st.commit(t);

        // Two replicas load the same state and process the same ack: the
        // same next state and the same intents, so the Portal deduplicates.
        let r1 = st.load().ack(&link("b"), &ack_b(), T0 + 2).unwrap();
        let r2 = AckLedger::from_json(&st.committed)
            .unwrap()
            .ack(&link("b"), &ack_b(), T0 + 2)
            .unwrap();
        assert_eq!(r1, r2);
        assert_eq!(jcs(&r1.next.to_json()), jcs(&r2.next.to_json()));
        st.commit(r1);
        st.deliver(true, false);
        st.deliver(false, false);
        st.deliver(false, false);
        assert_eq!(st.load().pending_reports(), vec![]);
        let kinds: BTreeSet<&str> = st
            .portal
            .keys()
            .map(|id| id.split(':').next().unwrap())
            .collect();
        assert_eq!(st.portal.len(), 3);
        assert_eq!(kinds, BTreeSet::from(["revocation_applied", "revoked"]));
    }

    #[test]
    fn report_ids_are_stable_across_restart_and_replicas() {
        let (l, s) = revoked_ledger();
        let a = ack("a", vec![res(&s, &[(E::Revocation, R::Applied)])]);
        let live = l.ack(&link("a"), &a, T0).unwrap();
        let restarted = AckLedger::from_json(&l.to_json())
            .unwrap()
            .ack(&link("a"), &a, T0)
            .unwrap();
        let replica = l.clone().ack(&link("a"), &a, T0 + 5 * HOUR).unwrap();
        assert_eq!(live, restarted);
        assert_eq!(ids(&live.made), ids(&replica.made));
        // The id comes from the report's identity, never from time, a
        // counter or the order of events: `a` reports through another
        // record, later, after `b`.
        let mut other = l.clone();
        let n = revoke(By::Native, false, 7);
        other.rec(&n, T0, &["a", "b"]);
        other.ack_by("b", vec![res(&s, &[(E::Revocation, R::Applied)])], T0);
        let via_n = other.ack_by(
            "a",
            vec![res(&n, &[(E::Revocation, R::Applied)])],
            T0 + HOUR,
        );
        assert_eq!(via_n[0].report_id, live.made[0].report_id);

        // Known answer: SHA-256 of enc(["atem-station-report-id-v1",
        // "revocation_applied", account, genesis (raw), principal,
        // integration, host]), computed independently with Python's
        // hashlib.
        assert_eq!(
            live.made[0].report_id,
            "revocation_applied:078ccdbdd6b5148ded0176c622edf34bcda5d856223d19909be0b60e84bf8a8c"
        );
        let mut all = l.clone();
        all.ack_by("a", vec![res(&s, &[(E::Revocation, R::Applied)])], T0);
        let fin = all.ack_by("b", vec![res(&s, &[(E::Revocation, R::Applied)])], T0);
        assert_eq!(
            fin[1].report_id,
            "revoked:3a5426b6eb2f7c7c4ea92347b0371ae7b64006326709d69d37448e98372b20bb"
        );
        // Both outcomes of one revocation share the id: one final per
        // revocation, so two diverging Station histories can't both count.
        let (mut late, _) = revoked_ledger();
        assert_eq!(late.tick_at(T0 + DAY)[0].report_id, fin[1].report_id);
    }

    #[test]
    fn report_ids_fit_the_portal_format() {
        fn fits(id: &str) -> bool {
            (1..=128).contains(&id.chars().count())
                && id
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-'))
        }
        let (mut l, s) = revoked_ledger();
        let mut made = l.ack_by("a", vec![res(&s, &[(E::Revocation, R::Applied)])], T0);
        made.extend(l.tick_at(T0 + DAY));
        assert_eq!(made.len(), 2);
        for intent in &made {
            assert!(fits(&intent.report_id), "{}", intent.report_id);
            assert!(id_ok(&intent.report_id));
        }
        // The longest inputs still fit: an id is a kind and a hash.
        let long = "x".repeat(128);
        let mut l = AckLedger::new(ORIGIN, &long, genesis()).unwrap();
        let s = rec_of(
            &long,
            ORIGIN,
            By::Own,
            ControlAction::Revoke {
                interrupt_running: false,
            },
            1,
        );
        l.rec(&s, T0, &[&long]);
        let mut big = link(&long);
        big.account_id = long.clone();
        big.connection_id = "conn-long".into();
        let mut a = ack(&long, vec![res(&s, &[(E::Revocation, R::Applied)])]);
        a.account_id = long.clone();
        let t = l.ack(&big, &a, T0).unwrap();
        for intent in &t.made {
            assert!(fits(&intent.report_id), "{}", intent.report_id);
        }
    }

    #[test]
    fn one_report_id_always_has_one_body() {
        let mut seen: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut note = |intents: &[ReportIntent]| {
            for i in intents {
                seen.entry(i.report_id.clone())
                    .or_default()
                    .insert(bytes(i));
            }
        };
        let (l, s) = revoked_ledger();
        let n = revoke(By::Native, true, 2);
        let step = |l: &AckLedger| -> AckLedger {
            let mut l = l.clone();
            l.rec(&n, T0, &["a", "b"]);
            l
        };
        let l = step(&l);
        let a = ack(
            "a",
            vec![
                res(
                    &n,
                    &[(E::Revocation, R::Applied), (E::Interrupt, R::Applied)],
                ),
                res(&s, &[(E::Revocation, R::Duplicate)]),
            ],
        );
        let b = ack("b", vec![res(&s, &[(E::Revocation, R::Applied)])]);
        // Retry, restart and replica, for each ack in turn.
        let mut current = l;
        for (host, a) in [("a", &a), ("b", &b)] {
            let first = current.ack(&link(host), a, T0).unwrap();
            let retry = current.ack(&link(host), a, T0).unwrap();
            let restart = AckLedger::from_json(&current.to_json())
                .unwrap()
                .ack(&link(host), a, T0)
                .unwrap();
            let replica = current.clone().ack(&link(host), a, T0 + HOUR).unwrap();
            for t in [&first, &retry, &restart, &replica] {
                note(&t.made);
                note(&t.next.pending_reports());
            }
            for (x, y) in [(&first, &retry), (&first, &restart)] {
                let bx: Vec<String> = x.made.iter().map(bytes).collect();
                let by: Vec<String> = y.made.iter().map(bytes).collect();
                assert_eq!(bx, by);
            }
            current = first.next;
        }
        note(&current.tick(T0 + DAY).made);
        assert_eq!(seen.len(), 3);
        for (id, bodies) in &seen {
            assert_eq!(bodies.len(), 1, "{id}");
        }
    }

    // ---------------------------------------------------------- refusals

    #[test]
    fn ack_from_another_association_refused() {
        let (l, s) = revoked_ledger();
        let good = || ack("a", vec![res(&s, &[(E::Revocation, R::Applied)])]);
        assert!(l.ack(&link("a"), &good(), T0).is_ok());

        // The ack's claims differ from the link's association: the
        // account, the root, the host or the trust generation.
        let mut claims: Vec<ControlAck> = Vec::new();
        let mut x = good();
        x.account_id = "acct-other".into();
        claims.push(x);
        let mut x = good();
        x.genesis_hash = Hash32([8; 32]);
        claims.push(x);
        let mut x = good();
        x.host_id = "b".into();
        claims.push(x);
        let mut x = good();
        x.host_trust_gen = 2;
        claims.push(x);
        for x in &claims {
            assert_eq!(l.ack(&link("a"), x, T0), Err(AckRefusal::NotTheLink));
        }
        // The link's own association differs the same way.
        let mut links: Vec<LinkAssociation> = Vec::new();
        let mut x = link("a");
        x.host_trust_gen = 2;
        links.push(x);
        let mut x = link("a");
        x.host_id = "b".into();
        links.push(x);
        for x in &links {
            assert_eq!(l.ack(x, &good(), T0), Err(AckRefusal::NotTheLink));
        }
        // Link and ack agree, but name another account or root than this
        // ledger's.
        for (account, root) in [("acct-other", genesis()), (ACCOUNT, Hash32([8; 32]))] {
            let mut x = link("a");
            x.account_id = account.into();
            x.genesis_hash = root;
            let mut a = good();
            a.account_id = account.into();
            a.genesis_hash = root;
            assert_eq!(l.ack(&x, &a, T0), Err(AckRefusal::OtherAccount));
        }
        // The connection: an association without one, or with one out of
        // grammar, is no authenticated association.
        for connection in ["", "conn a", &"c".repeat(129)] {
            let mut x = link("a");
            x.connection_id = connection.into();
            assert_eq!(l.ack(&x, &good(), T0), Err(AckRefusal::IncompleteLink));
        }
        let mut x = link("a");
        x.host_trust_gen = 0;
        assert_eq!(l.ack(&x, &good(), T0), Err(AckRefusal::IncompleteLink));
        // Another Station's feed.
        let mut a = good();
        a.origin = "https://station-b.example.com".into();
        assert_eq!(l.ack(&link("a"), &a, T0), Err(AckRefusal::OtherStation));
        // An ack the relay reader would refuse.
        let mut a = good();
        a.feed_id = "not-a-uuid".into();
        assert_eq!(
            l.ack(&link("a"), &a, T0),
            Err(AckRefusal::Malformed(RelayError::Malformed("feed_id")))
        );
        // Each refusal has its own stable code.
        let codes: BTreeSet<&str> = [
            AckRefusal::IncompleteLink,
            AckRefusal::NotTheLink,
            AckRefusal::OtherAccount,
            AckRefusal::OtherStation,
            AckRefusal::Malformed(RelayError::TooLarge),
            AckRefusal::NotTheRecord(rid(1)),
        ]
        .iter()
        .map(AckRefusal::code)
        .collect();
        assert_eq!(codes.len(), 6);
    }

    #[test]
    fn ack_effects_must_be_the_records() {
        let (l, s) = revoked_ledger();
        // `s` carries the revocation only; this ack names an interrupt too.
        let a = ack(
            "a",
            vec![res(
                &s,
                &[(E::Revocation, R::Applied), (E::Interrupt, R::Applied)],
            )],
        );
        assert_eq!(
            l.ack(&link("a"), &a, T0),
            Err(AckRefusal::NotTheRecord(rid(1)))
        );
        let a = ack("a", vec![res(&s, &[(E::Interrupt, R::Applied)])]);
        assert_eq!(
            l.ack(&link("a"), &a, T0),
            Err(AckRefusal::NotTheRecord(rid(1)))
        );
        // One bad result refuses the whole ack: the good one isn't counted.
        let i = interrupt(By::Native, 2);
        let mut l2 = l.clone();
        l2.rec(&i, T0, &["a"]);
        let a = ack(
            "a",
            vec![
                res(&s, &[(E::Revocation, R::Applied)]),
                res(&i, &[(E::Revocation, R::Applied)]),
            ],
        );
        assert_eq!(
            l2.ack(&link("a"), &a, T0),
            Err(AckRefusal::NotTheRecord(rid(2)))
        );
    }

    /// Every effect set a record carries (the control state's own list) is
    /// an ack the relay builds and reads: the ledger's records and the
    /// relay's canonical sets can't drift apart (Task 14 review, minor 1).
    #[test]
    fn every_record_effect_set_is_an_ack_the_relay_reads() {
        // Every action, each after the one before: an exhaustive match with
        // no wildcard, so a new `ControlAction` variant fails to compile
        // here until it is chained in.
        fn after(a: Option<ControlAction>) -> Option<ControlAction> {
            use ControlAction::*;
            match a {
                None => Some(Cover),
                Some(Cover) => Some(Revoke {
                    interrupt_running: false,
                }),
                Some(Revoke {
                    interrupt_running: false,
                }) => Some(Revoke {
                    interrupt_running: true,
                }),
                Some(Revoke {
                    interrupt_running: true,
                }) => Some(Hold),
                Some(Hold) => Some(Release),
                Some(Release) => Some(InterruptRunning { revoke_seq: None }),
                Some(InterruptRunning { revoke_seq: None }) => Some(InterruptRunning {
                    revoke_seq: Some(7),
                }),
                Some(InterruptRunning {
                    revoke_seq: Some(_),
                }) => None,
            }
        }
        let actions: Vec<ControlAction> =
            std::iter::successors(after(None), |a| after(Some(*a))).collect();
        assert_eq!(actions.len(), 7);
        for action in actions {
            let effects = EffectKind::of(action)
                .into_iter()
                .map(|effect| EffectResult {
                    effect,
                    result: R::Applied,
                })
                .collect();
            let a = ack(
                "a",
                vec![AckResult::Record {
                    record_id: rid(1),
                    effects,
                }],
            );
            let wire = a.to_json().unwrap();
            assert_eq!(ControlAck::decode(wire.to_string().as_bytes()).unwrap(), a);
        }
    }

    #[test]
    fn record_refusals() {
        let l = ledger();
        let s = revoke(By::Own, false, 1);
        // Another account, another root, another Station's feed.
        let other = rec_of("acct-other", ORIGIN, By::Own, ControlAction::Hold, 2);
        assert_eq!(
            l.record(&other, T0, &[], T0).unwrap_err(),
            RecordRefusal::OtherAccount
        );
        let rooted = AckLedger::new(ORIGIN, ACCOUNT, Hash32([8; 32])).unwrap();
        assert_eq!(
            rooted.record(&s, T0, &[], T0).unwrap_err(),
            RecordRefusal::OtherAccount
        );
        let elsewhere = rec_of(
            ACCOUNT,
            "https://station-b.example.com",
            By::Native,
            ControlAction::Revoke {
                interrupt_running: false,
            },
            3,
        );
        assert_eq!(
            l.record(&elsewhere, T0, &[], T0).unwrap_err(),
            RecordRefusal::OtherStation
        );
        // Hosts out of grammar or too many, a time out of range.
        for bad in [
            hosts(&[""]),
            hosts(&["a b"]),
            (0..=MAX_HOSTS).map(|i| format!("h{i}")).collect(),
        ] {
            assert!(matches!(
                l.record(&s, T0, &bad, T0).unwrap_err(),
                RecordRefusal::Malformed(_)
            ));
        }
        assert!(matches!(
            l.record(&s, MAX_SAFE_INTEGER + 1, &[], T0).unwrap_err(),
            RecordRefusal::Malformed(_)
        ));
        // The same record again is no change (a retried intake, a
        // snapshot's re-issue in a new feed); its first hosts stand.
        let mut l = ledger();
        l.rec(&s, T0, &["a", "b"]);
        let t = l.record(&s, T0 + HOUR, &hosts(&["c"]), T0 + HOUR).unwrap();
        assert_eq!((t.next, t.made), (l.clone(), vec![]));
        // Another body under a record id the ledger holds: an ack naming
        // that id would be ambiguous.
        let reused = rec(
            By::Own,
            ControlAction::Revoke {
                interrupt_running: true,
            },
            1,
        );
        assert_eq!(
            l.record(&reused, T0, &[], T0).unwrap_err(),
            RecordRefusal::RecordIdReused
        );
        // A hold reusing it is refused too: ids are this feed's.
        let reused = rec(By::Own, ControlAction::Hold, 1);
        assert_eq!(
            l.record(&reused, T0, &[], T0).unwrap_err(),
            RecordRefusal::RecordIdReused
        );
        // Duplicated hosts are one set.
        let mut d = ledger();
        d.rec(&s, T0, &["b", "a", "b"]);
        assert_eq!(
            reports(&d.tick_at(T0 + DAY)),
            vec![revoked(RevokedOutcome::DeadlinePassed, &["a", "b"])]
        );
        // `new` takes only an exact origin and an account id in grammar.
        assert!(AckLedger::new("https://Station-dev.agora.build/", ACCOUNT, genesis()).is_err());
        assert!(AckLedger::new(ORIGIN, "", genesis()).is_err());
        assert!(AckLedger::new(ORIGIN, &"x".repeat(129), genesis()).is_err());
    }

    // ------------------------------------------------------------- state

    /// A ledger with every kind of entry: tracked own, native and host
    /// principal records, counted effects of both kinds, revocations with
    /// and without an outcome, pending intents with `not_before`.
    fn full() -> AckLedger {
        let (mut l, s) = revoked_ledger();
        let n = revoke(By::Native, true, 2);
        l.rec(&n, T0, &["a", "c"]);
        let h = host_interrupt(5, 3);
        l.rec(&h, T0, &["b"]);
        l.ack_by(
            "a",
            vec![
                res(
                    &n,
                    &[(E::Revocation, R::Duplicate), (E::Interrupt, R::Applied)],
                ),
                res(&s, &[(E::Revocation, R::Applied)]),
            ],
            T0,
        );
        l.ack_by("b", vec![res(&h, &[(E::Interrupt, R::Applied)])], T0);
        l.ack_by("b", vec![res(&s, &[(E::Revocation, R::Applied)])], T0);
        l
    }

    #[test]
    fn state_json_round_trips() {
        for l in [
            ledger(),
            revoked_ledger().0,
            full(),
            {
                let mut d = full();
                d.tick_at(T0 + DAY);
                d
            },
            {
                let (mut d, _) = revoked_ledger();
                d.tick_at(T0 + DAY);
                d
            },
        ] {
            let v = l.to_json();
            let back = AckLedger::from_json(&v).unwrap();
            assert_eq!(back, l);
            assert_eq!(back.to_json(), v);
            // Deterministic bytes: sorted keys, sets sorted.
            assert_eq!(v.to_string(), jcs(&v).unwrap());
            // A state read from bytes is the same.
            let reread: Value = serde_json::from_str(&v.to_string()).unwrap();
            assert_eq!(AckLedger::from_json(&reread).unwrap(), l);
        }
        let v = full().to_json();
        assert_eq!(v["v"], json!(1));
        assert_eq!(v["origin"], json!(ORIGIN));
        assert_eq!(v["records"][rid(1)]["native"], json!(false));
        assert_eq!(
            v["records"][rid(2)]["effects"],
            json!(["revocation", "interrupt"])
        );
        assert_eq!(v["records"][rid(3)]["revoke_seq"], json!(5));
        assert_eq!(
            v["revocations"]["service:svc-1"]["revoked_at_ms"],
            json!(T0)
        );
    }

    #[test]
    fn state_json_is_read_strictly() {
        let good = full().to_json();
        assert!(AckLedger::from_json(&good).is_ok());
        type Edit = Box<dyn Fn(&mut Value)>;
        let edits: Vec<(&str, Edit)> = vec![
            ("v", Box::new(|v| v["v"] = json!(2))),
            ("unknown", Box::new(|v| v["extra"] = json!(1))),
            ("null", Box::new(|v| v["revocations"] = Value::Null)),
            (
                "origin",
                Box::new(|v| v["origin"] = json!("https://Station-dev.agora.build/")),
            ),
            ("account", Box::new(|v| v["account_id"] = json!(""))),
            ("genesis", Box::new(|v| v["genesis_hash"] = json!("AB"))),
            (
                "record id",
                Box::new(|v| {
                    let r = v["records"][rid(1)].take();
                    v["records"]["nope"] = r;
                    v["records"].as_object_mut().unwrap().remove(&rid(1));
                }),
            ),
            (
                "record field",
                Box::new(|v| v["records"][rid(1)]["x"] = json!(1)),
            ),
            (
                "effects",
                Box::new(|v| v["records"][rid(1)]["effects"] = json!(["interrupt", "revocation"])),
            ),
            (
                "host effects",
                Box::new(|v| v["records"][rid(3)]["effects"] = json!(["revocation"])),
            ),
            (
                "revoke_seq on a service",
                Box::new(|v| v["records"][rid(1)]["revoke_seq"] = json!(5)),
            ),
            (
                "no revoke_seq on a host",
                Box::new(|v| {
                    v["records"][rid(3)]
                        .as_object_mut()
                        .unwrap()
                        .remove("revoke_seq");
                }),
            ),
            (
                "covered unsorted",
                Box::new(|v| v["records"][rid(1)]["covered"] = json!(["b", "a"])),
            ),
            (
                "covered repeated",
                Box::new(|v| v["records"][rid(1)]["covered"] = json!(["a", "a"])),
            ),
            (
                "digest",
                Box::new(|v| v["records"][rid(1)]["digest"] = json!("00")),
            ),
            (
                "revocation without its record",
                Box::new(|v| {
                    v["records"][rid(1)]["native"] = json!(true);
                }),
            ),
            (
                "revocation key",
                Box::new(|v| {
                    let r = v["revocations"]["service:svc-1"].take();
                    v["revocations"] = json!({"host:svc-1": r});
                }),
            ),
            (
                "revocation outcome",
                Box::new(|v| v["revocations"]["service:svc-1"]["outcome"] = json!("done")),
            ),
            (
                "revocation without an outcome though all applied",
                Box::new(|v| {
                    v["revocations"]["service:svc-1"]
                        .as_object_mut()
                        .unwrap()
                        .remove("outcome");
                }),
            ),
            (
                "revoked_at_ms",
                Box::new(|v| v["revocations"]["service:svc-1"]["revoked_at_ms"] = json!(-1)),
            ),
            (
                "done order",
                Box::new(|v| {
                    let d = v["done"].as_array_mut().unwrap();
                    d.reverse();
                }),
            ),
            (
                "done repeated",
                Box::new(|v| {
                    let d = v["done"].as_array_mut().unwrap();
                    let first = d[0].clone();
                    d.insert(0, first);
                }),
            ),
            (
                "done of an unknown record",
                Box::new(|v| v["done"][0]["record_id"] = json!(rid(99))),
            ),
            (
                "done of another principal",
                Box::new(|v| v["done"][0]["principal"] = json!("service:svc-2")),
            ),
            (
                "done of an effect the record lacks",
                Box::new(|v| {
                    for d in v["done"].as_array_mut().unwrap() {
                        if d["record_id"] == json!(rid(1)) {
                            d["effect"] = json!("interrupt");
                        }
                    }
                }),
            ),
            (
                "pending id",
                Box::new(|v| v["pending"][0]["report_id"] = json!("revocation_applied:00")),
            ),
            (
                "pending principal",
                Box::new(|v| v["pending"][0]["principal"] = json!("service:svc-2")),
            ),
            (
                "pending record",
                Box::new(|v| v["pending"][0]["report"]["record_id"] = json!(rid(3))),
            ),
            (
                "pending integration",
                Box::new(|v| v["pending"][0]["report"]["integration_id"] = json!("i-other")),
            ),
            (
                "pending kind",
                Box::new(|v| v["pending"][0]["report"]["kind"] = json!("ready")),
            ),
            (
                "pending not_before",
                Box::new(|v| v["pending"][0]["not_before"] = json!(["x"])),
            ),
            (
                "pending repeated",
                Box::new(|v| {
                    let p = v["pending"].as_array_mut().unwrap();
                    let first = p[0].clone();
                    p.push(first);
                }),
            ),
            (
                "final not_before",
                Box::new(|v| {
                    let p = v["pending"].as_array_mut().unwrap();
                    let last = p.len() - 1;
                    p[last]["not_before"] = json!([]);
                }),
            ),
            (
                "final outcome",
                Box::new(|v| {
                    let p = v["pending"].as_array_mut().unwrap();
                    let last = p.len() - 1;
                    p[last]["report"]["outcome"] = json!("deadline_passed");
                }),
            ),
            (
                "final outcome not the revocation's",
                Box::new(|v| {
                    v["revocations"]["service:svc-1"]["outcome"] = json!("deadline_passed");
                }),
            ),
        ];
        for (what, edit) in edits {
            let mut v = good.clone();
            edit(&mut v);
            assert!(AckLedger::from_json(&v).is_err(), "{what}: {v}");
        }

        // With every report confirmed, the revocation's outcome alone says a
        // final was made: one missing would make it again.
        let mut l = full();
        while let Some(intent) = l.pending_reports().into_iter().next() {
            l.confirm_id(&intent.report_id);
        }
        assert!(l.pending.is_empty());
        let mut v = l.to_json();
        assert!(AckLedger::from_json(&v).is_ok());
        v["revocations"]["service:svc-1"]
            .as_object_mut()
            .unwrap()
            .remove("outcome");
        assert!(AckLedger::from_json(&v).is_err());
        // And `all_applied` while a covered host doesn't have it in force.
        let (mut l, s) = revoked_ledger();
        l.ack_by("a", vec![res(&s, &[(E::Revocation, R::Applied)])], T0);
        let mut v = l.to_json();
        v["revocations"]["service:svc-1"]["outcome"] = json!("all_applied");
        assert!(AckLedger::from_json(&v).is_err());
    }

    /// The feed an ack names is the host's word about what it read; the
    /// counting is per record, so a snapshot's feed after a reset counts
    /// the same record once.
    #[test]
    fn a_record_counts_once_from_any_feed_of_this_station() {
        let (mut l, s) = revoked_ledger();
        let mut a = ack("a", vec![res(&s, &[(E::Revocation, R::Applied)])]);
        a.feed_id = FEED2.into();
        let t = l.ack(&link("a"), &a, T0).unwrap();
        assert_eq!(reports(&t.made), vec![applied("a", &s)]);
        l = t.next;
        assert_eq!(
            l.ack_by("a", vec![res(&s, &[(E::Revocation, R::Duplicate)])], T0),
            vec![]
        );
    }

    // ------------------------------------------------------ Portal answers

    /// The Portal's answers to a report, in their classes (Auth/Portal,
    /// 2026-11-10).
    #[test]
    fn portal_answers_fall_in_four_classes() {
        use ReportAnswer as A;
        assert_eq!(ReportAnswer::of_status(200), A::Confirm);
        // 408 is a timeout: retried like one.
        for status in [500, 501, 502, 503, 504, 599, 429, 401, 408] {
            assert_eq!(ReportAnswer::of_status(status), A::Retry, "{status}");
        }
        for status in [400, 404, 405, 409, 410, 413, 415, 422, 451, 499] {
            assert_eq!(ReportAnswer::of_status(status), A::Refuse, "{status}");
        }
        assert_eq!(ReportAnswer::of_status(403), A::StopReporting);
        // A status the Portal never answers with: final, with an alert.
        for status in [0, 100, 201, 202, 204, 301, 302, 304, 600, 999] {
            assert_eq!(ReportAnswer::of_status(status), A::Refuse, "{status}");
        }
        let codes: Vec<&str> = [A::Confirm, A::Retry, A::Refuse, A::StopReporting]
            .into_iter()
            .map(ReportAnswer::code)
            .collect();
        assert_eq!(codes, ["confirm", "retry", "refuse", "stop_reporting"]);
    }

    #[test]
    fn a_report_refused_for_good_is_done_and_alerted_once() {
        let (mut l, s) = revoked_ledger();
        let a = l.ack_by("a", vec![res(&s, &[(E::Revocation, R::Applied)])], T0);
        let t = l.refuse(&a[0].report_id);
        assert_eq!(t.made, vec![]);
        assert_eq!(
            t.alerts,
            vec![LedgerAlert::ReportRefused {
                report_id: a[0].report_id.clone()
            }]
        );
        assert_eq!(
            t.alerts[0].to_json(),
            json!({"kind": "report_refused", "report_id": a[0].report_id})
        );
        assert_eq!(l.pending_reports(), a, "the ledger refused on is unchanged");
        l = t.next;
        assert_eq!(l.pending_reports(), vec![]);
        assert_eq!(l.refused_reports(), ids(&a));
        // Refused again, or an id never made: no change and no alert. A
        // late confirmation of a refused report changes nothing either.
        for id in [a[0].report_id.as_str(), "revoked:nope"] {
            let t = l.refuse(id);
            assert_eq!((t.next, t.made, t.alerts), (l.clone(), vec![], vec![]));
        }
        assert_eq!(l.confirm(&a[0].report_id).next, l);
        // A report waiting for a refused one goes once the others are
        // confirmed: the refusal settled it.
        let b = l.ack_by("b", vec![res(&s, &[(E::Revocation, R::Applied)])], T0);
        assert_eq!(b[1].not_before.len(), 2);
        assert_eq!(l.pending_reports(), vec![b[0].clone()]);
        l.confirm_id(&b[0].report_id);
        assert_eq!(l.pending_reports(), vec![b[1].clone()]);
        // The state keeps the refusals and reads them back exactly.
        let v = l.to_json();
        assert_eq!(v["refused"], json!(ids(&a)));
        assert_eq!(v.get("stopped"), None);
        assert_eq!(AckLedger::from_json(&v).unwrap(), l);
    }

    const CLIENT: &str = "station-dev-client-1";
    const CLIENT2: &str = "station-dev-client-2";

    /// A 403 stops reporting under the report client ID that got it: every
    /// report is held, none is sent, counting and reports go on, one alert.
    #[test]
    fn a_stop_holds_every_report_and_alerts_once() {
        let (mut l, s) = revoked_ledger();
        let a = l.ack_by("a", vec![res(&s, &[(E::Revocation, R::Applied)])], T0);
        let t = l.stop_reporting(CLIENT).unwrap();
        assert_eq!(t.made, vec![]);
        assert_eq!(
            t.alerts,
            vec![LedgerAlert::ReportingStopped {
                client_id: CLIENT.into()
            }]
        );
        assert_eq!(
            t.alerts[0].to_json(),
            json!({"kind": "reporting_stopped", "client_id": CLIENT})
        );
        assert!(!l.reporting_stopped(), "the ledger stopped on is unchanged");
        l = t.next;
        assert!(l.reporting_stopped());
        assert_eq!(l.stopped_client_id(), Some(CLIENT));
        // Held, not dropped: nothing to send, nothing refused.
        assert_eq!(l.pending_reports(), vec![]);
        assert_eq!(l.refused_reports(), Vec::<String>::new());
        assert_eq!(l.pending.len(), a.len());
        // Counting goes on, and so do the reports, held until a resume.
        let n = revoke(By::Native, false, 2);
        assert_eq!(l.rec(&n, T0, &["b"]), vec![]);
        assert_eq!(l.resign_alerts(), vec![rid(2)]);
        let b = l.ack_by(
            "b",
            vec![
                res(&n, &[(E::Revocation, R::Applied)]),
                res(&s, &[(E::Revocation, R::Duplicate)]),
            ],
            T0,
        );
        assert_eq!(
            reports(&b),
            vec![applied("b", &n), revoked(RevokedOutcome::AllApplied, &[])]
        );
        assert_eq!(l.resign_alerts(), Vec::<String>::new());
        assert_eq!(l.pending_reports(), vec![]);
        // A second stop, under any ID: nothing new, no second alert.
        for id in [CLIENT, CLIENT2] {
            let t = l.stop_reporting(id).unwrap();
            assert_eq!((t.next, t.made, t.alerts), (l.clone(), vec![], vec![]));
        }
        let v = l.to_json();
        assert_eq!(v["stopped"], json!(CLIENT));
        assert_eq!(AckLedger::from_json(&v).unwrap(), l);
        // A client ID out of grammar is refused.
        let long = "x".repeat(129);
        for bad in ["", "a b", long.as_str()] {
            assert!(ledger().stop_reporting(bad).is_err());
            assert!(l.resume_reporting(bad).is_err());
        }
    }

    /// A resume under the same report client ID (an operator fixed the
    /// token, the Station restarted) clears the stop and keeps every report.
    #[test]
    fn a_resume_under_the_same_client_id_keeps_every_report() {
        let (mut l, s) = revoked_ledger();
        let a = l.ack_by("a", vec![res(&s, &[(E::Revocation, R::Applied)])], T0);
        // Not stopped: a resume changes nothing.
        let t = l.resume_reporting(CLIENT).unwrap();
        assert_eq!((t.next, t.made, t.alerts), (l.clone(), vec![], vec![]));
        l = l.stop_reporting(CLIENT).unwrap().next;
        let b = l.ack_by("b", vec![res(&s, &[(E::Revocation, R::Applied)])], T0);
        let stopped = l.clone();
        let t = l.resume_reporting(CLIENT).unwrap();
        assert_eq!((t.made.clone(), t.alerts.clone()), (vec![], vec![]));
        assert!(
            stopped.reporting_stopped(),
            "the ledger resumed on is unchanged"
        );
        l = t.next;
        assert!(!l.reporting_stopped());
        assert_eq!(l.stopped_client_id(), None);
        // Everything held goes, in the order it was made, the final after
        // the per-host reports.
        assert_eq!(l.pending_reports(), vec![a[0].clone()]);
        l.confirm_id(&a[0].report_id);
        assert_eq!(l.pending_reports(), vec![b[0].clone()]);
        l.confirm_id(&b[0].report_id);
        assert_eq!(l.pending_reports(), vec![b[1].clone()]);
        assert_eq!(l.to_json().get("stopped"), None);
        assert_eq!(AckLedger::from_json(&l.to_json()).unwrap(), l);
    }

    /// A resume under another report client ID than the stop's (another
    /// Station at Auth, as Atem reads "start fresh") drops the reports
    /// pending at that moment, names each in its alert and keeps their ids;
    /// it retires nothing, so every revocation reports on as usual.
    #[test]
    fn a_resume_under_another_client_id_drops_only_the_pending_reports() {
        let (mut l, s) = revoked_ledger();
        let a = l.ack_by("a", vec![res(&s, &[(E::Revocation, R::Applied)])], T0);
        l = l.stop_reporting(CLIENT).unwrap().next;
        let t = l.resume_reporting(CLIENT2).unwrap();
        assert_eq!(t.made, vec![]);
        assert_eq!(
            t.alerts,
            vec![LedgerAlert::ReportsDropped {
                client_id: CLIENT.into(),
                dropped: ids(&a),
            }]
        );
        assert_eq!(
            t.alerts[0].to_json(),
            json!({"kind": "reports_dropped", "client_id": CLIENT, "dropped": ids(&a)})
        );
        l = t.next;
        assert!(!l.reporting_stopped());
        assert_eq!(l.pending_reports(), vec![]);
        // Kept apart from the refusals, each with the client ID it was
        // dropped under, so a Station raises the alert again whole.
        assert_eq!(l.dropped_reports(), ids(&a));
        assert_eq!(l.dropped_client_ids(), vec![CLIENT.to_owned()]);
        assert_eq!(l.refused_reports(), Vec::<String>::new());
        // The revocation reports on: a late host, then the final, which
        // waits for nothing dropped (a dropped report is settled).
        let b = l.ack_by("b", vec![res(&s, &[(E::Revocation, R::Applied)])], T0);
        assert_eq!(
            reports(&b),
            vec![applied("b", &s), revoked(RevokedOutcome::AllApplied, &[])]
        );
        let mut both = vec![a[0].report_id.clone(), b[0].report_id.clone()];
        both.sort();
        assert_eq!(b[1].not_before, both);
        assert_eq!(l.pending_reports(), vec![b[0].clone()]);
        l.confirm_id(&b[0].report_id);
        assert_eq!(l.pending_reports(), vec![b[1].clone()]);
        // A dropped report is never made again.
        assert_eq!(
            l.ack_by("a", vec![res(&s, &[(E::Revocation, R::Duplicate)])], T0),
            vec![]
        );
        let v = l.to_json();
        assert_eq!(v["dropped"], json!({a[0].report_id.clone(): CLIENT}));
        assert_eq!(AckLedger::from_json(&v).unwrap(), l);
        let mut bad = v.clone();
        bad["dropped"][a[0].report_id.as_str()] = json!("a b");
        assert!(
            AckLedger::from_json(&bad).is_err(),
            "a client ID out of grammar"
        );
        // Not stopped, a resume compares no ID: it changes nothing.
        let t = l.resume_reporting(CLIENT).unwrap();
        assert_eq!((t.next, t.made, t.alerts), (l.clone(), vec![], vec![]));
    }

    #[test]
    fn refusals_and_stops_are_read_strictly() {
        let (mut l, s) = revoked_ledger();
        let a = l.ack_by("a", vec![res(&s, &[(E::Revocation, R::Applied)])], T0);
        let b = l.ack_by("b", vec![res(&s, &[(E::Revocation, R::Applied)])], T0);
        l = l.refuse(&a[0].report_id).next;
        let good = l.to_json();
        assert!(AckLedger::from_json(&good).is_ok());
        type Edit = Box<dyn Fn(&mut Value)>;
        let (ra, rb) = (a[0].report_id.clone(), b[0].report_id.clone());
        let edits: Vec<(&str, Edit)> = vec![
            (
                "no refused",
                Box::new(|v| {
                    v.as_object_mut().unwrap().remove("refused");
                }),
            ),
            (
                "stopped not a client id",
                Box::new(|v| v["stopped"] = json!(true)),
            ),
            (
                "stopped out of grammar",
                Box::new(|v| v["stopped"] = json!("a b")),
            ),
            (
                "no dropped",
                Box::new(|v| {
                    v.as_object_mut().unwrap().remove("dropped");
                }),
            ),
            (
                "dropped not an object",
                Box::new(|v| v["dropped"] = json!([])),
            ),
            (
                "dropped and pending",
                Box::new({
                    let rb = rb.clone();
                    move |v| v["dropped"] = json!({rb.clone(): "c-1"})
                }),
            ),
            (
                "dropped and refused",
                Box::new({
                    let ra = ra.clone();
                    move |v| v["dropped"] = json!({ra.clone(): "c-1"})
                }),
            ),
            (
                "dropped, never made",
                Box::new(|v| v["dropped"] = json!({format!("revoked:{}", "0".repeat(64)): "c-1"})),
            ),
            (
                "a revocation retired",
                Box::new(|v| v["revocations"]["service:svc-1"]["retired"] = json!(true)),
            ),
            (
                "refused not a list",
                Box::new(|v| v["refused"] = json!("x")),
            ),
            (
                "refused and pending",
                Box::new(move |v| v["refused"] = json!([ra.clone(), rb.clone()])),
            ),
            (
                "refused, never made",
                Box::new(|v| {
                    v["refused"] = json!([format!("revocation_applied:{}", "0".repeat(64))])
                }),
            ),
            (
                "refused repeated",
                Box::new(|v| {
                    let id = v["refused"][0].clone();
                    v["refused"] = json!([id.clone(), id]);
                }),
            ),
        ];
        for (what, edit) in edits {
            let mut v = good.clone();
            edit(&mut v);
            assert!(AckLedger::from_json(&v).is_err(), "{what}: {v}");
        }
    }

    // ---------------------------------------------------------- record time

    /// An own revoke recorded after its deadline (the Station recorded it
    /// late) is final at once, as an ack at that time would make it: the
    /// hosts in force then are reported, the others pending.
    #[test]
    fn an_own_revoke_recorded_after_its_deadline_is_final_at_once() {
        let mut l = ledger();
        let n = revoke(By::Native, false, 2);
        l.rec(&n, T0, &["a", "b"]);
        l.ack_by(
            "a",
            vec![res(&n, &[(E::Revocation, R::Applied)])],
            T0 + HOUR,
        );
        let s = revoke(By::Own, false, 1);
        let late = l.record(&s, T0, &hosts(&["a", "b"]), T0 + DAY).unwrap();
        assert_eq!(
            reports(&late.made),
            vec![
                applied("a", &n),
                revoked(RevokedOutcome::DeadlinePassed, &["b"])
            ]
        );
        assert_eq!(late.made[1].not_before, ids(&late.made[..1]));
        // Before its deadline: only the host in force.
        let t = l.record(&s, T0, &hosts(&["a", "b"]), T0 + DAY - 1).unwrap();
        assert_eq!(reports(&t.made), vec![applied("a", &n)]);
        // Every covered host in force: all applied, whenever it is recorded.
        let t = l.record(&s, T0, &hosts(&["a"]), T0 + 2 * DAY).unwrap();
        assert_eq!(
            reports(&t.made),
            vec![applied("a", &n), revoked(RevokedOutcome::AllApplied, &[])]
        );
        // Any record passes the deadlines of earlier revocations first, as a
        // tick at its time would.
        let (l, _) = revoked_ledger();
        let t = l
            .record(&interrupt(By::Native, 3), T0, &hosts(&["a"]), T0 + DAY)
            .unwrap();
        assert_eq!(
            reports(&t.made),
            vec![revoked(RevokedOutcome::DeadlinePassed, &["a", "b"])]
        );
        let again = l
            .record(&revoke(By::Own, false, 1), T0, &[], T0 + DAY)
            .unwrap();
        assert_eq!(reports(&again.made), reports(&t.made));
    }
}
