//! The Station's side of delegated host work (design I.5.8;
//! `designs/protocol/atem-host-work-v1.md` §11.4): the relay calls a host
//! makes to its Station and their answers, and the Station's reference
//! acknowledgment ledger. Planned: no host advertises `host.senders` yet.
//!
//! These are production exports for Station builders (plan decision 6): a
//! Station that isn't written in Rust uses them instead of reimplementing
//! the wire, the counting or the report rules. The built-in Station uses
//! `atem_client::control` directly; both are the same code and pass the
//! same fixtures (`r9-control-ack-*`).
//!
//! - **Relay calls.** `relay_decode_to_station` reads a host's call
//!   (`control_sync`, `control_ack`, `membership_fetch`) strictly, and the
//!   builders write the Station's answers (`relay_control_sync_result`,
//!   `relay_heads`, `relay_membership_fetch_result`), each checked as the
//!   host's reader checks it. The host side (`relay_control_sync`,
//!   `relay_control_ack`, `relay_membership_fetch`, `relay_decode_to_host`)
//!   is exported too, for tests and other hosts. The calling host is the
//!   link's verified association, never a field of a call.
//! - **The ledger.** `AckLedgerHandle` is one device list's
//!   acknowledgments at one Station: what each covered host has in force,
//!   the reports owed to the Portal and the re-sign alerts. A handle never
//!   changes: every call that moves it returns an `AckTransition` whose
//!   `next` state and intents the Station persists in one transaction
//!   before any HTTP, and adopts only once that committed.
//!
//! Errors: input a reader, a builder or the ledger refuses is
//! `Invalid{code}` (the relay's `too_large`, `not_strict`, `wrong_message`,
//! `unknown_field`, `malformed`; a record's parse codes; the ledger's
//! `incomplete_link`, `not_the_link`, `other_account`, `other_station`,
//! `not_the_record`, `record_id_reused`); a state that doesn't load is
//! `Stored{code}`.
use std::sync::Arc;

use atem_client::canonical::{Numbers, parse_strict};
use atem_client::control::{
    AckLedger, AckResult, ApplicationResult, ControlAck, ControlRecord, ControlSync,
    ControlSyncResult, EffectKind, EffectResult, EntryRef, FeedEntry, FeedHead, Heads, LedgerAlert,
    LedgerTransition, LinkAssociation, MembershipFetch, MembershipFetchResult, Report,
    ReportAnswer, ReportIntent, ToHost, ToStation,
};
use serde_json::Value;

use crate::control::{effect_kind, result_kind};
use crate::encoding::{canonical, canonical_lossy, hash_of};
use crate::error::{AtemError, Result};
use crate::log::{object_json, objects_of};
use crate::types::{
    ControlAckInfo, ControlEffectKind, ControlEffectResult, ControlResultKind, LedgerAlertInfo,
    LinkAssociationInfo, LogHead, RelayAckResult, RelayFeedHead, RelayFeedRecord, RelayToHost,
    RelayToStation, ReportAnswerKind, ReportIntentInfo, StationReport,
};

/// Largest ledger state `AckLedgerHandle::from_json` reads, checked before
/// parsing.
pub const MAX_ACK_LEDGER_JSON: usize = 64 << 20;

/// The ledger state's format (`"v"`).
const STATE_VERSION: u64 = 1;

// ------------------------------------------------------------ conversions

fn effect_of(kind: ControlEffectKind) -> EffectKind {
    match kind {
        ControlEffectKind::Revocation => EffectKind::Revocation,
        ControlEffectKind::Interrupt => EffectKind::Interrupt,
        ControlEffectKind::Hold => EffectKind::Hold,
        ControlEffectKind::Release => EffectKind::Release,
        ControlEffectKind::Cover => EffectKind::Cover,
    }
}

fn result_of(kind: ControlResultKind) -> ApplicationResult {
    match kind {
        ControlResultKind::Applied => ApplicationResult::Applied,
        ControlResultKind::Duplicate => ApplicationResult::Duplicate,
        ControlResultKind::Pending => ApplicationResult::Pending,
        ControlResultKind::Refused => ApplicationResult::Refused,
    }
}

/// An effect kind by its wire name (`revocation`, `interrupt`, `hold`,
/// `release`, `cover`).
#[cfg(feature = "wasm")]
pub(crate) fn effect_kind_of(code: &str) -> Option<ControlEffectKind> {
    EffectKind::from_code(code).map(effect_kind)
}

/// A result by its wire name (`applied`, `duplicate`, `pending`,
/// `refused`).
#[cfg(feature = "wasm")]
pub(crate) fn result_kind_of(code: &str) -> Option<ControlResultKind> {
    ApplicationResult::from_code(code).map(result_kind)
}

fn effects_of(effects: &[ControlEffectResult]) -> Vec<EffectResult> {
    effects
        .iter()
        .map(|e| EffectResult {
            effect: effect_of(e.effect),
            result: result_of(e.result),
        })
        .collect()
}

fn effects_info(effects: &[EffectResult]) -> Vec<ControlEffectResult> {
    effects
        .iter()
        .map(|e| ControlEffectResult {
            effect: effect_kind(e.effect),
            result: result_kind(e.result),
        })
        .collect()
}

impl ControlAckInfo {
    fn to_ack(&self) -> Result<ControlAck> {
        let results = self
            .results
            .iter()
            .map(|r| {
                Ok(match r {
                    RelayAckResult::Record { record_id, effects } => AckResult::Record {
                        record_id: record_id.clone(),
                        effects: effects_of(effects),
                    },
                    RelayAckResult::Entry {
                        seq,
                        entry_hash,
                        applied_seq,
                        effects,
                    } => AckResult::Entry {
                        entry: EntryRef {
                            seq: *seq,
                            entry_hash: hash_of(entry_hash)?,
                        },
                        applied_seq: *applied_seq,
                        effects: effects_of(effects),
                    },
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(ControlAck {
            account_id: self.account_id.clone(),
            genesis_hash: hash_of(&self.genesis_hash)?,
            host_id: self.host_id.clone(),
            host_trust_gen: self.host_trust_gen,
            origin: self.origin.clone(),
            feed_id: self.feed_id.clone(),
            cursor: self.cursor,
            results,
        })
    }

    fn of(ack: &ControlAck) -> Self {
        ControlAckInfo {
            account_id: ack.account_id.clone(),
            genesis_hash: ack.genesis_hash.to_hex(),
            host_id: ack.host_id.clone(),
            host_trust_gen: ack.host_trust_gen,
            origin: ack.origin.clone(),
            feed_id: ack.feed_id.clone(),
            cursor: ack.cursor,
            results: ack
                .results
                .iter()
                .map(|r| match r {
                    AckResult::Record { record_id, effects } => RelayAckResult::Record {
                        record_id: record_id.clone(),
                        effects: effects_info(effects),
                    },
                    AckResult::Entry {
                        entry,
                        applied_seq,
                        effects,
                    } => RelayAckResult::Entry {
                        seq: entry.seq,
                        entry_hash: entry.entry_hash.to_hex(),
                        applied_seq: *applied_seq,
                        effects: effects_info(effects),
                    },
                })
                .collect(),
        }
    }
}

impl RelayFeedHead {
    fn to_feed(&self) -> FeedHead {
        FeedHead {
            origin: self.origin.clone(),
            feed_id: self.feed_id.clone(),
            head: self.head,
            station_time: self.station_time,
        }
    }
}

impl LinkAssociationInfo {
    fn to_link(&self) -> Result<LinkAssociation> {
        Ok(LinkAssociation {
            account_id: self.account_id.clone(),
            genesis_hash: hash_of(&self.genesis_hash)?,
            host_id: self.host_id.clone(),
            host_trust_gen: self.host_trust_gen,
            connection_id: self.connection_id.clone(),
        })
    }
}

fn report_info(report: &Report) -> StationReport {
    match report {
        Report::RevocationApplied {
            integration_id,
            host,
            record_id,
        } => StationReport::RevocationApplied {
            integration_id: integration_id.clone(),
            host: host.clone(),
            record_id: record_id.clone(),
        },
        Report::Revoked {
            integration_id,
            outcome,
            pending_hosts,
        } => StationReport::Revoked {
            integration_id: integration_id.clone(),
            outcome: outcome.code().into(),
            pending_hosts: pending_hosts.clone(),
        },
    }
}

fn intent_info(intent: &ReportIntent) -> ReportIntentInfo {
    ReportIntentInfo {
        report_id: intent.report_id.clone(),
        report: report_info(&intent.report),
        not_before: intent.not_before.clone(),
    }
}

fn alert_info(alert: &LedgerAlert) -> LedgerAlertInfo {
    match alert {
        LedgerAlert::ReportRefused { report_id } => LedgerAlertInfo::ReportRefused {
            report_id: report_id.clone(),
        },
        LedgerAlert::ReportingStopped { client_id } => LedgerAlertInfo::ReportingStopped {
            client_id: client_id.clone(),
        },
        LedgerAlert::ReportsDropped { client_id, dropped } => LedgerAlertInfo::ReportsDropped {
            client_id: client_id.clone(),
            dropped: dropped.clone(),
        },
    }
}

/// A builder's message, as the reader's bound measured it.
fn wire(value: Value) -> String {
    value.to_string()
}

// -------------------------------------------------------------- relay calls

/// Reads a host's call to its Station strictly (at most 256 KiB, one strict
/// I-JSON parse, exact fields): `control_sync`, `control_ack` or
/// `membership_fetch`. Another relay message (`push_hint`, …) is
/// `Invalid{wrong_message}`: dispatch it elsewhere. The calling host is the
/// link's verified association: compare a `control_ack`'s claim with it
/// (`AckLedgerHandle::ack` does).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn relay_decode_to_station(message: String) -> Result<RelayToStation> {
    Ok(match ToStation::decode(message.as_bytes())? {
        ToStation::ControlSync(sync) => RelayToStation::ControlSync {
            origin: sync.origin,
            feed_id: sync.feed_id,
            after: sync.after,
        },
        ToStation::ControlAck(ack) => RelayToStation::ControlAck {
            ack: ControlAckInfo::of(&ack),
        },
        ToStation::MembershipFetch(fetch) => RelayToStation::MembershipFetch { after: fetch.after },
    })
}

/// Reads a Station's message to a host strictly: `control_sync_result`
/// (each record as the Station sent it, of any JSON type: judge each with
/// `parse_control_record`), `heads` or `membership_fetch_result`.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn relay_decode_to_host(message: String) -> Result<RelayToHost> {
    Ok(match ToHost::decode(message.as_bytes())? {
        ToHost::ControlSyncResult(page) => RelayToHost::ControlSyncResult {
            origin: page.origin,
            feed_id: page.feed_id,
            head: page.head,
            station_time: page.station_time,
            records: page
                .records
                .iter()
                .map(|e| RelayFeedRecord {
                    feed_seq: e.feed_seq,
                    record_json: e.raw().to_string(),
                })
                .collect(),
        },
        ToHost::Heads(heads) => RelayToHost::Heads {
            feeds: heads
                .feeds
                .iter()
                .map(|f| RelayFeedHead {
                    origin: f.origin.clone(),
                    feed_id: f.feed_id.clone(),
                    head: f.head,
                    station_time: f.station_time,
                })
                .collect(),
            membership: heads.membership.into(),
        },
        ToHost::MembershipFetchResult(result) => RelayToHost::MembershipFetchResult {
            head: result.head.into(),
            entries: result.entries.iter().map(object_json).collect(),
        },
    })
}

/// `control_sync{origin, feed_id?, after}` (host → Station). Without
/// `feed_id`, `after` is 0.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn relay_control_sync(origin: String, feed_id: Option<String>, after: u64) -> Result<String> {
    let sync = ControlSync {
        origin,
        feed_id,
        after,
    };
    Ok(wire(sync.to_json()?))
}

/// `control_sync_result{origin, feed_id, head, station_time, records}`
/// (Station → host): at most 64 records, ascending `feed_seq` in
/// `1..=head`, 256 KiB in all. Each record must be one the control parser
/// accepts (`Invalid{code}` with its parse code otherwise): a Station
/// validates records at intake and serves only what it stored.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn relay_control_sync_result(
    origin: String,
    feed_id: String,
    head: u64,
    station_time: u64,
    records: Vec<RelayFeedRecord>,
) -> Result<String> {
    let records = records
        .iter()
        .map(|r| {
            let record = ControlRecord::parse(r.record_json.as_bytes())?;
            Ok(FeedEntry::new(r.feed_seq, &record))
        })
        .collect::<Result<Vec<_>>>()?;
    let page = ControlSyncResult {
        origin,
        feed_id,
        head,
        station_time,
        records,
    };
    Ok(wire(page.to_json()?))
}

/// `heads{feeds, membership}` (Station → host): each covering feed's head
/// (at most 64, a feed once) and the device list's head. Send it on every
/// (re)connection, every 30 seconds and at once when a record is stored.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn relay_heads(feeds: Vec<RelayFeedHead>, membership: LogHead) -> Result<String> {
    let heads = Heads {
        feeds: feeds.iter().map(RelayFeedHead::to_feed).collect(),
        membership: membership.to_head()?,
    };
    Ok(wire(heads.to_json()?))
}

/// `control_ack{…}` (host → Station), checked as the Station's reader
/// checks it.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn relay_control_ack(ack: ControlAckInfo) -> Result<String> {
    Ok(wire(ack.to_ack()?.to_json()?))
}

/// `membership_fetch{after}` (host → Station): the host's own device-list
/// fetch.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn relay_membership_fetch(after: u64) -> Result<String> {
    Ok(wire(MembershipFetch { after }.to_json()?))
}

/// `membership_fetch_result{head, entries}` (Station → host): the device
/// list's head and the entries after the host's `after` (signed objects'
/// JSON), as an R9.3 carriage: at most 64.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn relay_membership_fetch_result(head: LogHead, entries: Vec<String>) -> Result<String> {
    let result = MembershipFetchResult {
        head: head.to_head()?,
        entries: objects_of(&entries)?,
    };
    Ok(wire(result.to_json()?))
}

/// The class of the Portal's HTTP `status` for a report (Auth/Portal's): a
/// network error or a timeout, which has no status, is `Retry`; never pass
/// a "no response" sentinel such as 0 (no status the Portal answers with:
/// `Refuse`). Never follow a 3xx: it would carry the `station.report`
/// bearer wherever it points.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn report_answer(status: u16) -> ReportAnswerKind {
    match ReportAnswer::of_status(status) {
        ReportAnswer::Confirm => ReportAnswerKind::Confirm,
        ReportAnswer::Retry => ReportAnswerKind::Retry,
        ReportAnswer::Refuse => ReportAnswerKind::Refuse,
        ReportAnswer::StopReporting => ReportAnswerKind::StopReporting,
    }
}

// --------------------------------------------------------------- the ledger

/// The Station's reference acknowledgment ledger for one device list (an
/// account and its root) at one Station (its exact origin): which covered
/// hosts have each revocation in force, the reports owed to the Portal
/// (`revocation_applied` per host and integration, `revoked` per
/// revocation) and the native-signed records still to re-sign.
///
/// **A handle never changes.** `record`, `ack`, `tick`, `confirm`,
/// `refuse`, `stop_reporting` and `resume_reporting` return an
/// `AckTransition`; the handle they were called on stays as it was, so it
/// is safe to share across threads.
///
/// **Persistence.** In one transaction, store `next.to_json()` (it holds
/// every report not yet settled, so the intents are in it). Only once it
/// committed, use `next`, then POST `pending_reports()` and raise the
/// transition's alerts. If the commit failed, keep the handle you called
/// on: the host resends its ack, and the same call gives the same next
/// state and the same report ids. Serialize transitions of one ledger
/// (compare-and-swap on the stored state): a replica whose commit lost
/// loads the new state and calls again.
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct AckLedgerHandle {
    ledger: AckLedger,
}

impl std::fmt::Debug for AckLedgerHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AckLedgerHandle").finish_non_exhaustive()
    }
}

impl AckLedgerHandle {
    fn wrap(ledger: AckLedger) -> Arc<Self> {
        Arc::new(AckLedgerHandle { ledger })
    }
}

/// What a ledger call gives: the state after it, the reports it made and
/// the operator alerts it raised.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct AckTransition {
    /// The state after the call. Store `next.to_json()` in one transaction
    /// and use `next` once it committed; until then (and if it failed) the
    /// handle called on is the current state.
    pub next: Arc<AckLedgerHandle>,
    /// The reports this call made, in delivery order (`next` holds them
    /// until settled; send `next.pending_reports()`).
    pub intents: Vec<ReportIntentInfo>,
    /// Raise these once the transaction committed.
    pub alerts: Vec<LedgerAlertInfo>,
}

fn transition(t: LedgerTransition) -> AckTransition {
    AckTransition {
        intents: t.intents.iter().map(intent_info).collect(),
        alerts: t.alerts.iter().map(alert_info).collect(),
        next: AckLedgerHandle::wrap(t.next),
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl AckLedgerHandle {
    /// The empty ledger of the device list `account_id`/`genesis_hash`
    /// (lowercase hex) at the Station `origin` (exact, as hosts compare it:
    /// `https://` and a lowercase host, no path). `Invalid{malformed}`
    /// otherwise.
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn new(origin: String, account_id: String, genesis_hash: String) -> Result<Arc<Self>> {
        let ledger = AckLedger::new(&origin, &account_id, hash_of(&genesis_hash)?)?;
        Ok(Self::wrap(ledger))
    }

    /// A state `to_json()` wrote. `Stored{code}`: `too_large` (over 64
    /// MiB), `malformed` (not strict JSON, not an object, no `v`),
    /// `unsupported_version` (a `v` other than 1), `stored_invalid` (the
    /// ledger's own rules refuse it, or it isn't exactly `to_json()`'s
    /// form). Nothing is loaded then: keep reporting stopped and never
    /// start again from an empty ledger (it would report again what the
    /// Portal has, under the same ids, and lose the deadlines).
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn from_json(state_json: String) -> Result<Arc<Self>> {
        if state_json.len() > MAX_ACK_LEDGER_JSON {
            return Err(AtemError::stored(
                "too_large",
                format!("a ledger state is at most {MAX_ACK_LEDGER_JSON} bytes"),
            ));
        }
        let value = parse_strict(
            state_json.as_bytes(),
            MAX_ACK_LEDGER_JSON,
            Numbers::IntegersOnly,
        )
        .map_err(|e| AtemError::stored("malformed", format!("not strict JSON: {e:?}")))?;
        let object = value
            .as_object()
            .ok_or_else(|| AtemError::stored("malformed", "not an object"))?;
        match object.get("v").map(Value::as_u64) {
            None => return Err(AtemError::stored("malformed", "no state version `v`")),
            Some(Some(STATE_VERSION)) => {}
            Some(_) => {
                return Err(AtemError::stored(
                    "unsupported_version",
                    format!("this binding reads ledger state version {STATE_VERSION}"),
                ));
            }
        }
        let ledger = AckLedger::from_json(&value)
            .map_err(|e| AtemError::stored("stored_invalid", e.to_string()))?;
        // Exactly the export: another spelling of the state is refused.
        let exact = match (canonical(&ledger.to_json()), canonical(&value)) {
            (Ok(ours), Ok(theirs)) => ours == theirs,
            _ => false,
        };
        if !exact {
            return Err(AtemError::stored(
                "stored_invalid",
                "the state isn't exactly to_json()'s form",
            ));
        }
        Ok(Self::wrap(ledger))
    }

    /// The durable state: canonical JSON (`"v": 1`).
    pub fn to_json(&self) -> String {
        canonical_lossy(&self.ledger.to_json())
    }

    pub fn origin(&self) -> String {
        self.ledger.origin().into()
    }

    pub fn account_id(&self) -> String {
        self.ledger.account_id().into()
    }

    /// Lowercase hex.
    pub fn genesis_hash(&self) -> String {
        self.ledger.genesis_hash().to_hex()
    }

    /// A record the Station stored in its feed (its JSON, as the control
    /// parser reads it), before it serves it, at `now_ms`. For the
    /// Station's own `revoke` (signed with the integration's service key),
    /// the first of its principal starts the revocation: `revoked_at_ms` is
    /// when the Portal revoked the integration and `covered_hosts` the
    /// hosts its grant covered. For any other record `revoked_at_ms` is
    /// unused and `covered_hosts` are the hosts its re-sign alert waits
    /// for. The same record again changes nothing.
    pub fn record(
        &self,
        record_json: String,
        revoked_at_ms: u64,
        covered_hosts: Vec<String>,
        now_ms: u64,
    ) -> Result<AckTransition> {
        let record = ControlRecord::parse(record_json.as_bytes())?;
        Ok(transition(self.ledger.record(
            &record,
            revoked_at_ms,
            &covered_hosts,
            now_ms,
        )?))
    }

    /// A host's `control_ack` (the message as received, read strictly) on
    /// the link whose verified association is `link`, at `now_ms`. Refused
    /// whole (`Invalid{code}`) when its claims aren't the link's
    /// (`not_the_link`), the link is incomplete (`incomplete_link`), it is
    /// another device list's or Station's (`other_account`,
    /// `other_station`), or a result names a record with other effects than
    /// it carries (`not_the_record`).
    pub fn ack(
        &self,
        link: LinkAssociationInfo,
        ack_json: String,
        now_ms: u64,
    ) -> Result<AckTransition> {
        let ack = ControlAck::decode(ack_json.as_bytes())?;
        Ok(transition(self.ledger.ack(
            &link.to_link()?,
            &ack,
            now_ms,
        )?))
    }

    /// The Station's timer at `now_ms`: a revocation whose deadline (24 h
    /// after `revoked_at_ms`) passed gets its `revoked` report.
    pub fn tick(&self, now_ms: u64) -> AckTransition {
        transition(self.ledger.tick(now_ms))
    }

    /// The Portal answered `200` (`ReportAnswerKind::Confirm`).
    pub fn confirm(&self, report_id: String) -> AckTransition {
        transition(self.ledger.confirm(&report_id))
    }

    /// The Portal refused the report for good (`ReportAnswerKind::Refuse`):
    /// it is settled, never sent again, with a `ReportRefused` alert.
    pub fn refuse(&self, report_id: String) -> AckTransition {
        transition(self.ledger.refuse(&report_id))
    }

    /// The Portal answered `403` (`ReportAnswerKind::StopReporting`) to the
    /// report client `client_id` (the Station's client at Auth): the ledger
    /// records the ID and holds every report, none sent, until
    /// `resume_reporting`; counting and reports go on. One
    /// `ReportingStopped` alert; a ledger already stopped changes nothing.
    /// `Invalid{malformed}` for an ID that isn't 1 to 128 characters of
    /// `[A-Za-z0-9._:-]`.
    pub fn stop_reporting(&self, client_id: String) -> Result<AckTransition> {
        Ok(transition(self.ledger.stop_reporting(&client_id)?))
    }

    /// The Station reports again as the report client `client_id` (at
    /// start; the built-in Station's ID comes from its configuration and
    /// always resumes). The ID is compared only at a resume after a `403`
    /// stop: a ledger not stopped changes nothing, whatever the ID. The
    /// stop's own ID clears the stop and keeps every report. Another ID than
    /// the stop's is, as Atem reads Auth/Portal's "start fresh" (for
    /// Auth/Portal to confirm), another Station at Auth: the reports pending
    /// at that moment are dropped, done unsent (`dropped_reports`, a
    /// `ReportsDropped` alert naming each), and every revocation reports on
    /// as usual under the new ID.
    pub fn resume_reporting(&self, client_id: String) -> Result<AckTransition> {
        Ok(transition(self.ledger.resume_reporting(&client_id)?))
    }

    /// What to send now, in order: every report not yet settled whose
    /// `not_before` are all settled.
    pub fn pending_reports(&self) -> Vec<ReportIntentInfo> {
        self.ledger
            .pending_reports()
            .iter()
            .map(intent_info)
            .collect()
    }

    /// The native-signed records not yet in force, for every effect they
    /// carry, on every host they cover (`record_id`s, sorted): Astation
    /// alerts the owner to re-sign those whose signer was removed.
    pub fn resign_alerts(&self) -> Vec<String> {
        self.ledger.resign_alerts()
    }

    /// The reports the Portal refused for good.
    pub fn refused_reports(&self) -> Vec<String> {
        self.ledger.refused_reports()
    }

    /// The reports a resume under another report client ID than the stop's
    /// dropped unsent (kept, so the alert can be raised again at start).
    pub fn dropped_reports(&self) -> Vec<String> {
        self.ledger.dropped_reports()
    }

    /// The Portal refused this Station's reports (`403`): every report is
    /// held.
    pub fn reporting_stopped(&self) -> bool {
        self.ledger.reporting_stopped()
    }

    /// The report client ID reporting is stopped under, while it is.
    pub fn stopped_client_id(&self) -> Option<String> {
        self.ledger.stopped_client_id().map(str::to_owned)
    }
}
