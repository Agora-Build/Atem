//! `designs/protocol/fixtures/r9-vectors-signer-report.json`: a native
//! manager's signed report of its control-record signing journal
//! (`atem_client::member_report`'s signer report; host-work-v1 §11.1 "The
//! signer report", agreed with Astation, #114 comment 7089435073):
//! challenges read strictly, reports verified with their exported records
//! against log L of `r9-vectors-membership-log` and this file's `entries`,
//! the builder's outcomes and the immutable request's signatures.
//!
//! `write_signer_report_vectors` (ignored) writes the file from
//! `signer_report_vectors`, which builds every case and checks each outcome
//! written here by hand against the shared core. The other tests read the
//! file: that it is what the generator makes now, and that every case comes
//! out as it says. `scripts/check-r9-vectors.py` checks the same file
//! independently; the FFI's `tests/signer_report.rs` and the Swift, Kotlin
//! and WASM suites run it through the bindings.
mod support;

use std::collections::BTreeSet;

use atem_client::canonical::{self, jcs};
use atem_client::control::{
    ControlAbout, ControlAction, ControlBody, ControlFeed, ControlPrincipal, ControlSigner,
    build_control, principal_key_of,
};
use atem_client::domain::{SignLabel, SigningInput};
use atem_client::encoding::{Hash32, b64u, b64u_decode, hex};
use atem_client::member_report::{
    JournalView, OutOfPlan, PlanRecord, SIGNER_VERIFY_ORDER, SignerReportChallenge,
    VerifiedSignerReport, process_generation, sign_signer_report, signer_report_body,
    signer_report_plan_record, verify_signer_report,
};
use atem_client::membership::{
    Action, HostNow, Member, MemberKind, Membership, Role, RolesChange, sign_entry,
};
use atem_client::provider::sign;
use atem_client::{KeyId, KeyProvider, PublicKey, SignedObject, SoftwareKeys};
use serde_json::{Map, Value, json};
use support::{Book, Vectors, fixtures_dir, load, strict};

const FILE: &str = "r9-vectors-signer-report";

const NOTE: &str = "A native manager's signed report of its control-record signing journal (host-work-v1 §11.1 \"The signer report\"; Astation #114 item 4, agreed with Astation, #114 comment 7089435073), for a Station recovering from a rollback: wire {\"body\":{…},\"sig\"}, the body {type: atem-signer-report, v: 1, account_id, genesis_hash, head{seq, hash}, signer, slot, process, challenge{origin, connection, nonce, issued_at, expires_at}, recovery{generation, plan_id, candidate_feed_id, source_hash, evidence_hash}, journal{id, since, revision, records, records_hash, drafts, drafts_hash}} signed by a current native member's own auth_key (signer member:<device_id>; one that held manage at some seq of the list) over enc([\"atem-signer-report-v1\", jcs(body)]) (R9.1), under the alg the device list pins. A challenge is what the minter stores, {signer, slot, origin, connection, nonce, issued_at, expires_at, recovery}: signer member:<id>, slot and ids 1-128 bytes of [A-Za-z0-9._:-], origin exact as station_route::normalize_relay writes it, connection 1 to 2^53-1, nonce 32 bytes, process and journal.id 16 bytes (base64url, no padding), 0 < expires_at - issued_at <= 30000 ms, recovery.generation a canonical decimal string 1 to 2^63-1 (no sign, no leading zero), plan_id and candidate_feed_id UUID v4, the hashes lowercase hex SHA-256; journal.since 1 to 2^53-1, revision, records and drafts 0 to 2^53-1; a challenge text is at most 4,096 bytes, the body's jcs at most 4,096 bytes and the object at most 16 KiB; no null, no array, no kit_sig, no field beyond these at any level, no duplicate key (escaped ones included). The plan's records (B2): a control-record body (r9-vectors-host-work-control's form) this member signs (signer member:<id>), of this account and genesis, a service's revoke or interrupt_running naming the challenge's origin, or a host principal's interrupt_running (no origin). records_hash = SHA-256(enc([\"atem-signer-report-records-v1\", d1…dn])) over each record body's SHA-256(jcs(body)) (32 bytes), sorted by bytes; drafts_hash the same with \"atem-signer-report-drafts-v1\". Device lists: log L of r9-vectors-membership-log followed by `chain` (labels of `entries`), then the carriage `freeze` (a label of r9-vectors-membership-log's others) when a case names one, which freezes it; each list verified at the case's now_ms. Keys are r9-vectors-keys' (`signed_with` names <name>/<part>: auth, host_key, or recovery/sign for the kit's recovery key); dev-desk is the Ed25519 native the chain adds without manage (SR7_add_desk) and makes a manager (SR8_desk_manages). `records`: the control records the cases use, each body, its jcs and digest, and the record as its signer signed it. `challenges`: texts read by SignerReportChallenge::parse (bindings parse_signer_report_challenge): `fields` when read, else `code`. `valid` and `invalid`: verify_signer_report(list, report, the stored challenge `challenge`, the exported signed records `exported`, now_ms): `expect` is the VerifiedSignerReport (process base64url, at_head true at the list's head, false at an ancestor, journal.id base64url, records the verified records as given), or `code`, the first failure in the order malformed, frozen, wrong_account, unknown_signer, not_a_manager, bad_signature, stale_log, fork, signer_mismatch, slot_mismatch, challenge_mismatch, recovery_mismatch, records_mismatch, expired (bindings: Report{code}). records_mismatch is an exported record that isn't a signed control record of the plan by this member, one whose signature doesn't verify under its key (low S), a duplicate, or another count or records_hash than the report's: a body in signing with no saved signature is in records and can't be exported, so such a report is refused (Astation's conservative rule). A report's process is the fixed bytes \"vectors-process!\"; a builder draws its own once per loaded core (process_generation). `builder`: signer_report_body(list, challenge, signer, slot, station, journal{id, since, revision, records, drafts: the bodies' texts}, now_ms): `body_but_process` (the body it builds, but its process), or `code` (origin_mismatch when the challenge's origin isn't station normalized; malformed for a journal body that isn't one of the plan's records by this member, or one twice in a set). `request`: the immutable request (bindings SignerReportRequest): built as a builder case, its sign_request (`purpose`, `fresh_confirmation`, `label`; input = enc([label, jcs(body)]), body_json = jcs(body)), then each `finishes` entry signs with `signed_with` the input of the held body (`over: held`) or of a request for the same challenge and journal with another `slot` (`over: {slot}`), and finish gives the report, byte-equal to {\"body\":<held body>,\"sig\":<the signature, low S>}, or `code`. `plan_predicate` (Astation's ask, #114 comment 7093796254): signer_report_plan_record(list, body, member, origin) (bindings signer_report_plan_record): whether a control-record body is one of the plan's records for member (member:<id>) at origin (the challenge's, exactly as normalize_relay writes it), the account and genesis the list's (L + `chain`, then `freeze`): `in_plan` true, or false with `reason`, in the order checked another_account, another_genesis, another_signer (another member, or the principal's own key), then another_origin (a service's revoke or interrupt_running naming another origin), or `code` malformed (this member's cover, hold or release, judged after the signer and before the origin; a body that isn't a control record's, read as the builder reads a journal's; a member that isn't member:<id>; an origin not in its exact form). The builder reads a journal's bodies by this one rule: a body in the plan is one it takes in a set, anything else refuses the build. Bodies only: the list's freeze and the member's standing change no answer. Consistency only: never completeness of anything outside the journal. Atem's readings, agreed with Astation, #114 comment 7093796254 (the agreed text left them open; each is fail-closed): (a) a challenge's signer is member:<id> only, a service: one malformed when read (a report body naming a service, a host, a grant or recovery is unknown_signer, as agreed); (b) the builder also takes now_ms and refuses an expired challenge; (c) a service's records of the plan are its revoke and interrupt_running only, so this member's cover, hold or release body refuses the build (malformed), never skipped; (d) one body may be both a record and a draft (only a body twice in one set is refused); (e) journal.since is compared with nothing, head.seq included.";

const STATION: &str = "https://station-dev.agora.build";
const OTHER_STATION: &str = "https://station.agora.build";
const SLOT: &str = "astation-ios";
const PHONE: &str = "member:dev-phone";
const MAC: &str = "member:dev-mac";
const DESK: &str = "member:dev-desk";
const NEWMAC: &str = "member:dev-newmac";
/// Every case's clock but the expiries': after L and its chain.
const NOW: u64 = 1_793_264_001_000;
const ISSUED: u64 = 1_793_264_000_000;
/// A full lease: 30 s.
const EXPIRES: u64 = ISSUED + 30_000;
/// Every report's process generation in the vectors.
const PROCESS: &[u8; 16] = b"vectors-process!";
const JOURNAL_ID: &[u8; 16] = b"vectors-journal!";
const REINSTALLED_ID: &[u8; 16] = b"reinstalled-jrnl";
const PLAN: &str = "5b7c9d1e-2f3a-4b5c-8d6e-7f8091a2b3c4";
const CANDIDATE: &str = "7a2d3c4b-5e6f-4071-9b8c-0d1e2f3a4b5c";
/// The old feed the stops name.
const FEED: &str = "6f1c2b3a-4d5e-4f60-8a7b-9c0d1e2f3a4b";
const INTEGRATION: &str = "i-01jc5zq9x8w7v6t5s4r3q2p1n0";

fn nonce(first: u8) -> [u8; 32] {
    std::array::from_fn(|i| first + i as u8)
}

fn record_id(n: u64) -> String {
    format!("00000000-0000-4000-8000-{n:012x}")
}

fn host_now(now_ms: u64) -> HostNow {
    HostNow {
        wall_ms: now_ms,
        mono_ms: 1_000,
        boot_id: "boot-1".into(),
    }
}

/// L of `v`, then `chain`, then the carriage `freeze`, verified at `now_ms`.
fn log_of(v: &Vectors, chain: &[SignedObject], freeze: Option<&str>, now_ms: u64) -> Membership {
    let now = host_now(now_ms);
    let l = v.entries(&["E1", "E2", "E3", "E4", "E5", "E6"]);
    let mut log = Membership::verify_chain(support::ACCOUNT, &v.hash("E1"), &l, &now)
        .unwrap()
        .membership;
    if !chain.is_empty() {
        let eval = log.evaluate_objects(chain, &now);
        assert!(eval.stop.is_none(), "the chain applies: {:?}", eval.stop);
        log = eval.next;
    }
    if let Some(label) = freeze {
        log = log.evaluate(&[strict(v.wire(label))], &now).next;
        assert!(log.frozen().is_some(), "{label} freezes the list");
    }
    log
}

fn recovery() -> Value {
    json!({"generation": "7", "plan_id": PLAN, "candidate_feed_id": CANDIDATE,
           "source_hash": "5a".repeat(32), "evidence_hash": "e7".repeat(32)})
}

/// The challenge a minter stores, as an object.
fn challenge(signer: &str, slot: &str, connection: u64) -> Value {
    json!({"signer": signer, "slot": slot, "origin": STATION, "connection": connection,
           "nonce": b64u(&nonce(0)), "issued_at": ISSUED, "expires_at": EXPIRES,
           "recovery": recovery()})
}

fn with(mut value: Value, field: &str, to: Value) -> Value {
    value[field] = to;
    value
}

fn read_challenge(value: &Value) -> SignerReportChallenge {
    SignerReportChallenge::parse(value.to_string().as_bytes()).unwrap()
}

fn edit(body: &Value, f: impl FnOnce(&mut Value)) -> Value {
    let mut body = body.clone();
    f(&mut body);
    body
}

/// `{"body":<jcs(body)>,"sig":…}` signed by `key` under `label`, with no
/// check of the body (a malformed one is signed too).
fn signed_as(keys: &SoftwareKeys, key: &str, label: SignLabel, body: &Value) -> String {
    let text = jcs(body).unwrap();
    let sig = sign(
        keys,
        &KeyId::new(key),
        &SigningInput::new(label, text.as_bytes()),
    )
    .unwrap();
    format!(r#"{{"body":{text},"sig":"{}"}}"#, b64u(&sig))
}

fn signed(keys: &SoftwareKeys, key: &str, body: &Value) -> String {
    signed_as(keys, key, SignLabel::SignerReport, body)
}

/// `s` replaced by `n − s`: the other P-256 signature of the same input.
fn high_s(sig: &[u8]) -> Vec<u8> {
    const N: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ];
    let mut out = sig[..32].to_vec();
    let mut tail = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let d = N[i] as i16 - sig[32 + i] as i16 - borrow;
        borrow = i16::from(d < 0);
        tail[i] = d.rem_euclid(256) as u8;
    }
    out.extend_from_slice(&tail);
    out
}

/// A signed object's text with its `sig` replaced by its high-S twin.
fn with_high_s(text: &str) -> String {
    let mut object: Value = serde_json::from_str(text).unwrap();
    let sig = b64u_decode(object["sig"].as_str().unwrap()).unwrap();
    object["sig"] = json!(b64u(&high_s(&sig)));
    jcs(&object).unwrap()
}

/// The control records the cases use: (label, note, body, the key that
/// signed it).
struct Rec {
    label: &'static str,
    note: &'static str,
    body: ControlBody,
    key: &'static str,
}

/// What the generator builds with: the book, log L, the chain's entries
/// and the records.
struct Gen {
    v: Vectors,
    keys: SoftwareKeys,
    /// The entries after L: (label, note, the labels it extends, entry).
    entries: Vec<(
        &'static str,
        &'static str,
        &'static [&'static str],
        SignedObject,
    )>,
    records: Vec<Rec>,
}

const NO_CHAIN: &[&str] = &[];
const DESK_ADDED: &[&str] = &["SR7_add_desk"];
const DESK_MANAGES: &[&str] = &["SR7_add_desk", "SR8_desk_manages"];
const DEMOTED: &[&str] = &["SR7_set_roles_phone"];
const RECOVERING: &[&str] = &["SR7_recovery_add_newmac"];
const RECOVERED: &[&str] = &["SR7_recovery_add_newmac", "SR8_recovery_approve_newmac"];

impl Gen {
    fn new() -> Gen {
        let v = Vectors::load();
        let keys = Book::load().provider;
        let mut made = Gen {
            v,
            keys,
            entries: Vec::new(),
            records: Vec::new(),
        };
        let desk = Action::Add {
            member: Member {
                device_id: "dev-desk".into(),
                auth_key: made.public("dev-desk/auth"),
                kind: MemberKind::Native {
                    enc_key: made.public("dev-desk/enc"),
                    roles: [Role::Control, Role::View].into_iter().collect(),
                },
            },
        };
        made.push(
            "SR7_add_desk",
            "add dev-desk, a native member with an Ed25519 auth_key and roles [control, view] (never manage), on E6, by dev-mac",
            NO_CHAIN,
            1_792_400_006_000,
            desk,
        );
        made.push(
            "SR8_desk_manages",
            "set_roles dev-desk to [control, manage, view] on SR7_add_desk, by dev-mac: an Ed25519 manager",
            DESK_ADDED,
            1_792_400_007_000,
            Action::SetRoles {
                device_id: "dev-desk".into(),
                change: RolesChange::Native(
                    [Role::Control, Role::Manage, Role::View]
                        .into_iter()
                        .collect(),
                ),
            },
        );
        made.push(
            "SR7_set_roles_phone",
            "set_roles dev-phone to [view] on E6, by dev-mac: a manager demoted, still a current native member that held manage",
            NO_CHAIN,
            1_792_400_006_000,
            Action::SetRoles {
                device_id: "dev-phone".into(),
                change: RolesChange::Native([Role::View].into_iter().collect()),
            },
        );
        // r9-vectors-membership-log's R7, byte for byte: the recovery key
        // adds dev-newmac, pending for 24 h on any list that carries it.
        let r7 = made.v.object("R7");
        made.entries.push((
            "SR7_recovery_add_newmac",
            "r9-vectors-membership-log's R7 (recovery_add of dev-newmac by the recovery key) on E6: dev-newmac is the subject of a recovery still waiting, no current member",
            NO_CHAIN,
            r7,
        ));
        // r9-vectors-membership-log's A8, byte for byte: dev-mac approves
        // R7, which takes effect at once. dev-newmac entered with manage.
        let a8 = made.v.object("A8");
        made.entries.push((
            "SR8_recovery_approve_newmac",
            "r9-vectors-membership-log's A8 (recovery_approve of R7 by dev-mac) on SR7_recovery_add_newmac: the recovery takes effect, and dev-newmac, added by the Recovery Kit with [control, manage, view], is a current manager",
            RECOVERING,
            a8,
        ));
        let svc_key = principal_key_of(&made.public("svc-discord/auth")).unwrap();
        let stop = |signer: &str, action: ControlAction, origin: &str, n: u64| ControlBody {
            account_id: support::ACCOUNT.into(),
            genesis_hash: made.v.hash("E1"),
            feed: Some(ControlFeed {
                origin: origin.into(),
                feed_id: FEED.into(),
            }),
            principal: ControlPrincipal::Service("svc-discord".into()),
            principal_key: Some(svc_key),
            signer: ControlSigner::Member(signer.into()),
            action,
            record_id: record_id(n),
            issued_at: ISSUED - 60_000 + n,
            about: ControlAbout {
                integration_id: Some(INTEGRATION.into()),
                by: "owner".into(),
            },
        };
        let host = |signer: &str, n: u64| ControlBody {
            account_id: support::ACCOUNT.into(),
            genesis_hash: made.v.hash("E1"),
            feed: None,
            principal: ControlPrincipal::Host("host-a".into()),
            principal_key: None,
            signer: ControlSigner::Member(signer.into()),
            action: ControlAction::InterruptRunning {
                revoke_seq: Some(7),
            },
            record_id: record_id(n),
            issued_at: ISSUED - 60_000 + n,
            about: ControlAbout {
                integration_id: None,
                by: "owner".into(),
            },
        };
        let revoke = ControlAction::Revoke {
            interrupt_running: true,
        };
        let interrupt = ControlAction::InterruptRunning { revoke_seq: None };
        made.records = vec![
            Rec {
                label: "phone_revoke",
                note: "dev-phone's revoke of svc-discord with interrupt_running, at this Station",
                body: stop("dev-phone", revoke, STATION, 1),
                key: "dev-phone/auth",
            },
            Rec {
                label: "phone_interrupt",
                note: "dev-phone's interrupt_running of svc-discord, at this Station",
                body: stop("dev-phone", interrupt, STATION, 2),
                key: "dev-phone/auth",
            },
            Rec {
                label: "phone_host_interrupt",
                note: "dev-phone's interrupt_running of the host sender host-a (revoke_seq 7): no origin",
                body: host("dev-phone", 3),
                key: "dev-phone/auth",
            },
            Rec {
                label: "phone_draft",
                note: "dev-phone's revoke of svc-discord without interrupt_running, at this Station: a draft",
                body: stop(
                    "dev-phone",
                    ControlAction::Revoke {
                        interrupt_running: false,
                    },
                    STATION,
                    4,
                ),
                key: "dev-phone/auth",
            },
            Rec {
                label: "phone_signing",
                note: "dev-phone's interrupt_running of svc-discord, at this Station: a body in signing, its signature possibly made and not saved (the record shown is one that could exist)",
                body: stop("dev-phone", interrupt, STATION, 5),
                key: "dev-phone/auth",
            },
            Rec {
                label: "phone_after_report",
                note: "dev-phone's revoke of svc-discord, at this Station, signed after the report",
                body: stop("dev-phone", revoke, STATION, 6),
                key: "dev-phone/auth",
            },
            Rec {
                label: "desk_revoke",
                note: "dev-desk's (Ed25519) revoke of svc-discord with interrupt_running, at this Station",
                body: stop("dev-desk", revoke, STATION, 7),
                key: "dev-desk/auth",
            },
            Rec {
                label: "mac_revoke",
                note: "dev-mac's revoke of svc-discord, at this Station: another member's",
                body: stop("dev-mac", revoke, STATION, 1),
                key: "dev-mac/auth",
            },
            Rec {
                label: "phone_elsewhere",
                note: "dev-phone's revoke of svc-discord at another Station's origin: not this plan's",
                body: stop("dev-phone", revoke, OTHER_STATION, 1),
                key: "dev-phone/auth",
            },
            Rec {
                label: "newmac_revoke",
                note: "dev-newmac's (a manager added by the Recovery Kit) revoke of svc-discord with interrupt_running, at this Station",
                body: stop("dev-newmac", revoke, STATION, 8),
                key: "dev-newmac/auth",
            },
        ];
        made
    }

    fn public(&self, id: &str) -> PublicKey {
        self.keys.public_key(&KeyId::new(id)).unwrap()
    }

    /// An entry by dev-mac on L and the entries `on`.
    fn push(
        &mut self,
        label: &'static str,
        note: &'static str,
        on: &'static [&'static str],
        at: u64,
        action: Action,
    ) {
        let log = self.log(on, None, NOW);
        let body = log.draft("dev-mac", at, &action);
        let entry = sign_entry(&self.keys, &KeyId::new("dev-mac/auth"), body).unwrap();
        self.entries.push((label, note, on, entry.object().clone()));
    }

    fn log(&self, chain: &[&str], freeze: Option<&str>, now_ms: u64) -> Membership {
        log_of(&self.v, &self.entry_objects(chain), freeze, now_ms)
    }

    fn entry_objects(&self, chain: &[&str]) -> Vec<SignedObject> {
        chain
            .iter()
            .map(|label| {
                self.entries
                    .iter()
                    .find(|(l, _, _, _)| l == label)
                    .unwrap_or_else(|| panic!("no entry {label}"))
                    .3
                    .clone()
            })
            .collect()
    }

    fn entries_json(&self) -> Vec<Value> {
        self.entries
            .iter()
            .map(|(label, note, on, object)| {
                json!({
                    "label": label,
                    "note": note,
                    "on": on,
                    "entry": object.to_json(),
                    "entry_hash": object.entry_hash().unwrap().to_hex(),
                })
            })
            .collect()
    }

    fn rec(&self, label: &str) -> &Rec {
        self.records
            .iter()
            .find(|r| r.label == label)
            .unwrap_or_else(|| panic!("no record {label}"))
    }

    /// A record's body as the journal holds it (its jcs).
    fn body(&self, label: &str) -> String {
        jcs(&self.rec(label).body.to_json()).unwrap()
    }

    /// A record as its signer signed it (its jcs).
    fn record(&self, label: &str) -> String {
        let rec = self.rec(label);
        let object = build_control(&self.keys, &KeyId::new(rec.key), &rec.body).unwrap();
        jcs(&object.to_json()).unwrap()
    }

    fn records_json(&self) -> Vec<Value> {
        self.records
            .iter()
            .map(|rec| {
                let body = rec.body.to_json();
                let text = jcs(&body).unwrap();
                json!({
                    "label": rec.label,
                    "note": rec.note,
                    "body": body,
                    "jcs": text,
                    "digest_hex": Hash32::of(text.as_bytes()).to_hex(),
                    "record": serde_json::from_str::<Value>(&self.record(rec.label)).unwrap(),
                    "signed_with": rec.key,
                })
            })
            .collect()
    }

    /// A journal of `records` and `drafts` (record labels).
    fn journal(
        &self,
        id: &[u8; 16],
        since: u64,
        revision: u64,
        records: &[&str],
        drafts: &[&str],
    ) -> Journal {
        Journal {
            id: *id,
            since,
            revision,
            records: records.iter().map(|l| self.body(l)).collect(),
            drafts: drafts.iter().map(|l| self.body(l)).collect(),
        }
    }

    /// The standard journal: three records, one draft.
    fn plan_journal(&self) -> Journal {
        self.journal(
            JOURNAL_ID,
            4,
            118,
            &["phone_revoke", "phone_interrupt", "phone_host_interrupt"],
            &["phone_draft"],
        )
    }

    fn plan_exported(&self) -> Vec<String> {
        ["phone_revoke", "phone_interrupt", "phone_host_interrupt"]
            .iter()
            .map(|l| self.record(l))
            .collect()
    }

    /// The body the builder makes for `signer` in `slot` at `log`'s head,
    /// with the vectors' process.
    fn body_of(
        &self,
        log: &Membership,
        challenge: &Value,
        signer: &str,
        journal: &Journal,
    ) -> Value {
        let built = signer_report_body(
            log,
            &read_challenge(challenge),
            signer,
            challenge["slot"].as_str().unwrap(),
            STATION,
            &journal.view(),
            NOW.min(challenge["expires_at"].as_u64().unwrap() - 1),
        )
        .unwrap_or_else(|e| panic!("{signer}: {e}"));
        let mut body = built.to_json();
        body["process"] = json!(b64u(PROCESS));
        body
    }
}

/// A journal view, as the file writes it.
#[derive(Clone)]
struct Journal {
    id: [u8; 16],
    since: u64,
    revision: u64,
    records: Vec<String>,
    drafts: Vec<String>,
}

impl Journal {
    fn view(&self) -> JournalView {
        JournalView {
            id: self.id,
            since: self.since,
            revision: self.revision,
            records: self.records.clone(),
            drafts: self.drafts.clone(),
        }
    }

    fn to_json(&self) -> Value {
        json!({"id": b64u(&self.id), "since": self.since, "revision": self.revision,
               "records": self.records, "drafts": self.drafts})
    }

    fn from_json(value: &Value) -> JournalView {
        let strings = |key: &str| -> Vec<String> {
            value[key]
                .as_array()
                .unwrap()
                .iter()
                .map(|t| t.as_str().unwrap().to_owned())
                .collect()
        };
        JournalView {
            id: b64u_decode(value["id"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
            since: value["since"].as_u64().unwrap(),
            revision: value["revision"].as_u64().unwrap(),
            records: strings("records"),
            drafts: strings("drafts"),
        }
    }
}

/// What a case expects of the core.
#[derive(Debug, Clone)]
enum Want {
    /// A verified report, at the list's head or not.
    Verified {
        at_head: bool,
    },
    Code(&'static str),
}

struct Report {
    label: &'static str,
    note: &'static str,
    chain: &'static [&'static str],
    freeze: Option<&'static str>,
    challenge: Value,
    now_ms: u64,
    text: String,
    exported: Vec<String>,
    /// The key that signed it, for a valid case.
    signed_with: Option<&'static str>,
    want: Want,
}

impl Gen {
    #[allow(clippy::too_many_arguments)]
    fn report(
        &self,
        label: &'static str,
        note: &'static str,
        chain: &'static [&'static str],
        challenge: Value,
        text: String,
        exported: Vec<String>,
        want: Want,
    ) -> Report {
        Report {
            label,
            note,
            chain,
            freeze: None,
            challenge,
            now_ms: NOW,
            text,
            exported,
            signed_with: None,
            want,
        }
    }

    /// The valid reports.
    fn valid(&self) -> Vec<Report> {
        let keys = &self.keys;
        let l = self.log(NO_CHAIN, None, NOW);
        let phone = challenge(PHONE, SLOT, 3);
        let plan = self.plan_journal();
        let good = signed(
            keys,
            "dev-phone/auth",
            &self.body_of(&l, &phone, PHONE, &plan),
        );
        let exported = self.plan_exported();
        let mut reversed = exported.clone();
        reversed.reverse();
        let ok = |at_head| Want::Verified { at_head };
        let empty = self.journal(JOURNAL_ID, 4, 0, &[], &[]);
        let drafts_only = self.journal(JOURNAL_ID, 4, 1, &[], &["phone_draft"]);
        let reinstalled = self.journal(REINSTALLED_ID, 6, 1, &["phone_revoke"], &[]);
        let demoted = self.log(DEMOTED, None, NOW);
        let one = self.journal(JOURNAL_ID, 4, 3, &["phone_revoke"], &[]);
        let desk_log = self.log(DESK_MANAGES, None, NOW);
        let desk = challenge(DESK, SLOT, 2);
        let desk_journal = self.journal(JOURNAL_ID, 8, 2, &["desk_revoke"], &[]);
        let recovered = self.log(RECOVERED, None, NOW);
        let newmac = challenge(NEWMAC, SLOT, 1);
        let newmac_journal = self.journal(JOURNAL_ID, 8, 1, &["newmac_revoke"], &[]);
        let mut out = vec![
            self.report(
                "at_head",
                "dev-phone (P-256) at L's head: a service's revoke and interrupt at this Station and a host sender's interrupt (no origin) together as records, one draft; the three records exported",
                NO_CHAIN,
                phone.clone(),
                good.clone(),
                exported.clone(),
                ok(true),
            ),
            self.report(
                "at_ancestor",
                "the same report, verified at L + SR7_add_desk: signed at an ancestor",
                DESK_ADDED,
                phone.clone(),
                good.clone(),
                exported.clone(),
                ok(false),
            ),
            self.report(
                "exported_in_another_order",
                "the same report with its records exported in reverse: a set",
                NO_CHAIN,
                phone.clone(),
                good,
                reversed,
                ok(true),
            ),
            self.report(
                "zero_records",
                "a journal that holds nothing of the plan: no records, no drafts, nothing exported",
                NO_CHAIN,
                phone.clone(),
                signed(keys, "dev-phone/auth", &self.body_of(&l, &phone, PHONE, &empty)),
                Vec::new(),
                ok(true),
            ),
            self.report(
                "drafts_only",
                "zero records and one draft: drafts are never exported",
                NO_CHAIN,
                phone.clone(),
                signed(keys, "dev-phone/auth", &self.body_of(&l, &phone, PHONE, &drafts_only)),
                Vec::new(),
                ok(true),
            ),
            self.report(
                "reinstalled_journal",
                "a reinstalled journal: another id, a later since (valid for the primitive; comparing it with the earlier report is the Station's)",
                NO_CHAIN,
                phone.clone(),
                signed(keys, "dev-phone/auth", &self.body_of(&l, &phone, PHONE, &reinstalled)),
                vec![self.record("phone_revoke")],
                ok(true),
            ),
            self.report(
                "demoted_manager",
                "dev-phone after its roles changed to [view] (L + SR7_set_roles_phone): it held manage at some seq, so it still reports",
                DEMOTED,
                phone.clone(),
                signed(keys, "dev-phone/auth", &self.body_of(&demoted, &phone, PHONE, &one)),
                vec![self.record("phone_revoke")],
                ok(true),
            ),
            self.report(
                "ed25519_manager",
                "dev-desk (Ed25519) once a manager (L + SR7_add_desk + SR8_desk_manages), its own revoke exported",
                DESK_MANAGES,
                desk.clone(),
                signed(keys, "dev-desk/auth", &self.body_of(&desk_log, &desk, DESK, &desk_journal)),
                vec![self.record("desk_revoke")],
                ok(true),
            ),
            self.report(
                "recovered_manager",
                "dev-newmac, added by the Recovery Kit (R7) with manage, once the recovery took effect (approved, A8: L + SR7_recovery_add_newmac + SR8_recovery_approve_newmac), its own revoke exported",
                RECOVERED,
                newmac.clone(),
                signed(
                    keys,
                    "dev-newmac/auth",
                    &self.body_of(&recovered, &newmac, NEWMAC, &newmac_journal),
                ),
                vec![self.record("newmac_revoke")],
                ok(true),
            ),
        ];
        let signers = [
            "dev-phone/auth",
            "dev-phone/auth",
            "dev-phone/auth",
            "dev-phone/auth",
            "dev-phone/auth",
            "dev-phone/auth",
            "dev-phone/auth",
            "dev-desk/auth",
            "dev-newmac/auth",
        ];
        for (case, key) in out.iter_mut().zip(signers) {
            case.signed_with = Some(key);
        }
        out
    }

    /// The reports refused, malformed ones first.
    fn invalid(&self) -> Vec<Report> {
        let keys = &self.keys;
        let l = self.log(NO_CHAIN, None, NOW);
        let phone = challenge(PHONE, SLOT, 3);
        let plan = self.plan_journal();
        let good = self.body_of(&l, &phone, PHONE, &plan);
        let good_text = signed(keys, "dev-phone/auth", &good);
        let exported = self.plan_exported();
        let resign = |f: &dyn Fn(&mut Value)| signed(keys, "dev-phone/auth", &edit(&good, f));
        let m = |label, note, text: String| {
            self.report(
                label,
                note,
                NO_CHAIN,
                phone.clone(),
                text,
                exported.clone(),
                Want::Code("malformed"),
            )
        };
        let in_body = |from: &str, to: &str| {
            assert!(good_text.contains(from), "{from}");
            good_text.replacen(from, to, 1)
        };
        let mut out = vec![
            m(
                "duplicate_key_beside_body",
                "sig twice",
                good_text.replacen(r#","sig":"#, r#","sig":"AA","sig":"#, 1),
            ),
            m(
                "duplicate_key_in_body",
                "slot twice, the first another's",
                in_body(r#""slot":"#, r#""slot":"astation-mac","slot":"#),
            ),
            m(
                "duplicate_key_escaped",
                "slot twice, the first spelled with an escape",
                in_body(r#""slot":"#, r#""\u0073lot":"astation-mac","slot":"#),
            ),
            m(
                "duplicate_key_in_challenge",
                "nonce twice in the body's challenge",
                in_body(r#""nonce":"#, r#""nonce":"AA","nonce":"#),
            ),
            m(
                "duplicate_key_in_recovery",
                "plan_id twice in the recovery",
                in_body(r#""plan_id":"#, r#""plan_id":"x","plan_id":"#),
            ),
            m(
                "duplicate_key_in_journal",
                "records twice in the journal",
                in_body(r#""records":3"#, r#""records":2,"records":3"#),
            ),
            m(
                "unknown_field_beside_body",
                "a third field beside body and sig",
                good_text.replacen(r#"{"body":"#, r#"{"note":"x","body":"#, 1),
            ),
            m(
                "unknown_field_in_body",
                "the body with a field beyond its eleven, signed",
                resign(&|b| b["note"] = json!("x")),
            ),
            m(
                "unknown_field_in_head",
                "head with a field beyond seq and hash, signed",
                resign(&|b| b["head"]["note"] = json!("x")),
            ),
            m(
                "unknown_field_in_challenge",
                "the body's challenge with a field beyond its five (signer and slot sit at the top, the recovery beside it), signed",
                resign(&|b| b["challenge"]["signer"] = json!(PHONE)),
            ),
            m(
                "recovery_in_challenge",
                "the recovery inside the body's challenge rather than beside it, signed",
                resign(&|b| {
                    let recovery = b.as_object_mut().unwrap().remove("recovery").unwrap();
                    b["challenge"]["recovery"] = recovery;
                }),
            ),
            m(
                "unknown_field_in_recovery",
                "recovery with a field beyond its five, signed",
                resign(&|b| b["recovery"]["note"] = json!("x")),
            ),
            m(
                "unknown_field_in_journal",
                "journal with a field beyond its seven, signed",
                resign(&|b| b["journal"]["note"] = json!("x")),
            ),
            m(
                "null_slot",
                "slot null, signed",
                resign(&|b| b["slot"] = Value::Null),
            ),
            m(
                "null_in_challenge",
                "the challenge's nonce null, signed",
                resign(&|b| b["challenge"]["nonce"] = Value::Null),
            ),
            m(
                "null_in_recovery",
                "the recovery's plan_id null, signed",
                resign(&|b| b["recovery"]["plan_id"] = Value::Null),
            ),
            m(
                "null_in_journal",
                "the journal's since null, signed",
                resign(&|b| b["journal"]["since"] = Value::Null),
            ),
            m(
                "missing_process",
                "no process, signed",
                resign(&|b| {
                    b.as_object_mut().unwrap().remove("process");
                }),
            ),
            m(
                "missing_recovery",
                "no recovery, signed",
                resign(&|b| {
                    b.as_object_mut().unwrap().remove("recovery");
                }),
            ),
            m(
                "missing_journal",
                "no journal, signed",
                resign(&|b| {
                    b.as_object_mut().unwrap().remove("journal");
                }),
            ),
            m(
                "missing_challenge_field",
                "the challenge without connection, signed",
                resign(&|b| {
                    b["challenge"].as_object_mut().unwrap().remove("connection");
                }),
            ),
            m(
                "missing_recovery_field",
                "the recovery without evidence_hash, signed",
                resign(&|b| {
                    b["recovery"]
                        .as_object_mut()
                        .unwrap()
                        .remove("evidence_hash");
                }),
            ),
            m(
                "missing_journal_field",
                "the journal without drafts_hash, signed",
                resign(&|b| {
                    b["journal"].as_object_mut().unwrap().remove("drafts_hash");
                }),
            ),
            m(
                "missing_sig",
                "the body alone",
                format!(r#"{{"body":{}}}"#, jcs(&good).unwrap()),
            ),
            m(
                "kit_sig_beside_body",
                "a kit_sig beside a report",
                good_text.replacen(r#"{"body":"#, r#"{"kit_sig":"AA","body":"#, 1),
            ),
        ];
        for (label, origin) in [
            ("origin_upper_case", "https://Station-dev.agora.build"),
            ("origin_trailing_slash", "https://station-dev.agora.build/"),
            ("origin_default_port", "https://station-dev.agora.build:443"),
            ("origin_path", "https://station-dev.agora.build/v1"),
            ("origin_userinfo", "https://user@station-dev.agora.build"),
            ("origin_http", "http://station-dev.agora.build"),
        ] {
            out.push(m(
                label,
                "a non-canonical origin, signed (the expected challenge is the canonical one)",
                resign(&|b| b["challenge"]["origin"] = json!(origin)),
            ));
        }
        let fields: Vec<(&'static str, &'static str, Value)> = vec![
            ("nonce_31_bytes", "challenge.nonce", json!(b64u(&[0u8; 31]))),
            ("nonce_33_bytes", "challenge.nonce", json!(b64u(&[0u8; 33]))),
            (
                "nonce_padded",
                "challenge.nonce",
                json!(format!("{}=", b64u(&nonce(0)))),
            ),
            (
                "nonce_standard_base64",
                "challenge.nonce",
                json!("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh+/"),
            ),
            ("slot_empty", "slot", json!("")),
            ("slot_129_bytes", "slot", json!("s".repeat(129))),
            ("slot_space", "slot", json!("astation ios")),
            ("process_15_bytes", "process", json!(b64u(&[1u8; 15]))),
            ("process_17_bytes", "process", json!(b64u(&[1u8; 17]))),
            (
                "process_not_base64url",
                "process",
                json!("vectors process!"),
            ),
            ("lease_zero", "challenge.expires_at", json!(ISSUED)),
            ("lease_negative", "challenge.expires_at", json!(ISSUED - 1)),
            (
                "lease_over_30_seconds",
                "challenge.expires_at",
                json!(ISSUED + 30_001),
            ),
            ("connection_zero", "challenge.connection", json!(0)),
            ("connection_negative", "challenge.connection", json!(-1)),
            ("connection_text", "challenge.connection", json!("3")),
            ("connection_true", "challenge.connection", json!(true)),
            ("issued_at_negative", "challenge.issued_at", json!(-1)),
            ("signer_without_prefix", "signer", json!("dev-phone")),
            ("signer_unknown_prefix", "signer", json!("device:dev-phone")),
            ("signer_empty_id", "signer", json!("member:")),
            ("head_seq_zero", "head.seq", json!(0)),
            (
                "head_hash_upper_case",
                "head.hash",
                json!(l.head().hash.to_hex().to_uppercase()),
            ),
            (
                "genesis_hash_upper_case",
                "genesis_hash",
                json!(l.genesis_hash().to_hex().to_uppercase()),
            ),
            ("account_id_129_bytes", "account_id", json!("a".repeat(129))),
            ("generation_number", "recovery.generation", json!(7)),
            ("generation_empty", "recovery.generation", json!("")),
            ("generation_zero", "recovery.generation", json!("0")),
            (
                "generation_leading_zero",
                "recovery.generation",
                json!("07"),
            ),
            ("generation_plus", "recovery.generation", json!("+7")),
            ("generation_minus", "recovery.generation", json!("-7")),
            ("generation_space", "recovery.generation", json!(" 7")),
            ("generation_fraction", "recovery.generation", json!("7.0")),
            ("generation_exponent", "recovery.generation", json!("1e3")),
            (
                "generation_2_63",
                "recovery.generation",
                json!("9223372036854775808"),
            ),
            (
                "generation_20_digits",
                "recovery.generation",
                json!("10000000000000000000"),
            ),
            (
                "plan_id_v1",
                "recovery.plan_id",
                json!("5b7c9d1e-2f3a-1b5c-8d6e-7f8091a2b3c4"),
            ),
            (
                "plan_id_upper_case",
                "recovery.plan_id",
                json!(PLAN.to_uppercase()),
            ),
            (
                "plan_id_no_dashes",
                "recovery.plan_id",
                json!(PLAN.replace('-', "")),
            ),
            (
                "candidate_feed_id_not_a_uuid",
                "recovery.candidate_feed_id",
                json!("feed-1"),
            ),
            (
                "source_hash_upper_case",
                "recovery.source_hash",
                json!("5A".repeat(32)),
            ),
            (
                "source_hash_31_bytes",
                "recovery.source_hash",
                json!("5a".repeat(31)),
            ),
            ("evidence_hash_number", "recovery.evidence_hash", json!(7)),
            ("journal_id_15_bytes", "journal.id", json!(b64u(&[1u8; 15]))),
            ("journal_id_17_bytes", "journal.id", json!(b64u(&[1u8; 17]))),
            (
                "journal_id_padded",
                "journal.id",
                json!(format!("{}==", b64u(JOURNAL_ID))),
            ),
            (
                "journal_id_not_base64url",
                "journal.id",
                json!("vectors journal!"),
            ),
            ("since_zero", "journal.since", json!(0)),
            ("since_negative", "journal.since", json!(-1)),
            ("since_text", "journal.since", json!("4")),
            ("revision_negative", "journal.revision", json!(-1)),
            ("revision_text", "journal.revision", json!("118")),
            ("records_negative", "journal.records", json!(-1)),
            ("records_true", "journal.records", json!(true)),
            (
                "records_hash_upper_case",
                "journal.records_hash",
                json!(
                    good["journal"]["records_hash"]
                        .as_str()
                        .unwrap()
                        .to_uppercase()
                ),
            ),
            (
                "records_hash_short",
                "journal.records_hash",
                json!(&good["journal"]["records_hash"].as_str().unwrap()[..62]),
            ),
            ("drafts_negative", "journal.drafts", json!(-1)),
            (
                "drafts_hash_upper_case",
                "journal.drafts_hash",
                json!(
                    good["journal"]["drafts_hash"]
                        .as_str()
                        .unwrap()
                        .to_uppercase()
                ),
            ),
            ("drafts_hash_empty", "journal.drafts_hash", json!("")),
        ];
        for (label, path, value) in fields {
            let text = resign(&|b| {
                let mut at = &mut *b;
                for part in path.split('.') {
                    at = &mut at[part];
                }
                *at = value.clone();
            });
            out.push(m(label, "one field outside its grammar, signed", text));
        }
        out.extend([
            m(
                "array_in_journal",
                "journal.records as an array of the bodies (signed): a report carries counts and hashes, never an array",
                resign(&|b| {
                    b["journal"]["records"] = json!(["a", "b", "c"]);
                }),
            ),
            m(
                "array_elsewhere",
                "slot as an array (signed)",
                resign(&|b| b["slot"] = json!([SLOT])),
            ),
            m(
                "fraction",
                "connection 3.5 (strict I-JSON: integers only)",
                in_body(r#""connection":3"#, r#""connection":3.5"#),
            ),
            m(
                "unsafe_integer",
                "revision 2^53, beyond the safe integers",
                in_body(r#""revision":118"#, r#""revision":9007199254740992"#),
            ),
            m("v_2", "v 2 (signed)", resign(&|b| b["v"] = json!(2))),
            m(
                "type_of_another_kind",
                "the body typed atem-verifier-report and signed under its label",
                signed_as(
                    keys,
                    "dev-phone/auth",
                    SignLabel::VerifierReport,
                    &edit(&good, |b| b["type"] = json!("atem-verifier-report")),
                ),
            ),
            m(
                "unknown_type",
                "the body typed atem-signer-report-2",
                resign(&|b| b["type"] = json!("atem-signer-report-2")),
            ),
            m("not_an_object", "an array", format!("[{good_text}]")),
            m(
                "sig_not_base64url",
                "sig with a character outside base64url",
                good_text.replacen(r#""sig":""#, r#""sig":"*"#, 1),
            ),
            m(
                "object_over_16_kib",
                "whitespace after the body: the object as received over 16 KiB",
                good_text.replacen(
                    r#","sig":"#,
                    &format!("{},\"sig\":", " ".repeat(16 * 1024)),
                    1,
                ),
            ),
        ]);
        // No body whose every field is in its grammar reaches 4,096 bytes
        // of jcs (it has no array): this one's account_id is beyond its
        // grammar too, and the size is what the reader refuses first.
        let big = edit(&good, |b| b["account_id"] = json!("a".repeat(4096)));
        assert!(jcs(&big).unwrap().len() > 4096);
        out.push(m(
            "body_over_4096_bytes",
            "an account_id of 4,096 bytes: the body's jcs over 4,096 bytes",
            signed(keys, "dev-phone/auth", &big),
        ));

        // Refused after reading, in the verifier's order.
        let r = |label, note, text: String, code| {
            self.report(
                label,
                note,
                NO_CHAIN,
                phone.clone(),
                text,
                exported.clone(),
                Want::Code(code),
            )
        };
        let as_signer = |signer: &str, key: &str| {
            signed(keys, key, &edit(&good, |b| b["signer"] = json!(signer)))
        };
        let mut frozen = r(
            "frozen",
            "a valid report, the list frozen by C6_mac",
            good_text.clone(),
            "frozen",
        );
        frozen.freeze = Some("C6_mac");
        let mut frozen_other = r(
            "frozen_before_wrong_account",
            "another account's report against a frozen list: frozen first",
            resign(&|b| b["account_id"] = json!("acct-other")),
            "frozen",
        );
        frozen_other.freeze = Some("C6_mac");
        out.extend([
            frozen,
            frozen_other,
            r(
                "wrong_account",
                "account_id acct-other, signed",
                resign(&|b| b["account_id"] = json!("acct-other")),
                "wrong_account",
            ),
            r(
                "wrong_genesis",
                "another genesis_hash (SUB1's), signed",
                resign(&|b| b["genesis_hash"] = json!(self.v.hash("SUB1").to_hex())),
                "wrong_account",
            ),
            r(
                "unknown_member",
                "member:dev-evil, never a member, with its own key",
                as_signer("member:dev-evil", "dev-evil/auth"),
                "unknown_signer",
            ),
            r(
                "removed_member",
                "member:dev-ipad, a manager removed by E6, with its own key",
                as_signer("member:dev-ipad", "dev-ipad/auth"),
                "unknown_signer",
            ),
            r(
                "recovery",
                "member:recovery, with the current kit's recovery key",
                as_signer("member:recovery", "recovery/sign"),
                "unknown_signer",
            ),
            r(
                "host",
                "host:host-a, with its host_channel_key",
                as_signer("host:host-a", "host-a/host_key"),
                "unknown_signer",
            ),
            r(
                "browser_grant",
                "browser:grant-1, with the browser's key",
                as_signer("browser:grant-1", "browser/auth"),
                "unknown_signer",
            ),
            r(
                "service",
                "service:svc-discord, a service with its own key: only a native member reports its signing journal",
                as_signer("service:svc-discord", "svc-discord/auth"),
                "unknown_signer",
            ),
            r(
                "service_as_member",
                "member:svc-discord: a service named as a native member, with its key",
                as_signer("member:svc-discord", "svc-discord/auth"),
                "unknown_signer",
            ),
        ]);
        let recovering = self.log(RECOVERING, None, NOW);
        let newmac = challenge("member:dev-newmac", SLOT, 3);
        let newmac_body = edit(&self.body_of(&recovering, &phone, PHONE, &plan), |b| {
            b["signer"] = json!("member:dev-newmac")
        });
        out.push(self.report(
            "pending_recovery_subject",
            "member:dev-newmac at L + SR7_recovery_add_newmac's head, with its own key: the subject of a recovery_add still waiting",
            RECOVERING,
            newmac,
            signed(keys, "dev-newmac/auth", &newmac_body),
            exported.clone(),
            Want::Code("unknown_signer"),
        ));
        let desk_added = self.log(DESK_ADDED, None, NOW);
        let desk = challenge(DESK, SLOT, 2);
        let desk_body = edit(
            &self.body_of(
                &desk_added,
                &phone,
                PHONE,
                &self.journal(JOURNAL_ID, 8, 0, &[], &[]),
            ),
            |b| b["signer"] = json!(DESK),
        );
        out.push(self.report(
            "not_a_manager",
            "dev-desk (L + SR7_add_desk), a current native member that never held manage, with its own key",
            DESK_ADDED,
            desk,
            signed(keys, "dev-desk/auth", &desk_body),
            Vec::new(),
            Want::Code("not_a_manager"),
        ));
        out.push(r(
            "another_members_key",
            "dev-phone's report signed by dev-mac's key",
            signed(keys, "dev-mac/auth", &good),
            "bad_signature",
        ));
        out.push(r(
            "tampered_after_signing",
            "the journal's revision changed after signing",
            good_text.replacen(r#""revision":118"#, r#""revision":119"#, 1),
            "bad_signature",
        ));
        for (label, other) in [
            ("signed_under_route_label", SignLabel::HostRoute),
            ("signed_under_proxy_route_label", SignLabel::HostRouteProxy),
            ("signed_under_sig_c_label", SignLabel::ChannelClient),
            ("signed_under_control_label", SignLabel::HostWorkControl),
            ("signed_under_entry_label", SignLabel::MembershipEntry),
            (
                "signed_under_verifier_report_label",
                SignLabel::VerifierReport,
            ),
        ] {
            out.push(r(
                label,
                "the report's body signed by dev-phone under another label",
                signed_as(keys, "dev-phone/auth", other, &good),
                "bad_signature",
            ));
        }
        out.push(r(
            "high_s_signature",
            "the valid P-256 report (at_head) with s replaced by n - s: a high S",
            with_high_s(&good_text),
            "bad_signature",
        ));
        let l7 = self.log(DESK_ADDED, None, NOW);
        out.push(r(
            "stale_log",
            "dev-phone at L + SR7_add_desk's head, verified at L",
            signed(
                keys,
                "dev-phone/auth",
                &self.body_of(&l7, &phone, PHONE, &plan),
            ),
            "stale_log",
        ));
        out.push(r(
            "fork",
            "head seq 6 at C6_ipad's hash (a sibling of E6)",
            resign(&|b| b["head"]["hash"] = json!(self.v.hash("C6_ipad").to_hex())),
            "fork",
        ));
        out.push(r(
            "fork_earlier_seq",
            "head seq 5 at E6's hash",
            resign(&|b| b["head"] = json!({"seq": 5, "hash": self.v.hash("E6").to_hex()})),
            "fork",
        ));
        // Substitution: a valid report by another member, and for another
        // slot.
        let mac = challenge(MAC, SLOT, 3);
        let empty = self.journal(JOURNAL_ID, 2, 0, &[], &[]);
        out.push(self.report(
            "signer_mismatch",
            "a valid report by dev-mac (a manager, its own empty journal), against the expectation for dev-phone",
            NO_CHAIN,
            phone.clone(),
            signed(keys, "dev-mac/auth", &self.body_of(&l, &mac, MAC, &empty)),
            Vec::new(),
            Want::Code("signer_mismatch"),
        ));
        let slot_x = with(phone.clone(), "slot", json!("astation-mac"));
        out.push(r(
            "slot_mismatch",
            "a valid report of dev-phone for slot astation-mac, against the expectation for astation-ios",
            signed(keys, "dev-phone/auth", &self.body_of(&l, &slot_x, PHONE, &plan)),
            "slot_mismatch",
        ));
        for (label, field, value) in [
            (
                "origin_mismatch",
                "origin",
                json!("https://station.agora.build"),
            ),
            ("connection_mismatch", "connection", json!(4)),
            ("nonce_mismatch", "nonce", json!(b64u(&nonce(32)))),
            ("issued_at_mismatch", "issued_at", json!(ISSUED + 1)),
            ("expires_at_mismatch", "expires_at", json!(EXPIRES - 1)),
        ] {
            let mut case = r(
                label,
                "a valid report against a stored challenge one field of which differs",
                good_text.clone(),
                "challenge_mismatch",
            );
            case.challenge = with(phone.clone(), field, value);
            out.push(case);
        }
        for (label, field, value) in [
            ("generation_mismatch", "generation", json!("8")),
            (
                "plan_id_mismatch",
                "plan_id",
                json!("9b7c9d1e-2f3a-4b5c-8d6e-7f8091a2b3c4"),
            ),
            (
                "candidate_feed_id_mismatch",
                "candidate_feed_id",
                json!("9a2d3c4b-5e6f-4071-9b8c-0d1e2f3a4b5c"),
            ),
            (
                "source_hash_mismatch",
                "source_hash",
                json!("5b".repeat(32)),
            ),
            (
                "evidence_hash_mismatch",
                "evidence_hash",
                json!("e8".repeat(32)),
            ),
        ] {
            let mut case = r(
                label,
                "a valid report against a stored challenge whose recovery differs in this field",
                good_text.clone(),
                "recovery_mismatch",
            );
            case.challenge["recovery"][field] = value;
            out.push(case);
        }
        // records_mismatch in each form, against the valid report (three
        // records), but where the report's own journal says otherwise.
        let with_record = |i: usize, record: String| {
            let mut all = exported.clone();
            all[i] = record;
            all
        };
        let rm = |label, note, exported: Vec<String>| {
            self.report(
                label,
                note,
                NO_CHAIN,
                phone.clone(),
                good_text.clone(),
                exported,
                Want::Code("records_mismatch"),
            )
        };
        let mut extra = exported.clone();
        extra.push(self.record("phone_after_report"));
        let mut twice = exported[..2].to_vec();
        twice.push(exported[0].clone());
        let forged = {
            let rec = self.rec("phone_revoke");
            let object = build_control(&self.keys, &KeyId::new("dev-mac/auth"), &rec.body).unwrap();
            jcs(&object.to_json()).unwrap()
        };
        out.extend([
            rm(
                "records_one_missing",
                "one of the three records not exported",
                exported[..2].to_vec(),
            ),
            rm(
                "records_one_extra",
                "a fourth record exported, one signed after the report",
                extra,
            ),
            rm(
                "records_signed_after_report",
                "a record signed after the report exported under it in place of one of the report's",
                with_record(0, self.record("phone_after_report")),
            ),
            rm(
                "records_body_without_signature",
                "a record exported as its body alone, with no signature (a body in signing whose signature wasn't saved)",
                with_record(0, self.body("phone_revoke")),
            ),
            rm(
                "records_wrong_signer",
                "another member's record (dev-mac's) exported in place of one",
                with_record(0, self.record("mac_revoke")),
            ),
            rm(
                "records_another_origin",
                "dev-phone's record naming another Station's origin in place of one",
                with_record(0, self.record("phone_elsewhere")),
            ),
            rm(
                "records_duplicate",
                "one record exported twice and another not at all",
                twice,
            ),
            rm(
                "records_signature_by_another_key",
                "dev-phone's record signed by dev-mac's key",
                with_record(0, forged),
            ),
            rm(
                "records_high_s",
                "one record's P-256 signature with a high S",
                with_record(0, with_high_s(&exported[0])),
            ),
            rm(
                "records_not_a_record",
                "an empty object in place of one",
                with_record(0, "{}".into()),
            ),
        ]);
        let signing = self.journal(
            JOURNAL_ID,
            4,
            119,
            &[
                "phone_revoke",
                "phone_interrupt",
                "phone_host_interrupt",
                "phone_signing",
            ],
            &["phone_draft"],
        );
        out.push(self.report(
            "records_possibly_signed",
            "the journal holds phone_signing in signing with no saved signature: it is in the report's records (4) and can't be exported as signed, so the three signed records exported don't match (Astation's conservative rule: no permissive path)",
            NO_CHAIN,
            phone.clone(),
            signed(keys, "dev-phone/auth", &self.body_of(&l, &phone, PHONE, &signing)),
            exported.clone(),
            Want::Code("records_mismatch"),
        ));
        let none = self.journal(JOURNAL_ID, 4, 0, &[], &[]);
        out.push(self.report(
            "records_against_zero",
            "a report of zero records, one record exported with it",
            NO_CHAIN,
            phone.clone(),
            signed(
                keys,
                "dev-phone/auth",
                &self.body_of(&l, &phone, PHONE, &none),
            ),
            vec![self.record("phone_revoke")],
            Want::Code("records_mismatch"),
        ));
        let mut at_expiry = r(
            "expired_at_expires_at",
            "a valid report verified at its expires_at exactly",
            good_text.clone(),
            "expired",
        );
        at_expiry.now_ms = EXPIRES;
        out.push(at_expiry);
        let mut after = r(
            "expired_after",
            "a valid report verified after its expires_at",
            good_text,
            "expired",
        );
        after.now_ms = EXPIRES + 1;
        out.push(after);
        out
    }
}

/// A challenge text and whether the reader takes it.
struct ChallengeCase {
    label: &'static str,
    text: String,
    read: bool,
}

fn challenge_cases() -> Vec<ChallengeCase> {
    let good = challenge(PHONE, SLOT, 3);
    let text = |v: &Value| v.to_string();
    let ok = |label, value: Value| ChallengeCase {
        label,
        text: text(&value),
        read: true,
    };
    let bad = |label, value: String| ChallengeCase {
        label,
        text: value,
        read: false,
    };
    let compact = text(&good);
    let recovery_with = |field: &str, value: Value| {
        let mut c = good.clone();
        c["recovery"][field] = value;
        text(&c)
    };
    let mut out = vec![
        ok("member", good.clone()),
        ok(
            "lease_one_millisecond",
            with(good.clone(), "expires_at", json!(ISSUED + 1)),
        ),
        ok(
            "largest_connection",
            with(
                good.clone(),
                "connection",
                json!(canonical::MAX_SAFE_INTEGER),
            ),
        ),
        ok(
            "loopback_http_origin",
            with(good.clone(), "origin", json!("http://127.0.0.1:8080")),
        ),
        ok(
            "slot_128_bytes",
            with(good.clone(), "slot", json!("s".repeat(128))),
        ),
        ChallengeCase {
            label: "largest_generation",
            text: recovery_with("generation", json!("9223372036854775807")),
            read: true,
        },
        ChallengeCase {
            label: "generation_one",
            text: recovery_with("generation", json!("1")),
            read: true,
        },
        bad(
            "duplicate_key",
            compact.replacen('{', r#"{"slot":"astation-mac","#, 1),
        ),
        bad(
            "duplicate_key_escaped",
            compact.replacen('{', r#"{"\u0073lot":"astation-mac","#, 1),
        ),
        bad(
            "duplicate_key_in_recovery",
            compact.replacen(r#""plan_id":"#, r#""plan_id":"x","plan_id":"#, 1),
        ),
        bad(
            "unknown_field",
            text(&with(good.clone(), "note", json!("x"))),
        ),
        bad(
            "unknown_field_in_recovery",
            recovery_with("note", json!("x")),
        ),
        bad("null", text(&with(good.clone(), "slot", Value::Null))),
        bad(
            "null_recovery",
            text(&with(good.clone(), "recovery", Value::Null)),
        ),
        bad("not_an_object", format!("[{compact}]")),
        bad(
            "over_4096_bytes",
            compact.replacen(',', &format!("{},", " ".repeat(4096)), 1),
        ),
    ];
    for field in [
        "signer",
        "slot",
        "origin",
        "connection",
        "nonce",
        "issued_at",
        "expires_at",
        "recovery",
    ] {
        let mut missing = good.clone();
        missing.as_object_mut().unwrap().remove(field);
        out.push(ChallengeCase {
            label: Box::leak(format!("missing_{field}").into_boxed_str()),
            text: text(&missing),
            read: false,
        });
    }
    for field in [
        "generation",
        "plan_id",
        "candidate_feed_id",
        "source_hash",
        "evidence_hash",
    ] {
        let mut missing = good.clone();
        missing["recovery"].as_object_mut().unwrap().remove(field);
        out.push(ChallengeCase {
            label: Box::leak(format!("missing_recovery_{field}").into_boxed_str()),
            text: text(&missing),
            read: false,
        });
    }
    for (label, field, value) in [
        ("signer_service", "signer", json!("service:svc-discord")),
        ("signer_host", "signer", json!("host:host-a")),
        ("signer_browser", "signer", json!("browser:grant-1")),
        ("signer_without_prefix", "signer", json!("dev-phone")),
        ("slot_empty", "slot", json!("")),
        ("slot_129_bytes", "slot", json!("s".repeat(129))),
        (
            "origin_upper_case",
            "origin",
            json!("https://Station-dev.agora.build"),
        ),
        (
            "origin_trailing_slash",
            "origin",
            json!("https://station-dev.agora.build/"),
        ),
        (
            "origin_default_port",
            "origin",
            json!("https://station-dev.agora.build:443"),
        ),
        (
            "origin_path",
            "origin",
            json!("https://station-dev.agora.build/v1"),
        ),
        (
            "origin_userinfo",
            "origin",
            json!("https://user@station-dev.agora.build"),
        ),
        (
            "origin_http",
            "origin",
            json!("http://station-dev.agora.build"),
        ),
        ("connection_zero", "connection", json!(0)),
        ("nonce_31_bytes", "nonce", json!(b64u(&[0u8; 31]))),
        ("lease_zero", "expires_at", json!(ISSUED)),
        ("lease_negative", "expires_at", json!(ISSUED - 1)),
        (
            "lease_over_30_seconds",
            "expires_at",
            json!(ISSUED + 30_001),
        ),
        ("issued_at_text", "issued_at", json!("1793264000000")),
        ("recovery_text", "recovery", json!("7")),
    ] {
        out.push(bad(label, text(&with(good.clone(), field, value))));
    }
    for (label, field, value) in [
        ("generation_number", "generation", json!(7)),
        ("generation_zero", "generation", json!("0")),
        ("generation_leading_zero", "generation", json!("07")),
        ("generation_plus", "generation", json!("+7")),
        ("generation_minus", "generation", json!("-7")),
        ("generation_space", "generation", json!("7 ")),
        (
            "generation_2_63",
            "generation",
            json!("9223372036854775808"),
        ),
        (
            "plan_id_v1",
            "plan_id",
            json!("5b7c9d1e-2f3a-1b5c-8d6e-7f8091a2b3c4"),
        ),
        ("plan_id_upper_case", "plan_id", json!(PLAN.to_uppercase())),
        ("candidate_feed_id_empty", "candidate_feed_id", json!("")),
        (
            "source_hash_upper_case",
            "source_hash",
            json!("5A".repeat(32)),
        ),
        (
            "evidence_hash_33_bytes",
            "evidence_hash",
            json!("e7".repeat(33)),
        ),
    ] {
        out.push(bad(label, recovery_with(field, value)));
    }
    out.push(bad(
        "unsafe_connection",
        compact.replacen(r#""connection":3"#, r#""connection":9007199254740992"#, 1),
    ));
    out.push(bad(
        "fraction",
        compact.replacen(r#""connection":3"#, r#""connection":3.0"#, 1),
    ));
    out
}

/// A builder case: its inputs and the refusal's code, if refused.
#[derive(Clone)]
struct BuildCase {
    label: &'static str,
    note: &'static str,
    chain: &'static [&'static str],
    freeze: Option<&'static str>,
    challenge: Value,
    signer: &'static str,
    slot: &'static str,
    station: &'static str,
    journal: Journal,
    now_ms: u64,
    code: Option<&'static str>,
}

impl Gen {
    fn build_cases(&self) -> Vec<BuildCase> {
        let phone = challenge(PHONE, SLOT, 3);
        let plan = self.plan_journal();
        let case = |label, note, signer, slot, station, code| BuildCase {
            label,
            note,
            chain: NO_CHAIN,
            freeze: None,
            challenge: phone.clone(),
            signer,
            slot,
            station,
            journal: plan.clone(),
            now_ms: NOW,
            code,
        };
        let mut out = vec![
            case(
                "native",
                "dev-phone answers its challenge with the plan's journal: three records, one draft",
                PHONE,
                SLOT,
                STATION,
                None,
            ),
            case(
                "station_normalized",
                "the configured Station as written, normalized to the challenge's origin",
                PHONE,
                SLOT,
                "https://Station-Dev.agora.build/",
                None,
            ),
            case(
                "another_station",
                "a challenge minted for another Station than the configured one",
                PHONE,
                SLOT,
                OTHER_STATION,
                Some("origin_mismatch"),
            ),
            case(
                "another_port",
                "the configured Station on another port",
                PHONE,
                SLOT,
                "https://station-dev.agora.build:8443",
                Some("origin_mismatch"),
            ),
            case(
                "station_not_an_origin",
                "a configured Station normalize_relay refuses",
                PHONE,
                SLOT,
                "ftp://station-dev.agora.build",
                Some("malformed"),
            ),
            case(
                "another_slot",
                "the challenge names astation-ios; the reporter's slot is astation-mac",
                PHONE,
                "astation-mac",
                STATION,
                Some("slot_mismatch"),
            ),
            case(
                "signer_service",
                "a service never reports its signing journal",
                "service:svc-discord",
                SLOT,
                STATION,
                Some("malformed"),
            ),
            case(
                "signer_host",
                "a host never reports",
                "host:host-a",
                SLOT,
                STATION,
                Some("malformed"),
            ),
            case(
                "slot_empty",
                "an empty slot",
                PHONE,
                "",
                STATION,
                Some("malformed"),
            ),
        ];
        let mut another_signer = case(
            "another_signer",
            "the challenge names dev-mac; the reporter is dev-phone",
            PHONE,
            SLOT,
            STATION,
            Some("signer_mismatch"),
        );
        another_signer.challenge = challenge(MAC, SLOT, 3);
        out.push(another_signer);
        let mut frozen = case(
            "frozen",
            "the reporter's list frozen by C6_mac",
            PHONE,
            SLOT,
            STATION,
            Some("frozen"),
        );
        frozen.freeze = Some("C6_mac");
        out.push(frozen);
        let mut removed = case(
            "removed_member",
            "dev-ipad, a manager removed by E6, answers a challenge for itself",
            "member:dev-ipad",
            SLOT,
            STATION,
            Some("unknown_signer"),
        );
        removed.challenge = challenge("member:dev-ipad", SLOT, 3);
        out.push(removed);
        let mut never = case(
            "not_a_manager",
            "dev-desk (L + SR7_add_desk), a current native member that never held manage",
            DESK,
            SLOT,
            STATION,
            Some("not_a_manager"),
        );
        never.chain = DESK_ADDED;
        never.challenge = challenge(DESK, SLOT, 2);
        never.journal = self.journal(JOURNAL_ID, 7, 0, &[], &[]);
        out.push(never);
        let mut expired = case(
            "challenge_expired",
            "the challenge at its expires_at on the reporter's clock",
            PHONE,
            SLOT,
            STATION,
            Some("expired"),
        );
        expired.now_ms = EXPIRES;
        out.push(expired);
        // Who never reports: the subject of a recovery still waiting, a
        // service named as a member, a device never added.
        let mut waiting = case(
            "pending_recovery_subject",
            "dev-newmac at L + SR7_recovery_add_newmac, the subject of a recovery still waiting, answers a challenge for itself",
            NEWMAC,
            SLOT,
            STATION,
            Some("unknown_signer"),
        );
        waiting.chain = RECOVERING;
        waiting.challenge = challenge(NEWMAC, SLOT, 1);
        waiting.journal = self.journal(JOURNAL_ID, 7, 0, &[], &[]);
        out.push(waiting);
        for (label, note, signer) in [
            (
                "service_as_member",
                "member:svc-discord: a service named as a native member",
                "member:svc-discord",
            ),
            (
                "unknown_member",
                "member:dev-evil, never a member",
                "member:dev-evil",
            ),
        ] {
            let mut c = case(label, note, signer, SLOT, STATION, Some("unknown_signer"));
            c.challenge = challenge(signer, SLOT, 1);
            c.journal = self.journal(JOURNAL_ID, 4, 0, &[], &[]);
            out.push(c);
        }
        let mut recovered = case(
            "recovered_manager",
            "dev-newmac, added by the Recovery Kit with manage, once its recovery took effect (L + SR7_recovery_add_newmac + SR8_recovery_approve_newmac)",
            NEWMAC,
            SLOT,
            STATION,
            None,
        );
        recovered.chain = RECOVERED;
        recovered.challenge = challenge(NEWMAC, SLOT, 1);
        recovered.journal = self.journal(JOURNAL_ID, 8, 1, &["newmac_revoke"], &[]);
        out.push(recovered);
        let mut zero = case(
            "zero_records",
            "a journal that holds nothing of the plan",
            PHONE,
            SLOT,
            STATION,
            None,
        );
        zero.journal = self.journal(JOURNAL_ID, 4, 0, &[], &[]);
        out.push(zero);
        let mut reinstalled = case(
            "reinstalled_journal",
            "another journal id, a later since",
            PHONE,
            SLOT,
            STATION,
            None,
        );
        reinstalled.journal = self.journal(REINSTALLED_ID, 6, 1, &["phone_revoke"], &[]);
        out.push(reinstalled);
        let mut demoted = case(
            "demoted_manager",
            "dev-phone after its roles changed to [view] (L + SR7_set_roles_phone)",
            PHONE,
            SLOT,
            STATION,
            None,
        );
        demoted.chain = DEMOTED;
        demoted.journal = self.journal(JOURNAL_ID, 4, 3, &["phone_revoke"], &[]);
        out.push(demoted);
        let mut desk = case(
            "ed25519_manager",
            "dev-desk (Ed25519) once a manager (L + SR7_add_desk + SR8_desk_manages)",
            DESK,
            SLOT,
            STATION,
            None,
        );
        desk.chain = DESK_MANAGES;
        desk.challenge = challenge(DESK, SLOT, 2);
        desk.journal = self.journal(JOURNAL_ID, 8, 2, &["desk_revoke"], &[]);
        out.push(desk);
        let mut spaced = case(
            "bodies_written_another_way",
            "the plan's journal with each body pretty-printed: each hashes as its jcs, the same body as native's",
            PHONE,
            SLOT,
            STATION,
            None,
        );
        let pretty = |texts: &[String]| -> Vec<String> {
            texts
                .iter()
                .map(|t| {
                    serde_json::to_string_pretty(&serde_json::from_str::<Value>(t).unwrap())
                        .unwrap()
                })
                .collect()
        };
        spaced.journal.records = pretty(&plan.records);
        spaced.journal.drafts = pretty(&plan.drafts);
        out.push(spaced);
        let mut both = case(
            "same_body_record_and_draft",
            "one body both as a record and as a draft: each set is read on its own",
            PHONE,
            SLOT,
            STATION,
            None,
        );
        both.journal = self.journal(JOURNAL_ID, 4, 2, &["phone_revoke"], &["phone_revoke"]);
        out.push(both);
        let mut since_zero = case(
            "journal_since_zero",
            "a journal whose since is 0 (a device-list seq is at least 1)",
            PHONE,
            SLOT,
            STATION,
            Some("malformed"),
        );
        since_zero.journal.since = 0;
        out.push(since_zero);
        // Each journal body that isn't one of the plan's records by this
        // member, as a record and as a draft.
        let good = self.rec("phone_revoke").body.clone();
        let text_of = |b: &ControlBody| jcs(&b.to_json()).unwrap();
        let edited = |f: &dyn Fn(&mut ControlBody)| {
            let mut b = good.clone();
            f(&mut b);
            text_of(&b)
        };
        let json_edited = |f: &dyn Fn(&mut Value)| {
            let mut b = good.to_json();
            f(&mut b);
            jcs(&b).unwrap()
        };
        let good_text = text_of(&good);
        let bodies: Vec<(&'static str, &'static str, String)> = vec![
            (
                "another_account",
                "a body of another account",
                edited(&|b| b.account_id = "acct-other".into()),
            ),
            (
                "another_genesis",
                "a body of another genesis (SUB1's)",
                edited(&|b| b.genesis_hash = self.v.hash("SUB1")),
            ),
            (
                "another_member",
                "a body dev-mac signs",
                edited(&|b| b.signer = ControlSigner::Member("dev-mac".into())),
            ),
            (
                "service_own_key",
                "a body the service's own key signs",
                edited(&|b| b.signer = ControlSigner::Principal),
            ),
            (
                "another_origin",
                "a service's stop naming another Station's origin",
                edited(&|b| {
                    b.feed = Some(ControlFeed {
                        origin: OTHER_STATION.into(),
                        feed_id: FEED.into(),
                    })
                }),
            ),
            (
                "cover",
                "a cover (a native manager never signs one)",
                edited(&|b| b.action = ControlAction::Cover),
            ),
            (
                "hold",
                "a hold",
                edited(&|b| b.action = ControlAction::Hold),
            ),
            (
                "release",
                "a release",
                edited(&|b| b.action = ControlAction::Release),
            ),
            (
                "host_revoke",
                "a host principal's revoke (its only record is interrupt_running)",
                {
                    let mut b = self.rec("phone_host_interrupt").body.to_json();
                    b["action"] = json!("revoke");
                    jcs(&b).unwrap()
                },
            ),
            ("not_json", "not JSON", "{".to_owned()),
            ("array", "an array of the body", format!("[{good_text}]")),
            (
                "field_beyond",
                "a field beyond the body's",
                json_edited(&|b| b["note"] = json!("x")),
            ),
            (
                "null",
                "about.by null",
                json_edited(&|b| b["about"]["by"] = Value::Null),
            ),
            (
                "duplicate_key",
                "v twice",
                good_text.replacen(r#""v":1"#, r#""v":1,"v":1"#, 1),
            ),
            (
                "duplicate_key_escaped",
                "v twice, the second spelled with an escape",
                good_text.replacen(r#""v":1"#, r#""v":1,"\u0076":1"#, 1),
            ),
            (
                "another_type",
                "typed atem-verifier-report",
                json_edited(&|b| b["type"] = json!("atem-verifier-report")),
            ),
            (
                "signed_object",
                "the signed record rather than its body",
                self.record("phone_revoke"),
            ),
            (
                "fraction",
                "v 1.5",
                good_text.replacen(r#""v":1"#, r#""v":1.5"#, 1),
            ),
            (
                "over_4096_bytes",
                "an account_id of 4,096 bytes: the body's jcs over 4,096 bytes (no control-record body in its grammar reaches the bound)",
                edited(&|b| b.account_id = "a".repeat(4096)),
            ),
            (
                "text_over_16_kib",
                "the body's text with 16 KiB of whitespace before it: over the 16 KiB a body's text may take",
                format!("{}{good_text}", " ".repeat(16 * 1024)),
            ),
        ];
        for (name, note, body) in &bodies {
            for (set, label_prefix) in [("records", "record"), ("drafts", "draft")] {
                let mut c = case(
                    Box::leak(format!("{label_prefix}_{name}").into_boxed_str()),
                    Box::leak(format!("a {label_prefix}: {note}").into_boxed_str()),
                    PHONE,
                    SLOT,
                    STATION,
                    Some("malformed"),
                );
                c.journal = self.journal(JOURNAL_ID, 4, 1, &[], &[]);
                if set == "records" {
                    c.journal.records = vec![body.clone()];
                } else {
                    c.journal.drafts = vec![body.clone()];
                }
                out.push(c);
            }
        }
        let mut twice = case(
            "record_twice",
            "one body twice in the records",
            PHONE,
            SLOT,
            STATION,
            Some("malformed"),
        );
        twice.journal.records = vec![self.body("phone_revoke"), self.body("phone_revoke")];
        out.push(twice);
        let mut twice_spaced = case(
            "draft_twice_written_another_way",
            "one body twice in the drafts, once pretty-printed: the same jcs",
            PHONE,
            SLOT,
            STATION,
            Some("malformed"),
        );
        twice_spaced.journal.drafts = vec![
            self.body("phone_draft"),
            serde_json::to_string_pretty(&self.rec("phone_draft").body.to_json()).unwrap(),
        ];
        out.push(twice_spaced);
        out
    }

    /// The plan predicate's cases (`signer_report_plan_record`): dev-phone
    /// at this Station on L unless a case says otherwise.
    fn plan_cases(&self) -> Vec<PlanCase> {
        let good = self.rec("phone_revoke").body.clone();
        let edited = |f: &dyn Fn(&mut ControlBody)| {
            let mut b = good.clone();
            f(&mut b);
            jcs(&b.to_json()).unwrap()
        };
        let json_edited = |f: &dyn Fn(&mut Value)| {
            let mut b = good.to_json();
            f(&mut b);
            jcs(&b).unwrap()
        };
        let good_text = self.body("phone_revoke");
        let elsewhere = |b: &mut ControlBody| {
            b.feed = Some(ControlFeed {
                origin: OTHER_STATION.into(),
                feed_id: FEED.into(),
            })
        };
        let case = |label, note, body: String, want| PlanCase {
            label,
            note,
            chain: NO_CHAIN,
            freeze: None,
            member: PHONE,
            origin: STATION,
            body,
            want,
        };
        let in_plan = Ok(None);
        let out = |reason| Ok(Some(reason));
        let malformed = Err("malformed");
        let mut out_cases = vec![
            case(
                "service_revoke",
                "dev-phone's revoke of svc-discord with interrupt_running, at this Station",
                good_text.clone(),
                in_plan,
            ),
            case(
                "service_interrupt",
                "dev-phone's interrupt_running of svc-discord, at this Station",
                self.body("phone_interrupt"),
                in_plan,
            ),
            case(
                "service_revoke_draft",
                "dev-phone's revoke without interrupt_running, at this Station (a draft's body)",
                self.body("phone_draft"),
                in_plan,
            ),
            case(
                "host_interrupt",
                "dev-phone's interrupt_running of the host sender host-a: no origin",
                self.body("phone_host_interrupt"),
                in_plan,
            ),
            PlanCase {
                origin: OTHER_STATION,
                ..case(
                    "host_interrupt_at_another_origin",
                    "the same host sender's interrupt asked for another Station's plan: it names no origin, so it is every origin's",
                    self.body("phone_host_interrupt"),
                    in_plan,
                )
            },
            case(
                "body_written_another_way",
                "dev-phone's revoke pretty-printed: read as its jcs",
                serde_json::to_string_pretty(&good.to_json()).unwrap(),
                in_plan,
            ),
            PlanCase {
                chain: DESK_MANAGES,
                member: DESK,
                ..case(
                    "ed25519_manager",
                    "dev-desk's (Ed25519) revoke, asked for dev-desk (L + SR7_add_desk + SR8_desk_manages)",
                    self.body("desk_revoke"),
                    in_plan,
                )
            },
            PlanCase {
                chain: DEMOTED,
                ..case(
                    "demoted_manager",
                    "dev-phone's revoke after its roles changed to [view] (L + SR7_set_roles_phone): bodies only, the member's standing changes no answer",
                    good_text.clone(),
                    in_plan,
                )
            },
            PlanCase {
                freeze: Some("C6_mac"),
                ..case(
                    "frozen_list",
                    "dev-phone's revoke, the list frozen by C6_mac: bodies only, a freeze changes no answer (the builder refuses it, frozen)",
                    good_text.clone(),
                    in_plan,
                )
            },
            case(
                "another_origin",
                "dev-phone's revoke of svc-discord at another Station's origin: that Station's plan's",
                self.body("phone_elsewhere"),
                out("another_origin"),
            ),
            PlanCase {
                origin: OTHER_STATION,
                ..case(
                    "asked_at_another_origin",
                    "dev-phone's revoke at this Station, asked for another Station's plan",
                    good_text.clone(),
                    out("another_origin"),
                )
            },
            case(
                "another_member",
                "dev-mac's revoke, asked for dev-phone",
                self.body("mac_revoke"),
                out("another_signer"),
            ),
            PlanCase {
                member: MAC,
                ..case(
                    "asked_for_another_member",
                    "dev-phone's revoke, asked for dev-mac",
                    good_text.clone(),
                    out("another_signer"),
                )
            },
            case(
                "service_own_key",
                "svc-discord's own revoke (signer service:svc-discord): no member's record",
                edited(&|b| b.signer = ControlSigner::Principal),
                out("another_signer"),
            ),
            case(
                "station_cover",
                "the Station's cover of svc-discord, signed with its own key: another signer, judged before the action",
                edited(&|b| {
                    b.signer = ControlSigner::Principal;
                    b.action = ControlAction::Cover;
                }),
                out("another_signer"),
            ),
            case(
                "another_account",
                "dev-phone's revoke under another account_id",
                edited(&|b| b.account_id = "acct-other".into()),
                out("another_account"),
            ),
            case(
                "another_account_cover",
                "dev-phone's cover under another account_id: the account is judged first",
                edited(&|b| {
                    b.account_id = "acct-other".into();
                    b.action = ControlAction::Cover;
                }),
                out("another_account"),
            ),
            case(
                "another_genesis",
                "dev-phone's revoke under another genesis (SUB1's)",
                edited(&|b| b.genesis_hash = self.v.hash("SUB1")),
                out("another_genesis"),
            ),
            case(
                "cover",
                "dev-phone's cover of svc-discord: a native manager signs none, so its journal never holds one; refused, never skipped",
                edited(&|b| b.action = ControlAction::Cover),
                malformed,
            ),
            case(
                "hold",
                "dev-phone's hold of svc-discord",
                edited(&|b| b.action = ControlAction::Hold),
                malformed,
            ),
            case(
                "release",
                "dev-phone's release of svc-discord",
                edited(&|b| b.action = ControlAction::Release),
                malformed,
            ),
            case(
                "hold_at_another_origin",
                "dev-phone's hold at another Station's origin: the action is judged before the origin",
                edited(&|b| {
                    elsewhere(b);
                    b.action = ControlAction::Hold;
                }),
                malformed,
            ),
            case(
                "host_revoke",
                "a host principal's revoke: no control record (its only record is interrupt_running)",
                {
                    let mut b = self.rec("phone_host_interrupt").body.to_json();
                    b["action"] = json!("revoke");
                    jcs(&b).unwrap()
                },
                malformed,
            ),
            case("not_json", "not JSON", "{".to_owned(), malformed),
            case(
                "signed_object",
                "the signed record rather than its body",
                self.record("phone_revoke"),
                malformed,
            ),
            case(
                "field_beyond",
                "a field beyond the body's",
                json_edited(&|b| b["note"] = json!("x")),
                malformed,
            ),
            case(
                "duplicate_key",
                "v twice",
                good_text.replacen(r#""v":1"#, r#""v":1,"v":1"#, 1),
                malformed,
            ),
            case(
                "text_over_16_kib",
                "the body's text with 16 KiB of whitespace before it",
                format!("{}{good_text}", " ".repeat(16 * 1024)),
                malformed,
            ),
        ];
        for (label, note, member) in [
            (
                "member_a_service",
                "asked for service:svc-discord: a member is member:<id>",
                "service:svc-discord",
            ),
            ("member_a_host", "asked for host:host-a", "host:host-a"),
            (
                "member_without_prefix",
                "asked for dev-phone, without member:",
                "dev-phone",
            ),
        ] {
            out_cases.push(PlanCase {
                member,
                ..case(label, note, good_text.clone(), malformed)
            });
        }
        out_cases.push(PlanCase {
            origin: "https://Station-Dev.agora.build/",
            ..case(
                "origin_not_exact",
                "asked for this Station written another way: the origin is the challenge's, exactly as normalize_relay writes it",
                good_text.clone(),
                malformed,
            )
        });
        out_cases
    }

    fn request_cases(&self) -> Vec<RequestCase> {
        let builds = self.build_cases();
        let take = |label: &str| builds.iter().find(|c| c.label == label).unwrap().clone();
        vec![
            RequestCase {
                build: take("native"),
                key: "dev-phone/auth",
                finishes: vec![
                    ("held_by_its_signer", "dev-phone/auth", None, None),
                    (
                        "another_body",
                        "dev-phone/auth",
                        Some("astation-mac"),
                        Some("bad_signature"),
                    ),
                    (
                        "another_member",
                        "dev-mac/auth",
                        None,
                        Some("bad_signature"),
                    ),
                ],
            },
            RequestCase {
                build: take("ed25519_manager"),
                key: "dev-desk/auth",
                finishes: vec![
                    ("held_by_its_signer", "dev-desk/auth", None, None),
                    (
                        "another_body",
                        "dev-desk/auth",
                        Some("astation-mac"),
                        Some("bad_signature"),
                    ),
                    (
                        "another_member",
                        "dev-phone/auth",
                        None,
                        Some("bad_signature"),
                    ),
                ],
            },
        ]
    }
}

/// A plan-predicate case: the body judged for `member` at `origin` on L
/// followed by `chain` (then `freeze`), and the answer written here:
/// `Ok(None)` in the plan, `Ok(Some(reason))` not in it, `Err(code)`
/// refused.
struct PlanCase {
    label: &'static str,
    note: &'static str,
    chain: &'static [&'static str],
    freeze: Option<&'static str>,
    member: &'static str,
    origin: &'static str,
    body: String,
    want: Result<Option<&'static str>, &'static str>,
}

/// The immutable request: a builder case and its finishes `(label,
/// signed_with, other slot (None: the held body), code)`.
struct RequestCase {
    build: BuildCase,
    key: &'static str,
    finishes: Vec<(
        &'static str,
        &'static str,
        Option<&'static str>,
        Option<&'static str>,
    )>,
}

fn but_process(body: &Value) -> Value {
    let mut body = body.clone();
    body.as_object_mut().unwrap().remove("process");
    body
}

fn verified_json(v: &VerifiedSignerReport) -> Value {
    json!({
        "signer": v.signer,
        "slot": v.slot,
        "process": b64u(&v.process),
        "connection": v.connection,
        "head": v.head.to_json(),
        "at_head": v.at_head,
        "recovery": v.recovery.to_json(),
        "journal": v.journal.to_json(),
        "records": v.records.iter().map(|r| jcs(&r.object().to_json()).unwrap()).collect::<Vec<_>>(),
    })
}

fn opt(map: &mut Map<String, Value>, key: &str, value: Option<Value>) {
    if let Some(value) = value {
        map.insert(key.into(), value);
    }
}

/// The file: every case's outcome checked against the shared core.
fn signer_report_vectors() -> Value {
    let made = Gen::new();
    let challenges: Vec<Value> = challenge_cases()
        .into_iter()
        .map(|case| {
            let read = SignerReportChallenge::parse(case.text.as_bytes());
            match (&read, case.read) {
                (Ok(c), true) => {
                    json!({"label": case.label, "text": case.text, "fields": c.to_json()})
                }
                (Err(e), false) => {
                    json!({"label": case.label, "text": case.text, "code": e.code()})
                }
                _ => panic!("{}: {read:?}", case.label),
            }
        })
        .collect();
    let report = |case: Report| {
        let log = made.log(case.chain, case.freeze, case.now_ms);
        let got = verify_signer_report(
            &log,
            case.text.as_bytes(),
            &read_challenge(&case.challenge),
            &case.exported,
            case.now_ms,
        );
        let mut out = Map::new();
        out.insert("label".into(), json!(case.label));
        out.insert("note".into(), json!(case.note));
        out.insert("chain".into(), json!(case.chain));
        opt(&mut out, "freeze", case.freeze.map(|f| json!(f)));
        out.insert("challenge".into(), case.challenge.clone());
        out.insert("now_ms".into(), json!(case.now_ms));
        out.insert("report".into(), json!(case.text));
        out.insert("exported".into(), json!(case.exported));
        match (case.want, got) {
            (Want::Verified { at_head }, Ok(v)) => {
                assert_eq!(v.at_head, at_head, "{}", case.label);
                assert_eq!(v.process, *PROCESS);
                let object = SignedObject::parse(case.text.as_bytes()).unwrap();
                out.insert("jcs".into(), json!(object.jcs()));
                out.insert(
                    "signing_input_hex".into(),
                    json!(hex(object.signing_input().as_bytes())),
                );
                opt(&mut out, "signed_with", case.signed_with.map(|k| json!(k)));
                out.insert("expect".into(), verified_json(&v));
            }
            (Want::Code(code), Err(e)) => {
                assert_eq!(e.code(), code, "{}: {e}", case.label);
                out.insert("code".into(), json!(code));
            }
            (want, got) => panic!("{}: {want:?} written here, {got:?} given", case.label),
        }
        Value::Object(out)
    };
    let valid: Vec<Value> = made.valid().into_iter().map(report).collect();
    let invalid: Vec<Value> = made.invalid().into_iter().map(report).collect();
    let build = |case: &BuildCase| {
        let log = made.log(case.chain, case.freeze, case.now_ms);
        let got = signer_report_body(
            &log,
            &read_challenge(&case.challenge),
            case.signer,
            case.slot,
            case.station,
            &case.journal.view(),
            case.now_ms,
        );
        let mut out = Map::new();
        out.insert("label".into(), json!(case.label));
        out.insert("note".into(), json!(case.note));
        out.insert("chain".into(), json!(case.chain));
        opt(&mut out, "freeze", case.freeze.map(|f| json!(f)));
        out.insert("challenge".into(), case.challenge.clone());
        out.insert("signer".into(), json!(case.signer));
        out.insert("slot".into(), json!(case.slot));
        out.insert("station".into(), json!(case.station));
        out.insert("journal".into(), case.journal.to_json());
        out.insert("now_ms".into(), json!(case.now_ms));
        match (case.code, got) {
            (None, Ok(body)) => {
                let json = body.to_json();
                assert_eq!(json["process"], json!(b64u(&process_generation())));
                out.insert("body_but_process".into(), but_process(&json));
                (Value::Object(out), Some(body))
            }
            (Some(code), Err(e)) => {
                assert_eq!(e.code(), code, "{}: {e}", case.label);
                out.insert("code".into(), json!(code));
                (Value::Object(out), None)
            }
            (want, got) => panic!("{}: {want:?} written here, {got:?} given", case.label),
        }
    };
    let builds = made.build_cases();
    let builder: Vec<Value> = builds.iter().map(|c| build(c).0).collect();
    // Bodies written another way are the same body.
    let body_of = |label: &str| {
        builder.iter().find(|c| c["label"] == label).unwrap()["body_but_process"].clone()
    };
    assert_eq!(body_of("bodies_written_another_way"), body_of("native"));
    let request: Vec<Value> = made
        .request_cases()
        .into_iter()
        .map(|case| {
            let (mut out, body) = build(&case.build);
            let body = body.unwrap();
            let held = sign_signer_report(&made.keys, &KeyId::new(case.key), &body).unwrap();
            assert_eq!(held.jcs(), body.jcs());
            let finishes: Vec<Value> = case
                .finishes
                .iter()
                .map(|(label, key, other_slot, code)| {
                    let input = match other_slot {
                        None => body.signing_input(),
                        Some(slot) => {
                            let log = made.log(case.build.chain, None, case.build.now_ms);
                            let other = with(case.build.challenge.clone(), "slot", json!(slot));
                            signer_report_body(
                                &log,
                                &read_challenge(&other),
                                case.build.signer,
                                slot,
                                case.build.station,
                                &case.build.journal.view(),
                                case.build.now_ms,
                            )
                            .unwrap()
                            .signing_input()
                        }
                    };
                    let sig = sign(&made.keys, &KeyId::new(*key), &input).unwrap();
                    match (code, body.with_signature(&sig)) {
                        (None, Ok(report)) => {
                            let text = jcs(&report.to_json()).unwrap();
                            assert_eq!(
                                text,
                                format!(r#"{{"body":{},"sig":"{}"}}"#, body.jcs(), b64u(&sig))
                            );
                        }
                        (Some(code), Err(e)) => assert_eq!(e.code(), *code, "{label}"),
                        (want, got) => panic!("{label}: {want:?} written here, {got:?} given"),
                    }
                    let mut f = Map::new();
                    f.insert("label".into(), json!(label));
                    f.insert("signed_with".into(), json!(key));
                    f.insert(
                        "over".into(),
                        other_slot.map_or(json!("held"), |slot| json!({"slot": slot})),
                    );
                    opt(&mut f, "code", code.map(|c| json!(c)));
                    Value::Object(f)
                })
                .collect();
            out["key"] = json!(case.key);
            out["sign_request"] = json!({
                "purpose": "signer_report",
                "fresh_confirmation": true,
                "label": "atem-signer-report-v1",
            });
            out["finishes"] = json!(finishes);
            out
        })
        .collect();
    let plan_predicate: Vec<Value> = made
        .plan_cases()
        .into_iter()
        .map(|case| {
            let log = made.log(case.chain, case.freeze, NOW);
            let got = signer_report_plan_record(&log, &case.body, case.member, case.origin);
            let mut out = Map::new();
            out.insert("label".into(), json!(case.label));
            out.insert("note".into(), json!(case.note));
            out.insert("chain".into(), json!(case.chain));
            opt(&mut out, "freeze", case.freeze.map(|f| json!(f)));
            out.insert("now_ms".into(), json!(NOW));
            out.insert("member".into(), json!(case.member));
            out.insert("origin".into(), json!(case.origin));
            out.insert("body".into(), json!(case.body));
            match (case.want, got) {
                (Ok(None), Ok(PlanRecord::InPlan)) => {
                    out.insert("in_plan".into(), json!(true));
                }
                (Ok(Some(reason)), Ok(PlanRecord::NotInPlan(why))) if why.code() == reason => {
                    out.insert("in_plan".into(), json!(false));
                    out.insert("reason".into(), json!(reason));
                }
                (Err(code), Err(e)) if e.code() == code => {
                    out.insert("code".into(), json!(code));
                }
                (want, got) => panic!("{}: {want:?} written here, {got:?} given", case.label),
            }
            Value::Object(out)
        })
        .collect();
    json!({
        "name": FILE,
        "kind": "vectors",
        "requires": "r9",
        "note": NOTE,
        "entries": made.entries_json(),
        "plan_predicate": plan_predicate,
        "records": made.records_json(),
        "challenges": challenges,
        "valid": valid,
        "invalid": invalid,
        "builder": builder,
        "request": request,
    })
}

#[test]
#[ignore = "writes the signer-report vectors"]
fn write_signer_report_vectors() {
    let mut text = serde_json::to_string_pretty(&signer_report_vectors()).unwrap();
    text.push('\n');
    std::fs::write(fixtures_dir().join(format!("{FILE}.json")), text).unwrap();
}

#[test]
fn signer_report_file_is_what_the_generator_makes() {
    let file = load(FILE);
    assert_eq!(
        file.as_object().unwrap().keys().collect::<Vec<_>>(),
        [
            "builder",
            "challenges",
            "entries",
            "invalid",
            "kind",
            "name",
            "note",
            "plan_predicate",
            "records",
            "request",
            "requires",
            "valid"
        ]
    );
    assert_eq!(
        file,
        signer_report_vectors(),
        "regenerate with write_signer_report_vectors"
    );
}

/// L, then the file's `chain` entries, then `freeze`, at `now_ms`.
fn case_log(v: &Vectors, file: &Value, case: &Value) -> Membership {
    let chain: Vec<SignedObject> = case["chain"]
        .as_array()
        .unwrap()
        .iter()
        .map(|label| {
            let entry = file["entries"]
                .as_array()
                .unwrap()
                .iter()
                .find(|e| e["label"] == *label)
                .unwrap();
            SignedObject::from_strict(&strict(&entry["entry"])).unwrap()
        })
        .collect();
    log_of(
        v,
        &chain,
        case.get("freeze").and_then(Value::as_str),
        case["now_ms"].as_u64().unwrap(),
    )
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t.as_str().unwrap().to_owned())
        .collect()
}

/// Every case as the file says, read from the file: the records, the
/// challenges, the reports' verdicts, the builder's bodies and refusals.
/// The cases cover every verifier code and the builder's.
#[test]
fn signer_report_vectors_run_through_the_shared_core() {
    let (file, v, book) = (load(FILE), Vectors::load(), Book::load());
    for rec in file["records"].as_array().unwrap() {
        let label = rec["label"].as_str().unwrap();
        let object = SignedObject::from_strict(&strict(&rec["record"])).unwrap();
        assert_eq!(object.jcs(), rec["jcs"].as_str().unwrap(), "{label}");
        assert_eq!(&object.to_json()["body"], &rec["body"], "{label}");
        assert_eq!(
            Hash32::of(object.jcs().as_bytes()).to_hex(),
            rec["digest_hex"].as_str().unwrap(),
            "{label}"
        );
        object
            .verify(&book.public(rec["signed_with"].as_str().unwrap()))
            .unwrap();
    }
    for case in file["challenges"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let read = SignerReportChallenge::parse(case["text"].as_str().unwrap().as_bytes());
        match case.get("fields") {
            Some(fields) => assert_eq!(&read.unwrap().to_json(), fields, "{label}"),
            None => assert_eq!(
                read.map(|_| ()).map_err(|e| e.code()),
                Err("malformed"),
                "{label}"
            ),
        }
    }
    let mut codes = BTreeSet::new();
    for case in file["valid"]
        .as_array()
        .unwrap()
        .iter()
        .chain(file["invalid"].as_array().unwrap())
    {
        let label = case["label"].as_str().unwrap();
        let log = case_log(&v, &file, case);
        let got = verify_signer_report(
            &log,
            case["report"].as_str().unwrap().as_bytes(),
            &read_challenge(&case["challenge"]),
            &strings(&case["exported"]),
            case["now_ms"].as_u64().unwrap(),
        );
        match case.get("expect") {
            Some(expect) => {
                assert_eq!(&verified_json(&got.unwrap()), expect, "{label}");
                let object =
                    SignedObject::parse(case["report"].as_str().unwrap().as_bytes()).unwrap();
                assert_eq!(object.jcs(), case["jcs"].as_str().unwrap());
                assert_eq!(
                    hex(object.signing_input().as_bytes()),
                    case["signing_input_hex"].as_str().unwrap()
                );
                object
                    .verify(&book.public(case["signed_with"].as_str().unwrap()))
                    .unwrap();
            }
            None => {
                let code = case["code"].as_str().unwrap();
                assert_eq!(got.map(|_| ()).map_err(|e| e.code()), Err(code), "{label}");
                codes.insert(code.to_owned());
            }
        }
    }
    assert_eq!(
        codes,
        SIGNER_VERIFY_ORDER.iter().map(|c| c.to_string()).collect(),
        "every verifier code has a vector"
    );
    // The high-S report is a genuine malleation: its low-S twin verifies.
    let high = file["invalid"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["label"] == "high_s_signature")
        .unwrap();
    let low = with_high_s(high["report"].as_str().unwrap());
    let log = case_log(&v, &file, high);
    assert!(
        verify_signer_report(
            &log,
            low.as_bytes(),
            &read_challenge(&high["challenge"]),
            &strings(&high["exported"]),
            NOW
        )
        .is_ok(),
        "its low-S twin verifies"
    );
    let mut build_codes = BTreeSet::new();
    for case in file["builder"]
        .as_array()
        .unwrap()
        .iter()
        .chain(file["request"].as_array().unwrap())
    {
        let label = case["label"].as_str().unwrap();
        let log = case_log(&v, &file, case);
        let got = signer_report_body(
            &log,
            &read_challenge(&case["challenge"]),
            case["signer"].as_str().unwrap(),
            case["slot"].as_str().unwrap(),
            case["station"].as_str().unwrap(),
            &Journal::from_json(&case["journal"]),
            case["now_ms"].as_u64().unwrap(),
        );
        match case.get("body_but_process") {
            Some(want) => {
                let body = got.unwrap();
                assert_eq!(&but_process(&body.to_json()), want, "{label}");
                assert_eq!(body.process(), process_generation());
            }
            None => {
                let code = case["code"].as_str().unwrap();
                assert_eq!(got.map(|_| ()).map_err(|e| e.code()), Err(code), "{label}");
                build_codes.insert(code.to_owned());
            }
        }
    }
    for code in [
        "frozen",
        "origin_mismatch",
        "signer_mismatch",
        "slot_mismatch",
        "unknown_signer",
        "not_a_manager",
        "expired",
        "malformed",
    ] {
        assert!(build_codes.contains(code), "the builder's {code}");
    }
}

/// The request's finishes, read from the file: the held body takes only
/// its signer's signature over itself, and the report is that body with
/// the signature, byte for byte.
#[test]
fn the_immutable_request_takes_only_a_signature_over_its_held_body() {
    let (file, v) = (load(FILE), Vectors::load());
    let keys = Book::load().provider;
    for case in file["request"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        assert_eq!(
            case["sign_request"]["label"],
            SignLabel::SignerReport.as_str()
        );
        assert_eq!(case["sign_request"]["fresh_confirmation"], true);
        let log = case_log(&v, &file, case);
        let journal = Journal::from_json(&case["journal"]);
        let build = |challenge: &Value, slot: &str| {
            signer_report_body(
                &log,
                &read_challenge(challenge),
                case["signer"].as_str().unwrap(),
                slot,
                case["station"].as_str().unwrap(),
                &journal,
                case["now_ms"].as_u64().unwrap(),
            )
            .unwrap()
        };
        let held = build(&case["challenge"], case["slot"].as_str().unwrap());
        let mut finished = 0;
        for f in case["finishes"].as_array().unwrap() {
            let input = match f["over"].as_str() {
                Some("held") => held.signing_input(),
                _ => {
                    let slot = f["over"]["slot"].as_str().unwrap();
                    build(&with(case["challenge"].clone(), "slot", json!(slot)), slot)
                        .signing_input()
                }
            };
            let key = KeyId::new(f["signed_with"].as_str().unwrap());
            let sig = sign(&keys, &key, &input).unwrap();
            match f.get("code") {
                None => {
                    let report = held.with_signature(&sig).unwrap();
                    assert_eq!(
                        jcs(&report.to_json()).unwrap(),
                        format!(r#"{{"body":{},"sig":"{}"}}"#, held.jcs(), b64u(&sig))
                    );
                    finished += 1;
                }
                Some(code) => assert_eq!(
                    held.with_signature(&sig).map(|_| ()).map_err(|e| e.code()),
                    Err(code.as_str().unwrap()),
                    "{label}: {}",
                    f["label"]
                ),
            }
        }
        assert_eq!(finished, 1, "{label}");
    }
}

/// The plan predicate's cases, read from the file
/// (`signer_report_plan_record`, Astation's ask on #114 comment
/// 7093796254): each answer, every reason among them, and the builder's
/// agreement: a body the predicate puts in the plan is one the builder
/// takes in a journal set, as a record and as a draft, and nothing else is.
#[test]
fn plan_predicate_vectors_run_through_the_shared_core() {
    let (file, v) = (load(FILE), Vectors::load());
    let cases = file["plan_predicate"].as_array().unwrap();
    let mut reasons = BTreeSet::new();
    let (mut in_plan, mut refused, mut agreed) = (0, 0, 0);
    for case in cases {
        let label = case["label"].as_str().unwrap();
        let log = case_log(&v, &file, case);
        let (body, member, origin) = (
            case["body"].as_str().unwrap(),
            case["member"].as_str().unwrap(),
            case["origin"].as_str().unwrap(),
        );
        let got = signer_report_plan_record(&log, body, member, origin);
        match case.get("code") {
            Some(code) => {
                assert_eq!(
                    got.map(|_| ()).map_err(|e| e.code()),
                    Err(code.as_str().unwrap()),
                    "{label}"
                );
                refused += 1;
            }
            None => {
                let want = match case["in_plan"].as_bool().unwrap() {
                    true => {
                        assert!(case.get("reason").is_none(), "{label}");
                        in_plan += 1;
                        PlanRecord::InPlan
                    }
                    false => {
                        let reason = case["reason"].as_str().unwrap();
                        reasons.insert(reason.to_owned());
                        PlanRecord::NotInPlan(
                            *OutOfPlan::ALL
                                .iter()
                                .find(|r| r.code() == reason)
                                .unwrap_or_else(|| panic!("{label}: {reason}")),
                        )
                    }
                };
                assert_eq!(got, Ok(want), "{label}");
            }
        }
        // The builder, for a member that may report here (a challenge for
        // it at this origin, its list not frozen), takes the body in a set
        // exactly when the predicate puts it in the plan.
        let reporter = [PHONE, MAC, DESK].contains(&member) && case.get("freeze").is_none();
        if reporter && origin_is_exact(origin) {
            let challenge = with(challenge(member, SLOT, 3), "origin", json!(origin));
            let wanted = case.get("code").is_none() && case["in_plan"] == true;
            for (records, drafts) in [(vec![body], vec![]), (vec![], vec![body])] {
                let journal = JournalView {
                    id: *JOURNAL_ID,
                    since: 4,
                    revision: 1,
                    records: records.iter().map(|t| t.to_string()).collect(),
                    drafts: drafts.iter().map(|t| t.to_string()).collect(),
                };
                let built = signer_report_body(
                    &log,
                    &read_challenge(&challenge),
                    member,
                    SLOT,
                    origin,
                    &journal,
                    case["now_ms"].as_u64().unwrap(),
                );
                assert_eq!(built.is_ok(), wanted, "{label}: the builder agrees");
            }
            agreed += 1;
        }
    }
    assert_eq!(
        reasons,
        OutOfPlan::ALL.iter().map(|r| r.code().to_owned()).collect(),
        "every reason has a vector"
    );
    assert!(
        in_plan >= 5 && refused >= 5 && agreed >= 20,
        "{in_plan} {refused} {agreed}"
    );
}

/// An origin exactly as `normalize_relay` writes it.
fn origin_is_exact(origin: &str) -> bool {
    atem_client::station_route::normalize_relay(origin).as_deref() == Ok(origin)
}
