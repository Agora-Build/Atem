//! `designs/protocol/fixtures/r9-vectors-resigned-copy.json`: a current
//! native manager's re-signed copy of a stop that a removed or demoted
//! manager signed (`atem_client::control::check_resigned_copy`;
//! host-work-v1 §11.1 "A current manager's copy of a former manager's
//! stop", condition (c), agreed with Astation, Astation #114 comments
//! 7208700195 and 7209301522): each copy judged against its original on
//! log L of `r9-vectors-membership-log` and this file's `entries`, in the
//! function's order, every refusal and each field of the stop intent once;
//! and two snapshots the effect-only snapshot checker passes whose stop the
//! copy check refuses (`checker_passes`).
//!
//! `write_resigned_copy_vectors` (ignored) writes the file from
//! `resigned_copy_vectors`, which builds every case and checks each outcome
//! written here by hand against the shared core. The other tests read the
//! file: that it is what the generator makes now, and that every case comes
//! out as it says. `scripts/check-r9-vectors.py` checks the same file
//! independently; the FFI's `tests/resigned_copy.rs` and the Swift, Kotlin
//! and WASM suites run it through the bindings.
mod support;

use std::collections::{BTreeMap, BTreeSet};

use atem_client::canonical::jcs;
use atem_client::control::{
    COPY_CHECK_CODES, ControlAbout, ControlAction, ControlBody, ControlCheck, ControlFeed,
    ControlPrincipal, ControlRecord, ControlSigner, CopyFeed, CopyRefusal, ResignedCopy,
    SnapshotConsistency, SnapshotInput, VerifiedSigner, build_control, check_resigned_copy,
    check_snapshot_consistency, principal_key_of, verify_control,
};
use atem_client::encoding::hex;
use atem_client::membership::{Action, HostNow, Membership, Role, RolesChange, sign_entry};
use atem_client::{KeyId, KeyProvider, PublicKey, SignedObject, SoftwareKeys};
use serde_json::{Map, Value, json};
use support::{Book, Vectors, fixtures_dir, load, strict};

const FILE: &str = "r9-vectors-resigned-copy";

const NOTE: &str = "A current native manager's re-signed copy of a stop that a removed or demoted manager signed (host-work-v1 §11.1 \"A current manager's copy of a former manager's stop\", condition (c); agreed with Astation, Astation #114 comments 7208700195 and 7209301522): check_resigned_copy(list, original_json, copy_json, candidate_feed_id) (bindings check_resigned_copy, JS checkResignedCopy), one shared judgement so the Mac and the Station judge a copy alike. Pure: no clock, no storage. Records are control records (r9-vectors-host-work-control's form, wire {\"body\":{…},\"sig\"}, signing input enc([\"atem-host-work-control-v1\", jcs(body)])), each with `signed_with` (r9-vectors-keys' test key) and `checks`, verify_control's verdict on each of the file's chains (valid with the verified signer, member:<id> for a current manager or the principal for its own key; pending or refused with its reason). Device lists: log L of r9-vectors-membership-log followed by `chain` (labels of `entries`, signed by dev-mac on L but RC7_hs7_revoke, r9-vectors-membership-log's HS7_revoke byte for byte: host-a revoked at seq 7; RC7_demote_phone and RC8_demote_phone take manage from dev-phone, on L and on RC7_hs7_revoke), each verified at `now_ms`. dev-ipad is the manager E6 removed, dev-phone the one the RC entries demote, dev-mac the current manager that signs the copies. `cases`: check_resigned_copy on the case's list with `original_json`, `copy_json` (exact texts; `original` and `copy` name the file's records when they are) and `candidate_feed_id`: `expect` {original_record_id, copy_record_id, signer (the copy's, member:<id>), principal, action, feed: original | candidate, absent for a host principal's record, which names no feed}, or `code` with `detail` where it has one. The checks, in this order, the first that fails the answer: malformed (either object isn't a signed control record that reads strictly, a non-v4 record_id among them; a candidate_feed_id that isn't a UUID v4; detail which); not_a_stop (the original's action isn't revoke or interrupt_running: a cover, hold or release is never copied, the Station signs those anew with its own key); original_invalid (the original's signature doesn't verify under any auth_key its signer had in the list's history, at some seq: its signer may since have been removed or demoted; detail unknown_signer when the list records no key of it, host_key_signed for a host's own key, bad_signature); copy_invalid (the copy isn't valid at the list's head with a current native manager as its signer: detail verify_control's pending or refusal reason, or signed_by_principal for a record valid under the principal's own key); same_record_id (the copy's record_id is the original's); then the stop intent, field by field in the body's order, the first that differs the answer: intent_mismatch with that field as detail (account_id, genesis_hash, origin, principal, principal_key, action, interrupt_running, revoke_seq, about.integration_id, about.by), but a service's feed_id, which may be the original's (feed original) or candidate_feed_id (feed candidate), else feed_mismatch at its place (after origin). signer, record_id and issued_at may differ; origin never. The field order, the details, the frozen list's refusal (malformed, as the snapshot checker refuses one) and signed_by_principal are Atem's readings. What it says: the copy, by a current manager, carries exactly the original's stop intent, so it discharges the original's obligation; whether the original needs one, and the publication's other conditions (the copy in its author's final verified signer report, the final snapshot checked), are the Station's. `checker_passes`: two snapshots check_snapshot_consistency (r9-vectors-host-work-control's snapshot checker, its station-dev origin and candidate feed) finds consistent although their stop isn't a conforming copy of the removed manager's retained original: the checker is effect-only (stop_not_resigned fires only when the snapshot alone drops an effect of the original), and a conforming copy always keeps every effect, so the two never disagree the other way; the copy rule is the adapter's publication rule, built on check_resigned_copy. Each gives its snapshot inputs ({retained, snapshot, marks, covered, provisioned} by record label) with the checker's `expect`, and the copy check's `code` and `detail` for (original, copy).";

const ORIGIN: &str = "https://station-dev.agora.build";
/// The old feed the originals name (the control vectors' `A`).
const FEED: &str = "6f1c2b3a-4d5e-4f60-8a7b-9c0d1e2f3a4b";
/// The replacement feed (the control vectors' `A2`).
const CANDIDATE: &str = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d";
/// A third feed of the same origin.
const THIRD_FEED: &str = "3c4d5e6f-7a8b-4c9d-8e0f-1a2b3c4d5e6f";
/// Another Station's feed (the control vectors' `B`).
const OTHER_ORIGIN: &str = "https://station-b.example.com";
const OTHER_FEED: &str = "1d2c3b4a-5f6e-4d7c-b8a9-0f1e2d3c4b5a";
const INTEGRATION: &str = "i-01jc5zq9x8w7v6t5s4r3q2p1n0";
const OTHER_INTEGRATION: &str = "i-01jc5zq9x8w7v6t5s4r3q2p1n9";
const SVC: &str = "service:svc-discord";
/// The lists' clock: after every entry.
const NOW: u64 = 1_793_620_850_000;
/// A removed manager's stop: signed while dev-ipad was a manager, before
/// E6 removed it.
const BEFORE_E6: u64 = 1_792_400_004_500;
/// A host principal's stop: after HS7_revoke, before dev-phone's demotion.
const AFTER_HS7: u64 = 1_793_620_807_500;
/// The copies, signed now.
const COPIED_AT: u64 = 1_793_620_900_000;

const L: &[&str] = &[];
const DEMOTED: &[&str] = &["RC7_demote_phone"];
const HOST: &[&str] = &["RC7_hs7_revoke"];
const HOST_DEMOTED: &[&str] = &["RC7_hs7_revoke", "RC8_demote_phone"];
const CHAINS: [&[&str]; 4] = [L, DEMOTED, HOST, HOST_DEMOTED];

fn record_id(n: u64) -> String {
    format!("00000000-0000-4000-8000-{n:012x}")
}

fn host_now() -> HostNow {
    HostNow {
        wall_ms: NOW,
        mono_ms: 1_000,
        boot_id: "boot-1".into(),
    }
}

/// L of `v`, then `chain`, verified at NOW.
fn log_of(v: &Vectors, chain: &[SignedObject]) -> Membership {
    let l = v.entries(&["E1", "E2", "E3", "E4", "E5", "E6"]);
    let mut log = Membership::verify_chain(support::ACCOUNT, &v.hash("E1"), &l, &host_now())
        .unwrap()
        .membership;
    if !chain.is_empty() {
        let eval = log.evaluate_objects(chain, &host_now());
        assert!(eval.stop.is_none(), "the chain applies: {:?}", eval.stop);
        log = eval.next;
    }
    log
}

/// A record of the file: its label, note, the test key that signed it, and
/// its wire text (jcs).
struct Rec {
    label: &'static str,
    note: &'static str,
    key: &'static str,
    text: String,
}

/// The expected answer, written here.
#[derive(Debug, Clone)]
enum Want {
    Copy { feed: Option<&'static str> },
    Code(&'static str, Option<&'static str>),
}

/// A case: the list, the two objects (record labels, or exact texts), the
/// candidate feed and the answer.
struct Case {
    label: &'static str,
    note: &'static str,
    chain: &'static [&'static str],
    original: Obj,
    copy: Obj,
    candidate: &'static str,
    want: Want,
}

#[derive(Clone)]
enum Obj {
    Rec(&'static str),
    Text(&'static str),
}

/// A snapshot the checker passes whose stop the copy check refuses.
struct Passes {
    label: &'static str,
    note: &'static str,
    original: &'static str,
    copy: &'static str,
    retained: &'static [&'static str],
    snapshot: &'static [&'static str],
    marks: &'static [(&'static str, u64)],
    code: &'static str,
    detail: &'static str,
}

struct Gen {
    v: Vectors,
    keys: SoftwareKeys,
    entries: Vec<(
        &'static str,
        &'static str,
        &'static [&'static str],
        SignedObject,
    )>,
    records: Vec<Rec>,
}

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
        let hs7 = made.v.object("HS7_revoke");
        made.entries.push((
            "RC7_hs7_revoke",
            "r9-vectors-membership-log's HS7_revoke (dev-mac's host_sender_revoke of host-a at seq 7, interrupt_running false) on E6, byte for byte",
            L,
            hs7,
        ));
        let demote = || Action::SetRoles {
            device_id: "dev-phone".into(),
            change: RolesChange::Native([Role::Control, Role::View].into_iter().collect()),
        };
        made.push(
            "RC7_demote_phone",
            "set_roles dev-phone to [control, view] on E6, by dev-mac: a manager demoted, still a current native member",
            L,
            1_792_400_006_000,
            demote(),
        );
        made.push(
            "RC8_demote_phone",
            "the same demotion on RC7_hs7_revoke: dev-phone demoted after it signed host-a's interrupt",
            HOST,
            1_793_620_808_000,
            demote(),
        );
        made.records = made.records();
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
        let log = self.log(on);
        let body = log.draft("dev-mac", at, &action);
        let entry = sign_entry(&self.keys, &KeyId::new("dev-mac/auth"), body).unwrap();
        self.entries.push((label, note, on, entry.object().clone()));
    }

    fn log(&self, chain: &[&str]) -> Membership {
        let objects: Vec<SignedObject> = chain
            .iter()
            .map(|label| {
                self.entries
                    .iter()
                    .find(|(l, _, _, _)| l == label)
                    .unwrap_or_else(|| panic!("no entry {label}"))
                    .3
                    .clone()
            })
            .collect();
        log_of(&self.v, &objects)
    }

    /// svc-discord's stop `n` by `signer` (`member:<id>`, or the service
    /// itself), at `feed` of `origin`, issued at `at`.
    #[allow(clippy::too_many_arguments)]
    fn svc(
        &self,
        n: u64,
        signer: &str,
        action: ControlAction,
        origin: &str,
        feed: &str,
        at: u64,
    ) -> ControlBody {
        ControlBody {
            account_id: support::ACCOUNT.into(),
            genesis_hash: self.v.hash("E1"),
            feed: Some(ControlFeed {
                origin: origin.into(),
                feed_id: feed.into(),
            }),
            principal: ControlPrincipal::Service("svc-discord".into()),
            principal_key: Some(principal_key_of(&self.public("svc-discord/auth")).unwrap()),
            signer: match signer.strip_prefix("member:") {
                Some(id) => ControlSigner::Member(id.into()),
                None => ControlSigner::Principal,
            },
            action,
            record_id: record_id(n),
            issued_at: at,
            about: ControlAbout {
                integration_id: Some(INTEGRATION.into()),
                by: "owner".into(),
            },
        }
    }

    /// `signer`'s interrupt_running `n` of host-a after the revoke at
    /// `revoke_seq`.
    fn host(&self, n: u64, signer: &str, revoke_seq: u64, at: u64) -> ControlBody {
        ControlBody {
            account_id: support::ACCOUNT.into(),
            genesis_hash: self.v.hash("E1"),
            feed: None,
            principal: ControlPrincipal::Host("host-a".into()),
            principal_key: None,
            signer: ControlSigner::Member(signer.strip_prefix("member:").unwrap().into()),
            action: ControlAction::InterruptRunning {
                revoke_seq: Some(revoke_seq),
            },
            record_id: record_id(n),
            issued_at: at,
            about: ControlAbout {
                integration_id: None,
                by: "owner".into(),
            },
        }
    }

    /// `body` signed by `key`: the record's text (jcs).
    fn signed(&self, key: &str, body: &ControlBody) -> String {
        let object = build_control(&self.keys, &KeyId::new(key), body).unwrap();
        jcs(&object.to_json()).unwrap()
    }

    /// `body` (any JSON) signed by `key` as a signed object, unchecked by
    /// the control parse.
    fn signed_raw(&self, key: &str, body: Value) -> String {
        let object = SignedObject::sign(&self.keys, &KeyId::new(key), body).unwrap();
        jcs(&object.to_json()).unwrap()
    }

    fn records(&self) -> Vec<Rec> {
        let revoke = |interrupt_running| ControlAction::Revoke { interrupt_running };
        let interrupt = ControlAction::InterruptRunning { revoke_seq: None };
        let ipad = "member:dev-ipad";
        let phone = "member:dev-phone";
        let o1 = self.svc(1, ipad, revoke(false), ORIGIN, FEED, BEFORE_E6);
        let o2 = self.svc(2, ipad, revoke(true), ORIGIN, FEED, BEFORE_E6 + 1);
        let o3 = self.svc(3, ipad, interrupt, ORIGIN, FEED, BEFORE_E6 + 2);
        let o4 = self.host(4, phone, 7, AFTER_HS7);
        let o5 = self.svc(5, phone, revoke(false), ORIGIN, FEED, BEFORE_E6 + 3);
        let edit = |base: &ControlBody, n: u64, f: &dyn Fn(&mut ControlBody)| {
            let mut b = base.clone();
            b.record_id = record_id(n);
            f(&mut b);
            b
        };
        let copy = |base: &ControlBody, n: u64, f: &dyn Fn(&mut ControlBody)| {
            let mut b = base.clone();
            b.signer = ControlSigner::Member("dev-mac".into());
            b.record_id = record_id(n);
            b.issued_at = COPIED_AT + n;
            f(&mut b);
            b
        };
        let to_feed = |origin: &'static str, feed: &'static str| {
            move |b: &mut ControlBody| {
                b.feed = Some(ControlFeed {
                    origin: origin.into(),
                    feed_id: feed.into(),
                })
            }
        };
        let keep = |_: &mut ControlBody| {};
        let r = |label, note, key, text: String| Rec {
            label,
            note,
            key,
            text,
        };
        let evil_key = principal_key_of(&self.public("dev-evil/auth")).unwrap();
        let mut out = vec![
            // ---- the originals: stops signed while their signer managed
            r(
                "O1_revoke",
                "dev-ipad's revoke of svc-discord (interrupt_running false) at station-dev's old feed, signed before E6 removed it",
                "dev-ipad/auth",
                self.signed("dev-ipad/auth", &o1),
            ),
            r(
                "O2_revoke_interrupt",
                "dev-ipad's revoke of svc-discord with interrupt_running, at the old feed",
                "dev-ipad/auth",
                self.signed("dev-ipad/auth", &o2),
            ),
            r(
                "O3_interrupt",
                "dev-ipad's interrupt_running of svc-discord, at the old feed",
                "dev-ipad/auth",
                self.signed("dev-ipad/auth", &o3),
            ),
            r(
                "O4_host_interrupt",
                "dev-phone's interrupt_running of host-a after its revoke at seq 7 (no origin, no feed), signed before RC8 demoted it",
                "dev-phone/auth",
                self.signed("dev-phone/auth", &o4),
            ),
            r(
                "O5_revoke_by_demoted",
                "dev-phone's revoke of svc-discord at the old feed (O1's intent), signed before RC7 demoted it",
                "dev-phone/auth",
                self.signed("dev-phone/auth", &o5),
            ),
            r(
                "O6_cover",
                "svc-discord's own cover at the old feed: never copied",
                "svc-discord/auth",
                self.signed(
                    "svc-discord/auth",
                    &self.svc(6, SVC, ControlAction::Cover, ORIGIN, FEED, BEFORE_E6),
                ),
            ),
            r(
                "O7_hold",
                "svc-discord's own hold at the old feed: never copied",
                "svc-discord/auth",
                self.signed(
                    "svc-discord/auth",
                    &self.svc(7, SVC, ControlAction::Hold, ORIGIN, FEED, BEFORE_E6),
                ),
            ),
            // ---- originals O1 or O4 but for one field, signed by its signer
            r(
                "X1_account",
                "O1 under another account_id (acct-other), signed by dev-ipad",
                "dev-ipad/auth",
                self.signed(
                    "dev-ipad/auth",
                    &edit(&o1, 11, &|b| b.account_id = "acct-other".into()),
                ),
            ),
            r(
                "X2_genesis",
                "O1 under another genesis_hash (SUB1's), signed by dev-ipad",
                "dev-ipad/auth",
                self.signed(
                    "dev-ipad/auth",
                    &edit(&o1, 12, &|b| b.genesis_hash = self.v.hash("SUB1")),
                ),
            ),
            r(
                "X3_principal",
                "O1 naming another principal, service:svc-other, signed by dev-ipad",
                "dev-ipad/auth",
                self.signed(
                    "dev-ipad/auth",
                    &edit(&o1, 13, &|b| {
                        b.principal = ControlPrincipal::Service("svc-other".into())
                    }),
                ),
            ),
            r(
                "X4_principal_key",
                "O1 naming another principal_key (the r9_svc of dev-evil's key), signed by dev-ipad",
                "dev-ipad/auth",
                self.signed(
                    "dev-ipad/auth",
                    &edit(&o1, 14, &|b| b.principal_key = Some(evil_key)),
                ),
            ),
            r(
                "X5_integration",
                "O1 with another about.integration_id, signed by dev-ipad",
                "dev-ipad/auth",
                self.signed(
                    "dev-ipad/auth",
                    &edit(&o1, 15, &|b| {
                        b.about.integration_id = Some(OTHER_INTEGRATION.into())
                    }),
                ),
            ),
            r(
                "X6_by",
                "O1 with about.by station, signed by dev-ipad",
                "dev-ipad/auth",
                self.signed(
                    "dev-ipad/auth",
                    &edit(&o1, 16, &|b| b.about.by = "station".into()),
                ),
            ),
            r(
                "X7_host_revoke_seq_12",
                "O4 for another revoke_seq (12), signed by dev-phone",
                "dev-phone/auth",
                self.signed(
                    "dev-phone/auth",
                    &edit(&o4, 17, &|b| {
                        b.action = ControlAction::InterruptRunning {
                            revoke_seq: Some(12),
                        }
                    }),
                ),
            ),
            // ---- originals that don't verify
            r(
                "B1_forged",
                "O1's body signed by dev-evil's key: no key dev-ipad had verifies it",
                "dev-evil/auth",
                self.signed("dev-evil/auth", &edit(&o1, 21, &keep)),
            ),
            r(
                "B2_unknown_signer",
                "O1 signed as member:dev-evil (never in the list), by dev-evil's key",
                "dev-evil/auth",
                self.signed(
                    "dev-evil/auth",
                    &edit(&o1, 22, &|b| {
                        b.signer = ControlSigner::Member("dev-evil".into())
                    }),
                ),
            ),
            r(
                "B3_host_key",
                "O4 signed as host-a itself, by its host_key: a host's own key signs no control record",
                "host-a/host_key",
                self.signed(
                    "host-a/host_key",
                    &edit(&o4, 23, &|b| b.signer = ControlSigner::Principal),
                ),
            ),
            // ---- dev-mac's copies, and copies by others
            r(
                "C1_revoke",
                "dev-mac's copy of O1 at the original's feed: the same intent, a new record_id",
                "dev-mac/auth",
                self.signed("dev-mac/auth", &copy(&o1, 31, &keep)),
            ),
            r(
                "C2_revoke_candidate",
                "dev-mac's copy of O1 naming the candidate feed",
                "dev-mac/auth",
                self.signed("dev-mac/auth", &copy(&o1, 32, &to_feed(ORIGIN, CANDIDATE))),
            ),
            r(
                "C3_revoke_interrupt",
                "dev-mac's copy of O2 (interrupt_running) naming the candidate feed",
                "dev-mac/auth",
                self.signed("dev-mac/auth", &copy(&o2, 33, &to_feed(ORIGIN, CANDIDATE))),
            ),
            r(
                "C4_interrupt",
                "dev-mac's copy of O3 at the original's feed",
                "dev-mac/auth",
                self.signed("dev-mac/auth", &copy(&o3, 34, &keep)),
            ),
            r(
                "C5_host_interrupt",
                "dev-mac's copy of O4 (host-a, revoke_seq 7)",
                "dev-mac/auth",
                self.signed("dev-mac/auth", &copy(&o4, 35, &keep)),
            ),
            r(
                "C6_revoke_other_origin",
                "dev-mac's revoke with O1's intent at another Station's origin",
                "dev-mac/auth",
                self.signed(
                    "dev-mac/auth",
                    &copy(&o1, 36, &to_feed(OTHER_ORIGIN, OTHER_FEED)),
                ),
            ),
            r(
                "C7_revoke_third_feed",
                "dev-mac's revoke with O1's intent at a third feed of station-dev: neither the original's nor the candidate",
                "dev-mac/auth",
                self.signed("dev-mac/auth", &copy(&o1, 37, &to_feed(ORIGIN, THIRD_FEED))),
            ),
            r(
                "C8_revoke_by_demoted",
                "dev-phone's copy of O1: valid on L, refused removed_manager once RC7 demoted it",
                "dev-phone/auth",
                self.signed(
                    "dev-phone/auth",
                    &copy(&o1, 38, &|b| {
                        b.signer = ControlSigner::Member("dev-phone".into())
                    }),
                ),
            ),
            r(
                "C9_revoke_by_service",
                "svc-discord's own revoke with O1's intent, signed anew for the candidate feed: valid, but by the principal's key, never a manager's copy",
                "svc-discord/auth",
                self.signed(
                    "svc-discord/auth",
                    &copy(&o1, 39, &|b| {
                        b.signer = ControlSigner::Principal;
                        to_feed(ORIGIN, CANDIDATE)(b);
                    }),
                ),
            ),
            r(
                "C10_same_record_id",
                "dev-mac's copy of O1 under O1's own record_id",
                "dev-mac/auth",
                self.signed(
                    "dev-mac/auth",
                    &copy(&o1, 40, &|b| b.record_id = record_id(1)),
                ),
            ),
            r(
                "C12_cover",
                "dev-mac's cover of svc-discord: a manager signs no cover",
                "dev-mac/auth",
                self.signed(
                    "dev-mac/auth",
                    &copy(&o1, 42, &|b| b.action = ControlAction::Cover),
                ),
            ),
            r(
                "C13_by_pending",
                "dev-newmac's copy of O1: not in L (signer_unknown)",
                "dev-newmac/auth",
                self.signed(
                    "dev-newmac/auth",
                    &copy(&o1, 43, &|b| {
                        b.signer = ControlSigner::Member("dev-newmac".into())
                    }),
                ),
            ),
            r(
                "C14_revoke_interrupt_reconciled",
                "dev-mac's revoke with O2's intent for the candidate feed, but about.by reconciled: every effect of O2, not its intent",
                "dev-mac/auth",
                self.signed(
                    "dev-mac/auth",
                    &copy(&o2, 44, &|b| {
                        to_feed(ORIGIN, CANDIDATE)(b);
                        b.about.by = "reconciled".into();
                    }),
                ),
            ),
        ];
        // A copy whose record_id isn't a UUID v4: a signed object the control
        // parse refuses.
        let mut non_v4 = copy(&o1, 41, &keep).to_json();
        non_v4["record_id"] = json!("00000000-0000-1000-8000-000000000029");
        out.push(r(
            "C11_record_id_not_v4",
            "dev-mac's copy of O1 whose record_id is a UUID v1: not a control record that reads",
            "dev-mac/auth",
            self.signed_raw("dev-mac/auth", non_v4),
        ));
        out
    }

    fn rec(&self, label: &str) -> &Rec {
        self.records
            .iter()
            .find(|r| r.label == label)
            .unwrap_or_else(|| panic!("no record {label}"))
    }

    fn text(&self, obj: &Obj) -> String {
        match obj {
            Obj::Rec(label) => self.rec(label).text.clone(),
            Obj::Text(text) => (*text).to_owned(),
        }
    }

    fn cases(&self) -> Vec<Case> {
        let ok = |feed| Want::Copy { feed };
        let code = |code, detail| Want::Code(code, detail);
        let c = |label, note, chain, original, copy, want| Case {
            label,
            note,
            chain,
            original: Obj::Rec(original),
            copy: Obj::Rec(copy),
            candidate: CANDIDATE,
            want,
        };
        let mismatch = |field| code("intent_mismatch", Some(field));
        vec![
            // ---- copies that discharge their original
            c(
                "service_revoke_original_feed",
                "a removed manager's revoke, dev-mac's copy naming the original's feed",
                L,
                "O1_revoke",
                "C1_revoke",
                ok(Some("original")),
            ),
            c(
                "service_revoke_candidate_feed",
                "the same, the copy naming the candidate feed (M8/M11's form)",
                L,
                "O1_revoke",
                "C2_revoke_candidate",
                ok(Some("candidate")),
            ),
            c(
                "revoke_with_interrupt_running",
                "a removed manager's revoke with interrupt_running, its copy for the candidate feed",
                L,
                "O2_revoke_interrupt",
                "C3_revoke_interrupt",
                ok(Some("candidate")),
            ),
            c(
                "service_interrupt_running",
                "a removed manager's interrupt_running of svc-discord, its copy at the original's feed",
                L,
                "O3_interrupt",
                "C4_interrupt",
                ok(Some("original")),
            ),
            c(
                "host_interrupt_running",
                "a demoted manager's interrupt_running of host-a (on HS7, then demoted), its copy: a host principal's record names no feed",
                HOST_DEMOTED,
                "O4_host_interrupt",
                "C5_host_interrupt",
                ok(None),
            ),
            c(
                "demoted_managers_revoke",
                "a demoted manager's revoke (dev-phone, RC7), dev-mac's copy of the same intent",
                DEMOTED,
                "O5_revoke_by_demoted",
                "C1_revoke",
                ok(Some("original")),
            ),
            // ---- malformed
            Case {
                original: Obj::Text("{"),
                ..c(
                    "original_not_json",
                    "the original isn't JSON",
                    L,
                    "O1_revoke",
                    "C1_revoke",
                    code("malformed", Some("original")),
                )
            },
            Case {
                copy: Obj::Text(r#"{"body":{},"sig":"AA"}"#),
                ..c(
                    "copy_not_a_record",
                    "the copy is no control record",
                    L,
                    "O1_revoke",
                    "C1_revoke",
                    code("malformed", Some("copy")),
                )
            },
            c(
                "copy_record_id_not_v4",
                "the copy's record_id is a UUID v1: it doesn't read as a control record",
                L,
                "O1_revoke",
                "C11_record_id_not_v4",
                code("malformed", Some("copy")),
            ),
            Case {
                candidate: "feed-2",
                ..c(
                    "candidate_not_a_uuid",
                    "the candidate feed isn't a UUID v4",
                    L,
                    "O1_revoke",
                    "C2_revoke_candidate",
                    code("malformed", Some("candidate_feed_id")),
                )
            },
            // ---- not a stop
            c(
                "cover_never_copied",
                "the original is a cover: a cover, hold or release is never copied (the Station signs those anew)",
                L,
                "O6_cover",
                "C1_revoke",
                code("not_a_stop", None),
            ),
            c(
                "hold_never_copied",
                "the original is a hold",
                L,
                "O7_hold",
                "C1_revoke",
                code("not_a_stop", None),
            ),
            // ---- the original doesn't verify
            c(
                "original_forged",
                "the original's signature isn't dev-ipad's",
                L,
                "B1_forged",
                "C1_revoke",
                code("original_invalid", Some("bad_signature")),
            ),
            c(
                "original_by_an_unknown_member",
                "the original's signer was never in the list",
                L,
                "B2_unknown_signer",
                "C1_revoke",
                code("original_invalid", Some("unknown_signer")),
            ),
            c(
                "original_by_a_hosts_key",
                "the original is signed by host-a's own key",
                HOST,
                "B3_host_key",
                "C5_host_interrupt",
                code("original_invalid", Some("host_key_signed")),
            ),
            // ---- the copy isn't a current manager's valid stop
            c(
                "copy_by_a_demoted_manager",
                "dev-phone's copy once RC7 demoted it",
                DEMOTED,
                "O1_revoke",
                "C8_revoke_by_demoted",
                code("copy_invalid", Some("removed_manager")),
            ),
            c(
                "copy_by_a_removed_manager",
                "a removed manager's own stop as the copy",
                L,
                "O1_revoke",
                "O2_revoke_interrupt",
                code("copy_invalid", Some("removed_manager")),
            ),
            c(
                "copy_by_the_service_key",
                "svc-discord's own revoke signed anew: valid, but by the principal's key",
                L,
                "O1_revoke",
                "C9_revoke_by_service",
                code("copy_invalid", Some("signed_by_principal")),
            ),
            c(
                "copy_a_cover",
                "a manager's cover as the copy",
                L,
                "O1_revoke",
                "C12_cover",
                code("copy_invalid", Some("signer_not_allowed")),
            ),
            c(
                "copy_by_a_member_not_yet_in_the_list",
                "dev-newmac's copy on L",
                L,
                "O1_revoke",
                "C13_by_pending",
                code("copy_invalid", Some("signer_unknown")),
            ),
            c(
                "host_copy_before_its_revoke",
                "the host principal's copy on L, before the list holds its revoke at seq 7",
                L,
                "O4_host_interrupt",
                "C5_host_interrupt",
                code("copy_invalid", Some("revoke_not_in_list")),
            ),
            // ---- the same record_id
            c(
                "same_record_id",
                "the copy under the original's record_id",
                L,
                "O1_revoke",
                "C10_same_record_id",
                code("same_record_id", None),
            ),
            // ---- the stop intent, field by field
            c(
                "account_id_differs",
                "the original under another account",
                L,
                "X1_account",
                "C1_revoke",
                mismatch("account_id"),
            ),
            c(
                "genesis_hash_differs",
                "the original under another genesis",
                L,
                "X2_genesis",
                "C1_revoke",
                mismatch("genesis_hash"),
            ),
            c(
                "origin_differs",
                "the copy at another Station's origin: never substituted",
                L,
                "O1_revoke",
                "C6_revoke_other_origin",
                mismatch("origin"),
            ),
            c(
                "feed_id_a_third_feed",
                "the copy at a third feed of the origin: neither the original's nor the candidate",
                L,
                "O1_revoke",
                "C7_revoke_third_feed",
                code("feed_mismatch", None),
            ),
            c(
                "principal_differs",
                "the original names another principal",
                L,
                "X3_principal",
                "C1_revoke",
                mismatch("principal"),
            ),
            c(
                "principal_key_differs",
                "the original names another principal_key",
                L,
                "X4_principal_key",
                "C1_revoke",
                mismatch("principal_key"),
            ),
            c(
                "action_differs",
                "an interrupt_running original, a revoke copy",
                L,
                "O3_interrupt",
                "C1_revoke",
                mismatch("action"),
            ),
            c(
                "interrupt_running_differs",
                "a revoke with interrupt_running, its copy without",
                L,
                "O2_revoke_interrupt",
                "C1_revoke",
                mismatch("interrupt_running"),
            ),
            c(
                "revoke_seq_differs",
                "a host principal's interrupt for revoke_seq 12, the copy for 7",
                HOST,
                "X7_host_revoke_seq_12",
                "C5_host_interrupt",
                mismatch("revoke_seq"),
            ),
            c(
                "about_integration_id_differs",
                "the original names another integration",
                L,
                "X5_integration",
                "C1_revoke",
                mismatch("about.integration_id"),
            ),
            c(
                "about_by_differs",
                "the original's about.by is station",
                L,
                "X6_by",
                "C1_revoke",
                mismatch("about.by"),
            ),
            c(
                "host_stop_as_a_services",
                "a host principal's original, a service's copy: the forms differ first at origin",
                HOST,
                "O4_host_interrupt",
                "C1_revoke",
                mismatch("origin"),
            ),
        ]
    }

    fn passes(&self) -> Vec<Passes> {
        vec![
            Passes {
                label: "another_about",
                note: "a removed manager's revoke with interrupt_running retained, a current manager's revoke with interrupt_running for the candidate feed in the snapshot: the checker finds both effects kept (consistent); the copy check refuses it as a copy, its about.by not the original's",
                original: "O2_revoke_interrupt",
                copy: "C14_revoke_interrupt_reconciled",
                retained: &["O2_revoke_interrupt"],
                snapshot: &["C14_revoke_interrupt_reconciled"],
                marks: &[],
                code: "intent_mismatch",
                detail: "about.by",
            },
            Passes {
                label: "the_services_own_key",
                note: "a removed manager's revoke retained, svc-discord's own revoke signed anew for the candidate feed above its mark in the snapshot: the checker finds the revocation kept (consistent; D's item 1 ends its coverage); the copy check refuses it, no manager's copy",
                original: "O1_revoke",
                copy: "C9_revoke_by_service",
                retained: &["O1_revoke"],
                snapshot: &["C9_revoke_by_service"],
                marks: &[(SVC, COPIED_AT)],
                code: "copy_invalid",
                detail: "signed_by_principal",
            },
        ]
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

    /// verify_control's verdict of `rec` on each chain, as the control
    /// vectors write it.
    fn checks(&self, rec: &ControlRecord) -> Vec<Value> {
        CHAINS
            .iter()
            .map(|chain| {
                let mut v = json!({"chain": chain});
                match verify_control(rec, &self.log(chain)) {
                    ControlCheck::Valid(valid) => {
                        v["verdict"] = json!("valid");
                        v["signer"] = json!(match valid.signer {
                            VerifiedSigner::Manager { device_id } => format!("member:{device_id}"),
                            VerifiedSigner::Principal { .. } => rec.principal().name(),
                        });
                    }
                    ControlCheck::Pending(reason) => {
                        v["verdict"] = json!("pending");
                        v["reason"] = json!(reason.code());
                    }
                    ControlCheck::Refused(reason) => {
                        v["verdict"] = json!("refused");
                        v["reason"] = json!(reason.code());
                    }
                }
                v
            })
            .collect()
    }

    fn records_json(&self) -> Vec<Value> {
        self.records
            .iter()
            .map(|rec| {
                let mut out = json!({
                    "label": rec.label,
                    "note": rec.note,
                    "signed_with": rec.key,
                    "record": serde_json::from_str::<Value>(&rec.text).unwrap(),
                    "jcs": jcs(&serde_json::from_str::<Value>(&rec.text).unwrap()["body"]).unwrap(),
                });
                match ControlRecord::parse(rec.text.as_bytes()) {
                    Ok(parsed) => {
                        out["checks"] = json!(self.checks(&parsed));
                        out["signing_input_hex"] =
                            json!(hex(parsed.object().signing_input().as_bytes()));
                    }
                    Err(e) => out["parse_error"] = json!(e.code()),
                }
                out
            })
            .collect()
    }
}

fn copy_json(copy: &ResignedCopy) -> Value {
    let mut out = json!({
        "original_record_id": copy.original_record_id,
        "copy_record_id": copy.copy_record_id,
        "signer": copy.signer,
        "principal": copy.principal,
        "action": copy.action.name(),
    });
    if let Some(feed) = copy.feed {
        out["feed"] = json!(feed.code());
    }
    out
}

fn refusal_json(refusal: &CopyRefusal) -> Value {
    let mut out = json!({"code": refusal.code()});
    if let Some(detail) = refusal.detail() {
        out["detail"] = json!(detail);
    }
    out
}

/// The snapshot inputs of a `checker_passes` case, as records.
fn snapshot_of(made: &Gen, labels: &[&str]) -> Vec<ControlRecord> {
    labels
        .iter()
        .map(|l| ControlRecord::parse(made.rec(l).text.as_bytes()).unwrap())
        .collect()
}

/// The file: every case's outcome checked against the shared core.
fn resigned_copy_vectors() -> Value {
    let made = Gen::new();
    let cases: Vec<Value> = made
        .cases()
        .into_iter()
        .map(|case| {
            let (original, copy) = (made.text(&case.original), made.text(&case.copy));
            let log = made.log(case.chain);
            let got =
                check_resigned_copy(&log, original.as_bytes(), copy.as_bytes(), case.candidate);
            let mut out = Map::new();
            out.insert("label".into(), json!(case.label));
            out.insert("note".into(), json!(case.note));
            out.insert("chain".into(), json!(case.chain));
            out.insert("now_ms".into(), json!(NOW));
            if let Obj::Rec(label) = case.original {
                out.insert("original".into(), json!(label));
            }
            if let Obj::Rec(label) = case.copy {
                out.insert("copy".into(), json!(label));
            }
            out.insert("original_json".into(), json!(original));
            out.insert("copy_json".into(), json!(copy));
            out.insert("candidate_feed_id".into(), json!(case.candidate));
            match (case.want, got) {
                (Want::Copy { feed }, Ok(got)) => {
                    assert_eq!(got.feed.map(CopyFeed::code), feed, "{}", case.label);
                    assert_eq!(got.signer, "member:dev-mac", "{}", case.label);
                    out.insert("expect".into(), copy_json(&got));
                }
                (Want::Code(code, detail), Err(e)) => {
                    assert_eq!((e.code(), e.detail()), (code, detail), "{}", case.label);
                    out.insert("code".into(), json!(code));
                    if let Some(detail) = detail {
                        out.insert("detail".into(), json!(detail));
                    }
                }
                (want, got) => panic!("{}: {want:?} written here, {got:?} given", case.label),
            }
            Value::Object(out)
        })
        .collect();
    let passes: Vec<Value> = made
        .passes()
        .into_iter()
        .map(|p| {
            let log = made.log(L);
            let marks: BTreeMap<String, u64> =
                p.marks.iter().map(|(k, v)| ((*k).to_owned(), *v)).collect();
            let (covered, provisioned) = (BTreeSet::new(), BTreeSet::new());
            let answer = check_snapshot_consistency(&SnapshotInput {
                list: &log,
                origin: ORIGIN,
                candidate_feed_id: CANDIDATE,
                retained: &snapshot_of(&made, p.retained),
                snapshot: &snapshot_of(&made, p.snapshot),
                marks: &marks,
                covered: &covered,
                provisioned: &provisioned,
            })
            .unwrap();
            assert_eq!(answer, SnapshotConsistency::Consistent, "{}", p.label);
            let got = check_resigned_copy(
                &log,
                made.rec(p.original).text.as_bytes(),
                made.rec(p.copy).text.as_bytes(),
                CANDIDATE,
            );
            assert_eq!(
                got.as_ref().map_err(|e| (e.code(), e.detail())),
                Err((p.code, Some(p.detail))),
                "{}",
                p.label
            );
            let marks_json: Map<String, Value> =
                marks.iter().map(|(k, v)| (k.clone(), json!(v))).collect();
            json!({
                "label": p.label,
                "note": p.note,
                "chain": L,
                "now_ms": NOW,
                "original": p.original,
                "copy": p.copy,
                "candidate_feed_id": CANDIDATE,
                "code": p.code,
                "detail": p.detail,
                "snapshot": {
                    "origin": ORIGIN,
                    "candidate_feed_id": CANDIDATE,
                    "retained": p.retained,
                    "snapshot": p.snapshot,
                    "marks": marks_json,
                    "covered": [],
                    "provisioned": [],
                    "expect": {"consistent": true},
                },
            })
        })
        .collect();
    json!({
        "name": FILE,
        "kind": "vectors",
        "requires": "r9",
        "note": NOTE,
        "codes": COPY_CHECK_CODES,
        "entries": made.entries_json(),
        "records": made.records_json(),
        "cases": cases,
        "checker_passes": passes,
    })
}

#[test]
#[ignore = "writes the resigned-copy vectors"]
fn write_resigned_copy_vectors() {
    let mut text = serde_json::to_string_pretty(&resigned_copy_vectors()).unwrap();
    text.push('\n');
    std::fs::write(fixtures_dir().join(format!("{FILE}.json")), text).unwrap();
}

#[test]
fn resigned_copy_file_is_what_the_generator_makes() {
    let file = load(FILE);
    assert_eq!(
        file.as_object().unwrap().keys().collect::<Vec<_>>(),
        [
            "cases",
            "checker_passes",
            "codes",
            "entries",
            "kind",
            "name",
            "note",
            "records",
            "requires"
        ]
    );
    assert_eq!(
        file,
        resigned_copy_vectors(),
        "regenerate with write_resigned_copy_vectors"
    );
}

/// L, then the file's `chain` entries, at the case's `now_ms`.
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
    assert_eq!(case["now_ms"], NOW);
    log_of(v, &chain)
}

/// Every case as the file says, read from the file; every code among them,
/// and each field of the stop intent once.
#[test]
fn resigned_copy_vectors_run_through_the_shared_core() {
    let (file, v, book) = (load(FILE), Vectors::load(), Book::load());
    assert_eq!(
        file["codes"],
        json!([
            "malformed",
            "not_a_stop",
            "original_invalid",
            "copy_invalid",
            "same_record_id",
            "intent_mismatch",
            "feed_mismatch"
        ])
    );
    for rec in file["records"].as_array().unwrap() {
        let object = SignedObject::from_strict(&strict(&rec["record"])).unwrap();
        assert_eq!(object.jcs(), rec["jcs"].as_str().unwrap());
        object
            .verify(&book.public(rec["signed_with"].as_str().unwrap()))
            .unwrap();
    }
    let (mut codes, mut fields) = (BTreeSet::new(), BTreeSet::new());
    for case in file["cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let log = case_log(&v, &file, case);
        let got = check_resigned_copy(
            &log,
            case["original_json"].as_str().unwrap().as_bytes(),
            case["copy_json"].as_str().unwrap().as_bytes(),
            case["candidate_feed_id"].as_str().unwrap(),
        );
        match case.get("expect") {
            Some(expect) => assert_eq!(&copy_json(&got.unwrap()), expect, "{label}"),
            None => {
                let e = got.unwrap_err();
                assert_eq!(refusal_json(&e)["code"], case["code"], "{label}");
                assert_eq!(
                    e.detail(),
                    case.get("detail").and_then(Value::as_str),
                    "{label}"
                );
                codes.insert(e.code().to_owned());
                if e.code() == "intent_mismatch" {
                    fields.insert(e.detail().unwrap().to_owned());
                }
            }
        }
    }
    assert_eq!(
        codes,
        COPY_CHECK_CODES.iter().map(|c| c.to_string()).collect(),
        "every code has a vector"
    );
    assert_eq!(
        fields,
        [
            "about.by",
            "about.integration_id",
            "account_id",
            "action",
            "genesis_hash",
            "interrupt_running",
            "origin",
            "principal",
            "principal_key",
            "revoke_seq"
        ]
        .into_iter()
        .map(String::from)
        .collect(),
        "each field of the intent mismatched once"
    );
    // The snapshot checker passes what the copy check refuses.
    for p in file["checker_passes"].as_array().unwrap() {
        let label = p["label"].as_str().unwrap();
        let log = case_log(&v, &file, p);
        let rec = |l: &Value| {
            let text = file["records"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["label"] == *l)
                .unwrap()["record"]
                .to_string();
            ControlRecord::parse(text.as_bytes()).unwrap()
        };
        let snap = &p["snapshot"];
        let records = |key: &str| -> Vec<ControlRecord> {
            snap[key].as_array().unwrap().iter().map(rec).collect()
        };
        let marks: BTreeMap<String, u64> = snap["marks"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.as_u64().unwrap()))
            .collect();
        let answer = check_snapshot_consistency(&SnapshotInput {
            list: &log,
            origin: snap["origin"].as_str().unwrap(),
            candidate_feed_id: snap["candidate_feed_id"].as_str().unwrap(),
            retained: &records("retained"),
            snapshot: &records("snapshot"),
            marks: &marks,
            covered: &BTreeSet::new(),
            provisioned: &BTreeSet::new(),
        })
        .unwrap();
        assert_eq!(answer, SnapshotConsistency::Consistent, "{label}");
        let (original, copy) = (rec(&p["original"]), rec(&p["copy"]));
        let got = check_resigned_copy(
            &log,
            jcs(&original.object().to_json()).unwrap().as_bytes(),
            jcs(&copy.object().to_json()).unwrap().as_bytes(),
            p["candidate_feed_id"].as_str().unwrap(),
        )
        .unwrap_err();
        assert_eq!(
            (got.code(), got.detail()),
            (p["code"].as_str().unwrap(), p["detail"].as_str()),
            "{label}"
        );
    }
}

/// A conforming copy keeps every effect of its original: for each valid
/// case of the file, a snapshot carrying the copy alone keeps the removed
/// or demoted manager's retained original (no `stop_not_resigned`), the
/// direction in which the two checks never disagree.
#[test]
fn a_conforming_copy_satisfies_the_snapshot_checker() {
    let (file, v) = (load(FILE), Vectors::load());
    let mut checked = 0;
    for case in file["cases"].as_array().unwrap() {
        if case.get("expect").is_none() {
            continue;
        }
        let label = case["label"].as_str().unwrap();
        let log = case_log(&v, &file, case);
        let parse =
            |key: &str| ControlRecord::parse(case[key].as_str().unwrap().as_bytes()).unwrap();
        let (original, copy) = (parse("original_json"), parse("copy_json"));
        let answer = check_snapshot_consistency(&SnapshotInput {
            list: &log,
            origin: ORIGIN,
            candidate_feed_id: CANDIDATE,
            retained: &[original],
            snapshot: &[copy],
            marks: &BTreeMap::new(),
            covered: &BTreeSet::new(),
            provisioned: &BTreeSet::new(),
        })
        .unwrap();
        assert_eq!(answer, SnapshotConsistency::Consistent, "{label}");
        checked += 1;
    }
    assert_eq!(checked, 6);
}

/// The input's own grammar, beyond the file: a frozen list verifies
/// nothing new (R9.4), so it is refused `malformed` as the snapshot checker
/// refuses one; and the answer names the copy's signer and principal.
#[test]
fn a_frozen_list_judges_no_copy() {
    let (v, made) = (Vectors::load(), Gen::new());
    let frozen = log_of(&v, &[])
        .evaluate(&[strict(v.wire("C6_mac"))], &host_now())
        .next;
    assert!(frozen.frozen().is_some());
    let (o1, c1) = (made.rec("O1_revoke"), made.rec("C1_revoke"));
    assert_eq!(
        check_resigned_copy(&frozen, o1.text.as_bytes(), c1.text.as_bytes(), CANDIDATE)
            .map_err(|e| (e.code(), e.detail())),
        Err(("malformed", Some("list frozen")))
    );
    let got = check_resigned_copy(
        &log_of(&v, &[]),
        o1.text.as_bytes(),
        c1.text.as_bytes(),
        CANDIDATE,
    )
    .unwrap();
    assert_eq!(
        got,
        ResignedCopy {
            original_record_id: record_id(1),
            copy_record_id: record_id(31),
            signer: "member:dev-mac".into(),
            principal: SVC.into(),
            action: ControlAction::Revoke {
                interrupt_running: false
            },
            feed: Some(CopyFeed::Original),
        }
    );
}
