//! `designs/protocol/fixtures/r9-vectors-station-binding.json`: a native
//! manager's Station binding proof (`atem_client::station_binding`;
//! delegated host-work III.5 (b), Atem's answer on #120 comment 7207827118,
//! owner decision 2026-11-27: unbind needs the same proof): Astation's
//! three public examples verbatim (verify-only), challenges read strictly,
//! proofs verified against log L of `r9-vectors-membership-log` and this
//! file's `entries`, the builder's outcomes and the immutable request's
//! signatures.
//!
//! `write_station_binding_vectors` (ignored) writes the file from
//! `station_binding_vectors`, which builds every case and checks each
//! outcome written here by hand against the shared core. The other tests
//! read the file: that it is what the generator makes now, and that every
//! case comes out as it says. `scripts/check-r9-vectors.py` checks the same
//! file independently; the FFI's `tests/station_binding.rs` and the Swift,
//! Kotlin and WASM suites run it through the bindings.
mod support;

use std::collections::BTreeSet;

use atem_client::canonical::jcs;
use atem_client::domain::{SignLabel, SigningInput};
use atem_client::encoding::{b64u, b64u_decode, hex};
use atem_client::membership::{
    Action, HostNow, HostRecord, Member, MemberKind, Membership, Role, RolesChange, sign_entry,
};
use atem_client::provider::sign;
use atem_client::station_binding::{
    AuthClaims, BINDING_BUILD_ORDER, BINDING_VERIFY_ORDER, StationBindingChallenge,
    VerifiedStationBinding, sign_station_binding, station_binding_request, verify_station_binding,
};
use atem_client::{Alg, KeyId, KeyProvider, PublicKey, SignedObject, SoftwareKeys};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use support::{Book, Vectors, fixtures_dir, load, strict};

const FILE: &str = "r9-vectors-station-binding";

const NOTE: &str = "A native manager's Station binding proof (delegated host-work III.5 (b) \"Creating it\"; Atem's answer on #120 comment 7207827118, owner decision 2026-11-27: a voluntary unbind needs the same proof as a bind or a transfer; agreed by Auth/Portal, owner-approved, Portal #41 comment 7212286584: the current owner's valid Agora.Build session and a current manager's fresh, signed confirmation with action unbind, while D27's admin release and account deletion keep their separate rules): wire {\"body\":<the Station's challenge>,\"sig\"} (R9.1's signed object, no kit_sig), signed over enc([\"atem-station-binding-v1\", jcs(body)]) by a current native member holding manage at the head (signer member:<device_id>) with its auth_key, Ed25519 (verify_strict) or P-256/SHA-256 64-byte r||s with low S, under the alg the device list pins. The body is the challenge, exactly: {type: atem-station-binding, v: 1, action, origin, issuer, subject, auth_time, account_id, genesis_hash, head{seq, hash}, signer, expected_binding, nonce, issued_at, expires_at}; action bind, transfer or unbind; origin exact as station_route::normalize_relay writes it; issuer and subject the token's exact iss and sub, 1-256 bytes of printable ASCII (0x21-0x7E), compared byte for byte; auth_time the token's auth_time in Unix seconds, 0 to 2^53-1, with auth_time * 1000 <= issued_at; account_id 1-128 bytes of [A-Za-z0-9._:-]; genesis_hash and head.hash lowercase hex; head.seq 1 to 2^53-1; signer member:<id> only (id 1-128 bytes of [A-Za-z0-9._:-]): a service:, host: or browser: signer is malformed, unlike the reports' unknown_signer (Atem's reading of that grammar, agreed with Astation); expected_binding exactly {state: never_bound} or {state: bound | unbound | released, binding_id (1-128 bytes of [A-Za-z0-9._:-]), version (1 to 2^53-1), owner (the exact sub the record names, the issuer's grammar)}; nonce 32 bytes base64url without padding; issued_at and expires_at ms with 0 < expires_at - issued_at <= 30000. Per action: bind names never_bound, unbound or released; transfer names bound and subject != owner (subject the intended new owner); unbind names bound and subject = owner. Strict I-JSON, exact fields at every level, no null, no array, no duplicate key (escaped ones included); a challenge text at most 4,096 bytes, the body's jcs at most 4,096 bytes, the proof at most 16 KiB. Atem's proposals, agreed with Astation (Atem #210 comment 7209922243; #120 comments 7209926358 and 7208696433): owner is named in the unbound and released states too (they keep the last owner); the builder compares a transfer's subject, like every action's, with the subject the app supplies (its own login: the new owner, whose authenticated session makes a transfer request, Astation's answer on #120 comments 7210632733 and 7234537291); and both refusal orders below are those of Atem's answer (#120 comment 7207827118). Never fill expected from the challenge or anything the Station sent: it always comes from the app's own login, for a transfer too (else binding_mismatch can never fire); before it prompts, the app compares the challenge's action (and, for a transfer, expected_binding.owner) with what the user started. A first binding of a legacy room is a bind naming never_bound, its foreign room owners' consents the Station's, with no field added (Astation's reading, #120 7211915578, confirmed by Atem, #120 7234876387). `external`: Astation's three public examples (#120 comment 7205033056), verbatim, verify-only (no device list holds acct-example): each challenge reads, SHA-256(enc([\"atem-station-binding-v1\", jcs(challenge)])) is its signing_input_sha256, and its ed25519_sig and p256_sig verify under public_keys' ed25519 and p256 keys over that input (and over no other case's). Device lists: log L of r9-vectors-membership-log followed by `chain` (labels of `entries`, each with `on`, the labels it extends; signed by dev-mac but SB7_recovery_add_newmac, r9-vectors-membership-log's R7 byte for byte), then the carriage `freeze` (a label of r9-vectors-membership-log's others) when a case names one, which freezes it; each list verified at the case's now_ms. Keys are r9-vectors-keys' (`signed_with` names <name>/<part>: auth, or recovery/sign for the kit's recovery key); dev-desk is the Ed25519 manager SB7_add_desk adds; SB7_set_roles_phone demotes dev-phone to [control, view]. `challenges`: texts read by StationBindingChallenge::parse (bindings parse_station_binding_challenge): `fields` when read, else `code` malformed. `valid` and `invalid`: verify_station_binding(list, proof, the stored challenge `challenge`, now_ms): `expect` the VerifiedStationBinding {action, signer, head, at_head (true at the list's head, false at an ancestor), account_id, genesis_hash, issuer, subject, auth_time, expected_binding, nonce (base64url), expires_at}, with the proof's `jcs`, `signing_input_hex` and `signed_with`; or `code`, the first failure in the order malformed, frozen, wrong_account, unknown_signer, not_a_manager (no manage at the verifier's head), bad_signature, stale_log, fork, challenge_mismatch (the body isn't the stored challenge, compared on jcs), expired (bindings: Report{code}). The Station requires at_head. `builder`: station_binding_request(list, challenge, signer, station, expected{issuer, subject, auth_time}, now_ms): `body_json` (the held body, jcs(challenge)), or `code`, the first failure in the order malformed (signer not member:<id>, station not an origin, expected outside its grammar), frozen, wrong_account, origin_mismatch (the challenge minted for another Station than station normalized), signer_mismatch, unknown_signer, not_a_manager (no manage at the signer's own head), stale_log (the Station ahead of the signer: fetch first), fork, binding_mismatch (issuer, subject or auth_time other than expected), expired. `request`: the immutable request (bindings StationBindingRequest): built as a builder case, its sign_request (`purpose`, `fresh_confirmation`, `label`; input = enc([label, jcs(body)]), body_json = jcs(body)), then each `finishes` entry signs with `signed_with` the input of the held body (`over: held`) or of a request for the same challenge with another `nonce` (`over: {nonce}`), and finish gives the proof, byte-equal to {\"body\":<held body>,\"sig\":<the signature, low S>}, or `code`. What stays the Station's: the token's validation (aud = origin, iss, sub, exp, auth_time equal to the body's), the nonce store and single use, a transfer's consent, the disabled-account and binding_attempt rules, the commit-time recheck (head current, signer still manage, the record's state, binding_id and version equal to expected_binding) and exact retries.";

/// Where `external` comes from.
const EXTERNAL_SOURCE: &str = "Astation's three public examples (#120 comment 7205033056), verbatim: their challenges, input digests, both signatures and both public keys";

/// Astation's examples as posted (#120 comment 7205033056), byte for byte.
const EXTERNAL: &str = r#"{
  "cases": [
    {
      "challenge": {
        "account_id": "acct-example",
        "action": "bind",
        "auth_time": 1795700000,
        "expected_binding": {
          "state": "never_bound"
        },
        "expires_at": 1795700040000,
        "genesis_hash": "1111111111111111111111111111111111111111111111111111111111111111",
        "head": {
          "hash": "2222222222222222222222222222222222222222222222222222222222222222",
          "seq": 12
        },
        "issued_at": 1795700010000,
        "issuer": "https://auth.dev.agora.build",
        "nonce": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
        "origin": "https://station-dev.agora.build",
        "signer": "member:manager-example",
        "subject": "ab00000000000000000000000001",
        "type": "atem-station-binding",
        "v": 1
      },
      "ed25519_sig": "Dim15QhycnREa7wx2GeAmnECwVmSgR6bdeEz1R-vW_rorlx8zuclpGvtS7zgFNaAOSZ-dpVGDnw6UmhLivWuAQ",
      "p256_sig": "SnOhZK-dLbtzcyfDvXTQiXJYBs-UFU4WmtC4_c6mnvxFM5aIMoNEOfzX8yFGd4ZVWbR7XfeVitQVXxr0j_WPiw",
      "signing_input_sha256": "8f3be6fc65d1eee5539d83fa8574d3759431ba12701d6eff2239d2b20db83a1b"
    },
    {
      "challenge": {
        "account_id": "acct-example",
        "action": "transfer",
        "auth_time": 1795700000,
        "expected_binding": {
          "binding_id": "bind-example",
          "owner": "ab00000000000000000000000001",
          "state": "bound",
          "version": 1
        },
        "expires_at": 1795700040000,
        "genesis_hash": "1111111111111111111111111111111111111111111111111111111111111111",
        "head": {
          "hash": "2222222222222222222222222222222222222222222222222222222222222222",
          "seq": 12
        },
        "issued_at": 1795700010000,
        "issuer": "https://auth.dev.agora.build",
        "nonce": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI",
        "origin": "https://station-dev.agora.build",
        "signer": "member:manager-example",
        "subject": "ab00000000000000000000000002",
        "type": "atem-station-binding",
        "v": 1
      },
      "ed25519_sig": "hmHDmQMnEbYhZEXE8b8MEJ84pAdsGf71VkhuaiEYQcThoacXJfQ8zZkpQ_HUhZbcDQuReMb6IW5Mp-pWrtpBCQ",
      "p256_sig": "crwslwjyWS6caS2959IDvAh8ui28IUtKDfU1Jz3Mlo5ZkhrGviY-5rSRACQRuCRVsItbNpmAHdw3kzh_UTX39w",
      "signing_input_sha256": "2283ae75b1f09e7cf59aee851109284515d5b7514f19875b805ab4994926dc10"
    },
    {
      "challenge": {
        "account_id": "acct-example",
        "action": "unbind",
        "auth_time": 1795700000,
        "expected_binding": {
          "binding_id": "bind-example",
          "owner": "ab00000000000000000000000002",
          "state": "bound",
          "version": 2
        },
        "expires_at": 1795700040000,
        "genesis_hash": "1111111111111111111111111111111111111111111111111111111111111111",
        "head": {
          "hash": "2222222222222222222222222222222222222222222222222222222222222222",
          "seq": 12
        },
        "issued_at": 1795700010000,
        "issuer": "https://auth.dev.agora.build",
        "nonce": "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM",
        "origin": "https://station-dev.agora.build",
        "signer": "member:manager-example",
        "subject": "ab00000000000000000000000002",
        "type": "atem-station-binding",
        "v": 1
      },
      "ed25519_sig": "cHOhgFhDZMxB9YVKomCG830ptPROCtJbn-D0wh5EAff_GvBKjRyJrgk1akEQ01FGDx44vwaXg8Q591vgFhSGDA",
      "p256_sig": "Uo4Idt5BZ14DvbLmqWr7iUBZdpk1Pj8dvjoWgV6RZNQfQlOHvSXTecCJvkmF6ML6ajQulwt1n5qxyy2RFEiJAQ",
      "signing_input_sha256": "4915aef3d04a761044549e96d0bccc121585b0aa42a66bdd0016fab8dc562ba1"
    }
  ],
  "public_keys": [
    {
      "alg": "ed25519",
      "pub": "MfMyLUkj02xBwQm9sAmRkxh77ZmUIJbkkmokx379DS8"
    },
    {
      "alg": "p256",
      "pub": "BPoQnGV0ymJy099pdi4dqieIlj0PrwbnBNCsZKvTjwoDZUx_LH99qFfjYyE60NSf8qqF74ZJOv0IxavnFbWkRpc"
    }
  ]
}"#;

const STATION: &str = "https://station-dev.agora.build";
const OTHER_STATION: &str = "https://station.agora.build";
const ISSUER: &str = "https://auth.dev.agora.build";
/// The Agora.Build accounts the cases name (Auth `sub`s).
const OWNER_A: &str = "ab00000000000000000000000001";
const OWNER_B: &str = "ab00000000000000000000000002";
const OWNER_C: &str = "ab00000000000000000000000003";
const BINDING_ID: &str = "bind-0001";
const PHONE: &str = "member:dev-phone";
const MAC: &str = "member:dev-mac";
const DESK: &str = "member:dev-desk";
/// Every case's clock but the expiries': after L and its chain.
const NOW: u64 = 1_793_264_001_000;
const ISSUED: u64 = 1_793_264_000_000;
/// A full lease: 30 s.
const EXPIRES: u64 = ISSUED + 30_000;
/// The token's `auth_time` (seconds): ten minutes before the challenge.
const AUTH_TIME: u64 = ISSUED / 1000 - 600;

fn nonce(first: u8) -> [u8; 32] {
    std::array::from_fn(|i| first.wrapping_add(i as u8))
}

const NO_CHAIN: &[&str] = &[];
const DESK_ADDED: &[&str] = &["SB7_add_desk"];
const DESK_LATER: &[&str] = &["SB7_add_desk", "SB8_add_host_b"];
const DEMOTED: &[&str] = &["SB7_set_roles_phone"];
const RECOVERING: &[&str] = &["SB7_recovery_add_newmac"];

/// What the generator builds with: the book, log L and the chain's entries.
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
}

impl Gen {
    fn new() -> Gen {
        let v = Vectors::load();
        let keys = Book::load().provider;
        let mut made = Gen {
            v,
            keys,
            entries: Vec::new(),
        };
        let desk = Action::Add {
            member: Member {
                device_id: "dev-desk".into(),
                auth_key: made.public("dev-desk/auth"),
                kind: MemberKind::Native {
                    enc_key: made.public("dev-desk/enc"),
                    roles: [Role::Control, Role::Manage, Role::View]
                        .into_iter()
                        .collect(),
                },
            },
        };
        made.push(
            "SB7_add_desk",
            "add dev-desk, a native manager with an Ed25519 auth_key ([control, manage, view]), on E6, by dev-mac",
            NO_CHAIN,
            1_792_400_006_000,
            desk,
        );
        made.push(
            "SB8_add_host_b",
            "add_host host-b on SB7_add_desk, by dev-mac: a later head, no member changed",
            DESK_ADDED,
            1_792_400_007_000,
            Action::AddHost {
                host: HostRecord {
                    host_id: "host-b".into(),
                    host_trust_gen: 1,
                    host_key: made.public("host-b/host_key"),
                },
            },
        );
        made.push(
            "SB7_set_roles_phone",
            "set_roles dev-phone to [control, view] on E6, by dev-mac: a manager demoted, still a current native member",
            NO_CHAIN,
            1_792_400_006_000,
            Action::SetRoles {
                device_id: "dev-phone".into(),
                change: RolesChange::Native([Role::Control, Role::View].into_iter().collect()),
            },
        );
        // r9-vectors-membership-log's R7, byte for byte: the recovery key
        // adds dev-newmac, pending for 24 h on any list that carries it.
        let r7 = made.v.object("R7");
        made.entries.push((
            "SB7_recovery_add_newmac",
            "r9-vectors-membership-log's R7 (recovery_add of dev-newmac by the recovery key) on E6: dev-newmac is the subject of a recovery still waiting, no current member",
            NO_CHAIN,
            r7,
        ));
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

    /// L, then `chain`, then the carriage `freeze`, verified at `now_ms`.
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
}

fn host_now(now_ms: u64) -> HostNow {
    HostNow {
        wall_ms: now_ms,
        mono_ms: 1_000,
        boot_id: "boot-1".into(),
    }
}

/// L of `v`, then `chain`, then the carriage `freeze` (a label of the
/// membership-log vectors), verified at `now_ms`.
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

fn never_bound() -> Value {
    json!({"state": "never_bound"})
}

fn recorded(state: &str, version: u64, owner: &str) -> Value {
    json!({"state": state, "binding_id": BINDING_ID, "version": version, "owner": owner})
}

/// The challenge a Station mints at `log`'s head for `signer`, as an
/// object: the body the manager signs.
fn body(
    log: &Membership,
    signer: &str,
    action: &str,
    subject: &str,
    expected: Value,
    n: u8,
) -> Value {
    json!({
        "type": "atem-station-binding",
        "v": 1,
        "action": action,
        "origin": STATION,
        "issuer": ISSUER,
        "subject": subject,
        "auth_time": AUTH_TIME,
        "account_id": log.account_id(),
        "genesis_hash": log.genesis_hash().to_hex(),
        "head": log.head().to_json(),
        "signer": signer,
        "expected_binding": expected,
        "nonce": b64u(&nonce(n)),
        "issued_at": ISSUED,
        "expires_at": EXPIRES,
    })
}

/// `value` with the field at the dotted `path` set to `to`.
fn with(mut value: Value, path: &str, to: Value) -> Value {
    let mut at = &mut value;
    for part in path.split('.') {
        at = &mut at[part];
    }
    *at = to;
    value
}

/// `value` without the field at the dotted `path`.
fn without(mut value: Value, path: &str) -> Value {
    let (parent, last) = match path.rsplit_once('.') {
        Some((p, l)) => (Some(p), l),
        None => (None, path),
    };
    let mut at = &mut value;
    if let Some(parent) = parent {
        for part in parent.split('.') {
            at = &mut at[part];
        }
    }
    at.as_object_mut().unwrap().remove(last);
    value
}

fn read_challenge(value: &Value) -> StationBindingChallenge {
    StationBindingChallenge::parse(value.to_string().as_bytes())
        .unwrap_or_else(|e| panic!("{e}: {value}"))
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
    signed_as(keys, key, SignLabel::StationBinding, body)
}

/// `s` replaced by `n − s`: the other P-256 signature of the same input,
/// whose S is high.
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

/// What a case expects of the core.
#[derive(Debug, Clone)]
enum Want {
    /// A verified proof: whether at the list's head.
    Verified { at_head: bool },
    /// A refusal's code.
    Code(&'static str),
}

struct Proof {
    label: &'static str,
    note: &'static str,
    chain: &'static [&'static str],
    freeze: Option<&'static str>,
    challenge: Value,
    now_ms: u64,
    text: String,
    /// The key that signed it, for a valid case.
    signed_with: Option<&'static str>,
    want: Want,
}

fn proof(
    label: &'static str,
    note: &'static str,
    chain: &'static [&'static str],
    challenge: Value,
    text: String,
    want: Want,
) -> Proof {
    Proof {
        label,
        note,
        chain,
        freeze: None,
        challenge,
        now_ms: NOW,
        text,
        signed_with: None,
        want,
    }
}

impl Gen {
    /// The valid proofs: P-256 and Ed25519 managers, each action, at the
    /// head and at an ancestor.
    fn valid(&self) -> Vec<Proof> {
        let keys = &self.keys;
        let l = self.log(NO_CHAIN, None, NOW);
        let l7 = self.log(DESK_ADDED, None, NOW);
        // (signer, its key, whether it signs at L + SB7_add_desk (else at
        // L), the cases (label, note, the list it is verified at, at_head),
        // action, subject, expected_binding)
        type Row = (
            &'static str,
            &'static str,
            bool,
            Vec<(&'static str, &'static str, &'static [&'static str], bool)>,
            &'static str,
            &'static str,
            Value,
        );
        let rows: Vec<Row> = vec![
            (
                PHONE,
                "dev-phone/auth",
                false,
                vec![
                    (
                        "bind_p256_at_head",
                        "dev-phone (P-256) at L's head",
                        NO_CHAIN,
                        true,
                    ),
                    (
                        "bind_p256_at_ancestor",
                        "the same proof, verified at L + SB7_add_desk: signed at an ancestor",
                        DESK_ADDED,
                        false,
                    ),
                ],
                "bind",
                OWNER_A,
                never_bound(),
            ),
            (
                DESK,
                "dev-desk/auth",
                true,
                vec![
                    (
                        "bind_ed25519_at_head",
                        "dev-desk (Ed25519) at L + SB7_add_desk's head",
                        DESK_ADDED,
                        true,
                    ),
                    (
                        "bind_ed25519_at_ancestor",
                        "the same proof, verified at L + SB7_add_desk + SB8_add_host_b",
                        DESK_LATER,
                        false,
                    ),
                ],
                "bind",
                OWNER_A,
                never_bound(),
            ),
            (
                PHONE,
                "dev-phone/auth",
                false,
                vec![(
                    "rebind_after_unbound",
                    "a bind after an unbind, to another account: the prior record's id, state, version and owner named",
                    NO_CHAIN,
                    true,
                )],
                "bind",
                OWNER_B,
                recorded("unbound", 3, OWNER_A),
            ),
            (
                PHONE,
                "dev-phone/auth",
                false,
                vec![(
                    "rebind_same_owner_after_unbound",
                    "a bind after an unbind, to the account it unbound",
                    NO_CHAIN,
                    true,
                )],
                "bind",
                OWNER_A,
                recorded("unbound", 3, OWNER_A),
            ),
            (
                PHONE,
                "dev-phone/auth",
                false,
                vec![(
                    "rebind_after_released",
                    "a bind after an admin release (D27), to another account",
                    NO_CHAIN,
                    true,
                )],
                "bind",
                OWNER_B,
                recorded("released", 4, OWNER_A),
            ),
            (
                PHONE,
                "dev-phone/auth",
                false,
                vec![(
                    "transfer_p256",
                    "a transfer from OWNER_A to OWNER_B (subject the intended new owner), by dev-phone",
                    NO_CHAIN,
                    true,
                )],
                "transfer",
                OWNER_B,
                recorded("bound", 1, OWNER_A),
            ),
            (
                DESK,
                "dev-desk/auth",
                true,
                vec![(
                    "transfer_ed25519",
                    "the same transfer by dev-desk (Ed25519) at L + SB7_add_desk",
                    DESK_ADDED,
                    true,
                )],
                "transfer",
                OWNER_B,
                recorded("bound", 1, OWNER_A),
            ),
            (
                PHONE,
                "dev-phone/auth",
                false,
                vec![(
                    "unbind_p256",
                    "an unbind by its current owner (subject = owner), with a current manager's proof (owner decision 2026-11-27)",
                    NO_CHAIN,
                    true,
                )],
                "unbind",
                OWNER_B,
                recorded("bound", 2, OWNER_B),
            ),
            (
                DESK,
                "dev-desk/auth",
                true,
                vec![(
                    "unbind_ed25519",
                    "the same unbind by dev-desk (Ed25519) at L + SB7_add_desk",
                    DESK_ADDED,
                    true,
                )],
                "unbind",
                OWNER_B,
                recorded("bound", 2, OWNER_B),
            ),
            (
                MAC,
                "dev-mac/auth",
                false,
                vec![(
                    "bind_by_the_genesis_manager",
                    "dev-mac, the genesis manager (P-256), at L's head",
                    NO_CHAIN,
                    true,
                )],
                "bind",
                OWNER_A,
                never_bound(),
            ),
        ];
        let mut out = Vec::new();
        for (signer, key, on_desk, cases, action, subject, expected) in rows {
            let signing_log = if on_desk { &l7 } else { &l };
            let b = body(signing_log, signer, action, subject, expected, 0);
            let text = signed(keys, key, &b);
            for (label, note, chain, at_head) in cases {
                let mut case = proof(
                    label,
                    note,
                    chain,
                    b.clone(),
                    text.clone(),
                    Want::Verified { at_head },
                );
                case.signed_with = Some(key);
                out.push(case);
            }
        }
        // Boundaries: a 1 ms lease verified at issued_at, auth_time at
        // issued_at exactly, an earlier head on the chain, the longest
        // fields.
        let short = with(
            body(&l, PHONE, "bind", OWNER_A, never_bound(), 0),
            "expires_at",
            json!(ISSUED + 1),
        );
        let mut c = proof(
            "lease_of_one_millisecond",
            "issued_at + 1 = expires_at, verified at issued_at",
            NO_CHAIN,
            short.clone(),
            signed(keys, "dev-phone/auth", &short),
            Want::Verified { at_head: true },
        );
        c.now_ms = ISSUED;
        out.push(c);
        let same_second = with(
            body(&l, PHONE, "bind", OWNER_A, never_bound(), 0),
            "auth_time",
            json!(ISSUED / 1000),
        );
        out.push(proof(
            "auth_time_at_issued_at",
            "auth_time × 1000 = issued_at",
            NO_CHAIN,
            same_second.clone(),
            signed(keys, "dev-phone/auth", &same_second),
            Want::Verified { at_head: true },
        ));
        let earlier = with(
            body(&l, PHONE, "bind", OWNER_A, never_bound(), 0),
            "head",
            self.v.head("E5").to_json(),
        );
        out.push(proof(
            "earlier_head_on_the_chain",
            "a challenge at head seq 5 (E5), verified at L: at_head false",
            NO_CHAIN,
            earlier.clone(),
            signed(keys, "dev-phone/auth", &earlier),
            Want::Verified { at_head: false },
        ));
        let printable: String = (0..256).map(|i| (b'!' + (i % 94) as u8) as char).collect();
        let longest = with(
            with(
                with(
                    body(
                        &l,
                        PHONE,
                        "transfer",
                        &printable,
                        recorded("bound", 1, OWNER_A),
                        0,
                    ),
                    "issuer",
                    json!(printable.chars().rev().collect::<String>()),
                ),
                "expected_binding.binding_id",
                json!("b".repeat(128)),
            ),
            "expected_binding.version",
            json!(atem_client::canonical::MAX_SAFE_INTEGER),
        );
        out.push(proof(
            "longest_fields",
            "issuer and subject of 256 printable ASCII bytes (\\\" and \\\\ included), a binding_id of 128 bytes, version 2^53 - 1",
            NO_CHAIN,
            longest.clone(),
            signed(keys, "dev-phone/auth", &longest),
            Want::Verified { at_head: true },
        ));
        for case in out.iter_mut().filter(|c| c.signed_with.is_none()) {
            case.signed_with = Some("dev-phone/auth");
        }
        out
    }

    /// The proofs refused, malformed ones first, then in the verifier's
    /// order.
    fn invalid(&self) -> Vec<Proof> {
        let keys = &self.keys;
        let l = self.log(NO_CHAIN, None, NOW);
        let l7 = self.log(DESK_ADDED, None, NOW);
        let good = body(&l, PHONE, "bind", OWNER_A, never_bound(), 0);
        let good_text = signed(keys, "dev-phone/auth", &good);
        let transfer = body(
            &l,
            PHONE,
            "transfer",
            OWNER_B,
            recorded("bound", 1, OWNER_A),
            0,
        );
        let resign = |b: &Value| signed(keys, "dev-phone/auth", b);
        let m = |label, note, text: String| {
            proof(
                label,
                note,
                NO_CHAIN,
                good.clone(),
                text,
                Want::Code("malformed"),
            )
        };
        let in_body = |from: &str, to: &str| good_text.replacen(from, to, 1);
        let transfer_text = resign(&transfer);
        let mut out = vec![
            m(
                "duplicate_key_beside_body",
                "sig twice",
                good_text.replacen(r#","sig":"#, r#","sig":"AA","sig":"#, 1),
            ),
            m(
                "duplicate_key_in_body",
                "subject twice, the first another's",
                in_body(
                    r#""subject":"#,
                    r#""subject":"ab00000000000000000000000003","subject":"#,
                ),
            ),
            m(
                "duplicate_key_escaped",
                "subject twice, the first spelled with an escape",
                in_body(
                    r#""subject":"#,
                    r#""\u0073ubject":"ab00000000000000000000000003","subject":"#,
                ),
            ),
            m(
                "duplicate_key_in_head",
                "seq twice in head",
                in_body(r#""seq":"#, r#""seq":5,"seq":"#),
            ),
            m(
                "duplicate_key_in_expected_binding",
                "owner twice in expected_binding",
                transfer_text.replacen(
                    r#""owner":"#,
                    r#""owner":"ab00000000000000000000000003","owner":"#,
                    1,
                ),
            ),
            m(
                "unknown_field_beside_body",
                "a third field beside body and sig",
                good_text.replacen(r#"{"body":"#, r#"{"note":"x","body":"#, 1),
            ),
            m(
                "unknown_field_in_body",
                "the body with a field beyond its fifteen, signed",
                resign(&with(good.clone(), "note", json!("x"))),
            ),
            m(
                "unknown_field_in_head",
                "head with a field beyond seq and hash, signed",
                resign(&with(good.clone(), "head.note", json!("x"))),
            ),
            m(
                "unknown_field_in_expected_binding",
                "a bound record with a fifth field, signed",
                resign(&with(transfer.clone(), "expected_binding.note", json!("x"))),
            ),
            m(
                "null_subject",
                "subject null, signed",
                resign(&with(good.clone(), "subject", Value::Null)),
            ),
            m(
                "null_in_expected_binding",
                "a bound record's owner null, signed",
                resign(&with(
                    transfer.clone(),
                    "expected_binding.owner",
                    Value::Null,
                )),
            ),
            m(
                "missing_sig",
                "the body alone",
                format!(r#"{{"body":{}}}"#, jcs(&good).unwrap()),
            ),
            m(
                "kit_sig_beside_body",
                "a kit_sig beside a proof",
                good_text.replacen(r#"{"body":"#, r#"{"kit_sig":"AA","body":"#, 1),
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
            m(
                "body_over_4096_bytes",
                "an issuer of 4,000 bytes: the body's jcs over 4,096 bytes, refused before its grammar is read",
                resign(&with(good.clone(), "issuer", json!("i".repeat(4000)))),
            ),
            m(
                "fraction",
                "auth_time with a fraction (strict I-JSON: integers only)",
                in_body(
                    &format!(r#""auth_time":{AUTH_TIME}"#),
                    &format!(r#""auth_time":{AUTH_TIME}.5"#),
                ),
            ),
            m(
                "unsafe_integer",
                "a bound record's version 2^53, beyond the safe integers",
                transfer_text.replacen(r#""version":1"#, r#""version":9007199254740992"#, 1),
            ),
            m(
                "v_2",
                "v 2, signed",
                resign(&with(good.clone(), "v", json!(2))),
            ),
            m(
                "v_text",
                "v \"1\", signed",
                resign(&with(good.clone(), "v", json!("1"))),
            ),
            m(
                "type_of_another_kind",
                "the body typed atem-verifier-report and signed under its label",
                signed_as(
                    keys,
                    "dev-phone/auth",
                    SignLabel::VerifierReport,
                    &with(good.clone(), "type", json!("atem-verifier-report")),
                ),
            ),
            m(
                "unknown_type",
                "the body typed atem-station-binding-2",
                resign(&with(good.clone(), "type", json!("atem-station-binding-2"))),
            ),
        ];
        for field in [
            "type",
            "v",
            "action",
            "origin",
            "issuer",
            "subject",
            "auth_time",
            "account_id",
            "genesis_hash",
            "head",
            "signer",
            "expected_binding",
            "nonce",
            "issued_at",
            "expires_at",
        ] {
            out.push(m(
                Box::leak(format!("missing_{field}").into_boxed_str()),
                "the body without this field, signed",
                resign(&without(good.clone(), field)),
            ));
        }
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
                "a non-canonical origin, signed (the stored challenge is the canonical one)",
                resign(&with(good.clone(), "origin", json!(origin))),
            ));
        }
        let fields: Vec<(&'static str, &'static str, Value)> = vec![
            ("action_unknown", "action", json!("release")),
            ("action_upper_case", "action", json!("Bind")),
            ("issuer_empty", "issuer", json!("")),
            ("issuer_257_bytes", "issuer", json!("i".repeat(257))),
            (
                "issuer_space",
                "issuer",
                json!("https://auth dev.agora.build"),
            ),
            (
                "issuer_non_ascii",
                "issuer",
                json!("https://auth.dév.agora.build"),
            ),
            ("subject_empty", "subject", json!("")),
            ("subject_257_bytes", "subject", json!("s".repeat(257))),
            (
                "subject_space",
                "subject",
                json!("ab 0000000000000000000000001"),
            ),
            (
                "subject_tab",
                "subject",
                json!("ab\t0000000000000000000000001"),
            ),
            (
                "subject_del",
                "subject",
                json!("ab0000000000000000000000001\u{7f}"),
            ),
            (
                "subject_non_ascii",
                "subject",
                json!("ab000000000000000000000000é"),
            ),
            (
                "auth_time_after_issued_at",
                "auth_time",
                json!(ISSUED / 1000 + 1),
            ),
            ("auth_time_negative", "auth_time", json!(-1)),
            ("auth_time_text", "auth_time", json!(AUTH_TIME.to_string())),
            ("account_id_empty", "account_id", json!("")),
            ("account_id_129_bytes", "account_id", json!("a".repeat(129))),
            ("account_id_space", "account_id", json!("acct test-1")),
            ("account_id_slash", "account_id", json!("acct/test-1")),
            ("account_id_non_ascii", "account_id", json!("acct-tést-1")),
            (
                "genesis_hash_upper_case",
                "genesis_hash",
                json!(l.genesis_hash().to_hex().to_uppercase()),
            ),
            ("genesis_hash_short", "genesis_hash", json!("ab".repeat(31))),
            ("head_seq_zero", "head.seq", json!(0)),
            (
                "head_hash_upper_case",
                "head.hash",
                json!(l.head().hash.to_hex().to_uppercase()),
            ),
            ("signer_service", "signer", json!("service:svc-discord")),
            ("signer_host", "signer", json!("host:host-a")),
            ("signer_browser", "signer", json!("browser:grant-1")),
            ("signer_without_prefix", "signer", json!("dev-phone")),
            ("signer_empty_id", "signer", json!("member:")),
            ("signer_space", "signer", json!("member:dev phone")),
            ("nonce_31_bytes", "nonce", json!(b64u(&[0u8; 31]))),
            ("nonce_33_bytes", "nonce", json!(b64u(&[0u8; 33]))),
            (
                "nonce_padded",
                "nonce",
                json!(format!("{}=", b64u(&nonce(0)))),
            ),
            (
                "nonce_standard_base64",
                "nonce",
                json!("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh+/"),
            ),
            ("lease_zero", "expires_at", json!(ISSUED)),
            ("lease_negative", "expires_at", json!(ISSUED - 1)),
            (
                "lease_over_30_seconds",
                "expires_at",
                json!(ISSUED + 30_001),
            ),
            ("issued_at_negative", "issued_at", json!(-1)),
            (
                "expected_binding_not_an_object",
                "expected_binding",
                json!("never_bound"),
            ),
            ("expected_binding_empty", "expected_binding", json!({})),
            (
                "never_bound_with_a_record",
                "expected_binding",
                json!({"state": "never_bound", "binding_id": BINDING_ID}),
            ),
            (
                "state_unknown",
                "expected_binding",
                json!({"state": "pending", "binding_id": BINDING_ID, "version": 1, "owner": OWNER_B}),
            ),
            (
                "state_upper_case",
                "expected_binding",
                json!({"state": "Never_bound"}),
            ),
        ];
        for (label, path, value) in fields {
            out.push(m(
                label,
                "one field outside its grammar, signed",
                resign(&with(good.clone(), path, value)),
            ));
        }
        // A record's fields, on a transfer from OWNER_A to OWNER_B.
        let records: Vec<(&'static str, &'static str, Value)> = vec![
            ("bound_without_owner", "expected_binding.owner", Value::Null),
            (
                "bound_without_binding_id",
                "expected_binding.binding_id",
                Value::Null,
            ),
            (
                "bound_without_version",
                "expected_binding.version",
                Value::Null,
            ),
            ("binding_id_empty", "expected_binding.binding_id", json!("")),
            (
                "binding_id_129_bytes",
                "expected_binding.binding_id",
                json!("b".repeat(129)),
            ),
            (
                "binding_id_space",
                "expected_binding.binding_id",
                json!("bind 0001"),
            ),
            ("version_zero", "expected_binding.version", json!(0)),
            ("version_text", "expected_binding.version", json!("1")),
            ("owner_empty", "expected_binding.owner", json!("")),
            (
                "owner_257_bytes",
                "expected_binding.owner",
                json!("o".repeat(257)),
            ),
            (
                "owner_space",
                "expected_binding.owner",
                json!("ab 0000000000000000000000001"),
            ),
        ];
        for (label, path, value) in records {
            let changed = if value.is_null() {
                without(transfer.clone(), path)
            } else {
                with(transfer.clone(), path, value)
            };
            out.push(m(
                label,
                "a transfer's bound record with one field missing or outside its grammar, signed",
                resign(&changed),
            ));
        }
        // `owner` in every recorded state (Atem's proposal, agreed with
        // Astation, Atem #210 comment 7209922243): an unbound or released
        // record without it.
        for (label, state) in [
            ("unbound_without_owner", "unbound"),
            ("released_without_owner", "released"),
        ] {
            let b = body(&l, PHONE, "bind", OWNER_B, recorded(state, 3, OWNER_A), 0);
            out.push(m(
                label,
                "a rebind whose prior record names no owner (Atem's proposal, agreed with Astation: owner in every state but never_bound), signed",
                resign(&without(b, "expected_binding.owner")),
            ));
        }
        // The per-action rules.
        for (label, note, action, subject, expected) in [
            (
                "bind_of_a_bound_account",
                "a bind naming a bound record (a transfer moves it)",
                "bind",
                OWNER_B,
                recorded("bound", 1, OWNER_A),
            ),
            (
                "transfer_of_a_never_bound_account",
                "a transfer naming never_bound",
                "transfer",
                OWNER_B,
                never_bound(),
            ),
            (
                "transfer_of_an_unbound_account",
                "a transfer naming an unbound record",
                "transfer",
                OWNER_B,
                recorded("unbound", 1, OWNER_A),
            ),
            (
                "transfer_of_a_released_account",
                "a transfer naming a released record",
                "transfer",
                OWNER_B,
                recorded("released", 1, OWNER_A),
            ),
            (
                "transfer_to_the_current_owner",
                "a transfer whose subject is the record's owner",
                "transfer",
                OWNER_A,
                recorded("bound", 1, OWNER_A),
            ),
            (
                "unbind_of_a_never_bound_account",
                "an unbind naming never_bound",
                "unbind",
                OWNER_A,
                never_bound(),
            ),
            (
                "unbind_of_an_unbound_account",
                "an unbind naming an unbound record",
                "unbind",
                OWNER_A,
                recorded("unbound", 1, OWNER_A),
            ),
            (
                "unbind_of_a_released_account",
                "an unbind naming a released record",
                "unbind",
                OWNER_A,
                recorded("released", 1, OWNER_A),
            ),
            (
                "unbind_by_another_account",
                "an unbind whose subject isn't the record's owner",
                "unbind",
                OWNER_B,
                recorded("bound", 1, OWNER_A),
            ),
            (
                "unbind_owner_case_differs",
                "an unbind whose subject is the owner upper-cased: compared byte for byte",
                "unbind",
                "AB00000000000000000000000001",
                recorded("bound", 1, OWNER_A),
            ),
        ] {
            out.push(m(
                label,
                note,
                resign(&body(&l, PHONE, action, subject, expected, 0)),
            ));
        }

        // Refused after reading, in the verifier's order.
        let r = |label, note, text: String, code| {
            proof(label, note, NO_CHAIN, good.clone(), text, Want::Code(code))
        };
        let as_signer = |signer: &str, key: &str| {
            let b = with(good.clone(), "signer", json!(signer));
            (b.clone(), signed(keys, key, &b))
        };
        let mut frozen = r(
            "frozen",
            "a valid proof, the list frozen by C6_mac",
            good_text.clone(),
            "frozen",
        );
        frozen.freeze = Some("C6_mac");
        let mut frozen_other = r(
            "frozen_before_wrong_account",
            "another account's proof against a frozen list: frozen first",
            resign(&with(good.clone(), "account_id", json!("acct-other"))),
            "frozen",
        );
        frozen_other.freeze = Some("C6_mac");
        out.extend([
            frozen,
            frozen_other,
            r(
                "wrong_account",
                "account_id acct-other, signed",
                resign(&with(good.clone(), "account_id", json!("acct-other"))),
                "wrong_account",
            ),
            r(
                "wrong_genesis",
                "another genesis_hash (SUB1's), signed",
                resign(&with(
                    good.clone(),
                    "genesis_hash",
                    json!(self.v.hash("SUB1").to_hex()),
                )),
                "wrong_account",
            ),
        ]);
        for (label, note, signer, key) in [
            (
                "unknown_member",
                "member:dev-evil, never a member, with its own key",
                "member:dev-evil",
                "dev-evil/auth",
            ),
            (
                "removed_member",
                "member:dev-ipad, a manager removed by E6, with its own key",
                "member:dev-ipad",
                "dev-ipad/auth",
            ),
            (
                "recovery",
                "member:recovery, with the current kit's recovery key",
                "member:recovery",
                "recovery/sign",
            ),
            (
                "service_as_member",
                "member:svc-discord: a service named as a native member, with its own key",
                "member:svc-discord",
                "svc-discord/auth",
            ),
        ] {
            let (b, text) = as_signer(signer, key);
            let mut case = r(label, note, text, "unknown_signer");
            case.challenge = b;
            out.push(case);
        }
        let recovering = self.log(RECOVERING, None, NOW);
        let newmac = body(
            &recovering,
            "member:dev-newmac",
            "bind",
            OWNER_A,
            never_bound(),
            0,
        );
        out.push(proof(
            "pending_recovery_subject",
            "member:dev-newmac at L + SB7_recovery_add_newmac's head, with its own key: the subject of a recovery_add still waiting",
            RECOVERING,
            newmac.clone(),
            signed(keys, "dev-newmac/auth", &newmac),
            Want::Code("unknown_signer"),
        ));
        // A manager demoted after it signed, and one demoted before.
        out.push(proof(
            "demoted_manager",
            "dev-phone's valid proof at L, verified at L + SB7_set_roles_phone: no manage at the verifier's head",
            DEMOTED,
            good.clone(),
            good_text.clone(),
            Want::Code("not_a_manager"),
        ));
        let demoted = self.log(DEMOTED, None, NOW);
        let at_demoted = body(&demoted, PHONE, "bind", OWNER_A, never_bound(), 0);
        out.push(proof(
            "demoted_manager_at_its_head",
            "dev-phone, demoted to [control, view], signs at L + SB7_set_roles_phone's head",
            DEMOTED,
            at_demoted.clone(),
            signed(keys, "dev-phone/auth", &at_demoted),
            Want::Code("not_a_manager"),
        ));
        out.push(proof(
            "not_a_manager_before_bad_signature",
            "the demoted dev-phone's body signed by dev-mac's key: not_a_manager first",
            DEMOTED,
            good.clone(),
            signed(keys, "dev-mac/auth", &good),
            Want::Code("not_a_manager"),
        ));
        out.push(r(
            "another_members_key",
            "dev-phone's body signed by dev-mac's key",
            signed(keys, "dev-mac/auth", &good),
            "bad_signature",
        ));
        let tampered = with(good.clone(), "subject", json!(OWNER_C));
        let mut t = r(
            "tampered_after_signing",
            "subject changed after signing (the stored challenge names the new subject)",
            good_text.replacen(OWNER_A, OWNER_C, 1),
            "bad_signature",
        );
        t.challenge = tampered;
        out.push(t);
        for (label, other) in [
            (
                "signed_under_verifier_report_label",
                SignLabel::VerifierReport,
            ),
            ("signed_under_signer_report_label", SignLabel::SignerReport),
            ("signed_under_route_label", SignLabel::HostRoute),
            ("signed_under_proxy_route_label", SignLabel::HostRouteProxy),
            ("signed_under_sig_c_label", SignLabel::ChannelClient),
            ("signed_under_control_label", SignLabel::HostWorkControl),
            ("signed_under_entry_label", SignLabel::MembershipEntry),
        ] {
            out.push(r(
                label,
                "the binding's body (typed atem-station-binding) signed by dev-phone under another label: a relabelled body",
                signed_as(keys, "dev-phone/auth", other, &good),
                "bad_signature",
            ));
        }
        let mut high: Value = serde_json::from_str(&good_text).unwrap();
        let sig = b64u_decode(high["sig"].as_str().unwrap()).unwrap();
        high["sig"] = json!(b64u(&high_s(&sig)));
        out.push(r(
            "high_s_signature",
            "the valid P-256 proof (bind_p256_at_head) with s replaced by n - s: a high S",
            format!(
                r#"{{"body":{},"sig":{}}}"#,
                jcs(&good).unwrap(),
                high["sig"]
            ),
            "bad_signature",
        ));
        let ahead = body(&l7, PHONE, "bind", OWNER_A, never_bound(), 0);
        let mut stale = r(
            "stale_log",
            "dev-phone at L + SB7_add_desk's head, verified at L",
            signed(keys, "dev-phone/auth", &ahead),
            "stale_log",
        );
        stale.challenge = ahead;
        out.push(stale);
        out.push(r(
            "fork",
            "head seq 6 at C6_ipad's hash (a sibling of E6)",
            resign(&with(
                good.clone(),
                "head.hash",
                json!(self.v.hash("C6_ipad").to_hex()),
            )),
            "fork",
        ));
        out.push(r(
            "fork_earlier_seq",
            "head seq 5 at E6's hash",
            resign(&with(
                good.clone(),
                "head",
                json!({"seq": 5, "hash": self.v.hash("E6").to_hex()}),
            )),
            "fork",
        ));
        // The body against a stored challenge one field of which differs.
        for (label, path, value) in [
            ("origin_mismatch", "origin", json!(OTHER_STATION)),
            (
                "issuer_mismatch",
                "issuer",
                json!("https://auth.agora.build"),
            ),
            ("subject_mismatch", "subject", json!(OWNER_C)),
            ("auth_time_mismatch", "auth_time", json!(AUTH_TIME - 1)),
            ("account_id_mismatch", "account_id", json!("acct-other")),
            (
                "genesis_hash_mismatch",
                "genesis_hash",
                json!(self.v.hash("SUB1").to_hex()),
            ),
            ("head_mismatch", "head", self.v.head("E5").to_json()),
            ("signer_mismatch", "signer", json!(MAC)),
            (
                "binding_id_mismatch",
                "expected_binding.binding_id",
                json!("bind-0002"),
            ),
            ("version_mismatch", "expected_binding.version", json!(2)),
            ("owner_mismatch", "expected_binding.owner", json!(OWNER_C)),
            ("nonce_mismatch", "nonce", json!(b64u(&nonce(32)))),
            ("issued_at_mismatch", "issued_at", json!(ISSUED + 1)),
            ("expires_at_mismatch", "expires_at", json!(EXPIRES - 1)),
        ] {
            let mut case = r(
                label,
                "a valid transfer against a stored challenge one field of which differs",
                transfer_text.clone(),
                "challenge_mismatch",
            );
            case.challenge = with(transfer.clone(), path, value);
            out.push(case);
        }
        let mut action = r(
            "action_mismatch",
            "a valid transfer against a stored unbind of the same record (an action can't differ alone: each names its own state and subject rule)",
            transfer_text.clone(),
            "challenge_mismatch",
        );
        action.challenge = body(
            &l,
            PHONE,
            "unbind",
            OWNER_A,
            recorded("bound", 1, OWNER_A),
            0,
        );
        out.push(action);
        let released = body(
            &l,
            PHONE,
            "bind",
            OWNER_B,
            recorded("released", 3, OWNER_A),
            0,
        );
        let mut state = r(
            "state_mismatch",
            "a valid rebind after a release against a stored rebind after an unbind of the same record",
            resign(&released),
            "challenge_mismatch",
        );
        state.challenge = with(released, "expected_binding.state", json!("unbound"));
        out.push(state);
        let mut at_expiry = r(
            "expired_at_expires_at",
            "a valid proof verified at its expires_at exactly",
            good_text.clone(),
            "expired",
        );
        at_expiry.now_ms = EXPIRES;
        out.push(at_expiry);
        let mut after = r(
            "expired_after",
            "a valid proof verified after its expires_at",
            good_text,
            "expired",
        );
        after.now_ms = EXPIRES + 1;
        out.push(after);
        out
    }
}

/// A challenge text and what the reader makes of it.
struct ChallengeCase {
    label: &'static str,
    text: String,
    read: bool,
}

fn challenge_cases(made: &Gen) -> Vec<ChallengeCase> {
    let l = made.log(NO_CHAIN, None, NOW);
    let good = body(&l, PHONE, "bind", OWNER_A, never_bound(), 0);
    let transfer = body(
        &l,
        PHONE,
        "transfer",
        OWNER_B,
        recorded("bound", 1, OWNER_A),
        0,
    );
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
    let mut out = vec![
        ok("bind", good.clone()),
        ok("transfer", transfer.clone()),
        ok(
            "unbind",
            body(
                &l,
                PHONE,
                "unbind",
                OWNER_A,
                recorded("bound", 1, OWNER_A),
                0,
            ),
        ),
        ok(
            "rebind_after_released",
            body(
                &l,
                PHONE,
                "bind",
                OWNER_B,
                recorded("released", 2, OWNER_A),
                0,
            ),
        ),
        ChallengeCase {
            label: "pretty_printed",
            text: serde_json::to_string_pretty(&good).unwrap(),
            read: true,
        },
        ok(
            "loopback_http_origin",
            with(good.clone(), "origin", json!("http://127.0.0.1:8080")),
        ),
        ok(
            "lease_one_millisecond",
            with(good.clone(), "expires_at", json!(ISSUED + 1)),
        ),
        ok("auth_time_zero", with(good.clone(), "auth_time", json!(0))),
        ok(
            "account_id_128_bytes",
            with(good.clone(), "account_id", json!("a".repeat(128))),
        ),
        ok(
            "signer_128_byte_id",
            with(
                good.clone(),
                "signer",
                json!(format!("member:{}", "d".repeat(128))),
            ),
        ),
        bad(
            "duplicate_key",
            compact.replacen('{', r#"{"subject":"ab00000000000000000000000003","#, 1),
        ),
        bad(
            "duplicate_key_escaped",
            compact.replacen('{', r#"{"\u0073ubject":"ab00000000000000000000000003","#, 1),
        ),
        bad(
            "unknown_field",
            text(&with(good.clone(), "note", json!("x"))),
        ),
        bad("null", text(&with(good.clone(), "subject", Value::Null))),
        bad("not_an_object", format!("[{compact}]")),
        bad(
            "over_4096_bytes",
            compact.replacen(',', &format!("{},", " ".repeat(4096)), 1),
        ),
        bad(
            "fraction",
            compact.replacen(
                &format!(r#""issued_at":{ISSUED}"#),
                &format!(r#""issued_at":{ISSUED}.0"#),
                1,
            ),
        ),
        bad(
            "signer_service",
            text(&with(good.clone(), "signer", json!("service:svc-discord"))),
        ),
        bad(
            "transfer_to_the_current_owner",
            text(&with(transfer.clone(), "subject", json!(OWNER_A))),
        ),
        bad(
            "unbound_without_owner",
            text(&without(
                body(
                    &l,
                    PHONE,
                    "bind",
                    OWNER_B,
                    recorded("unbound", 2, OWNER_A),
                    0,
                ),
                "expected_binding.owner",
            )),
        ),
        bad(
            "auth_time_after_issued_at",
            text(&with(good.clone(), "auth_time", json!(ISSUED / 1000 + 1))),
        ),
    ];
    for field in good.as_object().unwrap().keys() {
        out.push(ChallengeCase {
            label: Box::leak(format!("missing_{field}").into_boxed_str()),
            text: text(&without(good.clone(), field)),
            read: false,
        });
    }
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
    station: &'static str,
    expected: Value,
    now_ms: u64,
    code: Option<&'static str>,
}

fn claims_json(subject: &str) -> Value {
    json!({"issuer": ISSUER, "subject": subject, "auth_time": AUTH_TIME})
}

fn claims_of(value: &Value) -> AuthClaims {
    AuthClaims {
        issuer: value["issuer"].as_str().unwrap().into(),
        subject: value["subject"].as_str().unwrap().into(),
        auth_time: value["auth_time"].as_u64().unwrap(),
    }
}

fn build_cases(made: &Gen) -> Vec<BuildCase> {
    let l = made.log(NO_CHAIN, None, NOW);
    let l7 = made.log(DESK_ADDED, None, NOW);
    let demoted = made.log(DEMOTED, None, NOW);
    let desk_later = made.log(DESK_LATER, None, NOW);
    let recovering = made.log(RECOVERING, None, NOW);
    let good = body(&l, PHONE, "bind", OWNER_A, never_bound(), 0);
    let case = |label, note, code| BuildCase {
        label,
        note,
        chain: NO_CHAIN,
        freeze: None,
        challenge: good.clone(),
        signer: PHONE,
        station: STATION,
        expected: claims_json(OWNER_A),
        now_ms: NOW,
        code,
    };
    vec![
        case("bind", "dev-phone answers a bind's challenge", None),
        BuildCase {
            station: "https://Station-Dev.agora.build/",
            ..case(
                "station_normalized",
                "the configured Station as written, normalized to the challenge's origin",
                None,
            )
        },
        BuildCase {
            challenge: body(
                &l,
                PHONE,
                "transfer",
                OWNER_B,
                recorded("bound", 1, OWNER_A),
                0,
            ),
            expected: claims_json(OWNER_B),
            ..case(
                "transfer",
                "a transfer to OWNER_B, the new owner the app was shown",
                None,
            )
        },
        BuildCase {
            challenge: body(
                &l,
                PHONE,
                "unbind",
                OWNER_A,
                recorded("bound", 2, OWNER_A),
                0,
            ),
            ..case("unbind", "an unbind by its current owner", None)
        },
        BuildCase {
            challenge: body(
                &l,
                PHONE,
                "bind",
                OWNER_B,
                recorded("released", 4, OWNER_A),
                0,
            ),
            expected: claims_json(OWNER_B),
            ..case(
                "rebind_after_released",
                "a bind after an admin release",
                None,
            )
        },
        BuildCase {
            chain: DESK_ADDED,
            challenge: body(&l7, DESK, "bind", OWNER_A, never_bound(), 0),
            signer: DESK,
            ..case(
                "bind_ed25519",
                "dev-desk (Ed25519) at L + SB7_add_desk",
                None,
            )
        },
        BuildCase {
            chain: DESK_ADDED,
            ..case(
                "challenge_at_an_ancestor",
                "a challenge at L's head, the signer's list at L + SB7_add_desk: the signer's list moved on",
                None,
            )
        },
        BuildCase {
            signer: "service:svc-discord",
            ..case(
                "signer_service",
                "a service never signs a binding",
                Some("malformed"),
            )
        },
        BuildCase {
            signer: "host:host-a",
            ..case(
                "signer_host",
                "a host never signs a binding",
                Some("malformed"),
            )
        },
        BuildCase {
            signer: "dev-phone",
            ..case(
                "signer_without_prefix",
                "a signer without member:",
                Some("malformed"),
            )
        },
        BuildCase {
            station: "ftp://station-dev.agora.build",
            ..case(
                "station_not_an_origin",
                "a configured Station normalize_relay refuses",
                Some("malformed"),
            )
        },
        BuildCase {
            expected: json!({"issuer": "", "subject": OWNER_A, "auth_time": AUTH_TIME}),
            ..case(
                "expected_issuer_empty",
                "the app's issuer outside its grammar",
                Some("malformed"),
            )
        },
        BuildCase {
            expected: json!({"issuer": ISSUER, "subject": "ab 1", "auth_time": AUTH_TIME}),
            ..case(
                "expected_subject_space",
                "the app's subject outside its grammar",
                Some("malformed"),
            )
        },
        BuildCase {
            expected: json!({"issuer": ISSUER, "subject": "s".repeat(257), "auth_time": AUTH_TIME}),
            ..case(
                "expected_subject_257_bytes",
                "the app's subject over 256 bytes",
                Some("malformed"),
            )
        },
        BuildCase {
            freeze: Some("C6_mac"),
            ..case(
                "frozen",
                "the signer's list frozen by C6_mac",
                Some("frozen"),
            )
        },
        BuildCase {
            freeze: Some("C6_mac"),
            challenge: with(good.clone(), "account_id", json!("acct-other")),
            ..case(
                "frozen_before_wrong_account",
                "another account's challenge against a frozen list",
                Some("frozen"),
            )
        },
        BuildCase {
            challenge: with(good.clone(), "account_id", json!("acct-other")),
            station: OTHER_STATION,
            ..case(
                "wrong_account",
                "a challenge for another account (and another Station): wrong_account first",
                Some("wrong_account"),
            )
        },
        BuildCase {
            challenge: with(
                good.clone(),
                "genesis_hash",
                json!(made.v.hash("SUB1").to_hex()),
            ),
            ..case(
                "wrong_genesis",
                "a challenge for another genesis (SUB1's)",
                Some("wrong_account"),
            )
        },
        BuildCase {
            station: OTHER_STATION,
            challenge: with(good.clone(), "signer", json!(MAC)),
            ..case(
                "another_station",
                "a challenge minted by station-dev, the app configured with another Station (and naming dev-mac): origin_mismatch first",
                Some("origin_mismatch"),
            )
        },
        BuildCase {
            station: "https://station-dev.agora.build:8443",
            ..case(
                "another_port",
                "the configured Station on another port",
                Some("origin_mismatch"),
            )
        },
        BuildCase {
            challenge: with(good.clone(), "signer", json!(MAC)),
            signer: "member:dev-ipad",
            ..case(
                "another_signer",
                "the challenge names dev-mac; the app is the removed dev-ipad: signer_mismatch first",
                Some("signer_mismatch"),
            )
        },
        BuildCase {
            challenge: with(good.clone(), "signer", json!("member:dev-ipad")),
            signer: "member:dev-ipad",
            ..case(
                "removed_member",
                "dev-ipad, removed by E6, answers a challenge for itself",
                Some("unknown_signer"),
            )
        },
        BuildCase {
            challenge: with(good.clone(), "signer", json!("member:svc-discord")),
            signer: "member:svc-discord",
            ..case(
                "service_as_member",
                "a service named as a native member",
                Some("unknown_signer"),
            )
        },
        BuildCase {
            chain: RECOVERING,
            challenge: body(
                &recovering,
                "member:dev-newmac",
                "bind",
                OWNER_A,
                never_bound(),
                0,
            ),
            signer: "member:dev-newmac",
            ..case(
                "pending_recovery_subject",
                "dev-newmac, the subject of a recovery_add still waiting (L + SB7_recovery_add_newmac)",
                Some("unknown_signer"),
            )
        },
        BuildCase {
            chain: DEMOTED,
            challenge: body(&demoted, PHONE, "bind", OWNER_A, never_bound(), 0),
            ..case(
                "demoted_manager",
                "dev-phone demoted to [control, view] (L + SB7_set_roles_phone): no manage at its own head",
                Some("not_a_manager"),
            )
        },
        BuildCase {
            chain: DEMOTED,
            challenge: body(&desk_later, PHONE, "bind", OWNER_A, never_bound(), 0),
            ..case(
                "not_a_manager_before_stale_log",
                "dev-phone demoted (L + SB7_set_roles_phone), the challenge at L + SB7_add_desk + SB8_add_host_b's head, beyond its list: not_a_manager first",
                Some("not_a_manager"),
            )
        },
        BuildCase {
            challenge: body(&l7, "member:dev-ipad", "bind", OWNER_A, never_bound(), 0),
            signer: "member:dev-ipad",
            ..case(
                "unknown_signer_before_stale_log",
                "the removed dev-ipad answers a challenge at L + SB7_add_desk's head, beyond its list L: unknown_signer first",
                Some("unknown_signer"),
            )
        },
        BuildCase {
            challenge: body(&l7, PHONE, "bind", OWNER_A, never_bound(), 0),
            expected: claims_json(OWNER_B),
            ..case(
                "station_ahead",
                "a challenge at L + SB7_add_desk's head, the signer's list at L: fetch first (stale_log before binding_mismatch)",
                Some("stale_log"),
            )
        },
        BuildCase {
            challenge: with(
                good.clone(),
                "head.hash",
                json!(made.v.hash("C6_ipad").to_hex()),
            ),
            ..case("fork", "head seq 6 at C6_ipad's hash", Some("fork"))
        },
        BuildCase {
            expected: json!({"issuer": "https://auth.agora.build", "subject": OWNER_A, "auth_time": AUTH_TIME}),
            now_ms: EXPIRES,
            ..case(
                "issuer_mismatch",
                "the app was told another issuer (at expires_at: binding_mismatch first)",
                Some("binding_mismatch"),
            )
        },
        BuildCase {
            challenge: body(
                &l,
                PHONE,
                "transfer",
                OWNER_B,
                recorded("bound", 1, OWNER_A),
                0,
            ),
            expected: claims_json(OWNER_C),
            ..case(
                "transfer_subject_mismatch",
                "a transfer to OWNER_B, the app shown OWNER_C as the new owner",
                Some("binding_mismatch"),
            )
        },
        BuildCase {
            expected: json!({"issuer": ISSUER, "subject": OWNER_A, "auth_time": AUTH_TIME + 1}),
            ..case(
                "auth_time_mismatch",
                "the app's token signed in a second later",
                Some("binding_mismatch"),
            )
        },
        BuildCase {
            now_ms: EXPIRES,
            ..case(
                "challenge_expired",
                "the challenge at its expires_at on the signer's clock",
                Some("expired"),
            )
        },
    ]
}

/// The immutable request: a builder case and its finishes `(label,
/// signed_with, another nonce (None: the held body), code)`.
struct RequestCase {
    build: BuildCase,
    key: &'static str,
    finishes: Vec<(&'static str, &'static str, Option<u8>, Option<&'static str>)>,
}

fn request_cases(made: &Gen) -> Vec<RequestCase> {
    let builds = build_cases(made);
    let take = |label: &str| builds.iter().find(|c| c.label == label).unwrap().clone();
    let finishes = |key: &'static str, other: &'static str| {
        vec![
            ("held_by_its_signer", key, None, None),
            ("another_body", key, Some(64), Some("bad_signature")),
            ("another_member", other, None, Some("bad_signature")),
        ]
    };
    vec![
        RequestCase {
            build: take("bind"),
            key: "dev-phone/auth",
            finishes: finishes("dev-phone/auth", "dev-mac/auth"),
        },
        RequestCase {
            build: take("transfer"),
            key: "dev-phone/auth",
            finishes: finishes("dev-phone/auth", "dev-mac/auth"),
        },
        RequestCase {
            build: take("bind_ed25519"),
            key: "dev-desk/auth",
            finishes: finishes("dev-desk/auth", "dev-phone/auth"),
        },
    ]
}

fn verified_json(v: &VerifiedStationBinding) -> Value {
    json!({
        "action": v.action.as_str(),
        "signer": v.signer,
        "head": v.head.to_json(),
        "at_head": v.at_head,
        "account_id": v.account_id,
        "genesis_hash": v.genesis_hash.to_hex(),
        "issuer": v.issuer,
        "subject": v.subject,
        "auth_time": v.auth_time,
        "expected_binding": v.expected_binding.to_json(),
        "nonce": b64u(&v.nonce),
        "expires_at": v.expires_at,
    })
}

fn opt(map: &mut Map<String, Value>, key: &str, value: Option<Value>) {
    if let Some(value) = value {
        map.insert(key.into(), value);
    }
}

/// The challenge of `case` with its nonce replaced: another body.
fn other_nonce(challenge: &Value, first: u8) -> Value {
    with(challenge.clone(), "nonce", json!(b64u(&nonce(first))))
}

/// Astation's examples, each checked here: the challenge reads, the
/// signing input's digest is the one posted, and both signatures verify
/// under the posted keys over that input, never under another case's or
/// another label.
fn external_json() -> Value {
    let posted: Value = serde_json::from_str(EXTERNAL).unwrap();
    let keys: Vec<PublicKey> = posted["public_keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| {
            let alg = match k["alg"].as_str().unwrap() {
                "ed25519" => Alg::Ed25519,
                _ => Alg::P256,
            };
            PublicKey::new(alg, &b64u_decode(k["pub"].as_str().unwrap()).unwrap()).unwrap()
        })
        .collect();
    let cases = posted["cases"].as_array().unwrap();
    let inputs: Vec<SigningInput> = cases
        .iter()
        .map(|case| {
            let challenge = read_challenge(&case["challenge"]);
            SigningInput::new(SignLabel::StationBinding, challenge.jcs().as_bytes())
        })
        .collect();
    for (i, case) in cases.iter().enumerate() {
        assert_eq!(
            hex(&Sha256::digest(inputs[i].as_bytes())),
            case["signing_input_sha256"].as_str().unwrap(),
            "case {i}'s digest"
        );
        for (key, field) in keys.iter().zip(["ed25519_sig", "p256_sig"]) {
            let sig = b64u_decode(case[field].as_str().unwrap()).unwrap();
            for (j, input) in inputs.iter().enumerate() {
                assert_eq!(
                    key.verify(input, &sig).is_ok(),
                    i == j,
                    "case {i} {field} over {j}"
                );
            }
            let jcs = jcs(&case["challenge"]).unwrap();
            for label in [
                SignLabel::VerifierReport,
                SignLabel::SignerReport,
                SignLabel::HostRoute,
            ] {
                assert!(
                    key.verify(&SigningInput::new(label, jcs.as_bytes()), &sig)
                        .is_err()
                );
            }
        }
    }
    json!({
        "source": EXTERNAL_SOURCE,
        "cases": posted["cases"],
        "public_keys": posted["public_keys"],
    })
}

/// The file: every case's outcome checked against the shared core.
fn station_binding_vectors() -> Value {
    let made = Gen::new();
    let challenges: Vec<Value> = challenge_cases(&made)
        .into_iter()
        .map(|case| {
            let read = StationBindingChallenge::parse(case.text.as_bytes());
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
    let proof_json = |case: Proof| {
        let log = made.log(case.chain, case.freeze, case.now_ms);
        let got = verify_station_binding(
            &log,
            case.text.as_bytes(),
            &read_challenge(&case.challenge),
            case.now_ms,
        );
        let mut out = Map::new();
        out.insert("label".into(), json!(case.label));
        out.insert("note".into(), json!(case.note));
        out.insert("chain".into(), json!(case.chain));
        opt(&mut out, "freeze", case.freeze.map(|f| json!(f)));
        out.insert("challenge".into(), case.challenge.clone());
        out.insert("now_ms".into(), json!(case.now_ms));
        out.insert("proof".into(), json!(case.text));
        match (case.want, got) {
            (Want::Verified { at_head }, Ok(v)) => {
                assert_eq!(v.at_head, at_head, "{}", case.label);
                let object = SignedObject::parse(case.text.as_bytes()).unwrap();
                assert_eq!(object.jcs(), read_challenge(&case.challenge).jcs());
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
    let valid: Vec<Value> = made.valid().into_iter().map(proof_json).collect();
    let invalid: Vec<Value> = made.invalid().into_iter().map(proof_json).collect();
    let build = |case: &BuildCase| {
        let log = made.log(case.chain, case.freeze, case.now_ms);
        let got = station_binding_request(
            &log,
            &read_challenge(&case.challenge),
            case.signer,
            case.station,
            &claims_of(&case.expected),
            case.now_ms,
        );
        let mut out = Map::new();
        out.insert("label".into(), json!(case.label));
        out.insert("note".into(), json!(case.note));
        out.insert("chain".into(), json!(case.chain));
        opt(&mut out, "freeze", case.freeze.map(|f| json!(f)));
        out.insert("challenge".into(), case.challenge.clone());
        out.insert("signer".into(), json!(case.signer));
        out.insert("station".into(), json!(case.station));
        out.insert("expected".into(), case.expected.clone());
        out.insert("now_ms".into(), json!(case.now_ms));
        match (case.code, got) {
            (None, Ok(request)) => {
                assert_eq!(request.body_json(), jcs(&case.challenge).unwrap());
                out.insert("body_json".into(), json!(request.body_json()));
                (Value::Object(out), Some(request))
            }
            (Some(code), Err(e)) => {
                assert_eq!(e.code(), code, "{}: {e}", case.label);
                out.insert("code".into(), json!(code));
                (Value::Object(out), None)
            }
            (want, got) => panic!("{}: {want:?} written here, {got:?} given", case.label),
        }
    };
    let builder: Vec<Value> = build_cases(&made).iter().map(|c| build(c).0).collect();
    let request: Vec<Value> = request_cases(&made)
        .into_iter()
        .map(|case| {
            let (mut out, request) = build(&case.build);
            let request = request.unwrap();
            let held = sign_station_binding(&made.keys, &KeyId::new(case.key), &request).unwrap();
            assert_eq!(held.jcs(), request.body_json());
            let finishes: Vec<Value> = case
                .finishes
                .iter()
                .map(|(label, key, other, code)| {
                    let input = match other {
                        None => request.signing_input(),
                        Some(first) => {
                            let log = made.log(case.build.chain, None, case.build.now_ms);
                            station_binding_request(
                                &log,
                                &read_challenge(&other_nonce(&case.build.challenge, *first)),
                                case.build.signer,
                                case.build.station,
                                &claims_of(&case.build.expected),
                                case.build.now_ms,
                            )
                            .unwrap()
                            .signing_input()
                        }
                    };
                    let sig = sign(&made.keys, &KeyId::new(*key), &input).unwrap();
                    match (code, request.finish(&sig)) {
                        (None, Ok(proof)) => {
                            assert_eq!(
                                jcs(&proof.to_json()).unwrap(),
                                format!(
                                    r#"{{"body":{},"sig":"{}"}}"#,
                                    request.body_json(),
                                    b64u(&sig)
                                )
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
                        other.map_or(json!("held"), |first| json!({"nonce": b64u(&nonce(first))})),
                    );
                    opt(&mut f, "code", code.map(|c| json!(c)));
                    Value::Object(f)
                })
                .collect();
            out["key"] = json!(case.key);
            out["sign_request"] = json!({
                "purpose": "station_binding",
                "fresh_confirmation": true,
                "label": "atem-station-binding-v1",
            });
            out["finishes"] = json!(finishes);
            out
        })
        .collect();
    json!({
        "name": FILE,
        "kind": "vectors",
        "requires": "r9",
        "note": NOTE,
        "entries": made.entries_json(),
        "external": external_json(),
        "challenges": challenges,
        "valid": valid,
        "invalid": invalid,
        "builder": builder,
        "request": request,
    })
}

#[test]
#[ignore = "writes the station-binding vectors"]
fn write_station_binding_vectors() {
    let mut text = serde_json::to_string_pretty(&station_binding_vectors()).unwrap();
    text.push('\n');
    std::fs::write(fixtures_dir().join(format!("{FILE}.json")), text).unwrap();
}

#[test]
fn station_binding_file_is_what_the_generator_makes() {
    let file = load(FILE);
    assert_eq!(
        file.as_object().unwrap().keys().collect::<Vec<_>>(),
        [
            "builder",
            "challenges",
            "entries",
            "external",
            "invalid",
            "kind",
            "name",
            "note",
            "request",
            "requires",
            "valid"
        ]
    );
    assert_eq!(
        file,
        station_binding_vectors(),
        "regenerate with write_station_binding_vectors"
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

/// Astation's examples as the file holds them: the challenges read, the
/// digests are the posted ones and every signature verifies under its
/// posted key, byte for byte with what Astation posted.
#[test]
fn astations_examples_verify_byte_for_byte() {
    let file = load(FILE);
    let external = &file["external"];
    let posted: Value = serde_json::from_str(EXTERNAL).unwrap();
    assert_eq!(external["cases"], posted["cases"]);
    assert_eq!(external["public_keys"], posted["public_keys"]);
    let keys: Vec<(String, PublicKey)> = external["public_keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| {
            let alg = k["alg"].as_str().unwrap().to_owned();
            let key = PublicKey::new(
                if alg == "ed25519" {
                    Alg::Ed25519
                } else {
                    Alg::P256
                },
                &b64u_decode(k["pub"].as_str().unwrap()).unwrap(),
            )
            .unwrap();
            (alg, key)
        })
        .collect();
    let mut actions = BTreeSet::new();
    for case in external["cases"].as_array().unwrap() {
        let challenge = read_challenge(&case["challenge"]);
        actions.insert(challenge.action().as_str());
        let input = SigningInput::new(SignLabel::StationBinding, challenge.jcs().as_bytes());
        assert_eq!(
            hex(&Sha256::digest(input.as_bytes())),
            case["signing_input_sha256"].as_str().unwrap()
        );
        for (alg, key) in &keys {
            let sig = b64u_decode(case[format!("{alg}_sig")].as_str().unwrap()).unwrap();
            key.verify(&input, &sig).unwrap();
            // The proof as a signed object: R9.1's form verifies too.
            let proof = format!(
                r#"{{"body":{},"sig":"{}"}}"#,
                challenge.jcs(),
                case[format!("{alg}_sig")].as_str().unwrap()
            );
            SignedObject::parse(proof.as_bytes())
                .unwrap()
                .verify(key)
                .unwrap();
        }
    }
    assert_eq!(
        actions.into_iter().collect::<Vec<_>>(),
        ["bind", "transfer", "unbind"]
    );
}

/// Every case as the file says, read from the file: the challenges, the
/// proofs' verdicts, the builder's bodies and refusals, and the request's
/// finishes. The cases cover every verifier code and every builder code.
#[test]
fn station_binding_vectors_run_through_the_shared_core() {
    let (file, v, book) = (load(FILE), Vectors::load(), Book::load());
    for case in file["challenges"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let read = StationBindingChallenge::parse(case["text"].as_str().unwrap().as_bytes());
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
    let mut actions = BTreeSet::new();
    for case in file["valid"]
        .as_array()
        .unwrap()
        .iter()
        .chain(file["invalid"].as_array().unwrap())
    {
        let label = case["label"].as_str().unwrap();
        let log = case_log(&v, &file, case);
        let got = verify_station_binding(
            &log,
            case["proof"].as_str().unwrap().as_bytes(),
            &read_challenge(&case["challenge"]),
            case["now_ms"].as_u64().unwrap(),
        );
        match case.get("expect") {
            Some(expect) => {
                let verified = got.unwrap();
                actions.insert(verified.action.as_str());
                assert_eq!(&verified_json(&verified), expect, "{label}");
                let object =
                    SignedObject::parse(case["proof"].as_str().unwrap().as_bytes()).unwrap();
                assert_eq!(object.jcs(), case["jcs"].as_str().unwrap());
                assert_eq!(
                    hex(object.signing_input().as_bytes()),
                    case["signing_input_hex"].as_str().unwrap()
                );
                let key = book.public(case["signed_with"].as_str().unwrap());
                object.verify(&key).unwrap();
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
        BINDING_VERIFY_ORDER.iter().map(|c| c.to_string()).collect(),
        "every verifier code has a vector"
    );
    assert_eq!(
        actions.into_iter().collect::<Vec<_>>(),
        ["bind", "transfer", "unbind"],
        "every action verifies"
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
        let got = station_binding_request(
            &log,
            &read_challenge(&case["challenge"]),
            case["signer"].as_str().unwrap(),
            case["station"].as_str().unwrap(),
            &claims_of(&case["expected"]),
            case["now_ms"].as_u64().unwrap(),
        );
        match case.get("body_json") {
            Some(want) => assert_eq!(got.unwrap().body_json(), want.as_str().unwrap(), "{label}"),
            None => {
                let code = case["code"].as_str().unwrap();
                assert_eq!(got.map(|_| ()).map_err(|e| e.code()), Err(code), "{label}");
                build_codes.insert(code.to_owned());
            }
        }
    }
    assert_eq!(
        build_codes,
        BINDING_BUILD_ORDER.iter().map(|c| c.to_string()).collect(),
        "every builder code has a vector"
    );
}

/// The request's finishes, read from the file: the held body takes only
/// its signer's signature over itself, and the proof is that body with the
/// signature, byte for byte.
#[test]
fn the_immutable_request_takes_only_a_signature_over_its_held_body() {
    let (file, v, book) = (load(FILE), Vectors::load(), Book::load());
    for case in file["request"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        assert_eq!(
            case["sign_request"]["label"],
            SignLabel::StationBinding.as_str()
        );
        let log = case_log(&v, &file, case);
        let build = |challenge: &Value| {
            station_binding_request(
                &log,
                &read_challenge(challenge),
                case["signer"].as_str().unwrap(),
                case["station"].as_str().unwrap(),
                &claims_of(&case["expected"]),
                case["now_ms"].as_u64().unwrap(),
            )
            .unwrap()
        };
        let held = build(&case["challenge"]);
        let mut finished = 0;
        for f in case["finishes"].as_array().unwrap() {
            let input = match f["over"].as_str() {
                Some("held") => held.signing_input(),
                _ => build(&with(
                    case["challenge"].clone(),
                    "nonce",
                    f["over"]["nonce"].clone(),
                ))
                .signing_input(),
            };
            let key = KeyId::new(f["signed_with"].as_str().unwrap());
            let sig = sign(&book.provider, &key, &input).unwrap();
            match f.get("code") {
                None => {
                    let proof = held.finish(&sig).unwrap();
                    assert_eq!(
                        jcs(&proof.to_json()).unwrap(),
                        format!(r#"{{"body":{},"sig":"{}"}}"#, held.body_json(), b64u(&sig))
                    );
                    finished += 1;
                }
                Some(code) => assert_eq!(
                    held.finish(&sig).map(|_| ()).map_err(|e| e.code()),
                    Err(code.as_str().unwrap()),
                    "{label}: {}",
                    f["label"]
                ),
            }
        }
        assert_eq!(finished, 1, "{label}");
    }
}
