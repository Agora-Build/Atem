//! Host-sender Revoke and Readmit in the device list (delegated host-work
//! design II.3.1) and a host's membership epoch (II.2.2): the
//! `host_sender_revoke` and `host_sender_readmit` entries, through the public
//! API the way a host or a managing device drives the verifier. Each test
//! builds its own log with its own software keys.
use atem_client::encoding::{Hash32, b64u};
use atem_client::membership::{
    Action, ChangeRefusal, Check, Effect, Entry, Head, HostNow, HostRecord, HostSenderState,
    Invalid, MAX_ENTRIES, MAX_HOSTS, Member, MemberKind, Membership, Role, RolesChange, Scope,
    check_body, check_change, draft_on, host_sender_readmit, host_sender_revoke, sign_entry,
};
use atem_client::{Alg, KeyId, PublicKey, SoftwareKeys};
use serde_json::{Value, json};

const ACCOUNT: &str = "acct-host-senders";
const ALL: [Role; 3] = [Role::Control, Role::Manage, Role::View];
const T0: u64 = 1_793_620_800_000;
const HOSTS: [&str; 4] = ["host-a", "host-b", "host-c", "host-z"];

fn now(wall_ms: u64) -> HostNow {
    HostNow {
        wall_ms,
        mono_ms: wall_ms,
        boot_id: "b".into(),
    }
}

fn auth() -> KeyId {
    KeyId::new("auth")
}

fn authorized(generation: u64) -> Option<HostSenderState> {
    Some(HostSenderState::Authorized { generation })
}

fn revoked(seq: u64) -> Option<HostSenderState> {
    Some(HostSenderState::Revoked { seq })
}

fn revoke(host_id: &str, interrupt_running: bool) -> Action {
    host_sender_revoke(host_id, interrupt_running, T0).unwrap_or_else(|e| panic!("{host_id}: {e}"))
}

fn readmit(host_id: &str) -> Action {
    host_sender_readmit(host_id, T0).unwrap_or_else(|e| panic!("{host_id}: {e}"))
}

/// A log on one verifier: `dev-mac` (a native manager, Ed25519) signs
/// every entry; every host shares one host key (nothing here checks it).
/// Each committed entry is replayed (`assert_replays`) unless `replay` is
/// off (long logs: a fresh verification of the whole chain per entry).
struct Log {
    m: Membership,
    mac: SoftwareKeys,
    host_key: PublicKey,
    at: u64,
    replay: bool,
}

impl Log {
    fn new() -> Log {
        let mut mac = SoftwareKeys::new();
        let auth_key = mac.generate(auth(), Alg::Ed25519).unwrap();
        let enc_key = mac.generate(KeyId::new("enc"), Alg::X25519).unwrap();
        let recovery_key = mac.generate(KeyId::new("kit"), Alg::Ed25519).unwrap();
        let host_key = mac.generate(KeyId::new("host"), Alg::Ed25519).unwrap();
        let body = draft_on(
            ACCOUNT,
            &Hash32([0; 32]),
            1,
            &Hash32([0; 32]),
            "dev-mac",
            T0,
            &Action::Genesis {
                member: Member {
                    device_id: "dev-mac".into(),
                    auth_key,
                    kind: MemberKind::Native {
                        enc_key,
                        roles: ALL.into_iter().collect(),
                    },
                },
                recovery_key,
            },
        );
        let genesis = sign_entry(&mac, &auth(), body).unwrap();
        let m = Membership::from_genesis(ACCOUNT, &genesis.hash(), genesis).unwrap();
        Log {
            m,
            mac,
            host_key,
            at: T0,
            replay: true,
        }
    }

    /// The next entry, drafted on the head and signed by `dev-mac`.
    fn sign(&self, action: &Action) -> Result<Entry, Invalid> {
        sign_entry(&self.mac, &auth(), self.m.draft("dev-mac", self.at, action))
    }

    fn check(&self, action: &Action) -> Check {
        self.m.check_next(&self.sign(action).unwrap())
    }

    /// Signed, carried and committed as a host does; the effects.
    fn apply(&mut self, action: Action) -> Vec<Effect> {
        self.at += 1;
        let entry = self.sign(&action).unwrap();
        let eval = self
            .m
            .evaluate_objects(&[entry.object().clone()], &now(self.at));
        assert_eq!(eval.stop, None, "{action:?}");
        self.m = eval.next;
        if self.replay {
            self.assert_replays();
        }
        eval.effects
    }

    /// The entry's `seq`.
    fn add_host(&mut self, host_id: &str, host_trust_gen: u64) -> u64 {
        self.apply(Action::AddHost {
            host: HostRecord {
                host_id: host_id.into(),
                host_trust_gen,
                host_key: self.host_key.clone(),
            },
        });
        self.m.head().seq
    }

    fn remove_host(&mut self, host_id: &str) -> u64 {
        self.apply(Action::RemoveHost {
            host_id: host_id.into(),
        });
        self.m.head().seq
    }

    fn revoke(&mut self, host_id: &str, interrupt_running: bool) -> u64 {
        self.apply(revoke(host_id, interrupt_running));
        self.m.head().seq
    }

    fn readmit(&mut self, host_id: &str) -> u64 {
        self.apply(readmit(host_id));
        self.m.head().seq
    }

    fn state(&self, host_id: &str) -> Option<HostSenderState> {
        self.m.host_sender_state(host_id)
    }

    fn epoch(&self, host_id: &str) -> Option<u64> {
        self.m.host_membership_epoch(host_id)
    }

    /// The stored form reads back as the same state, and a fresh verifier
    /// of the same entries derives the same sending states and epochs (both
    /// replay them).
    fn assert_replays(&self) {
        let back = Membership::from_stored(ACCOUNT, &self.m.genesis_hash(), &self.m.to_stored())
            .unwrap_or_else(|e| panic!("stored form refused: {e}"));
        assert_eq!(back, self.m);
        let fresh = Membership::verify_chain(
            ACCOUNT,
            &self.m.genesis_hash(),
            self.m.entries(),
            &now(self.at),
        )
        .unwrap();
        assert_eq!(fresh.deferred, None);
        for host in HOSTS {
            assert_eq!(fresh.membership.host_sender_state(host), self.state(host));
            assert_eq!(
                fresh.membership.host_membership_epoch(host),
                self.epoch(host)
            );
        }
    }
}

/// An unsigned body after a placeholder head: the verifier's structural
/// parse only ([`check_body`]).
fn body(fields: Value) -> Value {
    let mut body = json!({
        "type": "atem-membership-entry", "v": 1, "account_id": ACCOUNT,
        "genesis_hash": "ab".repeat(32), "seq": 2, "prev_hash": "cd".repeat(32),
        "signer": "dev-mac", "signed_at": T0,
    });
    body.as_object_mut()
        .unwrap()
        .extend(fields.as_object().unwrap().clone());
    body
}

/// Parsed as received: the wire bytes `{"body", "sig"}`.
fn parse_wire(body: Value) -> Result<Entry, Invalid> {
    let wire = json!({"body": body, "sig": b64u(&[0u8; 64])});
    Entry::parse_bytes(wire.to_string().as_bytes())
}

fn invalid(reason: Invalid) -> Check {
    Check::Invalid(reason)
}

#[test]
fn first_add_host_authorizes_at_its_seq() {
    let mut log = Log::new();
    assert_eq!(log.state("host-a"), None);
    assert_eq!(log.epoch("host-a"), None);
    let a = log.add_host("host-a", 1);
    assert_eq!(a, 2);
    assert_eq!(log.state("host-a"), authorized(a));
    assert_eq!(log.epoch("host-a"), Some(a));
    let b = log.add_host("host-b", 1);
    assert_eq!(log.state("host-b"), authorized(b));
    // Another host's first add_host changes nothing of host-a's.
    assert_eq!(log.state("host-a"), authorized(a));
    assert_eq!(log.state("host-z"), None);
    assert_eq!(log.epoch("host-z"), None);

    // `signed_at_head` checks read an entry's hash by its `seq`.
    for seq in 1..=log.m.head().seq {
        assert_eq!(
            log.m.entry_hash_at(seq),
            Some(log.m.entry(seq).unwrap().hash())
        );
    }
    assert_eq!(log.m.entry_hash_at(b), Some(log.m.head().hash));
    assert_eq!(log.m.entry_hash_at(0), None);
    assert_eq!(log.m.entry_hash_at(log.m.head().seq + 1), None);
    assert_eq!(log.m.entry_hash_at(u64::MAX), None);
}

#[test]
fn revoke_then_readmit_generations() {
    let mut log = Log::new();
    let a = log.add_host("host-a", 1);
    let b = log.add_host("host-b", 1);
    let r1 = log.revoke("host-a", false);
    assert_eq!(log.state("host-a"), revoked(r1));
    let m1 = log.readmit("host-a");
    assert_eq!(log.state("host-a"), authorized(m1));
    assert!(m1 > r1 && r1 > a);
    let r2 = log.revoke("host-a", true);
    assert_eq!(log.state("host-a"), revoked(r2));
    let m2 = log.readmit("host-a");
    assert_eq!(log.state("host-a"), authorized(m2));
    // Only the named host moves; the membership epoch is no generation.
    assert_eq!(log.state("host-b"), authorized(b));
    assert_eq!(log.epoch("host-a"), Some(a));
    // Revoke and readmit change nothing about the host as a host.
    assert!(log.m.host("host-a").is_some());
    // Both entries stay in the log.
    for seq in [r1, m1, r2, m2] {
        assert!(log.m.entry(seq).is_some());
    }
}

#[test]
fn revoke_in_revoked_is_already_revoked() {
    let mut log = Log::new();
    log.add_host("host-a", 1);
    log.revoke("host-a", false);
    for interrupt_running in [false, true] {
        assert_eq!(
            log.check(&revoke("host-a", interrupt_running)),
            invalid(Invalid::AlreadyRevoked)
        );
    }
    assert_eq!(Invalid::AlreadyRevoked.code(), "already_revoked");
    assert_eq!(Invalid::AlreadyRevoked.to_string(), "already_revoked");
    // Readmitted, it may be revoked again.
    log.readmit("host-a");
    assert_eq!(log.check(&revoke("host-a", true)), Check::Valid);
}

#[test]
fn readmit_in_authorized_is_not_revoked() {
    let mut log = Log::new();
    log.add_host("host-a", 1);
    assert_eq!(log.check(&readmit("host-a")), invalid(Invalid::NotRevoked));
    assert_eq!(Invalid::NotRevoked.code(), "not_revoked");
    // A host never added isn't revoked either (II.3.1: `not_revoked`).
    assert_eq!(log.check(&readmit("host-z")), invalid(Invalid::NotRevoked));
    // A readmit after a readmit.
    log.revoke("host-a", false);
    log.readmit("host-a");
    assert_eq!(log.check(&readmit("host-a")), invalid(Invalid::NotRevoked));
}

#[test]
fn revoke_unknown_host_is_unknown_host() {
    let mut log = Log::new();
    assert_eq!(
        log.check(&revoke("host-a", false)),
        invalid(Invalid::UnknownHost)
    );
    assert_eq!(Invalid::UnknownHost.code(), "unknown_host");
    log.add_host("host-a", 1);
    for interrupt_running in [false, true] {
        assert_eq!(
            log.check(&revoke("host-z", interrupt_running)),
            invalid(Invalid::UnknownHost)
        );
    }
    // A host only a service scope names is still unknown: only an
    // `add_host` makes a host known.
    let mut bot_keys = SoftwareKeys::new();
    log.apply(Action::Add {
        member: Member {
            device_id: "svc-bot".into(),
            auth_key: bot_keys.generate(auth(), Alg::Ed25519).unwrap(),
            kind: MemberKind::Service {
                scope: Scope {
                    hosts: vec!["host-y".into()],
                    projects: None,
                    sessions: None,
                    ops: vec!["view".into()],
                },
                expires_at: T0 + 86_400_000,
            },
        },
    });
    assert_eq!(
        log.check(&revoke("host-y", false)),
        invalid(Invalid::UnknownHost)
    );
    assert_eq!(log.check(&revoke("host-a", false)), Check::Valid);
}

#[test]
fn revoke_removed_host_allowed() {
    let mut log = Log::new();
    log.add_host("host-a", 1);
    log.remove_host("host-a");
    assert_eq!(log.m.host("host-a"), None);
    assert_eq!(log.check(&revoke("host-a", true)), Check::Valid);
    let r = log.revoke("host-a", true);
    assert_eq!(log.state("host-a"), revoked(r));
    // Still removed: a revoke adds no host.
    assert_eq!(log.m.host("host-a"), None);
    assert_eq!(log.epoch("host-a"), None);
    // And a removed host's readmit is valid too (its state is `revoked`).
    assert_eq!(
        log.check(&revoke("host-a", false)),
        invalid(Invalid::AlreadyRevoked)
    );
    let m = log.readmit("host-a");
    assert_eq!(log.state("host-a"), authorized(m));
    assert_eq!(log.m.host("host-a"), None);
}

#[test]
fn readd_after_remove_keeps_revoked() {
    let mut log = Log::new();
    log.add_host("host-a", 1);
    let r = log.revoke("host-a", false);
    log.remove_host("host-a");
    log.add_host("host-a", 2);
    assert!(log.m.host("host-a").is_some());
    // `revoked` if it was: only a readmit authorizes it again.
    assert_eq!(log.state("host-a"), revoked(r));
    assert_eq!(
        log.check(&revoke("host-a", false)),
        invalid(Invalid::AlreadyRevoked)
    );
    assert_eq!(log.check(&readmit("host-a")), Check::Valid);

    // `authorized` if it was, at the same generation: a re-add is no
    // readmit, and envelopes signed before it stay as acceptable as before.
    let b = log.add_host("host-b", 1);
    log.remove_host("host-b");
    log.add_host("host-b", 2);
    assert_eq!(log.state("host-b"), authorized(b));
}

#[test]
fn reverify_keeps_state() {
    let mut log = Log::new();
    let a = log.add_host("host-a", 1);
    // A newer add_host without a removal (`atem pair verify`).
    log.add_host("host-a", 2);
    assert_eq!(log.state("host-a"), authorized(a));
    let r = log.revoke("host-a", false);
    log.add_host("host-a", 3);
    // Re-verification never restores a host sender's authorization.
    assert_eq!(log.state("host-a"), revoked(r));
    let m = log.readmit("host-a");
    log.add_host("host-a", 4);
    assert_eq!(log.state("host-a"), authorized(m));
}

#[test]
fn membership_epoch_changes_only_on_readd() {
    let mut log = Log::new();
    let a1 = log.add_host("host-a", 1);
    let b = log.add_host("host-b", 1);
    assert_eq!(log.epoch("host-a"), Some(a1));
    // Re-verification, revoke and readmit keep it.
    log.add_host("host-a", 2);
    assert_eq!(log.epoch("host-a"), Some(a1));
    log.revoke("host-a", true);
    assert_eq!(log.epoch("host-a"), Some(a1));
    log.readmit("host-a");
    assert_eq!(log.epoch("host-a"), Some(a1));
    // A removed host has none: no add_host follows its last remove_host.
    log.remove_host("host-a");
    assert_eq!(log.epoch("host-a"), None);
    // A re-add after the removal starts a new one, at its own `seq`.
    let a3 = log.add_host("host-a", 3);
    assert_eq!(log.epoch("host-a"), Some(a3));
    assert_ne!(a3, a1);
    log.add_host("host-a", 4);
    assert_eq!(log.epoch("host-a"), Some(a3));
    log.remove_host("host-a");
    let a5 = log.add_host("host-a", 5);
    assert_eq!(log.epoch("host-a"), Some(a5));
    // Other hosts' epochs never move with it.
    assert_eq!(log.epoch("host-b"), Some(b));
    assert_eq!(log.epoch("host-z"), None);
}

#[test]
fn check_change_refuses_redundant_drafts() {
    let mut log = Log::new();
    log.replay = false;
    for i in 0..MAX_HOSTS {
        log.add_host(&format!("host-{i:02}"), 1);
    }
    let host = "host-00";
    let (quiet, interrupt, back) = (revoke(host, false), revoke(host, true), readmit(host));
    let check = |log: &Log, action: &Action| check_change(&log.m, action, log.at);
    // Authorized: a revoke goes ahead (hosts full: it adds no host), a
    // readmit is redundant.
    assert_eq!(check(&log, &quiet), Ok(()));
    assert_eq!(check(&log, &interrupt), Ok(()));
    assert_eq!(check(&log, &back), Err(ChangeRefusal::NotRevoked));
    // A host never added: nothing to readmit (the verifier refuses a revoke
    // of it, `unknown_host`).
    assert_eq!(
        check(&log, &readmit("host-zz")),
        Err(ChangeRefusal::NotRevoked)
    );
    log.revoke(host, false);
    // Revoked: a second revoke is redundant, with or without an interrupt
    // ("also interrupt" later is a control record, not an entry).
    assert_eq!(check(&log, &quiet), Err(ChangeRefusal::AlreadyRevoked));
    assert_eq!(check(&log, &interrupt), Err(ChangeRefusal::AlreadyRevoked));
    assert_eq!(check(&log, &back), Ok(()));
    assert_eq!(ChangeRefusal::AlreadyRevoked.code(), "already_revoked");
    assert_eq!(ChangeRefusal::NotRevoked.code(), "not_revoked");
    assert_eq!(ChangeRefusal::NotRevoked.to_string(), "not_revoked");
    // Never paced: a readmit at once after the revoke, and another revoke
    // at once after it, at any clock.
    log.readmit(host);
    assert_eq!(check_change(&log.m, &quiet, 0), Ok(()));
    assert_eq!(
        check_change(&log.m, &back, 0),
        Err(ChangeRefusal::NotRevoked)
    );
    log.assert_replays();

    // A full log: no entry at all, whatever the state.
    let phone = {
        let mut keys = SoftwareKeys::new();
        Member {
            device_id: "dev-phone".into(),
            auth_key: keys.generate(auth(), Alg::Ed25519).unwrap(),
            kind: MemberKind::Native {
                enc_key: keys.generate(KeyId::new("enc"), Alg::X25519).unwrap(),
                roles: [Role::View].into(),
            },
        }
    };
    log.apply(Action::Add { member: phone });
    let mut toggle = false;
    while log.m.head().seq < MAX_ENTRIES {
        toggle = !toggle;
        let roles = if toggle {
            [Role::Control, Role::View].into()
        } else {
            [Role::View].into()
        };
        let action = Action::SetRoles {
            device_id: "dev-phone".into(),
            change: RolesChange::Native(roles),
        };
        let entry = parse_wire(log.m.draft("dev-mac", log.at, &action)).unwrap();
        log.m.append_unchecked_for_tests(entry, &now(log.at));
    }
    for action in [&quiet, &interrupt, &back] {
        assert_eq!(
            check_change(&log.m, action, log.at),
            Err(ChangeRefusal::LogFull),
            "{action:?}"
        );
    }
}

#[test]
fn effects_name_seq_and_interrupt() {
    let mut log = Log::new();
    log.add_host("host-a", 1);
    let head = |log: &Log| Head {
        seq: log.m.head().seq,
        hash: log.m.head().hash,
    };
    for interrupt_running in [false, true] {
        let effects = log.apply(revoke("host-a", interrupt_running));
        let r = head(&log);
        assert_eq!(
            effects,
            [
                Effect::Appended(r),
                Effect::HostSenderRevoked {
                    host_id: "host-a".into(),
                    seq: r.seq,
                    interrupt_running,
                },
            ]
        );
        let effects = log.apply(readmit("host-a"));
        let m = head(&log);
        assert_eq!(
            effects,
            [
                Effect::Appended(m),
                Effect::HostSenderReadmitted {
                    host_id: "host-a".into(),
                    seq: m.seq,
                },
            ]
        );
    }
    // A removal and a re-add say nothing about sending.
    log.revoke("host-a", false);
    let removal = log.apply(Action::RemoveHost {
        host_id: "host-a".into(),
    });
    assert!(!removal.iter().any(|e| matches!(
        e,
        Effect::HostSenderRevoked { .. } | Effect::HostSenderReadmitted { .. }
    )));
    let readd = log.apply(Action::AddHost {
        host: HostRecord {
            host_id: "host-a".into(),
            host_trust_gen: 2,
            host_key: log.host_key.clone(),
        },
    });
    assert_eq!(
        readd,
        [
            Effect::Appended(head(&log)),
            Effect::HostKeyChanged {
                host_id: "host-a".into()
            },
        ]
    );
}

#[test]
fn host_sender_entries_parse_strictly() {
    let revoke_body = || {
        body(
            json!({"action": "host_sender_revoke", "host_id": "host-a", "interrupt_running": false}),
        )
    };
    let readmit_body = || body(json!({"action": "host_sender_readmit", "host_id": "host-a"}));
    assert!(check_body(&revoke_body()).is_ok());
    assert!(check_body(&readmit_body()).is_ok());
    // Unknown fields: beside them, or another action's.
    for (mut b, field, value) in [
        (revoke_body(), "note", json!("x")),
        (readmit_body(), "interrupt_running", json!(false)),
        (revoke_body(), "name", json!("p")),
        (readmit_body(), "host", json!({})),
    ] {
        b[field] = value;
        assert_eq!(
            check_body(&b).map(|e| e.action),
            Err(Invalid::UnknownField),
            "{field}"
        );
    }
    // Every field is required (`interrupt_running` too: no default) and
    // none is `null`.
    for (b, field) in [
        (revoke_body(), "host_id"),
        (revoke_body(), "interrupt_running"),
        (readmit_body(), "host_id"),
    ] {
        let mut missing = b.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert_eq!(
            check_body(&missing).map(|e| e.action),
            Err(Invalid::Malformed(field)),
            "{field}"
        );
        let mut null = b;
        null[field] = Value::Null;
        assert_eq!(
            parse_wire(null).map(|e| e.action),
            Err(Invalid::Malformed("null")),
            "{field}"
        );
    }
    // Mistyped: a boolean is a JSON boolean, a host id a string.
    for value in [json!("false"), json!(0), json!(1), json!({})] {
        let mut b = revoke_body();
        b["interrupt_running"] = value;
        assert_eq!(
            check_body(&b).map(|e| e.action),
            Err(Invalid::Malformed("interrupt_running"))
        );
    }
    for (b, value) in [
        (revoke_body(), json!(7)),
        (readmit_body(), json!(7)),
        (revoke_body(), json!("")),
        (readmit_body(), json!("host a")),
        (revoke_body(), json!("h".repeat(129))),
        (readmit_body(), json!({"host_id": "host-a"})),
    ] {
        let mut b = b;
        b["host_id"] = value.clone();
        assert_eq!(
            check_body(&b).map(|e| e.action),
            Err(Invalid::Malformed("host_id")),
            "{value}"
        );
    }
    // Arrays only where a set is.
    let mut b = readmit_body();
    b["host_id"] = json!(["host-a"]);
    assert_eq!(
        check_body(&b).map(|e| e.action),
        Err(Invalid::ArrayNotCanonical)
    );
    // The builders refuse what the verifier refuses.
    assert_eq!(
        host_sender_revoke("host a", true, T0),
        Err(Invalid::Malformed("host_id"))
    );
    assert_eq!(
        host_sender_readmit("", T0),
        Err(Invalid::Malformed("host_id"))
    );
}

#[test]
fn host_sender_entries_need_a_native_manager() {
    let mut log = Log::new();
    log.add_host("host-a", 1);
    log.add_host("host-b", 1);
    log.revoke("host-b", false);
    let mut phone_keys = SoftwareKeys::new();
    let phone = Member {
        device_id: "dev-phone".into(),
        auth_key: phone_keys.generate(auth(), Alg::Ed25519).unwrap(),
        kind: MemberKind::Native {
            enc_key: phone_keys.generate(KeyId::new("enc"), Alg::X25519).unwrap(),
            roles: [Role::Control, Role::View].into(),
        },
    };
    log.apply(Action::Add { member: phone });
    // A native member without `manage`.
    for action in [revoke("host-a", true), readmit("host-b")] {
        let body = log.m.draft("dev-phone", log.at, &action);
        let entry = sign_entry(&phone_keys, &auth(), body).unwrap();
        assert_eq!(
            log.m.check_next(&entry),
            invalid(Invalid::SignerNotManager),
            "{action:?}"
        );
    }
    // The recovery key signs only `recovery_add`.
    for fields in [
        json!({"action": "host_sender_revoke", "host_id": "host-a", "interrupt_running": true}),
        json!({"action": "host_sender_readmit", "host_id": "host-b"}),
    ] {
        let mut by_kit = body(fields);
        by_kit["signer"] = json!("recovery");
        assert_eq!(
            check_body(&by_kit).map(|e| e.action),
            Err(Invalid::RecoverySignerAction)
        );
    }
}

#[test]
fn draft_round_trips_through_check_body() {
    let mut log = Log::new();
    log.add_host("host-a", 1);
    let revoke = host_sender_revoke("host-a", false, T0).unwrap();
    assert_eq!(
        revoke,
        Action::HostSenderRevoke {
            host_id: "host-a".into(),
            interrupt_running: false,
        }
    );
    let body = log.m.draft("dev-mac", T0, &revoke);
    // The design's example body (II.3.1), field for field.
    assert_eq!(body["action"], "host_sender_revoke");
    assert_eq!(body["host_id"], "host-a");
    assert_eq!(body["interrupt_running"], false);
    assert_eq!(body.as_object().unwrap().len(), 11);
    assert_eq!(check_body(&body).unwrap().action, revoke);
    let entry = log.sign(&revoke).unwrap();
    assert_eq!(entry.action, revoke);
    assert_eq!(entry.subject(), None);
    // As received: the signed wire bytes parse back to the same entry.
    let again = Entry::parse_bytes(entry.object().to_json().to_string().as_bytes()).unwrap();
    assert_eq!(again, entry);
    let with_interrupt = host_sender_revoke("host-a", true, T0).unwrap();
    assert_eq!(
        log.m.draft("dev-mac", T0, &with_interrupt)["interrupt_running"],
        true
    );

    let readmit = host_sender_readmit("host-a", T0).unwrap();
    assert_eq!(
        readmit,
        Action::HostSenderReadmit {
            host_id: "host-a".into()
        }
    );
    let body = log.m.draft("dev-mac", T0, &readmit);
    assert_eq!(body["action"], "host_sender_readmit");
    assert_eq!(body["host_id"], "host-a");
    assert_eq!(body.as_object().unwrap().len(), 10);
    assert_eq!(check_body(&body).unwrap().action, readmit);
    assert_eq!(revoke.name(), "host_sender_revoke");
    assert_eq!(readmit.name(), "host_sender_readmit");
    assert!(!revoke.is_pending_type() && !readmit.is_pending_type());
}
