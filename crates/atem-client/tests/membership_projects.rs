//! Signed project grants in the device list (delegated host-work design
//! II.2.2): `project_set` and `project_remove`, through the public API the
//! way a host or a managing device drives the verifier. Each test builds its
//! own log with its own software keys.
use std::collections::BTreeSet;

use atem_client::encoding::{Hash32, b64u};
use atem_client::membership::{
    Action, ChangeRefusal, Check, Effect, Entry, HostNow, HostRecord, Invalid, MAX_ENTRIES,
    MAX_HOSTS, Member, MemberKind, Membership, Project, ProjectOp, Role, RolesChange, check_body,
    check_change, draft_on, project_remove, project_set, sign_entry,
};
use atem_client::{Alg, KeyId, PublicKey, SoftwareKeys};
use serde_json::{Value, json};

const ACCOUNT: &str = "acct-projects";
const ALL: [Role; 3] = [Role::Control, Role::Manage, Role::View];
const T0: u64 = 1_793_620_800_000;
const EVERY_OP: [ProjectOp; 4] = [
    ProjectOp::Launch,
    ProjectOp::Message,
    ProjectOp::Notify,
    ProjectOp::Prompt,
];

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

/// A log on one verifier: `dev-mac` (a native manager, Ed25519) signs
/// every entry; every host shares one host key (nothing here checks it).
struct Log {
    m: Membership,
    mac: SoftwareKeys,
    host_key: PublicKey,
    at: u64,
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
        eval.effects
    }

    fn add_host(&mut self, host_id: &str, host_trust_gen: u64) {
        self.apply(Action::AddHost {
            host: HostRecord {
                host_id: host_id.into(),
                host_trust_gen,
                host_key: self.host_key.clone(),
            },
        });
    }

    fn remove_host(&mut self, host_id: &str) {
        self.apply(Action::RemoveHost {
            host_id: host_id.into(),
        });
    }

    fn set(&mut self, name: &str, hosts: &[&str], ops: &[ProjectOp]) -> Vec<Effect> {
        let action = project_set(name, hosts.iter().copied(), ops.iter().copied(), self.at)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        self.apply(action)
    }

    /// The stored form reads back as the same state, and a fresh verifier
    /// of the same entries derives the same projects (both replay them).
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
        let projects = |m: &Membership| m.projects().cloned().collect::<Vec<_>>();
        assert_eq!(projects(&fresh.membership), projects(&self.m));
        for host in ["host-a", "host-b", "host-c", "host-d"] {
            assert_eq!(
                fresh.membership.host_projects(host),
                self.m.host_projects(host)
            );
        }
    }
}

fn ops(list: &[ProjectOp]) -> BTreeSet<ProjectOp> {
    list.iter().copied().collect()
}

fn hosts(n: usize) -> Vec<String> {
    (0..n).map(|i| format!("host-{i:02}")).collect()
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

fn project_body(project: Value) -> Value {
    body(json!({"action": "project_set", "project": project}))
}

/// Parsed as received: the wire bytes `{"body", "sig"}`.
fn parse_wire(body: Value) -> Result<Entry, Invalid> {
    let wire = json!({"body": body, "sig": b64u(&[0u8; 64])});
    Entry::parse_bytes(wire.to_string().as_bytes())
}

#[test]
fn project_set_valid_and_replaces_whole_state() {
    let mut log = Log::new();
    for host in ["host-a", "host-b", "host-c"] {
        log.add_host(host, 1);
    }
    let effects = log.set("astation", &["host-a", "host-b"], &EVERY_OP);
    assert_eq!(
        effects.last(),
        Some(&Effect::ProjectSet {
            name: "astation".into()
        })
    );
    assert_eq!(
        log.m.project("astation"),
        Some(&Project {
            name: "astation".into(),
            hosts: vec!["host-a".into(), "host-b".into()],
            ops: EVERY_OP.to_vec(),
        })
    );
    assert_eq!(log.m.host_projects("host-a"), ["astation"]);
    assert_eq!(log.m.host_projects("host-b"), ["astation"]);
    assert!(log.m.host_projects("host-c").is_empty());
    assert_eq!(
        log.m.project_ops_between("host-a", "host-b"),
        ops(&EVERY_OP)
    );
    log.assert_replays();

    // The body is the project's whole new state: another host list and
    // fewer ops replace both, nothing is merged.
    let effects = log.set("astation", &["host-b", "host-c"], &[ProjectOp::Message]);
    assert!(effects.contains(&Effect::ProjectSet {
        name: "astation".into()
    }));
    let project = log.m.project("astation").unwrap();
    assert_eq!(project.hosts, ["host-b", "host-c"]);
    assert_eq!(project.ops, [ProjectOp::Message]);
    assert_eq!(log.m.projects().count(), 1);
    assert!(log.m.host_projects("host-a").is_empty());
    assert_eq!(log.m.host_projects("host-c"), ["astation"]);
    assert!(log.m.project_ops_between("host-a", "host-b").is_empty());
    assert_eq!(
        log.m.project_ops_between("host-b", "host-c"),
        ops(&[ProjectOp::Message])
    );
    // The same state again is a valid entry too (it takes an entry).
    assert_eq!(
        log.check(&project_set("astation", ["host-b", "host-c"], [ProjectOp::Message], 0).unwrap()),
        Check::Valid
    );
    log.assert_replays();
}

#[test]
fn project_name_grammar() {
    let set = |name: &str| project_set(name, ["host-a", "host-b"], [ProjectOp::Launch], T0);
    for bad in [
        String::new(),
        "a".repeat(33),
        "Astation".into(),
        "astation_1".into(),
        "astation.1".into(),
        "astation 1".into(),
        "astatión".into(),
    ] {
        assert_eq!(set(&bad), Err(Invalid::BadProject), "{bad:?}");
        assert_eq!(
            project_remove(&bad, T0),
            Err(Invalid::BadProject),
            "{bad:?}"
        );
    }
    for good in [
        "a",
        "0",
        "-",
        "astation-2",
        &"z9-".repeat(10),
        &"a".repeat(32),
    ] {
        assert!(set(good).is_ok(), "{good:?}");
        assert!(project_remove(good, T0).is_ok(), "{good:?}");
    }
    assert_eq!(Invalid::BadProject.code(), "bad_project");
    // The same rule on received bytes.
    assert_eq!(
        check_body(&project_body(
            json!({"name": "Astation", "hosts": ["host-a", "host-b"], "ops": ["launch"]})
        ))
        .map(|e| e.action),
        Err(Invalid::BadProject)
    );
    assert_eq!(
        check_body(&body(json!({"action": "project_remove", "name": ""}))).map(|e| e.action),
        Err(Invalid::BadProject)
    );
}

#[test]
fn hosts_set_of_2_to_64_current_hosts() {
    let launch = [ProjectOp::Launch];
    // Shape: 2 to 64 hosts, each an id.
    assert_eq!(
        project_set("p", ["host-a"], launch, T0),
        Err(Invalid::BadProject)
    );
    assert_eq!(
        project_set("p", Vec::<String>::new(), launch, T0),
        Err(Invalid::BadProject)
    );
    assert_eq!(
        project_set("p", hosts(65), launch, T0),
        Err(Invalid::BadProject)
    );
    assert_eq!(
        project_set("p", ["host-a", "host/b"], launch, T0),
        Err(Invalid::BadProject)
    );
    assert_eq!(MAX_HOSTS, 64);

    // A set on the wire: sorted by bytes, no duplicates.
    for list in [json!(["host-a", "host-a"]), json!(["host-b", "host-a"])] {
        assert_eq!(
            check_body(&project_body(
                json!({"name": "p", "hosts": list, "ops": ["launch"]})
            ))
            .map(|e| e.action),
            Err(Invalid::ArrayNotCanonical),
            "{list}"
        );
    }
    // A hand-built action out of order fails at signing, as the verifier
    // would refuse it.
    let mut log = Log::new();
    let unsorted = Action::ProjectSet {
        project: Project {
            name: "p".into(),
            hosts: vec!["host-b".into(), "host-a".into()],
            ops: vec![ProjectOp::Launch],
        },
    };
    assert_eq!(log.sign(&unsorted), Err(Invalid::ArrayNotCanonical));
    // The builder takes any order and repeats: a set.
    let Action::ProjectSet { project } =
        project_set("p", ["host-b", "host-a", "host-b"], launch, T0).unwrap()
    else {
        panic!("a project_set");
    };
    assert_eq!(project.hosts, ["host-a", "host-b"]);

    // Each one current at seq-1: an add_host and no later remove_host.
    for host in ["host-a", "host-b", "host-c"] {
        log.add_host(host, 1);
    }
    log.remove_host("host-c");
    let refused = |log: &Log, list: &[&str]| {
        log.check(&project_set("p", list.iter().copied(), launch, T0).unwrap())
    };
    assert_eq!(
        refused(&log, &["host-a", "host-c"]),
        Check::Invalid(Invalid::NotAHost)
    );
    assert_eq!(
        refused(&log, &["host-a", "host-z"]),
        Check::Invalid(Invalid::NotAHost)
    );
    assert_eq!(refused(&log, &["host-a", "host-b"]), Check::Valid);

    // 64 current hosts, the most a log holds and a project lists.
    let mut log = Log::new();
    for host in hosts(MAX_HOSTS) {
        log.add_host(&host, 1);
    }
    let effects = log.apply(project_set("all", hosts(MAX_HOSTS), launch, log.at).unwrap());
    assert!(effects.contains(&Effect::ProjectSet { name: "all".into() }));
    assert_eq!(log.m.project("all").unwrap().hosts.len(), 64);
    assert_eq!(log.m.host_projects("host-63"), ["all"]);
}

#[test]
fn notify_needs_message_and_prompt() {
    use ProjectOp::*;
    let set = |list: &[ProjectOp]| project_set("p", ["host-a", "host-b"], list.iter().copied(), T0);
    for bad in [
        &[Notify][..],
        &[Message, Notify],
        &[Notify, Prompt],
        &[Launch, Notify],
        &[Launch, Message, Notify],
    ] {
        assert_eq!(set(bad), Err(Invalid::BadProject), "{bad:?}");
    }
    for good in [
        &[Message, Notify, Prompt][..],
        &EVERY_OP,
        &[Launch],
        &[Message],
        &[Prompt],
        &[Message, Prompt],
    ] {
        let Action::ProjectSet { project } = set(good).unwrap() else {
            panic!("a project_set");
        };
        assert_eq!(project.ops, good);
    }
    // On received bytes too.
    assert_eq!(
        check_body(&project_body(
            json!({"name": "p", "hosts": ["host-a", "host-b"], "ops": ["message", "notify"]})
        ))
        .map(|e| e.action),
        Err(Invalid::BadProject)
    );
}

#[test]
fn ops_empty_or_unknown_refused() {
    assert_eq!(
        project_set("p", ["host-a", "host-b"], [], T0),
        Err(Invalid::BadProject)
    );
    // Wire names, in canonical (byte) order.
    assert_eq!(
        EVERY_OP.map(ProjectOp::as_str),
        ["launch", "message", "notify", "prompt"]
    );
    for op in EVERY_OP {
        assert_eq!(ProjectOp::parse(op.as_str()), Some(op));
    }
    // A service op that isn't a project op, an unknown one, none, or a
    // name of another case.
    for list in [
        json!([]),
        json!(["fly"]),
        json!(["launch", "view"]),
        json!(["approval", "launch"]),
        json!(["Launch"]),
    ] {
        assert_eq!(
            check_body(&project_body(
                json!({"name": "p", "hosts": ["host-a", "host-b"], "ops": list})
            ))
            .map(|e| e.action),
            Err(Invalid::BadProject),
            "{list}"
        );
    }
    assert_eq!(
        check_body(&project_body(
            json!({"name": "p", "hosts": ["host-a", "host-b"], "ops": ["prompt", "launch"]})
        ))
        .map(|e| e.action),
        Err(Invalid::ArrayNotCanonical)
    );
}

#[test]
fn project_remove_needs_project_in_effect() {
    let mut log = Log::new();
    log.add_host("host-a", 1);
    log.add_host("host-b", 1);
    let remove = |name: &str| project_remove(name, T0).unwrap();
    assert_eq!(
        log.check(&remove("astation")),
        Check::Invalid(Invalid::NotAProject)
    );
    assert_eq!(Invalid::NotAProject.code(), "not_a_project");
    log.set("astation", &["host-a", "host-b"], &[ProjectOp::Launch]);
    log.set("chisel", &["host-a", "host-b"], &[ProjectOp::Message]);
    assert_eq!(
        log.check(&remove("atem")),
        Check::Invalid(Invalid::NotAProject)
    );
    let effects = log.apply(remove("astation"));
    assert_eq!(
        effects.last(),
        Some(&Effect::ProjectRemoved {
            name: "astation".into()
        })
    );
    assert_eq!(log.m.project("astation"), None);
    assert_eq!(log.m.host_projects("host-a"), ["chisel"]);
    assert_eq!(
        log.m.project_ops_between("host-a", "host-b"),
        ops(&[ProjectOp::Message])
    );
    assert_eq!(
        log.check(&remove("astation")),
        Check::Invalid(Invalid::NotAProject)
    );
    log.assert_replays();
    // A removed project's name can be set again.
    log.set("astation", &["host-a", "host-b"], &[ProjectOp::Prompt]);
    assert_eq!(
        log.m.project_ops_between("host-a", "host-b"),
        ops(&[ProjectOp::Message, ProjectOp::Prompt])
    );
    log.assert_replays();
}

#[test]
fn remove_host_ends_membership() {
    let mut log = Log::new();
    for host in ["host-a", "host-b", "host-c"] {
        log.add_host(host, 1);
    }
    log.set("p", &["host-a", "host-b", "host-c"], &[ProjectOp::Launch]);
    log.set("q", &["host-b", "host-c"], &[ProjectOp::Message]);
    log.remove_host("host-c");
    // Out of every project at once; the projects stay, as signed.
    assert!(log.m.host_projects("host-c").is_empty());
    assert_eq!(log.m.project_hosts("p"), ["host-a", "host-b"]);
    assert_eq!(log.m.project_hosts("q"), ["host-b"]);
    assert_eq!(
        log.m.project("p").unwrap().hosts,
        ["host-a", "host-b", "host-c"]
    );
    assert!(log.m.project_ops_between("host-a", "host-c").is_empty());
    assert!(log.m.project_ops_between("host-b", "host-c").is_empty());
    assert_eq!(
        log.m.project_ops_between("host-a", "host-b"),
        ops(&[ProjectOp::Launch])
    );
    assert_eq!(log.m.host_projects("host-b"), ["p", "q"]);
    log.assert_replays();
    // A project with one host left grants nothing, and is still in effect:
    // it can be removed.
    log.remove_host("host-b");
    assert!(log.m.project_ops_between("host-a", "host-b").is_empty());
    assert_eq!(log.m.host_projects("host-a"), ["p"]);
    assert!(log.m.project_hosts("q").is_empty());
    assert_eq!(log.m.projects().count(), 2);
    log.assert_replays();
    log.apply(project_remove("q", log.at).unwrap());
    assert_eq!(log.m.projects().count(), 1);
}

#[test]
fn readded_host_needs_new_project_set() {
    let mut log = Log::new();
    log.add_host("host-a", 1);
    log.add_host("host-b", 1);
    log.set("p", &["host-a", "host-b"], &EVERY_OP);
    log.remove_host("host-b");
    log.add_host("host-b", 2);
    assert!(log.m.host("host-b").is_some());
    // Current again, but no project counts it until one lists it anew.
    assert!(log.m.host_projects("host-b").is_empty());
    assert_eq!(log.m.project_hosts("p"), ["host-a"]);
    assert!(log.m.project_ops_between("host-a", "host-b").is_empty());
    log.assert_replays();
    log.set("p", &["host-a", "host-b"], &EVERY_OP);
    assert_eq!(log.m.host_projects("host-b"), ["p"]);
    assert_eq!(
        log.m.project_ops_between("host-a", "host-b"),
        ops(&EVERY_OP)
    );
    log.assert_replays();
}

#[test]
fn reverified_host_keeps_membership() {
    let mut log = Log::new();
    log.add_host("host-a", 1);
    log.add_host("host-b", 1);
    log.set(
        "p",
        &["host-a", "host-b"],
        &[ProjectOp::Message, ProjectOp::Prompt],
    );
    // A newer add_host without a removal: `atem pair verify`.
    log.add_host("host-b", 2);
    assert_eq!(log.m.host("host-b").unwrap().host_trust_gen, 2);
    assert_eq!(log.m.host_projects("host-b"), ["p"]);
    assert_eq!(log.m.project_hosts("p"), ["host-a", "host-b"]);
    assert_eq!(
        log.m.project_ops_between("host-b", "host-a"),
        ops(&[ProjectOp::Message, ProjectOp::Prompt])
    );
    log.assert_replays();
}

#[test]
fn project_ops_between_is_union_of_current_projects() {
    use ProjectOp::*;
    let mut log = Log::new();
    for host in ["host-a", "host-b", "host-c", "host-d"] {
        log.add_host(host, 1);
    }
    log.set("p1", &["host-a", "host-b"], &[Launch]);
    log.set("p2", &["host-a", "host-b", "host-c"], &[Message]);
    log.set("p3", &["host-b", "host-c"], &[Message, Notify, Prompt]);
    let between = |log: &Log, a: &str, b: &str| log.m.project_ops_between(a, b);
    assert_eq!(between(&log, "host-a", "host-b"), ops(&[Launch, Message]));
    // Both ways: every host it lists may send to every other one.
    assert_eq!(between(&log, "host-b", "host-a"), ops(&[Launch, Message]));
    assert_eq!(
        between(&log, "host-b", "host-c"),
        ops(&[Message, Notify, Prompt])
    );
    assert_eq!(between(&log, "host-a", "host-c"), ops(&[Message]));
    // No project lists both; a host and itself; a host never added.
    assert!(between(&log, "host-a", "host-d").is_empty());
    assert!(between(&log, "host-a", "host-a").is_empty());
    assert!(between(&log, "host-a", "host-z").is_empty());
    assert_eq!(log.m.host_projects("host-b"), ["p1", "p2", "p3"]);
    assert!(log.m.host_projects("host-d").is_empty());
    assert_eq!(
        log.m
            .projects()
            .map(|p| p.name.as_str())
            .collect::<Vec<_>>(),
        ["p1", "p2", "p3"]
    );
    // A removed project, a narrowed one.
    log.apply(project_remove("p2", log.at).unwrap());
    assert!(between(&log, "host-a", "host-c").is_empty());
    assert_eq!(between(&log, "host-a", "host-b"), ops(&[Launch]));
    log.set("p3", &["host-b", "host-c"], &[Prompt]);
    assert_eq!(between(&log, "host-c", "host-b"), ops(&[Prompt]));
    log.assert_replays();
}

#[test]
fn unknown_field_and_null_refused() {
    let project = || json!({"name": "p", "hosts": ["host-a", "host-b"], "ops": ["launch"]});
    assert!(check_body(&project_body(project())).is_ok());
    // An unknown field inside `project`, beside it, or another action's.
    let mut extra = project();
    extra["note"] = json!("x");
    assert_eq!(
        check_body(&project_body(extra)).map(|e| e.action),
        Err(Invalid::UnknownField)
    );
    let mut beside = project_body(project());
    beside["name"] = json!("p");
    assert_eq!(
        check_body(&beside).map(|e| e.action),
        Err(Invalid::UnknownField)
    );
    assert_eq!(
        check_body(&body(
            json!({"action": "project_remove", "name": "p", "project": project()})
        ))
        .map(|e| e.action),
        Err(Invalid::UnknownField)
    );
    assert_eq!(
        check_body(&body(
            json!({"action": "project_remove", "name": "p", "host_id": "host-a"})
        ))
        .map(|e| e.action),
        Err(Invalid::UnknownField)
    );
    // Every field is required; none is `null`.
    for field in ["name", "hosts", "ops"] {
        let mut missing = project();
        missing.as_object_mut().unwrap().remove(field);
        assert!(
            matches!(
                check_body(&project_body(missing)).map(|e| e.action),
                Err(Invalid::Malformed(_))
            ),
            "{field}"
        );
        let mut null = project();
        null[field] = Value::Null;
        assert_eq!(
            parse_wire(project_body(null)).map(|e| e.action),
            Err(Invalid::Malformed("null")),
            "{field}"
        );
    }
    assert_eq!(
        parse_wire(project_body(Value::Null)).map(|e| e.action),
        Err(Invalid::Malformed("null"))
    );
    assert_eq!(
        parse_wire(body(json!({"action": "project_remove", "name": null}))).map(|e| e.action),
        Err(Invalid::Malformed("null"))
    );
    assert!(matches!(
        check_body(&body(json!({"action": "project_remove"}))).map(|e| e.action),
        Err(Invalid::Malformed(_))
    ));
    // Mistyped.
    for (field, value) in [
        ("name", json!(7)),
        ("hosts", json!("host-a")),
        ("ops", json!({"launch": true})),
    ] {
        let mut mistyped = project();
        mistyped[field] = value;
        assert!(check_body(&project_body(mistyped)).is_err(), "{field}");
    }
    assert!(check_body(&project_body(json!(["p"]))).is_err());
    // Arrays only where a project's sets are.
    assert_eq!(
        check_body(&body(json!({"action": "project_remove", "name": ["p"]}))).map(|e| e.action),
        Err(Invalid::ArrayNotCanonical)
    );
}

#[test]
fn project_entries_need_a_native_manager() {
    let mut log = Log::new();
    log.add_host("host-a", 1);
    log.add_host("host-b", 1);
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
    log.set("p", &["host-a", "host-b"], &[ProjectOp::Launch]);
    // A native member without `manage`.
    for action in [
        project_set("q", ["host-a", "host-b"], [ProjectOp::Launch], T0).unwrap(),
        project_remove("p", T0).unwrap(),
    ] {
        let body = log.m.draft("dev-phone", log.at, &action);
        let entry = sign_entry(&phone_keys, &auth(), body).unwrap();
        assert_eq!(
            log.m.check_next(&entry),
            Check::Invalid(Invalid::SignerNotManager),
            "{action:?}"
        );
    }
    // The recovery key signs only `recovery_add`.
    let mut by_kit = body(json!({"action": "project_remove", "name": "p"}));
    by_kit["signer"] = json!("recovery");
    assert_eq!(
        check_body(&by_kit).map(|e| e.action),
        Err(Invalid::RecoverySignerAction)
    );
}

#[test]
fn draft_round_trips_through_check_body() {
    let mut log = Log::new();
    log.add_host("host-a", 1);
    log.add_host("host-b", 1);
    let set = project_set("astation", ["host-a", "host-b"], EVERY_OP, T0).unwrap();
    let body = log.m.draft("dev-mac", T0, &set);
    // The design's example body (II.2.2), field for field.
    assert_eq!(body["action"], "project_set");
    assert_eq!(
        body["project"],
        json!({"name": "astation", "hosts": ["host-a", "host-b"],
               "ops": ["launch", "message", "notify", "prompt"]})
    );
    assert_eq!(check_body(&body).unwrap().action, set);
    let entry = log.sign(&set).unwrap();
    assert_eq!(entry.action, set);
    assert_eq!(entry.subject(), None);
    // As received: the signed wire bytes parse back to the same entry.
    let again = Entry::parse_bytes(entry.object().to_json().to_string().as_bytes()).unwrap();
    assert_eq!(again, entry);

    let remove = project_remove("astation", T0).unwrap();
    assert_eq!(
        remove,
        Action::ProjectRemove {
            name: "astation".into()
        }
    );
    let body = log.m.draft("dev-mac", T0, &remove);
    assert_eq!(body["action"], "project_remove");
    assert_eq!(body["name"], "astation");
    assert_eq!(check_body(&body).unwrap().action, remove);
    assert_eq!(set.name(), "project_set");
    assert_eq!(remove.name(), "project_remove");
    assert!(!set.is_pending_type() && !remove.is_pending_type());
}

#[test]
fn check_change_counts_capacity_only() {
    let mut log = Log::new();
    for host in hosts(MAX_HOSTS) {
        log.add_host(&host, 1);
    }
    let pair = || hosts(2);
    let set = project_set("p", pair(), [ProjectOp::Launch], log.at).unwrap();
    // Hosts full: a project adds no host.
    assert_eq!(check_change(&log.m, &set, log.at), Ok(()));
    log.apply(set.clone());
    // Never paced: the same project again at once, a narrowing, a widening,
    // a removal.
    let wider = project_set("p", hosts(3), EVERY_OP, log.at).unwrap();
    let remove = project_remove("p", log.at).unwrap();
    for action in [&set, &wider, &remove] {
        assert_eq!(check_change(&log.m, action, log.at), Ok(()), "{action:?}");
        assert_eq!(check_change(&log.m, action, 0), Ok(()), "{action:?}");
    }
    // A full log: no entry at all.
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
    for action in [&set, &wider, &remove] {
        assert_eq!(
            check_change(&log.m, action, log.at),
            Err(ChangeRefusal::LogFull),
            "{action:?}"
        );
    }
}
