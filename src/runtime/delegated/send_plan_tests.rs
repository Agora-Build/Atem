// The sending host's plan (design II.6; host-work-v1 §11.5, "`select`
// from host senders"): a list of this host `a`, hosts `b` and `c` with
// keys, `d` without one; project `build` lists a, b, c with a task's ops
// and launch, `docs` lists a and d, `notes` a and b with `message` only,
// `far` b and c (not a).
use super::*;
use crate::session_protocol::membership::r9log::{MAC, TestLog, secret};
use atem_client::membership::{host_enc_key, project_set, sign_host_enc_key};
use atem_client::{KeyId, KeyProvider, SoftwareKeys};

const ME: Me<'static> = Me {
    host_id: "a",
    atem_id: "a",
    host_trust_gen: 1,
};

/// `host`'s encryption key in `log` (its `enc_sig` by its host key, seeded
/// by `host`).
pub(crate) fn add_enc(log: &mut TestLog, host: &str) -> PublicKey {
    let mut keys = SoftwareKeys::new();
    let (host_key, enc) = (KeyId::new("host"), KeyId::new("enc"));
    keys.insert_ed25519(host_key.clone(), &secret(host));
    keys.insert_x25519(enc.clone(), &secret(&format!("{host} enc")));
    let enc_key = keys.public_key(&enc).unwrap();
    let genesis = log.genesis_hash();
    let sig = sign_host_enc_key(
        &keys,
        &host_key,
        &log.account.clone(),
        &genesis,
        host,
        1,
        enc_key.as_32().unwrap(),
    )
    .unwrap();
    log.append(
        MAC,
        host_enc_key(host, 1, &enc_key, &sig, false, 0).unwrap(),
    );
    enc_key
}

fn list() -> TestLog {
    let mut log = TestLog::genesis("acct", &secret("plan astation"));
    for host in ["a", "b", "c", "d"] {
        log.add_host(host, 1, &secret(host));
    }
    for host in ["a", "b", "c"] {
        add_enc(&mut log, host);
    }
    let task = [ProjectOp::Message, ProjectOp::Notify, ProjectOp::Prompt];
    let launch = [task.as_slice(), &[ProjectOp::Launch]].concat();
    for (name, hosts, ops) in [
        ("build", &["a", "b", "c"][..], &launch[..]),
        ("docs", &["a", "d"], &task),
        ("notes", &["a", "b"], &[ProjectOp::Message]),
        ("far", &["b", "c"], &task),
    ] {
        log.append(
            MAC,
            project_set(name, hosts.iter().copied(), ops.iter().copied(), 0).unwrap(),
        );
    }
    log
}

fn to(selectors: &[&str]) -> Vec<String> {
    selectors.iter().map(|s| s.to_string()).collect()
}

/// (host, selectors, budget, launch) of each planned host.
fn remote(plan: &Plan) -> Vec<(&str, Vec<&str>, u32, bool)> {
    plan.remote
        .iter()
        .map(|t| {
            (
                t.host_id.as_str(),
                t.selectors.iter().map(String::as_str).collect(),
                t.budget,
                t.launch,
            )
        })
        .collect()
}

/// Each selector form: `atem:` of another host (and a route), `project:`
/// fan-out with labels riding along, several `project:` terms, this
/// host's own `atem:`, and labels alone (local only).
#[test]
fn each_selector_form_plans_its_hosts() {
    let log = list();
    let plan_of = |s: &[&str]| plan(&log.log, ME, &to(s), false).unwrap();
    let p = plan_of(&["atem:b/auth"]);
    assert_eq!(p.local, None);
    assert_eq!(remote(&p), [("b", vec!["atem:b/auth"], 32, false)]);
    let target = &p.remote[0];
    assert_eq!(target.host_trust_gen, 1);
    let key = log.log.host_enc_key("b").unwrap();
    assert_eq!(target.enc_key, key.current.key);
    assert_eq!(
        target.enc_kid,
        atem_client::keys::enc_kid(&key.current.key).unwrap()
    );
    let p = plan_of(&["project:build+tag:auth"]);
    assert_eq!(p.local, Some(11));
    assert_eq!(
        remote(&p),
        [
            ("b", vec!["project:build+tag:auth"], 11, false),
            ("c", vec!["project:build+tag:auth"], 10, false),
        ]
    );
    // Every named project's hosts: `build` and `notes` share only b.
    let p = plan_of(&["project:build+project:notes"]);
    assert_eq!(
        remote(&p),
        [("b", vec!["project:build+project:notes"], 16, false)]
    );
    let p = plan_of(&["atem:a", "tag:auth", "self:tokens"]);
    assert_eq!(
        p,
        Plan {
            local: Some(32),
            remote: vec![]
        }
    );
    // A project that doesn't list this host reaches no other host.
    assert_eq!(plan_of(&["project:far"]).remote, vec![]);
    assert_eq!(plan_of(&["project:nothing"]).remote, vec![]);
    // Selectors that plan the same host are its selectors, in order.
    let p = plan_of(&["atem:b", "project:build", "atem:c/r"]);
    assert_eq!(
        remote(&p),
        [
            ("b", vec!["atem:b", "project:build"], 11, false),
            ("c", vec!["project:build", "atem:c/r"], 10, false),
        ]
    );
    assert_eq!(p.local, Some(11));
}

#[test]
fn an_unknown_host_is_refused() {
    let log = list();
    assert_eq!(
        plan(&log.log, ME, &to(&["atem:z/auth"]), false),
        Err("atem:z: no current host of this account's device list has that id".into())
    );
}

#[test]
fn a_host_without_a_key_is_refused() {
    let log = list();
    for selectors in [&["atem:d"][..], &["project:docs"]] {
        assert_eq!(
            plan(&log.log, ME, &to(selectors), false),
            Err("host d has no encryption key in the device list yet; it can't receive messages from other hosts".into()),
            "{selectors:?}"
        );
    }
}

#[test]
fn a_host_no_project_covers_is_refused() {
    let mut log = list();
    for host in ["e", "f"] {
        log.add_host(host, 1, &secret(host));
        add_enc(&mut log, host);
    }
    // f shares a project granting `message` only; e shares none.
    log.append(
        MAC,
        project_set("memo", ["a", "f"], [ProjectOp::Message], 0).unwrap(),
    );
    for (selector, host) in [("atem:e", "e"), ("atem:f/r", "f"), ("project:memo", "f")] {
        assert_eq!(
            plan(&log.log, ME, &to(&[selector]), false),
            Err(format!(
                "no signed project of this host and {host} grants message, notify and prompt"
            )),
            "{selector}"
        );
    }
    // b's `notes` grants only `message`, but `build` grants a task.
    assert!(plan(&log.log, ME, &to(&["project:notes"]), false).is_ok());
}

/// `--launch` needs an `atem:<id>/<route>` naming this host or a planned
/// one; a remote host's recipient carries it only when such a selector
/// names it, and needs the project's `launch` op.
#[test]
fn launch_needs_an_atem_selector_with_a_route() {
    let mut log = list();
    for selectors in [&["project:build"][..], &["atem:b"], &["tag:auth"]] {
        assert_eq!(
            plan(&log.log, ME, &to(selectors), true),
            Err(LAUNCH_NEEDS_ROUTE.into()),
            "{selectors:?}"
        );
    }
    let p = plan(&log.log, ME, &to(&["atem:b/auth", "project:build"]), true).unwrap();
    assert_eq!(
        remote(&p),
        [
            ("b", vec!["atem:b/auth", "project:build"], 11, true),
            ("c", vec!["project:build"], 10, false),
        ]
    );
    // This host's own route: a local launch, no remote one.
    let p = plan(&log.log, ME, &to(&["atem:a/auth", "atem:b"]), true).unwrap();
    assert_eq!(remote(&p), [("b", vec!["atem:b"], 16, false)]);
    // A host whose projects grant no launch.
    log.append(
        MAC,
        project_set(
            "build",
            ["a", "b", "c"],
            [ProjectOp::Message, ProjectOp::Notify, ProjectOp::Prompt],
            0,
        )
        .unwrap(),
    );
    assert_eq!(
        plan(&log.log, ME, &to(&["atem:b/auth"]), true),
        Err("no signed project of this host and b grants launch".into())
    );
}

/// A send that reaches this host's agents and others' at once: one budget
/// of 32 across every part, the local part first.
#[test]
fn a_mixed_send_splits_one_budget() {
    let log = list();
    let p = plan(&log.log, ME, &to(&["tag:auth", "atem:b", "atem:c"]), false).unwrap();
    assert_eq!(p.local, Some(11));
    assert_eq!(
        remote(&p),
        [
            ("b", vec!["atem:b"], 11, false),
            ("c", vec!["atem:c"], 10, false),
        ]
    );
    let total: u32 = p.local.unwrap() + p.remote.iter().map(|t| t.budget).sum::<u32>();
    assert_eq!(total, 32);
    let p = plan(&log.log, ME, &to(&["atem:b", "atem:c"]), false).unwrap();
    assert_eq!(p.local, None);
    assert_eq!(p.remote.iter().map(|t| t.budget).sum::<u32>(), 32);
}

/// More hosts than agents: each part needs one.
#[test]
fn more_than_32_parts_are_refused() {
    let mut log = list();
    let mut hosts = vec!["a".to_string()];
    for n in 0..32 {
        let host = format!("h{n}");
        log.add_host(&host, 1, &secret(&host));
        add_enc(&mut log, &host);
        hosts.push(host);
    }
    log.append(
        MAC,
        project_set(
            "wide",
            hosts.iter().map(String::as_str),
            [ProjectOp::Message, ProjectOp::Notify, ProjectOp::Prompt],
            0,
        )
        .unwrap(),
    );
    assert_eq!(
        plan(&log.log, ME, &to(&["atem:h0", "atem:h1"]), false).map(|p| p.remote.len()),
        Ok(2)
    );
    assert_eq!(
        plan(&log.log, ME, &to(&["project:wide"]), false),
        Err("a message reaches the agents of at most 32 hosts; this one plans 33".into())
    );
}

/// This host signs only as a current host at its own generation,
/// `authorized`; a local-only send needs neither.
#[test]
fn this_host_must_be_authorized_to_send_to_others() {
    let mut log = list();
    let stale = Me {
        host_trust_gen: 2,
        ..ME
    };
    assert_eq!(
        plan(&log.log, stale, &to(&["atem:b"]), false),
        Err("this host isn't a current host of its device list at trust generation 2; it can't send to other hosts".into())
    );
    assert!(plan(&log.log, stale, &to(&["tag:auth"]), false).is_ok());
    log.append(
        MAC,
        atem_client::membership::host_sender_revoke("a", false, 0).unwrap(),
    );
    assert_eq!(
        plan(&log.log, ME, &to(&["atem:b"]), false),
        Err("this host is revoked as a host sender (host_sender_revoke); a native manager readmits it".into())
    );
}
