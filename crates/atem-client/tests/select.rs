use atem_client::session::select::{AgentLabels, Label, Selector, is_atem_id, selectors_problem};
use std::collections::BTreeSet;

#[test]
fn shared_select_vectors() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("vectors/select.json")).unwrap();
    let labels = vectors["labels"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l.as_str().unwrap().parse().unwrap())
        .collect();
    let agent = AgentLabels {
        atem_id: vectors["atem_id"].as_str().unwrap(),
        route_id: vectors["route_id"].as_str().unwrap(),
        labels: &labels,
    };
    for case in vectors["cases"].as_array().unwrap() {
        assert_eq!(
            case["selector"]
                .as_str()
                .unwrap()
                .parse::<Selector>()
                .unwrap()
                .matches(&agent),
            case["matches"].as_bool().unwrap(),
            "{case}"
        );
    }
    for value in vectors["invalid"].as_array().unwrap() {
        assert!(value.as_str().unwrap().parse::<Selector>().is_err());
    }
}

#[test]
fn labels_and_selectors_parse() {
    for value in [
        "project:a",
        "tag:auth-1",
        "self:tokens",
        "project:a+tag:auth",
        "atem:host-1",
        "atem:host-1/auth",
    ] {
        assert!(value.parse::<Selector>().is_ok(), "{value}");
    }
    for value in [
        "",
        "tag:",
        "self:Tokens",
        "tag:a_b",
        "other:x",
        "tag:é",
        "tag:a+",
        "atem:",
        "atem:h/",
        "atem:h/a/b",
    ] {
        assert!(value.parse::<Selector>().is_err(), "{value}");
    }
    assert!(format!("tag:{}", "a".repeat(33)).parse::<Label>().is_err());
    let label: Label = "self:tokens".parse().unwrap();
    assert_eq!(label.as_str(), "self:tokens");
}

#[test]
fn and_selectors_need_every_label() {
    let mut labels = BTreeSet::from(["project:a".parse().unwrap()]);
    let selector: Selector = "project:a+tag:b".parse().unwrap();
    assert!(!selector.matches(&AgentLabels {
        atem_id: "host-1",
        route_id: "auth",
        labels: &labels
    }));
    labels.insert("tag:b".parse().unwrap());
    assert!(selector.matches(&AgentLabels {
        atem_id: "host-1",
        route_id: "auth",
        labels: &labels
    }));
}

#[test]
fn instance_selectors_match_one_atem_id_and_route() {
    let labels = BTreeSet::new();
    let agent = AgentLabels {
        atem_id: "host-1",
        route_id: "auth",
        labels: &labels,
    };
    for value in ["atem:host-1", "atem:host-1/auth"] {
        assert!(value.parse::<Selector>().unwrap().matches(&agent));
    }
    for value in ["atem:host-2", "atem:host-1/mobile"] {
        assert!(!value.parse::<Selector>().unwrap().matches(&agent));
    }
}

/// `build_atem_id` keeps non-ASCII characters (CJK host names) and ASCII
/// `[A-Za-z0-9-]`; every id it can make must be addressable.
#[test]
fn atem_ids_accept_what_the_relay_identity_builds() {
    for id in [
        "Genie-dc1649f-956631ec",
        "测试主机-1a2b3c4d-956631ec",
        "ホスト-dc1649f-956631ec",
        "x",
    ] {
        assert!(is_atem_id(id), "{id}");
        for value in [format!("atem:{id}"), format!("atem:{id}/auth")] {
            let Selector::Instance { atem_id, .. } = value.parse().unwrap() else {
                panic!("{value}");
            };
            assert_eq!(atem_id, id);
        }
    }
    let labels = BTreeSet::new();
    let selector: Selector = "atem:测试主机-1a2b3c4d-956631ec/auth".parse().unwrap();
    assert!(selector.matches(&AgentLabels {
        atem_id: "测试主机-1a2b3c4d-956631ec",
        route_id: "auth",
        labels: &labels,
    }));
}

#[test]
fn atem_ids_refuse_what_the_selector_grammar_uses() {
    let long = "a".repeat(65);
    for id in [
        "",
        "a:b",
        "a/b",
        "a+b",
        "a b",
        "a\tb",
        "a\nb",
        "a\u{7}b",
        "a\u{3000}b",
        long.as_str(),
    ] {
        assert!(!is_atem_id(id), "{id:?}");
        // `a/b` is the instance `a`, route `b`: the slash is the separator.
        if !id.contains('/') {
            assert!(format!("atem:{id}").parse::<Selector>().is_err(), "{id:?}");
        }
    }
    assert!(is_atem_id(&"主".repeat(64)));
    assert!(!is_atem_id(&"主".repeat(65)));
    // The route id keeps the opaque-id rules.
    assert!("atem:host/a b".parse::<Selector>().is_err());
    assert!("atem:host/".parse::<Selector>().is_err());
}

#[test]
fn a_bad_selector_reports_its_own_reason() {
    let list = |items: &[&str]| items.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    assert_eq!(
        selectors_problem(&list(&["tag:a", "project:b", "tag:Bad"]), 32).as_deref(),
        Some("selector 3: names are 1-32 of a-z, 0-9 and -")
    );
    assert_eq!(
        selectors_problem(&list(&["tag:a", "atem:h/a/b"]), 32).as_deref(),
        Some(
            "selector 2: route ids are letters, digits, `.`, `_`, `:` and `-` (at most 128 bytes)"
        )
    );
    assert_eq!(
        selectors_problem(&list(&["atem:a:b"]), 32).as_deref(),
        Some("selector 1: atem ids are 1-64 characters without spaces, controls, `:`, `/` or `+`")
    );
    assert_eq!(
        selectors_problem(&list(&["other:x"]), 32).as_deref(),
        Some("selector 1: labels are project:, tag: or self:")
    );
    assert_eq!(
        selectors_problem(&[], 32).as_deref(),
        Some("a message needs 1 to 16 selectors")
    );
    let many = vec!["tag:a".to_string(); 17];
    assert_eq!(
        selectors_problem(&many, 32).as_deref(),
        Some("a message needs 1 to 16 selectors")
    );
    assert_eq!(
        selectors_problem(&list(&["tag:a"]), 33).as_deref(),
        Some("the budget is 1 to 32 agents")
    );
    assert_eq!(selectors_problem(&list(&["tag:a", "atem:h/r"]), 32), None);
}
