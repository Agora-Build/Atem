use atem_client::session::select::{AgentLabels, Label, Selector};
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
