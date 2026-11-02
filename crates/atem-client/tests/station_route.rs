use atem_client::station_route::{Accepted, Message, Offer, normalize_relay};
use serde_json::{Value, json};

fn vector() -> Value {
    serde_json::from_str(include_str!(
        "../../../designs/protocol/fixtures/station-route/v1.json"
    ))
    .unwrap()
}

#[test]
fn station_route_independent_mac_vector_and_tampering() {
    let v = vector();
    let Message::Request { request, .. } =
        Message::parse(v["request"].to_string().as_bytes()).unwrap()
    else {
        panic!()
    };
    let token = v["test_session_token"].as_str().unwrap().as_bytes();
    let offer = Offer::sign(request, "https://STATION-DEV.agora.build:443/", true, token).unwrap();
    assert_eq!(
        Message::Offer {
            v: 1,
            offer: offer.clone()
        }
        .to_json()
        .parse::<Value>()
        .unwrap(),
        v["offer"]
    );
    offer.verify(token).unwrap();
    assert!(offer.verify(b"other-session").is_err());
    for field in [
        "relay_url",
        "relay_only",
        "id",
        "binding_id",
        "host_trust_gen",
        "account_id",
        "astation_id",
        "atem_id",
        "session_id",
        "genesis_hash",
        "route_revision",
        "policy_revision",
    ] {
        let mut changed = v["offer"].clone();
        let o = &mut changed["data"]["offer"];
        match field {
            "relay_url" => o[field] = json!("https://attacker.example"),
            "relay_only" => o[field] = json!(false),
            "id" => o["request"][field] = json!("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeef"),
            "route_revision" | "policy_revision" => o["request"][field] = json!(99),
            "host_trust_gen" => o["request"]["context"][field] = json!(99),
            "genesis_hash" => o["request"]["context"][field] = json!("34".repeat(32)),
            _ => o["request"]["context"][field] = json!("other"),
        }
        let Message::Offer { offer, .. } = Message::parse(changed.to_string().as_bytes()).unwrap()
        else {
            panic!()
        };
        assert!(offer.verify(token).is_err(), "{field}");
    }
}

#[test]
fn station_route_acceptance_authenticates_the_exact_persisted_offer() {
    let v = vector();
    let token = v["test_session_token"].as_str().unwrap().as_bytes();
    let Message::Offer { offer, .. } = Message::parse(v["offer"].to_string().as_bytes()).unwrap()
    else {
        panic!()
    };
    let accepted = Accepted::sign(offer.clone(), true, token).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(
            &Message::Accepted {
                v: 1,
                accepted: accepted.clone()
            }
            .to_json()
        )
        .unwrap(),
        v["accepted"]
    );
    assert_eq!(accepted.verify(&offer, token).unwrap(), 8);
    assert!(accepted.verify(&offer, b"another-session").is_err());
    let mut other = offer.clone();
    other.request.id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeef".into();
    assert!(accepted.verify(&other, token).is_err());
    for field in ["direct_blocked", "route_revision", "proof", "offer"] {
        let mut changed = v["accepted"].clone();
        let a = &mut changed["data"]["accepted"];
        match field {
            "direct_blocked" => a[field] = json!(false),
            "route_revision" => a[field] = json!(9),
            "proof" => a[field] = json!(atem_client::encoding::b64u(&[0; 32])),
            "offer" => a[field]["relay_url"] = json!("https://other.example"),
            _ => unreachable!(),
        }
        if let Ok(Message::Accepted { accepted, .. }) =
            Message::parse(changed.to_string().as_bytes())
        {
            assert!(accepted.verify(&offer, token).is_err(), "{field}");
        }
    }
}

#[test]
fn station_route_preserves_unicode_relay_ids() {
    let v = vector();
    let Message::Request { mut request, .. } =
        Message::parse(v["request"].to_string().as_bytes()).unwrap()
    else {
        panic!()
    };
    request.context.atem_id = "\u{6211}\u{7684}\u{7535}\u{8111}-abcdef12".into();
    let offer = Offer::sign(
        request,
        "https://station-dev.agora.build",
        true,
        b"test-only",
    )
    .unwrap();
    let Message::Offer { offer: decoded, .. } = Message::parse(
        Message::Offer {
            v: 1,
            offer: offer.clone(),
        }
        .to_json()
        .as_bytes(),
    )
    .unwrap() else {
        panic!()
    };
    assert_eq!(decoded, offer);
    decoded.verify(b"test-only").unwrap();
}

#[test]
fn station_route_strict_shapes_and_origins() {
    for url in [
        "https://station-dev.agora.build",
        "https://custom.example:8443/",
        "http://127.0.0.1:3210",
        "http://[::1]:3210",
    ] {
        assert!(normalize_relay(url).is_ok(), "{url}");
    }
    for url in [
        "http://custom.example",
        "http://localhost:3210",
        "ws://127.0.0.1",
        "https://user:secret@example.com",
        "https://example.com/path",
        "https://example.com/?token=s",
        "https://example.com/#f",
        "https://example.com\\x",
        " https://example.com",
        "https://example.com\n",
        "file:///tmp/a",
    ] {
        assert!(normalize_relay(url).is_err(), "{url}");
    }
    let original = vector()["offer"].clone();
    for mutate in [
        |v: &mut Value| {
            v["extra"] = json!(true);
        },
        |v: &mut Value| {
            v["data"]["v"] = json!(2);
        },
        |v: &mut Value| {
            v["data"]["offer"]["extra"] = json!(true);
        },
        |v: &mut Value| {
            v["data"]["offer"]["request"]["context"]["host_trust_gen"] = json!(1.0);
        },
        |v: &mut Value| {
            v["data"]["offer"]["request"]["route_revision"] = json!(9007199254740992u64);
        },
        |v: &mut Value| {
            v["data"]["offer"]["relay_url"] = json!("https://STATION-DEV.agora.build/");
        },
    ] {
        let mut v = original.clone();
        mutate(&mut v);
        assert!(Message::parse(v.to_string().as_bytes()).is_err(), "{v}");
    }
    assert!(
        Message::parse(
            br#"{"type":"stationRoute","type":"stationRoute","data":{"v":1,"op":"changed"}}"#
        )
        .is_err()
    );
    assert!(Message::parse(&vec![b' '; 4097]).is_err());
    let mut request = vector()["request"].clone();
    for field in ["account_id", "genesis_hash", "host_device_id"] {
        request["data"]["request"]["context"][field] = Value::Null;
    }
    assert!(Message::parse(request.to_string().as_bytes()).is_ok());
    request["data"]["request"]["context"]
        .as_object_mut()
        .unwrap()
        .remove("account_id");
    assert!(Message::parse(request.to_string().as_bytes()).is_err());
    let mut accepted = vector()["accepted"].clone();
    accepted["data"]["accepted"]["offer"]["proof"] = json!("invalid");
    assert!(Message::parse(accepted.to_string().as_bytes()).is_err());
}
