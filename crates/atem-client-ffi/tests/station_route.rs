#[test]
fn native_binding_uses_the_same_station_route_vector() {
    let v: serde_json::Value = serde_json::from_str(include_str!(
        "../../../designs/protocol/fixtures/station-route/v1.json"
    ))
    .unwrap();
    let got = atem_client_ffi::station_route::station_route_offer(
        v["request"].to_string(),
        "https://station-dev.agora.build/".into(),
        true,
        v["test_session_token"].as_str().unwrap().into(),
    )
    .unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&got).unwrap(),
        v["offer"]
    );
    assert!(
        atem_client_ffi::station_route::station_route_offer(
            v["offer"].to_string(),
            "https://station-dev.agora.build".into(),
            true,
            "test-only".into(),
        )
        .is_err()
    );
}

#[test]
fn native_binding_verifies_acceptance_for_its_pending_offer_only() {
    use atem_client_ffi::station_route::station_route_verify_accepted;
    let v: serde_json::Value = serde_json::from_str(include_str!(
        "../../../designs/protocol/fixtures/station-route/v1.json"
    ))
    .unwrap();
    let token = v["test_session_token"].as_str().unwrap().to_string();
    assert_eq!(
        station_route_verify_accepted(
            v["offer"].to_string(),
            v["accepted"].to_string(),
            token.clone()
        )
        .unwrap(),
        8
    );
    assert!(
        station_route_verify_accepted(
            v["offer"].to_string(),
            v["accepted"].to_string(),
            "wrong-session".into()
        )
        .is_err()
    );
    let mut stale = v["offer"].clone();
    stale["data"]["offer"]["relay_url"] = serde_json::json!("https://stale.example");
    assert!(
        station_route_verify_accepted(stale.to_string(), v["accepted"].to_string(), token.clone())
            .is_err()
    );
    let mut altered = v["accepted"].clone();
    altered["data"]["accepted"]["direct_blocked"] = serde_json::json!(false);
    assert!(
        station_route_verify_accepted(v["offer"].to_string(), altered.to_string(), token).is_err()
    );
}
