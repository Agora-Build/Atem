//! atem-core must produce exactly what Agora's own crate produces. Upstream
//! picks the issue time and salt itself, so each test decodes upstream's
//! token, rebuilds it with atem-core from the same issue time and salt, and
//! requires the same string.

use agora_token::{rtc_token_builder as rtc, rtm_token_builder as rtm};
use atem_core::token::*;

const APP_ID: &str = "970CA35de60c44645bbae8a215061b33";
const CERT: &str = "5CFd2fd1755d40ecb72977518be15d3b";
const CHANNEL: &str = "7d72365eb983485397e3e3f9d460bdda";

fn same_issue(upstream: &str) -> Issue {
    let d = decode_token(upstream).unwrap();
    Issue {
        issued_at: d.issued_at,
        salt: d.salt,
    }
}

fn rtc_request<'a>(
    identity: RtcIdentity<'a>,
    privileges: RtcPrivileges,
    token_expire: u32,
) -> RtcTokenRequest<'a> {
    RtcTokenRequest {
        app_id: APP_ID,
        app_certificate: CERT,
        channel: CHANNEL,
        identity,
        privileges,
        token_expire,
        rtm: None,
    }
}

#[test]
fn rtc_uid_publisher_and_subscriber_match_upstream() {
    for (role, privileges) in [
        (
            rtc::ROLE_PUBLISHER,
            RtcPrivileges::Publisher { expire: 1800 },
        ),
        (
            rtc::ROLE_SUBSCRIBER,
            RtcPrivileges::Subscriber { expire: 1800 },
        ),
    ] {
        let upstream =
            rtc::build_token_with_uid(APP_ID, CERT, CHANNEL, 2882341273, role, 3600, 1800).unwrap();
        let ours = build_rtc_token(
            &rtc_request(RtcIdentity::Uid(2882341273), privileges, 3600),
            same_issue(&upstream),
        )
        .unwrap();
        assert_eq!(ours, upstream);
    }
}

#[test]
fn rtc_uid_zero_is_the_empty_account_like_upstream() {
    let upstream =
        rtc::build_token_with_uid(APP_ID, CERT, CHANNEL, 0, rtc::ROLE_PUBLISHER, 600, 600).unwrap();
    let ours = build_rtc_token(
        &rtc_request(
            RtcIdentity::Uid(0),
            RtcPrivileges::Publisher { expire: 600 },
            600,
        ),
        same_issue(&upstream),
    )
    .unwrap();
    assert_eq!(ours, upstream);
}

#[test]
fn rtc_user_account_matches_upstream() {
    let upstream = rtc::build_token_with_user_account(
        APP_ID,
        CERT,
        CHANNEL,
        "alice",
        rtc::ROLE_PUBLISHER,
        3600,
        3600,
    )
    .unwrap();
    let ours = build_rtc_token(
        &rtc_request(
            RtcIdentity::UserAccount("alice"),
            RtcPrivileges::Publisher { expire: 3600 },
            3600,
        ),
        same_issue(&upstream),
    )
    .unwrap();
    assert_eq!(ours, upstream);
}

#[test]
fn rtc_explicit_privileges_match_upstream() {
    let upstream = rtc::build_token_with_uid_and_privilege(
        APP_ID, CERT, CHANNEL, 42, 3600, 3000, 2000, 1000, 500,
    )
    .unwrap();
    let privileges = RtcPrivileges::Explicit {
        join: 3000,
        publish_audio: 2000,
        publish_video: 1000,
        publish_data: 500,
    };
    let ours = build_rtc_token(
        &rtc_request(RtcIdentity::Uid(42), privileges, 3600),
        same_issue(&upstream),
    )
    .unwrap();
    assert_eq!(ours, upstream);
}

#[test]
fn rtc_with_rtm_same_account_matches_upstream() {
    let upstream = rtc::build_token_with_rtm(
        APP_ID,
        CERT,
        CHANNEL,
        "alice",
        rtc::ROLE_PUBLISHER,
        3600,
        1800,
    )
    .unwrap();
    let mut request = rtc_request(
        RtcIdentity::UserAccount("alice"),
        RtcPrivileges::Publisher { expire: 1800 },
        3600,
    );
    request.rtm = Some(RtmLogin {
        user_id: None,
        expire: 3600,
    });
    assert_eq!(
        build_rtc_token(&request, same_issue(&upstream)).unwrap(),
        upstream
    );
}

#[test]
fn rtc_with_rtm_separate_account_matches_upstream() {
    let upstream = rtc::build_token_with_rtm2(
        APP_ID,
        CERT,
        CHANNEL,
        "alice",
        rtc::ROLE_SUBSCRIBER,
        3600,
        1800,
        1800,
        1800,
        1800,
        "bob",
        900,
    )
    .unwrap();
    let mut request = rtc_request(
        RtcIdentity::UserAccount("alice"),
        RtcPrivileges::Subscriber { expire: 1800 },
        3600,
    );
    request.rtm = Some(RtmLogin {
        user_id: Some("bob"),
        expire: 900,
    });
    assert_eq!(
        build_rtc_token(&request, same_issue(&upstream)).unwrap(),
        upstream
    );
}

#[test]
fn rtm_matches_upstream() {
    let upstream = rtm::build_token(APP_ID, CERT, "atem01", 3600).unwrap();
    let request = RtmTokenRequest {
        app_id: APP_ID,
        app_certificate: CERT,
        user_id: "atem01",
        expire: 3600,
    };
    assert_eq!(
        build_rtm_token(&request, same_issue(&upstream)).unwrap(),
        upstream
    );
}

#[test]
fn upstream_tokens_verify_and_decode() {
    let upstream = rtc::build_token_with_rtm2(
        APP_ID,
        CERT,
        CHANNEL,
        "alice",
        rtc::ROLE_PUBLISHER,
        3600,
        1800,
        1700,
        1600,
        1500,
        "bob",
        900,
    )
    .unwrap();
    assert!(verify_token_signature(&upstream, CERT).unwrap());
    assert!(!verify_token_signature(&upstream, "00000000000000000000000000000000").unwrap());
    let d = decode_token(&upstream).unwrap();
    assert_eq!(d.app_id, APP_ID);
    assert_eq!(d.expire, 3600);
    assert_eq!(d.services.len(), 2);
    assert_eq!(
        d.services[0].details,
        ServiceDetails::Rtc {
            channel: CHANNEL.into(),
            account: "alice".into()
        }
    );
    assert_eq!(
        d.services[0].privileges.get(&PRIVILEGE_PUBLISH_DATA_STREAM),
        Some(&1500)
    );
    assert_eq!(
        d.services[1].details,
        ServiceDetails::Rtm {
            user_id: "bob".into()
        }
    );
    assert_eq!(
        d.services[1].privileges.get(&PRIVILEGE_RTM_LOGIN),
        Some(&900)
    );
}
