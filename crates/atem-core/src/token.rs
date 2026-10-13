//! Agora AccessToken2 (version "007") for RTC and RTM. See designs/atem-core.md.

use std::collections::BTreeMap;

pub use crate::error::TokenError;

/// Service types inside a token.
pub const SERVICE_RTC: u16 = 1;
pub const SERVICE_RTM: u16 = 2;
pub const SERVICE_FPA: u16 = 4;
pub const SERVICE_CHAT: u16 = 5;
pub const SERVICE_APAAS: u16 = 7;

/// RTC privileges.
pub const PRIVILEGE_JOIN_CHANNEL: u16 = 1;
pub const PRIVILEGE_PUBLISH_AUDIO_STREAM: u16 = 2;
pub const PRIVILEGE_PUBLISH_VIDEO_STREAM: u16 = 3;
pub const PRIVILEGE_PUBLISH_DATA_STREAM: u16 = 4;
/// RTM privilege.
pub const PRIVILEGE_RTM_LOGIN: u16 = 1;

/// The service-specific fields of one service in a token.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(tag = "kind", rename_all = "snake_case"))]
pub enum ServiceDetails {
    /// `account` is the user account, or the decimal uid; empty means uid 0 (any user).
    Rtc {
        channel: String,
        account: String,
    },
    Rtm {
        user_id: String,
    },
    Fpa,
    Chat {
        user_id: String,
    },
    Apaas {
        room_uuid: String,
        user_uuid: String,
        role: i16,
    },
}

impl ServiceDetails {
    pub fn service_type(&self) -> u16 {
        match self {
            ServiceDetails::Rtc { .. } => SERVICE_RTC,
            ServiceDetails::Rtm { .. } => SERVICE_RTM,
            ServiceDetails::Fpa => SERVICE_FPA,
            ServiceDetails::Chat { .. } => SERVICE_CHAT,
            ServiceDetails::Apaas { .. } => SERVICE_APAAS,
        }
    }
}

/// One service as read from a token: its privileges (privilege → expiry in
/// seconds after the issue time) and fields.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct DecodedService {
    pub service_type: u16,
    pub privileges: BTreeMap<u16, u32>,
    pub details: ServiceDetails,
}

/// What a token says about itself. Reading these fields does **not**
/// establish that the token is authentic: use `verify_token_signature`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct DecodedToken {
    pub version: String,
    pub app_id: String,
    /// Unix seconds.
    pub issued_at: u32,
    /// Seconds after `issued_at`.
    pub expire: u32,
    pub salt: u32,
    pub services: Vec<DecodedService>,
}

impl DecodedToken {
    /// Unix seconds at which the token itself expires.
    pub fn expires_at(&self) -> u64 {
        self.issued_at as u64 + self.expire as u64
    }
}

use crate::wire;

/// Who the RTC token is for. `Uid(0)` means any user (stored as an empty
/// account, as Agora does). Strings and numbers are never converted into
/// each other: a numeric user account is still a user account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtcIdentity<'a> {
    Uid(u32),
    UserAccount(&'a str),
}

impl RtcIdentity<'_> {
    /// The account string stored in the token.
    pub fn token_account(&self) -> String {
        match self {
            RtcIdentity::Uid(0) => String::new(),
            RtcIdentity::Uid(uid) => uid.to_string(),
            RtcIdentity::UserAccount(account) => (*account).to_string(),
        }
    }
}

/// RTC privileges, each valid for `expire` seconds after the issue time.
/// `Publisher` = join + publish audio, video and data; `Subscriber` = join.
/// Publish privileges only matter when co-host authentication is enabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtcPrivileges {
    Publisher {
        expire: u32,
    },
    Subscriber {
        expire: u32,
    },
    Explicit {
        join: u32,
        publish_audio: u32,
        publish_video: u32,
        publish_data: u32,
    },
}

/// Adds an RTM login to an RTC token. `user_id: None` reuses the RTC account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtmLogin<'a> {
    pub user_id: Option<&'a str>,
    pub expire: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtcTokenRequest<'a> {
    pub app_id: &'a str,
    pub app_certificate: &'a str,
    pub channel: &'a str,
    pub identity: RtcIdentity<'a>,
    pub privileges: RtcPrivileges,
    /// Seconds after the issue time.
    pub token_expire: u32,
    pub rtm: Option<RtmLogin<'a>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtmTokenRequest<'a> {
    pub app_id: &'a str,
    pub app_certificate: &'a str,
    pub user_id: &'a str,
    /// Seconds after the issue time (token and login privilege).
    pub expire: u32,
}

/// When the token is issued (unix seconds) and its random salt. Fixed values
/// make tokens reproducible (tests); `now()` is what callers normally use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Issue {
    pub issued_at: u32,
    pub salt: u32,
}

impl Issue {
    /// The system clock and a random salt.
    ///
    /// Panics if the operating system's random source is unavailable.
    pub fn now() -> Issue {
        let issued_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);
        Issue::at(issued_at)
    }

    /// A caller-supplied issue time (e.g. from a synced clock) and a random salt.
    pub fn at(issued_at: u32) -> Issue {
        let mut bytes = [0u8; 4];
        getrandom::getrandom(&mut bytes).expect("operating system random source");
        // 1..99_999_999, the range Agora's own builders use.
        Issue {
            issued_at,
            salt: 1 + u32::from_le_bytes(bytes) % 99_999_998,
        }
    }
}

fn is_hex32(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn check_credentials(app_id: &str, app_certificate: &str) -> Result<(), TokenError> {
    if !is_hex32(app_id) {
        return Err(TokenError::InvalidAppId);
    }
    if !is_hex32(app_certificate) {
        return Err(TokenError::InvalidAppCertificate);
    }
    Ok(())
}

fn check_len(value: &str, max: usize) -> Result<(), String> {
    match value.len() {
        0 => Err("must not be empty".into()),
        n if n > max => Err(format!("must be at most {max} bytes, got {n}")),
        _ => Ok(()),
    }
}

fn check_expiry(what: &str, seconds: u32) -> Result<(), TokenError> {
    if seconds == 0 {
        return Err(TokenError::InvalidExpiry(format!(
            "{what} must be at least 1 second"
        )));
    }
    Ok(())
}

/// Builds an RTC token (optionally with an RTM login).
pub fn build_rtc_token(request: &RtcTokenRequest, issue: Issue) -> Result<String, TokenError> {
    check_credentials(request.app_id, request.app_certificate)?;
    check_len(request.channel, 64).map_err(TokenError::InvalidChannel)?;
    if let RtcIdentity::UserAccount(account) = request.identity {
        check_len(account, 255).map_err(TokenError::InvalidUserAccount)?;
    }
    check_expiry("token expiry", request.token_expire)?;

    let mut privileges = std::collections::BTreeMap::new();
    match request.privileges {
        RtcPrivileges::Publisher { expire } => {
            check_expiry("privilege expiry", expire)?;
            for p in [
                PRIVILEGE_JOIN_CHANNEL,
                PRIVILEGE_PUBLISH_AUDIO_STREAM,
                PRIVILEGE_PUBLISH_VIDEO_STREAM,
                PRIVILEGE_PUBLISH_DATA_STREAM,
            ] {
                privileges.insert(p, expire);
            }
        }
        RtcPrivileges::Subscriber { expire } => {
            check_expiry("privilege expiry", expire)?;
            privileges.insert(PRIVILEGE_JOIN_CHANNEL, expire);
        }
        RtcPrivileges::Explicit {
            join,
            publish_audio,
            publish_video,
            publish_data,
        } => {
            for (what, privilege, expire) in [
                ("join channel expiry", PRIVILEGE_JOIN_CHANNEL, join),
                (
                    "publish audio expiry",
                    PRIVILEGE_PUBLISH_AUDIO_STREAM,
                    publish_audio,
                ),
                (
                    "publish video expiry",
                    PRIVILEGE_PUBLISH_VIDEO_STREAM,
                    publish_video,
                ),
                (
                    "publish data expiry",
                    PRIVILEGE_PUBLISH_DATA_STREAM,
                    publish_data,
                ),
            ] {
                check_expiry(what, expire)?;
                privileges.insert(privilege, expire);
            }
        }
    }

    let account = request.identity.token_account();
    let mut services = vec![wire::Service {
        privileges,
        details: ServiceDetails::Rtc {
            channel: request.channel.to_string(),
            account: account.clone(),
        },
    }];
    if let Some(rtm) = request.rtm {
        check_expiry("RTM login expiry", rtm.expire)?;
        let user_id = rtm.user_id.map(str::to_string).unwrap_or(account);
        check_len(&user_id, 64).map_err(TokenError::InvalidRtmUserId)?;
        services.push(wire::Service {
            privileges: std::collections::BTreeMap::from([(PRIVILEGE_RTM_LOGIN, rtm.expire)]),
            details: ServiceDetails::Rtm { user_id },
        });
    }
    wire::encode(
        &wire::Content {
            app_id: request.app_id.to_string(),
            issue_ts: issue.issued_at,
            expire: request.token_expire,
            salt: issue.salt,
            services,
        },
        request.app_certificate,
    )
}

/// Builds an RTM token (login privilege for `expire` seconds).
pub fn build_rtm_token(request: &RtmTokenRequest, issue: Issue) -> Result<String, TokenError> {
    check_credentials(request.app_id, request.app_certificate)?;
    check_len(request.user_id, 64).map_err(TokenError::InvalidRtmUserId)?;
    check_expiry("expiry", request.expire)?;
    wire::encode(
        &wire::Content {
            app_id: request.app_id.to_string(),
            issue_ts: issue.issued_at,
            expire: request.expire,
            salt: issue.salt,
            services: vec![wire::Service {
                privileges: std::collections::BTreeMap::from([(
                    PRIVILEGE_RTM_LOGIN,
                    request.expire,
                )]),
                details: ServiceDetails::Rtm {
                    user_id: request.user_id.to_string(),
                },
            }],
        },
        request.app_certificate,
    )
}

/// Reads a token's fields. This does **not** establish that the token is
/// authentic; use `verify_token_signature` for that.
pub fn decode_token(token: &str) -> Result<DecodedToken, TokenError> {
    let parsed = wire::parse(token.trim())?;
    let content = parsed.content;
    Ok(DecodedToken {
        version: wire::VERSION.to_string(),
        app_id: content.app_id,
        issued_at: content.issue_ts,
        expire: content.expire,
        salt: content.salt,
        services: content
            .services
            .into_iter()
            .map(|s| DecodedService {
                service_type: s.details.service_type(),
                privileges: s.privileges,
                details: s.details,
            })
            .collect(),
    })
}

/// Whether `token` was signed with `app_certificate`. `Ok(false)` for a
/// well-formed token signed with another certificate.
pub fn verify_token_signature(token: &str, app_certificate: &str) -> Result<bool, TokenError> {
    if !is_hex32(app_certificate) {
        return Err(TokenError::InvalidAppCertificate);
    }
    Ok(wire::signature_matches(
        &wire::parse(token.trim())?,
        app_certificate,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const APP_ID: &str = "970CA35de60c44645bbae8a215061b33";
    const CERT: &str = "5CFd2fd1755d40ecb72977518be15d3b";
    const FIXED: Issue = Issue {
        issued_at: 1_700_000_000,
        salt: 7,
    };

    fn request() -> RtcTokenRequest<'static> {
        RtcTokenRequest {
            app_id: APP_ID,
            app_certificate: CERT,
            channel: "test-channel",
            identity: RtcIdentity::Uid(1),
            privileges: RtcPrivileges::Publisher { expire: 600 },
            token_expire: 600,
            rtm: None,
        }
    }

    #[test]
    fn credentials_must_be_32_hex_characters() {
        for bad in [
            "",
            "abc",
            "970CA35de60c44645bbae8a215061b3Z",
            "970CA35de60c44645bbae8a215061b333",
        ] {
            let mut r = request();
            r.app_id = bad;
            assert_eq!(
                build_rtc_token(&r, FIXED).unwrap_err(),
                TokenError::InvalidAppId
            );
            let mut r = request();
            r.app_certificate = bad;
            assert_eq!(
                build_rtc_token(&r, FIXED).unwrap_err(),
                TokenError::InvalidAppCertificate
            );
        }
    }

    #[test]
    fn channel_must_be_1_to_64_bytes() {
        let long = "c".repeat(65);
        for bad in ["", long.as_str()] {
            let mut r = request();
            r.channel = bad;
            assert!(matches!(
                build_rtc_token(&r, FIXED),
                Err(TokenError::InvalidChannel(_))
            ));
        }
        let max = "c".repeat(64);
        let mut r = request();
        r.channel = &max;
        assert!(build_rtc_token(&r, FIXED).is_ok());
    }

    #[test]
    fn user_account_must_be_1_to_255_bytes_and_uids_cover_the_whole_u32_range() {
        let long = "a".repeat(256);
        for bad in ["", long.as_str()] {
            let mut r = request();
            r.identity = RtcIdentity::UserAccount(bad);
            assert!(matches!(
                build_rtc_token(&r, FIXED),
                Err(TokenError::InvalidUserAccount(_))
            ));
        }
        let max = "a".repeat(255);
        let mut r = request();
        r.identity = RtcIdentity::UserAccount(&max);
        assert!(build_rtc_token(&r, FIXED).is_ok());
        for uid in [0, 1, u32::MAX] {
            let mut r = request();
            r.identity = RtcIdentity::Uid(uid);
            let d = decode_token(&build_rtc_token(&r, FIXED).unwrap()).unwrap();
            let expected = if uid == 0 {
                String::new()
            } else {
                uid.to_string()
            };
            assert_eq!(
                d.services[0].details,
                ServiceDetails::Rtc {
                    channel: "test-channel".into(),
                    account: expected
                }
            );
        }
    }

    #[test]
    fn every_expiry_must_be_at_least_one_second() {
        let mut r = request();
        r.token_expire = 0;
        assert!(matches!(
            build_rtc_token(&r, FIXED),
            Err(TokenError::InvalidExpiry(_))
        ));
        for privileges in [
            RtcPrivileges::Publisher { expire: 0 },
            RtcPrivileges::Subscriber { expire: 0 },
            RtcPrivileges::Explicit {
                join: 1,
                publish_audio: 0,
                publish_video: 1,
                publish_data: 1,
            },
        ] {
            let mut r = request();
            r.privileges = privileges;
            assert!(matches!(
                build_rtc_token(&r, FIXED),
                Err(TokenError::InvalidExpiry(_))
            ));
        }
        let mut r = request();
        r.rtm = Some(RtmLogin {
            user_id: Some("bob"),
            expire: 0,
        });
        assert!(matches!(
            build_rtc_token(&r, FIXED),
            Err(TokenError::InvalidExpiry(_))
        ));
        let rtm = RtmTokenRequest {
            app_id: APP_ID,
            app_certificate: CERT,
            user_id: "bob",
            expire: 0,
        };
        assert!(matches!(
            build_rtm_token(&rtm, FIXED),
            Err(TokenError::InvalidExpiry(_))
        ));
        let mut r = request();
        r.token_expire = u32::MAX;
        assert!(build_rtc_token(&r, FIXED).is_ok());
    }

    #[test]
    fn rtm_user_id_must_be_1_to_64_bytes_including_a_reused_rtc_account() {
        let long = "u".repeat(65);
        for bad in ["", long.as_str()] {
            let rtm = RtmTokenRequest {
                app_id: APP_ID,
                app_certificate: CERT,
                user_id: bad,
                expire: 60,
            };
            assert!(matches!(
                build_rtm_token(&rtm, FIXED),
                Err(TokenError::InvalidRtmUserId(_))
            ));
        }
        // Uid 0 is the empty account: there is no RTM user to reuse.
        let mut r = request();
        r.identity = RtcIdentity::Uid(0);
        r.rtm = Some(RtmLogin {
            user_id: None,
            expire: 60,
        });
        assert!(matches!(
            build_rtc_token(&r, FIXED),
            Err(TokenError::InvalidRtmUserId(_))
        ));
    }

    #[test]
    fn the_same_issue_gives_the_same_token_and_now_differs() {
        assert_eq!(
            build_rtc_token(&request(), FIXED).unwrap(),
            build_rtc_token(&request(), FIXED).unwrap()
        );
        let a = Issue::now();
        assert!(a.salt >= 1 && a.salt < 99_999_999);
        assert!(a.issued_at > 1_700_000_000);
        assert_eq!(Issue::at(5).issued_at, 5);
    }

    #[test]
    fn errors_never_contain_the_certificate_or_the_token() {
        let token = build_rtc_token(&request(), FIXED).unwrap();
        let mut r = request();
        r.channel = "";
        let messages = [
            build_rtc_token(&r, FIXED).unwrap_err().to_string(),
            decode_token(&format!("{}!", &token[..token.len() - 1]))
                .unwrap_err()
                .to_string(),
            verify_token_signature("007garbage", CERT)
                .unwrap_err()
                .to_string(),
        ];
        for m in messages {
            assert!(!m.contains(CERT) && !m.contains(&token[3..20]), "{m}");
        }
    }
}
