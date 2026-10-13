//! AccessToken2 wire format: packing, signing, zlib, base64, and parsing.
//! Crate-private; `token` validates inputs before anything reaches here.

use std::collections::BTreeMap;

use crate::error::TokenError;
use crate::token::ServiceDetails;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Service {
    pub privileges: BTreeMap<u16, u32>,
    pub details: ServiceDetails,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Content {
    pub app_id: String,
    pub issue_ts: u32,
    pub expire: u32,
    pub salt: u32,
    /// At most one service per type.
    pub services: Vec<Service>,
}

#[derive(Debug)]
pub(crate) struct Parsed {
    pub signature: Vec<u8>,
    /// The signed bytes: everything after the signature.
    pub body: Vec<u8>,
    pub content: Content,
}

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use flate2::Compression;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::io::{Read, Write};

pub(crate) const VERSION: &str = "007";
const MAX_TOKEN_LEN: usize = 16 * 1024;
const MAX_DECOMPRESSED: usize = 64 * 1024;

type HmacSha256 = Hmac<Sha256>;

fn put_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn put_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

/// `u16` length + bytes; longer fields don't fit the format.
fn put_bytes(buf: &mut Vec<u8>, field: &str, bytes: &[u8]) -> Result<(), TokenError> {
    let len = u16::try_from(bytes.len()).map_err(|_| {
        TokenError::Malformed(format!(
            "{field} is {} bytes, more than a token can hold",
            bytes.len()
        ))
    })?;
    put_u16(buf, len);
    buf.extend_from_slice(bytes);
    Ok(())
}

impl Content {
    fn pack(&self) -> Result<Vec<u8>, TokenError> {
        let mut buf = Vec::new();
        put_bytes(&mut buf, "app id", self.app_id.as_bytes())?;
        put_u32(&mut buf, self.issue_ts);
        put_u32(&mut buf, self.expire);
        put_u32(&mut buf, self.salt);
        let mut services: Vec<&Service> = self.services.iter().collect();
        services.sort_by_key(|s| s.details.service_type());
        put_u16(&mut buf, services.len() as u16);
        for service in services {
            put_u16(&mut buf, service.details.service_type());
            put_u16(&mut buf, service.privileges.len() as u16);
            for (privilege, expire) in &service.privileges {
                put_u16(&mut buf, *privilege);
                put_u32(&mut buf, *expire);
            }
            match &service.details {
                ServiceDetails::Rtc { channel, account } => {
                    put_bytes(&mut buf, "channel", channel.as_bytes())?;
                    put_bytes(&mut buf, "account", account.as_bytes())?;
                }
                ServiceDetails::Rtm { user_id } | ServiceDetails::Chat { user_id } => {
                    put_bytes(&mut buf, "user id", user_id.as_bytes())?;
                }
                ServiceDetails::Fpa => {}
                ServiceDetails::Apaas {
                    room_uuid,
                    user_uuid,
                    role,
                } => {
                    put_bytes(&mut buf, "room uuid", room_uuid.as_bytes())?;
                    put_bytes(&mut buf, "user uuid", user_uuid.as_bytes())?;
                    buf.extend_from_slice(&role.to_le_bytes());
                }
            }
        }
        Ok(buf)
    }
}

/// HMAC(key = salt, HMAC(key = issue_ts, certificate)), as Agora defines it.
fn sign_key(app_certificate: &str, issue_ts: u32, salt: u32) -> [u8; 32] {
    let mut h =
        HmacSha256::new_from_slice(&issue_ts.to_le_bytes()).expect("HMAC takes any key length");
    h.update(app_certificate.as_bytes());
    let inner = h.finalize().into_bytes();
    let mut h = HmacSha256::new_from_slice(&salt.to_le_bytes()).expect("HMAC takes any key length");
    h.update(&inner);
    h.finalize().into_bytes().into()
}

fn signer(content_issue_ts: u32, salt: u32, app_certificate: &str) -> HmacSha256 {
    HmacSha256::new_from_slice(&sign_key(app_certificate, content_issue_ts, salt))
        .expect("HMAC takes any key length")
}

pub(crate) fn encode(content: &Content, app_certificate: &str) -> Result<String, TokenError> {
    let body = content.pack()?;
    let mut mac = signer(content.issue_ts, content.salt, app_certificate);
    mac.update(&body);
    let signature = mac.finalize().into_bytes();

    let mut plain = Vec::with_capacity(2 + signature.len() + body.len());
    put_bytes(&mut plain, "signature", &signature)?;
    plain.extend_from_slice(&body);

    let mut zlib = ZlibEncoder::new(Vec::new(), Compression::default());
    zlib.write_all(&plain)
        .and_then(|_| zlib.finish())
        .map(|compressed| format!("{VERSION}{}", STANDARD.encode(compressed)))
        .map_err(|_| TokenError::Malformed("compression failed".into()))
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], TokenError> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|end| *end <= self.data.len());
        let end = end.ok_or_else(|| TokenError::Malformed("token data ends early".into()))?;
        let slice = &self.data[self.pos..end];
        self.pos = end;
        Ok(slice)
    }
    fn u16(&mut self) -> Result<u16, TokenError> {
        Ok(u16::from_le_bytes(
            self.take(2)?.try_into().expect("2 bytes"),
        ))
    }
    fn u32(&mut self) -> Result<u32, TokenError> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("4 bytes"),
        ))
    }
    fn i16(&mut self) -> Result<i16, TokenError> {
        Ok(i16::from_le_bytes(
            self.take(2)?.try_into().expect("2 bytes"),
        ))
    }
    fn bytes(&mut self) -> Result<&'a [u8], TokenError> {
        let len = self.u16()? as usize;
        self.take(len)
    }
    fn string(&mut self) -> Result<String, TokenError> {
        String::from_utf8(self.bytes()?.to_vec())
            .map_err(|_| TokenError::Malformed("a text field is not UTF-8".into()))
    }
}

pub(crate) fn parse(token: &str) -> Result<Parsed, TokenError> {
    if token.len() > MAX_TOKEN_LEN {
        return Err(TokenError::Malformed("token is longer than 16 KiB".into()));
    }
    let encoded = token
        .strip_prefix(VERSION)
        .ok_or(TokenError::UnsupportedVersion)?;
    let compressed = STANDARD
        .decode(encoded)
        .or_else(|_| STANDARD_NO_PAD.decode(encoded))
        .map_err(|_| TokenError::Malformed("not base64".into()))?;
    let mut data = Vec::new();
    ZlibDecoder::new(compressed.as_slice())
        .take(MAX_DECOMPRESSED as u64 + 1)
        .read_to_end(&mut data)
        .map_err(|_| TokenError::Malformed("not zlib data".into()))?;
    if data.len() > MAX_DECOMPRESSED {
        return Err(TokenError::Malformed(
            "decompressed token is larger than 64 KiB".into(),
        ));
    }

    let mut r = Reader {
        data: &data,
        pos: 0,
    };
    let signature = r.bytes()?.to_vec();
    let body_start = r.pos;
    let app_id = r.string()?;
    let issue_ts = r.u32()?;
    let expire = r.u32()?;
    let salt = r.u32()?;
    let count = r.u16()?;
    let mut services = Vec::with_capacity((count as usize).min((data.len() - r.pos) / 4));
    for _ in 0..count {
        let service_type = r.u16()?;
        let n = r.u16()?;
        let mut privileges = BTreeMap::new();
        for _ in 0..n {
            let privilege = r.u16()?;
            privileges.insert(privilege, r.u32()?);
        }
        let details = match service_type {
            1 => ServiceDetails::Rtc {
                channel: r.string()?,
                account: r.string()?,
            },
            2 => ServiceDetails::Rtm {
                user_id: r.string()?,
            },
            4 => ServiceDetails::Fpa,
            5 => ServiceDetails::Chat {
                user_id: r.string()?,
            },
            7 => ServiceDetails::Apaas {
                room_uuid: r.string()?,
                user_uuid: r.string()?,
                role: r.i16()?,
            },
            other => {
                return Err(TokenError::Malformed(format!(
                    "unknown service type {other}"
                )));
            }
        };
        services.push(Service {
            privileges,
            details,
        });
    }
    if r.pos != data.len() {
        return Err(TokenError::Malformed(
            "trailing bytes after the last service".into(),
        ));
    }
    Ok(Parsed {
        signature,
        body: data[body_start..].to_vec(),
        content: Content {
            app_id,
            issue_ts,
            expire,
            salt,
            services,
        },
    })
}

/// Recomputes the signature over the signed bytes (constant-time compare).
pub(crate) fn signature_matches(parsed: &Parsed, app_certificate: &str) -> bool {
    let mut mac = signer(
        parsed.content.issue_ts,
        parsed.content.salt,
        app_certificate,
    );
    mac.update(&parsed.body);
    mac.verify_slice(&parsed.signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const APP_ID: &str = "970CA35de60c44645bbae8a215061b33";
    const APP_CERT: &str = "5CFd2fd1755d40ecb72977518be15d3b";
    // Upstream's published vector (agora_token access_token.rs test_service_rtc).
    const VECTOR: &str = "007eJwBigB1/yAAFqC4TFpegsv3T7gT0J9ZxUvaycBhIFgFOayXV46VixogADk3MENBMzVkZTYwYzQ0NjQ1YmJhZThhMjE1MDYxYjMzR/QQAFgCAAABAAAAAQABAAEAAQBYAgAAIAA3ZDcyMzY1ZWI5ODM0ODUzOTdlM2UzZjlkNDYwYmRkYQoAMjg4MjM0MTI3M8JqJOM=";

    fn vector_content() -> Content {
        Content {
            app_id: APP_ID.into(),
            issue_ts: 1111111,
            expire: 600,
            salt: 1,
            services: vec![Service {
                privileges: BTreeMap::from([(1, 600)]),
                details: ServiceDetails::Rtc {
                    channel: "7d72365eb983485397e3e3f9d460bdda".into(),
                    account: "2882341273".into(),
                },
            }],
        }
    }

    /// `007` + base64(zlib(bytes)), for hand-made malformed tokens.
    fn wrap(bytes: &[u8]) -> String {
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(bytes).unwrap();
        format!(
            "007{}",
            base64::engine::general_purpose::STANDARD.encode(z.finish().unwrap())
        )
    }

    #[test]
    fn encodes_upstreams_published_vector_byte_for_byte() {
        assert_eq!(encode(&vector_content(), APP_CERT).unwrap(), VECTOR);
    }

    #[test]
    fn parses_the_vector_back() {
        let parsed = parse(VECTOR).unwrap();
        assert_eq!(parsed.content, vector_content());
        assert_eq!(parsed.signature.len(), 32);
    }

    #[test]
    fn signature_matches_only_with_the_right_certificate() {
        let parsed = parse(VECTOR).unwrap();
        assert!(signature_matches(&parsed, APP_CERT));
        assert!(!signature_matches(
            &parsed,
            "00000000000000000000000000000000"
        ));
    }

    #[test]
    fn round_trips_every_service_kind_in_type_order() {
        let mut content = vector_content();
        content.services = vec![
            Service {
                privileges: BTreeMap::from([(1, 60), (2, 60), (3, 60), (4, 60)]),
                details: ServiceDetails::Rtc {
                    channel: "c".into(),
                    account: "".into(),
                },
            },
            Service {
                privileges: BTreeMap::from([(1, 30)]),
                details: ServiceDetails::Rtm {
                    user_id: "bob".into(),
                },
            },
            Service {
                privileges: BTreeMap::from([(1, 10)]),
                details: ServiceDetails::Fpa,
            },
            Service {
                privileges: BTreeMap::from([(1, 10), (2, 20)]),
                details: ServiceDetails::Chat {
                    user_id: "u".into(),
                },
            },
            Service {
                privileges: BTreeMap::from([(1, 5)]),
                details: ServiceDetails::Apaas {
                    room_uuid: "r".into(),
                    user_uuid: "u".into(),
                    role: -1,
                },
            },
        ];
        let token = encode(&content, APP_CERT).unwrap();
        assert_eq!(parse(&token).unwrap().content, content);
    }

    #[test]
    fn accepts_unpadded_base64() {
        let unpadded = VECTOR.trim_end_matches('=');
        assert_eq!(parse(unpadded).unwrap().content, vector_content());
    }

    #[test]
    fn rejects_other_versions() {
        assert_eq!(parse("").unwrap_err(), TokenError::UnsupportedVersion);
        assert_eq!(parse("006abc").unwrap_err(), TokenError::UnsupportedVersion);
    }

    #[test]
    fn rejects_malformed_tokens_without_echoing_them() {
        let cases = [
            "007!!!not-base64".to_string(),
            format!(
                "007{}",
                base64::engine::general_purpose::STANDARD.encode(b"not zlib")
            ),
            wrap(&[1, 0]),             // signature length 1, then nothing
            wrap(&[0, 0, 3, 0, b'a']), // app id cut short
        ];
        for token in cases {
            match parse(&token) {
                Err(TokenError::Malformed(why)) => assert!(!why.contains(&token[3..]), "{why}"),
                other => panic!("{token}: {other:?}"),
            }
        }
    }

    #[test]
    fn rejects_trailing_bytes_and_unknown_services() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0, 0]); // empty signature
        bytes.extend_from_slice(&[1, 0, b'a']); // app id "a"
        bytes.extend_from_slice(&[0; 12]); // issue_ts, expire, salt
        bytes.extend_from_slice(&[1, 0, 9, 0, 0, 0]); // one service of type 9, no privileges
        assert!(
            matches!(parse(&wrap(&bytes)), Err(TokenError::Malformed(why)) if why.contains("unknown service type 9"))
        );

        let mut ok = Vec::new();
        ok.extend_from_slice(&[0, 0, 1, 0, b'a']);
        ok.extend_from_slice(&[0; 12]);
        ok.extend_from_slice(&[0, 0]); // no services
        assert!(parse(&wrap(&ok)).is_ok());
        ok.push(7);
        assert!(
            matches!(parse(&wrap(&ok)), Err(TokenError::Malformed(why)) if why.contains("trailing"))
        );
    }

    #[test]
    fn rejects_oversized_input_and_decompression_bombs() {
        let long = format!("007{}", "A".repeat(16 * 1024));
        assert!(matches!(parse(&long), Err(TokenError::Malformed(why)) if why.contains("16 KiB")));
        let bomb = wrap(&vec![0u8; 100 * 1024]);
        assert!(bomb.len() < 16 * 1024);
        assert!(matches!(parse(&bomb), Err(TokenError::Malformed(why)) if why.contains("64 KiB")));
    }

    #[test]
    fn refuses_fields_longer_than_the_format_allows() {
        let mut content = vector_content();
        content.app_id = "x".repeat(70_000);
        assert!(matches!(
            encode(&content, APP_CERT),
            Err(TokenError::Malformed(_))
        ));
    }
}
