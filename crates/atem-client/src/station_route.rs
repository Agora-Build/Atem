//! Paired Astation's selected Station, independent of session authority.
//! See `designs/protocol/station-route-v1.md`. The session secret never goes
//! on the wire; a single-use host challenge binds every routing offer.
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::canonical::{Numbers, jcs, parse_strict};
use crate::encoding::{b64u, b64u_decode_array, enc};

pub const MAX_BYTES: usize = 4096;
pub const LABEL: &[u8] = b"atem-station-route-v1";
pub const ACCEPTED_LABEL: &[u8] = b"atem-station-route-accepted-v1";
pub const UNSUPPORTED_VERSION: &str =
    "station-route v1 is required; upgrade Atem and Astation to the current shared protocol";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Context {
    pub astation_id: String,
    pub atem_id: String,
    pub binding_id: String,
    pub host_trust_gen: u64,
    pub session_id: String,
    #[serde(deserialize_with = "required_nullable")]
    pub host_device_id: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    pub account_id: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    pub genesis_hash: Option<String>,
}

fn required_nullable<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    Option::deserialize(d)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub id: String,
    pub context: Context,
    pub route_revision: u64,
    pub policy_revision: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Offer {
    pub request: Request,
    pub relay_url: String,
    pub relay_only: bool,
    pub proof: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Accepted {
    pub offer: Offer,
    pub route_revision: u64,
    pub direct_blocked: bool,
    pub proof: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", deny_unknown_fields)]
pub enum Message {
    /// Untrusted wake hint: only asks for a fresh host challenge.
    #[serde(rename = "changed")]
    Changed { v: u64 },
    #[serde(rename = "request")]
    Request { v: u64, request: Request },
    #[serde(rename = "offer")]
    Offer { v: u64, offer: Offer },
    #[serde(rename = "accepted")]
    Accepted { v: u64, accepted: Accepted },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    #[serde(rename = "type")]
    kind: String,
    data: Message,
}

fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._:-".contains(&c))
}

impl Request {
    pub fn validate(&self) -> Result<(), &'static str> {
        let c = &self.context;
        if !crate::session::wire::is_uuid_v4(&self.id)
            || ![&c.astation_id, &c.binding_id, &c.session_id]
                .into_iter()
                .all(|s| identifier(s))
            // Atem's stable relay ID preserves non-ASCII hostnames.
            || c.atem_id.is_empty()
            || c.atem_id.len() > 128
            || !c.atem_id.chars().all(|c| !c.is_ascii() || c.is_ascii_alphanumeric() || b"._:-".contains(&(c as u8)))
            || c.host_trust_gen == 0
            || c.account_id.as_ref().is_some_and(|s| !identifier(s))
            || c.host_device_id.as_ref().is_some_and(|s| !identifier(s))
            || c.account_id.is_some() != c.genesis_hash.is_some()
            || c.account_id.is_some() != c.host_device_id.is_some()
            || c.genesis_hash
                .as_ref()
                .is_some_and(|s| crate::encoding::hex_decode_array::<32>(s).is_err())
            || [c.host_trust_gen, self.route_revision, self.policy_revision]
                .into_iter()
                .any(|n| n > crate::canonical::MAX_SAFE_INTEGER)
        {
            return Err("invalid routing context");
        }
        Ok(())
    }
}

/// An origin only: HTTPS, or HTTP on an explicit loopback IP for local
/// development. No credentials, paths, queries, fragments or redirects.
pub fn normalize_relay(input: &str) -> Result<String, &'static str> {
    if input.len() > 1024
        || input.contains('@')
        || !input.is_ascii()
        || input
            .bytes()
            .any(|c| c.is_ascii_control() || c.is_ascii_whitespace() || c == b'\\')
    {
        return Err("invalid relay origin");
    }
    let u = url::Url::parse(input).map_err(|_| "invalid relay origin")?;
    let loopback = matches!(u.host(), Some(url::Host::Ipv4(ip)) if ip.is_loopback())
        || matches!(u.host(), Some(url::Host::Ipv6(ip)) if ip.is_loopback());
    if !(u.scheme() == "https" || u.scheme() == "http" && loopback)
        || u.host_str().is_none()
        || !u.username().is_empty()
        || u.password().is_some()
        || u.path() != "/"
        || u.query().is_some()
        || u.fragment().is_some()
    {
        return Err("invalid relay origin");
    }
    Ok(u.origin().ascii_serialization())
}

impl Offer {
    fn input(&self) -> Result<Vec<u8>, &'static str> {
        self.request.validate()?;
        if normalize_relay(&self.relay_url)? != self.relay_url {
            return Err("relay origin is not normalized");
        }
        let body = serde_json::json!({"request": self.request,
            "relay_url": self.relay_url, "relay_only": self.relay_only});
        let canonical = jcs(&body).map_err(|_| "invalid routing body")?;
        Ok(enc(&[LABEL, canonical.as_bytes()]))
    }

    /// Native captures its selected Station/account/socket, then rechecks
    /// them immediately before signing and sending this offer.
    pub fn sign(
        request: Request,
        relay_url: &str,
        relay_only: bool,
        session_token: &[u8],
    ) -> Result<Self, &'static str> {
        if session_token.is_empty() || session_token.len() > 4096 {
            return Err("invalid key");
        }
        let mut offer = Self {
            request,
            relay_url: normalize_relay(relay_url)?,
            relay_only,
            proof: String::new(),
        };
        let mut mac = Hmac::<Sha256>::new_from_slice(session_token).map_err(|_| "invalid key")?;
        mac.update(&offer.input()?);
        offer.proof = b64u(&mac.finalize().into_bytes());
        Ok(offer)
    }

    pub fn verify(&self, session_token: &[u8]) -> Result<(), &'static str> {
        if session_token.is_empty() || session_token.len() > 4096 {
            return Err("invalid key");
        }
        let proof = b64u_decode_array::<32>(&self.proof).map_err(|_| "invalid route proof")?;
        let mut mac = Hmac::<Sha256>::new_from_slice(session_token).map_err(|_| "invalid key")?;
        mac.update(&self.input()?);
        mac.verify_slice(&proof).map_err(|_| "invalid route proof")
    }
}

impl Accepted {
    fn input(&self) -> Result<Vec<u8>, &'static str> {
        self.offer.input()?;
        if self.route_revision > crate::canonical::MAX_SAFE_INTEGER
            || self.route_revision != self.offer.request.route_revision + 1
        {
            return Err("invalid accepted revision");
        }
        let body = serde_json::json!({"offer": self.offer,
            "route_revision": self.route_revision, "direct_blocked": self.direct_blocked});
        let canonical = jcs(&body).map_err(|_| "invalid acceptance body")?;
        Ok(enc(&[ACCEPTED_LABEL, canonical.as_bytes()]))
    }

    pub fn sign(offer: Offer, direct_blocked: bool, token: &[u8]) -> Result<Self, &'static str> {
        offer.verify(token)?;
        let mut accepted = Self {
            route_revision: offer.request.route_revision + 1,
            offer,
            direct_blocked,
            proof: String::new(),
        };
        let mut mac = Hmac::<Sha256>::new_from_slice(token).map_err(|_| "invalid key")?;
        mac.update(&accepted.input()?);
        accepted.proof = b64u(&mac.finalize().into_bytes());
        Ok(accepted)
    }

    pub fn verify(&self, expected: &Offer, token: &[u8]) -> Result<u64, &'static str> {
        if self.offer != *expected {
            return Err("stale routing acceptance");
        }
        self.offer.verify(token)?;
        let proof = b64u_decode_array::<32>(&self.proof).map_err(|_| "invalid acceptance proof")?;
        let mut mac = Hmac::<Sha256>::new_from_slice(token).map_err(|_| "invalid key")?;
        mac.update(&self.input()?);
        mac.verify_slice(&proof)
            .map_err(|_| "invalid acceptance proof")?;
        Ok(self.route_revision)
    }
}

impl Message {
    pub fn parse(bytes: &[u8]) -> Result<Self, &'static str> {
        let value = parse_strict(bytes, MAX_BYTES, Numbers::IntegersOnly)
            .map_err(|_| "invalid routing JSON")?;
        if value.get("type").and_then(serde_json::Value::as_str) != Some("stationRoute") {
            return Err("invalid routing type");
        }
        if value
            .get("data")
            .and_then(|data| data.get("v"))
            .and_then(serde_json::Value::as_u64)
            != Some(1)
        {
            return Err(UNSUPPORTED_VERSION);
        }
        let envelope: Envelope =
            serde_json::from_value(value).map_err(|_| "invalid routing message")?;
        if envelope.kind != "stationRoute" {
            return Err("invalid routing type");
        }
        match &envelope.data {
            Self::Changed { v: 1 } => {}
            Self::Request { v: 1, request } => request.validate()?,
            Self::Offer { v: 1, offer } => {
                offer.input()?;
                b64u_decode_array::<32>(&offer.proof).map_err(|_| "invalid route proof")?;
            }
            Self::Accepted { v: 1, accepted } => {
                accepted.input()?;
                b64u_decode_array::<32>(&accepted.offer.proof)
                    .map_err(|_| "invalid route proof")?;
                b64u_decode_array::<32>(&accepted.proof).map_err(|_| "invalid acceptance proof")?;
            }
            _ => return Err(UNSUPPORTED_VERSION),
        }
        Ok(envelope.data)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(&Envelope {
            kind: "stationRoute".into(),
            data: self.clone(),
        })
        .expect("routing message serializes")
    }
}
