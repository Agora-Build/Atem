//! The `host:<host_id>` principal (delegated host-work design II.2.1).
//!
//! A host's identity in the device list is its `host_id` (the
//! `atem_device_id` its `add_host` names); as a sender of envelopes and in
//! route principals it is `host:<host_id>`. Its key is the host key of its
//! newest `add_host`, Ed25519: the `host_channel_key` the host already
//! signs channel acceptances, push hints and route proofs with (R9.3,
//! R9.6, R9.7b, R9.9); its *principal key* is the lowercase hex SHA-256 of
//! that key's raw bytes (the shape of `r9_svc`,
//! [`crate::membership::service::service_key_fingerprint`]).
//!
//! **Never a channel principal.** A host never opens an `atem-ch1` channel
//! as a client (R9.6), so this isn't a [`crate::principal`] kind and no
//! admission check reads it: it only names who signed an envelope or
//! which sender a route consents to. The id grammar is the device list's
//! ([`crate::membership::entry::id_ok`]: 1 to 128 bytes of
//! `[A-Za-z0-9._:-]`), so a name parsed here is a `host_id` a device list
//! can hold, and every reader of `host:<id>` agrees on it.
use crate::encoding::Hash32;
use crate::keys::PublicKey;
use crate::membership::entry::id_ok;

/// The prefix of a host sender's principal.
const PREFIX: &str = "host:";

/// `host:<host_id>`: how a host appears as a sender. `host_id` is the
/// `atem_device_id` of its `add_host`; [`parse_host_principal`] reads
/// the result back only for an id the device list allows.
pub fn host_principal(host_id: &str) -> String {
    format!("{PREFIX}{host_id}")
}

/// The `host_id` of a `host:<host_id>` principal; `None` for anything else:
/// another principal kind, a different case or spacing, or an id outside
/// the device list's grammar (`id_ok`).
pub fn parse_host_principal(principal: &str) -> Option<&str> {
    principal.strip_prefix(PREFIX).filter(|id| id_ok(id))
}

/// A host's principal key: the lowercase hex SHA-256 ([`Hash32::to_hex`]) of
/// its host key's raw bytes, as `r9_svc` is of a service's `auth_key`:
/// nothing else is hashed (no algorithm prefix, no JSON). `host_key` is the
/// one of the host's newest `add_host` (Ed25519 there: the entry's parse
/// refuses any other). Vectors: `r9-svc-fingerprint.json`'s Ed25519 cases.
pub fn host_principal_key(host_key: &PublicKey) -> Hash32 {
    Hash32::of(host_key.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Alg;
    use crate::membership::entry::id_ok;
    use crate::membership::service::service_key_fingerprint;

    fn vectors() -> serde_json::Value {
        serde_json::from_str(include_str!("../vectors/r9-svc-fingerprint.json")).unwrap()
    }

    #[test]
    fn host_principal_format_parse() {
        assert_eq!(host_principal("host-a"), "host:host-a");
        assert_eq!(parse_host_principal("host:host-a"), Some("host-a"));
        // Every id the device list's grammar allows round-trips, the
        // longest and the one with every allowed punctuation included.
        for id in [
            "a",
            "Host_A.1-b:2",
            "dev-mac",
            "0",
            &"h".repeat(128),
            "host:inner",
        ] {
            assert!(id_ok(id), "{id}");
            assert_eq!(parse_host_principal(&host_principal(id)), Some(id), "{id}");
        }
        // The same grammar as `id_ok`, for any id: parse accepts exactly
        // the ids the device list does (PR 3's `ControlPrincipal::parse`
        // reads `host:<id>` with it too).
        for id in ["", "a b", "a/b", "é", &"h".repeat(129), "a\n", " a"] {
            assert_eq!(
                parse_host_principal(&format!("host:{id}")).is_some(),
                id_ok(id),
                "{id:?}"
            );
        }
    }

    #[test]
    fn bad_host_ids_refused() {
        for text in [
            "",
            "host",
            "host:",
            "host: ",
            "Host:a",
            "HOST:a",
            "host :a",
            " host:a",
            "host:a ",
            "host:a\n",
            "host:a/b",
            "host:a b",
            "host:\u{e9}",
            "host:a\u{0}",
            "host:\u{ff41}",
            // Another principal kind, never read as a host.
            "member:a",
            "service:a",
            "browser:a",
            "local",
            "astation:acct:a",
            "hosts:a",
            "xhost:a",
        ] {
            assert_eq!(parse_host_principal(text), None, "{text:?}");
        }
        // One byte over the id bound.
        assert_eq!(
            parse_host_principal(&format!("host:{}", "h".repeat(129))),
            None
        );
        assert_eq!(
            parse_host_principal(&format!("host:{}", "h".repeat(128))),
            Some("h".repeat(128).as_str())
        );
    }

    /// The principal key is `r9_svc`'s shape: the lowercase hex SHA-256 of
    /// the key's raw bytes, nothing else hashed. The Ed25519 vectors of
    /// `r9-svc-fingerprint.json` hold for it too.
    #[test]
    fn host_principal_key_is_the_hex_sha256_of_the_raw_key() {
        let v = vectors();
        let mut keys = Vec::new();
        for c in v["valid"].as_array().unwrap() {
            let key = PublicKey::from_json(&c["auth_key"]).unwrap();
            if key.alg() != Alg::Ed25519 {
                continue;
            }
            let k = host_principal_key(&key);
            assert_eq!(
                k.to_hex(),
                c["fingerprint"].as_str().unwrap(),
                "{}",
                c["case"]
            );
            assert_eq!(k.to_hex(), service_key_fingerprint(&key).unwrap());
            assert_eq!(k, crate::encoding::Hash32::of(key.as_bytes()));
            assert_eq!(k.to_hex().len(), 64);
            keys.push(key);
        }
        assert!(keys.len() >= 2, "the vectors name Ed25519 keys");
        // A different key is a different principal key.
        assert_ne!(host_principal_key(&keys[0]), host_principal_key(&keys[1]));
        assert_eq!(host_principal_key(&keys[0]), host_principal_key(&keys[0]));
    }
}
