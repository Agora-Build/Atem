//! Signed objects (§R9.1): wire `{"body":{…},"sig":"<b64u>"}`, signing input
//! `enc([label, jcs(body)])` with the label of the body's `type`, and the
//! array rules of §R9.2 (sets sorted and unique, sequences kept in order).
//!
//! Parsing checks only what holds for every signed object: strict I-JSON,
//! no `null`, the size bound, a known `type` with `v: 1`, canonical arrays,
//! and which fields may sit beside `body`. What each field means (an entry's
//! action rules, a grant's lifetime, a hint's times) is checked by the layer
//! that knows the log and the clock. The signature is checked with a key the
//! caller pins (`verify`), never one the object names.
use serde_json::{Map, Value};

use crate::canonical::{self, Numbers, jcs};
use crate::domain::{self, SignLabel, SigningInput};
use crate::encoding::{Hash32, b64u, b64u_decode};
use crate::error::{Error, Result};
use crate::keys::{Alg, PublicKey};
use crate::provider::{KeyId, KeyProvider, sign};

/// A signed body's `jcs` is at most this long (§R9.1).
pub const MAX_BODY_BYTES: usize = 4096;
/// Bound on a whole signed object as it arrives (body, signatures, and a
/// push hint's sealed part).
pub const MAX_OBJECT_BYTES: usize = 16 * 1024;

/// How an array field is encoded (§R9.2 "Arrays").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArrayKind {
    /// Strings sorted ascending by bytes (UTF-8), no duplicates.
    Set,
    /// Strings in meaning order (current first), no duplicates, never
    /// sorted, `1..=max` long.
    Sequence { max: usize },
    /// Objects in meaning order, unique by `kid`, `1..=max` long (the K
    /// backup plaintext's `keys`).
    KeyedSequence { max: usize },
}

/// The retained K generations a backup carries: 1 to 8 (§R9.5).
pub const MAX_BACKUP_KEYS: usize = 8;

/// Where arrays may appear in a body of each signed type. `*` matches any
/// one object key. Anything else that is an array is invalid.
fn array_rule(label: SignLabel, path: &[&str]) -> Option<ArrayKind> {
    const SCOPE_SETS: [&str; 4] = ["hosts", "projects", "sessions", "ops"];
    match (label, path) {
        (SignLabel::MembershipEntry, ["member", "roles"] | ["roles"]) => Some(ArrayKind::Set),
        (SignLabel::MembershipEntry, ["member", "scope", field] | ["scope", field])
            if SCOPE_SETS.contains(field) =>
        {
            Some(ArrayKind::Set)
        }
        (SignLabel::MembershipEntry, ["k_backup", "kids"]) => Some(ArrayKind::Sequence {
            max: MAX_BACKUP_KEYS,
        }),
        (SignLabel::BrowserGrant, ["ops"]) => Some(ArrayKind::Set),
        _ => None,
    }
}

/// Checks a parsed value: no `null` anywhere, and every array is where
/// `rule` allows one and is canonical for its kind.
pub(crate) fn check_value(
    value: &Value,
    rule: &dyn Fn(&[&str]) -> Option<ArrayKind>,
) -> Result<()> {
    fn walk<'a>(
        value: &'a Value,
        path: &mut Vec<&'a str>,
        rule: &dyn Fn(&[&str]) -> Option<ArrayKind>,
    ) -> Result<()> {
        match value {
            Value::Null => Err(Error::NullValue),
            Value::Object(map) => {
                for (key, child) in map {
                    path.push(key);
                    walk(child, path, rule)?;
                    path.pop();
                }
                Ok(())
            }
            Value::Array(items) => {
                let kind = rule(path).ok_or(Error::ArrayNotCanonical)?;
                check_array(kind, items)?;
                // Elements of a keyed sequence are objects: walk them too
                // (any array inside one has no rule and is refused).
                path.push("*");
                for item in items {
                    walk(item, path, rule)?;
                }
                path.pop();
                Ok(())
            }
            _ => Ok(()),
        }
    }
    walk(value, &mut Vec::new(), rule)
}

/// The §R9.2 rule for one array.
pub fn check_array(kind: ArrayKind, items: &[Value]) -> Result<()> {
    match kind {
        ArrayKind::Set => {
            let strings = strings(items)?;
            // Strictly ascending by bytes: sorted and no duplicates at once.
            if strings
                .windows(2)
                .all(|w| w[0].as_bytes() < w[1].as_bytes())
            {
                Ok(())
            } else {
                Err(Error::ArrayNotCanonical)
            }
        }
        ArrayKind::Sequence { max } => {
            let strings = strings(items)?;
            sequence_ok(&strings, max)
        }
        ArrayKind::KeyedSequence { max } => {
            let kids = items
                .iter()
                .map(|item| item.get("kid").and_then(Value::as_str))
                .collect::<Option<Vec<&str>>>()
                .ok_or(Error::ArrayNotCanonical)?;
            sequence_ok(&kids, max)
        }
    }
}

fn strings(items: &[Value]) -> Result<Vec<&str>> {
    items
        .iter()
        .map(Value::as_str)
        .collect::<Option<Vec<&str>>>()
        .ok_or(Error::ArrayNotCanonical)
}

fn sequence_ok(items: &[&str], max: usize) -> Result<()> {
    if items.is_empty() || items.len() > max {
        return Err(Error::ArrayNotCanonical);
    }
    for (i, a) in items.iter().enumerate() {
        if items[i + 1..].contains(a) {
            return Err(Error::ArrayNotCanonical);
        }
    }
    Ok(())
}

/// A push hint's sealed part (§R9.9), beside the body like `sig`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedPart {
    pub enc: Vec<u8>,
    pub ct: Vec<u8>,
}

/// A parsed, structurally valid signed object. Not yet verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedObject {
    label: SignLabel,
    body: Value,
    jcs: String,
    sig: Vec<u8>,
    kit_sig: Option<Vec<u8>>,
    sealed: Option<SealedPart>,
}

impl SignedObject {
    /// Strict parse of the wire bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let value = canonical::parse_strict(bytes, MAX_OBJECT_BYTES, Numbers::IntegersOnly)?;
        Self::from_value(&value)
    }

    /// From a value already parsed strictly (e.g. an entry inside a larger
    /// message, which `parse_strict` checked for duplicate keys).
    pub fn from_value(value: &Value) -> Result<Self> {
        let object = value
            .as_object()
            .ok_or(Error::Malformed("a signed object must be a JSON object"))?;
        let body = object.get("body").ok_or(Error::Malformed("body"))?;
        let sig = b64u_decode(
            object
                .get("sig")
                .and_then(Value::as_str)
                .ok_or(Error::Malformed("sig"))?,
        )?;
        let (label, jcs) = check_body(body)?;

        let kit_sig = object
            .get("kit_sig")
            .map(|v| {
                v.as_str()
                    .ok_or(Error::Malformed("kit_sig"))
                    .and_then(b64u_decode)
            })
            .transpose()?;
        let takes_kit_sig = label == SignLabel::MembershipEntry
            && body.get("action").and_then(Value::as_str) == Some("set_recovery_key")
            && body.get("kit").and_then(Value::as_str) == Some("current");
        match (takes_kit_sig, kit_sig.is_some()) {
            (true, false) => return Err(Error::KitSigMissing),
            (false, true) => return Err(Error::KitSigUnexpected),
            _ => {}
        }

        let sealed = match (object.get("enc"), object.get("ct")) {
            (None, None) => None,
            (Some(enc), Some(ct)) => Some(SealedPart {
                enc: b64u_decode(enc.as_str().ok_or(Error::Malformed("enc"))?)?,
                ct: b64u_decode(ct.as_str().ok_or(Error::Malformed("ct"))?)?,
            }),
            _ => return Err(Error::Malformed("enc and ct come together")),
        };
        // Only a push hint carries a sealed part. Whether a given hint must
        // (an open one is sealed per recipient, §R9.9) is the hint layer's
        // rule: the shared vectors refuse unsealed open hints for their times.
        if sealed.is_some() && label != SignLabel::PushHint {
            return Err(Error::Malformed("only a push hint has enc and ct"));
        }

        let allowed = 2 + usize::from(kit_sig.is_some()) + 2 * usize::from(sealed.is_some());
        if object.len() != allowed {
            return Err(Error::Malformed("unknown field beside body"));
        }
        Ok(SignedObject {
            label,
            body: body.clone(),
            jcs,
            sig,
            kit_sig,
            sealed,
        })
    }

    /// Signs `body` (checked as `from_value` would) with `key`.
    pub fn sign(provider: &dyn KeyProvider, key: &KeyId, body: Value) -> Result<Self> {
        let (label, jcs) = check_body(&body)?;
        let sig = sign(provider, key, &SigningInput::new(label, jcs.as_bytes()))?;
        Ok(SignedObject {
            label,
            body,
            jcs,
            sig,
            kit_sig: None,
            sealed: None,
        })
    }

    /// Adds the recovery key's co-signature to a `set_recovery_key` entry
    /// with `kit: "current"` (§R9.5). The key must be Ed25519.
    pub fn cosign(&mut self, provider: &dyn KeyProvider, recovery: &KeyId) -> Result<()> {
        let input = self.cosign_input().ok_or(Error::KitSigUnexpected)?;
        if provider.public_key(recovery)?.alg() != Alg::Ed25519 {
            return Err(Error::WrongAlg);
        }
        self.kit_sig = Some(sign(provider, recovery, &input)?);
        Ok(())
    }

    /// Attaches a push hint's sealed part.
    pub fn with_sealed(mut self, sealed: SealedPart) -> Self {
        self.sealed = Some(sealed);
        self
    }

    pub fn label(&self) -> SignLabel {
        self.label
    }

    pub fn body(&self) -> &Value {
        &self.body
    }

    pub fn body_type(&self) -> &str {
        self.body["type"].as_str().unwrap_or_default()
    }

    /// `jcs(body)`.
    pub fn jcs(&self) -> &str {
        &self.jcs
    }

    pub fn sig(&self) -> &[u8] {
        &self.sig
    }

    pub fn kit_sig(&self) -> Option<&[u8]> {
        self.kit_sig.as_deref()
    }

    pub fn sealed(&self) -> Option<&SealedPart> {
        self.sealed.as_ref()
    }

    /// `enc([label, jcs(body)])`.
    pub fn signing_input(&self) -> SigningInput {
        SigningInput::new(self.label, self.jcs.as_bytes())
    }

    /// `enc(["atem-recovery-cosign-v1", jcs(body)])`, for an entry that
    /// takes a `kit_sig`.
    pub fn cosign_input(&self) -> Option<SigningInput> {
        let takes = self.label == SignLabel::MembershipEntry
            && self.body.get("action").and_then(Value::as_str) == Some("set_recovery_key")
            && self.body.get("kit").and_then(Value::as_str) == Some("current");
        takes.then(|| SigningInput::new(SignLabel::RecoveryCosign, self.jcs.as_bytes()))
    }

    /// Verifies `sig` with the key the caller pinned for the body's signer.
    pub fn verify(&self, signer: &PublicKey) -> Result<()> {
        signer.verify(&self.signing_input(), &self.sig)
    }

    /// Verifies `kit_sig` with the current recovery key (Ed25519 only).
    pub fn verify_kit_sig(&self, recovery_key: &PublicKey) -> Result<()> {
        if recovery_key.alg() != Alg::Ed25519 {
            return Err(Error::WrongAlg);
        }
        let input = self.cosign_input().ok_or(Error::KitSigUnexpected)?;
        let kit_sig = self.kit_sig.as_deref().ok_or(Error::KitSigMissing)?;
        recovery_key.verify(&input, kit_sig)
    }

    /// `entry_hash = SHA-256(enc(["atem-membership-hash-v1", jcs(body)]))`.
    /// The signatures are not hashed (§R9.2).
    pub fn entry_hash(&self) -> Option<Hash32> {
        (self.label == SignLabel::MembershipEntry)
            .then(|| Hash32::of_enc(&[domain::MEMBERSHIP_HASH.as_bytes(), self.jcs.as_bytes()]))
    }

    /// `grant_hash = SHA-256(enc(["atem-browser-grant-hash-v1", jcs(body)]))`.
    pub fn grant_hash(&self) -> Option<Hash32> {
        (self.label == SignLabel::BrowserGrant)
            .then(|| Hash32::of_enc(&[domain::BROWSER_GRANT_HASH.as_bytes(), self.jcs.as_bytes()]))
    }

    /// The wire object.
    pub fn to_json(&self) -> Value {
        let mut object = Map::new();
        object.insert("body".into(), self.body.clone());
        object.insert("sig".into(), Value::String(b64u(&self.sig)));
        if let Some(kit_sig) = &self.kit_sig {
            object.insert("kit_sig".into(), Value::String(b64u(kit_sig)));
        }
        if let Some(sealed) = &self.sealed {
            object.insert("enc".into(), Value::String(b64u(&sealed.enc)));
            object.insert("ct".into(), Value::String(b64u(&sealed.ct)));
        }
        Value::Object(object)
    }
}

/// The checks every signed body gets; returns its label and `jcs`.
fn check_body(body: &Value) -> Result<(SignLabel, String)> {
    if !body.is_object() {
        return Err(Error::Malformed("body must be an object"));
    }
    let body_type = body
        .get("type")
        .and_then(Value::as_str)
        .ok_or(Error::Malformed("type"))?;
    let label = SignLabel::of_body_type(body_type).ok_or(Error::UnknownType)?;
    if body.get("v").and_then(Value::as_u64) != Some(1) {
        return Err(Error::Malformed("v must be 1"));
    }
    check_value(body, &|path| array_rule(label, path))?;
    let jcs = jcs(body)?;
    if jcs.len() > MAX_BODY_BYTES {
        return Err(Error::TooLarge);
    }
    Ok((label, jcs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn entry(extra: Value) -> Value {
        let mut body = json!({"type": "atem-membership-entry", "v": 1, "seq": 2});
        body.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        json!({"body": body, "sig": "AA"})
    }

    fn parse(v: &Value) -> Result<SignedObject> {
        SignedObject::parse(v.to_string().as_bytes())
    }

    #[test]
    fn sets_must_be_sorted_and_unique() {
        assert!(parse(&entry(json!({"roles": ["control", "view"]}))).is_ok());
        for roles in [json!(["view", "control"]), json!(["view", "view"])] {
            assert_eq!(
                parse(&entry(json!({"roles": roles}))),
                Err(Error::ArrayNotCanonical)
            );
        }
        // Bytes, not case-folded: "Z" < "a".
        assert!(parse(&entry(json!({"member": {"scope": {"ops": ["Z", "a"]}}}))).is_ok());
    }

    #[test]
    fn sequences_keep_their_order_but_refuse_duplicates() {
        let kids = |k: Value| entry(json!({"k_backup": {"kids": k}}));
        assert!(parse(&kids(json!(["b9", "1f"]))).is_ok(), "never sorted");
        assert_eq!(
            parse(&kids(json!(["b9", "b9"]))),
            Err(Error::ArrayNotCanonical)
        );
        assert_eq!(parse(&kids(json!([]))), Err(Error::ArrayNotCanonical));
        let nine: Vec<String> = (0..9).map(|i| format!("k{i}")).collect();
        assert_eq!(parse(&kids(json!(nine))), Err(Error::ArrayNotCanonical));
    }

    #[test]
    fn no_other_field_may_be_an_array() {
        assert_eq!(
            parse(&entry(json!({"device_id": ["a"]}))),
            Err(Error::ArrayNotCanonical)
        );
        assert_eq!(
            parse(&entry(json!({"roles": [["a"]]}))),
            Err(Error::ArrayNotCanonical)
        );
    }

    #[test]
    fn null_unknown_types_and_extra_fields_are_refused() {
        assert_eq!(parse(&entry(json!({"x": null}))), Err(Error::NullValue));
        assert_eq!(
            parse(&json!({"body": {"type": "atem-other", "v": 1}, "sig": "AA"})),
            Err(Error::UnknownType)
        );
        let mut extra = entry(json!({}));
        extra["note"] = json!("x");
        assert!(matches!(parse(&extra), Err(Error::Malformed(_))));
        assert!(matches!(
            SignedObject::parse(br#"{"body":{"type":"atem-seen","v":1},"sig":"AA","sig":"AA"}"#),
            Err(Error::Strict(_))
        ));
    }

    #[test]
    fn a_body_over_4096_bytes_is_refused() {
        let big = "x".repeat(MAX_BODY_BYTES);
        assert_eq!(parse(&entry(json!({"pad": big}))), Err(Error::TooLarge));
    }

    #[test]
    fn kit_sig_goes_only_with_kit_current() {
        let current = json!({"action": "set_recovery_key", "kit": "current"});
        assert_eq!(parse(&entry(current.clone())), Err(Error::KitSigMissing));
        let mut with = entry(current);
        with["kit_sig"] = json!("AA");
        assert!(parse(&with).is_ok());
        let mut lost = entry(json!({"action": "set_recovery_key", "kit": "lost"}));
        lost["kit_sig"] = json!("AA");
        assert_eq!(parse(&lost), Err(Error::KitSigUnexpected));
    }
}
