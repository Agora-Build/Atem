//! Property-style checks of the canonical encodings, over generated inputs
//! (a fixed-seed generator: reproducible, no extra dependency).
//!
//! - re-encoding a canonical value gives the same bytes;
//! - every non-canonical spelling of a value either canonicalizes to the
//!   same bytes (and so the same signing input and hash) or is refused;
//! - binary fields (`b64u`, hex) and `enc` have exactly one encoding.
use atem_client::canonical::{self, Numbers, jcs, parse_payload};
use atem_client::encoding::{b64u, b64u_decode, dec, enc, hex, hex_decode_array};
use atem_client::{Alg, Error, KeyId, SignedObject, SoftwareKeys};
use serde_json::{Map, Value, json};

/// xorshift64*: deterministic and good enough to explore shapes.
struct Gen(u64);

impl Gen {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn string(&mut self) -> String {
        const POOL: [&str; 14] = [
            "a",
            "b",
            "Z",
            "é",
            "\u{1f600}",
            "\"",
            "\\",
            "/",
            "\n",
            "\u{7}",
            " ",
            "\u{2028}",
            "0",
            "\u{fffd}",
        ];
        (0..self.below(6))
            .map(|_| POOL[self.below(POOL.len() as u64) as usize])
            .collect()
    }

    fn value(&mut self, depth: u32) -> Value {
        match self.below(if depth > 3 { 4 } else { 6 }) {
            0 => Value::Bool(self.below(2) == 0),
            1 => {
                let n = self.next() % canonical::MAX_SAFE_INTEGER;
                if self.below(2) == 0 {
                    Value::from(n)
                } else {
                    Value::from(-(n as i64))
                }
            }
            2 | 3 => Value::String(self.string()),
            4 => Value::Array((0..self.below(4)).map(|_| self.value(depth + 1)).collect()),
            _ => {
                let mut map = Map::new();
                for _ in 0..self.below(5) {
                    map.insert(self.string(), self.value(depth + 1));
                }
                Value::Object(map)
            }
        }
    }

    fn bytes(&mut self, max: u64) -> Vec<u8> {
        (0..self.below(max + 1))
            .map(|_| self.next() as u8)
            .collect()
    }
}

/// Another spelling of the same value: whitespace, reversed key order,
/// escaped characters.
fn respell(v: &Value, g: &mut Gen) -> String {
    let ws = |g: &mut Gen| [" ", "", "\n", "\t", "  "][g.below(5) as usize].to_owned();
    match v {
        Value::String(s) => {
            let mut out = String::from("\"");
            for c in s.chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '/' if g.below(2) == 0 => out.push_str("\\/"),
                    c if (c as u32) < 0x20 || g.below(3) == 0 => {
                        let mut buf = [0u16; 2];
                        for unit in c.encode_utf16(&mut buf) {
                            out.push_str(&format!("\\u{unit:04X}"));
                        }
                    }
                    c => out.push(c),
                }
            }
            out.push('"');
            out
        }
        Value::Array(items) => {
            let inner: Vec<String> = items
                .iter()
                .map(|i| format!("{}{}{}", ws(g), respell(i, g), ws(g)))
                .collect();
            format!("[{}]", inner.join(","))
        }
        Value::Object(map) => {
            let mut entries: Vec<String> = map
                .iter()
                .map(|(k, v)| {
                    format!(
                        "{}{}{}:{}{}",
                        ws(g),
                        respell(&Value::String(k.clone()), g),
                        ws(g),
                        ws(g),
                        respell(v, g)
                    )
                })
                .collect();
            entries.reverse();
            format!("{{{}}}", entries.join(","))
        }
        other => other.to_string(),
    }
}

#[test]
fn canonical_bytes_are_a_fixed_point() {
    let mut g = Gen(0x9e37_79b9_7f4a_7c15);
    for _ in 0..2000 {
        let v = g.value(0);
        let canon = jcs(&v).unwrap();
        let reparsed = parse_payload(canon.as_bytes()).unwrap();
        assert_eq!(reparsed, v);
        assert_eq!(jcs(&reparsed).unwrap(), canon, "re-encoding is stable");
    }
}

#[test]
fn every_spelling_of_a_value_has_one_canonical_form() {
    let mut g = Gen(0x1234_5678_9abc_def1);
    for _ in 0..2000 {
        let v = g.value(0);
        let canon = jcs(&v).unwrap();
        let spelled = respell(&v, &mut g);
        let parsed =
            parse_payload(spelled.as_bytes()).unwrap_or_else(|e| panic!("{spelled}: {e:?}"));
        assert_eq!(jcs(&parsed).unwrap(), canon, "{spelled}");
    }
}

#[test]
fn ambiguous_spellings_are_refused_not_resolved() {
    // Inputs where "the same" value could be read two ways: refused.
    for bad in [
        r#"{"a":1,"a":2}"#, // duplicate key
        r#"{"a":1,"a":1}"#, // duplicate after unescaping
        r#"{"n":1.0}"#,     // a float where integers live
        r#"{"n":1e0}"#,
        r#"{"n":9007199254740992}"#, // beyond 2^53 − 1
        r#"{"n":00}"#,
        r#"{"s":"\ud800"}"#,  // lone surrogate
        "{\"s\":\"\u{1}\"}",  // raw control character
        r#"{"a":1} {"b":2}"#, // trailing data
    ] {
        assert!(parse_payload(bad.as_bytes()).is_err(), "{bad}");
    }
    assert!(canonical::parse_strict(b"\"\xff\"", 100, Numbers::IntegersOnly).is_err());
}

#[test]
fn a_signed_object_is_the_same_however_it_is_spelled() {
    let mut keys = SoftwareKeys::new();
    let public = keys.generate(KeyId::new("k"), Alg::Ed25519).unwrap();
    let mut g = Gen(0x0f0f_f0f0_1234_4321);
    for _ in 0..200 {
        let mut body = Map::new();
        body.insert("type".into(), json!("atem-membership-entry"));
        body.insert("v".into(), json!(1));
        for _ in 0..g.below(4) {
            let mut key = g.string();
            key.push('x');
            // Arrays have their own rules; keep the rest of the shape free.
            let mut value = g.value(2);
            while value.is_array() || value.is_null() || has_array(&value) {
                value = Value::String(g.string());
            }
            body.insert(key, value);
        }
        let object = SignedObject::sign(&keys, &KeyId::new("k"), Value::Object(body)).unwrap();
        let spelled = respell(&object.to_json(), &mut g);
        let parsed = SignedObject::parse(spelled.as_bytes()).unwrap();
        assert_eq!(parsed.jcs(), object.jcs());
        assert_eq!(parsed.entry_hash(), object.entry_hash());
        assert_eq!(parsed.signing_input(), object.signing_input());
        parsed.verify(&public).unwrap();
    }
}

fn has_array(v: &Value) -> bool {
    match v {
        Value::Array(_) => true,
        Value::Object(map) => map.values().any(has_array),
        _ => false,
    }
}

#[test]
fn binary_fields_have_exactly_one_encoding() {
    let mut g = Gen(0xdead_beef_cafe_f00d);
    for _ in 0..2000 {
        let bytes = g.bytes(70);
        let text = b64u(&bytes);
        assert_eq!(b64u_decode(&text).unwrap(), bytes);
        // Padding or the standard alphabet: refused.
        assert!(b64u_decode(&format!("{text}=")).is_err() || text.len().is_multiple_of(4));
        if text.contains(['-', '_']) {
            assert!(b64u_decode(&text.replace('-', "+").replace('_', "/")).is_err());
        }
        // Non-zero trailing bits spell the same bytes another way: refused.
        if !text.len().is_multiple_of(4) {
            let last = text.chars().last().unwrap();
            const ALPHABET: &str =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
            let index = ALPHABET.find(last).unwrap();
            let spare = if text.len() % 4 == 2 { 4 } else { 2 };
            for low in 1..(1 << spare) {
                let other = ALPHABET.as_bytes()[(index & !((1 << spare) - 1)) | low] as char;
                let mut twin = text.clone();
                twin.pop();
                twin.push(other);
                assert!(b64u_decode(&twin).is_err(), "{twin} would alias {text}");
            }
        }

        let mut h = [0u8; 8];
        for b in h.iter_mut() {
            *b = g.next() as u8;
        }
        let lower = hex(&h);
        assert_eq!(hex_decode_array::<8>(&lower).unwrap(), h);
        if lower.chars().any(|c| c.is_ascii_alphabetic()) {
            assert!(hex_decode_array::<8>(&lower.to_uppercase()).is_err());
        }
    }
}

#[test]
fn enc_is_injective() {
    let mut g = Gen(42);
    let mut seen = std::collections::HashMap::new();
    for _ in 0..5000 {
        let fields: Vec<Vec<u8>> = (0..g.below(4)).map(|_| g.bytes(3)).collect();
        let refs: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
        let bytes = enc(&refs);
        assert_eq!(dec(&bytes).unwrap(), refs);
        if let Some(previous) = seen.insert(bytes, fields.clone()) {
            assert_eq!(previous, fields, "two field lists, one encoding");
        }
    }
    // A truncated encoding is refused, except at a field boundary, where it
    // is exactly the shorter list.
    let bytes = enc(&[b"label", b"x"]);
    for cut in 1..bytes.len() {
        match dec(&bytes[..cut]) {
            Ok(fields) => assert!(cut == 9 && fields == [b"label"]),
            Err(e) => assert!(matches!(e, Error::Malformed(_))),
        }
    }
    assert!(matches!(dec(&bytes[..3]), Err(Error::Malformed(_))));
}
