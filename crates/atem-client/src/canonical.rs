//! Strict JSON parsing and RFC 8785 (JCS) canonicalisation for atem-session v1
//! (r8 payload digests and r9 signed bodies, §R9.1).
//!
//! serde_json alone accepts duplicate keys (last wins), lone surrogate escapes
//! (replaced) and any number, so wire input goes through `parse_strict`, a small
//! recursive-descent parser that builds a `serde_json::Value` while refusing:
//!
//! - input longer than the caller's bound (checked before anything is built);
//! - invalid UTF-8 (`std::str::from_utf8` over the whole input first);
//! - duplicate object keys at any depth, compared after unescaping;
//! - `\u` escapes that leave a lone high or low surrogate;
//! - integers outside ±(2^53−1), and — with `Numbers::IntegersOnly` — any
//!   number with a fraction or an exponent (wire messages use
//!   `Numbers::AllowFractions` so unknown fields stay ignorable; every field
//!   that needs an integer is a `u64` in the typed layer, which refuses them);
//! - nesting deeper than `MAX_DEPTH` (no stack exhaustion).
//!
//! `jcs` covers the v1 digest domain: objects (keys sorted by UTF-16 code
//! units), arrays, strings (ECMAScript `JSON.stringify` escaping), booleans,
//! null and safe integers. Floats are outside the domain and refused.

use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};

pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
/// Bound for a standalone payload parse (the message bound, §1).
pub const MAX_INPUT_BYTES: usize = 1024 * 1024;
pub const MAX_DEPTH: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Numbers {
    /// Digest domain: every number must be a safe integer literal.
    IntegersOnly,
    /// Wire messages: fractions/exponents parse as floats (typed integer fields
    /// still refuse them); integer literals must be safe.
    AllowFractions,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StrictError {
    TooLarge,
    InvalidUtf8,
    /// Malformed JSON at this byte offset.
    Syntax(usize),
    DuplicateKey,
    LoneSurrogate,
    NonInteger,
    UnsafeInteger,
    TooDeep,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalError {
    NonInteger,
    UnsafeInteger,
}

/// Parses `bytes` as one strict JSON value (see the module docs).
pub fn parse_strict(
    bytes: &[u8],
    max_bytes: usize,
    numbers: Numbers,
) -> Result<Value, StrictError> {
    if bytes.len() > max_bytes {
        return Err(StrictError::TooLarge);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| StrictError::InvalidUtf8)?;
    let mut p = Parser {
        s: text.as_bytes(),
        text,
        pos: 0,
        numbers,
    };
    p.ws();
    let v = p.value(0)?;
    p.ws();
    if p.pos != p.s.len() {
        return Err(StrictError::Syntax(p.pos));
    }
    Ok(v)
}

/// A value that came out of `parse_strict` (or is a part of one): no
/// duplicate keys, no lone surrogates, no unsafe integers. Signed objects and
/// K-backup envelopes are built only from these, so a value that plain
/// `serde_json` parsed (which silently keeps the last of two equal keys)
/// can't reach them.
#[derive(Debug, Clone, PartialEq)]
pub struct StrictValue(Value);

impl StrictValue {
    /// `parse_strict` of `bytes`, integers only.
    pub fn parse(bytes: &[u8], max_bytes: usize) -> Result<Self, StrictError> {
        parse_strict(bytes, max_bytes, Numbers::IntegersOnly).map(StrictValue)
    }

    pub fn value(&self) -> &Value {
        &self.0
    }

    /// A field of an object (a part of a strict value is strict).
    pub fn get(&self, key: &str) -> Option<StrictValue> {
        self.0.get(key).cloned().map(StrictValue)
    }

    /// The items of an array.
    pub fn items(&self) -> Option<Vec<StrictValue>> {
        self.0
            .as_array()
            .map(|items| items.iter().cloned().map(StrictValue).collect())
    }

    pub fn into_value(self) -> Value {
        self.0
    }
}

/// Strict parse for the digest domain (integers only).
pub fn parse_payload(bytes: &[u8]) -> Result<Value, StrictError> {
    parse_strict(bytes, MAX_INPUT_BYTES, Numbers::IntegersOnly)
}

struct Parser<'a> {
    s: &'a [u8],
    text: &'a str,
    pos: usize,
    numbers: Numbers,
}

impl Parser<'_> {
    fn err(&self) -> StrictError {
        StrictError::Syntax(self.pos)
    }

    fn ws(&mut self) {
        while let Some(b' ' | b'\t' | b'\n' | b'\r') = self.s.get(self.pos) {
            self.pos += 1;
        }
    }

    fn eat(&mut self, b: u8) -> Result<(), StrictError> {
        if self.s.get(self.pos) == Some(&b) {
            self.pos += 1;
            Ok(())
        } else {
            Err(self.err())
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, StrictError> {
        match self.s.get(self.pos) {
            Some(b'{') => self.object(depth + 1),
            Some(b'[') => self.array(depth + 1),
            Some(b'"') => self.string().map(Value::String),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(b't') => self.literal("true", Value::Bool(true)),
            Some(b'f') => self.literal("false", Value::Bool(false)),
            Some(b'n') => self.literal("null", Value::Null),
            _ => Err(self.err()),
        }
    }

    fn literal(&mut self, word: &str, v: Value) -> Result<Value, StrictError> {
        if self.s[self.pos..].starts_with(word.as_bytes()) {
            self.pos += word.len();
            Ok(v)
        } else {
            Err(self.err())
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, StrictError> {
        if depth > MAX_DEPTH {
            return Err(StrictError::TooDeep);
        }
        self.eat(b'{')?;
        let mut map = Map::new();
        self.ws();
        if self.s.get(self.pos) == Some(&b'}') {
            self.pos += 1;
            return Ok(Value::Object(map));
        }
        loop {
            self.ws();
            if self.s.get(self.pos) != Some(&b'"') {
                return Err(self.err());
            }
            let key = self.string()?;
            self.ws();
            self.eat(b':')?;
            self.ws();
            let v = self.value(depth)?;
            if map.insert(key, v).is_some() {
                return Err(StrictError::DuplicateKey);
            }
            self.ws();
            match self.s.get(self.pos) {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Value::Object(map));
                }
                _ => return Err(self.err()),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, StrictError> {
        if depth > MAX_DEPTH {
            return Err(StrictError::TooDeep);
        }
        self.eat(b'[')?;
        let mut items = Vec::new();
        self.ws();
        if self.s.get(self.pos) == Some(&b']') {
            self.pos += 1;
            return Ok(Value::Array(items));
        }
        loop {
            self.ws();
            items.push(self.value(depth)?);
            self.ws();
            match self.s.get(self.pos) {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Value::Array(items));
                }
                _ => return Err(self.err()),
            }
        }
    }

    fn hex4(&mut self) -> Result<u16, StrictError> {
        let digits = self
            .s
            .get(self.pos..self.pos + 4)
            .ok_or_else(|| self.err())?;
        let mut n = 0u16;
        for &d in digits {
            let v = (d as char).to_digit(16).ok_or_else(|| self.err())?;
            n = n * 16 + v as u16;
        }
        self.pos += 4;
        Ok(n)
    }

    fn string(&mut self) -> Result<String, StrictError> {
        self.eat(b'"')?;
        let mut out = String::new();
        loop {
            // Copy the longest run without quotes, escapes or control bytes.
            let start = self.pos;
            while let Some(&b) = self.s.get(self.pos) {
                if b == b'"' || b == b'\\' || b < 0x20 {
                    break;
                }
                self.pos += 1;
            }
            // Input is valid UTF-8 and the run stops at ASCII bytes, so this
            // slice is on character boundaries.
            out.push_str(&self.text[start..self.pos]);
            match self.s.get(self.pos) {
                Some(b'"') => {
                    self.pos += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.pos += 1;
                    let e = *self.s.get(self.pos).ok_or_else(|| self.err())?;
                    self.pos += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hi = self.hex4()?;
                            let c = match hi {
                                0xD800..=0xDBFF => {
                                    if !self.s[self.pos..].starts_with(b"\\u") {
                                        return Err(StrictError::LoneSurrogate);
                                    }
                                    self.pos += 2;
                                    let lo = self.hex4()?;
                                    if !(0xDC00..=0xDFFF).contains(&lo) {
                                        return Err(StrictError::LoneSurrogate);
                                    }
                                    0x10000
                                        + (((hi as u32) - 0xD800) << 10)
                                        + ((lo as u32) - 0xDC00)
                                }
                                0xDC00..=0xDFFF => return Err(StrictError::LoneSurrogate),
                                _ => hi as u32,
                            };
                            out.push(char::from_u32(c).ok_or(StrictError::LoneSurrogate)?);
                        }
                        _ => return Err(StrictError::Syntax(self.pos - 1)),
                    }
                }
                // Raw control character or end of input.
                _ => return Err(self.err()),
            }
        }
    }

    fn digits(&mut self) -> usize {
        let start = self.pos;
        while let Some(b'0'..=b'9') = self.s.get(self.pos) {
            self.pos += 1;
        }
        self.pos - start
    }

    fn number(&mut self) -> Result<Value, StrictError> {
        let start = self.pos;
        let negative = self.s[self.pos] == b'-';
        if negative {
            self.pos += 1;
        }
        let int_start = self.pos;
        match self.s.get(self.pos) {
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => {
                self.digits();
            }
            _ => return Err(self.err()),
        }
        let int_end = self.pos;
        let mut fractional = false;
        if self.s.get(self.pos) == Some(&b'.') {
            self.pos += 1;
            if self.digits() == 0 {
                return Err(self.err());
            }
            fractional = true;
        }
        if let Some(b'e' | b'E') = self.s.get(self.pos) {
            self.pos += 1;
            if let Some(b'+' | b'-') = self.s.get(self.pos) {
                self.pos += 1;
            }
            if self.digits() == 0 {
                return Err(self.err());
            }
            fractional = true;
        }
        if fractional {
            if self.numbers == Numbers::IntegersOnly {
                return Err(StrictError::NonInteger);
            }
            let f: f64 = self.text[start..self.pos].parse().map_err(|_| self.err())?;
            return Number::from_f64(f)
                .map(Value::Number)
                .ok_or(StrictError::NonInteger);
        }
        let digits = &self.text[int_start..int_end];
        // MAX_SAFE_INTEGER has 16 digits; longer can't be safe (and can't overflow u64 below).
        if digits.len() > 16 {
            return Err(StrictError::UnsafeInteger);
        }
        let n: u64 = digits.parse().map_err(|_| self.err())?;
        if n > MAX_SAFE_INTEGER {
            return Err(StrictError::UnsafeInteger);
        }
        // `-0` becomes 0: counters and other integers have no negative zero.
        Ok(if negative {
            Value::from(-(n as i64))
        } else {
            Value::from(n)
        })
    }
}

/// RFC 8785 canonical form of `v` over the v1 digest domain.
pub fn jcs(v: &Value) -> Result<String, CanonicalError> {
    let mut out = String::new();
    write_jcs(v, &mut out)?;
    Ok(out)
}

fn write_jcs(v: &Value, out: &mut String) -> Result<(), CanonicalError> {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                if u > MAX_SAFE_INTEGER {
                    return Err(CanonicalError::UnsafeInteger);
                }
                out.push_str(&u.to_string());
            } else if let Some(i) = n.as_i64() {
                if i.unsigned_abs() > MAX_SAFE_INTEGER {
                    return Err(CanonicalError::UnsafeInteger);
                }
                out.push_str(&i.to_string());
            } else {
                return Err(CanonicalError::NonInteger);
            }
        }
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_jcs(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(k, out);
                out.push(':');
                write_jcs(&map[k], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// ECMAScript `JSON.stringify` string escaping (RFC 8785 §3.2.2.2).
fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// `sha256(JCS(payload))`, lowercase hex (§6).
pub fn payload_digest(v: &Value) -> Result<String, CanonicalError> {
    Ok(sha256_hex(jcs(v)?.as_bytes()))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
