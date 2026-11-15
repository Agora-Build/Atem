//! A relay message's top-level names read with no tree and no recursion
//! (Task 33 review m2): what tells a Station page that no reader takes (a
//! duplicate `op` key, a page cut short, nesting past a parser's depth)
//! from any other message, so the Station link can answer it as the
//! Station fault it is (host-work-v1 §11.4) rather than have it dropped
//! unseen. It decides routing only: every message it routes is read
//! strictly afterwards, and refused there.

/// The string values of `key` among the top-level members of the JSON
/// object `text`, every occurrence in order, as far as the text is well
/// formed: the scan stops at the first defect and keeps what it read
/// before it. Nested values are skipped by counting brackets (strings
/// respected), with no recursion. Escapes are decoded; a lone surrogate
/// reads as U+FFFD.
pub fn top_level_strings(text: &str, key: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut s = Scan {
        b: text.as_bytes(),
        i: 0,
    };
    s.ws();
    if !s.eat(b'{') {
        return found;
    }
    loop {
        s.ws();
        if s.eat(b'}') {
            return found;
        }
        let Some(name) = s.string() else {
            return found;
        };
        s.ws();
        if !s.eat(b':') {
            return found;
        }
        s.ws();
        if s.peek() == Some(b'"') {
            let Some(value) = s.string() else {
                return found;
            };
            if name == key {
                found.push(value);
            }
        } else if !s.skip_value() {
            return found;
        }
        s.ws();
        if s.eat(b',') {
            continue;
        }
        return found;
    }
}

/// Whether `text` is a relay message (a top-level `type` of `relay`) whose
/// top-level `op` (any occurrence) is one `is_op` takes.
pub fn relay_op(text: &str, is_op: impl Fn(&str) -> bool) -> bool {
    top_level_strings(text, "type").iter().any(|t| t == "relay")
        && top_level_strings(text, "op").iter().any(|op| is_op(op))
}

struct Scan<'a> {
    b: &'a [u8],
    i: usize,
}

impl Scan<'_> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn eat(&mut self, c: u8) -> bool {
        if self.peek() == Some(c) {
            self.i += 1;
            true
        } else {
            false
        }
    }

    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    /// A string at the cursor, decoded; none at a defect.
    fn string(&mut self) -> Option<String> {
        if !self.eat(b'"') {
            return None;
        }
        let mut out: Vec<u16> = Vec::new();
        let mut bytes = Vec::new();
        loop {
            let c = self.peek()?;
            self.i += 1;
            match c {
                b'"' => {
                    flush(&mut bytes, &mut out);
                    return Some(String::from_utf16_lossy(&out));
                }
                b'\\' => {
                    flush(&mut bytes, &mut out);
                    let e = self.peek()?;
                    self.i += 1;
                    let unit = match e {
                        b'"' => u16::from(b'"'),
                        b'\\' => u16::from(b'\\'),
                        b'/' => u16::from(b'/'),
                        b'b' => 0x08,
                        b'f' => 0x0c,
                        b'n' => u16::from(b'\n'),
                        b'r' => u16::from(b'\r'),
                        b't' => u16::from(b'\t'),
                        b'u' => {
                            let hex = self.b.get(self.i..self.i + 4)?;
                            self.i += 4;
                            u16::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?
                        }
                        _ => return None,
                    };
                    out.push(unit);
                }
                c if c < 0x20 => return None,
                c => bytes.push(c),
            }
        }
    }

    /// Skips a value that isn't a string: a scalar, or an object or array
    /// by counting brackets (strings inside skipped as strings). False at a
    /// defect.
    fn skip_value(&mut self) -> bool {
        match self.peek() {
            Some(b'{' | b'[') => {
                let mut depth: u64 = 0;
                loop {
                    match self.peek() {
                        None => return false,
                        Some(b'"') => {
                            if self.string().is_none() {
                                return false;
                            }
                            continue;
                        }
                        Some(b'{' | b'[') => depth += 1,
                        Some(b'}' | b']') => {
                            depth -= 1;
                            if depth == 0 {
                                self.i += 1;
                                return true;
                            }
                        }
                        Some(_) => {}
                    }
                    self.i += 1;
                }
            }
            Some(_) => {
                let start = self.i;
                while let Some(c) = self.peek() {
                    if matches!(c, b',' | b'}' | b']' | b' ' | b'\t' | b'\n' | b'\r') {
                        break;
                    }
                    self.i += 1;
                }
                self.i > start
            }
            None => false,
        }
    }
}

/// UTF-8 bytes read so far into UTF-16 units (lossy: what isn't UTF-8
/// becomes U+FFFD).
fn flush(bytes: &mut Vec<u8>, out: &mut Vec<u16>) {
    if !bytes.is_empty() {
        out.extend(String::from_utf8_lossy(bytes).encode_utf16());
        bytes.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn top_level_strings_read_what_no_reader_takes() {
        // Every occurrence, in order; nested names aren't top level.
        let twice = r#"{"type":"relay","op":"heads","data":{"op":"x"},"op":"control_sync_result"}"#;
        assert_eq!(
            top_level_strings(twice, "op"),
            ["heads", "control_sync_result"]
        );
        // Nesting far past any parser's depth, with no recursion.
        let deep = format!(
            r#"{{"x":{}"]}}"{},"op":"y"}}"#,
            "[".repeat(100_000),
            "]".repeat(100_000)
        );
        assert_eq!(top_level_strings(&deep, "op"), ["y"]);
        // Cut short: what came before the defect.
        let cut = r#"{"type":"relay","op":"control_sync_result","records":[{"feed_seq":1"#;
        assert_eq!(top_level_strings(cut, "op"), ["control_sync_result"]);
        assert!(relay_op(cut, |op| op == "control_sync_result"));
        // Escapes decoded; a lone surrogate elsewhere is no defect for the
        // names around it.
        let escaped = r#"{"type":"relay","x":"\ud800","op":"heads"}"#;
        assert_eq!(top_level_strings(escaped, "type"), ["relay"]);
        assert_eq!(top_level_strings(escaped, "op"), ["heads"]);
        // Not an object, or no such name: nothing.
        assert!(top_level_strings("[1]", "op").is_empty());
        assert!(top_level_strings("not json", "op").is_empty());
        assert!(!relay_op(r#"{"type":"session","op":"heads"}"#, |_| true));
        assert!(top_level_strings(r#"{"op":1,"op":["a"]}"#, "op").is_empty());
    }
}
