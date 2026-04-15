//! Tiny HTML helpers shared between the browser-facing servers.

/// Escape a string for safe inclusion in HTML text content or attribute
/// values (quoted with `"`). Handles the minimum set needed to prevent
/// injection through project names, channel names, etc.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&'  => out.push_str("&amp;"),
            '<'  => out.push_str("&lt;"),
            '>'  => out.push_str("&gt;"),
            '"'  => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c    => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_html_special_chars() {
        assert_eq!(escape("plain"), "plain");
        assert_eq!(escape("<script>alert('x')</script>"),
                   "&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;");
        assert_eq!(escape("A & B"), "A &amp; B");
        assert_eq!(escape(r#"say "hi""#), "say &quot;hi&quot;");
    }

    #[test]
    fn passes_through_unicode() {
        assert_eq!(escape("café 日本語"), "café 日本語");
    }
}
