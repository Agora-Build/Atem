//! Detects credential VALUES, never names: `dialf/openai` or
//! `atem vault get dialf/openai` pass, a pasted `sk-…` key does not.
//! Fail-closed: input that can't be checked counts as a finding.
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub struct SecretFinding {
    pub kind: &'static str,
    pub masked: String,
    pub line: usize,
}

/// First 3 + "…" + last 4 characters; "****" for 8 characters or fewer.
pub fn mask(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= 8 {
        return "****".into();
    }
    let head: String = chars[..3].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{}…{}", head, tail)
}

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '+' | '/')
}

/// Shannon entropy in bits per character.
fn entropy(s: &str) -> f64 {
    let n = s.chars().count() as f64;
    if n == 0.0 {
        return 0.0;
    }
    let mut counts: HashMap<char, usize> = HashMap::new();
    for c in s.chars() {
        *counts.entry(c).or_insert(0) += 1;
    }
    counts.values().map(|&c| {
        let p = c as f64 / n;
        -p * p.log2()
    }).sum()
}

fn classify(tok: &str) -> Option<&'static str> {
    let len = tok.len(); // tokens are ASCII-only (see is_token_char)
    if tok.starts_with("sk-") && len >= 20 {
        return Some("api key (sk-)");
    }
    if tok.starts_with("AKIA") && len == 20
        && tok[4..].chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
    {
        return Some("aws access key");
    }
    if ["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"].iter().any(|p| tok.starts_with(p)) && len >= 30 {
        return Some("github token");
    }
    if ["xoxb-", "xoxp-", "xoxa-", "xoxs-", "xoxr-"].iter().any(|p| tok.starts_with(p)) && len >= 20 {
        return Some("slack token");
    }
    if tok.starts_with("eyJ") && len >= 30 {
        let parts: Vec<&str> = tok.split('.').collect();
        if parts.len() == 3 && parts.iter().all(|p| !p.is_empty()) {
            return Some("jwt");
        }
    }
    // Hex digests (≤4.0 bits/char), UUIDs, and mem_ ids stay below 4.3.
    // Skip path/URL-like tokens to avoid false positives on paths with digits
    // (their segments are checked one by one in `find_secrets`).
    // Note: requires both digits and letters; purely alphabetic tokens are not checked.
    if len >= 32
        && tok.chars().any(|c| c.is_ascii_digit())
        && tok.chars().any(|c| c.is_ascii_alphabetic())
        && entropy(tok) > 4.3
        && !is_path_like(tok)
    {
        return Some("high-entropy token");
    }
    None
}

/// `//host/...` is what's left of a URL after ':' splits off the scheme.
fn is_path_like(tok: &str) -> bool {
    tok.starts_with("//") || tok.starts_with('/') || tok.starts_with("./") || tok.starts_with("~/")
}

/// `scheme://user:password@host` — returns each non-empty password.
fn url_passwords(line: &str) -> Vec<&str> {
    let mut out = Vec::new();
    for (i, _) in line.match_indices("://") {
        let rest = &line[i + 3..];
        let end = rest.find(|c: char| c.is_whitespace() || c == '/').unwrap_or(rest.len());
        let authority = &rest[..end];
        let Some(at) = authority.rfind('@') else { continue };
        if let Some((_, password)) = authority[..at].split_once(':')
            && !password.is_empty() {
            out.push(password);
        }
    }
    out
}

/// `hooks.slack.com/services/T…/B…/<secret>` — returns the secret segment.
fn slack_webhook_secret(line: &str) -> Option<&str> {
    const HOOK: &str = "hooks.slack.com/services/";
    let i = line.find(HOOK)?;
    let rest = &line[i + HOOK.len()..];
    let end = rest.find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ')' | '>' | '`')).unwrap_or(rest.len());
    let segs: Vec<&str> = rest[..end].split('/').collect();
    (segs.len() >= 3 && segs[..3].iter().all(|s| !s.is_empty())).then(|| segs[2])
}

pub fn find_secrets(text: &str) -> Vec<SecretFinding> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let lineno = i + 1;
        if line.contains("-----BEGIN") && line.contains("PRIVATE KEY") {
            out.push(SecretFinding { kind: "private key", masked: "-----BEGIN …PRIVATE KEY-----".into(), line: lineno });
            continue;
        }
        for pw in url_passwords(line) {
            out.push(SecretFinding { kind: "credentials in URL", masked: mask(pw), line: lineno });
        }
        if let Some(secret) = slack_webhook_secret(line) {
            out.push(SecretFinding { kind: "slack webhook", masked: mask(secret), line: lineno });
        }
        for tok in line.split(|c: char| !is_token_char(c)) {
            if tok.is_empty() {
                continue;
            }
            if let Some(kind) = classify(tok) {
                out.push(SecretFinding { kind, masked: mask(tok), line: lineno });
            }
            if is_path_like(tok) {
                // A key can hide in a URL path or userinfo: check each segment.
                for seg in tok.split(['/', '@']).filter(|s| !s.is_empty()) {
                    if let Some(kind) = classify(seg) {
                        out.push(SecretFinding { kind, masked: mask(seg), line: lineno });
                    }
                }
            }
        }
    }
    out
}

/// Like `find_secrets`, but for file bytes. Non-UTF-8 content can't be
/// checked, so it is reported as a finding (fail-closed).
pub fn check_bytes(bytes: &[u8]) -> Vec<SecretFinding> {
    match std::str::from_utf8(bytes) {
        Ok(text) => find_secrets(text),
        Err(_) => vec![SecretFinding { kind: "unreadable (binary)", masked: String::new(), line: 0 }],
    }
}

/// Every finding in a skill's files, as `path:line  kind masked`. Binary
/// (non-UTF-8) files can't be checked and are reported as unreadable.
pub fn skill_file_problems(files: &std::collections::BTreeMap<String, Vec<u8>>) -> Vec<String> {
    let mut out = Vec::new();
    for (path, bytes) in files {
        for f in check_bytes(bytes) {
            out.push(format!("{}:{}  {} {}", path, f.line, f.kind, f.masked));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_openai_style_key() {
        let f = find_secrets("key is sk-proj-abcdef1234567890ABCDEF");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, "api key (sk-)");
        assert_eq!(f[0].masked, "sk-…CDEF");
        assert_eq!(f[0].line, 1);
    }

    #[test]
    fn vault_references_pass() {
        assert!(find_secrets(
            "DialF's OpenAI key is the vault credential dialf/openai; fetch with `atem vault get dialf/openai`"
        ).is_empty());
    }

    #[test]
    fn flags_aws_github_slack_jwt() {
        assert_eq!(find_secrets("AKIAIOSFODNN7EXAMPLE")[0].kind, "aws access key");
        assert_eq!(find_secrets("token ghp_abcdefghijklmnopqrstuvwxyz0123456789")[0].kind, "github token");
        assert_eq!(find_secrets("xoxb-1234567890-abcdefghij")[0].kind, "slack token");
        assert_eq!(find_secrets("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abc123def456")[0].kind, "jwt");
    }

    #[test]
    fn flags_private_key_block() {
        let f = find_secrets("x\n-----BEGIN RSA PRIVATE KEY-----\nMIIE");
        assert_eq!(f[0].kind, "private key");
        assert_eq!(f[0].line, 2);
    }

    #[test]
    fn flags_high_entropy_base64() {
        let f = find_secrets("salt Q4mTLy5h9qtD46vrdMgotPH9WrZxDsLxThPD9vtlf+o=");
        assert_eq!(f[0].kind, "high-entropy token");
    }

    #[test]
    fn ignores_hashes_uuids_and_memory_ids() {
        assert!(find_secrets("commit 3f5a9c1e2b4d6f8091a2b3c4d5e6f708192a3b4c").is_empty());
        assert!(find_secrets("instance 550e8400-e29b-41d4-a716-446655440000").is_empty());
        assert!(find_secrets("a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90").is_empty());
        assert!(find_secrets("mem_0f8fad5bd9cb469fa16570867728950e").is_empty());
        assert!(find_secrets("/home/guohai/Dev/Agora.Build/Atem/designs/atem-memory.md").is_empty());
    }

    #[test]
    fn binary_is_fail_closed() {
        let f = check_bytes(&[0xff, 0xfe, 0x00]);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, "unreadable (binary)");
        assert!(check_bytes(b"plain text").is_empty());
    }

    #[test]
    fn mask_short_and_long() {
        assert_eq!(mask("abc"), "****");
        assert_eq!(mask("sk-1234567890"), "sk-…7890");
    }

    #[test]
    fn reports_line_numbers() {
        let f = find_secrets("ok\nok\nsk-abcdefghijklmnopqrstu");
        assert_eq!(f[0].line, 3);
    }

    #[test]
    fn assignment_forms_are_detected() {
        assert_eq!(find_secrets("AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE")[0].kind, "aws access key");
        assert_eq!(find_secrets("OPENAI_API_KEY=sk-proj-abcdef1234567890ABCDEF")[0].kind, "api key (sk-)");
    }

    #[test]
    fn paths_and_urls_with_digits_pass() {
        assert!(find_secrets("/home/guohai/Dev/Agora.Build/Atem/designs/atem-memory-implementation-plan/task-3-report.md").is_empty());
        assert!(find_secrets("https://api.example.com/v2/projects/12345/deployments/abcdef").is_empty());
        assert!(find_secrets("https://github.com/Agora-Build/Atem/commit/3f5a9c1e2b4d6f8091a2b3c4d5e6f708192a3b4c").is_empty());
    }

    #[test]
    fn token_inside_url_userinfo_is_detected() {
        let f = find_secrets("git remote https://ghp_abcdefghijklmnopqrstuvwxyz0123456789@github.com/o/r");
        assert!(f.iter().any(|x| x.kind == "github token"), "{:?}", f);
        assert!(f.iter().all(|x| !x.masked.contains("abcdefghijklmnop")));
    }

    #[test]
    fn url_password_is_detected() {
        let f = find_secrets("https://alice:hunter2pass@example.com/x");
        let hit = f.iter().find(|x| x.kind == "credentials in URL").expect("finding");
        assert_eq!(hit.masked, "hun…pass");
        assert!(find_secrets("https://alice@example.com/x").is_empty());
        assert!(find_secrets("ssh://git@github.com:22/o/r").is_empty());
    }

    #[test]
    fn slack_webhook_is_detected() {
        // Built at runtime so the fixture isn't a literal webhook URL (GitHub push protection).
        let url = format!("https://hooks.slack.com/services/{}/{}/{}", "T00000000", "B00000000", "X".repeat(24));
        let f = find_secrets(&url);
        assert!(f.iter().any(|x| x.kind == "slack webhook"), "{:?}", f);
        assert!(find_secrets("see https://hooks.slack.com/services/ for docs").is_empty());
    }

    #[test]
    fn high_entropy_segment_inside_path_is_detected() {
        let f = find_secrets("https://example.com/cb/Q4mTLy5h9qtD46vrdMgotPH9WrZxDsLxThPD9vtlf+o");
        assert!(f.iter().any(|x| x.kind == "high-entropy token"), "{:?}", f);
    }

    #[test]
    fn entropy_of_empty_is_zero() {
        assert_eq!(entropy(""), 0.0);
    }

    #[test]
    fn skill_file_problems_are_masked_per_file() {
        let mut files = std::collections::BTreeMap::new();
        files.insert("SKILL.md".to_string(), b"# fine".to_vec());
        files.insert("creds.txt".to_string(), b"AKIAIOSFODNN7EXAMPLE".to_vec());
        files.insert("img.png".to_string(), vec![0xff, 0xfe, 0x00]);
        let p = skill_file_problems(&files);
        assert_eq!(p.len(), 2, "{p:?}");
        assert!(p.iter().any(|l| l.starts_with("creds.txt:1") && !l.contains("IOSFODNN7")));
        assert!(p.iter().any(|l| l.starts_with("img.png:0") && l.contains("unreadable (binary)")));
    }
}
