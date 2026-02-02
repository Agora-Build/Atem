use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::{SystemTime, UNIX_EPOCH};

const TOKEN_PREFIX: &str = "007";

pub fn generate_rtm_token(
    app_id: &str,
    app_certificate: &str,
    user_id: &str,
    expire_seconds: u32,
) -> String {
    if app_certificate.is_empty() {
        return String::new();
    }

    let expiry_epoch = current_unix_time() + expire_seconds as u64;
    let mut hasher = DefaultHasher::new();
    app_id.hash(&mut hasher);
    app_certificate.hash(&mut hasher);
    user_id.hash(&mut hasher);
    expiry_epoch.hash(&mut hasher);
    let hash_value = hasher.finish();
    format!("{}{:016x}{:016x}", TOKEN_PREFIX, hash_value, expiry_epoch)
}

fn current_unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::from_secs(0))
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_certificate_returns_empty_token() {
        let token = generate_rtm_token("app_id", "", "user1", 3600);
        assert!(token.is_empty());
    }

    #[test]
    fn token_starts_with_prefix() {
        let token = generate_rtm_token("app_id", "cert", "user1", 3600);
        assert!(token.starts_with(TOKEN_PREFIX));
    }

    #[test]
    fn token_has_expected_length() {
        // "007" (3) + 16-char hex hash + 16-char hex expiry = 35
        let token = generate_rtm_token("app_id", "cert", "user1", 3600);
        assert_eq!(token.len(), 35);
    }

    #[test]
    fn different_inputs_produce_different_tokens() {
        let token_a = generate_rtm_token("app_a", "cert", "user1", 3600);
        let token_b = generate_rtm_token("app_b", "cert", "user1", 3600);
        assert_ne!(token_a, token_b);
    }

    #[test]
    fn different_users_produce_different_tokens() {
        let token_a = generate_rtm_token("app", "cert", "alice", 3600);
        let token_b = generate_rtm_token("app", "cert", "bob", 3600);
        assert_ne!(token_a, token_b);
    }

    #[test]
    fn token_expiry_is_in_the_future() {
        let token = generate_rtm_token("app", "cert", "user", 3600);
        // Last 16 hex chars are the expiry epoch
        let expiry_hex = &token[19..35];
        let expiry = u64::from_str_radix(expiry_hex, 16).unwrap();
        let now = current_unix_time();
        assert!(expiry > now, "expiry {} should be after now {}", expiry, now);
        assert!(
            expiry <= now + 3601,
            "expiry {} should be at most now+3601 {}",
            expiry,
            now + 3601
        );
    }

    #[test]
    fn token_is_pure_hex_after_prefix() {
        let token = generate_rtm_token("app", "cert", "user", 60);
        let after_prefix = &token[3..];
        assert!(
            after_prefix.chars().all(|c| c.is_ascii_hexdigit()),
            "expected hex chars, got: {}",
            after_prefix
        );
    }

    #[test]
    fn same_inputs_same_second_produce_same_token() {
        let a = generate_rtm_token("app", "cert", "user", 3600);
        let b = generate_rtm_token("app", "cert", "user", 3600);
        // Within the same second these should be identical
        assert_eq!(a, b);
    }
}
