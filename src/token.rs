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
