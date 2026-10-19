//! Machine-bound encryption: AES-256-GCM under a key derived from this
//! machine's id, so a copied file can't be opened on another machine. Used by
//! `login.enc`, `pairing/pairing.enc` and `project_cache.enc`.
//!
//! Dependency-light (aes-gcm, hmac, sha2, rand), so binary tests include
//! this file (`#[path]`) to write fixtures the binary can read.
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use anyhow::{Result, anyhow, bail};
use hmac::{Hmac, Mac};
use sha2::Sha256;

fn derive_key() -> [u8; 32] {
    let id = machine_id();
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(b"atem-credentials-v1").expect("hmac");
    mac.update(id.as_bytes());
    let out = mac.finalize().into_bytes();
    let mut key = [0u8; 32];
    key.copy_from_slice(&out[..32]);
    key
}

fn machine_id() -> String {
    #[cfg(target_os = "linux")]
    {
        if let Ok(s) = std::fs::read_to_string("/etc/machine-id") {
            return s.trim().to_string();
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(out) = std::process::Command::new("ioreg")
            .args(["-rd1", "-c", "IOPlatformExpertDevice"])
            .output()
        {
            let s = String::from_utf8_lossy(&out.stdout);
            for line in s.lines() {
                if let Some((_, rest)) = line.split_once("IOPlatformUUID")
                    && let Some(v) = rest.split('"').nth(1)
                {
                    return v.to_string();
                }
            }
        }
    }
    let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".into());
    let user = std::env::var("USER").unwrap_or_else(|_| "unknown".into());
    format!("{host}-{user}")
}

/// `plain` encrypted: a 12-byte nonce, then the ciphertext.
pub fn encrypt(plain: &[u8]) -> Result<Vec<u8>> {
    use rand::RngCore;
    let key = derive_key();
    let cipher = Aes256Gcm::new((&key).into());
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plain)
        .map_err(|e| anyhow!("encrypt: {e}"))?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// What `encrypt` made on this machine (an error for anything else).
pub fn decrypt(raw: &[u8]) -> Result<Vec<u8>> {
    if raw.len() < 12 {
        bail!("ciphertext too short");
    }
    let (nonce_bytes, ct) = raw.split_at(12);
    let key = derive_key();
    let cipher = Aes256Gcm::new((&key).into());
    cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ct)
        .map_err(|e| anyhow!("decrypt: {e}"))
}
