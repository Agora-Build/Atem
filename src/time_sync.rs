use anyhow::Result;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Cached time offset between local clock and Agora server.
pub struct TimeSync {
    offset_secs: i64,
    synced_at: Option<Instant>,
    max_age: Duration,
}

impl TimeSync {
    pub fn new() -> Self {
        Self {
            offset_secs: 0,
            synced_at: None,
            max_age: Duration::from_secs(3600), // 1 hour
        }
    }

    /// Fetch server time from Agora API Date header, compute drift offset.
    pub async fn sync(&mut self) -> Result<()> {
        // Try to load credentials from config for the HEAD request
        let config = crate::config::AtemConfig::load().unwrap_or_default();

        let client = reqwest::Client::new();
        let mut req = client.head("https://api.agora.io/dev/v1/projects");

        // Add auth if available (makes the request more reliable)
        if let (Some(cid), Some(csecret)) = (&config.customer_id, &config.customer_secret) {
            use base64::{Engine as _, engine::general_purpose};
            let credentials = format!("{}:{}", cid, csecret);
            let encoded = general_purpose::STANDARD.encode(credentials.as_bytes());
            req = req.header("Authorization", format!("Basic {}", encoded));
        }

        let resp = req.send().await?;

        if let Some(date_header) = resp.headers().get("date") {
            let date_str = date_header.to_str()?;
            // Parse HTTP date format: "Sun, 02 Feb 2026 19:30:00 GMT"
            let server_time = parse_http_date(date_str)?;
            let local_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
            self.offset_secs = server_time as i64 - local_time;
            self.synced_at = Some(Instant::now());

            if self.offset_secs.abs() > 30 {
                eprintln!(
                    "Warning: local clock is {}s off from Agora server",
                    self.offset_secs
                );
            }
        }

        Ok(())
    }

    /// Returns corrected current Unix timestamp.
    pub async fn now(&mut self) -> Result<u64> {
        let needs_sync = match self.synced_at {
            None => true,
            Some(at) => at.elapsed() > self.max_age,
        };

        if needs_sync {
            if let Err(e) = self.sync().await {
                eprintln!("Warning: time sync failed ({}), using local clock", e);
            }
        }

        let local = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
        Ok((local + self.offset_secs) as u64)
    }

    /// Raw offset for diagnostics.
    pub fn offset(&self) -> i64 {
        self.offset_secs
    }

    /// Force re-sync on next call to now().
    pub fn invalidate(&mut self) {
        self.synced_at = None;
    }
}

/// Parse HTTP date format "Sun, 02 Feb 2026 19:30:00 GMT" to Unix timestamp.
fn parse_http_date(s: &str) -> Result<u64> {
    // Simple parser for "Day, DD Mon YYYY HH:MM:SS GMT"
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() < 5 {
        anyhow::bail!("Invalid HTTP date format: {}", s);
    }

    let day: u32 = parts[1].parse()?;
    let month = match parts[2] {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => anyhow::bail!("Invalid month: {}", parts[2]),
    };
    let year: u32 = parts[3].parse()?;
    let time_parts: Vec<&str> = parts[4].split(':').collect();
    if time_parts.len() != 3 {
        anyhow::bail!("Invalid time format: {}", parts[4]);
    }
    let hour: u32 = time_parts[0].parse()?;
    let minute: u32 = time_parts[1].parse()?;
    let second: u32 = time_parts[2].parse()?;

    // Convert to Unix timestamp
    let days = days_from_civil(year, month, day);
    let timestamp = days as u64 * 86400 + hour as u64 * 3600 + minute as u64 * 60 + second as u64;
    Ok(timestamp)
}

/// Convert year/month/day to days since Unix epoch.
fn days_from_civil(y: u32, m: u32, d: u32) -> i64 {
    let y = y as i64;
    let m = m as i64;
    let d = d as i64;

    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_http_date_valid() {
        let ts = parse_http_date("Sun, 02 Feb 2025 19:30:00 GMT").unwrap();
        // 2025-02-02 19:30:00 UTC
        assert!(ts > 1738000000 && ts < 1739000000);
    }

    #[test]
    fn parse_http_date_invalid() {
        assert!(parse_http_date("invalid").is_err());
    }

    #[test]
    fn days_from_civil_epoch() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
    }

    #[test]
    fn days_from_civil_known_date() {
        // 2025-01-01 should be day 20089
        let days = days_from_civil(2025, 1, 1);
        assert_eq!(days, 20089);
    }

    #[test]
    fn time_sync_new_has_zero_offset() {
        let ts = TimeSync::new();
        assert_eq!(ts.offset(), 0);
    }
}
