use anyhow::Result;
use base64::{Engine as _, engine::general_purpose};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct AgoraApiResponse {
    pub projects: Vec<AgoraApiProject>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AgoraApiProject {
    #[allow(dead_code)]
    pub id: String,
    pub name: String,
    pub vendor_key: String,
    pub sign_key: String,
    #[allow(dead_code)]
    pub recording_server: Option<String>,
    pub status: i32,
    pub created: u64,
}

/// Fetch projects using explicit credentials (used by CLI commands with config)
pub async fn fetch_agora_projects_with_credentials(
    customer_id: &str,
    customer_secret: &str,
) -> Result<Vec<AgoraApiProject>> {
    let credentials =
        general_purpose::STANDARD.encode(format!("{}:{}", customer_id, customer_secret));

    let client = reqwest::Client::new();
    let resp = client
        .get("https://api.agora.io/dev/v1/projects")
        .header("Authorization", format!("Basic {}", credentials))
        .header("Content-Type", "application/json")
        .send()
        .await?;

    if !resp.status().is_success() {
        return Err(anyhow::anyhow!(
            "Agora API returned status {}",
            resp.status()
        ));
    }

    let api_response: AgoraApiResponse = resp.json().await?;
    Ok(api_response.projects)
}

/// Fetch projects - tries config first, then env vars
pub async fn fetch_agora_projects() -> Result<Vec<AgoraApiProject>> {
    // Try loading from config first
    if let Ok(config) = crate::config::AtemConfig::load() {
        if let (Some(cid), Some(csecret)) = (&config.customer_id, &config.customer_secret) {
            return fetch_agora_projects_with_credentials(cid, csecret).await;
        }
    }

    // Fall back to env vars (existing behavior)
    let customer_id = std::env::var("AGORA_CUSTOMER_ID").ok();
    let customer_secret = std::env::var("AGORA_CUSTOMER_SECRET").ok();
    let (customer_id, customer_secret) = match (customer_id, customer_secret) {
        (Some(id), Some(secret)) => (id, secret),
        (None, None) => anyhow::bail!("No credentials found"),
        (None, Some(_)) => anyhow::bail!("AGORA_CUSTOMER_ID not set"),
        (Some(_), None) => anyhow::bail!("AGORA_CUSTOMER_SECRET not set"),
    };

    fetch_agora_projects_with_credentials(&customer_id, &customer_secret).await
}

pub fn format_projects(projects: &[AgoraApiProject], show_certificates: bool) -> String {
    if projects.is_empty() {
        return "No projects found in your Agora account.\n".to_string();
    }

    let mut text = String::new();
    for (i, project) in projects.iter().enumerate() {
        let status_str = if project.status == 1 {
            "Enabled"
        } else {
            "Disabled"
        };
        let created_date = format_unix_timestamp(project.created);
        text.push_str(&format!(
            "{}. {}\n   App ID: {}\n",
            i + 1,
            project.name,
            project.vendor_key,
        ));
        if show_certificates {
            let cert_display = if project.sign_key.is_empty() {
                "(none)"
            } else {
                &project.sign_key
            };
            text.push_str(&format!("   Certificate: {}\n", cert_display));
        }
        text.push_str(&format!(
            "   Status: {}  |  Created: {}\n\n",
            status_str, created_date,
        ));
    }
    text
}

pub fn format_unix_timestamp(ts: u64) -> String {
    let secs = ts;
    let days_since_epoch = secs / 86400;
    // Compute year/month/day from days since 1970-01-01
    let mut remaining_days = days_since_epoch as i64;
    let mut year = 1970i64;
    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }
    let days_in_months: [i64; 12] = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut month = 0;
    for (i, &dim) in days_in_months.iter().enumerate() {
        if remaining_days < dim {
            month = i + 1;
            break;
        }
        remaining_days -= dim;
    }
    let day = remaining_days + 1;
    format!("{:04}-{:02}-{:02}", year, month, day)
}

pub fn is_leap_year(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_unix_timestamp_known_date() {
        // 2016-05-25 in UTC corresponds to unix timestamp 1464134400
        // The created value 1464165672 is 2016-05-25 (with some hours offset)
        assert_eq!(format_unix_timestamp(1464165672), "2016-05-25");
    }

    #[test]
    fn format_unix_timestamp_epoch() {
        assert_eq!(format_unix_timestamp(0), "1970-01-01");
    }

    #[test]
    fn format_unix_timestamp_leap_year() {
        // 2020-02-29 00:00:00 UTC = 1582934400
        assert_eq!(format_unix_timestamp(1582934400), "2020-02-29");
    }

    #[tokio::test]
    async fn fetch_agora_projects_missing_credentials() {
        // Ensure env vars are not set for this test
        // SAFETY: test is single-threaded for env access
        unsafe {
            std::env::remove_var("AGORA_CUSTOMER_ID");
            std::env::remove_var("AGORA_CUSTOMER_SECRET");
        }

        let result = fetch_agora_projects().await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("No credentials found"),
            "Error should say 'No credentials found', got: {}",
            err_msg
        );
    }

    #[test]
    fn format_timestamps_from_real_api_data() {
        // Timestamps from the actual API response
        assert_eq!(format_unix_timestamp(1736297713), "2025-01-08"); // Demo for 128
        assert_eq!(format_unix_timestamp(1715721645), "2024-05-14"); // Demo for Conv API
        assert_eq!(format_unix_timestamp(1715297148), "2024-05-09"); // Demo for OJ
        assert_eq!(format_unix_timestamp(1714432004), "2024-04-29"); // W/O Certificate
        assert_eq!(format_unix_timestamp(1476599483), "2016-10-16"); // Demo for realtime TTS
    }

    fn make_test_project(name: &str, vendor_key: &str, sign_key: &str, status: i32) -> AgoraApiProject {
        AgoraApiProject {
            id: "test_id".to_string(),
            name: name.to_string(),
            vendor_key: vendor_key.to_string(),
            sign_key: sign_key.to_string(),
            recording_server: None,
            status,
            created: 1736297713,
        }
    }

    #[test]
    fn format_projects_hides_certificates_by_default() {
        let projects = vec![
            make_test_project("MyApp", "appid123", "cert456", 1),
        ];
        let output = format_projects(&projects, false);
        assert!(output.contains("MyApp"));
        assert!(output.contains("appid123"));
        assert!(!output.contains("Certificate:"), "Certificate should be hidden, got:\n{}", output);
        assert!(!output.contains("cert456"), "sign_key should not appear, got:\n{}", output);
    }

    #[test]
    fn format_projects_shows_certificates_when_toggled() {
        let projects = vec![
            make_test_project("MyApp", "appid123", "cert456", 1),
        ];
        let output = format_projects(&projects, true);
        assert!(output.contains("MyApp"));
        assert!(output.contains("appid123"));
        assert!(output.contains("Certificate: cert456"), "Certificate should be visible, got:\n{}", output);
    }

    #[test]
    fn format_projects_shows_none_for_empty_certificate() {
        let projects = vec![
            make_test_project("NoCert", "appid789", "", 1),
        ];
        let output = format_projects(&projects, true);
        assert!(output.contains("Certificate: (none)"), "Empty cert should show (none), got:\n{}", output);
    }

    #[test]
    fn format_projects_empty_list() {
        let output = format_projects(&[], false);
        assert!(output.contains("No projects found"));
    }

    #[tokio::test]
    async fn fetch_agora_projects_with_real_credentials() {
        // Skip when credentials are not available in env
        let has_creds = std::env::var("AGORA_CUSTOMER_ID").ok().filter(|s| !s.is_empty()).is_some()
            && std::env::var("AGORA_CUSTOMER_SECRET").ok().filter(|s| !s.is_empty()).is_some();
        if !has_creds {
            eprintln!("Skipping: AGORA_CUSTOMER_ID / AGORA_CUSTOMER_SECRET not set");
            return;
        }
        let result = fetch_agora_projects().await;
        assert!(result.is_ok(), "API call failed: {:?}", result.err());

        let projects = result.unwrap();
        assert!(!projects.is_empty(), "Project list should not be empty");

        // Verify known project from the account
        let demo128 = projects.iter().find(|p| p.name == "Demo for 128");
        assert!(demo128.is_some(), "Expected 'Demo for 128' project");
        let demo128 = demo128.unwrap();
        assert_eq!(demo128.vendor_key, "2655d20a82fc47cebcff82d5bd5d53ef");
        assert_eq!(demo128.status, 1);

        // Verify formatting with certificates hidden
        let output_hidden = format_projects(&projects, false);
        assert!(!output_hidden.contains("Certificate:"));
        assert!(output_hidden.contains("Enabled"));

        // Verify formatting with certificates shown
        let output_shown = format_projects(&projects, true);
        assert!(output_shown.contains("Certificate:"));
        // "W/O Certificate" project has empty sign_key
        assert!(output_shown.contains("(none)"));
    }
}
