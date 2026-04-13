use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Project as returned by the Agora BFF API (/api/cli/v1/projects).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BffProject {
    #[serde(rename = "projectId")]
    pub project_id: String,
    pub name: String,
    #[serde(rename = "appId")]
    pub app_id: String,
    #[serde(rename = "signKey")]
    pub sign_key: Option<String>,
    pub status: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    /// Numeric vendor id from the BFF. Kept alongside `project_id` for reference.
    #[serde(default)]
    pub vid: Option<u64>,
}

/// Fetch all projects from the BFF API using a Bearer access token.
pub async fn fetch_projects(access_token: &str, bff_url: &str) -> Result<Vec<BffProject>> {
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/api/cli/v1/projects", bff_url))
        .header("Authorization", format!("Bearer {}", access_token))
        .send()
        .await?;

    if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
        anyhow::bail!("Session expired — run 'atem login'");
    }
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("API error {}: {}", status, body);
    }

    #[derive(Deserialize)]
    struct BffResponse {
        items: Vec<BffProject>,
    }
    let parsed: BffResponse = resp.json().await?;
    Ok(parsed.items)
}

/// Format a project list for terminal output.
pub fn format_projects(projects: &[BffProject], show_certificates: bool) -> String {
    if projects.is_empty() {
        return "No projects found.\n".to_string();
    }
    let mut text = String::new();
    for (i, p) in projects.iter().enumerate() {
        text.push_str(&format!("{}. {}\n   App ID: {}\n", i + 1, p.name, p.app_id));
        let vid_suffix = p.vid.map(|v| format!("  |  vid: {}", v)).unwrap_or_default();
        text.push_str(&format!("   Project ID: {}{}\n", p.project_id, vid_suffix));
        if show_certificates {
            let cert = p.sign_key.as_deref().unwrap_or("(none)");
            text.push_str(&format!("   Certificate: {}\n", cert));
        }
        text.push_str(&format!(
            "   Status: {}  |  Created: {}\n\n",
            p.status, p.created_at
        ));
    }
    text
}

pub fn format_unix_timestamp(secs: u64) -> String {
    let days_since_epoch = secs / 86400;
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

    fn project(name: &str, app_id: &str, sign_key: Option<&str>, status: &str) -> BffProject {
        BffProject {
            project_id: "pid".to_string(),
            name: name.to_string(),
            app_id: app_id.to_string(),
            sign_key: sign_key.map(str::to_string),
            status: status.to_string(),
            created_at: "2025-01-08T00:00:00Z".to_string(),
            vid: Some(12345),
        }
    }

    #[test]
    fn format_projects_hides_certs_by_default() {
        let projects = vec![project("MyApp", "appid123", Some("cert456"), "active")];
        let out = format_projects(&projects, false);
        assert!(out.contains("MyApp"));
        assert!(out.contains("appid123"));
        assert!(!out.contains("Certificate:"));
        assert!(!out.contains("cert456"));
    }

    #[test]
    fn format_projects_shows_certs_when_requested() {
        let projects = vec![project("MyApp", "appid123", Some("cert456"), "active")];
        let out = format_projects(&projects, true);
        assert!(out.contains("Certificate: cert456"));
    }

    #[test]
    fn format_projects_shows_none_for_missing_cert() {
        let projects = vec![project("NoCert", "appid789", None, "active")];
        let out = format_projects(&projects, true);
        assert!(out.contains("Certificate: (none)"));
    }

    #[test]
    fn format_projects_empty_list() {
        let out = format_projects(&[], false);
        assert!(out.contains("No projects found"));
    }

    #[test]
    fn format_projects_shows_status_and_created() {
        let projects = vec![project("App", "id", None, "suspended")];
        let out = format_projects(&projects, false);
        assert!(out.contains("suspended"));
        assert!(out.contains("2025-01-08T00:00:00Z"));
    }

    #[test]
    fn format_unix_timestamp_known_date() {
        assert_eq!(format_unix_timestamp(1464165672), "2016-05-25");
    }

    #[test]
    fn format_unix_timestamp_epoch() {
        assert_eq!(format_unix_timestamp(0), "1970-01-01");
    }

    #[test]
    fn format_unix_timestamp_leap_year() {
        assert_eq!(format_unix_timestamp(1582934400), "2020-02-29");
    }
}
