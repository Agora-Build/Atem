//! Optional public links for the HTTPS dev servers. Only processes started
//! here are owned and stopped by the server; existing tunnels are untouched.

use super::access::AccessCode;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};

pub const REPORT_ENV: &str = "ATEM_SERV_TUNNEL_REPORT";
const START_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
enum Provider {
    Ngrok,
    Cloudflared,
}

impl Provider {
    fn binary(self) -> &'static str {
        match self {
            Self::Ngrok => "ngrok",
            Self::Cloudflared => "cloudflared",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Ngrok => "Ngrok",
            Self::Cloudflared => "Cloudflared",
        }
    }

    fn args(self, port: u16) -> Vec<String> {
        let origin = format!("https://127.0.0.1:{port}");
        match self {
            Self::Ngrok => vec![
                "http".into(),
                origin,
                "--upstream-tls-verify=false".into(),
                "--inspect=false".into(),
                "--log=stdout".into(),
                "--log-format=json".into(),
            ],
            Self::Cloudflared => vec![
                "tunnel".into(),
                "--no-autoupdate".into(),
                "--url".into(),
                origin,
                "--no-tls-verify".into(),
            ],
        }
    }

    fn public_url(self, line: &str) -> Option<String> {
        let candidate = match self {
            Self::Ngrok => {
                let event: serde_json::Value = serde_json::from_str(line).ok()?;
                if event["msg"] != "started tunnel" {
                    return None;
                }
                event["url"].as_str()?.to_owned()
            }
            Self::Cloudflared => line
                .split_ascii_whitespace()
                .find(|word| word.starts_with("https://") && word.contains(".trycloudflare.com"))?
                .to_owned(),
        };
        let url = reqwest::Url::parse(&candidate).ok()?;
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return None;
        }
        let host = url.host_str()?;
        if matches!(self, Self::Cloudflared) && !host.ends_with(".trycloudflare.com") {
            return None;
        }
        Some(url.as_str().trim_end_matches('/').to_owned())
    }
}

fn installed(binary: &str) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join(binary))
        .find(|path| {
            path.metadata()
                .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        })
}

#[derive(Clone, Deserialize, Serialize)]
struct Link {
    provider: Provider,
    url: String,
}

pub fn field(label: &str, value: impl std::fmt::Display) {
    println!("  {:<13} {value}", format!("{label}:"));
}

#[derive(Deserialize, Serialize)]
struct Failure {
    provider: Provider,
    detail: String,
}

#[derive(Default, Deserialize, Serialize)]
pub struct StartupReport {
    links: Vec<Link>,
    failures: Vec<Failure>,
    #[serde(default)]
    warnings: Vec<String>,
}

impl StartupReport {
    pub fn print_urls(
        &self,
        access: &AccessCode,
        target_path: &str,
        local: &str,
        lan: &str,
        custom: &[String],
    ) {
        field("Local", local);
        field("LAN", lan);
        for provider in [Provider::Cloudflared, Provider::Ngrok] {
            if let Some(link) = self.links.iter().find(|link| link.provider == provider) {
                field(
                    provider.label(),
                    access.url(&format!("{}{target_path}", link.url)),
                );
            } else if self
                .failures
                .iter()
                .any(|failure| failure.provider == provider)
            {
                field(provider.label(), "(unavailable)");
            }
        }
        for url in custom {
            field("Custom", url);
        }
    }

    /// The URLs `print_urls` prints after Local and LAN (public tunnels,
    /// each with the access code, then the custom hostnames), for the
    /// server registry (`atem serv info`).
    pub fn links(
        &self,
        access: &AccessCode,
        target_path: &str,
        custom: &[String],
    ) -> Vec<crate::rtc_test_server::ServerLink> {
        let mut links: Vec<_> = [Provider::Cloudflared, Provider::Ngrok]
            .into_iter()
            .filter_map(|provider| {
                self.links
                    .iter()
                    .find(|link| link.provider == provider)
                    .map(|link| crate::rtc_test_server::ServerLink {
                        label: provider.label().into(),
                        url: access.url(&format!("{}{target_path}", link.url)),
                    })
            })
            .collect();
        links.extend(custom.iter().map(|url| crate::rtc_test_server::ServerLink {
            label: "Custom".into(),
            url: url.clone(),
        }));
        links
    }

    pub fn print_warnings(&self) {
        for failure in &self.failures {
            eprintln!(
                "warning: {} link unavailable: {}",
                failure.provider.label(),
                failure.detail
            );
            if matches!(failure.provider, Provider::Ngrok) && !failure.detail.contains("ERR_NGROK_")
            {
                eprintln!(
                    "  Check ngrok configuration (`ngrok config check`) and account/tunnel limits."
                );
            }
        }
        for warning in &self.warnings {
            eprintln!("warning: {warning}");
        }
    }
}

struct Tunnel {
    child: Child,
    link: Link,
}

fn ngrok_error_code(line: &str) -> Option<String> {
    let (_, tail) = line.split_once("ERR_NGROK_")?;
    let digits: String = tail
        .chars()
        .take_while(char::is_ascii_digit)
        .take(9)
        .collect();
    if digits.is_empty() || digits.len() > 8 {
        return None;
    }
    Some(format!("ERR_NGROK_{digits}"))
}

fn ngrok_error_detail(code: &str) -> String {
    match code {
        "ERR_NGROK_334" => format!(
            "the configured ngrok endpoint is already online ({code}); stop the existing endpoint before retrying"
        ),
        "ERR_NGROK_4018" => format!(
            "ngrok requires a verified account and authtoken ({code}); configure it with `ngrok config add-authtoken`"
        ),
        _ => format!(
            "ngrok reported {code}; see https://ngrok.com/docs/errors/{}",
            code.to_ascii_lowercase()
        ),
    }
}

fn drain(
    pipe: impl tokio::io::AsyncRead + Unpin + Send + 'static,
    provider: Provider,
    tx: tokio::sync::mpsc::Sender<String>,
) -> tokio::task::JoinHandle<Option<String>> {
    tokio::spawn(async move {
        let mut lines = BufReader::new(pipe).lines();
        let mut error_code = None;
        while let Ok(Some(line)) = lines.next_line().await {
            // Capture only the code: ngrok's raw auth errors can contain
            // credential values and must not be copied into Atem's output.
            if matches!(provider, Provider::Ngrok) {
                if let Some(code) = ngrok_error_code(&line) {
                    error_code = Some(code);
                }
            }
            if let Some(url) = provider.public_url(&line) {
                let _ = tx.try_send(url);
            }
        }
        error_code
    })
}

async fn start(provider: Provider, binary: &Path, port: u16) -> Result<Tunnel> {
    let mut child = Command::new(binary)
        .args(provider.args(port))
        .env_remove(REPORT_ENV)
        .env_remove(super::access::ENV)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("could not start {}", provider.binary()))?;

    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    let mut readers = [
        drain(
            child.stdout.take().expect("piped stdout"),
            provider,
            tx.clone(),
        ),
        drain(
            child.stderr.take().expect("piped stderr"),
            provider,
            tx.clone(),
        ),
    ];
    drop(tx);

    // Read this child's announcement, never a foreign ngrok's :4040 API.
    let result: Result<String> = async {
        let url = tokio::select! {
            result = tokio::time::timeout(START_TIMEOUT, rx.recv()) => {
                result.context("no public URL announced within 15 seconds")?
                    .context("tunnel exited without announcing a public URL")?
            }
            status = child.wait() => anyhow::bail!("tunnel exited ({})", status?),
        };
        if let Some(status) = child.try_wait()? {
            anyhow::bail!("tunnel exited ({status})");
        }
        Ok(url)
    }
    .await;
    match result {
        Ok(url) => Ok(Tunnel {
            child,
            link: Link { provider, url },
        }),
        Err(mut error) => {
            let _ = child.start_kill();
            let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
            // Exit notification can win the race against the log readers.
            // Drain both pipes before deciding what failure to report.
            let mut error_code = None;
            for reader in &mut readers {
                if let Ok(Ok(Some(code))) =
                    tokio::time::timeout(Duration::from_millis(250), &mut *reader).await
                {
                    error_code = Some(code);
                }
                reader.abort();
            }
            if let Some(code) = error_code {
                error = error.context(ngrok_error_detail(&code));
            }
            Err(error)
        }
    }
}

async fn start_installed(port: u16) -> (Vec<Tunnel>, StartupReport) {
    let start_one = |provider: Provider| async move {
        let Some(binary) = installed(provider.binary()) else {
            return (None, None);
        };
        match start(provider, &binary, port).await {
            Ok(tunnel) => (Some(tunnel), None),
            Err(error) => (
                None,
                Some(Failure {
                    provider,
                    detail: format!("{error:#}"),
                }),
            ),
        }
    };
    let (ngrok, cloudflared) =
        tokio::join!(start_one(Provider::Ngrok), start_one(Provider::Cloudflared));
    let mut tunnels = Vec::new();
    let mut report = StartupReport::default();
    for (tunnel, failure) in [cloudflared, ngrok] {
        if let Some(tunnel) = tunnel {
            report.links.push(tunnel.link.clone());
            tunnels.push(tunnel);
        }
        if let Some(failure) = failure {
            report.failures.push(failure);
        }
    }
    (tunnels, report)
}

async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}

/// Keep serving local requests while tunnels start, and reap owned tunnels
/// on Ctrl+C, SIGTERM (`atem serv kill`), or a listener error.
pub async fn serve(
    port: u16,
    server: impl Future<Output = Result<()>>,
    ready: impl FnOnce(&StartupReport),
) -> Result<()> {
    let startup = start_installed(port);
    let shutdown = shutdown_signal();
    tokio::pin!(server, startup, shutdown);
    let (mut tunnels, report) = tokio::select! {
        started = &mut startup => started,
        result = &mut server => return result,
        _ = &mut shutdown => return Ok(()),
    };

    if let Some(path) = std::env::var_os(REPORT_ENV) {
        // The parent created this private file; do not recreate it if the
        // parent has already timed out and removed it. No access codes here.
        use std::io::Write;
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(path)
        {
            let _ = file.write_all(&serde_json::to_vec(&report)?);
        }
    }
    ready(&report);

    let result = tokio::select! {
        result = &mut server => result,
        _ = &mut shutdown => Ok(()),
    };
    for tunnel in &mut tunnels {
        let _ = tunnel.child.start_kill();
    }
    for tunnel in &mut tunnels {
        let _ = tokio::time::timeout(Duration::from_secs(2), tunnel.child.wait()).await;
    }
    result
}

/// A background daemon starts its own tunnels. Relay their links to the
/// launching terminal without starting a second pair in the parent.
pub struct BackgroundReport(tempfile::NamedTempFile);

impl BackgroundReport {
    pub fn new() -> Result<Self> {
        Ok(Self(tempfile::NamedTempFile::new()?))
    }

    pub fn path(&self) -> &Path {
        self.0.path()
    }

    pub async fn read(&self, child: &mut std::process::Child) -> StartupReport {
        let wait = async {
            loop {
                if let Ok(bytes) = std::fs::read(self.path()) {
                    if let Ok(report) = serde_json::from_slice::<StartupReport>(&bytes) {
                        return report;
                    }
                }
                if child.try_wait().ok().flatten().is_some() {
                    return StartupReport {
                        warnings: vec![
                            "server exited before reporting tunnel links; check its log".into(),
                        ],
                        ..StartupReport::default()
                    };
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        };
        match tokio::time::timeout(START_TIMEOUT + Duration::from_secs(5), wait).await {
            Ok(report) => report,
            Err(_) => StartupReport {
                warnings: vec!["tunnel links are not ready; check the server log".into()],
                ..StartupReport::default()
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The registry gets the URLs printed after Local and LAN, each public
    /// one with the access code.
    #[test]
    fn registry_links_carry_the_code() {
        crate::web_server::access::use_code_for_test("AbCdEfGhIjKlMnOpQrStUv");
        let access = AccessCode::for_server(8443, true);
        let report = StartupReport {
            links: vec![
                Link {
                    provider: Provider::Ngrok,
                    url: "https://n.ngrok-free.app".into(),
                },
                Link {
                    provider: Provider::Cloudflared,
                    url: "https://c.trycloudflare.com".into(),
                },
            ],
            failures: vec![],
            warnings: vec![],
        };
        let links: Vec<(String, String)> = report
            .links(
                &access,
                "/a.md",
                &["https://dev.box:8443/a.md?t=x".to_string()],
            )
            .into_iter()
            .map(|l| (l.label, l.url))
            .collect();
        assert_eq!(
            links,
            vec![
                (
                    "Cloudflared".into(),
                    "https://c.trycloudflare.com/a.md?t=AbCdEfGhIjKlMnOpQrStUv".into()
                ),
                (
                    "Ngrok".into(),
                    "https://n.ngrok-free.app/a.md?t=AbCdEfGhIjKlMnOpQrStUv".into()
                ),
                ("Custom".into(), "https://dev.box:8443/a.md?t=x".into()),
            ]
        );
    }

    #[test]
    fn ngrok_diagnostics_extract_codes_without_copying_raw_errors() {
        let line = r#"{"msg":"command failed","err":"Your authtoken: diagnostic-secret-canary\nERR_NGROK_4018"}"#;
        let code = ngrok_error_code(line).unwrap();
        assert_eq!(code, "ERR_NGROK_4018");
        assert!(!ngrok_error_detail(&code).contains("diagnostic-secret-canary"));
        assert!(ngrok_error_detail("ERR_NGROK_334").contains("endpoint is already online"));
        assert!(
            ngrok_error_detail("ERR_NGROK_99999")
                .contains("https://ngrok.com/docs/errors/err_ngrok_99999")
        );
        for line in [
            "no code",
            "ERR_NGROK_",
            "ERR_NGROK_secret",
            "ERR_NGROK_123456789",
        ] {
            assert!(ngrok_error_code(line).is_none());
        }
    }

    #[test]
    fn accepts_only_public_endpoint_announcements() {
        assert_eq!(
            Provider::Ngrok
                .public_url(r#"{"msg":"started tunnel","url":"https://test.ngrok-free.app"}"#),
            Some("https://test.ngrok-free.app".into())
        );
        assert!(
            Provider::Ngrok
                .public_url(r#"{"msg":"starting web service","url":"http://127.0.0.1:4040"}"#)
                .is_none()
        );
        assert_eq!(
            Provider::Cloudflared.public_url("INF | https://test.trycloudflare.com |"),
            Some("https://test.trycloudflare.com".into())
        );
        for line in [
            "https://test.trycloudflare.com.evil.example",
            "https://test.trycloudflare.com@evil.example",
            "https://test.trycloudflare.com/not-an-origin",
            "https://developers.cloudflare.com/tunnels",
        ] {
            assert!(Provider::Cloudflared.public_url(line).is_none(), "{line}");
        }
    }
}
