//! Real HTTPS servers with fake tunnel executables: no public endpoints or
//! real credentials. Exercise startup output, background handoff and cleanup.
mod support;

use std::os::unix::fs::PermissionsExt;
use std::process::{Child, Command, Stdio};
use support::{Sandbox, atem_bin, within};

struct Fixture {
    sandbox: Sandbox,
}

impl Fixture {
    fn new(providers: &[&str]) -> Self {
        let sandbox = Sandbox::new();
        let bin = sandbox.dir.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        for provider in providers {
            let announcement = match *provider {
                "ngrok" => {
                    r#"printf '%s\n' '{"msg":"started tunnel","url":"https://fixture.ngrok-free.app"}'"#
                }
                "cloudflared" => "printf '%s\\n' 'INF | https://fixture.trycloudflare.com |' >&2",
                _ => unreachable!(),
            };
            let script = format!(
                r#"#!/bin/sh
printf '%s\n' "$@" > "$ATEM_TUNNEL_FIXTURE/{provider}.args"
printf '%s' "$$" > "$ATEM_TUNNEL_FIXTURE/{provider}.pid"
if [ "$ATEM_TUNNEL_FAIL" = "{provider}" ]; then
  printf '%s\n' "$ATEM_TUNNEL_ERROR" >&2
  exit 1
fi
if [ "$ATEM_TUNNEL_SILENT" != 1 ]; then
  {announcement}
fi
exec /bin/sleep 60
"#
            );
            let path = bin.join(provider);
            std::fs::write(&path, script).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self { sandbox }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(atem_bin());
        command
            .env_clear()
            .envs(self.sandbox.env())
            .env("PATH", self.sandbox.dir.path().join("bin"))
            .env("ATEM_TUNNEL_FIXTURE", self.sandbox.dir.path())
            .stdin(Stdio::null());
        command
    }

    fn file(&self) -> std::path::PathBuf {
        let path = self.sandbox.dir.path().join("spec with spaces.md");
        std::fs::write(&path, "# Tunnel fixture\n").unwrap();
        path
    }

    fn read(&self, name: &str) -> String {
        std::fs::read_to_string(self.sandbox.dir.path().join(name)).unwrap_or_default()
    }

    fn pid(&self, provider: &str) -> u32 {
        self.read(&format!("{provider}.pid")).parse().unwrap()
    }

    fn assert_stopped(&self, providers: &[&str]) {
        for provider in providers {
            let pid = self.pid(provider);
            within("tunnel process reaped", || unsafe {
                libc::kill(pid as i32, 0) != 0
            });
        }
    }

    fn start(&self, command: &mut Command) -> Running {
        let log = self.sandbox.dir.path().join("output");
        let output = std::fs::File::create(log).unwrap();
        Running(
            command
                .stdout(output.try_clone().unwrap())
                .stderr(output)
                .spawn()
                .unwrap(),
        )
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Failure cleanup is confined to the PIDs recorded by this fixture.
        if let Ok(entries) = std::fs::read_dir(self.sandbox.config().join("servers")) {
            for path in entries.flatten().map(|entry| entry.path()) {
                if path.extension().is_some_and(|ext| ext == "json") {
                    if let Ok(value) = serde_json::from_str::<serde_json::Value>(
                        &std::fs::read_to_string(path).unwrap_or_default(),
                    ) {
                        if let Some(pid) = value["pid"].as_u64() {
                            unsafe {
                                libc::kill(pid as i32, libc::SIGTERM);
                            }
                        }
                    }
                }
            }
        }
        for provider in ["ngrok", "cloudflared"] {
            if let Ok(pid) = self.read(&format!("{provider}.pid")).parse::<i32>() {
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
            }
        }
    }
}

struct Running(Child);

impl Running {
    fn stop(&mut self, signal: i32) {
        unsafe {
            libc::kill(self.0.id() as i32, signal);
        }
        within("server shutdown", || self.0.try_wait().unwrap().is_some());
        assert!(self.0.wait().unwrap().success());
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn link<'a>(output: &'a str, label: &str) -> &'a str {
    output
        .lines()
        .find_map(|line| line.trim().strip_prefix(label).map(str::trim))
        .unwrap_or_else(|| panic!("missing {label}: {output}"))
}

fn check_links(output: &str, target: &str) {
    let lines: Vec<_> = output.lines().collect();
    let first = lines
        .iter()
        .position(|line| line.trim_start().starts_with("Local:"))
        .unwrap();
    for (offset, label) in ["Local:", "LAN:", "Cloudflared:", "Ngrok:"]
        .iter()
        .enumerate()
    {
        let line = lines[first + offset];
        assert!(line.trim_start().starts_with(label), "{output}");
        let value = line.split_once(':').unwrap().1.trim();
        assert_eq!(line.find(value), Some(16), "{line}");
    }
    if let Some(dir) = lines
        .get(first.wrapping_sub(1))
        .filter(|line| line.trim_start().starts_with("DIR:"))
    {
        assert_eq!(dir.find(dir.split_once(':').unwrap().1.trim()), Some(16));
    }
    if let Some(custom) = lines
        .get(first + 4)
        .filter(|line| line.trim_start().starts_with("Custom:"))
    {
        assert_eq!(custom.find("https://"), Some(16), "{custom}");
    }
    assert!(!output.contains("Network:"));
    let local = reqwest::Url::parse(link(output, "Local:")).unwrap();
    for label in ["Ngrok:", "Cloudflared:"] {
        let public = reqwest::Url::parse(link(output, label)).unwrap();
        assert_eq!(public.scheme(), "https");
        assert_eq!(public.path(), target);
        assert_eq!(public.query(), local.query());
        assert!(public.query().unwrap().starts_with("t="));
    }
}

#[test]
fn foreground_links_preserve_path_and_code_and_ctrl_c_reaps_tunnels() {
    let fixture = Fixture::new(&["ngrok", "cloudflared"]);
    let mut command = fixture.command();
    command
        .env("ATEM_EXTRA_HOSTNAMES", "fixture.example.org")
        .args(["serv", "files"])
        .arg(fixture.file())
        .arg("--no-browser");
    let mut server = fixture.start(&mut command);
    within("both public links", || {
        fixture.read("output").contains("Cloudflared:") && fixture.read("output").contains("Ngrok:")
    });
    let output = fixture.read("output");
    check_links(&output, "/spec%20with%20spaces.md");
    assert!(
        output
            .lines()
            .any(|line| line.trim_start().starts_with("Custom:"))
    );
    assert!(output.find("Custom:").unwrap() < output.find("Press Ctrl+C").unwrap());
    let local = reqwest::Url::parse(link(&output, "Local:")).unwrap();
    let origin = format!("https://127.0.0.1:{}", local.port().unwrap());
    assert!(fixture.read("ngrok.args").contains(&origin));
    assert!(
        fixture
            .read("ngrok.args")
            .contains("--upstream-tls-verify=false")
    );
    assert!(fixture.read("cloudflared.args").contains(&origin));
    assert!(fixture.read("cloudflared.args").contains("--no-tls-verify"));
    for provider in ["ngrok", "cloudflared"] {
        assert!(!fixture.read(&format!("{provider}.args")).contains("?t="));
    }
    server.stop(libc::SIGINT);
    fixture.assert_stopped(&["ngrok", "cloudflared"]);
}

#[test]
fn background_parent_prints_daemon_links_and_kill_reaps_tunnels() {
    let fixture = Fixture::new(&["ngrok", "cloudflared"]);
    let output = fixture
        .command()
        .args(["serv", "files"])
        .arg(fixture.file())
        .args(["--background", "--no-browser"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = String::from_utf8(output.stdout).unwrap();
    check_links(&output, "/spec%20with%20spaces.md");
    let id = link(&output, "ID:");
    let killed = fixture
        .command()
        .args(["serv", "kill", id])
        .output()
        .unwrap();
    assert!(killed.status.success());
    fixture.assert_stopped(&["ngrok", "cloudflared"]);
    within("server unregistered", || {
        !fixture
            .sandbox
            .config()
            .join("servers")
            .join(format!("{id}.json"))
            .exists()
    });
}

#[test]
fn unavailable_provider_keeps_other_links_and_local_server_working() {
    let fixture = Fixture::new(&["ngrok", "cloudflared"]);
    let mut command = fixture.command();
    command
        .env("ATEM_TUNNEL_FAIL", "ngrok")
        .args(["serv", "files"])
        .arg(fixture.file())
        .arg("--no-browser");
    let mut server = fixture.start(&mut command);
    within("failed provider diagnostic", || {
        fixture.read("output").contains("Ngrok link unavailable")
            && fixture.read("output").contains("Cloudflared:")
    });
    let output = fixture.read("output");
    assert_eq!(link(&output, "Ngrok:"), "(unavailable)");
    assert!(output.find("Cloudflared:").unwrap() < output.find("Ngrok:").unwrap());
    assert!(output.find("Ngrok:").unwrap() < output.find("warning:").unwrap());
    let local = link(&output, "Local:");
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        assert_eq!(client.get(local).send().await.unwrap().status(), 302);
        let mut no_code = reqwest::Url::parse(local).unwrap();
        no_code.set_query(None);
        assert_eq!(client.get(no_code).send().await.unwrap().status(), 404);
    });
    server.stop(libc::SIGTERM);
    fixture.assert_stopped(&["ngrok", "cloudflared"]);
}

#[test]
fn ngrok_endpoint_collision_reports_reason_without_raw_log_secrets() {
    let fixture = Fixture::new(&["ngrok", "cloudflared"]);
    let mut command = fixture.command();
    command
        .env("ATEM_TUNNEL_FAIL", "ngrok")
        .env(
            "ATEM_TUNNEL_ERROR",
            r#"{"msg":"command failed","err":"private diagnostic-secret-canary ERR_NGROK_334"}"#,
        )
        .args(["serv", "files"])
        .arg(fixture.file())
        .arg("--no-browser");
    let mut server = fixture.start(&mut command);
    within("ngrok failure reason", || {
        fixture.read("output").contains("ERR_NGROK_334")
            && fixture.read("output").contains("Cloudflared:")
    });
    let output = fixture.read("output");
    assert!(
        output.contains("configured ngrok endpoint is already online"),
        "{output}"
    );
    assert!(!output.contains("diagnostic-secret-canary"), "{output}");
    assert!(!output.contains("Check ngrok configuration"), "{output}");
    server.stop(libc::SIGTERM);
    fixture.assert_stopped(&["ngrok", "cloudflared"]);
}

#[test]
fn absent_tools_do_not_add_links_or_block_startup() {
    let fixture = Fixture::new(&[]);
    let output = fixture
        .command()
        .args(["serv", "files"])
        .arg(fixture.file())
        .args(["--background", "--no-browser"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let output = String::from_utf8(output.stdout).unwrap();
    assert!(output.contains("Local:"));
    assert!(!output.contains("Ngrok:"));
    assert!(!output.contains("Cloudflared:"));
    assert!(
        fixture
            .command()
            .args(["serv", "kill", link(&output, "ID:")])
            .status()
            .unwrap()
            .success()
    );
}

#[test]
fn shutdown_during_tunnel_startup_does_not_leave_processes() {
    let fixture = Fixture::new(&["ngrok", "cloudflared"]);
    let mut command = fixture.command();
    command
        .env("ATEM_TUNNEL_SILENT", "1")
        .args(["serv", "files"])
        .arg(fixture.file())
        .arg("--no-browser");
    let mut server = fixture.start(&mut command);
    within("tunnel startup", || {
        !fixture.read("ngrok.pid").is_empty() && !fixture.read("cloudflared.pid").is_empty()
    });
    server.stop(libc::SIGINT);
    fixture.assert_stopped(&["ngrok", "cloudflared"]);
}

#[test]
fn background_rtc_releases_parent_listener_before_waiting_for_tunnels() {
    let fixture = Fixture::new(&["ngrok", "cloudflared"]);
    let output = fixture
        .command()
        .env("AGORA_APP_ID", "a".repeat(32))
        .env("AGORA_APP_CERTIFICATE", "b".repeat(32))
        .args([
            "serv",
            "rtc",
            "--channel",
            "tunnel-fixture",
            "--port",
            "0",
            "--background",
            "--no-browser",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = String::from_utf8(output.stdout).unwrap();
    check_links(&output, "/");
    assert!(
        fixture
            .command()
            .args(["serv", "kill", link(&output, "ID:")])
            .status()
            .unwrap()
            .success()
    );
    fixture.assert_stopped(&["ngrok", "cloudflared"]);
}
