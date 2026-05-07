//! `atem serv files <DIR>` — static-file HTTPS server for sharing
//! AI-generated documents (md, html, png, …) on a remote machine.
//!
//! Foreground mode binds 0.0.0.0:<port>, prints Local/Network/Custom
//! URLs (matching `serv rtc`/`serv convo`), and serves files under
//! the chosen directory. Markdown files are rendered to HTML by
//! default; append `?raw=1` to any URL to view the raw bytes.
//!
//! Background mode re-execs as a detached daemon, registers in
//! `~/.config/atem/servers/files-<port>.json`, exits — manageable
//! via `atem serv list/kill/killall`.

use anyhow::{Context, Result, anyhow};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

pub struct ServeFilesConfig {
    pub dir: PathBuf,
    pub port: u16,
    pub no_browser: bool,
    pub background: bool,
    /// Hidden flag — set when re-execed as the daemon child.
    pub _daemon: bool,
}

pub async fn run_server(cfg: ServeFilesConfig) -> Result<()> {
    // Accept either a directory or a single file. For a file, the
    // parent directory becomes the served root and the URL points at
    // the file (so siblings remain browsable, and the auto-opened
    // browser lands directly on the doc).
    let path = cfg.dir.canonicalize()
        .with_context(|| format!("Path does not exist: {}", cfg.dir.display()))?;
    let (root, target_path): (PathBuf, String) = if path.is_file() {
        let parent = path.parent()
            .ok_or_else(|| anyhow!("file has no parent directory: {}", path.display()))?
            .to_path_buf();
        let name = path.file_name()
            .ok_or_else(|| anyhow!("invalid filename: {}", path.display()))?
            .to_string_lossy().to_string();
        (parent, format!("/{}", urlencoding::encode(&name)))
    } else if path.is_dir() {
        (path, "/".to_string())
    } else {
        anyhow::bail!("Not a file or directory: {}", path.display());
    };

    // ── Background fork: parent re-execs the daemon, registers, exits ──
    if cfg.background && !cfg._daemon {
        // Auto-pick a port if not given. Parent briefly binds 0 to
        // discover an OS-assigned port, drops the listener, then
        // hands the port to the daemon. The race window between
        // drop and child re-bind is sub-millisecond locally; if you
        // care about it, pass --port explicitly.
        let port = if cfg.port == 0 {
            let probe = std::net::TcpListener::bind(("0.0.0.0", 0))
                .context("failed to probe a free port")?;
            probe.local_addr()?.port()
        } else {
            cfg.port
        };

        let exe = std::env::current_exe()?;
        let log_dir = crate::rtc_test_server::servers_dir();
        std::fs::create_dir_all(&log_dir)?;
        let sid = format!("files-{}", port);
        let log_path = log_dir.join(format!("{}.log", sid));
        let log_file = std::fs::File::create(&log_path)?;

        let daemon_args: Vec<String> = vec![
            "serv".into(), "files".into(),
            cfg.dir.display().to_string(),
            "--port".into(), port.to_string(),
            "--background".into(),
            "--no-browser".into(),
            "--serv-daemon".into(),
        ];

        let child = std::process::Command::new(exe)
            .args(&daemon_args)
            .stdin(std::process::Stdio::null())
            .stdout(log_file.try_clone()?)
            .stderr(log_file)
            .spawn()?;

        let lan_ip = crate::web_server::net::get_lan_ip();
        let sslip  = crate::web_server::net::sslip_host(&lan_ip);
        let extra_hostnames = crate::config::AtemConfig::load()
            .map(|c| c.extra_hostnames())
            .unwrap_or_default();
        let local_url   = format!("https://localhost:{}{}", port, target_path);
        let network_url = format!("https://{}:{}{}", sslip, port, target_path);
        let custom_urls: Vec<String> = extra_hostnames
            .iter()
            .map(|h| format!("https://{}:{}{}", h.trim(), port, target_path))
            .collect();
        let entry = crate::rtc_test_server::ServerEntry {
            id: sid.clone(),
            pid: child.id(),
            kind: "files".to_string(),
            port,
            channel: String::new(),
            local_url:   local_url.clone(),
            network_url: network_url.clone(),
            started_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            last_status: None,
            last_checked_at: None,
        };
        crate::rtc_test_server::register_server(&entry)?;

        println!("atem serv files");
        println!("  dir:     {}", root.display());
        println!("  Local:   {}", local_url);
        println!("  Network: {}", network_url);
        for u in &custom_urls {
            println!("  Custom:  {}", u);
        }
        println!("  ID:      {}", sid);
        println!("  PID:     {}", child.id());
        println!("  Log:     {}", log_path.display());
        println!();
        println!("Use `atem serv list` to see running servers.");
        println!("Use `atem serv kill {}` (or `killall`) to stop.", sid);
        return Ok(());
    }

    // ── Bind ───────────────────────────────────────────────────────────
    let lan_ip = crate::web_server::net::get_lan_ip();
    let sslip  = crate::web_server::net::sslip_host(&lan_ip);
    let extra_hostnames = crate::config::AtemConfig::load()
        .map(|c| c.extra_hostnames())
        .unwrap_or_default();
    let (certs, key) =
        crate::web_server::cert::generate_self_signed_cert(&lan_ip, &extra_hostnames)?;
    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let bind_addr = std::net::SocketAddr::from(([0, 0, 0, 0], cfg.port));
    let listener  = TcpListener::bind(bind_addr).await
        .with_context(|| format!("Failed to bind {}", bind_addr))?;
    let bound_port = listener.local_addr()?.port();

    let local_url   = format!("https://localhost:{}{}", bound_port, target_path);
    let network_url = format!("https://{}:{}{}", sslip, bound_port, target_path);
    let custom_urls: Vec<String> = extra_hostnames
        .iter()
        .map(|h| format!("https://{}:{}{}", h.trim(), bound_port, target_path))
        .collect();

    let header = if cfg._daemon { "atem serv files (daemon)" } else { "atem serv files" };
    println!("{}", header);
    println!("  dir:     {}", root.display());
    println!("  Local:   {}", local_url);
    println!("  Network: {}", network_url);
    for u in &custom_urls {
        println!("  Custom:  {}", u);
    }
    if !cfg._daemon {
        println!();
        println!("Press Ctrl+C to stop.");
    }
    println!();

    if !cfg.no_browser && !cfg._daemon {
        let _ = crate::web_server::browser::open_browser(&local_url);
    }

    let root = Arc::new(root);
    loop {
        let (stream, _) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let root = root.clone();
        tokio::spawn(async move {
            if let Ok(tls) = acceptor.accept(stream).await {
                let _ = handle_connection(tls, &root).await;
            }
        });
    }
}

async fn handle_connection<S>(mut stream: S, root: &Path) -> Result<()>
where S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    // Read the request line + headers (we ignore body — GET only).
    let mut buf = [0u8; 8192];
    let n = stream.read(&mut buf).await?;
    if n == 0 { return Ok(()); }
    let head = std::str::from_utf8(&buf[..n]).unwrap_or("");
    let request_line = head.lines().next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("/");

    if method != "GET" && method != "HEAD" {
        return write_response(&mut stream, 405, "text/plain", b"Method Not Allowed").await;
    }

    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let raw_mode = query.split('&').any(|p| p == "raw=1");

    let response = match resolve_path(root, path) {
        Ok(fs_path) => serve_path(&fs_path, root, path, raw_mode).await,
        Err(_) => Response::status(404, "text/plain", b"Not Found".to_vec()),
    };

    write_response(&mut stream, response.status, &response.content_type, &response.body).await
}

struct Response {
    status: u16,
    content_type: String,
    body: Vec<u8>,
}

impl Response {
    fn status(status: u16, ct: &str, body: Vec<u8>) -> Self {
        Self { status, content_type: ct.to_string(), body }
    }
    fn ok(ct: &str, body: Vec<u8>) -> Self {
        Self::status(200, ct, body)
    }
}

/// Resolve URL path → filesystem path under `root`. Rejects `..`
/// traversal and ensures the result is contained in `root`.
fn resolve_path(root: &Path, url_path: &str) -> Result<PathBuf> {
    // Strip leading slash, percent-decode each segment, reject `..`.
    let trimmed = url_path.trim_start_matches('/');
    let mut out = root.to_path_buf();
    for seg in trimmed.split('/') {
        if seg.is_empty() { continue; }
        let decoded = urlencoding::decode(seg)
            .map_err(|_| anyhow!("bad encoding"))?
            .into_owned();
        if decoded == ".." || decoded == "." || decoded.contains('\0') {
            return Err(anyhow!("rejected path segment"));
        }
        out.push(decoded);
    }
    // Final canonicalize-or-best-effort: if file exists, canonicalize and
    // ensure we're still under root. If it doesn't exist (e.g. /missing.md
    // — let serve_path return 404), still verify the parent is under root.
    let check = if out.exists() { out.canonicalize()? } else { out.clone() };
    if !check.starts_with(root) {
        return Err(anyhow!("escaped root"));
    }
    Ok(out)
}

async fn serve_path(fs_path: &Path, root: &Path, url_path: &str, raw: bool) -> Response {
    if !fs_path.exists() {
        return Response::status(404, "text/plain", b"Not Found".to_vec());
    }
    if fs_path.is_dir() {
        // Auto-serve index.html / index.md when present.
        for idx in &["index.html", "index.md", "README.md"] {
            let candidate = fs_path.join(idx);
            if candidate.is_file() {
                return serve_file(&candidate, raw);
            }
        }
        return render_directory(fs_path, root, url_path);
    }
    serve_file(fs_path, raw)
}

fn serve_file(path: &Path, raw: bool) -> Response {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(_) => return Response::status(500, "text/plain", b"Read error".to_vec()),
    };
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase();
    let is_md = matches!(ext.as_str(), "md" | "markdown");
    if is_md && !raw {
        let text = String::from_utf8_lossy(&bytes);
        let html = render_markdown(&text, path);
        return Response::ok("text/html; charset=utf-8", html.into_bytes());
    }
    let ct = match ext.as_str() {
        "html" | "htm"   => "text/html; charset=utf-8",
        "md" | "markdown"=> "text/markdown; charset=utf-8",
        "txt" | "log"    => "text/plain; charset=utf-8",
        "css"            => "text/css; charset=utf-8",
        "js"             => "application/javascript; charset=utf-8",
        "json"           => "application/json; charset=utf-8",
        "png"            => "image/png",
        "jpg" | "jpeg"   => "image/jpeg",
        "gif"            => "image/gif",
        "svg"            => "image/svg+xml",
        "webp"           => "image/webp",
        "ico"            => "image/x-icon",
        "pdf"            => "application/pdf",
        _                => "application/octet-stream",
    };
    Response::ok(ct, bytes)
}

fn render_markdown(src: &str, path: &Path) -> String {
    use pulldown_cmark::{Parser, Options, html};
    let mut opts = Options::empty();
    opts.insert(Options::ENABLE_TABLES);
    opts.insert(Options::ENABLE_FOOTNOTES);
    opts.insert(Options::ENABLE_STRIKETHROUGH);
    opts.insert(Options::ENABLE_TASKLISTS);
    let parser = Parser::new_ext(src, opts);
    let mut body = String::new();
    html::push_html(&mut body, parser);

    let title = path.file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("file");
    let title_esc = html_escape(title);
    let body_esc_link = format!("?raw=1");
    format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
* {{ box-sizing: border-box; }}
body {{
  margin: 0; padding: 32px;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
  font-size: 16px; line-height: 1.6;
  color: #1f2328; background: #fff;
  max-width: 920px; margin-inline: auto;
}}
.toolbar {{
  display: flex; justify-content: flex-end;
  border-bottom: 1px solid #d1d9e0; margin-bottom: 24px; padding-bottom: 8px;
}}
.toolbar a {{ color: #0969da; text-decoration: none; font-size: 13px; }}
.toolbar a:hover {{ text-decoration: underline; }}
h1, h2, h3, h4 {{ border-bottom: 1px solid #eaecef; padding-bottom: 6px; }}
h1 {{ font-size: 2em; }} h2 {{ font-size: 1.5em; }}
code {{ background: #f6f8fa; padding: 2px 6px; border-radius: 4px; font-size: 85%; font-family: ui-monospace, SFMono-Regular, monospace; }}
pre {{ background: #f6f8fa; padding: 16px; border-radius: 6px; overflow-x: auto; }}
pre code {{ background: transparent; padding: 0; }}
table {{ border-collapse: collapse; width: 100%; }}
table th, table td {{ border: 1px solid #d0d7de; padding: 6px 13px; }}
table th {{ background: #f6f8fa; }}
blockquote {{ border-left: 4px solid #d0d7de; color: #57606a; padding-left: 16px; margin-left: 0; }}
a {{ color: #0969da; }}
img {{ max-width: 100%; }}
ul, ol {{ padding-left: 28px; }}
hr {{ border: none; border-top: 1px solid #d1d9e0; margin: 24px 0; }}
</style>
</head>
<body>
<div class="toolbar">
  <a href="{raw}">View raw</a>
</div>
{body}
</body>
</html>
"#, title = title_esc, raw = body_esc_link, body = body)
}

fn render_directory(fs_path: &Path, root: &Path, url_path: &str) -> Response {
    let mut entries: Vec<_> = match std::fs::read_dir(fs_path) {
        Ok(rd) => rd.filter_map(|e| e.ok()).collect(),
        Err(_) => return Response::status(500, "text/plain", b"Read error".to_vec()),
    };
    // Skip dotfiles (.git, .env, …) — common AI-doc trees include them
    // and exposing them by accident is the wrong default.
    entries.retain(|e| {
        e.file_name().to_str().map(|n| !n.starts_with('.')).unwrap_or(false)
    });
    entries.sort_by_key(|e| e.file_name());

    let display_path = if url_path == "/" || url_path.is_empty() {
        root.display().to_string()
    } else {
        url_path.to_string()
    };
    let display_esc = html_escape(&display_path);

    let mut rows = String::new();
    if url_path != "/" && !url_path.is_empty() {
        rows.push_str(r#"<li><a href="../">../</a></li>"#);
    }
    for e in &entries {
        let name = e.file_name().to_string_lossy().to_string();
        let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
        let suffix = if is_dir { "/" } else { "" };
        let href = urlencoding::encode(&name).to_string();
        rows.push_str(&format!(
            r#"<li><a href="{href}{suffix}">{name_esc}{suffix}</a></li>"#,
            href = href, suffix = suffix, name_esc = html_escape(&name),
        ));
    }
    let body = format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Index of {display}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, system-ui, sans-serif; padding: 32px; max-width: 920px; margin-inline: auto; }}
h1 {{ font-size: 1.2em; color: #57606a; font-weight: 500; word-break: break-all; }}
ul {{ list-style: none; padding: 0; }}
li {{ padding: 4px 0; }}
a {{ color: #0969da; text-decoration: none; }}
a:hover {{ text-decoration: underline; }}
</style>
</head>
<body>
<h1>Index of {display}</h1>
<ul>
{rows}
</ul>
</body>
</html>
"#, display = display_esc, rows = rows);
    Response::ok("text/html; charset=utf-8", body.into_bytes())
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

async fn write_response<S>(stream: &mut S, status: u16, ct: &str, body: &[u8]) -> Result<()>
where S: tokio::io::AsyncWrite + Unpin,
{
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        _   => "OK",
    };
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status, reason, ct, body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn resolve_path_rejects_traversal() {
        let td = TempDir::new().unwrap();
        let root = td.path().canonicalize().unwrap();
        assert!(resolve_path(&root, "/../etc/passwd").is_err());
        assert!(resolve_path(&root, "/foo/../../etc").is_err());
        assert!(resolve_path(&root, "/./hidden").is_err());
    }

    #[test]
    fn resolve_path_accepts_files_under_root() {
        let td = TempDir::new().unwrap();
        let root = td.path().canonicalize().unwrap();
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("sub/a.md"), "hi").unwrap();
        let got = resolve_path(&root, "/sub/a.md").unwrap();
        assert!(got.ends_with("sub/a.md"));
    }

    #[test]
    fn resolve_path_decodes_percent_encoding() {
        let td = TempDir::new().unwrap();
        let root = td.path().canonicalize().unwrap();
        std::fs::write(root.join("hello world.md"), "x").unwrap();
        let got = resolve_path(&root, "/hello%20world.md").unwrap();
        assert!(got.ends_with("hello world.md"));
    }

    #[test]
    fn render_markdown_wraps_in_html_with_raw_link() {
        let html = render_markdown("# Hello\n\n**bold**", Path::new("test.md"));
        assert!(html.contains("<h1>Hello</h1>"));
        assert!(html.contains("<strong>bold</strong>"));
        assert!(html.contains(r#"href="?raw=1""#), "raw view link missing");
        assert!(html.contains("<title>test.md</title>"));
    }

    #[test]
    fn serve_file_md_renders_to_html_by_default() {
        let td = TempDir::new().unwrap();
        let p = td.path().join("doc.md");
        std::fs::write(&p, "# Hi").unwrap();
        let r = serve_file(&p, false);
        assert_eq!(r.status, 200);
        assert!(r.content_type.starts_with("text/html"));
        assert!(String::from_utf8_lossy(&r.body).contains("<h1>Hi</h1>"));
    }

    #[test]
    fn serve_file_md_raw_returns_text() {
        let td = TempDir::new().unwrap();
        let p = td.path().join("doc.md");
        std::fs::write(&p, "# Hi").unwrap();
        let r = serve_file(&p, true);
        assert_eq!(r.content_type, "text/markdown; charset=utf-8");
        assert_eq!(r.body, b"# Hi");
    }

    #[test]
    fn serve_file_picks_content_type_by_extension() {
        let td = TempDir::new().unwrap();
        let p = td.path().join("page.html");
        std::fs::write(&p, "<p>hi</p>").unwrap();
        let r = serve_file(&p, false);
        assert!(r.content_type.starts_with("text/html"));
    }

    #[test]
    fn single_file_path_resolves_to_parent_with_target() {
        // Mirror the resolution logic at the top of run_server: when
        // the given path is a file, root = parent, target = "/<name>".
        let td = TempDir::new().unwrap();
        let f = td.path().join("spec.md");
        std::fs::write(&f, "# x").unwrap();
        let canon = f.canonicalize().unwrap();
        assert!(canon.is_file());
        let parent = canon.parent().unwrap().to_path_buf();
        let name = canon.file_name().unwrap().to_string_lossy().to_string();
        let target = format!("/{}", urlencoding::encode(&name));
        assert_eq!(target, "/spec.md");
        assert!(parent.is_dir());
    }

    #[test]
    fn single_file_with_spaces_url_encoded() {
        let td = TempDir::new().unwrap();
        let f = td.path().join("hello world.md");
        std::fs::write(&f, "x").unwrap();
        let canon = f.canonicalize().unwrap();
        let name = canon.file_name().unwrap().to_string_lossy().to_string();
        let target = format!("/{}", urlencoding::encode(&name));
        assert_eq!(target, "/hello%20world.md");
    }

    #[test]
    fn render_directory_skips_dotfiles() {
        let td = TempDir::new().unwrap();
        let root = td.path().canonicalize().unwrap();
        std::fs::write(root.join(".hidden"), "x").unwrap();
        std::fs::write(root.join("visible.md"), "y").unwrap();
        let r = render_directory(&root, &root, "/");
        let body = String::from_utf8_lossy(&r.body);
        assert!(body.contains("visible.md"));
        assert!(!body.contains(".hidden"));
    }
}
