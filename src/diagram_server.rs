/// Diagram hosting server — SQLite blob storage + HTTP serving.
///
/// `atem serv diagrams` runs a lightweight HTTP server that stores HTML diagrams
/// in a SQLite database and serves them at `/d/{id}`.
use anyhow::Result;
use rusqlite::Connection;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::rtc_test_server::{ServerEntry, get_lan_ip, servers_dir};

/// Default port for the diagram server.
pub const DEFAULT_PORT: u16 = 8787;

// ── SQLite diagram store ───────────────────────────────────────────────

/// Entry returned when fetching a diagram.
pub struct DiagramEntry {
    pub id: String,
    pub topic: String,
    pub html: Vec<u8>,
    pub created_at: i64,
}

/// Metadata returned when listing diagrams.
#[derive(serde::Serialize)]
pub struct DiagramMeta {
    pub id: String,
    pub topic: String,
    pub created_at: i64,
}

/// SQLite-backed diagram store.
pub struct DiagramStore {
    conn: Connection,
}

impl DiagramStore {
    /// Open (or create) the SQLite database at the given path.
    pub fn open(path: &std::path::Path) -> Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS diagrams (
                id         TEXT PRIMARY KEY,
                topic      TEXT NOT NULL,
                html       BLOB NOT NULL,
                created_at INTEGER NOT NULL
            );",
        )?;
        Ok(Self { conn })
    }

    /// Default database path: `~/.config/atem/diagrams.db`.
    pub fn db_path() -> PathBuf {
        crate::config::AtemConfig::config_dir().join("diagrams.db")
    }

    /// Insert a diagram, returning its 8-char alphanumeric ID.
    pub fn insert(&self, topic: &str, html: &[u8]) -> Result<String> {
        let id = generate_id();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        self.conn.execute(
            "INSERT INTO diagrams (id, topic, html, created_at) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![id, topic, html, now],
        )?;
        Ok(id)
    }

    /// Fetch a diagram by ID.
    pub fn get(&self, id: &str) -> Option<DiagramEntry> {
        self.conn
            .query_row(
                "SELECT id, topic, html, created_at FROM diagrams WHERE id = ?1",
                rusqlite::params![id],
                |row| {
                    Ok(DiagramEntry {
                        id: row.get(0)?,
                        topic: row.get(1)?,
                        html: row.get(2)?,
                        created_at: row.get(3)?,
                    })
                },
            )
            .ok()
    }

    /// List recent diagrams (newest first).
    pub fn list(&self, limit: usize) -> Vec<DiagramMeta> {
        let mut stmt = match self.conn.prepare(
            "SELECT id, topic, created_at FROM diagrams ORDER BY created_at DESC LIMIT ?1",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = match stmt.query_map(rusqlite::params![limit as i64], |row| {
            Ok(DiagramMeta {
                id: row.get(0)?,
                topic: row.get(1)?,
                created_at: row.get(2)?,
            })
        }) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        rows.flatten().collect()
    }

    /// Delete a diagram by ID. Returns true if a row was deleted.
    pub fn delete(&self, id: &str) -> bool {
        self.conn
            .execute("DELETE FROM diagrams WHERE id = ?1", rusqlite::params![id])
            .map(|n| n > 0)
            .unwrap_or(false)
    }
}

/// Generate an 8-char alphanumeric ID.
fn generate_id() -> String {
    use rand::Rng;
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..8)
        .map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char)
        .collect()
}

// ── HTTP server ────────────────────────────────────────────────────────

/// Configuration for `atem serv diagrams`.
pub struct DiagramServerConfig {
    pub port: u16,
    pub background: bool,
    pub _daemon: bool,
}

/// Run the diagram hosting HTTP server.
pub async fn run_server(config: DiagramServerConfig) -> Result<()> {
    let lan_ip = get_lan_ip();
    let bind_addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    let listener = TcpListener::bind(bind_addr).await?;
    let port = listener.local_addr()?.port();

    let local_url = format!("http://localhost:{}", port);
    let network_url = format!("http://{}:{}", lan_ip, port);

    // ── Background mode: re-exec as daemon ─────────────────────────
    if config.background && !config._daemon {
        return spawn_background_daemon(port, &local_url, &network_url);
    }

    // ── Daemon mode: register self and set up cleanup ──────────────
    let sid = server_id(port);
    if config._daemon {
        let entry = build_server_entry(&sid, port, &local_url, &network_url);
        register_server(&entry)?;

        let cleanup_id = sid.clone();
        ctrlc::set_handler(move || {
            let _ = unregister_server(&cleanup_id);
            std::process::exit(0);
        })
        .ok();
    }

    // ── Foreground output ──────────────────────────────────────────
    println!("Diagram server running:");
    println!("  Local:   {}", local_url);
    println!("  Network: {}", network_url);
    println!();
    println!("Press Ctrl+C to stop.");
    println!();

    let db_path = DiagramStore::db_path();
    let store = Arc::new(Mutex::new(DiagramStore::open(&db_path)?));
    let network_url = Arc::new(network_url);

    loop {
        let (stream, peer) = listener.accept().await?;
        let store = store.clone();
        let network_url = network_url.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, peer, &store, &network_url).await {
                eprintln!("[{}] Error: {}", peer, e);
            }
        });
    }
}

/// Handle a single HTTP connection.
async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    _peer: SocketAddr,
    store: &Arc<Mutex<DiagramStore>>,
    server_url: &str,
) -> Result<()> {
    let mut buf = vec![0u8; 2 * 1024 * 1024]; // 2 MB max request
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }
    let request = String::from_utf8_lossy(&buf[..n]).to_string();

    let first_line = request.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        send_response(&mut stream, 400, "text/plain", b"Bad Request").await?;
        return Ok(());
    }
    let method = parts[0];
    let path = parts[1];

    match (method, path) {
        ("GET", "/") => {
            let html = build_landing_page(store, server_url);
            send_response(&mut stream, 200, "text/html; charset=utf-8", html.as_bytes()).await?;
        }
        ("GET", "/favicon.ico") => {
            send_response(&mut stream, 204, "text/plain", b"").await?;
        }
        ("POST", "/api/diagrams") => {
            let body = extract_body(&request);
            handle_post_diagram(&mut stream, &body, store, server_url).await?;
        }
        ("GET", "/api/diagrams") => {
            handle_list_diagrams(&mut stream, store).await?;
        }
        ("OPTIONS", _) => {
            // CORS preflight
            send_response(&mut stream, 204, "text/plain", b"").await?;
        }
        _ if method == "GET" && path.starts_with("/d/") => {
            let id = &path[3..];
            handle_get_diagram(&mut stream, id, store).await?;
        }
        _ if method == "DELETE" && path.starts_with("/api/diagrams/") => {
            let id = &path["/api/diagrams/".len()..];
            handle_delete_diagram(&mut stream, id, store).await?;
        }
        _ => {
            send_response(&mut stream, 404, "text/plain", b"Not Found").await?;
        }
    }

    Ok(())
}

/// POST /api/diagrams — store a new diagram.
async fn handle_post_diagram(
    stream: &mut tokio::net::TcpStream,
    body: &str,
    store: &Arc<Mutex<DiagramStore>>,
    server_url: &str,
) -> Result<()> {
    let parsed: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => {
            let err = r#"{"error":"Invalid JSON body"}"#;
            send_response(stream, 400, "application/json", err.as_bytes()).await?;
            return Ok(());
        }
    };

    let topic = parsed["topic"].as_str().unwrap_or("untitled");
    let html = match parsed["html"].as_str() {
        Some(h) => h,
        None => {
            let err = r#"{"error":"Missing 'html' field"}"#;
            send_response(stream, 400, "application/json", err.as_bytes()).await?;
            return Ok(());
        }
    };

    let result = {
        let db = store.lock().unwrap();
        db.insert(topic, html.as_bytes())
    };
    let id = match result {
        Ok(id) => id,
        Err(e) => {
            let err = serde_json::json!({"error": format!("Store failed: {}", e)});
            send_response(stream, 500, "application/json", err.to_string().as_bytes()).await?;
            return Ok(());
        }
    };

    let url = format!("{}/d/{}", server_url, id);
    let resp = serde_json::json!({ "id": id, "url": url });
    send_response(stream, 200, "application/json", resp.to_string().as_bytes()).await?;
    Ok(())
}

/// GET /d/{id} — serve HTML diagram.
async fn handle_get_diagram(
    stream: &mut tokio::net::TcpStream,
    id: &str,
    store: &Arc<Mutex<DiagramStore>>,
) -> Result<()> {
    let entry = {
        let db = store.lock().unwrap();
        db.get(id)
    };
    match entry {
        Some(e) => {
            send_response(stream, 200, "text/html; charset=utf-8", &e.html).await?;
        }
        None => {
            send_response(stream, 404, "text/plain", b"Diagram not found").await?;
        }
    }
    Ok(())
}

/// GET /api/diagrams — list recent diagrams as JSON.
async fn handle_list_diagrams(
    stream: &mut tokio::net::TcpStream,
    store: &Arc<Mutex<DiagramStore>>,
) -> Result<()> {
    let diagrams = {
        let db = store.lock().unwrap();
        db.list(100)
    };
    let json = serde_json::to_string(&diagrams).unwrap_or_else(|_| "[]".to_string());
    send_response(stream, 200, "application/json", json.as_bytes()).await?;
    Ok(())
}

/// DELETE /api/diagrams/{id} — remove a diagram.
async fn handle_delete_diagram(
    stream: &mut tokio::net::TcpStream,
    id: &str,
    store: &Arc<Mutex<DiagramStore>>,
) -> Result<()> {
    let deleted = {
        let db = store.lock().unwrap();
        db.delete(id)
    };
    if deleted {
        let resp = serde_json::json!({"deleted": true});
        send_response(stream, 200, "application/json", resp.to_string().as_bytes()).await?;
    } else {
        send_response(stream, 404, "text/plain", b"Diagram not found").await?;
    }
    Ok(())
}

// ── HTTP helpers ───────────────────────────────────────────────────────

/// Extract the HTTP body after the blank line separator.
fn extract_body(request: &str) -> String {
    if let Some(idx) = request.find("\r\n\r\n") {
        request[idx + 4..].to_string()
    } else if let Some(idx) = request.find("\n\n") {
        request[idx + 2..].to_string()
    } else {
        String::new()
    }
}

/// Write an HTTP response with CORS headers.
async fn send_response(
    stream: &mut tokio::net::TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> Result<()> {
    let status_text = match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "Unknown",
    };
    let header = format!(
        "HTTP/1.1 {} {}\r\n\
         Content-Type: {}\r\n\
         Content-Length: {}\r\n\
         Access-Control-Allow-Origin: *\r\n\
         Access-Control-Allow-Methods: GET, POST, DELETE, OPTIONS\r\n\
         Access-Control-Allow-Headers: Content-Type\r\n\
         Connection: close\r\n\r\n",
        status, status_text, content_type, body.len()
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    Ok(())
}

// ── Landing page ───────────────────────────────────────────────────────

/// Build a simple landing page listing recent diagrams.
fn build_landing_page(store: &Arc<Mutex<DiagramStore>>, server_url: &str) -> String {
    let diagrams = {
        let db = store.lock().unwrap();
        db.list(50)
    };

    let mut rows = String::new();
    for d in &diagrams {
        let ts = chrono_lite(d.created_at);
        rows.push_str(&format!(
            "<tr><td><a href=\"/d/{}\">{}</a></td><td>{}</td><td>{}</td></tr>\n",
            d.id, d.id, html_escape(&d.topic), ts
        ));
    }

    if rows.is_empty() {
        rows = "<tr><td colspan=\"3\" style=\"text-align:center;color:#7d8590\">No diagrams yet</td></tr>".to_string();
    }

    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Atem Diagrams</title>
<style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif; background:#0d1117; color:#e6edf3; min-height:100vh; padding:24px; }}
h1 {{ font-size:20px; margin-bottom:16px; }}
table {{ width:100%; border-collapse:collapse; }}
th,td {{ text-align:left; padding:8px 12px; border-bottom:1px solid #30363d; }}
th {{ color:#7d8590; font-size:12px; text-transform:uppercase; }}
a {{ color:#58a6ff; text-decoration:none; }}
a:hover {{ text-decoration:underline; }}
.url {{ font-size:12px; color:#7d8590; margin-bottom:16px; }}
</style>
</head>
<body>
<h1>Atem Diagrams</h1>
<p class="url">Server: {server_url}</p>
<table>
<thead><tr><th>ID</th><th>Topic</th><th>Created</th></tr></thead>
<tbody>
{rows}
</tbody>
</table>
</body>
</html>"##,
        server_url = server_url,
        rows = rows,
    )
}

/// Minimal timestamp formatter (no chrono dependency).
fn chrono_lite(unix_secs: i64) -> String {
    // Just show as relative or ISO-ish. Keep it simple.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let ago = now - unix_secs;
    if ago < 60 {
        "just now".to_string()
    } else if ago < 3600 {
        format!("{}m ago", ago / 60)
    } else if ago < 86400 {
        format!("{}h ago", ago / 3600)
    } else {
        format!("{}d ago", ago / 86400)
    }
}

/// Basic HTML escaping.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

// ── Background daemon / server registry ────────────────────────────────

/// Deterministic server ID for diagram server.
fn server_id(port: u16) -> String {
    format!("diagrams-{}", port)
}

fn build_server_entry(sid: &str, port: u16, local_url: &str, network_url: &str) -> ServerEntry {
    ServerEntry {
        id: sid.to_string(),
        pid: std::process::id(),
        kind: "diagrams".to_string(),
        port,
        channel: String::new(),
        local_url: local_url.to_string(),
        network_url: network_url.to_string(),
        started_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    }
}

fn register_server(entry: &ServerEntry) -> Result<()> {
    let dir = servers_dir();
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.json", entry.id));
    let json = serde_json::to_string_pretty(entry)?;
    std::fs::write(path, json)?;
    Ok(())
}

fn unregister_server(id: &str) -> Result<()> {
    let path = servers_dir().join(format!("{}.json", id));
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

/// Spawn `atem serv diagrams --_serv-daemon` as a detached background process.
fn spawn_background_daemon(port: u16, local_url: &str, network_url: &str) -> Result<()> {
    let exe = std::env::current_exe()?;
    let log_dir = servers_dir();
    std::fs::create_dir_all(&log_dir)?;
    let sid = server_id(port);
    let log_path = log_dir.join(format!("{}.log", sid));
    let log_file = std::fs::File::create(&log_path)?;

    let child = std::process::Command::new(exe)
        .args([
            "serv",
            "diagrams",
            "--port",
            &port.to_string(),
            "--_serv-daemon",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(log_file.try_clone()?)
        .stderr(log_file)
        .spawn()?;

    let entry = ServerEntry {
        id: sid.clone(),
        pid: child.id(),
        kind: "diagrams".to_string(),
        port,
        channel: String::new(),
        local_url: local_url.to_string(),
        network_url: network_url.to_string(),
        started_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };
    register_server(&entry)?;

    println!("Diagram server started in background:");
    println!("  ID:      {}", sid);
    println!("  PID:     {}", child.id());
    println!("  Local:   {}", local_url);
    println!("  Network: {}", network_url);
    println!("  Log:     {}", log_path.display());
    println!();
    println!("Use `atem serv list` to see running servers.");
    println!("Use `atem serv kill {}` to stop it.", sid);
    Ok(())
}

// ── Auto-start helper ──────────────────────────────────────────────────

/// Ensure a diagram server is running.  Returns the server URL (e.g. `http://192.168.1.5:8787`).
///
/// Checks the server registry for a running diagram server.  If none found,
/// spawns `atem serv diagrams --background` and waits briefly for it to start.
pub fn ensure_running() -> Result<String> {
    // Check existing servers
    let dir = servers_dir();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let data = match std::fs::read_to_string(&path) {
                Ok(d) => d,
                Err(_) => continue,
            };
            let server: ServerEntry = match serde_json::from_str(&data) {
                Ok(s) => s,
                Err(_) => continue,
            };
            if server.kind == "diagrams" && is_pid_alive(server.pid) {
                return Ok(server.network_url);
            }
        }
    }

    // No running diagram server — spawn one
    let lan_ip = get_lan_ip();
    let port = DEFAULT_PORT;
    let local_url = format!("http://localhost:{}", port);
    let network_url = format!("http://{}:{}", lan_ip, port);

    spawn_background_daemon(port, &local_url, &network_url)?;

    // Wait briefly for the server to start accepting connections
    std::thread::sleep(std::time::Duration::from_millis(500));

    Ok(network_url)
}

/// Check if a PID is still alive.
fn is_pid_alive(pid: u32) -> bool {
    unsafe { libc::kill(pid as i32, 0) == 0 }
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── ID generation ─────────────────────────────────────────────────

    #[test]
    fn test_generate_id_length() {
        let id = generate_id();
        assert_eq!(id.len(), 8);
    }

    #[test]
    fn test_generate_id_alphanumeric() {
        let id = generate_id();
        assert!(id.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
    }

    #[test]
    fn test_generate_id_uniqueness() {
        let ids: Vec<String> = (0..100).map(|_| generate_id()).collect();
        let unique: std::collections::HashSet<&String> = ids.iter().collect();
        assert_eq!(unique.len(), ids.len());
    }

    // ── DiagramStore CRUD ─────────────────────────────────────────────

    #[test]
    fn test_diagram_store_round_trip() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = DiagramStore::open(tmp.path()).unwrap();

        let html = b"<html><body>Hello</body></html>";
        let id = store.insert("test topic", html).unwrap();
        assert_eq!(id.len(), 8);

        let entry = store.get(&id).unwrap();
        assert_eq!(entry.topic, "test topic");
        assert_eq!(entry.html, html);
        assert_eq!(entry.id, id);
        assert!(entry.created_at > 0);
    }

    #[test]
    fn test_diagram_store_get_missing() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = DiagramStore::open(tmp.path()).unwrap();
        assert!(store.get("nonexist").is_none());
    }

    #[test]
    fn test_diagram_store_insert_multiple_same_topic() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = DiagramStore::open(tmp.path()).unwrap();

        let id1 = store.insert("same topic", b"<html>v1</html>").unwrap();
        let id2 = store.insert("same topic", b"<html>v2</html>").unwrap();

        // Different IDs for different inserts
        assert_ne!(id1, id2);

        let e1 = store.get(&id1).unwrap();
        let e2 = store.get(&id2).unwrap();
        assert_eq!(e1.html, b"<html>v1</html>");
        assert_eq!(e2.html, b"<html>v2</html>");
    }

    #[test]
    fn test_diagram_store_empty_html() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = DiagramStore::open(tmp.path()).unwrap();

        let id = store.insert("empty", b"").unwrap();
        let entry = store.get(&id).unwrap();
        assert!(entry.html.is_empty());
    }

    #[test]
    fn test_diagram_store_empty_topic() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = DiagramStore::open(tmp.path()).unwrap();

        let id = store.insert("", b"<html></html>").unwrap();
        let entry = store.get(&id).unwrap();
        assert_eq!(entry.topic, "");
    }

    #[test]
    fn test_diagram_store_list() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = DiagramStore::open(tmp.path()).unwrap();

        store.insert("first", b"<html>1</html>").unwrap();
        store.insert("second", b"<html>2</html>").unwrap();

        let list = store.list(10);
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn test_diagram_store_list_empty() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = DiagramStore::open(tmp.path()).unwrap();
        let list = store.list(10);
        assert!(list.is_empty());
    }

    #[test]
    fn test_diagram_store_list_limit() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = DiagramStore::open(tmp.path()).unwrap();

        for i in 0..5 {
            store.insert(&format!("topic {}", i), b"<html></html>").unwrap();
        }

        let list = store.list(3);
        assert_eq!(list.len(), 3);
    }

    #[test]
    fn test_diagram_store_list_newest_first() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = DiagramStore::open(tmp.path()).unwrap();

        // Insert with explicit timestamps via raw SQL to guarantee ordering
        store.conn.execute(
            "INSERT INTO diagrams (id, topic, html, created_at) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params!["aaaaaaaa", "older", b"<html>old</html>".to_vec(), 1000],
        ).unwrap();
        store.conn.execute(
            "INSERT INTO diagrams (id, topic, html, created_at) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params!["bbbbbbbb", "newer", b"<html>new</html>".to_vec(), 2000],
        ).unwrap();

        let list = store.list(10);
        assert_eq!(list.len(), 2);
        // Newest first (created_at=2000 before created_at=1000)
        assert_eq!(list[0].topic, "newer");
        assert_eq!(list[1].topic, "older");
    }

    #[test]
    fn test_diagram_store_list_contains_metadata() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = DiagramStore::open(tmp.path()).unwrap();

        let id = store.insert("meta test", b"<html></html>").unwrap();
        let list = store.list(10);

        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, id);
        assert_eq!(list[0].topic, "meta test");
        assert!(list[0].created_at > 0);
    }

    #[test]
    fn test_diagram_store_delete() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = DiagramStore::open(tmp.path()).unwrap();

        let id = store.insert("to delete", b"<html>bye</html>").unwrap();
        assert!(store.get(&id).is_some());

        assert!(store.delete(&id));
        assert!(store.get(&id).is_none());
    }

    #[test]
    fn test_diagram_store_delete_missing() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = DiagramStore::open(tmp.path()).unwrap();
        assert!(!store.delete("nope"));
    }

    #[test]
    fn test_diagram_store_delete_removes_from_list() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = DiagramStore::open(tmp.path()).unwrap();

        let id = store.insert("will delete", b"<html></html>").unwrap();
        assert_eq!(store.list(10).len(), 1);

        store.delete(&id);
        assert_eq!(store.list(10).len(), 0);
    }

    #[test]
    fn test_diagram_store_large_html() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = DiagramStore::open(tmp.path()).unwrap();

        let large_html = vec![b'x'; 500_000];
        let id = store.insert("large diagram", &large_html).unwrap();

        let entry = store.get(&id).unwrap();
        assert_eq!(entry.html.len(), 500_000);
    }

    #[test]
    fn test_diagram_store_binary_html() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = DiagramStore::open(tmp.path()).unwrap();

        // HTML with all byte values (blob storage must handle arbitrary bytes)
        let html: Vec<u8> = (0..=255).collect();
        let id = store.insert("binary", &html).unwrap();
        let entry = store.get(&id).unwrap();
        assert_eq!(entry.html, html);
    }

    #[test]
    fn test_diagram_store_unicode_topic() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = DiagramStore::open(tmp.path()).unwrap();

        let id = store.insert("WebRTC architecture", b"<html></html>").unwrap();
        let entry = store.get(&id).unwrap();
        assert_eq!(entry.topic, "WebRTC architecture");
    }

    #[test]
    fn test_diagram_store_special_chars_topic() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = DiagramStore::open(tmp.path()).unwrap();

        let topic = "auth <system> & \"flow\" 100% (v2)";
        let id = store.insert(topic, b"<html></html>").unwrap();
        let entry = store.get(&id).unwrap();
        assert_eq!(entry.topic, topic);
    }

    #[test]
    fn test_diagram_store_reopen_persists() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();

        let id = {
            let store = DiagramStore::open(&path).unwrap();
            store.insert("persist test", b"<html>data</html>").unwrap()
        };

        // Reopen the DB — data should still be there
        let store2 = DiagramStore::open(&path).unwrap();
        let entry = store2.get(&id).unwrap();
        assert_eq!(entry.topic, "persist test");
        assert_eq!(entry.html, b"<html>data</html>");
    }

    // ── Path / config ─────────────────────────────────────────────────

    #[test]
    fn test_db_path_under_config() {
        let path = DiagramStore::db_path();
        assert!(path.to_string_lossy().contains("atem"));
        assert!(path.to_string_lossy().ends_with("diagrams.db"));
    }

    #[test]
    fn test_server_id_format() {
        assert_eq!(server_id(8787), "diagrams-8787");
        assert_eq!(server_id(0), "diagrams-0");
    }

    #[test]
    fn test_build_server_entry_fields() {
        let entry = build_server_entry("diagrams-8787", 8787, "http://localhost:8787", "http://10.0.0.1:8787");
        assert_eq!(entry.id, "diagrams-8787");
        assert_eq!(entry.kind, "diagrams");
        assert_eq!(entry.port, 8787);
        assert_eq!(entry.channel, ""); // diagrams have no channel
        assert_eq!(entry.local_url, "http://localhost:8787");
        assert_eq!(entry.network_url, "http://10.0.0.1:8787");
        assert_eq!(entry.pid, std::process::id());
        assert!(entry.started_at > 0);
    }

    #[test]
    fn test_build_server_entry_serializes() {
        let entry = build_server_entry("diagrams-9000", 9000, "http://localhost:9000", "http://10.0.0.1:9000");
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("diagrams-9000"));
        assert!(json.contains("\"kind\":\"diagrams\""));

        // Deserialize back
        let parsed: ServerEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, "diagrams-9000");
        assert_eq!(parsed.port, 9000);
    }

    // ── HTTP helpers ──────────────────────────────────────────────────

    #[test]
    fn test_extract_body() {
        let req = "POST /api/diagrams HTTP/1.1\r\nHost: localhost\r\n\r\n{\"topic\":\"test\"}";
        assert_eq!(extract_body(req), "{\"topic\":\"test\"}");
    }

    #[test]
    fn test_extract_body_lf_only() {
        let req = "POST /api/diagrams HTTP/1.1\nHost: localhost\n\n{\"topic\":\"lf\"}";
        assert_eq!(extract_body(req), "{\"topic\":\"lf\"}");
    }

    #[test]
    fn test_extract_body_empty() {
        let req = "GET / HTTP/1.1\r\nHost: localhost";
        assert!(extract_body(req).is_empty());
    }

    #[test]
    fn test_extract_body_empty_body() {
        let req = "POST /api/diagrams HTTP/1.1\r\nHost: localhost\r\n\r\n";
        assert_eq!(extract_body(req), "");
    }

    #[test]
    fn test_html_escape() {
        assert_eq!(html_escape("<script>alert('xss')</script>"), "&lt;script&gt;alert('xss')&lt;/script&gt;");
        assert_eq!(html_escape("a & b"), "a &amp; b");
        assert_eq!(html_escape("\"hello\""), "&quot;hello&quot;");
    }

    #[test]
    fn test_html_escape_clean_string() {
        assert_eq!(html_escape("hello world"), "hello world");
    }

    #[test]
    fn test_html_escape_empty() {
        assert_eq!(html_escape(""), "");
    }

    #[test]
    fn test_chrono_lite() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        assert_eq!(chrono_lite(now), "just now");
        assert_eq!(chrono_lite(now - 30), "just now");
        assert!(chrono_lite(now - 120).contains("m ago"));
        assert!(chrono_lite(now - 7200).contains("h ago"));
        assert!(chrono_lite(now - 172800).contains("d ago"));
    }

    #[test]
    fn test_chrono_lite_boundary_values() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Exact boundaries
        assert_eq!(chrono_lite(now - 59), "just now");
        assert!(chrono_lite(now - 60).contains("m ago"));
        assert!(chrono_lite(now - 3599).contains("m ago"));
        assert!(chrono_lite(now - 3600).contains("h ago"));
        assert!(chrono_lite(now - 86399).contains("h ago"));
        assert!(chrono_lite(now - 86400).contains("d ago"));
    }

    // ── Landing page ──────────────────────────────────────────────────

    #[test]
    fn test_landing_page_empty_store() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = Arc::new(Mutex::new(DiagramStore::open(tmp.path()).unwrap()));

        let html = build_landing_page(&store, "http://localhost:8787");
        assert!(html.contains("Atem Diagrams"));
        assert!(html.contains("No diagrams yet"));
        assert!(html.contains("http://localhost:8787"));
    }

    #[test]
    fn test_landing_page_with_diagrams() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = Arc::new(Mutex::new(DiagramStore::open(tmp.path()).unwrap()));

        let id = {
            let db = store.lock().unwrap();
            db.insert("WebRTC flow", b"<html>diagram</html>").unwrap()
        };

        let html = build_landing_page(&store, "http://10.0.0.5:8787");
        assert!(html.contains(&id));
        assert!(html.contains("WebRTC flow"));
        assert!(html.contains(&format!("/d/{}", id))); // clickable link
        assert!(html.contains("http://10.0.0.5:8787"));
        assert!(!html.contains("No diagrams yet"));
    }

    #[test]
    fn test_landing_page_escapes_xss_topic() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = Arc::new(Mutex::new(DiagramStore::open(tmp.path()).unwrap()));

        {
            let db = store.lock().unwrap();
            db.insert("<script>alert(1)</script>", b"<html></html>").unwrap();
        }

        let html = build_landing_page(&store, "http://localhost:8787");
        // XSS must be escaped
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(html.contains("&lt;script&gt;"));
    }

    // ── HTTP server end-to-end ────────────────────────────────────────

    /// Helper: start a diagram server on an ephemeral port, return (port, store).
    async fn start_test_server() -> (u16, Arc<Mutex<DiagramStore>>) {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = Arc::new(Mutex::new(DiagramStore::open(tmp.path()).unwrap()));
        // Keep the tempfile alive by leaking the path (test only)
        std::mem::forget(tmp);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server_url = format!("http://127.0.0.1:{}", port);

        let store_clone = store.clone();
        tokio::spawn(async move {
            loop {
                if let Ok((stream, peer)) = listener.accept().await {
                    let s = store_clone.clone();
                    let url = server_url.clone();
                    tokio::spawn(async move {
                        let _ = handle_connection(stream, peer, &s, &url).await;
                    });
                }
            }
        });

        // Wait for server to be ready
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        (port, store)
    }

    /// Send a raw HTTP request and read the response.
    async fn http_request(port: u16, request: &str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        stream.flush().await.unwrap();

        let mut buf = vec![0u8; 1024 * 1024];
        let n = stream.read(&mut buf).await.unwrap();
        String::from_utf8_lossy(&buf[..n]).to_string()
    }

    #[tokio::test]
    async fn test_http_get_landing_page() {
        let (port, _store) = start_test_server().await;
        let resp = http_request(port, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").await;

        assert!(resp.starts_with("HTTP/1.1 200 OK"));
        assert!(resp.contains("text/html"));
        assert!(resp.contains("Atem Diagrams"));
    }

    #[tokio::test]
    async fn test_http_post_and_get_diagram() {
        let (port, _store) = start_test_server().await;

        // POST a diagram
        let body = r#"{"topic":"auth flow","html":"<html><body>Auth Diagram</body></html>"}"#;
        let req = format!(
            "POST /api/diagrams HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let resp = http_request(port, &req).await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"));
        assert!(resp.contains("\"id\""));
        assert!(resp.contains("\"url\""));

        // Extract ID from response
        let body_start = resp.find('{').unwrap();
        let json: serde_json::Value = serde_json::from_str(&resp[body_start..]).unwrap();
        let id = json["id"].as_str().unwrap();
        let url = json["url"].as_str().unwrap();
        assert_eq!(id.len(), 8);
        assert!(url.contains(&format!("/d/{}", id)));

        // GET the diagram
        let get_req = format!("GET /d/{} HTTP/1.1\r\nHost: localhost\r\n\r\n", id);
        let get_resp = http_request(port, &get_req).await;
        assert!(get_resp.starts_with("HTTP/1.1 200 OK"));
        assert!(get_resp.contains("text/html"));
        assert!(get_resp.contains("Auth Diagram"));
    }

    #[tokio::test]
    async fn test_http_get_diagram_not_found() {
        let (port, _store) = start_test_server().await;

        let resp = http_request(port, "GET /d/nonexist HTTP/1.1\r\nHost: localhost\r\n\r\n").await;
        assert!(resp.starts_with("HTTP/1.1 404"));
        assert!(resp.contains("Diagram not found"));
    }

    #[tokio::test]
    async fn test_http_list_diagrams_empty() {
        let (port, _store) = start_test_server().await;

        let resp = http_request(port, "GET /api/diagrams HTTP/1.1\r\nHost: localhost\r\n\r\n").await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"));
        assert!(resp.contains("application/json"));
        let body_start = resp.find('[').unwrap();
        let json: serde_json::Value = serde_json::from_str(&resp[body_start..]).unwrap();
        assert!(json.as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_http_list_diagrams_with_entries() {
        let (port, store) = start_test_server().await;

        // Insert directly into store
        {
            let db = store.lock().unwrap();
            db.insert("topic A", b"<html>A</html>").unwrap();
            db.insert("topic B", b"<html>B</html>").unwrap();
        }

        let resp = http_request(port, "GET /api/diagrams HTTP/1.1\r\nHost: localhost\r\n\r\n").await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"));
        let body_start = resp.find('[').unwrap();
        let json: serde_json::Value = serde_json::from_str(&resp[body_start..]).unwrap();
        assert_eq!(json.as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_http_delete_diagram() {
        let (port, store) = start_test_server().await;

        let id = {
            let db = store.lock().unwrap();
            db.insert("to delete", b"<html>bye</html>").unwrap()
        };

        // DELETE
        let req = format!("DELETE /api/diagrams/{} HTTP/1.1\r\nHost: localhost\r\n\r\n", id);
        let resp = http_request(port, &req).await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"));
        assert!(resp.contains("\"deleted\":true"));

        // Verify gone
        let get_resp = http_request(port, &format!("GET /d/{} HTTP/1.1\r\nHost: localhost\r\n\r\n", id)).await;
        assert!(get_resp.starts_with("HTTP/1.1 404"));
    }

    #[tokio::test]
    async fn test_http_delete_not_found() {
        let (port, _store) = start_test_server().await;

        let resp = http_request(port, "DELETE /api/diagrams/nope HTTP/1.1\r\nHost: localhost\r\n\r\n").await;
        assert!(resp.starts_with("HTTP/1.1 404"));
    }

    #[tokio::test]
    async fn test_http_post_invalid_json() {
        let (port, _store) = start_test_server().await;

        let body = "not json at all";
        let req = format!(
            "POST /api/diagrams HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let resp = http_request(port, &req).await;
        assert!(resp.starts_with("HTTP/1.1 400"));
        assert!(resp.contains("Invalid JSON"));
    }

    #[tokio::test]
    async fn test_http_post_missing_html_field() {
        let (port, _store) = start_test_server().await;

        let body = r#"{"topic":"no html field"}"#;
        let req = format!(
            "POST /api/diagrams HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let resp = http_request(port, &req).await;
        assert!(resp.starts_with("HTTP/1.1 400"));
        assert!(resp.contains("Missing 'html' field"));
    }

    #[tokio::test]
    async fn test_http_post_defaults_topic() {
        let (port, _store) = start_test_server().await;

        // No topic field — should default to "untitled"
        let body = r#"{"html":"<html>no topic</html>"}"#;
        let req = format!(
            "POST /api/diagrams HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let resp = http_request(port, &req).await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"));
    }

    #[tokio::test]
    async fn test_http_404_unknown_route() {
        let (port, _store) = start_test_server().await;

        let resp = http_request(port, "GET /unknown HTTP/1.1\r\nHost: localhost\r\n\r\n").await;
        assert!(resp.starts_with("HTTP/1.1 404"));
    }

    #[tokio::test]
    async fn test_http_options_cors_preflight() {
        let (port, _store) = start_test_server().await;

        let resp = http_request(port, "OPTIONS /api/diagrams HTTP/1.1\r\nHost: localhost\r\n\r\n").await;
        assert!(resp.starts_with("HTTP/1.1 204"));
        assert!(resp.contains("Access-Control-Allow-Origin"));
        assert!(resp.contains("Access-Control-Allow-Methods"));
    }

    #[tokio::test]
    async fn test_http_cors_headers_on_response() {
        let (port, _store) = start_test_server().await;

        let resp = http_request(port, "GET /api/diagrams HTTP/1.1\r\nHost: localhost\r\n\r\n").await;
        assert!(resp.contains("Access-Control-Allow-Origin: *"));
    }

    #[tokio::test]
    async fn test_http_favicon_returns_204() {
        let (port, _store) = start_test_server().await;

        let resp = http_request(port, "GET /favicon.ico HTTP/1.1\r\nHost: localhost\r\n\r\n").await;
        assert!(resp.starts_with("HTTP/1.1 204"));
    }

    #[tokio::test]
    async fn test_http_full_cycle_post_list_get_delete() {
        let (port, _store) = start_test_server().await;

        // 1. List — empty
        let resp = http_request(port, "GET /api/diagrams HTTP/1.1\r\nHost: localhost\r\n\r\n").await;
        let body_start = resp.find('[').unwrap();
        let json: serde_json::Value = serde_json::from_str(&resp[body_start..]).unwrap();
        assert_eq!(json.as_array().unwrap().len(), 0);

        // 2. POST a diagram
        let body = r#"{"topic":"cycle test","html":"<html>cycle</html>"}"#;
        let req = format!(
            "POST /api/diagrams HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{}",
            body.len(), body
        );
        let resp = http_request(port, &req).await;
        let body_start = resp.find('{').unwrap();
        let json: serde_json::Value = serde_json::from_str(&resp[body_start..]).unwrap();
        let id = json["id"].as_str().unwrap().to_string();

        // 3. List — now has 1
        let resp = http_request(port, "GET /api/diagrams HTTP/1.1\r\nHost: localhost\r\n\r\n").await;
        let body_start = resp.find('[').unwrap();
        let json: serde_json::Value = serde_json::from_str(&resp[body_start..]).unwrap();
        assert_eq!(json.as_array().unwrap().len(), 1);
        assert_eq!(json[0]["topic"].as_str().unwrap(), "cycle test");

        // 4. GET the HTML
        let resp = http_request(port, &format!("GET /d/{} HTTP/1.1\r\nHost: localhost\r\n\r\n", id)).await;
        assert!(resp.contains("<html>cycle</html>"));

        // 5. DELETE
        let resp = http_request(port, &format!("DELETE /api/diagrams/{} HTTP/1.1\r\nHost: localhost\r\n\r\n", id)).await;
        assert!(resp.contains("\"deleted\":true"));

        // 6. List — empty again
        let resp = http_request(port, "GET /api/diagrams HTTP/1.1\r\nHost: localhost\r\n\r\n").await;
        let body_start = resp.find('[').unwrap();
        let json: serde_json::Value = serde_json::from_str(&resp[body_start..]).unwrap();
        assert_eq!(json.as_array().unwrap().len(), 0);

        // 7. GET returns 404 after delete
        let resp = http_request(port, &format!("GET /d/{} HTTP/1.1\r\nHost: localhost\r\n\r\n", id)).await;
        assert!(resp.starts_with("HTTP/1.1 404"));
    }
}
