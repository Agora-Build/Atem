use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Read an HTTP request from the TLS stream until headers are complete and
/// `Content-Length` bytes of body have arrived. Returns:
///   - Ok(Some(bytes)) — full request available
///   - Ok(None)        — connection closed before any data
///   - Err(_)          — IO error
///
/// Caps total request size at 64KiB to avoid memory exhaustion.
pub async fn read_full_http_request(
    stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
) -> Result<Option<Vec<u8>>> {
    const MAX_BYTES: usize = 64 * 1024;
    const HEADER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];

    // Phase 1: read until \r\n\r\n is in the buffer (or limit hit).
    let headers_end = loop {
        let read_fut = stream.read(&mut tmp);
        let n = match tokio::time::timeout(HEADER_TIMEOUT, read_fut).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => anyhow::bail!("timeout waiting for headers"),
        };
        if n == 0 {
            // Closed cleanly with no full request.
            return Ok(if buf.is_empty() { None } else { Some(buf) });
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(idx) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break idx + 4;
        }
        if buf.len() >= MAX_BYTES {
            anyhow::bail!("request headers exceeded {} bytes", MAX_BYTES);
        }
    };

    // Phase 2: parse Content-Length (case-insensitive) from headers.
    let header_str = String::from_utf8_lossy(&buf[..headers_end]);
    let content_length: usize = header_str
        .lines()
        .find_map(|line| {
            let mut parts = line.splitn(2, ':');
            let name = parts.next()?.trim();
            let value = parts.next()?.trim();
            if name.eq_ignore_ascii_case("Content-Length") {
                value.parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);

    // Phase 3: read until body is complete.
    let target_total = headers_end + content_length;
    if target_total > MAX_BYTES {
        anyhow::bail!("Content-Length {} exceeds limit", content_length);
    }
    while buf.len() < target_total {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            // Connection closed mid-body — return what we have.
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }

    Ok(Some(buf))
}

/// Extract the HTTP body (after the blank line).
pub fn extract_body(request: &str) -> String {
    if let Some(idx) = request.find("\r\n\r\n") {
        request[idx + 4..].to_string()
    } else if let Some(idx) = request.find("\n\n") {
        request[idx + 2..].to_string()
    } else {
        String::new()
    }
}

/// Write an HTTP response.
pub async fn send_response(
    stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
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
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n",
        status, status_text, content_type, body.len()
    );

    stream.write_all(header.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_body_from_http_request() {
        let req = "POST /api/token HTTP/1.1\r\nHost: localhost\r\nContent-Length: 37\r\n\r\n{\"channel\":\"test\",\"uid\":\"123\"}";
        let body = extract_body(req);
        assert_eq!(body, "{\"channel\":\"test\",\"uid\":\"123\"}");
    }

    #[test]
    fn extract_body_empty_when_no_blank_line() {
        let req = "GET / HTTP/1.1\r\nHost: localhost";
        let body = extract_body(req);
        assert!(body.is_empty());
    }
}
