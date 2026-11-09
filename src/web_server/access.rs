//! Access codes for the `atem serv` pages and APIs (rtc, convo, files and the
//! webhooks console).
//!
//! Each server start makes a random code (16 bytes, base64url) and prints its
//! URLs with `?t=<code>`. A request carrying the code gets a cookie for this
//! port and a redirect to the same URL without the code, so it doesn't stay
//! in the address bar or the history; later requests (pages and API calls)
//! carry the cookie. Anything else is a plain 404, so a scan of the network
//! learns nothing. Pages are sent with `Referrer-Policy: no-referrer`.
//!
//! A `--background` server passes its code to the daemon it starts in
//! [`ENV`] (never on the command line, which `ps` shows to every user).
//!
//! Since the code leaves the address bar, every page has a **Copy link**
//! button ([`copy_link_button`], [`COPY_LINK`]): it asks [`LINK_PATH`] for the
//! code (only with the cookie, never cached) and copies the page's URL with
//! the code added back, on whichever host the page was opened.

use base64::Engine;
use rand::RngCore;

/// The daemon of a `--background` server reads its code here.
pub const ENV: &str = "ATEM_SERV_ACCESS_CODE";

/// The query parameter carrying the code.
const PARAM: &str = "t";

/// The path a page's Copy link asks for the code (answered for every server
/// by [`admit`], only with the cookie).
pub const LINK_PATH: &str = "/__atem/link";

/// What a request may do.
#[derive(Debug, PartialEq, Eq)]
pub enum Gate {
    /// It carries this server's cookie: serve it.
    Open,
    /// It carries the code in its URL: answer with these bytes (the cookie
    /// and a redirect to the same URL without the code).
    Enter(Vec<u8>),
    /// Neither: answer with these bytes (a plain 404).
    Closed(Vec<u8>),
    /// It carries the cookie and asks for [`LINK_PATH`]: answer with these
    /// bytes (the code as JSON, never cached).
    Link(Vec<u8>),
}

/// One server's access code.
pub struct AccessCode {
    code: String,
    cookie: String,
    secure: bool,
}

impl AccessCode {
    /// The code for a server on `port`: the one a parent handed over in
    /// [`ENV`] (a `--background` daemon), else a new random one. `secure`:
    /// the server speaks HTTPS (the cookie is marked `Secure`).
    pub fn for_server(port: u16, secure: bool) -> Self {
        // Read only: changing the environment isn't safe once the runtime's
        // threads run, and only this user can read a process's environment.
        let handed = std::env::var(ENV).ok().filter(|c| valid(c));
        #[cfg(test)]
        let handed = handed.or_else(|| TEST_CODE.with(|c| c.borrow().clone()));
        Self::new(handed.unwrap_or_else(generate), port, secure)
    }

    fn new(code: String, port: u16, secure: bool) -> Self {
        Self {
            code,
            // Cookies ignore the port: one name per port keeps two servers
            // on one host apart.
            cookie: format!("atem_access_{port}"),
            secure,
        }
    }

    /// The code, for a daemon's environment ([`ENV`]).
    pub fn code(&self) -> &str {
        &self.code
    }

    /// `url` with the code added (`?t=` or `&t=`).
    pub fn url(&self, url: &str) -> String {
        let sep = if url.contains('?') { '&' } else { '?' };
        format!("{url}{sep}{PARAM}={}", self.code)
    }

    /// Whether the request with this head (request line and headers) may
    /// be served.
    pub fn gate(&self, head: &str) -> Gate {
        let target = head
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .unwrap_or("");
        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        if self.has_cookie(head) {
            if path == LINK_PATH {
                return Gate::Link(self.link());
            }
            return Gate::Open;
        }
        let mut carried = false;
        let rest: Vec<&str> = query
            .split('&')
            .filter(|kv| !kv.is_empty())
            .filter(|kv| match kv.split_once('=') {
                Some((PARAM, value)) if same(value, &self.code) => {
                    carried = true;
                    false
                }
                _ => true,
            })
            .collect();
        if !carried {
            return Gate::Closed(not_found());
        }
        let path = if path.starts_with('/') { path } else { "/" };
        let location = if rest.is_empty() {
            path.to_string()
        } else {
            format!("{path}?{}", rest.join("&"))
        };
        Gate::Enter(self.enter(&location))
    }

    fn has_cookie(&self, head: &str) -> bool {
        head.lines()
            .skip(1)
            .take_while(|line| !line.is_empty())
            .filter_map(|line| line.split_once(':'))
            .filter(|(name, _)| name.trim().eq_ignore_ascii_case("cookie"))
            .flat_map(|(_, value)| value.split(';'))
            .filter_map(|pair| pair.trim().split_once('='))
            .any(|(name, value)| name == self.cookie && same(value, &self.code))
    }

    fn link(&self) -> Vec<u8> {
        let body = format!("{{\"{PARAM}\":\"{}\"}}", self.code);
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    fn enter(&self, location: &str) -> Vec<u8> {
        let secure = if self.secure { "; Secure" } else { "" };
        format!(
            "HTTP/1.1 302 Found\r\nLocation: {location}\r\nSet-Cookie: {}={}; HttpOnly; SameSite=Lax; Path=/{secure}\r\nReferrer-Policy: no-referrer\r\nCache-Control: no-store\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            self.cookie, self.code
        )
        .into_bytes()
    }
}

/// Answers a request that may not be served ([`Gate::Enter`] or
/// [`Gate::Closed`]) on `stream`; `true` when it may (the caller serves it).
pub async fn admit<W>(stream: &mut W, access: &AccessCode, head: &str) -> anyhow::Result<bool>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    let bytes = match access.gate(head) {
        Gate::Open => return Ok(true),
        Gate::Enter(bytes) | Gate::Closed(bytes) | Gate::Link(bytes) => bytes,
    };
    stream.write_all(&bytes).await?;
    stream.flush().await?;
    Ok(false)
}

/// A page's Copy link button; the page also includes [`COPY_LINK`].
pub fn copy_link_button(class: &str) -> String {
    format!(r#"<button type="button" class="{class}" data-atem-copy-link>Copy link</button>"#)
}

/// The script behind every Copy link button: it asks [`LINK_PATH`] for the
/// code, adds it to this page's URL (its host, path, other parameters and
/// fragment kept) and copies the link. When clipboard access is unavailable
/// or denied, the link is shown to copy instead.
pub const COPY_LINK: &str = r#"<script>
(function () {
  async function copyLink(button) {
    const label = button.textContent;
    try {
      const answer = await fetch('/__atem/link', { cache: 'no-store', credentials: 'same-origin' });
      if (!answer.ok) throw new Error('HTTP ' + answer.status);
      const url = new URL(location.href);
      url.searchParams.set('t', (await answer.json()).t);
      const link = url.toString();
      if (window.isSecureContext && navigator.clipboard) {
        try {
          await navigator.clipboard.writeText(link);
          button.textContent = 'Copied';
          setTimeout(function () { button.textContent = label; }, 1500);
          return;
        } catch (_) { /* A browser may deny clipboard access after the fetch. */ }
      }
      window.prompt('Copy this link (it includes the access code):', link);
    } catch (err) {
      console.warn('Copy link failed', err);
      button.textContent = 'Copy failed';
    }
    setTimeout(function () { button.textContent = label; }, 1500);
  }
  document.addEventListener('click', function (event) {
    const button = event.target.closest('[data-atem-copy-link]');
    if (button) { event.preventDefault(); copyLink(button); }
  });
})();
</script>"#;

#[cfg(test)]
thread_local! {
    static TEST_CODE: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

/// Servers started on this thread use `code` (tests that talk to a real
/// server).
#[cfg(test)]
pub fn use_code_for_test(code: &str) {
    TEST_CODE.with(|c| *c.borrow_mut() = Some(code.to_string()));
}

/// A new random code: 16 bytes, base64url without padding (22 characters).
fn generate() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// A code this module could have made.
fn valid(code: &str) -> bool {
    code.len() == 22
        && code
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Equal, in time that depends on the length only.
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

/// A plain 404, the same as an unknown path's.
fn not_found() -> Vec<u8> {
    b"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: 9\r\nConnection: close\r\n\r\nNot Found"
        .to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    const CODE: &str = "AbCdEfGhIjKlMnOpQrStUv";

    fn code() -> AccessCode {
        AccessCode::new(CODE.into(), 9443, true)
    }

    fn get(target: &str, headers: &str) -> String {
        format!("GET {target} HTTP/1.1\r\nHost: localhost:9443\r\n{headers}\r\n")
    }

    fn text(gate: Gate) -> String {
        match gate {
            Gate::Enter(b) | Gate::Closed(b) | Gate::Link(b) => String::from_utf8(b).unwrap(),
            Gate::Open => "open".into(),
        }
    }

    #[test]
    fn a_page_with_the_cookie_gets_its_code_for_copy_link() {
        let code = code();
        let cookie = format!("Cookie: atem_access_9443={CODE}\r\n");
        let Gate::Link(bytes) = code.gate(&get(LINK_PATH, &cookie)) else {
            panic!("not answered with the link code");
        };
        let answer = String::from_utf8(bytes).unwrap();
        assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"), "{answer}");
        assert!(
            answer.contains("Content-Type: application/json\r\n"),
            "{answer}"
        );
        assert!(answer.contains("Cache-Control: no-store\r\n"), "{answer}");
        assert!(
            answer.ends_with(&format!("{{\"t\":\"{CODE}\"}}")),
            "{answer}"
        );
        // Without the cookie: the same 404 as any unknown request.
        assert_eq!(
            text(code.gate(&get(LINK_PATH, ""))),
            String::from_utf8(not_found()).unwrap()
        );
        // Other pages are still served by the server itself.
        assert_eq!(code.gate(&get("/", &cookie)), Gate::Open);
    }

    #[test]
    fn copy_link_asks_for_the_code_and_adds_it_to_this_page() {
        assert!(COPY_LINK.contains(LINK_PATH));
        assert!(COPY_LINK.contains("searchParams.set('t'"));
        assert!(COPY_LINK.contains("[data-atem-copy-link]"));
        assert!(COPY_LINK.contains("isSecureContext"));
        assert!(copy_link_button("x").contains("data-atem-copy-link"));
    }

    #[test]
    fn a_request_without_the_code_or_cookie_is_a_plain_404() {
        let code = code();
        for head in [
            get("/", ""),
            get("/api/token", ""),
            get("/?t=wrong", ""),
            get("/?t=AbCdEfGhIjKlMnOpQrStUw", ""),
            get("/", "Cookie: atem_access_9443=wrong\r\n"),
            // Another port's cookie (cookies ignore the port).
            get("/", &format!("Cookie: atem_access_9444={CODE}\r\n")),
        ] {
            let gate = code.gate(&head);
            assert!(matches!(gate, Gate::Closed(_)), "{head:?}");
            assert!(text(gate).starts_with("HTTP/1.1 404 Not Found\r\n"));
        }
    }

    #[test]
    fn the_code_sets_the_cookie_and_redirects_without_it() {
        let code = code();
        let response = text(code.gate(&get(&format!("/?t={CODE}"), "")));
        assert!(response.starts_with("HTTP/1.1 302 Found\r\n"), "{response}");
        assert!(response.contains("\r\nLocation: /\r\n"), "{response}");
        assert!(
            response.contains(&format!(
                "\r\nSet-Cookie: atem_access_9443={CODE}; HttpOnly; SameSite=Lax; Path=/; Secure\r\n"
            )),
            "{response}"
        );
        assert!(response.contains("\r\nReferrer-Policy: no-referrer\r\n"));
        // Other parameters and the path stay.
        let response = text(code.gate(&get(&format!("/docs/a.md?x=1&t={CODE}&y=2"), "")));
        assert!(
            response.contains("\r\nLocation: /docs/a.md?x=1&y=2\r\n"),
            "{response}"
        );
    }

    #[test]
    fn the_cookie_opens_every_path() {
        let code = code();
        let cookie = format!("Cookie: other=1; atem_access_9443={CODE}\r\n");
        assert_eq!(code.gate(&get("/", &cookie)), Gate::Open);
        assert_eq!(code.gate(&get("/api/convo/history", &cookie)), Gate::Open);
        let lower = format!("cookie: atem_access_9443={CODE}\r\n");
        assert_eq!(code.gate(&get("/events", &lower)), Gate::Open);
    }

    #[test]
    fn a_plain_http_server_sets_no_secure_cookie() {
        let code = AccessCode::new(CODE.into(), 8090, false);
        let response = text(code.gate(&get(&format!("/?t={CODE}"), "")));
        assert!(response.contains("Path=/\r\n"), "{response}");
        assert!(!response.contains("Secure"));
    }

    #[test]
    fn urls_carry_the_code() {
        let code = code();
        assert_eq!(
            code.url("https://localhost:9443/"),
            format!("https://localhost:9443/?t={CODE}")
        );
        assert_eq!(
            code.url("https://h:1/a?x=1"),
            format!("https://h:1/a?x=1&t={CODE}")
        );
    }

    #[test]
    fn new_codes_are_random_and_well_formed() {
        let (a, b) = (generate(), generate());
        assert_ne!(a, b);
        assert!(valid(&a) && valid(&b), "{a} {b}");
        assert!(!valid("short") && !valid("AbCdEfGhIjKlMnOpQrStU!"));
        assert!(same(CODE, CODE) && !same(CODE, "AbCdEfGhIjKlMnOpQrStUw") && !same(CODE, "x"));
    }
}
