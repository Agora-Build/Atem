//! A worker's session log: the agent's output (bounded to its last 1 MiB)
//! and, when the agent ends after printing something,
//! `<logs>/<session_id>/session.ansi` and `summary.md` (directories 0700,
//! files 0600, written atomically). Only what the agent printed is kept:
//! never the launch environment.

use std::path::{Path, PathBuf};

/// Most bytes of output kept (the newest).
pub const LIMIT: usize = 1024 * 1024;

#[derive(Default)]
pub struct SessionLog {
    raw: String,
}

impl SessionLog {
    /// Adds output text, keeping the last `LIMIT` bytes (on a char boundary).
    pub fn append(&mut self, text: &str) {
        self.raw.push_str(text);
        if self.raw.len() > LIMIT {
            let mut start = self.raw.len() - LIMIT;
            while !self.raw.is_char_boundary(start) {
                start += 1;
            }
            self.raw.drain(..start);
        }
    }

    /// The agent ended: writes the log and summary when it printed
    /// something; the notice for its frontend. `screen` is the final screen.
    pub fn finish(
        &mut self,
        logs: &Path,
        session_id: &str,
        provider: crate::session::Provider,
        screen: &vt100::Screen,
    ) -> String {
        let label = provider.label();
        if self.raw.trim().is_empty() {
            return format!("{label} session ended (no output captured).");
        }
        self.append(&format!(
            "\u{2699}\u{fe0f} {} CLI session ended.\n",
            provider.product()
        ));
        let mut parts = Vec::new();
        let log = match write(logs, session_id, "session.ansi", self.raw.as_bytes()) {
            Ok(path) => {
                parts.push(format!("\u{1f4dd} {label} log saved to {}", path.display()));
                Some(path)
            }
            Err(error) => {
                parts.push(format!(
                    "\u{26a0}\u{fe0f} Failed to save {label} log: {error}"
                ));
                None
            }
        };
        let summary = summary(provider, &output_lines(screen), log.as_deref());
        match write(logs, session_id, "summary.md", summary.as_bytes()) {
            Ok(path) => parts.push(format!("\u{1f4c4} Summary saved to {}", path.display())),
            Err(error) => parts.push(format!(
                "\u{26a0}\u{fe0f} Failed to save {label} summary: {error}"
            )),
        }
        parts.join(" | ")
    }
}

/// The final screen's text without trailing blank lines.
fn output_lines(screen: &vt100::Screen) -> String {
    let (_, cols) = screen.size();
    let mut lines: Vec<String> = screen
        .rows(0, cols)
        .map(|line| line.replace('\u{0000}', ""))
        .collect();
    while lines.last().is_some_and(|line| line.trim().is_empty()) {
        lines.pop();
    }
    lines.join("\n")
}

/// `summary.md`, as Atem has always written it.
pub fn summary(provider: crate::session::Provider, output: &str, log: Option<&Path>) -> String {
    let mut summary = format!("# {} Session Summary\n\n", provider.product());
    // Commands are typed into the agent's own terminal; Atem records none.
    summary.push_str("Commands executed: 0\n");
    summary.push('\n');
    summary.push_str(&format!(
        "Total output lines captured: {}\n",
        output.lines().count()
    ));
    match log {
        Some(path) => summary.push_str(&format!("Full log saved at: {}\n", path.display())),
        None => summary.push_str("Full log has not been saved yet.\n"),
    }
    summary
}

/// `<logs>/<session_id>/<name>` (0600, atomic), its directories 0700.
fn write(logs: &Path, session_id: &str, name: &str, bytes: &[u8]) -> std::io::Result<PathBuf> {
    if logs.as_os_str().is_empty() {
        return Err(std::io::Error::other("session logs are off"));
    }
    let dir = logs.join(session_id);
    super::worker::private_dir(logs)?;
    super::worker::private_dir(&dir)?;
    let path = dir.join(name);
    super::worker::write_atomic(&path, bytes)?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn the_log_keeps_the_newest_megabyte_on_a_char_boundary() {
        let mut log = SessionLog::default();
        log.append(&"a".repeat(LIMIT));
        log.append("\u{4e2d}tail");
        assert!(log.raw.len() <= LIMIT);
        assert!(log.raw.ends_with("\u{4e2d}tail"));
    }

    #[test]
    fn finish_writes_private_files_only_with_output() {
        let dir = tempfile::tempdir().unwrap();
        let logs = dir.path().join("logs");
        let parser = vt100::Parser::new(4, 20, 0);
        let mut empty = SessionLog::default();
        empty.append("  \r\n");
        let notice = empty.finish(
            &logs,
            "ses-aaaaaaaaaaaa",
            crate::session::Provider::Claude,
            parser.screen(),
        );
        assert_eq!(notice, "Claude session ended (no output captured).");
        assert!(!logs.exists());

        let mut parser = vt100::Parser::new(4, 20, 0);
        parser.process(b"hi\r\nthere");
        let mut log = SessionLog::default();
        log.append("hi\r\nthere");
        let notice = log.finish(
            &logs,
            "ses-aaaaaaaaaaaa",
            crate::session::Provider::Claude,
            parser.screen(),
        );
        let path = logs.join("ses-aaaaaaaaaaaa");
        assert_eq!(
            notice,
            format!(
                "\u{1f4dd} Claude log saved to {} | \u{1f4c4} Summary saved to {}",
                path.join("session.ansi").display(),
                path.join("summary.md").display()
            )
        );
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path.join("summary.md")), 0o600);
        assert_eq!(mode(&path), 0o700);
        let summary = std::fs::read_to_string(path.join("summary.md")).unwrap();
        assert_eq!(
            summary,
            format!(
                "# Claude Code Session Summary\n\nCommands executed: 0\n\nTotal output lines captured: 2\nFull log saved at: {}\n",
                path.join("session.ansi").display()
            )
        );
    }
}
