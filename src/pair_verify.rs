//! `atem pair` and `atem pair verify` device verification: the safety-code confirmation (read from
//! the terminal, never from stdin) and what happens when verification fails
//! (the pending pin is dropped and Astation is told, unless it cancelled).

use anyhow::{Result, anyhow};
use std::io::{self, Read, Write};
use std::path::Path;
use std::time::Duration;

use crate::memory::grant::GrantWire;
use crate::memory::statements::SignedWire;
use crate::websocket_client::{AstationClient, AstationMessage};

/// How long Astation has to answer `verifyCommit` (older Astations never do).
pub(crate) const FIRST_REPLY_TIMEOUT: Duration = Duration::from_secs(15);
/// How long the user has to approve on the Mac with Touch ID.
pub(crate) const TOUCH_ID_TIMEOUT: Duration = Duration::from_secs(300);

/// The question the runtime asks (the CLI adds "Type y or n: ").
pub(crate) const CODES_QUESTION: &str = "Does the code on your Mac match?";
#[cfg(test)]
const PROMPT: &str = "Does the code on your Mac match? Type y or n: ";
/// Longer answers are cut (they are never y/n anyway).
const MAX_LINE: usize = 256;

/// The user's answer to "does the code match?".
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CodeAnswer {
    Match,
    Refused,
    /// No answer: the terminal closed or couldn't be read.
    Unanswered(String),
    /// There is no terminal to ask on.
    NoTerminal(String),
    /// The CLI went away (interrupted) before it answered.
    Interrupted,
}

/// The terminal the confirmation is read from and the prompt written to.
pub(crate) trait Terminal: Read + Write {
    /// Discards anything typed before the prompt.
    fn discard_pending(&mut self);
}

#[cfg(unix)]
impl Terminal for std::fs::File {
    fn discard_pending(&mut self) {
        use std::os::unix::io::AsRawFd;
        // SAFETY: tcflush on a descriptor this File owns.
        unsafe {
            libc::tcflush(self.as_raw_fd(), libc::TCIFLUSH);
        }
    }
}

/// Asks until the answer is y/yes (match) or n/no (refused). Keys typed
/// before the prompt are discarded first, and the input is read a byte at a
/// time, so nothing beyond the answer line is consumed.
#[cfg(test)]
pub(crate) fn ask_codes_match<T: Terminal>(terminal: &mut T) -> CodeAnswer {
    ask_yes_no(terminal, PROMPT)
}

/// Asks `prompt` until the answer is y/yes or n/no (`ask_codes_match`).
pub(crate) fn ask_yes_no<T: Terminal>(terminal: &mut T, prompt: &str) -> CodeAnswer {
    terminal.discard_pending();
    loop {
        if let Err(error) = terminal
            .write_all(prompt.as_bytes())
            .and_then(|_| terminal.flush())
        {
            return CodeAnswer::Unanswered(format!("couldn't write to the terminal ({error})"));
        }
        match read_line(terminal) {
            Ok(None) => {
                return CodeAnswer::Unanswered(
                    "the terminal closed before you answered".to_string(),
                );
            }
            Err(error) => {
                return CodeAnswer::Unanswered(format!(
                    "couldn't read your answer from the terminal ({error})"
                ));
            }
            Ok(Some(line)) => match line.trim().to_ascii_lowercase().as_str() {
                "y" | "yes" => return CodeAnswer::Match,
                "n" | "no" => return CodeAnswer::Refused,
                // Empty or a typo asks again: only a deliberate y trusts.
                _ => continue,
            },
        }
    }
}

/// One line, read a byte at a time (no read-ahead). `None` at end of input.
fn read_line<R: Read>(input: &mut R) -> io::Result<Option<String>> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match input.read(&mut byte) {
            Ok(0) if line.is_empty() => return Ok(None),
            Ok(0) => break,
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => {
                if line.len() < MAX_LINE {
                    line.push(byte[0]);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(Some(String::from_utf8_lossy(&line).into_owned()))
}

/// Opens the terminal with `open` and asks `prompt` on it.
pub(crate) fn confirm_with<T: Terminal>(
    open: impl FnOnce() -> io::Result<T>,
    prompt: &str,
) -> CodeAnswer {
    match open() {
        Ok(mut terminal) => ask_yes_no(&mut terminal, prompt),
        Err(error) => CodeAnswer::NoTerminal(format!("couldn't open /dev/tty: {error}")),
    }
}

/// Asks `prompt` on the controlling terminal (`/dev/tty`), never stdin: an
/// answer piped in (`yes | atem pair`) or typed ahead is not a person
/// comparing the codes.
#[cfg(unix)]
pub(crate) fn prompt_yes_no(prompt: &str) -> CodeAnswer {
    confirm_with(
        || {
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/tty")
        },
        prompt,
    )
}

/// Reads one line of text from the controlling terminal (`/dev/tty`).
#[cfg(unix)]
pub(crate) fn prompt_text(prompt: &str) -> Result<String, CodeAnswer> {
    let mut terminal = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|error| CodeAnswer::NoTerminal(format!("couldn't open /dev/tty: {error}")))?;
    terminal.discard_pending();
    terminal
        .write_all(prompt.as_bytes())
        .and_then(|_| terminal.flush())
        .map_err(|error| {
            CodeAnswer::Unanswered(format!("couldn't write to the terminal ({error})"))
        })?;
    match read_line(&mut terminal) {
        Ok(Some(line)) => Ok(line.trim().to_string()),
        Ok(None) => Err(CodeAnswer::Unanswered(
            "the terminal closed before you answered".to_string(),
        )),
        Err(error) => Err(CodeAnswer::Unanswered(format!(
            "couldn't read your answer from the terminal ({error})"
        ))),
    }
}

/// atem ships for Linux and macOS only; elsewhere the answer comes from stdin.
#[cfg(not(unix))]
pub(crate) fn prompt_text(prompt: &str) -> Result<String, CodeAnswer> {
    print!("{prompt}");
    let _ = io::stdout().flush();
    let mut line = String::new();
    io::stdin()
        .read_line(&mut line)
        .map_err(|error| CodeAnswer::Unanswered(error.to_string()))?;
    Ok(line.trim().to_string())
}

/// atem ships for Linux and macOS only; elsewhere the answer comes from stdin.
#[cfg(not(unix))]
pub(crate) fn prompt_yes_no(prompt: &str) -> CodeAnswer {
    struct Console;
    impl Read for Console {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            io::stdin().read(buf)
        }
    }
    impl Write for Console {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            io::stdout().write(buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            io::stdout().flush()
        }
    }
    impl Terminal for Console {
        fn discard_pending(&mut self) {}
    }
    confirm_with(|| Ok(Console), prompt)
}

/// A device verification that failed after Astation was shown the code.
#[derive(Debug)]
pub(crate) struct VerifyFailure {
    /// Sent to Astation as `verifyAbort`; `None` when Astation cancelled.
    abort_reason: Option<String>,
    error: anyhow::Error,
}

impl VerifyFailure {
    /// atem stops the verification: Astation is told why.
    pub(crate) fn local(reason: impl Into<String>, error: anyhow::Error) -> Self {
        Self {
            abort_reason: Some(reason.into()),
            error,
        }
    }

    /// Astation stopped it: nothing is sent back.
    pub(crate) fn by_astation(error: anyhow::Error) -> Self {
        Self {
            abort_reason: None,
            error,
        }
    }

    #[cfg(test)]
    pub(crate) fn abort_reason(&self) -> Option<&str> {
        self.abort_reason.as_deref()
    }

    #[cfg(test)]
    pub(crate) fn error(&self) -> &anyhow::Error {
        &self.error
    }
}

/// The failure for an answer other than a match.
pub(crate) fn code_failure(answer: CodeAnswer) -> Option<VerifyFailure> {
    match answer {
        CodeAnswer::Match => None,
        CodeAnswer::Refused => Some(VerifyFailure::local(
            "codes didn't match on atem",
            anyhow!(
                "Device verification cancelled: the codes didn't match, so nothing was trusted."
            ),
        )),
        CodeAnswer::Unanswered(detail) => Some(VerifyFailure::local(
            "no answer on atem",
            anyhow!(
                "Device verification cancelled: {detail}, so nothing was trusted (only y confirms the code)."
            ),
        )),
        CodeAnswer::Interrupted => Some(VerifyFailure::local(
            "atem was interrupted",
            anyhow!("Device verification cancelled: atem was interrupted, so nothing was trusted."),
        )),
        CodeAnswer::NoTerminal(detail) => Some(VerifyFailure::local(
            "no terminal to compare the code",
            anyhow!(
                "Device verification needs a terminal to compare the safety code ({detail}); run `atem pair verify` in an interactive terminal."
            ),
        )),
    }
}

/// Waits for the next device-verification message, holding unrelated
/// encryption traffic for after the verification.
pub(crate) async fn next_verify_message(client: &mut AstationClient) -> Result<AstationMessage> {
    loop {
        match client.recv_message_async().await {
            Some(
                message @ (AstationMessage::VerifyKeys { .. }
                | AstationMessage::DeviceVerified { .. }
                | AstationMessage::VerifyAbort { .. }),
            ) => return Ok(message),
            // Applied after the verification, against the pins it sets.
            Some(message) => client.hold_encryption(message),
            None => anyhow::bail!("Astation connection closed during device verification"),
        }
    }
}

/// Astation's signed answer after Touch ID.
pub(crate) struct DeviceVerifiedReply {
    pub device_verified: SignedWire,
    pub account_state: SignedWire,
    pub grants: Vec<GrantWire>,
}

/// Applies Astation's `deviceVerified` (`complete_verification`) only while
/// the pairing the verification started under is current, under the pairing
/// lock: a certificate that arrives after `atem unpair` (or a new `atem
/// pair`) is dropped and nothing is pinned. `agent` must not be a
/// `BoundAgent` (the lock is already held).
pub(crate) fn apply_device_verified(
    capture: &crate::pairing_binding::Captured,
    paths: &crate::memory::verification::CredPaths,
    agent: &dyn crate::memory::cred_agent::CredAgentApi,
    astation_id: &str,
    keys: crate::memory::verification::VerificationKeys,
    reply: &DeviceVerifiedReply,
) -> Result<crate::memory::verification::VerificationOutcome> {
    capture.bound_to(astation_id)?;
    capture.apply(|| {
        crate::memory::verification::complete_verification(
            paths,
            agent,
            astation_id,
            keys,
            &reply.device_verified,
            &reply.account_state,
            &reply.grants,
        )
    })
}

/// Waits up to `wait` for Astation's `deviceVerified`.
pub(crate) async fn await_device_verified(
    client: &mut AstationClient,
    wait: Duration,
) -> Result<DeviceVerifiedReply, VerifyFailure> {
    match tokio::time::timeout(wait, next_verify_message(client)).await {
        Err(_) => Err(VerifyFailure::local(
            "timed out waiting for Astation",
            anyhow!("Timed out waiting for Astation to confirm this device."),
        )),
        Ok(Err(error)) => Err(VerifyFailure::local("atem lost the connection", error)),
        Ok(Ok(AstationMessage::DeviceVerified {
            device_verified,
            account_state,
            grants,
        })) => Ok(DeviceVerifiedReply {
            device_verified,
            account_state,
            grants,
        }),
        Ok(Ok(AstationMessage::VerifyAbort { reason })) => Err(VerifyFailure::by_astation(
            anyhow!("Astation declined device verification: {reason}"),
        )),
        Ok(Ok(_)) => Err(VerifyFailure::local(
            "unexpected message on atem",
            anyhow!("unexpected message during device verification"),
        )),
    }
}

/// At most this many characters of an abort reason are sent.
const MAX_ABORT_REASON: usize = 200;

/// Drops the pending pin and, unless Astation cancelled, tells Astation
/// (`verifyAbort`, delivery confirmed, at most ~5 s, failure ignored).
/// Returns the error to report.
pub(crate) async fn abandon_verification(
    client: &AstationClient,
    trust_path: &Path,
    astation_id: &str,
    failure: VerifyFailure,
) -> anyhow::Error {
    // The pin goes first, so it goes even if the send fails.
    let _ = crate::memory::trust::TrustStore::update(trust_path, |trust| {
        trust.remove_pending(astation_id);
        Ok(())
    });
    if let Some(mut reason) = failure.abort_reason {
        // Short enough for Astation's dialog: an error chain can be long.
        if let Some((cut, _)) = reason.char_indices().nth(MAX_ABORT_REASON) {
            reason.truncate(cut);
            reason.push('…');
        }
        // Bounded: send_message_flushed waits at most 5 s.
        let _ = client
            .send_message_flushed(AstationMessage::VerifyAbort { reason })
            .await;
    }
    failure.error
}

/// Asks Astation for `K` after a successful verification. A failure is a
/// warning (returned), never a verification failure: `atem cred unlock`
/// asks again.
pub(crate) async fn request_key_after_verification(
    client: &AstationClient,
    public_key: String,
) -> Option<String> {
    match client
        .send_message_flushed(AstationMessage::KeyRequest { public_key })
        .await
    {
        Ok(()) => None,
        Err(error) => Some(format!(
            "Couldn't request the encryption key: {error:#}; run `atem cred unlock` to ask again"
        )),
    }
}

/// `atem pair` after the pairing was saved, and `atem pair verify`: a failed verification is shown
/// in full here, then reported as a short error so the exit status is
/// nonzero.
pub(crate) fn verification_result(
    verification: Result<()>,
    mut warn: impl FnMut(&str),
) -> Result<()> {
    match verification {
        Ok(()) => Ok(()),
        Err(error) => {
            warn(&format!("\u{26a0}\u{fe0f}  {error}"));
            warn("Pairing is saved. Run 'atem pair verify' to verify this device.");
            Err(anyhow!("device verification failed"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    /// A terminal with keys typed before the prompt (`pending`) and keys
    /// typed after it (`fresh`).
    struct FakeTerminal {
        pending: io::Cursor<Vec<u8>>,
        fresh: io::Cursor<Vec<u8>>,
        fail_reads: bool,
        output: Vec<u8>,
    }

    impl FakeTerminal {
        fn new(pending: &str, fresh: &str) -> Self {
            Self {
                pending: io::Cursor::new(pending.as_bytes().to_vec()),
                fresh: io::Cursor::new(fresh.as_bytes().to_vec()),
                fail_reads: false,
                output: Vec::new(),
            }
        }

        fn prompts(&self) -> usize {
            String::from_utf8_lossy(&self.output)
                .matches(PROMPT)
                .count()
        }
    }

    impl Read for FakeTerminal {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.fail_reads {
                return Err(io::Error::other("input/output error"));
            }
            match self.pending.read(buf)? {
                0 => self.fresh.read(buf),
                n => Ok(n),
            }
        }
    }

    impl Write for FakeTerminal {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.output.write(buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Terminal for FakeTerminal {
        fn discard_pending(&mut self) {
            self.pending = io::Cursor::new(Vec::new());
        }
    }

    #[test]
    fn a_y_typed_before_the_prompt_is_discarded_and_a_fresh_y_accepted() {
        let mut terminal = FakeTerminal::new("y\n", "y\n");
        assert_eq!(ask_codes_match(&mut terminal), CodeAnswer::Match);
        let mut terminal = FakeTerminal::new("y\nyes\n", "n\n");
        assert_eq!(ask_codes_match(&mut terminal), CodeAnswer::Refused);
    }

    #[test]
    fn a_fresh_n_refuses() {
        let mut terminal = FakeTerminal::new("", "no\n");
        assert_eq!(ask_codes_match(&mut terminal), CodeAnswer::Refused);
        let failure = code_failure(CodeAnswer::Refused).unwrap();
        assert_eq!(failure.abort_reason(), Some("codes didn't match on atem"));
        assert!(failure.error().to_string().contains("nothing was trusted"));
    }

    #[test]
    fn end_of_input_is_a_refusal_with_a_message() {
        let mut terminal = FakeTerminal::new("y\n", "");
        let answer = ask_codes_match(&mut terminal);
        let CodeAnswer::Unanswered(detail) = &answer else {
            panic!("expected no answer, got {answer:?}");
        };
        assert!(detail.contains("closed"), "{detail}");
        let failure = code_failure(answer).unwrap();
        assert_eq!(failure.abort_reason(), Some("no answer on atem"));
        assert!(failure.error().to_string().contains("nothing was trusted"));
    }

    #[test]
    fn a_read_error_is_a_refusal() {
        let mut terminal = FakeTerminal::new("", "y\n");
        terminal.fail_reads = true;
        let answer = ask_codes_match(&mut terminal);
        let CodeAnswer::Unanswered(detail) = &answer else {
            panic!("expected no answer, got {answer:?}");
        };
        assert!(detail.contains("input/output error"), "{detail}");
        assert!(code_failure(answer).is_some());
    }

    #[test]
    fn no_terminal_is_an_actionable_error() {
        let answer = confirm_with(
            || -> io::Result<FakeTerminal> {
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "No such device or address",
                ))
            },
            PROMPT,
        );
        assert!(matches!(answer, CodeAnswer::NoTerminal(_)), "{answer:?}");
        let failure = code_failure(answer).unwrap();
        assert_eq!(
            failure.abort_reason(),
            Some("no terminal to compare the code")
        );
        let message = failure.error().to_string();
        assert!(message.contains("needs a terminal"), "{message}");
        assert!(message.contains("run `atem pair verify` in an interactive terminal"));
    }

    #[test]
    fn anything_else_asks_again() {
        let mut terminal = FakeTerminal::new("", "maybe\n\nyes please\nY\n");
        assert_eq!(ask_codes_match(&mut terminal), CodeAnswer::Match);
        assert_eq!(terminal.prompts(), 4);
        assert!(code_failure(CodeAnswer::Match).is_none());
    }

    #[test]
    fn reading_stops_at_the_answer_line() {
        let mut terminal = FakeTerminal::new("", "y\nleft for later\n");
        assert_eq!(ask_codes_match(&mut terminal), CodeAnswer::Match);
        let mut rest = String::new();
        terminal.fresh.read_to_string(&mut rest).unwrap();
        assert_eq!(rest, "left for later\n");
    }

    /// A real pseudo-terminal: a `y` typed before the prompt is flushed from
    /// the kernel's input queue; the `n` typed after the prompt answers.
    #[cfg(unix)]
    #[test]
    fn a_real_terminal_discards_keys_typed_before_the_prompt() {
        use portable_pty::{PtySize, native_pty_system};
        use std::os::unix::fs::OpenOptionsExt;

        let pair = native_pty_system()
            .openpty(PtySize::default())
            .expect("openpty");
        let path = pair.master.tty_name().expect("tty name");
        let mut tty = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOCTTY)
            .open(&path)
            .expect("open the pty");
        let mut keys = pair.master.take_writer().unwrap();
        let mut screen = pair.master.try_clone_reader().unwrap();

        keys.write_all(b"y\n").unwrap();
        keys.flush().unwrap();
        std::thread::sleep(Duration::from_millis(200));

        let (done, answer) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = done.send(ask_codes_match(&mut tty));
        });
        // Type only once the prompt is on screen (after the flush).
        let mut seen = Vec::new();
        let mut chunk = [0u8; 256];
        while !String::from_utf8_lossy(&seen).contains("Type y or n") {
            let n = screen.read(&mut chunk).expect("read the screen");
            assert!(n > 0, "the pty closed before the prompt");
            seen.extend_from_slice(&chunk[..n]);
        }
        keys.write_all(b"n\n").unwrap();
        keys.flush().unwrap();
        let answer = answer
            .recv_timeout(Duration::from_secs(5))
            .expect("no answer within 5 s");
        assert_eq!(answer, CodeAnswer::Refused);
    }

    /// A test Astation: sends `send`, then collects every text frame atem
    /// sends until the connection closes.
    async fn astation(
        send: Vec<AstationMessage>,
    ) -> (String, tokio::task::JoinHandle<Vec<serde_json::Value>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            for message in send {
                socket
                    .send(Message::Text(serde_json::to_string(&message).unwrap()))
                    .await
                    .unwrap();
            }
            let mut frames = Vec::new();
            while let Ok(Some(Ok(frame))) =
                tokio::time::timeout(Duration::from_secs(3), socket.next()).await
            {
                if let Message::Text(text) = frame {
                    frames.push(serde_json::from_str(&text).unwrap());
                }
            }
            frames
        });
        (format!("ws://{address}"), server)
    }

    async fn connected(url: &str) -> AstationClient {
        let mut client = AstationClient::new();
        client.connect_raw(url).await.unwrap();
        client
    }

    fn types(frames: &[serde_json::Value]) -> Vec<String> {
        frames
            .iter()
            .map(|frame| frame["type"].as_str().unwrap_or_default().to_string())
            .collect()
    }

    #[tokio::test]
    async fn a_refused_code_reaches_astation_even_when_the_client_is_dropped_at_once() {
        let dir = tempfile::tempdir().unwrap();
        let (url, server) = astation(Vec::new()).await;
        let client = connected(&url).await;
        let failure = code_failure(CodeAnswer::Refused).unwrap();
        let error = abandon_verification(
            &client,
            &crate::memory::verification::CredPaths::in_dir(dir.path()).trust,
            "a",
            failure,
        )
        .await;
        drop(client);
        assert!(error.to_string().contains("codes didn't match"));
        let frames = server.await.unwrap();
        assert_eq!(types(&frames), ["verifyAbort"]);
        assert_eq!(frames[0]["data"]["reason"], "codes didn't match on atem");
    }

    #[tokio::test]
    async fn a_timeout_waiting_for_touch_id_reaches_astation() {
        let dir = tempfile::tempdir().unwrap();
        let (url, server) = astation(Vec::new()).await;
        let mut client = connected(&url).await;
        let Err(failure) = await_device_verified(&mut client, Duration::from_millis(50)).await
        else {
            panic!("expected a timeout");
        };
        assert_eq!(
            failure.abort_reason(),
            Some("timed out waiting for Astation")
        );
        let error = abandon_verification(
            &client,
            &crate::memory::verification::CredPaths::in_dir(dir.path()).trust,
            "a",
            failure,
        )
        .await;
        drop(client);
        assert!(error.to_string().contains("Timed out"));
        let frames = server.await.unwrap();
        assert_eq!(types(&frames), ["verifyAbort"]);
        assert_eq!(
            frames[0]["data"]["reason"],
            "timed out waiting for Astation"
        );
    }

    #[tokio::test]
    async fn astations_own_abort_is_not_echoed_back() {
        let dir = tempfile::tempdir().unwrap();
        let (url, server) = astation(vec![AstationMessage::VerifyAbort {
            reason: "declined on the Mac".into(),
        }])
        .await;
        let mut client = connected(&url).await;
        let Err(failure) = await_device_verified(&mut client, Duration::from_secs(5)).await else {
            panic!("expected Astation's abort");
        };
        assert_eq!(failure.abort_reason(), None);
        let error = abandon_verification(
            &client,
            &crate::memory::verification::CredPaths::in_dir(dir.path()).trust,
            "a",
            failure,
        )
        .await;
        drop(client);
        assert!(error.to_string().contains("declined on the Mac"));
        assert!(server.await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn the_key_request_is_delivered_after_a_verification() {
        let (url, server) = astation(Vec::new()).await;
        let client = connected(&url).await;
        assert_eq!(
            request_key_after_verification(&client, "cHVi".into()).await,
            None
        );
        drop(client);
        let frames = server.await.unwrap();
        assert_eq!(types(&frames), ["keyRequest"]);
        assert_eq!(frames[0]["data"]["public_key"], "cHVi");
    }

    #[tokio::test]
    async fn a_failed_key_request_is_a_warning_not_a_failure() {
        let client = AstationClient::new();
        let warning = request_key_after_verification(&client, "cHVi".into())
            .await
            .expect("a warning");
        assert!(
            warning.contains("Couldn't request the encryption key"),
            "{warning}"
        );
        assert!(warning.contains("atem cred unlock"), "{warning}");
    }

    #[test]
    fn pair_fails_after_a_failed_verification() {
        assert!(verification_result(Ok(()), |_| panic!("nothing to warn about")).is_ok());
        let mut warned = Vec::new();
        let error = verification_result(Err(anyhow!("codes didn't match")), |line| {
            warned.push(line.to_string())
        })
        .unwrap_err();
        assert!(warned[0].contains("codes didn't match"), "{warned:?}");
        assert_eq!(error.to_string(), "device verification failed");
    }

    /// Astation's certificate for a verification whose pairing was removed
    /// (or replaced) meanwhile is never applied.
    #[test]
    fn a_delayed_device_verified_for_an_old_binding_is_not_applied() {
        use crate::memory::cred_agent::{CredAgentApi, Reply, Request};
        struct NeverCalled;
        impl CredAgentApi for NeverCalled {
            fn call(&self, _: Request) -> Result<Reply> {
                panic!("the cred agent was asked to apply a stale verification")
            }
        }
        let wire = || SignedWire {
            statement: "c3RhdGVtZW50".into(),
            signature: "c2lnbmF0dXJl".into(),
        };
        for re_pair in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let capture = crate::pairing_binding::tests::bound_profile(dir.path(), "astation-1");
            let src = capture.sources().clone();
            crate::pairing_binding::commit_unpair(&src).unwrap();
            if re_pair {
                let before = crate::pairing_binding::capture(&src).unwrap();
                crate::pairing_binding::bind_new(&src, &before, "astation-1").unwrap();
            }
            let before = crate::status::tests::snapshot(dir.path());
            let reply = DeviceVerifiedReply {
                device_verified: wire(),
                account_state: wire(),
                grants: Vec::new(),
            };
            let keys = crate::memory::device_keys::DeviceKeys::generate().into();
            let error = apply_device_verified(
                &capture,
                &src.keys,
                &NeverCalled,
                "astation-1",
                keys,
                &reply,
            )
            .unwrap_err();
            assert_eq!(error.to_string(), crate::pairing_binding::CHANGED);
            assert_eq!(crate::status::tests::snapshot(dir.path()), before);
            assert!(!src.keys.trust.exists());
        }
    }
}
