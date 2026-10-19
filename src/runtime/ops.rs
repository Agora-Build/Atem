//! Astation operations in the broker: `atem pair` (first pairing), `atem
//! pair verify`, `atem cred unlock|projects` and the paired-token refresh
//! run here, on the broker's own Astation link. The CLI is only the user
//! interface (`print`/`ask` out, `answer` in, `done` at the end; see
//! `op_client.rs`). One operation at a time; while one runs, the handshake
//! replies it waits for are routed to it (`app/op_route.rs`) and dropped
//! once it ended. A CLI that goes away ends its operation as a failure
//! (device verification tells Astation with `verifyAbort`); a lost link
//! ends it too, never replayed. See designs/agent-runtime.md "Astation
//! operations through the runtime".

use super::protocol::{AnswerValue, AskKind, OpKind, OpOptions, PrintLevel, RuntimeMsg};
use crate::memory::cred_agent::{CredAgentApi, LOCKED, blocking, default_agent};
use crate::memory::unlock::{AstationLink, shown};
use crate::pair_verify::{CodeAnswer, VerifyFailure};
use crate::paths::CredPaths;
use crate::status::Sources;
use crate::websocket_client::{AstationClient, AstationMessage};
use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use futures_util::FutureExt;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, watch};

/// A second operation while one runs is refused with this.
pub const BUSY: &str = "another pairing or unlock is in progress";
/// How long an operation waits for the runtime's link to come up.
pub const LINK_WAIT: Duration = Duration::from_secs(15);
/// The link didn't come up within `LINK_WAIT`.
pub const NO_LINK: &str =
    "The atem runtime isn't connected to Astation; open Astation and try again";
/// The CLI went away mid-operation.
pub const INTERRUPTED: &str = "atem was interrupted";
/// How long the token refresh waits for Astation's `credentialSync`.
const CREDENTIALS_WAIT: Duration = Duration::from_secs(15);
/// How long a first pairing waits for Astation's credentials.
const PAIR_CREDENTIALS_WAIT: Duration = Duration::from_secs(60);

/// The operation's user interface: the CLI that asked for it.
pub(crate) trait OpUi: Send + Sync {
    fn print(&self, level: PrintLevel, text: &str);
    /// `print` at info level, as a closure (pairing lines from the client).
    fn printer(&self) -> Arc<dyn Fn(&str) + Send + Sync>;
    /// The answer; `None` once the CLI went away.
    fn ask(&self, kind: AskKind, text: &str) -> impl Future<Output = Option<AnswerValue>> + Send;
    /// Completes once the CLI went away.
    fn gone(&self) -> impl Future<Output = ()> + Send;
}

/// The broker's `OpUi`: messages to one client, its answers back.
pub(super) struct ClientUi {
    request_id: String,
    out: Arc<dyn Fn(RuntimeMsg) + Send + Sync>,
    answers: tokio::sync::Mutex<mpsc::UnboundedReceiver<(u64, AnswerValue)>>,
    next_question: AtomicU64,
    gone: watch::Receiver<bool>,
}

impl ClientUi {
    pub(super) fn new(
        request_id: String,
        out: Arc<dyn Fn(RuntimeMsg) + Send + Sync>,
        answers: mpsc::UnboundedReceiver<(u64, AnswerValue)>,
        gone: watch::Receiver<bool>,
    ) -> Self {
        Self {
            request_id,
            out,
            answers: tokio::sync::Mutex::new(answers),
            next_question: AtomicU64::new(0),
            gone,
        }
    }

    fn done(&self, ok: bool, error: Option<String>) {
        (self.out)(RuntimeMsg::Done {
            request_id: self.request_id.clone(),
            ok,
            error,
        });
    }
}

impl OpUi for ClientUi {
    fn print(&self, level: PrintLevel, text: &str) {
        (self.out)(RuntimeMsg::Print {
            request_id: self.request_id.clone(),
            level,
            text: text.to_string(),
        });
    }

    fn printer(&self) -> Arc<dyn Fn(&str) + Send + Sync> {
        let (out, request_id) = (self.out.clone(), self.request_id.clone());
        Arc::new(move |text: &str| {
            out(RuntimeMsg::Print {
                request_id: request_id.clone(),
                level: PrintLevel::Info,
                text: text.to_string(),
            })
        })
    }

    async fn ask(&self, kind: AskKind, text: &str) -> Option<AnswerValue> {
        let question_id = self.next_question.fetch_add(1, Ordering::SeqCst) + 1;
        (self.out)(RuntimeMsg::Ask {
            request_id: self.request_id.clone(),
            question_id,
            kind,
            text: text.to_string(),
        });
        let mut answers = self.answers.lock().await;
        let answer = async {
            while let Some((id, value)) = answers.recv().await {
                if id == question_id {
                    return Some(value);
                }
            }
            None
        };
        tokio::select! {
            answer = answer => answer,
            _ = self.gone() => None,
        }
    }

    async fn gone(&self) {
        let mut gone = self.gone.clone();
        loop {
            if *gone.borrow_and_update() {
                return;
            }
            if gone.changed().await.is_err() {
                return;
            }
        }
    }
}

/// Where an operation's profile comes from (read when it starts).
type ProfileSource = Arc<dyn Fn() -> Result<Sources> + Send + Sync>;
/// Where an operation's cred agent comes from.
type AgentSource = Arc<dyn Fn() -> Result<Arc<dyn CredAgentApi>> + Send + Sync>;

/// What operations need besides the link: the profile, the cred agent and
/// how long to wait for the link. Named explicitly: this user's
/// (`for_user`, `atem runtime`), a given one (`for_profile`, tests), or
/// none (`unavailable`: every operation fails).
#[derive(Clone)]
pub struct OpEnv {
    profile: ProfileSource,
    agent: AgentSource,
    /// How long an operation waits for the link to come up.
    pub link_wait: Duration,
}

impl OpEnv {
    /// This user's profile (read when each operation starts) and cred agent.
    pub fn for_user() -> Self {
        Self {
            profile: Arc::new(Sources::current),
            agent: Arc::new(|| Ok(Arc::from(default_agent()))),
            link_wait: LINK_WAIT,
        }
    }

    /// The profile `src` and the cred agent `agent`.
    #[cfg(test)]
    pub fn for_profile(src: Sources, agent: Arc<dyn CredAgentApi>) -> Self {
        Self {
            profile: Arc::new(move || Ok(src.clone())),
            agent: Arc::new(move || Ok(agent.clone())),
            link_wait: LINK_WAIT,
        }
    }

    /// Waits `wait` for the link instead.
    #[cfg(test)]
    pub fn with_link_wait(mut self, wait: Duration) -> Self {
        self.link_wait = wait;
        self
    }

    /// No profile: every operation fails (a runtime that runs none).
    #[cfg(test)]
    pub fn unavailable() -> Self {
        Self {
            profile: Arc::new(|| Err(anyhow!("this runtime runs no Astation operations"))),
            agent: Arc::new(|| Err(anyhow!("this runtime runs no Astation operations"))),
            link_wait: LINK_WAIT,
        }
    }

    fn sources(&self) -> Result<Sources> {
        (self.profile)()
    }

    fn agent(&self) -> Result<Arc<dyn CredAgentApi>> {
        (self.agent)()
    }

    /// A fresh client of the profile `src` for a first pairing.
    fn new_client(&self, src: &Sources) -> Result<AstationClient> {
        Ok(AstationClient::new()
            .with_profile(src.clone())
            .with_agent(self.agent()?))
    }
}

/// Why the link couldn't authenticate with the saved session, with what to
/// do (an operation waiting for the link fails with it).
#[derive(Debug)]
pub struct SessionAdvice(pub String);

impl std::fmt::Display for SessionAdvice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SessionAdvice {}

/// A connect error caused by the saved session (a `SessionError` the
/// connect path returned): says what to do (`atem pair` alone would only
/// show the status), unless it already did. Other errors are kept.
pub fn session_advice(error: anyhow::Error) -> anyhow::Error {
    use crate::websocket_client::{SessionError, SessionProblem};
    let Some(session) = error.downcast_ref::<SessionError>() else {
        return error;
    };
    let advise = !session.advised
        && matches!(
            session.problem,
            SessionProblem::Refused | SessionProblem::Missing | SessionProblem::PairingRequired
        );
    let text = if advise {
        format!("{error:#}. {}", crate::status::SESSION_GONE)
    } else {
        format!("{error:#}")
    };
    anyhow::Error::new(SessionAdvice(text))
}

/// What an operation asks of the broker's loop.
pub(super) enum OpCall {
    /// A handle on the authenticated link, its replies routed to it (waits
    /// for the link to come up).
    Link {
        encryption: bool,
        credentials: bool,
        /// The link, or why the saved session couldn't authenticate it.
        reply: oneshot::Sender<Result<AstationClient, String>>,
    },
    /// A first pairing's authenticated client becomes the broker's link.
    Install {
        client: Box<AstationClient>,
        reply: oneshot::Sender<()>,
    },
    /// The operation ended (its `done` was sent).
    Finished {
        request_id: String,
        kind: OpKind,
        ok: bool,
    },
}

/// Runs `kind` on its own task; `done` and then `Finished` follow, also when
/// it panics.
pub(super) fn start(
    request_id: String,
    kind: OpKind,
    options: OpOptions,
    ui: ClientUi,
    calls: mpsc::UnboundedSender<OpCall>,
    env: OpEnv,
) {
    tokio::spawn(async move {
        let run = std::panic::AssertUnwindSafe(run(kind, &options, &ui, &calls, &env))
            .catch_unwind()
            .await;
        let (ok, error) = match run {
            Ok(Ok(())) => (true, None),
            Ok(Err(error)) => (false, Some(format!("{error:#}"))),
            Err(_) => {
                eprintln!("atem runtime: the {} operation panicked", kind.as_str());
                (
                    false,
                    Some(format!("the {} operation failed", kind.as_str())),
                )
            }
        };
        if let Some(error) = &error {
            eprintln!("atem runtime: {} failed: {error}", kind.as_str());
        }
        ui.done(ok, error);
        let _ = calls.send(OpCall::Finished {
            request_id,
            kind,
            ok,
        });
    });
}

async fn run<U: OpUi>(
    kind: OpKind,
    options: &OpOptions,
    ui: &U,
    calls: &mpsc::UnboundedSender<OpCall>,
    env: &OpEnv,
) -> Result<()> {
    match kind {
        // Verification ends itself when the CLI goes away (`verifyAbort`).
        OpKind::Pair => pair(options.save, ui, calls, env).await,
        OpKind::PairVerify => pair_verify(ui, calls, env).await,
        OpKind::CredUnlock => guard(ui, cred_unlock(ui, calls, env)).await,
        OpKind::CredProjects => guard(ui, cred_projects(options.cwd.clone(), ui, calls, env)).await,
        OpKind::Token => guard(ui, token(options.astation_id.clone(), ui, calls, env)).await,
    }
}

/// `work`, ended as a failure when the CLI goes away first.
async fn guard<U: OpUi, T>(ui: &U, work: impl Future<Output = Result<T>>) -> Result<T> {
    tokio::select! {
        result = work => result,
        _ = ui.gone() => Err(anyhow!(INTERRUPTED)),
    }
}

/// A handle on the broker's authenticated link (waits up to `LINK_WAIT`).
async fn link(
    calls: &mpsc::UnboundedSender<OpCall>,
    wait: Duration,
    encryption: bool,
    credentials: bool,
) -> Result<AstationClient> {
    let (reply, answer) = oneshot::channel();
    calls
        .send(OpCall::Link {
            encryption,
            credentials,
            reply,
        })
        .map_err(|_| anyhow!("the atem runtime is stopping"))?;
    tokio::time::timeout(wait, answer)
        .await
        .map_err(|_| anyhow!(NO_LINK))?
        .map_err(|_| anyhow!(NO_LINK))?
        .map_err(|advice| anyhow!(advice))
}

/// `link`, which must be authenticated with `astation_id` (`what` names it).
async fn link_to(
    calls: &mpsc::UnboundedSender<OpCall>,
    env: &OpEnv,
    astation_id: &str,
    what: &str,
    encryption: bool,
) -> Result<AstationClient> {
    link_routing(calls, env, astation_id, what, encryption, false).await
}

/// `link_to`, with `credentialSync` routed to the operation when `credentials`.
async fn link_routing(
    calls: &mpsc::UnboundedSender<OpCall>,
    env: &OpEnv,
    astation_id: &str,
    what: &str,
    encryption: bool,
    credentials: bool,
) -> Result<AstationClient> {
    let view = link(calls, env.link_wait, encryption, credentials).await?;
    match view.connected_astation_id() {
        Some(id) if id == astation_id => Ok(view),
        other => bail!(
            "The atem runtime is connected to Astation {}, not {what} ({astation_id})",
            other.unwrap_or("(unknown)")
        ),
    }
}

/// An `AstationLink` over a link handle whose output goes to the CLI.
pub(crate) struct UiLink<'a, U: OpUi> {
    pub client: &'a mut AstationClient,
    pub ui: &'a U,
}

impl<U: OpUi> AstationLink for UiLink<'_, U> {
    async fn send(&mut self, message: AstationMessage) -> Result<()> {
        self.client.send_message(message).await
    }

    async fn recv(&mut self) -> Option<AstationMessage> {
        self.client.recv_message_async().await
    }

    async fn apply_encryption(&mut self, message: &AstationMessage) -> Result<Option<String>> {
        self.client.handle_encryption_message(message).await
    }

    fn print(&mut self, level: PrintLevel, text: &str) {
        self.ui.print(level, text);
    }
}

/// Applies the encryption messages held during the operation and any still
/// queued for it (they were routed to it), against the pins it set.
async fn settle_encryption<U: OpUi>(view: &mut AstationClient, ui: &U) {
    while let Some(message) = view.recv_message() {
        view.hold_encryption(message);
    }
    for status in view.apply_held_encryption().await {
        if !status.is_empty() {
            ui.print(PrintLevel::Info, &shown(&status));
        }
    }
}

// ── atem pair verify ──

async fn pair_verify<U: OpUi>(
    ui: &U,
    calls: &mpsc::UnboundedSender<OpCall>,
    env: &OpEnv,
) -> Result<()> {
    let src = env.sources()?;
    let astation_id = match crate::status::verify_start(&src)? {
        crate::status::VerifyStart::AlreadyVerified(message) => {
            ui.print(PrintLevel::Info, &message);
            return Ok(());
        }
        crate::status::VerifyStart::Verify(astation_id) => astation_id,
    };
    let mut view = guard(
        ui,
        link_to(calls, env, &astation_id, "the paired Astation", true),
    )
    .await?;
    ui.print(
        PrintLevel::Info,
        &format!("Verifying this device with Astation {astation_id}..."),
    );
    let verified = crate::pair_verify::verification_result(
        verify_device(&mut view, &astation_id, &src.paths.cred, env.agent()?, ui).await,
        |line| ui.print(PrintLevel::Warn, line),
    );
    settle_encryption(&mut view, ui).await;
    verified
}

/// The CLI's answer to "does the code match?".
fn code_answer(answer: Option<AnswerValue>) -> CodeAnswer {
    match answer {
        Some(AnswerValue::Yes) => CodeAnswer::Match,
        Some(AnswerValue::No) => CodeAnswer::Refused,
        Some(AnswerValue::NoTerminal(detail)) => CodeAnswer::NoTerminal(detail),
        Some(AnswerValue::Unanswered(detail)) => CodeAnswer::Unanswered(detail),
        Some(AnswerValue::Text(_)) => CodeAnswer::Unanswered("the answer wasn't y or n".into()),
        None => CodeAnswer::Interrupted,
    }
}

/// Verifies this device with Astation on `client` (a handle on the
/// broker's link): commit, receive Astation's keys, reveal, compare the
/// safety code on both sides, then wait for Astation's signed certificate.
/// Nothing is trusted unless both sides confirm. Every failure after the
/// commit tells Astation (`verifyAbort`), unless Astation cancelled.
pub(crate) async fn verify_device<U: OpUi>(
    client: &mut AstationClient,
    astation_id: &str,
    paths: &CredPaths,
    raw_agent: Arc<dyn CredAgentApi>,
    ui: &U,
) -> Result<()> {
    use crate::memory::trust::TrustStore;
    use crate::memory::unlock::PairEscrow;
    use crate::memory::verification::{AstationKeys, Handshake, device_keys_for_verification};
    use crate::pair_verify::{
        FIRST_REPLY_TIMEOUT, TOUCH_ID_TIMEOUT, abandon_verification, await_device_verified,
        code_failure, next_verify_message, request_key_after_verification,
    };

    // The pairing this verification runs under: every cred-agent request,
    // the pending pin, Astation's certificate and the escrow apply only while
    // it is current.
    let capture = client
        .capture()
        .cloned()
        .ok_or_else(|| anyhow!(crate::pairing::NO_BINDING))?;
    capture.bound_to(astation_id)?;
    // The device id is this atem's relay identity (`atem_id`): Astation checks it
    // equals the id the connection authenticated as.
    let device_id = client.device_atem_id();
    let agent: Arc<dyn CredAgentApi> = Arc::new(crate::pairing::BoundAgent::new(
        capture.clone(),
        raw_agent.clone(),
    )?);
    let keys = {
        let (paths, agent) = (paths.clone(), agent.clone());
        // Revoked keys are never set aside here (`atem unpair` does that):
        // verification never replaces the keys an Astation trusts.
        blocking(move || device_keys_for_verification(&paths, agent.as_ref())).await?
    };
    let handshake = Handshake::start(keys);
    client
        .send_message(AstationMessage::VerifyCommit {
            device_id: device_id.clone(),
            commitment: STANDARD.encode(handshake.commitment()),
        })
        .await?;

    let first = tokio::select! {
        first = tokio::time::timeout(FIRST_REPLY_TIMEOUT, next_verify_message(client)) => Some(first),
        _ = ui.gone() => None,
    };
    let astation = match first {
        None => {
            // Nothing is pinned yet; Astation is still told.
            let failure = code_failure(CodeAnswer::Interrupted).expect("a failure");
            return Err(abandon_verification(client, &paths.trust, astation_id, failure).await);
        }
        Some(Err(_)) => {
            let text = if TrustStore::load_from(&paths.trust)?
                .verified(astation_id)
                .is_some()
            {
                "This Astation doesn't support device verification yet. Pairing is saved; this device stays verified with its existing keys."
            } else {
                "This Astation doesn't support device verification yet. Pairing is saved; encrypted sync stays off on this device."
            };
            ui.print(PrintLevel::Info, text);
            return Ok(());
        }
        Some(Ok(result)) => match result? {
            AstationMessage::VerifyKeys {
                sign_pub,
                enc_pub,
                recovery_sign_pub,
                nonce,
            } => AstationKeys::from_wire(&sign_pub, &enc_pub, &recovery_sign_pub, &nonce)?,
            AstationMessage::VerifyAbort { reason } => {
                bail!("Astation stopped device verification: {}", shown(&reason))
            }
            _ => bail!("unexpected message during device verification"),
        },
    };

    let reveal = handshake.reveal();
    client
        .send_message(AstationMessage::VerifyReveal {
            device_pub: STANDARD.encode(reveal.device_pub),
            device_sign_pub: STANDARD.encode(reveal.device_sign_pub),
            unlock_auth_pub: STANDARD.encode(reveal.unlock_auth_pub),
            nonce: STANDARD.encode(reveal.nonce_a),
        })
        .await?;
    let code = handshake.safety_code(&astation);
    let transcript = handshake.transcript(&astation);
    capture.apply(|| {
        TrustStore::update(&paths.trust, |trust| {
            trust.set_pending(
                astation_id,
                &device_id,
                handshake.keys(),
                &astation,
                &code,
                &transcript,
            );
            Ok(())
        })
    })?;

    // From here on every failure drops the pending pin and, unless Astation
    // cancelled, tells Astation (`abandon_verification`).
    ui.print(PrintLevel::Info, "");
    ui.print(PrintLevel::Info, &format!("Safety code:  {code}"));
    ui.print(
        PrintLevel::Info,
        "Your Mac shows a code too. They must match exactly.",
    );
    ui.print(
        PrintLevel::Info,
        "Confirm on both, in either order: type y here, and approve on your Mac with Touch ID.",
    );
    // The CLI reads it from its terminal (/dev/tty), never stdin.
    let answer = ui
        .ask(AskKind::YesNo, crate::pair_verify::CODES_QUESTION)
        .await;
    if let Some(failure) = code_failure(code_answer(answer)) {
        return Err(abandon_verification(client, &paths.trust, astation_id, failure).await);
    }

    ui.print(
        PrintLevel::Info,
        "Waiting for your Mac (approve with Touch ID if you haven't yet)…",
    );
    let reply = tokio::select! {
        reply = await_device_verified(client, TOUCH_ID_TIMEOUT) => reply,
        _ = ui.gone() => Err(code_failure(CodeAnswer::Interrupted).expect("a failure")),
    };
    let reply = match reply {
        Ok(reply) => reply,
        Err(failure) => {
            return Err(abandon_verification(client, &paths.trust, astation_id, failure).await);
        }
    };
    let applied = {
        // The raw agent: the whole apply holds the pairing lock already.
        let (paths, agent, capture) = (paths.clone(), raw_agent.clone(), capture.clone());
        let astation_id = astation_id.to_string();
        let keys = handshake.into_keys();
        blocking(move || {
            crate::pair_verify::apply_device_verified(
                &capture,
                &paths,
                agent.as_ref(),
                &astation_id,
                keys,
                &reply,
            )
        })
        .await
    };
    let outcome = match applied {
        Ok(outcome) => outcome,
        Err(error) => {
            let failure = VerifyFailure::local(
                format!("atem could not apply the verification: {error:#}"),
                error,
            );
            return Err(abandon_verification(client, &paths.trust, astation_id, failure).await);
        }
    };

    // Verified: nothing below fails the verification.
    ui.print(
        PrintLevel::Info,
        &format!("✅ Device verified with Astation (safety code {code})."),
    );
    if let Some(warning) = &outcome.warning {
        ui.print(PrintLevel::Warn, &format!("⚠️  {warning}"));
    }
    // The first escrow, in this run. Until Astation holds the storage key
    // the plain device_keys file stays on disk.
    let escrowed = {
        let mut link = UiLink {
            client: &mut *client,
            ui,
        };
        crate::memory::unlock::pair_escrow(&mut link, &agent, paths, astation_id, outcome.escrow)
            .await
    };
    match escrowed {
        Ok(PairEscrow::Escrowed(storage_kid)) => ui.print(
            PrintLevel::Info,
            &format!("Astation holds this device's storage key ({storage_kid})."),
        ),
        Ok(PairEscrow::HeldByHome(home)) => ui.print(
            PrintLevel::Info,
            &format!(
                "This device's storage key is held via your home Astation {home}; nothing to do."
            ),
        ),
        Ok(PairEscrow::Nothing) => {}
        Err(error) => ui.print(
            PrintLevel::Warn,
            &format!(
                "⚠️  {}",
                crate::memory::unlock::escrow_failure_message(&error)
            ),
        ),
    }
    if outcome.key_needed {
        match request_key_after_verification(client, STANDARD.encode(reveal.device_pub)).await {
            None => ui.print(PrintLevel::Info, "Encryption key requested from Astation"),
            Some(warning) => ui.print(PrintLevel::Warn, &format!("⚠️  {warning}")),
        }
    }
    Ok(())
}

// ── atem pair (first pairing) ──

/// Tokens from Astation's `credentialSync` during a first pairing.
struct Received {
    access_token: String,
    refresh_token: String,
    expires_at: u64,
    login_id: Option<String>,
    astation_id: String,
}

async fn pair<U: OpUi>(
    save: bool,
    ui: &U,
    calls: &mpsc::UnboundedSender<OpCall>,
    env: &OpEnv,
) -> Result<()> {
    let src = env.sources()?;
    let already = {
        let src = src.clone();
        blocking(move || Ok(crate::status::already_paired(&src))).await?
    };
    if let Some(text) = already {
        ui.print(PrintLevel::Info, text.trim_end());
        return Ok(());
    }
    // The trust state this pairing starts from: its binding is created only
    // if nothing changed meanwhile (another atem pair or atem unpair).
    let before = {
        let src = src.clone();
        blocking(move || crate::pairing::capture(&src)).await?
    };
    let config = src.config.clone();
    ui.print(PrintLevel::Info, "Connecting to Astation...");
    let mut client = env.new_client(&src)?.with_pairing_notice(ui.printer());
    // Local first, then a relay pairing code. Returns the code (or "local").
    let result = guard(ui, client.connect_with_pairing(&config)).await?;
    if result == "local" {
        ui.print(PrintLevel::Info, "Connected to local Astation.");
    } else {
        ui.print(PrintLevel::Info, &format!("Pairing code: {result}"));
        ui.print(
            PrintLevel::Info,
            "Approve the pairing in your Astation app.",
        );
    }
    let save_credentials = save
        || match ui
            .ask(
                AskKind::YesNo,
                "Save credentials so they keep working when Astation disconnects?",
            )
            .await
        {
            Some(answer) => answer == AnswerValue::Yes,
            None => bail!(INTERRUPTED),
        };
    // For peers that support it; the local choice is what's stored.
    client
        .send_message(AstationMessage::PairSavePreference { save_credentials })
        .await?;
    ui.print(
        PrintLevel::Info,
        "Waiting for Astation to send SSO credentials...",
    );
    let received = guard(ui, async {
        tokio::time::timeout(PAIR_CREDENTIALS_WAIT, credentials_from(&mut client, ui))
            .await
            .map_err(|_| {
                anyhow!(
                    "Pairing timed out waiting for credentials. (Astation may not yet support SSO token sync — check Astation version.)"
                )
            })?
    })
    .await?;
    let astation_id = received.astation_id.clone();
    let mut active = if result != "local" {
        ui.print(
            PrintLevel::Info,
            "Establishing an authenticated relay session...",
        );
        // The pairing-code connection never learns Astation's identity:
        // encryption messages it held are applied on the authenticated one.
        let held = client.take_held_encryption();
        drop(client);
        let mut identity = env.new_client(&src)?.with_pairing_notice(ui.printer());
        guard(
            ui,
            identity.connect_relay_identity(config.astation_relay_url(), &astation_id),
        )
        .await
        .map_err(|error| {
            anyhow!("Relay room paired, but device authentication failed: {error:#}")
        })?;
        for message in held {
            identity.hold_encryption(message);
        }
        identity
    } else {
        client
    };
    // The new pairing's binding, in the next host trust generation; the
    // connection goes on under it.
    let after = crate::pairing::bind_new(&src, &before, &astation_id)?;
    active.adopt_binding(&before, &after)?;
    let login = shared_login(
        &src,
        received.login_id.clone(),
        received.access_token.clone(),
        received.refresh_token.clone(),
        received.expires_at,
    );
    active.apply_bound(&astation_id, || {
        active.remember_relay_code(&astation_id);
        crate::pairing::PairingRecord::receive_login(
            &src.paths.pairing,
            &astation_id,
            login,
            Some(save_credentials),
        )
    })?;
    ui.print(
        PrintLevel::Info,
        &match &received.login_id {
            Some(id) => format!("Paired with Astation. (SSO: {id})"),
            None => "Paired with Astation.".to_string(),
        },
    );
    ui.print(
        PrintLevel::Info,
        if save_credentials {
            "Credentials saved — will work offline."
        } else {
            "Credentials are session-only (5 min grace period after disconnect)."
        },
    );
    // The new connection is the runtime's link from now on; the
    // verification runs on it.
    let held = active.take_held_encryption();
    let (reply, installed) = oneshot::channel();
    calls
        .send(OpCall::Install {
            client: Box::new(active),
            reply,
        })
        .map_err(|_| anyhow!("the atem runtime is stopping"))?;
    installed
        .await
        .map_err(|_| anyhow!("the atem runtime is stopping"))?;
    let mut view = guard(
        ui,
        link_to(calls, env, &astation_id, "the paired Astation", true),
    )
    .await?;
    for message in held {
        view.hold_encryption(message);
    }
    // A failed verification is shown, then makes the result a failure; the
    // pairing stays saved.
    let verified = crate::pair_verify::verification_result(
        verify_device(&mut view, &astation_id, &src.paths.cred, env.agent()?, ui).await,
        |line| ui.print(PrintLevel::Warn, line),
    );
    settle_encryption(&mut view, ui).await;
    verified
}

/// Astation's `credentialSync` on the pairing connection, applying (or
/// holding) encryption messages on the way.
async fn credentials_from<U: OpUi>(client: &mut AstationClient, ui: &U) -> Result<Received> {
    loop {
        let Some(message) = client.recv_message_async().await else {
            bail!("Astation connection closed before sending credentials.");
        };
        match client.handle_encryption_message(&message).await {
            Ok(Some(status)) => {
                if status != crate::websocket_client::HOLDING_ENCRYPTION && !status.is_empty() {
                    ui.print(PrintLevel::Info, &shown(&status));
                }
                continue;
            }
            Ok(None) => {}
            Err(error) => {
                ui.print(
                    PrintLevel::Warn,
                    &format!(
                        "Ignored an encryption message: {}",
                        shown(&format!("{error:#}"))
                    ),
                );
                continue;
            }
        }
        if let AstationMessage::CredentialSync {
            access_token,
            refresh_token,
            expires_at,
            login_id,
            astation_id,
            ..
        } = message
        {
            return Ok(Received {
                access_token,
                refresh_token,
                expires_at,
                login_id,
                astation_id,
            });
        }
    }
}

// ── atem cred unlock | projects ──

async fn cred_unlock<U: OpUi>(
    ui: &U,
    calls: &mpsc::UnboundedSender<OpCall>,
    env: &OpEnv,
) -> Result<()> {
    use crate::memory::trust::TrustStore;
    use crate::memory::unlock::{
        already_unlocked, migration_pending, unlock_and_rotate, unlock_home,
    };
    let src = env.sources()?;
    let paths = &src.paths.cred;
    let home = unlock_home(&src)?;
    let agent = env.agent()?;
    let nothing_to_do = {
        let (agent, paths, home) = (agent.clone(), paths.clone(), home.clone());
        blocking(move || already_unlocked(agent.as_ref(), &paths, &home)).await?
    };
    if let Some(message) = nothing_to_do {
        ui.print(PrintLevel::Info, &message);
        if migration_pending(&TrustStore::load_from(&paths.trust)?, &home)? {
            ui.print(
                PrintLevel::Info,
                "Finishing the encryption migration with Astation…",
            );
            let view = link_to(calls, env, &home, "this device's home Astation", true).await?;
            match view.finish_pending_migration(&home).await {
                Ok(Some(status)) => ui.print(PrintLevel::Info, &shown(&status)),
                Ok(None) => {}
                Err(error) => ui.print(
                    PrintLevel::Warn,
                    &format!("⚠️  {}", shown(&format!("{error:#}"))),
                ),
            }
        }
        return Ok(());
    }
    let mut view = link_to(calls, env, &home, "this device's home Astation", true).await?;
    // Every cred-agent request from here on (finishing the unlock, rotation,
    // escrow) runs only while the pairing the link authenticated under is
    // current: a grant or ack arriving after `atem unpair` is dropped.
    let capture = view
        .capture()
        .cloned()
        .ok_or_else(|| anyhow!(crate::pairing::NO_BINDING))?;
    let agent: Arc<dyn CredAgentApi> = Arc::new(crate::pairing::BoundAgent::new(capture, agent)?);
    {
        let mut link = UiLink {
            client: &mut view,
            ui,
        };
        unlock_and_rotate(
            &mut link,
            &agent,
            paths,
            &home,
            crate::memory::unlock::UNLOCK_TIMEOUT,
        )
        .await?;
    }
    settle_encryption(&mut view, ui).await;
    // The report sent on connect was skipped (the keys were still locked);
    // send it now. Best effort, like on connect.
    let _ = view
        .report_credential_projects_with(None, env.agent()?)
        .await;
    Ok(())
}

async fn cred_projects<U: OpUi>(
    cwd: Option<std::path::PathBuf>,
    ui: &U,
    calls: &mpsc::UnboundedSender<OpCall>,
    env: &OpEnv,
) -> Result<()> {
    let src = env.sources()?;
    let trust = crate::memory::trust::TrustStore::load_from(&src.paths.cred.trust)?;
    let home = trust
        .home()
        .ok_or_else(|| anyhow!("Verify this device with Astation first"))?
        .to_string();
    let agent = env.agent()?;
    let status = agent.clone();
    if !blocking(move || status.status().map(|status| status.unlocked)).await? {
        bail!(LOCKED);
    }
    let view = link_to(calls, env, &home, "this device's home Astation", false).await?;
    view.report_credential_projects_with(cwd, agent)
        .await
        .context("Project reporting requires an updated, unlocked Atem cred agent")?;
    ui.print(PrintLevel::Info, "Sent project suggestions to Astation.");
    Ok(())
}

// ── The paired-token refresh ──

/// The login Astation shares: issued by the configured Agora SSO.
pub(crate) fn shared_login(
    src: &Sources,
    login_id: Option<String>,
    access_token: String,
    refresh_token: String,
    expires_at: u64,
) -> crate::credentials::Login {
    crate::credentials::Login::from_sso(
        src.config.effective_sso_url(),
        login_id,
        crate::credentials::Tokens {
            access_token,
            refresh_token,
            expires_at,
        },
    )
}

/// Fresh paired credentials for `astation_id`: Astation sends a
/// `credentialSync` on connect and whenever it refreshes its own session;
/// the link applies them. When they aren't fresh yet, waits for the next.
async fn token<U: OpUi>(
    astation_id: Option<String>,
    ui: &U,
    calls: &mpsc::UnboundedSender<OpCall>,
    env: &OpEnv,
) -> Result<()> {
    let astation_id = astation_id.ok_or_else(|| anyhow!("no Astation named for the token"))?;
    let src = env.sources()?;
    let fresh = || crate::sso_auth::fresh_shared(&src.paths.pairing, &astation_id).is_some();
    if fresh() {
        return Ok(());
    }
    let mut view =
        link_routing(calls, env, &astation_id, "the paired Astation", false, true).await?;
    if fresh() {
        return Ok(());
    }
    // The link routes `credentialSync` here from now on.
    ui.print(PrintLevel::Info, "Waiting for Astation's credentials…");
    let view_recv = async {
        loop {
            match view.recv_message_async().await {
                Some(AstationMessage::CredentialSync {
                    access_token,
                    refresh_token,
                    expires_at,
                    login_id,
                    astation_id: from,
                    ..
                }) if from == astation_id => {
                    // Saved only under the pairing the link authenticated with.
                    let login =
                        shared_login(&src, login_id, access_token, refresh_token, expires_at);
                    view.apply_bound(&from, || {
                        crate::pairing::PairingRecord::receive_login(
                            &src.paths.pairing,
                            &from,
                            login,
                            None,
                        )
                    })?;
                    return Ok(());
                }
                Some(_) => continue,
                None => bail!("Astation closed the connection before sending credentials"),
            }
        }
    };
    tokio::time::timeout(CREDENTIALS_WAIT, view_recv)
        .await
        .map_err(|_| anyhow!("timed out waiting for Astation"))?
}
