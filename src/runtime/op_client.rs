//! The CLI side of an Astation operation (`atem pair`, `atem pair verify`,
//! `atem cred unlock|projects`, the paired-token refresh): asks `atem
//! runtime` (started on demand) to run it on its link, shows what it prints,
//! answers its questions from the terminal (`/dev/tty`, never stdin) and
//! ends with its result. It never opens a connection to Astation itself.

use super::client::RuntimeClient;
use super::protocol::{AnswerValue, AskKind, ClientMsg, OpKind, OpOptions, PrintLevel, RuntimeMsg};
use crate::pair_verify::CodeAnswer;
use anyhow::{Result, anyhow, bail};

/// What the CLI says when the runtime can't run the operation.
pub const NO_RUNTIME: &str =
    "Pairing and unlock run in the atem runtime, which couldn't be reached";

/// How the CLI shows an operation and answers its questions.
pub(crate) trait CliUi {
    fn print(&mut self, level: PrintLevel, text: &str);
    fn ask(&mut self, kind: AskKind, text: &str) -> impl std::future::Future<Output = AnswerValue>;
}

/// The terminal: output on stdout/stderr, answers from `/dev/tty`.
pub(crate) struct Terminal;

impl CliUi for Terminal {
    fn print(&mut self, level: PrintLevel, text: &str) {
        match level {
            PrintLevel::Info => println!("{text}"),
            PrintLevel::Warn | PrintLevel::Error => eprintln!("{text}"),
        }
    }

    async fn ask(&mut self, kind: AskKind, text: &str) -> AnswerValue {
        let text = crate::memory::unlock::shown(text);
        let answer = tokio::task::spawn_blocking(move || match kind {
            AskKind::YesNo => {
                match crate::pair_verify::prompt_yes_no(&format!("{text} Type y or n: ")) {
                    CodeAnswer::Match => AnswerValue::Yes,
                    CodeAnswer::Refused => AnswerValue::No,
                    CodeAnswer::NoTerminal(detail) => AnswerValue::NoTerminal(detail),
                    CodeAnswer::Unanswered(detail) => AnswerValue::Unanswered(detail),
                    CodeAnswer::Interrupted => AnswerValue::Unanswered("interrupted".into()),
                }
            }
            AskKind::Text => match crate::pair_verify::prompt_text(&format!("{text} ")) {
                Ok(line) => AnswerValue::Text(line),
                Err(CodeAnswer::NoTerminal(detail)) => AnswerValue::NoTerminal(detail),
                Err(other) => AnswerValue::Unanswered(format!("{other:?}")),
            },
        })
        .await;
        answer.unwrap_or_else(|error| AnswerValue::Unanswered(error.to_string()))
    }
}

/// Runs `kind` in this user's runtime (started if needed), on the terminal.
pub async fn run(kind: OpKind, options: OpOptions) -> Result<()> {
    let client = RuntimeClient::connect_or_start()
        .await
        .map_err(|error| anyhow!("{NO_RUNTIME}: {error:#}"))?;
    run_with(client, kind, options, &mut Terminal).await
}

/// Collects what an operation prints (nothing goes to the screen, which a
/// TUI may own); questions are left unanswered.
#[derive(Default)]
pub(crate) struct Quiet {
    pub lines: Vec<String>,
}

impl CliUi for Quiet {
    fn print(&mut self, _: PrintLevel, text: &str) {
        self.lines.push(text.to_string());
    }

    async fn ask(&mut self, _: AskKind, _: &str) -> AnswerValue {
        AnswerValue::NoTerminal("this operation runs without a terminal".into())
    }
}

/// Runs `kind` without printing; what it printed, or its error with them.
pub async fn run_quiet(kind: OpKind, options: OpOptions) -> Result<Vec<String>> {
    let client = RuntimeClient::connect_or_start()
        .await
        .map_err(|error| anyhow!("{NO_RUNTIME}: {error:#}"))?;
    let mut quiet = Quiet::default();
    match run_with(client, kind, options, &mut quiet).await {
        Ok(()) => Ok(quiet.lines),
        Err(error) if quiet.lines.is_empty() => Err(error),
        Err(error) => Err(anyhow!("{error:#} ({})", quiet.lines.join("; "))),
    }
}

/// Runs `kind` through `client`, shown on `ui`; the operation's result.
pub(crate) async fn run_with(
    mut client: RuntimeClient,
    kind: OpKind,
    options: OpOptions,
    ui: &mut impl CliUi,
) -> Result<()> {
    let request_id = uuid::Uuid::new_v4().to_string();
    client
        .send(&ClientMsg::AstationOp {
            request_id: request_id.clone(),
            kind,
            options,
        })
        .await?;
    loop {
        match client.recv().await? {
            None => bail!(
                "the atem runtime closed the connection during the {}; nothing more is known",
                kind.as_str()
            ),
            Some(RuntimeMsg::Print {
                request_id: re,
                level,
                text,
            }) if re == request_id => ui.print(level, &text),
            Some(RuntimeMsg::Ask {
                request_id: re,
                question_id,
                kind,
                text,
            }) if re == request_id => {
                let value = ui.ask(kind, &text).await;
                client
                    .send(&ClientMsg::Answer {
                        request_id: request_id.clone(),
                        question_id,
                        value,
                    })
                    .await?;
            }
            Some(RuntimeMsg::Done {
                request_id: re,
                ok,
                error,
            }) if re == request_id => {
                return match (ok, error) {
                    (true, _) => Ok(()),
                    (false, Some(error)) => Err(anyhow!(error)),
                    (false, None) => Err(anyhow!("the {} failed", kind.as_str())),
                };
            }
            Some(RuntimeMsg::Error { text, op }) if op.as_deref() == Some("astation_op") => {
                bail!(text)
            }
            Some(_) => {}
        }
    }
}
