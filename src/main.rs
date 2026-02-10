mod agora_api;
mod ai_client;
mod app;
mod command;
mod dispatch;
mod auth;
mod claude_client;
mod cli;
mod codex_client;
mod config;
mod repl;
mod rtm_client;
mod time_sync;
mod token;
mod tui;
mod websocket_client;

use anyhow::Result;
use clap::Parser;

#[tokio::main]
async fn main() -> Result<()> {
    let cli_args = cli::Cli::parse();
    if let Some(command) = cli_args.command {
        cli::handle_cli_command(command).await
    } else {
        tui::run_tui().await
    }
}
