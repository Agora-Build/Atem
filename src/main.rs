mod agora_api;
mod ai_client;
mod app;
mod command;
mod dispatch;
mod auth;
mod sso_auth;
mod claude_client;
mod cli;
mod codex_client;
mod pty_session;
mod session;
mod terminal_share;
mod terminal_keys;
mod diagnostics;
mod config;
mod convo_config;
mod convo_test_server;
mod convo_wizard;
mod credentials;
mod repl;
mod time_sync;
mod token;
mod tui;
mod vault_client;
mod memory;
mod pair_verify;
mod pairing;
mod machine_key;
mod paths;
mod profile;
mod records;
mod status;
mod version;
mod chat;
mod daemon;
mod runtime;
mod session_protocol;
#[cfg(test)]
mod test_profile;
// Agora RTM client: kept but unused for now (voice coding was removed in atem-session r6).
#[allow(dead_code)]
mod rtm_client;
mod websocket_client;
// Agent status on the Astation wire
// Shared HTTPS scaffolding
mod web_server;
// RTC test server
mod rtc_test_server;
// Static-file HTTPS server (atem serv files)
mod files_server;
// Local Agora webhook receiver + ngrok tunnel
mod webhook_server;

use anyhow::Result;
use clap::Parser;

#[tokio::main]
async fn main() -> Result<()> {
    let cli_args = cli::Cli::parse();
    if cli_args.version {
        print!("{}", tokio::task::spawn_blocking(version::text).await?);
        return Ok(());
    }
    if let Some(command) = cli_args.command {
        cli::handle_cli_command(command).await
    } else {
        tui::run_tui().await
    }
}
