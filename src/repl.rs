use anyhow::Result;
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;
use std::io::Write;

use crate::ai_client::AiClient;

const HISTORY_FILE: &str = ".atem_history";

/// Known commands for exact matching (without the "atem" prefix).
const KNOWN_COMMANDS: &[&str] = &[
    "list project",
    "list project --show-certificates",
    "project show",
    "config show",
    "token rtc create",
    "token rtc decode",
    "token rtm create",
    "login",
    "logout",
    "help",
    "quit",
    "exit",
];

/// Try to match user input to a known command exactly.
fn try_exact_match(input: &str) -> Option<String> {
    let normalized = input.trim().to_lowercase();

    // Strip optional "atem " prefix
    let stripped = normalized
        .strip_prefix("atem ")
        .unwrap_or(&normalized);

    // Check direct matches
    for &cmd in KNOWN_COMMANDS {
        if stripped == cmd || stripped.starts_with(&format!("{} ", cmd)) {
            // Return the full command with "atem" prefix
            return Some(format!("atem {}", stripped));
        }
    }

    // Check partial command starts that need arguments
    if stripped.starts_with("project use ") {
        return Some(format!("atem {}", stripped));
    }
    if stripped.starts_with("token rtc decode ") {
        return Some(format!("atem {}", stripped));
    }
    if stripped.starts_with("token rtc create") {
        return Some(format!("atem {}", stripped));
    }
    if stripped.starts_with("token rtm create") {
        return Some(format!("atem {}", stripped));
    }

    None
}

/// Parse an "atem ..." command string into CLI args for clap.
fn command_to_args(command: &str) -> Vec<String> {
    let stripped = command
        .trim()
        .strip_prefix("atem ")
        .unwrap_or(command.trim());

    // Simple shell-like splitting (handles quoted strings)
    shell_split(stripped)
}

/// Basic shell argument splitting that handles double quotes.
fn shell_split(input: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '"' => in_quotes = !in_quotes,
            ' ' if !in_quotes => {
                if !current.is_empty() {
                    args.push(current.clone());
                    current.clear();
                }
            }
            _ => current.push(ch),
        }
    }
    if !current.is_empty() {
        args.push(current);
    }
    args
}

/// Execute a parsed atem command programmatically.
/// Uses Box::pin to break the async recursion cycle:
/// handle_cli_command -> run_repl -> execute_command -> handle_cli_command
fn execute_command(command: &str) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + '_>> {
    Box::pin(async move {
        use clap::Parser;

        let args = command_to_args(command);
        let mut full_args = vec!["atem".to_string()];
        full_args.extend(args);

        let cli = crate::cli::Cli::try_parse_from(&full_args)
            .map_err(|e| anyhow::anyhow!("Invalid command: {}", e))?;

        match cli.command {
            Some(crate::cli::Commands::Repl) => {
                println!("Already in REPL mode.");
                Ok(())
            }
            Some(cmd) => crate::cli::handle_cli_command(cmd).await,
            None => {
                println!("No command specified. Type 'help' for available commands.");
                Ok(())
            }
        }
    })
}

fn print_help() {
    println!("Atem REPL - Interactive command shell with AI assistance");
    println!();
    println!("Available commands:");
    println!("  list project [--show-certificates]  List all Agora projects");
    println!("  project use <APP_ID>                Set active project");
    println!("  project show                        Show active project");
    println!("  config show                         Show configuration");
    println!("  token rtc create [options]           Generate RTC token");
    println!("    --channel <NAME>  --uid <ID>  --role publisher|subscriber  --expire <SECS>");
    println!("  token rtc decode <TOKEN>            Decode RTC token");
    println!("  token rtm create [options]           Generate RTM token");
    println!("    --user-id <ID>  --expire <SECS>");
    println!();
    println!("You can also type natural language and AI will interpret it.");
    println!("  Example: \"show me all my projects\"");
    println!("  Example: \"create an rtc token for channel test123\"");
    println!();
    println!("  help   Show this help");
    println!("  quit   Exit the REPL");
}

/// Prompt the user for confirmation.
fn confirm(prompt: &str) -> bool {
    print!("{} [Y/n] ", prompt);
    let _ = std::io::stdout().flush();

    let mut input = String::new();
    match std::io::stdin().read_line(&mut input) {
        Ok(_) => {
            let trimmed = input.trim().to_lowercase();
            trimmed.is_empty() || trimmed == "y" || trimmed == "yes"
        }
        Err(_) => false,
    }
}

/// Run the interactive REPL.
pub async fn run_repl() -> Result<()> {
    println!("Atem REPL v0.1.0");
    println!("Type 'help' for commands, or use natural language. 'quit' to exit.");
    println!();

    let ai_client = match AiClient::new() {
        Ok(client) => {
            println!("AI assistant enabled (set ANTHROPIC_API_KEY)");
            Some(client)
        }
        Err(_) => {
            println!("AI assistant disabled (ANTHROPIC_API_KEY not set)");
            println!("Only exact command matching available.");
            None
        }
    };
    println!();

    let mut rl = DefaultEditor::new()?;

    // Load history
    let history_path = dirs::config_dir()
        .map(|d| d.join("atem").join(HISTORY_FILE))
        .unwrap_or_else(|| std::path::PathBuf::from(HISTORY_FILE));
    let _ = rl.load_history(&history_path);

    loop {
        match rl.readline("atem> ") {
            Ok(line) => {
                let input = line.trim();
                if input.is_empty() {
                    continue;
                }

                rl.add_history_entry(input)?;

                // Handle built-in REPL commands
                match input.to_lowercase().as_str() {
                    "quit" | "exit" | "q" => {
                        println!("Goodbye.");
                        break;
                    }
                    "help" | "?" => {
                        print_help();
                        continue;
                    }
                    _ => {}
                }

                // Try exact command match first
                if let Some(command) = try_exact_match(input) {
                    if let Err(e) = execute_command(&command).await {
                        println!("Error: {}", e);
                    }
                    continue;
                }

                // Fall back to AI interpretation
                match &ai_client {
                    Some(client) => {
                        print!("Thinking...");
                        let _ = std::io::stdout().flush();

                        match client.interpret_command(input).await {
                            Ok(intent) => {
                                // Clear the "Thinking..." text
                                print!("\r              \r");
                                let _ = std::io::stdout().flush();

                                if intent.command.is_empty() {
                                    println!("Could not map to a command: {}", intent.explanation);
                                    continue;
                                }

                                println!("  {} ", intent.explanation);
                                let prompt_msg = format!("Run: {} ?", intent.command);
                                if confirm(&prompt_msg) {
                                    if let Err(e) = execute_command(&intent.command).await {
                                        println!("Error: {}", e);
                                    }
                                } else {
                                    println!("Cancelled.");
                                }
                            }
                            Err(e) => {
                                print!("\r              \r");
                                let _ = std::io::stdout().flush();
                                println!("AI error: {}", e);
                                println!("Try typing an exact command instead.");
                            }
                        }
                    }
                    None => {
                        println!(
                            "Unknown command: '{}'. Type 'help' for available commands.",
                            input
                        );
                    }
                }
            }
            Err(ReadlineError::Interrupted) => {
                println!("^C");
                continue;
            }
            Err(ReadlineError::Eof) => {
                println!("Goodbye.");
                break;
            }
            Err(err) => {
                println!("Input error: {}", err);
                break;
            }
        }
    }

    // Save history
    if let Some(parent) = history_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = rl.save_history(&history_path);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_match_list_project() {
        assert_eq!(
            try_exact_match("list project"),
            Some("atem list project".to_string())
        );
    }

    #[test]
    fn exact_match_with_atem_prefix() {
        assert_eq!(
            try_exact_match("atem list project"),
            Some("atem list project".to_string())
        );
    }

    #[test]
    fn exact_match_case_insensitive() {
        assert_eq!(
            try_exact_match("List Project"),
            Some("atem list project".to_string())
        );
    }

    #[test]
    fn exact_match_with_flags() {
        assert_eq!(
            try_exact_match("list project --show-certificates"),
            Some("atem list project --show-certificates".to_string())
        );
    }

    #[test]
    fn exact_match_project_use() {
        assert_eq!(
            try_exact_match("project use abc123"),
            Some("atem project use abc123".to_string())
        );
    }

    #[test]
    fn exact_match_token_rtc_create_with_args() {
        assert_eq!(
            try_exact_match("token rtc create --channel test --uid 42"),
            Some("atem token rtc create --channel test --uid 42".to_string())
        );
    }

    #[test]
    fn exact_match_config_show() {
        assert_eq!(
            try_exact_match("config show"),
            Some("atem config show".to_string())
        );
    }

    #[test]
    fn no_match_for_unknown() {
        assert_eq!(try_exact_match("do something random"), None);
    }

    #[test]
    fn shell_split_simple() {
        assert_eq!(
            shell_split("list project --show-certificates"),
            vec!["list", "project", "--show-certificates"]
        );
    }

    #[test]
    fn shell_split_quoted() {
        assert_eq!(
            shell_split(r#"token rtc decode "abc def""#),
            vec!["token", "rtc", "decode", "abc def"]
        );
    }

    #[test]
    fn command_to_args_strips_prefix() {
        assert_eq!(
            command_to_args("atem list project"),
            vec!["list", "project"]
        );
    }

    #[test]
    fn command_to_args_without_prefix() {
        assert_eq!(
            command_to_args("config show"),
            vec!["config", "show"]
        );
    }
}
