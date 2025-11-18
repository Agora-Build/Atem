1. Launch Codex from Atem, with hooks for Atem to control Codex.
2. Support copy mode and can return to Atem.


- Selecting “🧠 Launch Codex” in the main menu switches the app into AppMode::CodexChat, clears input state, seeds the help banner, and immediately calls ensure_codex_session to make sure a Codex backend is running (src/main.rs:249-277).
  - ensure_codex_session lazily starts the Codex client (CodexClient::start_session) whenever sender/receiver handles are missing, resets the terminal buffer, syncs window size, and flips codex_waiting_exit off so the UI is ready to transmit (src/main.rs:468-500).
  - While in Codex mode, pressing Enter routes the input text to send_codex_prompt, which appends the command to the terminal log, forwards it over the session channel (with CR/LF), and updates status if an exit command was sent (src/main.rs:1576-1583,src/main.rs:408-459).


