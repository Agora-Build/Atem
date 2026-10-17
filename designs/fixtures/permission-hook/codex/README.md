# Codex PermissionRequest hook probe (interactive TUI)

codex-cli 0.162.1, Linux, tmux 3.4, `codex --profile oss -a on-request -s read-only`, throwaway CODEX_HOME,
hook = hooks.json (`matcher "*"`, type command, perm.sh from the Claude probe). Fixtures here: permission-request-stdin.json,
perm.sh, hooks-with-timeout.json, trust-state-excerpt.toml, pane-*.txt (capture-pane tails, paths anonymised).

1. Fires: yes. stdin = session_id, turn_id, transcript_path, cwd, hook_event_name, model, permission_mode ("default"),
   tool_name ("Bash"), tool_input{command, description}. No tool_use_id, prompt_id, effort, permission_suggestions.
2. OPPOSITE of Claude: the approval prompt is HELD until the hook exits. While `sleep 25` ran the status line showed
   "Working ... Running hook" with no dialog (pane-sleep25-prompt.txt shows the dialog only after the hook ended at ~25 s);
   the user cannot answer meanwhile. So the hook (a phone decision) is authoritative for up to its timeout.
3. no output -> normal dialog. allow JSON -> runs with no dialog (even in a read-only sandbox: probe.txt was created).
   deny+message -> "Blocked by hook: <message>"; message goes to the model, command not run, the turn continues
   (followed by "Automatic approval review rejected ... with the reason ..."), no dialog.
4. `"timeout": 5` honoured: after 5 s "Hook failed: hook timed out after 5s", then the normal dialog appears. A late
   allow was never delivered; the hook process was gone afterwards (no SIGTERM trap output, so probably SIGKILL).
   Default is 600 s (docs; not waited).
5. Esc while the hook waits: turn interrupted ("Conversation interrupted"), but the hook is NOT killed; it ran to its
   natural end (40 s) and its late output was ignored. (Claude: Esc killed the hook.)
6. Trust: hooks are on by default (`features.hooks` stable true, no flag). Non-managed hooks need trust: a startup screen
   "Hooks need review" (Review / Trust all and continue / Continue without trusting) or `/hooks` then `t`. Trust is stored
   as `[hooks.state."<hooks.json path>:permission_request:0:0"] trusted_hash = sha256:...` in the writable config layer
   of that CODEX_HOME (with `--profile oss` it went to oss.config.toml); any edit of the hook entry (e.g. adding
   timeout) changes the hash and prompts for review again. So persistent per CODEX_HOME/config layer, per hook content.
   `--dangerously-bypass-hook-trust` skips it for one run. Other setup notes: `-a untrusted` does not exist in this version
   (values: on-request, never); `--profile NAME` means $CODEX_HOME/NAME.config.toml, which was needed besides config.toml;
   the folder trust prompt and an update prompt appear on first start; typing before the TUI is ready loses input.

Design implication: with Codex a remote approval can be decided inside the hook, but the local terminal has no
prompt until it returns/times out; Esc does not stop the hook. Use a short timeout (fallback is the local dialog).

Cleanup: temp CODEX_HOME (with a copied auth.json), project and tmux session removed; ~/.codex untouched.
