# Claude Code PermissionRequest hook probe (interactive, `--settings`)

Claude Code 2.1.300 at start (auto-updated to 2.1.301 mid-probe; all runs below on 2.1.301), Linux, tmux 3.4, haiku,
`--permission-mode default` ("manual mode"), hooks only from `--settings <file>`.
Fixtures: permission-request-stdin.json, notification-stdin.json, perm.sh/notif.sh (probe hooks),
settings-with-timeout.json, pane-{none,allow,deny}.txt (capture-pane tails).

1. Fires: yes. stdin = session_id, transcript_path, cwd, prompt_id, permission_mode, effort{level},
   hook_event_name, tool_name, tool_input{command,description}, permission_suggestions[{type:addDirectories,...}].
2. The dialog is NOT hidden. It renders immediately and concurrently with the running hook (hook = `sleep 25`, dialog
   visible at t=5..25 s). Keys work: Enter (Yes) ran the command at once; the hook was NOT killed, it kept running to
   its natural end (40 s) and its late output was ignored. So the hook only wins if it answers before the user does.
3. none (exit 0, no output) -> normal dialog. allow -> no dialog, runs, tool result "Allowed by PermissionRequest hook".
   deny+message -> tool result "Error: Denied by phone probe: do not run this" + "Denied by PermissionRequest hook";
   the message reaches the model (it quoted it and did not retry).
4. `"timeout": 5` accepted. At 5 s the hook got SIGTERM (script exited); dialog was already up and stayed; no visible
   error text in the pane. A late `allow` (sleep 20) was never delivered. Default 600 s not tested (not waited).
5. Notification(permission_prompt) fires ("Claude needs your permission", notification_type permission_prompt) but only
   ~6 s after PermissionRequest started, and only if the dialog is still unanswered (not fired for allow/deny that
   answered immediately). It does not wait for the hook to end.
6. Esc on the visible dialog = "Interrupted - What should Claude do instead?" and the waiting hook got SIGTERM
   (killed; ps empty). Contrast with answering via Yes: hook left running.

Design implication: a hook that waits for a phone decision leaves the terminal dialog live (the local user can answer
first; the hook must tolerate being ignored/TERMed, and the runtime must treat a local answer as superseding the remote
approval). Never rely on the hook to hide the dialog.

Side effects: Claude added a trust entry for the temp project in ~/.claude.json (projects["/tmp/phprobe.*/proj"]);
the temp project dir under ~/.claude/projects was removed.
