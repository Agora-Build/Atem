#!/bin/sh
# Stand-in for the interactive Claude CLI, used by Atem's chat tests.
# Runs the hook command Atem put in --settings for each lifecycle event and
# writes a transcript the way Claude Code 2.1.x does (see claude/README.md).
# Each bracketed-paste line read from the terminal is one prompt; "exit" quits.
# It prints nothing, so Atem saves no session log for it.
settings=
session=
while [ $# -gt 0 ]; do
    case "$1" in
        --settings) settings=$2; shift ;;
        --session-id) session=$2; shift ;;
    esac
    shift
done
[ -n "$settings" ] || exec cat >/dev/null
[ -n "$session" ] || session=fake-session
hook=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["hooks"]["Stop"][0]["hooks"][0]["command"])' "$settings")
chat_dir=$(dirname "$settings")
transcript="$(dirname "$chat_dir")/transcripts/$session.jsonl"
mkdir -p "$(dirname "$transcript")"
: >> "$transcript"

fire() { printf '%s' "$1" | sh -c "$hook"; }
log() { printf '%s\n' "$1" >> "$transcript"; }
json_escape() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }

# Cooked mode: the paste's final \r arrives as a newline.
stty -echo icrnl 2>/dev/null || true
fire "{\"hook_event_name\":\"SessionStart\",\"session_id\":\"$session\",\"transcript_path\":\"$transcript\",\"source\":\"startup\"}"

esc=$(printf '\033')
n=0
while IFS= read -r line; do
    case "$line" in
        *"$esc[200~"*)
            n=$((n + 1))
            text=${line#*"$esc[200~"}
            text=${text%"$esc[201~"*}
            t=$(json_escape "$text")
            ts="2026-10-15T00:00:0$((n % 10)).000Z"
            fire "{\"hook_event_name\":\"UserPromptSubmit\",\"session_id\":\"$session\",\"prompt\":\"$t\",\"prompt_id\":\"p-$n\"}"
            log "{\"type\":\"user\",\"uuid\":\"u-$n\",\"promptId\":\"p-$n\",\"timestamp\":\"$ts\",\"message\":{\"role\":\"user\",\"content\":\"$t\"}}"
            fire "{\"hook_event_name\":\"PreToolUse\",\"session_id\":\"$session\",\"tool_name\":\"Bash\"}"
            log "{\"type\":\"assistant\",\"uuid\":\"a-$n-1\",\"promptId\":\"p-$n\",\"timestamp\":\"$ts\",\"message\":{\"id\":\"msg-$n\",\"role\":\"assistant\",\"content\":[{\"type\":\"tool_use\",\"id\":\"tool-$n\",\"name\":\"Bash\",\"input\":{\"command\":\"echo hi\"}}],\"stop_reason\":\"tool_use\"}}"
            fire "{\"hook_event_name\":\"PostToolUse\",\"session_id\":\"$session\",\"tool_name\":\"Bash\"}"
            log "{\"type\":\"user\",\"uuid\":\"r-$n\",\"promptId\":\"p-$n\",\"timestamp\":\"$ts\",\"message\":{\"role\":\"user\",\"content\":[{\"type\":\"tool_result\",\"tool_use_id\":\"tool-$n\",\"content\":\"hi\"}]}}"
            log "{\"type\":\"assistant\",\"uuid\":\"a-$n-2\",\"promptId\":\"p-$n\",\"timestamp\":\"$ts\",\"message\":{\"id\":\"msg-$n\",\"role\":\"assistant\",\"content\":[{\"type\":\"text\",\"text\":\"reply $n\"}],\"stop_reason\":\"end_turn\"}}"
            fire "{\"hook_event_name\":\"Stop\",\"session_id\":\"$session\"}"
            ;;
        exit) exit 0 ;;
    esac
done
