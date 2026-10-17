# Atem agent hook v1 (approvals, and Codex lifecycle events for chat).
# POSIX sh, no dependencies. The installed name stays approval-hook.sh:
# Codex trusts each hooks.json entry by a hash of its command, which names
# this file.
#
#   sh approval-hook.sh claude|codex <timeout-seconds>
#       Writes the agent's request (stdin) to $ATEM_APPROVAL_DIR/approvals/
#       req-<id>.json ("$$ $PPID" in pid-<id>, so Atem can tell its own
#       agent's hook from a nested one) and waits for Atem's decision
#       dec-<id>.json, which holds the exact output for the agent (empty: no
#       decision). It claims the decision by renaming it to taken-<id>.json
#       (stamped with the claim time; once read it becomes claimed-<id>, the
#       time kept); Atem withdraws one by renaming it too, so exactly one of
#       them gets it, and never touches a claimed one while the hook runs.
#       Prints it and exits 0. Gives up silently at the timeout or when Atem
#       withdraws the request.
#   sh approval-hook.sh post
#       Claude PostToolUse: tells Atem a tool ran while a request waits
#       (post-<id>.json), so a prompt answered in the terminal closes.
#   sh approval-hook.sh event [<Event>]
#       Codex lifecycle hooks (SessionStart, UserPromptSubmit, Stop, ...):
#       writes the hook's stdin to $ATEM_APPROVAL_DIR/events/
#       ev-<seq>-<Event>.json and exits 0 with no output (Codex runs these
#       hooks async; output or exit 2 could change what it does, so never).
#       <Event> is the argument, else stdin's "hook_event_name" (letters
#       only; "unknown" when neither names one). <seq> is the session's
#       event counter (events/seq), 1 for the first event and one more for
#       each next one, printed as 10 digits (ev-0000000001-SessionStart.json),
#       taken under the lock directory events/seq.lock. The file is written
#       to a temp file first (mode 0600, umask 077) and renamed into place
#       under that lock, so it appears whole and in seq order. A lock left
#       by a killed hook is taken over after about 2 s (its pid in
#       seq.lock/pid is gone); a live holder that long means the event is
#       dropped. PermissionRequest is never written here (its own mode).
#
# Without ATEM_APPROVAL_DIR (an agent not started by Atem) it exits at once
# with no output, so the agent asks as usual. It never decides anything
# itself and never prints anything but Atem's decision: any failure means
# "no decision".
d=${ATEM_APPROVAL_DIR:-}
[ -n "$d" ] && [ -d "$d/approvals" ] || exit 0
a=$d/approvals
umask 077
trap 'exit 0' HUP INT TERM

if [ "$1" = post ]; then
    for f in "$a"/req-*.json; do
        [ -e "$f" ] || exit 0
        break
    done
    { t=$(mktemp "$a/tmp.XXXXXXXX") && cat > "$t" && mv "$t" "$a/post-${t##*/tmp.}.json"; } 2>/dev/null
    exit 0
fi

if [ "$1" = event ]; then
    e=$d/events
    [ -d "$e" ] || exit 0
    l=$e/seq.lock
    held=
    t=$(mktemp "$e/tmp.XXXXXXXX" 2>/dev/null) || exit 0
    trap 'rm -f "$t"; [ -n "$held" ] && rm -rf "$l"; exit 0' HUP INT TERM
    cat > "$t" 2>/dev/null || { rm -f "$t"; exit 0; }
    ev=${2:-}
    case $ev in '' | *[!A-Za-z]*)
        ev=$(sed -n 's/.*"hook_event_name"[[:space:]]*:[[:space:]]*"\([A-Za-z]*\)".*/\1/p' "$t" 2>/dev/null | head -n 1) ;;
    esac
    case $ev in '' | *[!A-Za-z]*) ev=unknown ;; esac
    [ "$ev" = PermissionRequest ] && { rm -f "$t"; exit 0; }
    n=0
    until mkdir "$l" 2>/dev/null; do
        if [ "$n" -ge 20 ]; then
            p=$(cat "$l/pid" 2>/dev/null)
            if [ -n "$p" ] && kill -0 "$p" 2>/dev/null; then
                rm -f "$t"
                exit 0
            fi
            rm -rf "$l" 2>/dev/null
            mkdir "$l" 2>/dev/null && break
            rm -f "$t"
            exit 0
        fi
        if sleep 0.1 2>/dev/null; then n=$((n + 1)); else
            sleep 1
            n=$((n + 10))
        fi
    done
    held=1
    {
        printf '%s\n' "$$" > "$l/pid"
        s=$(cat "$e/seq" 2>/dev/null)
        case $s in '' | *[!0-9]*) s=0 ;; esac
        s=$((s + 1))
        printf '%s\n' "$s" > "$e/seq.tmp" && mv "$e/seq.tmp" "$e/seq" &&
            mv "$t" "$e/$(printf 'ev-%010d-%s.json' "$s" "$ev")"
    } 2>/dev/null
    rm -f "$t" 2>/dev/null
    rm -rf "$l" 2>/dev/null
    exit 0
fi

limit=${2:-120}
case $limit in '' | *[!0-9]*) limit=120 ;; esac
t=$(mktemp "$a/tmp.XXXXXXXX" 2>/dev/null) || exit 0
id=${t##*/tmp.}
req=$a/req-$id.json
dec=$a/dec-$id.json
{ printf '%s %s\n' "$$" "$PPID" > "$a/pid-$id" && cat > "$t" && mv "$t" "$req"; } 2>/dev/null || {
    rm -f "$t" "$a/pid-$id" 2>/dev/null
    exit 0
}

# Polls every 100 ms: about 10 forks (sleep, and mv/cat once decided) a
# second for as long as it waits, at most the timeout.
n=0
max=$((limit * 10))
while [ "$n" -lt "$max" ]; do
    if [ -f "$dec" ] && [ ! -h "$dec" ] && mv "$dec" "$a/taken-$id.json" 2>/dev/null; then
        touch "$a/taken-$id.json" 2>/dev/null
        out=$(cat "$a/taken-$id.json" 2>/dev/null) || exit 0
        # Read: out of the way, its time (the claim's) kept for Atem.
        mv "$a/taken-$id.json" "$a/claimed-$id" 2>/dev/null
        [ -n "$out" ] && printf '%s' "$out"
        exit 0
    fi
    [ -f "$req" ] || exit 0
    if sleep 0.1 2>/dev/null; then n=$((n + 1)); else
        sleep 1
        n=$((n + 10))
    fi
done
exit 0
