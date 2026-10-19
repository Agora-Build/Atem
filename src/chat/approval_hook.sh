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
#       Prints it and exits 0. Gives up silently (exit 0, no output: no
#       decision) at the timeout (counted in polls), when Atem withdraws the
#       request, when the agent that started it is gone (its parent pid no
#       longer exists), or on HUP, INT or TERM. Its request files stay for
#       Atem, which removes them once it is gone.
#   sh approval-hook.sh post
#       Claude PostToolUse: tells Atem a tool ran while a request waits
#       (post-<id>.json), so a prompt answered in the terminal closes.
#   sh approval-hook.sh event [<Event>]
#       Codex lifecycle hooks (SessionStart, UserPromptSubmit, Stop, ...):
#       writes "$$ $PPID" (one line, so Atem can tell its own agent's hook
#       from a nested codex's) and then the hook's stdin to
#       $ATEM_APPROVAL_DIR/events/ev-<seq>-<Event>.json and exits 0 with no
#       output (output or exit 2 could change what Codex does, so never),
#       within ~2.5 s (Codex's timeout is 3 s). <Event> is the argument, else stdin's
#       "hook_event_name" (letters only; "unknown" when neither names one).
#       <seq> is the session's event counter, printed as 10 digits
#       (ev-0000000001-SessionStart.json): one more than events/seq, taken
#       under the lock events/seq.lock, a symlink whose target is the
#       holder's pid (made atomically by `ln -s`, so it always names a
#       live or dead holder, never nobody). The stdin goes to a temp file
#       first (mode 0600, umask 077) and is published with `ln`, which never
#       replaces an existing file: a name already taken moves to the next
#       seq, so no event overwrites another even if two hooks ever held the
#       lock. A lock whose pid is gone (a killed hook) is taken over after
#       ~2 s (wall time); a live holder that long means this event is
#       dropped. A hook
#       releases only a lock naming its own pid. PermissionRequest is never
#       written here (its own mode).
#       Readers take only ev-*.json files and must ignore everything else
#       in events/: tmp.* (being written), seq, seq.<pid> and seq.lock.
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
    w=
    t=$(mktemp "$e/tmp.XXXXXXXX" 2>/dev/null) || exit 0
    # While this hook lives no other hook removes the lock it made (only
    # one whose pid is gone), so it needs no check (no fork) first.
    release() {
        [ -n "$held" ] && rm -f "$l" 2>/dev/null
        held=
    }
    # The lock wait's timer, if one runs.
    untime() {
        [ -n "$w" ] && kill "$w" 2>/dev/null
        w=
    }
    trap 'rm -f "$t"; untime; release; exit 0' HUP INT TERM
    { printf '%s %s\n' "$$" "$PPID" > "$t" && cat >> "$t"; } 2>/dev/null || { rm -f "$t"; exit 0; }
    ev=${2:-}
    case $ev in '' | *[!A-Za-z]*)
        ev=$(sed -n 's/.*"hook_event_name"[[:space:]]*:[[:space:]]*"\([A-Za-z]*\)".*/\1/p' "$t" 2>/dev/null | head -n 1) ;;
    esac
    case $ev in '' | *[!A-Za-z]*) ev=unknown ;; esac
    [ "$ev" = PermissionRequest ] && { rm -f "$t"; exit 0; }
    # A directory there isn't a lock any hook makes (and `ln -s` would
    # put the link inside it): out of the way.
    if [ -d "$l" ] && [ ! -h "$l" ]; then rm -rf "$l" 2>/dev/null; fi
    # The wait for a held lock is ~2 s of wall time, not a count of polls:
    # each poll forks (`ln`, `sleep`), which a loaded machine makes slow,
    # and Codex stops waiting at 3 s. A background `sleep 2` (no stdio, so
    # Codex never waits for its output) is the timer; the builtin `kill -0`
    # checks it. The poll count (the old bound) is only a backstop.
    n=0
    until ln -s "$$" "$l" 2>/dev/null; do
        if [ -z "$w" ]; then
            sleep 2 </dev/null >/dev/null 2>&1 &
            w=$!
        fi
        if [ "$n" -ge 20 ] || ! kill -0 "$w" 2>/dev/null; then
            untime
            if [ -h "$l" ]; then
                p=$(readlink "$l" 2>/dev/null)
                case $p in
                    '' | *[!0-9]*) ;; # not a pid: no live hook made it
                    *) if kill -0 "$p" 2>/dev/null; then
                        rm -f "$t"
                        exit 0
                    fi ;;
                esac
                # Gone: removed only if it still names that holder.
                [ "$(readlink "$l" 2>/dev/null)" = "$p" ] && rm -f "$l" 2>/dev/null
            elif [ -e "$l" ]; then
                rm -f "$l" 2>/dev/null # not a lock any hook makes
            fi
            ln -s "$$" "$l" 2>/dev/null && break
            rm -f "$t"
            exit 0
        fi
        if sleep 0.1 2>/dev/null; then n=$((n + 1)); else
            sleep 1
            n=$((n + 10))
        fi
    done
    untime
    held=1
    # Under the lock, as few forks as can be (each one is slow on a loaded
    # machine, and every hook waiting for the lock waits for them): the
    # counter is read and the name padded by builtins; `ln` publishes, `mv`
    # replaces the counter, `rm` releases.
    {
        s=
        read -r s < "$e/seq"
        case $s in '' | *[!0-9]*) s=0 ;; esac
        k=0
        while [ "$k" -lt 100 ]; do
            s=$((s + 1))
            z=0000000000$s
            f=$e/ev-${z#"${z%??????????}"}-$ev.json
            if ln "$t" "$f"; then break; fi
            # No hard links here: a rename, only onto a free name.
            if [ ! -e "$f" ] && mv "$t" "$f"; then break; fi
            k=$((k + 1))
        done
        if [ "$k" -lt 100 ]; then
            printf '%s\n' "$s" > "$e/seq.$$" && mv "$e/seq.$$" "$e/seq" || rm -f "$e/seq.$$"
        fi
    } 2>/dev/null
    release
    rm -f "$t" 2>/dev/null
    exit 0
fi

limit=${2:-120}
case $limit in '' | *[!0-9]*) limit=120 ;; esac
# The agent that started it: once that pid is gone (killed, or exited
# without killing its hook), nobody reads the answer.
parent=$PPID
t=
trap '[ -n "$t" ] && rm -f "$t" 2>/dev/null; exit 0' HUP INT TERM
t=$(mktemp "$a/tmp.XXXXXXXX" 2>/dev/null) || exit 0
id=${t##*/tmp.}
req=$a/req-$id.json
dec=$a/dec-$id.json
{ printf '%s %s\n' "$$" "$PPID" > "$a/pid-$id" && cat > "$t" && mv "$t" "$req"; } 2>/dev/null || {
    rm -f "$t" "$a/pid-$id" 2>/dev/null
    exit 0
}
t=

# Polls every 100 ms: about 10 forks (sleep, and mv/cat once decided) a
# second for as long as it waits, at most the timeout. The parent check
# (`kill -0`) is a builtin: no fork.
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
    kill -0 "$parent" 2>/dev/null || exit 0
    if sleep 0.1 2>/dev/null; then n=$((n + 1)); else
        sleep 1
        n=$((n + 10))
    fi
done
exit 0
