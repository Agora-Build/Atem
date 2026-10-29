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
#   sh approval-hook.sh event [<Event> [sync]]
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
#       live or dead holder, never nobody). The counter is advanced first,
#       then the stdin (in a temp file, mode 0600, umask 077) is published
#       with `ln`, which never replaces an existing file; either failing
#       fails the hook, and a number left without its event is a gap the
#       reader counts as lost. A lock whose pid is gone (a killed hook) is taken over after
#       ~2 s (wall time); a live holder that long means an async event is
#       dropped. A hook
#       releases only a lock naming its own pid. PermissionRequest is never
#       written here (its own mode).
#       Synchronous events (Codex waits for them: PreToolUse, PostToolUse,
#       UserPromptSubmit, Interrupt; any event with `sync`: Claude Code
#       waits for all its hooks) are never dropped by this script: each
#       first leaves start-<Event>.<pid> (a builtin redirection, before
#       anything that could fail), waits longer for the lock (~6 s; ~2 s for
#       Interrupt, which Codex clamps to 3 s), and removes the marker only
#       once its event is published. A marker whose pid is gone is a lost
#       event (killed, timed out, failed) that Atem detects. A PreToolUse
#       that can't publish exits 2, which makes Codex block the tool (its
#       marker removed: no call happened); Codex lets any other failure
#       through, so the marker is what tells.
#       Readers take only ev-*.json files and must ignore everything else
#       in events/: tmp.* (being written), seq, seq.<pid>, seq.lock and
#       start-*.
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
    named=${2:-}
    l=$e/seq.lock
    held=
    w=
    t=
    ev=
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
    # Synchronous events: the lock wait (seconds) and the start marker.
    # `event <Event> sync` (Claude: Claude Code waits for every hook) makes
    # any event one.
    case $named in
        PreToolUse | PostToolUse | UserPromptSubmit) sync=6 ;;
        Interrupt) sync=2 ;;
        *) sync= ;;
    esac
    [ "${3:-}" = sync ] && [ -z "$sync" ] && sync=6
    m=
    # Not published: a PreToolUse blocks its tool (exit 2: no call, so no
    # marker); any other event keeps its marker for Atem to find.
    fail() {
        [ -n "$t" ] && rm -f "$t" 2>/dev/null
        untime
        release
        if [ "$named" = PreToolUse ]; then
            [ -n "$m" ] && rm -f "$m" 2>/dev/null
            echo "Atem could not record this tool call; blocked" >&2
            exit 2
        fi
        exit 0
    }
    if [ -n "$sync" ]; then
        m=$e/start-$named.$$
        # `printf`, not `:`: a failed redirection on a special builtin
        # would exit the script (status 2) instead of reaching `fail`.
        printf '' 2>/dev/null > "$m" || { m=; fail; }
    fi
    t=$(mktemp "$e/tmp.XXXXXXXX" 2>/dev/null) || { t=; fail; }
    # A signal (Codex's timeout among them) lets the tool through: the
    # marker stays, so Atem knows this event was lost.
    trap '[ -n "$t" ] && rm -f "$t" 2>/dev/null; untime; release; exit 2' HUP INT TERM
    { printf '%s %s\n' "$$" "$PPID" > "$t" && cat >> "$t"; } 2>/dev/null || fail
    ev=${2:-}
    case $ev in '' | *[!A-Za-z]*)
        ev=$(sed -n 's/.*"hook_event_name"[[:space:]]*:[[:space:]]*"\([A-Za-z]*\)".*/\1/p' "$t" 2>/dev/null | head -n 1) ;;
    esac
    case $ev in '' | *[!A-Za-z]*) ev=unknown ;; esac
    [ "$ev" = PermissionRequest ] && { rm -f "$t" "$m"; exit 0; }
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
            sleep "${sync:-2}" </dev/null >/dev/null 2>&1 &
            w=$!
        fi
        if [ "$n" -ge $((${sync:-2} * 10)) ] || ! kill -0 "$w" 2>/dev/null; then
            untime
            if [ -h "$l" ]; then
                p=$(readlink "$l" 2>/dev/null)
                case $p in
                    '' | *[!0-9]*) ;; # not a pid: no live hook made it
                    *) if kill -0 "$p" 2>/dev/null; then
                        fail
                    fi ;;
                esac
                # Gone: removed only if it still names that holder.
                [ "$(readlink "$l" 2>/dev/null)" = "$p" ] && rm -f "$l" 2>/dev/null
            elif [ -e "$l" ]; then
                rm -f "$l" 2>/dev/null # not a lock any hook makes
            fi
            ln -s "$$" "$l" 2>/dev/null && break
            fail
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
    # counter is read and the name padded by builtins. The counter is
    # advanced first (`mv`, atomic), then the event published under that
    # number (`ln`, onto a free name only): an event never exists above
    # the counter (a request's `evseq` always covers what was published
    # before it), and a number without its event is a gap the reader
    # detects as a lost event. Either step failing fails the hook: never a
    # partial success.
    {
        s=
        read -r s < "$e/seq"
        case $s in '' | *[!0-9]*) s=0 ;; esac
        s=$((s + 1))
        z=0000000000$s
        f=$e/ev-${z#"${z%??????????}"}-$ev.json
        printf '%s\n' "$s" > "$e/seq.$$" && mv "$e/seq.$$" "$e/seq"
    } 2>/dev/null || { rm -f "$e/seq.$$" 2>/dev/null; fail; }
    ln "$t" "$f" 2>/dev/null || fail
    release
    rm -f "$t" 2>/dev/null
    # Published: no longer a lost event.
    [ -n "$m" ] && rm -f "$m" 2>/dev/null
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
# The events published so far (Codex ran this call's synchronous
# PreToolUse to its end before asking): Atem binds the request to a call
# only among events up to it. Missing: no binding.
s=
{ read -r s < "$d/events/seq"; } 2>/dev/null
case $s in '' | *[!0-9]*) s=0 ;; esac
{ printf '%s %s\n' "$$" "$PPID" > "$a/pid-$id" && printf '%s\n' "$s" > "$a/evseq-$id" && cat > "$t" && mv "$t" "$req"; } 2>/dev/null || {
    rm -f "$t" "$a/pid-$id" "$a/evseq-$id" 2>/dev/null
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
