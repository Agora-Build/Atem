# Atem approval hook v1 (PermissionRequest). POSIX sh, no dependencies.
#
#   sh approval-hook.sh claude|codex <timeout-seconds>
#       Writes the agent's request (stdin) to $ATEM_APPROVAL_DIR/approvals/
#       req-<id>.json ("$$ $PPID" in pid-<id>, so Atem can tell its own
#       agent's hook from a nested one) and waits for Atem's decision
#       dec-<id>.json, which holds the exact output for the agent (empty: no
#       decision). It claims the decision by renaming it to taken-<id>.json
#       (stamped with the claim time); Atem withdraws one by renaming it too,
#       so exactly one of them gets it. Prints it and exits 0. Gives up
#       silently at the timeout or when Atem withdraws the request.
#   sh approval-hook.sh post
#       Claude PostToolUse: tells Atem a tool ran while a request waits
#       (post-<id>.json), so a prompt answered in the terminal closes.
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

n=0
max=$((limit * 10))
while [ "$n" -lt "$max" ]; do
    if [ -f "$dec" ] && [ ! -h "$dec" ] && mv "$dec" "$a/taken-$id.json" 2>/dev/null; then
        touch "$a/taken-$id.json" 2>/dev/null
        out=$(cat "$a/taken-$id.json" 2>/dev/null) || exit 0
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
