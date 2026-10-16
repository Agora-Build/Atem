#!/bin/sh
D=$(dirname "$0")
T=$(dirname "$D")
n=$(date +%s%N)
cat > "$T/perm-$n.json"
echo "$(date +%s.%N) perm start pid=$$ file=perm-$n.json" >> "$T/log"
trap 'echo "$(date +%s.%N) perm got TERM" >> "$T/log"; exit 143' TERM
m=$(cat "$T/mode")
case "$m" in
 none) ;;
 sleep*)  # "sleep N [none|allow]"
   set -- $m; sleep $2 & wait $!; [ "$3" = allow ] && printf '{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"allow"}}}';;
 allow) printf '{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"allow"}}}';;
 deny) printf '{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"deny","message":"Denied by phone probe: do not run this"}}}';;
esac
echo "$(date +%s.%N) perm end mode=$m" >> "$T/log"
