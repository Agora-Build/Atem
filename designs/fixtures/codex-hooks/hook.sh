#!/bin/sh
# observe-only: record stdin, exit 0, no output
d=$EVENTS_DIR
t=$(date +%s.%N)
cat > "$d/tmp.$$"
ev=$(python3 -I -c 'import json,sys;print(json.load(open(sys.argv[1])).get("hook_event_name","x"))' "$d/tmp.$$" 2>/dev/null)
mv "$d/tmp.$$" "$d/$t-$ev.json"
exit 0
