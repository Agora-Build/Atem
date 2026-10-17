#!/bin/sh
T=$(dirname "$(dirname "$0")")
n=$(date +%s%N); cat > "$T/notif-$n.json"
echo "$(date +%s.%N) notif file=notif-$n.json" >> "$T/log"
