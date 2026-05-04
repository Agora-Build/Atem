#!/usr/bin/env bash
#
# Smoke test for the atem CLI. Exercises every non-interactive command and
# verifies that each one exits 0 (and for token commands, that decode matches
# what create produced).
#
# Usage:
#   ./scripts/smoke-test.sh                              # uses active project
#   APP_ID=... APP_CERT=... ./scripts/smoke-test.sh      # without active project
#
# Requires: cargo build (uses ./target/debug/atem by default; override with ATEM=...)
#
# Skips (interactive / network / external):
#   atem login, atem logout, atem pair, atem unpair, atem repl

set -u

ATEM="${ATEM:-./target/debug/atem}"
PASS=0
FAIL=0
SKIP=0
FAILED_NAMES=()

# Allow overriding via env so token commands work even with no active project.
if [[ -n "${APP_ID:-}" ]]; then
    export AGORA_APP_ID="$APP_ID"
fi
if [[ -n "${APP_CERT:-}" ]]; then
    export AGORA_APP_CERTIFICATE="$APP_CERT"
fi

color() { printf "\033[%sm%s\033[0m" "$1" "$2"; }
green() { color "32" "$1"; }
red()   { color "31" "$1"; }
yellow(){ color "33" "$1"; }
dim()   { color "2" "$1"; }

# run <name> <expected-exit-code-default-0> -- <command...>
#   Or: run <name> -- <command...>   (expects exit 0)
run() {
    local name="$1"; shift
    local expected=0
    if [[ "$1" =~ ^[0-9]+$ ]]; then
        expected="$1"; shift
    fi
    [[ "$1" == "--" ]] && shift

    printf "  %s ... " "$(dim "$name")"
    local output
    output="$("$@" 2>&1)"
    local rc=$?

    if [[ "$rc" == "$expected" ]]; then
        green "PASS"; echo
        PASS=$((PASS + 1))
    else
        red "FAIL"; echo " (exit=$rc, expected=$expected)"
        echo "$output" | sed 's/^/      /'
        FAIL=$((FAIL + 1))
        FAILED_NAMES+=("$name")
    fi
}

# run_contains <name> <substring> -- <command...>
#   PASS if command exits 0 AND stdout/stderr contains substring.
run_contains() {
    local name="$1"; shift
    local needle="$1"; shift
    [[ "$1" == "--" ]] && shift

    printf "  %s ... " "$(dim "$name")"
    local output
    output="$("$@" 2>&1)"
    local rc=$?

    if [[ "$rc" == 0 && "$output" == *"$needle"* ]]; then
        green "PASS"; echo
        PASS=$((PASS + 1))
    else
        red "FAIL"; echo " (exit=$rc, expected 0 + substring '$needle')"
        echo "$output" | sed 's/^/      /'
        FAIL=$((FAIL + 1))
        FAILED_NAMES+=("$name")
    fi
}

skip() {
    printf "  %s ... " "$(dim "$1")"
    yellow "SKIP"; echo " ($2)"
    SKIP=$((SKIP + 1))
}

# ── Pre-flight ───────────────────────────────────────────────────────
echo "$(green "atem smoke test") — binary: $ATEM"
if [[ ! -x "$ATEM" ]]; then
    red "Binary not found or not executable: $ATEM"; echo
    echo "  Run: cargo build"
    exit 1
fi
$ATEM --version 2>&1 | head -1 | sed 's/^/  /'
echo

# ── Help ─────────────────────────────────────────────────────────────
echo "$(yellow "Help")"
run_contains "atem --help"             "Commands"        -- "$ATEM" --help
run_contains "atem --version"          "atem"            -- "$ATEM" --version
run_contains "atem token --help"       "rtc"             -- "$ATEM" token --help
run_contains "atem token rtc --help"   "create"          -- "$ATEM" token rtc --help
run_contains "atem token rtm --help"   "create"          -- "$ATEM" token rtm --help
run_contains "atem list --help"        "project"         -- "$ATEM" list --help
run_contains "atem project --help"     "use"             -- "$ATEM" project --help
run_contains "atem config --help"      "show"            -- "$ATEM" config --help
run_contains "atem agent --help"       ""                -- "$ATEM" agent --help
run_contains "atem serv --help"        ""                -- "$ATEM" serv --help
run_contains "atem serv list --help"   ""                -- "$ATEM" serv list --help
run_contains "atem serv diagrams --help" ""              -- "$ATEM" serv diagrams --help
run_contains "atem login --help"       ""                -- "$ATEM" login --help
run_contains "atem logout --help"      ""                -- "$ATEM" logout --help
run_contains "atem pair --help"        "save"            -- "$ATEM" pair --help
run_contains "atem unpair --help"      ""                -- "$ATEM" unpair --help
echo

# ── Config ───────────────────────────────────────────────────────────
echo "$(yellow "Config")"
run_contains "atem config show"        "SSO"             -- "$ATEM" config show
echo

# ── Project ──────────────────────────────────────────────────────────
echo "$(yellow "Project")"
run "atem project show"                                  -- "$ATEM" project show
echo

# ── List (requires SSO login or cache) ───────────────────────────────
echo "$(yellow "List (requires SSO login)")"
if [[ -f "$HOME/.config/atem/credentials.enc" ]]; then
    run "atem list project"                      -- "$ATEM" list project
    run "atem list project --show-certificates"  -- "$ATEM" list project --show-certificates
else
    skip "atem list project"                    "no credentials.enc — run atem login first"
    skip "atem list project --show-certificates" "needs SSO"
fi
echo

# ── Token: RTC create + decode round-trip ───────────────────────────
echo "$(yellow "Token RTC")"
if [[ -n "${AGORA_APP_ID:-}" && -n "${AGORA_APP_CERTIFICATE:-}" ]] || [[ -f "$HOME/.config/atem/project_cache.enc" ]]; then
    run "atem token rtc create"        -- "$ATEM" token rtc create --channel smoketest --rtc-user-id 42 --expire 600

    # Capture a token and decode it
    run "atem token rtc create --role subscriber"          -- "$ATEM" token rtc create --channel smoketest --rtc-user-id 42 --role subscriber --expire 600
    run "atem token rtc create --with-rtm (int uid)"       -- "$ATEM" token rtc create --channel smoketest --rtc-user-id 42 --with-rtm --expire 600
    run "atem token rtc create --with-rtm (string account)"-- "$ATEM" token rtc create --channel smoketest --rtc-user-id alice --with-rtm --expire 600
    run "atem token rtc create --with-rtm --rtm-user-id"   -- "$ATEM" token rtc create --channel smoketest --rtc-user-id 42 --with-rtm --rtm-user-id rtm_bob --expire 600
    # --uid flag was removed — must be rejected
    run "atem token rtc create --uid (rejected)"     2     -- "$ATEM" token rtc create --channel smoketest --uid 42 --expire 600

    # Mode label in output must match auto-detection
    out_int="$("$ATEM" token rtc create --channel smoketest --rtc-user-id 42 --expire 60 2>&1 | grep -E "^  RTC User:")"
    out_str="$("$ATEM" token rtc create --channel smoketest --rtc-user-id alice --expire 60 2>&1 | grep -E "^  RTC User:")"
    # Escape hatch: leading `s/` forces string mode (for all-digit string accounts)
    out_sstr="$("$ATEM" token rtc create --channel smoketest --rtc-user-id s/1232 --expire 60 2>&1 | grep -E "^  RTC User:")"
    printf "  %s ... " "$(dim "atem token rtc create classifies --rtc-user-id correctly")"
    if echo "$out_int"  | grep -q "int uid" \
        && echo "$out_str"  | grep -q "string account" \
        && echo "$out_sstr" | grep -q "string account"; then
        green "PASS"; echo
        PASS=$((PASS + 1))
    else
        red "FAIL"; echo
        echo "    int:     $out_int"
        echo "    string:  $out_str"
        echo "    s/prefix: $out_sstr"
        FAIL=$((FAIL + 1))
        FAILED_NAMES+=("atem token rtc create classification")
    fi

    # Escape-hatch token must differ from bare-digit token even with same digits
    BARE_TOK="$("$ATEM" token rtc create --channel smoketest --rtc-user-id 1232   --expire 600 2>/dev/null | awk '/^00|^[0-9a-f]{10,}/ { print; exit }')"
    SPFX_TOK="$("$ATEM" token rtc create --channel smoketest --rtc-user-id s/1232 --expire 600 2>/dev/null | awk '/^00|^[0-9a-f]{10,}/ { print; exit }')"
    printf "  %s ... " "$(dim "atem token rtc: 1232 vs s/1232 yields different tokens")"
    if [[ -n "$BARE_TOK" && -n "$SPFX_TOK" && "$BARE_TOK" != "$SPFX_TOK" ]]; then
        green "PASS"; echo
        PASS=$((PASS + 1))
    else
        red "FAIL"; echo " (bare=$BARE_TOK /=$SPFX_TOK)"
        FAIL=$((FAIL + 1))
        FAILED_NAMES+=("atem token rtc 1232 vs s/1232")
    fi

    # --rtm-user-id without --with-rtm must be rejected (silent no-op would confuse)
    err_output="$("$ATEM" token rtc create --channel smoketest --rtc-user-id 42 --rtm-user-id alice 2>&1 || true)"
    printf "  %s ... " "$(dim "atem token rtc create --rtm-user-id without --with-rtm rejected")"
    if echo "$err_output" | grep -q "requires --with-rtm"; then
        green "PASS"; echo
        PASS=$((PASS + 1))
    else
        red "FAIL"; echo
        echo "$err_output" | sed 's/^/      /'
        FAIL=$((FAIL + 1))
        FAILED_NAMES+=("--rtm-user-id without --with-rtm")
    fi

    # Decoded RTC+RTM token must show both "RTC User:" and "RTM User:" labels
    COMBO_TOK="$("$ATEM" token rtc create --channel smoketest --rtc-user-id 42 --with-rtm --rtm-user-id alice --expire 600 2>/dev/null | awk '/^00|^[0-9a-f]{10,}/ { print; exit }')"
    if [[ -n "$COMBO_TOK" ]]; then
        decoded="$("$ATEM" token rtc decode "$COMBO_TOK" 2>&1)"
        printf "  %s ... " "$(dim "decoded RTC+RTM token shows RTC User / RTM User / Channel")"
        if echo "$decoded" | grep -q "RTC User  *42" \
            && echo "$decoded" | grep -q "RTM User  *alice" \
            && echo "$decoded" | grep -q "Channel  *smoketest" \
            && echo "$decoded" | grep -q "TOKEN INFO" \
            && echo "$decoded" | grep -q "VALIDITY" \
            && echo "$decoded" | grep -q "SERVICES"; then
            green "PASS"; echo
            PASS=$((PASS + 1))
        else
            red "FAIL"; echo
            echo "$decoded" | sed 's/^/      /'
            FAIL=$((FAIL + 1))
            FAILED_NAMES+=("decoded RTC+RTM labels")
        fi
    else
        skip "decoded RTC+RTM labels" "couldn't extract combined token"
    fi

    # atem token rtm create output should show "RTM User:" label
    rtm_out="$("$ATEM" token rtm create --rtm-user-id smoke_rtm --expire 60 2>&1)"
    printf "  %s ... " "$(dim "atem token rtm create shows RTM User label")"
    if echo "$rtm_out" | grep -q "RTM User: smoke_rtm"; then
        green "PASS"; echo
        PASS=$((PASS + 1))
    else
        red "FAIL"; echo
        echo "$rtm_out" | sed 's/^/      /'
        FAIL=$((FAIL + 1))
        FAILED_NAMES+=("atem token rtm create label")
    fi

    # RTC+RTM round-trip (int uid): decoded token must mention both RTC and RTM services
    RTC_RTM_TOKEN="$("$ATEM" token rtc create --channel smoketest --rtc-user-id 42 --with-rtm --expire 600 2>/dev/null \
        | awk '/^00|^[0-9a-f]{10,}/ { print; exit }')"
    if [[ -n "$RTC_RTM_TOKEN" ]]; then
        DECODED="$("$ATEM" token rtc decode "$RTC_RTM_TOKEN" 2>&1)"
        printf "  %s ... " "$(dim "atem token rtc decode (int+with-rtm) shows both services")"
        if echo "$DECODED" | grep -q "^  RTC (type 1)" && echo "$DECODED" | grep -q "^  RTM (type 2)"; then
            green "PASS"; echo
            PASS=$((PASS + 1))
        else
            red "FAIL"; echo
            echo "$DECODED" | sed 's/^/      /'
            FAIL=$((FAIL + 1))
            FAILED_NAMES+=("atem token rtc decode (int+with-rtm)")
        fi
    else
        skip "atem token rtc decode (int+with-rtm)" "couldn't extract combined token"
    fi

    # RTC+RTM with separate RTM account: both services present, token differs from same-account variant
    SAME_ACCT="$("$ATEM" token rtc create --channel smoketest --rtc-user-id alice --with-rtm --expire 600 2>/dev/null | awk '/^00|^[0-9a-f]{10,}/ { print; exit }')"
    SEP_ACCT="$("$ATEM" token rtc create --channel smoketest --rtc-user-id alice --with-rtm --rtm-user-id bob --expire 600 2>/dev/null | awk '/^00|^[0-9a-f]{10,}/ { print; exit }')"
    printf "  %s ... " "$(dim "atem token rtc --rtm-user-id produces distinct token")"
    if [[ -n "$SAME_ACCT" && -n "$SEP_ACCT" && "$SAME_ACCT" != "$SEP_ACCT" ]]; then
        green "PASS"; echo
        PASS=$((PASS + 1))
    else
        red "FAIL"; echo " (same=$SAME_ACCT sep=$SEP_ACCT)"
        FAIL=$((FAIL + 1))
        FAILED_NAMES+=("atem token rtc --rtm-user-id distinct")
    fi

    RTC_TOKEN="$("$ATEM" token rtc create --channel smoketest --rtc-user-id 42 --expire 600 2>/dev/null \
        | awk '/^00|^[0-9a-f]{10,}/ { print; exit }')"
    if [[ -n "$RTC_TOKEN" ]]; then
        run_contains "atem token rtc decode"                    "SERVICES" -- "$ATEM" token rtc decode "$RTC_TOKEN"
        # Negative: garbage input should fail cleanly
        run "atem token rtc decode (garbage) fails" 1            -- "$ATEM" token rtc decode "not-a-real-token"
    else
        skip "atem token rtc decode"         "couldn't extract token from create output"
        skip "atem token rtc decode garbage" "depends on create"
    fi
else
    skip "atem token rtc create"               "no AGORA_APP_ID / active project"
    skip "atem token rtc create subscriber"    "no AGORA_APP_ID / active project"
    skip "atem token rtc decode"               "depends on create"
    skip "atem token rtc decode garbage"       "depends on create"
fi
echo

# ── Token: RTM create + decode round-trip ───────────────────────────
echo "$(yellow "Token RTM (Signaling)")"
if [[ -n "${AGORA_APP_ID:-}" && -n "${AGORA_APP_CERTIFICATE:-}" ]] || [[ -f "$HOME/.config/atem/project_cache.enc" ]]; then
    run "atem token rtm create"        -- "$ATEM" token rtm create --rtm-user-id smoke_user --expire 600

    RTM_TOKEN="$("$ATEM" token rtm create --rtm-user-id smoke_user --expire 600 2>/dev/null \
        | awk '/^00|^[0-9a-f]{10,}/ { print; exit }')"
    if [[ -n "$RTM_TOKEN" ]]; then
        run_contains "atem token rtm decode"                    "RTM" -- "$ATEM" token rtm decode "$RTM_TOKEN"
        # Negative: garbage input should fail cleanly
        run "atem token rtm decode (garbage) fails" 1            -- "$ATEM" token rtm decode "not-a-real-token"
    else
        skip "atem token rtm decode"         "couldn't extract token from create output"
        skip "atem token rtm decode garbage" "depends on create"
    fi
else
    skip "atem token rtm create"               "no AGORA_APP_ID / active project"
    skip "atem token rtm decode"               "depends on create"
    skip "atem token rtm decode garbage"       "depends on create"
fi
echo

# ── Agent / Serv (should not crash on empty state) ──────────────────
echo "$(yellow "Agent")"
run "atem agent list" -- "$ATEM" agent list
echo

echo "$(yellow "Serv")"
run "atem serv list" -- "$ATEM" serv list
echo

# ── RTC test server (/api/token over TLS) ───────────────────────────
echo "$(yellow "RTC test server (/api/token)")"
RTC_PORT=18443
RTC_PID=""
RTC_LOG="$(mktemp -t atem-rtc.XXXXXX.log)"

# Only attempt if we have credentials (active project or env vars)
if [[ -n "${AGORA_APP_ID:-}" && -n "${AGORA_APP_CERTIFICATE:-}" ]] || [[ -f "$HOME/.config/atem/project_cache.enc" ]]; then
    "$ATEM" serv rtc --channel smoketest --port "$RTC_PORT" >"$RTC_LOG" 2>&1 &
    RTC_PID=$!
    # wait up to 10s for the TLS port to be accepting connections
    for _ in $(seq 1 20); do
        if curl -sk --max-time 1 "https://127.0.0.1:$RTC_PORT/" -o /dev/null 2>/dev/null; then
            break
        fi
        sleep 0.5
    done

    # ── Test 1: 50× POST /api/token, count non-200 responses
    printf "  %s ... " "$(dim "atem serv rtc — 50× /api/token (no 400s)")"
    counts="$(for i in $(seq 1 50); do
        curl -sk --max-time 5 -X POST "https://127.0.0.1:$RTC_PORT/api/token" \
            -H 'Content-Type: application/json' \
            -d '{"channel":"smoketest","uid":"123"}' \
            -o /dev/null -w '%{http_code}\n'
    done | sort | uniq -c)"
    non_200="$(echo "$counts" | grep -v ' 200$' || true)"
    if [[ -z "$non_200" ]]; then
        green "PASS"; echo " (50× 200)"
        PASS=$((PASS + 1))
    else
        red "FAIL"; echo
        echo "$counts" | sed 's/^/      /'
        FAIL=$((FAIL + 1))
        FAILED_NAMES+=("atem serv rtc — 50× /api/token")
    fi

    # ── Test 2: deterministic split-write reproduction
    printf "  %s ... " "$(dim "atem serv rtc — split-write POST returns 200")"
    if command -v python3 >/dev/null 2>&1; then
        out="$(python3 - <<PY 2>&1
import socket, ssl, time, sys
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
try:
    sock = socket.create_connection(("127.0.0.1", $RTC_PORT), timeout=5)
    ssock = ctx.wrap_socket(sock, server_hostname="localhost")
    body = b'{"channel":"smoketest","uid":"123"}'
    headers = (
        f"POST /api/token HTTP/1.1\r\n"
        f"Host: localhost:$RTC_PORT\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n\r\n"
    ).encode()
    ssock.sendall(headers)
    time.sleep(0.5)
    ssock.sendall(body)
    data = b""
    while True:
        chunk = ssock.recv(4096)
        if not chunk: break
        data += chunk
        if len(data) > 65536: break
    print(data.decode(errors='replace').split('\\r\\n')[0])
except Exception as e:
    print(f"ERROR: {e}")
PY
)"
        if echo "$out" | grep -q "200 OK"; then
            green "PASS"; echo " ($out)"
            PASS=$((PASS + 1))
        else
            red "FAIL"; echo " ($out)"
            FAIL=$((FAIL + 1))
            FAILED_NAMES+=("atem serv rtc — split-write POST")
        fi
    else
        yellow "SKIP"; echo " (python3 not available)"
        SKIP=$((SKIP + 1))
    fi

    # cleanup
    if [[ -n "$RTC_PID" ]]; then
        kill "$RTC_PID" 2>/dev/null || true
        wait "$RTC_PID" 2>/dev/null || true
    fi
else
    skip "atem serv rtc — 50× /api/token"        "no AGORA_APP_ID / active project"
    skip "atem serv rtc — split-write POST"      "no AGORA_APP_ID / active project"
fi
rm -f "$RTC_LOG"
echo

# ── Convo test server ───────────────────────────────────────────────
echo "$(yellow "Convo test server")"

# Vendored toolkit must exist and carry a version marker.
run "assets/convo/conversational-ai-api.js exists" -- test -s assets/convo/conversational-ai-api.js
run "assets/convo/VERSION has sha"                 -- bash -c "grep -q '^sha:' assets/convo/VERSION"

if [[ -f tests/fixtures/convo_full.toml ]] && {
    [[ -n "${AGORA_APP_ID:-}" && -n "${AGORA_APP_CERTIFICATE:-}" ]] \
    || [[ -f "$HOME/.config/atem/project_cache.enc" ]]
}; then
    CONVO_PORT=19911
    CONVO_LOG="$(mktemp -t atem-convo.XXXXXX.log)"
    "$ATEM" serv convo --config tests/fixtures/convo_full.toml \
        --port "$CONVO_PORT" --no-browser >"$CONVO_LOG" 2>&1 &
    CONVO_PID=$!
    # Wait up to 10s for TLS port
    for _ in $(seq 1 20); do
        curl -sk --max-time 1 "https://127.0.0.1:$CONVO_PORT/" -o /dev/null 2>/dev/null && break
        sleep 0.5
    done

    run_contains "atem serv convo — GET /" "Welcome to Agora" \
        -- curl -sk "https://127.0.0.1:$CONVO_PORT/"
    run_contains "atem serv convo — GET /vendor/conversational-ai-api.js" "ConversationalAIAPI" \
        -- curl -sk "https://127.0.0.1:$CONVO_PORT/vendor/conversational-ai-api.js"
    run_contains "atem serv convo — POST /api/token" "007" \
        -- bash -c "curl -sk -X POST https://127.0.0.1:$CONVO_PORT/api/token -H 'Content-Type: application/json' -d '{\"channel\":\"demo\",\"uid\":\"42\"}'"
    run_contains "atem serv convo — GET /api/convo/status" "\"running\":false" \
        -- curl -sk "https://127.0.0.1:$CONVO_PORT/api/convo/status"

    # Cleanup
    kill "$CONVO_PID" 2>/dev/null || true
    wait "$CONVO_PID" 2>/dev/null || true
    rm -f "$CONVO_LOG"
elif [[ ! -f tests/fixtures/convo_full.toml ]]; then
    skip "atem serv convo — GET /"                              "no tests/fixtures/convo_full.toml"
    skip "atem serv convo — GET /vendor/conversational-ai-api.js" "no tests/fixtures/convo_full.toml"
    skip "atem serv convo — POST /api/token"                    "no tests/fixtures/convo_full.toml"
    skip "atem serv convo — GET /api/convo/status"              "no tests/fixtures/convo_full.toml"
else
    skip "atem serv convo — GET /"                              "no AGORA_APP_ID / active project"
    skip "atem serv convo — GET /vendor/conversational-ai-api.js" "no AGORA_APP_ID / active project"
    skip "atem serv convo — POST /api/token"                    "no AGORA_APP_ID / active project"
    skip "atem serv convo — GET /api/convo/status"              "no AGORA_APP_ID / active project"
fi
echo

# ── Webhooks server (no tunnel — local end-to-end) ──────────────────
echo "$(yellow "Webhooks server")"
WEBHOOK_PORT=19191
WEBHOOK_LOG="$(mktemp -t atem-webhooks.XXXXXX.log)"
"$ATEM" serv webhooks --port "$WEBHOOK_PORT" --no-tunnel --no-browser >"$WEBHOOK_LOG" 2>&1 &
WEBHOOK_PID=$!
# Wait up to 5s for HTTP listener
for _ in $(seq 1 10); do
    curl -s --max-time 1 "http://127.0.0.1:$WEBHOOK_PORT/" -o /dev/null 2>/dev/null && break
    sleep 0.5
done

run_contains "atem serv webhooks — GET /" "atem serv webhooks" \
    -- curl -s "http://127.0.0.1:$WEBHOOK_PORT/"

run_contains "atem serv webhooks — POST /webhook (unsigned, 200)" '{"ok":true}' \
    -- bash -c "curl -s -X POST http://127.0.0.1:$WEBHOOK_PORT/webhook \
        -H 'Content-Type: application/json' \
        -d '{\"noticeId\":\"smoke-1\",\"productId\":1,\"eventType\":101,\"notifyMs\":1,\"payload\":{\"agent_id\":\"x\"}}'"

# Unknown route should 404
printf "  %s ... " "$(dim "atem serv webhooks — GET /no-such returns 404")"
status=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$WEBHOOK_PORT/no-such")
if [[ "$status" == "404" ]]; then
    green "PASS"; echo
    PASS=$((PASS + 1))
else
    red "FAIL"; echo " (got $status)"
    FAIL=$((FAIL + 1))
    FAILED_NAMES+=("atem serv webhooks — 404 path")
fi

# Each POST should print a one-line summary in the daemon's stdout (we
# captured it via WEBHOOK_LOG). Eyeballing the log catches regressions
# in the broadcast / println path.
printf "  %s ... " "$(dim "atem serv webhooks — POST printed event summary to log")"
sleep 0.2  # let the broadcast task drain
if grep -q '101 agent_joined' "$WEBHOOK_LOG"; then
    green "PASS"; echo
    PASS=$((PASS + 1))
else
    red "FAIL"; echo
    sed 's/^/      /' "$WEBHOOK_LOG"
    FAIL=$((FAIL + 1))
    FAILED_NAMES+=("atem serv webhooks — log line")
fi

kill "$WEBHOOK_PID" 2>/dev/null || true
wait "$WEBHOOK_PID" 2>/dev/null || true
rm -f "$WEBHOOK_LOG"
echo

# ── Interactive / external commands (intentionally skipped) ─────────
echo "$(yellow "Interactive / external (skipped)")"
skip "atem login"    "opens browser — interactive"
skip "atem logout"   "mutates credentials — interactive"
skip "atem pair"     "requires Astation"
skip "atem unpair"   "mutates credentials"
skip "atem repl"     "interactive"
echo

# ── Summary ──────────────────────────────────────────────────────────
TOTAL=$((PASS + FAIL + SKIP))
echo "──────────────────────────────────────────"
echo "Total: $TOTAL  $(green "Pass: $PASS")  $(red "Fail: $FAIL")  $(yellow "Skip: $SKIP")"

if [[ "$FAIL" -gt 0 ]]; then
    echo "Failed:"
    for n in "${FAILED_NAMES[@]}"; do
        echo "  - $n"
    done
    exit 1
fi
exit 0
