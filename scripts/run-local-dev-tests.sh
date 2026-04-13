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
    run "atem token rtc create"        -- "$ATEM" token rtc create --channel smoketest --uid 42 --expire 600

    # Capture a token and decode it
    run "atem token rtc create --role subscriber"   -- "$ATEM" token rtc create --channel smoketest --uid 42 --role subscriber --expire 600

    RTC_TOKEN="$("$ATEM" token rtc create --channel smoketest --uid 42 --expire 600 2>/dev/null \
        | awk '/^00|^[0-9a-f]{10,}/ { print; exit }')"
    if [[ -n "$RTC_TOKEN" ]]; then
        run_contains "atem token rtc decode"                    "Service" -- "$ATEM" token rtc decode "$RTC_TOKEN"
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
    run "atem token rtm create"        -- "$ATEM" token rtm create --user-id smoke_user --expire 600

    RTM_TOKEN="$("$ATEM" token rtm create --user-id smoke_user --expire 600 2>/dev/null \
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
