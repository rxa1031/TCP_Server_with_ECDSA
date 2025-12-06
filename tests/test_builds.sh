#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# mTLS Server Build Validation Suite
# Defence-aligned audit & enforcement visibility
#
# Features:
#  - Tests allowed / blocked / override builds
#  - Distinguishes PASS, FAIL and CORRECT-FAIL
#  - Mode + Logging flags reported per build
#  - UTF-8 icon auto-detect (ASCII fallback)
#  - JSON log generation for CI/audit
#  - Timing per build (duration_seconds)
#  - Summary JSON aggregation (summary.json)
#  - Override audit for SKIP_SECURITY=1
#  - Compliance summary at end
# -----------------------------------------------------------------------------

set -o pipefail
set -u  # fail on use of unset variables

BUILD_LOG_DIR="build_logs"
JSON_DIR="$BUILD_LOG_DIR/json"
mkdir -p "$BUILD_LOG_DIR" "$JSON_DIR"

timestamp=$(date)

# -----------------------------------------------------------------------------
# UTF-8 Environment Detection (emojis on/off)
# -----------------------------------------------------------------------------
if locale | grep -qi "utf-8"; then
    PASS_ICON="✔"
    FAIL_ICON="✘"
    POLICY_ICON="🛡️"
else
    PASS_ICON="[PASS]"
    FAIL_ICON="[FAIL]"
    POLICY_ICON="[POLICY]"
fi

# -----------------------------------------------------------------------------
# ANSI Colors (TTY-aware)
# -----------------------------------------------------------------------------
if [ -t 1 ]; then
  GREEN="\033[32m"
  RED="\033[31m"
  YELLOW="\033[33m"
  BLUE="\033[34m"
  # High-contrast FAIL: bold red foreground on white background (accessibility)
  FAIL_COLOR="\033[1;31m\033[47m"
  RESET="\033[0m"
else
  GREEN=""
  RED=""
  YELLOW=""
  BLUE=""
  FAIL_COLOR=""
  RESET=""
fi

echo "============================================"
echo "  Build Validation — $timestamp"
echo "============================================"
echo

json_escape() {
    local s=$1
    s=${s//\\/\\\\}   # escape backslash
    s=${s//\"/\\\"}   # escape double quote
    s=${s//$'\n'/\\n} # escape newline
    s=${s//$'\r'/\\r} # escape carriage return
    s=${s//$'\t'/\\t} # escape tab
    printf '%s' "$s"
}

# -----------------------------------------------------------------------------
# JSON Writer — used for all test results (PASS / FAIL / CORRECT-FAIL)
# -----------------------------------------------------------------------------
write_json_report() {
    local name="$1"
    local cmd="$2"
    local status="$3"
    local log="$4"
    local gcc_cmd="$5"
    local mode="$6"
    local log_error="$7"
    local log_warn="$8"
    local log_info="$9"
    local log_debug="${10}"
    local duration="${11}"

    # SKIP_SECURITY override detection
    local skip_security="0"
    # SKIP_SECURITY override detection: Make cmd + GCC defines
    if echo "$gcc_cmd $cmd" | grep -q "SKIP_SECURITY=1"; then
        skip_security="1"
    fi

    # Extract basic configuration from GCC command
    local host tls_port rev_level rev_desc
    host=$(echo "$gcc_cmd" | sed -n 's/.*-D__ALLOWED_HOST__=\\"\(.*\)\\".*/\1/p')
    tls_port=$(echo "$gcc_cmd" | sed -n 's/.*-D__TLS_PORT__=\([0-9]*\).*/\1/p')
    rev_level=$(echo "$gcc_cmd" | sed -n 's/.*-D__REVOCATION_LEVEL__=\([0-9]*\).*/\1/p')

    [ -z "$host" ] && host="__UNSET__"
    [ -z "$tls_port" ] && tls_port="__UNSET__"
    [ -z "$rev_level" ] && rev_level="__UNSET__"

    case "$rev_level" in
        0) rev_desc="0 — Revocation disabled (DEV/override only)" ;;
        1) rev_desc="1 — CRL required (Hardened configuration requirement)" ;;
        2) rev_desc="2 — CRL + OCSP required (Highest security assurance)" ;;
        *) rev_desc="Unset — Makefile failed to specify a policy level" ;;
    esac

    local json_file="$JSON_DIR/${name}.json"
    cat > "$json_file" <<EOF
{
  "name": "$(json_escape "$name")",
  "command": "$(json_escape "$cmd")",
  "status": "$(json_escape "$status")",
  "mode": "$(json_escape "$mode")",
  "skip_security": "$(json_escape "$skip_security")",
  "host": "$(json_escape "$host")",
  "tls_port": "$(json_escape "$tls_port")",
  "revocation_level": "$(json_escape "$rev_level")",
  "revocation_description": "$(json_escape "$rev_desc")",
  "logging": {
    "error": "$(json_escape "$log_error")",
    "warn": "$(json_escape "$log_warn")",
    "info": "$(json_escape "$log_info")",
    "debug": "$(json_escape "$log_debug")"
  },
  "gcc_command": "$(json_escape "$gcc_cmd")",
  "log_file": "$(json_escape "$log")",
  "duration_seconds": "$(json_escape "$duration")",
  "timestamp": "$(json_escape "$timestamp")"
}
EOF
}

# -----------------------------------------------------------------------------
# Security Policy Detail Helper
# -----------------------------------------------------------------------------
detect_policy_category() {
    local src="$1"
    if echo "$src" | grep -qE "mTLS=0|-U__REQUIRE_MUTUAL_TLS__"; then
        echo "Mutual TLS Client Certificate Enforcement"
    elif echo "$src" | grep -qE "REVOCATION=0|-D__REVOCATION_LEVEL__=0"; then
        echo "Certificate Revocation Policy Enforcement"
    elif echo "$src" | grep -qE "DEBUG=1|__LOG_ENABLE_DEBUG__"; then
        echo "Secure Logging Policy (PROD debug restricted)"
    else
        echo "Security Configuration Enforcement"
    fi
}

# -----------------------------------------------------------------------------
# Counters
# -----------------------------------------------------------------------------
PASS_COUNT=0
FAIL_COUNT=0
CORRECT_FAIL_COUNT=0

# -----------------------------------------------------------------------------
# Core Test Handler
# -----------------------------------------------------------------------------
test_case() {
    local name="$1"
    local cmd="$2"
    local log="$BUILD_LOG_DIR/build_${name}.log"
    local result="FAIL"

    echo ">> Testing: $cmd"
    make clean >/dev/null 2>&1

    # Timing start
    local start_time end_time duration
    start_time=$(date +%s)

    # Execute build
    if bash -c "$cmd -B" &> "$log"; then
        result="PASS"
        PASS_COUNT=$((PASS_COUNT+1))
        echo -e "${GREEN}${PASS_ICON} [PASS] – Build succeeded${RESET}"
    else
        result="FAIL"
    fi

    # Timing end
    end_time=$(date +%s)
    duration=$(( end_time - start_time ))

    local gcc_cmd=""
    gcc_cmd=$(
        grep -E '\bgcc(-[0-9]+)?\b' "$log" \
        | grep -v " -c " \
        | tail -1 || true
    )

    # CORRECT-FAIL classification AFTER gcc_cmd exists
    if [ "$result" = "FAIL" ]; then
        if grep -qiE "(Invalid( certificate)?|verify.*failed|certificate.*(revoked|expired|unknown)|Missing required certificate)" "$log"; then
            result="CORRECT-FAIL"
            CORRECT_FAIL_COUNT=$((CORRECT_FAIL_COUNT+1))

            echo -e "${YELLOW}[CORRECT-FAIL]${RESET} ${POLICY_ICON} Enforcement Triggered"

            local reason
            reason=$(
                grep -iE "Invalid( certificate)?|verify.*failed|certificate.*(revoked|expired|unknown)|Missing required certificate" "$log" \
                | head -1 \
                | sed 's/.*Invalid: //; s/Stop\.$//'
            )

            if [ -n "$reason" ]; then
                echo -e "${FAIL_COLOR}Reason: ${reason}${RESET}"
            else
                echo -e "${FAIL_COLOR}Reason: Policy enforcement triggered (see log for details)${RESET}"
            fi

            echo "Policy Category: $(detect_policy_category "$cmd $gcc_cmd")"
            echo "---- Policy Enforcement Verified ----"

        else
            FAIL_COUNT=$((FAIL_COUNT+1))
            # High-contrast FAIL here (bold red on white)
            echo -e "${FAIL_COLOR}${FAIL_ICON} [FAIL] – Unexpected build failure${RESET}"
            echo "--- Compiler/Build Output ---"
            cat "$log"
            echo "----------------------------"
        fi
    fi

    # Optional visibility if we never reached the compile phase in an unexpected failure
    if [ "$result" = "FAIL" ] && [ -z "$gcc_cmd" ]; then
        echo -e "${YELLOW}Warning:${RESET} No GCC invocation detected (build may have failed before compilation)."
    fi

    # default is PROD
    local mode="PROD"
    [[ "$gcc_cmd" =~ -D__DEV__ ]] && mode="DEV"
    [[ "$gcc_cmd" =~ -D__BENCH__ ]] && mode="BENCH"

    # Logging macro detection
    local log_error="0" log_warn="0" log_info="0" log_debug="0"
    [[ "$gcc_cmd" =~ __LOG_ENABLE_ERROR__ ]] && log_error="1"
    [[ "$gcc_cmd" =~ __LOG_ENABLE_WARN__  ]] && log_warn="1"
    [[ "$gcc_cmd" =~ __LOG_ENABLE_INFO__  ]] && log_info="1"
    [[ "$gcc_cmd" =~ __LOG_ENABLE_DEBUG__ ]] && log_debug="1"

    # Summarize build mode & logging bits
    echo "---- Build Configuration ----"
    echo -e "${BLUE}Mode:${RESET} $mode"
    echo -e "${BLUE}Logging:${RESET} ERROR=$log_error WARN=$log_warn INFO=$log_info DEBUG=$log_debug"
    echo "----------------------------"

    write_json_report \
        "$name" "$cmd" "$result" "$log" "$gcc_cmd" "$mode" \
        "$log_error" "$log_warn" "$log_info" "$log_debug" \
        "$duration"

    echo
}

# -----------------------------------------------------------------------------
# Test Groups
# -----------------------------------------------------------------------------
echo "----- Testing Allowed Builds -----"
test_case "prod_default"         "make"
test_case "dev_default"          "make PROD=0"
test_case "dev_nomtls"           "make PROD=0 mTLS=0"
test_case "dev_info"             "make PROD=0 INFO=1"
test_case "dev_warn"             "make PROD=0 WARN=1"
test_case "dev_debug"            "make PROD=0 DEBUG=1"
test_case "bench_rev1"           "make BENCH=1 REVOCATION=1"
test_case "bench_warn_rev1"      "make BENCH=1 WARN=1 REVOCATION=1"
test_case "dev_san_failfast"     "make PROD=0 SANITIZER_FAIL_FAST=1"
test_case "prod_info"            "make INFO=1"
test_case "dev_rev2"             "make PROD=0 REVOCATION=2"

echo "----- Testing Blocked Builds (Security Policy Enforcement) -----"
test_case "rev0"                 "make REVOCATION=0"
test_case "debug_prod"           "make DEBUG=1"
test_case "bench_rev0"           "make BENCH=1 REVOCATION=0"
test_case "mtls0_prod"           "make mTLS=0"
test_case "bench_debug_block"    "make BENCH=1 DEBUG=1"
test_case "invalid_host_prod"    "make HOST=evil.com"
test_case "invalid_host_bench"   "make BENCH=1 HOST=evil.com"

echo "----- Testing Override Builds (SKIP_SECURITY=1) -----"
echo "NOTE: SKIP_SECURITY=1 is for CI/test only, TLS still ON. DO NOT ship artifacts built with this override."
test_case "skip_rev0"            "SKIP_SECURITY=1 make REVOCATION=0"
test_case "skip_debug"           "SKIP_SECURITY=1 make DEBUG=1"
test_case "skip_bench_rev0"      "SKIP_SECURITY=1 make BENCH=1 REVOCATION=0"
test_case "skip_nomtls"          "SKIP_SECURITY=1 make mTLS=0"

# -----------------------------------------------------------------------------
# Summary JSON
# -----------------------------------------------------------------------------
SUMMARY_FILE="$JSON_DIR/summary.json"
rm -f "$SUMMARY_FILE"

if command -v jq >/dev/null 2>&1; then
    if ls "$JSON_DIR"/*.json >/dev/null 2>&1; then
        jq -s --arg ts "$timestamp" '
          {
            timestamp: $ts,
            totals: {
              success:    (map(select(.status == "PASS")) | length),
              blocked:    (map(select(.status == "CORRECT-FAIL")) | length),
              unexpected: (map(select(.status == "FAIL")) | length)
            },
            builds: .
          }
        ' "$JSON_DIR"/*.json > "$SUMMARY_FILE" \
        || echo '{"error": "Summary generation failed"}' > "$SUMMARY_FILE"
        echo "Summary JSON generated: $SUMMARY_FILE"
    else
        echo "No per-build JSON files found; summary.json not generated."
    fi
else
    echo "jq not found; generating minimal summary.json without per-build entries."
    cat > "$SUMMARY_FILE" <<EOF
{
  "timestamp": "$(json_escape "$timestamp")",
  "totals": {
    "success": $PASS_COUNT,
    "blocked": $CORRECT_FAIL_COUNT,
    "unexpected": $FAIL_COUNT
  },
  "note": "Generated without jq; per-build details omitted."
}
EOF
    echo "Minimal summary JSON generated: $SUMMARY_FILE"
fi

# -----------------------------------------------------------------------------
# Override Audit Check
# -----------------------------------------------------------------------------
OVERRIDE_COUNT=$(grep -R "SKIP_SECURITY=1" "$BUILD_LOG_DIR" 2>/dev/null | wc -l | tr -d ' ')
if [ "$OVERRIDE_COUNT" -gt 0 ]; then
    echo -e "${YELLOW}Override audit:${RESET} SKIP_SECURITY=1 was used in one or more builds."
    echo "  This override is for CI/test only; ensure no artifacts built with it are shipped."
fi

# -----------------------------------------------------------------------------
# Compliance Summary
# -----------------------------------------------------------------------------
echo "================= Build Compliance Summary ================="
echo "Successful builds:     $PASS_COUNT"
echo "Policy-blocked builds: $CORRECT_FAIL_COUNT (CORRECT-FAIL)"
echo "Unexpected failures:   $FAIL_COUNT"
if [ "$FAIL_COUNT" -eq 0 ]; then
    echo -e "Audit Compliance:      ${GREEN}FULLY COMPLIANT ✔${RESET}"
else
    # Also high-contrast for NON-COMPLIANT summary
    echo -e "Audit Compliance:      ${FAIL_COLOR}NON-COMPLIANT ✘${RESET}"
fi
echo "============================================================"
echo "Logs:  $BUILD_LOG_DIR/"
echo "JSON:  $JSON_DIR/"
echo "============================================================"
