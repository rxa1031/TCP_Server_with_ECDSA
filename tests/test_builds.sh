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
#  - Compliance summary at end
# -----------------------------------------------------------------------------

set -o pipefail

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
  # High-contrast FAIL: red foreground on white background
  FAIL_COLOR="\033[31m\033[47m"
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

# -----------------------------------------------------------------------------
# JSON Writer — used for all PASS + CORRECT-FAIL cases
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

    # Revocation description (aligned to DefStan views)
    case "$rev_level" in
        0) rev_desc="0 — Revocation disabled (DEV/override only)" ;;
        1) rev_desc="1 — CRL required (Hardened configuration requirement)" ;;
        2) rev_desc="2 — CRL + OCSP required (Highest security assurance)" ;;
        *) rev_desc="Unset — Makefile failed to specify a policy level" ;;
    esac

    local json_file="$JSON_DIR/${name}.json"
    cat > "$json_file" <<EOF
{
  "name": "$name",
  "command": "$cmd",
  "status": "$status",
  "mode": "$mode",
  "skip_security": "$skip_security",
  "host": "$host",
  "tls_port": "$tls_port",
  "revocation_level": "$rev_level",
  "revocation_description": "$rev_desc",
  "logging": {
    "error": "$log_error",
    "warn": "$log_warn",
    "info": "$log_info",
    "debug": "$log_debug"
  },
  "gcc_command": "$gcc_cmd",
  "log_file": "$log",
  "timestamp": "$timestamp"
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
# Build Counters
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

    if bash -c "$cmd" &> "$log"; then
        result="PASS"
        PASS_COUNT=$((PASS_COUNT+1))
        echo -e "${GREEN}${PASS_ICON} [PASS] – Build succeeded${RESET}"
    else
        # Blocked or unexpected fail
        if grep -qiE "(Invalid:|Missing required certificate)" "$log"; then
            result="CORRECT-FAIL"
            CORRECT_FAIL_COUNT=$((CORRECT_FAIL_COUNT+1))
            echo -e "${YELLOW}[CORRECT-FAIL]${RESET} ${POLICY_ICON} Enforcement Triggered"
            # Provide a reason for both Invalid: and Missing required certificate
            if grep -qi "Invalid:" "$log"; then
                echo "Reason: $(grep 'Invalid:' "$log" | sed 's/.*Invalid: //')"
            elif grep -qi "Missing required certificate" "$log"; then
                echo "Reason: $(grep -i 'Missing required certificate' "$log" | head -1)"
            else
                echo "Reason: Policy enforcement triggered (see log for details)"
            fi
            echo "Policy Category: $(detect_policy_category "$cmd")"
            echo "---- Policy Enforcement Verified ----"
        else
            result="FAIL"
            FAIL_COUNT=$((FAIL_COUNT+1))
            # High-contrast FAIL here
            echo -e "${FAIL_COLOR}${FAIL_ICON} [FAIL] – Unexpected build failure${RESET}"
            echo "--- Compiler/Build Output ---"
            cat "$log"
            echo "----------------------------"
        fi
    fi

    local gcc_cmd
    gcc_cmd=$(grep -oE '(^| )gcc(-[0-9]+)? [^"]*' "$log" | tail -1 || true)

    # Optional visibility if we never reached the compile phase
    if [ -z "$gcc_cmd" ]; then
        echo -e "${YELLOW}Warning:${RESET} No GCC command found in log (build may have failed before compilation)."
    fi

    # default is PROD
    local mode="PROD"
    if [[ "$gcc_cmd" =~ -D__DEV__ ]]; then
        mode="DEV"
    elif [[ "$gcc_cmd" =~ -D__BENCH__ ]]; then
        mode="BENCH"
    fi

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
        "$log_error" "$log_warn" "$log_info" "$log_debug"

    echo
}

# -----------------------------------------------------------------------------
# Execute Test Matrix
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
test_case "invalid_host_prod"    "make HOST=evil.com"
test_case "invalid_host_bench"   "make BENCH=1 HOST=evil.com"

echo "----- Testing Blocked Builds -----"
test_case "rev0"                 "make REVOCATION=0"
test_case "debug_prod"           "make DEBUG=1"
test_case "bench_rev0"           "make BENCH=1 REVOCATION=0"
test_case "mtls0_prod"           "make mTLS=0"
test_case "bench_debug_block"    "make BENCH=1 DEBUG=1"

echo "----- Testing Override Builds (SKIP_SECURITY=1) -----"
test_case "skip_rev0"            "SKIP_SECURITY=1 make REVOCATION=0"
test_case "skip_debug"           "SKIP_SECURITY=1 make DEBUG=1"
test_case "skip_bench_rev0"      "SKIP_SECURITY=1 make BENCH=1 REVOCATION=0"
test_case "skip_nomtls"          "SKIP_SECURITY=1 make mTLS=0"

# -----------------------------------------------------------------------------
# Compliance Summary
# -----------------------------------------------------------------------------
echo "================= Build Compliance Summary ================="
echo "Allowed builds:        $PASS_COUNT PASS / $FAIL_COUNT FAIL"
echo "Blocked builds:        $CORRECT_FAIL_COUNT CORRECT-FAIL"
if [ $FAIL_COUNT -eq 0 ]; then
    echo -e "Audit Compliance:      ${GREEN}FULLY COMPLIANT ✔${RESET}"
else
    # Also high-contrast for NON-COMPLIANT summary
    echo -e "Audit Compliance:      ${FAIL_COLOR}NON-COMPLIANT ✘${RESET}"
fi
echo "============================================================"
echo "Logs:  $BUILD_LOG_DIR/"
echo "JSON:  $JSON_DIR/"
echo "============================================================"
