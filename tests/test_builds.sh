#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# mTLS Server Build Validation Suite (merged & enhanced)
#
# - Combines previous lightweight and audit-focused scripts
# - Retains PASS / CORRECT-FAIL / FAIL classification
# - Emits per-build JSON for CI/audit and a summary.json
# - Captures compiler command, first GCC error/warning lines and full excerpts
# - Timing per build and policy enforcement reasoning
# - Emits human-friendly console output with TTY-aware colors and icons
# - Exits non-zero on any UNEXPECTED failure (FAIL)
# -----------------------------------------------------------------------------

set -euo pipefail

BUILD_LOG_DIR="build_logs"
JSON_DIR="$BUILD_LOG_DIR/json"
CERT_DIR="certs"
mkdir -p "$BUILD_LOG_DIR" "$JSON_DIR" "$CERT_DIR"

timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

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
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    printf '%s' "$s"
}

# -----------------------------------------------------------------------------
# Cert Generation (only when needed)
# -----------------------------------------------------------------------------
gen_test_certs() {
    if [[ ! -f "$CERT_DIR/server-key.pem" || ! -f "$CERT_DIR/server-cert.pem" || \
          ! -f "$CERT_DIR/ca-cert.pem" || ! -f "$CERT_DIR/ca-crl.pem" ]]; then
        echo "[CERT] Generating temporary certs..."
        if [ -x "scripts/gen_test_certs.sh" ]; then
            scripts/gen_test_certs.sh
        else
            echo "[CERT] Warning: scripts/gen_test_certs.sh not found or not executable"
        fi
    fi
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
    local log_error_excerpt="$7"
    local log_warn_excerpt="$8"
    local duration="$9"

    local skip_security="0"
    if echo "$gcc_cmd $cmd" | grep -q "SKIP_SECURITY=1"; then
        skip_security="1"
    fi

    local host tls_port rev_level rev_desc
    host=$(echo "$gcc_cmd" | sed -n 's/.*-D__ALLOWED_HOST__=\\"\\(.*\\)\\".*/\1/p' || true)
    tls_port=$(echo "$gcc_cmd" | sed -n 's/.*-D__TLS_PORT__=\([0-9]*\).*/\1/p' || true)
    rev_level=$(echo "$gcc_cmd" | sed -n 's/.*-D__REVOCATION_LEVEL__=\([0-9]*\).*/\1/p' || true)

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
    "error_excerpt": "$(json_escape "$log_error_excerpt")",
    "warn_excerpt": "$(json_escape "$log_warn_excerpt")"
  },
  "gcc_command": "$(json_escape "$gcc_cmd")",
  "log_file": "$(json_escape "$log")",
  "duration_seconds": "$(json_escape "$duration")",
  "timestamp": "$(json_escape "$timestamp")"
}
EOF
}

# -----------------------------------------------------------------------------
# Policy classification helper
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
# Core test runner — captures GCC invocation, errors/warnings and classifies result
# -----------------------------------------------------------------------------
run_case() {
    local name="$1"
    local cmd="$2"
    local log="$BUILD_LOG_DIR/${name}.log"
    local start end duration

    echo "===== Test: $name → $cmd ====="

    make clean >/dev/null 2>&1 || true

    # Hardened tests → require certs first
    if echo "$cmd" | grep -qv "PROD=0" || echo "$cmd" | grep -q "BENCH=1"; then
        gen_test_certs
    fi

    start=$(date +%s)
    if bash -c "$cmd -B" &> "$log"; then
        result="PASS"
        PASS_COUNT=$((PASS_COUNT+1))
        echo -e "${GREEN}${PASS_ICON} [PASS] – Build succeeded${RESET}"
    else
        result="FAIL"
    fi
    end=$(date +%s)
    duration=$((end - start))

    # Extract GCC command line (last non-compile invocation is useful)
    gcc_cmd=$(grep -E '\bgcc(-[0-9]+)?\b' "$log" | tail -n 1 || true)

    # Extract error and warning excerpts (first few lines)
    log_error_excerpt=$(grep -iE "\berror:|undefined reference|fatal error" "$log" || true)
    log_warn_excerpt=$(grep -iE "\bwarning:" "$log" || true)

    # Reduce excerpts to at most first 5 lines each for JSON brevity
    log_error_excerpt=$(printf "%s" "$log_error_excerpt" | head -n 5 | tr '\n' ' ; ' | sed 's/; $//')
    log_warn_excerpt=$(printf "%s" "$log_warn_excerpt" | head -n 5 | tr '\n' ' ; ' | sed 's/; $//')

    # Classification of CORRECT-FAIL (policy enforcement) vs unexpected FAIL
    if [ "$result" = "FAIL" ]; then
        if grep -qiE "(Invalid( certificate)?|verify.*failed|certificate.*(revoked|expired|unknown)|Missing required certificate)" "$log"; then
            result="CORRECT-FAIL"
            CORRECT_FAIL_COUNT=$((CORRECT_FAIL_COUNT+1))
            echo -e "${YELLOW}[CORRECT-FAIL]${RESET} ${POLICY_ICON} Enforcement Triggered"

            reason=$(grep -iE "Invalid( certificate)?|verify.*failed|certificate.*(revoked|expired|unknown)|Missing required certificate" "$log" | head -n1)
            if [ -n "$reason" ]; then
                echo -e "${FAIL_COLOR}Reason: ${reason}${RESET}"
            else
                echo -e "${FAIL_COLOR}Reason: Policy enforcement triggered (see log for details)${RESET}"
            fi

            echo "Policy Category: $(detect_policy_category "$cmd $gcc_cmd")"
            echo "---- Policy Enforcement Verified ----"
        else
            FAIL_COUNT=$((FAIL_COUNT+1))
            echo -e "${FAIL_COLOR}${FAIL_ICON} [FAIL] – Unexpected build failure${RESET}"
            echo "--- Compiler/Build Output (first 200 lines) ---"
            head -n 200 "$log" || true
            echo "--- Relevant GCC invocation (last) ---"
            echo "$gcc_cmd"

            if [ -n "$log_error_excerpt" ]; then
                echo "--- Extracted errors ---"
                echo "$log_error_excerpt"
            fi
            if [ -n "$log_warn_excerpt" ]; then
                echo "--- Extracted warnings ---"
                echo "$log_warn_excerpt"
            fi

            echo "----------------------------"
        fi
    fi

    # If build failed before compilation, warn user
    if [ "$result" = "FAIL" ] && [ -z "$gcc_cmd" ]; then
        echo -e "${YELLOW}Warning:${RESET} No GCC invocation detected (build may have failed before compilation)."
    fi

    # infer mode from gcc_cmd or presence of flags in command
    mode="PROD"
    if echo "$cmd $gcc_cmd" | grep -q "PROD=0"; then mode="DEV"; fi
    if echo "$cmd $gcc_cmd" | grep -q "BENCH=1"; then mode="BENCH"; fi

    # Logging macro detection (heuristic from -D defines present in gcc_cmd)
    log_error_bit="0"; log_warn_bit="0"; log_info_bit="0"; log_debug_bit="0"
    if echo "$gcc_cmd" | grep -q "__LOG_ENABLE_ERROR__"; then log_error_bit="1"; fi
    if echo "$gcc_cmd" | grep -q "__LOG_ENABLE_WARN__";  then log_warn_bit="1"; fi
    if echo "$gcc_cmd" | grep -q "__LOG_ENABLE_INFO__";  then log_info_bit="1"; fi
    if echo "$gcc_cmd" | grep -q "__LOG_ENABLE_DEBUG__"; then log_debug_bit="1"; fi

    echo "---- Build Configuration ----"
    echo -e "${BLUE}Mode:${RESET} $mode"
    echo -e "${BLUE}Logging:${RESET} ERROR=$log_error_bit WARN=$log_warn_bit INFO=$log_info_bit DEBUG=$log_debug_bit"
    echo "----------------------------"

    write_json_report "$name" "$cmd" "$result" "$log" "$gcc_cmd" "$mode" "$log_error_excerpt" "$log_warn_excerpt" "$duration"

    echo
}

# -----------------------------------------------------------------------------
# Test list (customize as needed)
# -----------------------------------------------------------------------------
# Allowed builds (expected to PASS)
run_case "prod_default" "make"
run_case "dev_default" "make PROD=0"
run_case "dev_nomtls" "make PROD=0 mTLS=0"
run_case "dev_debug" "make PROD=0 DEBUG=1"
run_case "bench_default" "make BENCH=1"
run_case "dev_san" "make PROD=0 SAN=1"
run_case "dev_specific_SL" "make PROD=0 SL=1"

# Blocked builds (expected CORRECT-FAIL)
run_case "prod_nomtls_block" "make mTLS=0"
run_case "prod_debug_block" "make DEBUG=1"
run_case "bench_debug_block" "make BENCH=1 DEBUG=1"
run_case "prod_SL1_block" "make SL=1"
run_case "hardened_SL3_block" "make SL=3"

# Additional audit / override checks
run_case "skip_rev0" "SKIP_SECURITY=1 make REVOCATION=0"
run_case "skip_debug" "SKIP_SECURITY=1 make DEBUG=1"
run_case "skip_nomtls" "SKIP_SECURITY=1 make mTLS=0"

# -----------------------------------------------------------------------------
# Summary JSON aggregation
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
        ' "$JSON_DIR"/*.json > "$SUMMARY_FILE" || echo '{"error": "Summary generation failed"}' > "$SUMMARY_FILE"
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
# Override audit check (scan logs for SKIP_SECURITY uses)
# -----------------------------------------------------------------------------
OVERRIDE_COUNT=$(grep -R --line-number "SKIP_SECURITY=1" "$BUILD_LOG_DIR" 2>/dev/null | wc -l | tr -d ' ' || true)
if [ -n "$OVERRIDE_COUNT" ] && [ "$OVERRIDE_COUNT" -gt 0 ]; then
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
    echo -e "Audit Compliance:      ${FAIL_COLOR}NON-COMPLIANT ✘${RESET}"
fi
echo "============================================================"
echo "Logs:  $BUILD_LOG_DIR/"
echo "JSON:  $JSON_DIR/"
echo "============================================================"

n# Exit non-zero if any unexpected failures found (FAIL_COUNT)
if [ "$FAIL_COUNT" -gt 0 ]; then
    exit 1
else
    exit 0
fi
