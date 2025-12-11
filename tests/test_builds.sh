#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------
# COLORS (match Makefile)
# ---------------------------------------------------------
Y="\033[33m"        # WARN / Correct-Fail
G="\033[32m"        # PASS (green)
C="\033[36m"        # INFO (cyan)
R="\033[97;41m"     # FAIL (white text on red background)
RS="\033[0m"        # Reset

LOG_DIR="logs"
mkdir -p "$LOG_DIR"

echo ""
echo "====================================================="
echo "                BEGIN FULL BUILD MATRIX"
echo "====================================================="
echo ""

# ---------------------------------------------------------
# Run a single case
# ---------------------------------------------------------
run_case() {
    local label="$1"
    shift
    local cmd="$*"
    local logfile="${LOG_DIR}/${label}.log"

    echo -e "${C}=== Running: ${label} ===${RS}"
    echo "Command: $cmd"

    # Run build
    if $cmd >"$logfile" 2>&1; then
        echo -e "${G}PASS: ${label}${RS}"
        PASSED=$((PASSED + 1))
        echo ""
        return
    fi

    # -------------------------------
    # Classification rules
    # -------------------------------
    local mode sl info warn debug
    mode=$(echo "$label" | awk -F'_' '{print $1}')
    sl=$(echo "$label"   | sed -n 's/.*_SL\([0-9]\+\).*/\1/p')
    info=$(echo "$label" | sed -n 's/.*_I\([01]\).*/\1/p')
    warn=$(echo "$label" | sed -n 's/.*_W\([01]\).*/\1/p')
    debug=$(echo "$label" | sed -n 's/.*_D\([01]\).*/\1/p')

    # DEV SL=3 → Correct-Fail (OCSP not implemented)
    if [[ "$mode" == DEV && "$sl" -eq 3 ]]; then
        echo -e "${Y}CORRECT-FAIL: ${label}${RS}"
        POLICY_FAIL=$((POLICY_FAIL + 1))
        echo ""
        return
    fi

    # PROD / BENCH only allow SL=2
    if [[ "$mode" == PROD || "$mode" == BENCH ]]; then
        if [[ "$sl" -ne 2 ]]; then
            echo -e "${Y}CORRECT-FAIL: ${label}${RS}"
            POLICY_FAIL=$((POLICY_FAIL + 1))
            echo ""
            return
        fi
    fi

    # PROD → forbid WARN/INFO/DEBUG flags
    if [[ "$mode" == PROD ]]; then
        if [[ "$warn" -eq 1 || "$info" -eq 1 || "$debug" -eq 1 ]]; then
            echo -e "${Y}CORRECT-FAIL: ${label}${RS}"
            POLICY_FAIL=$((POLICY_FAIL + 1))
            echo ""
            return
        fi
    fi

    # BENCH → forbid DEBUG
    if [[ "$mode" == BENCH ]]; then
        if [[ "$debug" -eq 1 ]]; then
            echo -e "${Y}CORRECT-FAIL: ${label}${RS}"
            POLICY_FAIL=$((POLICY_FAIL + 1))
            echo ""
            return
        fi
    fi

    # Unexpected failure
    echo -e "${R}FAIL: ${label}${RS}"
    echo "---- First 20 error lines ----"
    sed -n '1,20p' "$logfile"
    echo "------------------------------"
    echo ""
    UNEXPECTED_FAIL=$((UNEXPECTED_FAIL + 1))
}

# ---------------------------------------------------------
# Certificate generation
# ---------------------------------------------------------
gen_certs() {
    local mode="$1"
    echo ""
    echo "====================================================="
    echo " Generating certificates for MODE = $mode"
    echo "====================================================="
    ./certs/generate_tls_certificates.sh "$mode"
}

# ---------------------------------------------------------
# Build matrices
# ---------------------------------------------------------
run_matrix() {
    local mode="$1"
    local mode_flag="$2"

    gen_certs "$mode"

    for sl in 1 2 3; do
        for info in 0 1; do
            for warn in 0 1; do
                for debug in 0 1; do

                    local label="${mode}_SL${sl}_I${info}_W${warn}_D${debug}"

                    local cmd=""
                    case "$mode_flag" in
                        DEV)   cmd="make PROD=0 SL=$sl INFO=$info WARN=$warn DEBUG=$debug" ;;
                        PROD)  cmd="make PROD=1 SL=$sl INFO=$info WARN=$warn DEBUG=$debug" ;;
                        BENCH) cmd="make BENCH=1 SL=$sl INFO=$info WARN=$warn DEBUG=$debug" ;;
                    esac

                    make clean >/dev/null 2>&1 || true
                    run_case "$label" "$cmd"

                done
            done
        done
    done
}

# ---------------------------------------------------------
# Counters
# ---------------------------------------------------------
PASSED=0
POLICY_FAIL=0
UNEXPECTED_FAIL=0

# ---------------------------------------------------------
# Execute
# ---------------------------------------------------------
run_matrix DEV  DEV
run_matrix PROD PROD
run_matrix BENCH BENCH

# ---------------------------------------------------------
# Summary
# ---------------------------------------------------------
echo "================= Build Compliance Summary ================="
echo "Successful builds:     ${PASSED}"
echo "Policy-blocked builds: ${POLICY_FAIL} (CORRECT-FAIL)"
echo "Unexpected failures:   ${UNEXPECTED_FAIL}"

if [[ $UNEXPECTED_FAIL -eq 0 ]]; then
    echo -e "Audit Compliance:      ${G}COMPLIANT ✓${RS}"
else
    echo -e "Audit Compliance:      ${R}NON-COMPLIANT ✘${RS}"
fi

echo "============================================================"
echo "Logs saved under: $LOG_DIR/"
echo "============================================================"
