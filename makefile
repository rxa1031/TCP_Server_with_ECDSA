CC := gcc

# =============================================================================
# TTY-aware ANSI Colors (disabled when piping/redirecting)
# =============================================================================
ifneq ("$(shell tty 2>/dev/null)","")
Y  := $(shell printf "\033[33m")
G  := $(shell printf "\033[32m")
C  := $(shell printf "\033[36m")
R  := $(shell printf "\033[97;41m")     # White text on RED background (your requirement)
RS := $(shell printf "\033[0m")
else
Y  :=
G  :=
C  :=
R  :=
RS :=
endif

# =============================================================================
# Build Modes
# =============================================================================
# make                → PROD (Hardened default)
# make PROD=0         → DEV  (Sanitizers + full logs)
# make BENCH=1        → BENCH (Performance hardened)
#
# PROD  = strict security (TLS + mTLS + Host + Security Level enforced)
# DEV   = debugging + testing mode (TLS always ON, mTLS optional — explicit mTLS=0 allowed)
# BENCH = PROD-like but tuned for performance benchmarking
#
# BENCH implies hardened behavior (treated as PROD for policy checks)
# =============================================================================

PROD  ?= 1
BENCH ?= 0

ifeq ($(BENCH),1)
PROD := 1
endif

# =============================================================================
# mTLS / Security Level
# =============================================================================
# mTLS=1 → Mutual TLS — client certificate required
# mTLS=0 → Server-auth-only TLS
#          Allowed ONLY in DEV (PROD=0, BENCH=0)
#
# SECURITY_LEVEL (authentication / revocation strength, TLS always ON):
#   1 → DEV baseline:
#        - TLS always ON
#        - mTLS optional (DEV only)
#        - CRL optional
#        - OCSP not used
#
#   2 → Hardened baseline (default for PROD/BENCH):
#        - TLS always ON
#        - mTLS REQUIRED in PROD/BENCH
#        - CRL REQUIRED in PROD/BENCH
#        - OCSP not used (reserved)
#
#   3 → Future hardened mode (OCSP + CRL + mTLS)
#        - Not yet implemented
#        - Hardened builds (PROD/BENCH) must reject SECURITY_LEVEL>=3
# =============================================================================

mTLS           ?= 1
SECURITY_LEVEL ?= 2   # Default hardened level; DEV will auto-downgrade to 1 if user did not override

# =============================================================================
# Logging Controls
# =============================================================================
# LOG_ERROR is always compiled in the C file (no macro needed)
# WARN / INFO / DEBUG controlled via Makefile macros below
# =============================================================================

WARN  ?= 0
INFO  ?= 0
DEBUG ?= 0

# =============================================================================
# Certificate Folder + Filenames (Override-Friendly)
# =============================================================================
CERT_FOLDER ?= certs

SERVER_CERT ?= server-cert.pem
SERVER_KEY  ?= server-key.pem
CA_CERT     ?= ca-cert.pem
CA_CRL      ?= ca-crl.pem

# Runtime paths (binary runs in ./build → certs are in ../certs)
SERVER_CERT_PATH = ../$(CERT_FOLDER)/$(SERVER_CERT)
SERVER_KEY_PATH  = ../$(CERT_FOLDER)/$(SERVER_KEY)
CA_CERT_PATH     = ../$(CERT_FOLDER)/$(CA_CERT)
CA_CRL_PATH      = ../$(CERT_FOLDER)/$(CA_CRL)

# Macros exported to C — must follow __NAME__ naming rule
CERT_DEFS := \
	-D__CERT_FOLDER__=\"$(CERT_FOLDER)\" \
	-D__SERVER_CERT_NAME__=\"$(SERVER_CERT)\" \
	-D__SERVER_KEY_NAME__=\"$(SERVER_KEY)\" \
	-D__CA_CERT_NAME__=\"$(CA_CERT)\" \
	-D__CA_CRL_NAME__=\"$(CA_CRL)\" \
	-D__SERVER_CERT_PATH__=\"$(SERVER_CERT_PATH)\" \
	-D__SERVER_KEY_PATH__=\"$(SERVER_KEY_PATH)\" \
	-D__CA_CERT_PATH__=\"$(CA_CERT_PATH)\" \
	-D__CA_CRL_PATH__=\"$(CA_CRL_PATH)\"

# =============================================================================
# Sanitizer Behaviour (DEV only)
# =============================================================================
# DEV default = Option B → Continue after sanitizer reporting
# SANITIZER_FAIL_FAST=1 → Option A → Abort immediately (fail-fast)
# =============================================================================
SANITIZER_FAIL_FAST ?= 0

# =============================================================================
# Host and Port Defaults
# =============================================================================
PROD_HOST  ?= secure.lab.linux
DEV_HOST   ?= localhost
BENCH_HOST ?= 127.0.0.1

PROD_PORT  ?= 443
BENCH_PORT ?= 443
DEV_PORT   ?= 8443

# =============================================================================
# Security Enforcement: Prevent insecure hardened builds unless overridden
# =============================================================================
__SKIP_SECURITY__ ?= 0

# =============================================================================
# Canonical mTLS Policy Matrix (Do Not Modify Without Security Review)
# =============================================================================
# TLS: Always ON in all modes (non-negotiable)
#
# Build Mode | User Request | Policy Allows? | Final mTLS State | Build Result
# ---------- | ------------ | -------------- | ---------------- | ------------
# PROD       | (none)       | N/A            | ON               | PASS
# PROD       | mTLS=1       | Yes            | ON               | PASS
# PROD       | mTLS=0       | No             | (Blocked)        | FAIL
# BENCH      | (none)       | N/A            | ON               | PASS
# BENCH      | mTLS=1       | Yes            | ON               | PASS
# BENCH      | mTLS=0       | No             | (Blocked)        | FAIL
# DEV        | (none)       | Yes            | ON (default)     | PASS
# DEV        | mTLS=1       | Yes            | ON               | PASS
# DEV        | mTLS=0       | Yes            | OFF              | PASS
#
# Policy Statement:
#   - TLS ALWAYS enabled
#   - mTLS required in PROD/BENCH
#   - mTLS may be disabled ONLY in DEV with explicit mTLS=0
# =============================================================================

# =============================================================================
# Always allow cleaning — bypass *all* security enforcement
# =============================================================================
ifneq ($(filter clean help ?,$(MAKECMDGOALS)),)
  __SKIP_SECURITY__ := 1
endif

# =============================================================================
# DEV-specific default for SECURITY_LEVEL
#   - If user did NOT explicitly set SECURITY_LEVEL, DEV should default to 1
#   - PROD/BENCH keep default 2 unless user overrides
# =============================================================================
ifeq ($(PROD),0)
  ifeq ($(origin SECURITY_LEVEL), default)
    SECURITY_LEVEL := 1
  endif
endif

ifeq ($(__SKIP_SECURITY__),0)

  # Hardened modes (PROD/BENCH): enforce mTLS ON
ifneq ($(PROD),0)
ifeq ($(mTLS),0)
$(error $(R)Invalid: mTLS=0 is forbidden in PROD/BENCH. Tip: To disable mTLS use: make PROD=0 mTLS=0  (DEV mode only).$(RS))
endif

  # Hardened modes (PROD/BENCH): SECURITY_LEVEL must be >= 2
ifeq ($(shell [ $(SECURITY_LEVEL) -ge 2 ] && echo ok || echo bad),bad)
$(error $(R)Invalid: SECURITY_LEVEL must be >= 2 in PROD/BENCH hardened builds$(RS))
endif

  # Hardened modes (PROD/BENCH): SECURITY_LEVEL >= 3 (OCSP) not yet supported
ifeq ($(shell [ $(SECURITY_LEVEL) -ge 3 ] && echo hi || echo ok),hi)
$(error $(R)Invalid: SECURITY_LEVEL >= 3 is reserved for future OCSP support and is forbidden in PROD/BENCH$(RS))
endif
endif

  # Secure logging policy enforcement: DEBUG only allowed in DEV
ifeq ($(DEBUG),1)
ifeq ($(BENCH),1)
$(error $(R)Invalid: DEBUG not allowed in BENCH hardened mode$(RS))
endif
ifneq ($(PROD),0)
$(error $(R)Invalid: DEBUG allowed only in DEV for secure logging policy$(RS))
endif
endif

  # Hardened mode (true PROD only): WARN and INFO must remain disabled
ifneq ($(PROD),0)
ifneq ($(BENCH),1)  # True PROD (BENCH also sets PROD=1)
ifneq ($(WARN),0)
$(error $(R)Invalid: WARN logging is forbidden in PROD builds$(RS))
endif
ifneq ($(INFO),0)
$(error $(R)Invalid: INFO logging is forbidden in PROD builds$(RS))
endif
endif
endif

endif # __SKIP_SECURITY__

# =============================================================================
# Certificate Requirement (Hardened builds — skipped only during clean)
# =============================================================================
# DEV builds allowed even if missing certs
# PROD/BENCH require full trust chain + CRL = 4 files
# =============================================================================
ifneq ($(filter clean,$(MAKECMDGOALS)),)
# ✓ Clean target → no certificate enforcement
else ifeq ($(__SKIP_SECURITY__),0)
ifneq ($(PROD),0)

# Hardened mode → full trust chain (cert + key + CA + CRL) required
CERT_FILES := \
	$(CERT_FOLDER)/$(SERVER_CERT) \
	$(CERT_FOLDER)/$(SERVER_KEY) \
	$(CERT_FOLDER)/$(CA_CERT) \
	$(CERT_FOLDER)/$(CA_CRL)

MISSING_CERT_FILES := \
	$(strip $(foreach f,$(CERT_FILES),$(if $(wildcard $(f)),,$(f))))

ifneq ($(MISSING_CERT_FILES),)
$(error $(R)CRITICAL: Missing certificate/CRL: $(MISSING_CERT_FILES)$(RS) \
→ Hardened mode (PROD/BENCH): SECURITY_LEVEL>=2 requires full trust chain. \
→ Fix: Place files under $(CERT_FOLDER)/ OR use DEV mode: make PROD=0)
endif

endif
endif

# =============================================================================
# Logging Macro Flags (LOG_ERROR always compiled in C)
# =============================================================================
# NOTE: __LOG_ENABLE_ERROR__ included ***only for test script reporting***
# =============================================================================
LOG_DEFS := -D__LOG_ENABLE_ERROR__

ifneq ($(filter 1,$(WARN) $(INFO) $(DEBUG)),)
ifneq ($(WARN),0)
LOG_DEFS += -D__LOG_ENABLE_WARN__
endif
ifneq ($(INFO),0)
LOG_DEFS += -D__LOG_ENABLE_INFO__
endif
ifneq ($(DEBUG),0)
LOG_DEFS += -D__LOG_ENABLE_DEBUG__
endif
endif

# =============================================================================
# Build Mode Selection (Enable flags + host + port)
# =============================================================================
ifeq ($(BENCH),1)
MODE_FLAGS   := -D__BENCH__
MODE_MSG     := BENCH hardened
CFLAGS_EXTRA := -O2 -pipe -fstack-clash-protection -DNDEBUG
LDFLAGS_EXTRA :=
HOST         := $(BENCH_HOST)
PORT         := $(BENCH_PORT)

else ifeq ($(PROD),0)
MODE_FLAGS   := -D__DEV__
MODE_MSG     := DEV build (debug)
CFLAGS_EXTRA := -g3 -O0 -fsanitize=address,undefined,leak -fno-omit-frame-pointer
LDFLAGS_EXTRA := -fsanitize=address,undefined,leak
HOST         := $(DEV_HOST)
PORT         := $(DEV_PORT)

  # DEV convenience: auto-enable logs when none provided
ifeq ($(filter 1,$(WARN) $(INFO) $(DEBUG)),)
WARN  := 1
INFO  := 1
DEBUG := 1
LOG_DEFS += -D__LOG_ENABLE_WARN__ -D__LOG_ENABLE_INFO__ -D__LOG_ENABLE_DEBUG__
endif

  # Sanitizer Mode (DEV only)
CFLAGS_EXTRA += -DMODE_SAN -DSANITIZER_OPTION_B_CONTINUE
ifeq ($(SANITIZER_FAIL_FAST),1)
CFLAGS_EXTRA += -DSANITIZER_OPTION_A_ABORT
endif

else
MODE_FLAGS   :=
MODE_MSG     := PROD hardened
CFLAGS_EXTRA := -O2 -pipe -fstack-clash-protection -DNDEBUG
HOST         := $(PROD_HOST)
PORT         := $(PROD_PORT)
LDFLAGS_EXTRA :=
endif

# =============================================================================
# mTLS Macro Declaration
# =============================================================================
ifeq ($(mTLS),1)
mTLS_MSG  := mTLS: ON  (Mutual TLS — client cert required)
DEFS_mTLS := -D__REQUIRE_MUTUAL_TLS__
else
mTLS_MSG  := mTLS: OFF (Server-auth-only TLS; DEV-only)
DEFS_mTLS := -U__REQUIRE_MUTUAL_TLS__
endif

# =============================================================================
# Security Override Handling (__SKIP_SECURITY__)
# =============================================================================
# __SKIP_SECURITY__=1:
#   - Disables only policy enforcement checks (NOT recommended for deployment).
#     TLS still ALWAYS ON.
#   - Allowed ONLY under CI/testing
#   - Not for operational hardened deployments
# =============================================================================
ifeq ($(__SKIP_SECURITY__),1)
CFLAGS_EXTRA += -D__SKIP_SECURITY__
HOST          := insecure.local
endif

# Apply host/port + security macros after override
HOST_DEF           := -D__ALLOWED_HOST__=\"$(HOST)\"
PORT_DEF           := -D__TLS_PORT__=$(PORT) -D__TLS_PORT_STR__=\"$(PORT)\"
SECURITY_LEVEL_DEF := -D__SECURITY_LEVEL__=$(SECURITY_LEVEL)

# =============================================================================
# C Standard Detection (prefer C23, fallback to C2x)
# =============================================================================
CHECK_C23 := $(shell printf "int main(){}" | $(CC) -std=c23 -xc - -o /dev/null 2>/dev/null && echo yes)
CSTD      := $(if $(CHECK_C23),-std=c23,-std=c2x)

# =============================================================================
# Hardening Flags
# =============================================================================
CFLAGS_BASE := \
	$(CSTD) \
	-Wall -Wextra -Werror -Wpedantic \
	-Wformat=2 -Wshadow -Wpointer-arith \
	-Wcast-align -Wwrite-strings \
	-Wconversion -Wstrict-prototypes \
	-D_FORTIFY_SOURCE=2 \
	-fstack-protector-strong -fPIE

LDFLAGS_BASE := \
	-lssl -lcrypto \
	-pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack

ifeq ($(PROD),1)
LDFLAGS_BASE += -Wl,-z,defs
endif

CFLAGS  := $(CFLAGS_BASE) $(CFLAGS_EXTRA) $(MODE_FLAGS) $(DEFS_mTLS) $(LOG_DEFS) $(HOST_DEF) $(PORT_DEF) $(SECURITY_LEVEL_DEF) $(CERT_DEFS)
LDFLAGS := $(LDFLAGS_BASE) $(LDFLAGS_EXTRA)

# =============================================================================
# Sources / Output Directory
# =============================================================================
BUILD_DIR := build
TARGET    := $(BUILD_DIR)/mtls_server
SRCS      := src/mtls_server.c

# =============================================================================
# Build Summary + Binary Build
# =============================================================================
all: $(TARGET)
	@echo "$(Y)---------------- BUILD SUMMARY ----------------$(RS)"
	@echo "Mode:         $(C)$(MODE_MSG)$(RS)"
ifeq ($(BENCH),1)
	@echo "$(Y)Note: BENCH hardened — logs may impact timing tests$(RS)"
endif
	@echo "TLS:          ON (TLS 1.3 enforced)"
	@echo "$(mTLS_MSG)"
	@echo "Security:     Level $(SECURITY_LEVEL) (1=DEV baseline, 2=Hardened, 3=Future OCSP)"
	@echo "CA Trust:     $(C)$(CA_CERT)$(RS)"
	@echo "Trust Chain:  server-key.pem + server-cert.pem + ca-cert.pem"
	@if [ $(SECURITY_LEVEL) -ge 2 ]; then \
		echo "CRL Status:   $(G)ENFORCED ($(CA_CRL))$(RS)"; \
	else \
		echo "CRL Status:   $(Y)DISABLED / not enforced at this level$(RS)"; \
	fi
	@if [ $(SECURITY_LEVEL) -ge 3 ]; then \
		echo "OCSP Status:  $(R)REQUESTED (not implemented; forbidden in PROD/BENCH)$(RS)"; \
	else \
		echo "OCSP Status:  OFF (not implemented)"; \
	fi
	@echo "Logging:      ERROR=$(G)1$(RS) WARN=$(Y)$(WARN)$(RS) INFO=$(C)$(INFO)$(RS) DEBUG=$(R)$(DEBUG)$(RS)"
	@echo "Host:         $(HOST)"
	@echo "Port:         $(PORT)"
	@echo "Output:       $(TARGET)"
	@echo "C Standard:   $(CSTD)"
ifeq ($(__SKIP_SECURITY__),1)
	@echo "$(R)*** WARNING: __SKIP_SECURITY__ ENABLED — INSECURE BUILD (CI/TEST ONLY) ***$(RS)"
	@echo "$(R)*** DO NOT DISTRIBUTE BUILDS MADE WITH __SKIP_SECURITY__=1 ***$(RS)"
endif
ifeq ($(SANITIZER_FAIL_FAST),1)
	@echo "$(R)Sanitizer: FAIL-FAST mode (Option A)$(RS)"
else
	@echo "Sanitizer:   Continue after issue (Option B)"
endif
	@echo "$(Y)------------------------------------------------$(RS)"

$(TARGET): $(SRCS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET) $(LDFLAGS)

# =============================================================================
# Help — also responds to `make ?`
# =============================================================================
.PHONY: help ?
? : help

help:
	@echo "$(Y)==================== Build Help ====================$(RS)"
	@echo "make             → PROD hardened build (TLS + mTLS + SECURITY_LEVEL>=2 enforced)"
	@echo "make PROD=0      → DEV build (TLS ALWAYS ON, SECURITY_LEVEL=1 default, mTLS optional — explicit mTLS=0 allowed for testing)"
	@echo "make BENCH=1     → BENCH hardened build (performance + security)"
	@echo ""
	@echo "$(G)mTLS / Security Level:$(RS)"
	@echo "  mTLS=1 (default)   → require client cert"
	@echo "  mTLS=0             → DEV only (server-auth TLS)"
	@echo "  SECURITY_LEVEL=1   → DEV baseline (TLS ON, mTLS/CRL optional)"
	@echo "  SECURITY_LEVEL=2   → Hardened baseline (default for PROD/BENCH; mTLS + CRL required)"
	@echo "  SECURITY_LEVEL>=3  → Reserved for future OCSP (forbidden in PROD/BENCH until implemented)"
	@echo "  NOTE: CA certificate is ALWAYS required — even when mTLS=0"
	@echo "  $(Y)Tip:$(RS) To disable mTLS: use DEV mode → $(C)make PROD=0 SECURITY_LEVEL=1 mTLS=0$(RS)"
	@echo "  __SKIP_SECURITY__=1 → CI/test only. Disables policy enforcement checks (TLS still ON). Not for PROD/BENCH artifacts."
	@echo ""
	@echo "$(G)Sanitizers (DEV only):$(RS)"
	@echo "  SANITIZER_FAIL_FAST=1 → Abort immediately"
	@echo ""
	@echo "$(G)Default Logging Behaviour (when no flags passed):$(RS)"
	@echo "  Applies to: make  | make PROD=1 | make PROD=0 | make BENCH=1"
	@echo "  ------------------+-------------+-------------+-------------"
	@echo "  Build Mode  ERROR | WARN        | INFO        | DEBUG"
	@echo "  PROD         ON   | OFF         | OFF         | OFF"
	@echo "  BENCH        ON   | OFF         | OFF         | OFF"
	@echo "  DEV          ON   | ON          | ON          | ON"
	@echo "    Note: \"ON\" = logging enabled by default; \"OFF\" = disabled by default."
	@echo ""
	@echo "$(G)Logging Configurability via Makefile Flags:$(RS)"
	@echo "  Flag / Macro                     | PROD     | BENCH        | DEV"
	@echo "  ---------------------------------+----------+--------------+-------------"
	@echo "  WARN=1 / -D__LOG_ENABLE_WARN__   | Blocked  | Configurable | Configurable"
	@echo "  INFO=1 / -D__LOG_ENABLE_INFO__   | Blocked  | Configurable | Configurable"
	@echo "  DEBUG=1 / -D__LOG_ENABLE_DEBUG__ | Blocked  | Blocked      | Configurable"
	@echo ""
	@echo "  Security Logging Policy Summary:"
	@echo "    • PROD  → only ERROR logs allowed (no WARN / INFO / DEBUG)"
	@echo "    • BENCH → ERROR always; WARN/INFO optional via user config; DEBUG forbidden"
	@echo "    • DEV   → WARN/INFO/DEBUG all configurable for debugging visibility"
	@echo ""
	@echo "$(Y)====================================================$(RS)"

# =============================================================================
# Clean
# =============================================================================
.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
