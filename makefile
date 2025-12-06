CC := gcc

# =============================================================================
# TTY-aware ANSI Colors (disabled when piping/redirecting)
# =============================================================================
ifneq ("$(shell tty 2>/dev/null)","")
Y  := $(shell printf "\033[33m")
G  := $(shell printf "\033[32m")
C  := $(shell printf "\033[36m")
R  := $(shell printf "\033[31m")
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
# PROD  = strict security (TLS + mTLS + Host + Revocation enforced)
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
# mTLS / Certificate Revocation
# =============================================================================
# mTLS=1 → Mutual TLS — client certificate required
# mTLS=0 → Server-auth-only TLS
#          Allowed ONLY in DEV (PROD=0, BENCH=0)
#
# REVOCATION:
#   0 → Disabled (DEV only or __SKIP_SECURITY__=1)
#   1 → CRL required (baseline hardened policy)
#   2 → CRL+OCSP (future enhancement hooks reserved)
# =============================================================================

mTLS       ?= 1
REVOCATION ?= 1

ifeq ($(REVOCATION),0)
REVOCATION_DESC := 0 (DISABLED — DEV only unless __SKIP_SECURITY__=1)
else ifeq ($(REVOCATION),1)
REVOCATION_DESC := 1 (CRL-only — hardened baseline)
else ifeq ($(REVOCATION),2)
REVOCATION_DESC := 2 (CRL+OCSP — future hardened mode)
else
REVOCATION_DESC := $(REVOCATION) (UNKNOWN — verify input)
endif

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

ifeq ($(__SKIP_SECURITY__),0)

  # Hardened modes (PROD/BENCH): enforce mTLS ON
ifneq ($(PROD),0)
ifeq ($(mTLS),0)
$(error $(R)Invalid: mTLS=0 is forbidden in PROD/BENCH. Tip: To disable mTLS use: make PROD=0 mTLS=0  (DEV mode only).$(RS))
endif

  # Hardened modes (PROD/BENCH): revocation must not be disabled
ifeq ($(REVOCATION),0)
$(error $(R)Invalid: REVOCATION=0 blocked in PROD/BENCH — CRL enforcement required$(RS))
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

endif # __SKIP_SECURITY__

# =============================================================================
# Certificate Requirement (Hardened builds — skipped only during clean)
# =============================================================================
# DEV builds allowed even if missing certs
# PROD/BENCH require all 3 PEM files to exist
# =============================================================================
ifneq ($(filter clean,$(MAKECMDGOALS)),)
# ✓ Clean target → no certificate enforcement
else ifeq ($(__SKIP_SECURITY__),0)
ifneq ($(PROD),0)

CERT_FILES := \
	certs/server-cert.pem \
	certs/server-key.pem \
	certs/ca-server-cert.pem

$(foreach f,$(CERT_FILES), \
	$(if $(wildcard $(f)),, \
		$(error $(R)Missing required certificate: $(f)$(RS))))
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

# Apply host/port + revocation macros after override
HOST_DEF        := -D__ALLOWED_HOST__=\"$(HOST)\"
PORT_DEF        := -D__TLS_PORT__=$(PORT) -D__TLS_PORT_STR__=\"$(PORT)\"
REVOCATION_DEFS := -D__REVOCATION_LEVEL__=$(REVOCATION)

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

CFLAGS  := $(CFLAGS_BASE) $(CFLAGS_EXTRA) $(MODE_FLAGS) $(DEFS_mTLS) $(LOG_DEFS) $(HOST_DEF) $(PORT_DEF) $(REVOCATION_DEFS)
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
	@echo "$(mTLS_MSG)"
	@echo "Revocation:   Level $(REVOCATION) → CRL=$$([[ $(REVOCATION) -ge 1 ]] && echo ON || echo OFF), OCSP=$$([[ $(REVOCATION) -ge 2 ]] && echo ON || echo OFF)"
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
	@echo "make             → PROD hardened build (TLS + mTLS + revocation enforced)"
	@echo "make PROD=0      → DEV build (TLS ALWAYS ON, mTLS optional — explicit mTLS=0 allowed for testing)"
	@echo "make BENCH=1     → BENCH hardened build (performance + security)"
	@echo ""
	@echo "$(G)mTLS / Revocation:$(RS)"
	@echo "  mTLS=1 (default) → require client cert"
	@echo "  mTLS=0 → DEV only (server-auth TLS)"
	@echo "  REVOCATION=1 (default) → CRL policy (hardened baseline)"
	@echo "  REVOCATION=2 → CRL+OCSP future mode (DEV only; blocked in PROD/BENCH until OCSP implemented)"
	@echo "  REVOCATION=0 → DEV only / __SKIP_SECURITY__ override (no revocation checks)"
	@echo "  $(Y)Tip:$(RS) To disable mTLS: use DEV mode → $(C)make PROD=0 mTLS=0$(RS)"
	@echo "$(Y)  __SKIP_SECURITY__=1 → CI/test only. Disables enforcement checks (TLS still ON). Not for PROD/BENCH artifacts.$(RS)"
	@echo ""
	@echo "$(G)Sanitizers (DEV only):$(RS)"
	@echo "  SANITIZER_FAIL_FAST=1 → Abort immediately"
	@echo ""
	@echo "$(G)Logging Policy:$(RS)"
	@echo "  WARN, INFO = optional in PROD/BENCH"
	@echo "  DEBUG = DEV only"
	@echo "  Default in DEV (no flags): WARN=1 INFO=1 DEBUG=1"
	@echo ""
	@# ⚠ POLICY REQUIREMENT — DO NOT REMOVE
	@# Policy Legend v1.5 — mTLS Policy Finalized (TLS always ON)
	@# Only incorrect information may be removed or corrected — do not delete this block
	@echo "$(G)Logging (ASCII Matrix):$(RS)"
	@echo "  Mode   ERROR INFO WARN DEBUG"
	@echo "  PROD    1     opt  opt   0"
	@echo "  BENCH   1     opt  opt   0"
	@echo "  DEV     1     d=1  d=1   d=1"
	@echo ""
	@echo "Legend:"
	@echo "  1   = Enabled always"
	@echo "  0   = Disabled always"
	@echo "  opt = Optional — enable explicitly in PROD/BENCH"
	@echo "  d=1 = Auto-enabled in DEV if user gives no flags"
	@echo ""
	@echo "$(Y)====================================================$(RS)"

# =============================================================================
# Clean
# =============================================================================
.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
