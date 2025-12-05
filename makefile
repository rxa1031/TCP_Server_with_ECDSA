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
# PROD  = strict security (TLS + mTLS + Host + Revocation)
# DEV   = relaxed for debugging (still TLS-only, mTLS optional)
# BENCH = PROD-like but tuned for performance benchmarking
# =============================================================================

PROD  ?= 1
BENCH ?= 0

# BENCH implies hardened behavior (treated as PROD for policy checks)
ifeq ($(BENCH),1)
PROD := 1
endif

# =============================================================================
# mTLS / Certificate Revocation
# =============================================================================
# mTLS=1 → mutual TLS (client certificate required)
# mTLS=0 → server-auth only TLS (client cert not requested)
#          Allowed ONLY in DEV (PROD=0, BENCH=0)
#
# REVOCATION:
#   0 → Disabled (DEV only or SKIP_SECURITY=1)
#   1 → CRL required (baseline hardened policy)
#   2 → CRL + OCSP (future enhancement, hooks reserved)
# =============================================================================

mTLS       ?= 1
REVOCATION ?= 1

ifeq ($(REVOCATION),0)
REVOCATION_DESC := 0 (DISABLED – DEV only unless SKIP_SECURITY=1)
else ifeq ($(REVOCATION),1)
REVOCATION_DESC := 1 (CRL-only – hardened baseline)
else ifeq ($(REVOCATION),2)
REVOCATION_DESC := 2 (CRL+OCSP – future hardened mode)
else
REVOCATION_DESC := $(REVOCATION) (UNKNOWN – verify input)
endif

# =============================================================================
# Logging Configuration
# =============================================================================
# LOG_ERROR is always compiled in the C file (no macro needed).
# Makefile controls WARN / INFO / DEBUG via preprocessor macros.
# =============================================================================

WARN  ?= 0
INFO  ?= 0
DEBUG ?= 0

# =============================================================================
# Sanitizer Behaviour (DEV only)
# =============================================================================
# DEV default = Option B → continue running after sanitizer issues
# SANITIZER_FAIL_FAST=1 → Option A → fail fast (abort on sanitizer issue)
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
SKIP_SECURITY ?= 0

ifeq ($(SKIP_SECURITY),0)

  # Hardened modes (PROD/BENCH): mTLS=0 is not allowed
ifneq ($(PROD),0)
ifeq ($(mTLS),0)
$(error $(R)Invalid: mTLS=0 allowed only in DEV$(RS))
endif
  # Hardened modes (PROD/BENCH): REVOCATION=0 is not allowed
ifeq ($(REVOCATION),0)
$(error $(R)Invalid: REVOCATION=0 blocked in PROD/BENCH$(RS))
endif
endif

  # DEBUG not allowed in BENCH or PROD (only in DEV)
ifeq ($(DEBUG),1)
ifeq ($(BENCH),1)
$(error $(R)Invalid: DEBUG not allowed in BENCH$(RS))
endif
ifneq ($(PROD),0)
$(error $(R)Invalid: DEBUG allowed only in DEV$(RS))
endif
endif

endif # SKIP_SECURITY

# =============================================================================
# Certificate Requirement (Hardened builds)
# =============================================================================
# DEV builds are allowed to compile even if certs are missing.
# PROD/BENCH (when SKIP_SECURITY=0) require all three PEMs to exist.
# =============================================================================
ifeq ($(SKIP_SECURITY),0)
ifneq ($(PROD),0)
CERT_FILES := \
	certs/server-cert.pem \
	certs/server-key.pem \
	certs/ca-server-cert.pem

$(foreach f,$(CERT_FILES), \
	$(if $(wildcard $(f)),, \
		$(error Missing required certificate: $(f))))
endif
endif

# =============================================================================
# Logging Macro Flags (LOG_ERROR always compiled in C)
# =============================================================================
# NOTE: __LOG_ENABLE_ERROR__ is defined for reporting purposes in tests.
# The C file does not actually gate LOG_ERROR on this macro.
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
# Build Mode Selection (HOST/PORT + CFLAGS_EXTRA + MODE_FLAGS)
# =============================================================================
ifeq ($(BENCH),1)
MODE_FLAGS   := -D__BENCH__
MODE_MSG     := BENCH hardened
CFLAGS_EXTRA := -O2 -pipe -fstack-clash-protection -DNDEBUG
HOST         := $(BENCH_HOST)
PORT         := $(BENCH_PORT)

else ifeq ($(PROD),0)
MODE_FLAGS   := -D__DEV__
MODE_MSG     := DEV build (debug)
CFLAGS_EXTRA := -g3 -O0 -fsanitize=address,undefined,leak -fno-omit-frame-pointer
LDFLAGS_EXTRA := -fsanitize=address,undefined,leak
HOST         := $(DEV_HOST)
PORT         := $(DEV_PORT)

  # DEV convenience: if no log levels set, enable all by default
ifeq ($(filter 1,$(WARN) $(INFO) $(DEBUG)),)
WARN  := 1
INFO  := 1
DEBUG := 1
LOG_DEFS += -D__LOG_ENABLE_WARN__ -D__LOG_ENABLE_INFO__ -D__LOG_ENABLE_DEBUG__
endif

  # Sanitizer mode for DEV
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
mTLS_MSG  := mTLS: ON  (Mutual TLS – client cert required)
DEFS_mTLS := -D__REQUIRE_MUTUAL_TLS__
else
mTLS_MSG  := mTLS: OFF (Server-auth TLS only; allowed only in DEV)
DEFS_mTLS := -U__REQUIRE_MUTUAL_TLS__
endif

# =============================================================================
# Security Override Handling (SKIP_SECURITY)
# =============================================================================
# SKIP_SECURITY=1:
#   - Disables Makefile policy errors (mTLS/REVOCATION/DEBUG/certs)
#   - Intended ONLY for CI experiments or controlled testing.
#   - NOT for deployment builds.
# =============================================================================
ifeq ($(SKIP_SECURITY),1)
CFLAGS_EXTRA += -DSKIP_SECURITY
HOST          := insecure.local
endif

# Apply host/port and revocation macros after overrides
HOST_DEF        := -D__ALLOWED_HOST__=\"$(HOST)\"
PORT_DEF        := -D__TLS_PORT__=$(PORT)
REVOCATION_DEFS := -D__REVOCATION_LEVEL__=$(REVOCATION)

# =============================================================================
# C Standard Detection (prefer C23, fall back to C2x)
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
	@echo "Mode:         $(MODE_MSG)"
	@echo "$(mTLS_MSG)"
	@echo "Revocation:   $(REVOCATION_DESC)"
	@echo "Logging:      ERROR=1 WARN=$(WARN) INFO=$(INFO) DEBUG=$(DEBUG)"
	@echo "Host:         $(HOST)"
	@echo "Port:         $(PORT)"
	@echo "Output:       $(TARGET)"
	@echo "C Standard:   $(CSTD)"
ifeq ($(SKIP_SECURITY),1)
	@echo "$(R)*** WARNING: SKIP_SECURITY ENABLED (INSECURE BUILD, CI/TEST ONLY) ***$(RS)"
endif
ifeq ($(SANITIZER_FAIL_FAST),1)
	@echo "$(R)Sanitizer: FAIL-FAST (Option A) enabled in DEV$(RS)"
else
	@echo "Sanitizer:   Continue after reporting (Option B) in DEV"
endif
	@echo "$(Y)------------------------------------------------$(RS)"
	@echo "$(G)Logging (ASCII Matrix):$(RS)"
	@echo "  Mode   ERROR INFO WARN DEBUG"
	@echo "  PROD    1     opt  opt   0"
	@echo "  BENCH   1     opt  opt   0"
	@echo "  DEV     1     d=1  d=1  d=1"
	@echo ""
	# ⚠ POLICY REQUIREMENT — DO NOT REMOVE
	# Policy Legend v1.4.1 — Unified TLS Server Requirements
	# Only incorrect information may be removed or corrected — do not delete this block
	@echo "Legend:"
	@echo "  1   = Enabled always"
	@echo "  0   = Disabled always"
	@echo "  opt = Optional (must enable explicitly)"
	@echo "  d=1 = Auto-enabled in DEV when no log flags set"
	@echo ""

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
	@echo "make             → PROD hardened build (TLS + mTLS + revocation)"
	@echo "make PROD=0      → DEV build (TLS-only, mTLS optional, sanitizers + logs)"
	@echo "make BENCH=1     → BENCH hardened (TLS + mTLS, performance focus)"
	@echo ""
	@echo "$(G)mTLS / Revocation:$(RS)"
	@echo "  mTLS=1 (default) → mutual TLS (client cert required)"
	@echo "  mTLS=0           → DEV only (server-auth TLS)"
	@echo "  REVOCATION=0     → disabled (DEV or SKIP_SECURITY=1 only)"
	@echo "  REVOCATION=1     → CRL-only baseline hardened policy"
	@echo "  REVOCATION=2     → CRL+OCSP (future hardening, hooks reserved)"
	@echo ""
	@echo "$(G)Logging Controls:$(RS)"
	@echo "  WARN=1 INFO=1 DEBUG=1 as needed (DEBUG only in DEV)"
	@echo ""
	@echo "$(G)Logging (ASCII Matrix):$(RS)"
	@echo "  Mode   ERROR INFO WARN DEBUG"
	@echo "  PROD    1     opt  opt   0"
	@echo "  BENCH   1     opt  opt   0"
	@echo "  DEV     1     d=1  d=1  d=1"
	@echo ""
	# ⚠ POLICY REQUIREMENT — DO NOT REMOVE
	# Policy Legend v1.4.1 — Unified TLS Server Requirements
	# Only incorrect information may be removed or corrected — do not delete this block
	@echo "Legend:"
	@echo "  1   = Enabled always"
	@echo "  0   = Disabled always"
	@echo "  opt = Optional; enable with WARN=1 or INFO=1"
	@echo "  d=1 = Auto-enabled in DEV when no log flags set"
	@echo ""
	@echo "$(G)Sanitizers (DEV only):$(RS)"
	@echo "  Default = Continue after reporting (Option B)"
	@echo "  SANITIZER_FAIL_FAST=1 → Fail-fast (Option A) in DEV"
	@echo ""
	@echo "SECURITY OVERRIDE (CI/test only, NOT for deployment):"
	@echo "  SKIP_SECURITY=1 make PROD=1 mTLS=0 REVOCATION=0"
	@echo "$(Y)====================================================$(RS)"

# =============================================================================
# Clean
# =============================================================================
.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
