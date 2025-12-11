# -----------------------------------------------------------------------------
# mtls_server Makefile (final, audited, dense comments)
#
# - Dense documentation included.
# - Mode selection: only one mode at a time (PROD / DEV / BENCH).
#   * PROD is default: `make` or `make PROD=1`.
#   * DEV is `make PROD=0`.
#   * BENCH is `make BENCH=1` (must be exactly 1; BENCH=0 or BENCH= empty -> error).
# - Security level (SL) is passed unchanged to compiler as:
#       -D__SECURITY_LEVEL__=$(SL)
# - C receives exactly one of: -D__DEV__  OR  -D__PROD__  OR  -D__BENCH__ plus SL.
# -----------------------------------------------------------------------------

CC := gcc

# =============================================================================
# TTY-aware ANSI Colors (disabled when piping/redirecting)
# =============================================================================
ifneq ("$(shell tty 2>/dev/null)","")
Y  := $(shell printf "\033[33m")
G  := $(shell printf "\033[32m")
C  := $(shell printf "\033[36m")
R  := $(shell printf "\033[97;41m")     # White text on RED background
RS := $(shell printf "\033[0m")
else
Y  :=
G  :=
C  :=
R  :=
RS :=
endif

# =============================================================================
# Basic user-facing flags
# =============================================================================
PROD  ?= 1
BENCH ?=
mTLS  ?= 1

# Validate PROD is 0 or 1
ifeq ($(filter 0 1,$(PROD)),)
  $(error $(R)Invalid PROD value '$(PROD)'. PROD must be 1 (default) or 0 to select DEV.$(RS))
endif

# =============================================================================
# Logging controls (0/1)
# =============================================================================
WARN  ?= 0
INFO  ?= 0
DEBUG ?= 0

# =============================================================================
# Sanitizer controls (0/1)
# =============================================================================
SAN  ?= 1
EXIT ?= 0

# =============================================================================
# Certificate filenames (override friendly)
# =============================================================================
CERT_FOLDER ?= certs

SERVER_CERT ?= server-cert.pem
SERVER_KEY  ?= server-key.pem
CA_CERT     ?= ca-cert.pem
CA_CRL      ?= ca-crl.pem

SERVER_CERT_PATH = $(CERT_FOLDER)/$(SERVER_CERT)
SERVER_KEY_PATH  = $(CERT_FOLDER)/$(SERVER_KEY)
CA_CERT_PATH     = $(CERT_FOLDER)/$(CA_CERT)
CA_CRL_PATH      = $(CERT_FOLDER)/$(CA_CRL)

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
# Host & ports
# =============================================================================
PROD_HOST  ?= secure.lab.linux
DEV_HOST   ?= localhost
BENCH_HOST ?= 127.0.0.1

PROD_PORT  ?= 443
DEV_PORT   ?= 8443
BENCH_PORT ?= 443

# =============================================================================
# Targets that skip certificate checks
# =============================================================================
SKIP_GOALS := clean help -h --help usage ? policy config

# =============================================================================
# Validate BENCH presence (must be omitted or BENCH=1). Catch BENCH= / BENCH=0.
# Use origin to detect command-line provision.
# =============================================================================
ifeq ($(origin BENCH),command line)
  ifneq ($(BENCH),1)
    $(error $(R)Invalid BENCH value '$(BENCH)'. BENCH is a mode and must be set exactly as BENCH=1 to enable BENCH mode.$(RS))
  endif
endif

# =============================================================================
# Validate boolean flags strictly (0 or 1)
# =============================================================================
define _bool_ok
$(shell printf "%s\n" "$(1)" | grep -E '^(0|1)$$' >/dev/null 2>&1 && echo ok || echo bad)
endef

ifeq ($(call _bool_ok,$(WARN)),bad)
  $(error $(R)Invalid WARN value '$(WARN)'. Allowed: 0 or 1.$(RS))
endif
ifeq ($(call _bool_ok,$(INFO)),bad)
  $(error $(R)Invalid INFO value '$(INFO)'. Allowed: 0 or 1.$(RS))
endif
ifeq ($(call _bool_ok,$(DEBUG)),bad)
  $(error $(R)Invalid DEBUG value '$(DEBUG)'. Allowed: 0 or 1.$(RS))
endif
ifeq ($(call _bool_ok,$(SAN)),bad)
  $(error $(R)Invalid SAN value '$(SAN)'. Allowed: 0 or 1.$(RS))
endif
ifeq ($(call _bool_ok,$(EXIT)),bad)
  $(error $(R)Invalid EXIT value '$(EXIT)'. Allowed: 0 or 1.$(RS))
endif
ifeq ($(call _bool_ok,$(mTLS)),bad)
  $(error $(R)Invalid mTLS value '$(mTLS)'. Allowed: 0 or 1.$(RS))
endif

# =============================================================================
# Final mode determination (exclusive)
# - BENCH=1 -> BENCH (must not combine with PROD=0)
# - else PROD=0 -> DEV
# - else PROD=1/default -> PROD
# =============================================================================
ifeq ($(BENCH),1)
  ifeq ($(PROD),0)
    $(error $(R)Invalid: BENCH=1 cannot be combined with PROD=0 (DEV mode). Use either BENCH=1 or PROD=0, not both.$(RS))
  endif
  MODE := BENCH
else ifeq ($(PROD),0)
  MODE := DEV
else
  MODE := PROD
endif

# =============================================================================
# Security Level SL (unified, single source of truth)
# =============================================================================
# SL_DEFAULT is the single authoritative hardened baseline value used by PROD
# and BENCH — and used as the default in DEV as well.  When OCSP support is
# enabled in the future, change SL_DEFAULT := 3 and all modes adopt that
# hardened baseline automatically.
#
# Behaviour:
#  - SL_DEFAULT ?= 2              # default hardened baseline (change to 3 later)
#  - If user did not set SL on the command-line, SL is set to SL_DEFAULT.
#  - DEV:
#      * Defaults to SL_DEFAULT when SL not set.
#      * User MAY override SL explicitly to one of: 1, 2, 3 (DEV-only).
#  - PROD and BENCH:
#      * Default to SL_DEFAULT.
#      * User MAY NOT override SL — SL must equal SL_DEFAULT exactly.
#
# The selected SL is always exported to the C compiler as:
#   -D__SECURITY_LEVEL__=$(SL)
# =============================================================================
SL_DEFAULT ?= 2

ifeq ($(origin SL),undefined)
  SL := $(SL_DEFAULT)
endif

ifeq ($(MODE),DEV)
  # DEV: only values 1,2,3 are accepted (1=TLS-only, 2=mTLS+CRL, 3=future OCSP)
  ifeq ($(shell printf "%s\n" "$(SL)" | grep -E '^(1|2|3)$$' >/dev/null && echo ok),)
    $(error $(R)Invalid SL value '$(SL)' for DEV. Allowed values: 1, 2, 3.$(RS))
  endif
else
  # PROD/BENCH: SL must match SL_DEFAULT exactly (no override)
  ifneq ($(SL),$(SL_DEFAULT))
    $(error $(R)Invalid SL value '$(SL)' for $(MODE). Allowed: SL=$(SL_DEFAULT) only.$(RS))
  endif
endif

# =============================================================================
# Certificate existence checks (only for real build operations)
# Skip when target is help/clean/policy/config, etc.
#
# IMPORTANT:
#   - This Makefile DOES NOT generate PEM files.
#   - PEM generation is done by external scripts.
#   - In PROD/BENCH, we enforce:
#       * All PEMs exist
#       * CN of server certificate matches HOST for MODE
#       * If CN encodes "host:port", port must match MODE PORT
# =============================================================================
ifneq ($(filter $(SKIP_GOALS),$(MAKECMDGOALS)),)
  CHECK_CERTS := 0
else
  CHECK_CERTS := 1
endif

ifeq ($(CHECK_CERTS),1)
  ifneq ($(MODE),DEV)
    CERT_FILES := $(SERVER_CERT_PATH) $(SERVER_KEY_PATH) $(CA_CERT_PATH) $(CA_CRL_PATH)
    MISSING_CERTS := $(strip $(foreach f,$(CERT_FILES),$(if $(wildcard $(f)),,$(f))))
    ifneq ($(MISSING_CERTS),)
      $(error $(R)CRITICAL: Missing certificate(s): $(MISSING_CERTS)$(RS) \
-> Hardened mode requires server cert/key + CA cert + CRL. Use DEV (make PROD=0) for testing or place files under $(CERT_FOLDER)/.)
    endif



    # OpenSSL CLI is required to perform CN/host/port sanity checks.
    OPENSSL ?= openssl
    OPENSSL_AVAILABLE := $(shell command -v $(OPENSSL) >/dev/null 2>&1 && echo yes || echo no)
    ifeq ($(OPENSSL_AVAILABLE),no)
      $(error $(R)OpenSSL CLI '$(OPENSSL)' not found. Required for certificate CN/port validation in $(MODE) builds.$(RS))
    endif

    # Expected HOST/PORT based on selected MODE
    EXPECTED_HOST := $(if $(filter PROD,$(MODE)),$(PROD_HOST),$(if $(filter BENCH,$(MODE)),$(BENCH_HOST),$(DEV_HOST)))
    EXPECTED_PORT := $(if $(filter PROD,$(MODE)),$(PROD_PORT),$(if $(filter BENCH,$(MODE)),$(BENCH_PORT),$(DEV_PORT)))

    # Extract CN from server certificate subject (strip everything before CN=
    # and any trailing components after first '/').
    SERVER_CN := $(shell $(OPENSSL) x509 -in $(SERVER_CERT_PATH) -noout -subject 2>/dev/null | sed -n 's/^subject=.*CN=//p' | sed 's:/.*::')
    ifeq ($(strip $(SERVER_CN)),)
      $(error $(R)Unable to read CN from $(SERVER_CERT_PATH). Check that it is a valid X.509 certificate for $(EXPECTED_HOST).$(RS))
    endif

    # Split CN into host and optional port (CN may be "host" or "host:port").
    CN_HOST := $(shell printf "%s\n" "$(SERVER_CN)" | awk -F: '{print $$1}')
    CN_PORT := $(shell printf "%s\n" "$(SERVER_CN)" | awk -F: 'NF>1 {print $$2}')

    # Host part must match expected host exactly.
    ifneq ($(CN_HOST),$(EXPECTED_HOST))
      $(error $(R)Certificate CN mismatch in $(SERVER_CERT_PATH): expected 'CN=$(EXPECTED_HOST)' but found 'CN=$(SERVER_CN)' for $(MODE).$(RS))
    endif

    # If CN encodes a port, it must match expected TLS port.
    ifneq ($(strip $(CN_PORT)),)
      ifneq ($(CN_PORT),$(EXPECTED_PORT))
        $(error $(R)Certificate CN port mismatch in $(SERVER_CERT_PATH): expected port $(EXPECTED_PORT) for $(MODE) but CN encodes port $(CN_PORT).$(RS))
      endif
    endif

  endif
endif

# =============================================================================
# Hardened policy checks (Makefile-level)
# - mTLS=0 forbidden in PROD/BENCH
# - SL constraints:
#     * DEV: SL defaults to SL_DEFAULT (=2) when not set; allowed values 1,2,3
#     * PROD/BENCH: SL must equal SL_DEFAULT (=2); SL>=3 reserved for OCSP
# - DEBUG allowed only in DEV
# - WARN/INFO forbidden in PROD; BENCH allows WARN/INFO when explicitly enabled
# =============================================================================

ifeq ($(MODE),BENCH)
  ifeq ($(mTLS),0)
    $(error $(R)Invalid: mTLS=0 forbidden in BENCH hardened builds. Use DEV (make PROD=0) to disable mTLS.$(RS))
  endif
  ifeq ($(shell [ $(SL) -ge 2 ] && echo ok || echo bad),bad)
    $(error $(R)Invalid: SL must be >= 2 in BENCH hardened builds$(RS))
  endif
  ifeq ($(shell [ $(SL) -ge 3 ] && echo hi || echo ok),hi)
    $(error $(R)Invalid: SL>=3 reserved for OCSP and is forbidden in BENCH hardened builds. Use DEV to test SL>=3$(RS))
  endif
endif

ifeq ($(MODE),PROD)
  ifeq ($(mTLS),0)
    $(error $(R)Invalid: mTLS=0 forbidden in PROD hardened builds. Use DEV (make PROD=0) to disable mTLS.$(RS))
  endif
  ifeq ($(shell [ $(SL) -ge 2 ] && echo ok || echo bad),bad)
    $(error $(R)Invalid: SL=1 forbidden in PROD hardened builds (requires SL>=2)$(RS))
  endif
  ifeq ($(shell [ $(SL) -ge 3 ] && echo hi || echo ok),hi)
    $(error $(R)Invalid: SL>=3 reserved for OCSP and is forbidden in PROD hardened builds. Use DEV to test SL>=3$(RS))
  endif
endif

ifeq ($(DEBUG),1)
  ifneq ($(MODE),DEV)
    $(error $(R)Invalid: DEBUG logging is allowed only in DEV builds$(RS))
  endif
endif

ifeq ($(MODE),PROD)
  ifneq ($(WARN),0)
    $(error $(R)Invalid: WARN logging is forbidden in PROD hardened builds$(RS))
  endif
  ifneq ($(INFO),0)
    $(error $(R)Invalid: INFO logging is forbidden in PROD hardened builds$(RS))
  endif
endif

ifeq ($(MODE),BENCH)
  # BENCH allows WARN/INFO when explicitly set; forbids DEBUG
  ifneq ($(DEBUG),0)
    $(error $(R)Invalid: DEBUG logging forbidden in BENCH hardened builds by policy (use DEV for debug)$(RS))
  endif
endif

# =============================================================================
# DEV defaults: if user didn't set WARN/INFO/DEBUG explicitly, enable them in DEV
# =============================================================================
ifeq ($(MODE),DEV)
  ifeq ($(filter 1,$(WARN) $(INFO) $(DEBUG)),)
    WARN  := 1
    INFO  := 1
    DEBUG := 1
  endif
endif

# =============================================================================
# Sanitizer enforcement: disabled for hardened modes
# =============================================================================
ifeq ($(MODE),DEV)
  # keep SAN as configured
else
  SAN := 0
endif

# =============================================================================
# Build-mode flags & messages (PASS EXACTLY ONE OF __DEV__/__PROD__/__BENCH__ to C)
# =============================================================================
ifeq ($(MODE),BENCH)
  MODE_FLAGS := -D__BENCH__
  MODE_MSG   := BENCH hardened (performance-focused)
  HOST       := $(BENCH_HOST)
  PORT       := $(BENCH_PORT)
  CFLAGS_EXTRA := -O2 -pipe -fstack-clash-protection -DNDEBUG
  LDFLAGS_EXTRA :=
else ifeq ($(MODE),DEV)
  MODE_FLAGS := -D__DEV__
  MODE_MSG   := DEV build (debug)
  HOST       := $(DEV_HOST)
  PORT       := $(DEV_PORT)
  ifeq ($(SAN),1)
    CFLAGS_EXTRA  := -g3 -O0 -fsanitize=address,undefined,leak -fno-omit-frame-pointer
    LDFLAGS_EXTRA := -fsanitize=address,undefined,leak
  else
    CFLAGS_EXTRA  := -g3 -O0
    LDFLAGS_EXTRA :=
  endif
else
  MODE_FLAGS := -D__PROD__
  MODE_MSG   := PROD hardened
  HOST       := $(PROD_HOST)
  PORT       := $(PROD_PORT)
  CFLAGS_EXTRA := -O2 -pipe -fstack-clash-protection -DNDEBUG
  LDFLAGS_EXTRA :=
endif

# mTLS macro: define or undefine to avoid stale object problem
ifeq ($(mTLS),1)
  DEFS_MTLS := -D__REQUIRE_MUTUAL_TLS__
else
  DEFS_MTLS := -U__REQUIRE_MUTUAL_TLS__
endif

# mTLS message for summary
ifeq ($(mTLS),1)
  mTLS_MSG := mTLS: ON  (Mutual TLS — client cert required)
else
  mTLS_MSG := mTLS: OFF (Server-auth-only TLS; DEV-only)
endif

# export host/port/SL to C
HOST_DEF := -D__ALLOWED_HOST__=\"$(HOST)\"
PORT_DEF := -D__TLS_PORT__=$(PORT) -D__TLS_PORT_STR__=\"$(PORT)\"
SL_DEF   := -D__SECURITY_LEVEL__=$(SL)

# logging macros
LOG_DEFS := -D__LOG_ENABLE_ERROR__
ifneq ($(WARN),0)
  LOG_DEFS += -D__LOG_ENABLE_WARN__
endif
ifneq ($(INFO),0)
  LOG_DEFS += -D__LOG_ENABLE_INFO__
endif
ifneq ($(DEBUG),0)
  LOG_DEFS += -D__LOG_ENABLE_DEBUG__
endif

# =============================================================================
# C standard detection and hardening flags
# =============================================================================
CHECK_C23 := $(shell printf "int main(){}" | $(CC) -std=c23 -xc - -o /dev/null 2>/dev/null && echo yes)
CSTD      := $(if $(CHECK_C23),-std=c23,-std=c2x)

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

ifeq ($(MODE),PROD)
  LDFLAGS_BASE += -Wl,-z,defs
endif

CFLAGS  := $(CFLAGS_BASE) $(CFLAGS_EXTRA) $(MODE_FLAGS) $(DEFS_MTLS) $(LOG_DEFS) $(HOST_DEF) $(PORT_DEF) $(SL_DEF) $(CERT_DEFS)
LDFLAGS := $(LDFLAGS_BASE) $(LDFLAGS_EXTRA)

# =============================================================================
# Sources / Output
# =============================================================================
BUILD_DIR := build
TARGET    := $(BUILD_DIR)/mtls_server
SRCS      := src/mtls_server.c

# =============================================================================
# Build + summary (OCSP messaging preserved). Also show user-origin for log flags.
# =============================================================================
.PHONY: all
all: $(TARGET)
	@echo "$(Y)---------------- BUILD SUMMARY ----------------$(RS)"
	@echo "Mode:         $(C)$(MODE_MSG)$(RS)"
ifeq ($(MODE),BENCH)
	@echo "$(Y)Note: BENCH hardened — logs may impact timing tests$(RS)"
endif
	@echo "TLS:          ON"
	@echo "  $(mTLS_MSG)"
	@echo "Security:     SL=$(SL) (1=TLS, 2=mTLS+CRL (Hardened), 3=mTLS+CRL+(Future)OCSP)"
	@echo "CA Trust:     $(C)$(CA_CERT)$(RS)"
	@echo "Trust Chain:  $(SERVER_KEY) + $(SERVER_CERT) + $(CA_CERT)"
	@if [ $(SL) -ge 2 ]; then \
		echo "CRL Status:   $(G)ENFORCED ($(CA_CRL))$(RS)"; \
	else \
		echo "CRL Status:   $(Y)DISABLED / not enforced at this level$(RS)"; \
	fi
	@if [ $(SL) -ge 3 ]; then \
		if [ "$(MODE)" = "DEV" ]; then \
			echo "OCSP Status:  $(Y)RESERVED (not implemented; allowed only in DEV)$(RS)"; \
		else \
			echo "OCSP Status:  $(R)ERROR (SL>=3 forbidden in PROD/BENCH)$(RS)"; \
		fi \
	else \
		echo "OCSP Status:  OFF (not implemented)"; \
	fi
	@echo "Logging (final): ERROR=$(G)1$(RS) WARN=$(Y)$(WARN)$(RS) INFO=$(C)$(INFO)$(RS) DEBUG=$(R)$(DEBUG)$(RS)"
	@echo "Logging (source): WARN=$(origin WARN) INFO=$(origin INFO) DEBUG=$(origin DEBUG)"
	@echo "Host:         $(HOST)"
	@echo "Port:         $(PORT)"
	@echo "Cert Folder:  $(CERT_FOLDER)"
	@echo "Output:       $(TARGET)"
	@echo "C Standard:   $(CSTD)"
ifeq ($(SAN),1)
	@echo "Sanitisers:   Enabled ($(if $(EXIT),Exit on first error,Continue after errors))"
else
	@echo "Sanitisers:   Disabled"
endif
	@echo "$(Y)------------------------------------------------$(RS)"

$(TARGET): $(SRCS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET) $(LDFLAGS)

# =============================================================================
# Help / policy / config
# =============================================================================
.PHONY: help usage -h --help ? policy config

help usage -h --help ?:
	@echo ""
	@echo "$(Y)Usage: make [OPTIONS] [TARGET]$(RS)"
	@echo ""
	@echo "$(G)Available Targets:$(RS)"
	@echo "  make                 → Default build (PROD hardened)"
	@echo "  make clean           → Remove build artifacts"
	@echo "  make help | -h | --help | ? | usage"
	@echo "                       → Show this help"
	@echo "  make policy          → Security & logging rules"
	@echo "  make config          → Show resolved build configuration"
	@echo ""
	@echo "$(G)Modes (mutually exclusive):$(RS)"
	@echo "  PROD (default)       → make  OR make PROD=1  (hardened)"
	@echo "  DEV                  → make PROD=0 (development; sanitizers & verbose logs)"
	@echo "  BENCH                → make BENCH=1  (performance-hardened)"
	@echo ""
	@echo "$(G)Important Mode Notes:$(RS)"
	@echo "  - Only one mode is allowed at a time. Contradictory flags result in a hard error."
	@echo "  - BENCH must be passed as BENCH=1 to enable BENCH mode. BENCH=0 or any other"
	@echo "    value is invalid and will cause an error."
	@echo ""
	@echo "$(G)Security Level (SL):$(RS)"
	@echo "  - SL is passed directly to the C compiler as: -D__SECURITY_LEVEL__=$(SL)"
	@echo "  - DEV defaults to SL_DEFAULT (=2)"
	@echo "    DEV allow SL = 1, 2, or 3 (explicit setting)"
	@echo "  - PROD/BENCH require SL = SL_DEFAULT (=2), (SL=3 i.e., TLS + mTLS + CRL + OCSP pending implementation)"
	@echo ""
	@echo "$(G)mTLS / Certificates:$(RS)"
	@echo "  - mTLS=1 (default) requires client certs. mTLS=0 is allowed only in DEV."
	@echo "  - Hardened builds (PROD/BENCH) require server cert, server key, CA cert and CRL."
	@echo ""
	@echo "$(G)Sanitizers & Debugging:$(RS)"
	@echo "  - SAN=1 (default in DEV) enables ASan+UBSan+LSan instrumentation."
	@echo "  - EXIT=1 causes sanitizer fail-fast behavior (only meaningful when SAN=1)."
	@echo ""
	@echo "$(G)Logging:$(RS)"
	@echo "  - ERROR logs are always compiled in for test harness integration."
	@echo "  - DEV defaults WARN/INFO/DEBUG to ON when not explicitly set by the user."
	@echo "  - PROD/BENCH disable DEBUG; BENCH can enable WARN/INFO explicitly."
	@echo ""
	@echo "Examples:"
	@echo "  make                  # PROD hardened"
	@echo "  make PROD=0           # DEV (sanitizers + verbose logs)"
	@echo "  make PROD=0 SL=3      # DEV with SL=3 (for OCSP development/testing)"
	@echo "  make BENCH=1          # BENCH hardened (must be BENCH=1 exactly)"
	@echo ""

policy:
	@echo "$(Y)==================== Security Policy ====================$(RS)"
	@echo "mTLS / Security Levels:"
	@echo "- SL=1: DEV baseline (TLS ON, mTLS optional)"
	@echo "- SL=2: Hardened baseline (default in PROD/BENCH: mTLS + CRL required)"
	@echo "- SL>=3: Reserved for future OCSP (not implemented). Allowed in DEV only."
	@echo ""
	@echo "Policy Summary:"
	@echo "- TLS is ALWAYS ON"
	@echo "- mTLS required in PROD/BENCH; may be disabled only in DEV"
	@echo "- PROD/BENCH require full trust chain + CRL"
	@echo ""
	@echo "$(Y)=============== Sanitizers ===============$(RS)"
	@echo "SAN=1 → ASan+UBSan+LSan (DEV only)"
	@echo "EXIT=1 → Fail fast on sanitizer error"
	@echo "SAN=0 → Disabled (PROD/BENCH always have SAN=0)"
	@echo ""
	@echo "$(Y)Note on SAN terminology$(RS)"
	@echo "SAN (Subject Alternative Name) is an identity-extension field inside X.509 certificates."
	@echo "It is used for hostname/IP validation in SSL/TLS."
	@echo "This is unrelated to the SAN flag in this Makefile, which controls sanitizers (ASan/UBSan/LSan)."
	@echo ""
	@echo "$(Y)=============== Logging Policy ===============$(RS)"
	@echo "| Mode      | ERROR | WARN | INFO | DEBUG | SAN |"
	@echo "|----------:|:-----:|:----:|:----:|:-----:|:---:|"
	@echo "| PROD      |  ON   | OFF  |  OFF | OFF   |  0  |"
	@echo "| BENCH     |  ON   | ON*  |  ON* | OFF   |  0  |"
	@echo "| DEV       |  ON   |  ON  |   ON |  ON   |  1  |"
	@echo ""
	@echo "* BENCH allows WARN/INFO when explicitly enabled by the user (WARN=1 INFO=1)."
	@echo "$(Y)====================================================$(RS)"

config:
	@echo "$(Y)=========== Resolved Build Configuration ===========$(RS)"
	@echo "Mode:     $(MODE)"
	@echo "mTLS:     $(mTLS)"
	@echo "SL:       $(SL)"
	@echo "SAN:      $(SAN)"
	@echo "Logging:  ERR=1 WARN=$(WARN) INFO=$(INFO) DEBUG=$(DEBUG)"
	@echo "Logging source: WARN=$(origin WARN) INFO=$(origin INFO) DEBUG=$(origin DEBUG)"
	@echo "Host:     $(HOST)"
	@echo "Port:     $(PORT)"
	@echo "CertDir:  $(CERT_FOLDER)"
	@echo "Output:   $(TARGET)"
	@echo "CFLAGS:   $(CFLAGS)"
	@echo "LDFLAGS:  $(LDFLAGS)"
	@echo "$(Y)====================================================$(RS)"

# =============================================================================
# Clean
# =============================================================================
.PHONY: clean
clean:
	@echo "[CLEAN] Removing build outputs only"
	@rm -f build/*.o build/*.d build/mtls_server
	@echo "[CLEAN] Done"
