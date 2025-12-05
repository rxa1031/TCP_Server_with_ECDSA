CC := gcc

# =====================================================================
# TTY-aware ANSI Colors (disabled when piping/redirecting)
# =====================================================================
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

# =====================================================================
# Build Modes
# =====================================================================
# make                → PROD (Hardened default)
# make PROD=0         → DEV  (Sanitizers + full logs)
# make BENCH=1        → BENCH (Performance hardened)
#
# PROD  = strict security (mTLS + Host + Revocation)
# DEV   = relaxed for debugging
# BENCH = PROD + performance tests (reduced logging)
# =====================================================================

PROD  ?= 1
BENCH ?= 0

# =====================================================================
# mTLS / Certificate Revocation
# =====================================================================
mTLS       ?= 1  # mTLS=0 → DEV only
REVOCATION ?= 1  # 0 = Disabled, 1 = CRL, 2 = CRL+OCSP

ifeq ($(REVOCATION),0)
REVOCATION_DESC := 0 (DISABLED – DEV only unless SKIP_SECURITY=1)
else ifeq ($(REVOCATION),1)
REVOCATION_DESC := 1 (CRL only – hard fail)
else ifeq ($(REVOCATION),2)
REVOCATION_DESC := 2 (CRL+OCSP – highest assurance)
else
REVOCATION_DESC := $(REVOCATION) (UNKNOWN – verify input)
endif

# =====================================================================
# Logging Configuration
# =====================================================================
WARN  ?= 0
INFO  ?= 0
DEBUG ?= 0

# =====================================================================
# Host and Port Defaults
# =====================================================================
PROD_HOST  ?= secure.lab.linux
DEV_HOST   ?= localhost
BENCH_HOST ?= 127.0.0.1

PROD_PORT  ?= 443
BENCH_PORT ?= 443
DEV_PORT   ?= 8443

# =====================================================================
# Security Enforcement: Prevent insecure builds unless overridden
# =====================================================================
SKIP_SECURITY ?= 0

ifeq ($(BENCH),1)
PROD := 1
endif

ifeq ($(SKIP_SECURITY),0)

ifneq ($(PROD),0)
ifeq ($(mTLS),0)
$(error $(R)Invalid: mTLS=0 allowed only in DEV$(RS))
endif
ifeq ($(REVOCATION),0)
$(error $(R)Invalid: REVOCATION=0 blocked in PROD/BENCH$(RS))
endif
endif

ifeq ($(DEBUG),1)
ifeq ($(BENCH),1)
$(error $(R)Invalid: DEBUG not allowed in BENCH$(RS))
endif
ifneq ($(PROD),0)
$(error $(R)Invalid: DEBUG allowed only in DEV$(RS))
endif
endif

endif # SKIP_SECURITY

# =====================================================================
# Certificate Requirement (Hardened Only)
# =====================================================================
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

# =====================================================================
# Logging Macro Flags
# =====================================================================
LOG_DEFS := -D__LOG_ENABLE_ERROR__

ifneq ($(filter 1,$(WARN) $(INFO) $(DEBUG)),)
ifneq ($(WARN),0)  ; LOG_DEFS += -D__LOG_ENABLE_WARN__ ; endif
ifneq ($(INFO),0)  ; LOG_DEFS += -D__LOG_ENABLE_INFO__ ; endif
ifneq ($(DEBUG),0) ; LOG_DEFS += -D__LOG_ENABLE_DEBUG__ ; endif
endif

# =====================================================================
# Build Mode Selection
# =====================================================================
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
HOST         := $(DEV_HOST)
PORT         := $(DEV_PORT)

ifeq ($(filter 1,$(WARN) $(INFO) $(DEBUG)),)
WARN=1 ; INFO=1 ; DEBUG=1
LOG_DEFS += -D__LOG_ENABLE_WARN__ -D__LOG_ENABLE_INFO__ -D__LOG_ENABLE_DEBUG__
endif

else
MODE_FLAGS   :=
MODE_MSG     := PROD hardened
CFLAGS_EXTRA := -O2 -pipe -fstack-clash-protection -DNDEBUG
HOST         := $(PROD_HOST)
PORT         := $(PROD_PORT)
endif

# =====================================================================
# mTLS Macro Declaration
# =====================================================================
ifeq ($(mTLS),1)
mTLS_MSG  := mTLS: ON
DEFS_mTLS := -D__REQUIRE_MUTUAL_TLS__
else
mTLS_MSG  := mTLS: OFF (DEV only)
DEFS_mTLS := -U__REQUIRE_MUTUAL_TLS__
endif

# =====================================================================
# Security Override Handling
# =====================================================================
ifeq ($(SKIP_SECURITY),1)
CFLAGS_EXTRA += -DSKIP_SECURITY
HOST          := insecure.local
endif

# Apply host/port after override
HOST_DEF        := -D__ALLOWED_HOST__=\"$(HOST)\"
PORT_DEF        := -D__TLS_PORT__=$(PORT)
REVOCATION_DEFS := -D__REVOCATION_LEVEL__=$(REVOCATION)

# =====================================================================
# C Standard Detection
# =====================================================================
CHECK_C23 := $(shell printf "int main(){}" | $(CC) -std=c23 -xc - -o /dev/null 2>/dev/null && echo yes)
CSTD      := $(if $(CHECK_C23),-std=c23,-std=c2x)

# =====================================================================
# Hardening Flags
# =====================================================================
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
LDFLAGS := $(LDFLAGS_BASE)

# =====================================================================
# Sources / Output Directory
# =====================================================================
BUILD_DIR := build
TARGET    := $(BUILD_DIR)/mtls_server
SRCS      := src/mtls_server.c

# =====================================================================
# Build Summary + Binary Build
# =====================================================================
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
	@echo "$(R)*** WARNING: SKIP_SECURITY ENABLED (INSECURE BUILD) ***$(RS)"
endif
	@echo "$(Y)------------------------------------------------$(RS)"

$(TARGET): $(SRCS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET) $(LDFLAGS)

# =====================================================================
# Help — also responds to `make ?`
# =====================================================================
.PHONY: help ?
? : help

help:
	@echo "$(Y)==================== Build Help ====================$(RS)"
	@echo "make             → PROD hardened build"
	@echo "make PROD=0      → DEV build (sanitizers + logs)"
	@echo "make BENCH=1     → BENCH hardened (performance)"
	@echo ""
	@echo "$(G)Logging Controls:$(RS)"
	@echo "WARN=1 INFO=1 DEBUG=1 as needed"
	@echo ""
	@echo "SECURITY OVERRIDE (CI only):"
	@echo "SKIP_SECURITY=1 make PROD=1 REVOCATION=0"
	@echo "$(Y)====================================================$(RS)"

# =====================================================================
# Clean
# =====================================================================
.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
