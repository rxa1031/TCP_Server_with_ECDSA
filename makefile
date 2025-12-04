CC      := gcc

# =====================================================================
# Build Options:
#   make                    : PROD (Hardened) build        → PROD=1 (default)
#   make PROD=0             : DEV build (sanitizers + selectable logging)
#   make BENCH=1            : BENCH build (hardened + optimized)
#
# Host Enforcement (per-mode defaults, override via make):
#   PROD_HOST  (default: secure.lab.linux)
#   DEV_HOST   (default: localhost)
#   BENCH_HOST (default: 127.0.0.1)
#
# Logging overrides:
#   make LOG_ALL=1         : Enable WARN + INFO only
#   make WARN=1
#   make INFO=1
#   make DEBUG=1           : Only allowed when PROD=0 (DEV mode)
#
# =====================================================================

PROD    ?= 1
BENCH   ?= 0
TLS     ?= 1
WARN    ?= 0
INFO    ?= 0
DEBUG   ?= 0
LOG_ALL ?= 0

PROD_HOST  ?= secure.lab.linux
DEV_HOST   ?= localhost
BENCH_HOST ?= 127.0.0.1

# =====================================================================
# Build Mode Safety Enforcement (HARD FAIL)
# =====================================================================

# DEV and BENCH must not be enabled together
ifeq ($(PROD),0)
ifeq ($(BENCH),1)
$(error DEV (PROD=0) and BENCH=1 cannot be enabled together)
endif
endif

# If DEBUG=1 requested outside DEV → reject
ifeq ($(DEBUG),1)
ifneq ($(PROD),0)
$(error DEBUG logging is only allowed in DEV builds. Use: make PROD=0 DEBUG=1)
endif
endif

# BENCH mode always implies PROD hardened build
ifeq ($(BENCH),1)
PROD := 1
endif

# If neither DEV nor BENCH selected → PROD default remains
# (PROD is already default 1)

# =====================================================================
# Logging Configuration
# =====================================================================

# LOG_ALL convenience: WARN + INFO ONLY
ifeq ($(LOG_ALL),1)
    WARN := 1
    INFO := 1
endif

LOG_DEFS :=

ifeq ($(WARN),1)
    LOG_DEFS += -D__LOG_ENABLE_WARN__
endif

ifeq ($(INFO),1)
    LOG_DEFS += -D__LOG_ENABLE_INFO__
endif

ifeq ($(DEBUG),1)
    LOG_DEFS += -D__LOG_ENABLE_DEBUG__
endif

# =====================================================================
# Mode Selection: BENCH → DEV → PROD
# =====================================================================

ifeq ($(BENCH),1)
	MODE_FLAGS    := -D__BENCH__
	MODE_MSG      := Mode: BENCH (Performance Testing)
	CFLAGS_EXTRA  := -O2 -pipe
	LDFLAGS_EXTRA :=
	HOST_DEF      := -DRV_ALLOWED_HOST=\"$(BENCH_HOST)\"
	HOST_MSG      := Host (BENCH): $(BENCH_HOST)

else ifeq ($(PROD),0)
	MODE_FLAGS    := -D__DEV__
	MODE_MSG      := Mode: DEV (Debug + Sanitizers)
	CFLAGS_EXTRA  := -g3 -O0 -fsanitize=address,undefined
	LDFLAGS_EXTRA := -fsanitize=address,undefined
	HOST_DEF      := -DRV_ALLOWED_HOST=\"$(DEV_HOST)\"
	HOST_MSG      := Host (DEV):   $(DEV_HOST)

else
	MODE_FLAGS    :=
	MODE_MSG      := Mode: PROD (Hardened Default)
	CFLAGS_EXTRA  := -O2 -pipe
	LDFLAGS_EXTRA :=
	HOST_DEF      := -DRV_ALLOWED_HOST=\"$(PROD_HOST)\"
	HOST_MSG      := Host (PROD):  $(PROD_HOST)
endif

# =====================================================================
# Mutual TLS Selection
# =====================================================================

ifeq ($(TLS),1)
	TLS_MSG  := Mutual TLS: ENABLED
	DEFS_TLS := -D__ENABLE_MUTUAL_TLS__
else
	TLS_MSG  := Mutual TLS: DISABLED
	DEFS_TLS := -U__ENABLE_MUTUAL_TLS__
endif

# =====================================================================
# Detect C23 support
# =====================================================================

CHECK_C23 := $(shell printf "int main(){}" | $(CC) -std=c23 -xc - -o /dev/null 2>/dev/null && echo yes || echo no)
ifeq ($(CHECK_C23),yes)
	CSTD := -std=c23
else
	CSTD := -std=c2x
endif

# =====================================================================
# Security Hardening Flags
# =====================================================================

CFLAGS_BASE := \
	$(CSTD) \
	-Wall -Wextra -Werror -Wpedantic \
	-Wformat=2 -Wshadow -Wpointer-arith \
	-Wcast-align -Wwrite-strings \
	-Wconversion -Wstrict-prototypes \
	-D_FORTIFY_SOURCE=2 \
	-fstack-protector-strong -fPIE

CFLAGS  := $(CFLAGS_BASE) $(CFLAGS_EXTRA) $(MODE_FLAGS) $(DEFS_TLS) $(LOG_DEFS) $(HOST_DEF)
LDFLAGS := -lssl -lcrypto -pie $(LDFLAGS_EXTRA)

TARGET  := TCP_Server
SRCS    := TCP_Server.c
PREFIX  := /usr/local/bin

# =====================================================================
# Build
# =====================================================================

all: $(TARGET)
	@echo "Using GCC: $$($(CC) --version | head -n 1)"
	@echo "$(MODE_MSG)"
	@echo "$(TLS_MSG)"
	@echo "Logging Flags: $(LOG_DEFS)"
	@echo "$(HOST_MSG)"
	@echo "C Standard: $(CSTD)"
	@echo "OpenSSL: $$(openssl version 2>/dev/null || echo not found)"

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET) $(LDFLAGS)

install: $(TARGET)
	install -m 755 $(TARGET) $(PREFIX)
	@echo "Installed to: $(PREFIX)"

clean:
	rm -f $(TARGET)
