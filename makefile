CC      := gcc

# BUILD options:
# "make"               : Mutual TLS enabled. Also enable full hardening (default)
# "make DEBUG=1"       : Debug with sanitizers
# "make TLS=0"         : Mutual TLS disabled
# "make TLS=1"         : Mutual TLS enabled
# "make DEBUG=1"       : Debug build (adds debug flags)
# "sudo make install"  : Install the built binary to /usr/local/bin
# "make clean"         : Cleanup

TLS     ?= 1
DEBUG   ?= 0

# Detect C23 support
CHECK_C23 := $(shell printf "int main(){}" | $(CC) -std=c23 -xc - -o /dev/null 2>/dev/null && echo yes || echo no)

ifeq ($(CHECK_C23),yes)
	CSTD := -std=c23
else
	CSTD := -std=c2x
endif

# Detect OpenSSL version and warn if insufficient
OPENSSL_VER := $(shell openssl version 2>/dev/null | awk '{print $$2}')
OPENSSL_OK := $(shell openssl version 2>/dev/null | grep -E "1\.1\.1|3\." > /dev/null && echo yes || echo no)

ifeq ($(OPENSSL_OK),no)
$(warning WARNING: Detected OpenSSL version '$(OPENSSL_VER)' may not fully support TLS 1.3)
endif

# Mutual TLS preprocessor flag
ifeq ($(TLS),1)
	DEFS := -DENABLE_MUTUAL_TLS
	TLS_MSG := Mutual TLS: ENABLED
else
	DEFS := -UENABLE_MUTUAL_TLS
	TLS_MSG := Mutual TLS: DISABLED
endif

# Debug options
ifeq ($(DEBUG),1)
	CFLAGS_EXTRA := -g3 -O0 -fsanitize=address,undefined
	DEBUG_MSG := Debug build: ENABLED
	LDFLAGS_EXTRA := -fsanitize=address,undefined
else
	CFLAGS_EXTRA := -O2 -pipe
	DEBUG_MSG := Debug build: DISABLED
	LDFLAGS_EXTRA :=
endif

# Base flags
CFLAGS  := $(CSTD) \
		   -Wall -Wextra -Werror -Wpedantic \
		   -Wformat=2 -Wshadow -Wpointer-arith \
		   -Wcast-align -Wwrite-strings \
		   -Wconversion -Wstrict-prototypes \
		   -D_FORTIFY_SOURCE=2 \
		   -fstack-protector-strong \
		   -fPIE \
		   $(CFLAGS_EXTRA) \
		   $(DEFS)

LDFLAGS := -lssl -lcrypto -pie $(LDFLAGS_EXTRA)

TARGET  := TCP_Server
SRCS    := TCP_Server.c
PREFIX  := /usr/local/bin

all: $(TARGET)
	@echo "Using GCC: $$($(CC) --version | head -n 1)"
	@echo "Selected C standard: $(CSTD)"
	@echo "$(TLS_MSG)"
	@echo "$(DEBUG_MSG)"
	@echo "OpenSSL: $$($(CC) -E -x c /dev/null 2>/dev/null >/dev/null && openssl version || echo not found)"

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET) $(LDFLAGS)

install: $(TARGET)
	install -m 755 $(TARGET) $(PREFIX)
	@echo "Installed to: $(PREFIX)"

clean:
	rm -f $(TARGET)
