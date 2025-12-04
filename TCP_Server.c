#if !defined( _DEFAULT_SOURCE )
#define _DEFAULT_SOURCE     /* request GNU extensions */
#endif // of !defined( _DEFAULT_SOURCE )

#if !defined( _POSIX_C_SOURCE )
#define _POSIX_C_SOURCE 200809L
#endif // of !defined( _POSIX_C_SOURCE )

#if !defined( _XOPEN_SOURCE )
#define _XOPEN_SOURCE 700    /* Required on some systems for addrinfo */
#endif // of !defined( _XOPEN_SOURCE )

/* Networking + address resolution */
#include <netdb.h>        /* struct addrinfo, getaddrinfo(), freeaddrinfo(), gai_strerror() */
#include <arpa/inet.h>    /* sockaddr conversions, AF_INET, AF_INET6, inet_pton() */
#include <sys/time.h>     /* struct timeval */
#include <signal.h>       /* Signals + process */
#include <sys/select.h>   /* FD_* macros if used later */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>   /* Required for socket functions like socket(), connect(), etc. */
#include <sys/types.h>
#include <unistd.h>       /* Required for close() */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <netinet/tcp.h>
#include <time.h>
#include <ctype.h>
#include <fcntl.h>        /* fcntl, FD_CLOEXEC */
#include <pwd.h>          /* getpwnam(), struct passwd           */
#include <sys/resource.h> /* setrlimit(), struct rlimit          */
#include <sys/stat.h>     /* For jail directory permissions etc. */

/*
===============================================================================
BUILD CONFIGURATION, MODE SELECTION, AND LOGGING
===============================================================================

This section is intentionally placed at the very top of the translation unit so
that any misuse of build flags or logging macros fails fast at compile time.

Build modes (selected via Makefile → GCC -D defines):

    - DEV build:
        __DEV__   defined
        __BENCH__ not defined
        (optional) MODE_SAN defined automatically here unless explicitly set

        Intended use:
            - Development and debugging
            - Sanitizers enabled via Makefile (e.g. -fsanitize=address,undefined)
            - Logging may include WARN / INFO / DEBUG if corresponding
              __LOG_ENABLE_* macros are defined.

    - BENCH build:
        __BENCH__ defined
        __DEV__   not defined

        Intended use:
            - Performance / benchmarking
            - Optimized build
            - DEBUG logging is forbidden to avoid disturbing timing.

    - PROD build (default):
        Neither __DEV__ nor __BENCH__ is defined.
        (This block sets __PROD__ internally as a convenience macro.)

        Intended use:
            - Hardened deployment mode
            - Minimal logging; DEBUG logging forbidden.

Mode selection is controlled ONLY via the Makefile. The C file never defines
__DEV__ / __BENCH__ directly; it merely validates and interprets them.

Valid final mode states are:

    - DEV build:   __DEV__   defined, __BENCH__ not defined
    - BENCH build: __BENCH__ defined, __DEV__   not defined
    - PROD build:  neither __DEV__ nor __BENCH__ defined (treated as PROD)

Any build that defines both __DEV__ and __BENCH__ at the same time is invalid.

-------------------------------------------------------------------------------
TLS Feature Selection (__ENABLE_MUTUAL_TLS__)
-------------------------------------------------------------------------------

    - If __ENABLE_MUTUAL_TLS__ is undefined:
          Mutual TLS is disabled (server authenticates itself only).

    - If __ENABLE_MUTUAL_TLS__ is defined:
          Client certificate authentication is required; the TLS context
          is configured accordingly (CA list, verify depth, etc.).

-------------------------------------------------------------------------------
Logging flags (from Makefile only)
-------------------------------------------------------------------------------

The following preprocessor symbols may be passed from the Makefile:

    -D__LOG_ENABLE_WARN__
    -D__LOG_ENABLE_INFO__
    -D__LOG_ENABLE_DEBUG__

Rules enforced here:

    - __LOG_ENABLE_DEBUG__ is only allowed when __DEV__ is defined.
      (DEBUG logging is forbidden in PROD and BENCH builds.)

    - WARN and INFO are always allowed in any mode. The Makefile may also
      provide a convenience flag (e.g. LOG_ALL=1) that expands to WARN+INFO.
      If LOG_ALL ever attempts to enable DEBUG in PROD/BENCH, this block
      will reject it at compile time.

In addition, the Makefile should reject invalid combinations early, e.g.:

    - make PROD=1 DEBUG=1   → error: "DEBUG is not allowed in PROD builds"
    - make BENCH=1 DEBUG=1  → error: "DEBUG is not allowed in BENCH builds"
    - make DEV=1 BENCH=1    → error: "DEV and BENCH cannot be enabled together"

This C block provides a second line of defense if the Makefile is bypassed.

===============================================================================
*/

/* ============================================================================
 * Build Mode Validation and Selection
 * ============================================================================
 */

#if defined(__DEV__) && defined(__BENCH__)
#error "__DEV__ and __BENCH__ must not both be defined (mode conflict)."
#endif

#if defined(__DEV__)
    #define MODE_NAME "DEV"
#elif defined(__BENCH__)
    #define MODE_NAME "BENCH"
#else
    /* Neither DEV nor BENCH: treat as PROD (secure default) */
    #define __PROD__ 1
    #define MODE_NAME "PROD"
#endif

/* ============================================================================
 * Auto-enable sanitizers in DEV (if not explicitly overridden)
 * ============================================================================
 */
#if defined(__DEV__) && !defined(MODE_SAN)
    #define MODE_SAN 1
#endif

/*
 * At this point:
 *   - Exactly one of: (__DEV__, __BENCH__, __PROD__) is logically active.
 *   - MODE_NAME is a human-readable string for logging / banners.
 *   - MODE_SAN may be used to gate sanitizer-specific logic if needed.
 */

/* ============================================================================
 * Logging Sub-Flag Enforcement
 * ============================================================================
 *
 * DEBUG logging is strictly restricted to DEV builds.
 * If __LOG_ENABLE_DEBUG__ is set without __DEV__, this is a hard error.
 */

#if defined(__LOG_ENABLE_DEBUG__) && !defined(__DEV__)
#error "DEBUG logging is only allowed in __DEV__ builds. Remove __LOG_ENABLE_DEBUG__ or build with DEV=1."
#endif

/* ============================================================================
 * Logging Helpers and Implementations
 * ============================================================================
 */

/* Print directly to output if the calling macro permits it */
#define LOG_PRINT_STD(stream, prefix, fmt, ...) \
    do { \
        fprintf((stream), prefix fmt "\n", ##__VA_ARGS__); \
        fflush((stream)); \
    } while (false)

/* Base error logger: always enabled */
#define LOG_ERROR(fmt, ...) \
    LOG_PRINT_STD(stderr, "[ERROR] ", fmt, ##__VA_ARGS__)

/* WARN logger: enabled only if explicitly requested */
#ifdef __LOG_ENABLE_WARN__
    #define LOG_WARN(fmt, ...) \
        LOG_PRINT_STD(stderr, "[WARN ] ", fmt, ##__VA_ARGS__)
#else
    #define LOG_WARN(fmt, ...) \
        do {} while (0)
#endif

/* INFO logger: enabled only if explicitly requested */
#ifdef __LOG_ENABLE_INFO__
    #define LOG_INFO(fmt, ...) \
        LOG_PRINT_STD(stdout, "[INFO ] ", fmt, ##__VA_ARGS__)
#else
    #define LOG_INFO(fmt, ...) \
        do {} while (0)
#endif

/*
 * DEBUG logger:
 *   - Only compiled in when both __DEV__ and __LOG_ENABLE_DEBUG__ are defined.
 *   - Otherwise becomes a no-op.
 */
#if defined(__DEV__) && defined(__LOG_ENABLE_DEBUG__)
    #define LOG_DEBUG(fmt, ...) \
        LOG_PRINT_STD(stdout, "[DEBUG] ", fmt, ##__VA_ARGS__)
#else
    #define LOG_DEBUG(fmt, ...) \
        do {} while (0)
#endif

/*
 * Convenience logger that appends strerror_r text for the current errno.
 * Uses POSIX strerror_r semantics; falls back to "errno N" if needed.
 */
#define LOG_ERROR_ERRNO(fmt, ...) \
    do { \
        char errbuf[512]; \
        const char *errstr = errbuf; \
        int __e = errno; \
        if (0 != strerror_r(__e, errbuf, sizeof(errbuf))) { \
            snprintf(errbuf, sizeof(errbuf), "errno %d", __e); \
        } \
        LOG_ERROR(fmt ": %s", ##__VA_ARGS__, errstr); \
    } while (0)

/**
===============================================================================
@file   TCP_Server.c
@brief  Hardened TLS Server (default) with Configurable Build Security Modes

Default build behavior (when running plain "make"):

    - PROD mode (hardened security, minimal logs).
    - Mutual TLS enabled (TLS=1, client certificate required).
    - Strict HTTP Host enforcement using RV_ALLOWED_HOST.
    - TLS listener on TCP port 443 (standard HTTPS/TLS port).

User-configurable build-time security modes and options:

    - Security mode:
        * PROD  (default, hardened deployment)
        * DEV   (debugging and sanitizers)
        * BENCH (performance benchmarking)

    - TLS authentication:
        * TLS=1: mutual TLS (client certificate required)
        * TLS=0: server-auth TLS only (no client certificate requested)

    - Logging visibility:
        * WARN, INFO, DEBUG enabled/disabled via Make flags,
          subject to strict per-mode policy (DEBUG forbidden in PROD/BENCH).

The final server binary is fully user configurable at build time via the
Makefile flags, with the default configuration being a hardened PROD TLS
server with strict host enforcement.

===============================================================================
BUILD MODES (MAKEFILE-CONTROLLED)
===============================================================================

Mode precedence (highest to lowest):

    1) BENCH=1   -> BENCH mode
    2) PROD=0    -> DEV mode
    3) Otherwise -> PROD mode (default)

Effective compile-time state:

    - DEV build:   __DEV__ is defined; __BENCH__ is not defined.
    - BENCH build: __BENCH__ is defined; __DEV__ is not defined.
    - PROD build:  neither __DEV__ nor __BENCH__ is defined (treated as PROD).

TLS is ALWAYS enabled in all modes (no plain TCP).

-------------------------------------------------------------------------------
TLS selection (via Makefile)
-------------------------------------------------------------------------------

    TLS=1 (default):
        - Mutual TLS (client certificate required).
        - Server certificate is presented to the client.
        - Client certificate must be presented and validated.
        - Hostname verification uses TLS SNI / certificate SAN.
        - Compile-time: __ENABLE_MUTUAL_TLS__ defined.

    TLS=0:
        - Server-auth TLS only (no client certificate requested).
        - Server certificate is validated by the client.
        - TLS encryption is still enforced; only mutual authentication is
          disabled.
        - Compile-time: __ENABLE_MUTUAL_TLS__ not defined.

All modes listen on TCP port 443 by default. Binding to port 443 normally
requires starting as root and then dropping privileges.

-------------------------------------------------------------------------------
Mode capabilities summary
-------------------------------------------------------------------------------

Mode | TLS (0/1) | Client Cert (TLS=1) | Logging Allowed            | Host Enforcement            | Typical Use
-----+-----------+---------------------+----------------------------+-----------------------------+--------------------------
PROD |   0 or 1  | Required when TLS=1 | ERROR + optional WARN/INFO | Strict reject on mismatch   | Hardened deployment
DEV  |   0 or 1  | Required when TLS=1 | ERROR/WARN/INFO/DEBUG/ALL  | Warning only (no reject)    | Development and debugging
BENCH|   0 or 1  | Required when TLS=1 | ERROR + optional WARN/INFO | Logged only, no reject      | Performance benchmarking

===============================================================================
FEATURES BY MODE (TLSH, LOGS, ASAN, TIMING, SANDBOX)
===============================================================================

Legend:
    TLSH   : TLS is always enabled (1 = enabled)
    Logs*  : Logs selectable via WARN / INFO / DEBUG flags (and LOG_ALL in DEV)
    ASan   : Address/Undefined sanitizers enabled (via Makefile flags)
    Timing : Optimized for stable timing (1) or debug (0)
    Sandbox: chroot + privilege drop required/enabled

Mode (rows) vs Feature (columns):

    Mode / Feature ->  TLSH  Logs*  ASan  Timing  Sandbox
    -----------------------------------------------------
    PROD (default)   1     sel    0     1       1
    DEV              1     sel    1     0       0
    BENCH            1     sel    0     0       1
    -----------------------------------------------------

Interpretation:

    - TLSH = 1 in all modes: TLS is never disabled.
    - Logs* "sel" means WARN/INFO/DEBUG are controlled via compile-time flags.
    - ASan enabled only in DEV (via Makefile: -fsanitize=address,undefined).
    - Timing:
        PROD  : Optimized with hardening.
        DEV   : Instrumented and non-optimized (not suitable for timing).
        BENCH : Optimized, minimal logs to avoid measurement distortion.
    - Sandbox:
        PROD/BENCH: use chroot + privilege drop.
        DEV      : no chroot / privilege drop for easier debugging.

===============================================================================
LOGGING ENFORCEMENT BY MODE
===============================================================================

Legend:
    "1"   : Always enabled.
    "0"   : Always disabled.
    "0/1" : Enabled or disabled depending on compile-time log flags.

Mode / Log-level matrix:

    Mode / Log ->   ERROR  WARN  INFO  DEBUG
    ----------------------------------------
    PROD (default)   1     0/1   0/1   0
    PROD (allowed)   1     1     1     0   (WARN and INFO only if requested)
    DEV              1     0/1   0/1   0/1
    BENCH            1     0/1   0/1   0
    ----------------------------------------

Log request macros (provided via Makefile -> GCC -D):

    -D__LOG_ENABLE_WARN__
    -D__LOG_ENABLE_INFO__
    -D__LOG_ENABLE_DEBUG__   (allowed only in DEV builds)
    LOG_ALL=1                (Makefile expands this to WARN+INFO+DEBUG in DEV)

Hard denials:

    - DEBUG logs are never allowed in PROD or BENCH builds.
    - If __LOG_ENABLE_DEBUG__ is defined without __DEV__, a compile-time
      error is raised by this file.

===============================================================================
VALID MAKE COMMANDS (TOTAL 34 SUPPORTED COMBINATIONS)
===============================================================================

PROD builds (PROD=1, DEBUG and LOG_ALL not allowed):

    make PROD=1 TLS=1
    make PROD=1 TLS=0
    make PROD=1 TLS=1 WARN=1
    make PROD=1 TLS=1 INFO=1
    make PROD=1 TLS=1 WARN=1 INFO=1
    make PROD=1 TLS=0 WARN=1
    make PROD=1 TLS=0 INFO=1
    make PROD=1 TLS=0 WARN=1 INFO=1

DEV builds (PROD=0, all logging flags allowed):

    make PROD=0 TLS=1
    make PROD=0 TLS=0
    make PROD=0 TLS=1 WARN=1
    make PROD=0 TLS=0 WARN=1
    make PROD=0 TLS=1 INFO=1
    make PROD=0 TLS=0 INFO=1
    make PROD=0 TLS=1 WARN=1 INFO=1
    make PROD=0 TLS=0 WARN=1 INFO=1
    make PROD=0 TLS=1 DEBUG=1
    make PROD=0 TLS=0 DEBUG=1
    make PROD=0 TLS=1 WARN=1 DEBUG=1
    make PROD=0 TLS=0 WARN=1 DEBUG=1
    make PROD=0 TLS=1 INFO=1 DEBUG=1
    make PROD=0 TLS=0 INFO=1 DEBUG=1
    make PROD=0 TLS=1 WARN=1 INFO=1 DEBUG=1
    make PROD=0 TLS=0 WARN=1 INFO=1 DEBUG=1
    make PROD=0 TLS=1 LOG_ALL=1
    make PROD=0 TLS=0 LOG_ALL=1

BENCH builds (BENCH=1, DEBUG and LOG_ALL not allowed):

    make BENCH=1 TLS=1
    make BENCH=1 TLS=0
    make BENCH=1 TLS=1 WARN=1
    make BENCH=1 TLS=0 WARN=1
    make BENCH=1 TLS=1 INFO=1
    make BENCH=1 TLS=0 INFO=1
    make BENCH=1 TLS=1 WARN=1 INFO=1
    make BENCH=1 TLS=0 WARN=1 INFO=1

Any other combination of PROD / BENCH / TLS / WARN / INFO / DEBUG / LOG_ALL
is considered invalid and should fail at Makefile or compile time.

Total valid build combinations: 34.

===============================================================================
CONFIGURATION MAPPING (MAKE vs DIRECT gcc -D... USAGE)
===============================================================================

This server is intended to be built via the Makefile. The Makefile ensures:

    - Exactly one mode is selected: PROD / DEV / BENCH.
    - TLS mode (TLS=0 / TLS=1) is correctly mapped to __ENABLE_MUTUAL_TLS__.
    - Logging macros (__LOG_ENABLE_WARN__/INFO/DEBUG) are consistent with mode.
    - RV_ALLOWED_HOST is set to the correct value per mode.
    - Hardened compiler/linker flags are applied for PROD and BENCH builds.

However, for debugging, experimentation, or when integrating with other build
systems, it can be useful to know how a given "make" configuration maps onto
an equivalent direct "gcc -D..." command.

Important rules:

    - The Makefile builds are the canonical, hardened builds.
    - Direct gcc examples below are approximate and do NOT include all
      hardening flags (RELRO, FORTIFY, PIE, etc.).
    - Direct gcc builds should NOT be used for production deployment.

Each configuration below is described as:

    Configuration:
        Make command:
            ...
        Equivalent gcc command:
            ...
        Why equivalent:
            ...
        Security note:
            ...

-------------------------------------------------------------------------------
1) PROD mode, TLS=1 (mutual TLS), WARN+INFO logs enabled
-------------------------------------------------------------------------------

Configuration:
    PROD mode (hardened), mutual TLS required, WARN+INFO logs enabled.

Make command (recommended):

    make PROD=1 TLS=1 WARN=1 INFO=1

Equivalent gcc command (approximate):

    gcc TCP_Server.c -o TCP_Server \
        -D__ENABLE_MUTUAL_TLS__ \
        -DRV_ALLOWED_HOST=\"secure.lab.linux\" \
        -D__LOG_ENABLE_WARN__ \
        -D__LOG_ENABLE_INFO__ \
        -std=c2x \
        -Wall -Wextra -Werror -Wpedantic \
        -Wformat=2 -Wshadow -Wpointer-arith \
        -Wcast-align -Wwrite-strings -Wconversion \
        -O2 \
        -lssl -lcrypto

Why equivalent:

    - PROD mode: neither __DEV__ nor __BENCH__ is defined.
    - TLS=1 maps to __ENABLE_MUTUAL_TLS__.
    - WARN=1 and INFO=1 map to __LOG_ENABLE_WARN__ and __LOG_ENABLE_INFO__.
    - RV_ALLOWED_HOST is set to "secure.lab.linux" as in the Makefile defaults.

Security note:

    - This gcc example does not enable all the hardening flags that the
      Makefile may add (such as full RELRO, PIE, stack protections).
    - Use the Makefile build for real deployments.

-------------------------------------------------------------------------------
2) PROD mode, TLS=0 (server-auth only), WARN logs only
-------------------------------------------------------------------------------

Configuration:
    PROD mode, server-auth TLS only, WARN logs enabled (no mutual TLS).

Make command:

    make PROD=1 TLS=0 WARN=1

Equivalent gcc command:

    gcc TCP_Server.c -o TCP_Server \
        -DRV_ALLOWED_HOST=\"secure.lab.linux\" \
        -D__LOG_ENABLE_WARN__ \
        -std=c2x \
        -Wall -Wextra -Werror -Wpedantic \
        -Wformat=2 -Wshadow -Wpointer-arith \
        -Wcast-align -Wwrite-strings -Wconversion \
        -O2 \
        -lssl -lcrypto

Why equivalent:

    - __ENABLE_MUTUAL_TLS__ is not defined (TLS=0).
    - WARN logs are enabled via __LOG_ENABLE_WARN__.
    - Host enforcement for PROD is still strict: HTTP Host must match
      RV_ALLOWED_HOST.

Security note:

    - Server still uses TLS on port 443, but does not require client
      certificates.
    - Hardened deployment should still use the Makefile build.

-------------------------------------------------------------------------------
3) DEV mode, TLS=1 (mutual TLS), all logs enabled (LOG_ALL)
-------------------------------------------------------------------------------

Configuration:
    DEV mode, mutual TLS, WARN + INFO + DEBUG logs enabled.

Make command:

    make PROD=0 TLS=1 LOG_ALL=1

Equivalent gcc command:

    gcc TCP_Server.c -o TCP_Server \
        -D__DEV__ \
        -D__ENABLE_MUTUAL_TLS__ \
        -D__LOG_ENABLE_WARN__ \
        -D__LOG_ENABLE_INFO__ \
        -D__LOG_ENABLE_DEBUG__ \
        -std=c2x \
        -g3 -O0 \
        -fsanitize=address,undefined \
        -Wall -Wextra -Wpedantic \
        -Wformat=2 -Wshadow -Wpointer-arith \
        -Wcast-align -Wwrite-strings -Wconversion \
        -lssl -lcrypto

Why equivalent:

    - PROD=0 maps to __DEV__ (DEV mode).
    - TLS=1 maps to __ENABLE_MUTUAL_TLS__.
    - LOG_ALL=1 in the Makefile expands to all three __LOG_ENABLE_* macros.
    - DEV builds enable sanitizers and debug information.

Security note:

    - DEV builds are not hardened for production (sanitizers, no chroot, no
      privilege drop).
    - Intended only for development and debugging.

-------------------------------------------------------------------------------
4) DEV mode, TLS=0 (server-auth only), DEBUG-only logging
-------------------------------------------------------------------------------

Configuration:
    DEV mode, TLS=0 (no mutual TLS), DEBUG logging enabled (no WARN/INFO).

Make command:

    make PROD=0 TLS=0 DEBUG=1

Equivalent gcc command:

    gcc TCP_Server.c -o TCP_Server \
        -D__DEV__ \
        -D__LOG_ENABLE_DEBUG__ \
        -std=c2x \
        -g3 -O0 \
        -fsanitize=address,undefined \
        -Wall -Wextra -Wpedantic \
        -Wformat=2 -Wshadow -Wpointer-arith \
        -Wcast-align -Wwrite-strings -Wconversion \
        -lssl -lcrypto

Why equivalent:

    - DEV mode is selected with __DEV__.
    - No __ENABLE_MUTUAL_TLS__ means TLS=0 (still encrypted, no client certs).
    - DEBUG=1 maps to __LOG_ENABLE_DEBUG__.
    - Sanitizers and debug info reflect DEV mode.

Security note:

    - DEBUG logging may expose internal data and is never allowed in PROD or
      BENCH builds.
    - Use only in safe development environments.

-------------------------------------------------------------------------------
5) BENCH mode, TLS=1 (mutual TLS), INFO logs only
-------------------------------------------------------------------------------

Configuration:
    BENCH mode, TLS=1, INFO logs enabled only.

Make command:

    make BENCH=1 TLS=1 INFO=1

Equivalent gcc command:

    gcc TCP_Server.c -o TCP_Server \
        -D__BENCH__ \
        -D__ENABLE_MUTUAL_TLS__ \
        -DRV_ALLOWED_HOST=\"127.0.0.1\" \
        -D__LOG_ENABLE_INFO__ \
        -std=c2x \
        -O2 \
        -Wall -Wextra -Wpedantic \
        -Wformat=2 -Wshadow -Wpointer-arith \
        -Wcast-align -Wwrite-strings -Wconversion \
        -lssl -lcrypto

Why equivalent:

    - BENCH=1 maps to __BENCH__, with neither __DEV__ nor __PROD__ defined.
    - TLS=1 maps to __ENABLE_MUTUAL_TLS__.
    - INFO=1 maps to __LOG_ENABLE_INFO__.
    - RV_ALLOWED_HOST is typically 127.0.0.1 for BENCH builds.

Security note:

    - BENCH mode aims for realistic performance with minimal logging.
    - DEBUG logging is forbidden to avoid affecting timing measurements.

-------------------------------------------------------------------------------
6) BENCH mode, TLS=0 (server-auth only), WARN logs only
-------------------------------------------------------------------------------

Configuration:
    BENCH mode, TLS=0, WARN logs enabled.

Make command:

    make BENCH=1 TLS=0 WARN=1

Equivalent gcc command:

    gcc TCP_Server.c -o TCP_Server \
        -D__BENCH__ \
        -DRV_ALLOWED_HOST=\"127.0.0.1\" \
        -D__LOG_ENABLE_WARN__ \
        -std=c2x \
        -O2 \
        -Wall -Wextra -Wpedantic \
        -Wformat=2 -Wshadow -Wpointer-arith \
        -Wcast-align -Wwrite-strings -Wconversion \
        -lssl -lcrypto

Why equivalent:

    - __BENCH__ selects BENCH mode.
    - No __ENABLE_MUTUAL_TLS__ corresponds to TLS=0 (still TLS, no client
      certificates).
    - WARN=1 maps to __LOG_ENABLE_WARN__.

Security note:

    - These builds are for benchmarking. Use the Makefile and avoid adding
      DEBUG logs or extra diagnostics which would distort measurements.

-------------------------------------------------------------------------------
7) Minimal examples (summary)
-------------------------------------------------------------------------------

Minimal PROD, mutual TLS, no extra logs:

    make PROD=1 TLS=1

Approximate gcc:

    gcc TCP_Server.c -o TCP_Server \
        -D__ENABLE_MUTUAL_TLS__ \
        -DRV_ALLOWED_HOST=\"secure.lab.linux\" \
        -std=c2x -O2 \
        -Wall -Wextra -Wpedantic \
        -Wformat=2 -Wshadow -Wpointer-arith \
        -Wcast-align -Wwrite-strings -Wconversion \
        -lssl -lcrypto

Minimal DEV, server-auth only, no extra logs:

    make PROD=0 TLS=0

Approximate gcc:

    gcc TCP_Server.c -o TCP_Server \
        -D__DEV__ \
        -std=c2x \
        -g3 -O0 \
        -fsanitize=address,undefined \
        -Wall -Wextra -Wpedantic \
        -Wformat=2 -Wshadow -Wpointer-arith \
        -Wcast-align -Wwrite-strings -Wconversion \
        -lssl -lcrypto

Minimal BENCH, mutual TLS, no extra logs:

    make BENCH=1 TLS=1

Approximate gcc:

    gcc TCP_Server.c -o TCP_Server \
        -D__BENCH__ \
        -D__ENABLE_MUTUAL_TLS__ \
        -DRV_ALLOWED_HOST=\"127.0.0.1\" \
        -std=c2x \
        -O2 \
        -Wall -Wextra -Wpedantic \
        -Wformat=2 -Wshadow -Wpointer-arith \
        -Wcast-align -Wwrite-strings -Wconversion \
        -lssl -lcrypto

Again, for any deployment, use the Makefile-based builds. The gcc examples
are only provided to clarify which -D macros and flags correspond to which
Makefile configurations.

===============================================================================
HOST ENFORCEMENT AND ALLOWED HOSTS
===============================================================================

The Makefile sets RV_ALLOWED_HOST at compile time, using:

    PROD_HOST  ?= secure.lab.linux
    DEV_HOST   ?= localhost
    BENCH_HOST ?= 127.0.0.1

and then:

    PROD  build  -> RV_ALLOWED_HOST = $(PROD_HOST)
    DEV   build  -> RV_ALLOWED_HOST = $(DEV_HOST)
    BENCH build  -> RV_ALLOWED_HOST = $(BENCH_HOST)

Runtime behavior:

    PROD  builds:
        - HTTP "Host" header must match RV_ALLOWED_HOST exactly.
        - On mismatch, the server returns HTTP 400 "Host not allowed!".

    DEV   builds:
        - Host mismatch is logged as a warning but the request is still allowed.

    BENCH builds:
        - Host is logged for visibility but never enforced.

TLS hostname verification:

    - When TLS=1 (mutual TLS), TLS-layer hostname verification is enabled.
    - When TLS=0, only HTTP-level Host checks (as above) apply.

===============================================================================
TESTING GUIDE (OPENSSL S_CLIENT EXAMPLES, PORT 443)
===============================================================================

All examples assume:

    - Server listens on port 443.
    - Server certificate:    cert.pem
    - Server private key:    key.pem
    - CA bundle on both sides: ca-cert.pem

DEV mode, TLS=1 (mutual TLS, all logs enabled):

    Build:

        make PROD=0 TLS=1 LOG_ALL=1

    Test:

        openssl s_client -connect 127.0.0.1:443 \
            -servername localhost \
            -cert client-cert.pem -key client-key.pem \
            -CAfile ca-cert.pem -crlf -tls1_3

    HTTP request:

        GET / HTTP/1.1
        Host: localhost

        <press Enter twice to complete headers>

    Expected:

        - TLS handshake succeeds if client certificate is valid and trusted.
        - HTTP/1.1 200 OK is returned.
        - If Host is not "localhost", a warning is logged, but request proceeds.

PROD mode, TLS=1 (mutual TLS, strict host enforcement):

    Build:

        make PROD=1 TLS=1 WARN=1 INFO=1

    Test:

        openssl s_client -connect 127.0.0.1:443 \
            -servername secure.lab.linux \
            -cert client-cert.pem -key client-key.pem \
            -CAfile ca-cert.pem -crlf -tls1_3

    HTTP request:

        GET / HTTP/1.1
        Host: secure.lab.linux

        <press Enter twice to complete headers>

    Expected:

        - TLS handshake succeeds only if:
            * client-cert.pem chains to ca-cert.pem, and
            * the server certificate SAN/CN matches "secure.lab.linux".
        - HTTP/1.1 200 OK is returned.
        - If Host does not match RV_ALLOWED_HOST, the server returns HTTP 400.

BENCH mode, TLS=0 (server-auth TLS, minimal logging):

    Build:

        make BENCH=1 TLS=0 INFO=1

    Test:

        openssl s_client -connect 127.0.0.1:443 \
            -servername 127.0.0.1 \
            -CAfile ca-cert.pem -crlf -tls1_3

    HTTP request:

        GET / HTTP/1.1
        Host: 127.0.0.1

        <press Enter twice to complete headers>

    Expected:

        - TLS handshake succeeds using server certificate only.
        - Client certificate is not requested.
        - Host header is logged, but not enforced.

Negative tests (expected failures):

    1) Missing client certificate with TLS=1:
        - Build with TLS=1.
        - Run s_client without -cert/-key.
        - Handshake must fail due to missing client auth.

    2) Wrong -servername with TLS=1:
        - Supply a name not present in server certificate SAN/CN.
        - TLS hostname verification must fail.

    3) Wrong Host header in PROD:
        - Use Host different from RV_ALLOWED_HOST.
        - Response must be HTTP 400 "Host not allowed!".

===============================================================================
RUNTIME SAFETY AND SHUTDOWN BEHAVIOR
===============================================================================

Signals and termination:

    - SIGINT, SIGTERM, SIGQUIT, SIGTSTP are trapped.
    - SIGTSTP (Ctrl+Z) is treated as a request to terminate, not to suspend.
    - On termination, the server:
        * shuts down the TLS connection,
        * closes client and listening sockets,
        * frees SSL objects and address info,
        * logs a final termination message.

Sandboxing (PROD and BENCH):

    - The process should start with sufficient privileges to:
        * bind port 443,
        * chroot into a restricted directory (for example: /var/secure-tls-server),
        * drop privileges to an unprivileged account (for example: www-data).

    - Certificate and key files should be placed inside the chroot and owned
      by root:root with strict permissions (for example: 750).

DEV builds:

    - No chroot or privilege drop is used (to simplify debugging).
    - Sanitizers are enabled via Makefile flags (ASan, UBSan).

===============================================================================
SYSTEM PREREQUISITES AND WHY THEY ARE REQUIRED
===============================================================================

Compiler requirements:

    Minimum required:
        - GCC 13 and g++ 13 or newer.

    Recommended:
        - Install the latest stable GCC and g++ versions available in your
          distribution repositories (for example: GCC 15 and g++ 15 if
          available).

    Rule:
        - Choose a single GCC major version V >= 13 (for example 13 or 15)
          and use that same V consistently in all commands below:
              gcc-V, g++-V, /usr/bin/gcc-V, /usr/bin/g++-V.

    Reason:
        - This project uses C23 features and modern security hardening flags.
          Earlier compilers (such as GCC 11 or below, commonly installed by
          default in many systems) will fail during compilation or lack
          required diagnostics.

Check current GCC version:

    gcc --version

If gcc < 13, upgrade toolchain as follows. In all commands below, replace
"<V>" with the major version you are installing (for example 13 or 15).

Step 1: enable access to recent toolchains:

    sudo apt install software-properties-common
    sudo add-apt-repository ppa:ubuntu-toolchain-r/test
    sudo apt update

    software-properties-common:
        - Provides add-apt-repository utility.
    add-apt-repository / apt update:
        - Enable and refresh the toolchain PPA for newer GCC.

Step 2: install compilers and essential build tools (using your chosen <V>):

    sudo apt install gcc-<V> g++-<V>
    sudo apt install build-essential apt-file openssl libssl-dev
    sudo apt-file update

    gcc-<V>, g++-<V>:
        - Required compilers (C23 features used in this project).
        - Examples:
            * Minimum: gcc-13 g++-13
            * Newer:   gcc-15 g++-15 (if available on your system)
    build-essential:
        - Installs make, linker, and C runtime headers.
    apt-file, apt-file update:
        - Allows searching which package provides a missing header/library.
    openssl:
        - Provides openssl CLI tools (including s_client) for testing.
    libssl-dev:
        - Provides OpenSSL headers and libraries required for compilation.

Step 3: select GCC <V> as the default compiler:

    sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-<V> 100
    sudo update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-<V> 100
    sudo update-alternatives --config gcc

    update-alternatives:
        - Ensures gcc and g++ invoke the chosen GCC version <V> by default.
        - Use the same <V> here that you installed in the previous step.

Examples:

    Minimum supported (V=13):

        sudo apt install gcc-13 g++-13
        sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-13 100
        sudo update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-13 100

    Newer toolchain (V=15, if available):

        sudo apt install gcc-15 g++-15
        sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-15 100
        sudo update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-15 100

Optional: build a recent OpenSSL from source if system OpenSSL is too old:

    mkdir ~/openssl_3_5
    cd ~/openssl_3_5
    wget https://github.com/openssl/openssl/releases/download/openssl-3.5.4/openssl-3.5.4.tar.gz
    tar xzvf openssl-3.5.4.tar.gz
    cd openssl-3.5.4
    ./config
    make
    sudo make install
    openssl version -a

Purpose:

    - Guarantees a recent OpenSSL 3.x version with modern TLS 1.3 support.
    - Avoids limitation of older distributions with outdated libssl.

Troubleshooting system packages:

    sudo apt list --upgradable
    sudo apt full-upgrade

    - Use these to bring system packages up to date.

If apt repeatedly warns about snapd:

    sudo apt-get --simulate install snapd
    sudo apt-get install snapd

    - These clear pending snapd-related upgrade warnings, if present.
    - They do not affect the TLS server itself but keep the package manager
      in a consistent state.

Summary of installed packages and commands:

    software-properties-common   -> Needed for add-apt-repository
    add-apt-repository           -> Adds toolchain PPA for GCC upgrades
    apt update                   -> Refreshes package index
    gcc-<V>, g++-<V> (V >= 13)   -> Required compilers for C23 code
    build-essential              -> Core build toolkit (make, ld, headers)
    apt-file, apt-file update    -> Helps locate missing headers/libraries
    openssl, libssl-dev          -> Runtime and development support for TLS
    update-alternatives ...      -> Switches system to chosen GCC <V> by default
    make / sudo make install     -> Builds and installs OpenSSL from source
    openssl version -a           -> Verifies installed OpenSSL version
    apt list / full-upgrade      -> Resolves outdated or missing packages
    apt-get ... snapd            -> Cleans up snapd warnings if necessary

===============================================================================
DIRECT GCC BUILD (DEVELOPER ONLY, NOT HARDENED)
===============================================================================

The recommended way to build is via the Makefile, using one of the 34 valid
make commands described above. Direct gcc commands should only be used for
quick local tests.

1) Simple functional test (no extra hardening):

    gcc TCP_Server.c -o TCP_Server -lssl -lcrypto

2) Closer to PROD-style warnings and optimisation:

    gcc -std=c2x TCP_Server.c -o TCP_Server \
        -Wall -Wextra -Werror -Wpedantic \
        -Wformat=2 -Wshadow -Wpointer-arith \
        -Wcast-align -Wwrite-strings -Wconversion \
        -O2 \
        -lssl -lcrypto

These direct builds:

    - Do NOT apply the full hardening that the Makefile adds.
    - Do NOT enforce the same mode, logging, and host policies automatically.
    - Should NOT be used for hardened deployment.

For real deployments or benchmarks, always use the Makefile with a valid
(PROD / DEV / BENCH, TLS, and logging) combination.

===============================================================================
@section security_compliance Security Compliance Summary (S16)
===============================================================================

This software is designed for hardened operational deployment only when built
using the Makefile in a valid PROD or BENCH configuration with TLS enabled
(TLS=1 or TLS=0). These Makefile builds apply:

    - Full compiler and linker security hardening flags,
    - Denial of DEBUG logging in production and benchmarking modes,
    - Strict or logged HTTP Host enforcement, and
    - Chroot and privilege drop requirements (PROD/BENCH only).

DEBUG logging, unrestricted host acceptance, or the absence of privilege and
filesystem isolation significantly reduces security posture. Therefore:

    - Any build that enables DEBUG logging outside of DEV mode, or
    - Any binary produced outside of Makefile enforcement,

shall not be deployed or executed in an operational or production environment.

DEV builds are permitted solely for development and troubleshooting and are not
authorized for deployment. All production or benchmark usage must use a valid
Makefile-controlled hardened build that meets the requirements above.

===============================================================================
END OF BUILD / TEST / SECURITY / SYSTEM REQUIREMENTS DOCUMENTATION
===============================================================================
*/

static SSL_CTX* ctx = (SSL_CTX*)NULL;
static SSL* ssl = (SSL*)NULL;
static struct addrinfo* server = (struct addrinfo*)NULL;
static int iSocketFieldDescription = -1;
static int iAcceptedClientFileDescriptor = -1;

static volatile sig_atomic_t g_exit_requested = 0;
static volatile sig_atomic_t g_last_signal = 0;

static void SignalHandler_SetExitFlag(int signum)
{
	g_exit_requested = 1;
	g_last_signal = signum;
}
/* ============================================================================
 * SAN-mode OpenSSL error handler
 * ============================================================================
 *
 * In MODE_SAN builds, we aggressively abort the process on unexpected OpenSSL
 * errors to surface issues under sanitizers as early as possible.
**/
static void rvSanAbortOnOpenSSLError(const char* where, int ssl_err)
{
#if defined(MODE_SAN)
	if ((SSL_ERROR_WANT_READ == ssl_err) ||
		(SSL_ERROR_WANT_WRITE == ssl_err) ||
		(SSL_ERROR_ZERO_RETURN == ssl_err))
	{
		return;
	}

	unsigned long ossl_err = ERR_peek_error();
	if (ossl_err != 0UL) {
		char buf[256];
		ERR_error_string_n(ossl_err, buf, sizeof(buf));
		LOG_ERROR("SAN MODE: OpenSSL error in %s (ssl_err=%d, ossl_err=%lu, msg=%s)",
			where, ssl_err, ossl_err, buf);
	}
	else {
		LOG_ERROR("SAN MODE: OpenSSL error in %s (ssl_err=%d)", where, ssl_err);
	}

	abort();
#else
	(void)where;
	(void)ssl_err;
#endif
}

static void FreeAndClose(void)
{
	if (((struct addrinfo*)NULL) != server)
	{
		LOG_INFO("Freeing Server Address Information...");
		freeaddrinfo(server);
		server = (struct addrinfo*)NULL;
	}

	if (-1 != iSocketFieldDescription)
	{
		LOG_INFO("Closing Listen Socket...");
		close(iSocketFieldDescription);
		iSocketFieldDescription = -1;
	}

	if (((SSL_CTX*)NULL) != ctx)
	{
		LOG_INFO("Freeing SSL Context...");
		SSL_CTX_free(ctx);
		ctx = (SSL_CTX*)NULL;
	}
}

static void rvShutDownSSL_AndCloseFD(void)
{
	if (((SSL*)NULL) != ssl)
	{
		int sd_ret = SSL_shutdown(ssl);

		if (0 == sd_ret)
		{
			/* Ensure bidirectional shutdown completes on some stacks */
			sd_ret = SSL_shutdown(ssl);
		}

		if (0 > sd_ret)
		{
			int sd_err = SSL_get_error(ssl, sd_ret);
			LOG_ERROR("SSL_shutdown failed, error=%d", sd_err);
			rvSanAbortOnOpenSSLError("SSL_shutdown", sd_err);
		}

		SSL_free(ssl);
		ssl = (SSL*)NULL;
	}

	if (-1 != iAcceptedClientFileDescriptor)
	{
		close(iAcceptedClientFileDescriptor);
		iAcceptedClientFileDescriptor = -1;
	}
}

/* ============================================================================
 * OS-level sandbox for PROD / BENCH
 *
 *  - In PROD and BENCH builds (no __DEV__):
 *      * The process is expected to start as root (to allow chroot + priv-drop).
 *      * After InitializeServer() binds the listening socket:
 *          - chroot() into /var/secure-tls-server
 *          - drop to www-data:www-data
 *          - apply RLIMIT_NOFILE and RLIMIT_NPROC
 *
 *  - In __DEV__ builds:
 *      * We intentionally skip this to keep debugging simple.
 *
 *  NOTE:
 *    The jail directory /var/secure-tls-server must be prepared beforehand:
 *
 *      sudo mkdir -p /var/secure-tls-server
 *      sudo cp cert.pem key.pem ca-cert.pem /var/secure-tls-server
 *      sudo chown -R root:root /var/secure-tls-server
 *      sudo chmod -R 750 /var/secure-tls-server
 * ============================================================================
**/
static bool rvDropPrivileges_AndChroot(void)
{
	bool ret = false;

	do
	{
		struct passwd* pw = getpwnam("www-data");
		if ((struct passwd*)NULL == pw)
		{
			LOG_ERROR_ERRNO("getpwnam(\"www-data\") failed");
			break;
		}

		/* Enter hardened jail. Directory must already exist and be owned by root. */
		if (0 != chroot("/var/secure-tls-server"))
		{
			LOG_ERROR_ERRNO("chroot(\"/var/secure-tls-server\") failed");
			break;
		}

		if (0 != chdir("/"))
		{
			LOG_ERROR_ERRNO("chdir(\"/\") after chroot failed");
			break;
		}

		/* Drop group first, then user */
		if (0 != setgid(pw->pw_gid))
		{
			LOG_ERROR_ERRNO("setgid(www-data) failed");
			break;
		}

		if (0 != setuid(pw->pw_uid))
		{
			LOG_ERROR_ERRNO("setuid(www-data) failed");
			break;
		}

		/* Safety check: we must no longer be root */
		if (0 == geteuid())
		{
			LOG_ERROR("Privilege drop failed, still running as root!");
			break;
		}

		LOG_INFO("Dropped privileges to www-data inside /var/secure-tls-server chroot.");
		ret = true;
	} while (false);

	return ret;
}

static void rvApplyResourceLimits(void)
{
	struct rlimit rl;

	/* Limit number of open file descriptors */
	rl.rlim_cur = 256;
	rl.rlim_max = 256;
	if (0 != setrlimit(RLIMIT_NOFILE, &rl))
	{
		LOG_ERROR_ERRNO("setrlimit(RLIMIT_NOFILE) failed");
	}

	/* Limit number of processes/threads */
	rl.rlim_cur = 64;
	rl.rlim_max = 64;
	if (0 != setrlimit(RLIMIT_NPROC, &rl))
	{
		LOG_ERROR_ERRNO("setrlimit(RLIMIT_NPROC) failed");
	}
}

static int ssl_write_all(SSL* ssl_handle, const char* buffer, int length)
{
	int ret = -1;
	int total = 0;
	const unsigned char* p = (const unsigned char*)buffer;

	do
	{
		if ((((SSL*)NULL) == ssl_handle) || (((const void*)NULL) == buffer) || (0 >= length))
		{
			LOG_ERROR("Invalid parameters in ssl_write_all");
			break;
		}

		int attempts = 0;
		const int max_attempts = 1000;

		while ((total < length) && (attempts < max_attempts))
		{
			int written = SSL_write(ssl_handle, p + total, (length - total));
			if (0 >= written)
			{
				int err = SSL_get_error(ssl_handle, written);
				if ((SSL_ERROR_WANT_READ == err) || (SSL_ERROR_WANT_WRITE == err))
				{
					attempts++;
					continue;
				}
				LOG_ERROR("SSL_write failed, error %d", err);
				rvSanAbortOnOpenSSLError("SSL_write", err);
				break;
			}
			total += written;
		}

		if ((total < length) && (attempts >= max_attempts))
		{
			LOG_ERROR("SSL_write aborted after too many retries");
		}

		if (total != length)
		{
			break;
		}

		ret = total;  /* total bytes written */
	} while (false);

	return ret; /* -1 or total bytes written. */
}

static int send_http_response(SSL* ssl_handle, int status, const char* reason, const char* body)
{
	int ret = -1;

	do
	{
		if ((((SSL*)NULL) == ssl_handle) || (((const char*)NULL) == reason) || (((const char*)NULL) == body))
		{
			LOG_ERROR("Invalid parameters in send_http_response");
			break;
		}

		const int body_len = (int)strlen(body);

		/* Format current date */
		char datebuf[128];
		time_t now = time((time_t*)NULL);
		struct tm* gmt = gmtime(&now);

		if (((struct tm*)NULL) != gmt)
		{
			(void)strftime(datebuf, sizeof(datebuf), "%a, %d %b %Y %H:%M:%S GMT", gmt);
		}
		else
		{
			/* Fallback if gmtime fails */
			(void)snprintf(datebuf, sizeof(datebuf), "Thu, 01 Jan 1970 00:00:00 GMT");
		}

		char header[512];
		int header_len = snprintf(header,
			sizeof(header),
			"HTTP/1.1 %d %s\r\n"
			"Date: %s\r\n"
			"Content-Type: text/plain\r\n"
			"Content-Length: %d\r\n"
			"Connection: close\r\n"
			"Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n"
			"X-Content-Type-Options: nosniff\r\n"
			"X-Frame-Options: DENY\r\n"
			"Referrer-Policy: no-referrer\r\n"
			"\r\n",
			status,
			reason,
			datebuf,
			body_len);

		if ((0 >= header_len) || ((int)sizeof(header) <= header_len))
		{
			LOG_ERROR("HTTP header formatting failed");
			break;
		}

		if (0 > ssl_write_all(ssl_handle, header, header_len))
		{
			LOG_ERROR("[ERROR] Failed sending HTTP header");
			break;
		}

		if (0 > ssl_write_all(ssl_handle, body, body_len))
		{
			LOG_ERROR("[ERROR] Failed sending HTTP body");
			break;
		}

		ret = 0;
	} while (false);

	return ret;
}

static bool InitializeServer(void)
{
	bool ret = false;

	do
	{
#if ( 0x10100000L > OPENSSL_VERSION_NUMBER )
		/* OpenSSL < 1.1.0 requires manual initialization */
		/* Initialize OpenSSL */
		SSL_library_init();
		OpenSSL_add_ssl_algorithms();
		SSL_load_error_strings();
#endif // of ( 0x10100000L > OPENSSL_VERSION_NUMBER )

		const SSL_METHOD* method = TLS_server_method();
		ctx = SSL_CTX_new(method);
		if (((SSL_CTX*)NULL) == ctx)
		{
			ERR_print_errors_fp(stderr);
			break;
		}

		/* Disable TLS compression (CRIME mitigation) + renegotiation */
		SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION | SSL_OP_NO_RENEGOTIATION);

		/* Load certificate and ECDSA private key (PEM files) */
		if (0 >= SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM))
		{
			LOG_ERROR("Failed to load server certificate (cert.pem)");
#if defined(__DEV__) && defined(__LOG_ENABLE_DEBUG__)
			/* Only in DEV + DEBUG: show OpenSSL error details */
			ERR_print_errors_fp(stderr);
#endif

#if !defined(__DEV__)
			/* BENCH + PROD: stop silently without debug trace */
			break;
#else
			/* DEV: PANIC with SAN-style abort */
			rvSanAbortOnOpenSSLError("SSL_CTX_use_certificate_file", SSL_ERROR_SSL);
#endif
		}

		if (0 >= SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM))
		{
			LOG_ERROR("Failed to load private key (key.pem)");
#if defined(__DEV__) && defined(__LOG_ENABLE_DEBUG__)
			/* Only in DEV + DEBUG: show OpenSSL error details */
			ERR_print_errors_fp(stderr);
#endif

#if !defined(__DEV__)
			/* BENCH + PROD: stop silently without debug trace */
			break;
#else
			/* DEV: PANIC with SAN-style abort */
			rvSanAbortOnOpenSSLError("SSL_CTX_use_PrivateKey_file", SSL_ERROR_SSL);
#endif
		}

		/* Ensure private key matches certificate */
		if (1 != SSL_CTX_check_private_key(ctx))
		{
			LOG_ERROR("Private key mismatch");
			break;
		}

#if defined( __ENABLE_MUTUAL_TLS__ )
		/* Load CA first */
		static const char CACertFileName[] = "ca-cert.pem";
		if (1 != SSL_CTX_load_verify_locations(ctx, CACertFileName, ((const char*)NULL)))
		{
			LOG_ERROR("Failed to load CA certificate for mutual TLS");

#if defined(__DEV__) && defined(__LOG_ENABLE_DEBUG__)
			ERR_print_errors_fp(stderr);
#endif

#if !defined(__DEV__)
			/* PROD/BENCH: fail silently, no OpenSSL internals leak */
			break;
#else
			/* DEV: fail securely with SAN panic */
			rvSanAbortOnOpenSSLError("SSL_CTX_load_verify_locations", SSL_ERROR_SSL);
#endif
		}
		LOG_INFO("Mutual TLS enabled: verifying client certificates using ca-cert.pem");
		/*
		 * Mutual TLS (Client Certificate Authentication)
		 * Require clients to present a certificate and verify it using our CA.
		 */
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, ((int (*)(int, X509_STORE_CTX*))NULL));
#else // of defined( __ENABLE_MUTUAL_TLS__ )
		SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, ((int (*)(int, X509_STORE_CTX*))NULL));
#endif // of defined( __ENABLE_MUTUAL_TLS__ )

#if defined( __ENABLE_MUTUAL_TLS__ )
		/* Allow intermediate chains up to depth 3 */
		SSL_CTX_set_verify_depth(ctx, 3);

		STACK_OF(X509_NAME)* ca_list = SSL_load_client_CA_file(CACertFileName);
		if (((STACK_OF(X509_NAME)*)NULL) != ca_list)
		{
			SSL_CTX_set_client_CA_list(ctx, ca_list);
		}
		else
		{
			LOG_WARN("Warning: Failed to load client CA list from %s", CACertFileName);
		}
#endif // of defined( __ENABLE_MUTUAL_TLS__ )

		/* TLS Cipher Configuration
		 *
		 * Priority: TLS 1.3 (explicitly set)
		 * Fallback: TLS 1.2 (strong AEAD + PFS)
		 */
		if (1 != SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) ||
			1 != SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION))
		{
			LOG_ERROR("Failed to set TLS protocol range");
			break;
		}

		/* Explicit TLS 1.3 cipher suites */
		if (1 != SSL_CTX_set_ciphersuites(ctx,
			"TLS_AES_256_GCM_SHA384:"
			"TLS_AES_128_GCM_SHA256:"
			"TLS_CHACHA20_POLY1305_SHA256"))
		{
			LOG_ERROR("Failed to set TLS 1.3 ciphersuites");
			break;
		}

		/* Strong TLS 1.2 fallback */
		if (1 != SSL_CTX_set_cipher_list(ctx,
			"ECDHE-ECDSA-AES256-GCM-SHA384:"
			"ECDHE-ECDSA-AES128-GCM-SHA256:"
			"ECDHE-ECDSA-CHACHA20-POLY1305"))
		{
			LOG_ERROR("Failed to set TLS 1.2 cipher list");
			break;
		}

		/* Preferring ECDSA/ECDHE curves */
		if (0 == SSL_CTX_set1_curves_list(ctx, "P-256:P-384"))
		{
			LOG_ERROR("Failed to set ECDHE curves");
			break;
		}

		/* Address resolution for IPv4 / IPv6 */
		struct addrinfo hints;
		memset(&hints, 0, sizeof(hints));
		hints.ai_flags = AI_PASSIVE;
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = 0;

		const int iGetAddInfoErrCode = getaddrinfo((const char*)NULL, (const char*)"8080", &hints, &server);
		if (0 != iGetAddInfoErrCode)
		{
			LOG_ERROR("getaddrinfo: %s", gai_strerror(iGetAddInfoErrCode));
			break;
		}

		struct addrinfo* ptrAddrInfo = server;

		/*
		 * getaddrinfo() returns a list of address structures.
		 * Try each address until we successfully bind(2).
		 * If socket(2) fails we try the next address.
		 * If bind(2) fails, we close the socket
		 * and try the next address.
		 */
		for (; ((struct addrinfo*)NULL) != ptrAddrInfo; ptrAddrInfo = ptrAddrInfo->ai_next)
		{
			iSocketFieldDescription = socket(ptrAddrInfo->ai_family, ptrAddrInfo->ai_socktype, ptrAddrInfo->ai_protocol);
			if (-1 == iSocketFieldDescription)
			{
				if (AF_INET == ptrAddrInfo->ai_family)
				{
					LOG_ERROR_ERRNO("socket IPv4");
				}
				else if (AF_INET6 == ptrAddrInfo->ai_family)
				{
					LOG_ERROR_ERRNO("socket IPv6");
				}
				else
				{
					LOG_ERROR_ERRNO("socket Unknown AF");
				}
				continue;
			}

			/* Ensure the listening socket is not inherited across exec() */
			if (-1 == fcntl(iSocketFieldDescription, F_SETFD, FD_CLOEXEC))
			{
				LOG_ERROR_ERRNO("fcntl(FD_CLOEXEC)");
				/* Not fatal for this sample server; continue */
			}

			const int opt = 1;
			if (0 != setsockopt(iSocketFieldDescription, SOL_SOCKET, SO_REUSEADDR, &opt, (socklen_t)sizeof(opt)))
			{
				LOG_ERROR_ERRNO("setsockopt SO_REUSEADDR");
				/* Let centralized cleanup handle listener close */
				break;
			}

			/* Protect against blocked receiving */
			const struct timeval tv = { 10, 0 }; /* Seconds, microseconds */
			if (0 != setsockopt(iSocketFieldDescription, SOL_SOCKET, SO_RCVTIMEO, &tv, (socklen_t)sizeof(tv)))
			{
				LOG_ERROR_ERRNO("setsockopt SO_RCVTIMEO");
				/* Let centralized cleanup handle listener close */
				break;
			}

			/* Protect against slow senders */
			const struct timeval tv_send = { 10, 0 }; /* Seconds, microseconds */
			if (0 != setsockopt(iSocketFieldDescription, SOL_SOCKET, SO_SNDTIMEO, &tv_send, (socklen_t)sizeof(tv_send)))
			{
				LOG_ERROR_ERRNO("setsockopt SO_SNDTIMEO");
				/* Let centralized cleanup handle listener close */
				break;
			}

			/* Prevents small-response delays due to Nagle’s algorithm. */
			const int flag = 1;
			if (0 != setsockopt(iSocketFieldDescription, IPPROTO_TCP, TCP_NODELAY, &flag, (socklen_t)sizeof(flag)))
			{
				LOG_ERROR_ERRNO("setsockopt TCP_NODELAY");
				break;
			}

			if (0 == bind(iSocketFieldDescription, ptrAddrInfo->ai_addr, ptrAddrInfo->ai_addrlen))
			{
				/* Success */
				break;
			}

			LOG_ERROR_ERRNO("bind");
			close(iSocketFieldDescription);
			iSocketFieldDescription = -1;
		}

		/* No address succeeded */
		if (((struct addrinfo*)NULL) == ptrAddrInfo)
		{
			LOG_ERROR("Could not bind to any IPv4 or IPv6 address");
			break;
		}

		/* No longer needed, hence closing */
		freeaddrinfo(server);
		server = (struct addrinfo*)NULL;

		/* Catch termination signals using sigaction (more predictable than signal()) */
		{
			struct sigaction sa;
			memset(&sa, 0, sizeof(sa));
			sa.sa_handler = SignalHandler_SetExitFlag;
			sigemptyset(&sa.sa_mask);
			sa.sa_flags = SA_RESTART;

			if (0 != sigaction(SIGINT, &sa, NULL))     /* Ctrl+C */
			{
				LOG_ERROR_ERRNO("sigaction(SIGINT)");
			}
			if (0 != sigaction(SIGTERM, &sa, NULL))    /* kill */
			{
				LOG_ERROR_ERRNO("sigaction(SIGTERM)");
			}
			if (0 != sigaction(SIGQUIT, &sa, NULL))    /* Ctrl+\ */
			{
				LOG_ERROR_ERRNO("sigaction(SIGQUIT)");
			}
			if (0 != sigaction(SIGTSTP, &sa, NULL))    /* Ctrl+Z treated as exit request */
			{
				LOG_ERROR_ERRNO("sigaction(SIGTSTP)");
			}

			/* Ignore SIGPIPE (e.g., when peer closes unexpectedly) */
			struct sigaction sa_ign;
			memset(&sa_ign, 0, sizeof(sa_ign));
			sa_ign.sa_handler = SIG_IGN;
			sigemptyset(&sa_ign.sa_mask);
			sa_ign.sa_flags = 0;
			if (0 != sigaction(SIGPIPE, &sa_ign, NULL))
			{
				LOG_ERROR_ERRNO("sigaction(SIGPIPE)");
			}
		}

		const int iListenStatus = listen(iSocketFieldDescription, SOMAXCONN);
		if (-1 == iListenStatus)
		{
			LOG_ERROR_ERRNO("listen");
			break;
		}
#if defined( __ENABLE_MUTUAL_TLS__ )
		LOG_INFO("\nHTTPS (Mutual TLS) server listening on port 8080...");
#else // of defined( __ENABLE_MUTUAL_TLS__ )
		LOG_INFO("\nHTTPS (TLS) server listening on port 8080...");
#endif // of defined( __ENABLE_MUTUAL_TLS__ )

		ret = true;
	} while (false);

	return ret;
}

/* Safe & optimized case-insensitive substring search */
static const char* pc_strcasestr(const char* haystack, const char* needle)
{
	const char* p_h = (const char*)NULL;
	size_t len_h = 0U;
	size_t len_n = 0U;
	size_t i = 0U;
	size_t j = 0U;

	/* NULL checks */
	if (((const char*)NULL) == haystack)
	{
		return (const char*)NULL;
	}

	if (((const char*)NULL) == needle)
	{
		return (const char*)NULL;
	}

	len_h = strlen(haystack);
	len_n = strlen(needle);

	/* Empty needle matches at beginning */
	if (0U == len_n)
	{
		return haystack;
	}

	/* If impossible to match */
	if (len_n > len_h)
	{
		return (const char*)NULL;
	}

	p_h = haystack;

	/* Only search up to a safe point */
	for (i = 0U; i <= (len_h - len_n); i++)
	{
		/* Fast-path optimization: first character must match */
		if ((int)tolower((unsigned char)p_h[i]) != (int)tolower((unsigned char)needle[0]))
		{
			continue;
		}

		/* Compare subsequent characters */
		for (j = 1U; j < len_n; j++)
		{
			if ((int)tolower((unsigned char)p_h[i + j]) != (int)tolower((unsigned char)needle[j]))
			{
				break;
			}
		}

		/* Full match */
		if (j == len_n)
		{
			return &p_h[i];
		}
	}

	return (const char*)NULL;
}

/* Fully-validated Host header parser: IPv4, Hostname, and [IPv6] */
static bool rv_parse_http_host(const char* host_hdr, char* out_host, size_t out_host_size)
{
	bool ret = false;
	size_t src_len;
	size_t start = 0U;
	size_t end = 0U;
	size_t copy_len = 0U;

	do
	{
		/* Input sanity */
		if ((NULL == host_hdr) || (NULL == out_host) || (2U > out_host_size))
		{
			break;
		}

		src_len = strlen(host_hdr);
		if (0U == src_len)
		{
			break;
		}

		/* Skip leading whitespace */
		while ((start < src_len) && ((' ' == host_hdr[start]) || ('\t' == host_hdr[start])))
		{
			start++;
		}
		if (start >= src_len)
		{
			break;
		}

		/* IPv6 literal in [ ] */
		if ('[' == host_hdr[start])
		{
			size_t closing = start + 1U;
			while ((closing < src_len) && (']' != host_hdr[closing]) && ('\r' != host_hdr[closing]) && ('\n' != host_hdr[closing]))
			{
				closing++;
			}

			/* If no closing bracket or empty [] → invalid */
			if ((closing >= src_len) || (closing <= (start + 1U)))
			{
				break;
			}

			copy_len = closing - (start + 1U);
			if ((out_host_size - 1U) <= copy_len)
			{
				copy_len = out_host_size - 1U;
			}

			(void)memcpy(out_host, &host_hdr[start + 1U], copy_len);
			out_host[copy_len] = '\0';

			/* Validate IPv6 */
			if (1 != inet_pton(AF_INET6, out_host, NULL))
			{
				break;
			}
		}
		else
		{
			/* Hostname or IPv4 stops at colon/space/CR/LF */
			end = start;
			while ((end < src_len) && (':' != host_hdr[end]) && (' ' != host_hdr[end]) && ('\t' != host_hdr[end]) && ('\r' != host_hdr[end]) && ('\n' != host_hdr[end]))
			{
				end++;
			}

			if (end == start)
			{
				break;
			}

			copy_len = end - start;
			if ((out_host_size - 1U) <= copy_len)
			{
				copy_len = out_host_size - 1U;
			}

			(void)memcpy(out_host, &host_hdr[start], copy_len);
			out_host[copy_len] = '\0';

			/* Accept IPv4 or hostname */
			unsigned char dst[sizeof(struct in6_addr)];

			if (1 == inet_pton(AF_INET, out_host, dst))
			{
				/* Valid IPv4 → ok */
			}
			else
			{
				/* Treat as hostname — must start alnum and cannot contain raw colon */
				if ((0 == isalnum((unsigned char)out_host[0])) || (NULL != strchr(out_host, ':')))
				{
					break;
				}
			}
		}

		ret = true;

	} while (false);

	return ret;
}

static void RunServerLoop(void)
{
	/* Refer file socket.h. It is evident that size of sockaddr_storage is larger than that of sockaddr */
	struct sockaddr_storage ClientAddress;

	while (0 == g_exit_requested)
	{
		char host[NI_MAXHOST];
		char serv[NI_MAXSERV];
		/*
		 * Reset ClientLength for every accept() call.
		 * accept() modifies ClientLength to actual addr size (IPv4 smaller than IPv6).
		 * Not resetting would break the next IPv6 connection.
		 */
		socklen_t ClientLength = (socklen_t)sizeof(ClientAddress);
		iAcceptedClientFileDescriptor = accept(iSocketFieldDescription, (struct sockaddr*)&ClientAddress, &ClientLength);

		if (-1 == iAcceptedClientFileDescriptor)
		{
			/* If interrupted or temporarily no connections, continue */
			if ((EINTR == errno) || (EAGAIN == errno))
			{
				iAcceptedClientFileDescriptor = -1;
				continue;
			}
			LOG_ERROR_ERRNO("accept");
			break;
		}

		/* Ensure accepted socket is not inherited across exec() */
		if (-1 == fcntl(iAcceptedClientFileDescriptor, F_SETFD, FD_CLOEXEC))
		{
			LOG_ERROR_ERRNO("fcntl(FD_CLOEXEC client)");
			/* Not fatal; continue handling this connection */
		}

		/* Log client endpoint information */
		{
			const int status = getnameinfo((struct sockaddr*)&ClientAddress, ClientLength, host, sizeof(host), serv, sizeof(serv), NI_NUMERICHOST | NI_NUMERICSERV);

			if (0 == status)
			{
				LOG_INFO("\nAccept new connection on file descriptor %d from Client %s:%s\n", iAcceptedClientFileDescriptor, host, serv);
			}
			else
			{
				LOG_ERROR_ERRNO("\nAccept new connection on file descriptor %d (address unresolved: %s)\n", iAcceptedClientFileDescriptor, gai_strerror(status));
			}

			ssl = SSL_new(ctx);
			if (((SSL*)NULL) == ssl)
			{
				LOG_ERROR("SSL_new failed");
#if defined(__DEV__)
				ERR_print_errors_fp(stderr);
#endif
				close(iAcceptedClientFileDescriptor);
				iAcceptedClientFileDescriptor = -1;
				continue;
			}

			if (0 == SSL_set_fd(ssl, iAcceptedClientFileDescriptor))
			{
				LOG_ERROR("SSL_set_fd failed");
				SSL_free(ssl);
				ssl = (SSL*)NULL;
				close(iAcceptedClientFileDescriptor);
				iAcceptedClientFileDescriptor = -1;
				continue;
			}

#if defined( __ENABLE_MUTUAL_TLS__ )
			/* Enforce hostname check against certificate (SAN/CN) */
			if (1 != SSL_set1_host(ssl, host))
			{
				LOG_ERROR("SSL_set1_host failed for host '%s'", host);
				SSL_free(ssl);
				ssl = (SSL*)NULL;
				close(iAcceptedClientFileDescriptor);
				iAcceptedClientFileDescriptor = -1;
				continue;
			}
#endif // of defined( __ENABLE_MUTUAL_TLS__ )
		}

		const int ret_ssl = SSL_accept(ssl);
		if (0 >= ret_ssl)
		{
			const int err = SSL_get_error(ssl, ret_ssl);

			if ((SSL_ERROR_WANT_READ == err) || (SSL_ERROR_WANT_WRITE == err))
			{
				LOG_WARN("TLS handshake did not complete (SSL_ERROR_WANT_%s) on fd %d", (SSL_ERROR_WANT_READ == err) ? "READ" : "WRITE", iAcceptedClientFileDescriptor);
			}
			else
			{
				LOG_ERROR("TLS connection closed or client did not send HTTP request (SSL error=%d) on fd %d", err, iAcceptedClientFileDescriptor);
				ERR_print_errors_fp(stderr);
				rvSanAbortOnOpenSSLError("SSL_accept", err);
			}

			rvShutDownSSL_AndCloseFD();
			continue;
		}

		/* ---- Start: Mutual TLS block ---- */
#if defined( __ENABLE_MUTUAL_TLS__ )
		{
			X509* client_cert = SSL_get_peer_certificate(ssl);
			if (NULL != client_cert)
			{
				char* subj = X509_NAME_oneline(X509_get_subject_name(client_cert), NULL, 0);
				LOG_INFO("Client certificate subject: %s", subj);
				OPENSSL_free(subj);
				X509_free(client_cert);

				long verify_result = SSL_get_verify_result(ssl);
				if (X509_V_OK != verify_result)
				{
					LOG_ERROR("Client certificate verification failed: %s", X509_verify_cert_error_string(verify_result));
					rvShutDownSSL_AndCloseFD();
					continue;
				}
			}
			else
			{
				LOG_ERROR("No client certificate presented");
				rvShutDownSSL_AndCloseFD();
				continue;
			}
		}
#endif // of defined( __ENABLE_MUTUAL_TLS__ )
		/* ---- End: mutual TLS block ---- */

		/**** Read request (accumulate full header) ****/
		{
			char buf[4096];
			int total_bytes = 0;
			bool header_complete = false;
			int status_code = 400;
			const int max_header = (int)sizeof(buf) - 1;

			while (0 == g_exit_requested)
			{
				int bytes = SSL_read(ssl, buf + total_bytes, max_header - total_bytes);

				if (bytes > 0)
				{
					total_bytes += bytes;
					buf[total_bytes] = '\0';

					/* Full header received?
					 * Simple rule: header is complete once "\r\n\r\n" appears anywhere.
					 */
					if ((total_bytes >= 4) && (NULL != strstr(buf, "\r\n\r\n")))
					{
						header_complete = true;
						break;
					}

					/* Protect against header overflow */
					if (total_bytes >= max_header)
					{
						status_code = 413;
						break;
					}

					/* Continue reading */
					continue;
				}

				/* Handle SSL error conditions */
				int ssl_err = SSL_get_error(ssl, bytes);

				if ((SSL_ERROR_WANT_READ == ssl_err) || (SSL_ERROR_WANT_WRITE == ssl_err))
				{
					/* Retry on permissible non-fatal condition */
					continue;
				}
				else if (SSL_ERROR_ZERO_RETURN == ssl_err)
				{
					/* Clean close by peer */
					break;
				}
				else if (SSL_ERROR_SYSCALL == ssl_err)
				{
					/* Likely EOF or OS-level error */
					if (0 == bytes)
					{
						break;
					}
					LOG_ERROR_ERRNO("SSL_read syscall error");
					break;
				}
				else
				{
					/* Fatal TLS failure */
					LOG_ERROR("SSL_read failed, SSL error=%d", ssl_err);
					rvSanAbortOnOpenSSLError("SSL_read", ssl_err);
					break;
				}
			}

			if (false == header_complete)
			{
				switch (status_code)
				{
				case 413:
				{
					(void)send_http_response(ssl, 413, "Payload Too Large", "Request header too large!\r\n");
					break;
				}
				case 400:
				default:
				{
					(void)send_http_response(ssl, 400, "Bad Request", "Header not complete!\r\n");
					break;
				}
				}

				rvShutDownSSL_AndCloseFD();
				continue;
			}

			/* Enforce a maximum request-line length (e.g., 2048) for simple DoS protection */
			{
				const char* first_crlf = strstr(buf, "\r\n");
				if ((NULL != first_crlf) && ((first_crlf - buf) > 2048))
				{
					(void)send_http_response(ssl, 414, "URI Too Long", "Request line too long!\r\n");
					rvShutDownSSL_AndCloseFD();
					continue;
				}
			}

			/* Validate HTTP method and request-target form */
			if (0 != strncmp(buf, "GET /", 5))
			{
				if (0 == strncmp(buf, "GET ", 4))
				{
					/* GET exists but no valid resource format */
					(void)send_http_response(ssl, 400, "Bad Request", "Malformed request target!\r\n");
				}
				else
				{
					/* Wrong method */
					(void)send_http_response(ssl, 405, "Method Not Allowed", "Only GET method supported!\r\n");
				}
				rvShutDownSSL_AndCloseFD();
				continue;
			}

			/* Reject path traversal attempts */
			if ((NULL != strstr(buf, "/..")) || (NULL != strstr(buf, "%2e")))
			{
				(void)send_http_response(ssl, 400, "Bad Request", "Illegal path!\r\n");
				rvShutDownSSL_AndCloseFD();
				continue;
			}

			/* Validate HTTP version presence */
			if (NULL == strstr(buf, "HTTP/1.1"))
			{
				(void)send_http_response(ssl, 400, "Bad Request", "Missing or wrong HTTP version!\r\n");
				rvShutDownSSL_AndCloseFD();
				continue;
			}

#if defined(__DEV__) && defined(__LOG_ENABLE_DEBUG__)
			LOG_INFO("--- Received request with %d bytes ---\n%s\n------------------------", total_bytes, buf);
#endif

			/* Find Host header */
			const char* host_hdr = pc_strcasestr(buf, "\nhost:");

			if ((const char*)NULL != host_hdr)
			{
				host_hdr += 6; /* past "\nhost:" */

				/* Skip leading SP / HTAB */
				while ((' ' == *host_hdr) || ('\t' == *host_hdr))
				{
					host_hdr++;
				}
			}

			if (((const char*)NULL == host_hdr) || ('\0' == *host_hdr) || ('\r' == *host_hdr) || ('\n' == *host_hdr))
			{
				(void)send_http_response(ssl, 400, "Bad Request", "Missing Host header!\r\n");
				rvShutDownSSL_AndCloseFD();
				continue;
			}

			/* Strip CRLF at end of line for clean parsing */
			char* end = strpbrk(host_hdr, "\r\n");
			if ((char*)NULL != end)
			{
				*end = '\0';
			}

			/* Parse host (no port, IPv4/IPv6/hostname supported).
			 * Used only for basic HTTP validation / logging.
			 * Identity is enforced by TLS certificate verification,
			 * not by comparing Host header to remote IP address.
			 */
			char req_host[NI_MAXHOST + 1U];
			if (false == rv_parse_http_host(host_hdr, req_host, (size_t)sizeof(req_host)))
			{
				(void)send_http_response(ssl, 400, "Bad Request", "Invalid Host header!\r\n");
				rvShutDownSSL_AndCloseFD();
				continue;
			}

			/* Log validated Host header */
			LOG_INFO("Validated Host: %s", req_host);

			/*
			 * Host enforcement:
			 *
			 *   - The allowed Host header value is provided at compile time via
			 *     RV_ALLOWED_HOST, which is set from the Makefile using:
			 *
			 *         -DRV_ALLOWED_HOST="secure.lab.linux"
			 *
			 *     or per-mode overrides (PROD_HOST / DEV_HOST / BENCH_HOST).
			 *
			 *   - PROD  : strict enforcement → mismatch is rejected.
			 *   - DEV   : mismatch is logged but the request is allowed.
			 *   - BENCH : no enforcement; Host is only logged for visibility.
			 */
#if defined(__BENCH__)
			LOG_INFO("BENCH mode: Host header = %s (RV_ALLOWED_HOST=%s)", req_host, RV_ALLOWED_HOST);
#else
			if (0 != strcmp(req_host, RV_ALLOWED_HOST))
			{
#if defined(__DEV__)
				LOG_WARN("DEV mode: Host header '%s' != expected '%s' (allowing in DEV build)", req_host, RV_ALLOWED_HOST);
				/* Continue processing request in DEV mode. */
#else
				/* PROD: strict Host enforcement. */
				(void)send_http_response(ssl, 400, "Bad Request", "Host not allowed!\r\n");
				rvShutDownSSL_AndCloseFD();
				continue;
#endif
			}
#endif

			/* Log client certificate CN, if any */
			{
				X509* peer_cert = SSL_get_peer_certificate(ssl);
				if (NULL != peer_cert)
				{
					char cn[256U] = { 0 };
					X509_NAME* subj = X509_get_subject_name(peer_cert);

					(void)X509_NAME_get_text_by_NID(subj, NID_commonName, cn, (int)sizeof(cn));
					LOG_INFO("Client certificate CN: %s", cn);

					X509_free(peer_cert);
				}
			}

			/* SUCCESS! */
			(void)send_http_response(ssl, 200, "OK", "Hello, HTTPS!\r\n");
			rvShutDownSSL_AndCloseFD();
			continue;
		}

		/* START: Defensive coding, DO NOT REMOVE */
		rvShutDownSSL_AndCloseFD();
		/* END: Defensive coding, DO NOT REMOVE */
	}

	/* One-time exit message */
	if (0 != g_exit_requested)
	{
		LOG_INFO("\nCaught signal %d. Cleaning up server loop and exiting...", (int)g_last_signal);
	}
}

int main(void)
{
	bool init_ok = InitializeServer();

	if ((true == init_ok) && (0 == g_exit_requested))
	{
#if defined(__DEV__)
		/* DEV build: no chroot/priv-drop/rlimits to keep debugging simple. */
		LOG_INFO("DEV build: running WITHOUT chroot/priv-drop/rlimits (for debugging only).");
#else
		/*
		 * PROD / BENCH builds:
		 *   - Process is expected to start as root so we can chroot and drop privileges.
		 *   - After InitializeServer() binds the listening socket, we:
		 *       - chroot into /var/secure-tls-server
		 *       - drop to www-data:www-data
		 *       - apply resource limits (NOFILE / NPROC)
		 */
		if (0 != geteuid())
		{
			LOG_ERROR("ERROR: Must run as root in PROD/BENCH builds to apply chroot/priv-drop.");
			rvShutDownSSL_AndCloseFD();
			FreeAndClose();
			return EXIT_FAILURE;
		}

		if (false == rvDropPrivileges_AndChroot())
		{
			LOG_ERROR("ERROR: Failed to chroot/drop privileges. Aborting.");
			rvShutDownSSL_AndCloseFD();
			FreeAndClose();
			return EXIT_FAILURE;
		}

		rvApplyResourceLimits();
#endif /* __DEV__ */
		RunServerLoop();
	}

	rvShutDownSSL_AndCloseFD();
	FreeAndClose();

	LOG_INFO("Server terminated.");

	return ((true == init_ok) && (0 == g_exit_requested)) ? EXIT_SUCCESS : EXIT_FAILURE;
}
