/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Rajeev Arora
 *
 * NOTE:
 * This software incorporates OpenSSL and other third-party libraries whose
 * licenses remain with their respective authors.
 *
 * Full Apache 2.0 license text is provided in the LICENSE file.
 */

#if !defined( _DEFAULT_SOURCE )
#define _DEFAULT_SOURCE     /* request GNU extensions */
#endif // of !defined( _DEFAULT_SOURCE )

#if !defined( _POSIX_C_SOURCE )
#define _POSIX_C_SOURCE 200809L
#endif // of !defined( _POSIX_C_SOURCE )

#if !defined( _XOPEN_SOURCE )
#define _XOPEN_SOURCE 700    /* Required on some systems for addrinfo */
#endif // of !defined( _XOPEN_SOURCE )

//#include <sys/time.h>     /* struct timeval */
//#include <sys/select.h>   /* FD_* macros if used later */
//#include <openssl/x509_vfy.h>   /* X509_V_FLAG_CRL_CHECK, X509_V_FLAG_CRL_CHECK_ALL */
//#include <time.h>
//#include <sys/resource.h> /* setrlimit(), struct rlimit          */

/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright … */

/* ==== System Headers (must be first) ==== */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>        /* fcntl, FD_CLOEXEC */
#include <pwd.h>          /* getpwnam(), struct passwd           */
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/socket.h>   /* Required for socket functions like socket(), connect(), etc. */
#include <sys/stat.h>     /* For jail directory permissions etc. */
#include <arpa/inet.h>    /* sockaddr conversions, AF_INET, AF_INET6, inet_pton() */
#include <netdb.h>				/* NI_MAXHOST, NI_MAXSERV and getnameinfo() */
//	#include <netinet/in.h>
#include <netinet/tcp.h>

/* ==== OpenSSL ==== */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

/* ==== Then all code comments, macros, policies ==== */

/* ============================================================================
 * Compile-time TLS port and certificate paths (runtime-relative)
 * ============================================================================
 *
 * Expected runtime execution:
 *
 *     cd <repo-root>
 *     ./build/mtls_server
 *
 * Certificate files must exist at:
 *
 *     <repo-root>/certs/server-cert.pem
 *     <repo-root>/certs/server-key.pem
 *     <repo-root>/certs/ca-cert.pem
 *     <repo-root>/certs/ca-crl.pem        (required in hardened modes)
 *
 * For OpenSSL loading (from ./build/):
 *     "../certs/<filename>"
 *
 * For log messages we only print filenames (the *_NAME macros).
 * ============================================================================
 */

/* ============================================================================
 * Certificate paths and filenames from Makefile
 *
 * Makefile guarantees these -D defines:
 *   __SERVER_CERT_PATH__   → full runtime path (ex: "../certs/server-cert.pem")
 *   __SERVER_KEY_PATH__
 *   __CA_CERT_PATH__
 *   __CA_CRL_PATH__
 *   __SERVER_CERT_NAME__   → filename only (ex: "server-cert.pem")
 *   __SERVER_KEY_NAME__
 *   __CA_CERT_NAME__
 *   __CA_CRL_NAME__
 * ============================================================================
 */
#if !defined(__SERVER_CERT_PATH__) || \
    !defined(__SERVER_KEY_PATH__)  || \
    !defined(__CA_CERT_NAME__)     || \
    !defined(__CA_CERT_PATH__)     || \
    !defined(__CA_CRL_PATH__)      || \
    !defined(__CA_CRL_NAME__)
#error "Required certificate macros missing — ensure build uses Makefile"
#endif

#define SERVER_CERT_PATH_FULL  __SERVER_CERT_PATH__
#define SERVER_KEY_PATH_FULL   __SERVER_KEY_PATH__
#define CA_CERT_PATH_FULL      __CA_CERT_PATH__
#define CA_CRL_PATH_FULL       __CA_CRL_PATH__

#define SERVER_CERT_NAME       __SERVER_CERT_NAME__
#define SERVER_KEY_NAME        __SERVER_KEY_NAME__
#define CA_CERT_NAME           __CA_CERT_NAME__
#define CA_CRL_NAME            __CA_CRL_NAME__


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
Mutual TLS Feature Selection (__REQUIRE_MUTUAL_TLS__)
-------------------------------------------------------------------------------

		- mTLS is abbreviation for Mutual TLS

    - If __REQUIRE_MUTUAL_TLS__ is undefined:
          mTLS is disabled (server authenticates itself only).

    - If __REQUIRE_MUTUAL_TLS__ is defined:
          Client certificate authentication is required; the TLS context
          is configured accordingly (CA list, verify depth, etc.).

		Security Policy Update:
			In PROD and BENCH modes, mTLS=0 is NOT permitted.
			Makefile enforces build failure if mTLS=0 with PROD OR BENCH.
			mTLS=0 is valid ONLY in DEV mode.

-------------------------------------------------------------------------------
Logging flags (from Makefile only)
-------------------------------------------------------------------------------

The following preprocessor symbols may be passed from the Makefile:

    -D__LOG_ENABLE_WARN__
    -D__LOG_ENABLE_INFO__
    -D__LOG_ENABLE_DEBUG__

Rules enforced here:

    - LOG_ERROR is always compiled and active in all modes.

    - PROD:
        * WARN / INFO / DEBUG are not allowed.
        * Any attempt to enable them must be rejected by the Makefile and/or
          compile-time checks in this file. __LOG_ENABLE_DEBUG__ is forbidden.

    - BENCH:
        * WARN and INFO may be enabled via __LOG_ENABLE_WARN__ and __LOG_ENABLE_INFO__.
        * DEBUG (__LOG_ENABLE_DEBUG__) is forbidden.

    - DEV:
        * WARN, INFO, and DEBUG are all enabled by default.
        * Each may be individually disabled or re-enabled via their associated flags, namely:
          __LOG_ENABLE_WARN__, __LOG_ENABLE_INFO__, __LOG_ENABLE_DEBUG__
        * Sanitizers are typically enabled (SAN=1 by default).

    - __LOG_ENABLE_DEBUG__ is only allowed when __DEV__ is defined.
      (DEBUG logging is forbidden in PROD and BENCH builds.)
===============================================================================
*/

/* ============================================================================
 * Hardened TLS / mTLS Cryptographic Requirements
 * ============================================================================
 *
 * TLS is ALWAYS enabled in ALL build modes. Plain TCP is never permitted.
 *
 * Mutual TLS requirement (controlled by Makefile TLS flag):
 *
 *   Mode   | mTLS Required? | Comments
 *   -------+----------------+-----------------------------------------------
 *   PROD   | YES            | Hardened deployment — fail-closed
 *   BENCH  | YES            | Performance test — hardened trust behavior
 *   DEV    | OPTIONAL       | Developer convenience
 *                            Enable mTLS explicitly:
 *                              make PROD=0 mTLS=1
 *                            or disable mTLS:
 *                              make PROD=0 mTLS=0
 *
 * ---------------------------------------------------------------------------
 * Security Level Enforcement (__SECURITY_LEVEL__)
 * ---------------------------------------------------------------------------
 *
 * Security Level is passed from the Makefile as:
 *
 *   -D__SECURITY_LEVEL__=<1|2|3>
 *
 * Mapping:
 *
 *   __SECURITY_LEVEL__ = 1  → mTLS only
 *        - TLS always ON
 *        - mTLS optional (DEV only)
 *        - CRL/OCSP disabled
 *
 *   __SECURITY_LEVEL__ = 2  → Hardened baseline (mTLS + CRL)
 *        - TLS always ON
 *        - mTLS REQUIRED in PROD/BENCH
 *        - CRL REQUIRED (revocation enforced via CRL)
 *        - OCSP not used (reserved)
 *
 *   __SECURITY_LEVEL__ = 3  → Future hardened mode (mTLS + CRL + OCSP)
 *        - TLS always ON
 *        - OCSP NOT IMPLEMENTED in this server
 *        - Allowed only in DEV builds
 *        - PROD/BENCH builds must reject SECURITY_LEVEL >= 3
 *
 * CRL must exist in hardened builds when SECURITY_LEVEL >= 2.
 * In DEV, CRL is optional and failure to configure it only logs a warning.
 *
 * ---------------------------------------------------------------------------
 * Trust Roles and Dependencies — Visual Trust Chain
 * ---------------------------------------------------------------------------
 *
 *    [ ca-key.pem ] (CA private key)
 *          │   highly protected, NEVER shipped
 *          ▼
 *    [ ca-cert.pem ] (Public root of trust)
 *          │
 *          ├── signs server.csr → [ server-cert.pem ]
 *          │                         validates server identity
 *          │
 *          ├── signs client.csr → [ client-cert.pem ] (mTLS only)
 *          │                         validates client identity
 *          │
 *          └── signs CRL → [ ca-crl.pem ]
 *                                lists revoked serial numbers
 *
 * Server ALWAYS needs:  server-key.pem, server-cert.pem, ca-cert.pem
 * CRL is required in hardened builds:  ca-crl.pem
 * Client artifacts only required in mTLS mode: client-key.pem + client-cert.pem
 * ============================================================================
 */

/* ============================================================================
 * REQUIRED CERTIFICATE ARTIFACTS AND EXACT OPENSSL COMMANDS
 * ============================================================================
 *
 * All certificate/key files reside under:
 *
 *     <repo-root>/certs/
 *
 * This server requires the following artifacts (filenames fixed by Makefile):
 *
 *   - server-key.pem   → Server private key
 *   - server-cert.pem  → Server X.509 certificate
 *   - ca-cert.pem      → Certificate Authority – public trust anchor
 *   - ca-crl.pem       → Certificate Revocation List (required in hardened modes)
 *   - client-key.pem   → Client private key (mTLS only)
 *   - client-cert.pem  → Client certificate (mTLS only)
 *
 * Runtime Requirements Per Build Mode
 * ----------------------------------
 *
 *   Mode    | TLS | mTLS | CRL | Required Files
 *   --------+-----+------+-----+-----------------------------------------------
 *   PROD    | ON  | YES  | YES | server-key.pem
 *           |     |      |     | server-cert.pem
 *           |     |      |     | ca-cert.pem
 *           |     |      |     | ca-crl.pem
 *           |     |      |     | client-key.pem + client-cert.pem (client side)
 *
 *   BENCH   | ON  | YES  | YES | Same as PROD
 *
 *   DEV     | ON  | optional | optional | always: server-key.pem, server-cert.pem, ca-cert.pem
 *           |                |          | optional: ca-crl.pem
 *           |                |          | optional: client-key.pem + client-cert.pem
 *
 * NOTE:
 *   - TLS is ALWAYS ON in ALL MODES — plain TCP is forbidden.
 *   - In PROD/BENCH: missing mTLS/CRL files → server initialization fails.
 *   - In DEV: missing optional files logs warnings but server runs for testing.
 *
 * ---------------------------------------------------------------------------
 * CERTIFICATE GENERATION (OpenSSL CLI)
 *
 * Execute these commands from: <repo-root>/certs/
 *
 * 1) Root CA (one-time)
 * --------------------
 *   openssl genpkey -algorithm RSA -out ca-key.pem -pkeyopt rsa_keygen_bits:4096
 *
 *   openssl req -x509 -new -nodes \
 *       -key ca-key.pem \
 *       -sha256 -days 1825 \
 *       -subj "/CN=Security-Authority-Root-CA" \
 *       -out ca-cert.pem
 *
 *
 * 2) Server Certificate (required in ALL MODES)
 * --------------------------------------------
 *   openssl genpkey -algorithm RSA \
 *       -out server-key.pem -pkeyopt rsa_keygen_bits:2048
 *
 *   # Create SAN extension file for modern hostname validation
 *   cat > server-san.ext <<EOF
 *   subjectAltName=DNS:secure.lab.linux,IP:127.0.0.1
 *   EOF
 *
 *   openssl req -new \
 *       -key server-key.pem \
 *       -out server.csr \
 *       -subj "/CN=secure.lab.linux"
 *
 *   openssl x509 -req -in server.csr \
 *       -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial \
 *       -out server-cert.pem -days 825 -sha256 \
 *       -extfile server-san.ext
 *
 *   rm -f server.csr server-san.ext
 *
 *
 * 3) Client Certificate (ONLY when mTLS is enabled)
 * ------------------------------------------------
 *   openssl genpkey -algorithm RSA \
 *       -out client-key.pem -pkeyopt rsa_keygen_bits:2048
 *
 *   openssl req -new \
 *       -key client-key.pem \
 *       -out client.csr \
 *       -subj "/CN=Secure-Client"
 *
 *   openssl x509 -req -in client.csr \
 *       -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial \
 *       -out client-cert.pem -days 825 -sha256
 *
 *   rm -f client.csr
 *
 *
 * 4) Certificate Revocation List (required in PROD/BENCH)
 * ------------------------------------------------------
 *   # First-time CRL database requirements
 *   touch index.txt
 *   echo 01 > serial
 *
 *   openssl ca -gencrl \
 *       -keyfile ca-key.pem \
 *       -cert ca-cert.pem \
 *       -out ca-crl.pem \
 *       -crldays 30
 *
 *
 * ---------------------------------------------------------------------------
 * SECURITY RATIONALE
 *
 *  - CA_CERT acts as trust anchor for both server and clients
 *  - CRL ensures revoked clients cannot connect (fail-closed in PROD/BENCH)
 *  - SAN must match the SNI / Host used by clients (hostname validation)
 *  - Client certs are required in hardened deployments (identity enforcement)
 *
 * ---------------------------------------------------------------------------
 * MANAGEMENT NOTES
 *
 *  - NEVER distribute ca-key.pem (private key)
 *  - Store CA private key offline; use separate signing host in production
 *  - Always regenerate CRL before shipping hardened builds
 *
 * ============================================================================
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

#if defined(__LOG_ENABLE_DEBUG__) && !defined(__DEV__) && !defined(__SKIP_SECURITY__)
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

/*
 * Runtime security banner (printed once at startup).
 *
 * Intent:
 *   - Summarise *effective* build-time security configuration:
 *       • Mode (PROD / DEV / BENCH)
 *       • mTLS requirement (ON / OFF)
 *       • Security level (__SECURITY_LEVEL__)
 *       • Allowed host
 *       • Certificate / CRL filenames
 *
 *   - This is intentionally lightweight (Option A): one-time banner only.
 *     No per-request noise, no repeated printing.
 */
static void
print_runtime_security_banner(void)
{
    LOG_INFO("==============================================================");
    LOG_INFO(" Runtime Security Summary (Build + Policy Snapshot)");
    LOG_INFO("--------------------------------------------------------------");

    /* Mode comes from the earlier mode-selection block */
    LOG_INFO(" Mode: %s", MODE_NAME);

    /* mTLS requirement (driven by Makefile → __REQUIRE_MUTUAL_TLS__) */
#ifdef __REQUIRE_MUTUAL_TLS__
    LOG_INFO(" mTLS: ON  (client certificate is REQUIRED)");
#else
    LOG_INFO(" mTLS: OFF (server-auth TLS only; client cert not required)");
#endif

    /* Host enforcement (compile-time) */
#ifdef __ALLOWED_HOST__
    LOG_INFO(" Allowed Host (HTTP Host header): %s", __ALLOWED_HOST__);
#else
    LOG_INFO(" Allowed Host (HTTP Host header): <not defined>");
#endif

    /* Security Level (__SECURITY_LEVEL__ from Makefile) */
#if defined(__SECURITY_LEVEL__)
    LOG_INFO(" Security Level: %d", __SECURITY_LEVEL__);
    LOG_INFO("   CRL enforcement: %s",
             (__SECURITY_LEVEL__ >= 2) ? "ENABLED" : "DISABLED");
    LOG_INFO("   OCSP support   : %s",
             (__SECURITY_LEVEL__ >= 3)
                 ? "RESERVED (not implemented; forbidden in PROD/BENCH)"
                 : "OFF");
#else // of defined(__SECURITY_LEVEL__)
    LOG_INFO(" Security Level: not configured (__SECURITY_LEVEL__ undefined)");
#endif // of defined(__SECURITY_LEVEL__)

    /* Certificate / CRL filenames (from Makefile CERT_DEFS) */
#ifdef __CERT_FOLDER__
    LOG_INFO(" Certificate folder: %s", __CERT_FOLDER__);
#endif

#ifdef __SERVER_CERT_NAME__
    LOG_INFO("   Server certificate : %s", __SERVER_CERT_NAME__);
#endif
#ifdef __SERVER_KEY_NAME__
    LOG_INFO("   Server key         : %s", __SERVER_KEY_NAME__);
#endif
#ifdef __CA_CERT_NAME__
    LOG_INFO("   CA certificate     : %s", __CA_CERT_NAME__);
#endif
#ifdef __CA_CRL_NAME__
    LOG_INFO("   CA CRL             : %s", __CA_CRL_NAME__);
#endif

    LOG_INFO("--------------------------------------------------------------");
    LOG_INFO(" TLS is ALWAYS ON in all modes (no plain TCP permitted).");
#ifdef __REQUIRE_MUTUAL_TLS__
    LOG_INFO(" This build REQUIRES mutual TLS (client authentication).");
#else
    LOG_INFO(" This build uses server-auth TLS; mTLS is disabled by policy.");
#endif
    LOG_INFO("==============================================================");
}

/**
===============================================================================
@file   TCP_Server.c
@brief  Hardened TLS Server (default) with Configurable Build Security Modes

Default build behavior (when running plain "make"):

    - PROD mode (hardened security, minimal logs).
    - Mutual TLS enabled (mTLS=1, client certificate required).
    - Strict HTTP Host enforcement using __ALLOWED_HOST__.
    - TLS listener on TCP port 443 (standard HTTPS/TLS port).

User-configurable build-time security modes and options:

    - Security mode:
        * PROD  (default, hardened deployment)
        * DEV   (debugging and sanitizers)
        * BENCH (performance benchmarking)

    - TLS authentication:
        * mTLS=1: mutual TLS (client certificate required)
        * mTLS=0: server-auth TLS only (no client certificate requested)

    - Logging visibility:
        * WARN, INFO, DEBUG enabled/disabled via Make flags,
          subject to strict per-mode policy (DEBUG forbidden in PROD/BENCH).

The final server binary is fully user configurable at build time via the
Makefile flags, with the default configuration being a hardened PROD TLS
server with strict host enforcement.

-------------------------------------------------------------------------------
Security Level (__SECURITY_LEVEL__)
-------------------------------------------------------------------------------

The Makefile defines __SECURITY_LEVEL__ (integer macro) to control both
authentication and revocation behaviour:

    __SECURITY_LEVEL__ = 1
        - mTLS only.
        - CRL/OCSP disabled.
        - Intended for DEV / CI builds only.

    __SECURITY_LEVEL__ = 2
        - Hardened baseline.
        - CRL-based revocation checking enabled and required in PROD/BENCH.
        - Server is expected to load and use CRLs for peer validation.

    __SECURITY_LEVEL__ = 3
        - Intended for CRL + OCSP in the future.
        - OCSP support is NOT yet implemented in this server.
        - In DEV builds: compilation emits a warning and runtime logs a warning.
        - In PROD/BENCH builds: compilation fails (hardened builds must not
          claim OCSP support until fully implemented and validated).

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
mTLS selection (via Makefile)
-------------------------------------------------------------------------------

    mTLS=1 (default):
        - Mutual TLS (client certificate required).
        - Server certificate is presented to the client.
        - Client certificate must be presented and validated.
        - Hostname verification uses TLS SNI / certificate SAN.
        - Compile-time: __REQUIRE_MUTUAL_TLS__ defined.

    mTLS=0:
        - Server-auth TLS only (no client certificate requested).
        - Server certificate is validated by the client.
        - TLS encryption is still enforced; only mutual authentication is
          disabled.
        - Compile-time: __REQUIRE_MUTUAL_TLS__ not defined.

All modes listen on TCP port 443 by default. Binding to port 443 normally
requires starting as root and then dropping privileges.

-------------------------------------------------------------------------------
Mode capabilities summary
-------------------------------------------------------------------------------

-----+-------------------------+----------------------+----------------------------+-----------------------------+--------------------------
Mode | TLS (0/1)               | Client Cert (mTLS=1) | Logging Allowed            | Host Enforcement            | Typical Use
-----+-------------------------+----------------------+----------------------------+-----------------------------+--------------------------
PROD | 1 (TLS always enforced) | Required when mTLS=1 | ERROR only                 | Strict reject on mismatch   | Hardened deployment
DEV  | 0 or 1                  | Required when mTLS=1 | ERROR/WARN/INFO/DEBUG      | Warning only (no reject)    | Development and debugging
BENCH| 1 (TLS always enforced) | Required when mTLS=1 | ERROR + optional WARN/INFO | Logged only, no reject      | Performance benchmarking

============================================================================
TLS AND MUTUAL TLS (mTLS) POLICY — FINAL CANONICAL DEFINITION
============================================================================

TLS — ALWAYS ON
----------------
 - TLS is ALWAYS ENABLED in ALL build modes (PROD / BENCH / DEV).
 - Plain TCP / cleartext is strictly forbidden in all modes.
 - Build tools do NOT allow disabling TLS under any circumstance.


Mutual TLS (client certificate authentication)
----------------------------------------------
 - Default: ENABLED in ALL modes.

 - PROD mode:
     * mTLS = ON is mandatory.
     * Makefile blocks mTLS=0 builds.

 - BENCH mode:
     * mTLS = ON is mandatory.
     * Makefile blocks mTLS=0 builds.

 - DEV mode:
     * mTLS can be turned OFF for local debugging or integration testing.
     * When mTLS=0 (mTLS disabled):
         - TLS encryption still enforced.
         - No client certificate requested.
         - CRL is optional.
         - Host mismatch logs WARNING but request is allowed.


Security rationale
------------------
 - mTLS required for hardened deployments → strict client identity validation.
 - Developer iteration must be frictionless → allow mTLS OFF temporarily.


Summary Matrix
--------------
  Mode   | TLS | mTLS (mTLS=1 required?) | Policy
  -------+-----+-------------------------+------------------------------------
  PROD   | ON  | ALWAYS ON               | Hardened deployment — fail closed
  BENCH  | ON  | ALWAYS ON               | Performance measurement — hardened
  DEV    | ON  | ON (default) or OFF     | Debug mode — fail open allowed


Enforcement
-----------
 - Makefile prevents invalid builds:
     PROD/BENCH + mTLS=0 → build error
     DEBUG logging without DEV → build error

 - C code enforces:
     * SSL_CTX_verify behavior by mTLS=1 vs mTLS=0 <<== #FixThis: ??
     * Host mismatch: reject in PROD/BENCH, warn-only in DEV
     * Revocation required in PROD/BENCH only

============================================================================
*/

/**
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

Hard denials:

    - DEBUG logs are never allowed in PROD or BENCH builds.
    - If __LOG_ENABLE_DEBUG__ is defined without __DEV__, a compile-time
      error is raised by this file.

===============================================================================
VALID MAKE COMMANDS (TOTAL 34 SUPPORTED COMBINATIONS)
===============================================================================

PROD builds (PROD=1, DEBUG not allowed):

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

BENCH builds (BENCH=1, DEBUG not allowed):

    make BENCH=1 TLS=1
    make BENCH=1 TLS=0
    make BENCH=1 TLS=1 WARN=1
    make BENCH=1 TLS=0 WARN=1
    make BENCH=1 TLS=1 INFO=1
    make BENCH=1 TLS=0 INFO=1
    make BENCH=1 TLS=1 WARN=1 INFO=1
    make BENCH=1 TLS=0 WARN=1 INFO=1

Any other combination of PROD / BENCH / mTLS / WARN / INFO / DEBUG
is considered invalid and should fail at Makefile or compile time.

Total valid build combinations: 34.

===============================================================================
CONFIGURATION MAPPING (MAKE vs DIRECT gcc -D... USAGE)
===============================================================================

This server is intended to be built via the Makefile. The Makefile ensures:

    - Exactly one mode is selected: PROD / DEV / BENCH.
    - mTLS mode (mTLS=0 / mTLS=1) is correctly mapped to __REQUIRE_MUTUAL_TLS__.
    - Logging macros (__LOG_ENABLE_WARN__/INFO/DEBUG) are consistent with mode.
    - __ALLOWED_HOST__ is set to the correct value per mode.
    - Hardened compiler/linker flags are applied for PROD and BENCH builds.

However, for debugging, experimentation, or when integrating with other build
systems, it can be useful to know how a given "make" configuration maps onto
an equivalent direct "gcc -D..." command.

Important rules:

    - The Makefile builds are the canonical, hardened builds.
    - Direct gcc examples below are approximate and do NOT include all
      hardening flags (RELRO, FORTIFY, PIE, etc.).
    - Direct gcc builds should NOT be used for production deployment.
*/

/**
-------------------------------------------------------------------------------
1) PROD mode, mTLS=1 (mutual TLS), WARN+INFO logs enabled
-------------------------------------------------------------------------------

Configuration:
    PROD mode (hardened), mutual TLS required, WARN+INFO logs enabled.

Make command (recommended):

    make PROD=1 mTLS=1 WARN=1 INFO=1

Equivalent gcc command (approximate):

    gcc TCP_Server.c -o TCP_Server \
        -D__REQUIRE_MUTUAL_TLS__ \
        -D__ALLOWED_HOST__=\"secure.lab.linux\" \
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
    - mTLS=1 maps to __REQUIRE_MUTUAL_TLS__.
    - WARN=1 and INFO=1 map to __LOG_ENABLE_WARN__ and __LOG_ENABLE_INFO__.
    - __ALLOWED_HOST__ is set to "secure.lab.linux" as in the Makefile defaults.

Security note:

    - This gcc example does not enable all the hardening flags that the
      Makefile may add (such as full RELRO, PIE, stack protections).
    - Use the Makefile build for real deployments.

-------------------------------------------------------------------------------
2) PROD mode, mTLS=0 (server-auth only), WARN logs only
-------------------------------------------------------------------------------

Configuration:
    PROD mode, server-auth TLS only, WARN logs enabled (no mutual TLS).

Make command:

    make PROD=1 mTLS=0 WARN=1

Equivalent gcc command:

    gcc TCP_Server.c -o TCP_Server \
        -D__ALLOWED_HOST__=\"secure.lab.linux\" \
        -D__LOG_ENABLE_WARN__ \
        -std=c2x \
        -Wall -Wextra -Werror -Wpedantic \
        -Wformat=2 -Wshadow -Wpointer-arith \
        -Wcast-align -Wwrite-strings -Wconversion \
        -O2 \
        -lssl -lcrypto

Why equivalent:

    - __REQUIRE_MUTUAL_TLS__ is not defined (mTLS=0).
    - WARN logs are enabled via __LOG_ENABLE_WARN__.
    - Host enforcement for PROD is still strict: HTTP Host must match
      __ALLOWED_HOST__.

Security note:

    - Server still uses TLS on port 443, but does not require client
      certificates.
    - Hardened deployment should still use the Makefile build.

-------------------------------------------------------------------------------
3) DEV mode, mTLS=1 (mutual TLS)
-------------------------------------------------------------------------------

Configuration:
    DEV mode: mutual TLS, WARN + INFO + DEBUG logs are disable.

Make command:

    make PROD=0 mTLS=1

Equivalent gcc command:

    gcc TCP_Server.c -o TCP_Server \
        -D__DEV__ \
        -D__REQUIRE_MUTUAL_TLS__ \
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
    - mTLS=1 maps to __REQUIRE_MUTUAL_TLS__.
    - DEV builds enable sanitizers and debug information.

Security note:

    - DEV builds are not hardened for production (sanitizers, no chroot, no
      privilege drop).
    - Intended only for development and debugging.

-------------------------------------------------------------------------------
4) DEV mode, mTLS=0 (server-auth only), DEBUG-only logging
-------------------------------------------------------------------------------

Configuration:
    DEV mode, mTLS=0 (no mutual TLS), DEBUG logging enabled (no WARN/INFO).

Make command:

    make PROD=0 mTLS=0 DEBUG=1

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
    - No __REQUIRE_MUTUAL_TLS__ means mTLS=0 (still encrypted, no client certs).
    - DEBUG=1 maps to __LOG_ENABLE_DEBUG__.
    - Sanitizers and debug info reflect DEV mode.

Security note:

    - DEBUG logging may expose internal data and is never allowed in PROD or
      BENCH builds.
    - Use only in safe development environments.

-------------------------------------------------------------------------------
5) BENCH mode, mTLS=1 (mutual TLS), INFO logs only
-------------------------------------------------------------------------------

Configuration:
    BENCH mode, mTLS=1, INFO logs enabled only.

Make command:

    make BENCH=1 mTLS=1 INFO=1

Equivalent gcc command:

    gcc TCP_Server.c -o TCP_Server \
        -D__BENCH__ \
        -D__REQUIRE_MUTUAL_TLS__ \
        -D__ALLOWED_HOST__=\"127.0.0.1\" \
        -D__LOG_ENABLE_INFO__ \
        -std=c2x \
        -O2 \
        -Wall -Wextra -Wpedantic \
        -Wformat=2 -Wshadow -Wpointer-arith \
        -Wcast-align -Wwrite-strings -Wconversion \
        -lssl -lcrypto

Why equivalent:

    - BENCH=1 maps to __BENCH__, with neither __DEV__ nor __PROD__ defined.
    - mTLS=1 maps to __REQUIRE_MUTUAL_TLS__.
    - INFO=1 maps to __LOG_ENABLE_INFO__.
    - __ALLOWED_HOST__ is typically 127.0.0.1 for BENCH builds.

Security note:

    - BENCH mode aims for realistic performance with minimal logging.
    - DEBUG logging is forbidden to avoid affecting timing measurements.

-------------------------------------------------------------------------------
6) BENCH mode, mTLS=0 (server-auth only), WARN logs only
-------------------------------------------------------------------------------

Configuration:
    BENCH mode, mTLS=0, WARN logs enabled.

Make command:

    make BENCH=1 mTLS=0 WARN=1

Equivalent gcc command:

    gcc TCP_Server.c -o TCP_Server \
        -D__BENCH__ \
        -D__ALLOWED_HOST__=\"127.0.0.1\" \
        -D__LOG_ENABLE_WARN__ \
        -std=c2x \
        -O2 \
        -Wall -Wextra -Wpedantic \
        -Wformat=2 -Wshadow -Wpointer-arith \
        -Wcast-align -Wwrite-strings -Wconversion \
        -lssl -lcrypto

Why equivalent:

    - __BENCH__ selects BENCH mode.
    - No __REQUIRE_MUTUAL_TLS__ corresponds to mTLS=0 (still TLS, no client
      certificates).
    - WARN=1 maps to __LOG_ENABLE_WARN__.

Security note:

    - These builds are for benchmarking. Use the Makefile and avoid adding
      DEBUG logs or extra diagnostics which would distort measurements.

-------------------------------------------------------------------------------
7) Minimal examples (summary)
-------------------------------------------------------------------------------

Minimal PROD, mutual TLS, no extra logs:

    make PROD=1 mTLS=1

Approximate gcc:

    gcc TCP_Server.c -o TCP_Server \
        -D__REQUIRE_MUTUAL_TLS__ \
        -D__ALLOWED_HOST__=\"secure.lab.linux\" \
        -std=c2x -O2 \
        -Wall -Wextra -Wpedantic \
        -Wformat=2 -Wshadow -Wpointer-arith \
        -Wcast-align -Wwrite-strings -Wconversion \
        -lssl -lcrypto

Minimal DEV, server-auth only, no extra logs:

    make PROD=0 mTLS=0

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
        -D__REQUIRE_MUTUAL_TLS__ \
        -D__ALLOWED_HOST__=\"127.0.0.1\" \
        -std=c2x \
        -O2 \
        -Wall -Wextra -Wpedantic \
        -Wformat=2 -Wshadow -Wpointer-arith \
        -Wcast-align -Wwrite-strings -Wconversion \
        -lssl -lcrypto

Again, for any deployment, use the Makefile-based builds. The gcc examples
are only provided to clarify which -D macros and flags correspond to which
Makefile configurations.
*/

/**
===============================================================================
HOST ENFORCEMENT AND ALLOWED HOSTS
===============================================================================

The Makefile sets __ALLOWED_HOST__ at compile time, using:

    PROD_HOST  ?= secure.lab.linux
    DEV_HOST   ?= localhost
    BENCH_HOST ?= 127.0.0.1

and then:

    PROD  build  -> __ALLOWED_HOST__ = $(PROD_HOST)
    DEV   build  -> __ALLOWED_HOST__ = $(DEV_HOST)
    BENCH build  -> __ALLOWED_HOST__ = $(BENCH_HOST)

Runtime behavior:

    PROD  builds:
        - HTTP "Host" header must match __ALLOWED_HOST__ exactly.
        - On mismatch, the server returns HTTP 400 "Host not allowed!".

    DEV   builds:
        - Host mismatch is logged as a warning but the request is still allowed.

    BENCH builds:
        - Host is logged for visibility but never enforced.

TLS hostname verification:

    - When mTLS=1 (mutual TLS), TLS-layer hostname verification is enabled.
    - When mTLS=0, only HTTP-level Host checks (as above) apply.

===============================================================================
TESTING GUIDE (OPENSSL S_CLIENT EXAMPLES, PORT 443)
===============================================================================

All examples assume:

    - Server listens on port 443.
    - Server certificate:    server-cert.pem
    - Server private key:    key.pem
    - CA bundle on both sides: ca-cert.pem

DEV mode, mTLS=1 (mutual TLS, all logs enabled):

    Build:

        make PROD=0 mTLS=1

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

PROD mode, mTLS=1 (mutual TLS, strict host enforcement):

    Build:

        make PROD=1 mTLS=1 WARN=1 INFO=1

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
        - If Host does not match __ALLOWED_HOST__, the server returns HTTP 400.

BENCH mode, mTLS=0 (server-auth TLS, minimal logging):

    Build:

        make BENCH=1 mTLS=0 INFO=1

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

    1) Missing client certificate with mTLS=1:
        - Build with mTLS=1.
        - Run s_client without -cert/-key.
        - Handshake must fail due to missing client auth.

    2) Wrong -servername with mTLS=1:
        - Supply a name not present in server certificate SAN/CN.
        - TLS hostname verification must fail.

    3) Wrong Host header in PROD:
        - Use Host different from __ALLOWED_HOST__.
        - Response must be HTTP 400 "Host not allowed!".

*/

/**
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

*/

/**
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


Optional: JSON audit utility (recommended for CI/test environments)

    sudo apt install jq

    jq:
        - Used by test_builds.sh to merge per-build JSON results into
          summary.json for audit and compliance visibility.
        - If jq is not installed, test_builds.sh will still run using a
          minimal JSON summary (no runtime dependency in the server).

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
    jq (optional)                -> JSON compliance audit reports for CI
    update-alternatives ...      -> Switches system to chosen GCC <V> by default
    make / sudo make install     -> Builds and installs OpenSSL from source
    openssl version -a           -> Verifies installed OpenSSL version
    apt list / full-upgrade      -> Resolves outdated or missing packages
    apt-get ... snapd            -> Cleans up snapd warnings if necessary

*/

/**
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
(PROD / DEV / BENCH, mTLS, and logging) combination.

===============================================================================
@section security_compliance Security Compliance Summary (S16)
===============================================================================

This software is designed for hardened operational deployment only when built
using the Makefile in a valid PROD or BENCH configuration with:

		- TLS encryption always enabled, and
		- Mutual TLS (TLS=1) enforced by policy in PROD/BENCH.

These Makefile builds apply:

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

/* ============================================================================
 * Security Level Enforcement (__SECURITY_LEVEL__)
 *
 * OCSP is not yet implemented. Until full support is added:
 *
 *   - DEV builds:
 *       __SECURITY_LEVEL__ >= 3  → compile-time warning only.
 *
 *   - BENCH / PROD builds:
 *       __SECURITY_LEVEL__ >= 3  → compile-time error (hardened builds
 *       must not claim OCSP capability until implementation is complete).
 * ============================================================================
 */
#if defined(__SECURITY_LEVEL__) && (__SECURITY_LEVEL__ >= 3)
    #if defined(__DEV__)
        #warning "OCSP (SECURITY_LEVEL>=3) not implemented yet — continuing in DEV build only"
    #else
        #error "OCSP (SECURITY_LEVEL>=3) not implemented — SECURITY_LEVEL>=3 is forbidden in PROD/BENCH builds"
    #endif
#endif

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

#if !defined(__DEV__)

/* ============================================================================
 * OS-level sandbox for PROD / BENCH
 *
 *  - In PROD and BENCH builds (no __DEV__):
 *      * The process is expected to start as root (to allow chroot + priv-drop).
 *      * After InitialiseServer() binds the listening socket:
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

#endif // of !defined(__DEV__)

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

/* ============================================================================
 * Revocation store configuration for __SECURITY_LEVEL__
 *
 *  SECURITY_LEVEL = 1:
 *      - CRL checks OFF
 *      - OCSP OFF
 *      - Intended for DEV/CI only (no revocation enforcement).
 *
 *  SECURITY_LEVEL = 2:
 *      - Enable CRL-based revocation:
 *          X509_V_FLAG_CRL_CHECK
 *      - Required for hardened PROD/BENCH builds.
 *
 *  SECURITY_LEVEL >= 3:
 *      - Intended for stricter CRL + OCSP in the future.
 *      - OCSP is NOT implemented, needs X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL (future extension: deeper chain)
 *      - DEV: allowed with compile-time warning only.
 *      - PROD/BENCH: forbidden (compile-time error).
 *
 *  Notes:
 *      - CRL file is loaded from CA_CRL_PATH_FULL.
 *      - OCSP is enforced as "not implemented" elsewhere via compile-time checks.
 *
 *  Returns:
 *      true  → configuration applied successfully
 *      false → configuration failed (must abort in hardened builds)
 * ============================================================================
 */
static bool rvConfigureRevocationStore(SSL_CTX* ssl_ctx)
{
#if !defined(__SECURITY_LEVEL__)
    (void)ssl_ctx;
    LOG_INFO("Security Level: not defined at compile time (CRL/OCSP disabled)");
    return true;  /* No revocation policy enforced */
#else
    /* Get the verification store (always exists after SSL_CTX_new) */
    X509_STORE* store = SSL_CTX_get_cert_store(ssl_ctx);
    if ((X509_STORE*)NULL == store)
    {
        LOG_ERROR("Revocation: SSL_CTX_get_cert_store() returned NULL");
        return false;
    }

		 /* Level 1 → CRL and OCSP disabled */
		if (__SECURITY_LEVEL__ <= 1)
		{
				LOG_INFO("Revocation: SECURITY_LEVEL=%d → CRL=OFF, OCSP=OFF (DEV/CI only)",
								 (int)__SECURITY_LEVEL__);
				return true;
		}

		/*
		 * Level 2 or higher → enable CRL checking.
		 * OCSP is *not* implemented; SECURITY_LEVEL>=3 is guarded at compile time.
		 */
		unsigned long flags = X509_V_FLAG_CRL_CHECK;

		/* SECURITY_LEVEL >= 3 → stricter CRL chain checking (still CRL-only) */
		if (__SECURITY_LEVEL__ >= 3)
		{
				flags |= X509_V_FLAG_CRL_CHECK_ALL;
				LOG_WARN("OCSP NOT IMPLEMENTED — revocation is CRL-only (SECURITY_LEVEL >= 3)");
		}

    /*
     * Attach a file-based lookup so the store can actually load the CRL file.
     */
    X509_LOOKUP* lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
    if ((X509_LOOKUP*)NULL == lookup)
    {
        LOG_ERROR("Revocation: X509_STORE_add_lookup(file) failed");
        return false;
    }

    if (1 != X509_load_crl_file(lookup, CA_CRL_PATH_FULL, X509_FILETYPE_PEM))
    {
        LOG_ERROR("Revocation: failed to load CRL file '%s'", CA_CRL_PATH_FULL);
#if defined(__DEV__)
        /* In DEV builds, show detailed OpenSSL errors for debugging */
        ERR_print_errors_fp(stderr);
#endif
        return false;
    }

    /* Now enable CRL flags on the store */
    if (0 == X509_STORE_set_flags(store, flags))
    {
        LOG_ERROR("Revocation: X509_STORE_set_flags(0x%lx) failed", flags);
        return false;
    }

    LOG_INFO("Revocation: Enabled CRL checks (SECURITY_LEVEL=%d, flags=0x%lx, crl='%s')",
             (int)__SECURITY_LEVEL__, flags, CA_CRL_PATH_FULL);

    return true;
#endif /* !defined(__SECURITY_LEVEL__) */
}

static bool InitialiseServer(void)
{
	bool ret = false;

    /* Log security level and revocation policy at startup */
#if defined(__SECURITY_LEVEL__)
	LOG_INFO("Security Level: %d (CRL=%s, OCSP=%s)",
					 (int)__SECURITY_LEVEL__,
					 (__SECURITY_LEVEL__ >= 2) ? "ON" : "OFF",
					 (__SECURITY_LEVEL__ >= 3) ? "ON (NOT IMPLEMENTED)" : "OFF");
#else
	LOG_INFO("Security Level: (not defined at compile time)");
#endif

#if defined(__DEV__) && defined(__SECURITY_LEVEL__) && (__SECURITY_LEVEL__ >= 3)
	LOG_WARN("DEV: OCSP support is NOT IMPLEMENTED — revocation is CRL-only despite SECURITY_LEVEL >= 3");
#endif

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
		if (0 >= SSL_CTX_use_certificate_file(ctx, SERVER_CERT_PATH_FULL, SSL_FILETYPE_PEM))
		{
			LOG_ERROR("Failed to load server certificate (%s)", SERVER_CERT_NAME);
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

		if (0 >= SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY_PATH_FULL, SSL_FILETYPE_PEM))
		{
			LOG_ERROR("Failed to load private key (%s)", SERVER_KEY_NAME);
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

		/* Load CA first */
		/* 	Present a server certificate → CA needed for proper certificate chain
				Support client verification if DEV toggles mTLS later
				Enable TLS handshake authentication correctly
		*/
		if (1 != SSL_CTX_load_verify_locations(ctx, CA_CERT_PATH_FULL, ((const char*)NULL)))
		{
			LOG_ERROR("Failed to load CA certificate (%s)", CA_CERT_NAME);

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

		/* Configure revocation (CRL) policy based on __SECURITY_LEVEL__ */
		if (!rvConfigureRevocationStore(ctx))
		{
#if defined(__DEV__)
			/*
			 * DEV:
			 *   - Allow server to continue even if CRL configuration fails.
			 *   - This keeps developer iteration easy while still surfacing the error.
			 */
			LOG_WARN("Revocation: configuration failed in DEV build — continuing WITHOUT revocation checks");
#else
			/*
			 * PROD / BENCH:
			 *   - Hardened requirement: CRL must be configured correctly when
			 *     SECURITY_LEVEL >= 2 (the Makefile already enforces files exist).
			 *   - Treat failure as fatal for server initialization.
			 */
			LOG_ERROR("Revocation: configuration failed in hardened build — aborting server initialization");
			break;
#endif
		}

#if defined( __REQUIRE_MUTUAL_TLS__ )
		LOG_INFO("Mutual TLS enabled: verifying client certificates using %s", CA_CERT_NAME);
		/*
		 * Mutual TLS (Client Certificate Authentication)
		 * Require clients to present a certificate and verify it using our CA.
		 */
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, ((int (*)(int, X509_STORE_CTX*))NULL));
#else // of defined( __REQUIRE_MUTUAL_TLS__ )
    /*
     * DEV or BENCH with mTLS=0:
     * -------------------------------------
     * - TLS encryption still required
     * - No client certificate authentication
     * - Do NOT enable SSL_VERIFY_FAIL_IF_NO_PEER_CERT
     *
     * Defense rule:
     *   Verification must be explicitly disabled when TLS=0,
     *   to avoid accidental partial client-auth dependencies.
     */
		SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, ((int (*)(int, X509_STORE_CTX*))NULL));
#endif // of defined( __REQUIRE_MUTUAL_TLS__ )

#if defined( __REQUIRE_MUTUAL_TLS__ )
		/* Allow intermediate chains up to depth 3 */
		SSL_CTX_set_verify_depth(ctx, 3);

		STACK_OF(X509_NAME)* ca_list = SSL_load_client_CA_file(CA_CERT_PATH_FULL);
		if (((STACK_OF(X509_NAME)*)NULL) != ca_list)
		{
			SSL_CTX_set_client_CA_list(ctx, ca_list);
		}
		else
		{
			LOG_WARN("Warning: Failed to load client CA list from %s", CA_CERT_PATH_FULL);
		}
#endif // of defined( __REQUIRE_MUTUAL_TLS__ )

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

		const int iGetAddInfoErrCode = getaddrinfo((const char*)NULL, (const char*)__TLS_PORT_STR__, &hints, &server);
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
#if defined( __REQUIRE_MUTUAL_TLS__ )
		LOG_INFO("\nHTTPS (Mutual TLS) server listening on port %d...", (int)__TLS_PORT__);
#else // of defined( __REQUIRE_MUTUAL_TLS__ )
		LOG_INFO("\nHTTPS (TLS) server listening on port %d...", (int)__TLS_PORT__);
#endif // of defined( __REQUIRE_MUTUAL_TLS__ )

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

#if defined( __REQUIRE_MUTUAL_TLS__ )
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
#endif // of defined( __REQUIRE_MUTUAL_TLS__ )
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
#if defined(__DEV__)
				ERR_print_errors_fp(stderr);
#endif
				rvSanAbortOnOpenSSLError("SSL_accept", err);
			}

			rvShutDownSSL_AndCloseFD();
			continue;
		}

		/* ---- Start: Mutual TLS block ---- */
#if defined( __REQUIRE_MUTUAL_TLS__ )
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
#endif // of defined( __REQUIRE_MUTUAL_TLS__ )
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
			 * Host Enforcement (Defense-Grade Policy)
			 *
			 * Enforcement rules:
			 *
			 *   DEV:
			 *     - Log mismatch but allow request (development convenience)
			 *
			 *   BENCH / PROD:
			 *     - STRICT reject on mismatch — ensures performance evaluation
			 *       is done under correct operational hostname
			 */

#if defined(__DEV__)
			if (0 != strcmp(req_host, __ALLOWED_HOST__))
			{
				LOG_WARN("DEV: Host '%s' != allowed '%s' (allowed only in DEV)", req_host, __ALLOWED_HOST__);
			}
#else /* BENCH/PROD — strict */
			if (0 != strcmp(req_host, __ALLOWED_HOST__))
			{
				LOG_ERROR("Host mismatch '%s' != '%s' (rejected in BENCH/PROD)", req_host, __ALLOWED_HOST__);
				(void)send_http_response(ssl, 400, "Bad Request", "Host not allowed!\r\n");
				rvShutDownSSL_AndCloseFD();
				continue;
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
	bool init_ok = InitialiseServer();

	if ((true == init_ok) && (0 == g_exit_requested))
	{
#if defined(__DEV__)
		/* DEV build: no chroot/priv-drop/rlimits to keep debugging simple. */
		LOG_INFO("DEV build: running WITHOUT chroot/priv-drop/rlimits (for debugging only).");
#else
		/*
		 * PROD / BENCH builds:
		 *   - Process is expected to start as root so we can chroot and drop privileges.
		 *   - After InitialiseServer() binds the listening socket, we:
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
    /* Option A: one-time runtime security banner */
    print_runtime_security_banner();
		RunServerLoop();
	}

	rvShutDownSSL_AndCloseFD();
	FreeAndClose();

	LOG_INFO("Server terminated.");

	return ((true == init_ok) && (0 == g_exit_requested)) ? EXIT_SUCCESS : EXIT_FAILURE;
}
