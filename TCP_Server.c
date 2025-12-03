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
 * =============================================================================
 * Build Options
 * =============================================================================
 *   make TLS=1     → TLS Server with Mutual TLS (client certificate required)
 *   make TLS=0     → TLS Server only (client certificate NOT required)
 *
 * Notes:
 *   - TLS is always enabled in both builds.
 *   - Plain TCP (without TLS) is not supported and will fail.
 *
 * =============================================================================
 * Testing: TLS=0 Build (Server Authentication Only)
 * =============================================================================
 * - Server presents its certificate: cert.pem
 * - Client is NOT required to present a certificate
 *
 * Command:
 *   openssl s_client -connect 127.0.0.1:8080 -servername 127.0.0.1 -CAfile ca-cert.pem -crlf -tls1_3
 * or
 *   openssl s_client -connect 127.0.0.1:8080 -servername localhost -CAfile ca-cert.pem -crlf -tls1_3
 *
 * Once connected, manually type:
 *   GET / HTTP/1.1
 *   Host: localhost
 *
 *   <press Enter twice to end headers>
 *
 * Expected:
 *   HTTP/1.1 200 OK
 *
 * =============================================================================
 * Testing: TLS=1 Build (Mutual TLS + Hostname Verification)
 * =============================================================================
 * A) Valid client certificate → Should succeed
 *    Command:
 *      openssl s_client -connect 127.0.0.1:8080 -servername 127.0.0.1 \
 *          -cert client-cert.pem -key client-key.pem \
 *          -CAfile ca-cert.pem -crlf -tls1_3
 *    Then manually type the HTTP request (as above)
 *
 * B) Missing client certificate → Should fail TLS handshake
 *    Command:
 *      openssl s_client -connect 127.0.0.1:8080 -servername 127.0.0.1 \
 *          -CAfile ca-cert.pem -crlf -tls1_3
 *
 * C) Wrong hostname → Should fail hostname verification
 *    Command:
 *      openssl s_client -connect 127.0.0.1:8080 -servername WRONG \
 *          -cert client-cert.pem -key client-key.pem \
 *          -CAfile ca-cert.pem -crlf -tls1_3
 *
 * Mutual TLS + Hostname Verification Validation:
 *   - A succeeds
 *   - B fails (no client certificate)
 *   - C fails (hostname mismatch)
 *
 * =============================================================================
 * Manual HTTP Request (All Builds)
 * =============================================================================
 * After handshake succeeds (TLS=0 OR TLS=1 with valid cert):
 *
 *   GET / HTTP/1.1
 *   Host: localhost
 *
 *   <press Enter twice to complete headers>
 *
 * Expected:
 *   HTTP/1.1 200 OK
 *
 * =============================================================================
 * Clean Shutdown
 * =============================================================================
 * Press Ctrl+C in the server terminal
 * Expected:
 *   Caught signal <n>. Cleaning up server loop and exiting...
 *   Server terminated.
 *
 * Ctrl+Z (SIGTSTP) is handled as a request to terminate cleanly rather than
 * suspending the process, to avoid leaving a background process that later
 * needs to be killed manually.
 *
 * =============================================================================
 */

/*
 * =============================================================================
 * System Prerequisites (Ubuntu / Debian-based / WSL2)
 * =============================================================================
 *
 * GCC 13 or newer is mandatory due to C23 usage in this project.
 *
 * Check current GCC version:
 *
 *     gcc --version
 *
 * If version is lower than 13 (common on WSL2 and Ubuntu 22.04 upgrades),
 * install and select GCC 13 as default:
 *
 *     sudo apt install software-properties-common
 *     sudo add-apt-repository ppa:ubuntu-toolchain-r/test
 *     sudo apt update
 *     sudo apt install gcc-13 g++-13
 *
 *     # Configure GCC 13 as the system default compiler:
 *     sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-13 100
 *     sudo update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-13 100
 *     sudo update-alternatives --config gcc
 *
 * Required packages for building this server:
 *
 *     sudo apt install build-essential apt-file openssl libssl-dev
 *     sudo apt-file update
 *
 * Optional:
 *   If system OpenSSL version is older and TLS feature support is insufficient,
 *   build a recent OpenSSL manually:
 *
 *     mkdir ~/openssl_3_5
 *     cd ~/openssl_3_5
 *     wget https://github.com/openssl/openssl/releases/download/openssl-3.5.4/openssl-3.5.4.tar.gz
 *     tar xzvf openssl-3.5.4.tar.gz
 *     cd openssl-3.5.4
 *     ./config
 *     make
 *     sudo make install
 *     openssl version -a
 *
 * Troubleshooting:
 *   If missing headers or link errors occur:
 *
 *     sudo apt list --upgradable
 *     sudo apt full-upgrade
 *
 *   If a specific package upgrade notice persists (e.g., snapd):
 *
 *     sudo apt-get --simulate install snapd
 *     sudo apt-get install snapd
 *
 * -----------------------------------------------------------------------------
 * Build Configuration and Host Enforcement (Makefile-controlled)
 * -----------------------------------------------------------------------------
 *
 *  - This C file does NOT hard-code build modes, logging policy, TLS enable/disable,
 *    or Host enforcement values.
 *
 *  - All such settings are injected by the Makefile via compiler definitions, e.g.:
 *
 *        -D__DEV__
 *        -D__BENCH__
 *        -D__ENABLE_MUTUAL_TLS__
 *        -DRV_ALLOWED_HOST="secure.lab.linux"
 *
 *  - Per-mode Host defaults (defined in Makefile, not here):
 *
 *        PROD_HOST  ?= secure.lab.linux
 *        DEV_HOST   ?= localhost
 *        BENCH_HOST ?= 127.0.0.1
 *
 *    The Makefile maps these to RV_ALLOWED_HOST at compile time.
 *
 * -----------------------------------------------------------------------------
 * PROD / BENCH Deployment Requirement:
 *   For hardened sandboxing, a chroot jail must be prepared before running:
 *
 *       sudo mkdir -p /var/secure-tls-server
 *       sudo cp cert.pem key.pem ca-cert.pem /var/secure-tls-server
 *       sudo chown -R root:root /var/secure-tls-server
 *       sudo chmod -R 750 /var/secure-tls-server
 *
 *   See rvDropPrivileges_AndChroot() for more details.
 * -----------------------------------------------------------------------------
 *
 * =============================================================================
*/

/*
 * =============================================================================
 * Local Build Options (direct gcc - alternative to using make)
 * =============================================================================
 * 1) Quick functional test (not hardened):
 *
 *      gcc TCP_Server.c -o TCP_Server -lssl -lcrypto
 *
 * NOTE:
 *   Not for performance or security validation. Use Makefile build instead.
 *
 * 2) Hardened warnings + optimisation  --> Equivalent to PROD behaviour
 *
 *      gcc -std=c2x TCP_Server.c -o TCP_Server \
 *          -Wall -Wextra -Werror -Wpedantic \
 *          -Wformat=2 -Wshadow -Wpointer-arith \
 *          -Wcast-align -Wwrite-strings -Wconversion \
 *          -O2 \
 *          -lssl -lcrypto
 *
 * NOTE for reviewers:
 *   This approximates the PROD mode produced via Makefile,
 *   but it does NOT include the complete set of hardening
 *   flags that Makefile adds (PIE, FORTIFY, RELRO, stack protector, etc.).
 *   In Makefile terms: this corresponds to PROD mode (default) without full hardening.
 *
 * 3) Mutual TLS (client certificate required):
 *
 *      gcc -std=c2x TCP_Server.c -o TLS_Server_mTLS \
 *          -Wall -Wextra -Werror -Wpedantic \
 *          -Wformat=2 -Wshadow -Wpointer-arith \
 *          -Wcast-align -Wwrite-strings -Wconversion \
 *          -O2 \
 *          -D__ENABLE_MUTUAL_TLS__ \
 *          -lssl -lcrypto
 *
 * 4) Development mode (sanitisers + verbose logging - equivalent to make PROD=0):
 *
 *      gcc -std=c2x TCP_Server.c -o TLS_Server_DEV \
 *          -Wall -Wextra -g3 -O0 \
 *          -D__DEV__ \
 *          -D__LOG_ENABLE_WARN__ \
 *          -D__LOG_ENABLE_INFO__ \
 *          -D__LOG_ENABLE_DEBUG__ \
 *          -fsanitize=address,undefined \
 *          -lssl -lcrypto
 *
 * For actual hardened deployment or performance benchmarking:
 *      Please build using:  make
 *
 * This guarantees:
 *   - All security hardening flags are enabled
 *   - Mode selection (__DEV__ / __BENCH__) is correct
 *   - Logging rules are enforced based on security policy
 */

/*
 * =============================================================================
 *  PRIMARY MODES, SECURITY FEATURES, AND LOGGING BEHAVIOR
 * =============================================================================
 *
 * Selected at build time using Makefile (GCC -D defines):
 *
 *   PROD   (default): make
 *   DEV mode        : make PROD=0
 *   BENCH=1         : make BENCH=1
 *
 * Mode Precedence:
 *
 * Mutually exclusive modes:
 *   - Makefile ensures only one mode (__DEV__ or __BENCH__) is ever defined
 *   - If neither is defined → PROD (safe default)
 *
 * -----------------------------------------------------------------------------
 * Features by Mode
 * -----------------------------------------------------------------------------
 * Mode ↓ / Feature →  TLSH  Logs*  ASan  Timing  Sandbox
 * -----------------------------------------------------
 * PROD (default)       1     sel    0     1       1
 * DEV                  1     sel    1     0       0
 * BENCH                1     sel    0     0       1
 * -----------------------------------------------------
 *
 * -----------------------------------------------------------------------------
 * Logging Enforcement by Mode
 * -----------------------------------------------------------------------------
 * Mode ↓  / Log →   ERROR  WARN  INFO  DEBUG
 * ------------------------------------------
 * PROD (default)     1     0/1   0/1   0   ← WARN & INFO allowed only if requested
 * PROD (allowed)     1     1     1     0   ← WARN & INFO allowed only if requested
 * DEV                1     0/1   0/1   0/1 ← Developer decides via sub-flags
 * BENCH              1     0/1   0/1   0   ← DEBUG never allowed
 * ------------------------------------------
 *
 * Log Request Macros (optional, via Makefile → GCC -D)
 *   -D__LOG_ENABLE_WARN__
 *   -D__LOG_ENABLE_INFO__
 *   -D__LOG_ENABLE_DEBUG__  (denied in PROD/BENCH)
 *   LOG_ALL=1  (Makefile expands this to all three __LOG_ENABLE_*__ macros)
 *
 * Hard Denials:
 *   DEBUG logs are never allowed in PROD or BENCH builds:
 *     #error raised if LOG_ENABLE_DEBUG is requested in forbidden modes
 *
 * =============================================================================
 */

/* ============================================================================
 * Logging Macros
 * ============================================================================
 *
 * LOG_ERROR / LOG_WARN / LOG_INFO:
 *   - Always compiled in.
 *   - Never include __FILE__ or __LINE__ in messages.
 *
 * LOG_DEBUG:
 *   - Enabled only when (__DEV__ & __LOG_ENABLE_DEBUG__) from Makefile
 *   - Compiled out entirely in BENCH or PROD builds
 *   - Intended for developer diagnostics only
 */

/* ============================================================================
 * Default log threshold per mode
 * ============================================================================
 */

/* Print directly to output if the calling macro permits it */
#define LOG_PRINT_STD(stream, prefix, fmt, ...) \
    do { \
        fprintf((stream), prefix fmt "\n", ##__VA_ARGS__); \
        fflush((stream)); \
    } while (false)

/* ============================================================================
 * Build Mode Detection
 * ============================================================================
 *
 * This server now supports three logical build modes, selected only via
 * Makefile → GCC -D defines:
 *
 *   PROD  : Default when neither __DEV__ nor __BENCH__ is defined.
 *           Hardened deployment mode. Minimal logging; DEBUG forbidden.
 *
 *   __DEV__  : Development mode (sanitizers enabled via Makefile, e.g. -fsanitize).
 *              Logging can include WARN/INFO/DEBUG if corresponding
 *              __LOG_ENABLE_*__ macros are defined.
 *
 *   __BENCH__ : Performance benchmarking mode. Optimized, minimal logs.
 *               DEBUG logging is forbidden to avoid distorting measurements.
 *
 * Notes:
 *   - __DEV__ and __BENCH__ must never both be defined at the same time.
 *   - DEV vs BENCH is chosen by Makefile based on DEV=1 / BENCH=1 flags.
 */

/*
 * ============================================================================
 * Mode Selection (Enforced + Auto SAN in DEV)
 * ============================================================================
 *
 * - __DEV__ and __BENCH__ must not coexist
 * - MODE_SAN enabled automatically for DEV builds
 * - If neither defined → PROD mode (secure default)
 */
#if defined(__DEV__) && defined(__BENCH__)
#error "__DEV__ and __BENCH__ must not be defined together."
#endif

#if defined(__DEV__) && !defined(MODE_SAN)
#define MODE_SAN 1
#endif

#if defined(__DEV__)
	/* DEV Mode: Sanitizers + Expanded Logging */
#elif defined(__BENCH__)
	/* BENCH Mode: Performance benchmarking */
#else
	/* PROD Mode: Hardened minimal logging */
#endif

/* ============================================================================
 * TLS Feature Selection (__ENABLE_MUTUAL_TLS__)
 * ============================================================================
 *
 * If undefined → Mutual TLS is disabled
 * If defined   → Client authentication required
 */

/* ============================================================================
 * Logging Sub-Flag Enforcement
 * ============================================================================
 *
 * Flags allowed only from Makefile:
 *   -D__LOG_ENABLE_WARN__
 *   -D__LOG_ENABLE_INFO__
 *   -D__LOG_ENABLE_DEBUG__
 *
 * DEBUG allowed **only** in __DEV__ mode.
 */

#if !defined(__DEV__) && defined(__LOG_ENABLE_DEBUG__)
#error "DEBUG logging is only allowed in __DEV__ builds. Remove __LOG_ENABLE_DEBUG__ or build with DEV=1."
#endif

/* ============================================================================
 * Logging Implementations
 * ============================================================================
 */

#define LOG_ERROR(fmt, ...) \
    LOG_PRINT_STD(stderr, "[ERROR] ", fmt, ##__VA_ARGS__)

#ifdef __LOG_ENABLE_WARN__
#define LOG_WARN(fmt, ...) \
    LOG_PRINT_STD(stderr, "[WARN ] ", fmt, ##__VA_ARGS__)
#else
#define LOG_WARN(fmt, ...) do {} while(0)
#endif

#ifdef __LOG_ENABLE_INFO__
#define LOG_INFO(fmt, ...) \
    LOG_PRINT_STD(stdout, "[INFO ] ", fmt, ##__VA_ARGS__)
#else
#define LOG_INFO(fmt, ...) do {} while(0)
#endif

#if defined(__DEV__) && defined(__LOG_ENABLE_DEBUG__)
#define LOG_DEBUG(fmt, ...) \
    LOG_PRINT_STD(stdout, "[DEBUG] ", fmt, ##__VA_ARGS__)
#else
#define LOG_DEBUG(fmt, ...) do {} while(0)
#endif

#if 1
#define LOG_ERROR_ERRNO(fmt, ...) \
    do { \
        char errbuf[512]; \
        const char* errstr = errbuf; \
        int __e = errno; \
        if (0 != strerror_r(__e, errbuf, sizeof(errbuf))) { \
            snprintf(errbuf, sizeof(errbuf), "errno %d", __e); \
        } \
        LOG_ERROR(fmt ": %s", ##__VA_ARGS__, errstr); \
    } while(0)
#else // of 1
#define LOG_ERROR_ERRNO(msg) \
    do { \
        char errbuf[512]; \
        const char* errstr = errbuf; \
        int __e = errno; \
        /* POSIX strerror_r */ \
        if (0 != strerror_r(__e, errbuf, sizeof(errbuf))) { \
            snprintf(errbuf, sizeof(errbuf), "errno %d", __e); \
        } \
        LOG_ERROR("%s: %s", msg, errstr); \
    } while(0)
#endif // of 1

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
 */
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
    } else {
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
 */
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
