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
#include <arpa/inet.h>    /* sockaddr conversions, AF_INET, AF_INET6 */
#include <sys/time.h>     /* struct timeval */
#include <signal.h>	/* Signals + process */
#include <sys/select.h>   /* FD_* macros if used later */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h> /* Required for socket functions like socket(), connect(), etc. */
#include <sys/types.h>
#include <unistd.h> /* Required for close() */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netinet/tcp.h>
#include <time.h>
#include <ctype.h>

/*
 * =============================================================================
 * INPUT TO USER:
 * =============================================================================
 *
 *	Enable macro ENABLE_MUTUAL_TLS using gcc or makefile to enforce client certificate authentication
 *	To enforce Mutual TLS build with:
 *		gcc -DENABLE_MUTUAL_TLS ...
 *	or
 *		make TLS=1
 */

/*
 * =============================================================================
 * Build Options
 * =============================================================================
 *   make TLS=1     → TLS Server with Mutual TLS (client certificate required)
 *   make TLS=0     → TLS Server only (client certificate NOT required)
 *
 * Notes:
 *   - TLS is always enabled in both builds.
 *   - Plain TCP (telnet/nc without TLS) is not supported and will fail.
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
 * =============================================================================
 */

/*
 *	Install requred tools & packages:
 *		donot use "sudo apt install gcc" as this installs GCC version 11. Rather use below commands to install GCC-13
 *		sudo apt install software-properties-common
 *		sudo add-apt-repository ppa:ubuntu-toolchain-r/test
 *		sudo apt update
 *		sudo apt install gcc-13
 *		sudo apt install build-essential
 *		sudo apt install libssl-dev
 *		sudo apt update
 *		sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-13 100 --slave /usr/bin/g++ g++ /usr/bin/g++-13
 *		sudo update-alternatives --config gcc
 *		sudo apt update
 *		sudo apt autoclean
 *		mkdir ~/openssl_3.5
 *		cd ~/openssl_3.5
 *		wget https://github.com/openssl/openssl/releases/download/openssl-3.5.4/openssl-3.5.4.tar.gz
 *		tar xzvf openssl-3.5.4.tar.gz
 *		cd openssl-3.5.4
 *		./config -Wl,--enable-new-dtags,-rpath,'$(LIBRPATH)'
 *		make
 *		sudo make install
 *		# check installed OpenSSL version using below command. It should report:
 *		# OpenSSL 3.5.4 30 Sep 2025 (Library: OpenSSL 3.5.4 30 Sep 2025)
 *		openssl version -a
 *
 *	For initial testing, compile code using below command (where flag -l is used to link OpenSSL libraries,
 *	typically libssl and libcrypto):
 *		gcc TCP_Server.c -o TCP_Server.o -lssl -lcrypto
 *
 *	RELEASE: COMPILE CODE USING either using the
 *		make command (with makefile present in code compile directory):
 *	or
 *		gcc -std=c2x TCP_Server.c -o TCP_Server.o -Wall -Wextra -Werror -Wpedantic -Wformat=2 -Wshadow -Wpointer-arith -Wcast-align -Wwrite-strings -Wconversion -lssl -lcrypto
 *
 *	Install packages to find a header file:
 *		sudo apt update
 *	NOTES:
 *		 1. If error/message like below pops up:
 *				1 package can be upgraded. Run 'apt list --upgradable' to see it.
 *				execute "sudo apt list --upgradable"
 *		 2. If error/message like below (2 lines) pops up:
 *				snapd/jammy-updates 2.72+ubuntu22.04 amd64 [upgradable from: 2.71+ubuntu22.04]
 *				N: There are 3 additional versions. Please use the '-a' switch to see them.
 *				First execute "sudo apt-get --simulate install jammy-updates"
 *				Then after ensuring there are no dependency issues execute "sudo apt-get install jammy-updates"
 *				or otherwise install the dependencies as well.
 *		sudo apt full-upgrade
 *		sudo apt install apt-file
 *		sudo apt-file update
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

static void FreeAndClose(void)
{
	if (((struct addrinfo*)NULL) != server)
	{
		fprintf(stdout, "Freeing Server Address Information...\n");
		freeaddrinfo(server);
		server = (struct addrinfo*)NULL;
	}

	if (-1 != iSocketFieldDescription)
	{
		fprintf(stdout, "Closing Listen Socket...\n");
		close(iSocketFieldDescription);
		iSocketFieldDescription = -1;
	}

	if (((SSL_CTX*)NULL) != ctx)
	{
		fprintf(stdout, "Freeing SSL Context...\n");
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
			fprintf(stderr, "SSL_shutdown failed, error=%d\n", sd_err);
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

static int ssl_write_all(SSL* ssl_handle, const char* buffer, int length)
{
	int ret = -1;
	int total = 0;
	const unsigned char* p = (const unsigned char*)buffer;

	do
	{
		if ((((SSL*)NULL) == ssl_handle) || (((const void*)NULL) == buffer) || (0 >= length))
		{
			fprintf(stderr, "Invalid parameters in ssl_write_all\n");
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
				fprintf(stderr, "SSL_write failed, error %d\n", err);
				break;
			}
			total += written;
		}

		if ((total < length) && (attempts >= max_attempts))
		{
				fprintf(stderr, "SSL_write aborted after too many retries\n");
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
			fprintf(stderr, "Invalid parameters in send_http_response\n");
			break;
		}

		const int body_len = (int)strlen(body);

		/* Format current date */
		char datebuf[128];
		time_t now = time((time_t*)NULL);
		struct tm* gmt = gmtime(&now);

		if (((struct tm*)NULL) != gmt)
		{
			strftime(datebuf, sizeof(datebuf), "%a, %d %b %Y %H:%M:%S GMT", gmt);
		}
		else
		{
			/* Fallback if gmtime fails */
			snprintf(datebuf, sizeof(datebuf), "Thu, 01 Jan 1970 00:00:00 GMT");
		}

		char header[512];
		int header_len = snprintf(header,
			sizeof(header),
			"HTTP/1.1 %d %s\r\n"
			"Date: %s\r\n"
			"Content-Type: text/plain\r\n"
			"Content-Length: %d\r\n"
			"Connection: close\r\n"
			"\r\n",
			status,
			reason,
			datebuf,
			body_len);

		if ((0 >= header_len) || ((int)sizeof(header) <= header_len))
		{
			fprintf(stderr, "HTTP header formatting failed\n");
			break;
		}

		if (0 > ssl_write_all(ssl_handle, header, header_len))
		{
			fprintf(stderr, "[ERROR] Failed sending HTTP header\n");
			break;
		}

		if (0 > ssl_write_all(ssl_handle, body, body_len))
		{
			fprintf(stderr, "[ERROR] Failed sending HTTP body\n");
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

		/* Disable TLS compression (CRIME mitigation) */
 		SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);

		/* Load certificate and ECDSA private key (PEM files) */
		if (0 >= SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM))
		{
			ERR_print_errors_fp(stderr);
			break;
		}

		if (0 >= SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM))
		{
			ERR_print_errors_fp(stderr);
			break;
		}

		/* Ensure private key matches certificate */
		if (1 != SSL_CTX_check_private_key(ctx))
		{
			fprintf(stderr, "Private key mismatch\n");
			break;
		}

#if defined( ENABLE_MUTUAL_TLS )
    /* Load CA first */
		const char CACertFileName[] = "ca-cert.pem";
		if (1 != SSL_CTX_load_verify_locations(ctx, CACertFileName, ((const char*)NULL)))
		{
			fprintf(stderr, "Failed to load CA certificate for mutual TLS\n");
			break;
		}
		fprintf(stdout, "Mutual TLS enabled: verifying client certificates using ca-cert.pem\n");
		/*
		 * Mutual TLS (Client Certificate Authentication)
		 * Require clients to present a certificate and verify it using our CA.
		 */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, ((int (*)(int, X509_STORE_CTX*))NULL));
#else // of defined( ENABLE_MUTUAL_TLS )
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, ((int (*)(int, X509_STORE_CTX*))NULL));
#endif // of defined( ENABLE_MUTUAL_TLS )

#if defined( ENABLE_MUTUAL_TLS )

		/* Allow intermediate chains up to depth 3 */
		SSL_CTX_set_verify_depth(ctx, 3);

		STACK_OF(X509_NAME) *ca_list = SSL_load_client_CA_file(CACertFileName);
		if ( ( (STACK_OF(X509_NAME) *)NULL ) != ca_list )
		{
			SSL_CTX_set_client_CA_list(ctx, ca_list);
		}
		else
		{
			fprintf(stderr, "Warning: Failed to load client CA list from %s\n", CACertFileName);
		}

#endif // of defined( ENABLE_MUTUAL_TLS )

		/* Enable strong TLS versions only */
		if (0 == SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION))
		{
			fprintf(stderr, "Failed to set minimum TLS version to 1.2\n");
			break;
		}

		if (0 == SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION))
		{
			fprintf(stderr, "Failed to set maximum TLS version to 1.3\n");
			break;
		}

		/* Allow only strong AEAD + ECDHE-ECDSA ciphers for TLS 1.2 */
		if (1 != SSL_CTX_set_cipher_list(ctx,
			"ECDHE-ECDSA-AES128-GCM-SHA256:"
			"ECDHE-ECDSA-AES256-GCM-SHA384:"
			"ECDHE-ECDSA-CHACHA20-POLY1305"))
		{
			fprintf(stderr, "Failed to set TLS 1.2 cipher list\n");
			break;
		}

		/* Preferring ECDSA/ECDHE curves */
		if (0 == SSL_CTX_set1_curves_list(ctx, "P-256:P-384"))
		{
			fprintf(stderr, "Failed to set ECDHE curves\n");
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
			fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(iGetAddInfoErrCode));
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
					perror("socket IPv4");
				}
				else if (AF_INET6 == ptrAddrInfo->ai_family)
				{
					perror("socket IPv6");
				}
				else
				{
					perror("socket Unknown AF");
				}
				continue;
			}

			const int opt = 1;
			if (0 != setsockopt(iSocketFieldDescription, SOL_SOCKET, SO_REUSEADDR, &opt, (socklen_t)sizeof(opt)))
			{
				perror("setsockopt SO_REUSEADDR");
				/* Let centralized cleanup handle listener close */
				break;
			}

			/* Protect against blocked receiving */
			const struct timeval tv = { 10, 0 }; /* Seconds, microseconds */
			if (0 != setsockopt(iSocketFieldDescription, SOL_SOCKET, SO_RCVTIMEO, &tv, (socklen_t)sizeof(tv)))
			{
				perror("setsockopt SO_RCVTIMEO");
				/* Let centralized cleanup handle listener close */
				break;
			}

			/* Protect against slow senders */
			const struct timeval tv_send = { 10, 0 }; /* Seconds, microseconds */
			if (0 != setsockopt(iSocketFieldDescription, SOL_SOCKET, SO_SNDTIMEO, &tv_send, (socklen_t)sizeof(tv_send)))
			{
				perror("setsockopt SO_SNDTIMEO");
				/* Let centralized cleanup handle listener close */
				break;
			}

			/* Prevents small-response delays due to Nagle’s algorithm. */
			const int flag = 1;
			if (0 != setsockopt(iSocketFieldDescription, IPPROTO_TCP, TCP_NODELAY, &flag, (socklen_t)sizeof(flag)))
			{
				perror("setsockopt TCP_NODELAY");
				break;
			}

			if (0 == bind(iSocketFieldDescription, ptrAddrInfo->ai_addr, ptrAddrInfo->ai_addrlen))
			{
				/* Success */
				break;
			}

			perror("bind");
			close(iSocketFieldDescription);
			iSocketFieldDescription = -1;
		}

		/* No address succeeded */
		if (((struct addrinfo*)NULL) == ptrAddrInfo)
		{
			fprintf(stderr, "Could not bind to any IPv4 or IPv6 address\n");
			break;
		}

		/* No longer needed, hence closing */
		freeaddrinfo(server);
		server = (struct addrinfo*)NULL;

		/* Catch termination signals */
		if (SIG_ERR == signal(SIGINT, SignalHandler_SetExitFlag))		/* Ctrl+C */
		{
			fprintf(stderr, "signal(SIGINT) failed\n");
		}
		if (SIG_ERR == signal(SIGTERM, SignalHandler_SetExitFlag))	/* kill */
		{
			fprintf(stderr, "signal(SIGTERM) failed\n");
		}
		if (SIG_ERR == signal(SIGQUIT, SignalHandler_SetExitFlag))	/* Ctrl+\ */
		{
			fprintf(stderr, "signal(SIGQUIT) failed\n");
		}

		// Ctrl+Z suspends (default), process still fully terminable via Ctrl+C or kill.
		struct sigaction sa;
		memset(&sa, 0, sizeof(sa));
		sa.sa_handler = SignalHandler_SetExitFlag;
		if (0 != sigaction(SIGTSTP, &sa, NULL))								/* Ctrl+Z */
		{
			perror("sigaction(SIGTSTP)");
		}
		const int iListenStatus = listen(iSocketFieldDescription, SOMAXCONN);
		if (-1 == iListenStatus)
		{
			perror("listen");
			break;
		}
#if defined( ENABLE_MUTUAL_TLS )
		fprintf(stdout, "\nHTTPS (Mutual TLS) server listening on port 8080...\n\n");
#else // of defined( ENABLE_MUTUAL_TLS )
		fprintf(stdout, "\nHTTPS (TLS) server listening on port 8080...\n\n");
#endif // of defined( ENABLE_MUTUAL_TLS )

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
		if (tolower((unsigned char)p_h[i]) != 
				tolower((unsigned char)needle[0]))
		{
			continue;
		}

		/* Compare subsequent characters */
		for (j = 1U; j < len_n; j++)
		{
			if (tolower((unsigned char)p_h[i + j]) !=
					tolower((unsigned char)needle[j]))
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

bool HostHeaderCharWhitelist(char * out_host)
{
	bool bIsBreak = false;
/* Host header character whitelist:
 * Letters, digits, hyphen, dot only (RFC 3986 / RFC 952)
 */
	do
	{
		size_t k = 0U;
		while ('\0' != out_host[k])
		{
			unsigned char c = (unsigned char)out_host[k];

			if (!((c >= 'A' && c <= 'Z') ||
						(c >= 'a' && c <= 'z') ||
						(c >= '0' && c <= '9') ||
						(c == '-') ||
						(c == '.')))
			{
				/* Reject: illegal character in host */
				out_host[0] = '\0';
				bIsBreak = true;
				break;
			}
			k++;
		}

		/* If emptied due to invalid character */
		if ('\0' == out_host[0])
		{
			bIsBreak = true;
			break; /* return false later */
		}
	}while( false );
	return bIsBreak;
}

/* Parse HTTP Host header value into out_host (no port, no IPv6 brackets).
 * Supports:
 *   host
 *   host:port
 *   [ipv6]
 *   [ipv6]:port
 *
 * Returns:
 *   true  → out_host contains a non-empty host (null-terminated)
 *   false → invalid or empty host
 */
static bool rv_parse_http_host(const char* host_hdr, char* out_host, size_t out_host_size)
{
	bool ret = false;
	size_t src_len = 0U;
	size_t start = 0U;
	size_t end = 0U;
	size_t copy_len = 0U;

	do
	{
		if (((const char*)NULL) == host_hdr)
		{
			break;
		}

		if (((char*)NULL) == out_host)
		{
			break;
		}

		/* Need at least 1 char + '\0' */
		if (2U > out_host_size)
		{
			break;
		}

		src_len = strlen(host_hdr);
		if (0U == src_len)
		{
			break;
		}

		/* Skip leading SP / HTAB */
		while ((start < src_len) &&
		       ((' ' == host_hdr[start]) || ('\t' == host_hdr[start])))
		{
			start++;
		}

		if (start >= src_len)
		{
			break;
		}

		/* Case 1: IPv6 literal in [ ] (optionally with :port) */
		if ('[' == host_hdr[start])
		{
			size_t closing = start + 1U;

			/* Find matching ']' before CR/LF */
			while ((closing < src_len) &&
			       (']' != host_hdr[closing]) &&
			       ('\r' != host_hdr[closing]) &&
			       ('\n' != host_hdr[closing]))
			{
				closing++;
			}

			/* Must end with a ']' for valid IPv6 literal */
			if ((closing >= src_len) || (']' != host_hdr[closing]))
			{
				break;
			}

			/* Extract inside [ ... ] (IPv6 host without brackets) */
			if (closing <= (start + 1U))
			{
				/* "[]" or "[\r" etc. → invalid */
				break;
			}

			copy_len = (closing - (start + 1U));
			if (copy_len >= (out_host_size - 1U))
			{
				copy_len = (out_host_size - 1U);
			}

			(void)memcpy(out_host, &host_hdr[start + 1U], copy_len);
			out_host[copy_len] = '\0';
			if( true == HostHeaderCharWhitelist(out_host))
			{
				break;
			}
	
			/* Ignore optional :port after closing ']' (no need to parse port) */
		}
		else
		{
			/* Case 2: hostname or IPv4, optional :port */
			end = start;

			/* Host ends at ':', SP, HTAB, CR, or LF */
			while ((end < src_len) &&
			       (':' != host_hdr[end]) &&
			       (' ' != host_hdr[end]) &&
			       ('\t' != host_hdr[end]) &&
			       ('\r' != host_hdr[end]) &&
			       ('\n' != host_hdr[end]))
			{
				end++;
			}

			if (end == start)
			{
				/* No actual host characters */
				break;
			}

			copy_len = (end - start);
			if (copy_len >= (out_host_size - 1U))
			{
				copy_len = (out_host_size - 1U);
			}

			(void)memcpy(out_host, &host_hdr[start], copy_len);
			out_host[copy_len] = '\0';
			if( true == HostHeaderCharWhitelist(out_host))
			{
				break;
			}
		}

		/* Final sanity: must not be empty */
		if ('\0' == out_host[0])
		{
			break;
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
			//if ((EINTR == errno) && (0 != g_exit_requested))
			//{
				//iAcceptedClientFileDescriptor = -1;
				//continue;
			//}
			if ((EINTR == errno) || (EAGAIN == errno))
			{
					/* Temporary condition (signal or no pending connection) */
					iAcceptedClientFileDescriptor = -1;
					continue;
			}
			perror("accept");
			break;
		}

		/* Log client endpoint information */
		{
			const int status = getnameinfo((struct sockaddr*)&ClientAddress, ClientLength, host, sizeof(host), serv, sizeof(serv), NI_NUMERICHOST | NI_NUMERICSERV);

			if (0 == status)
			{
				fprintf(stdout, "\nAccept new connection on file descriptor %d from Client %s:%s\n\n", iAcceptedClientFileDescriptor, host, serv);
			}
			else
			{
				fprintf(stderr, "\nAccept new connection on file descriptor %d (address unresolved: %s)\n\n", iAcceptedClientFileDescriptor, gai_strerror(status));
			}

			ssl = SSL_new(ctx);
			if (((SSL*)NULL) == ssl)
			{
				fprintf(stderr, "SSL_new failed\n");
				close(iAcceptedClientFileDescriptor);
				iAcceptedClientFileDescriptor = -1;
				continue;
			}

			if (0 == SSL_set_fd(ssl, iAcceptedClientFileDescriptor))
			{
				fprintf(stderr, "SSL_set_fd failed\n");
				SSL_free(ssl);
				ssl = (SSL*)NULL;
				close(iAcceptedClientFileDescriptor);
				iAcceptedClientFileDescriptor = -1;
				continue;
			}

#if defined(ENABLE_MUTUAL_TLS)
			/* Enforce hostname check against certificate (SAN/CN) */
			SSL_set1_host(ssl, host);
#endif // of defined( ENABLE_MUTUAL_TLS )
		}

		const int ret_ssl = SSL_accept(ssl);
		if( 0 >= ret_ssl )
		{
			const int err = SSL_get_error(ssl, ret_ssl);

			if ((SSL_ERROR_WANT_READ == err) || (SSL_ERROR_WANT_WRITE == err))
			{
				fprintf(stderr, "TLS handshake did not complete (SSL_ERROR_WANT_%s) on fd %d\n", (SSL_ERROR_WANT_READ == err) ? "READ" : "WRITE", iAcceptedClientFileDescriptor);
			}
			else
			{
				fprintf(stderr, "TLS connection closed or client did not send HTTP request (SSL error=%d) on fd %d\n", err, iAcceptedClientFileDescriptor);
				ERR_print_errors_fp(stderr);
			}

			rvShutDownSSL_AndCloseFD();
			continue;
		}

		/* ---- Start: Mutual TLS block ---- */
#if defined( ENABLE_MUTUAL_TLS )
		{
			X509* client_cert = SSL_get_peer_certificate(ssl);
			if (client_cert)
			{
				char* subj = X509_NAME_oneline(X509_get_subject_name(client_cert), NULL, 0);
				fprintf(stdout, "Client certificate subject: %s\n", subj);
				OPENSSL_free(subj);
				X509_free(client_cert);

				long verify_result = SSL_get_verify_result(ssl);
				if (X509_V_OK != verify_result)
				{
					fprintf(stderr, "Client certificate verification failed: %s\n", X509_verify_cert_error_string(verify_result));
					rvShutDownSSL_AndCloseFD();
					continue;
				}
			}
			else
			{
				fprintf(stderr, "No client certificate presented\n");
				rvShutDownSSL_AndCloseFD();
				continue;
			}
		}
#endif // of defined( ENABLE_MUTUAL_TLS )
		/* ---- End: mutual TLS block ---- */

		/**** Read request (accumulate full header) ****/
		{
			char buf[4096];
			int total_bytes = 0;
			bool header_complete = false;
			int status_code;
			while (true)
			{
				status_code = 400;
				int bytes = SSL_read(ssl, buf + total_bytes,
														 (int)sizeof(buf) - 1 - total_bytes);

				if (bytes > 0)
				{
					total_bytes += bytes;
					buf[total_bytes] = '\0';

					/* Check for full header */
					if (strstr(buf, "\r\n\r\n"))
					{
						header_complete = true;
						break;
					}

					/* Avoid overrun */
					if (total_bytes >= ((int)sizeof(buf) - 1))
					{
						status_code = 413;
						break;
					}

					/* Continue reading */
					continue;
				}

				/* Client closed or read error */
				break;
			}

			if (false == header_complete)
			{
				switch( status_code )
				{
					case 413:
					{
						send_http_response(ssl, 413, "Payload Too Large", "Request header too large!\r\n");
						break;
					}
					case 400:
					{
						send_http_response(ssl, 400, "Bad Request", "Header not complete!\r\n");
						break;
					}
				}
				rvShutDownSSL_AndCloseFD();
				continue;
			}

			/* Validate HTTP method and request-target form */
			if (0 != strncmp(buf, "GET /", 5))
			{
				if (0 == strncmp(buf, "GET ", 4))
				{
					/* GET exists but no valid resource format */
					send_http_response(ssl, 400, "Bad Request", "Malformed request target!\r\n");
				}
				else
				{
					/* Wrong method */
					send_http_response(ssl, 405, "Method Not Allowed", "Only GET method supported!\r\n");
				}
				rvShutDownSSL_AndCloseFD();
				continue;
			}

			/* Reject path traversal attempts */
			if (strstr(buf, "/..") || strstr(buf, "%2e"))
			{
				send_http_response(ssl, 400, "Bad Request", "Illegal path!\r\n");
				rvShutDownSSL_AndCloseFD();
				continue;
			}

			/* Validate HTTP version presence */
			if (NULL == strstr(buf, "HTTP/1.1"))
			{
				send_http_response(ssl, 400, "Bad Request", "Missing or wrong HTTP version!\r\n");
				rvShutDownSSL_AndCloseFD();
				continue;
			}

			fprintf(stdout, "--- Received request with %d bytes ---\n%s\n------------------------\n", total_bytes, buf);

			/* Find Host header */
			const char* host_hdr = pc_strcasestr(buf, "\nhost:");

			if ((const char*)NULL != host_hdr)
			{
				host_hdr += 6; /* past "\nhost:" */

				/* Skip SP / HTAB */
				while ((' ' == *host_hdr) || ('\t' == *host_hdr))
				{
					host_hdr++;
				}
			}

			if (((const char*)NULL == host_hdr) || ('\0' == *host_hdr) || ('\r' == *host_hdr) || ('\n' == *host_hdr))
			{
				send_http_response(ssl, 400, "Bad Request", "Missing Host header!\r\n");
				rvShutDownSSL_AndCloseFD();
				continue;
			}

			/* Strip CRLF at end of line for clean parsing */
			char* end = strpbrk(host_hdr, "\r\n");
			if ((char*)NULL != end)
			{
				*end = '\0';
			}

			/* Parse host (no port, no IPv6 brackets).
			 * Used only for basic HTTP validation / logging.
			 * Identity is enforced by TLS certificate verification,
			 * not by comparing Host header to remote IP address.
			 */
			char req_host[NI_MAXHOST + 1U];
			if (false == rv_parse_http_host(host_hdr, req_host, (size_t)sizeof(req_host)))
			{
				send_http_response(ssl, 400, "Bad Request", "Invalid Host header!\r\n");
				rvShutDownSSL_AndCloseFD();
				continue;
			}

			/* SUCCESS! */
			send_http_response(ssl, 200, "OK", "Hello, HTTPS!\r\n");
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
		fprintf(stdout, "\nCaught signal %d. Cleaning up server loop and exiting...\n", (int)g_last_signal);
	}
}

int main(void)
{
	bool init_ok = InitializeServer();

	if ((true == init_ok) && (0 == g_exit_requested))
	{
		RunServerLoop();
	}

	rvShutDownSSL_AndCloseFD();
	FreeAndClose();

	fprintf(stdout, "Server terminated.\n");

	return ((true == init_ok) && (0 == g_exit_requested)) ? EXIT_SUCCESS : EXIT_FAILURE;
}
