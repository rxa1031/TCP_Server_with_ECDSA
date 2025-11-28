#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h> /* Required for socket functions like socket(), connect(), etc. */
#include <sys/types.h>
#include <unistd.h> /* Required for close() */
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define __IMPLEMENT_CONTINUE__

/*
 * Using TABs instead of spaces. 1 TAB = 2 spaces
 *
 * HTTPS = HTTP sent over a TLS connection
 *
 * Keep using the same TCP socket calls (socket, bind, listen, accept, connect, read, write),
 * but wrap that socket with a TLS library (OpenSSL / mbedTLS / wolfSSL, etc.)
 *
 * Use ECDSA keys: create or load an ECDSA private key + certificate and load them into the TLS context
 * before doing the TLS handshake.
 *
 * Below are practical steps + minimal OpenSSL examples (server and client) that show how to do this:
 *		 1. Create a TCP socket, then bind and accept exactly as one would for plain HTTP.
 *		 2. Initialize a TLS library (using OpenSSL in the below code).
 *		 3. Create an SSL_CTX (server or client) and configure it.
 *		 4. Load generated ECDSA private key and certificate into the SSL_CTX. Generate ECDSA keys with
 *				OpenSSL (commands shown in next comment).
 *		 5. After you have a connected socket File Descriptor, call SSL_new() + SSL_set_fd() then execute
 *				SSL_accept() (server) or SSL_connect() (client).
 *		 6. Use SSL_read() / SSL_write() to send/receive HTTP requests/responses — the contents are normal
 *				HTTP bytes (with \r\n line endings).
 *		 7. Close SSL_shutdown(), then close the socket and free TLS objects.
 */

/*
 *	# generate ECDSA private key (prime256v1 aka P-256)
 *		openssl ecparam -name prime256v1 -genkey -noout -out key.pem
 *
 *	# create a self-signed certificate using that key with below command.
 *		openssl req -new -x509 -key key.pem -out cert.pem -days 365 -subj "/C=IN/ST=State/L=City/O=Org/CN=localhost"
 *		openssl Command Breakdown:
 *		req (i.e. Request) Options		Description
 *		-new													New request.
 *		-x509													Output an X.509 certificate structure instead of a cert request.
 *		-key val											Key for signing, and to include unless -in given (example: key.pem as value for val).
 *		-out outfile									out outfile (example: cert.pem as value for outfile)
 *		-days +int										Number of days cert is valid for.
 *		-subj val											Set or modify subject of request or cert
 *																	Country (C), State (ST), Locality (L), Organization (O), and Common Name (CN).
 *		Example:
 *		openssl req -new -x509 -key key.pem -out cert.pem -days 365 -subj "/C=IN/ST=Maharashtra/L=Pune/O=Org/CN=localhost"
 */

/*
 *	Install requred tools & packages:
 *		sudo apt install gcc
 *		sudo apt install build-essential
 *		sudo apt install libssl-dev
 *
 *	Compile code using below command (where flag -l is used to link OpenSSL libraries, typically libssl and libcrypto):
 *		gcc TCP_Server.C -o TCP_Server.o -lssl -lcrypto
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

SSL_CTX* ctx = (SSL_CTX*)NULL;
SSL* ssl = (SSL*)NULL;
struct addrinfo* server = (struct addrinfo*)NULL;
int iSocketFieldDescription = -1;
int iAcceptedClientFileDescriptor = -1;

void FreeAndClose(void)
{
	if (NULL != server)
	{
		fprintf(stdout, "Freeing Server Address Information...\n");
		freeaddrinfo(server);
	}
	if (-1 != iSocketFieldDescription)
	{
		fprintf(stdout, "Closing Socket...\n");
		close(iSocketFieldDescription);
	}
	if (NULL != ctx)
	{
		SSL_CTX_free(ctx);
	}
}

void CleanupAndExit(int signum)
{
	printf("\nCaught signal %d. Cleaning up...\n", signum);
	FreeAndClose();
	exit(0);
}

void rvShutDownSSL_AndCloseFD(void)
{
	if (NULL != ssl)
	{
		SSL_shutdown(ssl);
		SSL_free(ssl);
		ssl = NULL;
	}
	if (-1 != iAcceptedClientFileDescriptor)
	{
		close(iAcceptedClientFileDescriptor);
		iAcceptedClientFileDescriptor = -1;
	}
}

int main()
{
	do
	{
		/* Initialize OpenSSL */
		SSL_library_init();
		OpenSSL_add_ssl_algorithms();
		SSL_load_error_strings();

		const SSL_METHOD* method = TLS_server_method();
		ctx = SSL_CTX_new(method);
		if (NULL == ctx)
		{
			ERR_print_errors_fp(stderr);
			break;
		}
		// Load certificate and ECDSA private key (PEM files)
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
		// Ensure private key matches certificate
		if (0 == SSL_CTX_check_private_key(ctx))
		{
			fprintf(stderr, "Private key check failed\n");
			break;
		}

		/* Enable strong TLS versions only */
		SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
		SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

		/* Preferring ECDSA/ECDHE curves */
		SSL_CTX_set1_curves_list(ctx, "P-256:P-384");

		const struct addrinfo hints = {
			.ai_flags = AI_PASSIVE,
			/* Allow IPv4 or IPv6 */ /* Ealier set to AF_INET to use IPV4 */
			.ai_family = AF_UNSPEC,
			.ai_socktype = SOCK_STREAM,
			.ai_protocol = 0,
			.ai_addrlen = 0,
			.ai_addr = NULL,
			.ai_canonname = NULL,
			.ai_next = NULL
		};
		const int iGetAddInfoErrCode = getaddrinfo((const char*)NULL, (const char*)"8080", &hints, &server);
		if (0 != iGetAddInfoErrCode)
		{
			perror(gai_strerror(iGetAddInfoErrCode));
			break;
		}
		struct addrinfo* ptrAddrInfo = server;
		/* getaddrinfo() returns a list of address structures.
			Try each address until we successfully bind(2).
			If socket(2)fails we try the next address.
			If bind(2) fails, we close the socket
			and try the next address. */
		for (; ptrAddrInfo != NULL; ptrAddrInfo = ptrAddrInfo->ai_next)
		{
			iSocketFieldDescription = socket(server->ai_family, server->ai_socktype, server->ai_protocol);
			if (-1 == iSocketFieldDescription)
			{
				fprintf(stderr, "%s Socket open failed!\n",
					server->ai_family == AF_INET
					? "IPV4"
					: (server->ai_family == AF_INET6 ? "IPV6" : "UNKNOWN"));
				perror(strerror(errno));
				continue;
			}
			const int opt = 1;
			setsockopt(iSocketFieldDescription, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
			if (0 == bind(iSocketFieldDescription, ptrAddrInfo->ai_addr, ptrAddrInfo->ai_addrlen))
			{
				break; /* Success */
			}
			else
			{
				fprintf(stderr, "Bind failed with error %s\n", strerror(errno));
			}
			close(iSocketFieldDescription);
		}
		/* No longer needed, hence closing */
		freeaddrinfo(server);
		server = NULL;
		/* No address succeeded */
		if (NULL == ptrAddrInfo)
		{
			fprintf(stderr, "Could not bind\n");
			// exit(EXIT_FAILURE);
			break;
		}
		// Catch termination signals
		signal(SIGINT, CleanupAndExit);   // Ctrl+C
		signal(SIGTERM, CleanupAndExit);  // kill command
		signal(SIGQUIT, CleanupAndExit);  // Ctrl+\

		// Catch Ctrl+Z (SIGTSTP)
		struct sigaction sa;
		memset(&sa, 0, sizeof(sa));
		sa.sa_handler = CleanupAndExit;
		sigaction(SIGTSTP, &sa, NULL);

		const int iListenStatus = listen(iSocketFieldDescription, 1);
		if (-1 == iListenStatus)
		{
			fprintf(stderr, "Listening failed with error %s!\n", strerror(errno));
			break;
		}
		fprintf(stdout, "\nHTTPS (TLS) server is listening...\n\n");

		struct sockaddr ClientAddress;
		socklen_t ClientLength = sizeof(ClientAddress);
#if defined( __IMPLEMENT_CONTINUE__ )
		while (true)
#else // of defined( __IMPLEMENT_CONTINUE__ )
		bool bIsCloseSSL = false;
#endif // of defined( __IMPLEMENT_CONTINUE__ )
		{
			iAcceptedClientFileDescriptor = accept(iSocketFieldDescription, &ClientAddress, &ClientLength);
			if (-1 == iAcceptedClientFileDescriptor)
			{
				fprintf(stderr, "Accept connection on scoket failed with error %s!\n", strerror(errno));
				break;
			}
			fprintf(stdout, "\nAccept new connection on file descriptor %d\n\n", iAcceptedClientFileDescriptor);

			char host[NI_MAXHOST];
			char serv[NI_MAXSERV];

			int status = getnameinfo(&ClientAddress, ClientLength, host, NI_MAXHOST, serv, NI_MAXSERV, NI_NUMERICSERV);

			if (0 == status)
			{
				printf("Received %u bytes from %s:%s\n", ClientLength, host, serv);
			}
			else
			{
				fprintf(stderr, "getnameinfo: %s\n", gai_strerror(status));
			}

#if 1
			ssl = SSL_new(ctx);
			SSL_set_fd(ssl, iAcceptedClientFileDescriptor);

			if (0 >= SSL_accept(ssl))
			{
				ERR_print_errors_fp(stderr);
				SSL_free(ssl);
				close(iAcceptedClientFileDescriptor);
#if defined( __IMPLEMENT_CONTINUE__ )
				continue;
#else // of defined( __IMPLEMENT_CONTINUE__ )
				bIsCloseSSL = true;
				break;
#endif // of defined( __IMPLEMENT_CONTINUE__ )
			}
			// Read request
			char buf[4096];
			int bytes = SSL_read(ssl, buf, sizeof(buf) - 1);
			if (bytes > 0)
			{
				buf[bytes] = '\0';
				printf("--- Received request ---\n%s\n------------------------\n", buf);
			}

			// Send a tiny HTTPS response (note CR LF: \r\n)
			const char* response =
				"HTTP/1.1 200 OK\r\n"
				"Content-Type: text/plain\r\n"
				"Content-Length: 13\r\n"
				"\r\n"
				"Hello, HTTPS!\n";

			SSL_write(ssl, response, strlen(response));

			rvShutDownSSL_AndCloseFD();
#else // of 1
			const int iBufSz = 512;
			char cBuf[iBufSz];
			const ssize_t PeerMsgLen = recv(iAcceptedClientFileDescriptor, cBuf, iBufSz, 0);
			if (-1 == PeerMsgLen)
			{
				fprintf(stderr, "Message receive failed with error %s!\n", strerror(errno));
				break;
			}
			if (0 < PeerMsgLen)
			{
				printf("Received %zd bytes:\n---\n", PeerMsgLen);
				for (int x = 0; x < PeerMsgLen; x++)
				{
					putchar(cBuf[x]);
				}
			}
#endif // of 1
		}
#if !defined( __IMPLEMENT_CONTINUE__ )
		if (bIsCloseSSL)
		{
			rvShutDownSSL_AndCloseFD();
		}
#endif // of !defined( __IMPLEMENT_CONTINUE__ )

	} while (false);
	CleanupAndExit(0);
	return EXIT_SUCCESS;
}
