/***************************************************************************
 *  Project      _           _ _
 *     ___ _ __ (_)_ __   __| | |_   _
 *    / __| '_ \| | '_ \ / _` | | | | |
 *    \__ \ |_) | | | | | (_| | | |_| |
 *    |___/ .__/|_|_| |_|\__,_|_|\__, |
 *        |_|                    |___/
 *
 * Copyright (c) 2012, Samsung Electronics Co., Ltd. All rights reserved.
 * Author(s): Venkatesh Perumalla <venkatesh.p@samsung.com>, Tarun Kumar <tarun.kr@samsung.com>
 *
 * This software is licensed as described in the file LICENSE, which you
 * should have received as part of this distribution. The terms are also
 * available at http://spindly.haxx.se/license.html
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <spindly.h>
#include <openssl/tls1.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "sockets.h"
#include <netdb.h>

void ssl_handshake(SSL *ssl, int fd);
void setup_ssl_ctx(SSL_CTX *ssl_ctx, void *next_proto_select_cb_arg);
#define printf(...)
typedef struct {
	/**
	 * SPDY protocol version name which can be used as TLS NPN protocol
	 * string.
	 */
	const unsigned char *proto;
	/**
	 * The length of proto member.
	 */
	uint8_t len;
	/**
	 * The corresponding SPDY version constant which can be passed to
	 * as version argument.
	 */
	uint16_t version;
} test_npn_proto;

static const test_npn_proto proto_list[] = {
	{ (const unsigned char*)"spdy/3", 6, 3 }, /*comment this line to test spdy2*/
	{ (const unsigned char*)"spdy/2", 6, 2 } /*comment this line to test spdy3*/
};

void ssl_handshake(SSL *ssl, int fd)
{
	int rv;
	if (SSL_set_fd(ssl, fd) == 0) {
		errorout("SSL_set_fd");
	}
	ERR_clear_error();
	rv = SSL_connect(ssl);
	if (rv <= 0) {
		errorout("SSL_connect\n");
	}
}

int test_select_next_protocol(unsigned char **out, unsigned char *outlen,
		const unsigned char *in, unsigned int inlen)
{
	int http_selected = 0;
	unsigned int i = 0;
	for (; i < inlen; i += in[i]+1) {
		unsigned int j;
		for (j = 0; j < sizeof(proto_list)/sizeof(test_npn_proto); ++j) {
			if (in[i] == proto_list[j].len &&
					memcmp(&in[i+1], proto_list[j].proto, in[i]) == 0) {
				*out = (unsigned char*)&in[i+1];
				*outlen = in[i];
				return proto_list[j].version;
			}
		}
		if(in[i] == 8 && memcmp(&in[i+1], "http/1.1", in[i]) == 0) {
			http_selected = 1;
			*out = (unsigned char*)&in[i+1];
			*outlen = in[i];
			/* Go through to the next iteration, because "spdy/X" may be
			   there */
		}
	}
	if (http_selected) {
		return 0;
	} else {
		return -1;
	}
}

static int select_next_proto_cb(SSL* ssl,
		unsigned char **out, unsigned char *outlen,
		const unsigned char *in, unsigned int inlen,
		void *arg)
{
	int rv;
	uint16_t *spdy_proto_version;
	/* test_select_next_protocol() selects SPDY protocol version the
	   Spdylay library supports. */
	rv = test_select_next_protocol(out, outlen, in, inlen);
	if (rv <= 0) {
		printf("Server did not advertise spdy/2 or spdy/3 protocol.");
	}
	spdy_proto_version = (uint16_t*)arg;
	*spdy_proto_version = rv;
	return SSL_TLSEXT_ERR_OK;
}

void setup_ssl_ctx(SSL_CTX *ssl_ctx, void *next_proto_select_cb_arg)
{
	/* Disable SSLv2 and enable all workarounds for buggy servers */
	SSL_CTX_set_options(ssl_ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2);
	SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);
	SSL_CTX_set_mode(ssl_ctx, SSL_MODE_RELEASE_BUFFERS);
	SSL_CTX_set_mode(ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
	uint16_t spdy_proto_version;
	/*Following line commented to resolve build break: Latest openssl require for
	  following function */
	SSL_CTX_set_next_proto_select_cb(ssl_ctx, select_next_proto_cb,
			&spdy_proto_version);
}

int main(int argc, char *argv[])
{
	socket_t sock;
	struct sockaddr_in servaddr;
	char *server = NULL;
	int rc;
	char bye[3];
	int len;
	struct spindly_phys *phys_client;
	struct spindly_stream *stream_client;
	spindly_error_t spint;
	unsigned char *data;
	size_t datalen;
	char *url;
	char *scheme;
	char * path;
	int i;

	if (argc > 2) {
		url = argv[2];
		scheme = argv[1];

	} else {
		url = "www.google.co.in";
		scheme = "https";
	}

	if (argc > 3) {
		path = argv[3];
	} else {
		path = "/";
	}
	int count = 10;


#if 0
	server = "107.108.87.68";
	//server = "107.108.86.228";

	sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock == SOCKET_BAD)
		errorout("socket() failed");

	/* create a spindly handle for the physical connection */
	phys_client = spindly_phys_init(SPINDLY_SIDE_CLIENT, SPINDLY_DEFAULT, NULL);

	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = inet_addr(server);
	servaddr.sin_port = htons(SERVER_PORT);
#else
	struct hostent *host = (struct hostent *)gethostbyname(url);

	printf("host  name = %s \n", host->h_name);

	sock = socket(PF_INET, SOCK_STREAM, 0);
	if (sock == SOCKET_BAD)
		errorout("socket() failed");

	/* create a spindly handle for the physical connection */
	phys_client = spindly_phys_init(SPINDLY_SIDE_CLIENT, SPINDLY_DEFAULT, NULL);

	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	memcpy(&servaddr.sin_addr.s_addr, host->h_addr, host->h_length);
	servaddr.sin_port = htons(443);
	memset(&(servaddr.sin_zero), '\0', 8);
#endif
	/* Establish the connection to the echo server */
	rc = connect(sock, (struct sockaddr *) &servaddr, sizeof(servaddr));
	if (rc < 0)
		errorout("connect() failed");

	/* Handshake */
	/* SSL Part*/
	SSL_library_init();
	SSL_load_error_strings();


	SSL_CTX *ssl_ctx;
	ssl_ctx = SSL_CTX_new(TLSv1_client_method());
	if (!ssl_ctx) {
		errorout("0\n");
		return -1;
	}
	char *next_proto;
	next_proto = strdup("spdy/3");
	setup_ssl_ctx(ssl_ctx, &next_proto);

	SSL *ssl = SSL_new(ssl_ctx);
	if (!ssl) {
		errorout("1");
		return -1;
	}
	if (!SSL_set_tlsext_host_name(ssl, server)) {
		errorout("2");
		return -1;
	}
	ssl_handshake(ssl, sock);
	/* Handshake */

	printf("Connected! Pretend TLS-NPN succeeded.\n");

	struct spindly_headers test_headers = { 0 };
	int j;

	spindly_add_header(&test_headers, "accept", "*/*");
	spindly_add_header(&test_headers, ":host", url);
	spindly_add_header(&test_headers, ":method", "GET");
	spindly_add_header(&test_headers, ":scheme", "https");
	spindly_add_header(&test_headers, ":path", "/");
	spindly_add_header(&test_headers, "user-agent", "Mozilla/5.0 (X11; Linux i686) AppleWebKit/534.24 (KHTML, like Gecko) Chrome/11.0.696.16 Safari/534.24");
	spindly_add_header(&test_headers, ":version", "HTTP/1.1");

	//SEND_STREAM :
	for (j = 0; j < 1; j++) {
		/* create a new stream on the physical connection */
		spint = spindly_stream_new(phys_client,
				0x01,  /* FLAG_FIN is set, as there is no more data to send. */
				0,
				&stream_client,
				NULL,
				NULL,
				&test_headers);

		/* get data to send over the socket */
		spint = spindly_phys_outgoing(phys_client, &data, &datalen);

		printf("Ask for a new stream\n");

		/* send away the SPDY packet */
		/*rc = send(sock, data, datalen, 0);*/
		printf("Sending Data Length = %d\n", datalen);
		for(i=0;i<32;i++)
			printf("[%d] ",data[i]);
		rc = SSL_write(ssl,data,datalen);

		if (rc > 0) {
			/* tell spindly how much of that data that was actually sent */
			spindly_phys_sent(phys_client, rc);
			printf("Sent %d bytes\n", rc);
		} else {
			printf("SEND FAILED\n");
		}
	}
	/* now wait for data to arrive on the socket and demux it to figure out
	   what the peer says to us */
	unsigned char buffer[102400] = {0};

	while (1) {
		len = SSL_read(ssl, buffer, sizeof(buffer));

		fprintf(stderr, "\nReceived Data...........\n");
		if (len > 0) {
			fprintf(stderr, "recv() returned %d!\n", len);
			struct spindly_demux demux;
			/* get the received data into spindly data structures. */
			spint = spindly_phys_incoming(phys_client,
					buffer,
					len,
					SPINDLY_INCOMING_COPY,
					NULL);
			if (spint != SPINDLYE_OK)
				return -1;

			/* demux the incoming data to figure out if there's anything to do (yet) */
			spint = spindly_phys_demux(phys_client, &demux);

			fprintf(stderr, "demux type: %d\n", demux.type);
			fprintf(stderr, "demux strem id: %u\n", demux.msg.stream.streamid);
#if 1
			if(SPINDLY_DX_DATA == demux.type && SPINDLY_DATA_FLAGS_FIN == demux.msg.data.flags) {
				int res;
				printf("sending window update\n");
				stream_client=spindly_stream_get_stream(phys_client,demux.msg.stream.streamid);
				if((res=spindly_stream_wndupdate(stream_client,-1)) == SPINDLYE_OK){
					spint = spindly_phys_outgoing(phys_client, &data, &datalen);
					/* send away the SPDY packet */
					/*rc = send(sock, data, datalen, 0);*/
					printf("Sending Data Length = %d\n",datalen);
					for(i=0;i<datalen;i++)
						printf("[%d] ",data[i]);
					rc = SSL_write(ssl,data,datalen);

					if (rc > 0) {
						/* tell spindly how much of that data that was actually sent */
						spindly_phys_sent(phys_client, rc);
						printf("Sent %d bytes\n", rc);
					} else {
						printf("WINDOW UPDATE SEND FAILED\n");
					}
				} else {
					if(res == SPINDLYE_STOP) {
						count--;
						printf("number of request left =%d\n",count);
						if(count >0){
							//	goto SEND_STREAM;
						} else {
							exit(0);
						}
					}
				}
			}
#endif
		}else {
			printf("Length unkown\n");
			break;
		}
	}

	sclose(sock);
	return 0;
}
