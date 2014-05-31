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
			&spdy_proto_version); /*Commented to avoid OSC build break*/
}

int main(int argc, char *argv[])
{
	socket_t sock;
	struct sockaddr_in servaddr;
	char *server = NULL;
	int rc;
	char bye[3];
	int len;
	int i;
	struct spindly_phys *phys_client;
	struct spindly_stream *stream_client;
	spindly_error_t spint;
	unsigned char *data;
	unsigned char *data2;
	unsigned char *data_final;
	size_t datalen;
	size_t data2len;
	size_t datafinallen;

	struct hostent *host = (struct hostent *)gethostbyname("picasaweb.google.com");

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
	/* Create a new album on Picasa "Trip To Italy" under user tarun123456789123456789*/
	/*valid access token should be provide in auth=*/
	struct spindly_headers test_headers = { 0 };
	char *url = NULL;

	spindly_add_header(&test_headers, "accept", "*/*");
	spindly_add_header(&test_headers, ":host", "picasaweb.google.com");
	spindly_add_header(&test_headers, ":method", "POST");
	spindly_add_header(&test_headers, ":scheme", "https");
	spindly_add_header(&test_headers, ":path", "/data/feed/api/user/shakthimshree");
	spindly_add_header(&test_headers, ":version", "HTTP/1.1");
	spindly_add_header(&test_headers, "user-agent", "Samsung User Agent");
	spindly_add_header(&test_headers, "authorization", "GoogleLogin auth=DQAAAMQAAAALZKgoNwBmkTahTxp1FNHD-h4SH2Jm1oBNcNvdPDu5c7NuH7xRpWx1uzQY_sRKiSDxCtm4MuCO0pBikV5vFI_4Tb0jYXbTWhNdN0mdLEbDBxfgzOnUIcpaCuVL3zK-rXEY77q9KhM9if4EYJ6Hucm-ri7wq2BYUsjwz5pdqGBLOhX7oY8lOLJV7Hb6dJlpNX_ts7ST1EWty5aE1zj1LTGTRh_x78e7V988xivZYMKrD6EdaUjZ_tdKZC_NVUi1x85UfFE1VCY-0fc20_-zmWtM");
	spindly_add_header(&test_headers, "content-length", "571");
	spindly_add_header(&test_headers, "gdata-version", "2");
	spindly_add_header(&test_headers, "content-type", "application/atom+xml"),
	spindly_add_header(&test_headers, "accept-charset", "ISO-8859-1,utf-8,q=0.7,*;q=0.2");
	spindly_add_header(&test_headers, "accept-encoding", "gzip,deflate,sdcch");
	spindly_add_header(&test_headers, "accept-language", "en-US,en;q=0.8");

	/* create a new stream on the physical connection */
	spint = spindly_stream_new(phys_client,
			0,
			0,
			&stream_client,
			NULL,
			NULL,
			&test_headers);

	/* get data to send over the socket */
	spint = spindly_phys_outgoing(phys_client, &data, &datalen);
	url = "<entry xmlns='http://www.w3.org/2005/Atom' xmlns:media='http://search.yahoo.com/mrss/' xmlns:gphoto='http://schemas.google.com/photos/2007'><title type='text'>I visited MyHospet</title><summary type='text'>My photo with My Family. </summary><gphoto:location>HBHalli</gphoto:location><gphoto:access>public</gphoto:access><gphoto:timestamp>1152255600000</gphoto:timestamp><media:group><media:keywords>Bellary, India</media:keywords></media:group><category scheme='http://schemas.google.com/g/2005#kind' term='http://schemas.google.com/photos/2007#album'></category></entry>";

	/* send away the SPDY packet */
	printf("Sending Data Length = %d\n", datalen);
	for (i = 0; i < datalen; i++)
		printf("[%d] ", data[i]);
	putchar('\n');
	rc = SSL_write(ssl, data, datalen);
	if (rc > 0) {
		/* tell spindly how much of that data that was actually sent */
		spindly_phys_sent(phys_client, rc);
		printf("Sent %d bytes\n", rc);
	} else {
		printf("SEND FAILED\n");
	}

	spint = spindly_stream_data(stream_client,
			0x1,
			url,
			strlen(url),
			NULL);

	spint = spindly_phys_outgoing(phys_client, &data2, &data2len);

	printf("Sending Data Length = %d\n", datalen);
	for (i = 0; i < data2len; i++)
		printf("[%d] ", data2[i]);
	putchar('\n');
	rc = SSL_write(ssl, data2, data2len);
	if (rc > 0) {
		/* tell spindly how much of that data that was actually sent */
		spindly_phys_sent(phys_client, rc);
		printf("Sent %d bytes\n", rc);
	} else {
		printf("SEND FAILED\n");
	}

	/* now wait for data to arrive on the socket and demux it to figure out
	   what the peer says to us */

	unsigned char buffer[102400] = {0};

	while (1) {
		memset(buffer, 0, 102400);
		len = SSL_read(ssl, buffer, sizeof(buffer));
		printf("Received Data...........");
		if (len>0) {
			printf("%d\n",len);
			printf("recv() returned %d!\n", len);
			struct spindly_demux demux;
			spint = spindly_phys_incoming(phys_client,
					(unsigned char *)buffer,
					len,
					SPINDLY_INCOMING_COPY, NULL);
			if (spint != SPINDLYE_OK)
				return -1;

			/* demux the incoming data to figure out if there's anything to do (yet) */
			spint = spindly_phys_demux(phys_client, &demux);
			printf("demux type: %d\n", demux.type);
			printf("demux strem id: %u\n", demux.msg.stream.streamid);
		}else {
			printf("Length unkown\n");
			break;
		}
	}

	if (data_final)
		free(data_final);

	sclose(sock);
	return 0;
}
