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
	/*SSL_CTX_set_next_proto_select_cb(ssl_ctx, select_next_proto_cb,
			&spdy_proto_version);*/ /*Commented to avoid OSC build break*/
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

	/* Update album name with album ID as 5807679875862166833 under user tarun123456789123456789 to "PUT Request test"*/
	/*valid access token should be provide in auth=*/
	struct spindly_header_pair test_header_pairs[15] = {
			{0, "accept", 0, "*/*"},
			{0, ":host", 0, "picasaweb.google.com"},
			{0, ":method", 0 , "PUT"},
			{0, ":scheme", 0, "https"},
			{0, ":path", 0, "/data/entry/api/user/tarun123456789123456789/albumid/5807679875862166833"},
			{0, ":version", 0, "HTTP/1.1"},
			{0, "user-agent", 0, "Samsung User Agent"},
			{0, "authorization", 0, "GoogleLogin auth=DQAAAMkAAABQ7cRdlNeOKeuf_NBX8WGU-7FZGzxrfuH3UmaqfPDODXb3b_Dn4XpoDAK4lag5G65Es7OgO-eXsN5Mkky8oKb3EqHKDqmyYBC7ETuZYCxS-neKVVXZVVekr-mT3X5tfmkfAS786wy546vZyV9QIg1sueIZMZixKwcbGFFOIOt3XXnVP9cpQ86OmcdQF4Ll6iQzF71m-Y5RvuvbwCc2UbAAgbWqymDLfKEpT5-V4EgJ6arA74Jle3bdDEmNnMOxgh84Y1_OlPsmJ1tnjc82dGAS"},
		{0, "content-length", 0, "584"},
		{0, "gdata-version", 0, "2"},
		{0, "content-type", 0, "application/atom+xml"},
		{0, "accept-charset", 0, "ISO-8859-1,utf-8;q=0.7,*;q=0.3"},
		{0, "accept-encoding", 0, "gzip,deflate,sdch"},
		{0, "if-match", 0, "*"},
		{0, "accept-language", 0, "en-US,en;q=0.8"}
	};
	struct spindly_headers test_headers =  { 0 };
	test_headers.count = 15;
	test_headers.pairs = test_header_pairs;
	/* create a new stream on the physical connection */
	spint = spindly_stream_new(phys_client, 0, 0, &stream_client, NULL, NULL, &test_headers);
	spint = spindly_stream_data(&stream_client, 0x1,
					"<entry xmlns='http://www.w3.org/2005/Atom' xmlns:media='http://search.yahoo.com/mrss/' xmlns:gphoto='http://schemas.google.com/photos/2007'><title type='text'>PUT Request test</title><summary type='text'>This was the recent trip I took to Italy.</summary><gphoto:location>Italy</gphoto:location><gphoto:access>public</gphoto:access><gphoto:timestamp>1152255600000</gphoto:timestamp><media:group><media:keywords>italy, vacation</media:keywords></media:group><category scheme='http://schemas.google.com/g/2005#kind' term='http://schemas.google.com/photos/2007#album'></category></entry>",
					strlen("<entry xmlns='http://www.w3.org/2005/Atom' xmlns:media='http://search.yahoo.com/mrss/' xmlns:gphoto='http://schemas.google.com/photos/2007'><title type='text'>PUT Request test</title><summary type='text'>This was the recent trip I took to Italy.</summary><gphoto:location>Italy</gphoto:location><gphoto:access>public</gphoto:access><gphoto:timestamp>1152255600000</gphoto:timestamp><media:group><media:keywords>italy, vacation</media:keywords></media:group><category scheme='http://schemas.google.com/g/2005#kind' term='http://schemas.google.com/photos/2007#album'></category></entry>"),
					NULL);

	/* get data to send over the socket */
	spint = spindly_phys_outgoing(phys_client, &data, &datalen);

	spindly_phys_sent(phys_client, datalen);


	spint = spindly_phys_outgoing(phys_client, &data2, &data2len);

	printf("Ask for a new stream\n");
	printf("PACK Length = %d\n", data2len);

	/* send away the SPDY packet */
	datafinallen = datalen + data2len;
	data_final = (unsigned char *)malloc(datafinallen);

	memcpy(data_final, data, datalen);
	memcpy(data_final + datalen, data2, data2len);

	printf("Sending Data Length = %d\n",datafinallen);
	rc = SSL_write(ssl,data_final,datafinallen);

	if (rc > 0) {
		/* tell spindly how much of that data that was actually sent */
		spindly_phys_sent(phys_client, rc- datalen);
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
