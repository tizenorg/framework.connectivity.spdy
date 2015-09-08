/*
 *  Spindly Unit test.
 *
 * Copyright (c) 2000 - 2012 Samsung Electronics Co., Ltd. All rights reserved.
 * Contact: Shakthi Prashanth <sh.prashanth@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <spindly.h>
#include <spdy_log.h>

#define fail_if(cond, format, args...) do {\
	if (cond) {\
		fprintf(stderr, "$$ @line %d: "format"\n", __LINE__, ##args);\
		exit(EXIT_FAILURE);\
	}\
} while(0);

#define	MAXBUF	128
#define	MAXSTR	64

#define F_STR(f) #f

#define SYNC_STREAM_SIZE	30

typedef enum {
	Error,
	Sanity
} TestCaseType;

typedef enum {
	Integer,
	Pointer
} RetType;

static const char *_get_next_tc_str()
{
	static char tc_str[MAXSTR];
	static int	tc_no = 0;
	sprintf(tc_str, "TC#%d", ++tc_no);
	return tc_str;
}

static void _spindly_print_test_result(TestCaseType tctype,
		RetType rettype,
		const void *retcode,
		const char *func_name)
{
	char buf[MAXBUF];
	bool result = false;
	int r = 0;

	if (tctype == Sanity) {
		if (rettype == Integer) {
			r = (int) retcode;
			result = (r == SPINDLYE_OK);
		} else { /* Pointer */
			result = (retcode != NULL);
		}
	} else { /* Error TC */
		if (rettype == Integer) {
			r = (int) retcode;
			result = (r != SPINDLYE_OK);
		} else { /* Pointer */
			result = (retcode == NULL);
		}
	}
	printf("---------------> %s: %s(): %s\n", func_name, _get_next_tc_str(),
			result ? "SUCCESS" : "FAIL");
}

static void _spindly_phys_init_test()
{
	struct spindly_phys *phys_client = NULL;
	struct spindly_phys *phys_server = NULL;
	const char *fun_name = F_STR(spindly_phys_init);

	phys_client = spindly_phys_init(SPINDLY_SIDE_CLIENT, SPINDLY_DEFAULT, NULL);
	_spindly_print_test_result(Sanity, Pointer, phys_client, fun_name);
	spindly_phys_cleanup(phys_client);

	phys_server= spindly_phys_init(SPINDLY_SIDE_SERVER, SPINDLY_SPDYVER2,
			NULL);
	_spindly_print_test_result(Sanity, Pointer, phys_client, fun_name);
	spindly_phys_cleanup(phys_server);

	phys_client = spindly_phys_init(SPINDLY_SIDE_CLIENT, SPINDLY_SPDYVER3,
			NULL);
	_spindly_print_test_result(Sanity, Pointer, phys_client, fun_name);
	spindly_phys_cleanup(phys_client);

	phys_client = spindly_phys_init(SPINDLY_SIDE_SERVER, SPINDLY_DEFAULT, NULL);
	_spindly_print_test_result(Sanity, Pointer, phys_client, fun_name);
	spindly_phys_cleanup(phys_server);

	phys_client = spindly_phys_init(-100, SPINDLY_DEFAULT, NULL);
	_spindly_print_test_result(Error, Pointer, phys_client, fun_name);
	spindly_phys_cleanup(phys_client);

	phys_client = spindly_phys_init(SPINDLY_SIDE_CLIENT, 8, NULL);
	_spindly_print_test_result(Error, Pointer, phys_client, fun_name);
	spindly_phys_cleanup(phys_client);
}

static void _spindly_phys_incoming_test()
{
	struct spindly_phys *phys_client = NULL;
	struct spindly_phys *phys_server = NULL;

	struct spindly_stream *str = NULL;

	spindly_error_t spint = SPINDLYE_OK;
	const void *retcode = NULL;

	unsigned char *in_data = NULL, *out_data = NULL;
	size_t in_datalen = 0, out_datalen = 0;
	const char *fun_name = F_STR(spindly_phys_incoming);

	/* CLIENT: create a handle for the physical connection */
	phys_client = spindly_phys_init(SPINDLY_SIDE_CLIENT, SPINDLY_DEFAULT, NULL);
	fail_if(phys_client == NULL, "%s", "spindly_phys_init() failed");

	/* SERVER: create a handle for the physical connection */
	phys_server = spindly_phys_init(SPINDLY_SIDE_SERVER, SPINDLY_DEFAULT, NULL);
	fail_if(phys_server == NULL, "%s", "spindly_phys_init() failed");

	/* CLIENT: create a stream on the physical connection ; Send dummy data. */
	spint = spindly_stream_new(phys_client, 0x01, 0, &str, NULL, NULL, NULL);
	fail_if(spint != SPINDLYE_OK, "%s [%d]", "spindly_stream_new() failed",
			spint);

	/* CLIENT: get data to send */
	spint = spindly_phys_outgoing(phys_client, &out_data, &out_datalen);
	fail_if(spint != SPINDLYE_OK, "%s [%d]", "spindly_phys_outgoing() failed", spint);

	fail_if(out_datalen != SYNC_STREAM_SIZE, "%s %d",
			"spindly_phys_outgoing() returned bad value", out_datalen);

	in_data = out_data; // incoming data
	in_datalen = out_datalen; // length of incoming data

	/* SERVER: now feed the created outgoing packet from the client as incoming
	   in the server! */
	spint = spindly_phys_incoming(phys_server, in_data, in_datalen,
			SPINDLY_INCOMING_COPY, NULL);

	retcode = (const void *) spint;
	_spindly_print_test_result(Sanity, Integer, retcode, fun_name);

	spint = spindly_phys_incoming(NULL, in_data, in_datalen,
			SPINDLY_INCOMING_COPY, NULL);

	retcode = (const void *) spint;
	_spindly_print_test_result(Error, Integer, retcode, fun_name);

	spint = spindly_phys_incoming(phys_server, NULL, in_datalen,
			SPINDLY_INCOMING_COPY, NULL);

	retcode = (const void *) spint;
	_spindly_print_test_result(Error, Integer, retcode, fun_name);

	spint = spindly_phys_incoming(phys_server, in_data, 0,
			SPINDLY_INCOMING_COPY, NULL);

	retcode = (const void *) spint;
	_spindly_print_test_result(Error, Integer, retcode, fun_name);

	spint = spindly_phys_incoming(phys_server, in_data, in_datalen,
			1000, NULL);

	retcode = (const void *) spint;
	_spindly_print_test_result(Error, Integer, retcode, fun_name);

	spint = spindly_phys_incoming(phys_server, in_data, in_datalen,
			SPINDLY_INCOMING_COPY, NULL);

	retcode = (const void *) spint;
	_spindly_print_test_result(Sanity, Integer, retcode, fun_name);

	/* CLIENT: close connection */
	spindly_phys_cleanup(phys_client);

	/* SERVER: close connection */
	spindly_phys_cleanup(phys_server);
}

static void _spindly_phys_demux_test()
{
	struct spindly_phys *phys_client = NULL;
	struct spindly_phys *phys_server = NULL;
	struct spindly_stream *str = NULL;
	spindly_error_t spint = SPINDLYE_OK;
	unsigned char *in_data = NULL, *out_data = NULL;
	size_t in_datalen = 0, out_datalen = 0;
	struct spindly_demux demux;
	const char *fun_name = F_STR(spindly_phys_demux);

	/* CLIENT: create a handle for the physical connection */
	phys_client = spindly_phys_init(SPINDLY_SIDE_CLIENT, SPINDLY_DEFAULT, NULL);
	fail_if(phys_client == NULL, "%s", "spindly_phys_init() failed");

	/* SERVER: create a handle for the physical connection */
	phys_server = spindly_phys_init(SPINDLY_SIDE_SERVER, SPINDLY_DEFAULT, NULL);
	fail_if(phys_server == NULL, "%s", "spindly_phys_init() failed");

	/* CLIENT: create a stream on the physical connection ; Send dummy data. */
	spint = spindly_stream_new(phys_client, 0x01, 0, &str, NULL, NULL, NULL);
	fail_if(spint != SPINDLYE_OK, "%s [%d]", "spindly_stream_new() failed",
			spint);

	/* CLIENT: get data to send */
	spint = spindly_phys_outgoing(phys_client, &out_data, &out_datalen);
	fail_if(spint != SPINDLYE_OK, "%s [%d]", "spindly_phys_outgoing() failed",
			spint);

	fail_if(out_datalen != SYNC_STREAM_SIZE, "%s %d",
			"spindly_phys_outgoing() returned bad value", out_datalen);

	in_data = out_data; // incoming data
	in_datalen = out_datalen; // length of incoming data

	/* SERVER: now feed the created outgoing packet from the client as incoming
	   in the server! */
	spint = spindly_phys_incoming(phys_server, in_data, in_datalen,
			SPINDLY_INCOMING_COPY, NULL);

	spint = spindly_phys_demux(phys_client, &demux);

	spint = (spint == SPINDLYE_OK) && (demux.type == SPINDLY_DX_STREAM_ACK);
	_spindly_print_test_result(Sanity, Integer, (const void *) spint, fun_name);

	spint = spindly_phys_demux(NULL, &demux);

	_spindly_print_test_result(Error, Integer, (const void *) spint, fun_name);

	spint = spindly_phys_demux(phys_client, NULL);

	_spindly_print_test_result(Error, Integer, (const void *) spint, fun_name);

	/* Free demux */
	spindly_free_demux(phys_client, &demux);
	spindly_phys_cleanup(phys_client); phys_client = NULL;
	spindly_phys_cleanup(phys_server); phys_server= NULL;
}

static void _spindly_free_demux_test()
{
	struct spindly_phys *phys_client = NULL;
	struct spindly_phys *phys_server = NULL;
	struct spindly_stream *str = NULL;
	spindly_error_t spint = SPINDLYE_OK;
	unsigned char *in_data = NULL, *out_data = NULL;
	size_t in_datalen = 0, out_datalen = 0;
	struct spindly_demux demux;
	const char *fun_name = F_STR(spindly_free_demux);

	/* CLIENT: create a handle for the physical connection */
	phys_client = spindly_phys_init(SPINDLY_SIDE_CLIENT, SPINDLY_DEFAULT, NULL);
	fail_if(phys_client == NULL, "%s", "spindly_phys_init() failed");

	/* SERVER: create a handle for the physical connection */
	phys_server = spindly_phys_init(SPINDLY_SIDE_SERVER, SPINDLY_DEFAULT, NULL);
	fail_if(phys_server == NULL, "%s", "spindly_phys_init() failed");

	/* CLIENT: create a stream on the physical connection ; Send dummy data. */
	spint = spindly_stream_new(phys_client, 0x01, 0, &str, NULL, NULL, NULL);
	fail_if(spint != SPINDLYE_OK, "%s [%d]", "spindly_stream_new() failed",
			spint);

	/* CLIENT: get data to send */
	spint = spindly_phys_outgoing(phys_client, &out_data, &out_datalen);
	fail_if(spint != SPINDLYE_OK, "%s [%d]", "spindly_phys_outgoing() failed",
			spint);

	fail_if(out_datalen != SYNC_STREAM_SIZE, "%s %d",
			"spindly_phys_outgoing() returned bad value", out_datalen);

	in_data = out_data; // incoming data
	in_datalen = out_datalen; // length of incoming data

	/* SERVER: now feed the created outgoing packet from the client as incoming
	   in the server! */
	spint = spindly_phys_incoming(phys_server, in_data, in_datalen,
			SPINDLY_INCOMING_COPY, NULL);

	spint = spindly_phys_demux(phys_client, &demux);

	/*
	   Interpret spint value and demux's type....
	   ...
	 */
	/* Free demux */
	spint = spindly_free_demux(phys_client, &demux);

	_spindly_print_test_result(Sanity, Integer, (const void *) spint, fun_name);

	/* SERVER: now feed AGAIN the created outgoing packet from the client as
	   incoming in the server! */
	spint = spindly_phys_incoming(phys_server, in_data, in_datalen,
			SPINDLY_INCOMING_COPY, NULL);

	spint = spindly_phys_demux(phys_client, &demux);
	/*
	   Interpret spint value and demux's type....
	   ...
	 */
	/* Free demux */
	spint = spindly_free_demux(NULL, &demux);

	_spindly_print_test_result(Error, Integer, (const void *) spint, fun_name);

	/* SERVER: now feed AGAIN the created outgoing packet from the client as
	   incoming in the server! */
	spint = spindly_phys_incoming(phys_server, in_data, in_datalen,
			SPINDLY_INCOMING_COPY, NULL);

	spint = spindly_phys_demux(phys_client, &demux);
	/*
	   Interpret spint value and demux's type....
	   ...
	 */
	/* Free demux */
	spint = spindly_free_demux(phys_client, NULL);

	_spindly_print_test_result(Error, Integer, (const void *) spint, fun_name);

}

static void _spindly_phys_outgoing_test()
{
	struct spindly_phys *phys_client = NULL;
	struct spindly_stream *str[10] = { NULL };
	spindly_error_t spint = SPINDLYE_OK;
	unsigned char *out_data = NULL;
	size_t out_datalen = 0;
	const char *fun_name = F_STR(spindly_phys_outgoing);

	/* CLIENT: create a handle for the physical connection */
	phys_client = spindly_phys_init(SPINDLY_SIDE_CLIENT, SPINDLY_DEFAULT, NULL);
	fail_if(phys_client == NULL, "%s", "spindly_phys_init() failed");

	/* CLIENT: create a stream on the physical connection ; Send dummy data. */
	spint = spindly_stream_new(phys_client, 0x01, 0, &str[0], NULL, NULL, NULL);
	fail_if(spint != SPINDLYE_OK, "%s [%d]", "spindly_stream_new() failed",
			spint);

	/* CLIENT: get data to send */
	spint = spindly_phys_outgoing(phys_client, &out_data, &out_datalen);
	if (spint == SPINDLYE_OK && out_data && out_datalen == SYNC_STREAM_SIZE)
		spint = SPINDLYE_OK;
	else if (!out_data || out_datalen != SYNC_STREAM_SIZE)
		spint = SPINDLYE_INVAL;
	free(out_data);	out_data = NULL;
	_spindly_print_test_result(Sanity, Integer, (const void *) spint, fun_name);


	/* CLIENT: create a stream on the physical connection ; Send dummy data. */
	spint = spindly_stream_new(phys_client, 0x01, 0, &str[1], NULL, NULL, NULL);
	fail_if(spint != SPINDLYE_OK, "%s [%d]", "spindly_stream_new() failed",
			spint);

	/* CLIENT: get data to send */
	spint = spindly_phys_outgoing(NULL, &out_data, &out_datalen);
	if (spint == SPINDLYE_OK && out_data && out_datalen == SYNC_STREAM_SIZE)
		spint = SPINDLYE_OK;
	else if (!out_data || out_datalen != SYNC_STREAM_SIZE)
		spint = SPINDLYE_INVAL;
	free(out_data); out_data = NULL;
	_spindly_print_test_result(Error, Integer, (const void *) spint, fun_name);

	/* CLIENT: create a stream on the physical connection ; Send dummy data. */
	spint = spindly_stream_new(phys_client, 0x01, 0, &str[2], NULL, NULL, NULL);
	fail_if(spint != SPINDLYE_OK, "%s [%d]", "spindly_stream_new() failed",
			spint);

	/* CLIENT: get data to send */
	spint = spindly_phys_outgoing(phys_client, NULL, &out_datalen);
	_spindly_print_test_result(Error, Integer, (const void *) spint, fun_name);

	/* CLIENT: create a stream on the physical connection ; Send dummy data. */
	spint = spindly_stream_new(phys_client, 0x01, 0, &str[3], NULL, NULL, NULL);
	fail_if(spint != SPINDLYE_OK, "%s [%d]", "spindly_stream_new() failed",
			spint);

	/* CLIENT: get data to send */
	spint = spindly_phys_outgoing(phys_client, &out_data, NULL);
	_spindly_print_test_result(Error, Integer, (const void *) spint, fun_name);
	spindly_phys_cleanup(phys_client); phys_client = NULL;
}

static void _spindly_phys_sent_test()
{
	struct spindly_phys *phys_client = NULL;
	struct spindly_stream *str[10] = { NULL };
	spindly_error_t spint = SPINDLYE_OK;
	const void *retcode = NULL;
	unsigned char *out_data[10] = { NULL };
	size_t out_datalen[10] = { 0 };
	const char *fun_name = F_STR(spindly_phys_sent);

	/* CLIENT: create a handle for the physical connection */
	phys_client = spindly_phys_init(SPINDLY_SIDE_CLIENT, SPINDLY_DEFAULT, NULL);
	fail_if(phys_client == NULL, "%s", "spindly_phys_init() failed");

	/* CLIENT: create a stream on the physical connection ; Send dummy data. */
	spint = spindly_stream_new(phys_client, 0x01, 0, &str[0], NULL, NULL, NULL);
	fail_if(spint != SPINDLYE_OK, "%s [%d]", "spindly_stream_new() failed", spint);

	/* CLIENT: get data to send */
	spint = spindly_phys_outgoing(phys_client, &out_data[0], &out_datalen[0]);
	fail_if(spint != SPINDLYE_OK, "%s [%d]", "spindly_phys_outgoing() failed",
			spint);

	fail_if(out_datalen[0] != SYNC_STREAM_SIZE, "%s %d",
			"spindly_phys_outgoing() returned bad value", out_datalen[0]);
	/*
	   Data will be sent to the Server. Assume that ALL the data sent successfully.
	 */
	spint = spindly_phys_sent(phys_client, out_datalen[0]);
	_spindly_print_test_result(Sanity, Integer, (const void *) spint, fun_name);

	spindly_phys_cleanup(phys_client); phys_client = NULL;

	/* CLIENT: create a handle for the physical connection */
	phys_client = spindly_phys_init(SPINDLY_SIDE_CLIENT, SPINDLY_DEFAULT, NULL);
	fail_if(phys_client == NULL, "%s", "spindly_phys_init() failed");

	/* CLIENT: create a stream on the physical connection ; Send dummy data. */
	spint = spindly_stream_new(phys_client, 0x01, 0, &str[1], NULL, NULL,
			NULL);
	fail_if(spint != SPINDLYE_OK, "%s [%d]", "spindly_stream_new() failed",
			spint);

	/* CLIENT: get data to send */
	spint = spindly_phys_outgoing(phys_client, &out_data[1], &out_datalen[1]);
	fail_if(spint != SPINDLYE_OK, "%s [%d]", "spindly_phys_outgoing() failed",
			spint);

	fail_if(out_datalen[1] != SYNC_STREAM_SIZE, "%s %d",
			"spindly_phys_outgoing() returned bad value", out_datalen[1]);
	/*
	   Data will be sent to the Server. Assume that ALL the data sent successfully.
	 */
	spint = spindly_phys_sent(NULL, out_datalen[1]);
	_spindly_print_test_result(Error, Integer, (const void *) spint, fun_name);

	/* CLIENT: close connection */
	spindly_phys_cleanup(phys_client);


	/* CLIENT: create a handle for the physical connection */
	phys_client = spindly_phys_init(SPINDLY_SIDE_CLIENT, SPINDLY_DEFAULT, NULL);
	fail_if(phys_client == NULL, "%s", "spindly_phys_init() failed");

	/* CLIENT: create a stream on the physical connection ; Send dummy data. */
	spint = spindly_stream_new(phys_client, 0x01, 0, &str[2], NULL, NULL,
			NULL);
	fail_if(spint != SPINDLYE_OK, "%s [%d]", "spindly_stream_new() failed",
			spint);

	/* CLIENT: get data to send */
	spint = spindly_phys_outgoing(phys_client, &out_data[2], &out_datalen[2]);
	fail_if(spint != SPINDLYE_OK, "%s [%d]", "spindly_phys_outgoing() failed",
			spint);

	fail_if(out_datalen[2] != SYNC_STREAM_SIZE, "%s %d",
			"spindly_phys_outgoing() returned bad value", out_datalen[2]);
	/*
	   Data will be sent to the Server. Assume that ALL the data sent successfully.
	 */
	spint = spindly_phys_sent(phys_client, 2000000000);
	_spindly_print_test_result(Error, Integer, (const void *) spint, fun_name);

	/* CLIENT: close connection */
	spindly_phys_cleanup(phys_client);

}

static void _spindly_phys_settings_test()
{
	struct spindly_phys *phys_client = NULL;
	struct spindly_iv_block settings_iv_block;
	spindly_error_t spint = SPINDLYE_OK;
	const char *fun_name = F_STR(spindly_phys_settings);

	/* Reset settings IV block */
	bzero(&settings_iv_block, sizeof(settings_iv_block));

	/* CLIENT: create a handle for the physical connection */
	phys_client = spindly_phys_init(SPINDLY_SIDE_CLIENT, SPINDLY_DEFAULT, NULL);
	fail_if(phys_client == NULL, "%s", "spindly_phys_init() failed");

	/* Add IV pairs to it */
	spindly_iv_block_add_pairs(&settings_iv_block,
			SETTINGS_MAX_CONCURRENT_STREAMS, /* Id */
			SETTINGS_FLAG_NONE, 			/* Flag */
			1000);							/* Value */
	spindly_iv_block_add_pairs(&settings_iv_block,
			SETTINGS_INITIAL_WINDOW_SIZE,	/* Id */
			SETTINGS_FLAG_NONE, 			/* Flag */
			10485760);						/* Value */

	/* Send a SETTINGS frame. */
	spint = spindly_phys_settings(phys_client, &settings_iv_block);
	_spindly_print_test_result(Sanity, Integer, (const void *) spint, fun_name);

	/* Reset settings IV block */
	bzero(&settings_iv_block, sizeof(settings_iv_block));

	spindly_iv_block_add_pairs(&settings_iv_block,
			SETTINGS_MAX_CONCURRENT_STREAMS, /* Id */
			SETTINGS_FLAG_PERSISTED,		/* Flag */
			100);							/* Value */
	spindly_iv_block_add_pairs(&settings_iv_block,
			SETTINGS_CURRENT_CWND,			/* Id */
			SETTINGS_FLAG_PERSISTED,		/* Flag */
			27);							/* Value */
	spindly_iv_block_add_pairs(&settings_iv_block,
			SETTINGS_DOWNLOAD_RETRANS_RATE, /* Id */
			SETTINGS_FLAG_PERSISTED,		/* Flag */
			0); 						/* Value */

	/* Resend a SETTINGS frame. */
	spint = spindly_phys_settings(phys_client, NULL);
	_spindly_print_test_result(Error, Integer, (const void *) spint, fun_name);

	spindly_iv_block_add_pairs(&settings_iv_block,
			SETTINGS_MAX_CONCURRENT_STREAMS, /* Id */
			SETTINGS_FLAG_PERSISTED,		/* Flag */
			100);							/* Value */
	spindly_iv_block_add_pairs(&settings_iv_block,
			SETTINGS_CURRENT_CWND,			/* Id */
			SETTINGS_FLAG_PERSISTED,		/* Flag */
			27);							/* Value */
	spindly_iv_block_add_pairs(&settings_iv_block,
			SETTINGS_DOWNLOAD_RETRANS_RATE, /* Id */
			SETTINGS_FLAG_PERSISTED,		/* Flag */
			0); 						/* Value */

	/* Resend a SETTINGS frame. */
	spint = spindly_phys_settings(NULL, &settings_iv_block);
	_spindly_print_test_result(Error, Integer, (const void *) spint, fun_name);


	/* Free settings ID-Value block. */
	spindly_destroy_iv_block(&settings_iv_block);

	/* CLIENT: close connection */
	spindly_phys_cleanup(phys_client);
}

static void _spindly_phys_ping_test()
{
	struct spindly_phys *phys_client = NULL;
	spindly_error_t spint = SPINDLYE_OK;
	const char *fun_name = F_STR(spindly_phys_ping);

	/* CLIENT: create a handle for the physical connection */
	phys_client = spindly_phys_init(SPINDLY_SIDE_CLIENT, SPINDLY_DEFAULT, NULL);
	fail_if(phys_client == NULL, "%s", "spindly_phys_init() failed");

	spint = spindly_phys_ping(phys_client, 100);
	_spindly_print_test_result(Sanity, Integer, (const void *) spint, fun_name);

	spint = spindly_phys_ping(NULL, 101);
	_spindly_print_test_result(Error, Integer, (const void *) spint, fun_name);

}

static void _spindly_phys_goaway_test()
{
	struct spindly_phys *phys_client = NULL;
	spindly_error_t spint = SPINDLYE_OK;
	const char *fun_name = F_STR(spindly_phys_goaway);
	enum {
		STATUS_OK = 0, STATUS_PROTOCOL_ERR = 1, STATUS_INT_ERR = 2
	};

	/* CLIENT: create a handle for the physical connection */
	phys_client = spindly_phys_init(SPINDLY_SIDE_CLIENT, SPINDLY_DEFAULT, NULL);
	fail_if(phys_client == NULL, "%s", "spindly_phys_init() failed");

	spint = spindly_phys_goaway(phys_client, STATUS_OK);
	_spindly_print_test_result(Sanity, Integer, (const void *) spint, fun_name);

	spint = spindly_phys_goaway(NULL, STATUS_OK);
	_spindly_print_test_result(Error, Integer, (const void *) spint, fun_name);

}

static void _spindly_phys_cleanup_test()
{
	struct spindly_phys *phys_client = NULL;
	spindly_error_t spint = SPINDLYE_OK;
	const char *fun_name = F_STR(spindly_phys_cleanup);

	/* CLIENT: create a handle for the physical connection */
	phys_client = spindly_phys_init(SPINDLY_SIDE_CLIENT, SPINDLY_DEFAULT, NULL);
	fail_if(phys_client == NULL, "%s", "spindly_phys_init() failed");

	spindly_phys_cleanup(phys_client);
	_spindly_print_test_result(Sanity, Integer, (const void *) spint, fun_name);

	spindly_phys_cleanup(NULL);
	spint = SPINDLYE_INVAL;
	_spindly_print_test_result(Error, Integer, (const void *) spint, fun_name);

}

static void _spindly_add_header_test()
{
	struct spindly_headers test_headers = { 0 };
	char *url = "www.google.co.in";

	spindly_add_header(&test_headers, "accept", "*/*");
	spindly_add_header(&test_headers, ":host", url);
	spindly_add_header(&test_headers, ":method", "GET");
	spindly_add_header(&test_headers, ":scheme", "https");
	spindly_add_header(&test_headers, ":path", "/");
	spindly_add_header(&test_headers, "user-agent",
			"Mozilla/5.0 (X11; Linux i686) AppleWebKit/534.24 (KHTML, like Gecko) "
			"Chrome/11.0.696.16 Safari/534.24");
	spindly_add_header(&test_headers, ":version", "HTTP/1.1");
}

void _spindly_stream_new_test()
{
	struct spindly_phys *phys_client = NULL;
	struct spindly_stream *streams[10] = { NULL };
	struct spindly_stream *stream = NULL;
	struct spindly_stream **pstr = streams;
	spindly_error_t spint = SPINDLYE_OK;
	const void *retcode = NULL;
	unsigned char *out_data = NULL;
	size_t out_datalen = 0;
	const char *fun_name = F_STR(spindly_stream_new);

	/* CLIENT: create a handle for the physical connection */
	phys_client = spindly_phys_init(SPINDLY_SIDE_CLIENT, SPINDLY_DEFAULT,
			NULL);
	fail_if(phys_client == NULL, "%s", "spindly_phys_init() failed");

	/* CLIENT: create a stream on the physical connection ; Send dummy data. */
	spint = spindly_stream_new(phys_client, 0x01, 0, pstr, NULL, NULL,	NULL);
	spint = (spint == SPINDLYE_OK) && (*pstr != NULL) ? spint : SPINDLYE_INVAL;
	_spindly_print_test_result(Sanity, Integer, (const void *) spint, fun_name);

	pstr++; // Next stream [NULL phys handle]
	/* CLIENT: create a stream on the physical connection ; Send dummy data. */
	spint = spindly_stream_new(NULL, 0x01, 0, pstr, NULL, NULL, NULL);
	spint = (spint == SPINDLYE_OK) && (*pstr != NULL) ? spint : SPINDLYE_INVAL;
	_spindly_print_test_result(Error, Integer, (const void *) spint, fun_name);

	pstr++; // Next stream	[Wrong flags]
	/* CLIENT: create a stream on the physical connection ; Send dummy data. */
	spint = spindly_stream_new(phys_client, 0x04, 8, pstr, NULL, NULL, NULL);
	_spindly_print_test_result(Error, Integer, (const void *) spint, fun_name);

	pstr++; // Next stream  [Wrong prio]
	/* CLIENT: create a stream on the physical connection ; Send dummy data. */
	spint = spindly_stream_new(phys_client, 0x01, 8, pstr, NULL, NULL, NULL);
	_spindly_print_test_result(Error, Integer, (const void *) spint, fun_name);

	pstr++; // Next stream	[NULL stream pointer]
	/* CLIENT: create a stream on the physical connection ; Send dummy data. */
	spint = spindly_stream_new(phys_client, 0x01, 0, NULL, NULL, NULL, NULL);
	_spindly_print_test_result(Error, Integer, (const void *) spint, fun_name);

	/* Closes all the open streams and the connection as well. */
	spindly_phys_cleanup(phys_client); phys_client = NULL;
}

static void _spindly_stream_get_stream_id_test()
{
	struct spindly_phys *phys_client = NULL;
	struct spindly_stream *stream = NULL;
	spindly_error_t spint = SPINDLYE_OK;
	unsigned char *out_data = NULL;
	size_t out_datalen = 0;
	uint32_t str_id = 0;
	const char *fun_name = F_STR(spindly_stream_get_stream_id);

	/* CLIENT: create a handle for the physical connection */
	phys_client = spindly_phys_init(SPINDLY_SIDE_CLIENT,
			SPINDLY_DEFAULT,
			NULL);
	fail_if(phys_client == NULL, "%s", "spindly_phys_init() failed");

	/* CLIENT: create a stream on the physical connection ; Send dummy data. */
	spint = spindly_stream_new(phys_client, 0x01, 0, &stream, NULL, NULL, NULL);
	fail_if(spint != SPINDLYE_OK, "%s [%d]", "spindly_stream_new() failed",
			spint);
	// pass valid stream
	str_id = spindly_stream_get_stream_id(stream);
	spint = str_id ? SPINDLYE_OK : -1;
	_spindly_print_test_result(Sanity, Integer, (const void *) spint, fun_name);

	// pass NULL stream
	str_id = spindly_stream_get_stream_id(NULL);
	spint = !str_id ? -1 : SPINDLYE_OK;
	_spindly_print_test_result(Error, Integer, (const void *) spint, fun_name);

	spindly_phys_cleanup(phys_client); phys_client = NULL;
}

static void _spindly_stream_ack_test()
{
	struct spindly_phys *phys_client = NULL;
	struct spindly_phys *phys_server = NULL;
	struct spindly_stream *stream_client = NULL;
	struct spindly_demux demux;
	spindly_error_t spint = SPINDLYE_OK;
	unsigned char *out_data = NULL;
	unsigned char *in_data = NULL;
	size_t out_datalen = 0;
	size_t in_datalen = 0;
	const char *fun_name = F_STR(spindly_stream_ack);

	/* CLIENT: create a handle for the physical connection */
	phys_client = spindly_phys_init(SPINDLY_SIDE_CLIENT, SPINDLY_DEFAULT, NULL);
	fail_if(phys_client == NULL, "%s", "spindly_phys_init() failed");

	/* SERVER: create a handle for the physical connection */
	phys_server = spindly_phys_init(SPINDLY_SIDE_SERVER, SPINDLY_DEFAULT, NULL);
	fail_if(phys_server == NULL, "%s", "spindly_phys_init() failed");

	/* CLIENT: create a stream on the physical connection ; Send dummy data. */
	spint = spindly_stream_new(phys_client, 0x01, 0, &stream_client, NULL, NULL,
			NULL);
	fail_if(spint != SPINDLYE_OK, "%s [%d]", "spindly_stream_new() failed",
			spint);

	/* CLIENT: get data to send */
	spint = spindly_phys_outgoing(phys_client, &out_data, &out_datalen);
	fail_if(spint != SPINDLYE_OK, "%s [%d]", "spindly_phys_outgoing() failed",
			spint);

	fail_if(out_datalen != SYNC_STREAM_SIZE, "%s %d",
			"spindly_phys_outgoing() returned bad value", out_datalen);

	in_data = out_data; // incoming data
	in_datalen = out_datalen; // length of incoming data
	/* SERVER: now feed the created outgoing packet from the client as incoming
	   in the server! */
	spint = spindly_phys_incoming(phys_server,
			in_data,
			in_datalen,
			SPINDLY_INCOMING_COPY,
			NULL);
	fail_if(spint != SPINDLYE_OK, "%s", "spindly_phys_incoming() failed");

	/* NOTE: since spindly_phys_incoming() does not immediately copy the data
	   passed to it, we cannot immediately call spindly_phys_sent() */

	/* SERVER: demux the incoming data */
	spint = spindly_phys_demux(phys_server, &demux);
	fail_if(spint != SPINDLYE_OK, "%s", "spindly_phys_demux() failed");

	fail_if(demux.type != SPINDLY_DX_STREAM_REQ, "%s",
			"spindly_phys_demux() demuxed incorrect message");
	fail_if(demux.msg.stream.stream == NULL, "%s",
			"spindly_phys_demux() demuxed incorrect message");

	/* CLIENT: consider the data is sent and tell spindly so */
	spint = spindly_phys_sent(phys_client, out_datalen);
	fail_if(spint != SPINDLYE_OK, "%s", "spindly_phys_sent() failed");

	/* SERVER: ACK the new stream (sending the same stream) */
	spint = spindly_stream_ack(demux.msg.stream.stream);

	_spindly_print_test_result(Sanity, Integer, (const void *) spint, fun_name);

	/* SERVER: ACK the new stream (sending the NULL stream) */
	spint = spindly_stream_ack(NULL);

	_spindly_print_test_result(Error, Integer, (const void *) spint, fun_name);
	spindly_phys_cleanup(phys_client); phys_client = NULL;
	spindly_phys_cleanup(phys_server); phys_server = NULL;

}


static void _spindly_stream_nack_test()
{
	struct spindly_phys *phys_client = NULL;
	struct spindly_phys *phys_server = NULL;
	struct spindly_stream *stream_client = NULL;
	struct spindly_demux demux;
	spindly_error_t spint = SPINDLYE_OK;
	unsigned char *out_data = NULL;
	unsigned char *in_data = NULL;
	size_t out_datalen = 0;
	size_t in_datalen = 0;
	const char *fun_name = F_STR(spindly_stream_nack);

	/* CLIENT: create a handle for the physical connection */
	phys_client = spindly_phys_init(SPINDLY_SIDE_CLIENT, SPINDLY_DEFAULT, NULL);
	fail_if(phys_client == NULL, "%s", "spindly_phys_init() failed");

	/* SERVER: create a handle for the physical connection */
	phys_server = spindly_phys_init(SPINDLY_SIDE_SERVER, SPINDLY_DEFAULT, NULL);
	fail_if(phys_server == NULL, "%s", "spindly_phys_init() failed");

	/* CLIENT: create a stream on the physical connection ; Send dummy data. */
	spint = spindly_stream_new(phys_client, 0x01, 0, &stream_client, NULL, NULL,
			NULL);
	fail_if(spint != SPINDLYE_OK, "%s [%d]", "spindly_stream_new() failed",
			spint);

	/* CLIENT: get data to send */
	spint = spindly_phys_outgoing(phys_client, &out_data, &out_datalen);
	fail_if(spint != SPINDLYE_OK, "%s [%d]", "spindly_phys_outgoing() failed",
			spint);

	fail_if(out_datalen != SYNC_STREAM_SIZE, "%s %d",
			"spindly_phys_outgoing() returned bad value", out_datalen);

	in_data = out_data; // incoming data
	in_datalen = out_datalen; // length of incoming data
	/* SERVER: now feed the created outgoing packet from the client as incoming
	   in the server! */
	spint = spindly_phys_incoming(phys_server,
			in_data,
			in_datalen,
			SPINDLY_INCOMING_COPY,
			NULL);
	fail_if(spint != SPINDLYE_OK, "%s", "spindly_phys_incoming() failed");

	/* NOTE: since spindly_phys_incoming() does not immediately copy the data
	   passed to it, we cannot immediately call spindly_phys_sent() */

	/* SERVER: demux the incoming data */
	spint = spindly_phys_demux(phys_server, &demux);
	fail_if(spint != SPINDLYE_OK, "%s", "spindly_phys_demux() failed");

	fail_if(demux.type != SPINDLY_DX_STREAM_REQ, "%s",
			"spindly_phys_demux() demuxed incorrect message");
	fail_if(demux.msg.stream.stream == NULL, "%s",
			"spindly_phys_demux() demuxed incorrect message");

	/* CLIENT: consider the data is sent and tell spindly so */
	spint = spindly_phys_sent(phys_client, out_datalen);
	fail_if(spint != SPINDLYE_OK, "%s", "spindly_phys_sent() failed");

	/* SERVER: ACK the new stream (sending the same stream) */
	spint = spindly_stream_nack(demux.msg.stream.stream);

	_spindly_print_test_result(Sanity, Integer, (const void *) spint, fun_name);

	/* SERVER: ACK the new stream (sending the NULL stream) */
	spint = spindly_stream_nack(NULL);

	_spindly_print_test_result(Error, Integer, (const void *) spint, fun_name);
	spindly_phys_cleanup(phys_client); phys_client = NULL;
	spindly_phys_cleanup(phys_server); phys_server = NULL;

}

static void _spindly_stream_data_test()
{
	struct spindly_phys *phys_client = NULL;
	struct spindly_stream *streams[10]  = { NULL };
	struct spindly_stream **stream_client = streams;
	spindly_error_t spint = SPINDLYE_OK;
	unsigned char *data = NULL;
	size_t datalen = 0;
	const char *fun_name = F_STR(spindly_stream_data);

	/* CLIENT: create a handle for the physical connection */
	phys_client = spindly_phys_init(SPINDLY_SIDE_CLIENT, SPINDLY_DEFAULT, NULL);
	fail_if(phys_client == NULL, "%s", "spindly_phys_init() failed");


	struct spindly_headers test_headers = { 0 };
	char *url = "www.google.co.in";

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
	spindly_add_header(&test_headers, "content-type", "application/atom+xml");
	spindly_add_header(&test_headers, "accept-charset",
			"ISO-8859-1,utf-8,q=0.7,*;q=0.2");
	spindly_add_header(&test_headers, "accept-encoding", "gzip,deflate,sdcch");
	spindly_add_header(&test_headers, "accept-language", "en-US,en;q=0.8");

	/* create a new stream on the physical connection */
	spint = spindly_stream_new(phys_client,
			0,
			0,
			stream_client,
			NULL,
			NULL,
			&test_headers);

	/* get data to send over the socket */
	spint = spindly_phys_outgoing(phys_client, &data, &datalen);
	url = "<entry xmlns='http://www.w3.org/2005/Atom' "
		"xmlns:media='http://search.yahoo.com/mrss/' "
		"xmlns:gphoto='http://schemas.google.com/photos/2007'>"
		"<title type='text'>I visited MyHospet</title>"
		"<summary type='text'>My photo with My Family. </summary>"
		"<gphoto:location>HBHalli</gphoto:location><gphoto:access>"
		"public</gphoto:access><gphoto:timestamp>1152255600000"
		"</gphoto:timestamp><media:group><media:keywords>Bellary, India"
		"</media:keywords></media:group><category "
		"scheme='http://schemas.google.com/g/2005#kind' "
		"term='http://schemas.google.com/photos/2007#album'></category></entry>";


	spindly_phys_sent(phys_client, datalen);

	spint = spindly_stream_data(*stream_client,
			0x1,
			url,
			strlen(url),
			NULL);
	_spindly_print_test_result(Sanity, Integer, (const void *) spint, fun_name);

	/* create a new stream on the physical connection */
	spint = spindly_stream_new(phys_client,
			0,
			0,
			&stream_client[1],
			NULL,
			NULL,
			&test_headers);
	spint = spindly_stream_data(NULL, // stream is null
			0x1,
			url,
			strlen(url),
			NULL);
	_spindly_print_test_result(Error, Integer, (const void *) spint, fun_name);

	/* create a new stream on the physical connection */
	spint = spindly_stream_new(phys_client,
			0,
			0,
			&stream_client[2],
			NULL,
			NULL,
			&test_headers);
	spint = spindly_stream_data(stream_client[2],
			0x4, // Invalid flags
			url,
			strlen(url),
			NULL);
	_spindly_print_test_result(Error, Integer, (const void *) spint,
			fun_name);

	/* create a new stream on the physical connection */
	spint = spindly_stream_new(phys_client,
			0,
			0,
			&stream_client[3],
			NULL,
			NULL,
			&test_headers);
	spint = spindly_stream_data(stream_client[3],
			0x1,
			NULL, // NULL data
			strlen(url),
			NULL);
	_spindly_print_test_result(Error, Integer, (const void *) spint,
			fun_name);

	/* create a new stream on the physical connection */
	spint = spindly_stream_new(phys_client,
			0,
			0,
			&stream_client[4],
			NULL,
			NULL,
			&test_headers);
	spint = spindly_stream_data(stream_client[4],
			0x1,
			url,
			0,  // len is 0
			NULL);
	_spindly_print_test_result(Error, Integer, (const void *) spint,
			fun_name);

}

static void _spindly_stream_get_stream_test()
{
	struct spindly_phys *phys_client = NULL;
	struct spindly_stream *stream_clients[10]	= { NULL };
	struct spindly_stream *str = NULL;
	spindly_error_t spint = SPINDLYE_OK;
	unsigned char *data = NULL;
	size_t datalen = 0;
	const char *fun_name = F_STR(spindly_stream_get_stream);
	uint32_t str_id = 0;

	/* CLIENT: create a handle for the physical connection */
	phys_client = spindly_phys_init(SPINDLY_SIDE_CLIENT, SPINDLY_DEFAULT, NULL);
	fail_if(phys_client == NULL, "%s", "spindly_phys_init() failed");

	/* create a new stream on the physical connection */
	spint = spindly_stream_new(phys_client,
			0,
			0,
			&stream_clients[0],
			NULL,
			NULL,
			NULL);
	fail_if(spint != SPINDLYE_OK, "%s", "spindly_stream_new() failed");

	str_id = spindly_stream_get_stream_id(stream_clients[0]);
	fail_if(str_id == 0, "%s", "spindly_stream_get_stream_id() failed");

	str = spindly_stream_get_stream(phys_client, str_id);
	_spindly_print_test_result(Sanity, Pointer, (const void *) str, fun_name);

	// NULL phys handle
	str = spindly_stream_get_stream(NULL, str_id);
	_spindly_print_test_result(Error, Pointer, (const void *) str, fun_name);

	// Invalid stream id (0)
	str = spindly_stream_get_stream(phys_client, 0);
	_spindly_print_test_result(Error, Pointer, (const void *) str, fun_name);

	// Invalid stream id (Non existant)
	str = spindly_stream_get_stream(phys_client, 200);
	_spindly_print_test_result(Error, Pointer, (const void *) str, fun_name);

}

int main()
{
	_spindly_phys_init_test();
	_spindly_phys_incoming_test();
	_spindly_phys_demux_test();
	_spindly_free_demux_test();
	_spindly_phys_outgoing_test();
	_spindly_phys_sent_test();
	_spindly_phys_settings_test();
	_spindly_phys_ping_test();
	_spindly_phys_goaway_test();
	_spindly_phys_cleanup_test();
	_spindly_add_header_test();
	_spindly_stream_new_test();
	_spindly_stream_get_stream_id_test();
	_spindly_stream_ack_test();
	_spindly_stream_nack_test();
	_spindly_stream_data_test();
	_spindly_stream_get_stream_test();

	return 0;
}
