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
 * Copyright (C) 2012, Daniel Stenberg <daniel@haxx.se>
 *
 * This software is licensed as described in the file LICENSE, which you
 * should have received as part of this distribution. The terms are also
 * available at http://spindly.haxx.se/license.html
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
/*
 * Home of the spindly_phys_*() functions.
 */
#include "spdy_setup.h"         /* MUST be the first header to include */


#include "spdy_syn_stream.h"
#include "spdy_syn_reply.h"
#include "spdy_rst_stream.h"
#include "spdy_log.h"
#include "spdy_error.h"

#include "spindly.h"
#include "spindly_stream.h"
#include "spindly_phys.h"
#include "hash.h"


#include <string.h>
#include <stdlib.h>

#define MAXDATA (30*1024) //TODO, should find best logic, to send update

/*
 * Internal function for creating and setting up a new stream.
 */

/*#define HTTP_POST_TEST */ /*uncomment it to test HTTP POST request */
/*#define HTTP_PUT_TEST*/  /*uncomment it to test HTTP PUT request */

spindly_error_t _spindly_stream_init0(spdy_stream *stream,
                     bool store_received_data,
                     bool store_frames,
                     spdy_zlib_context *in, spdy_zlib_context *out)
{
	memset(stream, 0, sizeof(spdy_stream));

	stream->state = SPDY_STREAM_IDLE;

	stream->store_received_data = store_received_data;
	stream->store_frames = store_frames;

	/* The C standard doesn't guarantee that NULL == 0x00000000, so we have to
	* NULL the pointers explicitely.
	*/
	stream->data_received = NULL;
	stream->data_sent = NULL;
	stream->frames = NULL;

	stream->zlib_ctx_in = in;
	stream->zlib_ctx_out = out;

	return SPDY_ERROR_NONE;
}


/**
 * Creates a new stream which belongs to the given phys handle
 *
 * @param phys
 * @param flags
 * @param prio
 * @param stream
 * @param userp
 * @param config
 * @param streamid
 * @param headers
 * @return SPINDLYE_OK if stream is created, error code otherwise.
 */
spindly_error_t _spindly_stream_init(struct spindly_phys *phys,
                                     unsigned int flags,
                                     unsigned int prio,
                                     struct spindly_stream **stream,
                                     void *userp,
                                     struct spindly_stream_config *config,
                                     uint32_t streamid,
	                              struct spindly_headers *headers)
{
	struct spindly_stream *s;
	int rc;
	spdy_control_frame ctrl_frame = { 0 };
	int i;
	spdy_nv_block nv_block;
	int num_of_pairs = 0;
	struct spindly_header_pair* pairs = NULL;

	ASSERT_RET_VAL(phys != NULL, SPINDLYE_INVAL);

	if (prio > PRIO_MAX || !stream || flags > 0x1)
		return SPINDLYE_INVAL;

	memset(&nv_block, 0, sizeof(nv_block));
	if (headers) {
		num_of_pairs = headers->count;
		pairs = headers->pairs;
	}
	/* if there's a given streamid, this stream was created by the peer */
	bool madebypeer = streamid ? true : false;

	if (!madebypeer)
		streamid = phys->streamid;

	if (phys->num_streams >= phys->max_concurrent_streams) {
		SPDYDEBUG("wait --");
		return SPINDLYE_WAIT_FOR_UPDATE;
	}
	SPDYDEBUG("Phys: %p", phys);

	s = CALLOC(phys, sizeof(struct spindly_stream));
	if (!s)
		return SPINDLYE_NOMEM;

	s->prio = prio;
	s->phys = phys;
	s->state = STREAM_NEW;
	s->userp = userp;
	s->config = config;

	/* init the SPDY protocol handle for this stream */
	rc = _spindly_stream_init0(&s->spdy, false, false, &phys->zlib_in,
	                    &phys->zlib_out);
	if (rc)
		goto fail;

	if (!madebypeer) {
		/* only send a SYN_STREAM if this stream is not the result of a received
		   SYN_STREAM from the peer */
		struct spindly_outdata *od;

		/* make it a SYN_STREAM frame.

		   "If the server is initiating the stream, the Stream-ID must be even.
		   If the client is initiating the stream, the Stream-ID must be odd.

		   0 is not a valid Stream-ID."

		   NOTES:

		   - code currently makes all streams independent
		   - doesn't include any NV block yet
		   - bumps the physical connection's streamid at the bottom of this
		   function
		*/
		if (num_of_pairs > 0 && pairs != NULL) {
			nv_block.count = num_of_pairs;
			nv_block.pairs = NULL;
			nv_block.pairs_parsed = num_of_pairs;

			spdy_nv_pair_create( &(nv_block.pairs), nv_block.count);
			for (i = 0 ; i < nv_block.count; i++) {
				if (STRLEN(pairs[i].name) > 0) {
					nv_block.pairs[i].name = STRDUP(pairs[i].name);
				}
				nv_block.pairs[i].values_count = 1;
				if (STRLEN(pairs[i].value) > 0) {
					nv_block.pairs[i].values =  STRDUP(pairs[i].value);
				}
			}
		}
		rc = spdy_control_mk_syn_stream(&ctrl_frame, streamid , 0, flags, prio, &nv_block);
		/*
		rc = spdy_control_mk_ping(&ctrl_frame, 3);
		rc = spdy_control_mk_setting(&ctrl_frame);
		rc = spdy_control_mk_rst_stream(&ctrl_frame, 1, 11);
		rc = spdy_control_mk_goaway(&ctrl_frame, 1, 1);
		*/
		if (rc)
			goto fail;

		/* get an out buffer, TODO: what if drained? */
		od = _spindly_list_first(&phys->pendq);
		if (!od) {
			rc = SPINDLYE_NOMEM;
			ASSERT(0);
			goto fail;
		}

		/* remove the node from the pending list */
		_spindly_list_remove(&od->node);
		/* pack a control frame to the output buffer */
		rc = spdy_control_frame_pack(phys, &od->buffer, PHYS_OUTBUFSIZE,
		                             &od->len, &ctrl_frame);

		SPDYDEBUG("PACK Length = %d streamid %d\n\n\n", od->len, streamid);
		//for(i=0;i<4;i++)
			//SPDYDEBUG("[%d][%d][%d][%d]",
			//od->buffer[(i*4)+0], od->buffer[(i*4)+1],
			//od->buffer[(i*4)+2], od->buffer[(i*4)+3]);
		if (rc)
			goto fail;

		od->stream = s;

		/* add this handle to the outq */
		_spindly_list_add(&phys->outq, &od->node);
	}
	s->streamid = streamid;
	// Set FLAG_FIN if it is.
	s->spdy.fin_sent = (SPINDLY_DATA_FLAGS_FIN == flags) ? true : false;

	/* append this stream to the list of streams held by the phys handle */
	//_spindly_phys_add_stream(phys, s);

	/* store a lookup from the streamid to the stream struct */
	_spindly_hash_store(phys, &phys->streamhash, streamid, s);

	*stream = s;

	if (!madebypeer)
		phys->streamid+=2; /* bump counter last so that it isn't bumped in vain */

	rc = SPINDLYE_OK;

fail:

	/* the control frame was only ever held on the stack */
	spdy_control_frame_destroy(&ctrl_frame);
	spindly_destroy_header(headers);

	if(rc != SPINDLYE_OK)
		FREE(phys, s);

	return rc;
}

/**
 * Closes a stream pointed by s
 *
 * @param s: pointer to a stream to be closed.
 *
 * @return SPINDLYE_OK if stream is closed, error code otherwise.
 */
spindly_error_t spindly_stream_close(struct spindly_stream *s)
{

	struct spindly_outdata *od = NULL, *mover = NULL;
	spindly_error_t rc = SPINDLYE_OK;
	struct spindly_phys *phys = NULL;
	struct hashnode *n = NULL;
	struct spindly_stream *stream = NULL;

	phys = spindly_stream_getphys(s);
	if (!phys)
		return SPINDLYE_INVAL;
	SPDYDEBUG("@@@@ Stream close called for %p::#%d!", phys, s->streamid);

	SPDYDEBUG("$$$$ BEFORE: No. of Pending streams in phys:%p are %d!", phys, phys->num_streams);
	n = _spindly_list_first(&phys->streamhash.lhead);
	while (n) {
		stream = n->ptr;
		SPDYDEBUG("--> Stream-id %p::[%d], State(NEW, ACKED, CLOSED): %d!", phys, n->id, stream->state);
		n = _spindly_list_next(&n->node);
	}

	// Remove the node from Hash-list
	rc = _spindly_hash_remove(phys, &phys->streamhash, s->streamid);
	if (rc != SPINDLYE_OK) {
		SPDYDEBUG("Error: ERROR IN REMOVING NODE FROM HASH");
		return rc;
	}
	SPDYDEBUG("$$$$ AFTER: No. of Pending streams in phys:%p are %d!", phys, phys->num_streams);
	n = _spindly_list_first(&phys->streamhash.lhead);
	while (n) {
		stream = n->ptr;
		SPDYDEBUG("--> Stream-id %p::[%d], State(NEW, ACKED, CLOSED): %d!", phys, n->id, stream->state);
		n = _spindly_list_next(&n->node);
	}


	// Check are there any data related to the stream in OUTQ.
	od = _spindly_list_first(&phys->outq);
	if (!od) {
		SPDYDEBUG("OutQ is EMPTY!");
		return rc;
	}

	for (mover = od; mover != NULL; mover = _spindly_list_next(mover))
		if (mover->stream->streamid == s->streamid)
			break;

	if (!mover)	// If there is no data in OUTQ, return.
		return rc;

	// De-link from OUTQ, if there is.
	_spindly_list_remove(mover);
	SPDYDEBUG("@@@@ Deleted Stream %p::#%d from OUTQ!", phys, mover->stream->streamid);

	// Add the node back to PENDQ.
	_spindly_list_add(&phys->pendq, &mover->node);

end:
	return rc;
}

/* Portable, consistent toupper (remember EBCDIC). Do not use toupper() because
   its behavior is altered by the current locale. */
void spindly_raw_to_lower(char* str)
{
int i=0;
 while(str[i]!=NULL){
  switch (str[i]) {
  case 'A':
    str[i]= 'a';
    break;
  case 'B':
    str[i]= 'b';
    break;
  case 'C':
    str[i]= 'c';
    break;
  case 'D':
    str[i]= 'd';
    break;
  case 'E':
    str[i]= 'e';
    break;
  case 'F':
    str[i]= 'f';
    break;
  case 'G':
    str[i]= 'g';
    break;
  case 'H':
    str[i]= 'h';
    break;
  case 'I':
    str[i]= 'i';
    break;
  case 'J':
    str[i]= 'j';
    break;
  case 'K':
    str[i]= 'k';
    break;
  case 'L':
    str[i]= 'l';
    break;
  case 'M':
    str[i]= 'm';
    break;
  case 'N':
    str[i]= 'n';
    break;
  case 'O':
    str[i]= 'o';
    break;
  case 'P':
    str[i]= 'p';
    break;
  case 'Q':
    str[i]= 'q';
    break;
  case 'R':
    str[i]= 'r';
    break;
  case 'S':
    str[i]= 's';
    break;
  case 'T':
    str[i]= 't';
    break;
  case 'U':
    str[i]= 'u';
    break;
  case 'V':
    str[i]= 'v';
    break;
  case 'W':
    str[i]= 'w';
    break;
  case 'X':
    str[i]= 'x';
    break;
  case 'Y':
    str[i]= 'y';
    break;
  case 'Z':
    str[i]= 'z';
    break;
  }
  i++;
}
  return;
}

spindly_error_t spindly_add_header(struct spindly_headers *header,
					const char* name,
					const char* value)
{
	header->pairs = realloc(header->pairs,
					sizeof(struct spindly_header_pair) * (header->count + 1));
	struct spindly_header_pair* pair = &header->pairs[header->count];
	//Remove unsupported packets hear
	if(!strcasecmp(name, "Transfer-Encoding") && !strcasecmp(value, "chunked"))
		return SPINDLYE_OK;

	if(!strcasecmp(name, "expect") && !strcasecmp(value, "100-continue"))
		return SPINDLYE_OK;

	if(!strcasecmp(name, "Connection"))
		return SPINDLYE_OK;

	if(!strcasecmp(name, "keep-alive"))
		return SPINDLYE_OK;

	pair->name = malloc(STRLEN(name) + 1);
	if (!pair->name)
		return SPINDLYE_NOMEM;
	STRCPY(pair->name, name);
	spindly_raw_to_lower(pair->name);
	pair->value = malloc(STRLEN(value) + 1);
	if (!pair->value)
		return SPINDLYE_NOMEM;
	STRCPY(pair->value, value);
	header->count++;
	return SPINDLYE_OK;

}


void spindly_destroy_header(struct spindly_headers *header)
{
	int i =0;

	if(header ==NULL)
		return;
	if(header->pairs) {
		for (i = 0; i < header->count; i++) {
			FREEIF(header->pairs[i].name);
			FREEIF(header->pairs[i].value);
		}
		FREEIF(header->pairs);
	}
	header->count = 0;
	header->pairs = NULL;
	return;

}

spindly_error_t spindly_mk_header(struct spindly_headers *header,
					spdy_nv_block* nv_block)
{
	int i=0, j =0;
	int nvpairsSize = 0;
	spdy_nv_pair *nvpairs;     /*!< Array of Name/Value pairs */
	struct spindly_header_pair *spairs;
	spindly_error_t ret = SPINDLYE_OK;

	for (i = 0; i < nv_block->count; i++) {
		nvpairsSize += nv_block->pairs[i].values_count;
	}
	header->pairs = calloc(nvpairsSize, sizeof(struct spindly_header_pair));
	if (header->pairs) {
		nvpairs = nv_block->pairs;
		spairs = header->pairs;

		for (i = 0, j = 0; i < nv_block->count; i++, j++) {
			int count = nvpairs[i].values_count;
			char* temp_values = nvpairs[i].values;
			while(count) {
				if (STRLEN(nvpairs[i].name) > 0) {
					spairs[j].name = STRDUP(nvpairs[i].name);
				}

				if (STRLEN(temp_values) > 0) {
					spairs[j].value =  STRDUP(temp_values);
				}
				count--;
				if(count > 0)
				{
					temp_values += STRLEN(temp_values)+1;
					j++;
				}
			}

		}
		header->count = nvpairsSize;
	} else
		ret = SPINDLYE_NOMEM;

	return ret;

}

unsigned int spindly_stream_get_stream_id(struct spindly_stream *stream)
{
	//TODO should implement common api to get details of stream
	if(stream) {
		return stream->streamid;
	}
	else {
		return 0;//0 is not a valid Stream-ID
	}
}
/*
 * Creates a request for a new stream and muxes the request into the output
 * connection, creates a STREAM handle for the new stream and returns the
 * RESULT. The CUSTOMP pointer will be associated with the STREAM to allow the
 * application to identify it.
 *
 */

spindly_error_t spindly_stream_new(struct spindly_phys *phys,
                                   unsigned int flags,
                                   unsigned int prio,
                                   struct spindly_stream **stream,
                                   void *userp,
                                   struct spindly_stream_config *config,
                                   struct spindly_headers *headers)
{
	return _spindly_stream_init(phys, flags, prio, stream, userp,
								config, 0, headers);
}

/*
 * Send data on this stream.
 */
spindly_error_t spindly_stream_data(struct spindly_stream *s,
                                    unsigned int flags,
                                    unsigned char *data,
                                    size_t len, void *handled)
{
	spindly_error_t rc = SPINDLYE_OK;
	spdy_data_frame data_frame;
	struct spindly_outdata *od;
	int i = 0;

	ASSERT_RET_VAL(s != NULL, SPINDLYE_INVAL);

	if (flags > 0x1 || !data || !len)
		return SPINDLYE_INVAL;

	if (s->state != STREAM_NEW)
		/* only allow this function on a brand new stream, but it must also have
		been received from the peer. TODO: check that it came from the peer */
		return SPINDLYE_INVAL;

	SPDYDEBUG("window send len before %d", s->spdy.wndw_sent_length);
	if(s->phys->max_window_size < s->spdy.wndw_sent_length+len)
		return SPINDLYE_WAIT_FOR_UPDATE;

	/* queue up a data message */
	rc = spdy_mk_data_stream(&data_frame, s->streamid, flags, data, len);

	s->spdy.wndw_sent_length += len;
	SPDYDEBUG("window send len %d", s->spdy.wndw_sent_length);
	if (rc)
		goto fail;

	/* get an out buffer TODO: what if drained? */
	od = _spindly_list_first(&s->phys->pendq);
	if (!od) {
		ASSERT(0);
		goto fail;
	}

	/* remove the node from the pending list */
	_spindly_list_remove(&od->node);

	/* pack a data frame to the output buffer */
	rc = spdy_data_frame_pack_header(&od->buffer,
	                             &od->len, &data_frame);
	if (rc)
		goto fail;

	SPDYDEBUG("data Length = %d\n", od->len);
	//for(i=0;i<2;i++)
		//SPDYDEBUG("[%d][%d][%d][%d]",
		//od->buffer[(i*4)+0], od->buffer[(i*4)+1],
		//od->buffer[(i*4)+2], od->buffer[(i*4)+3]);

	od->stream = s;
	// Set FLAG_FIN if it is.
	s->spdy.fin_sent = (SPINDLY_DATA_FLAGS_FIN == flags) ? true : false;

	/* add this handle to the outq */
	_spindly_list_add(&s->phys->outq, &od->node);

fail:
	spdy_data_frame_destroy(&data_frame);
	return rc;
}

/*
 * Send headers on this stream.
 */
spindly_error_t spindly_stream_headers(struct spindly_stream *s,
                                       unsigned int flags,
                                       struct spindly_headers *headers,
                                       void *handled)
{
	spindly_error_t rc = SPINDLYE_OK;
	spdy_control_frame ctrl_frame;
	struct spindly_outdata *od;
	spdy_nv_block nv_block;
	int num_of_pairs = 0;
	struct spindly_header_pair* pairs = NULL;
	int i = 0;

	memset(&nv_block, 0, sizeof(nv_block));
	if(headers) {
		num_of_pairs = headers->count;
		pairs = headers->pairs;
	}

	ASSERT_RET_VAL(s != NULL, SPINDLYE_INVAL);

	if (s->state != STREAM_NEW)
		/* only allow this function on a brand new stream, but it must also have
		been received from the peer. TODO: check that it came from the peer */
		return SPINDLYE_INVAL;

	if (num_of_pairs > 0 && pairs != NULL) {
		nv_block.count = num_of_pairs;
		nv_block.pairs = NULL;
		nv_block.pairs_parsed = 0;

		spdy_nv_pair_create( &(nv_block.pairs), nv_block.count);
		for (i = 0 ; i < nv_block.count; i++) {
			if (STRLEN(pairs[i].name) > 0) {
				nv_block.pairs[i].name = STRDUP(pairs[i].name);
				SPDYDEBUG("pairs[%d].name = %s \n",i, pairs[i].name);
			}
			nv_block.pairs[i].values_count = 1;
			if (STRLEN(pairs[i].value) > 0) {
				nv_block.pairs[i].values =  STRDUP(pairs[i].value);
				SPDYDEBUG("pairs[%d].value = %s \n", i, pairs[i].value);
			}
		}
	}

	/* queue up a SYN_REPLY or RST_STREAM message */
	rc = spdy_control_mk_header(&ctrl_frame, s->streamid, flags, &nv_block);

	if (rc)
		goto fail;

	/* get an out buffer TODO: what if drained? */
	od = _spindly_list_first(&s->phys->pendq);
	if (!od) {
		ASSERT(0);
		goto fail;
	}

	/* remove the node from the pending list */
	_spindly_list_remove(&od->node);

	/* pack a control frame to the output buffer */
	rc = spdy_control_frame_pack(s->phys, &od->buffer, PHYS_OUTBUFSIZE,
	   &od->len, &ctrl_frame);
	if (rc)
		goto fail;

	SPDYDEBUG("header Length = %d\n\n\n", od->len);
	//for(i=0;i<od->len;i++)
	//	printf("[%d]", od->buffer[i]);

	od->stream = s;

	/* add this handle to the outq */
	_spindly_list_add(&s->phys->outq, &od->node);

fail:
	return rc;
}

/*
 * Send nack or ack on a stream that was received from the peer.
 */
static spindly_error_t stream_acknack(struct spindly_stream *s,
		bool ack,
		uint32_t status)
{
	spindly_error_t rc = SPINDLYE_OK;
	spdy_control_frame ctrl_frame;
	struct spindly_outdata *od;

	ASSERT_RET_VAL(s != NULL, SPINDLYE_INVAL);


	/*	If stream is closed or
		if it is a SYNC_REPLY stream,
		then stream state must be NEW.
	*/
	if (s->state == STREAM_CLOSED ||
		ack && s->state != STREAM_NEW) {
		/* only allow this function on a brand new stream, but it must also have
		   been received from the peer. TODO: check that it came from the peer */
		rc = SPINDLYE_INVAL;
		goto fail;
	}

	SPDYDEBUG("Phys::Stream => %p::%d", spindly_stream_getphys(s), s->streamid);
	/* queue up a SYN_REPLY or RST_STREAM message */
	if (ack)
		rc = spdy_control_mk_syn_reply(&ctrl_frame, s->streamid, NULL);
	else
		rc = spdy_control_mk_rst_stream(&ctrl_frame, s->streamid, status);

	if (rc)
		goto fail;

	/* get an out buffer TODO: what if drained? */
	od = _spindly_list_first(&s->phys->pendq);
	if (!od) {
		ASSERT(0);
		goto fail;
	}

	/* remove the node from the pending list */
	_spindly_list_remove(&od->node);

	/* pack a control frame to the output buffer */
	rc = spdy_control_frame_pack(s->phys, &od->buffer, PHYS_OUTBUFSIZE,
	   &od->len, &ctrl_frame);
	if (rc)
		goto fail;

	od->stream = s;

	/* add this handle to the outq */
	_spindly_list_add(&s->phys->outq, &od->node);

	/* set the state of the stream after this function */
	s->state = ack ? STREAM_ACKED : STREAM_CLOSED;

fail:
	return rc;
}

spindly_error_t spindly_stream_wndupdate(struct spindly_stream *s,
	int size)
{
	spindly_error_t rc = SPINDLYE_OK;
	spdy_control_frame ctrl_frame;
	struct spindly_outdata *od;

	ASSERT_RET_VAL(s != NULL, SPINDLYE_INVAL);

	if (size == -1) {
		if (s->phys->data.needed == 0) {
			//size= s->phys->frame.frame.data.length;
			/* send window update */
			if (s->spdy.wndw_received_length > MAXDATA) {
				SPDYDEBUG("data crossed should send window update = %d",
					s->spdy.wndw_received_length);
					size = s->spdy.wndw_received_length;
			} else {
				return SPINDLYE_STOP;
			}
		} else {
			return SPINDLYE_INVAL;
		}
	}
	SPDYDEBUG("----------> stream id=%d", s->streamid);
	SPDYDEBUG("----------> fin flag=%d",s->spdy.fin_received);
	if( s->spdy.fin_received)
		return SPINDLYE_STOP;
	rc = spdy_control_mk_wndup(&ctrl_frame, s->streamid, size);

	if (rc)
		goto fail;

	/* get an out buffer TODO: what if drained? */
	od = _spindly_list_first(&s->phys->pendq);
	if (!od) {
		ASSERT(0);
		goto fail;
	}

	/* remove the node from the pending list */
	_spindly_list_remove(&od->node);

	/* pack a control frame to the output buffer */
	rc = spdy_control_frame_pack(s->phys, &od->buffer, PHYS_OUTBUFSIZE,
	   &od->len, &ctrl_frame);
	if (rc)
		goto fail;
	//TODO, should set to 0, when send is success. after interface provided
	s->spdy.wndw_received_length = 0;
	od->stream = s;

	/* add this handle to the outq */
	_spindly_list_add(&s->phys->outq, &od->node);
	SPDYDEBUG("sending window update");


fail:
	return rc;
}
/*
 * The STREAM as requested to get opened by the remote is allowed! This
 * function is only used as a response to a SPINDLY_DX_STREAM_REQ.
 */
spindly_error_t spindly_stream_ack(struct spindly_stream *s)
{
	return stream_acknack(s, true, 0);
}

/*
 * The STREAM as requested to get opened by the remote is NOT allowed! This
 * function is only used as a response to a SPINDLY_DX_STREAM_REQ.
 */
spindly_error_t spindly_stream_nack(struct spindly_stream *s, uint32_t status)
{
	return stream_acknack(s, false, status);
}


struct spindly_stream *spindly_stream_get_stream(struct spindly_phys *phys,int streamid)
{
	struct hashnode *n;
	if (!phys || !streamid)
		return NULL;

	n = _spindly_hash_get(&phys->streamhash, streamid);
	if (!n) {
       return NULL;
	} else {
	  return  n->ptr;
	}

}

/**
 * Get Phys handle associated with the given stream
 *
 * @param stream: pointer to stream
 * @return pointer to phys handle
 */
struct spindly_phys *spindly_stream_getphys(struct spindly_stream *stream)
{
	if (stream)
		return stream->phys;
	return NULL;
}
