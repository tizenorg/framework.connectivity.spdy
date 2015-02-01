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
	Shakthi Prashanth <sh.prashanth@samsung.com>
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

#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include "spindly.h"
#include "spindly_phys.h"
#include "spindly_stream.h"
#include "spdy_error.h"
#include "spdy_log.h"


static spindly_error_t remove_inqnode(struct spindly_phys *phys,
                                      struct spindly_indata *chunk);

/*
 * Create a handle for a single duplex physical connection, SIDE is either
 * client or server - what side the handle is made to handle. PROTVER is the
 * specific SPDY protocol version.
 *
 * TODO: provide a means to replace the memory functions
 */
struct spindly_phys *spindly_phys_init(spindly_side_t side,
                                       spindly_spdyver_t protver,
                                       struct spindly_phys_config *config)
{
	struct spindly_phys *phys;
	int rc;
	struct spindly_outdata *od;

	if (side < SPINDLY_SIDE_CLIENT || side > SPINDLY_SIDE_SERVER ||
		protver < SPINDLY_SPDYVER2 || protver > SPINDLY_DEFAULT)
		return NULL;


	/* this is the first malloc, it should use the malloc function provided in
	 the config struct if set, but probably cannot use the MALLOC macro */
	phys = calloc(1, sizeof(struct spindly_phys));
	if (!phys)
		goto fail;
	phys->config = config;
	phys->side = side;
	phys->protver = protver;
	phys->num_streams = 0;
	phys->streamid = side == SPINDLY_SIDE_CLIENT?1:2;
	phys->pingid = side == SPINDLY_SIDE_CLIENT?1:2;
	phys->outgoing = NULL;
	phys->outgoing_tosend = 0;
	phys->max_concurrent_streams = SPDY_DEFAULT_CONCURRENT_STREAMS;
	phys->max_window_size = MIN_WINDOW_SIZE;

	/* create zlib contexts for incoming and outgoing data */
	rc = spdy_zlib_inflate_init(&phys->zlib_in);
	if (rc)
		goto fail;

	rc = spdy_zlib_deflate_init(&phys->zlib_out);
	if (rc)
		goto fail;

	_spindly_list_init(&phys->outq);
	_spindly_list_init(&phys->inq);
	_spindly_list_init(&phys->pendq);

	/* now add all outdata nodes to the pending queue */
	for (rc = 0; rc < PHYS_NUM_OUTDATA; rc++) {
		od = CALLOC(phys, sizeof(struct spindly_outdata));
		if (!od)
			goto fail;
		_spindly_list_add(&phys->pendq, &od->node);
	}

	/* init receiver variables  */
	spdy_frame_init(&phys->frame);
	spdy_data_use(&phys->data, NULL, 0);

	/* for stream-ID to stream struct lookups */
	_spindly_hash_init(&phys->streamhash, phys);

	SPDYDEBUG("phys: %p", phys);

	return phys;

fail:
	spdy_zlib_inflate_end(&phys->zlib_in);
	spdy_zlib_deflate_end(&phys->zlib_out);

	/* TODO: clean up the pendq list */

	if (phys)
		free(phys);

	return NULL;
}

spindly_error_t _spindly_phys_add_stream(struct spindly_phys *phys,
                                         struct spindly_stream *s)
{
	//_spindly_list_add(&phys->streams, &s->node);
	//phys->num_streams++;
	return SPINDLYE_OK;
}

/*
 * Returns info (pointer and length) with data that PHYS holds that is
 * available to send over the transport medium immediately.
 */
spindly_error_t spindly_phys_outgoing(struct spindly_phys *phys,
                                      unsigned char **data,
                                      size_t *len)
{
	struct spindly_outdata *od;

	ASSERT_RET_VAL(phys != NULL, SPINDLYE_INVAL);

	if (phys->outgoing)
		/* data returned previously has not yet been reported to have been sent
		   off */
		return SPINDLYE_INVAL;

	od = _spindly_list_first(&phys->outq);
	if (od) {
		*data = od->buffer;
		*len = od->len;

		SPDYDEBUG("out Length = %d\n", *len);
		SPDYDEBUG("[%d][%d][%d][%d][%d][%d][%d][%d][%d][%d][%d][%d]",
			od->buffer[0], od->buffer[1], od->buffer[2], od->buffer[3],
			od->buffer[4], od->buffer[5], od->buffer[5], od->buffer[7],
			od->buffer[8], od->buffer[9], od->buffer[10], od->buffer[11]);
		/* remove this node from the outgoing queue */
		_spindly_list_remove(&od->node);

		phys->outgoing = od;
		phys->outgoing_tosend = *len; /* send this to be done */
	} else {
		*data = NULL;
		*len = 0;
	}

	return SPINDLYE_OK;
}

/*
 * when the application has read data off the transport, this function is
 * called to tell Spindly about more data that has arrived. As spindly doesn't
 * read any network data by itself, it needs to get the data passed into it by
 * the application.
 *
 * After data has been fed into the handle, call spindly_phys_demux() to make
 * it demux the incoming data.
 *
 */

spindly_error_t spindly_phys_incoming(struct spindly_phys *phys,
                                      unsigned char *data, size_t datalen,
                                      int flags,
                                      void *identifier)
{
	int i = 0;
	struct spindly_indata *in = NULL;


	if (!phys || !data || !datalen)
		return SPINDLYE_INVAL;

	in = MALLOC(phys, sizeof(*in));
	if (!in)
		return SPINDLYE_NOMEM;

	SPDYDEBUG("IN Length = %d\n", datalen);
	SPDYDEBUG("[%d][%d][%d][%d][%d][%d][%d][%d][%d][%d][%d][%d]"
	"[%d][%d][%d][%d]", data[0], data[1],data[2], data[3], data[4],
	data[5], data[6], data[7], data[8], data[9],data[10], data[11],
	data[12], data[13], data[14], data[15], data[16]);

	in->identifier = identifier;
	if (flags & SPINDLY_INCOMING_COPY) {
		in->copied = true;
		in->data = MALLOC(phys, datalen);
		if (!in->data) {
			FREE(phys, in);
			return SPINDLYE_NOMEM;
		}
		memcpy(in->data, data, datalen);
		in->datalen = datalen;
	} else {
		in->copied = false;
		in->datalen = datalen;
		in->data = data;
	}

	phys->inq_size += datalen;

	/* add this to the phys' incoming queue */
	_spindly_list_add(&phys->inq, &in->node);
	SPDYDEBUG("phys: %p\n", phys);

	return SPINDLYE_OK;
}

/*
 * 'more' will be set to true/false if there was more data added
 */

static int parse_append(struct spindly_phys *phys, bool *more)
{
	/* the existing data is too small, merge it with the next in the malloc'ed
	buffer */
	struct list_node *n = _spindly_list_first(&phys->inq);
	if (n == NULL) {
		*more=false;
		return SPINDLYE_OK;
	}

	spdy_data *data = &phys->data;
	size_t needed;
	size_t copylen;
	copylen = data->data_end - data->cursor;

	struct list_node *next = _spindly_list_next(n);
	needed=data->needed;
	SPDYDEBUG("parse len=%d, copylen=%d, needed=%d",phys->parselen, copylen, needed);
	//LOADER team
	//begin ISSUE2(WEB-7386): boundary case, when data->cursor reaches data->end, there is no more data to copy from current node of phys->InQueue
	//and next node is also NULL, remove current node and skip parse_append
	if(copylen == 0 && next == NULL) {
		*more=false;
		remove_inqnode(phys, (struct spindly_indata *)n);
		SPDYDEBUG("Skip parse append: copylen is %d needed=%d but there is No next phys->inq", copylen, needed);
		return SPINDLYE_OK;
	}
	//end
	if (!phys->parselen)
		phys->parselen = needed+copylen;
	if (phys->parsealloc < needed+copylen) {
		//LOADER team
		//begin ISSUE1(WEB-7429): memory(buffer) corruption due to realloc
		phys->parse = NULL;
		//end
		char *newp = realloc(phys->parse, needed+copylen);
		if (!newp)
			return SPINDLYE_NOMEM;
		phys->parsealloc = needed+copylen;
		phys->parse=newp;
		memmove(phys->parse, data->cursor, copylen);
//		phys->parselen = copylen;
	}
	int copied=copylen;
	int remained=0;
	n=next;
	while (needed>0 && n) {
		struct spindly_indata *in= (struct spindly_indata *)n;
		if(needed >= in->datalen) {
			memcpy(&phys->parse[copylen], in->data, in->datalen);
			needed-=in->datalen;
			copied+=in->datalen;
			//LOADER team
			//begin ISSUE1(WEB-7429): if loop is executed again and if we dont update copylen, it overwrites the existing buffer
			copylen = copied;
			//end
			struct list_node *next = _spindly_list_next(n);
			remove_inqnode(phys, (struct spindly_indata *)n);
			n=next;
		} else {
			phys->parse=realloc(phys->parse, in->datalen+copylen);
			memcpy(&phys->parse[copylen], in->data, in->datalen);
			copied+=in->datalen;
			//remained+=in->datalen-needed;
			needed=0;
			phys->parselen = copied;
			remove_inqnode(phys, (struct spindly_indata *)n);
		}
	}
	spdy_data_use(&phys->data, phys->parse, copied+remained);
	*more=false;
	SPDYDEBUG("parse len=%d, copied=%d",phys->parselen,copied);
	if (phys->parselen == copied) {
		*more=true;
		SPDYDEBUG("************Complete frame received[size=%d] ***************",copied);
		phys->parselen = 0;
	    phys->parsealloc =0 ;
	}

	return SPINDLYE_OK;
}

/* TODO: if the complete inq node was consumed::
   1 - call the callback.
   2 - possibly free the ->data
   3 - remove the node from the list
*/
static spindly_error_t remove_inqnode(struct spindly_phys *phys,
                                      struct spindly_indata *chunk)
{
	/* call the completetion callback? */
	(void)phys;

	/* free the data if it was previously copied into the node */
	if (chunk->copied)
		FREE(phys, chunk->data);

	/* remove the node from the linked list */
	_spindly_list_remove(&chunk->node);
	FREE(phys, chunk);

	return SPINDLYE_OK;
}

spindly_error_t spindly_free_demux(struct spindly_phys *phys,
                                   struct spindly_demux *ptr)
{
	if(ptr == NULL || phys == NULL) {
		return SPINDLYE_INVAL;
	}
	switch(ptr->type) {
		case SPINDLY_DX_STREAM_ACK:
			spindly_destroy_header(&ptr->msg.stream_ack.headers);
			break;
		case SPINDLY_DX_DATA:
			if (ptr->msg.data.datap) {
				free(ptr->msg.data.datap);
				ptr->msg.data.datap = NULL;
			}
			break;
		case SPINDLY_DX_SETTINGS:
			if(ptr->msg.settings.pairs) {
				free(ptr->msg.settings.pairs);
				ptr->msg.settings.pairs = NULL;
			}
		default: //TODO should implement for others
			break;
	}
	return SPINDLYE_OK;
}

/*
 * Returns information about incoming data, split up for consumption.
 * Subsequent calls will return the next result and so on until there's
 * nothing left to demux - until spindly_phys_incoming() is called again to
 * feed it with more data.
 *
 * When this function returns that there is no more message, it may still hold
 * trailing data that forms the beginning of the subsequent message.
 *
 * 'ptr' must point to the correct struct, read the first 'type' field of that
 * to know how to interpret the rest!
 */
spindly_error_t spindly_phys_demux(struct spindly_phys *phys,
                                   struct spindly_demux *ptr)
{
	struct list_node *n = NULL;
	struct spindly_indata *in = NULL;
	int rc = SPINDLYE_OK;
	bool fin_sent_by_us = false;
	bool fin_sent_by_sender = false;
	bool is_unidirectional = false;
	bool is_fin_rcvd = false;

	ASSERT_RET_VAL(ptr != NULL, SPINDLYE_INVAL);
	ASSERT_RET_VAL(phys != NULL, SPINDLYE_INVAL);

	memset(ptr, 0, sizeof(struct spindly_demux));
	n = _spindly_list_first(&phys->inq);
	in = (struct spindly_indata *) n;

	if (!in)
		/* there's no more right now */
		return SPINDLYE_OK;

	do {

		if ((phys->data.data_end <= phys->data.cursor) ||
				((phys->data.error != SPDY_ERROR_NONE) &&
				(phys->data.error != SPDY_ERROR_INSUFFICIENT_DATA))) {
			/* if the previously stored data is all consumed and if there is error in parsing
			then get the current queue data */
			//Loader Team
			//begin Issue2(WEB-7386): For case data left 8, data->cursor = data->end and it parsed control frame or data frame header successfully, because of only 8 bytes left
			//and it returned INSUFFICIENT_DATA, For next incoming data, here it is forced to _header_parsed to 0, we should retain status of _header_parsed if error is INSUFFICIENT.
			SPDYDEBUG("Frame type  %s error %d\n",
					spdy_control_frame_get_type_name(phys->frame.frame.control.type), phys->data.error);
			if(phys->data.error != SPDY_ERROR_INSUFFICIENT_DATA)
				phys->frame._header_parsed =0;
			spdy_data_use(&phys->data, in->data, in->datalen);
			//end
		}

		/*
		 * Parse data. The parsing function wants a full frame to be in a
		 * contiguous buffer so unless it is, we must create a full frame from the
		 * input we have.
		 */
		rc = spdy_frame_parse(&phys->frame, phys, &phys->data);

		if ((phys->data.cursor == phys->data.data_end) &&
			(rc != SPDY_ERROR_INSUFFICIENT_DATA))
			/* the complete inq node was consumed */
			remove_inqnode(phys, in);

		if (rc == SPDY_ERROR_NONE) {
			struct spindly_stream *stream = NULL;
			struct hashnode *n = NULL;
			if (phys->frame.type == SPDY_CONTROL_FRAME) {
				spdy_syn_stream *syn = NULL;
				spdy_syn_reply *rep = NULL;
				spdy_headers *header = NULL;
				spdy_wndup *wnd = NULL;
				spdy_rst_stream *rst = NULL;
				spdy_iv_block	 *iv_block = NULL;
				int i;

				SPDYDEBUG("Frame type  %s \n",
						spdy_control_frame_get_type_name(
							phys->frame.frame.control.type));
				switch(phys->frame.frame.control.type) {
				case SPDY_CTRL_SYN_STREAM:
					/*
					 * At this point there's a syn_stream struct that needs to be
					 * converted to a full spinly_stream struct!
					 *
					 * phys->frame.frame.control.obj.syn_stream
					 */
					syn = &phys->frame.frame.control.obj.syn_stream;
					phys->received_streamid = syn->stream_id;
					ptr->type = SPINDLY_DX_STREAM_REQ;
					ptr->msg.stream.streamid = syn->stream_id;
					ptr->msg.stream.associated_to = syn->associated_to;
					ptr->msg.stream.priority = syn->priority;
					ptr->msg.stream.slot = syn->slot;
					ptr->msg.stream.flags = phys->frame.frame.control.flags;

					is_unidirectional = syn->associated_to ? true : false;
					if (SPINDLY_DATA_FLAGS_FIN == phys->frame.frame.control.flags)
						is_fin_rcvd = true;
					else
						is_fin_rcvd = false;

					// create the stream if its NOT uni-directional and FLAG_FIN is NOT received.
					if (!is_unidirectional || !is_fin_rcvd) {
						rc = _spindly_stream_init(phys,
								phys->frame.frame.control.flags, // FLAG_FIN
								syn->priority,
								&stream,
								NULL,
								NULL,
								syn->stream_id,
								NULL);
						if (!rc) {
							/* update stream info */
							stream->spdy.unidirectional = is_unidirectional;
							stream->spdy.fin_received = is_fin_rcvd;

							ptr->msg.stream.stream = stream;
							spindly_mk_header(&ptr->msg.stream.headers, &syn->nv_block);
						} else {
							/* TODO: how do we deal with a failure here? */
						}
					}
					break;
				case SPDY_CTRL_SYN_REPLY:
					/*
					 * At this point there's a syn_reply struct that needs to be
					 * converted to a full spinly_stream struct!
					 *
					 * phys->frame.frame.control.obj.syn_reply
					 */
					rep = &phys->frame.frame.control.obj.syn_reply;
					ptr->type = SPINDLY_DX_STREAM_ACK;
					ptr->msg.stream_ack.streamid = rep->stream_id;
					ptr->msg.stream_ack.flags = phys->frame.frame.control.flags;

					n = _spindly_hash_get(&phys->streamhash, rep->stream_id);
					if (!n) {
						/* received a SYN_REPLY for an unknown streamid or alread closed*/
						rc = SPINDLYE_INVALID_STREAM;
						SPDYDEBUG("**** OOPS! Stream %p::#%d is INVALID!", phys, rep->stream_id);
						break;
					} else {
						stream = n->ptr;
						if (stream->state == STREAM_CLOSED) {
							rc = SPINDLYE_STREAM_ALREADY_CLOSED;
							SPDYDEBUG("#### Ahh! Stream %p::#%d is Already closed!",
									phys, rep->stream_id);
							break;
						}
						fin_sent_by_us = stream->spdy.fin_sent;
						fin_sent_by_sender = ptr->msg.stream.flags;

						if(!fin_sent_by_us || stream->state == STREAM_ACKED) {
							/* received a SYN_REPLY for stream which was not send fin
							   or SYN_REPLY already recieviced */
							rc = SPINDLYE_STREAM_IN_USE;
							break;
						}
						stream->state = STREAM_ACKED;
						ptr->msg.stream_ack.stream = stream;
						spindly_mk_header(&ptr->msg.stream_ack.headers, &rep->nv_block);

						/* If SYN_REPLY has FLAG_FIN set and
						   we have stream half-closed from our end,
						   then set the stream as CLOSED state..
						 */
						if (fin_sent_by_sender) {
							stream->spdy.fin_received = true;
							// Set the stream state as CLOSED.
							stream->state = STREAM_CLOSED;
							SPDYDEBUG("Stream #%d is now in CLOSED state. # of open streams [%d]",
									stream->streamid, phys->num_streams);
						}
					}
					break;
				case SPDY_CTRL_RST_STREAM:
					rst = &phys->frame.frame.control.obj.rst_stream;
					ptr->type = SPINDLY_DX_RST_STREAM;
					ptr->msg.rst_stream.stream_id = rst->stream_id;
					ptr->msg.rst_stream.status_code = rst->status_code;

					n = _spindly_hash_get(&phys->streamhash, rst->stream_id);
					if (!n) {
						/* received a SYN_REPLY for an unknown streamid */
						rc = SPINDLYE_INVAL;
						SPDYDEBUG("Error: OOPS!! Stream doesn't exist!");
						break;
					} else {
						stream = n->ptr;
						stream->spdy.rst_received = true;
						if (stream->state == STREAM_CLOSED) {
							rc = SPINDLYE_STREAM_ALREADY_CLOSED;
							SPDYDEBUG("#### Ahh! Stream %p::#%d is Already closed!",
									phys, rst->stream_id);
							break;
						}
						// Set the stream state as CLOSED.
						stream->state = STREAM_CLOSED;
						SPDYDEBUG("Stream #%d is now in CLOSED state. # of open streams [%d]",
								stream->streamid, phys->num_streams);
					}
					break;
				case SPDY_CTRL_SETTINGS:
					iv_block = &phys->frame.frame.control.obj.setting.iv_block;
					ptr->type = SPINDLY_DX_SETTINGS;
					ptr->msg.settings.has_count = iv_block->has_count;
					ptr->msg.settings.count = iv_block->count;
					ptr->msg.settings.pairs_parsed = iv_block->pairs_parsed;
					ptr->msg.settings.pairs = calloc(iv_block->count, sizeof(spdy_iv_pair));
					if(ptr->msg.settings.pairs == NULL) {
						rc = SPINDLYE_NOMEM;
						break;
					}

					int old_max_window_size = 0;
					int diff = 0;
					for (i = 0; i < iv_block->count; i++) {
						ptr->msg.settings.pairs[i].id = iv_block->pairs[i].id;
						ptr->msg.settings.pairs[i].value = iv_block->pairs[i].value;
						if(iv_block->pairs[i].id == SETTINGS_INITIAL_WINDOW_SIZE ) {
							SPDYDEBUG("before INITIAL_WINDOW_SIZE!%d", phys->max_window_size);
							phys->max_window_size = iv_block->pairs[i].value;
							SPDYDEBUG("INITIAL_WINDOW_SIZE!%d", phys->max_window_size);
						}
						else if(iv_block->pairs[i].id == SETTINGS_MAX_CONCURRENT_STREAMS ) {
							SPDYDEBUG("before MAX_CONCURRENT_STREAMS!%d", phys->max_concurrent_streams);
							phys->max_concurrent_streams = iv_block->pairs[i].value;
							SPDYDEBUG("MAX_CONCURRENT_STREAMS!%d", phys->max_concurrent_streams);
						}
					}
					break;
				case SPDY_CTRL_NOOP:
					ptr->type = SPINDLY_DX_NOOP;
					break;
				case SPDY_CTRL_PING:
					ptr->type = SPINDLY_DX_PING;
					ptr->msg.ping.stream_id =
						phys->frame.frame.control.obj.ping.id;
					break;
				case SPDY_CTRL_GOAWAY:
					ptr->type = SPINDLY_DX_GOAWAY;
					ptr->msg.goaway.stream_id =
						phys->frame.frame.control.obj.goaway.stream_id;
					ptr->msg.goaway.status_code =
						phys->frame.frame.control.obj.goaway.status_code;
					break;
				case SPDY_CTRL_HEADERS:
					header = &phys->frame.frame.control.obj.headers;
					ptr->type = SPINDLY_DX_HEADERS;
					ptr->msg.headers.streamid = header->stream_id;

					n = _spindly_hash_get(&phys->streamhash, header->stream_id);
					if (!n) {
						/* received a HEADERS for an unknown streamid or alread closed*/
						rc = SPINDLYE_INVALID_STREAM;
						SPDYDEBUG("**** OOPS! Stream %p::#%d is INVALID!", phys, header->stream_id);
					} else {
						stream = n->ptr;
						if (stream->state == STREAM_CLOSED) {
							rc = SPINDLYE_STREAM_ALREADY_CLOSED;
							SPDYDEBUG("#### Ahh! Stream %p::#%d is Already closed!",
									phys, header->stream_id);
							break;
						}
						ptr->msg.headers.stream = stream;
						spindly_mk_header(&ptr->msg.headers.headers, &header->nv_block);
					}
					break;
				case SPDY_CTRL_WINDOW_UPDATE:
					wnd = &phys->frame.frame.control.obj.wndup;
					ptr->type = SPINDLY_DX_WND_UPDATE;
					ptr->msg.wnd.stream_id = wnd->stream_id;

					n = _spindly_hash_get(&phys->streamhash, wnd->stream_id);
					if (!n) {
						/* received a WND_UPDATE for an unknown streamid or alread closed*/
						rc = SPINDLYE_INVALID_STREAM;
						SPDYDEBUG("**** OOPS! Stream %p::#%d is INVALID!", phys, wnd->stream_id);
					} else {
						stream = n->ptr;
						if (stream->state == STREAM_CLOSED) {
							rc = SPINDLYE_STREAM_ALREADY_CLOSED;
							SPDYDEBUG("#### Ahh! Stream %p::#%d is Already closed!",
									phys, wnd->stream_id);
							break;
						}
						SPDYDEBUG("++++ 1 %p::#%d Wndw remaining size: [%u], Wndw size: [%u]",
									phys, wnd->stream_id, stream->spdy.wndw_remaining_size, wnd->size);
						stream->spdy.wndw_remaining_size += wnd->size;
						ptr->msg.wnd.remainaing_size = stream->spdy.wndw_remaining_size;
						SPDYDEBUG("++++ 2 %p::#%d Wndw remaining size: [%u], Wndw size: [%u]",
									phys, wnd->stream_id, stream->spdy.wndw_remaining_size, wnd->size);
					}
					break;
				default:
					/*assert(0);*/ /* internal error */
					break;
				}
				spdy_frame_destroy(&phys->frame);
			} else { /* data */
				ptr->type = SPINDLY_DX_DATA;
				ptr->msg.data.streamid = phys->frame.frame.data.stream_id;
				ptr->msg.data.len = phys->frame.frame.data.length;
				ptr->msg.data.flags = phys->frame.frame.data.flags;
				ptr->msg.data.datap = phys->frame.frame.data.data;
				n = _spindly_hash_get(&phys->streamhash, ptr->msg.data.streamid);
				if (!n) {
					/* received a DATA for an unknown streamid */
					rc = SPINDLYE_INVALID_STREAM;
					SPDYDEBUG("**** OOPS! Stream %p::#%d is INVALID!", phys, ptr->msg.data.streamid);
					ptr->msg.data.datap = NULL;
				} else {
					stream = n->ptr;
					if (stream->state == STREAM_CLOSED) {
						rc = SPINDLYE_STREAM_ALREADY_CLOSED;
						SPDYDEBUG("#### Ahh! Stream %p::#%d is Already closed!",
								phys, ptr->msg.data.streamid);
						break;
					}
					fin_sent_by_us = stream->spdy.fin_sent;
					fin_sent_by_sender = ptr->msg.data.flags;

					if(!fin_sent_by_us) {
						/* received a data for stream which was not send fin flag */
						SPDYDEBUG("Error: Server started sending without "
								"waiting for us to finish!");
						rc = SPINDLYE_STREAM_IN_USE;
						break;
					}
					/* If FLAG_FIN is sent by both Sender and Receiver, then free the stream. */
					if (fin_sent_by_us && fin_sent_by_sender) {
						stream->spdy.fin_received = true;
						// Set the stream state as CLOSED.
						stream->state = STREAM_CLOSED;
						SPDYDEBUG("Stream #%d is now in CLOSED state. # of open streams [%d]",
								stream->streamid, phys->num_streams);
					}
					SPDYDEBUG("before = %d", stream->spdy.wndw_received_length);
					stream->spdy.wndw_received_length += phys->frame.frame.data.length;
					SPDYDEBUG("after = %d len %d",
							stream->spdy.wndw_received_length,
							phys->frame.frame.data.length);
					ptr->msg.data.stream = stream;
					phys->frame.frame.data.data = NULL; //will be freed by application in demux
				}
				spdy_frame_destroy(&phys->frame);
			}

			if (phys->data.cursor != phys->data.data_end){
				SPDYDEBUG("Data left %d\n", phys->data.data_end-phys->data.cursor);
			}
			if (stream)
				SPDYDEBUG("Stream state: (NEW, ACKED, CLOSED) %d", stream->state);
			return rc;
		} else if(rc == SPDY_ERROR_INSUFFICIENT_DATA) {
			/* if there's too little data to parse, merge the buffer with the next
			 * in the queue and loop and parse the bigger one
			 */
			ptr->type = SPINDLY_DX_NONE;
			bool more;
			rc = parse_append(phys, &more);
			if (rc)
				break;

			if (!more)
				/* there's no more right now */
				return SPINDLYE_OK;
		}
	} while (!rc);

	return rc;
}

/*
 * Tell Spindly how many bytes of the data that has been sent and should be
 * considered consumed. The PHYS will then contain updated information of
 * amount of remaining data to send etc.
 */
spindly_error_t spindly_phys_sent(struct spindly_phys *phys, size_t len)
{
	if (!phys || len > phys->outgoing_tosend)
		/* a larger value that outstanding means badness and we rather tell the
		   user than adapt in silence */
		return SPINDLYE_INVAL;

	struct spindly_outdata *od = phys->outgoing;

	phys->outgoing_tosend -= len;

	if (phys->outgoing_tosend == 0) {
		phys->outgoing = NULL;

		/* if send remove this buffer */
		FREEIF(od->buffer);
		od->buffer = NULL;

		/* add this node back to the pending queue */
		_spindly_list_add(&phys->pendq, &od->node);
	}
	return SPINDLYE_OK;
}

/*
 * Change one or more settings associated with the connection. This will
 * result in a SPINDLY_DX_SETTINGS message to end up on the remote side.
 *
 * TODO: figure out how to pass in 'settings' the best way
 */
spindly_error_t spindly_phys_settings(struct spindly_phys *phys,
		spindly_iv_block* iv_block)
{
	spindly_error_t rc = SPINDLYE_OK;
	spdy_control_frame ctrl_frame;
	struct spindly_outdata *od;
	int i = 0;

	ASSERT_RET_VAL(phys != NULL, SPINDLYE_INVAL);

	if (!iv_block)
		return SPINDLYE_INVAL;

	for (i = 0; i < iv_block->count; i++) {
		if(iv_block->pairs[i].id == SETTINGS_INITIAL_WINDOW_SIZE ) {
			SPDYDEBUG("before INITIAL_WINDOW_SIZE!%d", phys->max_window_size);
			phys->max_window_size = iv_block->pairs[i].value;
			SPDYDEBUG("INITIAL_WINDOW_SIZE!%d", phys->max_window_size);
		}
		else if(iv_block->pairs[i].id == SETTINGS_MAX_CONCURRENT_STREAMS ) {
			SPDYDEBUG("before MAX_CONCURRENT_STREAMS!%d", phys->max_concurrent_streams);
			phys->max_concurrent_streams = iv_block->pairs[i].value;
			SPDYDEBUG("MAX_CONCURRENT_STREAMS!%d", phys->max_concurrent_streams);
		}
	}

	rc = spdy_control_mk_setting(&ctrl_frame, (spdy_iv_block*)iv_block);

	if (rc)
		goto fail;

	/* get an out buffer TODO: what if drained? */
	od = _spindly_list_first(&phys->pendq);
	if (!od) {
		rc = SPINDLYE_NOMEM;
		goto fail;
	}

	/* remove the node from the pending list */
	_spindly_list_remove(&od->node);

	/* pack a control frame to the output buffer */
	rc = spdy_control_frame_pack(phys, &od->buffer, PHYS_OUTBUFSIZE,
			&od->len, &ctrl_frame);
	if (rc)
		goto fail;
	//TODO, should set to 0, when send is success. after interface provided

	/* add this handle to the outq */
	_spindly_list_add(&phys->outq, &od->node);
	SPDYDEBUG("sending settings");


fail:
	return rc;
}


spindly_error_t spindly_phys_goaway(struct spindly_phys *phys, int status)
{
	spindly_error_t rc = SPINDLYE_OK;
	spdy_control_frame ctrl_frame;
	struct spindly_outdata *od;

	ASSERT_RET_VAL(phys != NULL, SPINDLYE_INVAL);

	rc = spdy_control_mk_goaway(&ctrl_frame, phys->received_streamid, status);

	if (rc)
		goto fail;

	/* get an out buffer TODO: what if drained? */
	od = _spindly_list_first(&phys->pendq);
	if (!od) {
		rc = SPINDLYE_NOMEM;
		goto fail;
	}

	/* remove the node from the pending list */
	_spindly_list_remove(&od->node);

	/* pack a control frame to the output buffer */
	rc = spdy_control_frame_pack(phys, &od->buffer, PHYS_OUTBUFSIZE,
			&od->len, &ctrl_frame);
	if (rc)
		goto fail;
	//TODO, should set to 0, when send is success. after interface provided

	/* add this handle to the outq */
	_spindly_list_add(&phys->outq, &od->node);
	SPDYDEBUG("sending GOAWAY");


fail:
	return rc;
}

spindly_error_t spindly_phys_ping(struct spindly_phys *phys,
		uint32_t id)
{
	spindly_error_t rc = SPINDLYE_OK;
	spdy_control_frame ctrl_frame;
	struct spindly_outdata *od;

	ASSERT_RET_VAL(phys != NULL, SPINDLYE_INVAL);

	bool reply = id ? true : false;

	if (!reply)
		id = phys->pingid;

	rc = spdy_control_mk_ping(&ctrl_frame, id);

	if (rc)
		goto fail;

	/* get an out buffer TODO: what if drained? */
	od = _spindly_list_first(&phys->pendq);
	if (!od) {
		rc = SPINDLYE_NOMEM;
		goto fail;
	}

	/* remove the node from the pending list */
	_spindly_list_remove(&od->node);

	/* pack a control frame to the output buffer */
	rc = spdy_control_frame_pack(phys, &od->buffer, PHYS_OUTBUFSIZE,
			&od->len, &ctrl_frame);
	if (rc)
		goto fail;
	//TODO, should set to 0, when send is success. after interface provided

	/* add this handle to the outq */
	_spindly_list_add(&phys->outq, &od->node);
	SPDYDEBUG("sending ping");

	if (!reply)
		phys->pingid+=2; /* bump counter last so that it isn't bumped in vain */


fail:
	return rc;
}

/*
 * Cleanup the entire connection.
 */
void spindly_phys_cleanup(struct spindly_phys *phys)
{
	struct spindly_outdata *od = NULL;
	struct spindly_indata *in = NULL;
	struct spindly_stream *s = NULL;

	ASSERT_RET(phys != NULL);

	/* TODO: move over all attached streams and clean them up as well */
	spdy_zlib_inflate_end(&phys->zlib_in);
	spdy_zlib_deflate_end(&phys->zlib_out);

	while(od  = _spindly_list_first(&phys->pendq)) {
		_spindly_list_remove(&od->node);
		FREE(phys, od->buffer);
		FREE(phys, od);
	}

	od = NULL;
	while(od  = _spindly_list_first(&phys->outq)) {
		_spindly_list_remove(&od->node);
		FREE(phys, od->buffer);
		FREE(phys, od);
	}

	while(in  = _spindly_list_first(&phys->inq)) {
		_spindly_list_remove(&in->node);
		if (in->copied)
			FREE(phys, in->data);
		FREE(phys, in);
	}

	/*while(s  = _spindly_list_first(&phys->streams)) {
	  _spindly_list_remove(&s->node);
	//TODO should free if any stream data to be freed
	FREE(phys, s);
	}*/

	_spindly_hash_destroy(phys, &phys->streamhash);
	FREEIF(phys->parse);

	SPDYDEBUG("Cleaning phys: %p", phys);
	FREE(phys, phys);
}

/**
 * @brief  Adds a IV-pair to IV-Block.
 *
 * @param iv_block: pointer to IV Block to which IV pair is added.
 * @param id:
 * @param flag:
 * @param value:
 *
 * @return SPINDLYE_OK when all is well, error code otherwise.
 */
spindly_error_t spindly_iv_block_add_pairs(spindly_iv_block *iv_block,
		uint32_t id,
		uint32_t flag,
		uint32_t value)
{
	spindly_error_t err = SPINDLYE_OK;
	spindly_iv_pair *pairs = NULL;
	spindly_iv_pair *this_pair = NULL;
	int i = 0;

	if (!iv_block) {
		err = SPINDLYE_INVAL;
		goto END;
	}

	pairs = realloc(iv_block->pairs,
			sizeof(spindly_iv_pair) * (iv_block->count + 1));
	if (!pairs) {
		err = SPINDLYE_NOMEM;
		goto END;
	}

	iv_block->pairs = pairs;
	this_pair = iv_block->pairs + iv_block->count;
	this_pair->id = id;
	this_pair->flag = flag;
	this_pair->value = value;
	SPDYDEBUG("[%d] %d %d %d\n", iv_block->count, id, flag, value);

	iv_block->count++;
END:
	return err;
}


/**
 * @brief Cleanup a IV Block.
 *
 * @param iv_block: pointer to IV Block.
 */
void spindly_destroy_iv_block(spindly_iv_block *iv_block)
{
	if (!iv_block)
		return;

	FREEIF(iv_block->pairs);
	iv_block->count = 0;
	iv_block->pairs = NULL;

	return;
}

