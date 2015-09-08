#include "spdy_setup.h"         /* MUST be the first header to include */

#include "spindly_phys.h"
#include "spdy_frame.h"
#include "spdy_control_frame.h"
#include "spdy_syn_stream.h"
#include "spdy_syn_reply.h"
#include "spdy_rst_stream.h"
#include "spdy_headers.h"
#include "spdy_log.h"
#include "spdy_error.h"
#include "spdy_bytes.h"
#include "spdy_data_frame.h"
#include "spdy_headers.h"

#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

/** Minimum length of a control frame. */
#define SPDY_CONTROL_FRAME_MIN_LENGTH 8

int spdy_control_frame_init(spdy_control_frame *frame)
{
	if(frame) {
		memset(frame, 0, sizeof(spdy_control_frame));
		return SPDY_ERROR_NONE;
	}
	return SPDY_ERROR_INVALID_DATA;
}

/**
 * Parse the header of a control frame.
 * @param frame - Target control frame.
 * @param data - Data to parse.
 * @see spdy_control_frame
 * @todo Evaluate how to store data in the frame.
 * @return 0 on success, -1 on failure.
 */
int spdy_control_frame_parse_header(spdy_control_frame *frame, spdy_data *data)
{
	size_t length;
	/* Check if the header has already been parsed. */
	if (frame->_header_parsed)
		return SPDY_ERROR_NONE;

	length = data->data_end - data->cursor;
	if (length < SPDY_CONTROL_FRAME_MIN_LENGTH) {
		SPDYDEBUG("Insufficient data for control frame.");
		data->needed = SPDY_CONTROL_FRAME_MIN_LENGTH - length;
		return SPDY_ERROR_INSUFFICIENT_DATA;
	}
	/* Read SPDY version. (AND is there to remove the first bit
	* which is used as frame type identifier. */
	frame->version = BE_LOAD_16(data->cursor) & 0x7FFF;
	data->cursor += 2;
	frame->type = BE_LOAD_16(data->cursor);
	data->cursor += 2;
	/* Read one byte */
	frame->flags = (uint8_t) data->cursor[0];
	/* Read four byte, including the flags byte and removing it with the AND. */
	frame->length = BE_LOAD_32(data->cursor) & 0x00FFFFFF;
	data->cursor += 4;
	frame->_header_parsed = 1;
	return SPDY_ERROR_NONE;
}

/**
 * Parse a control frame.
 * @param frame - Target control fame.
 * @param data - Data to parse.
 * @param zlib_ctx - zlib context to use.
 * @see spdy_control_frame
 * @return Errorcode
 */
int spdy_control_frame_parse(spdy_control_frame *frame,
                             struct spindly_phys *phys,
                             spdy_data *data)
{
	int ret;
	size_t length;

	ASSERT_RET_VAL(phys, SPINDLYE_INVAL);

	if (!frame->_header_parsed) {
		ret = spdy_control_frame_parse_header(frame, data);
		if(ret != SPDY_ERROR_NONE) {
			SPDYDEBUG("Control frame parse header failed.");
			return ret;
		}
		if(frame->version != phys->protver){
			SPDYDEBUG("Control frame parse header failed.");
			return SPINDLYE_UNSUPPORTED_VERSION;
		}
	}

	/* TODO: Check if control_frame_min_length is contained in length or not */
	length = data->data_end - data->cursor;
	if(frame->length > length) {
		data->needed = frame->length - length;
		SPDYDEBUG("Insufficient data for control frame.");
		return SPDY_ERROR_INSUFFICIENT_DATA;
	}

	switch (frame->type) {
		case SPDY_CTRL_SYN_STREAM:
			ret = spdy_syn_stream_parse(&frame->obj.syn_stream, phys,
			                            data, frame->length, frame->version);
			if (ret != SPDY_ERROR_NONE) {
				SPDYDEBUG("SYN_STREAM parsing failed.");
				return ret;
			}
			break;
		case SPDY_CTRL_SYN_REPLY:
			ret = spdy_syn_reply_parse(&frame->obj.syn_reply, phys,
			                           data, frame->length, frame->version);
			if (ret != SPDY_ERROR_NONE) {
				SPDYDEBUG("SYN_REPLY parsing failed.");
				return ret;
			}
			break;
		case SPDY_CTRL_RST_STREAM:
			ret = spdy_rst_stream_parse(&frame->obj.rst_stream,
			                            data, frame->length);
			if (ret != SPDY_ERROR_NONE) {
				SPDYDEBUG("RST_STREAM parsing failed.");
				return ret;
			}
			break;
		case SPDY_CTRL_SETTINGS:
			ret = spdy_setting_parse(&frame->obj.setting, phys,
			                            data, frame->length, frame->version);
			if (ret != SPDY_ERROR_NONE) {
				SPDYDEBUG("RST_STREAM parsing failed.");
				return ret;
			}
			break;
		case SPDY_CTRL_PING:
			ret = spdy_ping_parse(&frame->obj.ping,
			                            data, frame->length);
			if (ret != SPDY_ERROR_NONE) {
				SPDYDEBUG("GOAWAY parsing failed.");
				return ret;
			}
			break;
		case SPDY_CTRL_GOAWAY:
			ret = spdy_goaway_parse(&frame->obj.goaway,
			                            data, frame->length, frame->version);
			if (ret != SPDY_ERROR_NONE) {
				SPDYDEBUG("GOAWAY parsing failed.");
				return ret;
			}
			break;
		case SPDY_CTRL_HEADERS:
			ret = spdy_headers_parse(&frame->obj.headers, phys,
			                         data, frame->length, frame->version);
			if (ret != SPDY_ERROR_NONE) {
				SPDYDEBUG("HEADERS parsing failed.");
				return SPDY_ERROR_INVALID_DATA;
			}
			break;
		case SPDY_CTRL_WINDOW_UPDATE:
			ret = spdy_wndup_parse(&frame->obj.wndup,
			                         data, frame->length, frame->version);
			if (ret != SPDY_ERROR_NONE) {
				SPDYDEBUG("HEADERS parsing failed.");
				return SPDY_ERROR_INVALID_DATA;
			}
			break;
		default:
			return SPDY_ERROR_INVALID_DATA;
	}
	return SPDY_ERROR_NONE;
}

/**
 * Pack the control frame HEADER into an output buffer for transmitting.
 * @param out Target buffer
 * @param buffer Length of target buffer
 * @param outsize Pointer to length of the output data
 * @param frame Frame to pack
 * @see spdy_control_frame
 * @return SPDY_ERRORS
 */
int spdy_control_frame_pack_header(struct spindly_phys* phys, unsigned char *out,
						size_t bufsize, size_t *outsize, spdy_control_frame *frame)
{
	if (bufsize < 8)
		return SPDY_ERROR_TOO_SMALL_BUFFER;

	/* The OR sets the first bit to true, indicating that this is a
	* control frame. */
	BE_STORE_16(out, (phys->protver| 0x8000));
	out += 2;
	BE_STORE_16(out, frame->type);
	out += 2;
	*out++ = frame->flags;
	BE_STORE_24(out, frame->length);

	*outsize = 8;
	return SPDY_ERROR_NONE;
}

/**
 * Pack the entire control frame into an output buffer for transmitting.
 *
 * @param out Target buffer
 * @param buffer Length of target buffer
 * @param outsize Pointer to length of the output data
 * @param frame Frame to pack
 * @see spdy_control_frame
 * @return SPDY_ERRORS
 */
int spdy_control_frame_pack(struct spindly_phys* phys,unsigned char **out,
				size_t bufsize, size_t *outsize, spdy_control_frame *frame)
{
	size_t headersize=0;
	size_t payloadsize=0;
	int rc;

	/* fill in the control frame payload */
	switch (frame->type) {
		case SPDY_CTRL_SYN_STREAM:
			rc = spdy_syn_stream_pack(phys,out, &payloadsize,
			                          &frame->obj.syn_stream);
			break;
		case SPDY_CTRL_SYN_REPLY:
			rc = spdy_syn_reply_pack(phys,out, &payloadsize,
			                         &frame->obj.syn_reply);
			break;
		case SPDY_CTRL_RST_STREAM:
			rc = spdy_rst_stream_pack(phys, out, &payloadsize,
			                         &frame->obj.rst_stream);
			break;
		case SPDY_CTRL_PING:
			rc = spdy_ping_pack(phys, out, &payloadsize,
			                         &frame->obj.ping);
			break;
		case SPDY_CTRL_SETTINGS:
			rc = spdy_setting_pack(phys, out, &payloadsize,
			                         &frame->obj.setting);
			break;
		case SPDY_CTRL_GOAWAY:
			rc = spdy_goaway_pack(phys, out, &payloadsize,
			                         &frame->obj.goaway);
			break;
		case SPDY_CTRL_HEADERS:
			rc = spdy_header_pack(phys, out, &payloadsize,
			                         &frame->obj.headers);
			break;
		case SPDY_CTRL_WINDOW_UPDATE:
			rc = spdy_wndup_pack(phys, out, &payloadsize,
			                         &frame->obj.wndup);
			break;
		default:
			ASSERT_RET_VAL(0, SPINDLYE_INVAL); /* not implemented or internal error! */
			break;
	}
	if (rc)
		return rc;

	/* create the control frame header after payload data, to calculate actual length*/
	frame->length = payloadsize;
	rc = spdy_control_frame_pack_header(phys, *out, SPDY_HEADER, &headersize, frame);
	if (rc)
		return rc;

	*outsize = headersize + payloadsize;
	return SPDY_ERROR_NONE;
}

/**
 * Returns the name of the given control frame type.
 * @param type - Type of which the name is needed.
 * @return String with type name
 */
char *spdy_control_frame_get_type_name(int type)
{
	switch (type) {
		case SPDY_CTRL_SYN_STREAM:
			return "SYN_STREAM";
		case SPDY_CTRL_SYN_REPLY:
			return "SYN_REPLY";
		case SPDY_CTRL_RST_STREAM:
			return "RST_STREAM";
		case SPDY_CTRL_SETTINGS:
			return "SETTINGS";
		case SPDY_CTRL_NOOP:
			return "NOOP";
		case SPDY_CTRL_PING:
			return "PING";
		case SPDY_CTRL_GOAWAY:
			return "GOAWAY";
		case SPDY_CTRL_HEADERS:
			return "HEADERS";
		case SPDY_CTRL_WINDOW_UPDATE:
			return "WINDOW_UPDATE";
		default:
			return "UNKNOWN";
	}
}

void spdy_control_frame_destroy(spdy_control_frame *frame)
{
	switch (frame->type) {
		case SPDY_CTRL_SYN_STREAM:
			spdy_syn_stream_destroy(&frame->obj.syn_stream);
			break;
		case SPDY_CTRL_SYN_REPLY:
			spdy_syn_reply_destroy(&frame->obj.syn_reply);
			break;
		case SPDY_CTRL_HEADERS:
			spdy_header_destroy(&frame->obj.headers);
			break;
		case SPDY_CTRL_SETTINGS:
			spdy_setting_destroy(&frame->obj.setting);
			break;
		default:
			break;
	}
}

int spdy_control_mk_syn_stream(spdy_control_frame *frame,
                               uint32_t stream_id,
                               uint32_t associated_to,
                               unsigned int flags,
                               int prio,
                               spdy_nv_block *nv_block)
{
	int rc;
	ASSERT_RET_VAL(frame, SPINDLYE_INVAL);

	memset(frame, 0, sizeof(spdy_control_frame));
	frame->type = SPDY_CTRL_SYN_STREAM;
	frame->_header_parsed = true; /* consider it parsed */
	/*frame->version = 2; */ /* SPDY draft protocol version */
	frame->version = 3; /* SPDY draft protocol version */
	frame->flags = flags;
	rc = spdy_syn_stream_init(&frame->obj.syn_stream,
	                        stream_id,
	                        associated_to,
	                        0x1, nv_block);
	frame->length += 10; /* fixed size */
	return rc;
}

int spdy_control_mk_header(spdy_control_frame *frame,
                               uint32_t stream_id,
                               unsigned int flags,
                               spdy_nv_block *nv_block)
{
	int rc;
	ASSERT_RET_VAL(frame, SPINDLYE_INVAL);

	memset(frame, 0, sizeof(spdy_control_frame));
	frame->type = SPDY_CTRL_HEADERS;
	frame->_header_parsed = true; /* consider it parsed */
	/*frame->version = 2; */ /* SPDY draft protocol version */
	frame->version = 3; /* SPDY draft protocol version */
	frame->flags = flags;
	rc = spdy_header_init(&frame->obj.headers,
	                        stream_id,
	                        nv_block);
	frame->length += 10; /* fixed size */
	return rc;
}

int spdy_mk_data_stream(spdy_data_frame *frame,
                               uint32_t stream_id,
                               int flags,
                               char *data,
                               size_t len)
{
	int rc;
	ASSERT_RET_VAL(frame, SPINDLYE_INVAL);

	memset(frame, 0, sizeof(spdy_data_frame));
	rc = spdy_data_frame_init(frame);
	frame->stream_id = stream_id;
	frame->flags = flags;
	frame->length = len;
	//TODO: if non char data
	frame->data = calloc ( len+1, sizeof(char));
	if (frame->data && len)
		memcpy ( frame->data, data, len);
	else if (!len)
		frame->flags = SPDY_DATA_FLAG_FIN; //last frame
	else {
		rc = SPINDLYE_NOMEM;
		SPDYDEBUG("Error: calloc() failed.");
	}
	SPDYDEBUG("frame->length = %d \n", frame->length);
	return rc;
}

int spdy_control_mk_syn_reply(spdy_control_frame *frame,
                              uint32_t stream_id,
                              spdy_nv_block *nv_block)
{
	(void)nv_block; /* TODO: use it! */

	ASSERT_RET_VAL(frame, SPINDLYE_INVAL);

	memset(frame, 0, sizeof(spdy_control_frame));
	frame->type = SPDY_CTRL_SYN_REPLY;
	frame->_header_parsed = true; /* consider it parsed */
	/*frame->version = 2; */ /* SPDY draft protocol version */
	frame->version = 3; /* SPDY draft protocol version */
	frame->obj.syn_reply.stream_id = stream_id;
	frame->length += 10; /* fixed size */
	return SPDY_ERROR_NONE;
}

int spdy_control_mk_rst_stream(spdy_control_frame *frame,
                               uint32_t stream_id,
                               uint32_t status)
{
	ASSERT_RET_VAL(frame, SPINDLYE_INVAL);

	memset(frame, 0, sizeof(spdy_control_frame));
	frame->type = SPDY_CTRL_RST_STREAM;
	frame->_header_parsed = true; /* consider it parsed */
	frame->version = 3; /* SPDY draft protocol version */
	/* frame->version = 3;*/ /* SPDY draft protocol version */
	frame->obj.rst_stream.stream_id = stream_id;
	frame->obj.rst_stream.status_code = status;
	frame->length += 8; /* fixed size */
	return SPDY_ERROR_NONE;
}

int spdy_control_mk_ping(spdy_control_frame *frame,
                               uint32_t id)
{
	ASSERT_RET_VAL(frame, SPINDLYE_INVAL);

	memset(frame, 0, sizeof(spdy_control_frame));
	frame->type = SPDY_CTRL_PING;
	frame->_header_parsed = true; /* consider it parsed */
	frame->version = 3; /* SPDY draft protocol version */
	/* frame->version = 3; */ /* SPDY draft protocol version */
	frame->obj.ping.id = id;
	frame->length += 4; /* fixed size */
	return SPDY_ERROR_NONE;
}

int spdy_control_mk_goaway(spdy_control_frame *frame,
                               uint32_t id, int status_code)
{
	ASSERT_RET_VAL(frame, SPINDLYE_INVAL);

	memset(frame, 0, sizeof(spdy_control_frame));
	frame->type = SPDY_CTRL_GOAWAY;
	frame->_header_parsed = true; /* consider it parsed */
	/*frame->version = 2; */ /* SPDY draft protocol version */
	frame->version = 3; /* SPDY draft protocol version */
	frame->obj.goaway.stream_id = id;
	frame->obj.goaway.status_code = status_code;
	frame->length += 4; /* fixed size */
	return SPDY_ERROR_NONE;
}

int spdy_control_mk_wndup(spdy_control_frame *frame,
                               uint32_t id, int size)
{
	ASSERT_RET_VAL(frame, SPINDLYE_INVAL);

	memset(frame, 0, sizeof(spdy_control_frame));
	frame->type = SPDY_CTRL_WINDOW_UPDATE;
	frame->_header_parsed = true; /* consider it parsed */
	/*frame->version = 2; */ /* SPDY draft protocol version */
	frame->version = 3; /* SPDY draft protocol version */
	frame->obj.wndup.stream_id = id;
	frame->obj.wndup.size = size;
	frame->length += 4; /* fixed size */
	SPDYDEBUG("Window update frame prepared");
	return SPDY_ERROR_NONE;
}

int spdy_control_mk_setting(spdy_control_frame *frame,
	spdy_iv_block* iv_block)
{
	ASSERT_RET_VAL(frame, SPINDLYE_INVAL);

	memset(frame, 0, sizeof(spdy_control_frame));
	frame->type = SPDY_CTRL_SETTINGS;
	frame->_header_parsed = true; /* consider it parsed */
	frame->version = 3; /* SPDY draft protocol version */
	/*frame->version = 3;*/ /* SPDY draft protocol version */
	spdy_setting_init(&frame->obj.setting, iv_block);
	frame->length += 4; /* fixed size */
	return SPDY_ERROR_NONE;
}
