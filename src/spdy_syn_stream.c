#include "spdy_setup.h"         /* MUST be the first header to include */

#include <netinet/in.h>
#include <string.h>

#include "spdy_syn_stream.h"
#include "spdy_log.h"
#include "spdy_error.h"
#include "spdy_bytes.h"
#include "spindly_phys.h"
#include "hash.h"

/* Minimum length of a SYN_STREAM frame. */
#define SPDY2_SYN_STREAM_MIN_LENGTH 12
#define SPDY3_SYN_STREAM_MIN_LENGTH 14

/* Minimum length of a SYN_STREAM frame header. (The frame without
 * the NV block.) */
#define SPDY_SYN_STREAM_HEADER_MIN_LENGTH 10

int spdy_syn_stream_init(spdy_syn_stream *str,
                         uint32_t stream_id,
                         uint32_t associated_to,
                         int prio,
                         spdy_nv_block *nv_block)
{
	ASSERT_RET_VAL(str, SPINDLYE_INVAL);

	str->stream_id = stream_id;
	str->associated_to = associated_to;
	str->priority = prio;
	if (nv_block) {
		memcpy(&str->nv_block, nv_block, sizeof(str->nv_block));
	} else {
		memset(&str->nv_block, 0, sizeof(str->nv_block));
	}

	return SPDY_ERROR_NONE;
}


/**
 * Parse the header of a SYN_STREAM control frame.
 * This function can be used to parse the header of a SYN_STREAM frame
 * before the whole NV block has been received. (Minimum of bytes needed
 * is stored in SPDY_SYN_STREAM_HEADER_MIN_LENGTH.)
 * @param syn_stream - Destination frame.
 * @param data - Data to parse.
 * @param version - The version number of the SPDY protocol.
 * @see SPDY_SYN_STREAM_HEADER_MIN_LENGTH
 * @return Errorcode
 */
int spdy_syn_stream_parse_header(spdy_syn_stream *syn_stream, spdy_data *data,
										uint16_t version)
{
	size_t length = data->data_end - data->cursor;
	if (length < SPDY_SYN_STREAM_HEADER_MIN_LENGTH) {
		SPDYDEBUG("Not enough data for parsing the header.");
		data->needed = SPDY_SYN_STREAM_HEADER_MIN_LENGTH - length;
		return SPDY_ERROR_INSUFFICIENT_DATA;
	}
	/*
	   +------------------------------------+
	   |1|    version    |         1        |
	   +------------------------------------+
	   |  Flags (8)  |  Length (24 bits)    |
	   +------------------------------------+
	   |X|           Stream-ID (31bits)     |
	   +------------------------------------+
	   |X| Associated-To-Stream-ID (31bits) |
	   +------------------------------------+
	   | Pri|Unused | Slot |                |
	   +-------------------+                |
	   | Number of Name/Value pairs (int32) |   <+
	   +------------------------------------+    |
	   |     Length of name (int32)         |    | This section is the "Name/Value
	   +------------------------------------+    | Header Block", and is compressed.
	   |           Name (string)            |    |
	   +------------------------------------+    |
	   |     Length of value  (int32)       |    |
	   +------------------------------------+    |
	   |          Value   (string)          |    |
	   +------------------------------------+    |
	   |           (repeats)                |   <+
	 */

	/* Read the Stream-ID. */
	syn_stream->stream_id = BE_LOAD_32(data->cursor) & 0x7FFFFFFF;
	data->cursor += 4;
	/* Read the 'Associated-To-Stream-ID'. */
	syn_stream->associated_to = BE_LOAD_32(data->cursor) & 0x7FFFFFFF;
	data->cursor += 4;
	if (version == SPINDLY_SPDYVER2) {
		/* Read the two priority bits. */
		syn_stream->priority = (data->cursor[0] & 0xC0) >> 6;
	} else {
		/* Read the 3 priority bits. and slot */
		syn_stream->priority = (data->cursor[0] & 0xC0) >> 5;
		syn_stream->slot= data->cursor[1];
	}
	/* Skip the unused block. */
	data->cursor += 2;

	SPDYDEBUG("parsing streamid %d\n", syn_stream->stream_id);
	return SPDY_ERROR_NONE;
}

/**
 * Parse a SYN_STREAM control frame.
 * Parses the header of a SYN_STREAM control frame and extracts the
 * NV block.
 * @param syn_stream - Destination frame.
 * @param hash - Streamid lookup
 * @param data - Data to parse.
 * @param frame_length - Length of the frame.
 * @param version - The version number of the SPDY protocol.
 * @see spdy_control_frame
 * @see SPDY_SYN_STREAM_MIN_LENGTH
 * @return 0 on success, -1 on failure.
 */
int spdy_syn_stream_parse(spdy_syn_stream *syn_stream,
                          struct spindly_phys *phys,
                          spdy_data *data,
                          uint32_t frame_length,
                          uint16_t version)
{
	int ret;
	size_t length = data->data_end - data->cursor;
	struct hashnode *hn;

	ASSERT_RET_VAL(phys != NULL, SPINDLYE_INVAL);

	if (length < frame_length) {
		data->needed = frame_length - length;
		SPDYDEBUG("Not enough data for parsing the stream.");
		return SPDY_ERROR_INSUFFICIENT_DATA;
	}
	/* TODO: Optimize the double length check away. */
	if (version == SPINDLY_SPDYVER2) {
		if (length < SPDY2_SYN_STREAM_MIN_LENGTH) {
			data->needed = SPDY2_SYN_STREAM_MIN_LENGTH - length;
			SPDYDEBUG("Not enough data for parsing the stream.");
			return SPDY_ERROR_INSUFFICIENT_DATA;
		}
	} else {
		if (length < SPDY3_SYN_STREAM_MIN_LENGTH) {
			data->needed = SPDY3_SYN_STREAM_MIN_LENGTH - length;
			SPDYDEBUG("Not enough data for parsing the stream.");
			return SPDY_ERROR_INSUFFICIENT_DATA;
		}
	}

	/* Parse the frame header. */
	ret = spdy_syn_stream_parse_header(syn_stream, data, version);
	if (ret) {
		SPDYDEBUG("Failed to parse header.");
		return ret;
	}

	/* make sure the incoming streamid isn't already used */
	hn = _spindly_hash_get(&phys->streamhash, syn_stream->stream_id);
	if (hn) {
		SPDYDEBUG("Got a SPDY_STREAM with an exiting id!");
		return SPDY_ERROR_INVALID_DATA;
	}

	/* Init NV block. */
	ret = spdy_nv_block_init(&syn_stream->nv_block);
	if (ret)
		return ret;

	/* Parse NV block. */
	ret = spdy_nv_block_inflate_parse(&syn_stream->nv_block,
	                        data->cursor,
	                        frame_length - SPDY_SYN_STREAM_HEADER_MIN_LENGTH,
	                        &phys->zlib_in,
	                        version);
	if (ret) {
		/* Clean up. */
		SPDYDEBUG("Failed to parse NV block.");
		return ret;
	}
	data->cursor += frame_length - SPDY_SYN_STREAM_HEADER_MIN_LENGTH;

	return SPDY_ERROR_NONE;
}

/*
 * Pack SYN_STREAM into an output buffer for transmitting.
 */
int spdy_syn_stream_pack(struct spindly_phys * phys,unsigned char **out,
                         size_t *outsize, spdy_syn_stream *str)
{
	char *buf = NULL;
	size_t consumed=0;
	unsigned char *deflated=NULL;
	size_t deflated_length=0;
	int rc;
	int i =0;
	char *dest;
	size_t dest_size;

	*out = NULL;

	SPDYDEBUG("packing streamid %d\n", str->stream_id);
	rc = spdy_nv_block_pack(&dest, &dest_size, &str->nv_block, phys->protver);
	if (rc)
		goto fail;

	/* create the NV block to include */
	rc = spdy_zlib_deflate(&phys->zlib_out, dest, dest_size, &consumed, &deflated, &deflated_length,phys->protver);
	if (rc)
		goto fail;

	buf = MALLOC(phys, (SPDY_HEADER + SPDY_SYN_STREAM_HEADER_MIN_LENGTH + deflated_length));

	if (buf == NULL) {
		rc = SPDY_ERROR_MALLOC_FAILED;
		goto fail;
	}
	*out = buf;
	buf += SPDY_HEADER;

	BE_STORE_32(buf, str->stream_id);
	buf += 4;
	BE_STORE_32(buf, str->associated_to);
	buf += 4;
	if (phys->protver == SPINDLY_SPDYVER2) {
		/* store the two priority bits. */
		BE_STORE_16(buf, (str->priority << 14)); /* 14 bits unused */
	} else {
		/* store the 3 priority bits. and slot */
		BE_STORE_16(buf, (str->priority << 13)); /* 5 bits unused and 8 bit slot*/
		buf[1] = str->slot;
	}
	buf += 2;


	memcpy(buf, deflated, deflated_length);
	*outsize = SPDY_SYN_STREAM_HEADER_MIN_LENGTH + deflated_length;
	rc = SPDY_ERROR_NONE;

fail:
	FREE(phys, deflated);
	FREE(phys, dest);
	return rc;
}

/*
 * Destroy/free all data this struct has allocated.
 */
void spdy_syn_stream_destroy(spdy_syn_stream *syn_stream)
{
	spdy_nv_block_destroy(&syn_stream->nv_block);
}
