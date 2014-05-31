#include "spdy_setup.h"         /* MUST be the first header to include */

#include <string.h>
#include <netinet/in.h>
#include "spdy_syn_reply.h"
#include "spdy_log.h"
#include "spdy_error.h"
#include "spdy_bytes.h"
#include "spindly_phys.h"


/* Minimum length of a SYN_REPLY frame. */
#define SPDY_SYN_REPLY_MIN_LENGTH 8
/* Minimum length of a SYN_STREAM frame header. (The frame without
 * the NV Block.) */
#define SPDY2_SYN_REPLY_HEADER_MIN_LENGTH 6
#define SPDY3_SYN_REPLY_HEADER_MIN_LENGTH 4


int spdy_syn_reply_init(spdy_syn_reply *syn_reply,
                         uint32_t stream_id,
                         spdy_nv_block *nv_block)
{
	ASSERT_RET_VAL(syn_reply, SPINDLYE_INVAL);

	syn_reply->stream_id = stream_id;
	if (nv_block) {
		memcpy(&syn_reply->nv_block, nv_block, sizeof(syn_reply->nv_block));
	} else {
		memset(&syn_reply->nv_block, 0, sizeof(syn_reply->nv_block));
	}

	return SPDY_ERROR_NONE;
}

/**
 * Parse the header of a SYN_REPLY control frame.
 * This function can be used to parse the header of a SYN_REPLY frame
 * before the whole NV block has been received.
 * @param syn_reply - Destination frame.
 * @param data - Data to parse.
 * @param version - The version number of the SPDY protocol.
 * @see SPDY_SYN_REPLY_HEADER_MIN_LENGTH
 * @return 0 on success, 01 on failure.
 */
int spdy_syn_reply_parse_header(spdy_syn_reply *syn_reply, spdy_data *data,
									uint16_t version)
{
	size_t length = data->data_end - data->cursor;
	if (version == SPINDLY_SPDYVER2) {
		if(length < SPDY2_SYN_REPLY_HEADER_MIN_LENGTH) {
			SPDYDEBUG("Not enough data for parsing the header.");
			data->needed = SPDY2_SYN_REPLY_HEADER_MIN_LENGTH - length;
			return SPDY_ERROR_INSUFFICIENT_DATA;
		}
	} else {
		if (length < SPDY3_SYN_REPLY_HEADER_MIN_LENGTH) {
			SPDYDEBUG("Not enough data for parsing the header.");
			data->needed = SPDY3_SYN_REPLY_HEADER_MIN_LENGTH - length;
			return SPDY_ERROR_INSUFFICIENT_DATA;
		}
	}

	/* Read the Stream-ID. */
	syn_reply->stream_id = BE_LOAD_32(data->cursor) & 0x7FFFFFFF;
	data->cursor += 4;

	/* Skip Stream-ID and 2 bytes of unused space. */
	if (version == SPINDLY_SPDYVER2)
		data->cursor += 2;

	return SPDY_ERROR_NONE;
}

/**
 * Parse a SYN_REPLY control frame.
 * Parses the header of a SYN_REPLY control frame and extracts the
 * NV block.
 * @param syn_reply - Destination frame.
 * @param hash - streamid lookup
 * @param data - Data to parse.
 * @param frame_length - Length of the frame.
 * @param version - The version number of the SPDY protocol.
 * @see SPDY_SYN_STREAM_MIN_LENGTH
 * @return 0 on success, -1 on failure.
 */
int spdy_syn_reply_parse(spdy_syn_reply *syn_reply,
                         struct spindly_phys *phys,
                         spdy_data *data,
                         uint32_t frame_length,
                         uint16_t version)
{
	int ret;
	int header_len;
	size_t length = data->data_end - data->cursor;

	if (length < SPDY_SYN_REPLY_MIN_LENGTH) {
		SPDYDEBUG("Not enough data for parsing the stream.");
		data->needed = SPDY_SYN_REPLY_MIN_LENGTH - length;
		return SPDY_ERROR_INSUFFICIENT_DATA;
	}

	/* Parse the frame header. */
	if ((ret = spdy_syn_reply_parse_header(syn_reply, data, version))
			!= SPDY_ERROR_NONE) {
		return ret;
	}

	/* Init NV block. */
	ret = spdy_nv_block_init(&syn_reply->nv_block);
	if (ret) {
		return ret;
	}

	if (version == SPINDLY_SPDYVER2)
		header_len = SPDY2_SYN_REPLY_HEADER_MIN_LENGTH;
	else
		header_len = SPDY3_SYN_REPLY_HEADER_MIN_LENGTH;

	/* Parse NV block */
	ret = spdy_nv_block_inflate_parse(&syn_reply->nv_block,
	                        data->cursor,
	                        frame_length-header_len,
	                        &phys->zlib_in,
	                        version);
	if (ret != SPDY_ERROR_NONE) {
		/* Clean up. */
		SPDYDEBUG("Failed to parse NV block.");
		return ret;
	}
	data->cursor += frame_length - header_len;
	return SPDY_ERROR_NONE;
}


/*
 * Pack SYN_REPLY into an output buffer for transmitting.
 */
int spdy_syn_reply_pack(struct spindly_phys* phys,unsigned char **out,
                        size_t *outsize, spdy_syn_reply *rep)
{
	size_t consumed=0;
	unsigned char *deflated = NULL;
	size_t deflated_length;
	int rc;
	int i=0;
	char *buf = NULL;

	char *dest;
	size_t dest_size;
	*out = NULL;

	rc = spdy_nv_block_pack(&dest, &dest_size, &(rep->nv_block), phys->protver);
	if (rc)
		goto fail;

	/* create the NV block to include */
	rc = spdy_zlib_deflate(&phys->zlib_out,dest, dest_size, &consumed, &deflated, &deflated_length, phys->protver);
	if (rc)
		goto fail;

	*outsize = deflated_length;
	if (phys->protver == SPINDLY_SPDYVER2)
		*outsize += SPDY2_SYN_REPLY_HEADER_MIN_LENGTH;
	else
		*outsize += SPDY2_SYN_REPLY_HEADER_MIN_LENGTH;

	buf = MALLOC(phys, (*outsize)+SPDY_HEADER);
	if (buf == NULL) {
		rc = SPDY_ERROR_MALLOC_FAILED;
		*outsize = 0;
		goto fail;
	}
	*out = buf;
	buf += SPDY_HEADER;

	BE_STORE_32(buf, rep->stream_id);
	buf += 4;

	if (phys->protver == SPINDLY_SPDYVER2) {
		BE_STORE_16(buf, 0); /* 16 bits unused */
		buf += 2;
	}

	memcpy(buf, deflated, deflated_length);
	rc = SPDY_ERROR_NONE;
fail:
	FREE(phys, deflated);
	FREE(phys, dest);
	return rc;

}

/*
 * Destroy/free all data this struct has allocated.
 */
void spdy_syn_reply_destroy(spdy_syn_reply *syn_reply)
{
	spdy_nv_block_destroy(&syn_reply->nv_block);
}
