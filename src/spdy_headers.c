#include "spdy_setup.h"         /* MUST be the first header to include */

#include <string.h>
#include <netinet/in.h>
#include "spdy_headers.h"
#include "spdy_log.h"
#include "spdy_error.h"
#include "spdy_bytes.h"
#include "spindly_phys.h"

/* Minimum length of a HEADERS frame. */
#define SPDY_HEADERS_MIN_LENGTH 8

#define SPDY2_HEADERS_HEADER_MIN_LENGTH 6
#define SPDY3_HEADERS_HEADER_MIN_LENGTH 4


int spdy_header_init(spdy_headers *headers,
                         uint32_t stream_id,
                         spdy_nv_block *nv_block)
{
	ASSERT_RET_VAL(headers, SPINDLYE_INVAL);

	headers->stream_id = stream_id;
	if (nv_block) {
		memcpy(&headers->nv_block, nv_block, sizeof(headers->nv_block));
	} else {
		memset(&headers->nv_block, 0, sizeof(headers->nv_block));
	}

	return SPDY_ERROR_NONE;
}

/**
 * Parse the header of a HEADERS control frame.
 * This function can be used to parse the header of a HEADERS frame
 * before the whole NV block has been received.
 * @param hdr - Destination frame.
 * @param data - Data to parse.
 * @param version - The version number of the SPDY protocol.
 * @return 0 on success, 01 on failure.
 */
int spdy_headers_parse_header(spdy_headers *hdr, spdy_data *data,
									uint16_t version)
{
	size_t length = data->data_end - data->cursor;
	if (version == SPINDLY_SPDYVER2) {
		if(length < SPDY2_HEADERS_HEADER_MIN_LENGTH) {
			SPDYDEBUG("Not enough data for parsing the header.");
			data->needed = SPDY2_HEADERS_HEADER_MIN_LENGTH - length;
			return SPDY_ERROR_INSUFFICIENT_DATA;
		}
	} else {
		if (length < SPDY3_HEADERS_HEADER_MIN_LENGTH) {
			SPDYDEBUG("Not enough data for parsing the header.");
			data->needed = SPDY3_HEADERS_HEADER_MIN_LENGTH - length;
			return SPDY_ERROR_INSUFFICIENT_DATA;
		}
	}

	/* Read the Stream-ID. */
	hdr->stream_id = BE_LOAD_32(data->cursor) & 0x7FFFFFFF;
	data->cursor += 4;

	/* Skip Stream-ID and 2 bytes of unused space. */
	if (version == SPINDLY_SPDYVER2)
		data->cursor += 2;

	return SPDY_ERROR_NONE;
}

/**
 * Parse a HEADERS control frame.
 * Parses the header of a HEADERS control frame and extracts the
 * NV block.
 * @param headers - Destination frame.
 * @param hash - streamid lookup
 * @param data - Data to parse.
 * @param frame_length - Length of the frame.
 * @param version - The version number of the SPDY protocol.
 * @see SPDY_SYN_STREAM_MIN_LENGTH
 * @return 0 on success, -1 on failure.
 */
int spdy_headers_parse(spdy_headers *headers,
                       struct spindly_phys *phys,
                       spdy_data *data,
                       uint32_t frame_length,
                       uint16_t version)
{
	int ret;
	int header_len;
	size_t length = data->data_end - data->cursor;

	if (length < SPDY_HEADERS_MIN_LENGTH) {
		data->needed = SPDY_HEADERS_MIN_LENGTH - length;
		SPDYDEBUG("Not enough data for parsing the frame.");
		return SPDY_ERROR_INSUFFICIENT_DATA;
	}

	if ((ret = spdy_headers_parse_header(headers, data, version)) != SPDY_ERROR_NONE) {
		SPDYDEBUG("Failed to parse header.");
		return ret;
	}
	/* Init NV block. */
	ret = spdy_nv_block_init(&headers->nv_block);
	if (ret) {
		return ret;
	}

	if (version == SPINDLY_SPDYVER2)
		header_len = SPDY2_HEADERS_HEADER_MIN_LENGTH;
	else
		header_len = SPDY3_HEADERS_HEADER_MIN_LENGTH;


	/* Parse NV block. */
	ret = spdy_nv_block_inflate_parse(&headers->nv_block,
	                                data->cursor,
	                                frame_length - header_len,
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
 * Pack HEADERS into an output buffer for transmitting.
 */
int spdy_header_pack(struct spindly_phys * phys,unsigned char **out,
                         size_t *outsize, spdy_headers *hdr)
{
	char *buf = NULL;
	size_t consumed=0;
	unsigned char *deflated=NULL;
	size_t deflated_length=0;
	int rc;
	int i =0;
	char *dest;
	size_t dest_size;

	rc = spdy_nv_block_pack(&dest, &dest_size, &(hdr->nv_block), phys->protver);
	if (rc)
		goto fail;

	rc = spdy_zlib_deflate(&phys->zlib_out,dest, dest_size, &consumed, &deflated, &deflated_length, phys->protver);
	if (rc)
		goto fail;
	if (phys->protver == SPINDLY_SPDYVER2)
		*outsize = SPDY2_HEADERS_HEADER_MIN_LENGTH;
	else
		*outsize = SPDY3_HEADERS_HEADER_MIN_LENGTH;


	buf = MALLOC(phys, (SPDY_HEADER+ (*outsize) + deflated_length));
	if (buf == NULL) {
		rc = SPDY_ERROR_MALLOC_FAILED;
		goto fail;
	}
	*out = buf;
	buf += SPDY_HEADER;

	BE_STORE_32(buf, hdr->stream_id);
	buf += 4;

	if (phys->protver == SPINDLY_SPDYVER2) {
		BE_STORE_16(buf, 0); /* 16 bits unused */
		buf += 2;
	}

	/* create the NV block to include */
	SPDYDEBUG("deflated_length %d.", deflated_length);
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
void spdy_header_destroy(spdy_headers *headers)
{
	spdy_nv_block_destroy(&headers->nv_block);
}
