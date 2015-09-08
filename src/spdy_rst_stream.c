#include "spdy_setup.h"         /* MUST be the first header to include */
#include "spindly_phys.h"
#include "spdy_rst_stream.h"
#include "spdy_log.h"
#include "spdy_error.h"
#include "spdy_bytes.h"
#include "spdy_frame.h"

#include <netinet/in.h>

/* Length of a RST_STREAM frame. (No minimum length - the length
 * of a RST_STREAM frame is always 8. */
#define SPDY_RST_STREAM_LENGTH 8

int spdy_rst_stream_init(spdy_rst_stream *str)
{
	ASSERT_RET_VAL(str, SPINDLYE_INVAL);

	str->stream_id = 0;
	str->status_code = 0;
	return SPDY_ERROR_NONE;
}


/*
 * Pack RST_STREAM into an output buffer for transmitting.
 */
int spdy_rst_stream_pack(struct spindly_phys* phys, unsigned char **out,
                         size_t *outsize, spdy_rst_stream *str)
{
	char *buf = NULL;

	*outsize = SPDY_RST_STREAM_LENGTH;
	buf = ALLOC((*outsize)+SPDY_HEADER);
	if (buf == NULL) {
		*out = NULL;
		*outsize = 0;
		return SPDY_ERROR_MALLOC_FAILED;
	}
	*out = buf;
	buf += SPDY_HEADER;

	/* Read the Stream-ID. */
	BE_STORE_32(buf, str->stream_id);
	buf+=4;
	/* Read the status code. */
	BE_STORE_32(buf, str->status_code);
	buf+=4;

	return SPDY_ERROR_NONE;
}


/**
 * Parse a RST_STREAM control frame.
 * @param rst_stream - Destination frame.
 * @param data - Data to parse.
 * @param data_length - Length of data.
 * @see spdy_rst_stream
 * @see SPDY_RST_STREAM_LENGTH
 * @return 0 on success, -1 on failure.
 */
int spdy_rst_stream_parse(spdy_rst_stream *rst_stream, spdy_data *data,
                          size_t data_length)
{
	if (data_length != SPDY_RST_STREAM_LENGTH) {
		SPDYDEBUG("Not enough data for parsing the header.");
		return SPDY_ERROR_INSUFFICIENT_DATA;
	}

	/* Read the Stream-ID. */
	rst_stream->stream_id = BE_LOAD_32(data->cursor) & 0x7FFFFFFF;
	data->cursor+=4;
	/* Read the status code. */
	rst_stream->status_code = BE_LOAD_32(data->cursor);
	data->cursor+=4;

	SPDYDEBUG("status %d stream %d \n",
					rst_stream->status_code,
					rst_stream->stream_id);

	return SPDY_ERROR_NONE;
}

/*
 * Destroy/free all data this struct has allocated.
 */
void spdy_rst_stream_destroy(spdy_rst_stream *rst_stream)
{
	/*nothing to free as of now */
}

