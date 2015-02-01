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

#include "spdy_setup.h"
#include "spindly_phys.h"
#include "spdy_wndup.h"
#include "spdy_log.h"
#include "spdy_error.h"
#include "spdy_bytes.h"
#include "spdy_frame.h"

#include <netinet/in.h>

/* Length of a WNDUP frame. (No minimum length - the length
 * of a WNDUP frame is always 8. */
#define SPDY3_WNDUP_LENGTH 8

int spdy_wndup_init(spdy_wndup *str)
{
	ASSERT_RET_VAL(str, SPINDLYE_INVAL);

	str->stream_id = 0;
	str->size = 0;
	return SPDY_ERROR_NONE;
}


/*
 * Pack WNDUP into an output buffer for transmitting.
 */
int spdy_wndup_pack(struct spindly_phys* phys, unsigned char **out,
                         size_t *outsize, spdy_wndup *wndup)
{
	char *buf = NULL;

	*outsize = SPDY3_WNDUP_LENGTH;

	buf = ALLOC((*outsize)+SPDY_HEADER);
	if (buf == NULL) {
		*out = NULL;
		*outsize = 0;
		return SPDY_ERROR_MALLOC_FAILED;
	}
	*out = buf;
	buf += SPDY_HEADER;

	/* Add the Stream-ID. */
	BE_STORE_32(buf, wndup->stream_id);
	buf+=4;

	BE_STORE_32(buf, wndup->size);
	buf+=4;

	return SPDY_ERROR_NONE;
}

/**
 * Parse a WNDUP control frame.
 * @param wndup - Destination frame.
 * @param data - Data to parse.
 * @param data_length - Length of data.
 * @param version - The version number of the SPDY protocol.
 * @see spdy_wndup
 * @see SPDY_WNDUP_LENGTH
 * @return 0 on success, -1 on failure.
 */
int spdy_wndup_parse(spdy_wndup *wndup, spdy_data *data,
                          size_t data_length, uint16_t version)
{
	int s = 0;
	if(data_length != SPDY3_WNDUP_LENGTH) {
		SPDYDEBUG("Not enough data for parsing the header.");
		return SPDY_ERROR_INSUFFICIENT_DATA;
	}

	spdy_wndup_init(wndup);
	/* Read the Stream-ID. */
	wndup->stream_id = BE_LOAD_32(data->cursor) & 0x7FFFFFFF;
	/* Read the status code. */
	data->cursor+=4;
	if (version == SPINDLY_SPDYVER3) {
		wndup->size = BE_LOAD_32(data->cursor) & 0x7FFFFFFF;
		s = BE_LOAD_32(data->cursor);
		data->cursor+=4;
	}
	SPDYDEBUG("status %d [Old: %d] stream %d version %d\n",
					wndup->size,
					s,
					wndup->stream_id,
					version);

	return SPDY_ERROR_NONE;
}

/*
 * Destroy/free all data this struct has allocated.
 */
void spdy_wndup_destroy(spdy_wndup *wndup)
{
	/*nothing to do */
}

