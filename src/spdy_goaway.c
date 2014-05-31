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
#include "spdy_goaway.h"
#include "spdy_log.h"
#include "spdy_error.h"
#include "spdy_bytes.h"
#include "spdy_frame.h"

#include <netinet/in.h>

/* Length of a GOAWAY frame. (No minimum length - the length
 * of a GOAWAY frame is always 8. */
#define SPDY2_GOAWAY_LENGTH 4
#define SPDY3_GOAWAY_LENGTH 8

int spdy_goaway_init(spdy_goaway *str)
{
	ASSERT_RET_VAL(str, SPINDLYE_INVAL);

	str->stream_id = 0;
	str->status_code = 0;
	return SPDY_ERROR_NONE;
}


/*
 * Pack GOAWAY into an output buffer for transmitting.
 */
int spdy_goaway_pack(struct spindly_phys* phys, unsigned char **out,
                         size_t *outsize, spdy_goaway *str)
{
	char *buf = NULL;

	if(phys->protver == SPINDLY_SPDYVER2)
		*outsize = SPDY2_GOAWAY_LENGTH;
	else
		*outsize = SPDY3_GOAWAY_LENGTH;

	buf = ALLOC((*outsize)+SPDY_HEADER);
	if (buf == NULL) {
		*out = NULL;
		*outsize = 0;
		return SPDY_ERROR_MALLOC_FAILED;
	}
	*out = buf;
	buf += SPDY_HEADER;

	/* Add the Stream-ID. */
	BE_STORE_32(buf, str->stream_id);
	buf+=4;

	/* Add the status code. only in spdly3*/
	if (phys->protver == SPINDLY_SPDYVER3) {
		BE_STORE_32(buf, str->status_code);
		buf+=4;
	}
	return SPDY_ERROR_NONE;
}


/**
 * Parse a GOAWAY control frame.
 * @param goaway - Destination frame.
 * @param data - Data to parse.
 * @param data_length - Length of data.
 * @param version - The version number of the SPDY protocol.
 * @see spdy_goaway
 * @see SPDY_GOAWAY_LENGTH
 * @return 0 on success, -1 on failure.
 */
int spdy_goaway_parse(spdy_goaway *goaway, spdy_data *data,
                          size_t data_length, uint16_t version)
{
	if (version == SPINDLY_SPDYVER2) {
		if (data_length != SPDY2_GOAWAY_LENGTH) {
			SPDYDEBUG("Not enough data for parsing the header.");
			return SPDY_ERROR_INSUFFICIENT_DATA;
		}
	} else {
		if(data_length != SPDY3_GOAWAY_LENGTH) {
			SPDYDEBUG("Not enough data for parsing the header.");
			return SPDY_ERROR_INSUFFICIENT_DATA;
		}
	}

	spdy_goaway_init(goaway);
	/* Read the Stream-ID. */
	goaway->stream_id = BE_LOAD_32(data->cursor) & 0x7FFFFFFF;
	/* Read the status code. */
	data->cursor+=4;
	if (version == SPINDLY_SPDYVER3) {
		goaway->status_code = BE_LOAD_32(data->cursor);
		data->cursor+=4;
	}
	SPDYDEBUG("status %d stream %d version %d\n",
					goaway->status_code,
					goaway->stream_id,
					version);

	return SPDY_ERROR_NONE;
}

/*
 * Destroy/free all data this struct has allocated.
 */
void spdy_goaway_destroy(spdy_goaway *goaway)
{
	/*nothing to do */
}

