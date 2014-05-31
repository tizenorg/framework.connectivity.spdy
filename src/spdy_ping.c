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
#include "spdy_ping.h"
#include "spdy_log.h"
#include "spdy_error.h"
#include "spdy_bytes.h"
#include "spdy_frame.h"

#include <netinet/in.h>

/* Length of a PING frame. (No minimum length - the length
 * of a PING frame is always 4. */
#define SPDY_PING_LENGTH 4

int spdy_ping_init(spdy_ping *str)
{
	ASSERT_RET_VAL(str, SPINDLYE_INVAL);

	str->id= 0;
	return SPDY_ERROR_NONE;
}


/*
 * Pack PING into an output buffer for transmitting.
 */
int spdy_ping_pack(struct spindly_phys* phys, unsigned char **out,
                         size_t *outsize, spdy_ping *str)
{
	char *buf = NULL;

	*outsize = SPDY_PING_LENGTH;
	buf = ALLOC((*outsize)+SPDY_HEADER);
	if (buf == NULL) {
		*out = NULL;
		*outsize = 0;
		return SPDY_ERROR_MALLOC_FAILED;
	}
	*out = buf;
	buf += SPDY_HEADER;

	/* Read the ID. */
	/*TODO send unique number, client initiates a ping, it must use an odd numbered ID*/
	BE_STORE_32(buf, str->id);

	return SPDY_ERROR_NONE;
}


/**
 * Parse a PING control frame.
 * @param ping - Destination frame.
 * @param data - Data to parse.
 * @param data_length - Length of data.
 * @see spdy_ping
 * @see SPDY_PING_LENGTH
 * @return 0 on success, -1 on failure.
 */
int spdy_ping_parse(spdy_ping *ping, spdy_data *data,
                          size_t data_length)
{
	if (data_length != SPDY_PING_LENGTH) {
		SPDYDEBUG("Not enough data for parsing the header.");
		return SPDY_ERROR_INSUFFICIENT_DATA;
	}

	/* Read the Stream-ID. */
	ping->id = BE_LOAD_32(data->cursor);
	data->cursor+=4;

	SPDYDEBUG("Id %d", ping->id);

	return SPDY_ERROR_NONE;
}

/*
 * Destroy/free all data this struct has allocated.
 */
void spdy_ping_destroy(spdy_ping *ping)
{
	/*nothing to do */
}

