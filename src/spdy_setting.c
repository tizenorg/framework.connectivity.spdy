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
#include <netinet/in.h>
#include <string.h>
#include "spdy_setting.h"
#include "spdy_log.h"
#include "spdy_error.h"
#include "spdy_bytes.h"
#include "spindly_phys.h"
#include "hash.h"

/* Minimum length of a SETTING frame. */
#define SPDY_SETTING_MIN_LENGTH 4

int spdy_setting_init(spdy_setting *str,
                         spdy_iv_block *iv_block)
{
	ASSERT_RET_VAL(str, SPDY_ERROR_INVALID_DATA);

	if (iv_block) {
		memcpy(&str->iv_block, iv_block, sizeof(str->iv_block));
	} else {
		memset(&str->iv_block, 0, sizeof(str->iv_block));
	}

	return SPDY_ERROR_NONE;
}

/**
 * Parse a SETTING control frame.
 * Parses the header of a SETTING control frame and extracts the
 * IV block.
 * @param setting - Destination frame.
 * @param hash - Streamid lookup
 * @param data - Data to parse.
 * @param frame_length - Length of the frame.
 * @param version - The version number of the SPDY protocol.
 * @see spdy_control_frame
 * @see SPDY_SETTING_MIN_LENGTH
 * @return 0 on success, -1 on failure.
 */
int spdy_setting_parse(spdy_setting *setting,
                          struct spindly_phys *phys,
                          spdy_data *data,
                          uint32_t frame_length,
                          uint16_t version)
{
	int ret;
	size_t length = data->data_end - data->cursor;
	struct hashnode *hn;

	ASSERT_RET_VAL(phys != NULL, SPDY_ERROR_INVALID_DATA);

	if (length < frame_length) {
		data->needed = frame_length - length;
		SPDYDEBUG("Not enough data for parsing the stream.");
		return SPDY_ERROR_INSUFFICIENT_DATA;
	}
	/* TODO: Optimize the double length check away. */
	if (length < SPDY_SETTING_MIN_LENGTH) {
		data->needed = SPDY_SETTING_MIN_LENGTH - length;
		SPDYDEBUG("Not enough data for parsing the stream.");
		return SPDY_ERROR_INSUFFICIENT_DATA;
	}

	/* Init IV block. */
	ret = spdy_iv_block_init(&setting->iv_block);
	if (ret)
		return ret;

	/* Parse IV block. */
	ret = spdy_iv_block_parse(&setting->iv_block, data->cursor, length, version);
	if (ret) {
		/* Clean up. */
		SPDYDEBUG("Failed to parse IV block.");
		return ret;
	}
	data->cursor += frame_length;

	return SPDY_ERROR_NONE;
}

/*
 * Pack SETTING into an output buffer for transmitting.
 */
int spdy_setting_pack(struct spindly_phys* phys, unsigned char **out,
                         size_t *outsize, spdy_setting *str)
{
	size_t consumed;
	int i =0;
	char *dest = NULL;
	char *buf = NULL;
	size_t dest_size;
	int rc;

	rc = spdy_iv_block_pack(&dest, &dest_size, &str->iv_block, phys->protver);
	if(rc)
		goto fail;

	*outsize = dest_size;
	buf = ALLOC(SPDY_HEADER+(*outsize));
	if (buf == NULL) {
		rc = SPDY_ERROR_MALLOC_FAILED;
		*outsize = 0;
		goto fail;
	}
	*out = buf;
	buf += SPDY_HEADER;
	memcpy(buf, dest, dest_size);
	rc = SPDY_ERROR_NONE;

fail:
	FREEIF(dest);
	return rc;
}

/*
 * Destroy/free all data this struct has allocated.
 */
void spdy_setting_destroy(spdy_setting *setting)
{
	spdy_iv_block_destroy(&setting->iv_block);
}
