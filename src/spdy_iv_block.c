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
#include "spdy_iv_block.h"
#include "spdy_log.h"
#include "spdy_error.h"
#include "spdy_bytes.h"

#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

/**
 * Allocate and initialize an IV pair.
 *
 * @param pair - Pair to create
 * @see spdy_iv_pair
 * @return Errorcode
 */
int spdy_iv_pair_create(spdy_iv_pair **pair)
{
	*pair = malloc(sizeof(spdy_iv_pair));
	if (!(*pair)) {
		return SPDY_ERROR_MALLOC_FAILED;
	}

	return spdy_iv_pair_init(*pair);
}

/**
 * Initialize an already allocated IV pair with sane default values.
 *
 * @param pair - Pair to initialize
 * @see spdy_iv_pair
 * @return Errorcode
 */
int spdy_iv_pair_init(spdy_iv_pair *pair)
{
	pair->id = 0;
	pair->flag = 0;
	pair->value = 0;
	return SPDY_ERROR_NONE;
}

/**
 * Destroy and free an IV pair created by spdy_iv_pair_create.
 *
 * @param pair - Pair to destroy
 * @see spdy_iv_pair
 * @return Errorcode
 */
int spdy_iv_pair_destroy(spdy_iv_pair **pair)
{
	/* Free id & value pairs */
	free(*pair);
	*pair = NULL;
	return SPDY_ERROR_NONE;
}


/**
 * Initialize an IV block.
 *
 * @param block - IV block to initialize
 * @see spdy_iv_block
 * @return Errorcode
 */
int spdy_iv_block_init(spdy_iv_block *block)
{
	block->has_count = 0;
	block->count = 0;
	block->pairs_parsed = 0;
	block->pairs = NULL;
	return SPDY_ERROR_NONE;
}

/**
 * Parse a Name/Value block payload.
 * @param block - Target block.
 * @param data - Data to parse.
 * @param data_length - Length of data.
 * @param version - The version number of the SPDY protocol.
 * @see spdy_iv_block
 * @todo Replace mallocs with a single one. (Speed up!)
 * @todo Freeing in the loop.
 * @todo Multiple value support.
 * @return Errorcode
 */
int spdy_iv_block_parse(spdy_iv_block *block, unsigned char *data,
                        size_t data_length, uint16_t version)
{
	/* The bounds of data. */
	unsigned char *data_max = data + data_length;

	/* For the for-loop: */

	/* Parsing block pair count */
	if (!block->has_count) {
		/* Data must at least contain the number of IV pairs. */
		if (data_length < 4) {
			SPDYDEBUG("Data to small.");
			return SPDY_ERROR_INSUFFICIENT_DATA;
		}

		/* Read the 32 bit integer containing the number of id/flag/value pairs. */
		block->count = BE_LOAD_32(data);
		block->has_count = 1;
		block->pairs_parsed = 0;
		/* Move forward by two bytes. */
		data += 4;
		if (block->count == 0) {
			block->pairs = NULL;
			return SPDY_ERROR_NONE;
		}

		/* Allocate memory for Name/Value pairs. */
		block->pairs = calloc(block->count, sizeof(spdy_iv_pair));
		/* Malloc failed */
		if (!block->pairs) {
			SPDYDEBUG("Malloc of pairs failed.");
			return SPDY_ERROR_MALLOC_FAILED;
		}
	}
	/* End of parsing block pair count */


	/* Loop through all pairs */
	for (; block->pairs_parsed < block->count; block->pairs_parsed++) {
		size_t size;
		spdy_iv_pair *pair;

		if (data + 8 > data_max) {
			SPDYDEBUG("Data to small.");
			return SPDY_ERROR_INSUFFICIENT_DATA;
		}

		pair = &block->pairs[block->pairs_parsed];
		/* Read id/flag/value */
		if (version == SPINDLY_SPDYVER2) {
			pair->id =BE_LOAD_LE_24(data);
			data += 3;
			pair->flag = *data;
			data += 1;
		} else {
			pair->flag = *data;
			data += 1;
			pair->id =BE_LOAD_24(data);
			data += 3;
		}
		pair->value = BE_LOAD_32(data);
		SPDYDEBUG("IV block pair IDV %d:%d:%d",pair->flag,pair->id,pair->value);
		data += 4;
	}

	return SPDY_ERROR_NONE;
}

/**
 * Pack a Name/Value block into a payload for transmitting.
 *
 * Note that this function returns an allocated string in 'dest'.
 *
 * @param dest - Destination buffer.
 * @param dest_size - Pointer for storing the size of the destination buffer.
 * @param iv_block - IV block to pack.
 * @param version - The version number of the SPDY protocol.
 * @see spdy_iv_block
 * @see spdy_iv_block_parse
 * @todo Multiple value support.
 * @return 0 on success, -1 on failure.
 */
int spdy_iv_block_pack(char **dest, size_t *dest_size,
						spdy_iv_block	 *iv_block, uint16_t version)
{
	int i;
	char *cursor;

	if(dest == NULL || dest_size == NULL) {
		SPDYDEBUG("Invalid data.");
		return SPDY_ERROR_INVALID_DATA;
	}

	*dest = NULL;
	*dest_size = 0;

	if(iv_block == NULL ||
		iv_block->count <= 0 ||
		iv_block->pairs == NULL) {
		SPDYDEBUG("No iv pairs.");
		return SPDY_ERROR_INVALID_DATA;
	}

	/* Two bytes for the number of pairs. */
	*dest_size += 4;
	/* Calculate the size needed for the ouput buffer. */
	*dest_size +=  iv_block->count*8;


	/* Allocate memory for dest */
	*dest = malloc(*dest_size);
	if (!*dest) {
		SPDYDEBUG("Memoy allocation failed.");
		return SPDY_ERROR_MALLOC_FAILED;
	}
	/* Cursor always points to the location in dest where we're working. */
	cursor = *dest;

	/* 2-bytes for the number of IV-pairs that follow. */
	BE_STORE_32(cursor, iv_block->count);
	cursor += 4;

	for (i = 0; i < iv_block->count; i++) {
		/* Clients MUST NOT request servers to use the persistence features of the SETTINGS frames,
		and servers MUST ignore persistence related flags sent by a client. */
		/*if(iv_block->pairs[i].id == SETTINGS_INITIAL_WINDOW_SIZE &&
			iv_block->pairs[i].value < MIN_WINDOW_SIZE)
			iv_block->pairs[i].value = MIN_WINDOW_SIZE;*/

		if(version == SPINDLY_SPDYVER2) {
			BE_STORE_LE_24(cursor, iv_block->pairs[i].id);
			cursor += 3;
			*cursor++ = iv_block->pairs[i].flag;
		} else {
			*cursor++ = iv_block->pairs[i].flag;
			BE_STORE_24(cursor, iv_block->pairs[i].id);
			cursor += 3;
		}

		BE_STORE_32(cursor, iv_block->pairs[i].value);
		cursor += 4;
		SPDYDEBUG("IV block pack IDV %d:%d:%d",
			iv_block->pairs[i].flag,iv_block->pairs[i].id,iv_block->pairs[i].value);
	}
	return SPDY_ERROR_NONE;
}

/**
 * Frees all the content of an iv_block and the iv_block itself.
 * @param iv_block - IV block to destroy.
 * @todo How to test this?
 */
void spdy_iv_block_destroy(spdy_iv_block *iv_block)
{
	if((iv_block) && (iv_block->pairs)) {
		free(iv_block->pairs);
	}
}
