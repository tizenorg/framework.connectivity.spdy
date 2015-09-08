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

#ifndef SPDY_IV_BLOCK_H_
#define SPDY_IV_BLOCK_H_ 1

#include <stdint.h>
#include <stdlib.h>

#include "spdy_zlib.h"

typedef struct spdy_iv_pair spdy_iv_pair;
typedef struct spdy_iv_block spdy_iv_block;

/**
 * Id/Flag/Value Pair
 * Contains the Id and the values of a single Id/Flag/Value pair.
 */
struct spdy_iv_pair
{
	uint32_t id;                   /*!< Id of the value 24bit*/
	uint8_t flag;     /*!< flag of the id 8bit*/
	uint32_t value;                 /*!< Value */
};

/**
 * Id/Value Header Block
 * Structure for holding data from a id/value header like in
 * in SYN_STREAM and SYN_REPLY.
 */
struct spdy_iv_block
{
	uint8_t has_count;          /*!< Determines if the count has been parsed. */
	int count;               /*!< Number of Id/Value pairs */
	int pairs_parsed;        /*!< Number of pairs that have been parsed. */
	spdy_iv_pair *pairs;     /*!< Array of Id/Value pairs */
};


/* IV pair functions */
int spdy_iv_pair_create(spdy_iv_pair **pair);
int spdy_iv_pair_init(spdy_iv_pair *pair);
int spdy_iv_pair_destroy(spdy_iv_pair **pair);

/* IV block functions */
int spdy_iv_block_init(spdy_iv_block *block);

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
                        size_t data_length, uint16_t version);
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
						spdy_iv_block	 *iv_block, uint16_t version);
void spdy_iv_block_destroy(spdy_iv_block *iv_block);

#endif
