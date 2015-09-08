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

#ifndef SPDY_WNDUP_H_
#define SPDY_WNDUP_H_ 1

#include "spdy_data.h"

#include <stdint.h>
#include <stdlib.h>


/**
 * GOAWAY control frame
 */
typedef struct
{
	uint32_t stream_id;           /*!< 31 bit stream id */
	uint32_t size;         /*!< 32 bit status code */
} spdy_wndup;

int spdy_wndup_init(spdy_wndup *wndup);

/*
 * Pack GOAWAY into an output buffer for transmitting.
 */
int spdy_wndup_pack(struct spindly_phys* phys, unsigned char **out,
                         size_t *outsize, spdy_wndup *str);

/**
 * Parse a GOAWAY control frame.
 * @param wndup - Destination frame.
 * @param data - Data to parse.
 * @param data_length - Length of data.
 * @param version - The version number of the SPDY protocol.
 * @see spdy_wndup
 * @see SPDY_GOAWAY_LENGTH
 * @return 0 on success, -1 on failure.
 */
int spdy_wndup_parse(spdy_wndup *wndup, spdy_data *data,
                          size_t data_length, uint16_t version);
/*
 * Destroy/free all data this struct has allocated.
 */
void spdy_wndup_destroy(spdy_wndup *wndup);

#endif
