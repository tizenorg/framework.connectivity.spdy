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

#ifndef SPDY_GOAWAY_H_
#define SPDY_GOAWAY_H_ 1

#include "spdy_data.h"

#include <stdint.h>
#include <stdlib.h>

/**
 * SPDY Status codes as used in GOAWAY frames.
 */
enum SPDY_GOAWAY_STATUS_CODES
{
	SPDY_STATUS_OK = 0,      /*!< PROTOCOL_ERROR */
	SPDY_GOAWAY_PROTOCOL_ERROR = 1,      /*!< PROTOCOL_ERROR */
	SPDY_GOAWAY_INTERNAL_ERROR = 11,      /*!< INTERNAL ERROR */
};

/**
 * GOAWAY control frame
 */
typedef struct
{
	uint32_t stream_id;           /*!< 31 bit stream id */
	uint32_t status_code;         /*!< 32 bit status code */
} spdy_goaway;

int spdy_goaway_init(spdy_goaway *str);

/*
 * Pack GOAWAY into an output buffer for transmitting.
 */
int spdy_goaway_pack(struct spindly_phys* phys, unsigned char **out,
                         size_t *outsize, spdy_goaway *str);

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
                          size_t data_length, uint16_t version);
/*
 * Destroy/free all data this struct has allocated.
 */
void spdy_goaway_destroy(spdy_goaway *goaway);

#endif
