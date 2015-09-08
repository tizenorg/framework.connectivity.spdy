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

#ifndef SPDY_PING_H_
#define SPDY_PING_H_ 1

#include "spdy_data.h"

#include <stdint.h>
#include <stdlib.h>

/**
 * PING control frame
 */
typedef struct
{
	uint32_t id;           /*!< 32 bit id */
} spdy_ping;

int spdy_ping_init(spdy_ping *str);

/*
 * Pack PING into an output buffer for transmitting.
 */
int spdy_ping_pack(struct spindly_phys* phys, unsigned char **out,
                         size_t *outsize, spdy_ping *str);

int spdy_ping_parse(spdy_ping *ping, spdy_data *data,
                          size_t data_length);

/*
 * Destroy/free all data this struct has allocated.
 */
void spdy_ping_destroy(spdy_ping *ping);

#endif
