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

#ifndef SPDY_SETTING_H_
#define SPDY_SETTING_H_ 1

#include "spdy_data.h"
#include "spdy_iv_block.h"
#include "spdy_zlib.h"
#include <stdint.h>
#include <stdlib.h>

struct spindly_phys;

/**
 * Flags for SETTING frames.
 */
typedef enum
{
	SPDY_SETTING_FLAG_CLEAR_SETTINGS = 0x01        /*!< FLAG_CLEAR */
}SPDY_SETTING_FLAGS;

/**
 * Flags for SETTING ID/VALUE Pairs.
 */
typedef enum
{
	SPDY_SETTING_ID_FLAG_PERSIST_VALUE = 0x01,        /*!< FLAG_PERSIST_VALUE */
	SPDY_SETTING_ID_FLAG_PERSISTED = 0x02,        /*!< FLAG_PERSISTED */
}SPDY_SETTING_ID_FLAGS;

/**
 * Flags for SETTING IDs.
 */
typedef enum
{
	SPDY_SETTINGS_UPLOAD_BANDWIDTH,
	SPDY_SETTINGS_DOWNLOAD_BANDWIDTH,
	SPDY_SETTINGS_ROUND_TRIP_TIME,
	SPDY_SETTINGS_MAX_CONCURRENT_STREAMS,
	SPDY_SETTINGS_CURRENT_CWND,
	SPDY_SETTINGS_DOWNLOAD_RETRANS_RATE,
	SPDY_SETTINGS_INITIAL_WINDOW_SIZE,
	SPDY_SETTINGS_CLIENT_CERTIFICATE_VECTOR_SIZE, /*support only in spdy3*/
}SPDY_SETTING_ID;

/**
 * SETTING control frame
 */
typedef struct
{
	spdy_iv_block iv_block;       /*!< Id/Value block */
} spdy_setting;

int spdy_setting_parse_header(spdy_setting *setting, spdy_data *data);
int spdy_setting_parse(spdy_setting *setting,
                          struct spindly_phys *hash,
                          spdy_data *data,
                          uint32_t frame_length,
                          uint16_t version);

void spdy_setting_destroy(spdy_setting *setting);

int spdy_setting_pack(struct spindly_phys* phys, unsigned char **out,
                         size_t *outsize, spdy_setting *str);

int spdy_setting_init(spdy_setting *str, spdy_iv_block *iv_block);
#endif
