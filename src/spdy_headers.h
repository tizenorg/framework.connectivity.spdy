#ifndef SPDY_HEADERS_H_
#define SPDY_HEADERS_H_

#include "spdy_data.h"
#include "spdy_zlib.h"
#include "spdy_nv_block.h"

struct spindly_phys;

/**
 * Flags for HEADERS frames.
 */
enum SPDY_HEADERS_FLAGS
{
	SPDY_HEADERS_FLAG_FIN = 0x01        /*!< FLAG_FIN */
};


typedef struct
{
	uint32_t stream_id;           /*!< 31 bit stream_id */
	spdy_nv_block nv_block;
} spdy_headers;

int spdy_header_init(spdy_headers *headers,
                         uint32_t stream_id,
                         spdy_nv_block *nv_block);

int spdy_headers_parse(spdy_headers *headers, struct spindly_phys *phys,
                       spdy_data *data,
                       uint32_t frame_length,
                       uint16_t version);

/*
 * Pack HEADERS into an output buffer for transmitting.
 */
int spdy_header_pack(struct spindly_phys * phys,unsigned char **out,
                         size_t *outsize, spdy_headers *hdr);
/*
 * Destroy/free all data this struct has allocated.
 */
void spdy_header_destroy(spdy_headers *headers);
#endif
