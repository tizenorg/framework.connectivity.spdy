#ifndef SPDY_ZLIB_H_
#define SPDY_ZLIB_H_

#include <stdint.h>
#include <stdlib.h>
#include <zlib.h>

/**
 * Context for zlib deflating and inflating.
 * Allows to use the same zlib stream on multiple frames. (Needed
 * for inflating multiple compressed headers on a SPDY stream.)
 */
typedef struct
{
	z_stream stream;              /*!< zlib stream */
} spdy_zlib_context;

int spdy_zlib_deflate_init(spdy_zlib_context *ctx);
void spdy_zlib_deflate_end(spdy_zlib_context *ctx);
/**
 * Deflate data as used in the header compression of spdy.
 * @param src - Data to deflate
 * @param length - Length of data
 * @param data_used - Amount of data used by zlib.
 * @param dest - Destination of deflated data
 * @param dest_size - Pointer to size of deflated data.
 * @param version - The version number of the SPDY protocol.
 * @see spdy_zlib_inflate
 * @return Errorcode
 */
int spdy_zlib_deflate(spdy_zlib_context *ctx,char *src, uint32_t length, size_t *data_used,
                     unsigned char **dest, size_t *dest_size, uint16_t version);

int spdy_zlib_inflate_init(spdy_zlib_context *ctx);
void spdy_zlib_inflate_end(spdy_zlib_context *ctx);
/**
 * Inflate data as used in the header compression of spdy.
 * @param ctx - Compression context
 * @param src - Data to inflate
 * @param length - Length of data
 * @param dest - Destination of inflated data
 * @param dest_size - Pointer to size of inflated data.
 * @param version - The version number of the SPDY protocol.
 * @see spdy_zlib_deflate
 * @return Errorcode
 */
int spdy_zlib_inflate(spdy_zlib_context *ctx,
                      char *src,
                      uint32_t length, char **dest, size_t *dest_size,
                      uint16_t version);

#endif
