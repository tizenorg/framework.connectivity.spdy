#ifndef SPDY_SYN_STREAM_H_
#define SPDY_SYN_STREAM_H_ 1

#include "spdy_data.h"
#include "spdy_nv_block.h"
#include "spdy_zlib.h"

#include <stdint.h>
#include <stdlib.h>

struct spindly_phys;

/**
 * Flags for SYN_STREAM frames.
 */
enum SPDY_SYN_STREAM_FLAGS
{
	SPDY_SYN_STREAM_FLAG_FIN = 0x01,      /*!< FLAG_FIN */
	SPDY_SYN_STREAM_FLAG_UNIDIRECTIONAL = 0x02    /*!< FLAG_UNIDIRECTIONAL */
};

/**
 * SYN_STREAM control frame
 */
typedef struct
{
	uint32_t stream_id;           /*!< 31 bit stream id */
	uint32_t associated_to;       /*!< 31 bit assocaited to stream id */
	int priority;                 /*!< 3 bit priority */
	int slot;                 /*!< 8 bit slot, only in spdy3, index in the server's CREDENTIAL vector */
	spdy_nv_block nv_block;       /*!< Name/Value block */
} spdy_syn_stream;

/**
 * Parse the header of a SYN_STREAM control frame.
 * This function can be used to parse the header of a SYN_STREAM frame
 * before the whole NV block has been received. (Minimum of bytes needed
 * is stored in SPDY_SYN_STREAM_HEADER_MIN_LENGTH.)
 * @param syn_stream - Destination frame.
 * @param data - Data to parse.
 * @param version - The version number of the SPDY protocol.
 * @see SPDY_SYN_STREAM_HEADER_MIN_LENGTH
 * @return Errorcode
 */
int spdy_syn_stream_parse_header(spdy_syn_stream *syn_stream, spdy_data *data,
										uint16_t version);
/**
 * Parse a SYN_STREAM control frame.
 * Parses the header of a SYN_STREAM control frame and extracts the
 * NV block.
 * @param syn_stream - Destination frame.
 * @param hash - Streamid lookup
 * @param data - Data to parse.
 * @param frame_length - Length of the frame.
 * @param version - The version number of the SPDY protocol.
 * @see spdy_control_frame
 * @see SPDY_SYN_STREAM_MIN_LENGTH
 * @return 0 on success, -1 on failure.
 */
int spdy_syn_stream_parse(spdy_syn_stream *syn_stream,
                          struct spindly_phys *phys,
                          spdy_data *data,
                          uint32_t frame_length,
                          uint16_t version);
void spdy_syn_stream_destroy(spdy_syn_stream *syn_stream);

int spdy_syn_stream_pack(struct spindly_phys * phys,unsigned char **out,
                         size_t *outsize, spdy_syn_stream *str);

int spdy_syn_stream_init(spdy_syn_stream *str, uint32_t stream_id,
                         uint32_t associated_to, int prio,
                         spdy_nv_block *nv_block);
#endif
