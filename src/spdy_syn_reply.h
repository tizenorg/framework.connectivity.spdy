#ifndef SPDY_SYN_REPLY_H_
#define SPDY_SYN_REPLY_H_ 1

#include "spdy_data.h"
#include "spdy_nv_block.h"
#include "spdy_zlib.h"

#include <stdint.h>

struct spindly_phys;

/**
 * Flags for SYN_REPLY frames.
 */
enum SPDY_SYN_REPLY_FLAGS
{
	SPDY_SYN_REPLY_FLAG_FIN = 0x01        /*!< FLAG_FIN */
};

/**
 * SYN_REPLY control frame
 */
typedef struct
{
	uint32_t stream_id;           /*!< 31 bit stream id */
	spdy_nv_block nv_block;       /*!< Name/Value block */
} spdy_syn_reply;

/**
 * Parse the header of a SYN_REPLY control frame.
 * This function can be used to parse the header of a SYN_REPLY frame
 * before the whole NV block has been received.
 * @param syn_reply - Destination frame.
 * @param data - Data to parse.
 * @param version - The version number of the SPDY protocol.
 * @see SPDY_SYN_REPLY_HEADER_MIN_LENGTH
 * @return 0 on success, 01 on failure.
 */
int spdy_syn_reply_parse_header(spdy_syn_reply *syn_reply, spdy_data *data,
									uint16_t version);
/**
 * Parse a SYN_REPLY control frame.
 * Parses the header of a SYN_REPLY control frame and extracts the
 * NV block.
 * @param syn_reply - Destination frame.
 * @param hash - streamid lookup
 * @param data - Data to parse.
 * @param frame_length - Length of the frame.
 * @param version - The version number of the SPDY protocol.
 * @see SPDY_SYN_STREAM_MIN_LENGTH
 * @return 0 on success, -1 on failure.
 */
int spdy_syn_reply_parse(spdy_syn_reply *syn_reply,
                         struct spindly_phys *phys,
                         spdy_data *data,
                         uint32_t frame_length,
                         uint16_t version);

int spdy_syn_reply_pack(struct spindly_phys* phys,unsigned char **out,
                        size_t *outsize, spdy_syn_reply *rep);
void spdy_syn_reply_destroy(spdy_syn_reply *syn_reply);

#endif
