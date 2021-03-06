#ifndef PETTYCOIN_PREV_BLOCKS_H
#define PETTYCOIN_PREV_BLOCKS_H
#include "config.h"
#include "protocol.h"

struct block;
void make_prev_blocks(const struct block *prev,
		      struct protocol_block_id prevs[PROTOCOL_NUM_PREV_IDS]);

unsigned int num_prevs(const struct protocol_block_header *hdr);
#endif /* PETTYCOIN_PREV_BLOCKS_H */
