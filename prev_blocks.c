#include "block.h"
#include "chain.h"
#include "prev_blocks.h"


void make_prev_blocks(const struct block *prev,
		      struct protocol_block_id prevs[PROTOCOL_NUM_PREV_IDS])
{
	unsigned int i;

	for (i = 0; i < PROTOCOL_NUM_PREV_IDS && prev; i++) {
		prevs[i] = prev->sha;
		prev = block_ancestor(prev, 1 << i);
	}
	memset(prevs+i, 0, sizeof(*prevs) * (PROTOCOL_NUM_PREV_IDS-i));
}
