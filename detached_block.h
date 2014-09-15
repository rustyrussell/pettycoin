#ifndef PETTYCOIN_DETACHED_BLOCK_H
#define PETTYCOIN_DETACHED_BLOCK_H
#include "config.h"
#include <stdbool.h>

struct block;
struct state;
struct protocol_block_id;
struct block_info;
struct protocol_pkt_block;

void seek_detached_blocks(struct state *state, const struct block *block);

bool have_detached_block(const struct state *state, 
			 const struct protocol_block_id *sha);

void add_detached_block(struct state *state,
			const tal_t *pkt_ctx,
			const struct protocol_block_id *sha,
			const struct block_info *bi);

#endif /* PETTYCOIN_DETACHED_BLOCK_H */
