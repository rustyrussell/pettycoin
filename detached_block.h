#ifndef PETTYCOIN_DETACHED_BLOCK_H
#define PETTYCOIN_DETACHED_BLOCK_H
#include "config.h"
#include <stdbool.h>

struct block;
struct state;
struct protocol_block_id;
struct protocol_block_header;
struct protocol_pkt_block;

void seek_detached_blocks(struct state *state, const struct block *block);

bool have_detached_block(const struct state *state, 
			 const struct protocol_block_id *sha);

void add_detached_block(struct state *state,
			const struct protocol_block_id *sha,
			const struct protocol_block_header *hdr,
			const struct protocol_pkt_block *pkt);

#endif /* PETTYCOIN_DETACHED_BLOCK_H */
