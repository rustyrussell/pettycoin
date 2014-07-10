#ifndef PETTYCOIN_PREV_TXHASHES_H
#define PETTYCOIN_PREV_TXHASHES_H
#include "config.h"
#include "block.h"
#include <ccan/tal/tal.h>

/* We go back by powers of two from start.  So, S, S-1, S-2, S-4, S-8...
 * We're at S-1 already, so it's still powers of two backe relative each step */
#define for_each_prev_txhash(i, b, prev)			\
	for (i = 0, b = (prev);					\
	     i < PROTOCOL_PREV_BLOCK_TXHASHES && b;		\
	     b = block_ancestor(b, 1 << i), i++)

size_t num_prev_txhashes(const struct block *prev);

u8 *make_prev_txhashes(const tal_t *ctx, const struct block *prev,
		      const struct protocol_address *my_addr);

u8 prev_txhash(const struct protocol_address *addr,
	       const struct block *block, u16 shard);

#endif /* PETTYCOIN_PREV_TXHASHES_H */
