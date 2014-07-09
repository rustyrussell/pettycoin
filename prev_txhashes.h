#ifndef PETTYCOIN_PREV_TXHASHES_H
#define PETTYCOIN_PREV_TXHASHES_H
#include <ccan/tal/tal.h>
#include "block.h"

size_t num_prev_txhashes(const struct block *prev);

u8 *make_prev_txhashes(const tal_t *ctx, const struct block *prev,
		      const struct protocol_address *my_addr);

u8 prev_txhash(const struct protocol_address *addr,
	       const struct block *block, u16 shard);

#endif /* PETTYCOIN_PREV_TXHASHES_H */
