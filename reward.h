#ifndef PETTYCOIN_REWARD_H
#define PETTYCOIN_REWARD_H
#include "config.h"
#include <stdbool.h>

struct state;
struct block;

/* Returns false if we for_block is empty, or reward tx not yet known */
bool reward_get_tx(struct state *state,
		   const struct block *reward_block,
		   const struct block *claim_block,
		   u16 *shardnum, u8 *txoff);

/* If tx is the reward tx for block, how much is reward? */
u32 reward_amount(const struct block *reward_block,
		  const union protocol_tx *tx);

#endif /* PETTYCOIN_REWARD_H */
