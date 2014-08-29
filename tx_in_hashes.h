#ifndef PETTYCOIN_TX_IN_HASHES_H
#define PETTYCOIN_TX_IN_HASHES_H
#include "config.h"
#include <ccan/short_types/short_types.h>

struct state;
struct block;
struct txhash;
struct protocol_tx_id;

void add_txhash_to_hashes(struct state *state,
			  const tal_t *ctx,
			  struct block *block, u16 shard, u8 txoff,
			  const struct protocol_tx_id *txhash);

void add_tx_to_hashes(struct state *state,
		      const tal_t *ctx,
		      struct block *block, u16 shard, u8 txoff,
		      const union protocol_tx *tx);

void add_pending_tx_to_hashes(struct state *state,
			      const tal_t *ctx,
			      const union protocol_tx *tx);

void remove_pending_tx_from_hashes(struct state *state,
				   const union protocol_tx *tx);

/* It was a hash, now we found the tx. */
void upgrade_tx_in_hashes(struct state *state,
			  const tal_t *ctx,
			  const struct protocol_tx_id *sha,
			  const union protocol_tx *tx);

void remove_tx_from_hashes(struct state *state,
			   struct block *block, u16 shard, u8 txoff);

/* Get the transaction, in block <= this block. */
struct txhash_elem *txhash_gettx_ancestor(struct state *state,
					  const struct protocol_tx_id *sha,
					  const struct block *block);

/* Get the transaction, if it's pending. */
const union protocol_tx *
txhash_get_pending_tx(struct state *state,
		      const struct protocol_tx_id *sha);

const union protocol_tx *txhash_tx(const struct txhash_elem *te);

#endif /* PETTYCOIN_TX_IN_HASHES_H */
