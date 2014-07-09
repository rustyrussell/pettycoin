#ifndef PETTYCOIN_PENDING_H
#define PETTYCOIN_PENDING_H
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include "protocol.h"
#include "block.h"

struct pending_tx {
	const union protocol_tx *tx;
	struct protocol_input_ref *refs; /* num_inputs(t) array */
};

/* aka state->pending */
struct pending_block {
	u8 *prev_txhashes;
	/* FIXME: make this [num_shards(state->preferred_chain)]! */
	u32 pending_counts[1 << PROTOCOL_INITIAL_SHARD_ORDER];
	/* Available for the next block. */
	struct pending_tx **pend[1 << PROTOCOL_INITIAL_SHARD_ORDER];
};

struct state;
struct peer;
struct block;
struct protocol_tx_gateway;

/* This block is no longer on favoured chain.  Get transactions out. */
void steal_pending_txs(struct state *state,
		       const struct block *old,
		       const struct block *new);

/* Add a new transaction from peer to the current block. */
void add_pending_tx(struct peer *peer, const union protocol_tx *tx);

/* Get a new working block. */
struct pending_block *new_pending_block(struct state *state);

/* Look through pending to find if we have this tx & ref hash */
struct txptr_with_ref
find_pending_tx_with_ref(const tal_t *ctx,
			 struct state *state,
			 const struct block *block,
			 u16 shard,
			 const struct protocol_net_txrefhash *hash);
#endif /* PETTYCOIN_PENDING_H */
