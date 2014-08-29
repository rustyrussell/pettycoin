#ifndef PETTYCOIN_PENDING_H
#define PETTYCOIN_PENDING_H
#include "config.h"
#include "block.h"
#include "protocol.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

struct pending_tx {
	const union protocol_tx *tx;
	struct protocol_input_ref *refs; /* num_inputs(t) array */
};

struct pending_unknown_tx {
	struct list_node list;
	const union protocol_tx *tx;
};

/* aka state->pending */
struct pending_block {
	/* FIXME: make this [num_shards(state->preferred_chain)]! */
	/* Available for the next block. */
	struct pending_tx **pend[1 << PROTOCOL_INITIAL_SHARD_ORDER];

	/* Has the chain changed? */
	bool needs_recheck;

	/* List of pending_unknown_tx. */
	struct list_head unknown_tx;
	unsigned int num_unknown;
};

struct state;
struct peer;
struct block;
struct protocol_tx_gateway;

/* Transfer any transactions we can from block. */
void block_to_pending(struct state *state, const struct block *block);

/* Make sure pending txs are OK. */
void recheck_pending_txs(struct state *state);

/* Add a new transaction from peer to the current block.  If it returns
 * ECODE_INPUT_BAD, too_old (if non-NULL) is true if it's because an input
 * is too close to horizon, or beyond. */
enum input_ecode add_pending_tx(struct state *state,
				const union protocol_tx *tx,
				const struct protocol_tx_id *sha,
				unsigned int *bad_input_num,
				bool *too_old, bool *already_known);

/* Get a new working block. */
struct pending_block *new_pending_block(struct state *state);

void drop_pending_tx(struct state *state, const union protocol_tx *tx);

size_t num_pending_known(struct state *state);
#endif /* PETTYCOIN_PENDING_H */
