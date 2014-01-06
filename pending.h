#ifndef PETTYCOIN_PENDING_H
#define PETTYCOIN_PENDING_H
#include <ccan/short_types/short_types.h>

/* aka state->pending */
struct pending_block {
	struct block *prev;
	u8 *prev_merkles;
	const union protocol_transaction **t;
};

struct state;
struct block;
struct protocol_transaction_gateway;

/* This block is no longer on main chain.  Get transactions out. */
void steal_pending_transactions(struct state *state, const struct block *block);
void update_pending_transactions(struct state *state);

/* Add a gateway transaction to the pending block. */
void add_pending_gateway_transaction(struct state *state,
				     const struct protocol_transaction_gateway *hdr);

/* Get a new working block. */
struct pending_block *new_pending_block(struct state *state);

#endif /* PETTYCOIN_PENDING_H */
