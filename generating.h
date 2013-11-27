#ifndef PETTYCOIN_GENERATING_H
#define PETTYCOIN_GENERATING_H

struct state;
void start_generating(struct state *state);
void restart_generating(struct state *state);

/* Get a new working block. */
struct pending_block *new_pending_block(struct state *state);

struct protocol_transaction_gateway;
/* Add a gateway transaction to the pending block. */
void pending_gateway_transaction_add(struct state *state,
				const struct protocol_transaction_gateway *hdr);
#endif
