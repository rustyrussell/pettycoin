#ifndef PETTYCOIN_CREATE_REFS_H
#define PETTYCOIN_CREATE_REFS_H

struct state;
struct block;
union protocol_transaction;

struct protocol_input_ref *create_refs(struct state *state,
				       const struct block *prev_block,
				       const union protocol_transaction *tx);

#endif /* PETTYCOIN_CREATE_REFS_H */
