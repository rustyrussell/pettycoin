#ifndef PETTYCOIN_CREATE_REFS_H
#define PETTYCOIN_CREATE_REFS_H
#include "config.h"

struct state;
struct block;
union protocol_tx;

struct protocol_input_ref *create_refs(struct state *state,
				       const struct block *block,
				       const union protocol_tx *tx,
				       int offset);

#endif /* PETTYCOIN_CREATE_REFS_H */
