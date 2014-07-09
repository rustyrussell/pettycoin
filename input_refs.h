#ifndef PETTYCOIN_INPUT_REFS_H
#define PETTYCOIN_INPUT_REFS_H
#include "config.h"
#include "protocol_ecode.h"

struct state;
struct block;
union protocol_tx;
struct protocol_input_ref;

/* This simply checks that refs are sane with what every node should know */
enum protocol_ecode check_refs(struct state *state,
			       const struct block *block,
			       const struct protocol_input_ref *refs,
			       unsigned int num_refs);

/* This actually does the lookup, makes sure ref is what we expected. */
enum ref_ecode {
	ECODE_REF_OK,
	/* Ref is unknown. */
	ECODE_REF_UNKNOWN,
	/* Hash of that tx is not what input was expecting. */
	ECODE_REF_BAD_HASH
};

/* You must have called check_refs() to check for obvious errors. */
enum ref_ecode check_tx_refs(struct state *state,
			     const struct block *block,
			     const union protocol_tx *tx,
			     const struct protocol_input_ref *refs,
			     unsigned int *bad_ref,
			     struct block **block_referred_to);

#endif /* PETTYCOIN_INPUT_REFS_H */
