#ifndef PETTYCOIN_HASH_TRANSACTION_H
#define PETTYCOIN_HASH_TRANSACTION_H
#include <stddef.h>

union protocol_transaction;
struct protocol_double_sha;
struct protocol_input_ref;

/* Get txhash, by which we refer to transaction. */
void hash_tx(const union protocol_transaction *t,
	     struct protocol_double_sha *sha);

/* Get hash for merkle hash into block (include refs if num_refs != 0). */
void hash_tx_for_block(const union protocol_transaction *t,
		       const void *hash_prefix,
		       size_t hash_prefix_len,
		       const struct protocol_input_ref *refs,
		       size_t num_refs,
		       struct protocol_double_sha *sha);

#endif /* PETTYCOIN_HASH_TRANSACTION_H */
