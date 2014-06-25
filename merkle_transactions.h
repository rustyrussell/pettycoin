#ifndef PETTYCOIN_MERKLE_TRANSACTIONS_H
#define PETTYCOIN_MERKLE_TRANSACTIONS_H
#include <stddef.h>
#include "protocol.h"
#include "block.h"

/* Merkle together a shard of transactions */
void merkle_transactions(const void *prefix, size_t prefix_len,
			 const struct txptr_with_ref *txp,
			 size_t off, size_t num_trans,
			 struct protocol_double_sha *merkle);

/* For generator, which already has them as hashes. */
void merkle_transaction_hashes(const struct protocol_double_sha **hashes,
			       size_t off, size_t num_hashes,
			       struct protocol_double_sha *merkle);

#endif /* PETTYCOIN_MERKLE_TRANSACTIONS_H */


