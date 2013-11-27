#ifndef PETTYCOIN_MERKLE_TRANSACTIONS_H
#define PETTYCOIN_MERKLE_TRANSACTIONS_H
#include <stddef.h>
#include "protocol.h"

/* Merkle together a batch of transactions */
void merkle_transactions(const void *prefix, size_t prefix_len,
			 union protocol_transaction **t,
			 size_t num_trans,
			 struct protocol_double_sha *merkle);

/* For generator, which already has them as hashes. */
void merkle_transaction_hashes(const struct protocol_double_sha **hashes,
			       size_t num_hashes,
			       struct protocol_double_sha *merkle);

/* Given this number of transactions, how many merkle hashes/batches? */
static inline size_t num_merkles(u64 num_transactions)
{
	return (num_transactions + (1<<PETTYCOIN_BATCH_ORDER) - 1)
		>> PETTYCOIN_BATCH_ORDER;
}

#endif /* PETTYCOIN_MERKLE_TRANSACTIONS_H */


