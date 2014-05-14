#ifndef PETTYCOIN_MERKLE_TRANSACTIONS_H
#define PETTYCOIN_MERKLE_TRANSACTIONS_H
#include <stddef.h>
#include "protocol.h"

/* Merkle together a batch of transactions */
void merkle_transactions(const void *prefix, size_t prefix_len,
			 const union protocol_transaction *const*t,
			 const struct protocol_input_ref *const*refs,
			 size_t num_trans,
			 struct protocol_double_sha *merkle);

/* For generator, which already has them as hashes. */
void merkle_transaction_hashes(const struct protocol_double_sha **hashes,
			       size_t num_hashes,
			       struct protocol_double_sha *merkle);

#endif /* PETTYCOIN_MERKLE_TRANSACTIONS_H */


