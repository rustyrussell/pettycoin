#ifndef PETTYCOIN_HASH_TRANSACTION_H
#define PETTYCOIN_HASH_TRANSACTION_H
#include <stddef.h>

union protocol_transaction;
struct protocol_double_sha;

void hash_transaction(const union protocol_transaction *t,
		      const void *hash_prefix,
		      size_t hash_prefix_len,
		      struct protocol_double_sha *sha);

#endif /* PETTYCOIN_HASH_TRANSACTION_H */
