#ifndef PETTYCOIN_MERKLE_TXS_H
#define PETTYCOIN_MERKLE_TXS_H
#include <stddef.h>
#include "protocol.h"
#include "block.h"

/* Merkle together a shard of transactions */
void merkle_txs(const void *prefix, size_t prefix_len,
		const bitmap *txp_or_hash,
		const union txp_or_hash *u,
		size_t off, size_t num_txs,
		struct protocol_double_sha *merkle);

/* For generator, which already has them as hashes. */
void merkle_tx_hashes(const struct protocol_double_sha **hashes,
		      size_t off, size_t num_hashes,
		      struct protocol_double_sha *merkle);

#endif /* PETTYCOIN_MERKLE_TXS_H */


