#ifndef PETTYCOIN_MERKLE_TXS_H
#define PETTYCOIN_MERKLE_TXS_H
#include <ccan/short_types/short_types.h>
#include <stddef.h>

struct block;
struct block_shard;
struct protocol_double_sha;

/* Merkle together (some part of) a shard of transactions */
void merkle_txs(const void *prefix, size_t prefix_len,
		const struct block *block,
		const struct block_shard *shard,
		size_t off, size_t num_txs,
		struct protocol_double_sha *merkle);

#endif /* PETTYCOIN_MERKLE_TXS_H */


