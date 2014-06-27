#include "merkle_txs.h"
#include "merkle_recurse.h"
#include "tx.h"
#include "hash_tx.h"
#include "protocol.h"
#include "block_shard.h"
#include <assert.h>
#include <string.h>
#include <ccan/tal/tal.h>

struct merkle_txinfo {
	const void *prefix;
	size_t prefix_len;
	const struct block *block;
	const struct block_shard *shard;
};

static void merkle_tx(size_t n, void *data, struct protocol_double_sha *merkle)
{
	struct merkle_txinfo *info = data;
	struct protocol_net_txrefhash scratch;
	const struct protocol_net_txrefhash *h;

	h = txrefhash_in_shard(info->block, info->shard, n, &scratch);
	merkle_two_hashes(&h->txhash, &h->refhash, merkle);
}

void merkle_txs(const void *prefix, size_t prefix_len,
		const struct block *block,
		const struct block_shard *shard,
		size_t off, size_t num_txs,
		struct protocol_double_sha *merkle)
{
	struct merkle_txinfo txinfo;

	txinfo.prefix = prefix;
	txinfo.prefix_len = prefix_len;
	txinfo.block = block;
	txinfo.shard = shard;

	merkle_recurse(off, num_txs, 256, merkle_tx, &txinfo, merkle);
}
