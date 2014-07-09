#include "merkle_txs.h"
#include "merkle_recurse.h"
#include "tx.h"
#include "hash_tx.h"
#include "protocol.h"
#include "block_shard.h"
#include "block.h"
#include <assert.h>
#include <string.h>
#include <ccan/tal/tal.h>

struct merkle_txinfo {
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

void merkle_some_txs(const struct block *block,
		     const struct block_shard *shard,
		     size_t off, size_t max,
		     struct protocol_double_sha *merkle)
{
	struct merkle_txinfo txinfo;

	txinfo.block = block;
	txinfo.shard = shard;

	merkle_recurse(off, num_txs_in_shard(block, shard->shardnum), max,
		       merkle_tx, &txinfo, merkle);
}

void merkle_txs(const struct block *block, const struct block_shard *shard,
		struct protocol_double_sha *merkle)
{
	merkle_some_txs(block, shard, 0, 256, merkle);
}
