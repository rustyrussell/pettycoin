#include "block_shard.h"
#include "tx.h"
#include "block.h"
#include "shard.h"
#include <assert.h>

/* For compactness, struct block_shard needs tx and refs adjacent. */
struct txptr_with_ref txptr_with_ref(const tal_t *ctx,
				     const union protocol_tx *tx,
				     const struct protocol_input_ref *refs)
{
	struct txptr_with_ref txp;
	size_t txlen, reflen;
	char *p;

	txlen = marshal_tx_len(tx);
	reflen = num_inputs(tx) * sizeof(struct protocol_input_ref);

	p = tal_alloc_(ctx, txlen + reflen, false, "txptr_with_ref");
	memcpy(p, tx, txlen);
	memcpy(p + txlen, refs, reflen);

	txp.tx = (union protocol_tx *)p;
	return txp;
}

struct block_shard *new_block_shard(const tal_t *ctx, u16 shardnum, u8 num)
{
	struct block_shard *s;

	s = tal_alloc_(ctx,
		       offsetof(struct block_shard, u[num]),
		       true, "struct block_shard");
	s->shardnum = shardnum;
	return s;
}

/* If we have the tx, hash it, otherwise return hash. */
const struct protocol_net_txrefhash *
txrefhash_in_shard(const struct block *b, u16 shard, u8 txoff,
		   struct protocol_net_txrefhash *scratch)
{
	const struct block_shard *s = b->shard[shard];

	assert(shard < num_shards(b->hdr));
	assert(txoff < b->shard_nums[shard]);

	if (!s)
		return NULL;

	if (shard_is_tx(s, txoff)) {
		const union protocol_tx *tx = tx_for(s, txoff);
		if (!tx)
			return NULL;
		hash_tx(tx, &scratch->txhash);
		hash_refs(refs_for(s->u[txoff].txp), num_inputs(tx),
			  &scratch->refhash);
		return scratch;
	} else
		return s->u[txoff].hash;
}

bool shard_all_known(const struct block *block, u16 shardnum)
{
	u8 count;

	count = block->shard[shardnum] ? block->shard[shardnum]->txcount : 0;
	return count == block->shard_nums[shardnum];
}

/* Do we have every tx or hash? */
bool shard_all_hashes(const struct block *block, u16 shardnum)
{
	u8 count;

	if (block->shard[shardnum]) {
		count = block->shard[shardnum]->txcount
			+ block->shard[shardnum]->hashcount;
	} else
		count = 0;
	return count == block->shard_nums[shardnum];
}
