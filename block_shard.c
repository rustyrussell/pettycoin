#include <ccan/structeq/structeq.h>
#include "block_shard.h"
#include "tx.h"
#include "block.h"
#include "shard.h"
#include "merkle_txs.h"
#include "check_tx.h"
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
txrefhash_in_shard(const struct block *b,
		   const struct block_shard *s,
		   u8 txoff,
		   struct protocol_net_txrefhash *scratch)
{
	assert(s->shardnum < num_shards(b->hdr));
	assert(txoff < num_txs_in_shard(b, s->shardnum));

	if (!s)
		return NULL;

	if (shard_is_tx(s, txoff)) {
		const union protocol_tx *tx = tx_for(s, txoff);
		if (!tx)
			return NULL;
		hash_tx_and_refs(tx, refs_for(s->u[txoff].txp), scratch);
		return scratch;
	} else
		return s->u[txoff].hash;
}

bool shard_all_known(const struct block *block, u16 shardnum)
{
	u8 count;

	count = block->shard[shardnum] ? block->shard[shardnum]->txcount : 0;
	return count == num_txs_in_shard(block, shardnum);
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
	return count == num_txs_in_shard(block, shardnum);
}

u8 num_txs_in_shard(const struct block *block, u16 shardnum)
{
	assert(shardnum < num_shards(block->hdr));
	return block->shard_nums[shardnum];
}

void check_block_shard(struct state *state,
		       const struct block *block,
		       const struct block_shard *shard)
{
	unsigned int i, txcount = 0, hashcount = 0, num;

	num = num_txs_in_shard(block, shard->shardnum);
	for (i = 0; i < num; i++) {
		if (shard_is_tx(shard, i)) {
			if (shard->u[i].txp.tx) {
				enum protocol_ecode e;
				union protocol_tx *inp[PROTOCOL_TX_MAX_INPUTS];
				unsigned int bad_input_num;
				e = check_tx(state, shard->u[i].txp.tx, block,
					     refs_for(shard->u[i].txp), inp,
					     &bad_input_num);
				/* This can happen if we don't know input */
				if (e == PROTOCOL_ECODE_PRIV_TX_BAD_INPUT)
					assert(!inp[bad_input_num]);
				else
					assert(e == PROTOCOL_ECODE_NONE);
				txcount++;
			}
		} else {
			assert(shard->u[i].hash);
			hashcount++;
		}
	}
	assert(txcount == shard->txcount);
	assert(hashcount == shard->hashcount);

	assert(txcount + hashcount <= num);
	if (txcount + hashcount == num) {
		struct protocol_double_sha sha;
		merkle_txs(block, shard, &sha);
		assert(structeq(&sha, &block->merkles[shard->shardnum]));
	}
}
	
