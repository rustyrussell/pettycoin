#include "block.h"
#include "blockfile.h"
#include "chain.h"
#include "check_block.h"
#include "detached_block.h"
#include "difficulty.h"
#include "features.h"
#include "generating.h"
#include "log.h"
#include "peer.h"
#include "pending.h"
#include "proof.h"
#include "protocol.h"
#include "recv_block.h"
#include "shard.h"
#include "state.h"
#include "tal_arr.h"
#include "tal_packet.h"
#include "tx.h"
#include <ccan/structeq/structeq.h>
#include <string.h>

static void destroy_block(struct block *b)
{
	BN_free(&b->total_work);
	if (b->prev) {
		list_del_from(&b->prev->children, &b->sibling);
		list_del(&b->list);
	}
}

/* This allocates the block but doesn't sew it into data structures. */
static struct block *new_block(const tal_t *ctx,
			       BIGNUM *prev_work,
			       const struct protocol_block_id *sha,
			       const struct block_info *bi)
{
	struct block *block = tal(ctx, struct block);
	unsigned int i;

	total_work_done(le32_to_cpu(bi->tailer->difficulty),
			prev_work, &block->total_work);

	block->bi = *bi;
	block->all_known = false;
	list_head_init(&block->children);
	block->sha = *sha;
	block->shard = tal_arr(block, struct block_shard *,
			       num_shards(bi->hdr));
	for (i = 0; i < num_shards(bi->hdr); i++)
		block->shard[i] = new_block_shard(block->shard, i,
						  bi->num_txs[i]);

	/* In case we destroy before block_add(), eg. testing. */
	block->prev = NULL;

	tal_add_destructor(block, destroy_block);
	return block;
}

struct block *block_add(struct state *state,
			struct block *prev,
			const struct protocol_block_id *sha,
			const struct block_info *bi)
{
	u32 height = le32_to_cpu(bi->hdr->height);
	struct block *block;

	log_debug(state->log, "Adding block %u ", height);
	log_add_struct(state->log, struct protocol_block_id, sha);

	block = new_block(state, &prev->total_work, sha, bi);
	block->prev = prev;

	/* Add to list for that generation. */
	if (height >= tal_count(state->block_height)) {
		/* We can only increment block heights. */
		assert(height == tal_count(state->block_height));
		tal_arr_append(&state->block_height,
			       tal(state->block_height, struct list_head));
		list_head_init(state->block_height[height]);
	}

	/* We give some priority to blocks hear about first. */
	list_add_tail(state->block_height[height], &block->list);

	block->pending_features = pending_features(block);

	/* Link us into parent's children list. */
	list_add_tail(&block->prev->children, &block->sibling);

	/* Save it to disk for future use. */ 
	save_block(state, block);

	block->complaint = prev->complaint;

	if (block->complaint) {
		check_chains(state, false);

		/* This may be the prev for some detached blocks. */
		seek_detached_blocks(state, block);

		/* It's not a candidate for real use. */
		return block;
	}

	/* update pointers *before* we seek detached blocks.  Otherwise, if
	 * there's a huge chain of them, recheck_merkles() will walk them all
	 * multiple times, O(n^2). */
	update_block_ptrs_new_block(state, block);
	check_chains(state, false);
	check_block(state, block, false);

	/* This may be the prev for some detached blocks. */
	seek_detached_blocks(state, block);

	return block;
}

/* FIXME: use hash table. */
struct block *block_find_any(struct state *state,
			     const struct protocol_block_id *sha)
{
	int i, n = tal_count(state->block_height);
	struct block *b;

	/* Search recent blocks first. */
	for (i = n - 1; i >= 0; i--) {
		list_for_each(state->block_height[i], b, list) {
			if (structeq(&b->sha, sha))
				return b;
		}
	}
	return NULL;
}

bool block_all_known(const struct block *block)
{
	unsigned int i;

	for (i = 0; i < num_shards(block->bi.hdr); i++) {
		if (!shard_all_known(block->shard[i]))
			return false;
	}
	return true;
}

struct protocol_input_ref *block_get_refs(const struct block *block,
					  u16 shardnum, u8 txoff)
{
	const struct block_shard *s = block->shard[shardnum];

	assert(shardnum < num_shards(block->bi.hdr));
	assert(txoff < s->size);

	if (!shard_is_tx(s, txoff))
		return NULL;

	return cast_const(struct protocol_input_ref *,
			  refs_for(s->u[txoff].txp));
}

union protocol_tx *block_get_tx(const struct block *block,
				u16 shardnum, u8 txoff)
{
	const struct block_shard *s = block->shard[shardnum];

	assert(shardnum < num_shards(block->bi.hdr));
	assert(txoff < s->size);

	if (!shard_is_tx(s, txoff))
		return NULL;

	return s->u[txoff].txp.tx;
}

bool block_empty(const struct block *block)
{
	unsigned int i;

	for (i = 0; i < num_shards(block->bi.hdr); i++) {
		if (block->bi.num_txs[i] != 0)
			return false;
	}
	return true;
}
