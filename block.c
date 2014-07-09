#include <ccan/structeq/structeq.h>
#include "block.h"
#include "chain.h"
#include "protocol.h"
#include "state.h"
#include "peer.h"
#include "generating.h"
#include "log.h"
#include "pending.h"
#include "packet.h"
#include "proof.h"
#include "tx.h"
#include "features.h"
#include "shard.h"
#include <string.h>

struct block *block_find(struct block *start, const u8 lower_sha[4])
{
	struct block *b = start;

	while (b) {
		if (memcmp(b->sha.sha, lower_sha, 4) == 0)
			break;

		b = b->prev;
	}
	return b;
}

void block_add(struct state *state, struct block *block)
{
	u32 depth = le32_to_cpu(block->hdr->depth);

	log_debug(state->log, "Adding block %u ", depth);
	log_add_struct(state->log, struct protocol_double_sha, &block->sha);

	/* Add to list for that generation. */
	if (depth >= tal_count(state->block_depth)) {
		/* We can only increment block depths. */
		assert(depth == tal_count(state->block_depth));
		tal_resize(&state->block_depth, depth + 1);
		state->block_depth[depth]
			= tal(state->block_depth, struct list_head);
		list_head_init(state->block_depth[depth]);
	}
	/* We give some priority to blocks hear about first. */
	list_add_tail(state->block_depth[depth], &block->list);

	block->pending_features = pending_features(block);

	/* Link us into parent's children list. */
	list_head_init(&block->children);
	list_add_tail(&block->prev->children, &block->sibling);

	/* This can happen if precedessor has complaint. */
	if (block->complaint) {
		check_chains(state);
		/* It's not a candidate for real use. */
		return;
	}

	update_block_ptrs_new_block(state, block);
	check_chains(state);
}

/* FIXME: use hash table. */
struct block *block_find_any(struct state *state,
			     const struct protocol_double_sha *sha)
{
	int i, n = tal_count(state->block_depth);
	struct block *b;

	/* Search recent blocks first. */
	for (i = n - 1; i >= 0; i--) {
		list_for_each(state->block_depth[i], b, list) {
			if (structeq(&b->sha, sha))
				return b;
		}
	}
	return NULL;
}

bool block_all_known(const struct block *block, unsigned int *shardnum)
{
	unsigned int i;

	for (i = 0; i < num_shards(block->hdr); i++) {
		if (!shard_all_known(block->shard[i])) {
			if (shardnum)
				*shardnum = i;
			return false;
		}
	}
	return true;
}

struct protocol_input_ref *block_get_refs(const struct block *block,
					  u16 shardnum, u8 txoff)
{
	const struct block_shard *s = block->shard[shardnum];

	assert(shardnum < num_shards(block->hdr));
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

	assert(shardnum < num_shards(block->hdr));
	assert(txoff < s->size);

	if (!shard_is_tx(s, txoff))
		return NULL;

	return s->u[txoff].txp.tx;
}
