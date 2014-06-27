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

/* For compactness, struct tx_shard needs tx and refs adjacent. */
struct txptr_with_ref txptr_with_ref(const tal_t *ctx,
				     const union protocol_tx *tx,
				     const struct protocol_input_ref *refs)
{
	struct txptr_with_ref txp;
	size_t txlen, reflen;
	char *p;

	txlen = marshall_tx_len(tx);
	reflen = num_inputs(tx) * sizeof(struct protocol_input_ref);

	p = tal_alloc_(ctx, txlen + reflen, false, "txptr_with_ref");
	memcpy(p, tx, txlen);
	memcpy(p + txlen, refs, reflen);

	txp.tx = (union protocol_tx *)p;
	return txp;
}

struct tx_shard *new_shard(const tal_t *ctx, u16 shardnum, u8 num)
{
	struct tx_shard *s;

	s = tal_alloc_(ctx,
		       offsetof(struct tx_shard, u[num]),
		       true, "struct tx_shard");
	s->shardnum = shardnum;
	return s;
}

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
		if (!shard_all_known(block, i)) {
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
	const struct tx_shard *s = block->shard[shardnum];

	assert(shardnum < num_shards(block->hdr));
	assert(txoff < block->shard_nums[shardnum]);

	if (!s)
		return NULL;

	/* Must not be a hash. */
	assert(shard_is_tx(s, txoff));
	return cast_const(struct protocol_input_ref *,
			  refs_for(s->u[txoff].txp));
}

/* If we have the tx, hash it, otherwise return hash. */
const struct protocol_net_txrefhash *
txrefhash_in_shard(const struct block *b, u16 shard, u8 txoff,
		   struct protocol_net_txrefhash *scratch)
{
	const struct tx_shard *s = b->shard[shard];

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
