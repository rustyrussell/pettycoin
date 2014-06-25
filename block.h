#ifndef PETTYCOIN_BLOCK_H
#define PETTYCOIN_BLOCK_H
#include <ccan/cast/cast.h>
#include "protocol.h"
#include "protocol_net.h"
#include "shard.h"
#include "state.h"
#include "marshall.h"
#include <stdbool.h>
#include <ccan/list/list.h>
#include <openssl/bn.h>

/* Each of these is followed by:
   struct protocol_input_ref ref[num_inputs(tx)];
*/
struct txptr_with_ref {
	union protocol_transaction *tx;
};

static inline const struct protocol_input_ref *refs_for(struct txptr_with_ref t)
{
	char *p;

	p = (char *)t.tx + marshall_transaction_len(t.tx);
	return (struct protocol_input_ref *)p;
}

/* Convenient routine to allocate adjacent copied of tx and refs */
struct txptr_with_ref txptr_with_ref(const tal_t *ctx,
				     const union protocol_transaction *tx,
				     const struct protocol_input_ref *refs);

/* Only transactions we've proven are in block go in here! */
struct transaction_shard {
	/* Which shard is this? */
	unsigned int shardnum;
	/* How many transactions do we have?  Faster than counting NULLs */
	unsigned int count;
	/* FIXME: Size dynamically based on block->shard_nums[shard]. */
	struct txptr_with_ref txp[256];
};

struct block {
	/* In state->block_depths[le32_to_cpu(hdr->depth)]. */
	struct list_node list;

	/* Links through sibling. */
	struct list_head children;

	/* In prev->children list. */
	struct list_node sibling;

	/* What features have been locked in for next fortnight? */
	u8 pending_features;

	/* Do we know all transactions for this and ancestors? */
	bool all_known;

	/* Total work to get to this block. */
	BIGNUM total_work;

	/* Our parent (in previous generation). */
	struct block *prev;

	/* The block itself: */
	const struct protocol_block_header *hdr;
	const u8 *shard_nums;
	const struct protocol_double_sha *merkles;
	const u8 *prev_merkles;
	const struct protocol_block_tailer *tailer;

	/* This is set if there's a problem with the block (or ancestor). */
	const void *complaint;

	/* Cache double SHA of block */
	struct protocol_double_sha sha;
	/* Transactions: may not be fully populated. */
	struct transaction_shard **shard;
};

/* Find on this chain. */
struct state;
struct block *block_find(struct block *start, const u8 lower_sha[4]);

/* Find anywhere. */
struct block *block_find_any(struct state *state,
			     const struct protocol_double_sha *sha);


/* Do we have everything in this shard? */
static inline bool shard_full(const struct block *block, u16 shardnum)
{
	u8 count;

	count = block->shard[shardnum] ? block->shard[shardnum]->count : 0;
	return count == block->shard_nums[shardnum];
}

/* Do we have everything in this block? */
bool block_full(const struct block *block, unsigned int *shardnum);

static inline const struct block *genesis_block(const struct state *state)
{
	return list_top(state->block_depth[0], struct block, list);
}

/* Add this new block into the state structure. */
void block_add(struct state *state, struct block *b);

/* Get tx_idx'th tx inside shard shardnum inside block. */
static inline union protocol_transaction *
block_get_tx(const struct block *block, u16 shardnum, u8 txoff)
{
	const struct transaction_shard *s = block->shard[shardnum];

	assert(shardnum < num_shards(block->hdr));
	assert(txoff < block->shard_nums[shardnum]);

	if (!s)
		return NULL;

	return s->txp[txoff].tx;
}

/* Get this numbered references inside block. */
struct protocol_input_ref *block_get_refs(const struct block *block,
					  u16 shardnum, u8 txoff);

void invalidate_block_badtrans(struct state *state,
			       struct block *block,
			       enum protocol_error err,
			       unsigned int bad_shardnum,
			       unsigned int bad_txoff,
			       unsigned int bad_input,
			       union protocol_transaction *bad_intrans);

void invalidate_block_misorder(struct state *state,
			       struct block *block,
			       unsigned int bad_txoff1,
			       unsigned int bad_txoff2,
			       unsigned int bad_shardnum);

#endif /* PETTYCOIN_BLOCK_H */
