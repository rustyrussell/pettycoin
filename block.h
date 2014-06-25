#ifndef PETTYCOIN_BLOCK_H
#define PETTYCOIN_BLOCK_H
#include <ccan/cast/cast.h>
#include <ccan/bitmap/bitmap.h>
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
	union protocol_tx *tx;
};

union txp_or_hash {
	/* Pointers to the actual transactions followed by refs */
	struct txptr_with_ref txp;
	/* hash_tx() of tx and hash_ref() of refs (we don't know them). */
	const struct protocol_net_txrefhash *hash;
};

/* Only transactions we've proven are in block go in here! */
struct tx_shard {
	/* Which shard is this? */
	u16 shardnum;
	/* How many transactions do we have?  Faster than counting NULLs */
	u8 txcount;
	/* How many transaction hashes do we have? */
	u8 hashcount;

	/* Bits to discriminate the union: 0 = txp, 1 == hash */
	BITMAP_DECLARE(txp_or_hash, 255);

	union txp_or_hash u[ /* block->shard_nums[shard] */ ];
};

static inline bool shard_is_tx(const struct tx_shard *s, u8 txoff)
{
	return !bitmap_test_bit(s->txp_or_hash, txoff);
}

static inline const struct protocol_input_ref *refs_for(struct txptr_with_ref t)
{
	char *p;

	p = (char *)t.tx + marshall_tx_len(t.tx);
	return (struct protocol_input_ref *)p;
}

static inline const union protocol_tx *tx_for(const struct tx_shard *s,
					      u8 txoff)
{
	if (shard_is_tx(s, txoff))
		return s->u[txoff].txp.tx;
	else
		return NULL;
}

/* Convenient routine to allocate adjacent copied of tx and refs */
struct txptr_with_ref txptr_with_ref(const tal_t *ctx,
				     const union protocol_tx *tx,
				     const struct protocol_input_ref *refs);


/* Returns NULL if it we don't have this tx. */
const struct protocol_net_txrefhash *
txrefhash_in_shard(const struct block *b, u16 shard, u8 txoff,
		   struct protocol_net_txrefhash *scratch);

/* Allocate a new struct transaction_shard. */
struct tx_shard *new_shard(const tal_t *ctx, u16 shardnum, u8 num);

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
	struct tx_shard **shard;
};

/* Find on this chain. */
struct state;
struct block *block_find(struct block *start, const u8 lower_sha[4]);

/* Find anywhere. */
struct block *block_find_any(struct state *state,
			     const struct protocol_double_sha *sha);


/* Do we have every tx in this shard? */
static inline bool shard_all_known(const struct block *block, u16 shardnum)
{
	u8 count;

	count = block->shard[shardnum] ? block->shard[shardnum]->txcount : 0;
	return count == block->shard_nums[shardnum];
}

/* Do we have every tx or hash? */
static inline bool shard_all_hashes(const struct block *block, u16 shardnum)
{
	u8 count;

	if (block->shard[shardnum]) {
		count = block->shard[shardnum]->txcount
			+ block->shard[shardnum]->hashcount;
	} else
		count = 0;
	return count == block->shard_nums[shardnum];
}

/* Do we have every tx in this block?
 * If not, tell us about one in shardnum (if non-NULL).
 */
bool block_all_known(const struct block *block, unsigned int *shardnum);

static inline const struct block *genesis_block(const struct state *state)
{
	return list_top(state->block_depth[0], struct block, list);
}

/* Add this new block into the state structure. */
void block_add(struct state *state, struct block *b);

/* Get tx_idx'th tx inside shard shardnum inside block. */
static inline union protocol_tx *
block_get_tx(const struct block *block, u16 shardnum, u8 txoff)
{
	const struct tx_shard *s = block->shard[shardnum];

	assert(shardnum < num_shards(block->hdr));
	assert(txoff < block->shard_nums[shardnum]);

	if (!s)
		return NULL;

	/* Must not be a hash. */
	assert(!bitmap_test_bit(s->txp_or_hash, txoff));
	return s->u[txoff].txp.tx;
}

/* Get this numbered references inside block. */
struct protocol_input_ref *block_get_refs(const struct block *block,
					  u16 shardnum, u8 txoff);

void invalidate_block_badtx(struct state *state,
			    struct block *block,
			    enum protocol_ecode err,
			    unsigned int bad_shardnum,
			    unsigned int bad_txoff,
			    unsigned int bad_input,
			    union protocol_tx *bad_intx);

void invalidate_block_misorder(struct state *state,
			       struct block *block,
			       unsigned int bad_txoff1,
			       unsigned int bad_txoff2,
			       unsigned int bad_shardnum);

#endif /* PETTYCOIN_BLOCK_H */
