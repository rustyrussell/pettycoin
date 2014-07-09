#ifndef PETTYCOIN_BLOCK_SHARD_H
#define PETTYCOIN_BLOCK_SHARD_H
#include <ccan/bitmap/bitmap.h>
#include "marshal.h"

struct block;
struct state;

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
struct block_shard {
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

static inline bool shard_is_tx(const struct block_shard *s, u8 txoff)
{
	return !bitmap_test_bit(s->txp_or_hash, txoff);
}

static inline const struct protocol_input_ref *refs_for(struct txptr_with_ref t)
{
	char *p;

	p = (char *)t.tx + marshal_tx_len(t.tx);
	return (struct protocol_input_ref *)p;
}

static inline const union protocol_tx *tx_for(const struct block_shard *s,
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
txrefhash_in_shard(const struct block *b,
		   const struct block_shard *shard,
		   u8 txoff,
		   struct protocol_net_txrefhash *scratch);

/* Do we have every tx in this shard? */
bool shard_all_known(const struct block *block, u16 shardnum);

/* Do we have every tx or hash? */
bool shard_all_hashes(const struct block *block, u16 shardnum);

/* How many txs in this shard? */
u8 num_txs_in_shard(const struct block *block, u16 shardnum);

/* Allocate a new struct transaction_shard. */
struct block_shard *new_block_shard(const tal_t *ctx, u16 shardnum, u8 num);

/* Various assertions about a shard */
void check_block_shard(struct state *state,
		       const struct block *block,
		       const struct block_shard *shard);
#endif /* PETTYCOIN_BLOCK_SHARD_H */
