#include "block.h"
#include "chain.h"
#include "create_refs.h"
#include "horizon.h"
#include "state.h"
#include "timestamp.h"
#include "tx.h"
#include "tx_in_hashes.h"
#include "txhash.h"
#include <assert.h>

/* We don't include transactions which are close to being timed out. */
#define CLOSE_TO_HORIZON 3600

static bool resolve_input(struct state *state,
			  const struct block *prev_block,
			  const union protocol_tx *tx,
			  u32 num,
			  int offset,
			  struct protocol_input_ref *ref)
{
	const struct protocol_tx_id *sha;
	struct txhash_elem *te;

	sha = &tx_input(tx, num)->input;

	te = txhash_gettx_ancestor(state, sha, prev_block);
	if (!te)
		return false;

	/* Don't include any transactions expiring the next 1 hour. */
	if (block_expired_by(block_expiry(state, &te->u.block->bi),
			     current_time() + CLOSE_TO_HORIZON))
		return false;

	/* Add offset: it might be going to go into *next* block */
	ref->blocks_ago = cpu_to_le32(block_height(&prev_block->bi) -
				      block_height(&te->u.block->bi)
				      + offset);
	ref->shard = cpu_to_le16(te->shardnum);
	ref->txoff = te->txoff;
	ref->unused = 0;
	return true;
}

/* Try to find the inputs in block and its ancestors */
struct protocol_input_ref *create_refs(struct state *state,
				       const struct block *block,
				       const union protocol_tx *tx,
				       int offset)
{
	u32 i, num = num_inputs(tx);
	struct protocol_input_ref *refs;

	refs = tal_arr(state, struct protocol_input_ref, num);

	for (i = 0; i < num; i++)
		if (!resolve_input(state, block, tx, i, offset, &refs[i]))
			return tal_free(refs);

	return refs;
}
