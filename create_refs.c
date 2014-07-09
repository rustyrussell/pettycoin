#include "block.h"
#include "chain.h"
#include "create_refs.h"
#include "state.h"
#include "timestamp.h"
#include "tx.h"
#include "txhash.h"
#include <assert.h>

/* We don't include transactions which are close to being timed out. */
#define CLOSE_TO_HORIZON 3600

static bool resolve_input(struct state *state,
			  const struct block *prev_block,
			  const union protocol_tx *tx,
			  u32 num,
			  struct protocol_input_ref *ref)
{
	const struct protocol_double_sha *sha;
	struct txhash_iter iter;
	struct txhash_elem *te;

	assert(tx_type(tx) == TX_NORMAL);
	assert(num < le32_to_cpu(tx->normal.num_inputs));

	sha = &get_normal_inputs(&tx->normal)[num].input;

	for (te = txhash_firstval(&state->txhash, sha, &iter);
	     te;
	     te = txhash_nextval(&state->txhash, sha, &iter)) {
		if (!block_preceeds(te->block, prev_block))
			continue;

		/* Don't include any transactions within 1 hour of cutoff. */
		if (le32_to_cpu(te->block->tailer->timestamp)
		    + PROTOCOL_TX_HORIZON_SECS - CLOSE_TO_HORIZON
		    < current_time())
			return false;

		/* Add 1 since this will go into *next* block */
		ref->blocks_ago = 
			cpu_to_le32(le32_to_cpu(prev_block->hdr->depth) -
				    le32_to_cpu(te->block->hdr->depth) + 1);
		ref->shard = cpu_to_le16(te->shardnum);
		ref->txoff = te->txoff;
		ref->unused = 0;
		return true;
	}
	return false;
}

/* Try to find the inputs in block and its ancestors */
struct protocol_input_ref *create_refs(struct state *state,
				       const struct block *prev_block,
				       const union protocol_tx *tx)
{
	u32 i, num = num_inputs(tx);
	struct protocol_input_ref *refs;

	refs = tal_arr(state, struct protocol_input_ref, num);

	for (i = 0; i < num; i++)
		if (!resolve_input(state, prev_block, tx, i, &refs[i]))
			return tal_free(refs);

	return refs;
}
