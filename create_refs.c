#include "create_refs.h"
#include "thash.h"
#include "chain.h"
#include "state.h"
#include "block.h"
#include "timestamp.h"
#include "check_transaction.h"
#include <assert.h>

/* We don't include transactions which are close to being timed out. */
#define CLOSE_TO_HORIZON 3600

static bool resolve_input(struct state *state,
			  const struct block *prev_block,
			  const union protocol_transaction *tx,
			  u32 num,
			  struct protocol_input_ref *ref)
{
	const struct protocol_double_sha *sha;
	struct thash_iter iter;
	struct thash_elem *te;

	assert(tx->hdr.type == TRANSACTION_NORMAL);
	assert(num < le32_to_cpu(tx->normal.num_inputs));

	sha = &tx->normal.input[num].input;

	for (te = thash_firstval(&state->thash, sha, &iter);
	     te;
	     te = thash_nextval(&state->thash, sha, &iter)) {
		if (!block_preceeds(te->block, prev_block))
			continue;

		/* Don't include any transactions within 1 hour of cutoff. */
		if (le32_to_cpu(te->block->tailer->timestamp)
		    + TRANSACTION_HORIZON_SECS - CLOSE_TO_HORIZON
		    < current_time())
			return false;

		/* Add 1 since this will go into *next* block */
		ref->blocks_ago = 
			cpu_to_le32(le32_to_cpu(prev_block->hdr->depth) -
				    le32_to_cpu(te->block->hdr->depth) + 1);
		ref->txnum = cpu_to_le32(te->tnum);
		return true;
	}
	return false;
}

/* Try to find the inputs in block and its ancestors */
struct protocol_input_ref *create_refs(struct state *state,
				       const struct block *prev_block,
				       const union protocol_transaction *tx)
{
	u32 i, num = num_inputs(tx);
	struct protocol_input_ref *refs;

	refs = tal_arr(state, struct protocol_input_ref, num);

	for (i = 0; i < num; i++)
		if (!resolve_input(state, prev_block, tx, i, &refs[i]))
			return tal_free(refs);

	return refs;
}
