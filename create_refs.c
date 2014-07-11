#include "block.h"
#include "chain.h"
#include "create_refs.h"
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
	const struct protocol_double_sha *sha;
	struct txhash_elem *te;

	sha = &tx_input(tx, num)->input;

	te = txhash_gettx_ancestor(state, sha, prev_block);
	if (!te)
		return false;

	/* Don't include any transactions within 1 hour of cutoff. */
	if (le32_to_cpu(te->u.block->tailer->timestamp)
	    + PROTOCOL_TX_HORIZON_SECS - CLOSE_TO_HORIZON
	    < current_time())
		return false;

	/* Add offset: it might be going to go into *next* block */
	ref->blocks_ago = 
		cpu_to_le32(le32_to_cpu(prev_block->hdr->depth) -
			    le32_to_cpu(te->u.block->hdr->depth) + offset);
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
