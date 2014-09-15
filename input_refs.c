#include "block_shard.h"
#include "chain.h"
#include "input_refs.h"
#include "shard.h"
#include "tx.h"
#include <ccan/structeq/structeq.h>

static enum protocol_ecode check_ref(struct state *state,
				     const struct block *block,
				     const struct protocol_input_ref *ref)
{
	struct block *b = block_ancestor(block, le32_to_cpu(ref->blocks_ago));

	if (!b)
		return PROTOCOL_ECODE_REF_BAD_BLOCKS_AGO;

	/* Beyond horizon? */
	if (le32_to_cpu(b->tailer->timestamp) + PROTOCOL_TX_HORIZON_SECS(state->test_net)
	    < le32_to_cpu(block->tailer->timestamp))
		return PROTOCOL_ECODE_REF_BAD_BLOCKS_AGO;

	if (le16_to_cpu(ref->shard) >= num_shards(b->hdr))
		return PROTOCOL_ECODE_REF_BAD_SHARD;

	if (ref->txoff >= b->num_txs[le16_to_cpu(ref->shard)])
		return PROTOCOL_ECODE_REF_BAD_TXOFF;

	return PROTOCOL_ECODE_NONE;
}

enum protocol_ecode check_refs(struct state *state,
			       const struct block *block,
			       const struct protocol_input_ref *refs,
			       unsigned int num_refs)
{
	unsigned int i;
	enum protocol_ecode e = PROTOCOL_ECODE_NONE;

	for (i = 0; i < num_refs; i++) {
		e = check_ref(state, block, &refs[i]);
		if (e != PROTOCOL_ECODE_NONE)
			break;
	}
	return e;
}

enum ref_ecode check_tx_refs(struct state *state,
			     const struct block *block,
			     const union protocol_tx *tx,
			     const struct protocol_input_ref *refs,
			     unsigned int *bad_ref,
			     struct block **block_referred_to)
{
	unsigned int i, num = num_inputs(tx);
	bool all_known = true;

	assert(check_refs(state, block, refs, num) == PROTOCOL_ECODE_NONE);
	for (i = 0; i < num; i++) {
		struct block *b;
		struct protocol_txrefhash scratch;
		const struct protocol_txrefhash *txp;

		b = block_ancestor(block, le32_to_cpu(refs[i].blocks_ago));
		txp = txrefhash_in_shard(b->shard[le16_to_cpu(refs[i].shard)],
					 refs[i].txoff, &scratch);
		if (!txp) {
			*bad_ref = i;
			*block_referred_to = b;
			all_known = false;
			/* Keep looking in case there are worse issues. */
			continue;
		}

		if (!structeq(&txp->txhash, &tx_input(tx, i)->input)) {
			*bad_ref = i;
			*block_referred_to = b;
			return ECODE_REF_BAD_HASH;
		}
	}

	if (!all_known)
		return ECODE_REF_UNKNOWN;
	return ECODE_REF_OK;
}
