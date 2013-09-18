#include <ccan/cast/cast.h>
#include "block.h"
#include "protocol.h"
#include "state.h"
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

struct block *block_find_any(struct state *state,
			     const struct protocol_double_sha *sha)
{
	struct block *b;

	list_for_each_rev(&state->blocks, b, list) {
		struct block *i = b;
		/* Check all peers at this level. */
		do {
			if (memcmp(i->sha.sha, sha->sha, sizeof(sha->sha)) == 0)
				return i;
			i = i->peers;
		} while (i != b);
	}
	return NULL;
}

/* Do we have everything in this batch? */
bool batch_full(const struct block *block,
		const struct transaction_batch *batch)
{
	u32 full;

	assert((batch->trans_start & ((1 << PETTYCOIN_BATCH_ORDER)-1)) == 0);

	/* How many could we possibly fit? */
	full = le32_to_cpu(block->hdr->num_transactions) - batch->trans_start;
	/* But this is the max in a batch. */
	if (full > (1 << PETTYCOIN_BATCH_ORDER))
		full = (1 << PETTYCOIN_BATCH_ORDER);

	return batch->count == full;
}

union protocol_transaction *block_get_trans(const struct block *block,
					    u32 trans_num)
{
	const struct transaction_batch *b;

	assert(trans_num < block->hdr->num_transactions);
	b = block->batch[batch_index(trans_num)];
	return cast_const(union protocol_transaction *,
			  b->t[trans_num % (1 << PETTYCOIN_BATCH_ORDER)]);
}
