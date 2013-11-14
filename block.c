#include <ccan/cast/cast.h>
#include "block.h"
#include "protocol.h"
#include "state.h"
#include "peer.h"
#include <string.h>

bool block_in_main(const struct block *block)
{
	return block->main_chain;
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

static void update_peers_mutual(struct state *state)
{
	struct peer *p;

	list_for_each(&state->peers, p, list) {
		/* Not set up yet?  OK. */
		if (!p->mutual)
			continue;

		/* Move back to a mutual block we agree on. */
		while (!block_in_main(p->mutual))
			p->mutual = p->mutual->prev;
	}
}		

/* In normal operation, this is a convolud way of adding b to the main chain */
static void promote_to_main(struct state *state, struct block *b)
{
	struct block *i, *common;
	struct list_head to_main = LIST_HEAD_INIT(to_main);

	/* Find where we meet main chain, moving onto the to_main list. */
	for (i = b; !block_in_main(i); i = i->prev) {
		list_del_from(&state->off_main, &i->list);
		/* Add to front, since we're going backwards. */
		list_add(&to_main, &i->list);
		i->main_chain = true;
	}

	/* This is where we meet the (old) main chain. */
	common = i;

	/* Remove everything beyond that from the main chain. */
	for (i = list_tail(&state->main_chain, struct block, list);
	     i != common;
	     i = i->prev) {
		assert(block_in_main(i));
		list_del_from(&state->main_chain, &i->list);
		i->main_chain = false;
		list_add_tail(&state->off_main, &i->list);
	}

	/* Append blocks which are now on the main chain. */
	list_append_list(&state->main_chain, &to_main);

	/* We may need to revise what we consider mutual blocks with peers. */
 	update_peers_mutual(state);
}

void block_add(struct state *state, struct block *block)
{
	struct block *tail = list_tail(&state->main_chain, struct block, list);

	/* First we add to off_main. */
	block->main_chain = false;
	list_add_tail(&state->off_main, &block->list);

	/* If this has more work than main chain, move to main chain. */
	/* FIXME: if equal, do coinflip as per
	 * http://arxiv.org/pdf/1311.0243v2.pdf ? */
	if (BN_cmp(&block->total_work, &tail->total_work) > 0)
		promote_to_main(state, block);
}

/* FIXME: get rid of off_chain, use hash table. */
struct block *block_find_any(struct state *state,
			     const struct protocol_double_sha *sha)
{
	struct block *i;

	list_for_each_rev(&state->main_chain, i, list) {
		if (memcmp(i->sha.sha, sha->sha, sizeof(sha->sha)) == 0)
			return i;
	}

	list_for_each_rev(&state->off_main, i, list) {
		if (memcmp(i->sha.sha, sha->sha, sizeof(sha->sha)) == 0)
			return i;
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
