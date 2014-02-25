#include <ccan/cast/cast.h>
#include "block.h"
#include "protocol.h"
#include "state.h"
#include "peer.h"
#include "generating.h"
#include "log.h"
#include "merkle_transactions.h"
#include "pending.h"
#include <string.h>

bool block_in_main(const struct block *block)
{
	return block->main_chain;
}

static void check_chains(const struct state *state)
{
	const struct block *i, *prev;

	list_check(&state->main_chain, "bad main chain");
	list_check(&state->off_main, "bad off_main chain");

	prev = NULL;
	list_for_each(&state->main_chain, i, list) {
		assert(i->main_chain);
		assert(i->prev == prev);
		if (prev) {
			assert(i->blocknum == prev->blocknum + 1);
			assert(memcmp(&i->hdr->prev_block, &prev->sha,
				      sizeof(prev->sha)) == 0);
		} else
			assert(i->blocknum == 0);
		prev = i;
	}

	list_for_each(&state->off_main, i, list) {
		assert(!i->main_chain);
		assert(i->blocknum == i->prev->blocknum + 1);
		assert(memcmp(&i->hdr->prev_block, &i->prev->sha,
			      sizeof(i->prev->sha)) == 0);
	}
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

static void update_thashes(struct state *state, struct block *b)
{
	u32 i, num = le32_to_cpu(b->hdr->num_transactions);

	for (i = 0; i < num; i++) {
		union protocol_transaction *t = block_get_trans(b, i);
		struct thash_elem *te;
		struct protocol_double_sha sha;

		/* For the moment, blocks are always full.  Not forever. */
		if (!t)
			continue;

		/* Must already be in thash: added when added to block. */
		hash_transaction(t, NULL, 0, &sha);
		te = thash_get(&state->thash, &sha);

		if (te->block != b) {
			te->block = b;
			te->tnum = i;
		}
	}
}

/* In normal operation, this is a convoluted way of adding b to the main chain */
static void promote_to_main(struct state *state, struct block *b)
{
	struct block *i, *common;
	struct list_head to_main = LIST_HEAD_INIT(to_main);
	struct list_head from_main = LIST_HEAD_INIT(from_main);

	log_debug(state->log, "Promoting block %u ", b->blocknum);
	log_add_struct(state->log, struct protocol_double_sha, &b->sha);
	log_add(state->log, "to main chain");

	check_chains(state);

	/* Find where we meet main chain, moving onto the to_main list. */
	for (i = b; !block_in_main(i); i = i->prev) {
		list_del_from(&state->off_main, &i->list);
		/* Add to front, since we're going backwards. */
		list_add(&to_main, &i->list);
		i->main_chain = true;
		/* Make sure entries in thash point to *this* block. */
		update_thashes(state, i);
	}

	/* This is where we meet the (old) main chain. */
	common = i;

	log_debug(state->log, "Common block %u ", common->blocknum);
	log_add_struct(state->log, struct protocol_double_sha, &common->sha);

	/* Remove everything beyond that from the main chain. */
	for (i = list_tail(&state->main_chain, struct block, list);
	     i != common;
	     i = i->prev) {
		assert(block_in_main(i));
		list_del_from(&state->main_chain, &i->list);
		i->main_chain = false;
		list_add_tail(&from_main, &i->list);
		steal_pending_transactions(state, i);
	}

	/* Append blocks which are now on the main chain. */
	list_append_list(&state->main_chain, &to_main);
	update_pending_transactions(state);

	check_chains(state);
}

bool block_add(struct state *state, struct block *block)
{
	struct block *tail = list_tail(&state->main_chain, struct block, list);

	log_debug(state->log, "Adding block %u ", block->blocknum);
	log_add_struct(state->log, struct protocol_double_sha, &block->sha);

	/* First we add to off_main. */
	assert(!block->main_chain);
	list_add_tail(&state->off_main, &block->list);

	/* If this has more work than main chain, move to main chain. */
	/* FIXME: if equal, do coinflip as per
	 * http://arxiv.org/pdf/1311.0243v2.pdf ?  Or GHOST? */
	if (BN_cmp(&block->total_work, &tail->total_work) > 0) {
		log_debug(state->log, "New block work ");
		log_add_struct(state->log, BIGNUM, &block->total_work);
		log_add(state->log, " exceeds old work ");
		log_add_struct(state->log, BIGNUM, &tail->total_work);
		promote_to_main(state, block);
		return true;
	}
	check_chains(state);
	return false;
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

u32 batch_max(const struct block *block, unsigned int batchnum)
{
	unsigned int num_trans, batch_start, full;

	/* How many could we possibly fit? */
	num_trans = le32_to_cpu(block->hdr->num_transactions);
	batch_start = batchnum << PETTYCOIN_BATCH_ORDER;

	full = num_trans - batch_start;
	if (full > (1 << PETTYCOIN_BATCH_ORDER))
		return (1 << PETTYCOIN_BATCH_ORDER);

	return full;
}

/* Do we have everything in this batch? */
bool batch_full(const struct block *block,
		const struct transaction_batch *batch)
{
	unsigned int batchnum = batch->trans_start >> PETTYCOIN_BATCH_ORDER;
	return batch->count == batch_max(block, batchnum);
}

bool block_full(const struct block *block, unsigned int *batchnum)
{
	unsigned int i, num;

	num = num_merkles(le32_to_cpu(block->hdr->num_transactions));
	for (i = 0; i < num; i++) {
		const struct transaction_batch *b = block->batch[i];
		if (batchnum)
			*batchnum = i;
		if (!b)
			return false;
		if (!batch_full(block, b))
			return false;
	}
	return true;
}

union protocol_transaction *block_get_trans(const struct block *block,
					    u32 trans_num)
{
	const struct transaction_batch *b;

	assert(trans_num < block->hdr->num_transactions);
	b = block->batch[batch_index(trans_num)];
	if (!b)
		return NULL;
	return cast_const(union protocol_transaction *,
			  b->t[trans_num % (1 << PETTYCOIN_BATCH_ORDER)]);
}
