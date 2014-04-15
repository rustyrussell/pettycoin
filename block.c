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

/* Is a more work than b? */
static bool more_work(const struct block *a, const struct block *b)
{
	return BN_cmp(&a->total_work, &b->total_work) > 0;
}

bool block_in_main(const struct block *block)
{
	return block->main_chain;
}

static void check_chains(const struct state *state)
{
	const struct block *i, *prev_main = NULL;
	size_t n;
	bool found_prev_main = true;

	for (n = 0; n < tal_count(state->block_depth); n++) {
		bool found_main = false;

		list_check(state->block_depth[n], "bad block depth");
		list_for_each(state->block_depth[n], i, list) {
			if (i->main_chain) {
				/* Only one on main chain! */
				assert(!found_main);
				found_main = true;
				if (n == 0)
					assert(i == genesis_block(state));
				assert(i->prev == prev_main);
				prev_main = i;
			}
			assert(i->blocknum == n);
			if (n != 0) {
				assert(memcmp(&i->hdr->prev_block, &i->prev->sha,
					      sizeof(i->prev->sha)) == 0);
			}
		}
		/* You can't be in main if previous wasn't! */
		if (found_main)
			assert(found_prev_main);
		found_prev_main = found_main;
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

	/* Find where we meet (old) main chain, setting main flags. */
	for (i = b; !block_in_main(i); i = i->prev)
		i->main_chain = true;

	/* This is where we meet the (old) main chain. */
	common = i;

	log_debug(state->log, "Common block %u ", common->blocknum);
	log_add_struct(state->log, struct protocol_double_sha, &common->sha);

	/* Remove everything beyond that from the main chain. */
	for (i = state->longest_chain; i != common; i = i->prev) {
		assert(block_in_main(i));
		i->main_chain = false;
	}
}

/* Now this block is the end of the longest chain.
 *
 * This matters because we want to know all about that chain so we can
 * mine it.  If everyone is sharing information normally, that should be
 * easy.
 */
static void update_longest(struct state *state, struct block *block)
{
	log_debug(state->log, "Longest moved from %u to %u ",
		  state->longest_chain->blocknum,
		  block->blocknum);
	log_add_struct(state->log, struct protocol_double_sha, &block->sha);

	state->longest_chain = block;

	/* We want peers to ask about contents of these blocks. */
	wake_peers(state);
}

/* Now this block is the end of the longest chain we know completely about.
 *
 * This is the best block to mine on.
 */
void update_longest_known(struct state *state, struct block *block)
{
	struct block *old = state->longest_known;

	log_debug(state->log, "Longest known moved from %u to %u ",
		  old->blocknum, block->blocknum);
	log_add_struct(state->log, struct protocol_double_sha, &block->sha);

	state->longest_known = block;

	/* Any transactions from old branch go into pending. */
	steal_pending_transactions(state, old, block);

	/* Restart generator on this block. */
	restart_generating(state);

	/* We want peers to tell others about contents of this block. */
	wake_peers(state);
}

/* Now this block is the end of the longest chain from longest_known.
 *
 * If we can't get information about the longest chain, we'd like
 * information about this chain.
 */
void update_longest_known_descendent(struct state *state, struct block *block)
{
	log_debug(state->log, "Longest known descendent moved from %u to %u ",
		  state->longest_known_descendent->blocknum,
		  block->blocknum);
	log_add_struct(state->log, struct protocol_double_sha, &block->sha);

	state->longest_known_descendent = block;

	/* We want peers to ask about contents of these blocks. */
	wake_peers(state);
}

bool block_add(struct state *state, struct block *block)
{
	log_debug(state->log, "Adding block %u ", block->blocknum);
	log_add_struct(state->log, struct protocol_double_sha, &block->sha);

	/* First we add to off_main. */
	assert(!block->main_chain);
	if (block->blocknum >= tal_count(state->block_depth)) {
		/* We can only increment block depths. */
		assert(block->blocknum == tal_count(state->block_depth));
		tal_resize(&state->block_depth, block->blocknum + 1);
		state->block_depth[block->blocknum]
			= tal(state->block_depth, struct list_head);
		list_head_init(state->block_depth[block->blocknum]);
	}
	list_add_tail(state->block_depth[block->blocknum], &block->list);

	/* Corner case for zero transactions (will update
	 * longest_known_descendent if necessary). */
	if (le32_to_cpu(block->hdr->num_transactions) == 0)
		update_known(state, block);
	else {
		/* Have we just extended the longest known descendent? */
		if (block->prev == state->longest_known_descendent) {
			update_longest_known_descendent(state, block);
			check_chains(state);
		}
	}

	/* If this has more work than main chain, move to main chain. */
	/* FIXME: if equal, do coinflip as per
	 * http://arxiv.org/pdf/1311.0243v2.pdf ?  Or GHOST? */
	if (more_work(block, state->longest_chain)) {
		log_debug(state->log, "New block work ");
		log_add_struct(state->log, BIGNUM, &block->total_work);
		log_add(state->log, " exceeds old work ");
		log_add_struct(state->log, BIGNUM,
			       &state->longest_chain->total_work);
		promote_to_main(state, block);
		update_longest(state, block);
		check_chains(state);
		return true;
	}
	return false;
}

/* FIXME: use hash table. */
struct block *block_find_any(struct state *state,
			     const struct protocol_double_sha *sha)
{
	int i, n = tal_count(state->block_depth);
	struct block *b;

	/* Search recent blocks first. */
	for (i = n - 1; i >= 0; i--) {
		list_for_each(state->block_depth[i], b, list) {
			if (memcmp(b->sha.sha, sha->sha, sizeof(sha->sha)) == 0)
				return b;
		}
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

static void update_recursive(struct state *state, struct block *block,
			     struct block **best)
{
	if (!block->prev->all_known || !block_full(block, NULL))
		return;

	assert(!block->all_known);
	block->all_known = true;

	/* New winner to start mining on? */
	if (more_work(block, *best))
		*best = block;

	/* Check descendents. */
	if (block->blocknum + 1 < tal_count(state->block_depth)) {
		struct block *b;

		list_for_each(state->block_depth[block->blocknum + 1], b, list)
			if (b->prev == block)
				update_recursive(state, b, best);
	}
}

/* Search descendents to find if there's one with more work than *best. */
static void find_longest_descendent(struct state *state,
				    struct block *block,
				    struct block **best)
{
	struct block *b;

	if (block->blocknum + 1 >= tal_count(state->block_depth))
		return;

	list_for_each(state->block_depth[block->blocknum + 1], b, list) {
		if (b->prev != block)
			continue;

		if (more_work(b, *best)) {
			*best = b;
			find_longest_descendent(state, b, best);
		}
	}
}

/* We now know complete contents of block; update all_known for this
 * block (and maybe its descendents) and if necessary, update
 * longest_known and longest_known_descendent and restart generator
 * and wake peers (who might care). */
void update_known(struct state *state, struct block *block)
{
	struct block *longest_known = state->longest_known;

	update_recursive(state, block, &longest_known);
	if (longest_known != state->longest_known) {
		struct block *longest_descendent;

		update_longest_known(state, longest_known);

		/* Can't check chains until we've updated longest_descendent! */
		longest_descendent = longest_known;
		find_longest_descendent(state, longest_known,
					&longest_descendent);
		if (longest_descendent != state->longest_known_descendent)
			update_longest_known_descendent(state,
							longest_descendent);
		check_chains(state);
	}
}

bool block_preceeds(const struct block *a, const struct block *b)
{
	if (a == b)
		return true;

	if (a->blocknum >= b->blocknum)
		return false;

	return block_preceeds(a, b->prev);
}

struct block *step_towards(const struct block *curr, const struct block *target)
{
	const struct block *prev_target;

	/* Move back towards target. */
	while (curr->blocknum > target->blocknum)
		curr = curr->prev;

	/* Already past it, or equal to it */
	if (curr == target)
		return NULL;

	/* Move target back towards curr. */
	while (target->blocknum > curr->blocknum) {
		prev_target = target;
		target = target->prev;
	}

	/* Now move both back until they're at the common ancestor. */
	while (curr != target) {
		prev_target = target;
		target = target->prev;
		curr = curr->prev;
	}

	/* This is one step towards the target. */
	return cast_const(struct block *, prev_target);
}
