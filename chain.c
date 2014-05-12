#include "chain.h"
#include "block.h"
#include "peer.h"
#include "pending.h"
#include "generating.h"
#include <time.h>
#include <ccan/cast/cast.h>

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

/* Follow ->prev count times. */
struct block *block_ancestor(const struct block *a, unsigned int count)
{
	struct block *b;

	/* FIXME: Slow!  Optimize if both on main chain! */
	for (b = cast_const(struct block *, a); b->blocknum != count; b = b->prev);
	return b;
}

/* Is a more work than b? */
static bool more_work(const struct block *a, const struct block *b)
{
	return BN_cmp(&a->total_work, &b->total_work) > 0;
}

void check_chains(const struct state *state)
{
	const struct block *i;
	size_t n;

	for (n = 0; n < tal_count(state->block_depth); n++) {
		list_check(state->block_depth[n], "bad block depth");
		list_for_each(state->block_depth[n], i, list) {
			assert(i->blocknum == n);
			if (n == 0)
				assert(i == genesis_block(state));
			else {
				assert(memcmp(&i->hdr->prev_block, &i->prev->sha,
					      sizeof(i->prev->sha)) == 0);
				if (i->prev->complaint)
					assert(i->complaint);
			}
			assert(i->complaint ||
			       !more_work(i, state->longest_chain));
			if (!i->complaint && i->all_known)
				assert(!more_work(i, state->longest_known));
		}
	}

	/* longest_known_descendent should be a descendent of longest_known */
	for (i = state->longest_known_descendent;
	     i != state->longest_known;
	     i = i->prev) {
		assert(i != genesis_block(state));
		assert(!i->all_known);
	}

	/* We ignore blocks which have a problem. */
	assert(!state->longest_known->complaint);
	assert(!state->longest_known_descendent->complaint);
	assert(!state->longest_chain->complaint);
}

/* Now this block is the end of the longest chain.
 *
 * This matters because we want to know all about that chain so we can
 * mine it.  If everyone is sharing information normally, that should be
 * easy.
 */
static void update_longest(struct state *state, const struct block *block)
{
	log_debug(state->log, "Longest moved from %u to %u ",
		  state->longest_chain->blocknum,
		  block->blocknum);
	log_add_struct(state->log, struct protocol_double_sha, &block->sha);

	state->longest_chain = block;

	if (block->pending_features && !state->upcoming_features) {
		/* Be conservative, halve estimate of time to confirm feature */
		time_t impact = le32_to_cpu(block->tailer->timestamp)
			+ FEATURE_CONFIRM_DELAY * BLOCK_TARGET_TIME / 2;
		struct tm *when;

		when = localtime(&impact);

		/* FIXME: More prominent warning! */
		log_unusual(state->log,
			    "WARNING: unknown features 0x%02x voted in!",
			    block->pending_features);
		log_add(state->log, " Update your client! (Before %u-%u-%u)",
			when->tm_year, when->tm_mon, when->tm_mday);
		state->upcoming_features = block->pending_features;
	}

	/* We want peers to ask about contents of these blocks. */
	wake_peers(state);
}

/* Now this block is the end of the longest chain we know completely about.
 *
 * This is the best block to mine on.
 */
void update_longest_known(struct state *state, const struct block *block)
{
	const struct block *old = state->longest_known;

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
void update_longest_known_descendent(struct state *state,
				     const struct block *block)
{
	log_debug(state->log, "Longest known descendent moved from %u to %u ",
		  state->longest_known_descendent->blocknum,
		  block->blocknum);
	log_add_struct(state->log, struct protocol_double_sha, &block->sha);

	state->longest_known_descendent = block;

	/* We want peers to ask about contents of these blocks. */
	wake_peers(state);
}

static void update_recursive(struct state *state,
			     struct block *block,
			     const struct block **best)
{
	if (!block->prev->all_known || !block_full(block, NULL))
		return;

	block->all_known = true;

	/* Blocks which are flawed are not useful */
	if (block->complaint)
		return;

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
				    const struct block *block,
				    const struct block **best)
{
	struct block *b;

	if (block->blocknum + 1 >= tal_count(state->block_depth))
		return;

	list_for_each(state->block_depth[block->blocknum + 1], b, list) {
		if (b->prev != block)
			continue;

		if (b->complaint)
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
static void update_known(struct state *state, struct block *block)
{
	const struct block *longest_known = state->longest_known;

	update_recursive(state, block, &longest_known);
	if (longest_known != state->longest_known) {
		const struct block *longest_descendent;

		update_longest_known(state, longest_known);

		/* Can't check chains until we've updated longest_descendent! */
		longest_descendent = longest_known;
		find_longest_descendent(state, longest_known,
					&longest_descendent);
		if (longest_descendent != state->longest_known_descendent)
			update_longest_known_descendent(state,
							longest_descendent);
	}
}

/* Brute force calculation of longest_known and longest_known_descendent */
static void recalc_longest_known(struct state *state)
{
	state->longest_known_descendent
		= state->longest_known
		= genesis_block(state);

	update_known(state, cast_const(struct block *, genesis_block(state)));
}

/* Brute force calculation of longest_chain. */
static void recalc_longest_chain(struct state *state)
{
	state->longest_chain = genesis_block(state);
	find_longest_descendent(state, state->longest_chain,
				&state->longest_chain);
}

/* We've added a new block; update state->longest_chains, state->longest_knowns,
   state->longest_known_descendents as required. */
void update_block_ptrs_new_block(struct state *state, struct block *block)
{
	/* Is this the longest? */
	/* FIXME: if equal, do coinflip as per
	 * http://arxiv.org/pdf/1311.0243v2.pdf ?  Or GHOST? */
	if (more_work(block, state->longest_chain)) {
		log_debug(state->log, "New block work ");
		log_add_struct(state->log, BIGNUM, &block->total_work);
		log_add(state->log, " exceeds old work ");
		log_add_struct(state->log, BIGNUM,
			       &state->longest_chain->total_work);
		update_longest(state, block);
	}

	/* Corner case for zero transactions (will update
	 * longest_known_descendent if necessary). */
	if (le32_to_cpu(block->hdr->num_transactions) == 0)
		update_known(state, block);
	/* Have we just extended the longest known descendent? */
	else if (block->prev == state->longest_known_descendent)
		update_longest_known_descendent(state, block);

	check_chains(state);
}

/* We've added a new batch; update state->longest_chains, state->longest_knowns,
   state->longest_known_descendents as required. */
void update_block_ptrs_new_batch(struct state *state, struct block *block)
{
	if (block_full(block, NULL)) {
		update_known(state, block);
		check_chains(state);
	}
}

void update_block_ptrs_invalidated(struct state *state,
				   const struct block *block)
{
	if (block_preceeds(block, state->longest_chain))
		recalc_longest_chain(state);

	/* These blocks no longer qualify for longest or longest known. */
	if (block_preceeds(block, state->longest_known_descendent))
		recalc_longest_known(state);

	check_chains(state);
}
