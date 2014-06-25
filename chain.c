#include "chain.h"
#include "block.h"
#include "peer.h"
#include "pending.h"
#include "generating.h"
#include "todo.h"
#include "shard.h"
#include <time.h>
#include <ccan/cast/cast.h>

/* Simply block array helpers */
static void set_single(const struct block ***arr, const struct block *b)
{
	tal_resize(arr, 1);
	(*arr)[0] = b;
}

static void add_single(const struct block ***arr, const struct block *b)
{
	size_t num = tal_count(*arr);
	tal_resize(arr, num+1);
	(*arr)[num] = b;
}

struct block *step_towards(const struct block *curr, const struct block *target)
{
	const struct block *prev_target;

	/* Move back towards target. */
	while (le32_to_cpu(curr->hdr->depth) > le32_to_cpu(target->hdr->depth))
		curr = curr->prev;

	/* Already past it, or equal to it */
	if (curr == target)
		return NULL;

	/* Move target back towards curr. */
	while (le32_to_cpu(target->hdr->depth) > le32_to_cpu(curr->hdr->depth)) {
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

/* Is a more work than b? */
static int cmp_work(const struct block *a, const struct block *b)
{
	return BN_cmp(&a->total_work, &b->total_work);
}

/* Find a link between a known and a longest chain. */
static bool find_connected_pair(const struct state *state,
				size_t *chain_num, size_t *known_num)
{
	unsigned int i, j;

	for (i = 0; i < tal_count(state->longest_chains); i++) {
		for (j = 0; j < tal_count(state->longest_knowns); j++) {
			if (block_preceeds(state->longest_knowns[j],
					   state->longest_chains[i])) {
				*chain_num = i;
				*known_num = j;
				return true;
			}
		}
	}
	return false;
}

void check_chains(const struct state *state)
{
	const struct block *i;
	size_t n, num_next_level = 1;

	/* If multiple longest chains, all should have same work! */
	for (n = 1; n < tal_count(state->longest_chains); n++)
		assert(cmp_work(state->longest_chains[n],
				state->longest_chains[0]) == 0);

	/* If multiple longest known, all should have same work! */
	for (n = 1; n < tal_count(state->longest_knowns); n++)
		assert(cmp_work(state->longest_knowns[n],
				state->longest_knowns[0]) == 0);

	for (n = 0; n < tal_count(state->block_depth); n++) {
		size_t num_this_level = num_next_level;
		list_check(state->block_depth[n], "bad block depth");
		num_next_level = 0;
		list_for_each(state->block_depth[n], i, list) {
			const struct block *b;
			assert(le32_to_cpu(i->hdr->depth) == n);
			assert(num_this_level);
			num_this_level--;
			if (n == 0)
				assert(i == genesis_block(state));
			else {
				assert(memcmp(&i->hdr->prev_block, &i->prev->sha,
					      sizeof(i->prev->sha)) == 0);
				if (i->prev->complaint)
					assert(i->complaint);
			}
			assert(i->complaint ||
			       cmp_work(i, state->longest_chains[0]) <= 0);
			if (!i->complaint && i->all_known)
				assert(cmp_work(i, state->longest_knowns[0]) <= 0);

			list_for_each(&i->children, b, sibling) {
				num_next_level++;
				assert(b->prev == i);
			}
		}
		assert(num_this_level == 0);
	}
	assert(num_next_level == 0);

	/* preferred_chain should be a descendent of longest_knowns[0] */
	for (i = state->preferred_chain;
	     i != state->longest_knowns[0];
	     i = i->prev) {
		assert(i != genesis_block(state));
		assert(!i->all_known);
	}

	/*
	 * preferred_chain is *not* state->longest_chains[0], then no
	 * chain should connect any longest_knowns to longest_chains.
	 */
	if (state->preferred_chain != state->longest_chains[0]) {
		size_t a, b;
		assert(!find_connected_pair(state, &a, &b));
	}

	/* We ignore blocks which have a problem. */
	assert(!state->preferred_chain->complaint);

	for (n = 0; n < tal_count(state->longest_knowns); n++)
		assert(!state->longest_knowns[n]->complaint);

	for (n = 0; n < tal_count(state->longest_chains); n++)
		assert(!state->longest_chains[n]->complaint);
}

static void swap_blockptr(const struct block **a, const struct block **b)
{
	const struct block *tmp = *a;
	*a = *b;
	*b = tmp;
}

/* Search descendents to find if there's one with more work than bests. */
static void find_longest_descendents(struct state *state,
				     const struct block *block,
				     const struct block ***bests)
{
	struct block *b;

	switch (cmp_work(block, (*bests)[0])) {
	case 1:
		/* Ignore previous bests, this is the best. */
		set_single(bests, block);
		break;
	case 0:
		/* Add to bests. */
		add_single(bests, block);
		break;
	}

	list_for_each(&block->children, b, sibling)
		find_longest_descendents(state, b, bests);
}

/* Returns true if it updated state->preferred_chain. */
static bool update_preferred_chain(struct state *state)
{
	const struct block **arr;

	/* Set up temporary array so we can use find_longest_descendents */
	arr = tal_arr(state, const struct block *, 1);
	arr[0] = state->longest_knowns[0];

	find_longest_descendents(state, arr[0], &arr);
	if (arr[0] == state->preferred_chain) {
		tal_free(arr);
		return false;
	}
	state->preferred_chain = arr[0];
	tal_free(arr);
	return true;
}

/*
 * If we have a choice of multiple "best" known blocks, we prefer the
 * one which leads to the longest known block.  Similarly, we prefer
 * longest chains if they're lead to by our longest known blocks.
 *
 * So, if we find such a pair, move them to the front.  Returns true
 * if they changed.
 */
static bool order_block_pointers(struct state *state)
{
	size_t chain, known;

	if (!find_connected_pair(state, &chain, &known))
		return false;

	if (chain == 0 && known == 0)
		return false;

	/* Swap these both to the front. */
	swap_blockptr(&state->longest_chains[0], &state->longest_chains[chain]);
	swap_blockptr(&state->longest_knowns[0], &state->longest_knowns[known]);
	return true;
}

/* Returns true if we changed state->longest_knowns. */
static bool update_known_recursive(struct state *state, struct block *block)
{
	struct block *b;
	bool knowns_changed;

	if (!block->prev->all_known || !block_all_known(block, NULL))
		return false;

	/* FIXME: Hack avoids writing to read-only genesis block. */
	if (!block->all_known)
		block->all_known = true;

	/* Blocks which are flawed are not useful */
	if (block->complaint)
		return false;

	switch (cmp_work(block, state->longest_knowns[0])) {
	case 1:
		log_debug(state->log, "New known block work ");
		log_add_struct(state->log, BIGNUM, &block->total_work);
		log_add(state->log, " exceeds old known work ");
		log_add_struct(state->log, BIGNUM,
			       &state->longest_knowns[0]->total_work);
		/* They're no longer longest, we are. */
		set_single(&state->longest_knowns, block);
		knowns_changed = true;
		break;
	case 0:
		add_single(&state->longest_knowns, block);
		knowns_changed = true;
		break;
	case -1:
		knowns_changed = false;
		break;
	}

	/* Check descendents. */
	list_for_each(&block->children, b, sibling) {
		if (update_known_recursive(state, b))
			knowns_changed = true;
	}
	return knowns_changed;
}

/* FIXME: Ask only the shards we care about. */
static void ask_about_block(struct state *state, const struct block *block)
{
	u16 i;

	for (i = 0; i < num_shards(block->hdr); i++) {
		if (!shard_all_known(block, i))
			todo_add_get_shard(state, &block->sha, i);
	}
}

static void ask_about_children(struct state *state, const struct block *block)
{
	const struct block *b;

	list_for_each(&block->children, b, sibling) {
		ask_about_block(state, b);
		ask_about_children(state, b);
	}
}


/* We now know complete contents of block; update all_known for this
 * block (and maybe its descendents) and if necessary, update
 * longest_known and longest_known_descendent and restart generator.
 * Caller should wake_peers() if this returns true, in case they care.
 */
static bool update_known(struct state *state, struct block *block)
{
	const struct block *prev_known = state->longest_knowns[0];
	size_t i;

	if (!update_known_recursive(state, block))
		return false;

	order_block_pointers(state);
	update_preferred_chain(state);
	check_chains(state);

	/* Ask about any children who aren't completely known. */ 
	for (i = 0; i < tal_count(state->longest_knowns); i++)
		ask_about_children(state, state->longest_knowns[i]);

	if (state->longest_knowns[0] != prev_known) {
		/* Any transactions from old branch go into pending. */
		steal_pending_transactions(state,
					   prev_known, state->longest_knowns[0]);

		/* Restart generator on this block. */
		restart_generating(state);
	}

	return true;
}

/* Now this block is the end of the longest chain.
 *
 * This matters because we want to know all about that chain so we can
 * mine it.  If everyone is sharing information normally, that should be
 * easy.
 */
static void new_longest(struct state *state, const struct block *block)
{
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

	/* We may prefer a different known (which leads to longest) now. */
	order_block_pointers(state);
	update_preferred_chain(state);
}

static bool empty_block(const struct block *block)
{
	u16 i;

	for (i = 0; i < num_shards(block->hdr); i++)
		if (block->shard_nums[i] != 0)
			return false;
	return true;
}

/* We've added a new block; update state->longest_chains, state->longest_knowns,
   state->longest_known_descendents as required. */
void update_block_ptrs_new_block(struct state *state, struct block *block)
{
	switch (cmp_work(block, state->longest_chains[0])) {
	case 1:
		log_debug(state->log, "New block work ");
		log_add_struct(state->log, BIGNUM, &block->total_work);
		log_add(state->log, " exceeds old work ");
		log_add_struct(state->log, BIGNUM,
			       &state->longest_chains[0]->total_work);
		set_single(&state->longest_chains, block);
		new_longest(state, block);
		break;
	case 0:
		add_single(&state->longest_chains, block);
		new_longest(state, block);
		break;
	}

	/* Corner case for zero transactions (will update
	 * longest_known_descendent if necessary). */
	if (empty_block(block))
		update_known(state, block);
	else
		/* FIXME: Only needed if a descendent of known[0] */
		update_preferred_chain(state);

	check_chains(state);

	/* Now, if it's as long as the best we know about, want to know more */
	if (cmp_work(block, state->longest_knowns[0]) >= 0) {
		const struct block *b;

		for (b = block; !b->all_known; b = b->prev)
			ask_about_block(state, b);
	}
}

/* We've fille a new shard; update state->longest_chains, state->longest_knowns,
   state->longest_known_descendents as required. */
void update_block_ptrs_new_shard(struct state *state, struct block *block,
				 u16 shardnum)
{
	if (block_all_known(block, NULL)) {
		/* FIXME: re-check prev_merkles for any descendents. */
		update_known(state, block);
	}
}

static void forget_about_all(struct state *state, const struct block *block)
{
	const struct block *b;

	todo_forget_about_block(state, &block->sha);
	list_for_each(&block->children, b, sibling)
		forget_about_all(state, b);
}

void update_block_ptrs_invalidated(struct state *state,
				   const struct block *block)
{
	const struct block *g = genesis_block(state);

	/* Brute force recalculation. */
	set_single(&state->longest_chains, g);
	set_single(&state->longest_knowns, g);
	state->preferred_chain = g;

	find_longest_descendents(state, g, &state->longest_chains);
	update_known(state, cast_const(struct block *, g));

	check_chains(state);

	/* We don't need to know anything about this or any decendents. */
	forget_about_all(state, block);

	/* Tell peers everything changed. */
	wake_peers(state);
}
