#include "block.h"
#include "chain.h"
#include "check_block.h"
#include "complain.h"
#include "generating.h"
#include "hex.h"
#include "jsonrpc.h"
#include "peer.h"
#include "pending.h"
#include "shard.h"
#include "tal_arr.h"
#include "todo.h"
#include "tx.h"
#include <ccan/cast/cast.h>
#include <ccan/structeq/structeq.h>
#include <ccan/tal/str/str.h>
#include <time.h>

/* Simply block array helpers */
static void set_single(const struct block ***arr, const struct block *b)
{
	tal_resize(arr, 1);
	(*arr)[0] = b;
}

struct block *step_towards(const struct block *curr, const struct block *target)
{
	const struct block *prev_target;

	/* Move back towards target. */
	while (le32_to_cpu(curr->hdr->height) > le32_to_cpu(target->hdr->height))
		curr = curr->prev;

	/* Already past it, or equal to it */
	if (curr == target)
		return NULL;

	/* Move target back towards curr. */
	while (le32_to_cpu(target->hdr->height) > le32_to_cpu(curr->hdr->height)) {
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

void check_chains(struct state *state, bool all)
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

	/* Checking the actual blocks is expensive! */
	if (!all)
		return;

	for (n = 0; n < tal_count(state->block_height); n++) {
		size_t num_this_level = num_next_level;
		list_check(state->block_height[n], "bad block height");
		num_next_level = 0;
		list_for_each(state->block_height[n], i, list) {
			const struct block *b;
			assert(le32_to_cpu(i->hdr->height) == n);
			assert(num_this_level);
			num_this_level--;
			if (n == 0)
				assert(i == genesis_block(state));
			else {
				assert(structeq(&i->hdr->prev_block,
						&i->prev->sha));
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
			check_block(state, i, all);
		}
			assert(num_this_level == 0);
	}
	assert(num_next_level == 0);
}

static void swap_blockptr(const struct block **a, const struct block **b)
{
	const struct block *tmp = *a;
	*a = *b;
	*b = tmp;
}

/* Search descendents to find if there's one with more work than bests. */
static void find_longest_descendents(const struct block *block,
				     const struct block ***bests)
{
	struct block *b;

	if (block->complaint)
		return;

	switch (cmp_work(block, (*bests)[0])) {
	case 1:
		/* Ignore previous bests, this is the best. */
		set_single(bests, block);
		break;
	case 0:
		/* Add to bests. */
		tal_arr_append(bests, block);
		break;
	}

	list_for_each(&block->children, b, sibling)
		find_longest_descendents(b, bests);
}

/* Returns true if it updated state->preferred_chain. */
static bool update_preferred_chain(struct state *state)
{
	const struct block **arr;

	/* Set up temporary array so we can use find_longest_descendents */
	arr = tal_arr(state, const struct block *, 1);
	arr[0] = state->longest_knowns[0];

	find_longest_descendents(arr[0], &arr);
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

	if (block->prev && !block->prev->all_known)
		return false;

	if (!block_all_known(block))
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
		tal_arr_append(&state->longest_knowns, block);
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

/* We're moving longest_known from old to new.  Dump all its transactions into
 * pending. */
static void steal_pending_txs(struct state *state,
			      const struct block *old,
			      const struct block *new)
{
	const struct block *end, *b;

	/* Traverse old path and take transactions */
	end = step_towards(new, old);
	if (end) {
		for (b = old; b != end->prev; b = b->prev)
			block_to_pending(state, b);
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

	if (!update_known_recursive(state, block))
		return false;

	state->pending->needs_recheck = true;

	order_block_pointers(state);
	update_preferred_chain(state);

	if (state->longest_knowns[0] != prev_known) {
		/* Any transactions from old branch go into pending. */
		steal_pending_txs(state, prev_known, state->longest_knowns[0]);
	}

	/* FIXME: If we've timed out asking about preferred_chain or
	 * longest_knowns, refresh. */

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
			+ (PROTOCOL_FEATURE_CONFIRM_DELAY
			   * PROTOCOL_BLOCK_TARGET_TIME(state->test_net) / 2);
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

static void recheck_merkles(struct state *state, struct block *block)
{
	const struct block *bad_prev;
	u16 bad_prev_shard;

	if (!check_prev_txhashes(state, block, &bad_prev, &bad_prev_shard))
		complain_bad_prev_txhashes(state, block,
					   bad_prev, bad_prev_shard);
	else {
		struct block *b;

		/* FIXME: SLOW: We actually only need to check one byte of
		 * every 2^N-distance block */
		list_for_each(&block->children, b, sibling)
			recheck_merkles(state, b);
	}
}

static void update_block_ptrs_new_shard_or_empty(struct state *state,
						 struct block *block,
						 u16 shardnum)
{
	struct block *b;

	list_for_each(&block->children, b, sibling)
		recheck_merkles(state, block);
}

/* We've added a new block; update state->longest_chains, state->longest_knowns,
   state->longest_known_descendents as required. */
void update_block_ptrs_new_block(struct state *state, struct block *block)
{
	unsigned int i;

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
		tal_arr_append(&state->longest_chains, block);
		new_longest(state, block);
		break;
	}

	/* Corner case for zero transactions: we can't call
	 * update_block_ptrs_new_shard() directly, since that would
	 * call update_known multiple times if block completely
	 * known, which breaks the longest_known[] calc.  */
	for (i = 0; i < num_shards(block->hdr); i++) {
		if (block->shard_nums[i] == 0)
			update_block_ptrs_new_shard_or_empty(state, block, i);
	}
	if (block_all_known(block)) {
		update_known(state, block);
	}

	/* FIXME: Only needed if a descendent of known[0] */
	update_preferred_chain(state);
}

/* Filled a new shard; update state->longest_chains, state->longest_knowns,
   state->longest_known_descendents as required. */
void update_block_ptrs_new_shard(struct state *state, struct block *block,
				 u16 shardnum)
{
	update_block_ptrs_new_shard_or_empty(state, block, shardnum);
	if (block_all_known(block)) {
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

	find_longest_descendents(g, &state->longest_chains);
	update_known(state, cast_const(struct block *, g));

	check_chains(state, false);

	/* We don't need to know anything about this or any decendents. */
	forget_about_all(state, block);

	/* Tell peers everything changed. */
	wake_peers(state);
}

static void json_add_tx(char **response,
			const struct block_shard *s,
			unsigned int txoff)
{
	if (shard_is_tx(s, txoff)) {
		const union protocol_tx *tx = s->u[txoff].txp.tx;
		struct protocol_double_sha sha;
		const struct protocol_input_ref *refs;
		unsigned int i;

		/* Unknown?  We leave object empty. */
		if (!tx)
			return;

		hash_tx(s->u[txoff].txp.tx, &sha);
		/* "tx" indicates that we know this tx. */
		json_add_double_sha(response, "tx", &sha);
		json_array_start(response, "refs");
		refs = refs_for(s->u[txoff].txp);
		for (i = 0; i < num_inputs(tx); i++) {
			json_object_start(response, NULL);
			json_add_num(response, "blocks_ago",
				     le32_to_cpu(refs[i].blocks_ago));
			json_add_num(response, "shard",
				     le16_to_cpu(refs[i].shard));
			json_add_num(response, "txoff", refs[i].txoff);
			json_object_end(response);
		}
		json_array_end(response);
	} else {
		/* We know hash, but not actual tx. */
		const struct protocol_txrefhash *hash = s->u[txoff].hash;

		json_add_double_sha(response, "txhash", &hash->txhash);
		json_add_double_sha(response, "refhash", &hash->refhash);
	}
}

static char *json_getblock(struct json_connection *jcon,
			   const jsmntok_t *params,
			   char **response)
{
	struct protocol_double_sha sha;
	const struct block *b, *b2;
	jsmntok_t *block;
	unsigned int shardnum, i;

	json_get_params(jcon->buffer, params, "block", &block, NULL);
	if (!block)
		return "Need block param";

	if (!from_hex(jcon->buffer + block->start,
		      block->end - block->start, &sha, sizeof(sha)))
		return tal_fmt(jcon, "Invalid block hex %.*s",
			       json_tok_len(block),
			       json_tok_contents(jcon->buffer, block));

	b = block_find_any(jcon->state, &sha);
	if (!b)
		return tal_fmt(jcon, "Unknown block %.*s",
			       json_tok_len(block),
			       json_tok_contents(jcon->buffer, block));

	json_object_start(response, NULL);
	json_add_double_sha(response, "hash", &b->sha);
	json_add_num(response, "version", b->hdr->version);
	json_add_num(response, "features_vote", b->hdr->features_vote);
	json_add_num(response, "shard_order", b->hdr->shard_order);
	json_add_num(response, "nonce1", le32_to_cpu(b->tailer->nonce1));
	json_add_hex(response, "nonce2", b->hdr->nonce2,
		     sizeof(b->hdr->nonce2));
	json_add_num(response, "height", le32_to_cpu(b->hdr->height));
	json_add_address(response, "fees_to",
			 jcon->state->test_net, &b->hdr->fees_to);
	json_add_num(response, "timestamp",
		     le32_to_cpu(b->tailer->timestamp));
	json_add_num(response, "difficulty",
		     le32_to_cpu(b->tailer->difficulty));
	json_add_double_sha(response, "prev", &b->hdr->prev_block);
	json_array_start(response, "next");
	list_for_each(&b->children, b2, sibling)
		json_add_double_sha(response, NULL, &b2->sha);
	json_array_end(response);

	json_array_start(response, "merkles");
	for (shardnum = 0; shardnum < num_shards(b->hdr); shardnum++)
		json_add_double_sha(response, NULL, &b->merkles[shardnum]);
	json_array_end(response);
	
	json_array_start(response, "shards");
	for (shardnum = 0; shardnum < num_shards(b->hdr); shardnum++) {
		struct block_shard *s = b->shard[shardnum];

		json_array_start(response, NULL);
		for (i = 0; i < s->size; i++) {
			json_object_start(response, NULL);
			json_add_tx(response, s, i);
			json_object_end(response);
		}
		json_array_end(response);
	}
	json_array_end(response);
	json_object_end(response);
	return NULL;
}

const struct json_command getblock_command = {
	"getblock",
	json_getblock,
	"Get a description of a given block",
	"hash, version, features_vote, shard_order, nonce1, nonce2, height, fees_to, timestamp, difficulty, prev, next[], merkles[], shards[ [{tx,refs[]}|{}|{txhash,refhash} ] ]"
};
