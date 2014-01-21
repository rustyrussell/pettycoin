#include <ccan/asort/asort.h>
#include "pending.h"
#include "prev_merkles.h"
#include "state.h"
#include "generating.h"
#include "transaction_cmp.h"
#include "block.h"

/* Find the last block that we know everything about. */
static struct block *last_full(struct state *state)
{
	struct block *i=NULL, *prev=NULL;

	/* FIXME: slow. */
	list_for_each(&state->main_chain, i, list) {
		if (!block_full(i))
			break;
		prev = i;
	}
	return prev;
}

struct pending_block *new_pending_block(struct state *state)
{
	struct pending_block *b = tal(state, struct pending_block);

	b->prev = last_full(state);
	b->prev_merkles = make_prev_merkles(b, state, b->prev,
					    generating_address(state));
	b->t = tal_arr(b, const union protocol_transaction *, 0);
	return b;
}

/* Block is no longer in main chain.  Dump all its transactions into pending:
 * followed up cleanup_pending to remove any which are in main due to other
 * blocks. */
void steal_pending_transactions(struct state *state, const struct block *block)
{
	size_t curr = tal_count(state->pending->t), num, added = 0, i;

	num = le32_to_cpu(block->hdr->num_transactions);

	/* Worst case. */
	tal_resize(&state->pending->t, curr + num);

	for (i = 0; i < num; i++) {
		union protocol_transaction *t = block_get_trans(block, i);
		if (t)
			state->pending->t[curr + added++] = t;
	}

	log_debug(state->log, "Added %zu transactions from old block",
		  added);
	tal_resize(&state->pending->t, curr + added);
}

void update_pending_transactions(struct state *state)
{
	size_t i, updated_num, num;
	assert(state);
	assert(state->pending);
	num = tal_count(state->pending->t);

	log_debug(state->log, "Searching %zu pending transactions",
		  num);
	for (i = 0; i < num; i++) {
		struct thash_elem *te;
		struct protocol_double_sha sha;

		hash_transaction(state->pending->t[i], NULL, 0, &sha);
		te = thash_get(&state->thash, &sha);

		log_debug(state->log, "%zu is %s",
			  i, te ? (te->block->main_chain ? "IN MAIN" 
				   : "OFF MAIN")
			  : "NOT FOUND");

		/* Already in main chain?  Discard. */
		if (te && te->block->main_chain) {
			memmove(state->pending->t + i,
				state->pending->t + i + 1,
				(num - i - 1) * sizeof(*state->pending->t));
			num--;
			i--;
		}

		/* FIXME: Discard if not valid any more, eg. inputs
		 * already spent. */
	}
	updated_num = tal_count(state->pending->t);
	log_debug(state->log, "Cleaned up %zu of %zu pending transactions",
		  updated_num - num, updated_num);
	tal_resize(&state->pending->t, num);

	/* Make sure they're sorted into correct order! */
	asort((union protocol_transaction **)state->pending->t,
	      num, transaction_ptr_cmp, NULL);

	/* Finally, recalculate prev_merkles. */
	tal_free(state->pending->prev_merkles);

	state->pending->prev = last_full(state);
	state->pending->prev_merkles
		= make_prev_merkles(state->pending, state, state->pending->prev,
				    generating_address(state));
}

void add_pending_gateway_transaction(struct state *state,
				     const struct protocol_transaction_gateway *gt)
{
	struct pending_block *pending = state->pending;
	const union protocol_transaction *t = (void *)gt;
	size_t start = 0, num = tal_count(pending->t), end = num;

	/* Assumes tal_count < max-size_t / 2 */
	while (start < end) {
		size_t halfway = (start + end) / 2;
		int c;

		c = transaction_cmp(t, pending->t[halfway]);
		if (c < 0)
			end = halfway;
		else if (c > 0)
			start = halfway + 1;
		else
			/* Duplicate!  Ignore it. */
			return;
	}

	/* Move down to make room, and insert */
	tal_resize(&pending->t, num + 1);
	memmove(pending->t + start + 1,
		pending->t + start,
		(num - start) * sizeof(*pending->t));
	pending->t[start] = t;

	tell_generator_new_pending(state, start);
}
