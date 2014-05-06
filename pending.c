#include <ccan/asort/asort.h>
#include "pending.h"
#include "prev_merkles.h"
#include "state.h"
#include "generating.h"
#include "transaction_cmp.h"
#include "check_transaction.h"
#include "block.h"
#include "peer.h"
#include "chain.h"

struct pending_block *new_pending_block(struct state *state)
{
	struct pending_block *b = tal(state, struct pending_block);

	b->t = tal_arr(b, const union protocol_transaction *, 0);
	return b;
}

/* Transfer all transaction from this block into pending array. */
static void block_to_pending(struct state *state, const struct block *block)
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

/* We've added a whole heap of transactions, recheck them. */
static void recheck_pending_transactions(struct state *state)
{
	size_t i, num = tal_count(state->pending->t);

	log_debug(state->log, "Searching %zu pending transactions", num);
	for (i = 0; i < num; i++) {
		struct thash_elem *te;
		struct protocol_double_sha sha;
		union protocol_transaction *inputs[TRANSACTION_MAX_INPUTS];
		unsigned int bad_input_num;
		enum protocol_error e;
		struct thash_iter iter;
		bool in_known_chain = false;

		hash_transaction(state->pending->t[i], NULL, 0, &sha);

		for (te = thash_firstval(&state->thash, &sha, &iter);
		     te;
		     te = thash_nextval(&state->thash, &sha, &iter)) {
			if (block_preceeds(te->block, state->longest_known))
				in_known_chain = true;
		}

		/* Already in known chain?  Discard. */
		if (in_known_chain) {
			log_debug(state->log, "  %zu is FOUND", i);
			goto discard;
		}
		log_debug(state->log, "  %zu is NOT FOUND", i);
			
		/* Discard if no longer valid (inputs already spent) */
		e = check_transaction(state, state->pending->t[i],
				      inputs, &bad_input_num);
		if (e) {
			log_debug(state->log, "  %zu is now ", i);
			log_add_enum(state->log, enum protocol_error, e);
			if (e == PROTOCOL_ERROR_TRANS_BAD_INPUT) {
				log_add(state->log,
					": input %u ", bad_input_num);
				log_add_struct(state->log,
					       union protocol_transaction,
					       inputs[bad_input_num]);
			}
			goto discard;
		}
		continue;

	discard:
		remove_trans_from_peers(state, state->pending->t[i]);
		memmove(state->pending->t + i,
			state->pending->t + i + 1,
			(num - i - 1) * sizeof(*state->pending->t));
		num--;
		i--;
	}
	log_debug(state->log, "Cleaned up %zu of %zu pending transactions",
		  tal_count(state->pending->t) - num,
		  tal_count(state->pending->t));
	tal_resize(&state->pending->t, num);

	/* Make sure they're sorted into correct order! */
	asort((union protocol_transaction **)state->pending->t,
	      num, transaction_ptr_cmp, NULL);
}

/* We're moving longest_known from old to new.  Dump all its transactions into
 * pending: followed up update_pending_transactions to remove any
 * which are in main due to other blocks. */
void steal_pending_transactions(struct state *state,
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

	recheck_pending_transactions(state);
}

void add_pending_transaction(struct peer *peer,
			     const union protocol_transaction *t)
{
	struct pending_block *pending = peer->state->pending;
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
		else {
			/* Duplicate!  Ignore it. */
			log_debug(peer->log, "Ignoring duplicate transaction ");
			log_add_struct(peer->log, union protocol_transaction,
				       t);
			return;
		}
	}

	/* Move down to make room, and insert */
	tal_resize(&pending->t, num + 1);
	memmove(pending->t + start + 1,
		pending->t + start,
		(num - start) * sizeof(*pending->t));
	pending->t[start] = t;

	tell_generator_new_pending(peer->state, start);
	add_trans_to_peers(peer->state, peer, t);
}
