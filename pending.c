#include <ccan/asort/asort.h>
#include "pending.h"
#include "prev_merkles.h"
#include "state.h"
#include "generating.h"
#include "transaction_cmp.h"
#include "check_transaction.h"
#include "create_refs.h"
#include "block.h"
#include "peer.h"
#include "chain.h"
#include "timestamp.h"
#include "talv.h"

struct pending_block *new_pending_block(struct state *state)
{
	struct pending_block *b = tal(state, struct pending_block);

	b->pend = tal_arr(b, struct pending_trans *, 0);
	return b;
}


static struct pending_trans *new_pending_trans(const tal_t *ctx,
					       const union protocol_transaction *t)
{
	struct pending_trans *pend;

	pend = tal(ctx, struct pending_trans);
	pend->t = t;

	return pend;
}

/* Transfer all transaction from this block into pending array. */
static void block_to_pending(struct state *state,
			     const struct block *block)
{
	size_t curr = tal_count(state->pending->pend), num, added = 0, i;

	num = le32_to_cpu(block->hdr->num_transactions);

	/* Worst case. */
	tal_resize(&state->pending->pend, curr + num);

	for (i = 0; i < num; i++) {
		struct pending_trans *pend;
		union protocol_transaction *t = block_get_trans(block, i);

		if (!t)
			continue;

		/* FIXME: Transfer block->refs directly! */
		pend = new_pending_trans(state->pending, t);
		state->pending->pend[curr + added++] = pend;
	}

	log_debug(state->log, "Added %zu transactions from old block",
		  added);
	tal_resize(&state->pending->pend, curr + added);
}

static int pending_trans_cmp(struct pending_trans *const *a,
			     struct pending_trans *const *b,
			     void *unused)
{
	return transaction_cmp((*a)->t, (*b)->t);
}

/* We've added a whole heap of transactions, recheck them and set input refs. */
static void recheck_pending_transactions(struct state *state)
{
	size_t i, num = tal_count(state->pending->pend);

	log_debug(state->log, "Searching %zu pending transactions", num);
	for (i = 0; i < num; i++) {
		struct thash_elem *te;
		struct protocol_double_sha sha;
		union protocol_transaction *inputs[TRANSACTION_MAX_INPUTS];
		unsigned int bad_input_num;
		enum protocol_error e;
		struct thash_iter iter;
		bool in_known_chain = false;

		hash_tx(state->pending->pend[i]->t, &sha);

		for (te = thash_firstval(&state->thash, &sha, &iter);
		     te;
		     te = thash_nextval(&state->thash, &sha, &iter)) {
			if (block_preceeds(te->block, state->longest_knowns[0]))
				in_known_chain = true;
		}

		/* Already in known chain?  Discard. */
		if (in_known_chain) {
			log_debug(state->log, "  %zu is FOUND", i);
			goto discard;
		}
		log_debug(state->log, "  %zu is NOT FOUND", i);

		/* Discard if no longer valid (inputs already spent) */
		e = check_transaction(state, state->pending->pend[i]->t,
				      NULL, NULL, inputs, &bad_input_num);
		if (e) {
			log_debug(state->log, "  %zu is now ", i);
			log_add_enum(state->log, enum protocol_error, e);
			if (e == PROTOCOL_ERROR_PRIV_TRANS_BAD_INPUT) {
				log_add(state->log,
					": input %u ", bad_input_num);
				log_add_struct(state->log,
					       union protocol_transaction,
					       inputs[bad_input_num]);
			}
			goto discard;
		}

		/* FIXME: Usually this is a simple increment to
		 * ->refs[].blocks_ago. */
		tal_free(state->pending->pend[i]->refs);
		state->pending->pend[i]->refs
			= create_refs(state, state->longest_knowns[0],
				      state->pending->pend[i]->t);
		if (!state->pending->pend[i]->refs) {
			/* FIXME: put this into pending-awaiting list! */
			log_debug(state->log, "  inputs no longer known");
			goto discard;
		}
		continue;

	discard:
		/* FIXME:
		 * remove_trans_from_peers(state, state->pending->pend[i]->t);
		 */
		memmove(state->pending->pend + i,
			state->pending->pend + i + 1,
			(num - i - 1) * sizeof(*state->pending->pend));
		num--;
		i--;
	}
	log_debug(state->log, "Cleaned up %zu of %zu pending transactions",
		  tal_count(state->pending->pend) - num,
		  tal_count(state->pending->pend));
	tal_resize(&state->pending->pend, num);

	/* Make sure they're sorted into correct order! */
	asort(state->pending->pend, num, pending_trans_cmp, NULL);
}

/* We're moving longest_known from old to new.  Dump all its transactions into
 * pending, then check their validity in the new chain. */
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

	/* FIXME: Transfer any awaiting which are now known. */
	recheck_pending_transactions(state);
}

void add_pending_transaction(struct peer *peer,
			     const union protocol_transaction *t)
{
	struct pending_block *pending = peer->state->pending;
	struct pending_trans *pend;
	size_t start = 0, num = tal_count(pending->pend), end = num;

	/* Assumes tal_count < max-size_t / 2 */
	while (start < end) {
		size_t halfway = (start + end) / 2;
		int c;

		c = transaction_cmp(t, pending->pend[halfway]->t);
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

	pend = new_pending_trans(peer->state, t);
	pend->refs = create_refs(peer->state, peer->state->longest_knowns[0],
				 t);
	if (!pend->refs) {
		/* FIXME: put this into pending-awaiting list! */
		tal_free(pend);
		return;
	}

	/* Move down to make room, and insert */
	tal_resize(&pending->pend, num + 1);
	memmove(pending->pend + start + 1,
		pending->pend + start,
		(num - start) * sizeof(*pending->pend));
	pending->pend[start] = pend;

	tell_generator_new_pending(peer->state, start);
	send_trans_to_peers(peer->state, peer, t);
}
