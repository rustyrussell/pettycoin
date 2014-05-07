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
#include "timestamp.h"
#include "talv.h"

/* We don't include transactions which are close to being timed out. */
#define CLOSE_TO_HORIZON 3600

struct pending_block *new_pending_block(struct state *state)
{
	struct pending_block *b = tal(state, struct pending_block);

	b->pend = tal_arr(b, struct pending_trans *, 0);
	return b;
}

static bool resolve_input(struct state *state,
			  const struct block *block,
			  struct pending_trans *pend,
			  u32 num)
{
	const struct protocol_double_sha *sha;
	struct thash_iter iter;
	struct thash_elem *te;

	assert(pend->t->hdr.type == TRANSACTION_NORMAL);
	assert(num < le32_to_cpu(pend->t->normal.num_inputs));

	sha = &pend->t->normal.input[num].input;

	for (te = thash_firstval(&state->thash, sha, &iter);
	     te;
	     te = thash_nextval(&state->thash, sha, &iter)) {
		if (!block_preceeds(te->block, block))
			continue;

		/* Don't include any transactions within 1 hour of cutoff. */
		if (le32_to_cpu(te->block->tailer->timestamp)
		    + TRANSACTION_HORIZON_SECS - CLOSE_TO_HORIZON
		    < current_time())
			return false;

		/* Add 1 since this will go into *next* block */
		pend->refs[num].blocks_ago = 
			cpu_to_le32(block->blocknum - te->block->blocknum + 1);
		pend->refs[num].txnum = cpu_to_le32(te->tnum);
		return true;
	}
	return false;
}

/* Try to find the inputs in block and its ancestors */
static bool resolve_inputs(struct state *state,
			   const struct block *block,
			   struct pending_trans *pend)
{
	u32 i, num = num_inputs(pend->t);

	for (i = 0; i < num; i++)
		if (!resolve_input(state, block, pend, i))
			return false;

	return true;
}

static struct pending_trans *new_pending_trans(const tal_t *ctx,
					       const union protocol_transaction *t)
{
	struct pending_trans *pend;

	pend = tal(ctx, struct pending_trans);
	pend->t = t;
	pend->refs = tal_arr(pend, struct protocol_input_ref, num_inputs(t));

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
		e = check_transaction(state, state->pending->pend[i]->t,
				      NULL, NULL, inputs, &bad_input_num);
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

		/* FIXME: Usually this is a simple increment to
		 * ->refs[].blocks_ago. */
		if (!resolve_inputs(state, state->longest_known,
				    state->pending->pend[i])) {
			/* FIXME: put this into pending-awaiting list! */
			log_debug(state->log, "  inputs no longer known");
			goto discard;
		}
		continue;

	discard:
		remove_trans_from_peers(state, state->pending->pend[i]->t);
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
	if (!resolve_inputs(peer->state, peer->state->longest_known, pend)) {
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
	add_trans_to_peers(peer->state, peer, t);
}
