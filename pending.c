#include <ccan/asort/asort.h>
#include <ccan/array_size/array_size.h>
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
#include "shard.h"

struct pending_block *new_pending_block(struct state *state)
{
	struct pending_block *b = tal(state, struct pending_block);
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(b->pending_counts); i++) {
		b->pending_counts[i] = 0;
		b->pend[i] = tal_arr(b, struct pending_trans *, 0);
	}
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

/* Transfer all transaction from this shard into pending array. */
static void shard_to_pending(struct state *state,
			     const struct block *block, u16 shard)
{
	size_t curr = tal_count(state->pending->pend), num, added = 0, i;

	num = block->shard_nums[shard];

	/* Worst case. */
	tal_resize(&state->pending->pend[shard], curr + num);

	for (i = 0; i < num; i++) {
		struct pending_trans *pend;
		union protocol_transaction *t;

		t = block_get_tx(block, shard, i);
		if (!t)
			continue;

		/* FIXME: Transfer block->refs directly! */
		pend = new_pending_trans(state->pending, t);
		state->pending->pend[shard][curr + added++] = pend;
	}

	log_debug(state->log, "Added %zu transactions from old shard %u",
		  added, shard);
	tal_resize(&state->pending->pend[shard], curr + added);
}

/* Transfer all transaction from this block into pending array. */
static void block_to_pending(struct state *state,
			     const struct block *block)
{
	u16 shard;

	for (shard = 0; shard < num_shards(block->hdr); shard++)
		shard_to_pending(state, block, shard);
}

static int pending_trans_cmp(struct pending_trans *const *a,
			     struct pending_trans *const *b,
			     void *unused)
{
	return transaction_cmp((*a)->t, (*b)->t);
}

/* Returns num removed. */
static size_t recheck_one_shard(struct state *state, u16 shard)
{
	struct pending_trans **pend = state->pending->pend[shard];
	size_t i, num, start_num = tal_count(pend);

	num = start_num;
	for (i = 0; i < num; i++) {
		struct thash_elem *te;
		struct protocol_double_sha sha;
		union protocol_transaction *inputs[TRANSACTION_MAX_INPUTS];
		unsigned int bad_input_num;
		enum protocol_error e;
		struct thash_iter iter;
		bool in_known_chain = false;

		hash_tx(pend[i]->t, &sha);

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
		e = check_transaction(state, pend[i]->t,
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
		tal_free(pend[i]->refs);
		pend[i]->refs = create_refs(state, state->longest_knowns[0],
				            pend[i]->t);
		if (!pend[i]->refs) {
			/* FIXME: put this into pending-awaiting list! */
			log_debug(state->log, "  inputs no longer known");
			goto discard;
		}
		continue;

	discard:
		/* FIXME:
		 * remove_trans_from_peers(state, pend[i]->t);
		 */
		memmove(pend + i, pend + i + 1, (num - i - 1) * sizeof(*pend));
		num--;
		i--;
	}

	tal_resize(&state->pending->pend[shard], num);

	/* Make sure they're sorted into correct order (since
	 * block_to_pending doesn't) */
	asort(state->pending->pend[shard], num, pending_trans_cmp, NULL);

	return start_num - num;
}

/* We've added a whole heap of transactions, recheck them and set input refs. */
static void recheck_pending_transactions(struct state *state)
{
	size_t shard, removed = 0;

	log_debug(state->log, "Searching pending transactions");
	for (shard = 0; shard < ARRAY_SIZE(state->pending->pend); shard++)
		removed += recheck_one_shard(state, shard);

	log_debug(state->log, "Cleaned up %zu pending transactions", removed);
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

/* FIXME: Don't leak transactions on failure! */
void add_pending_transaction(struct peer *peer,
			     const union protocol_transaction *t)
{
	struct pending_block *pending = peer->state->pending;
	struct pending_trans *pend;
	u16 shard;
	size_t start, num, end;

	shard = shard_of_tx(t,next_shard_order(peer->state->longest_knowns[0]));
	num = tal_count(pending->pend[shard]);

	/* FIXME: put this into pending-awaiting list (and xmit) */
	if (num == 255)
		return;

	start = 0;
	end = num;
	while (start < end) {
		size_t halfway = (start + end) / 2;
		int c;

		c = transaction_cmp(t, pending->pend[shard][halfway]->t);
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
	tal_resize(&pending->pend[shard], num + 1);
	memmove(pending->pend[shard] + start + 1,
		pending->pend[shard] + start,
		(num - start) * sizeof(*pending->pend[shard]));
	pending->pend[shard][start] = pend;

	tell_generator_new_pending(peer->state, shard, start);
	send_trans_to_peers(peer->state, peer, t);
}

/* FIXME: SLOW! Put pending into txhash? */
struct txptr_with_ref
find_pending_tx_with_ref(const tal_t *ctx,
			 struct state *state,
			 const struct block *block,
			 const struct protocol_net_txrefhash *hash)
{
	size_t shard;
	struct protocol_input_ref *refs;
	struct txptr_with_ref r;

	for (shard = 0; shard < ARRAY_SIZE(state->pending->pend); shard++) {
		struct pending_trans **pend = state->pending->pend[shard];
		size_t i, num = tal_count(pend);

		for (i = 0; i < num; i++) {
			struct protocol_double_sha sha;

			/* FIXME: Cache sha of tx in pending? */
			hash_tx(pend[i]->t, &sha);
			if (memcmp(&hash->txhash, &sha, sizeof(sha)) != 0)
				continue;

			/* FIXME: If peer->state->longest_knowns[0]->prev ==
			   block->prev, then pending refs will be the same... */

			/* This can fail if refs don't work for that block. */
			refs = create_refs(state, block->prev, pend[i]->t);
			if (!refs)
				continue;

			hash_refs(refs, tal_count(refs), &sha);
			if (memcmp(&hash->refhash, &sha, sizeof(sha)) != 0) {
				tal_free(refs);
				continue;
			}

			r = txptr_with_ref(ctx, pend[i]->t, refs);
			tal_free(refs);
			return r;
		}
	}

	r.tx = NULL;
	return r;
}
