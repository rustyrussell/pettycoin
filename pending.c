#include "block.h"
#include "chain.h"
#include "check_tx.h"
#include "create_refs.h"
#include "generating.h"
#include "peer.h"
#include "pending.h"
#include "shard.h"
#include "state.h"
#include "timestamp.h"
#include "tx_cmp.h"
#include <ccan/array_size/array_size.h>
#include <ccan/asort/asort.h>
#include <ccan/structeq/structeq.h>

struct pending_block *new_pending_block(struct state *state)
{
	struct pending_block *b = tal(state, struct pending_block);
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(b->pending_counts); i++) {
		b->pending_counts[i] = 0;
		b->pend[i] = tal_arr(b, struct pending_tx *, 0);
	}
	return b;
}


static struct pending_tx *new_pending_tx(const tal_t *ctx,
					 const union protocol_tx *tx)
{
	struct pending_tx *pend;

	pend = tal(ctx, struct pending_tx);
	pend->tx = tx;

	return pend;
}

/* Transfer all transaction from this shard into pending array. */
static void shard_to_pending(struct state *state,
			     const struct block *block, u16 shard)
{
	size_t curr = tal_count(state->pending->pend[shard]), num, added = 0, i;

	num = block->shard_nums[shard];

	/* Worst case. */
	tal_resize(&state->pending->pend[shard], curr + num);

	for (i = 0; i < num; i++) {
		struct pending_tx *pend;
		union protocol_tx *tx;

		tx = block_get_tx(block, shard, i);
		if (!tx)
			continue;

		/* FIXME: Transfer block->refs directly! */
		pend = new_pending_tx(state->pending, tx);
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

static int pending_tx_cmp(struct pending_tx *const *a,
			  struct pending_tx *const *b,
			  void *unused)
{
	return tx_cmp((*a)->tx, (*b)->tx);
}

/* Returns num removed. */
static size_t recheck_one_shard(struct state *state, u16 shard)
{
	struct pending_tx **pend = state->pending->pend[shard];
	size_t i, num, start_num = tal_count(pend);

	num = start_num;
	for (i = 0; i < num; i++) {
		struct txhash_elem *te;
		struct protocol_double_sha sha;
		unsigned int bad_input_num;
		enum input_ecode e;
		struct txhash_iter iter;
		bool in_known_chain = false;

		hash_tx(pend[i]->tx, &sha);

		for (te = txhash_firstval(&state->txhash, &sha, &iter);
		     te;
		     te = txhash_nextval(&state->txhash, &sha, &iter)) {
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
		e = check_tx_inputs(state, pend[i]->tx, &bad_input_num);
		if (e) {
			log_debug(state->log, "  %zu is now ", i);
			log_add_enum(state->log, enum input_ecode, e);
			log_add(state->log, ": input %u ", bad_input_num);
			goto discard;
		}

		/* FIXME: Usually this is a simple increment to
		 * ->refs[].blocks_ago. */
		tal_free(pend[i]->refs);
		pend[i]->refs = create_refs(state, state->longest_knowns[0],
				            pend[i]->tx);
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
	asort(state->pending->pend[shard], num, pending_tx_cmp, NULL);

	return start_num - num;
}

/* We've added a whole heap of transactions, recheck them and set input refs. */
static void recheck_pending_txs(struct state *state)
{
	size_t shard, removed = 0;

	log_debug(state->log, "Searching pending transactions");
	for (shard = 0; shard < ARRAY_SIZE(state->pending->pend); shard++)
		removed += recheck_one_shard(state, shard);

	log_debug(state->log, "Cleaned up %zu pending transactions", removed);
}

/* We're moving longest_known from old to new.  Dump all its transactions into
 * pending, then check their validity in the new chain. */
void steal_pending_txs(struct state *state,
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
	recheck_pending_txs(state);
}

/* FIXME: Don't leak transactions on failure! */
void add_pending_tx(struct peer *peer, const union protocol_tx *tx)
{
	struct pending_block *pending = peer->state->pending;
	struct pending_tx *pend;
	u16 shard;
	size_t start, num, end;

	shard = shard_of_tx(tx,
			    next_shard_order(peer->state->longest_knowns[0]));
	num = tal_count(pending->pend[shard]);

	/* FIXME: put this into pending-awaiting list (and xmit) */
	if (num == 255) {
		log_unusual(peer->state->log,
			    "Too many pending txs in shard %u: dropping",
			    shard);
		return;
	}

	start = 0;
	end = num;
	while (start < end) {
		size_t halfway = (start + end) / 2;
		int c;

		c = tx_cmp(tx, pending->pend[shard][halfway]->tx);
		if (c < 0)
			end = halfway;
		else if (c > 0)
			start = halfway + 1;
		else {
			/* Duplicate!  Ignore it. */
			log_debug(peer->log, "Ignoring duplicate transaction ");
			log_add_struct(peer->log, union protocol_tx, tx);
			return;
		}
	}

	pend = new_pending_tx(peer->state, tx);
	pend->refs = create_refs(peer->state, peer->state->longest_knowns[0],
				 tx);
	if (!pend->refs) {
		log_debug(peer->log, "Could not create refs for tx");
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

	log_debug(peer->log, "Added tx to shard %u position %zu", shard, start);
	tell_generator_new_pending(peer->state, shard, start);
	send_tx_to_peers(peer->state, peer, tx);
}

static void remove_pending_tx(struct state *state,
			      u16 shard, unsigned int i)
{
	struct pending_block *pending = state->pending;
	size_t num = tal_count(pending->pend[shard]);

	memmove(pending->pend[shard] + i,
		pending->pend[shard] + i + 1,
		(num - i - 1) * sizeof(*pending->pend[shard]));
	tal_resize(&pending->pend[shard], num - 1);
}

/* FIXME: SLOW! Put pending into txhash? */
struct txptr_with_ref
find_pending_tx_with_ref(const tal_t *ctx,
			 struct state *state,
			 const struct block *block,
			 u16 shard,
			 const struct protocol_txrefhash *hash)
{
	struct protocol_input_ref *refs;
	struct txptr_with_ref r;
	struct pending_tx **pend = state->pending->pend[shard];
	size_t i, num = tal_count(pend);

	/* If this block preceeds where we're mining, we would have to change.
	 * But we always know everything about longest_knowns[0], so that
	 * can't happen. */
	assert(!block_preceeds(block, state->longest_knowns[0]));

	for (i = 0; i < num; i++) {
		struct protocol_double_sha sha;

		/* FIXME: Cache sha of tx in pending? */
		hash_tx(pend[i]->tx, &sha);
		if (!structeq(&hash->txhash, &sha))
			continue;

		/* FIXME: If peer->state->longest_knowns[0]->prev ==
		   block->prev, then pending refs will be the same... */

		/* This can fail if refs don't work for that block. */
		refs = create_refs(state, block->prev, pend[i]->tx);
		if (!refs)
			continue;

		hash_refs(refs, tal_count(refs), &sha);
		if (!structeq(&hash->refhash, &sha)) {
			tal_free(refs);
			continue;
		}

		r = txptr_with_ref(ctx, pend[i]->tx, refs);
		tal_free(refs);
		remove_pending_tx(state, shard, i);
		return r;
	}

	r.tx = NULL;
	return r;
}

/* FIXME: slow! */
const union protocol_tx *
find_pending_tx(struct state *state,
		const struct protocol_double_sha *hash)
{
	unsigned int shard, i;

	for (shard = 0; shard < ARRAY_SIZE(state->pending->pend); shard++) {
		for (i = 0; i < tal_count(state->pending->pend[shard]); i++) {
			struct protocol_double_sha sha;

			hash_tx(state->pending->pend[shard][i]->tx, &sha);
			if (structeq(&sha, hash))
				return state->pending->pend[shard][i]->tx;
		}
	}
	return NULL;
}

void drop_pending_tx(struct state *state, const union protocol_tx *tx)
{
	struct pending_tx **pend;
	u16 shard;
	size_t i, num;

	shard = shard_of_tx(tx, next_shard_order(state->longest_knowns[0]));
	pend = state->pending->pend[shard];
	num = tal_count(pend);

	for (i = 0; i < num; i++) {
		if (marshal_tx_len(pend[i]->tx) != marshal_tx_len(tx))
			continue;
		if (memcmp(pend[i]->tx, tx, marshal_tx_len(tx)) != 0)
			continue;
		remove_pending_tx(state, shard, i);
		break;
	}
}
