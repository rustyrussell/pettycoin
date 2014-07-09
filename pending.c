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
#include "tx.h"
#include "tx_cmp.h"
#include "tx_in_hashes.h"
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
	/* FIXME: time out or limit unknown txs. */
	list_head_init(&b->unknown_tx);
	b->num_unknown = 0;
	return b;
}

static union protocol_tx *tx_dup(const tal_t *ctx, const union protocol_tx *tx)
{
	return (void *)tal_dup(ctx, char, (char *)tx, marshal_tx_len(tx), 0);
}

static struct pending_tx *new_pending_tx(const tal_t *ctx,
					 const union protocol_tx *tx)
{
	struct pending_tx *pend;

	pend = tal(ctx, struct pending_tx);
	pend->tx = tx_dup(pend, tx);

	return pend;
}

static void add_to_unknown_pending(struct state *state,
				   const union protocol_tx *tx)
{
	struct pending_unknown_tx *unk;

	unk = tal(state->pending, struct pending_unknown_tx);
	unk->tx = tx_dup(unk, tx);

	list_add_tail(&state->pending->unknown_tx, &unk->list);
	state->pending->num_unknown++;
}

/* Transfer all transaction from this block into pending array.
 * You must call recheck_pending_txs() afterwards! */
void block_to_pending(struct state *state, const struct block *block)
{
	unsigned int shard, i;

	for (shard = 0; shard < num_shards(block->hdr); shard++) {
		for (i = 0; i < block->shard_nums[shard]; i++) {
			const union protocol_tx *tx;

			tx = tx_for(block->shard[shard], i);
			if (!tx)
				continue;
			add_to_unknown_pending(state, tx);
		}
	}
}

static bool insert_pending_tx(struct state *state, const union protocol_tx *tx)
{
	struct pending_block *pending = state->pending;
	struct pending_tx *pend;
	u16 shard;
	size_t start, num, end;

	shard = shard_of_tx(tx, next_shard_order(state->longest_knowns[0]));
	num = tal_count(pending->pend[shard]);

	if (num == 255) {
		log_unusual(state->log,
			    "Too many pending txs in shard %u", shard);
		return false;
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
			/* FIXME: if pending were in hash,
			   this couldn't happen */
			log_debug(state->log,
				  "Ignoring duplicate transaction ");
			log_add_struct(state->log, union protocol_tx, tx);
			return true;
		}
	}

	pend = new_pending_tx(state->pending, tx);
	pend->refs = create_refs(state, state->longest_knowns[0], tx);
	/* If check_tx_inputs() passed, this can't fail. */
	assert(pend->refs);

	/* Move down to make room, and insert */
	tal_resize(&pending->pend[shard], num + 1);
	memmove(pending->pend[shard] + start + 1,
		pending->pend[shard] + start,
		(num - start) * sizeof(*pending->pend[shard]));
	pending->pend[shard][start] = pend;

	log_debug(state->log, "Added tx to shard %u position %zu",
		  shard, start);
	tell_generator_new_pending(state, shard, start);
	return true;
}

/* We've added a whole heap of transactions, recheck them and set input refs. */
void recheck_pending_txs(struct state *state)
{
	unsigned int unknown, known, total;
	unsigned int i, shard;
	const union protocol_tx **txs;
	struct pending_unknown_tx *utx;

	/* Size up and allocate an array. */
	unknown = state->pending->num_unknown;
	known = 0;
	for (shard = 0; shard < ARRAY_SIZE(state->pending->pend); shard++)
		known += tal_count(state->pending->pend[shard]);

	txs = tal_arr(state, const union protocol_tx *, unknown + known);

	log_debug(state->log, "Rechecking pending (%u known, %u unknown)",
		  known, unknown);

	/* Now move pending from shards. */
	total = 0;
	for (shard = 0; shard < ARRAY_SIZE(state->pending->pend); shard++) {
		struct pending_tx **pend = state->pending->pend[shard];
		unsigned int i;

		for (i = 0; i < tal_count(pend); i++) {
			remove_pending_tx_from_hashes(state, pend[i]->tx);
			txs[total++] = tal_steal(txs, pend[i]->tx);
		}
	}

	/* And last we move the unknown ones. */
	while ((utx = list_pop(&state->pending->unknown_tx,
			       struct pending_unknown_tx, list)) != NULL) {
		remove_pending_tx_from_hashes(state, utx->tx);
		txs[total++] = tal_steal(txs, utx->tx);
	}

	assert(total == unknown + known);

	/* Clean up pending (frees everything above as a side effect). */
	tal_free(state->pending);
	state->pending = new_pending_block(state);

	total = 0;
	/* Now re-add them */
	for (i = 0; i < tal_count(txs); i++) {
		unsigned int bad_input_num;
		struct protocol_double_sha sha;
		enum input_ecode ierr;

		hash_tx(txs[i], &sha);
		ierr = add_pending_tx(state, txs[i], &sha, &bad_input_num);
		if (ierr == ECODE_INPUT_OK || ierr == ECODE_INPUT_UNKNOWN)
			total++;
	}
		
	log_debug(state->log, "Now have %u known, %u unknown",
		  total - state->pending->num_unknown,
		  state->pending->num_unknown);

	/* Restart generator on this block. */
	restart_generating(state);
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

	recheck_pending_txs(state);
}

static bool find_pending_doublespend(struct state *state,
				     const union protocol_tx *tx)
{
	unsigned int i;

	for (i = 0; i < num_inputs(tx); i++) {
		struct inputhash_elem *ie;
		struct inputhash_iter iter;
		const struct protocol_input *inp = tx_input(tx, i);

		for (ie = inputhash_firstval(&state->inputhash, &inp->input,
				     le16_to_cpu(inp->output), &iter);
		     ie;
		     ie = inputhash_nextval(&state->inputhash, &inp->input,
					    le16_to_cpu(inp->output), &iter)) {
			/* OK, is the tx which spend it pending? */
			if (txhash_get_pending_tx(state, &ie->used_by))
				return true;
		}
	}
	return false;
}

enum input_ecode add_pending_tx(struct state *state,
				const union protocol_tx *tx,
				const struct protocol_double_sha *sha,
				unsigned int *bad_input_num)
{
	enum input_ecode ierr;

	/* If it's already in longest known chain, would look like
	 * doublespend so sort that out now. */
	if (txhash_gettx_ancestor(state, sha, state->longest_knowns[0]))
		return ECODE_INPUT_OK;

	/* If we already have it in pending, don't re-add. */
	if (txhash_get_pending_tx(state, sha))
		return ECODE_INPUT_OK;

	/* We check inputs for where *we* would mine it.
	 * We currently don't allow two dependent txs in the same block,
	 * so only resolve inputs in the chain. */
	ierr = check_tx_inputs(state, state->longest_knowns[0],
			       NULL, tx, bad_input_num);

	if (ierr == ECODE_INPUT_OK) {
		/* But that doesn't find doublespends in *pending*. */
		if (find_pending_doublespend(state, tx))
			ierr = ECODE_INPUT_DOUBLESPEND;
	}

	switch (ierr) {
	case ECODE_INPUT_OK:
		/* If it overflows, pretend it's unknown. */
		if (!insert_pending_tx(state, tx))
			add_to_unknown_pending(state, tx);
		add_pending_tx_to_hashes(state, state->pending, tx);
		break;
	case ECODE_INPUT_UNKNOWN:
		add_to_unknown_pending(state, tx);
		add_pending_tx_to_hashes(state, state->pending, tx);
		break;
	case ECODE_INPUT_BAD:
	case ECODE_INPUT_BAD_AMOUNT:
	case ECODE_INPUT_DOUBLESPEND:
		break;
	}

	return ierr;
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
