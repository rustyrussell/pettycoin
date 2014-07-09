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

	for (i = 0; i < ARRAY_SIZE(b->pend); i++)
		b->pend[i] = tal_arr(b, struct pending_tx *, 0);

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
	pend->tx = tal_steal(pend, tx);

	return pend;
}

static void add_to_unknown_pending(struct state *state,
				   const union protocol_tx *tx)
{
	struct pending_unknown_tx *unk;

	unk = tal(state->pending, struct pending_unknown_tx);
	unk->tx = tal_steal(unk, tx);

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

static bool find_pending_in_arr(struct pending_tx **pend,
				const union protocol_tx *tx, size_t *pos)
{
	size_t num, end;

	end = num = tal_count(pend);

	*pos = 0;
	while (*pos < end) {
		size_t halfway = (*pos + end) / 2;
		int c;

		c = tx_cmp(tx, pend[halfway]->tx);
		if (c < 0)
			end = halfway;
		else if (c > 0)
			*pos = halfway + 1;
		else
			return true;
	}
	return false;
}

static bool insert_pending_tx(struct state *state, const union protocol_tx *tx)
{
	struct pending_block *pending = state->pending;
	struct pending_tx *pend;
	u16 shard;
	size_t num, pos;

	shard = shard_of_tx(tx, next_shard_order(state->longest_knowns[0]));
	num = tal_count(pending->pend[shard]);

	if (num == 255) {
		log_unusual(state->log,
			    "Too many pending txs in shard %u", shard);
		return false;
	}

	/* Caller checks it isn't a dup! */
	if (find_pending_in_arr(pending->pend[shard], tx, &pos))
		abort();

	pend = new_pending_tx(state->pending, tx);
	pend->refs = create_refs(state, state->longest_knowns[0], tx);
	/* If check_tx_inputs() passed, this can't fail. */
	assert(pend->refs);

	/* Move down to make room, and insert */
	tal_resize(&pending->pend[shard], num + 1);
	memmove(pending->pend[shard] + pos + 1,
		pending->pend[shard] + pos,
		(num - pos) * sizeof(*pending->pend[shard]));
	pending->pend[shard][pos] = pend;

	log_debug(state->log, "Added tx to shard %u position %zu",
		  shard, pos);
	tell_generator_new_pending(state, shard, pos);
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

	/* On success, we make copy of tx (which is inside a packet) */
	switch (ierr) {
	case ECODE_INPUT_OK:
		/* If it overflows, pretend it's unknown. */
		tx = tx_dup(state->pending, tx);
		if (!insert_pending_tx(state, tx))
			add_to_unknown_pending(state, tx);
		break;
	case ECODE_INPUT_UNKNOWN:
		tx = tx_dup(state->pending, tx);
		add_to_unknown_pending(state, tx);
		break;
	case ECODE_INPUT_BAD:
	case ECODE_INPUT_BAD_AMOUNT:
	case ECODE_INPUT_DOUBLESPEND:
		return ierr;
	}

	add_pending_tx_to_hashes(state, state->pending, tx);
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

	/* Very rare, so don't optimize the remove case.  */
	restart_generating(state);
}

void drop_pending_tx(struct state *state, const union protocol_tx *tx)
{
	struct pending_tx **pend;
	u16 shard;
	size_t pos;
	struct protocol_double_sha sha;

	hash_tx(tx, &sha);
	if (!txhash_get_pending_tx(state, &sha))
		return;

	shard = shard_of_tx(tx, next_shard_order(state->longest_knowns[0]));
	pend = state->pending->pend[shard];

	if (find_pending_in_arr(pend, tx, &pos))
		remove_pending_tx(state, shard, pos);
	else {
		/* Must be in unknowns. */
		struct pending_unknown_tx *utx;

		/* FIXME: SLOW! */
		list_for_each(&state->pending->unknown_tx, utx, list) {
			if (marshal_tx_len(utx->tx) != marshal_tx_len(tx))
				continue;
			if (memcmp(utx->tx, tx, marshal_tx_len(tx)) != 0)
				continue;
			list_del_from(&state->pending->unknown_tx, &utx->list);
			state->pending->num_unknown--;
			tal_free(utx);
			return;
		}

		/* Hash said it was here somewhere! */
		abort();
		
	}
}
