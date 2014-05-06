#include "check_block.h"
#include "version.h"
#include "overflows.h"
#include "protocol.h"
#include "protocol_net.h"
#include "block.h"
#include "state.h"
#include "timestamp.h"
#include "difficulty.h"
#include "shadouble.h"
#include "hash_transaction.h"
#include "merkle_transactions.h"
#include "transaction_cmp.h"
#include "hash_block.h"
#include "prev_merkles.h"
#include "generating.h"
#include "check_transaction.h"
#include <ccan/array_size/array_size.h>
#include <ccan/tal/tal.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* Returns NULL if bad.  Not sufficient by itself: see check_batch_valid and
 * check_block_prev_merkles! */
enum protocol_error
check_block_header(struct state *state,
		   const struct protocol_block_header *hdr,
		   const struct protocol_double_sha *merkles,
		   const u8 *prev_merkles,
		   const struct protocol_block_tailer *tailer,
		   struct block **blockp)
{
	struct block *block = (*blockp) = tal(state, struct block);
	enum protocol_error e;

	if (!version_ok(hdr->version)) {
		e = PROTOCOL_ERROR_BLOCK_HIGH_VERSION;
		goto fail;
	}

	/* Don't just search on main chain! */
	block->prev = block_find_any(state, &hdr->prev_block);
	if (!block->prev) {
		e = PROTOCOL_ERROR_UNKNOWN_PREV;
		goto fail;
	}

	/* If there's something wrong with the previous block, us too. */
	block->complaint = block->prev->complaint;

	/* We come after our predecessor, obviously. */
	block->blocknum = block->prev->blocknum + 1;

	/* Can't go backwards, can't be more than 2 hours in future. */
	if (!check_timestamp(state, le32_to_cpu(tailer->timestamp),block->prev)){
		e = PROTOCOL_ERROR_BAD_TIMESTAMP;
		goto fail;
	}

	/* Based on previous blocks, how difficult should this be? */
	if (le32_to_cpu(tailer->difficulty)
	    != get_difficulty(state, block->prev)) {
		e = PROTOCOL_ERROR_BAD_DIFFICULTY;
		goto fail;
	}

	/* Get SHA: should have enough leading zeroes to beat target. */
	hash_block(hdr, merkles, prev_merkles, tailer, &block->sha);

	if (!beats_target(&block->sha, le32_to_cpu(tailer->difficulty))) {
		e = PROTOCOL_ERROR_INSUFFICIENT_WORK;
		goto fail;
	}

	total_work_done(le32_to_cpu(tailer->difficulty),
			&block->prev->total_work,
			&block->total_work);

	block->batch = tal_arrz(block, struct transaction_batch *,
				num_merkles(le32_to_cpu(hdr->num_transactions)));

	block->hdr = hdr;
	block->merkles = merkles;
	block->prev_merkles = prev_merkles;
	block->tailer = tailer;
	block->all_known = false;

	return PROTOCOL_ERROR_NONE;

fail:
	*blockp = tal_free(block);
	return e;
}

static const union protocol_transaction *
last_trans(const struct transaction_batch *batch, unsigned int *transnum)
{
	int i;

	for (i = ARRAY_SIZE(batch->t)-1; i >= 0; i--) {
		if (batch->t[i]) {
			if (transnum)
				*transnum = batch->trans_start + i;
			return batch->t[i];
		}
	}
	abort();
}

static const union protocol_transaction *
first_trans(const struct transaction_batch *batch, unsigned int *transnum)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(batch->t); i++) {
		if (batch->t[i]) {
			if (transnum)
				*transnum = batch->trans_start + i;
			return batch->t[i];
		}
	}
	abort();
}

bool batch_belongs_in_block(const struct block *block,
			    const struct transaction_batch *batch)
{
	struct protocol_double_sha merkle;
	unsigned int batchnum = batch_index(batch->trans_start);

	merkle_transactions(NULL, 0, batch->t, batch->refs,
			    ARRAY_SIZE(batch->t), &merkle);
	return memcmp(block->merkles[batchnum].sha, merkle.sha,
		      sizeof(merkle.sha)) == 0;
}

bool check_batch_order(struct state *state,
		       const struct block *block,
		       const struct transaction_batch *batch,
		       unsigned int *bad_transnum1, unsigned int *bad_transnum2)
{
	int i;
	const union protocol_transaction *prev;
	unsigned int batchnum = batch->trans_start << PETTYCOIN_BATCH_ORDER;

	/* These should never happen, since we create batches. */
	assert(!(batch->trans_start & ((1 << PETTYCOIN_BATCH_ORDER)-1)));
	assert(batch->count <= ARRAY_SIZE(batch->t));
	assert(!add_overflows(batch->trans_start, batch->count));
	assert(batch->trans_start + batch->count <=
	       le32_to_cpu(block->hdr->num_transactions));

	/* Is it in order? */
	prev = NULL;
	for (i = 0; i < ARRAY_SIZE(batch->t); i++) {
		const union protocol_transaction *t = batch->t[i];

		if (!t)
			continue;

		if (prev && transaction_cmp(prev, t) >= 0) {
			if (bad_transnum2)
				*bad_transnum2 = batch->trans_start + i;
			return false;
		}
		prev = t;
		if (bad_transnum1)
			*bad_transnum1 = batch->trans_start + i;
	}

	/* Is it in order wrt other known blocks?  If not, it may not
	 * be this batch's fault, but it's still a problem. */
	for (i = batchnum - 1; i >= 0; i--) {
		if (!block->batch[i])
			continue;

		if (transaction_cmp(last_trans(block->batch[i], bad_transnum1),
				    first_trans(batch, bad_transnum2)) >= 0)
			return false;
	}

	for (i = batchnum + 1;
	     (i << PETTYCOIN_BATCH_ORDER) 
		     < le32_to_cpu(block->hdr->num_transactions);
	     i++) {
		if (!block->batch[i])
			continue;

		if (transaction_cmp(last_trans(batch, bad_transnum1),
				    first_trans(block->batch[i], bad_transnum2))
		    >= 0)
			return false;
	}

	return true;
}

static void add_to_thash(struct state *state,
			 struct block *block,
			 struct transaction_batch *batch)
{
	u32 i;

	for (i = batch->trans_start;
	     i < batch->trans_start + ARRAY_SIZE(batch->t);
	     i++) {
		struct thash_elem *te;
		struct protocol_double_sha sha;
		struct thash_iter iter;

		if (!batch->t[i])
			continue;

		hash_tx(batch->t[i], &sha);

		/* It could already be there (alternate chain, or previous
		 * partial batch which we just overwrote). */
		for (te = thash_firstval(&state->thash, &sha, &iter);
		     te;
		     te = thash_nextval(&state->thash, &sha, &iter)) {
			/* Previous partial batch which we just overwrote? */
			if (te->block == block && te->tnum == i)
				break;
		}

		if (!te) {
			/* Add a new one for this block. */
			te = tal(state, struct thash_elem);
			te->block = block;
			te->tnum = i;
			te->sha = sha;
			thash_add(&state->thash, te);
		}
	}
}

void put_batch_in_block(struct state *state,
			struct block *block,
			struct transaction_batch *batch)
{
	unsigned int batchnum = batch_index(batch->trans_start);

	assert(batch_belongs_in_block(block, batch));
	assert(batch_full(block, batch));
	assert(check_batch_order(state, block, batch, NULL, NULL));

	/* If there are already some transactions, we should agree! */
	if (block->batch[batchnum]) {
		unsigned int i;

		for (i = 0; i < ARRAY_SIZE(batch->t); i++) {
			const union protocol_transaction *t;

			t = block->batch[batchnum]->t[i];
			if (t)
				assert(transaction_cmp(t, batch->t[i]) == 0);
		}
		tal_free(block->batch[batchnum]);
	}
	block->batch[batchnum] = tal_steal(block, batch);

	add_to_thash(state, block, block->batch[batchnum]);

	if (block_full(block, NULL)) {
		update_known(state, block);
		check_chains(state);
	}

	/* FIXME: re-check prev_merkles for any descendents. */
	/* FIXME: re-check pending transactions with unknown inputs
	 * now we know more, or which we already added. */
}

enum protocol_error
batch_validate_transactions(struct state *state,
			    struct log *log,
			    struct block *block,
			    struct transaction_batch *batch,
			    unsigned int *bad_trans,
			    unsigned int *bad_input_num,
			    union protocol_transaction *
			      inputs[TRANSACTION_MAX_INPUTS])
{
	unsigned int i;
	enum protocol_error err;

	for (i = 0; i < ARRAY_SIZE(batch->t); i++) {
		if (!batch->t[i])
			continue;

		/* Make sure transactions themselves are valid. */
		err = check_transaction(state, batch->t[i], block,
					batch->refs[i], inputs, bad_input_num);
		if (err) {
			log_unusual(log, "Peer resp_batch transaction %u"
				    " gave error ",
				    batch->trans_start + i);
			log_add_enum(log, enum protocol_error, err);
			*bad_trans = batch->trans_start + i;
			return err;
		}
	}

	return PROTOCOL_ERROR_NONE;
}

/* Check what we can, using block->prev->...'s batch. */
bool check_block_prev_merkles(struct state *state,
			      const struct block *block)
{
	unsigned int i;
	size_t off = 0;
	const struct block *prev;

	for (i = 0, prev = block->prev;
	     i < PETTYCOIN_PREV_BLOCK_MERKLES && prev;
	     i++, prev = prev->prev) {
		unsigned int j;
		u32 prev_trans = le32_to_cpu(prev->hdr->num_transactions);

		/* It's bad if we don't have that many prev merkles. */
		if (off + num_merkles(prev_trans)
		    > le32_to_cpu(block->hdr->num_prev_merkles))
			return false;

		for (j = 0; j < num_merkles(prev_trans); j++) {
			struct protocol_double_sha merkle;

			/* We need to know everything in batch to check
			 * previous merkle. */
			if (!prev->batch[j] || !batch_full(prev, prev->batch[j]))
				continue;

			/* Merkle has block reward address prepended, so you
			 * can prove you know all the transactions. */
			merkle_transactions(&block->hdr->fees_to,
					    sizeof(block->hdr->fees_to),
					    prev->batch[j]->t,
					    prev->batch[j]->refs,
					    ARRAY_SIZE(prev->batch[j]->t),
					    &merkle);

			/* We only check one byte; that's enough. */
			if (merkle.sha[0] != block->prev_merkles[off+j]) {
				log_unusual(state->log,
					    "Incorrect merkle for block %u:"
					    " block %u batch %u was %u not %u",
					    block->blocknum,
					    block->blocknum - i, j,
					    merkle.sha[0],
					    block->prev_merkles[off+j]);
				return false;
			}
		}
		off += j;
	}

	/* Must have exactly the right number of previous merkle hashes. */
	return off == le32_to_cpu(block->hdr->num_prev_merkles);
}
