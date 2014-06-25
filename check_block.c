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
#include "chain.h"
#include "shard.h"
#include <ccan/array_size/array_size.h>
#include <ccan/tal/tal.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* Returns error if bad.  Not sufficient by itself: see check_tx_order,
 * shard_validate_transactions and check_block_prev_merkles! */
enum protocol_error
check_block_header(struct state *state,
		   const struct protocol_block_header *hdr,
		   const u8 *shard_nums,
		   const struct protocol_double_sha *merkles,
		   const u8 *prev_merkles,
		   const struct protocol_block_tailer *tailer,
		   struct block **blockp,
		   struct protocol_double_sha *sha)
{
	struct block *block = (*blockp) = tal(state, struct block);
	enum protocol_error e;

	/* Shouldn't happen, since we check in unmarshall. */
	if (!version_ok(hdr->version)) {
		e = PROTOCOL_ERROR_BLOCK_HIGH_VERSION;
		memset(sha, 0, sizeof(*sha));
		goto fail;
	}

	/* We check work *first*: if it meets its target we can spend
	 * resources on it, since it's not cheap to produce (eg. we could
	 * keep it around, or ask others about its predecessors, etc) */

	/* Get SHA: should have enough leading zeroes to beat target. */
	hash_block(hdr, shard_nums, merkles, prev_merkles, tailer, &block->sha);
	if (sha)
		*sha = block->sha;

	if (!beats_target(&block->sha, le32_to_cpu(tailer->difficulty))) {
		e = PROTOCOL_ERROR_INSUFFICIENT_WORK;
		goto fail;
	}

	/* Don't just search on main chain! */
	block->prev = block_find_any(state, &hdr->prev_block);
	if (!block->prev) {
		e = PROTOCOL_ERROR_PRIV_UNKNOWN_PREV;
		goto fail;
	}

	if (hdr->shard_order != next_shard_order(block->prev)) {
		e = PROTOCOL_ERROR_BAD_SHARD_ORDER;
		goto fail;
	}

	if (le32_to_cpu(hdr->depth) != le32_to_cpu(block->prev->hdr->depth)+1) {
		e = PROTOCOL_ERROR_BAD_DEPTH;
		goto fail;
	}

	/* If there's something wrong with the previous block, us too. */
	block->complaint = block->prev->complaint;

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

	total_work_done(le32_to_cpu(tailer->difficulty),
			&block->prev->total_work,
			&block->total_work);

	block->shard = tal_arrz(block, struct transaction_shard *,
				num_shards(hdr));
	block->hdr = hdr;
	block->shard_nums = shard_nums;
	block->merkles = merkles;
	block->prev_merkles = prev_merkles;
	block->tailer = tailer;
	block->all_known = false;
	list_head_init(&block->children);

	return PROTOCOL_ERROR_NONE;

fail:
	*blockp = tal_free(block);
	return e;
}

bool shard_belongs_in_block(const struct block *block,
			    const struct transaction_shard *shard)
{
	struct protocol_double_sha merkle;

	/* FIXME: Audit, can this happen?. */
	if (shard->shardnum >= num_shards(block->hdr))
		return false;

	/* merkle_transactions is happy with just the hashes. */
	assert(shard->txcount + shard->hashcount
	       == block->shard_nums[shard->shardnum]);
	merkle_transactions(NULL, 0, shard->txp_or_hash, shard->u, 0,
			    block->shard_nums[shard->shardnum], &merkle);
	return memcmp(block->merkles[shard->shardnum].sha, merkle.sha,
		      sizeof(merkle.sha)) == 0;
}

static u32 get_shard_start(const struct block *block,
			   const struct transaction_shard *shard)
{
	unsigned int i;
	u32 num = 0;

	for (i = 0; i < shard->shardnum; i++)
		num += block->shard_nums[i];

	return num;
}

bool check_tx_order(struct state *state,
		    const struct block *block,
		    const struct transaction_shard *shard,
		    unsigned int *bad_transnum1,
		    unsigned int *bad_transnum2)
{
	int i;
	const union protocol_transaction *prev;
	u32 shard_start = get_shard_start(block, shard);

	/* Is it in order? */
	prev = NULL;
	for (i = 0; i < block->shard_nums[shard->shardnum]; i++) {
		const union protocol_transaction *t;

		/* We can't determine order from the hash. */
		if (!shard_is_tx(shard, i))
			continue;

		t = shard->u[i].txp.tx;
		if (!t)
			continue;

		if (prev && transaction_cmp(prev, t) >= 0) {
			if (bad_transnum2)
				*bad_transnum2 = shard_start + i;
			return false;
		}
		prev = t;
		if (bad_transnum1)
			*bad_transnum1 = shard_start + i;
	}
	return true;
}

/* This is a fully known shard, add txs to thash. */
static void add_to_thash(struct state *state,
			 struct block *block,
			 struct transaction_shard *shard)
{
	u32 i;

	for (i = 0; i < block->shard_nums[shard->shardnum]; i++) {
		struct thash_elem *te;
		struct protocol_double_sha sha;
		struct thash_iter iter;

		assert(shard_is_tx(shard, i));

		hash_tx(shard->u[i].txp.tx, &sha);

		/* It could already be there (alternate chain, or previous
		 * partial shard which we just overwrote). */
		for (te = thash_firstval(&state->thash, &sha, &iter);
		     te;
		     te = thash_nextval(&state->thash, &sha, &iter)) {
			/* Previous partial shard which we just overwrote? */
			if (te->block == block
			    && te->shardnum == shard->shardnum
			    && te->txoff == i)
				break;
		}

		if (!te) {
			/* Add a new one for this block. */
			te = tal(shard, struct thash_elem);
			te->block = block;
			te->shardnum = shard->shardnum;
			te->txoff = i;
			te->sha = sha;
			thash_add(&state->thash, te);
			/* FIXME:
			   tal_add_destructor(te, delete_from_thash);
			*/
		}
	}
}

/* This is a fast-path used by generating.c */
void force_shard_into_block(struct state *state,
			    struct block *block,
			    struct transaction_shard *shard)
{
	assert(shard_belongs_in_block(block, shard));
	assert(shard->txcount == block->shard_nums[shard->shardnum]);
	assert(check_tx_order(state, block, shard, NULL, NULL));
	assert(!block->shard[shard->shardnum]);

	block->shard[shard->shardnum] = tal_steal(block, shard);

	add_to_thash(state, block, shard);

	update_block_ptrs_new_shard(state, block, shard->shardnum);

	/* FIXME: re-check prev_merkles for any descendents. */
	/* FIXME: re-check pending transactions with unknown inputs
	 * now we know more, or which we already added. */
}

/* FIXME: Only used by generate.c as an assertion... */
enum protocol_error
shard_validate_transactions(struct state *state,
			    struct log *log,
			    const struct block *block,
			    struct transaction_shard *shard,
			    unsigned int *bad_trans,
			    unsigned int *bad_input_num,
			    union protocol_transaction *
			      inputs[TRANSACTION_MAX_INPUTS])
{
	unsigned int i;
	enum protocol_error err;

	for (i = 0; i < block->shard_nums[shard->shardnum]; i++) {
		u32 tx_shard;

		assert(shard_is_tx(shard, i));
		tx_shard = shard_of_tx(shard->u[i].txp.tx,
				       block->hdr->shard_order);
		if (tx_shard != shard->shardnum) {
			*bad_trans = get_shard_start(block, shard) + i;
			log_unusual(log, "Transaction %u in wrong shard"
				    " (%u vs %u) ", *bad_trans,
				    tx_shard, shard->shardnum);
			return PROTOCOL_ERROR_BLOCK_BAD_TX_SHARD;
		}

		/* Make sure transactions themselves are valid. */
		err = check_transaction(state, shard->u[i].txp.tx, block,
					refs_for(shard->u[i].txp),
					inputs, bad_input_num);
		if (err) {
			*bad_trans = get_shard_start(block, shard) + i;
			log_unusual(log, "Transaction %u gave error ",
				    *bad_trans);
			log_add_enum(log, enum protocol_error, err);
			return err;
		}
	}

	return PROTOCOL_ERROR_NONE;
}

/* Check what we can, using block->prev->...'s shards. */
bool check_block_prev_merkles(struct state *state, const struct block *block)
{
	unsigned int i;
	size_t off = 0;
	const struct block *prev;

	for (i = 0, prev = block->prev;
	     i < PETTYCOIN_PREV_BLOCK_MERKLES && prev;
	     i++, prev = prev->prev) {
		unsigned int j;

		/* It's bad if we don't have that many prev merkles. */
		if (off + num_shards(prev->hdr)
		    > le32_to_cpu(block->hdr->num_prev_merkles))
			return false;

		for (j = 0; j < num_shards(prev->hdr); j++) {
			struct protocol_double_sha merkle;

			/* We need to know everything in shard to check
			 * previous merkle. */
			if (!shard_all_known(prev, j))
				continue;

			/* Merkle has block reward address prepended, so you
			 * can prove you know all the transactions. */
			merkle_transactions(&block->hdr->fees_to,
					    sizeof(block->hdr->fees_to),
					    prev->shard[j]->txp_or_hash,
					    prev->shard[j]->u,
					    0, prev->shard_nums[j],
					    &merkle);

			/* We only check one byte; that's enough. */
			if (merkle.sha[0] != block->prev_merkles[off+j]) {
				log_unusual(state->log,
					    "Incorrect merkle for block %u:"
					    " block %u shard %u was %u not %u",
					    le32_to_cpu(block->hdr->depth),
					    le32_to_cpu(block->hdr->depth) - i,
					    j,
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
