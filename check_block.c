#include "block.h"
#include "block_shard.h"
#include "blockfile.h"
#include "chain.h"
#include "check_block.h"
#include "check_tx.h"
#include "complain.h"
#include "difficulty.h"
#include "generating.h"
#include "hash_block.h"
#include "hash_tx.h"
#include "input_refs.h"
#include "inputhash.h"
#include "merkle_txs.h"
#include "overflows.h"
#include "pending.h"
#include "prev_txhashes.h"
#include "proof.h"
#include "protocol.h"
#include "protocol_net.h"
#include "shadouble.h"
#include "shard.h"
#include "state.h"
#include "timestamp.h"
#include "todo.h"
#include "tx.h"
#include "tx_cmp.h"
#include "tx_in_hashes.h"
#include "version.h"
#include <assert.h>
#include <ccan/array_size/array_size.h>
#include <ccan/structeq/structeq.h>
#include <ccan/tal/tal.h>
#include <stdlib.h>
#include <string.h>

/* Returns error if bad.  Not sufficient by itself: see check_tx_order,
 * shard_validate_transactions and check_prev_txhashes! */
enum protocol_ecode
check_block_header(struct state *state,
		   const struct protocol_block_header *hdr,
		   const u8 *shard_nums,
		   const struct protocol_double_sha *merkles,
		   const u8 *prev_txhashes,
		   const struct protocol_block_tailer *tailer,
		   struct block **prev,
		   struct protocol_double_sha *sha)
{
	/* Shouldn't happen, since we check in unmarshal. */
	if (!version_ok(hdr->version))
		return PROTOCOL_ECODE_BLOCK_HIGH_VERSION;

	/* We check work *first*: if it meets its target we can spend
	 * resources on it, since it's not cheap to produce (eg. we could
	 * keep it around, or ask others about its predecessors, etc) */

	/* Get SHA: should have enough leading zeroes to beat target. */
	hash_block(hdr, shard_nums, merkles, prev_txhashes, tailer, sha);

	if (!beats_target(sha, le32_to_cpu(tailer->difficulty)))
		return PROTOCOL_ECODE_INSUFFICIENT_WORK;

	/* Don't just search on main chain! */
	*prev = block_find_any(state, &hdr->prev_block);
	if (!*prev)
		return PROTOCOL_ECODE_PRIV_UNKNOWN_PREV;

	if (hdr->shard_order != next_shard_order(*prev))
		return PROTOCOL_ECODE_BAD_SHARD_ORDER;

	if (le32_to_cpu(hdr->depth) != le32_to_cpu((*prev)->hdr->depth)+1)
		return PROTOCOL_ECODE_BAD_DEPTH;

	/* Can't go backwards, can't be more than 2 hours in future. */
	if (!check_timestamp(state, le32_to_cpu(tailer->timestamp), *prev))
		return PROTOCOL_ECODE_BAD_TIMESTAMP;

	/* Based on previous blocks, how difficult should this be? */
	if (le32_to_cpu(tailer->difficulty) != get_difficulty(state, *prev))
		return PROTOCOL_ECODE_BAD_DIFFICULTY;

	return PROTOCOL_ECODE_NONE;
}

bool shard_belongs_in_block(const struct block *block,
			    const struct block_shard *shard)
{
	struct protocol_double_sha merkle;

	/* merkle_txs is happy with just the hashes. */
	assert(shard->txcount + shard->hashcount
	       == block->shard_nums[shard->shardnum]);
	merkle_txs(shard, &merkle);
	return structeq(&block->merkles[shard->shardnum], &merkle);
}

/* If we were to insert tx in block->shard[shardnum] at txoff, would it be
 * in order? */
bool check_tx_ordering(struct state *state,
		       struct block *block,
		       struct block_shard *shard, u8 txoff,
		       const union protocol_tx *tx,
		       u8 *bad_txoff)
{
	const union protocol_tx *other_tx;
	int i;

	/* Don't bother on empty shard. */
	if (shard->txcount == 0)
		return true;

	/* Check ordering against previous. */
	for (i = (int)txoff-1; i >= 0; i--) {
		other_tx = tx_for(shard, i);
		if (other_tx) {
			if (tx_cmp(other_tx, tx) >= 0) {
				*bad_txoff = i;
				return false;
			}
			break;
		}
	}

	/* Check ordering against next. */
	for (i = (int)txoff+1; i < shard->size; i++) {
		other_tx = tx_for(shard, i);
		if (other_tx) {
			if (tx_cmp(tx, other_tx) >= 0) {
				*bad_txoff = i;
				return false;
			}
			break;
		}
	}
	return true;
}

/* An input for this has been resolved; check it again. */
static bool recheck_tx(struct state *state,
		       const struct protocol_double_sha *tx)
{
	struct txhash_iter iter;
	struct txhash_elem *te;

	for (te = txhash_firstval(&state->txhash, tx, &iter);
	     te;
	     te = txhash_nextval(&state->txhash, tx, &iter)) {
		struct protocol_proof proof;

		if (te->status == TX_PENDING) {
			state->pending->needs_recheck = true;
			continue;
		}
		assert(!te->u.block->complaint);

		if (!shard_is_tx(te->u.block->shard[te->shardnum], te->txoff))
			continue;

		create_proof(&proof, te->u.block, te->shardnum, te->txoff);
		if (!check_tx_inputs_and_refs(state,
					      te->u.block, &proof,
					      block_get_tx(te->u.block,
							   te->shardnum,
							   te->txoff),
					      block_get_refs(te->u.block,
							     te->shardnum,
							     te->txoff))) {
			/* Caller will retry... */
			return false;
		}
	}

	return true;
}

static void check_resolved_txs(struct state *state,
			       const union protocol_tx *tx)
{
	unsigned int i;
	struct protocol_double_sha sha;

	hash_tx(tx, &sha);

	for (i = 0; i < num_outputs(tx); i++) {
		struct inputhash_elem *ie;
		struct inputhash_iter it;

		/* In case hash gets reordered, we restart on (unlikely) fail */
	again:
		for (ie = inputhash_firstval(&state->inputhash, &sha, i, &it);
		     ie;
		     ie = inputhash_nextval(&state->inputhash, &sha, i, &it)) {
			if (!recheck_tx(state, &ie->used_by))
				goto again;
		}
	}
}

void put_tx_in_shard(struct state *state,
		     const struct peer *source,
		     struct block *block,
		     struct block_shard *shard, u8 txoff,
		     struct txptr_with_ref txp)
{

	if (shard_is_tx(shard, txoff)) {
		if (tx_for(shard, txoff)) {
			/* It's already there?  Leave it alone. */
			assert(memcmp(txp.tx, tx_for(shard, txoff),
				      marshal_tx_len(txp.tx)
				      + marshal_input_ref_len(txp.tx)) == 0);
			return;
		}
		/* We didn't know about it before. */
		add_tx_to_hashes(state, shard, block, shard->shardnum, txoff,
				 txp.tx);
	} else {
		struct protocol_txrefhash hashes;

		/* We knew hash: tx must match hash. */
		hash_tx_and_refs(txp.tx, refs_for(txp), &hashes);
		assert(structeq(shard->u[txoff].hash, &hashes));
		shard->hashcount--;

		upgrade_tx_in_hashes(state, shard, &hashes.txhash, txp.tx);
	}

	/* Now it's a transaction. */
	bitmap_clear_bit(shard->txp_or_hash, txoff);
	shard->u[txoff].txp = txp;
	shard->txcount++;

	/* Did we just resolve a new input for an existing tx? */
	check_resolved_txs(state, txp.tx);

	/* If we've just filled it, we don't need proofs any more. */
	if (shard_all_hashes(shard))
		shard->proof = tal_free(shard->proof);

	/* We save once we know the entire contents. */
	if (shard_all_known(shard))
		update_block_ptrs_new_shard(state, block, shard->shardnum);

	/* This could eliminate a pending tx. */
	state->pending->needs_recheck = true;

	/* Save tx to disk. */
	save_tx(state, block, shard->shardnum, txoff);

	/* Tell peers about the new tx in block. */
	send_tx_in_block_to_peers(state, source, block, shard->shardnum, txoff);
}

bool put_txhash_in_shard(struct state *state,
			 struct block *block, u16 shardnum, u8 txoff,
			 const struct protocol_txrefhash *txrefhash)
{
	struct block_shard *shard = block->shard[shardnum];
	struct protocol_txrefhash scratch;
	const struct protocol_txrefhash *p;

	/* If we already have it, it must be the same. */
	p = txrefhash_in_shard(shard, txoff, &scratch);
	if (p) {
		assert(structeq(p, txrefhash));
		return false;
	}

	/* Now it's a hash. */
	bitmap_set_bit(shard->txp_or_hash, txoff);
	/* FIXME: Free this if we resolve it! */
	shard->u[txoff].hash
		= tal_dup(shard, struct protocol_txrefhash, txrefhash, 1, 0);
	shard->hashcount++;

	add_txhash_to_hashes(state, shard, block, shardnum, txoff,
			     &txrefhash->txhash);

	/* This could eliminate a pending tx. */
	state->pending->needs_recheck = true;
	return true;
}

void put_proof_in_shard(struct state *state,
			struct block *block,
			const struct protocol_proof *proof)
{
	struct block_shard *shard = block->shard[le16_to_cpu(proof->pos.shard)];

	/* If we have all hashes, we don't need to keep proof. */
	if (shard_all_hashes(shard))
		return;

	if (!shard->proof)
		shard->proof = tal_arrz(shard, struct protocol_proof *,
					block->shard_nums[shard->shardnum]);

	if (shard->proof[proof->pos.txoff])
		return;

	shard->proof[proof->pos.txoff]
		= tal_dup(shard, struct protocol_proof, proof, 1, 0);
}

bool check_num_prev_txhashes(struct state *state,
			     const struct block *prev_block,
			     const struct protocol_block_header *hdr,
			     const u8 *prev_txhashes)
{
	return le32_to_cpu(hdr->num_prev_txhashes)
		== num_prev_txhashes(prev_block);
}

/* Check what we can, using block->prev etc's shards. */
bool check_prev_txhashes(struct state *state, const struct block *block,
			 const struct block **bad_prev,
			 u16 *bad_shard)
{
	unsigned int i;
	const struct block *b;
	size_t off = 0;

	for_each_prev_txhash(i, b, block->prev) {
		unsigned int j;

		for (j = 0; j < num_shards(b->hdr); j++) {
			u8 prev_txh;

			/* We need to know everything in shard to check
			 * previous hash. */
			if (!shard_all_known(b->shard[j]))
				continue;

			prev_txh = prev_txhash(&block->hdr->fees_to, b, j);

			/* We only check one byte; that's enough. */
			if (prev_txh != block->prev_txhashes[off+j]) {
				log_unusual(state->log,
					    "Incorrect prev_txhash block %u:"
					    " block %u shard %u was %u not %u",
					    le32_to_cpu(block->hdr->depth),
					    le32_to_cpu(block->hdr->depth) - i,
					    j,
					    prev_txh,
					    block->prev_txhashes[off+j]);
				*bad_prev = b;
				*bad_shard = j;
				return false;
			}
		}
		off += j;
	}

	/* Must have exactly the right number of previous txhashes hashes. */
	assert(off == le32_to_cpu(block->hdr->num_prev_txhashes));
	return true;
}

void check_block(struct state *state, const struct block *block)
{
	u32 diff = le32_to_cpu(block->tailer->difficulty);
	struct protocol_double_sha sha;
	unsigned int shard;

	if (block != genesis_block(state)) {
		assert(beats_target(&block->sha, diff));
		assert(tal_count(block->shard) == num_shards(block->hdr));
	}
	hash_block(block->hdr, block->shard_nums, block->merkles,
		   block->prev_txhashes, block->tailer, &sha);
	assert(structeq(&sha, &block->sha));

	if (block->prev) {
		if (block->all_known)
			assert(block->prev->all_known);

		if (block->prev->complaint)
			assert(block->complaint);

	}

	/* FIXME: check block->prev_txhashes! */

	for (shard = 0; shard < num_shards(block->hdr); shard++) {
		check_block_shard(state, block, block->shard[shard]);
	}
}

/* Returns false if block invalid (ie. complaint has been generated) */
bool check_tx_inputs_and_refs(struct state *state,
			      struct block *b,
			      const struct protocol_proof *proof,
			      union protocol_tx *tx,
			      struct protocol_input_ref *refs)
{
	enum input_ecode ierr;
	enum ref_ecode rerr;
	unsigned int bad_input_num;
	struct block *block_referred_to;

	/* Check bad inputs, and generate complaints. */
	ierr = check_tx_inputs(state, b, NULL, tx, &bad_input_num);
	switch (ierr) {
	case ECODE_INPUT_OK:
		break;
	case ECODE_INPUT_UNKNOWN:
		/* Ask about this input if we're interested. */
		/* If this tx is in a shard, that means all inputs must
		 * affect that shard. */
		if (interested_in_shard(state, b->hdr->shard_order,
					le16_to_cpu(proof->pos.shard)))
			todo_add_get_tx(state,
					&tx_input(tx, bad_input_num)->input);
		/* We accept TXs with unknown inputs. */
		break;
	case ECODE_INPUT_BAD: {
		const union protocol_tx *input;

		input = txhash_gettx(&state->txhash,
				     &tx_input(tx, bad_input_num)->input,
				     TX_IN_BLOCK);
		/* This whole block is invalid.  Tell everyone. */
		complain_bad_input(state, b, proof, tx, refs,
				   bad_input_num, input);
		return false;
	}
	case ECODE_INPUT_BAD_AMOUNT: {
		unsigned int i;
		const union protocol_tx *inputs[PROTOCOL_TX_MAX_INPUTS];

		for (i = 0; i < num_inputs(tx); i++)
			inputs[i] = txhash_gettx(&state->txhash,
						 &tx_input(tx, i)->input,
						 TX_IN_BLOCK);

		/* This whole block is invalid.  Tell everyone. */
		complain_bad_amount(state, b, proof, tx, refs, inputs);
		return false;
	}
	case ECODE_INPUT_DOUBLESPEND: {
		struct txhash_elem *other;
		const union protocol_tx *other_tx;
		const struct protocol_input_ref *other_refs;
		const struct protocol_input *inp = tx_input(tx, bad_input_num);
		struct protocol_proof other_proof;

		other = tx_find_doublespend(state, b, NULL, inp);
		assert(other->status == TX_IN_BLOCK);
		create_proof(&other_proof, other->u.block, other->shardnum,
			     other->txoff);
		other_tx = block_get_tx(other->u.block, other->shardnum,
					other->txoff);
		other_refs = block_get_refs(other->u.block, other->shardnum,
					    other->txoff);

		if (block_preceeds(other->u.block, b)) {
			/* b is invalid. Tell everyone. */
			complain_doublespend(state,
					     other->u.block,
					     find_matching_input(other_tx, inp),
					     &other_proof, other_tx, other_refs,
					     b, bad_input_num,
					     proof, tx, refs);
			/* And we're done. */
			return false;
		}

		/* other->u.block is invalid.  Tell everyone. */
		complain_doublespend(state, b,
				     bad_input_num, proof, tx, refs,
				     other->u.block,
				     find_matching_input(other_tx, inp),
				     &other_proof, other_tx, other_refs);

		/* Nothing wrong with this block though! */
		break;
	}
	}

	rerr = check_tx_refs(state, b, tx, refs,
			     &bad_input_num, &block_referred_to);
	switch (rerr) {
	case ECODE_REF_OK:
		break;
	case ECODE_REF_UNKNOWN:
		/* If we don't know inputs, we've already asked. */
		if (ierr == ECODE_INPUT_UNKNOWN)
			break;
		/* Otherwise, we know tx but don't know it at this
		 * position.  Ask for it, but otherwise ok. */
		todo_add_get_tx_in_block(state, &block_referred_to->sha,
					 le16_to_cpu(refs[bad_input_num].shard),
					 refs[bad_input_num].txoff);
		break;
	case ECODE_REF_BAD_HASH:
		/* Tell everyone this block is bad due to bogus input_ref */
		complain_bad_input_ref(state, b, proof,
				       tx, refs, bad_input_num,
				       block_referred_to);
		return false;
	}

	return true;
}
