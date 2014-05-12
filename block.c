#include <ccan/cast/cast.h>
#include "block.h"
#include "chain.h"
#include "protocol.h"
#include "state.h"
#include "peer.h"
#include "generating.h"
#include "log.h"
#include "merkle_transactions.h"
#include "pending.h"
#include "packet.h"
#include "proof.h"
#include "check_transaction.h"
#include "features.h"
#include <string.h>

struct block *block_find(struct block *start, const u8 lower_sha[4])
{
	struct block *b = start;

	while (b) {
		if (memcmp(b->sha.sha, lower_sha, 4) == 0)
			break;

		b = b->prev;
	}
	return b;
}

void block_add(struct state *state, struct block *block)
{
	log_debug(state->log, "Adding block %u ", block->blocknum);
	log_add_struct(state->log, struct protocol_double_sha, &block->sha);

	/* Add to list for that generation. */
	if (block->blocknum >= tal_count(state->block_depth)) {
		/* We can only increment block depths. */
		assert(block->blocknum == tal_count(state->block_depth));
		tal_resize(&state->block_depth, block->blocknum + 1);
		state->block_depth[block->blocknum]
			= tal(state->block_depth, struct list_head);
		list_head_init(state->block_depth[block->blocknum]);
	}
	list_add_tail(state->block_depth[block->blocknum], &block->list);

	block->pending_features = pending_features(block);

	/* This can happen if precedessor has complaint. */
	if (block->complaint) {
		check_chains(state);
		/* It's not a candidate for real use. */
		return;
	}

	update_block_ptrs_new_block(state, block);
	check_chains(state);
}

/* FIXME: use hash table. */
struct block *block_find_any(struct state *state,
			     const struct protocol_double_sha *sha)
{
	int i, n = tal_count(state->block_depth);
	struct block *b;

	/* Search recent blocks first. */
	for (i = n - 1; i >= 0; i--) {
		list_for_each(state->block_depth[i], b, list) {
			if (memcmp(b->sha.sha, sha->sha, sizeof(sha->sha)) == 0)
				return b;
		}
	}
	return NULL;
}

u32 batch_max(const struct block *block, unsigned int batchnum)
{
	unsigned int num_trans, batch_start, full;

	/* How many could we possibly fit? */
	num_trans = le32_to_cpu(block->hdr->num_transactions);
	batch_start = batchnum << PETTYCOIN_BATCH_ORDER;

	full = num_trans - batch_start;
	if (full > (1 << PETTYCOIN_BATCH_ORDER))
		return (1 << PETTYCOIN_BATCH_ORDER);

	return full;
}

/* Do we have everything in this batch? */
bool batch_full(const struct block *block,
		const struct transaction_batch *batch)
{
	unsigned int batchnum = batch->trans_start >> PETTYCOIN_BATCH_ORDER;
	return batch->count == batch_max(block, batchnum);
}

bool block_full(const struct block *block, unsigned int *batchnum)
{
	unsigned int i, num;

	num = num_merkles(le32_to_cpu(block->hdr->num_transactions));
	for (i = 0; i < num; i++) {
		const struct transaction_batch *b = block->batch[i];
		if (batchnum)
			*batchnum = i;
		if (!b)
			return false;
		if (!batch_full(block, b))
			return false;
	}
	return true;
}

union protocol_transaction *block_get_trans(const struct block *block,
					    u32 trans_num)
{
	const struct transaction_batch *b;

	assert(trans_num < le32_to_cpu(block->hdr->num_transactions));
	b = block->batch[batch_index(trans_num)];
	if (!b)
		return NULL;
	return cast_const(union protocol_transaction *,
			  b->t[trans_num % (1 << PETTYCOIN_BATCH_ORDER)]);
}

struct protocol_input_ref *block_get_refs(const struct block *block,
					  u32 trans_num)
{
	const struct transaction_batch *b;

	assert(trans_num < le32_to_cpu(block->hdr->num_transactions));
	b = block->batch[batch_index(trans_num)];
	if (!b)
		return NULL;
	return cast_const(struct protocol_input_ref *,
			  b->refs[trans_num % (1 << PETTYCOIN_BATCH_ORDER)]);
}

static void invalidate_block(struct state *state,
			     struct block *block,
			     const void *complaint)
{
	unsigned int n;

	/* Mark block. */
	block->complaint = complaint;	

	/* FIXME: Save complaint to blockfile! */

	/* Mark descendents. */
	for (n = block->blocknum; n < tal_count(state->block_depth); n++) {
		struct block *i;
		list_for_each(state->block_depth[n], i, list) {
			if (i->prev->complaint)
				i->complaint = i->prev->complaint;
		}
	}

	update_block_ptrs_invalidated(state, block);

	/* Tell everyone... */
	complain_to_peers(state, complaint);
}

static void
invalidate_block_bad_input(struct state *state,
			   struct block *block,
			   const union protocol_transaction *trans,
			   const struct protocol_input_ref *refs,
			   unsigned int bad_transnum,
			   unsigned int bad_input,
			   const union protocol_transaction *intrans)
{
	struct protocol_req_block_bad_trans_input *req;

	assert(le32_to_cpu(trans->hdr.type) == TRANSACTION_NORMAL);
	log_unusual(state->log, "Block %u ", block->blocknum);
	log_add_struct(state->log, struct protocol_double_sha, &block->sha);
	log_add(state->log, " invalid due to trans %u ", bad_transnum);
	log_add_struct(state->log, union protocol_transaction, trans);
	log_add(state->log, " with bad input %u ", bad_input);
	log_add_struct(state->log, union protocol_transaction, intrans);

	req = tal_packet(block, struct protocol_req_block_bad_trans_input,
			 PROTOCOL_REQ_BLOCK_BAD_TRANS_INPUT);
	req->inputnum = cpu_to_le32(bad_input);

	tal_packet_append_proof(&req, block, bad_transnum);
	tal_packet_append_trans(&req, intrans);

	invalidate_block(state, block, req);
}

static void
invalidate_block_bad_amounts(struct state *state,
			     struct block *block,
			     const union protocol_transaction *trans,
			     const struct protocol_input_ref *refs,
			     unsigned int bad_transnum)
{
	struct protocol_req_block_bad_trans_amount *req;
	union protocol_transaction *input[TRANSACTION_MAX_INPUTS];
	unsigned int i;

	assert(le32_to_cpu(trans->hdr.type) == TRANSACTION_NORMAL);
	log_unusual(state->log, "Block %u ", block->blocknum);
	log_add_struct(state->log, struct protocol_double_sha, &block->sha);
	log_add(state->log, " invalid amounts in trans %u ", bad_transnum);
	log_add_struct(state->log, union protocol_transaction, trans);
	log_add(state->log, " with inputs: ");
	/* FIXME: What if input is pending? */
	for (i = 0; i < le32_to_cpu(trans->normal.num_inputs); i++) {
		input[i] = thash_gettrans(&state->thash,
					  &trans->normal.input[i].input);
		log_add_struct(state->log, union protocol_transaction, input[i]);
		log_add(state->log, " (output %u)",
			le16_to_cpu(trans->normal.input[i].output));
	}

	req = tal_packet(block, struct protocol_req_block_bad_trans_amount,
			 PROTOCOL_REQ_BLOCK_BAD_TRANS_AMOUNT);
	tal_packet_append_proof(&req, block, bad_transnum);

	for (i = 0; i < num_inputs(trans); i++)
		tal_packet_append_trans(&req, input[i]);

	invalidate_block(state, block, req);
}

static void
invalidate_block_bad_transaction(struct state *state,
				 struct block *block,
				 enum protocol_error err,
				 const union protocol_transaction *trans,
				 const struct protocol_input_ref *refs,
				 unsigned int bad_transnum)
{
	struct protocol_req_block_trans_invalid *req;	

	log_unusual(state->log, "Block %u ", block->blocknum);
	log_add_struct(state->log, struct protocol_double_sha, &block->sha);
	log_add(state->log, " invalid due to trans %u ", bad_transnum);
	log_add_struct(state->log, union protocol_transaction, trans);
	log_add(state->log, " error ");
	log_add_enum(state->log, enum protocol_error, err);

	req = tal_packet(block, struct protocol_req_block_trans_invalid,
			 PROTOCOL_REQ_BLOCK_TRANS_INVALID);
	req->error = cpu_to_le32(err);

	tal_packet_append_proof(&req, block, bad_transnum);

	invalidate_block(state, block, req);
}

void invalidate_block_misorder(struct state *state,
			       struct block *block,
			       unsigned int bad_transnum1,
			       unsigned int bad_transnum2)
{
	struct protocol_req_block_trans_misorder *req;	
	const union protocol_transaction *trans1, *trans2;

	trans1 = block_get_trans(block, bad_transnum1);
	trans2 = block_get_trans(block, bad_transnum2);

	log_unusual(state->log, "Block %u ", block->blocknum);
	log_add_struct(state->log, struct protocol_double_sha, &block->sha);
	log_add(state->log, " invalid due to misorder trans %u vs %u ",
		bad_transnum1, bad_transnum2);
	log_add_struct(state->log, union protocol_transaction, trans1);
	log_add(state->log, " vs ");
	log_add_struct(state->log, union protocol_transaction, trans2);

	req = tal_packet(block, struct protocol_req_block_trans_misorder,
			 PROTOCOL_REQ_BLOCK_TRANS_MISORDER);
	tal_packet_append_proof(&req, block, bad_transnum1);
	tal_packet_append_proof(&req, block, bad_transnum2);

	invalidate_block(state, block, req);
}

static void
invalidate_block_bad_input_ref_trans(struct state *state,
				     struct block *block,
				     const union protocol_transaction *trans,
				     const struct protocol_input_ref *refs,
				     unsigned int bad_transnum,
				     unsigned int bad_input,
				     const union protocol_transaction *bad_intrans)
{
	struct protocol_req_block_bad_input_ref_trans *req;	
	const struct protocol_input_ref *bad_ref;
	const struct block *input_block;
	u32 in_txnum;

	bad_ref = &refs[bad_input];
	input_block = block_ancestor(block, le32_to_cpu(bad_ref->blocks_ago));
	in_txnum = le32_to_cpu(bad_ref->txnum);

	log_unusual(state->log, "Block %u ", block->blocknum);
	log_add_struct(state->log, struct protocol_double_sha, &block->sha);
	log_unusual(state->log, " transaction %u ", bad_transnum);
	log_add_struct(state->log, union protocol_transaction, trans);
	log_add(state->log, 
		" invalid due to wrong input %u reference %u ago tx %u ",
		bad_input, le32_to_cpu(bad_ref->blocks_ago), in_txnum);
	log_add_struct(state->log, union protocol_transaction, bad_intrans);

	req = tal_packet(block, struct protocol_req_block_bad_input_ref_trans,
			 PROTOCOL_REQ_BLOCK_BAD_INPUT_REF_TRANS);
	req->inputnum = cpu_to_le32(bad_input);

	tal_packet_append_proof(&req, block, bad_transnum);
	tal_packet_append_proof(&req, input_block, in_txnum);

	invalidate_block(state, block, req);
}

/* See check_trans_normal_inputs: bad_input and bad_intrans are valid
 * iff err = PROTOCOL_ERROR_TRANS_BAD_INPUT. */
void invalidate_block_badtrans(struct state *state,
			       struct block *block,
			       enum protocol_error err,
			       unsigned int bad_transnum,
			       unsigned int bad_input,
			       union protocol_transaction *bad_intrans)
{
	union protocol_transaction *trans;
	const struct protocol_input_ref *refs;

	trans = block_get_trans(block, bad_transnum);
	refs = block_get_refs(block, bad_transnum);

	switch (err) {
	case PROTOCOL_ERROR_TRANS_HIGH_VERSION:
	case PROTOCOL_ERROR_TRANS_LOW_VERSION:
	case PROTOCOL_ERROR_TRANS_UNKNOWN:
	case PROTOCOL_ERROR_TOO_LARGE:
	case PROTOCOL_ERROR_TRANS_BAD_SIG:
		break;

	case PROTOCOL_ERROR_TRANS_BAD_GATEWAY:
	case PROTOCOL_ERROR_TRANS_CROSS_SHARDS:
		assert(trans->hdr.type == TRANSACTION_FROM_GATEWAY);
		break;

	case PROTOCOL_ERROR_TOO_MANY_INPUTS:
	case PROTOCOL_ERROR_BATCH_BAD_INPUT_REF:
		assert(trans->hdr.type == TRANSACTION_NORMAL);
		break;

	case PROTOCOL_ERROR_TRANS_BAD_INPUT:
		assert(trans->hdr.type == TRANSACTION_NORMAL);
		/* FIXME: This means an unknown input.  We don't
		 * complain. */
		if (!bad_intrans)
			return;
		invalidate_block_bad_input(state, block,
					   trans, refs, bad_transnum,
					   bad_input, bad_intrans);
		return;

	case PROTOCOL_ERROR_TRANS_BAD_AMOUNTS:
		assert(trans->hdr.type == TRANSACTION_NORMAL);
		invalidate_block_bad_amounts(state, block, trans, refs,
					     bad_transnum);
		return;

	case PROTOCOL_ERROR_BATCH_BAD_INPUT_REF_TRANS:
		assert(trans->hdr.type == TRANSACTION_NORMAL);
		invalidate_block_bad_input_ref_trans(state, block, trans, refs,
						   bad_transnum, bad_input,
						   bad_intrans);
		return;

	default:
		log_broken(state->log,
			   "Unknown invalidate_block_badtrans error ");
		log_add_enum(state->log, enum protocol_error, err);
		abort();
	}

	/* Simple single-transaction error. */
	invalidate_block_bad_transaction(state, block, err, trans, refs,
					 bad_transnum);
}
