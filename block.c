#include "block.h"
#include "chain.h"
#include "protocol.h"
#include "state.h"
#include "peer.h"
#include "generating.h"
#include "log.h"
#include "pending.h"
#include "packet.h"
#include "proof.h"
#include "transaction.h"
#include "features.h"
#include "shard.h"
#include <string.h>

/* For compactness, struct transaction_shard needs tx and refs adjacent. */
struct txptr_with_ref txptr_with_ref(const tal_t *ctx,
				     const union protocol_transaction *tx,
				     const struct protocol_input_ref *refs)
{
	struct txptr_with_ref txp;
	size_t txlen, reflen;
	char *p;

	txlen = marshall_transaction_len(tx);
	reflen = num_inputs(tx) * sizeof(struct protocol_input_ref);

	p = tal_alloc_(ctx, txlen + reflen, false, "txptr_with_ref");
	memcpy(p, tx, txlen);
	memcpy(p + txlen, refs, reflen);

	txp.tx = (union protocol_transaction *)p;
	return txp;
}

struct transaction_shard *new_shard(const tal_t *ctx, u16 shardnum, u8 num)
{
	struct transaction_shard *s;

	s = tal_alloc_(ctx,
		       offsetof(struct transaction_shard, u[num]),
		       true, "struct transaction_shard");
	s->shardnum = shardnum;
	return s;
}

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
	u32 depth = le32_to_cpu(block->hdr->depth);

	log_debug(state->log, "Adding block %u ", depth);
	log_add_struct(state->log, struct protocol_double_sha, &block->sha);

	/* Add to list for that generation. */
	if (depth >= tal_count(state->block_depth)) {
		/* We can only increment block depths. */
		assert(depth == tal_count(state->block_depth));
		tal_resize(&state->block_depth, depth + 1);
		state->block_depth[depth]
			= tal(state->block_depth, struct list_head);
		list_head_init(state->block_depth[depth]);
	}
	/* We give some priority to blocks hear about first. */
	list_add_tail(state->block_depth[depth], &block->list);

	block->pending_features = pending_features(block);

	/* Link us into parent's children list. */
	list_head_init(&block->children);
	list_add_tail(&block->prev->children, &block->sibling);

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

bool block_all_known(const struct block *block, unsigned int *shardnum)
{
	unsigned int i;

	for (i = 0; i < num_shards(block->hdr); i++) {
		if (!shard_all_known(block, i)) {
			if (shardnum)
				*shardnum = i;
			return false;
		}
	}
	return true;
}

struct protocol_input_ref *block_get_refs(const struct block *block,
					  u16 shardnum, u8 txoff)
{
	const struct transaction_shard *s = block->shard[shardnum];

	assert(shardnum < num_shards(block->hdr));
	assert(txoff < block->shard_nums[shardnum]);

	if (!s)
		return NULL;

	/* Must not be a hash. */
	assert(shard_is_tx(s, txoff));
	return cast_const(struct protocol_input_ref *,
			  refs_for(s->u[txoff].txp));
}

static void complaint_on_all(struct block *block, const void *complaint)
{
	struct block *b;

	/* Mark block. */
	block->complaint = complaint;

	/* Mark descendents. */
	list_for_each(&block->children, b, sibling)
		complaint_on_all(b, complaint);
}
	
static void invalidate_block(struct state *state,
			     struct block *block,
			     const void *complaint)
{
	/* FIXME: Save complaint to blockfile! */

	/* If it's invalid, so are any descendents. */
	complaint_on_all(block, complaint);

	/* Recalc everything.  Slow, but should be rare. */
	update_block_ptrs_invalidated(state, block);

	/* Tell everyone... */
	broadcast_to_peers(state, complaint);
}

static void
invalidate_block_bad_input(struct state *state,
			   struct block *block,
			   const union protocol_transaction *trans,
			   const struct protocol_input_ref *refs,
			   unsigned int bad_shardnum,
			   unsigned int bad_txoff,
			   unsigned int bad_input,
			   const union protocol_transaction *intrans)
{
	struct protocol_pkt_block_tx_bad_input *req;

	assert(le32_to_cpu(trans->hdr.type) == TRANSACTION_NORMAL);
	log_unusual(state->log, "Block %u ", le32_to_cpu(block->hdr->depth));
	log_add_struct(state->log, struct protocol_double_sha, &block->sha);
	log_add(state->log, " invalid due to trans %u in shard %u ",
		bad_txoff, bad_shardnum);
	log_add_struct(state->log, union protocol_transaction, trans);
	log_add(state->log, " with bad input %u ", bad_input);
	log_add_struct(state->log, union protocol_transaction, intrans);

	req = tal_packet(block, struct protocol_pkt_block_tx_bad_input,
			 PROTOCOL_PKT_BLOCK_TX_BAD_INPUT);
	req->inputnum = cpu_to_le32(bad_input);

	tal_packet_append_proof(&req, block, bad_shardnum, bad_txoff);
	tal_packet_append_trans(&req, intrans);

	invalidate_block(state, block, req);
}

static void
invalidate_block_bad_amounts(struct state *state,
			     struct block *block,
			     const union protocol_transaction *trans,
			     const struct protocol_input_ref *refs,
			     unsigned int bad_shardnum,
			     unsigned int bad_txoff)
{
	struct protocol_pkt_block_tx_bad_amount *req;
	union protocol_transaction *input[TRANSACTION_MAX_INPUTS];
	unsigned int i;
	struct protocol_input *inp;

	assert(le32_to_cpu(trans->hdr.type) == TRANSACTION_NORMAL);
	log_unusual(state->log, "Block %u ", le32_to_cpu(block->hdr->depth));
	log_add_struct(state->log, struct protocol_double_sha, &block->sha);
	log_add(state->log, " invalid amounts in trans %u of shard %u ",
		bad_txoff, bad_shardnum);
	log_add_struct(state->log, union protocol_transaction, trans);
	log_add(state->log, " with inputs: ");

	inp = get_normal_inputs(&trans->normal);

	/* FIXME: What if input is pending? */
	for (i = 0; i < le32_to_cpu(trans->normal.num_inputs); i++) {
		input[i] = thash_gettrans(&state->thash, &inp[i].input);
		log_add_struct(state->log, union protocol_transaction, input[i]);
		log_add(state->log, " (output %u)", le16_to_cpu(inp[i].output));
	}

	req = tal_packet(block, struct protocol_pkt_block_tx_bad_amount,
			 PROTOCOL_PKT_BLOCK_TX_BAD_AMOUNT);
	tal_packet_append_proof(&req, block, bad_shardnum, bad_txoff);

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
				 unsigned int bad_shardnum,
				 unsigned int bad_txoff)
{
	struct protocol_pkt_block_tx_invalid *req;	

	log_unusual(state->log, "Block %u ", le32_to_cpu(block->hdr->depth));
	log_add_struct(state->log, struct protocol_double_sha, &block->sha);
	log_add(state->log, " invalid due to trans %u ofshard %u ",
		bad_txoff, bad_shardnum);
	log_add_struct(state->log, union protocol_transaction, trans);
	log_add(state->log, " error ");
	log_add_enum(state->log, enum protocol_error, err);

	req = tal_packet(block, struct protocol_pkt_block_tx_invalid,
			 PROTOCOL_PKT_BLOCK_TX_INVALID);
	req->error = cpu_to_le32(err);

	tal_packet_append_proof(&req, block, bad_shardnum, bad_txoff);

	invalidate_block(state, block, req);
}

void invalidate_block_misorder(struct state *state,
			       struct block *block,
			       unsigned int bad_txoff1,
			       unsigned int bad_txoff2,
			       unsigned int bad_shardnum)
{
	struct protocol_pkt_block_tx_misorder *req;	
	const union protocol_transaction *trans1, *trans2;

	trans1 = block_get_tx(block, bad_shardnum, bad_txoff1);
	trans2 = block_get_tx(block, bad_shardnum, bad_txoff2);

	log_unusual(state->log, "Block %u ", le32_to_cpu(block->hdr->depth));
	log_add_struct(state->log, struct protocol_double_sha, &block->sha);
	log_add(state->log, " invalid due to misorder shard %u trans %u vs %u ",
		bad_shardnum, bad_txoff1, bad_txoff2);
	log_add_struct(state->log, union protocol_transaction, trans1);
	log_add(state->log, " vs ");
	log_add_struct(state->log, union protocol_transaction, trans2);

	req = tal_packet(block, struct protocol_pkt_block_tx_misorder,
			 PROTOCOL_PKT_BLOCK_TX_MISORDER);
	tal_packet_append_proof(&req, block, bad_shardnum, bad_txoff1);
	tal_packet_append_proof(&req, block, bad_shardnum, bad_txoff2);

	invalidate_block(state, block, req);
}

static void
invalidate_block_bad_input_ref_trans(struct state *state,
				     struct block *block,
				     const union protocol_transaction *trans,
				     const struct protocol_input_ref *refs,
				     u16 bad_shard,
				     u8 bad_txnum,
				     unsigned int bad_input,
				     const union protocol_transaction *bad_intrans)
{
	struct protocol_pkt_block_bad_input_ref *req;	
	const struct protocol_input_ref *bad_ref;
	const struct block *input_block;

	bad_ref = &refs[bad_input];
	input_block = block_ancestor(block, le32_to_cpu(bad_ref->blocks_ago));

	log_unusual(state->log, "Block %u ", le32_to_cpu(block->hdr->depth));
	log_add_struct(state->log, struct protocol_double_sha, &block->sha);
	log_unusual(state->log, " transaction %u of shard %u ", bad_txnum,
		    bad_shard);
	log_add_struct(state->log, union protocol_transaction, trans);
	log_add(state->log, 
		" invalid due to wrong input %u reference %u ago tx %u/%u ",
		bad_input, le32_to_cpu(bad_ref->blocks_ago),
		le16_to_cpu(bad_ref->shard), bad_ref->txoff);
	log_add_struct(state->log, union protocol_transaction, bad_intrans);

	req = tal_packet(block, struct protocol_pkt_block_bad_input_ref,
			 PROTOCOL_PKT_BLOCK_BAD_INPUT_REF);
	req->inputnum = cpu_to_le32(bad_input);

	tal_packet_append_proof(&req, block, bad_shard, bad_txnum);
	tal_packet_append_proof(&req, input_block,
				le16_to_cpu(bad_ref->shard), bad_ref->txoff);

	invalidate_block(state, block, req);
}

/* See check_trans_normal_inputs: bad_input and bad_intrans are valid
 * iff err = PROTOCOL_ERROR_PRIV_TRANS_BAD_INPUT. */
void invalidate_block_badtrans(struct state *state,
			       struct block *block,
			       enum protocol_error err,
			       unsigned int bad_shardnum,
			       unsigned int bad_txoff,
			       unsigned int bad_input,
			       union protocol_transaction *bad_intrans)
{
	union protocol_transaction *trans;
	const struct protocol_input_ref *refs;

	trans = block_get_tx(block, bad_shardnum, bad_txoff);
	refs = block_get_refs(block, bad_shardnum, bad_txoff);

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
	case PROTOCOL_ERROR_PRIV_BLOCK_BAD_INPUT_REF:
	case PROTOCOL_ERROR_BLOCK_BAD_TX_SHARD:
		assert(trans->hdr.type == TRANSACTION_NORMAL);
		break;

	case PROTOCOL_ERROR_PRIV_TRANS_BAD_INPUT:
		assert(trans->hdr.type == TRANSACTION_NORMAL);
		/* FIXME: This means an unknown input.  We don't
		 * complain. */
		if (!bad_intrans)
			return;
		invalidate_block_bad_input(state, block,
					   trans, refs, bad_shardnum, bad_txoff,
					   bad_input, bad_intrans);
		return;

	case PROTOCOL_ERROR_PRIV_TRANS_BAD_AMOUNTS:
		assert(trans->hdr.type == TRANSACTION_NORMAL);
		invalidate_block_bad_amounts(state, block, trans, refs,
					     bad_shardnum, bad_txoff);
		return;

	case PROTOCOL_ERROR_PRIV_BLOCK_BAD_INPUT_REF_TRANS:
		assert(trans->hdr.type == TRANSACTION_NORMAL);
		invalidate_block_bad_input_ref_trans(state, block, trans, refs,
						     bad_shardnum, bad_txoff,
						     bad_input, bad_intrans);
		return;

	default:
		log_broken(state->log,
			   "Unknown invalidate_block_badtrans error ");
		log_add_enum(state->log, enum protocol_error, err);
		abort();
	}

	/* Simple single-transaction error. */
	invalidate_block_bad_transaction(state, block, err, trans, refs,
					 bad_shardnum, bad_txoff);
}
