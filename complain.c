#include "complain.h"
#include "state.h"
#include "block.h"
#include "chain.h"
#include "packet.h"
#include "tal_packet_proof.h"
#include "tx.h"

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
	/* Don't complaint storm. */
	if (block->complaint) {
		tal_free(complaint);
		return;
	}

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
			   const union protocol_tx *tx,
			   const struct protocol_input_ref *refs,
			   unsigned int bad_shardnum,
			   unsigned int bad_txoff,
			   unsigned int bad_input,
			   const union protocol_tx *intx)
{
	struct protocol_pkt_block_tx_bad_input *req;

	assert(le32_to_cpu(tx->hdr.type) == TX_NORMAL);
	log_unusual(state->log, "Block %u ", le32_to_cpu(block->hdr->depth));
	log_add_struct(state->log, struct protocol_double_sha, &block->sha);
	log_add(state->log, " invalid due to tx %u in shard %u ",
		bad_txoff, bad_shardnum);
	log_add_struct(state->log, union protocol_tx, tx);
	log_add(state->log, " with bad input %u ", bad_input);
	log_add_struct(state->log, union protocol_tx, intx);

	req = tal_packet(block, struct protocol_pkt_block_tx_bad_input,
			 PROTOCOL_PKT_BLOCK_TX_BAD_INPUT);
	req->inputnum = cpu_to_le32(bad_input);

	tal_packet_append_proof(&req, block, bad_shardnum, bad_txoff);
	tal_packet_append_tx(&req, intx);

	invalidate_block(state, block, req);
}

static void
invalidate_block_bad_amounts(struct state *state,
			     struct block *block,
			     const union protocol_tx *tx,
			     const struct protocol_input_ref *refs,
			     unsigned int bad_shardnum,
			     unsigned int bad_txoff)
{
	struct protocol_pkt_block_tx_bad_amount *req;
	union protocol_tx *input[PROTOCOL_TX_MAX_INPUTS];
	unsigned int i;
	struct protocol_input *inp;

	assert(le32_to_cpu(tx->hdr.type) == TX_NORMAL);
	log_unusual(state->log, "Block %u ", le32_to_cpu(block->hdr->depth));
	log_add_struct(state->log, struct protocol_double_sha, &block->sha);
	log_add(state->log, " invalid amounts in tx %u of shard %u ",
		bad_txoff, bad_shardnum);
	log_add_struct(state->log, union protocol_tx, tx);
	log_add(state->log, " with inputs: ");

	inp = get_normal_inputs(&tx->normal);

	/* FIXME: What if input is pending? */
	for (i = 0; i < le32_to_cpu(tx->normal.num_inputs); i++) {
		input[i] = txhash_gettx(&state->txhash, &inp[i].input);
		log_add_struct(state->log, union protocol_tx, input[i]);
		log_add(state->log, " (output %u)", le16_to_cpu(inp[i].output));
	}

	req = tal_packet(block, struct protocol_pkt_block_tx_bad_amount,
			 PROTOCOL_PKT_BLOCK_TX_BAD_AMOUNT);
	tal_packet_append_proof(&req, block, bad_shardnum, bad_txoff);

	for (i = 0; i < num_inputs(tx); i++)
		tal_packet_append_tx(&req, input[i]);

	invalidate_block(state, block, req);
}

static void
invalidate_block_bad_tx(struct state *state,
				 struct block *block,
				 enum protocol_ecode err,
				 const union protocol_tx *tx,
				 const struct protocol_input_ref *refs,
				 unsigned int bad_shardnum,
				 unsigned int bad_txoff)
{
	struct protocol_pkt_block_tx_invalid *req;	

	log_unusual(state->log, "Block %u ", le32_to_cpu(block->hdr->depth));
	log_add_struct(state->log, struct protocol_double_sha, &block->sha);
	log_add(state->log, " invalid due to tx %u ofshard %u ",
		bad_txoff, bad_shardnum);
	log_add_struct(state->log, union protocol_tx, tx);
	log_add(state->log, " error ");
	log_add_enum(state->log, enum protocol_ecode, err);

	req = tal_packet(block, struct protocol_pkt_block_tx_invalid,
			 PROTOCOL_PKT_BLOCK_TX_INVALID);
	req->error = cpu_to_le32(err);

	tal_packet_append_proof(&req, block, bad_shardnum, bad_txoff);

	invalidate_block(state, block, req);
}

void complain_misorder(struct state *state,
			       struct block *block,
			       unsigned int bad_txoff1,
			       unsigned int bad_txoff2,
			       unsigned int bad_shardnum)
{
	struct protocol_pkt_block_tx_misorder *req;	
	const union protocol_tx *tx1, *tx2;

	tx1 = block_get_tx(block, bad_shardnum, bad_txoff1);
	tx2 = block_get_tx(block, bad_shardnum, bad_txoff2);

	log_unusual(state->log, "Block %u ", le32_to_cpu(block->hdr->depth));
	log_add_struct(state->log, struct protocol_double_sha, &block->sha);
	log_add(state->log, " invalid due to misorder shard %u tx %u vs %u ",
		bad_shardnum, bad_txoff1, bad_txoff2);
	log_add_struct(state->log, union protocol_tx, tx1);
	log_add(state->log, " vs ");
	log_add_struct(state->log, union protocol_tx, tx2);

	req = tal_packet(block, struct protocol_pkt_block_tx_misorder,
			 PROTOCOL_PKT_BLOCK_TX_MISORDER);
	tal_packet_append_proof(&req, block, bad_shardnum, bad_txoff1);
	tal_packet_append_proof(&req, block, bad_shardnum, bad_txoff2);

	invalidate_block(state, block, req);
}

static void
invalidate_block_bad_input_ref_tx(struct state *state,
				  struct block *block,
				  const union protocol_tx *tx,
				  const struct protocol_input_ref *refs,
				  u16 bad_shard,
				  u8 bad_txnum,
				  unsigned int bad_input,
				  const union protocol_tx *bad_intx)
{
	struct protocol_pkt_block_bad_input_ref *req;	
	const struct protocol_input_ref *bad_ref;
	const struct block *input_block;

	bad_ref = &refs[bad_input];
	input_block = block_ancestor(block, le32_to_cpu(bad_ref->blocks_ago));

	log_unusual(state->log, "Block %u ", le32_to_cpu(block->hdr->depth));
	log_add_struct(state->log, struct protocol_double_sha, &block->sha);
	log_unusual(state->log, " tx %u of shard %u ", bad_txnum,
		    bad_shard);
	log_add_struct(state->log, union protocol_tx, tx);
	log_add(state->log, 
		" invalid due to wrong input %u reference %u ago tx %u/%u ",
		bad_input, le32_to_cpu(bad_ref->blocks_ago),
		le16_to_cpu(bad_ref->shard), bad_ref->txoff);
	log_add_struct(state->log, union protocol_tx, bad_intx);

	req = tal_packet(block, struct protocol_pkt_block_bad_input_ref,
			 PROTOCOL_PKT_BLOCK_BAD_INPUT_REF);
	req->inputnum = cpu_to_le32(bad_input);

	tal_packet_append_proof(&req, block, bad_shard, bad_txnum);
	tal_packet_append_proof(&req, input_block,
				le16_to_cpu(bad_ref->shard), bad_ref->txoff);

	invalidate_block(state, block, req);
}

/* See check_tx_normal_inputs: bad_input and bad_intx are valid
 * iff err = PROTOCOL_ECODE_PRIV_TX_BAD_INPUT. */
void complain_bad_tx(struct state *state,
		     struct block *block,
		     enum protocol_ecode err,
		     unsigned int bad_shardnum,
		     unsigned int bad_txoff,
		     unsigned int bad_input,
		     union protocol_tx *bad_intx)
{
	union protocol_tx *tx;
	const struct protocol_input_ref *refs;

	tx = block_get_tx(block, bad_shardnum, bad_txoff);
	refs = block_get_refs(block, bad_shardnum, bad_txoff);

	switch (err) {
	case PROTOCOL_ECODE_TX_HIGH_VERSION:
	case PROTOCOL_ECODE_TX_LOW_VERSION:
	case PROTOCOL_ECODE_TX_UNKNOWN:
	case PROTOCOL_ECODE_TX_TOO_LARGE:
	case PROTOCOL_ECODE_TX_BAD_SIG:
		break;

	case PROTOCOL_ECODE_TX_BAD_GATEWAY:
	case PROTOCOL_ECODE_TX_CROSS_SHARDS:
		assert(tx->hdr.type == TX_FROM_GATEWAY);
		break;

	case PROTOCOL_ECODE_TX_TOO_MANY_INPUTS:
	case PROTOCOL_ECODE_PRIV_BLOCK_BAD_INPUT_REF:
	case PROTOCOL_ECODE_BLOCK_BAD_TX_SHARD:
		assert(tx->hdr.type == TX_NORMAL);
		break;

	case PROTOCOL_ECODE_PRIV_TX_BAD_INPUT:
		assert(tx->hdr.type == TX_NORMAL);
		/* FIXME: This means an unknown input.  We don't
		 * complain. */
		if (!bad_intx)
			return;
		invalidate_block_bad_input(state, block,
					   tx, refs, bad_shardnum, bad_txoff,
					   bad_input, bad_intx);
		return;

	case PROTOCOL_ECODE_PRIV_TX_BAD_AMOUNTS:
		assert(tx->hdr.type == TX_NORMAL);
		invalidate_block_bad_amounts(state, block, tx, refs,
					     bad_shardnum, bad_txoff);
		return;

	case PROTOCOL_ECODE_PRIV_BLOCK_BAD_INPUT_REF_TX:
		assert(tx->hdr.type == TX_NORMAL);
		invalidate_block_bad_input_ref_tx(state, block, tx, refs,
						  bad_shardnum, bad_txoff,
						  bad_input, bad_intx);
		return;

	default:
		log_broken(state->log,
			   "Unknown complain_badtx error ");
		log_add_enum(state->log, enum protocol_ecode, err);
		abort();
	}

	/* Simple single-transacion error. */
	invalidate_block_bad_tx(state, block, err, tx, refs,
				bad_shardnum, bad_txoff);
}
