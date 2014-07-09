#include "block.h"
#include "chain.h"
#include "complain.h"
#include "proof.h"
#include "state.h"
#include "tal_packet.h"
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
	
void publish_complaint(struct state *state,
		       struct block *block,
		       const void *complaint,
		       struct peer *origin)
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

	/* Tell everyone (except origin!) */
	broadcast_to_peers(state, complaint, origin);
}

void complain_bad_input(struct state *state,
			struct block *block,
			const struct protocol_proof *proof,
			const union protocol_tx *tx,
			const struct protocol_input_ref *refs,
			unsigned int bad_input,
			const union protocol_tx *intx)
{
	struct protocol_pkt_complain_tx_bad_input *pkt;

	assert(tx_type(tx) == TX_NORMAL);
	log_unusual(state->log, "Block %u ", le32_to_cpu(block->hdr->depth));
	log_add_struct(state->log, struct protocol_double_sha, &block->sha);
	log_add(state->log, " invalid due to tx %u in shard %u ",
		proof->pos.txoff, le16_to_cpu(proof->pos.shard));
	log_add_struct(state->log, union protocol_tx, tx);
	log_add(state->log, " with bad input %u ", bad_input);
	log_add_struct(state->log, union protocol_tx, intx);

	pkt = tal_packet(block, struct protocol_pkt_complain_tx_bad_input,
			 PROTOCOL_PKT_COMPLAIN_TX_BAD_INPUT);
	pkt->inputnum = cpu_to_le32(bad_input);

	tal_packet_append_proof(&pkt, proof);
	tal_packet_append_tx_with_refs(&pkt, tx, refs);
	tal_packet_append_tx(&pkt, intx);

	publish_complaint(state, block, pkt, NULL);
}

void complain_bad_amount(struct state *state,
			 struct block *block,
			 const struct protocol_proof *proof,
			 const union protocol_tx *tx,
			 const struct protocol_input_ref *refs,
			 const union protocol_tx *intx[])
{
	struct protocol_pkt_complain_tx_bad_amount *pkt;
	unsigned int i;

	assert(tx_type(tx) == TX_NORMAL);
	log_unusual(state->log, "Block %u ", le32_to_cpu(block->hdr->depth));
	log_add_struct(state->log, struct protocol_double_sha, &block->sha);
	log_add(state->log, " invalid amounts in tx %u of shard %u ",
		proof->pos.txoff, le16_to_cpu(proof->pos.shard));
	log_add_struct(state->log, union protocol_tx, tx);
	log_add(state->log, " with inputs: ");

	pkt = tal_packet(block, struct protocol_pkt_complain_tx_bad_amount,
			 PROTOCOL_PKT_COMPLAIN_TX_BAD_AMOUNT);
	tal_packet_append_proof(&pkt, proof);
	tal_packet_append_tx_with_refs(&pkt, tx, refs);

	/* FIXME: What if input is pending? */
	for (i = 0; i < num_inputs(tx); i++) {
		log_add_struct(state->log, union protocol_tx, intx[i]);
		log_add(state->log, " (output %u)",
			le16_to_cpu(tx_input(tx, i)->output));

		tal_packet_append_tx(&pkt, intx[i]);
	}

	publish_complaint(state, block, pkt, NULL);
}

/* We know conflict_txoff (ie. it's already in the block), and proof
 * shows another tx which is misordered relative to that. */
void complain_misorder(struct state *state,
		       struct block *block,
		       const struct protocol_proof *proof,
		       const union protocol_tx *tx,
		       const struct protocol_input_ref *refs,
		       unsigned int conflict_txoff)
{
	struct protocol_pkt_complain_tx_misorder *pkt;
	const union protocol_tx *conflict_tx;
	const struct protocol_input_ref *conflict_refs;
	struct protocol_proof conflict_proof;
	u16 shardnum = le16_to_cpu(proof->pos.shard);

	conflict_tx = block_get_tx(block, shardnum, conflict_txoff);
	conflict_refs = block_get_refs(block, shardnum, conflict_txoff);

	log_unusual(state->log, "Block %u ", le32_to_cpu(block->hdr->depth));
	log_add_struct(state->log, struct protocol_double_sha, &block->sha);
	log_add(state->log, " invalid due to misorder shard %u tx %u vs %u ",
		shardnum, conflict_txoff, proof->pos.txoff);
	log_add_struct(state->log, union protocol_tx, conflict_tx);
	log_add(state->log, " vs ");
	log_add_struct(state->log, union protocol_tx, tx);

	pkt = tal_packet(block, struct protocol_pkt_complain_tx_misorder,
			 PROTOCOL_PKT_COMPLAIN_TX_MISORDER);
	tal_packet_append_proof(&pkt, proof);
	tal_packet_append_tx_with_refs(&pkt, tx, refs);

	create_proof(&conflict_proof, block, shardnum, conflict_txoff);
	tal_packet_append_proof(&pkt, &conflict_proof);
	tal_packet_append_tx_with_refs(&pkt, conflict_tx, conflict_refs);

	publish_complaint(state, block, pkt, NULL);
}

/* refs[bad_refnum] points to the wrong tx! */
void complain_bad_input_ref(struct state *state,
			    struct block *block,
			    const struct protocol_proof *proof,
			    const union protocol_tx *tx,
			    const struct protocol_input_ref *refs,
			    unsigned int bad_refnum,
			    const struct block *block_referred_to)
{
	struct protocol_pkt_complain_bad_input_ref *pkt;	
	const struct protocol_input_ref *bad_ref;
	struct protocol_proof ref_proof;
	const union protocol_tx *bad_intx;
	const struct protocol_input_ref *bad_intx_refs;
	
	bad_ref = &refs[bad_refnum];
	bad_intx = block_get_tx(block_referred_to, le16_to_cpu(bad_ref->shard),
				bad_ref->txoff);
	bad_intx_refs = block_get_refs(block_referred_to,
				       le16_to_cpu(bad_ref->shard),
				       bad_ref->txoff);

	log_unusual(state->log, "Block %u ", le32_to_cpu(block->hdr->depth));
	log_add_struct(state->log, struct protocol_double_sha, &block->sha);
	log_unusual(state->log, " tx %u of shard %u ",
		    proof->pos.txoff, le16_to_cpu(proof->pos.shard));
	log_add_struct(state->log, union protocol_tx, tx);
	log_add(state->log, 
		" invalid due to wrong input %u reference %u ago tx %u/%u ",
		bad_refnum, le32_to_cpu(bad_ref->blocks_ago),
		le16_to_cpu(bad_ref->shard), bad_ref->txoff);
	log_add_struct(state->log, union protocol_tx, bad_intx);

	pkt = tal_packet(block, struct protocol_pkt_complain_bad_input_ref,
			 PROTOCOL_PKT_COMPLAIN_BAD_INPUT_REF);
	pkt->inputnum = cpu_to_le32(bad_refnum);

	/* This is the tx which has the bad reference. */
	tal_packet_append_proof(&pkt, proof);
	tal_packet_append_tx_with_refs(&pkt, tx, refs);

	/* This is where the ref points to. */
	create_proof(&ref_proof, block_referred_to,
		     le16_to_cpu(bad_ref->shard), bad_ref->txoff);
	tal_packet_append_proof(&pkt, &ref_proof);
	tal_packet_append_tx_with_refs(&pkt, bad_intx, bad_intx_refs);

	publish_complaint(state, block, pkt, NULL);
}

/* Simple single-transacion error. */
void complain_bad_tx(struct state *state,
		     struct block *block,
		     enum protocol_ecode err,
		     const struct protocol_proof *proof,
		     const union protocol_tx *tx,
		     const struct protocol_input_ref *refs)
{
	struct protocol_pkt_complain_tx_invalid *pkt;

	switch (err) {
	case PROTOCOL_ECODE_TX_HIGH_VERSION:
	case PROTOCOL_ECODE_TX_LOW_VERSION:
	case PROTOCOL_ECODE_TX_TYPE_UNKNOWN:
	case PROTOCOL_ECODE_TX_TOO_LARGE:
	case PROTOCOL_ECODE_TX_BAD_SIG:
		break;

	case PROTOCOL_ECODE_TX_BAD_GATEWAY:
	case PROTOCOL_ECODE_TX_CROSS_SHARDS:
		assert(tx_type(tx) == TX_FROM_GATEWAY);
		break;

	case PROTOCOL_ECODE_TX_TOO_MANY_INPUTS:
		assert(tx_type(tx) == TX_NORMAL);
		break;

	default:
		log_broken(state->log,
			   "Unknown complain_bad_tx error ");
		log_add_enum(state->log, enum protocol_ecode, err);
		abort();
	}

	log_unusual(state->log, "Block %u ", le32_to_cpu(block->hdr->depth));
	log_add_struct(state->log, struct protocol_double_sha, &block->sha);
	log_add(state->log, " invalid due to tx %u of shard %u ",
		proof->pos.txoff, le16_to_cpu(proof->pos.shard));
	log_add(state->log, " error ");
	log_add_enum(state->log, enum protocol_ecode, err);
	/* FIXME: Would be nice to log something about invalid tx! */

	pkt = tal_packet(block, struct protocol_pkt_complain_tx_invalid,
			 PROTOCOL_PKT_COMPLAIN_TX_INVALID);
	pkt->error = cpu_to_le32(err);

	tal_packet_append_proof(&pkt, proof);
	tal_packet_append_tx_with_refs(&pkt, tx, refs);

	publish_complaint(state, block, pkt, NULL);
}
