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
#include "tx.h"
#include "features.h"
#include "shard.h"
#include <string.h>

/* For compactness, struct tx_shard needs tx and refs adjacent. */
struct txptr_with_ref txptr_with_ref(const tal_t *ctx,
				     const union protocol_tx *tx,
				     const struct protocol_input_ref *refs)
{
	struct txptr_with_ref txp;
	size_t txlen, reflen;
	char *p;

	txlen = marshall_tx_len(tx);
	reflen = num_inputs(tx) * sizeof(struct protocol_input_ref);

	p = tal_alloc_(ctx, txlen + reflen, false, "txptr_with_ref");
	memcpy(p, tx, txlen);
	memcpy(p + txlen, refs, reflen);

	txp.tx = (union protocol_tx *)p;
	return txp;
}

struct tx_shard *new_shard(const tal_t *ctx, u16 shardnum, u8 num)
{
	struct tx_shard *s;

	s = tal_alloc_(ctx,
		       offsetof(struct tx_shard, u[num]),
		       true, "struct tx_shard");
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
	const struct tx_shard *s = block->shard[shardnum];

	assert(shardnum < num_shards(block->hdr));
	assert(txoff < block->shard_nums[shardnum]);

	if (!s)
		return NULL;

	/* Must not be a hash. */
	assert(shard_is_tx(s, txoff));
	return cast_const(struct protocol_input_ref *,
			  refs_for(s->u[txoff].txp));
}

/* If we have the tx, hash it, otherwise return hash. */
const struct protocol_net_txrefhash *
txrefhash_in_shard(const struct block *b, u16 shard, u8 txoff,
		   struct protocol_net_txrefhash *scratch)
{
	const struct tx_shard *s = b->shard[shard];

	assert(shard < num_shards(b->hdr));
	assert(txoff < b->shard_nums[shard]);

	if (!s)
		return NULL;

	if (shard_is_tx(s, txoff)) {
		const union protocol_tx *tx = tx_for(s, txoff);
		if (!tx)
			return NULL;
		hash_tx(tx, &scratch->txhash);
		hash_refs(refs_for(s->u[txoff].txp), num_inputs(tx),
			  &scratch->refhash);
		return scratch;
	} else
		return s->u[txoff].hash;
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

void invalidate_block_misorder(struct state *state,
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
void invalidate_block_badtx(struct state *state,
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
			   "Unknown invalidate_block_badtx error ");
		log_add_enum(state->log, enum protocol_ecode, err);
		abort();
	}

	/* Simple single-transacion error. */
	invalidate_block_bad_tx(state, block, err, tx, refs,
				bad_shardnum, bad_txoff);
}
