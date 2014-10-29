#include "block.h"
#include "chain.h"
#include "check_tx.h"
#include "complain.h"
#include "marshal.h"
#include "proof.h"
#include "recv_complain.h"
#include "shadouble.h"
#include "tal_packet.h"
#include "todo.h"
#include "tx.h"
#include "tx_cmp.h"
#include <ccan/structeq/structeq.h>

static enum protocol_ecode
unmarshal_proven_tx(struct state *state,
		    const char **p, size_t *len,
		    struct block **b,
		    const union protocol_tx **tx,
		    const struct protocol_position **pos)
{
	enum protocol_ecode e;
	const struct protocol_tx_with_proof *proof;
	const struct protocol_input_ref *refs;
	size_t used;

	if (*len < sizeof(*proof))
		return PROTOCOL_ECODE_INVALID_LEN;

	proof = (const struct protocol_tx_with_proof *)*p;
	*len -= sizeof(*proof);
	*pos = &proof->proof.pos;

	/* FIXME: change unmarshall to a pull-style function to do this? */
	e = unmarshal_tx(*p, *len, &used);
	if (e)
		return e;
	*tx = (const void *)*p;
	*p += used;
	*len -= used;

	e = unmarshal_input_refs(*p, *len, *tx, &used);
	if (e)
		return e;
	refs = (const void *)*p;
	*p += used;
	*len -= used;

	*b = block_find_any(state, &(*pos)->block);
	if (!*b)
		return PROTOCOL_ECODE_UNKNOWN_BLOCK;

	e = check_tx(state, *tx, *b);
	if (e)
		return e;

	if (!check_proof(&proof->proof, *b, *tx, refs))
		return PROTOCOL_ECODE_BAD_PROOF;

	return PROTOCOL_ECODE_NONE;
}

/* The marshalled txs are the same between protocol_pkt_tx_bad_amount
 * and protocol_pkt_complain_tx_bad_amount, so share this code: */
enum protocol_ecode
unmarshal_and_check_bad_amount(struct state *state, const union protocol_tx *tx,
			       const char *p, size_t len)
{
	const union protocol_tx *in[PROTOCOL_TX_MAX_INPUTS];
	unsigned int i;
	u32 total = 0;

	/* It doesn't make sense to complain about inputs if there are none! */
	if (num_inputs(tx) == 0)
		return PROTOCOL_ECODE_BAD_INPUTNUM;

	/* Unmarshall and check input transactions. */
	for (i = 0; i < num_inputs(tx); i++) {
		enum protocol_ecode e;
		enum input_ecode ierr;

		e = unmarshal_and_check_tx(state, &p, &len, &in[i]);
		if (e)
			return e;

		/* Make sure this tx match the bad input */
		e = verify_problem_input(state, tx, i, in[i], &ierr, &total);
		if (e)
			return e;
		if (ierr != ECODE_INPUT_OK)
			return PROTOCOL_ECODE_BAD_INPUT;
	}

	/* If there is any left over, that's bad. */
	if (len != 0)
		return PROTOCOL_ECODE_INVALID_LEN;

	if (total == tx_amount_sent(tx))
		return PROTOCOL_ECODE_COMPLAINT_INVALID;

	return PROTOCOL_ECODE_NONE;
}

/* They claim that @in is @tx's input_num'th input.  It may have an
 * input error.. */
enum protocol_ecode
verify_problem_input(struct state *state,
		     const union protocol_tx *tx, u32 input_num,
		     const union protocol_tx *in,
		     enum input_ecode *ierr,
		     u32 *total)
{
	struct protocol_tx_id sha;
	struct protocol_address tx_addr;
	const struct protocol_input *input;
	u32 amount;

	/* Make sure this tx match the bad input (and ensure it has inputs!) */
	if (input_num >= num_inputs(tx))
		return PROTOCOL_ECODE_BAD_INPUTNUM;

	/* You can't use this to complain about TX_CLAIMs. */
	if (tx_type(tx) == TX_CLAIM)
		return PROTOCOL_ECODE_BAD_INPUTNUM;

	input = tx_input(tx, input_num);
	hash_tx(in, &sha);

	if (!structeq(&input->input, &sha))
		return PROTOCOL_ECODE_BAD_INPUT;

	get_tx_input_address(tx, &tx_addr);

	/* We don't check for doublespends here. */
	*ierr = check_simple_input(state, input, in, &tx_addr, &amount);
	if (total)
		*total += amount;
	return PROTOCOL_ECODE_NONE;
}

enum protocol_ecode
recv_complain_tx_misorder(struct peer *peer,
			  const struct protocol_pkt_complain_tx_misorder *pkt)
{
	const union protocol_tx *tx1, *tx2;
	const struct protocol_position *pos1, *pos2;
	enum protocol_ecode e;
	struct block *b;
	const char *p;
	size_t len = le32_to_cpu(pkt->len);

	if (len < sizeof(*pkt))
		return PROTOCOL_ECODE_INVALID_LEN;

	p = (const char *)(pkt + 1);
	len -= sizeof(*pkt);

	e = unmarshal_proven_tx(peer->state, &p, &len, &b, &tx1, &pos1);
	if (e) {
		if (e == PROTOCOL_ECODE_UNKNOWN_BLOCK) {
			/* If we don't know it, that's OK.  Try to find out. */
			todo_add_get_block(peer->state, &pos1->block);
			/* FIXME: Keep complaint in this case? */
			return PROTOCOL_ECODE_NONE;
		}
		return e;
	}

	/* This one shouldn't be unknown: it should be the same block */
	e = unmarshal_proven_tx(peer->state, &p, &len, &b, &tx2, &pos2);
	if (e)
		return e;

	if (len != 0)
		return PROTOCOL_ECODE_INVALID_LEN;

	if (!structeq(&pos1->block, &pos2->block))
		return PROTOCOL_ECODE_BAD_MISORDER_POS;

	if (pos1->shard != pos2->shard)
		return PROTOCOL_ECODE_BAD_MISORDER_POS;

	if (pos1->txoff < pos2->txoff) {
		if (tx_cmp(tx1, tx2) < 0)
			return PROTOCOL_ECODE_COMPLAINT_INVALID;
	} else if (pos1->txoff > pos2->txoff) {
		if (tx_cmp(tx1, tx2) > 0)
			return PROTOCOL_ECODE_COMPLAINT_INVALID;
	} else
		/* Same position?  Weird. */
		return PROTOCOL_ECODE_BAD_MISORDER_POS;

	/* Mark it invalid, and tell everyone else if it wasn't already. */
	publish_complaint(peer->state, b, tal_packet_dup(b, pkt), peer);
	return PROTOCOL_ECODE_NONE;
}

enum protocol_ecode
recv_complain_tx_invalid(struct peer *peer,
			 const struct protocol_pkt_complain_tx_invalid *pkt)
{
	const void *tx, *refs;
	const struct protocol_tx_with_proof *proof;
	enum protocol_ecode e;
	struct block *b;
	const char *p;
	size_t len = le32_to_cpu(pkt->len), txlen, reflen;
	struct protocol_txrefhash txrefhash;
	SHA256_CTX shactx;

	if (len < sizeof(*pkt))
		return PROTOCOL_ECODE_INVALID_LEN;

	p = (const char *)(pkt + 1);
	len -= sizeof(*pkt);

	if (len < sizeof(*proof))
		return PROTOCOL_ECODE_INVALID_LEN;

	proof = (const struct protocol_tx_with_proof *)p;
	len -= sizeof(*proof);
	p += sizeof(*proof);

	b = block_find_any(peer->state, &proof->proof.pos.block);
	if (!b) {
		/* If we don't know it, that's OK.  Try to find out. */
		todo_add_get_block(peer->state, &proof->proof.pos.block);
		/* FIXME: Keep complaint in this case? */
		return PROTOCOL_ECODE_NONE;
	}

	/* These may be malformed, so we don't rely on unmarshal_tx */
	txlen = le32_to_cpu(pkt->txlen);
	if (len < txlen)
		return PROTOCOL_ECODE_INVALID_LEN;

	tx = (const void *)p;
	len -= txlen;
	p += txlen;

	reflen = len;
	refs = (const void *)p;

	/* Figure out what's wrong with it. */
	e = unmarshal_tx(tx, txlen, NULL);
	if (e == PROTOCOL_ECODE_NONE) {
		e = check_tx(peer->state, tx, b);
		if (e == PROTOCOL_ECODE_NONE)
			return PROTOCOL_ECODE_COMPLAINT_INVALID;
	}

	if (len != 0)
		return PROTOCOL_ECODE_INVALID_LEN;

	/* In theory we don't need to know the error, but it's good for
	 * diagnosing problems. */
	if (e != le32_to_cpu(pkt->error))
		return PROTOCOL_ECODE_COMPLAINT_INVALID;

	/* Treat tx and refs as blobs for hashing. */
	SHA256_Init(&shactx);
	SHA256_Update(&shactx, tx, txlen);
	SHA256_Double_Final(&shactx, &txrefhash.txhash.sha);

	SHA256_Init(&shactx);
	SHA256_Update(&shactx, refs, reflen);
	SHA256_Double_Final(&shactx, &txrefhash.refhash);

	if (!check_proof_byhash(&proof->proof, b, &txrefhash))
		return PROTOCOL_ECODE_BAD_PROOF;

	/* FIXME: We could look for the same hash in other blocks, too. */

	/* Mark it invalid, and tell everyone else if it wasn't already. */
	publish_complaint(peer->state, b, tal_packet_dup(b, pkt), peer);
	return PROTOCOL_ECODE_NONE;
}

enum protocol_ecode
recv_complain_tx_bad_input(struct peer *peer,
			   const struct protocol_pkt_complain_tx_bad_input *pkt)
{
	const union protocol_tx *tx, *in;
	const struct protocol_position *pos;
	enum protocol_ecode e;
	enum input_ecode ierr;
	struct block *b;
	const char *p;
	size_t len = le32_to_cpu(pkt->len);

	if (len < sizeof(*pkt))
		return PROTOCOL_ECODE_INVALID_LEN;

	p = (const char *)(pkt + 1);
	len -= sizeof(*pkt);

	e = unmarshal_proven_tx(peer->state, &p, &len, &b, &tx, &pos);
	if (e) {
		if (e == PROTOCOL_ECODE_UNKNOWN_BLOCK) {
			/* If we don't know it, that's OK.  Try to find out. */
			todo_add_get_block(peer->state, &pos->block);
			/* FIXME: Keep complaint in this case? */
			return PROTOCOL_ECODE_NONE;
		}
		return e;
	}

	e = unmarshal_and_check_tx(peer->state, &p, &len, &in);
	if (e)
		return e;

	if (len != 0)
		return PROTOCOL_ECODE_INVALID_LEN;

	/* Make sure this tx match the bad input */
	e = verify_problem_input(peer->state, tx, le32_to_cpu(pkt->inputnum),
				 in, &ierr, NULL);
	if (e)
		return e;

	/* The input should give an error. */
	if (ierr == ECODE_INPUT_OK)
		return PROTOCOL_ECODE_COMPLAINT_INVALID;

	/* FIXME: We could look for the same tx in other blocks, too. */

	/* Mark it invalid, and tell everyone else if it wasn't already. */
	publish_complaint(peer->state, b, tal_packet_dup(b, pkt), peer);
	return PROTOCOL_ECODE_NONE;
}

enum protocol_ecode
recv_complain_tx_bad_amount(struct peer *peer,
			const struct protocol_pkt_complain_tx_bad_amount *pkt)
{
	const union protocol_tx *tx;
	const struct protocol_position *pos;
	enum protocol_ecode e;
	struct block *b;
	const char *p;
	size_t len = le32_to_cpu(pkt->len);

	if (len < sizeof(*pkt))
		return PROTOCOL_ECODE_INVALID_LEN;

	p = (const char *)(pkt + 1);
	len -= sizeof(*pkt);

	e = unmarshal_proven_tx(peer->state, &p, &len, &b, &tx, &pos);
	if (e) {
		if (e == PROTOCOL_ECODE_UNKNOWN_BLOCK) {
			/* If we don't know it, that's OK.  Try to find out. */
			todo_add_get_block(peer->state, &pos->block);
			/* FIXME: Keep complaint in this case? */
			return PROTOCOL_ECODE_NONE;
		}
		return e;
	}

	e = unmarshal_and_check_bad_amount(peer->state, tx, p, len);
	if (e)
		return e;

	/* FIXME: We could look for the same tx in other blocks, too. */

	/* Mark it invalid, and tell everyone else if it wasn't already. */
	publish_complaint(peer->state, b, tal_packet_dup(b, pkt), peer);
	return PROTOCOL_ECODE_NONE;
}

enum protocol_ecode
recv_complain_doublespend(struct peer *peer,
			  const struct protocol_pkt_complain_doublespend *pkt)
{
	const union protocol_tx *tx1, *tx2;
	const struct protocol_position *pos1, *pos2;
	const struct protocol_input *inp1, *inp2;
	struct block *b1, *b2;
	enum protocol_ecode e;
	const char *p;
	size_t len = le32_to_cpu(pkt->len);

	if (len < sizeof(*pkt))
		return PROTOCOL_ECODE_INVALID_LEN;

	p = (const char *)(pkt + 1);
	len -= sizeof(*pkt);

	e = unmarshal_proven_tx(peer->state, &p, &len, &b1, &tx1, &pos1);
	if (e) {
		if (e == PROTOCOL_ECODE_UNKNOWN_BLOCK) {
			/* If we don't know it, that's OK.  Try to find out. */
			todo_add_get_block(peer->state, &pos1->block);
			/* FIXME: Keep complaint in this case? */
			return PROTOCOL_ECODE_NONE;
		}
		return e;
	}

	if (le32_to_cpu(pkt->input1) >= num_inputs(tx1))
		return PROTOCOL_ECODE_BAD_INPUTNUM;
	inp1 = tx_input(tx1, le32_to_cpu(pkt->input1));

	e = unmarshal_proven_tx(peer->state, &p, &len, &b2, &tx2, &pos2);
	if (e) {
		if (e == PROTOCOL_ECODE_UNKNOWN_BLOCK) {
			/* If we don't know it, that's OK.  Try to find out. */
			todo_add_get_block(peer->state, &pos2->block);
			/* FIXME: Keep complaint in this case? */
			return PROTOCOL_ECODE_NONE;
		}
		return e;
	}

	if (len != 0)
		return PROTOCOL_ECODE_INVALID_LEN;

	if (le32_to_cpu(pkt->input2) >= num_inputs(tx2))
		return PROTOCOL_ECODE_BAD_INPUTNUM;
	inp2 = tx_input(tx2, le32_to_cpu(pkt->input2));

	if (!structeq(&inp1->input, &inp2->input)
	    || inp1->output != inp2->output)
		return PROTOCOL_ECODE_BAD_INPUT;

	/* Since b1 comes first, b2 is wrong. */
	if (!block_preceeds(b1, b2))
		return PROTOCOL_ECODE_BAD_DOUBLESPEND_BLOCKS;

	/* Mark it invalid, and tell everyone else if it wasn't already. */
	publish_complaint(peer->state, b2, tal_packet_dup(b2, pkt), peer);
	return PROTOCOL_ECODE_NONE;
}

enum protocol_ecode
recv_complain_bad_input_ref(struct peer *peer,
		    const struct protocol_pkt_complain_bad_input_ref *pkt)
{
	const union protocol_tx *tx, *intx;
	const struct protocol_position *pos, *inpos;
	enum protocol_ecode e;
	struct block *b, *inb;
	const char *p;
	size_t len = le32_to_cpu(pkt->len);
	const struct protocol_input_ref *ref;
	struct protocol_tx_id sha;

	if (len < sizeof(*pkt))
		return PROTOCOL_ECODE_INVALID_LEN;

	p = (const char *)(pkt + 1);
	len -= sizeof(*pkt);

	e = unmarshal_proven_tx(peer->state, &p, &len, &b, &tx, &pos);
	if (e) {
		if (e == PROTOCOL_ECODE_UNKNOWN_BLOCK) {
			/* If we don't know it, that's OK.  Try to find out. */
			todo_add_get_block(peer->state, &pos->block);
			/* FIXME: Keep complaint in this case? */
			return PROTOCOL_ECODE_NONE;
		}
		return e;
	}

	if (le32_to_cpu(pkt->inputnum) >= num_inputs(tx))
		return PROTOCOL_ECODE_BAD_INPUTNUM;

	/* Refs follow tx in packet. */
	ref = ((const struct protocol_input_ref *)
	       ((const char *)tx + tx_len(tx)))
		+ le32_to_cpu(pkt->inputnum);

	e = unmarshal_proven_tx(peer->state, &p, &len, &inb, &intx, &inpos);
	if (e) {
		if (e == PROTOCOL_ECODE_UNKNOWN_BLOCK) {
			/* If we don't know it, that's OK.  Try to find out. */
			todo_add_get_block(peer->state, &inpos->block);
			/* FIXME: Keep complaint in this case? */
			return PROTOCOL_ECODE_NONE;
		}
		return e;
	}

	if (len != 0)
		return PROTOCOL_ECODE_INVALID_LEN;

	/* Now, check that they proved the referenced position */
	if (block_ancestor(b, le32_to_cpu(ref->blocks_ago)) != inb)
		return PROTOCOL_ECODE_BAD_INPUT;
	if (inpos->shard != ref->shard)
		return PROTOCOL_ECODE_BAD_INPUT;
	if (inpos->txoff != ref->txoff)
		return PROTOCOL_ECODE_BAD_INPUT;

	/* We expect it to be the wrong tx. */
	hash_tx(intx, &sha);
	if (structeq(&tx_input(tx, le32_to_cpu(pkt->inputnum))->input, &sha))
		return PROTOCOL_ECODE_COMPLAINT_INVALID;

	/* Mark it invalid, and tell everyone else if it wasn't already. */
	publish_complaint(peer->state, b, tal_packet_dup(b, pkt), peer);
	return PROTOCOL_ECODE_NONE;
}

enum protocol_ecode
recv_complain_claim_input_invalid(struct peer *peer,
		    const struct protocol_pkt_complain_claim_input_invalid *pkt)
{
	const union protocol_tx *claim_tx, *reward_tx;
	const struct protocol_position *claim_pos, *reward_pos;
	enum protocol_ecode e;
	struct block *claim_b, *reward_b;
	const char *p;
	struct protocol_tx_id sha;
	struct protocol_address claim_addr;
	size_t len = le32_to_cpu(pkt->len);
	u32 amount;

	if (len < sizeof(*pkt))
		return PROTOCOL_ECODE_INVALID_LEN;

	p = (const char *)(pkt + 1);
	len -= sizeof(*pkt);

	e = unmarshal_proven_tx(peer->state, &p, &len,
				&claim_b, &claim_tx, &claim_pos);
	if (e) {
		if (e == PROTOCOL_ECODE_UNKNOWN_BLOCK) {
			/* If we don't know it, that's OK.  Try to find out. */
			todo_add_get_block(peer->state, &claim_pos->block);
			/* FIXME: Keep complaint in this case? */
			return PROTOCOL_ECODE_NONE;
		}
		return e;
	}

	e = unmarshal_proven_tx(peer->state, &p, &len,
				&reward_b, &reward_tx, &reward_pos);
	if (e) {
		if (e == PROTOCOL_ECODE_UNKNOWN_BLOCK) {
			/* If we don't know it, that's OK.  Try to find out. */
			todo_add_get_block(peer->state, &reward_pos->block);
			/* FIXME: Keep complaint in this case? */
			return PROTOCOL_ECODE_NONE;
		}
		return e;
	}

	if (len != 0)
		return PROTOCOL_ECODE_INVALID_LEN;

	if (tx_type(claim_tx) != TX_CLAIM)
		return PROTOCOL_ECODE_COMPLAINT_INVALID;

	/* Reward tx must match input of claim. */
	hash_tx(reward_tx, &sha);
	if (!structeq(&claim_tx->claim.input.input, &sha))
		return PROTOCOL_ECODE_COMPLAINT_INVALID;

	get_tx_input_address(claim_tx, &claim_addr);
	if (check_claim_input(peer->state, claim_b, tx_input(claim_tx, 0),
			      reward_b, le16_to_cpu(reward_pos->shard),
			      reward_pos->txoff, reward_tx, &claim_addr,
			      &amount)) {
		/* OK, claim is valid, check amount */
		if (correct_amount(peer->state, claim_tx, amount))
			return PROTOCOL_ECODE_COMPLAINT_INVALID;
	}

	/* Mark it invalid, and tell everyone else if it wasn't already. */
	publish_complaint(peer->state, claim_b, tal_packet_dup(claim_b, pkt),
			  peer);
	return PROTOCOL_ECODE_NONE;
}
