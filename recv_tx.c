#include "block.h"
#include "check_block.h"
#include "check_tx.h"
#include "complain.h"
#include "input_refs.h"
#include "marshal.h"
#include "peer.h"
#include "proof.h"
#include "protocol_ecode.h"
#include "protocol_net.h"
#include "recv_tx.h"
#include "todo.h"
#include "tx.h"

static enum protocol_ecode
recv_tx(struct state *state,
	struct peer *peer,
	const struct protocol_pkt_tx_in_block *pkt)
{
	enum protocol_ecode e;
	union protocol_tx *tx;
	struct protocol_input_ref *refs;
	struct protocol_tx_with_proof *proof;
	struct block *b;
	struct protocol_tx_id sha;
	u16 shard;
	u8 conflict_txoff;
	size_t len = le32_to_cpu(pkt->len), used;

	if (len < sizeof(*pkt))
		return PROTOCOL_ECODE_INVALID_LEN;

	len -= sizeof(*pkt);

	e = le32_to_cpu(pkt->err);
	if (e) {
		struct protocol_position *pos = (void *)(pkt + 1);

		if (len != sizeof(*pos))
			return PROTOCOL_ECODE_INVALID_LEN;

		if (e == PROTOCOL_ECODE_UNKNOWN_BLOCK) {
			/* They don't know block at all, so don't ask. */
			if (peer)
				todo_done_get_block(peer, &pos->block, false);
		} else if (e != PROTOCOL_ECODE_UNKNOWN_TX)
			return PROTOCOL_ECODE_UNKNOWN_ERRCODE;

		if (peer)
			todo_done_get_tx_in_block(peer, &pos->block,
						  le16_to_cpu(pos->shard),
						  pos->txoff, false);
		return PROTOCOL_ECODE_NONE;
	}

	if (len < sizeof(*proof))
		return PROTOCOL_ECODE_INVALID_LEN;
	len -= sizeof(*proof);

	proof = (void *)(pkt + 1);

	b = block_find_any(state, &proof->proof.pos.block);
	if (!b) {
		if (peer)
			todo_add_get_block(state, &proof->proof.pos.block);
		/* FIXME: should we extract transaction? */
		return PROTOCOL_ECODE_NONE;
	}

	/* FIXME: We could check the proof before we check the tx & refs,
	 * then if a buggy implementation tried to send us invalid tx
	 * and refs we could turn it into a complaint. */

	tx = (void *)(proof + 1);
	e = unmarshal_tx(tx, len, &used);
	if (e)
		return e;
	len -= used;

	/* You can't send us bad txs this way: use a complaint packet. */
	e = check_tx(state, tx, b);
	if (e)
		return e;

	refs = (void *)((char *)tx + used);
	e = unmarshal_input_refs(refs, len, tx, &used);
	if (e)
		return e;

	if (used != len)
		return PROTOCOL_ECODE_INVALID_LEN;

	e = check_refs(state, b, refs, num_inputs(tx));
	if (e)
		return e;

	if (!check_proof(&proof->proof, b, tx, refs))
		return PROTOCOL_ECODE_BAD_PROOF;

	/* Now we know shard (and txoff) is valid. */
	shard = le16_to_cpu(proof->proof.pos.shard);

	/* Whatever happens from here, no point asking others for tx. */
	if (peer)
		todo_done_get_tx_in_block(peer, &proof->proof.pos.block,
					  shard, proof->proof.pos.txoff, true);

	/* This may have been a response to GET_TX as well. */
	hash_tx(tx, &sha);
	if (peer)
		todo_done_get_tx(peer, &sha, true);

	/* If we already have it, we're done. */
	if (block_get_tx(b, shard, proof->proof.pos.txoff))
		return PROTOCOL_ECODE_NONE;

	/* Now it's proven that it's in the block, handle bad inputs/refs.
	 * We don't hang up on them, since they may not have known. */
	if (!check_tx_inputs_and_refs(state, b, &proof->proof, tx, refs, NULL))
		return PROTOCOL_ECODE_NONE;

	/* Simularly, they might not know if it was misordered. */
	if (!check_tx_ordering(state, b, b->shard[shard],
			       proof->proof.pos.txoff, tx, &conflict_txoff)) {
		/* Tell everyone that txs are out of order in block */
		complain_misorder(state, b, &proof->proof,
				  tx, refs, conflict_txoff);
		return PROTOCOL_ECODE_NONE;
	}

	/* Keep proof in case anyone asks. */
	put_proof_in_shard(state, b, &proof->proof);
	/* Copy in tx and refs. */
	put_tx_in_shard(state, peer,
			b, b->shard[shard], proof->proof.pos.txoff,
			txptr_with_ref(b->shard[shard], tx, refs));

	if (peer) {
		/* This is OK for now, will be spammy in real network! */
		log_info(peer->log, "gave us TX in shard %u, off %u, block %u ",
			 shard, proof->proof.pos.txoff,
			 block_height(&b->bi));
		log_add_struct(peer->log, struct protocol_tx_id, &sha);
	}

	return PROTOCOL_ECODE_NONE;
}

enum protocol_ecode recv_tx_from_peer(struct peer *peer,
				const struct protocol_pkt_tx_in_block *pkt)
{
	return recv_tx(peer->state, peer, pkt);
}

enum protocol_ecode recv_tx_from_blockfile(struct state *state,
				const struct protocol_pkt_tx_in_block *pkt)
{
	return recv_tx(state, NULL, pkt);
}
