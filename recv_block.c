#include "block.h"
#include "blockfile.h"
#include "chain.h"
#include "check_block.h"
#include "complain.h"
#include "create_refs.h"
#include "difficulty.h"
#include "log.h"
#include "pending.h"
#include "proof.h"
#include "recv_block.h"
#include "shard.h"
#include "state.h"
#include "tal_packet.h"
#include "todo.h"
#include "tx_in_hashes.h"
#include <ccan/structeq/structeq.h>

/* Don't let them flood us with cheap, random blocks. */
static void seek_predecessor(struct state *state, 
			     const struct protocol_double_sha *sha,
			     const struct protocol_double_sha *prev)
{
	u32 diff;

	/* Make sure they did at least 1/16 current work. */
	diff = le32_to_cpu(state->preferred_chain->tailer->difficulty);
	diff = difficulty_one_sixteenth(diff);

	if (!beats_target(sha, diff)) {
		log_debug(state->log, "Ignoring unknown prev in easy block");
		return;
	}

	log_debug(state->log, "Seeking block prev ");
	log_add_struct(state->log, struct protocol_double_sha, prev);
	todo_add_get_block(state, prev);
}

/* When syncing, we ask for txmaps. */
static void sync_block_contents(struct state *state, const struct block *b)
{
	unsigned int shard;

	for (shard = 0; shard < num_shards(b->hdr); shard++) {
		if (shard_all_known(b->shard[shard]))
			continue;

		if (interested_in_shard(state, b->hdr->shard_order, shard))
			todo_add_get_shard(state, &b->sha, shard);
		else
			todo_add_get_txmap(state, &b->sha, shard);
	}
}

static void ask_block_contents(struct state *state, const struct block *b)
{
	unsigned int shard;

	for (shard = 0; shard < num_shards(b->hdr); shard++) {
		if (!interested_in_shard(state, b->hdr->shard_order, shard))
			continue;
		if (!shard_all_hashes(b->shard[shard]))
			todo_add_get_shard(state, &b->sha, shard);
	}
}

/* peer is NULL if from generator. */
static enum protocol_ecode
recv_block(struct state *state, struct log *log, struct peer *peer,
	   const struct protocol_pkt_block *pkt)
{
	struct block *b, *prev;
	enum protocol_ecode e;
	const struct protocol_double_sha *merkles;
	const u8 *shard_nums;
	const u8 *prev_txhashes;
	const struct protocol_block_tailer *tailer;
	const struct protocol_block_header *hdr;
	struct protocol_double_sha sha;

	e = unmarshal_block(log, pkt,
			    &hdr, &shard_nums, &merkles, &prev_txhashes,
			    &tailer);
	if (e != PROTOCOL_ECODE_NONE) {
		log_unusual(log, "unmarshaling new block gave %u", e);
		return e;
	}

	log_debug(log, "version = %u, features = %u, shard_order = %u",
		  hdr->version, hdr->features_vote, hdr->shard_order);

	e = check_block_header(state, hdr, shard_nums, merkles,
			       prev_txhashes, tailer, &prev, &sha);

	if (e != PROTOCOL_ECODE_NONE) {
		log_unusual(log, "checking new block gave ");
		log_add_enum(log, enum protocol_ecode, e);

		/* If it was due to unknown prev, ask about that. */
		if (peer) {
			if (e == PROTOCOL_ECODE_PRIV_UNKNOWN_PREV) {
				/* FIXME: Keep it around! */
				seek_predecessor(state, &sha, &hdr->prev_block);
				/* In case we were asking for this,
				 * we're not any more. */
				todo_done_get_block(peer, &sha, true);
			} else
				todo_done_get_block(peer, &sha, false);
			return PROTOCOL_ECODE_NONE;
		}
		return e;
	}

	/* In case we were asking for this, we're not any more. */
	todo_done_get_block(peer, &sha, true);

	/* Actually check the previous merkles are correct. */
	if (!check_block_prev_txhashes(state->log, prev, hdr, prev_txhashes)) {
		log_unusual(log, "new block has bad prev merkles");
		/* FIXME: provide proof. */
		return PROTOCOL_ECODE_BAD_PREV_TXHASHES;
	}

	log_debug(log, "New block %u is good!", le32_to_cpu(hdr->depth));

	if ((b = block_find_any(state, &sha)) != NULL) {
		log_debug(log, "already knew about block %u",
			  le32_to_cpu(hdr->depth));
	} else {
		b = block_add(state, prev, &sha, hdr, shard_nums, merkles,
			      prev_txhashes, tailer);

		/* Now new block owns the packet. */
		tal_steal(b, pkt);

		save_block(state, b);
		/* If we're syncing, ask about children, contents */
		if (peer && peer->we_are_syncing) {
			todo_add_get_children(state, &b->sha);
			sync_block_contents(state, b);
		} else {
			/* Otherwise, tell peers about new block. */
			send_block_to_peers(state, peer, b);
			/* Start asking about stuff we need. */
			ask_block_contents(state, b);
		}
	}

	/* If the block is known bad, tell them! */
	if (peer && b->complaint)
		todo_for_peer(peer, tal_packet_dup(peer, b->complaint));

	/* FIXME: Try to guess the shards */
	return PROTOCOL_ECODE_NONE;
}

static struct txptr_with_ref
find_tx_with_ref(const tal_t *ctx,
		 struct state *state,
		 const struct block *block,
		 const struct protocol_txrefhash *hash)
{
	struct protocol_input_ref *refs;
	struct txptr_with_ref r;
	struct txhash_iter iter;
	struct txhash_elem *te;

	for (te = txhash_firstval(&state->txhash, &hash->txhash, &iter);
	     te;
	     te = txhash_nextval(&state->txhash, &hash->txhash, &iter)) {
		struct protocol_double_sha sha;
		const union protocol_tx *tx = txhash_tx(te);

		/* Hash only?  Can't make references. */
		if (!tx)
			continue;

		/* Try creating input referneces back from this block */
		refs = create_refs(state, block, tx);
		if (!refs)
			continue;

		/* Do they hash correctly? */
		hash_refs(refs, tal_count(refs), &sha);
		if (!structeq(&hash->refhash, &sha)) {
			tal_free(refs);
			continue;
		}

		r = txptr_with_ref(ctx, tx, refs);
		tal_free(refs);

		/* Now, we don't drop from pending yet: that will happen
		 * when longest_knowns[0] moves. */
		return r;
	}

	r.tx = NULL;
	return r;
}

/* Returns true if it was resolved. */
bool try_resolve_hash(struct state *state,
		      const struct peer *source,
		      struct block *block, u16 shardnum, u8 txoff)
{
	struct txptr_with_ref txp;
	u8 conflict_txoff;
	struct block_shard *shard = block->shard[shardnum];

	assert(!shard_is_tx(shard, txoff));

	txp = find_tx_with_ref(shard, state, block, shard->u[txoff].hash);
	if (!txp.tx)
		return false;

	if (!check_tx_ordering(state, block, shard, txoff, txp.tx,
			       &conflict_txoff)) {
		struct protocol_proof proof;

		/* We can generate proof, since we at least have hashes. */
		create_proof(&proof, block, shardnum, txoff);

		complain_misorder(state, block, &proof, txp.tx, refs_for(txp),
				  conflict_txoff);
		return true;
	}

	put_tx_in_shard(state, block, shard, txoff, txp);
	/* If we need proof, we should already have it, so don't add. */

	send_tx_in_block_to_peers(state, source, block, shardnum, txoff);
	return true;
}

static void try_resolve_hashes(struct state *state,
			       const struct peer *source,
			       struct block *block,
			       u16 shard,
			       bool add_todos)
{
	unsigned int i;

	/* If we know any of these transactions, resolve them now! */
	for (i = 0; i < block->shard_nums[shard] && !block->complaint; i++) {
		if (shard_is_tx(block->shard[shard], i))
			continue;

		if (try_resolve_hash(state, source, block, shard, i))
			continue;

		if (add_todos)
			todo_add_get_tx_in_block(state, &block->sha, shard, i);
	}
}

static enum protocol_ecode
recv_shard(struct state *state, struct log *log, struct peer *peer,
	   const struct protocol_pkt_shard *pkt)
{
	struct block *b;
	u16 shard;
	unsigned int i;
	const struct protocol_txrefhash *hash;
	struct block_shard *s;

	if (le32_to_cpu(pkt->len) < sizeof(*pkt))
		return PROTOCOL_ECODE_INVALID_LEN;

	shard = le16_to_cpu(pkt->shard);

	/* FIXME: do block lookup and complaint in common code? */
	b = block_find_any(state, &pkt->block);
	if (!b) {
		/* If we don't know it, that's OK.  Try to find out. */
		todo_add_get_block(state, &pkt->block);
		return PROTOCOL_ECODE_NONE;
	}

	if (b->complaint) {
		log_debug(log, "shard on invalid block ");
		log_add_struct(log, struct protocol_double_sha, &pkt->block);
		/* Complain, but don't otherwise process. */
		if (peer)
			todo_for_peer(peer, tal_packet_dup(peer, b->complaint));
		return PROTOCOL_ECODE_NONE;
	}

	if (shard >= num_shards(b->hdr)) {
		log_unusual(log, "Invalid shard for shard %u of ", shard);
		log_add_struct(log, struct protocol_double_sha, &pkt->block);
		return PROTOCOL_ECODE_BAD_SHARDNUM;
	}

	if (le16_to_cpu(pkt->err) != PROTOCOL_ECODE_NONE) {
		/* Error can't have anything appended. */
		if (le32_to_cpu(pkt->len) != sizeof(*pkt))
			return PROTOCOL_ECODE_INVALID_LEN;

		log_debug(log, "Packet contains ecode ");
		log_add_enum(log, enum protocol_ecode, le16_to_cpu(pkt->err));
		log_add(log, " for shard %u of ", shard);
		log_add_struct(log, struct protocol_double_sha, &pkt->block);

		/* We failed to get shard. */
		if (peer)
			todo_done_get_shard(peer, &pkt->block, shard, false);
		if (le16_to_cpu(pkt->err) == PROTOCOL_ECODE_UNKNOWN_BLOCK) {
			/* Implies it doesn't know block, so don't ask. */
			if (peer)
				todo_done_get_block(peer, &pkt->block, false);
		} else if (le16_to_cpu(pkt->err) != PROTOCOL_ECODE_UNKNOWN_SHARD)
			return PROTOCOL_ECODE_UNKNOWN_ERRCODE;
		return PROTOCOL_ECODE_NONE;
	}

	/* Should have appended all txrefhashes. */
	if (le32_to_cpu(pkt->len)
	    != sizeof(*pkt) + b->shard_nums[shard] * sizeof(*hash))
		return PROTOCOL_ECODE_INVALID_LEN;

	log_debug(log, "Got shard %u of ", shard);
	log_add_struct(log, struct protocol_double_sha, &pkt->block);
			
	hash = (struct protocol_txrefhash *)(pkt + 1);
	s = b->shard[shard];

	/* Make shard own this packet. */
	tal_steal(s, pkt);

	/* Add hash pointers. */
	for (i = 0; i < b->shard_nums[shard]; i++) {
		s->hashcount++;
		bitmap_set_bit(s->txp_or_hash, i);
		s->u[i].hash = hash + i;
	}

	if (!shard_belongs_in_block(b, s)) {
		log_unusual(log, "Bad hash for shard %u of ", shard);
		log_add_struct(log, struct protocol_double_sha, &pkt->block);
		tal_free(s);
		return PROTOCOL_ECODE_BAD_MERKLE;
	}

	/* This may resolve some of the txs if we know them already. */
	put_shard_of_hashes_into_block(state, b, s);

	log_debug(log, "Shard now in block. txs %u, hashes %u (of %u)",
		  s->txcount, s->hashcount, s->size);

	/* This will try to match the rest, or trigger asking. */
	try_resolve_hashes(state, peer, b, shard, peer != NULL);

	log_debug(log, "Shard now resolved. txs %u, hashes %u (of %u)",
		  s->txcount, s->hashcount, s->size);

	/* We save once we know the entire contents. */
	if (shard_all_known(s)) {
		if (s->size)
			log_debug(log, "Shard all known!");
		save_shard(state, b, shard);
		update_block_ptrs_new_shard(state, b, shard);
	}

	/* FIXME: re-check pending transactions with unknown inputs
	 * now we know more, or pendings which might be invalidated. */

	return PROTOCOL_ECODE_NONE;
}

enum protocol_ecode recv_block_from_peer(struct peer *peer,
					 const struct protocol_pkt_block *pkt)
{
	assert(le32_to_cpu(pkt->err) == PROTOCOL_ECODE_NONE);
	return recv_block(peer->state, peer->log, peer, pkt);
}

enum protocol_ecode recv_shard_from_peer(struct peer *peer,
					 const struct protocol_pkt_shard *pkt)
{
	return recv_shard(peer->state, peer->log, peer, pkt);
}

bool recv_block_from_generator(struct state *state, struct log *log,
			       const struct protocol_pkt_block *pkt,
			       struct protocol_pkt_shard **shards)
{
	unsigned int i;
	enum protocol_ecode e;

	if (le32_to_cpu(pkt->err) != PROTOCOL_ECODE_NONE) {
		log_unusual(log, "Generator gave block with err: ");
		log_add_enum(log, enum protocol_ecode, le32_to_cpu(pkt->err));
		return false;
	}

	/* This "can't happen" when we know everything.  But in future,
	 * it's theoretically possible.  Plus, code sharing is nice. */
	e = recv_block(state, log, NULL, pkt);
	if (e != PROTOCOL_ECODE_NONE) {
		log_unusual(log, "Generator gave broken block: ");
		log_add_enum(log, enum protocol_ecode, e);
		return false;
	}

	for (i = 0; i < tal_count(shards); i++) {
		e = recv_shard(state, log, NULL, shards[i]);
		if (e != PROTOCOL_ECODE_NONE) {
			log_unusual(log, "Generator gave broken shard %i: ", i);
			log_add_enum(log, enum protocol_ecode, e);
			return false;
		}
	}

	return true;
}
