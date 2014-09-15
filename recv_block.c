#include "block.h"
#include "blockfile.h"
#include "chain.h"
#include "check_block.h"
#include "complain.h"
#include "create_refs.h"
#include "detached_block.h"
#include "difficulty.h"
#include "ecode_names.h"
#include "hex.h"
#include "jsonrpc.h"
#include "log.h"
#include "merkle_hashes.h"
#include "pending.h"
#include "prev_blocks.h"
#include "proof.h"
#include "recv_block.h"
#include "shard.h"
#include "state.h"
#include "tal_packet.h"
#include "todo.h"
#include "tx_in_hashes.h"
#include <ccan/structeq/structeq.h>

/* For a given height, what is the reasonable minimal difficulty? */
static u32 min_difficulty(struct state *state, u32 height)
{
	struct block *b;
	u32 min, lower_bound;

	/* Do we have other blocks of this height? */
	/* FIXME: Doesn't work if we ever SPV skip! */
	if (tal_count(state->block_height) >= height) {
		b = list_top(state->block_height[height], struct block, list);

		/* Different branches could have slightly different
		 * difficulties, but should be well within factor of 4. */
		min = difficulty_div4(block_difficulty(&b->bi));
	} else {
		unsigned int h = tal_count(state->block_height) - 1, updatenum;

		b = list_top(state->block_height[h], struct block, list);
		min = difficulty_div4(block_difficulty(&b->bi));

		/* Now, every PROTOCOL_DIFFICULTY_UPDATE_BLOCKS it
		 * could decrease by 4. */
		for (updatenum = h / PROTOCOL_DIFFICULTY_UPDATE_BLOCKS;
		     updatenum < height / PROTOCOL_DIFFICULTY_UPDATE_BLOCKS;
		     updatenum++) {
			min = difficulty_div4(min);
		}
	}

	/* Can never get easier than the genesis block. */
	lower_bound = block_difficulty(&genesis_block(state)->bi);
	if (difficulty_cmp(min, lower_bound) < 0)
		return lower_bound;
	return min;
}

/* Don't let them flood us with cheap, random blocks. */
static void seek_predecessor(struct state *state, 
			     const tal_t *pkt_ctx,
			     const struct protocol_block_id *sha,
			     const struct block_info *bi)
{
	u32 min_diff;
	size_t i;

	min_diff = min_difficulty(state, block_height(bi));
	if (difficulty_cmp(block_difficulty(bi), min_diff) < 0) {
		log_debug(state->log, "Ignoring unknown prev in easy block");
		return;
	}

	if (have_detached_block(state, sha)) {
		log_debug(state->log, "Already have detached block ");
		log_add_struct(state->log, struct protocol_block_id,
			       block_prev(bi, 0));
		return;
	}

	add_detached_block(state, pkt_ctx, sha, bi);

	/* Ask for all the prevs we don't have */
	for (i = 0; i < block_num_prevs(bi); i++) {
		if (block_find_any(state, block_prev(bi, i)))
			continue;
		if (have_detached_block(state, block_prev(bi, i)))
			continue;

		log_debug(state->log, "Seeking block prev %zi ", i);
		log_add_struct(state->log, struct protocol_block_id,
			       block_prev(bi, i));
		todo_add_get_block(state, block_prev(bi, i));
	}
}

/* When syncing, we ask for txmaps. */
void get_block_contents(struct state *state, const struct block *b)
{
	unsigned int shard;

	for (shard = 0; shard < block_num_shards(&b->bi); shard++) {
		if (shard_all_known(b->shard[shard]))
			continue;

		if (interested_in_shard(state, b->bi.hdr->shard_order, shard))
			todo_add_get_shard(state, &b->sha, shard);
		else
			todo_add_get_txmap(state, &b->sha, shard);
	}
}

static void ask_block_contents(struct state *state, const struct block *b)
{
	unsigned int shard;

	for (shard = 0; shard < block_num_shards(&b->bi); shard++) {
		if (!interested_in_shard(state, b->bi.hdr->shard_order, shard))
			continue;
		if (!shard_all_hashes(b->shard[shard]))
			todo_add_get_shard(state, &b->sha, shard);
	}
}

/* peer is NULL if from generator, re-trying detached block or jsonrpc. */
static enum protocol_ecode
recv_block(struct state *state, struct log *log, struct peer *peer,
	   const tal_t *pkt_ctx, const struct block_info *bi,
	   struct block **block)
{
	struct block *b, *prev;
	enum protocol_ecode e;
	struct protocol_block_id sha;

	e = check_block_header(state, bi, &prev, &sha.sha);
	if (e != PROTOCOL_ECODE_NONE) {
		log_unusual(log, "checking new block %u gave ",
			    block_height(bi));
		log_add_enum(log, enum protocol_ecode, e);

		/* If it was due to unknown prev, ask about that. */
		if (peer) {
			if (e == PROTOCOL_ECODE_PRIV_UNKNOWN_PREV) {
				seek_predecessor(state, pkt_ctx,
						 &sha, bi);
				/* In case we were asking for this,
				 * we're not any more. */
				todo_done_get_block(peer, &sha, true);
			} else
				todo_done_get_block(peer, &sha, false);
		}
		return e;
	}

	/* In case we were asking for this, we're not any more. */
	if (peer)
		todo_done_get_block(peer, &sha, true);

	/* Actually check the previous txhashes are correct. */
	if (!check_num_prev_txhashes(state, prev,
				     bi->hdr, bi->prev_txhashes)) {
		log_unusual(log, "new block has wrong number of prev txhashes");
		return PROTOCOL_ECODE_BAD_PREV_TXHASHES;
	}

	log_debug(log, "New block %u is good!", block_height(bi));
	if ((b = block_find_any(state, &sha)) != NULL) {
		log_debug(log, "already knew about block %u",
			  block_height(bi));
	} else {
		const struct block *bad_prev;
		u16 bad_shard;

		b = block_add(state, prev, &sha, bi);

		/* Now new block owns the packet. */
		tal_steal(b, pkt_ctx);

		/* Now check it matches known previous transactions. */
		if (!check_prev_txhashes(state, b, &bad_prev, &bad_shard)) {
			complain_bad_prev_txhashes(state, b, bad_prev,
						   bad_shard);
		} else {
			/* If we're syncing, ask about children, contents */
			if (peer && peer->we_are_syncing) {
				/* FIXME: Don't do these if below horizon */
				todo_add_get_children(state, &b->sha);
				get_block_contents(state, b);
			} else {
				/* Otherwise, tell peers about new block. */
				send_block_to_peers(state, peer, b);
				if (peer)
					/* Start asking about stuff we need. */
					ask_block_contents(state, b);
			}
		}
	}

	/* If the block is known bad, tell them! */
	if (peer && b->complaint)
		todo_for_peer(peer, tal_packet_dup(peer, b->complaint));

	if (block)
		*block = b;

	/* FIXME: Try to guess the shards */
	return PROTOCOL_ECODE_NONE;
}

/* peer is NULL if from generator, re-trying detached block or jsonrpc. */
static enum protocol_ecode
recv_block_pkt(struct state *state, struct log *log, struct peer *peer,
	       const struct protocol_pkt_block *pkt, struct block **block)
{
	enum protocol_ecode e;
	struct block_info bi;

	if (le32_to_cpu(pkt->len) < sizeof(*pkt)) {
		log_unusual(log, "total size %u < packet size %zu",
			    le32_to_cpu(pkt->len), sizeof(*pkt));
		return PROTOCOL_ECODE_INVALID_LEN;
	}

	e = unmarshal_block(log, pkt, &bi);
	if (e != PROTOCOL_ECODE_NONE) {
		log_unusual(log, "unmarshaling new block gave %u", e);
		return e;
	}

	return recv_block(state, log, peer, pkt, &bi, block);
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
		refs = create_refs(state, block, tx, 0);
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

	/* If we need proof, we should already have it, so don't add. */
	put_tx_in_shard(state, source, block, shard, txoff, txp);

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
	for (i = 0;
	     i < block_num_txs(&block->bi, shard) && !block->complaint;
	     i++) {
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
	struct protocol_double_sha merkle;
	const struct protocol_txrefhash *hashes;

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
		log_add_struct(log, struct protocol_block_id, &pkt->block);
		/* Complain, but don't otherwise process. */
		if (peer)
			todo_for_peer(peer, tal_packet_dup(peer, b->complaint));
		return PROTOCOL_ECODE_NONE;
	}

	if (shard >= block_num_shards(&b->bi)) {
		log_unusual(log, "Invalid shard for shard %u of ", shard);
		log_add_struct(log, struct protocol_block_id, &pkt->block);
		return PROTOCOL_ECODE_BAD_SHARDNUM;
	}

	if (le16_to_cpu(pkt->err) != PROTOCOL_ECODE_NONE) {
		/* Error can't have anything appended. */
		if (le32_to_cpu(pkt->len) != sizeof(*pkt))
			return PROTOCOL_ECODE_INVALID_LEN;

		log_debug(log, "Packet contains ecode ");
		log_add_enum(log, enum protocol_ecode, le16_to_cpu(pkt->err));
		log_add(log, " for shard %u of ", shard);
		log_add_struct(log, struct protocol_block_id, &pkt->block);

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

	/* The rest are the hash entries. */
	hashes = (struct protocol_txrefhash *)(pkt + 1);

	/* Should have appended all txrefhashes. */
	if (le32_to_cpu(pkt->len)
	    != sizeof(*pkt) + block_num_txs(&b->bi, shard) * sizeof(hashes[0]))
		return PROTOCOL_ECODE_INVALID_LEN;

	/* Don't send us empty packets! */
	if (block_num_txs(&b->bi, shard) == 0)
		return PROTOCOL_ECODE_INVALID_LEN;

	log_debug(log, "Got shard %u of ", shard);
	log_add_struct(log, struct protocol_block_id, &pkt->block);

	/* Check it's right. */
	merkle_hashes(hashes, 0, block_num_txs(&b->bi, shard), &merkle);
	if (!structeq(block_merkle(&b->bi, shard), &merkle)) {
		log_unusual(log, "Bad hash for shard %u of ", shard);
		log_add_struct(log, struct protocol_block_id, &pkt->block);
		return PROTOCOL_ECODE_BAD_MERKLE;
	}

	log_debug(log, "Before adding hashes: txs %u, hashes %u (of %u)",
		  b->shard[shard]->txcount,
		  b->shard[shard]->hashcount,
		  b->shard[shard]->size);

	/* Mark it off the TODO list. */
	if (peer)
		todo_done_get_shard(peer, &pkt->block, shard, true);

	/* This may resolve some of the txs if we know them already. */
	for (i = 0; i < block_num_txs(&b->bi, shard); i++)
		put_txhash_in_shard(state, b, shard, i, &hashes[i]);

	log_debug(log, "Hashes now in shar. txs %u, hashes %u (of %u)",
		  b->shard[shard]->txcount,
		  b->shard[shard]->hashcount,
		  b->shard[shard]->size);

	/* This will try to match the rest, or trigger asking. */
	try_resolve_hashes(state, peer, b, shard, peer != NULL);

	log_debug(log, "Shard now resolved. txs %u, hashes %u (of %u)",
		  b->shard[shard]->txcount,
		  b->shard[shard]->hashcount,
		  b->shard[shard]->size);

	return PROTOCOL_ECODE_NONE;
}

enum protocol_ecode recv_block_from_peer(struct peer *peer,
					 const struct protocol_pkt_block *pkt)
{
	enum protocol_ecode e;
	struct block *b;

	assert(le32_to_cpu(pkt->err) == PROTOCOL_ECODE_NONE);
	e = recv_block_pkt(peer->state, peer->log, peer, pkt, &b);
	if (e == PROTOCOL_ECODE_NONE) {
		log_info(peer->log, "gave us block %u: ",
			 block_height(&b->bi));
		log_add_struct(peer->log, struct protocol_block_id, &b->sha);
	}
	/* If we didn't know prev, this block is still OK so don't hang up. */
	if (e == PROTOCOL_ECODE_PRIV_UNKNOWN_PREV)
		return PROTOCOL_ECODE_NONE;
	return e;
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
	unsigned int i, num_txs;
	enum protocol_ecode e;
	struct block *b;

	if (le32_to_cpu(pkt->err) != PROTOCOL_ECODE_NONE) {
		log_unusual(log, "Generator gave block with err: ");
		log_add_enum(log, enum protocol_ecode, le32_to_cpu(pkt->err));
		return false;
	}

	/* This "can't happen" when we know everything.  But in future,
	 * it's theoretically possible.  Plus, code sharing is nice. */
	e = recv_block_pkt(state, log, NULL, pkt, &b);
	if (e != PROTOCOL_ECODE_NONE) {
		log_unusual(log, "Generator gave broken block: ");
		log_add_enum(log, enum protocol_ecode, e);
		return false;
	}

	num_txs = 0;
	for (i = 0; i < tal_count(shards); i++) {
		num_txs += block_num_txs(&b->bi, i);
		if (block_num_txs(&b->bi, i) == 0)
			continue;
		e = recv_shard(state, log, NULL, shards[i]);
		if (e != PROTOCOL_ECODE_NONE) {
			log_unusual(log, "Generator gave broken shard %i: ", i);
			log_add_enum(log, enum protocol_ecode, e);
			return false;
		}
	}

	log_info(log, "found block %u (%zu shards, %u txs): ",
		 block_height(&b->bi), tal_count(shards), num_txs);
	log_add_struct(log, struct protocol_block_id, &b->sha);

	if (!block_all_known(b))
		log_unusual(log, "created block but we don't know contents!");

	/* We call it manually here, since we're not in peer loop. */
	recheck_pending_txs(state);
	return true;
}

/* Now we know prev for a block, receive it again. */
void recv_block_reinject(struct state *state,
			 const tal_t *pkt_ctx,
			 const struct block_info *bi)
{
	struct block *b;

	recv_block(state, state->log, NULL, pkt_ctx, bi, &b);
}

static char *json_submitblock(struct json_connection *jcon,
			      const jsmntok_t *params,
			      char **response)
{
	jsmntok_t *tok;
	void *data;
	struct block *block;
	size_t len;
	struct block_info bi;
	enum protocol_ecode e;

	json_get_params(jcon->buffer, params, "block", &tok, NULL);
	if (!tok)
		return "Need block param";

	len = (tok->end - tok->start) / 2;

	data = tal_arr(jcon, char, len);
	if (!from_hex(jcon->buffer + tok->start, tok->end - tok->start,
		      data, len))
		return "Invalid block hex";
	e = unmarshal_block_into(jcon->log, len, data, &bi);
	if (e != PROTOCOL_ECODE_NONE)
		return (char *)ecode_name(e);

	e = recv_block(jcon->state, jcon->log, NULL, data, &bi, &block);
	if (e != PROTOCOL_ECODE_NONE)
		return (char *)ecode_name(e);

	json_add_block_id(response, NULL, &block->sha);
	return NULL;
}

const struct json_command submitblock_command = {
	"submitblock",
	json_submitblock,
	"Inject a block",
	"Takes marshalled block in hex, returns block"
};

