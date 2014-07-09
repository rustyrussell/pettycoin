#include "peer.h"
#include "state.h"
#include "protocol_net.h"
#include "packet.h"
#include "packet_io.h"
#include "dns.h"
#include "netaddr.h"
#include "welcome.h"
#include "peer_cache.h"
#include "block.h"
#include "hash_block.h"
#include "log.h"
#include "marshal.h"
#include "check_block.h"
#include "check_tx.h"
#include "tx.h"
#include "generating.h"
#include "blockfile.h"
#include "pending.h"
#include "chain.h"
#include "todo.h"
#include "sync.h"
#include "shard.h"
#include "difficulty.h"
#include "recv_block.h"
#include "tal_packet_proof.h"
#include "proof.h"
#include "complain.h"
#include "input_refs.h"
#include "peer_wants.h"
#include "addr.h"
#include <ccan/io/io.h>
#include <ccan/time/time.h>
#include <ccan/tal/tal.h>
#include <ccan/tal/path/path.h>
#include <ccan/err/err.h>
#include <ccan/build_assert/build_assert.h>
#include <ccan/cast/cast.h>
#include <ccan/structeq/structeq.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MIN_PEERS 16

struct peer_lookup {
	struct state *state;
	void *pkt;
};

static struct io_plan digest_peer_addrs(struct io_conn *conn,
					struct peer_lookup *lookup)
{
	le32 *len = lookup->pkt;
	u32 num, i;
	struct protocol_net_address *addr;

	num = (le32_to_cpu(*len) - sizeof(struct protocol_net_hdr))
	       / sizeof(*addr);
	/* Addresses are after header (which includes unused type field). */
	addr = (void *)(len + 2);

	log_debug(lookup->state->log,
		  "seed server supplied %u peers in %u bytes",
		  num, le32_to_cpu(*len));
	for (i = 0; i < num; i++) {
		log_debug(lookup->state->log, "Adding address to peer cache: ");
		log_add_struct(lookup->state->log,
			       struct protocol_net_address, &addr[i]);
		peer_cache_add(lookup->state, &addr[i]);
	}

	/* We can now get more from cache. */
	fill_peers(lookup->state);

	return io_close();
}

static struct io_plan read_seed_peers(struct io_conn *conn,
				      struct state *state)
{
	struct peer_lookup *lookup = tal(conn, struct peer_lookup);

	log_debug(state->log, "Connected to seed server, reading peers");
	lookup->state = state;
	return io_read_packet(&lookup->pkt, digest_peer_addrs, lookup);
}

/* This gets called when the connection closes, fail or success. */
static void unset_peer_seeding(struct state **statep)
{
	log_debug((*statep)->log, "Seeding connection closed");
	(*statep)->peer_seeding = false;
	fill_peers(*statep);
}

static void seed_peers(struct state *state)
{
	const char *server = "peers.pettycoin.org";
	tal_t *connector;

	/* Don't grab more if we're already doing that. */
	if (state->peer_seeding) {
		log_debug(state->log, "Seeding ongoing already");
		return;
	}

	if (state->peer_seed_count++ > 2) {
		if (state->developer_test)
			return;

		fatal(state, "Failed to connect to any peers, or peer server");
	}

	if (state->developer_test)
		server = "localhost";

	connector = dns_resolve_and_connect(state, server, "9000",
					    read_seed_peers);
	if (!connector) {
		log_unusual(state->log, "Could not connect to %s", server);
	} else {
		/* Temporary allocation, to get destructor called. */
		struct state **statep = tal(connector, struct state *);
		state->peer_seeding = true;
		(*statep) = state;
		tal_add_destructor(statep, unset_peer_seeding);

		log_debug(state->log, "Connecting to seed server %s", server);
	}
}

void fill_peers(struct state *state)
{
	if (!state->refill_peers)
		return;

	while (state->num_peers < MIN_PEERS) {
		struct protocol_net_address *a;
		int fd;

		a = read_peer_cache(state);
		if (!a) {
			log_debug(state->log, "Seeding peer cache");
			seed_peers(state);
			break;
		}
		fd = socket_for_addr(a);

		/* Maybe we don't speak IPv4/IPv6? */
		if (fd == -1) {
			log_unusual(state->log, "Creating socket failed for ");
			log_add_struct(state->log,
				       struct protocol_net_address, a);
			log_add(state->log, ": %s", strerror(errno));
			peer_cache_del(state, a, true);
		} else {
			new_peer(state, fd, a);
		}
	}
}

void send_tx_to_peers(struct state *state, struct peer *exclude,
		      const union protocol_tx *tx)
{
	struct peer *peer;

	list_for_each(&state->peers, peer, list) {
		struct protocol_pkt_tx *pkt;

		/* Avoid sending back to peer who told us. */
		if (peer == exclude)
			continue;

		/* Don't send trans to peers still starting up. */
		/* FIXME: Piggyback! */
		if (peer->they_are_syncing)
			continue;

		/* FIXME: Respect filter! */
		pkt = tal_packet(peer, struct protocol_pkt_tx, PROTOCOL_PKT_TX);
		pkt->err = cpu_to_le32(PROTOCOL_ECODE_NONE);
		tal_packet_append_tx(&pkt, tx);
		todo_for_peer(peer, pkt);
	}
}

static struct protocol_pkt_block *block_pkt(tal_t *ctx, const struct block *b)
{
	struct protocol_pkt_block *blk;
 
	blk = marshal_block(ctx,
			    b->hdr, b->shard_nums, b->merkles, b->prev_txhashes,
			    b->tailer);

	return blk;
}

void send_block_to_peers(struct state *state,
			 struct peer *exclude,
			 const struct block *block)
{
	struct peer *peer;

	list_for_each(&state->peers, peer, list) {
		/* Avoid sending back to peer who told us. */
		if (peer == exclude)
			continue;

		/* Don't send block to peers still starting up. */
		/* FIXME: Piggyback! */
		if (peer->they_are_syncing)
			continue;

		/* FIXME: Respect filter! */
		todo_for_peer(peer, block_pkt(peer, block));
	}
}

void broadcast_to_peers(struct state *state, const struct protocol_net_hdr *pkt)
{
	struct peer *peer;

	list_for_each(&state->peers, peer, list)
		todo_for_peer(peer, tal_packet_dup(peer, pkt));
}

static struct protocol_pkt_err *err_pkt(struct peer *peer,
					enum protocol_ecode e)
{
	struct protocol_pkt_err *pkt;

	pkt = tal_packet(peer, struct protocol_pkt_err, PROTOCOL_PKT_ERR);
	pkt->error = cpu_to_le32(e);

	return pkt;
}

static struct block *mutual_block_search(struct peer *peer,
					 const struct protocol_double_sha *block,
					 u16 num_blocks)
{
	int i;

	for (i = 0; i < num_blocks; i++) {
		struct block *b = block_find_any(peer->state, &block[i]);

		log_debug(peer->log, "Seeking mutual block ");
		log_add_struct(peer->log, struct protocol_double_sha, &block[i]);
		if (b) {
			log_add(peer->log, " found.");
			return b;
		}
		log_add(peer->log, " not found.");
	}
	return NULL;
}

/* Blockchain has been extended/changed. */
void wake_peers(struct state *state)
{
	struct peer *p;

	list_for_each(&state->peers, p, list)
		io_wake(p);
}

static void close_writer(struct io_conn *conn, struct peer *peer)
{
	assert(peer->w == conn);
	peer->w = NULL;
	if (peer->r)
		io_close_other(peer->r);
}

static void close_reader(struct io_conn *conn, struct peer *peer)
{
	assert(peer->r == conn);
	peer->r = NULL;
	if (peer->w)
		io_close_other(peer->w);
}

static struct protocol_pkt_set_filter *set_filter_pkt(struct peer *peer)
{
	struct protocol_pkt_set_filter *pkt;

	pkt = tal_packet(peer, struct protocol_pkt_set_filter,
			 PROTOCOL_PKT_SET_FILTER);
	/* FIXME: use filter! */
	pkt->filter = cpu_to_le64(0xFFFFFFFFFFFFFFFFULL);
	pkt->offset = cpu_to_le64(0);

	return pkt;
}

static struct io_plan plan_output(struct io_conn *conn, struct peer *peer)
{
	void *pkt;

	/* There was an error?  Send that then close. */
	if (peer->error_pkt) {
		log_debug(peer->log, "Writing error packet ");
		log_add_enum(peer->log, enum protocol_ecode,
			     peer->error_pkt->error);
		return io_write_packet(peer, peer->error_pkt, io_close_cb);
	}

	/* We're entirely TODO-driven at this point. */
	pkt = get_todo_pkt(peer->state, peer);
	if (pkt)
		return io_write_packet(peer, pkt, plan_output);

	/* FIXME: Timeout! */
	if (peer->we_are_syncing && peer->requests_outstanding == 0) {
		/* We're synced (or as far as we can get).  Start
		 * normal operation. */
		log_debug(peer->log, "Syncing finished, setting filter");
		peer->we_are_syncing = false;
		return io_write_packet(peer, set_filter_pkt(peer), plan_output);
	}

	log_debug(peer->log, "Awaiting responses");
	return io_wait(peer, plan_output, peer);
}

static enum protocol_ecode
recv_set_filter(struct peer *peer, const struct protocol_pkt_set_filter *pkt)
{
	if (le32_to_cpu(pkt->len) != sizeof(*pkt))
		return PROTOCOL_ECODE_INVALID_LEN;

	if (le64_to_cpu(pkt->filter) == 0)
		return PROTOCOL_ECODE_FILTER_INVALID;

	if (le64_to_cpu(pkt->offset) > 19)
		return PROTOCOL_ECODE_FILTER_INVALID;

#if 0 /* FIXME: Implement! */
	peer->filter = le64_to_cpu(pkt->filter);
	peer->filter_offset = le64_to_cpu(pkt->offset);
#endif

	/* This is our indication to send them unsolicited txs from now on */
	peer->they_are_syncing = false;
	return PROTOCOL_ECODE_NONE;
}

static enum protocol_ecode recv_pkt_block(struct peer *peer,
					  const struct protocol_pkt_block *pkt)
{
	const struct protocol_double_sha *sha;
	u32 len = le32_to_cpu(pkt->len) - sizeof(*pkt);
	
	if (le32_to_cpu(pkt->len) < sizeof(*pkt))
		return PROTOCOL_ECODE_INVALID_LEN;

	/* Normal case. */
	if (le32_to_cpu(pkt->err) == PROTOCOL_ECODE_NONE)
		return recv_block_from_peer(peer, pkt);

	if (le32_to_cpu(pkt->err) != PROTOCOL_ECODE_UNKNOWN_BLOCK)
		return PROTOCOL_ECODE_UNKNOWN_ERRCODE;

	if (len != sizeof(*sha))
		return PROTOCOL_ECODE_INVALID_LEN;

	sha = (const struct protocol_double_sha *)(pkt + 1);
	todo_done_get_block(peer, sha, false);
	return PROTOCOL_ECODE_NONE;
}

static void
tell_peer_about_bad_input(struct state *state,
			  struct peer *peer,
			  const union protocol_tx *tx,
			  unsigned int bad_input_num)
{
	struct protocol_pkt_tx_bad_input *pkt;
	const union protocol_tx *bad_tx;

	pkt = tal_packet(peer, struct protocol_pkt_tx_bad_input,
			 PROTOCOL_PKT_TX_BAD_INPUT);
	pkt->inputnum = cpu_to_le32(bad_input_num);

	bad_tx = txhash_gettx(&state->txhash,
			      &tx_input(tx, bad_input_num)->input);

	tal_packet_append_tx(&pkt, tx);
	tal_packet_append_tx(&pkt, bad_tx);

	todo_for_peer(peer, pkt);
}

static void
tell_peer_about_bad_amount(struct state *state,
			   struct peer *peer,
			   const union protocol_tx *tx)
{
	struct protocol_pkt_tx_bad_amount *pkt;
	struct protocol_input *inp;
	unsigned int i;

	assert(le32_to_cpu(tx->hdr.type) == TX_NORMAL);
	inp = get_normal_inputs(&tx->normal);

	pkt = tal_packet(peer, struct protocol_pkt_tx_bad_amount,
			 PROTOCOL_PKT_TX_BAD_AMOUNT);

	tal_packet_append_tx(&pkt, tx);

	/* FIXME: What if input still pending, not in txhash? */
	for (i = 0; i < le32_to_cpu(tx->normal.num_inputs); i++) {
		union protocol_tx *input;
		input = txhash_gettx(&state->txhash, &inp[i].input);
		tal_packet_append_tx(&pkt, input);
	}

	todo_for_peer(peer, pkt);
}

static enum protocol_ecode
recv_tx(struct peer *peer, const struct protocol_pkt_tx *pkt)
{
	enum protocol_ecode e;
	enum input_ecode ierr;
	union protocol_tx *tx;
	struct protocol_double_sha sha;
	u32 txlen = le32_to_cpu(pkt->len) - sizeof(*pkt);
	unsigned int bad_input_num;

	log_debug(peer->log, "Received PKT_TX");

	if (le32_to_cpu(pkt->len) < sizeof(*pkt))
		return PROTOCOL_ECODE_INVALID_LEN;

	/* If we asked for a tx and it didn't know, this is what it says. */
	e = le32_to_cpu(pkt->err);
	if (e != PROTOCOL_ECODE_NONE) {
		struct protocol_double_sha *txhash = (void *)(pkt + 1);

		if (e != PROTOCOL_ECODE_UNKNOWN_TX)
			return PROTOCOL_ECODE_UNKNOWN_ERRCODE;
		if (txlen != sizeof(*txhash))
			return PROTOCOL_ECODE_INVALID_LEN;
		todo_done_get_tx(peer, txhash, false);
		return PROTOCOL_ECODE_NONE;
	}

	tx = (void *)(pkt + 1);
	e = unmarshal_tx(tx, txlen, NULL);
	if (e)
		return e;

	e = check_tx(peer->state, tx, NULL);
	if (e)
		return e;

	ierr = check_tx_inputs(peer->state, tx, &bad_input_num);
	hash_tx(tx, &sha);
	todo_done_get_tx(peer, &sha, ierr == ECODE_INPUT_OK);

	/* If inputs are malformed, it might not have known so don't hang up. */
	switch (ierr) {
	case ECODE_INPUT_OK:
		break;
	case ECODE_INPUT_UNKNOWN:
		/* Ask about this input. */
		todo_add_get_tx(peer->state,
				&tx_input(tx, bad_input_num)->input);
		/* FIXME: Keep unresolved pending transaction. */
		return PROTOCOL_ECODE_NONE;
	case ECODE_INPUT_BAD:
		tell_peer_about_bad_input(peer->state, peer, tx, bad_input_num);
		return PROTOCOL_ECODE_NONE;
	case ECODE_INPUT_BAD_AMOUNT:
		tell_peer_about_bad_amount(peer->state, peer, tx);
		return PROTOCOL_ECODE_NONE;
	}

	/* OK, we own it now. */
	tal_steal(peer->state, pkt);
	add_pending_tx(peer, tx);

	return PROTOCOL_ECODE_NONE;
}

static enum protocol_ecode
recv_get_shard(struct peer *peer,
	       const struct protocol_pkt_get_shard *pkt,
	       void **reply)
{
	struct block *b;
	struct protocol_pkt_shard *r;
	u16 shard;

	if (le32_to_cpu(pkt->len) != sizeof(*pkt))
		return PROTOCOL_ECODE_INVALID_LEN;

	r = tal_packet(peer, struct protocol_pkt_shard, PROTOCOL_PKT_SHARD);
	r->block = pkt->block;
	r->shard = pkt->shard;
	shard = le16_to_cpu(pkt->shard);

	b = block_find_any(peer->state, &pkt->block);
	if (!b) {
		/* If we don't know it, that's OK.  Try to find out. */
		todo_add_get_block(peer->state, &pkt->block);
		r->err = cpu_to_le16(PROTOCOL_ECODE_UNKNOWN_BLOCK);
	} else if (shard >= num_shards(b->hdr)) {
		log_unusual(peer->log, "Invalid get_shard for shard %u of ",
			    shard);
		log_add_struct(peer->log, struct protocol_double_sha,
			       &pkt->block);
		tal_free(r);
		return PROTOCOL_ECODE_BAD_SHARDNUM;
	} else if (!shard_all_hashes(b->shard[shard])) {
		log_debug(peer->log, "Don't know all of shard %u of ",
			    le16_to_cpu(pkt->shard));
		log_add_struct(peer->log, struct protocol_double_sha,
			       &pkt->block);
		r->err = cpu_to_le16(PROTOCOL_ECODE_UNKNOWN_SHARD);
	} else if (b->complaint) {
		log_debug(peer->log, "get_shard on invalid block ");
		log_add_struct(peer->log, struct protocol_double_sha,
			       &pkt->block);
		/* Send complaint, but don't otherwise reply. */
		todo_for_peer(peer, tal_packet_dup(peer, b->complaint));
		r = tal_free(r);
	} else {
		unsigned int i;
		const struct block_shard *s = b->shard[shard];

		/* Success, give them all the hashes. */
		r->err = cpu_to_le16(PROTOCOL_ECODE_NONE);
		for (i = 0; i < s->size; i++) {
			struct protocol_net_txrefhash hashes;
			const struct protocol_net_txrefhash *p;

			/* shard_all_hashes() means p will not be NULL! */
			p = txrefhash_in_shard(s, i, &hashes);
			tal_packet_append_txrefhash(&r, p);
		}
	}

	*reply = r;
	return PROTOCOL_ECODE_NONE;
}

static enum protocol_ecode
recv_get_tx_in_block(struct peer *peer,
		     const struct protocol_pkt_get_tx_in_block *pkt,
		     void **reply)
{
	struct block *b;
	struct protocol_pkt_tx_in_block *r;
	struct protocol_proof proof;
	union protocol_tx *tx;
	u16 shard;
	u8 txoff;

	if (le32_to_cpu(pkt->len) != sizeof(*pkt))
		return PROTOCOL_ECODE_INVALID_LEN;

	r = tal_packet(peer, struct protocol_pkt_tx_in_block,
		       PROTOCOL_PKT_TX_IN_BLOCK);
		       
	shard = le16_to_cpu(pkt->pos.shard);
	txoff = pkt->pos.txoff;

	b = block_find_any(peer->state, &pkt->pos.block);
	if (!b) {
		/* If we don't know it, that's OK.  Try to find out. */
		todo_add_get_block(peer->state, &pkt->pos.block);
		r->err = cpu_to_le32(PROTOCOL_ECODE_UNKNOWN_BLOCK);
		goto unknown;
	} else if (shard >= num_shards(b->hdr)) {
		log_unusual(peer->log, "Invalid get_tx for shard %u of ",
			    shard);
		log_add_struct(peer->log, struct protocol_double_sha,
			       &pkt->pos.block);
		tal_free(r);
		return PROTOCOL_ECODE_BAD_SHARDNUM;
	} else if (txoff >= b->shard_nums[shard]) {
		log_unusual(peer->log, "Invalid get_tx for txoff %u of shard %u of ",
			    txoff, shard);
		log_add_struct(peer->log, struct protocol_double_sha,
			       &pkt->pos.block);
		tal_free(r);
		return PROTOCOL_ECODE_BAD_TXOFF;
	}

	tx = block_get_tx(b, shard, txoff);
	if (!tx) {
		r->err = cpu_to_le32(PROTOCOL_ECODE_UNKNOWN_TX);
		goto unknown;
	}

	r->err = cpu_to_le32(PROTOCOL_ECODE_NONE);
	create_proof(&proof, b->shard[shard], txoff);
	tal_packet_append_proof(&r, b, shard, txoff, &proof, tx,
				block_get_refs(b, shard, txoff));

done:
	*reply = r;
	return PROTOCOL_ECODE_NONE;

unknown:
	tal_packet_append_pos(&r, b, shard, txoff);
	goto done;
}

static enum protocol_ecode
recv_get_tx(struct peer *peer,
	    const struct protocol_pkt_get_tx *pkt, void **reply)
{
	struct txhash_elem *te;
	struct txhash_iter ti;
	const union protocol_tx *tx;
	struct protocol_pkt_tx *r;

	if (le32_to_cpu(pkt->len) != sizeof(*pkt))
		return PROTOCOL_ECODE_INVALID_LEN;

	/* First look for one in a block. */
	/* FIXME: Prefer main chain! */
	te = txhash_firstval(&peer->state->txhash, &pkt->tx, &ti);
	if (te) {
		struct protocol_pkt_tx_in_block *r;
		struct protocol_proof proof;
		struct block *b = te->block;

		r = tal_packet(peer, struct protocol_pkt_tx_in_block,
			       PROTOCOL_PKT_TX_IN_BLOCK);
		r->err = cpu_to_le32(PROTOCOL_ECODE_NONE);
		tx = block_get_tx(te->block, te->shardnum, te->txoff);
		create_proof(&proof, b->shard[te->shardnum], te->txoff);
		tal_packet_append_proof(&r, b, te->shardnum, te->txoff, &proof,
					tx, block_get_refs(te->block,
							   te->shardnum,
							   te->txoff));
		*reply = r;
		return PROTOCOL_ECODE_NONE;
	}

	r = tal_packet(peer, struct protocol_pkt_tx, PROTOCOL_PKT_TX);

	/* Does this exist in pending? */
	tx = find_pending_tx(peer->state, &pkt->tx);
	if (tx) {
		r->err = cpu_to_le32(PROTOCOL_ECODE_NONE);
		tal_packet_append_tx(&r, tx);
	} else {
		r->err = cpu_to_le32(PROTOCOL_ECODE_UNKNOWN_TX);
		tal_packet_append_sha(&r, &pkt->tx);
	}
	*reply = r;
	return PROTOCOL_ECODE_NONE;
}

static enum protocol_ecode
recv_tx_in_block(struct peer *peer, const struct protocol_pkt_tx_in_block *pkt)
{
	enum protocol_ecode e;
	enum input_ecode ierr;
	enum ref_ecode rerr;
	union protocol_tx *tx;
	struct protocol_input_ref *refs;
	struct protocol_tx_with_proof *proof;
	struct block *b, *block_referred_to;
	struct protocol_double_sha sha;
	unsigned int bad_input_num;
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
			todo_done_get_block(peer, &pos->block, false);
		} else if (e != PROTOCOL_ECODE_UNKNOWN_TX)
			return PROTOCOL_ECODE_UNKNOWN_ERRCODE;

		todo_done_get_tx_in_block(peer, &pos->block,
					  le16_to_cpu(pos->shard),
					  pos->txoff, false);
		return PROTOCOL_ECODE_NONE;
	}

	if (len < sizeof(*proof))
		return PROTOCOL_ECODE_INVALID_LEN;
	len -= sizeof(*proof);

	proof = (void *)(pkt + 1);
	shard = le16_to_cpu(proof->pos.shard);

	b = block_find_any(peer->state, &proof->pos.block);
	if (!b) {
		todo_add_get_block(peer->state, &proof->pos.block);
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
	e = check_tx(peer->state, tx, b);
	if (e)
		return e;

	refs = (void *)((char *)tx + used);
	e = unmarshal_input_refs(refs, len, tx, &used);
	if (e)
		return e;

	if (used != len)
		return PROTOCOL_ECODE_INVALID_LEN;

	e = check_refs(peer->state, b, refs, num_inputs(tx));
	if (e)
		return e;

	if (!check_proof(&proof->proof, b, shard, proof->pos.txoff, tx, refs))
		return PROTOCOL_ECODE_BAD_PROOF;

	/* Whatever happens from here, no point asking others for tx. */
	todo_done_get_tx_in_block(peer, &proof->pos.block,
				  shard, proof->pos.txoff, true);

	/* This may have been a response to GET_TX as well. */
	hash_tx(tx, &sha);
	todo_done_get_tx(peer, &sha, true);

	/* Now it's proven that it's in the block, handle bad inputs. */
	ierr = check_tx_inputs(peer->state, tx, &bad_input_num);
	switch (ierr) {
	case ECODE_INPUT_OK:
		break;
	case ECODE_INPUT_UNKNOWN:
		/* Ask about this input. */
		todo_add_get_tx(peer->state,
				&tx_input(tx, bad_input_num)->input);
		/* FIXME: Keep tx and proof around for later! */
		return PROTOCOL_ECODE_NONE;
	case ECODE_INPUT_BAD: {
		union protocol_tx *input;

		input = txhash_gettx(&peer->state->txhash,
				      &tx_input(tx, bad_input_num)->input);
		/* This whole block is invalid.  Tell everyone. */
		complain_bad_input(peer->state, b, shard,
				   proof->pos.txoff, &proof->proof,
				   tx, refs, bad_input_num, input);
		return PROTOCOL_ECODE_NONE;
	}
	case ECODE_INPUT_BAD_AMOUNT: {
		unsigned int i;
		const union protocol_tx *inputs[PROTOCOL_TX_MAX_INPUTS];

		for (i = 0; i < num_inputs(tx); i++)
			inputs[i] = txhash_gettx(&peer->state->txhash,
						 &tx_input(tx, i)->input);

		/* This whole block is invalid.  Tell everyone. */
		complain_bad_amount(peer->state, b, shard,
				    proof->pos.txoff, &proof->proof,
				    tx, refs, inputs);
		return PROTOCOL_ECODE_NONE;
	}
	}

	rerr = check_tx_refs(peer->state, b, tx, refs,
			     &bad_input_num, &block_referred_to);
	switch (rerr) {
	case ECODE_REF_OK:
		break;
	case ECODE_REF_UNKNOWN:
		/* This can happen if we know the tx, but don't know it
		 * is at that position.  We need to get it. */
		todo_add_get_tx_in_block(peer->state, &block_referred_to->sha,
					 shard, refs[bad_input_num].txoff);
		/* FIXME: Keep tx and proof around for later! */
		return PROTOCOL_ECODE_NONE;
	case ECODE_REF_BAD_HASH:
		/* Tell everyone this block is bad due to bogus input_ref */
		complain_bad_input_ref(peer->state, b, shard,
				       proof->pos.txoff, &proof->proof,
				       tx, refs, bad_input_num,
				       block_referred_to);
		return PROTOCOL_ECODE_NONE;
	}

	if (!check_tx_ordering(peer->state, b, b->shard[shard],
			       proof->pos.txoff, tx, &conflict_txoff)) {
		/* Tell everyone that txs are out of order in block */
		complain_misorder(peer->state, b, shard,
				  proof->pos.txoff, &proof->proof,
				  tx, refs, conflict_txoff);
		return PROTOCOL_ECODE_NONE;
	}

	/* Copy in tx and refs. */
	put_tx_in_shard(peer->state, b, b->shard[shard], proof->pos.txoff,
			txptr_with_ref(b->shard[shard], tx, refs));
	/* Keep proof in case anyone asks. */
	put_proof_in_shard(peer->state, b, b->shard[shard], proof->pos.txoff,
			   &proof->proof);

	return PROTOCOL_ECODE_NONE;
}

static enum protocol_ecode
recv_get_txmap(struct peer *peer, const struct protocol_pkt_get_txmap *pkt,
	       void **reply)
{
	struct block *b;
	struct block_shard *shard;
	struct protocol_pkt_txmap *r;
	unsigned int i;
	u8 map[256 / 8] = { 0 };

	if (le32_to_cpu(pkt->len) != sizeof(*pkt))
		return PROTOCOL_ECODE_INVALID_LEN;

	r = tal_packet(peer, struct protocol_pkt_txmap, PROTOCOL_PKT_TXMAP);
	r->block = pkt->block;
	r->shard = pkt->shard;

	b = block_find_any(peer->state, &pkt->block);
	if (!b) {
		/* If we don't know it, that's OK.  Try to find out. */
		todo_add_get_block(peer->state, &pkt->block);
		r->err = cpu_to_le16(PROTOCOL_ECODE_UNKNOWN_BLOCK);
		*reply = r;
		return PROTOCOL_ECODE_NONE;
	}

	if (le16_to_cpu(pkt->shard) >= num_shards(b->hdr))
		return PROTOCOL_ECODE_BAD_SHARDNUM;

	shard = b->shard[le16_to_cpu(pkt->shard)];
	for (i = 0; i < shard->size; i++) {
		const union protocol_tx *tx = tx_for(shard, i);

		/* If it's not in a shard they want, but affects one... */
		if (tx && peer_wants_tx_other(peer, tx))
			map[i / 8] |= (1 << (i % 8));
	}

	tal_packet_append(&r, map, (shard->size + 31) / 32 * 4);
	*reply = r;

	return PROTOCOL_ECODE_NONE;
}

static enum protocol_ecode
recv_txmap(struct peer *peer, const struct protocol_pkt_txmap *pkt)
{
	struct block *b;
	struct block_shard *shard;
	u32 i, len = le32_to_cpu(pkt->len);
	const u8 *map;

	if (le32_to_cpu(pkt->len) < sizeof(*pkt))
		return PROTOCOL_ECODE_INVALID_LEN;
	len -= sizeof(*pkt);

	b = block_find_any(peer->state, &pkt->block);
	if (!b) {
		/* If we don't know it, that's OK.  Try to find out. */
		todo_add_get_block(peer->state, &pkt->block);
		return PROTOCOL_ECODE_NONE;
	}

	if (le16_to_cpu(pkt->shard) >= num_shards(b->hdr))
		return PROTOCOL_ECODE_BAD_SHARDNUM;

	shard = b->shard[le16_to_cpu(pkt->shard)];

	map = (const u8 *)(pkt + 1);
	if (len != (shard->size + 31) / 32 * 4)
		return PROTOCOL_ECODE_INVALID_LEN;

	for (i = 0; i < shard->size; i++) {
		const union protocol_tx *tx = tx_for(shard, i);

		/* If we don't know it and they think we should, ask. */
		if (!tx && (map[i / 8] & (1 << (i % 8)))) {
			todo_add_get_tx_in_block(peer->state, &b->sha,
						 shard->shardnum, i);
		}
	}
	return PROTOCOL_ECODE_NONE;
}

static enum protocol_ecode
unmarshal_and_check_tx(struct state *state, const char **p, size_t *len,
		       const union protocol_tx **tx)
{
	enum protocol_ecode e;
	size_t used;

	e = unmarshal_tx(*p, *len, &used);
	if (e)
		return e;
	*tx = (const void *)*p;

	(*p) += used;
	*len -= used;

	return check_tx(state, *tx, NULL);
}

static enum protocol_ecode
recv_tx_bad_input(struct peer *peer,
		  const struct protocol_pkt_tx_bad_input *pkt)
{
	const union protocol_tx *tx, *in;
	const struct protocol_input *input;
	struct protocol_double_sha sha;
	struct protocol_address tx_addr;
	enum protocol_ecode e;
	enum input_ecode ierr;
	struct txhash_elem *te;
	struct txhash_iter ti;
	const char *p;
	u32 amount;
	size_t len = le32_to_cpu(pkt->len);

	if (len < sizeof(*pkt))
		return PROTOCOL_ECODE_INVALID_LEN;

	p = (const char *)(pkt + 1);
	len -= sizeof(*pkt);

	e = unmarshal_and_check_tx(peer->state, &p, &len, &tx);
	if (e)
		return e;

	e = unmarshal_and_check_tx(peer->state, &p, &len, &in);
	if (e)
		return e;

	if (len != 0)
		return PROTOCOL_ECODE_INVALID_LEN;

	/* Make sure this tx match the bad input */
	if (le32_to_cpu(pkt->inputnum) >= num_inputs(tx))
		return PROTOCOL_ECODE_BAD_INPUTNUM;

	assert(tx->hdr.type == TX_NORMAL);
	input = tx_input(tx, le32_to_cpu(pkt->inputnum));
	hash_tx(in, &sha);

	if (!structeq(&input->input, &sha))
		return PROTOCOL_ECODE_BAD_INPUT;

	pubkey_to_addr(&tx->normal.input_key, &tx_addr);

	ierr = check_one_input(peer->state, input, in, &tx_addr, &amount);
	if (ierr == ECODE_INPUT_OK)
		return PROTOCOL_ECODE_INPUT_NOT_BAD;

	hash_tx(tx, &sha);

	/* OK, it's bad.  Is it in any blocks? */
	for (te = txhash_firstval(&peer->state->txhash, &sha, &ti);
	     te;
	     te = txhash_nextval(&peer->state->txhash, &sha, &ti)) {
		struct protocol_proof proof;
		struct block_shard *shard = te->block->shard[te->shardnum];

		create_proof(&proof, shard, te->txoff);
		complain_bad_input(peer->state, te->block, te->shardnum,
				   te->txoff, &proof, tx,
				   refs_for(shard->u[te->txoff].txp),
				   le32_to_cpu(pkt->inputnum), in);
	}

	drop_pending_tx(peer->state, tx);
	return PROTOCOL_ECODE_NONE;
}


static struct io_plan pkt_in(struct io_conn *conn, struct peer *peer)
{
	const struct protocol_net_hdr *hdr = peer->incoming;
	tal_t *ctx = tal_arr(peer, char, 0);
	u32 len, type;
	enum protocol_ecode err;
	void *reply = NULL;

	len = le32_to_cpu(hdr->len);
	type = le32_to_cpu(hdr->type);

	log_debug(peer->log, "pkt_in: received ");
	log_add_enum(peer->log, enum protocol_pkt_type, type);

	/* Recipient function should steal this if it should outlive us. */
	tal_steal(ctx, peer->incoming);

	switch (type) {
	case PROTOCOL_PKT_ERR:
		if (len == sizeof(struct protocol_pkt_err)) {
			struct protocol_pkt_err *p = peer->incoming;
			log_unusual(peer->log, "Received PROTOCOL_PKT_ERR ");
			log_add_enum(peer->log, enum protocol_ecode,
				     cpu_to_le32(p->error));
		} else {
			log_unusual(peer->log,
				    "Received PROTOCOL_PKT_ERR len %u", len);
		}
		return io_close();

	case PROTOCOL_PKT_GET_CHILDREN:
		err = recv_get_children(peer, peer->incoming, &reply);
		break;
	case PROTOCOL_PKT_CHILDREN:
		err = recv_children(peer, peer->incoming);
		break;
	case PROTOCOL_PKT_SET_FILTER:
		err = recv_set_filter(peer, peer->incoming);
		break;
	case PROTOCOL_PKT_BLOCK:
		err = recv_pkt_block(peer, peer->incoming);
		break;
	case PROTOCOL_PKT_TX:
		err = recv_tx(peer, peer->incoming);
		break;
	case PROTOCOL_PKT_GET_BLOCK:
		err = recv_get_block(peer, peer->incoming, &reply);
		break;
	case PROTOCOL_PKT_GET_SHARD:
		err = recv_get_shard(peer, peer->incoming, &reply);
		break;
	case PROTOCOL_PKT_SHARD:
		err = recv_shard_from_peer(peer, peer->incoming);
		break;
	case PROTOCOL_PKT_GET_TX_IN_BLOCK:
		err = recv_get_tx_in_block(peer, peer->incoming, &reply);
		break;
	case PROTOCOL_PKT_TX_IN_BLOCK:
		err = recv_tx_in_block(peer, peer->incoming);
		break;
	case PROTOCOL_PKT_GET_TX:
		err = recv_get_tx(peer, peer->incoming, &reply);
		break;
	case PROTOCOL_PKT_GET_TXMAP:	
		err = recv_get_txmap(peer, peer->incoming, &reply);
		break;
	case PROTOCOL_PKT_TXMAP:
		err = recv_txmap(peer, peer->incoming);
		break;
	case PROTOCOL_PKT_TX_BAD_INPUT:
		err = recv_tx_bad_input(peer, peer->incoming);
		break;

	/* FIXME: Implement. */
	case PROTOCOL_PKT_TX_BAD_AMOUNT:

	/* FIXME: Implement complaints. */
	case PROTOCOL_PKT_BLOCK_TX_MISORDER:
	case PROTOCOL_PKT_BLOCK_TX_INVALID:
	case PROTOCOL_PKT_BLOCK_TX_BAD_INPUT:
	case PROTOCOL_PKT_BLOCK_BAD_INPUT_REF:
	case PROTOCOL_PKT_BLOCK_TX_BAD_AMOUNT:

	/* These should not be used after sync. */
	case PROTOCOL_PKT_WELCOME:
	case PROTOCOL_PKT_HORIZON:
	case PROTOCOL_PKT_SYNC:
	default:
		err = PROTOCOL_ECODE_UNKNOWN_COMMAND;
	}

	if (err) {
		peer->error_pkt = err_pkt(peer, err);

		/* In case writer is waiting. */
		io_wake(peer);

		/* Wait for writer to send error. */
		tal_free(ctx);
		return io_wait(peer, io_close_cb, NULL);
	}

	/* If we want to send something, queue it for plan_output */
	if (reply)
		todo_for_peer(peer, reply);

	tal_free(ctx);
	return io_read_packet(&peer->incoming, pkt_in, peer);
}

static struct io_plan check_sync_or_horizon(struct io_conn *conn,
					    struct peer *peer)
{
	const struct protocol_net_hdr *hdr = peer->incoming;
	enum protocol_ecode err;

	if (le32_to_cpu(hdr->type) == PROTOCOL_PKT_HORIZON)
		err = recv_horizon_pkt(peer, peer->incoming);
	else if (le32_to_cpu(hdr->type) == PROTOCOL_PKT_SYNC)
		err = recv_sync_pkt(peer, peer->incoming);
	else {
		err = PROTOCOL_ECODE_UNKNOWN_COMMAND;
	}

	if (err != PROTOCOL_ECODE_NONE)
		return io_write_packet(peer, err_pkt(peer, err), io_close_cb);

	/* Time to go duplex on this connection. */
	assert(conn == peer->w);
	peer->r = io_duplex(peer->w,
			    io_read_packet(&peer->incoming, pkt_in, peer));

	/* If one dies, kill both, and don't free peer when w freed! */
	io_set_finish(peer->r, close_reader, peer);
	io_set_finish(peer->w, close_writer, peer);
	tal_steal(peer->state, peer);

	/* Now we sync any children. */
	return plan_output(conn, peer);
}

static struct io_plan recv_sync_or_horizon(struct io_conn *conn,
					   struct peer *peer)
{
	return io_read_packet(&peer->incoming, check_sync_or_horizon, peer);
}

static struct io_plan welcome_received(struct io_conn *conn, struct peer *peer)
{
	struct state *state = peer->state;
	enum protocol_ecode e;
	const struct block *mutual;

	log_debug(peer->log, "Their welcome received");

	tal_steal(peer, peer->welcome);
	peer->state->num_peers_connected++;

	/* Are we talking to ourselves? */
	if (peer->welcome->random == state->random_welcome) {
		log_unusual(peer->log, "The peer is ourselves: closing");
		peer_cache_del(state, &peer->you, true);
		return io_close();
	}

	e = check_welcome(state, peer->welcome, &peer->welcome_blocks);
	if (e != PROTOCOL_ECODE_NONE) {
		log_unusual(peer->log, "Peer welcome was invalid:");
		log_add_enum(peer->log, enum protocol_ecode, e);
		return io_write_packet(peer, err_pkt(peer, e), io_close_cb);
	}

	log_info(peer->log, "Welcome received: listen port is %u",
		 be16_to_cpu(peer->welcome->listen_port));

	/* Replace port we see with port they want us to connect to. */
	peer->you.port = peer->welcome->listen_port;

	/* Create/update time for this peer. */
	peer_cache_update(state, &peer->you, time_now().ts.tv_sec);

	mutual = mutual_block_search(peer, peer->welcome_blocks,
				     le16_to_cpu(peer->welcome->num_blocks));
	return io_write_packet(peer, sync_or_horizon_pkt(peer, mutual),
			       recv_sync_or_horizon);
}

static struct io_plan welcome_sent(struct io_conn *conn, struct peer *peer)
{
	log_debug(peer->log, "Our welcome sent, awaiting theirs");
	return io_read_packet(&peer->welcome, welcome_received, peer);
}

static void destroy_peer(struct peer *peer)
{
	list_del_from(&peer->state->peers, &peer->list);
	if (peer->welcome) {
		peer->state->num_peers_connected--;
		log_info(peer->log, "Closing connected peer (%zu left)",
			 peer->state->num_peers_connected);

		if (peer->we_are_syncing) {
			log_add(peer->log, " (didn't finish syncing)");
			/* Don't delete on disk, just in memory. */
			peer_cache_del(peer->state, &peer->you, false);
		}
	} else {
		log_debug(peer->log, "Failed connect to peer %p", peer);
		/* Only delete from disk cache if we have *some* networking. */
		peer_cache_del(peer->state, &peer->you,
			       peer->state->num_peers_connected != 0);
	}

	peer->state->num_peers--;
	bitmap_clear_bit(peer->state->peer_map, peer->peer_num);
	remove_peer_from_todo(peer->state, peer);
	fill_peers(peer->state);
}

static struct io_plan setup_welcome(struct io_conn *unused, struct peer *peer)
{
	return io_write_packet(peer,
			       make_welcome(peer, peer->state, &peer->you),
			       welcome_sent);
}

static unsigned int get_peernum(const bitmap bits[])
{
	unsigned int i;

	/* FIXME: ffz in ccan/bitmap? */
	for (i = 0; i < MAX_PEERS; i++) {
		if (!bitmap_test_bit(bits, i))
			break;
	}
	return i;
}

static struct peer *alloc_peer(const tal_t *ctx, struct state *state)
{
	struct peer *peer;
	unsigned int peernum;

	peernum = get_peernum(state->peer_map);
	if (peernum == MAX_PEERS) {
		log_info(state->log, "Too many peers, closing incoming");
		return NULL;
	}

	peer = tal(ctx, struct peer);
	bitmap_set_bit(state->peer_map, peernum);
	list_add(&state->peers, &peer->list);
	peer->state = state;
	peer->we_are_syncing = true;
	peer->they_are_syncing = true;
	peer->error_pkt = NULL;
	peer->welcome = NULL;
	peer->outgoing = NULL;
	peer->incoming = NULL;
	peer->requests_outstanding = 0;
	list_head_init(&peer->todo);
	peer->peer_num = peernum;

	state->num_peers++;
	tal_add_destructor(peer, destroy_peer);

	return peer;
}

void new_peer(struct state *state, int fd, const struct protocol_net_address *a)
{
	struct peer *peer;
	char name[INET6_ADDRSTRLEN + strlen(":65000:")];

	peer = alloc_peer(NULL, state);
	if (!peer) {
		close(fd);
		return;
	}

	/* If a, we need to connect to there. */
	if (a) {
		struct addrinfo *ai;

		peer->you = *a;

		log_debug(state->log, "Connecting to peer %p (%zu) at ",
			  peer, state->num_peers);
		log_add_struct(state->log, struct protocol_net_address,
			       &peer->you);

		ai = mk_addrinfo(peer, a);
		peer->w = io_new_conn(fd,
				      io_connect(fd, ai, setup_welcome, peer));
		tal_free(ai);
	} else {
		if (!get_fd_addr(fd, &peer->you)) {
			log_unusual(state->log,
				    "Could not get address for peer: %s",
				    strerror(errno));
			tal_free(peer);
			close(fd);
			return;
		}
		peer->w = io_new_conn(fd, setup_welcome(NULL, peer));
		log_debug(state->log, "Peer %p (%zu) connected from ",
			  peer, state->num_peers);
		log_add_struct(state->log, struct protocol_net_address,
			       &peer->you);
	}

	if (inet_ntop(AF_INET6, peer->you.addr, name, sizeof(name)) == NULL)
		strcpy(name, "UNCONVERTABLE-IPV6");
	sprintf(name + strlen(name), ":%u:", be16_to_cpu(peer->you.port));
	peer->log = new_log(peer, state->log,
			    name, state->log_level, PEER_LOG_MAX);

	/* Conn owns us: we vanish when it does. */
	tal_steal(peer->w, peer);
}

static struct io_plan setup_peer(struct io_conn *conn, struct state *state)
{
	struct peer *peer = alloc_peer(conn, state);

	if (!peer)
		return io_close();

	/* FIXME: Disable nagle if we can use TCP_CORK */
	if (!get_fd_addr(io_conn_fd(conn), &peer->you)) {
		log_unusual(state->log, "Could not get address for peer: %s",
			    strerror(errno));
		return io_close();
	}

	log_info(state->log, "Set up --connect peer %u at ", peer->peer_num);
	log_add_struct(state->log, struct protocol_net_address, &peer->you);

	return setup_welcome(conn, peer);
}

/* We use this for command line --connect. */
bool new_peer_by_addr(struct state *state, const char *node, const char *port)
{
	return dns_resolve_and_connect(state, node, port, setup_peer);
}
