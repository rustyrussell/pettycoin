#include "addr.h"
#include "block.h"
#include "blockfile.h"
#include "chain.h"
#include "check_block.h"
#include "check_tx.h"
#include "complain.h"
#include "difficulty.h"
#include "dns.h"
#include "generating.h"
#include "hash_block.h"
#include "input_refs.h"
#include "log.h"
#include "marshal.h"
#include "netaddr.h"
#include "packet_io.h"
#include "peer.h"
#include "peer_cache.h"
#include "peer_wants.h"
#include "pending.h"
#include "proof.h"
#include "protocol_net.h"
#include "recv_block.h"
#include "shadouble.h"
#include "shard.h"
#include "state.h"
#include "sync.h"
#include "tal_packet.h"
#include "todo.h"
#include "tx.h"
#include "tx_cmp.h"
#include "welcome.h"
#include <arpa/inet.h>
#include <ccan/build_assert/build_assert.h>
#include <ccan/cast/cast.h>
#include <ccan/err/err.h>
#include <ccan/io/io.h>
#include <ccan/structeq/structeq.h>
#include <ccan/tal/path/path.h>
#include <ccan/tal/tal.h>
#include <ccan/time/time.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>

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

/* only_other is set if we only want to send to peers who aren't interested
 * in this tx's home shard. */
static void send_to_interested_peers(struct state *state,
				     const struct peer *exclude,
				     const union protocol_tx *tx,
				     bool only_other,
				     const void *pkt)
{
	struct peer *peer;

	list_for_each(&state->peers, peer, list) {
		/* Avoid sending back to peer who told us. */
		if (peer == exclude)
			continue;

		/* Don't send trans to peers still starting up. */
		/* FIXME: Piggyback! */
		if (peer->they_are_syncing)
			continue;

		if (only_other) {
			if (peer_wants_tx(peer, tx))
				continue;
			if (!peer_wants_tx_other(peer, tx))
				continue;
		} else {
			/* Not interested in any shards affected by this tx? */
			if (!peer_wants_tx(peer, tx)
			    && !peer_wants_tx_other(peer, tx))
				continue;
		}

		/* FIXME: Respect filter! */
		todo_for_peer(peer, tal_packet_dup(peer, pkt));
	}
}

/* We sent unsolicited TXs to any peer who's interested. */
void send_tx_to_peers(struct state *state, struct peer *exclude,
		      const union protocol_tx *tx)
{
	struct protocol_pkt_tx *pkt;

	pkt = tal_packet(state, struct protocol_pkt_tx, PROTOCOL_PKT_TX);
	pkt->err = cpu_to_le32(PROTOCOL_ECODE_NONE);
	tal_packet_append_tx(&pkt, tx);

	send_to_interested_peers(state, exclude, tx, false, pkt);
	tal_free(pkt);
}

/* We only send unsolicited TXs in blocks when the peer wouldn't get
 * it via their normal protocol_pkt_get_shard().  ie. it's not in one
 * of their block shards, but it affects a shard they want. */
void send_tx_in_block_to_peers(struct state *state, const struct peer *exclude,
			       struct block *block, u16 shard, u8 txoff)
{
	struct protocol_pkt_hashes_in_block *pkt;
	struct protocol_proof proof;
	struct protocol_txrefhash scratch;

	pkt = tal_packet(state, struct protocol_pkt_hashes_in_block,
			 PROTOCOL_PKT_HASHES_IN_BLOCK);
	create_proof(&proof, block, shard, txoff);
	tal_packet_append_proof(&pkt, &proof);
	tal_packet_append_txrefhash(&pkt,
				    txrefhash_in_shard(block->shard[shard],
						       txoff, &scratch));

	send_to_interested_peers(state, exclude,
				 block_get_tx(block, shard, txoff), true, pkt);
	tal_free(pkt);
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

void broadcast_to_peers(struct state *state, const struct protocol_net_hdr *pkt,
			const struct peer *exclude)
{
	struct peer *peer;

	list_for_each(&state->peers, peer, list)
		if (peer != exclude)
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

static void tell_peer_about_doublespend(struct state *state,
					const struct block *block,
					struct peer *peer,
					const union protocol_tx *tx,
					unsigned int ds_input_num)
{
	struct protocol_pkt_tx_doublespend *pkt;
	struct txhash_elem *other;
	const union protocol_tx *other_tx;

	pkt = tal_packet(peer, struct protocol_pkt_tx_doublespend,
			 PROTOCOL_PKT_TX_DOUBLESPEND);
	pkt->input1 = cpu_to_le32(ds_input_num);

	other = tx_find_doublespend(state, block, NULL,
				    tx_input(tx, ds_input_num));
	other_tx = block_get_tx(other->block, other->shardnum, other->txoff);

	pkt->input2 = cpu_to_le32(find_matching_input(other_tx,
						tx_input(tx, ds_input_num)));

	tal_packet_append_tx(&pkt, tx);
	tal_packet_append_tx(&pkt, other_tx);

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

	assert(tx_type(tx) == TX_NORMAL);
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

	hash_tx(tx, &sha);

	/* Stop now if we already have it in block (otherwise we'd
	 * report a doublespend). */
	if (txhash_gettx(&peer->state->txhash, &sha))
		return PROTOCOL_ECODE_NONE;

	/* We check inputs for where *we* would mine it. */
	ierr = check_tx_inputs(peer->state, peer->state->longest_knowns[0],
			       NULL, tx, &bad_input_num);
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
	case ECODE_INPUT_DOUBLESPEND:
		tell_peer_about_doublespend(peer->state,
					    peer->state->longest_knowns[0],
					    peer, tx, bad_input_num);
		return PROTOCOL_ECODE_NONE;
	}

	/* OK, we own it now. */
	tal_steal(peer->state, pkt);
	add_pending_tx(peer, tx);

	return PROTOCOL_ECODE_NONE;
}

static enum protocol_ecode
recv_hashes_in_block(struct peer *peer,
		     const struct protocol_pkt_hashes_in_block *pkt)
{
	struct block *b;
	u16 shard;
	u8 txoff;

	if (le32_to_cpu(pkt->len) != sizeof(*pkt))
		return PROTOCOL_ECODE_INVALID_LEN;

	shard = le16_to_cpu(pkt->hproof.proof.pos.shard);

	b = block_find_any(peer->state, &pkt->hproof.proof.pos.block);
	if (!b) {
		todo_add_get_block(peer->state,
				   &pkt->hproof.proof.pos.block);
		/* FIXME: should we extract hashes? */
		return PROTOCOL_ECODE_NONE;
	}

	if (!check_proof_byhash(&pkt->hproof.proof, b, &pkt->hproof.txrefhash))
		return PROTOCOL_ECODE_BAD_PROOF;

	shard = le16_to_cpu(pkt->hproof.proof.pos.shard);
	txoff = pkt->hproof.proof.pos.txoff;

	/* If we know this transaction, it gets returned. */
	if (put_txhash_in_shard(peer->state, b, shard, txoff,
				&pkt->hproof.txrefhash)) {
		/* Keep proof in case anyone asks. */
		put_proof_in_shard(peer->state, b, &pkt->hproof.proof);

		/* We might already know it. */
		if (!try_resolve_hash(peer->state, peer, b, shard, txoff)) {
			/* FIXME: If we put unresolved hashes in txhash,
			 * we could just ask for tx. */
			todo_add_get_tx_in_block(peer->state,
						 &b->sha, shard, txoff);
		}
	}

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
			struct protocol_txrefhash hashes;
			const struct protocol_txrefhash *p;

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
	create_proof(&proof, b, shard, txoff);
	tal_packet_append_proof(&r, &proof);
	tal_packet_append_tx_with_refs(&r, tx, block_get_refs(b, shard, txoff));

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
		create_proof(&proof, b, te->shardnum, te->txoff);
		tal_packet_append_proof(&r, &proof);
		tal_packet_append_tx_with_refs(&r, 
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
	union protocol_tx *tx;
	struct protocol_input_ref *refs;
	struct protocol_tx_with_proof *proof;
	struct block *b;
	struct protocol_double_sha sha;
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
	shard = le16_to_cpu(proof->proof.pos.shard);

	b = block_find_any(peer->state, &proof->proof.pos.block);
	if (!b) {
		todo_add_get_block(peer->state, &proof->proof.pos.block);
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

	if (!check_proof(&proof->proof, b, tx, refs))
		return PROTOCOL_ECODE_BAD_PROOF;

	/* Whatever happens from here, no point asking others for tx. */
	todo_done_get_tx_in_block(peer, &proof->proof.pos.block,
				  shard, proof->proof.pos.txoff, true);

	/* This may have been a response to GET_TX as well. */
	hash_tx(tx, &sha);
	todo_done_get_tx(peer, &sha, true);

	/* Now it's proven that it's in the block, handle bad inputs/refs.
	 * We don't hang up on them, since they may not have known. */
	if (!check_tx_inputs_and_refs(peer->state, b, &proof->proof, tx, refs))
		return PROTOCOL_ECODE_NONE;

	/* Simularly, they might not know if it was misordered. */
	if (!check_tx_ordering(peer->state, b, b->shard[shard],
			       proof->proof.pos.txoff, tx, &conflict_txoff)) {
		/* Tell everyone that txs are out of order in block */
		complain_misorder(peer->state, b, &proof->proof,
				  tx, refs, conflict_txoff);
		return PROTOCOL_ECODE_NONE;
	}

	/* Copy in tx and refs. */
	put_tx_in_shard(peer->state, b, b->shard[shard], proof->proof.pos.txoff,
			txptr_with_ref(b->shard[shard], tx, refs));
	/* Keep proof in case anyone asks. */
	put_proof_in_shard(peer->state, b, &proof->proof);

	/* Reuse packet as shortcut for send_tx_in_block_to_peers */
	send_to_interested_peers(peer->state, peer, tx, true, pkt);

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

/* They claim that @in is @tx's input_num'th input.  It may have an
 * input error.. */
static enum protocol_ecode
verify_problem_input(struct state *state,
		     const union protocol_tx *tx, u32 input_num,
		     const union protocol_tx *in,
		     enum input_ecode *ierr,
		     u32 *total)
{
	struct protocol_double_sha sha;
	struct protocol_address tx_addr;
	const struct protocol_input *input;
	u32 amount;

	/* Make sure this tx match the bad input */
	if (input_num >= num_inputs(tx))
		return PROTOCOL_ECODE_BAD_INPUTNUM;

	assert(tx_type(tx) == TX_NORMAL);
	input = tx_input(tx, input_num);
	hash_tx(in, &sha);

	if (!structeq(&input->input, &sha))
		return PROTOCOL_ECODE_BAD_INPUT;

	pubkey_to_addr(&tx->normal.input_key, &tx_addr);

	*ierr = check_one_input(state, NULL, NULL,
				input, in, &tx_addr, &amount);
	if (total)
		*total += amount;
	return PROTOCOL_ECODE_NONE;
}

static enum protocol_ecode
recv_tx_bad_input(struct peer *peer,
		  const struct protocol_pkt_tx_bad_input *pkt)
{
	const union protocol_tx *tx, *in;
	struct protocol_double_sha sha;
	enum protocol_ecode e;
	enum input_ecode ierr;
	struct txhash_elem *te;
	struct txhash_iter ti;
	const char *p;
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
	e = verify_problem_input(peer->state, tx, le32_to_cpu(pkt->inputnum),
				 in, &ierr, NULL);
	if (e)
		return e;

	/* The input should give an error though (and you can't use this
	 * to report double-spends!) */
	if (ierr == ECODE_INPUT_OK || ierr == ECODE_INPUT_DOUBLESPEND)
		return PROTOCOL_ECODE_COMPLAINT_INVALID;

	hash_tx(tx, &sha);

	/* OK, it's bad.  Is it in any blocks? */
	for (te = txhash_firstval(&peer->state->txhash, &sha, &ti);
	     te;
	     te = txhash_nextval(&peer->state->txhash, &sha, &ti)) {
		struct protocol_proof proof;

		create_proof(&proof, te->block, te->shardnum, te->txoff);
		complain_bad_input(peer->state, te->block, &proof, tx,
				   block_get_refs(te->block, te->shardnum,
						  te->txoff),
				   le32_to_cpu(pkt->inputnum), in);
	}

	drop_pending_tx(peer->state, tx);
	return PROTOCOL_ECODE_NONE;
}

/* The marshalled txs are the same between protocol_pkt_tx_bad_amount
 * and protocol_pkt_complain_tx_bad_amount, so share this code: */
static enum protocol_ecode
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

	assert(tx_type(tx) == TX_NORMAL);
	if (total == (le32_to_cpu(tx->normal.send_amount)
		      + le32_to_cpu(tx->normal.change_amount)))
		return PROTOCOL_ECODE_COMPLAINT_INVALID;

	return PROTOCOL_ECODE_NONE;
}

static enum protocol_ecode
recv_tx_bad_amount(struct peer *peer,
		   const struct protocol_pkt_tx_bad_amount *pkt)
{
	const union protocol_tx *tx, *in[PROTOCOL_TX_MAX_INPUTS];
	struct protocol_double_sha sha;
	enum protocol_ecode e;
	struct txhash_elem *te;
	struct txhash_iter ti;
	const char *p;
	size_t len = le32_to_cpu(pkt->len);

	if (len < sizeof(*pkt))
		return PROTOCOL_ECODE_INVALID_LEN;

	p = (const char *)(pkt + 1);
	len -= sizeof(*pkt);

	e = unmarshal_and_check_tx(peer->state, &p, &len, &tx);
	if (e)
		return e;

	e = unmarshal_and_check_bad_amount(peer->state, tx, p, len);
	if (e)
		return e;

	/* OK, it's bad.  Is it in any blocks? */
	hash_tx(tx, &sha);
	for (te = txhash_firstval(&peer->state->txhash, &sha, &ti);
	     te;
	     te = txhash_nextval(&peer->state->txhash, &sha, &ti)) {
		struct protocol_proof proof;

		create_proof(&proof, te->block, te->shardnum, te->txoff);
		complain_bad_amount(peer->state, te->block, &proof, tx,
				    block_get_refs(te->block,
						   te->shardnum, te->txoff),
				    in);
	}

	drop_pending_tx(peer->state, tx);
	return PROTOCOL_ECODE_NONE;
}

static enum protocol_ecode
recv_tx_doublespend(struct peer *peer,
		    const struct protocol_pkt_tx_doublespend *pkt)
{
	const union protocol_tx *tx_a, *tx_b;
	const char *p;
	size_t len = le32_to_cpu(pkt->len);
	const struct protocol_input *inp_a, *inp_b;
	enum protocol_ecode e;
	struct txhash_elem *te_a, *te_b;
	struct txhash_iter ti_a, ti_b;
	struct protocol_double_sha sha_a, sha_b;

	if (len < sizeof(*pkt))
		return PROTOCOL_ECODE_INVALID_LEN;

	p = (const char *)(pkt + 1);
	len -= sizeof(*pkt);

	e = unmarshal_and_check_tx(peer->state, &p, &len, &tx_a);
	if (e)
		return e;

	if (le32_to_cpu(pkt->input1) >= num_inputs(tx_a))
		return PROTOCOL_ECODE_BAD_INPUTNUM;
	inp_a = tx_input(tx_a, le32_to_cpu(pkt->input1));

	e = unmarshal_and_check_tx(peer->state, &p, &len, &tx_b);
	if (e)
		return e;

	if (len != 0)
		return PROTOCOL_ECODE_INVALID_LEN;

	if (le32_to_cpu(pkt->input2) >= num_inputs(tx_b))
		return PROTOCOL_ECODE_BAD_INPUTNUM;
	inp_b = tx_input(tx_b, le32_to_cpu(pkt->input2));

	if (!structeq(&inp_a->input, &inp_b->input)
	    || inp_a->output != inp_b->output)
		return PROTOCOL_ECODE_BAD_INPUT;

	/* So, they conflict.  First, remove them from pending. */
	drop_pending_tx(peer->state, tx_a);
	drop_pending_tx(peer->state, tx_b);

	hash_tx(tx_a, &sha_a);
	hash_tx(tx_b, &sha_b);

	/* Now, for each block tx_a appears in, if tx_b appears in the same
	 * chain, invalidate the earlier block. */
	for (te_a = txhash_firstval(&peer->state->txhash, &sha_a, &ti_a);
	     te_a;
	     te_a = txhash_nextval(&peer->state->txhash, &sha_a, &ti_a)) {
		for (te_b = txhash_firstval(&peer->state->txhash, &sha_b,&ti_b);
		     te_b;
		     te_b = txhash_nextval(&peer->state->txhash,&sha_b,&ti_b)) {
			struct protocol_proof proof1, proof2;
			struct txhash_elem *te1, *te2;
			unsigned int input1, input2;
			const union protocol_tx *tx1, *tx2;
			const struct protocol_input_ref *refs1, *refs2;

			if (block_preceeds(te_a->block, te_b->block)) {
				te1 = te_a;
				te2 = te_b;
				tx1 = tx_a;
				tx2 = tx_b;
				input1 = le32_to_cpu(pkt->input1);
				input2 = le32_to_cpu(pkt->input2);
			} else if (block_preceeds(te_b->block, te_a->block)) {
				te1 = te_b;
				te2 = te_a;
				tx1 = tx_b;
				tx2 = tx_a;
				input1 = le32_to_cpu(pkt->input2);
				input2 = le32_to_cpu(pkt->input1);
			} else
				continue;

			create_proof(&proof1, te1->block, te1->shardnum,
				     te1->txoff);
			create_proof(&proof2, te2->block, te2->shardnum,
				     te2->txoff);

			refs1 = block_get_refs(te1->block, te1->shardnum,
					       te1->txoff);
			refs2 = block_get_refs(te2->block, te2->shardnum,
					       te2->txoff);

			/* FIXME: when complain deletes from hash, this
			 * iteration will be unreliable! */
			complain_doublespend(peer->state,
					     te1->block, input1, &proof1, 
					     tx1, refs1,
					     te2->block, input2, &proof2, 
					     tx2, refs2);
		}
	}
	return PROTOCOL_ECODE_BAD_INPUT;
}

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

static enum protocol_ecode
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

static enum protocol_ecode
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

	/* In theory we don't need to know the error, but it's good for
	 * diagnosing problems. */
	if (e != le32_to_cpu(pkt->error))
		return PROTOCOL_ECODE_COMPLAINT_INVALID;

	/* Treat tx and refs as blobs for hashing. */
	SHA256_Init(&shactx);
	SHA256_Update(&shactx, tx, txlen);
	SHA256_Double_Final(&shactx, &txrefhash.txhash);

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

static enum protocol_ecode
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

static enum protocol_ecode
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

static enum protocol_ecode
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

static enum protocol_ecode
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
	struct protocol_double_sha sha;

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
	       ((const char *)tx + marshal_tx_len(tx)))
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

	/* Now, check that they proved the referenced position */
	if (block_ancestor(b, le32_to_cpu(ref->blocks_ago)) != inb)
		return PROTOCOL_ECODE_BAD_INPUT;
	if (inpos->shard != ref->shard)
		return PROTOCOL_ECODE_BAD_INPUT;
	if (inpos->txoff != ref->txoff)
		return PROTOCOL_ECODE_BAD_INPUT;

	/* Must be true: otherwise, it would have 0 inputs. */
	assert(tx_type(tx) == TX_NORMAL);

	/* We expect it to be the wrong tx. */
	hash_tx(intx, &sha);
	if (structeq(&tx_input(tx, le32_to_cpu(pkt->inputnum))->input, &sha))
		return PROTOCOL_ECODE_COMPLAINT_INVALID;

	/* Mark it invalid, and tell everyone else if it wasn't already. */
	publish_complaint(peer->state, b, tal_packet_dup(b, pkt), peer);
	return PROTOCOL_ECODE_NONE;
}

static struct io_plan pkt_in(struct io_conn *conn, struct peer *peer)
{
	const struct protocol_net_hdr *hdr = peer->incoming;
	tal_t *ctx = tal_arr(peer, char, 0);
	u32 len;
	enum protocol_pkt_type type;
	enum protocol_ecode err;
	void *reply = NULL;

	len = le32_to_cpu(hdr->len);
	type = le32_to_cpu(hdr->type);

	log_debug(peer->log, "pkt_in: received ");
	log_add_enum(peer->log, enum protocol_pkt_type, type);

	/* Recipient function should steal this if it should outlive us. */
	tal_steal(ctx, peer->incoming);

	err = PROTOCOL_ECODE_UNKNOWN_COMMAND;
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
	case PROTOCOL_PKT_HASHES_IN_BLOCK:
		err = recv_hashes_in_block(peer, peer->incoming);
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
	case PROTOCOL_PKT_TX_BAD_AMOUNT:
		err = recv_tx_bad_amount(peer, peer->incoming);
		break;
	case PROTOCOL_PKT_TX_DOUBLESPEND:
		err = recv_tx_doublespend(peer, peer->incoming);
		break;

	case PROTOCOL_PKT_COMPLAIN_TX_MISORDER:
		err = recv_complain_tx_misorder(peer, peer->incoming);
		break;
	case PROTOCOL_PKT_COMPLAIN_TX_INVALID:
		err = recv_complain_tx_invalid(peer, peer->incoming);
		break;
	case PROTOCOL_PKT_COMPLAIN_TX_BAD_INPUT:
		err = recv_complain_tx_bad_input(peer, peer->incoming);
		break;
	case PROTOCOL_PKT_COMPLAIN_TX_BAD_AMOUNT:
		err = recv_complain_tx_bad_amount(peer, peer->incoming);
		break;
	case PROTOCOL_PKT_COMPLAIN_DOUBLESPEND:
		err = recv_complain_doublespend(peer, peer->incoming);
		break;
	case PROTOCOL_PKT_COMPLAIN_BAD_INPUT_REF:
		err = recv_complain_bad_input_ref(peer, peer->incoming);
		break;

	/* These should not be used after sync. */
	case PROTOCOL_PKT_WELCOME:
	case PROTOCOL_PKT_HORIZON:
	case PROTOCOL_PKT_SYNC:

	/* These ones never valid. */
	case PROTOCOL_PKT_NONE:
	case PROTOCOL_PKT_PIGGYBACK:
	case PROTOCOL_PKT_MAX:
	case PROTOCOL_PKT_PRIV_FULLSHARD:
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
