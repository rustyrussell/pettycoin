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
#include "recv_complain.h"
#include "shadouble.h"
#include "shard.h"
#include "state.h"
#include "sync.h"
#include "tal_packet.h"
#include "todo.h"
#include "tx.h"
#include "tx_cmp.h"
#include "tx_in_hashes.h"
#include "welcome.h"
#include <arpa/inet.h>
#include <ccan/array_size/array_size.h>
#include <ccan/build_assert/build_assert.h>
#include <ccan/cast/cast.h>
#include <ccan/err/err.h>
#include <ccan/io/io.h>
#include <ccan/structeq/structeq.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/path/path.h>
#include <ccan/tal/tal.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>

#define MIN_PEERS 16

struct peer_lookup {
	struct state *state;
	struct protocol_pkt_peers *pkt;
};

/* Off state->connecting */
struct peer_connecting {
	struct list_node list;
	struct state *state;
	struct protocol_net_address address;
	struct addrinfo *addrinfo;
};

static bool digest_peer_addrs(struct state *state,
			      struct log *log,
			      const void *data, u32 len)
{
	u32 num, i;
	const struct protocol_net_address *addr = data;

	num = len / sizeof(*addr);
	if (num == 0 || (len % sizeof(*addr)) != 0)
		return false;

	for (i = 0; i < num; i++) {
		log_add(log, " ");
		log_add_struct(log, struct protocol_net_address, &addr[i]);
	}

	for (i = 0; i < num; i++)
		peer_cache_add(state, &addr[i]);

	/* We can now get more from cache. */
	fill_peers(state);
	return true;
}

static struct io_plan *digest_peer_pkt(struct io_conn *conn,
				       struct peer_lookup *lookup)
{
	log_debug(lookup->state->log,
		  "seed server supplied %u bytes of peers",
		  le32_to_cpu(lookup->pkt->len));

	/* Addresses are after header. */
	digest_peer_addrs(lookup->state, lookup->state->log, lookup->pkt + 1,
			  le32_to_cpu(lookup->pkt->len) - sizeof(*lookup->pkt));
	return io_close(conn);
}

static struct io_plan *read_seed_peers(struct io_conn *conn,
				       struct state *state,
				       struct protocol_net_address *addr)
{
	struct peer_lookup *lookup = tal(conn, struct peer_lookup);

	log_debug(state->log, "Connected to seed server, reading peers");
	lookup->state = state;
	return io_read_packet(conn, &lookup->pkt, digest_peer_pkt, lookup);
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

	/* This can happen in the early, sparse network. */
	if (state->peer_seed_count++ > 2) {
		if (state->num_peers || state->num_peers_connecting) {
			log_debug(state->log,
				  "Can't find many peers, settling with %zu",
				  state->num_peers);
			return;
		}

		if (state->nopeers_ok) {
			log_unusual(state->log,
				    "Can't find peers, staying lonely");
			return;
		}
		fatal(state, "Failed to connect to any peers");
	}

	if (state->developer_test) {
		void *data = grab_file(state, "addresses");

		if (!data)
			err(1, "Opening 'addresses' file");

		log_debug(state->log,
			  "seed file supplied %u bytes of peers",
			  le32_to_cpu(tal_count(data) - 1));

		if (!digest_peer_addrs(state, state->log,
				       data, tal_count(data) - 1))
			errx(1, "Invalid contents of addresses file");
		tal_free(data);
		return;
	}

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

static bool empty_uuid(const struct protocol_net_uuid *uuid)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(uuid->bytes); i++)
		if (uuid->bytes[i] != 0)
			return false;
	return true;
}

static bool peer_already(struct state *state,
			 const struct protocol_net_uuid *uuid,
			 const struct peer *exclude)
{
	struct peer *p;

	list_for_each(&state->peers, p, list)
		if (p != exclude && structeq(&p->you.uuid, uuid))
			return true;
	return false;
}

static bool connecting_already(struct state *state,
			       const struct protocol_net_uuid *uuid)
{
	struct peer_connecting *p;

	list_for_each(&state->connecting, p, list)
		if (structeq(&p->address.uuid, uuid))
			return true;
	return false;
}

void fill_peers(struct state *state)
{
	if (!state->refill_peers)
		return;

	while (state->num_peers + state->num_peers_connecting < MIN_PEERS) {
		struct protocol_net_address *a;
		int i, fd;

		for (a = peer_cache_first(state, &i);
		     a;
		     a = peer_cache_next(state, &i)) {
			if (empty_uuid(&a->uuid))
				break;
			if (!connecting_already(state, &a->uuid)
			    && !peer_already(state, &a->uuid, NULL))
				break;
		}

		if (!a) {
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
			connect_to_peer(state, fd, a);
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

/* We know this tx, create packet to prove it. */
static struct protocol_pkt_tx_in_block *pkt_tx_in_block(tal_t *ctx,
							const struct block *b,
							u16 shard,
							u8 txoff)
{
	struct protocol_pkt_tx_in_block *pkt;
	struct protocol_proof proof;

	pkt = tal_packet(ctx, struct protocol_pkt_tx_in_block,
			 PROTOCOL_PKT_TX_IN_BLOCK);

	pkt->err = cpu_to_le32(PROTOCOL_ECODE_NONE);
	create_proof(&proof, b, shard, txoff);
	tal_packet_append_proven_tx(&pkt, &proof,
				    block_get_tx(b, shard, txoff),
				    block_get_refs(b, shard, txoff));
	return pkt;
}

/* We don't know this tx, create packet to reply to pkt_get_tx_in_block. */
static struct protocol_pkt_tx_in_block *
pkt_tx_in_block_err(tal_t *ctx, enum protocol_ecode e,
		    const struct protocol_double_sha *block,
		    u16 shard, u8 txoff)
{
	struct protocol_pkt_tx_in_block *pkt;

	pkt = tal_packet(ctx, struct protocol_pkt_tx_in_block,
			 PROTOCOL_PKT_TX_IN_BLOCK);

	pkt->err = cpu_to_le32(e);
	tal_packet_append_pos(&pkt, block, shard, txoff);
	return pkt;
}

static struct protocol_pkt_block *pkt_block(tal_t *ctx, const struct block *b)
{
	struct protocol_pkt_block *blk;
 
	blk = marshal_block(ctx,
			    b->hdr, b->shard_nums, b->merkles, b->prev_txhashes,
			    b->tailer);

	return blk;
}

/* FIXME: Send these more regularly. */
static struct protocol_pkt_get_peers *pkt_get_peers(tal_t *ctx)
{
	return tal_packet(ctx, struct protocol_pkt_get_peers,
			  PROTOCOL_PKT_GET_PEERS);
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
	struct protocol_pkt_tx_in_block *pkt;

	pkt = pkt_tx_in_block(state, block, shard, txoff);
	send_to_interested_peers(state, exclude,
				 block_get_tx(block, shard, txoff), true, pkt);
	tal_free(pkt);
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
		todo_for_peer(peer, pkt_block(peer, block));
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

static struct io_plan *close_peer(struct io_conn *conn, struct peer *peer)
{
	return io_close(conn);
}

static struct io_plan *plan_output(struct io_conn *conn, struct peer *peer)
{
	void *pkt;

	/* There was an error?  Send that then close. */
	if (peer->error_pkt) {
		log_info(peer->log, "sending error packet ");
		log_add_enum(peer->log, enum protocol_ecode,
			     peer->error_pkt->error);
		return peer_write_packet(peer, peer->error_pkt, close_peer);
	}

	/* We're entirely TODO-driven at this point. */
	pkt = get_todo_pkt(peer->state, peer);
	if (pkt)
		return peer_write_packet(peer, pkt, plan_output);

	/* FIXME: Timeout! */
	if (peer->we_are_syncing && peer->requests_outstanding == 0) {
		/* We're synced (or as far as we can get).  Start
		 * normal operation. */
		log_info(peer->log, "We finished syncing with them");
		peer->we_are_syncing = false;
		return peer_write_packet(peer, set_filter_pkt(peer),
					 plan_output);
	}

	log_debug(peer->log, "Awaiting responses");
	return io_out_wait(conn, peer, plan_output, peer);
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

	if (peer->they_are_syncing)
		log_info(peer->log, "finished syncing with us");

	/* This is our indication to send them unsolicited txs from now on */
	peer->they_are_syncing = false;
	return PROTOCOL_ECODE_NONE;
}

static enum protocol_ecode
recv_get_peers(struct peer *peer, const struct protocol_pkt_peers *pkt,
	       void **reply)
{
	struct protocol_pkt_peers *r;
	struct protocol_net_address *a;
	int i;

	if (le32_to_cpu(pkt->len) != sizeof(*pkt))
		return PROTOCOL_ECODE_INVALID_LEN;

	r = tal_packet(peer, struct protocol_pkt_peers, PROTOCOL_PKT_PEERS);

	for (a = peer_cache_first(peer->state, &i);
	     a;
	     a = peer_cache_next(peer->state, &i))
		tal_packet_append_net_address(&r, a);

	*reply = r;
	return PROTOCOL_ECODE_NONE;
}

static enum protocol_ecode
recv_pkt_peers(struct peer *peer, const struct protocol_pkt_peers *pkt)
{
	unsigned int len = le32_to_cpu(pkt->len) - sizeof(*pkt);

	log_debug(peer->log, "Peer supplied %u peer bytes", len);

	if (!digest_peer_addrs(peer->state, peer->log, pkt + 1, len))
		return PROTOCOL_ECODE_INVALID_LEN;

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

	/* Doesn't matter if input is pending or in block. */
	bad_tx = txhash_gettx(&state->txhash,
			      &tx_input(tx, bad_input_num)->input, TX_PENDING);

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
	/* Can't be NULL, since tx_find_doublespend cant't match hash-only */
	other_tx = txhash_tx(other);

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
	unsigned int i;

	pkt = tal_packet(peer, struct protocol_pkt_tx_bad_amount,
			 PROTOCOL_PKT_TX_BAD_AMOUNT);

	tal_packet_append_tx(&pkt, tx);

	for (i = 0; i < num_inputs(tx); i++) {
		const union protocol_tx *input;
		input = txhash_gettx(&state->txhash,
				     &tx_input(tx, i)->input, TX_PENDING);
		tal_packet_append_tx(&pkt, input);
	}

	todo_for_peer(peer, pkt);
}

static void send_claim_input(struct peer *peer,
			     const struct protocol_double_sha *sha)
{
	struct txhash_elem *te;

	/* Since check_one_input() did this, it must give known tx */
	te = txhash_gettx_ancestor(peer->state, sha,
				   peer->state->longest_knowns[0]);
	assert(te->status == TX_IN_BLOCK);

	todo_for_peer(peer, pkt_tx_in_block(peer, te->u.block,
					    te->shardnum, te->txoff));
}

static enum protocol_ecode
recv_tx(struct peer *peer, const struct protocol_pkt_tx *pkt)
{
	enum protocol_ecode e;
	union protocol_tx *tx;
	struct protocol_double_sha sha;
	u32 txlen = le32_to_cpu(pkt->len) - sizeof(*pkt);
	unsigned int bad_input_num;
	struct txhash_iter it;
	struct txhash_elem *te;
	bool old, already_known;

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
	todo_done_get_tx(peer, &sha, true);

	/* If inputs are malformed, it might not have known so don't hang up. */
	switch (add_pending_tx(peer->state, tx, &sha, &bad_input_num, &old,
			       &already_known)) {
	case ECODE_INPUT_OK:
		if (already_known) {
			log_info(peer->log, "gave us duplicate TX ");
			log_add_struct(peer->log, struct protocol_double_sha,
				       &sha);
			return PROTOCOL_ECODE_NONE;
		}
		break;
	case ECODE_INPUT_UNKNOWN:
		/* We don't resolve inputs which are still pending, so
		 * check here before we bother our peers. */
		if (!txhash_gettx(&peer->state->txhash,
				  &tx_input(tx, bad_input_num)->input,
				  TX_PENDING))
			todo_add_get_tx(peer->state,
					&tx_input(tx, bad_input_num)->input);
		/* We can still use it to resolve hashes. */
		break;

	/* FIXME: Search blocks for this tx, make complaints! */
	case ECODE_INPUT_BAD:
		/* FIXME: Might be nice to tell peer why we're dropping it
		 * if it's too close to the horizon */
		if (!old)
			tell_peer_about_bad_input(peer->state, peer, tx,
						  bad_input_num);
		return PROTOCOL_ECODE_NONE;
	case ECODE_INPUT_BAD_AMOUNT:
		tell_peer_about_bad_amount(peer->state, peer, tx);
		return PROTOCOL_ECODE_NONE;
	case ECODE_INPUT_DOUBLESPEND:
		tell_peer_about_doublespend(peer->state,
					    peer->state->longest_knowns[0],
					    peer, tx, bad_input_num);
		return PROTOCOL_ECODE_NONE;
	case ECODE_INPUT_CLAIM_BAD:
		/* If we tell peer about input, it can figure it out:
		 * if their head block is different, the claim might
		 * be valid for them! */
		assert(tx_type(tx) == TX_CLAIM);
		send_claim_input(peer, &tx_input(tx, 0)->input);
		return PROTOCOL_ECODE_NONE;
	}

	/* See if we can use it to resolve any hashes. */
	for (te = txhash_firstval(&peer->state->txhash, &sha, &it);
	     te;
	     te = txhash_nextval(&peer->state->txhash, &sha, &it)) {
		/* We expect to find outselves in pending. */
		if (te->status != TX_IN_BLOCK)
			continue;

		if (!shard_is_tx(te->u.block->shard[te->shardnum], te->txoff))
			try_resolve_hash(peer->state, peer,
					 te->u.block, te->shardnum, te->txoff);
	}

	/* This is OK for now, will be spammy in real network! */
	log_info(peer->log, "gave us TX ");
	log_add_struct(peer->log, struct protocol_double_sha, &sha);

	/* Tell everyone. */
	send_tx_to_peers(peer->state, peer, tx);

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
	u16 shard;
	u8 txoff;

	if (le32_to_cpu(pkt->len) != sizeof(*pkt))
		return PROTOCOL_ECODE_INVALID_LEN;

	shard = le16_to_cpu(pkt->pos.shard);
	txoff = pkt->pos.txoff;

	b = block_find_any(peer->state, &pkt->pos.block);
	if (!b) {
		/* If we don't know it, that's OK.  Try to find out. */
		todo_add_get_block(peer->state, &pkt->pos.block);
		*reply = pkt_tx_in_block_err(peer, PROTOCOL_ECODE_UNKNOWN_BLOCK,
					     &pkt->pos.block, shard, txoff);
		return PROTOCOL_ECODE_NONE;
	} else if (shard >= num_shards(b->hdr)) {
		log_unusual(peer->log, "Invalid get_tx for shard %u of ",
			    shard);
		log_add_struct(peer->log, struct protocol_double_sha,
			       &pkt->pos.block);
		return PROTOCOL_ECODE_BAD_SHARDNUM;
	} else if (txoff >= b->shard_nums[shard]) {
		log_unusual(peer->log, "Invalid get_tx for txoff %u of shard %u of ",
			    txoff, shard);
		log_add_struct(peer->log, struct protocol_double_sha,
			       &pkt->pos.block);
		return PROTOCOL_ECODE_BAD_TXOFF;
	}

	if (!block_get_tx(b, shard, txoff)) {
		*reply = pkt_tx_in_block_err(peer, PROTOCOL_ECODE_UNKNOWN_TX,
					     &pkt->pos.block, shard, txoff);
		return PROTOCOL_ECODE_NONE;
	}

	*reply = pkt_tx_in_block(peer, b, shard, txoff);
	return PROTOCOL_ECODE_NONE;
}

static enum protocol_ecode
recv_get_tx(struct peer *peer,
	    const struct protocol_pkt_get_tx *pkt, void **reply)
{
	struct txhash_elem *te;
	const union protocol_tx *tx;
	struct protocol_pkt_tx *r;

	if (le32_to_cpu(pkt->len) != sizeof(*pkt))
		return PROTOCOL_ECODE_INVALID_LEN;

	/* First look for one in a block: kill two birds with one stone. */
	te = txhash_gettx_ancestor(peer->state, &pkt->tx,
				   peer->state->preferred_chain);
	if (te && shard_is_tx(te->u.block->shard[te->shardnum], te->txoff)) {
		*reply = pkt_tx_in_block(peer, 
					 te->u.block, te->shardnum, te->txoff);
		return PROTOCOL_ECODE_NONE;
	}

	/* Fallback is to reply with protocol_pkt_tx. */
	r = tal_packet(peer, struct protocol_pkt_tx, PROTOCOL_PKT_TX);

	/* Does this exist at all (maybe in pending)? */
	tx = txhash_gettx(&peer->state->txhash, &pkt->tx, TX_PENDING);
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

	/* Keep proof in case anyone asks. */
	put_proof_in_shard(peer->state, b, &proof->proof);
	/* Copy in tx and refs. */
	put_tx_in_shard(peer->state, peer,
			b, b->shard[shard], proof->proof.pos.txoff,
			txptr_with_ref(b->shard[shard], tx, refs));

	/* This is OK for now, will be spammy in real network! */
	log_info(peer->log, "gave us TX in shard %u, off %u, block %u ",
		 shard, proof->proof.pos.txoff, le32_to_cpu(b->hdr->height));
	log_add_struct(peer->log, struct protocol_double_sha, &sha);

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

enum protocol_ecode
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

		if (te->status != TX_IN_BLOCK)
			continue;

		create_proof(&proof, te->u.block, te->shardnum, te->txoff);
		complain_bad_input(peer->state, te->u.block, &proof, tx,
				   block_get_refs(te->u.block, te->shardnum,
						  te->txoff),
				   le32_to_cpu(pkt->inputnum), in);
	}

	drop_pending_tx(peer->state, tx);
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

		if (te->status != TX_IN_BLOCK)
			continue;

		create_proof(&proof, te->u.block, te->shardnum, te->txoff);
		complain_bad_amount(peer->state, te->u.block, &proof, tx,
				    block_get_refs(te->u.block,
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

again:
	/* Now, for each block tx_a appears in, if tx_b appears in the same
	 * chain, invalidate the earlier block. */
	for (te_a = txhash_firstval(&peer->state->txhash, &sha_a, &ti_a);
	     te_a;
	     te_a = txhash_nextval(&peer->state->txhash, &sha_a, &ti_a)) {

		if (te_a->status != TX_IN_BLOCK)
			continue;

		for (te_b = txhash_firstval(&peer->state->txhash, &sha_b,&ti_b);
		     te_b;
		     te_b = txhash_nextval(&peer->state->txhash,&sha_b,&ti_b)) {
			struct protocol_proof proof1, proof2;
			struct txhash_elem *te1, *te2;
			unsigned int input1, input2;
			const union protocol_tx *tx1, *tx2;
			const struct protocol_input_ref *refs1, *refs2;

			if (te_b->status != TX_IN_BLOCK)
				continue;

			if (block_preceeds(te_a->u.block, te_b->u.block)) {
				te1 = te_a;
				te2 = te_b;
				tx1 = tx_a;
				tx2 = tx_b;
				input1 = le32_to_cpu(pkt->input1);
				input2 = le32_to_cpu(pkt->input2);
			} else if (block_preceeds(te_b->u.block,
						  te_a->u.block)) {
				te1 = te_b;
				te2 = te_a;
				tx1 = tx_b;
				tx2 = tx_a;
				input1 = le32_to_cpu(pkt->input2);
				input2 = le32_to_cpu(pkt->input1);
			} else
				continue;

			create_proof(&proof1, te1->u.block, te1->shardnum,
				     te1->txoff);
			create_proof(&proof2, te2->u.block, te2->shardnum,
				     te2->txoff);

			refs1 = block_get_refs(te1->u.block, te1->shardnum,
					       te1->txoff);
			refs2 = block_get_refs(te2->u.block, te2->shardnum,
					       te2->txoff);

			complain_doublespend(peer->state,
					     te1->u.block, input1, &proof1, 
					     tx1, refs1,
					     te2->u.block, input2, &proof2, 
					     tx2, refs2);
			/* complain_doublespend deletes from hash, so restart */
			goto again;
		}
	}
	return PROTOCOL_ECODE_BAD_INPUT;
}

static struct io_plan *pkt_in(struct io_conn *conn, struct peer *peer)
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
		return io_close(conn);

	case PROTOCOL_PKT_GET_CHILDREN:
		err = recv_get_children(peer, peer->incoming, &reply);
		break;
	case PROTOCOL_PKT_CHILDREN:
		err = recv_children(peer, peer->incoming);
		break;
	case PROTOCOL_PKT_SET_FILTER:
		err = recv_set_filter(peer, peer->incoming);
		break;
	case PROTOCOL_PKT_GET_PEERS:
		err = recv_get_peers(peer, peer->incoming, &reply);
		break;
	case PROTOCOL_PKT_PEERS:
		err = recv_pkt_peers(peer, peer->incoming);
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
	case PROTOCOL_PKT_COMPLAIN_CLAIM_INPUT_INVALID:
		err = recv_complain_claim_input_invalid(peer, peer->incoming);
		break;

	/* These should not be used after sync. */
	case PROTOCOL_PKT_WELCOME:
	case PROTOCOL_PKT_HORIZON:
	case PROTOCOL_PKT_SYNC:

	/* These ones never valid. */
	case PROTOCOL_PKT_NONE:
	case PROTOCOL_PKT_PIGGYBACK:
	case PROTOCOL_PKT_MAX:
		err = PROTOCOL_ECODE_UNKNOWN_COMMAND;
	}

	if (err) {
		peer->error_pkt = err_pkt(peer, err);

		/* In case writer is waiting. */
		io_wake(peer);

		/* Wait for writer to send error. */
		tal_free(ctx);

		/* Writer will close. */
		return io_halfclose(conn);
	}

	/* If we want to send something, queue it for plan_output */
	if (reply)
		todo_for_peer(peer, reply);

	/* FIXME: Do this in ccan/io, with a "before_sleep" callback? */
	/* If things changed, this will make us recheck our pending txs. */
	recheck_pending_txs(peer->state);

	tal_free(ctx);
	return peer_read_packet(peer, pkt_in);
}

static struct io_plan *check_sync_or_horizon(struct io_conn *conn,
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
		return peer_write_packet(peer, err_pkt(peer, err), close_peer);

	/* Ask them for more peers. */
	todo_for_peer(peer, pkt_get_peers(peer));

	/* Time to go duplex on this connection: input reads packet,
	 * output asks about TODOs */
	return io_duplex(conn, peer_read_packet(peer, pkt_in),
			 plan_output(conn, peer));
}

static struct io_plan *recv_sync_or_horizon(struct io_conn *conn,
					    struct peer *peer)
{
	return peer_read_packet(peer, check_sync_or_horizon);
}

static struct io_plan *welcome_received(struct io_conn *conn, struct peer *peer)
{
	struct state *state = peer->state;
	enum protocol_ecode e;
	const struct block *mutual;

	log_debug(peer->log, "Their welcome received");

	tal_steal(peer, peer->welcome);

	e = check_welcome(state, peer->welcome, &peer->welcome_blocks);
	if (e != PROTOCOL_ECODE_NONE) {
		log_unusual(peer->log, "Peer welcome was invalid:");
		log_add_enum(peer->log, enum protocol_ecode, e);
		return peer_write_packet(peer, err_pkt(peer, e), close_peer);
	}

	log_info(peer->log, "Welcome received: listen port is %u",
		 le16_to_cpu(peer->welcome->listen_port));

	/* Are we talking to ourselves? */
	if (structeq(&peer->welcome->uuid, &state->uuid)) {
		log_debug(peer->log, "The peer is ourselves: closing");
		peer_cache_del(state, &peer->you, true);
		return io_close(conn);
	}

	/* Update UUID (it might have changed from what was in cache). */
	peer->you.uuid = peer->welcome->uuid;
	peer_cache_update_uuid(state, &peer->you);

	/* This can happen if using both IPv4 and IPv6. */
	if (peer_already(state, &peer->you.uuid, peer)) {
		log_debug(peer->log, "Duplicate peer: closing");
		return io_close(conn);
	}

	/* Replace port we see with port they want us to connect to. */
	if (peer->welcome->listen_port != peer->you.port) {
		struct protocol_net_address to_addr;
		log_debug(peer->log, "Peer wants us to connect to port %u",
			  le16_to_cpu(peer->welcome->listen_port));
		/* Don't remember this one, we can't connect there. */
		peer_cache_del(state, &peer->you, true);
		to_addr = peer->you;
		to_addr.port = peer->welcome->listen_port;
		peer_cache_add(state, &to_addr);
	}

	/* Create/update time for this peer. */
	peer_cache_refresh(state, &peer->you);

	mutual = mutual_block_search(peer, peer->welcome_blocks,
				     le16_to_cpu(peer->welcome->num_blocks));

	/* If we didn't know their best packet, start querying now. */
	if (!block_find_any(peer->state, &peer->welcome_blocks[0]))
		todo_add_get_block(peer->state, &peer->welcome_blocks[0]);

	return peer_write_packet(peer, sync_or_horizon_pkt(peer, mutual),
				 recv_sync_or_horizon);
}

static struct io_plan *welcome_sent(struct io_conn *conn, struct peer *peer)
{
	log_debug(peer->log, "Our welcome sent, awaiting theirs");
	return io_read_packet(conn, &peer->welcome, welcome_received, peer);
}

static void destroy_peer(struct peer *peer)
{
	list_del_from(&peer->state->peers, &peer->list);
	if (peer->welcome) {
		log_debug(peer->log, "Closing connected peer (%zu left)",
			  peer->state->num_peers);

		if (peer->we_are_syncing) {
			log_add(peer->log, " (didn't finish syncing)");
			/* Don't delete on disk, just in memory. */
			peer_cache_del(peer->state, &peer->you, false);
		}
	} else {
		log_debug(peer->log, "Failed connect to peer %p", peer);
		/* Only delete from disk cache if we have *some* networking. */
		peer_cache_del(peer->state, &peer->you,
			       peer->state->num_peers != 0);
	}

	peer->state->num_peers--;
	bitmap_clear_bit(peer->state->peer_map, peer->peer_num);
	remove_peer_from_todo(peer->state, peer);
	del_log_for_fd(peer->fd, peer->log);
	fill_peers(peer->state);
}

static struct io_plan *setup_welcome(struct io_conn *conn, struct peer *peer)
{
	return peer_write_packet(peer,
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

struct io_plan *peer_connected(struct io_conn *conn, struct state *state,
			       struct protocol_net_address *addr)
{
	/* Conn owns peer; peer vanishes if conn does. */
	struct peer *peer = tal(conn, struct peer);
	char prefix[strlen("Peer ") + STR_MAX_CHARS(unsigned int) + strlen(" @")
		    + INET6_ADDRSTRLEN + strlen(":65000:")];

	peer->peer_num = get_peernum(state->peer_map);
	if (peer->peer_num == MAX_PEERS) {
		log_info(state->log, "Too many peers, closing incoming");
		return io_close(conn);
	}
	bitmap_set_bit(state->peer_map, peer->peer_num);
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
	peer->you = *addr;
	peer->conn = conn;
	peer->fd = io_conn_fd(conn);

	/* Use address as log prefix. */
	sprintf(prefix, "Peer %u @", peer->peer_num);
	if (inet_ntop(AF_INET6, addr->addr, prefix + strlen(prefix),
		      INET6_ADDRSTRLEN) == NULL)
		strcat(prefix, "UNCONVERTABLE-IPV6");
	sprintf(prefix + strlen(prefix), ":%u:", le16_to_cpu(addr->port));
	peer->log = new_log(peer, state->log,
			    prefix, state->log_level, PEER_LOG_MAX);

	state->num_peers++;
	add_log_for_fd(peer->fd, peer->log);
	tal_add_destructor(peer, destroy_peer);

	log_debug(state->log, "Peer %p (%zu) connected from ",
		  peer, state->num_peers);
	log_add_struct(state->log, struct protocol_net_address, &peer->you);

	return setup_welcome(conn, peer);
}

static void connect_failed(struct io_conn *conn,
			   struct peer_connecting *connecting)
{
	struct state *state = connecting->state;

	log_debug(state->log, "Failed connect conn %p", conn);

	/* Only delete from disk cache if we have *some* networking. */
	peer_cache_del(state, &connecting->address, state->num_peers != 0);

	/* Free first, so it decrements connecting count before we call
	 * fill_peers. */
	tal_free(connecting);
	fill_peers(state);
}

static struct io_plan *peer_connected_out(struct io_conn *conn,
					  struct peer_connecting *connecting)
{
	struct state *state = connecting->state;
	struct protocol_net_address addr = connecting->address;

	/* Don't run connect_failed on finish any more. */
	io_set_finish(conn, NULL, NULL);
	tal_free(connecting);

	return peer_connected(conn, state, &addr);
}

static struct io_plan *start_connecting(struct io_conn *conn,
					struct peer_connecting *connecting)
{
	return io_connect(conn, connecting->addrinfo,
			  peer_connected_out, connecting);
}

static void destroy_connecting(struct peer_connecting *connecting)
{
	connecting->state->num_peers_connecting--;
	list_del_from(&connecting->state->connecting, &connecting->list);
}	

void connect_to_peer(struct state *state,
		     int fd, const struct protocol_net_address *a)
{
	struct io_conn *conn;
	struct peer_connecting *connecting;

	log_debug(state->log, "Connecting to peer (%zu) at ",
		  state->num_peers);
	log_add_struct(state->log, struct protocol_net_address, a);

	connecting = tal(state, struct peer_connecting);
	connecting->address = *a;
	connecting->state = state;
	connecting->addrinfo = mk_addrinfo(connecting, a);

	state->num_peers_connecting++;
	list_add_tail(&state->connecting, &connecting->list);
	tal_add_destructor(connecting, destroy_connecting);

	conn = io_new_conn(state, fd, start_connecting, connecting);
	io_set_finish(conn, connect_failed, connecting);
}

/* We use this for command line --connect. */
bool new_peer_by_addr(struct state *state, const char *node, const char *port)
{
	return dns_resolve_and_connect(state, node, port, peer_connected);
}
