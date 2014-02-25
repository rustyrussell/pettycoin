#include "peer.h"
#include "state.h"
#include "protocol_net.h"
#include "packet.h"
#include "dns.h"
#include "netaddr.h"
#include "welcome.h"
#include "peer_cache.h"
#include "block.h"
#include "log.h"
#include "marshall.h"
#include "check_block.h"
#include "check_transaction.h"
#include "generating.h"
#include "blockfile.h"
#include "pending.h"
#include <ccan/io/io.h>
#include <ccan/time/time.h>
#include <ccan/tal/tal.h>
#include <ccan/tal/path/path.h>
#include <ccan/err/err.h>
#include <ccan/build_assert/build_assert.h>
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

struct pending_trans {
	struct list_node list;
	const union protocol_transaction *t;
};

void remove_trans_from_peers(struct state *state,
			     const union protocol_transaction *t)
{
	struct peer *p;

	list_for_each(&state->peers, p, list) {
		struct pending_trans *pend;

		list_for_each(&p->pending, pend, list) {
			if (pend->t == t) {
				/* Destructor removes from list. */
				tal_free(pend);
				break;
			}
		}
	}
}

static void unlink_pend(struct pending_trans *pend)
{
	list_del(&pend->list);
}
	
void add_trans_to_peers(struct state *state,
			struct peer *exclude,
			const union protocol_transaction *t)
{
	struct peer *peer;

	list_for_each(&state->peers, peer, list) {
		struct pending_trans *pend;

		/* Avoid sending back to peer who told us. */
		if (peer == exclude)
			continue;

		pend = tal(peer, struct pending_trans);
		pend->t = t;
		list_add_tail(&peer->pending, &pend->list);
		tal_add_destructor(pend, unlink_pend);
	}
}

static struct protocol_req_err *protocol_req_err(struct peer *peer,
						 enum protocol_error e)
{
	struct protocol_req_err *pkt = tal(peer, struct protocol_req_err);

	pkt->len = cpu_to_le32(sizeof(*pkt));
	pkt->type = cpu_to_le32(PROTOCOL_REQ_ERR);
	pkt->error = cpu_to_le32(e);

	return pkt;
}

static struct protocol_resp_err *protocol_resp_err(struct peer *peer,
						   enum protocol_error e)
{
	struct protocol_resp_err *pkt = tal(peer, struct protocol_resp_err);

	pkt->len = cpu_to_le32(sizeof(*pkt));
	pkt->type = cpu_to_le32(PROTOCOL_RESP_ERR);
	pkt->error = cpu_to_le32(e);

	return pkt;
}

static struct block *find_mutual_block(struct peer *peer,
				       const struct protocol_double_sha *block)
{
	struct block *b = block_find_any(peer->state, block);

	log_debug(peer->log, "Seeking mutual block ");
	log_add_struct(peer->log, struct protocol_double_sha, block);

	if (b) {
		if (block_in_main(b)) {
			log_add(peer->log, " found in main chain");
			return b;
		}
		log_add(peer->log, "found off main chain.");
	} else
		log_add(peer->log, "not found.");

	return NULL;
}

static struct block *mutual_block_search(struct peer *peer,
					 const struct protocol_double_sha *block,
					 u32 num_blocks)
{
	int i;

	for (i = 0; i < num_blocks; i++) {
		struct block *b = find_mutual_block(peer, &block[i]);
		if (b)
			return b;
	}
	return NULL;
}

static struct io_plan plan_output(struct io_conn *conn, struct peer *peer);

/* Blockchain has been extended/changed. */
void update_peers_mutual(struct state *state)
{
	struct peer *p;

	list_for_each(&state->peers, p, list) {
		/* Not set up yet?  OK. */
		if (!p->mutual)
			continue;

		/* Move back to a mutual block we agree on. */
		while (!block_in_main(p->mutual))
			p->mutual = p->mutual->prev;

		if (p->w && io_is_idle(p->w))
			io_wake(p->w, plan_output(p->w, p));
	}
}

static struct protocol_req_new_block *block_pkt(tal_t *ctx, struct block *b)
{
	struct protocol_req_new_block *blk;
 
	blk = marshall_block(ctx,
			     b->hdr, b->merkles, b->prev_merkles, b->tailer);

	return blk;
}

static struct protocol_req_new_transaction *
trans_pkt(tal_t *ctx, const union protocol_transaction *t)
{
	struct protocol_req_new_transaction *r;
	size_t mlen, len;

	mlen = marshall_transaction_len(t);
	len = sizeof(struct protocol_net_hdr) + mlen;
	
	r = tal_alloc_(ctx, len, false, "struct protocol_req_new_trans");
	r->len = cpu_to_le32(len);
	r->type = cpu_to_le32(PROTOCOL_REQ_NEW_TRANSACTION);
	memcpy(&r->trans, t, mlen);

	return r;
}

static struct io_plan response_sent(struct io_conn *conn, struct peer *peer)
{
	/* We sent a response, now we're ready for another request. */
	peer->response = NULL;
	peer->curr_in_req = PROTOCOL_REQ_NONE;
	return plan_output(conn, peer);
}

static struct io_plan plan_output(struct io_conn *conn, struct peer *peer)
{
	struct block *next;
	struct pending_trans *pend;

	/* There was an error?  Send that then close. */
	if (peer->error_pkt) {
		log_debug(peer->log, "Writing error packet");
		return io_write_packet(peer, peer->error_pkt, io_close_cb);
	}

	/* First, response to their queries. */
	if (peer->response) {
		log_debug(peer->log, "Writing response packet");
		return io_write_packet(peer, peer->response, response_sent);
	}

	/* Are we waiting for a response? */
	if (peer->curr_out_req != PROTOCOL_REQ_NONE) {
		log_debug(peer->log, "Awaiting response packet");
		return io_idle();
	}

	/* Second, do we have any blocks to send? */
	next = list_next(&peer->state->main_chain, peer->mutual, list);
	if (next) {
		log_debug(peer->log, "Sending block %u", next->blocknum);
		peer->curr_out_req = PROTOCOL_REQ_NEW_BLOCK;
		peer->mutual = next;
		return io_write_packet(peer, block_pkt(peer, next),
				       plan_output);
	}

	pend = list_pop(&peer->pending, struct pending_trans, list);
	if (pend) {
		tal_del_destructor(pend, unlink_pend);

		log_debug(peer->log, "Sending transaction ");
		log_add_struct(peer->log, union protocol_transaction, pend->t);
		peer->new_trans_pending = pend;
		peer->curr_out_req = PROTOCOL_REQ_NEW_TRANSACTION;
		return io_write_packet(peer, trans_pkt(peer, pend->t),
				       plan_output);
	}

	/* Otherwise, we're idle. */
	log_debug(peer->log, "Nothing to send");
	return io_idle();
}

/* Returns an error packet if there was trouble. */
static struct protocol_resp_err *
receive_block(struct peer *peer, const struct protocol_req_new_block *req)
{
	struct block *new;
	enum protocol_error e;
	const struct protocol_double_sha *merkles;
	const u8 *prev_merkles;
	const struct protocol_block_tailer *tailer;
	struct protocol_resp_new_block *r;
	const struct protocol_block_header *hdr = (void *)req->block;
	u32 blocklen = le32_to_cpu(req->len) - sizeof(struct protocol_net_hdr);

	e = unmarshall_block(peer->log, blocklen, hdr,
			     &merkles, &prev_merkles, &tailer);
	if (e != PROTOCOL_ERROR_NONE) {
		log_unusual(peer->log, "unmarshalling new block gave %u", e);
		goto fail;
	}

	log_debug(peer->log, "version = %u, features = %u, num_transactions = %u",
		  hdr->version, hdr->features_vote, hdr->num_transactions);

	e = check_block_header(peer->state, hdr, merkles, prev_merkles,
			       tailer, &new);
	if (e != PROTOCOL_ERROR_NONE) {
		log_unusual(peer->log, "checking new block gave %u", e);
		goto fail;
	}

	/* Now new block owns the packet. */
	tal_steal(new, req);

	/* Actually check the previous merkles are correct. */
	if (!check_block_prev_merkles(peer->state, new)) {
		log_unusual(peer->log, "new block has bad prev merkles");
		e = PROTOCOL_ERROR_BAD_PREV_MERKLES;
		/* FIXME: provide proof. */
		goto fail;
	}

	log_debug(peer->log, "New block %u is good!", new->blocknum);

	if (block_find_any(peer->state, &new->sha)) {
		log_debug(peer->log, "already knew about block %u",
			  new->blocknum);
		tal_free(new);
	} else {
		if (block_add(peer->state, new))
			restart_generating(peer->state);

		save_block(peer->state, new);
		/* Update mutual block if this was in main chain. */
		if (new->main_chain) {
			peer->mutual = new;
			/* We may need to revise what we consider
			 * mutual blocks with other peers. */
			update_peers_mutual(peer->state);
		}
	}

	/* Reply, tell them we're all good... */
	r = tal(peer, struct protocol_resp_new_block);
	r->len = cpu_to_le32(sizeof(*r));
	r->type = cpu_to_le32(PROTOCOL_RESP_NEW_BLOCK);
	r->final = list_tail(&peer->state->main_chain, struct block, list)->sha;

	assert(!peer->response);
	peer->response = r;
	return NULL;

fail:
	return protocol_resp_err(peer, e);
}

/* Returns an error packet if there was trouble. */
static struct protocol_resp_new_transaction *
receive_trans(struct peer *peer,
	      const struct protocol_req_new_transaction *req)
{
	enum protocol_error e;
	struct protocol_resp_new_transaction *r;
	u32 translen = le32_to_cpu(req->len) - sizeof(struct protocol_net_hdr);

	r = tal(peer, struct protocol_resp_new_transaction);
	r->len = cpu_to_le32(sizeof(*r));
	r->type = cpu_to_le32(PROTOCOL_RESP_NEW_TRANSACTION);

	e = unmarshall_transaction(&req->trans, translen, NULL);
	if (e)
		goto fail;

	/* FIXME: Handle non-gateway transactions! */
	if (req->trans.hdr.type != TRANSACTION_FROM_GATEWAY) {
		e = PROTOCOL_ERROR_TRANS_UNKNOWN;
		goto fail;
	}

	e = check_trans_from_gateway(peer->state, &req->trans.gateway);
	if (e)
		goto fail;

	/* OK, we own it now. */
	tal_steal(peer->state, req);

	add_pending_transaction(peer, &req->trans);
	r->error = cpu_to_le32(PROTOCOL_ERROR_NONE);
	assert(!peer->response);
	peer->response = r;
	return NULL;

fail:
	r->error = cpu_to_le32(e);
	return r;
}

/* Packet arrives. */
static struct io_plan pkt_in(struct io_conn *conn, struct peer *peer)
{
	const struct protocol_net_hdr *hdr = peer->incoming;
	tal_t *ctx = tal_arr(peer, char, 0);
	struct block *mutual;
	u32 len, type;

	len = le32_to_cpu(hdr->len);
	type = le32_to_cpu(hdr->type);

	/* Recipient function should steal this if it should outlive function. */
	tal_steal(ctx, peer->incoming);

	/* Requests must be one-at-a-time. */
	if (type < PROTOCOL_REQ_MAX  && peer->curr_in_req != PROTOCOL_REQ_NONE) {
		log_unusual(peer->log,
			    "Peer placed request %u while %u still pending",
			    type, peer->curr_in_req);
		return io_close();
	}

	switch (type) {
	case PROTOCOL_REQ_NEW_BLOCK:
		log_debug(peer->log, "Received PROTOCOL_REQ_NEW_BLOCK");
		if (peer->curr_in_req != PROTOCOL_REQ_NONE)
			goto unexpected_req;
		peer->curr_in_req = PROTOCOL_REQ_NEW_BLOCK;
		peer->error_pkt = receive_block(peer, peer->incoming);
		if (peer->error_pkt)
			goto send_error;
			
		break;

	case PROTOCOL_RESP_NEW_BLOCK: {
		struct protocol_resp_new_block *resp = (void *)hdr;
		log_debug(peer->log, "Received PROTOCOL_RESP_NEW_BLOCK");
		if (len != sizeof(*resp))
			goto bad_resp_length;
		if (peer->curr_out_req != PROTOCOL_REQ_NEW_BLOCK)
			goto unexpected_resp;

		/* If we know the block they know, update it. */
		mutual = find_mutual_block(peer, &resp->final);
		if (mutual)
			peer->mutual = mutual;
			
		peer->curr_out_req = PROTOCOL_REQ_NONE;
		break;
	}

	case PROTOCOL_REQ_NEW_TRANSACTION:
		log_debug(peer->log,
			  "Received PROTOCOL_RESP_NEW_TRANSACTION");
		if (peer->curr_in_req != PROTOCOL_REQ_NONE)
			goto unexpected_req;
		peer->curr_in_req = PROTOCOL_REQ_NEW_TRANSACTION;
		peer->error_pkt = receive_trans(peer, peer->incoming);
		if (peer->error_pkt)
			goto send_error;
		break;

	case PROTOCOL_RESP_NEW_TRANSACTION: {
		struct protocol_resp_new_transaction *resp = (void *)hdr;
		log_debug(peer->log, "Received PROTOCOL_RESP_NEW_TRANSACTION");
		if (len != sizeof(*resp))
			goto bad_resp_length;
		if (peer->curr_out_req != PROTOCOL_REQ_NEW_TRANSACTION)
			goto unexpected_resp;

		if (le32_to_cpu(resp->error) != PROTOCOL_ERROR_NONE) {
			log_debug(peer->log,
				  "Error %u on PROTOCOL_RESP_NEW_TRANSACTION ",
				  le32_to_cpu(resp->error));
			log_add_struct(peer->log, union protocol_transaction,
				       peer->new_trans_pending->t);
		}
		tal_free(peer->new_trans_pending);
		peer->curr_out_req = PROTOCOL_REQ_NONE;
		break;
	}

	case PROTOCOL_REQ_ERR:
		log_unusual(peer->log, "Received PROTOCOL_REQ_ERR %u",
			    cpu_to_le32(((struct protocol_req_err*)hdr)->error));
		return io_close();

	case PROTOCOL_RESP_ERR:
		log_unusual(peer->log, "Received PROTOCOL_RESP_ERR %u",
			    cpu_to_le32(((struct protocol_resp_err *)hdr)
					->error));
		return io_close();

	default:
		log_unusual(peer->log, "Unexpected packet %u", type);
		if (type >= PROTOCOL_RESP_NONE)
			return io_close();

		peer->error_pkt = protocol_resp_err(peer,
						    PROTOCOL_UNKNOWN_COMMAND);
	}

	/* Wake output if necessary. */
	if (io_is_idle(peer->w)) {
		log_debug(peer->log, "Waking output");
		io_wake(peer->w, plan_output(peer->w, peer));
	}

	tal_free(ctx);
	return io_read_packet(&peer->incoming, pkt_in, peer);

unexpected_req:
	log_unusual(peer->log, "Peer sent req %u after unacknowledged %u",
		    type, peer->curr_in_req);
	peer->error_pkt = protocol_resp_err(peer, PROTOCOL_SHOULD_BE_WAITING);
	goto send_error;

unexpected_resp:
	log_unusual(peer->log, "Peer responded with %u after we sent %u",
		    type, peer->curr_out_req);
	peer->error_pkt = protocol_req_err(peer, PROTOCOL_INVALID_RESPONSE);
	goto send_error;

bad_resp_length:
	log_unusual(peer->log, "Peer sent %u with bad length %u", type, len);
	peer->error_pkt = protocol_req_err(peer, PROTOCOL_INVALID_LEN);
	goto send_error;

send_error:
	if (io_is_idle(peer->w))
		io_wake(peer->w, plan_output(peer->w, peer));

	tal_free(ctx);
	return io_idle();
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

static struct io_plan check_welcome_ack(struct io_conn *conn,
					struct peer *peer)
{
	struct protocol_resp_err *wresp = peer->incoming;
	void *errpkt;

	assert(conn == peer->w);

	if (wresp->len != cpu_to_le32(sizeof(*wresp))) {
		log_unusual(peer->log, "Bad welcome ack len %u",
			    le32_to_cpu(wresp->len));
		errpkt = protocol_req_err(peer, PROTOCOL_INVALID_LEN);
		goto fail;
	}

	if (wresp->type != cpu_to_le32(PROTOCOL_RESP_ERR)) {
		log_unusual(peer->log, "Peer responded to welcome with %u",
			    le32_to_cpu(wresp->type));
		errpkt = protocol_req_err(peer, PROTOCOL_UNKNOWN_COMMAND);
		goto fail;
	}

	/* It doesn't like us. */
	if (wresp->error != cpu_to_le32(PROTOCOL_ERROR_NONE)) {
		log_unusual(peer->log, "Peer responded to welcome with error %u",
			    le32_to_cpu(wresp->error));
		peer_cache_del(peer->state, &peer->you, true);
		return io_close();
	}

	/* Where do we disagree on main chain? */
	log_debug(peer->log, "Peer sent %u blocks",
		  le32_to_cpu(peer->welcome->num_blocks));
	peer->mutual = mutual_block_search(peer, peer->welcome->block,
					   le32_to_cpu(peer->welcome->num_blocks));

	log_info(peer->log, "Peer has mutual block %u", peer->mutual->blocknum);

	/* Time to go duplex on this connection. */
	peer->r = io_duplex(peer->w,
			    io_read_packet(&peer->incoming, pkt_in, peer));

	/* If one dies, kill both, and don't free peer when w freed! */
	io_set_finish(peer->r, close_reader, peer);
	io_set_finish(peer->w, close_writer, peer);
	tal_steal(peer->state, peer);

	return plan_output(conn, peer);

fail:
	return io_write_packet(peer, errpkt, io_close_cb); 
}

static struct io_plan receive_welcome_ack(struct io_conn *conn,
					  struct peer *peer)
{
	log_debug(peer->log, "Welcome ack sent: receiving theirs");
	return io_read_packet(&peer->incoming, check_welcome_ack, peer);
}

static struct io_plan welcome_received(struct io_conn *conn, struct peer *peer)
{
	struct protocol_resp_err *resp;
	struct state *state = peer->state;

	log_debug(peer->log, "Their welcome received");

	tal_steal(peer, peer->welcome);
	peer->state->num_peers_connected++;

	/* Are we talking to ourselves? */
	if (peer->welcome->random == state->random_welcome) {
		log_unusual(peer->log, "The peer is ourselves: closing");
		peer_cache_del(state, &peer->you, true);
		return io_close();
	}

	resp = protocol_resp_err(peer, check_welcome(state, peer->welcome));
	if (resp->error != cpu_to_le32(PROTOCOL_ERROR_NONE)) {
		log_unusual(peer->log, "Peer welcome was invalid (%u)",
			    le32_to_cpu(resp->error));
		return io_write_packet(peer, resp, io_close_cb);
	}

	log_info(peer->log, "Welcome received: listen port is %u",
		 be16_to_cpu(peer->welcome->listen_port));

	/* Replace port with see with port they want us to connect to. */
	peer->you.port = peer->welcome->listen_port;

	/* Create/update time for this peer. */
	peer_cache_update(state, &peer->you, time_to_sec(time_now()));

	return io_write_packet(peer, resp, receive_welcome_ack);
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
	} else {
		log_debug(peer->log, "Failed connect to peer %p", peer);
		/* Only delete from disk cache if we have *some* networking. */
		peer_cache_del(peer->state, &peer->you,
			       peer->state->num_peers_connected != 0);
	}

	peer->state->num_peers--;
	fill_peers(peer->state);
}

static struct io_plan setup_welcome(struct io_conn *unused, struct peer *peer)
{
	return io_write_packet(peer,
			       make_welcome(peer, peer->state, &peer->you),
			       welcome_sent);
}

void new_peer(struct state *state, int fd, const struct protocol_net_address *a)
{
	struct peer *peer = tal(state, struct peer);
	char name[INET6_ADDRSTRLEN + strlen(":65000:")];

	list_add(&state->peers, &peer->list);
	peer->state = state;
	peer->error_pkt = NULL;
	peer->welcome = NULL;
	peer->outgoing = NULL;
	peer->incoming = NULL;
	peer->response = NULL;
	peer->mutual = NULL;
	peer->curr_in_req = peer->curr_out_req = PROTOCOL_REQ_NONE;
	list_head_init(&peer->pending);

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

	state->num_peers++;
	tal_add_destructor(peer, destroy_peer);

	/* Conn owns us: we vanish when it does. */
	tal_steal(peer->w, peer);
}

static struct io_plan setup_peer(struct io_conn *conn, struct state *state)
{
	struct peer *peer = tal(conn, struct peer);

	peer->state = state;
	if (!get_fd_addr(io_conn_fd(conn), &peer->you)) {
		log_unusual(state->log, "Could not get address for peer: %s",
			    strerror(errno));
		return io_close();
	}

	log_info(state->log, "Set up --connect peer %zu at ", state->num_peers);
	log_add_struct(state->log, struct protocol_net_address, &peer->you);

	state->num_peers++;
	tal_add_destructor(peer, destroy_peer);

	return setup_welcome(conn, peer);
}

/* We use this for command line --connect. */
bool new_peer_by_addr(struct state *state, const char *node, const char *port)
{
	return dns_resolve_and_connect(state, node, port, setup_peer);
}
