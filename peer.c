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

	num = le32_to_cpu(*len) / sizeof(*addr);
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

static struct protocol_req_err *protocol_req_err(struct peer *peer,
						 enum protocol_error e)
{
	struct protocol_req_err *pkt = tal(peer, struct protocol_req_err);

	pkt->len = cpu_to_le32(sizeof(*pkt)
			       - sizeof(pkt->len) - sizeof(pkt->type));
	pkt->type = cpu_to_le32(PROTOCOL_REQ_ERR);
	pkt->error = cpu_to_le32(e);

	return pkt;
}

static struct protocol_resp_err *protocol_resp_err(struct peer *peer,
						   enum protocol_error e)
{
	struct protocol_resp_err *pkt = tal(peer, struct protocol_resp_err);

	pkt->len = cpu_to_le32(sizeof(*pkt)
			       - sizeof(pkt->len) - sizeof(pkt->type));
	pkt->type = cpu_to_le32(PROTOCOL_RESP_ERR);
	pkt->error = cpu_to_le32(e);

	return pkt;
}

static struct block *find_mutual_block(struct peer *peer,
				       struct protocol_double_sha *block,
				       u32 num_blocks)
{
	int i;

	log_debug(peer->log, "Peer sent %u blocks", num_blocks);

	for (i = num_blocks - 1; i >= 0; i++) {
		struct block *b = block_find_any(peer->state, &block[i]);

		log_debug(peer->log, "block[%i] ", i);
		log_add_struct(peer->log, struct protocol_double_sha, &block[i]);

		if (b) {
			if (block_in_main(b)) {
				log_add(peer->log, " found in main chain");
				return b;
			}
			log_add(peer->log, "found off main chain: ");
		} else
			log_add(peer->log, "not found ");
	}

	/* This should not happen, since we checked for mutual genesis block! */
	abort();
}

static struct io_plan check_welcome_ack(struct io_conn *conn,
					struct peer *peer)
{
	struct protocol_resp_err *wresp = peer->incoming;
	void *errpkt;

	if (wresp->len != cpu_to_le32(sizeof(*wresp) - sizeof(le32) * 2)) {
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
	peer->mutual = find_mutual_block(peer, peer->welcome->block,
					 le32_to_cpu(peer->welcome->num_blocks));

	log_debug(peer->log, "Peer has mutual block %u", peer->mutual->blocknum);

	fatal(peer->state, "FIXME: do something now!");

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
		log_info(peer->state->log, "Closing connected peer %p (%u left)",
			 peer, peer->state->num_peers_connected);
	} else {
		log_debug(peer->state->log, "Failed connect to peer %p", peer);
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
	peer->welcome = NULL;
	peer->outgoing = NULL;
	peer->incoming = NULL;

	/* If a, we need to connect to there. */
	if (a) {
		struct addrinfo *ai;

		peer->you = *a;

		log_debug(state->log, "Connecting to peer %p (%u) at ",
			  peer, state->num_peers);
		log_add_struct(state->log, struct protocol_net_address,
			       &peer->you);

		ai = mk_addrinfo(peer, a);
		peer->conn = io_new_conn(fd, io_connect(fd, ai, setup_welcome,
							peer));
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
		peer->conn = io_new_conn(fd, setup_welcome(NULL, peer));
		log_debug(state->log, "Peer %p (%u) connected from ",
			  peer, state->num_peers);
		log_add_struct(state->log, struct protocol_net_address,
			       &peer->you);
	}

	if (inet_ntop(AF_INET6, peer->you.addr, name, sizeof(name)) == NULL)
		strcpy(name, "UNCONVERTABLE-IPV6");
	sprintf(name + strlen(name), ":%u:", be16_to_cpu(peer->you.port));
	peer->log = new_log(peer, name, state->log_level, PEER_LOG_MAX);

	state->num_peers++;
	tal_add_destructor(peer, destroy_peer);

	/* Conn owns us: we vanish when it does. */
	tal_steal(peer->conn, peer);
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

	log_info(state->log, "Set up --connect peer %u at ", state->num_peers);
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
