#include "peer.h"
#include "state.h"
#include "protocol_net.h"
#include "packet.h"
#include "dns.h"
#include "netaddr.h"
#include "welcome.h"
#include "peer_cache.h"
#include <ccan/io/io.h>
#include <ccan/time/time.h>
#include <ccan/tal/tal.h>
#include <ccan/tal/path/path.h>
#include <ccan/err/err.h>
#include <ccan/build_assert/build_assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>

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
	/* Addresses are after header. */
	addr = (void *)(len + 1);

	for (i = 0; i < num; i++)
		peer_cache_add(lookup->state, &addr[i]);

	/* We can now get more from cache. */
	fill_peers(lookup->state);

	return io_close();
}

static struct io_plan read_seed_peers(struct io_conn *conn,
				      struct state *state)
{
	struct peer_lookup *lookup = tal(conn, struct peer_lookup);

	lookup->state = state;
	return io_read_packet(&lookup->pkt, digest_peer_addrs, lookup);
}

/* This gets called when the connection closes, fail or success. */
static void unset_peer_seeding(struct state **statep)
{
	(*statep)->peer_seeding = false;
	fill_peers(*statep);
}

static void seed_peers(struct state *state)
{
	const char *server = "peers.pettycoin.org";
	tal_t *connector;

	/* Don't grab more if we're already doing that. */
	if (state->peer_seeding)
		return;

	if (state->peer_seed_count++ > 2) {
		if (state->developer_test)
			return;

		errx(1, "Failed to connect to any peers, or peer server");
	}

	if (state->developer_test)
		server = "localhost";

	connector = dns_resolve_and_connect(state, server, "9000",
					    read_seed_peers);
	if (!connector)
		warn("Could not connect to %s", server);
	else {
		/* Temporary allocation, to get destructor called. */
		struct state **statep = tal(connector, struct state *);
		state->peer_seeding = true;
		(*statep) = state;
		tal_add_destructor(statep, unset_peer_seeding);
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
			seed_peers(state);
			break;
		}
		fd = socket_for_addr(a);

		/* Maybe we don't speak IPv4/IPv6? */
		if (fd == -1)
			peer_cache_del(state, a, true);
		else {
			new_peer(state, fd, a);
		}
	}
}

static struct io_plan welcome_received(struct io_conn *conn, struct peer *peer)
{
	tal_steal(peer, peer->welcome);
	peer->state->num_peers_connected++;

	/* Are we talking to ourselves? */
	if (peer->welcome->random == peer->state->random_welcome) {
		peer_cache_del(peer->state, &peer->you, true);
		return io_close();
	}

	printf("Welcome received on %p (%llu)!\n", peer, peer->welcome->random);

	/* Update time for this peer. */
	peer_cache_update(peer->state, &peer->you, time_to_sec(time_now()));

	return io_close();
}

static struct io_plan welcome_sent(struct io_conn *conn, struct peer *peer)
{
	return io_read_packet(&peer->welcome, welcome_received, peer);
}

static void destroy_peer(struct peer *peer)
{
	list_del_from(&peer->state->peers, &peer->list);
	if (peer->welcome) {
		peer->state->num_peers_connected--;
	} else {
		/* Only delete from disk cache if we have *some* networking. */
		peer_cache_del(peer->state, &peer->you,
			       peer->state->num_peers_connected != 0);
	}

	peer->state->num_peers--;
	fill_peers(peer->state);
}

static struct io_plan setup_welcome(struct io_conn *unused, struct peer *peer)
{
	peer->outgoing = make_welcome(peer, peer->state, &peer->you);
	return io_write_packet(peer->outgoing, welcome_sent, peer);
}

void new_peer(struct state *state, int fd, const struct protocol_net_address *a)
{
	struct peer *peer = tal(state, struct peer);

	list_add(&state->peers, &peer->list);
	peer->state = state;
	peer->welcome = NULL;

	/* If a, we need to connect to there. */
	if (a) {
		struct addrinfo *ai;

		peer->you = *a;

		ai = mk_addrinfo(peer, a);
		peer->conn = io_new_conn(fd, io_connect(fd, ai, setup_welcome,
							peer));
		tal_free(ai);
	} else {
		if (!get_fd_addr(fd, &peer->you)) {
			close(fd);
			return;
		}
		peer->conn = io_new_conn(fd, setup_welcome(NULL, peer));
	}

	state->num_peers++;
	tal_add_destructor(peer, destroy_peer);

	/* Conn owns us: we vanish when it does. */
	tal_steal(peer->conn, peer);
}

static struct io_plan setup_peer(struct io_conn *conn, struct state *state)
{
	struct peer *peer = tal(conn, struct peer);

	peer->state = state;
	if (!get_fd_addr(io_conn_fd(conn), &peer->you))
		return io_close();

	state->num_peers++;
	tal_add_destructor(peer, destroy_peer);

	return setup_welcome(conn, peer);
}

/* We use this for command line --connect. */
bool new_peer_by_addr(struct state *state, const char *node, const char *port)
{
	return dns_resolve_and_connect(state, node, port, setup_peer);
}
