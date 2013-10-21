#include "peer.h"
#include "state.h"
#include "protocol_net.h"
#include "packet.h"
#include "dns.h"
#include "netaddr.h"
#include "welcome.h"
#include <ccan/io/io.h>
#include <ccan/err/err.h>
#include <ccan/tal/tal.h>
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
	u32 num, num_new;
	struct protocol_net_address *addr;

	num_new = le32_to_cpu(*len) / sizeof(*addr);
	/* Addresses are after header. */
	addr = (void *)(len + 1);

	/* Append these addresses. */
	num = tal_count(lookup->state->peer_addrs);

	tal_resize(&lookup->state->peer_addrs, num + num_new);
	memcpy(lookup->state->peer_addrs, addr, num_new * sizeof(*addr));
	return io_close();
}

static struct io_plan read_seed_peers(struct io_conn *conn,
				      struct state *state)
{
	struct peer_lookup *lookup = tal(conn, struct peer_lookup);

	lookup->state = state;
	return io_read_packet(&lookup->pkt, digest_peer_addrs, lookup);
}

static bool read_peer_cache(struct state *state)
{
	/* FIXME */
	return false;
}

static bool lookup_peers(struct state *state)
{
	/* If we get some from cache, great. */
	if (read_peer_cache(state))
		return true;

	if (!dns_resolve_and_connect(state, "peers.pettycoin.org", "9000",
				     read_seed_peers)) {
		warn("Could not connect to peers.pettycoin.org");
	} else {
		/* Don't retry while we're waiting... */
		state->refill_peers = false;
		/* FIXME: on failure, re-set that. */
	}

	/* We don't have any (yet) */
	return false;
}

void fill_peers(struct state *state)
{
	if (!state->refill_peers)
		return;

	while (state->num_peers < MIN_PEERS) {
		const struct protocol_net_address *a;
		int fd;
		size_t num;

		/* Need more peer addresses? */
		if (tal_count(state->peer_addrs) == 0) {
			if (!lookup_peers(state))
				return;
		}

		a = &state->peer_addrs[0];
		fd = socket_for_addr(a);

		/* Maybe we don't speak IPv4/IPv6? */
		if (fd != -1)
			new_peer(state, fd, a);

		num = tal_count(state->peer_addrs);
		memmove(state->peer_addrs, state->peer_addrs + 1,
			(num - 1) * sizeof(state->peer_addrs[0]));
		tal_resize(&state->peer_addrs, num - 1);
	}
}

static struct io_plan welcome_received(struct io_conn *conn, struct peer *peer)
{
	tal_steal(peer, peer->welcome);

	printf("Welcome received on %p!\n", peer);
	return io_close();
}

static struct io_plan welcome_sent(struct io_conn *conn, struct peer *peer)
{
	return io_read_packet(&peer->welcome, welcome_received, peer);
}

static void destroy_peer(struct peer *peer)
{
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

	peer->state = state;

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
