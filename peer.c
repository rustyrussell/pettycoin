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
#include <ccan/tal/path/path.h>
#include <ccan/hash/hash.h>
#include <ccan/build_assert/build_assert.h>
#include <ccan/isaac/isaac.h>
#include <ccan/noerr/noerr.h>
#include <ccan/array_size/array_size.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#define MIN_PEERS 16

static struct isaac_ctx isaac;

struct peer_lookup {
	struct state *state;
	void *pkt;
};

/* We don't need more than 2,000 peer addresses. */
#define PEER_HASH_BITS 12
struct peer_hash_entry {
	struct protocol_net_address addr;
	u32 last_used;
};

struct peer_cache_file {
	le64 randbytes;
	struct peer_hash_entry h[1 << PEER_HASH_BITS];
};

struct peer_cache {
	int fd;
	struct peer_cache_file file;
};

static bool get_lock(int fd)
{
	struct flock fl;
	int ret;

	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;

	/* Note: non-blocking! */
	do {
		ret = fcntl(fd, F_SETLK, &fl);
	} while (ret == -1 && errno == EINTR);

	return ret == 0;
}

/* Create (and lock) peer_cache. */
static int new_peer_cache(le64 *randbytes)
{
	int fd;

	/* O_EXCL prevents race. */
	fd = open("peer_cache", O_RDWR|O_CREAT|O_EXCL, 0600);
	if (fd < 0)
		err(1, "Could not create peer_cache");

	if (!get_lock(fd))
		err(1, "Someone else using peer_cache during creation");

	if (RAND_bytes((unsigned char *)randbytes, sizeof(*randbytes)) != 1) {
		unlink_noerr("peer_cache");
		errx(1, "Could not seed peer_cache: %s",
		     ERR_error_string(ERR_get_error(), NULL));
	}

	if (write(fd, randbytes, sizeof(*randbytes)) != sizeof(*randbytes)) {
		unlink_noerr("peer_cache");
		err(1, "Writing seed to peer_cache");
	}
	if (ftruncate(fd, sizeof(struct peer_cache_file)) != 0) {
		unlink_noerr("peer_cache");
		err(1, "Extending peer_cache");
	}
	if (lseek(fd, SEEK_SET, 0) != 0) {
		unlink_noerr("peer_cache");
		err(1, "Seeking to beginning of peer_cache");
	}
	return fd;
}

static bool peer_hash_find(const struct peer_cache *pc,
			   const struct protocol_net_address *addr)
{
	u32 h = hash64((u8 *)addr, sizeof(*addr), pc->file.randbytes);

	return memcmp(addr, &pc->file.h[h].addr, sizeof(*addr)) == 0;
}

static bool is_zero_addr(const struct protocol_net_address *addr)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(addr->addr); i++)
		if (addr->addr[i])
			return false;
	return true;
}

static bool check_peer_cache(const struct peer_cache *pc)
{
	unsigned int i;
	u32 time = time_to_sec(time_now());

	for (i = 0; i < ARRAY_SIZE(pc->file.h); i++) {
		if (is_zero_addr(&pc->file.h[i].addr))
			continue;
		if (pc->file.h[i].last_used > time)
			return false;
		if (!peer_hash_find(pc, &pc->file.h[i].addr))
			return false;
	}
	return true;
}

void init_peer_cache(struct state *state)
{
	unsigned char seedbuf[sizeof(u64)];
	struct peer_cache *pc;

	state->peer_cache = pc = tal(state, struct peer_cache);

	pc->fd = open("peer_cache", O_RDWR);
	if (pc->fd < 0) {
		pc->fd = new_peer_cache(&pc->file.randbytes);
		memset(pc->file.h, 0, sizeof(pc->file.h));
	} else {
		if (!get_lock(pc->fd))
			err(1, "Someone else using peer_cache");

		if (read(pc->fd, &pc->file, sizeof(pc->file))!=sizeof(pc->file)
		    || !check_peer_cache(pc)) {
			warnx("Corrupt peer_cache: resetting");
			close(pc->fd);
			unlink("peer_cache");
			pc->fd = new_peer_cache(&pc->file.randbytes);
		}
	}

	/* PRNG */
	if (RAND_bytes(seedbuf, sizeof(seedbuf)) != 1)
		errx(1, "Could not seed PRNG: %s",
		     ERR_error_string(ERR_get_error(), NULL));

	isaac_init(&isaac, seedbuf, sizeof(seedbuf));
}

static void shuffle(struct protocol_net_address *addrs, unsigned num)
{
	int i;

	for (i = num - 1; i > 0; i--) {
		struct protocol_net_address tmp;
		int r = isaac_next_uint(&isaac, i);
		tmp = addrs[r];
		addrs[r] = addrs[i];
		addrs[i] = tmp;
	}
}

static bool read_peer_cache(struct state *state)
{
	struct peer_cache *pc = state->peer_cache;
	struct protocol_net_address addrs[MIN_PEERS];
	u32 start, i, num = 0;

	BUILD_ASSERT(sizeof(start) * CHAR_BIT >= PEER_HASH_BITS);

	/* Start at a psuedo-random point. */
	i = start = isaac_next_uint(&isaac, ARRAY_SIZE(pc->file.h));

	while (num < ARRAY_SIZE(addrs)) {
		if (!is_zero_addr(&pc->file.h[i].addr))
			addrs[num++] = pc->file.h[i].addr;
		i = (i+1) % ARRAY_SIZE(pc->file.h);
		if (i == start)
			break;
	}

	/* Don't expose too much about our hash table. */
	shuffle(addrs, num);
	return num;
}

static void peer_cache_add(struct state *state, 
			   const struct protocol_net_address *addr,
			   u32 last_used)
{
	struct peer_cache *pc = state->peer_cache;
	u32 h = hash64((u8 *)&addr, sizeof(addr), pc->file.randbytes);

	if (memcmp(&pc->file.h[h].addr, addr, sizeof(*addr)) == 0) {
		/* Don't go backwards (eg. if peer hands us known address. */
		if (last_used < pc->file.h[h].last_used)
			return;
	} else {
		/* 50% chance of replacing different entry. */
		if (!is_zero_addr(&pc->file.h[h].addr)
		    && isaac_next_uint(&isaac, 2))
			return;
	}
	pc->file.h[h].addr = *addr;
	pc->file.h[h].last_used = last_used;
	lseek(pc->fd, offsetof(struct peer_cache_file, h[h]), SEEK_SET);
	if (write(pc->fd, &pc->file.h[h], sizeof(pc->file.h[h]))
	    != sizeof(pc->file.h[h]))
		warn("Trouble writing pc cache");
}

static struct io_plan digest_peer_addrs(struct io_conn *conn,
					struct peer_lookup *lookup)
{
	le32 *len = lookup->pkt;
	u32 num, num_new, i;
	struct protocol_net_address *addr;

	num_new = le32_to_cpu(*len) / sizeof(*addr);
	/* Addresses are after header. */
	addr = (void *)(len + 1);

	for (i = 0; i < num_new; i++)
	peer_cache_add(lookup->state, &addr[i], 0);

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

	/* Update time for this peer. */
	peer_cache_add(peer->state, &peer->you, time_to_sec(time_now()));

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
	/* Update connect time. */
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
