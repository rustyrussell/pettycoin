/* This is a simple hash of IPv4/v6 address and port. */
#include "log.h"
#include "peer.h"
#include "peer_cache.h"
#include "protocol_net.h"
#include "pseudorand.h"
#include "state.h"
#include <ccan/array_size/array_size.h>
#include <ccan/cast/cast.h>
#include <ccan/err/err.h>
#include <ccan/hash/hash.h>
#include <ccan/noerr/noerr.h>
#include <ccan/tal/tal.h>
#include <ccan/time/time.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <stdbool.h>
#include <unistd.h>

/* We don't need more than 2,000 peer addresses. */
#define PEER_HASH_BITS 12
struct peer_cache_file {
	le64 randbytes;
	struct protocol_net_address h[1 << PEER_HASH_BITS];
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
static int new_peer_cache(struct state *state, le64 *randbytes)
{
	int fd;

	log_unusual(state->log, "Creating peer_cache file");

	/* O_EXCL prevents race. */
	fd = open("peer_cache", O_RDWR|O_CREAT|O_EXCL, 0600);
	if (fd < 0)
		fatal(state, "Could not create peer_cache");

	if (!get_lock(fd))
		fatal(state, "Someone else using peer_cache during creation");

	if (RAND_bytes((unsigned char *)randbytes, sizeof(*randbytes)) != 1) {
		unlink_noerr("peer_cache");
		fatal(state, "Could not seed peer_cache: %s",
		     ERR_error_string(ERR_get_error(), NULL));
	}

	if (write(fd, randbytes, sizeof(*randbytes)) != sizeof(*randbytes)) {
		unlink_noerr("peer_cache");
		fatal(state, "Writing seed to peer_cache gave %s",
		      strerror(errno));
	}
	if (ftruncate(fd, sizeof(struct peer_cache_file)) != 0) {
		unlink_noerr("peer_cache");
		fatal(state, "Extending peer_cache gave %s", strerror(errno));
	}
	if (lseek(fd, SEEK_SET, 0) != 0) {
		unlink_noerr("peer_cache");
		fatal(state, "Seeking to start of peer_cache gave %s",
		      strerror(errno));
	}
	return fd;
}

static struct protocol_net_address *
peer_hash_entry(const struct peer_cache *pc,
		const struct protocol_net_address *addr)
{
	u32 h = hash64((u8 *)addr->addr, sizeof(addr->addr),
		       pc->file.randbytes + le16_to_cpu(addr->port));

	return cast_const(struct protocol_net_address *,
			  &pc->file.h[h % ARRAY_SIZE(pc->file.h)]);
}

static bool is_zero_addr(const struct protocol_net_address *addr)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(addr->addr); i++)
		if (addr->addr[i])
			return false;
	return true;
}

static bool check_peer_cache(struct state *state, const struct peer_cache *pc)
{
	unsigned int i;
	u32 time = time_now().ts.tv_sec;

	for (i = 0; i < ARRAY_SIZE(pc->file.h); i++) {
		if (is_zero_addr(&pc->file.h[i]))
			continue;
		if (le32_to_cpu(pc->file.h[i].time) > time) {
			log_unusual(state->log,
				    "peer_cache entry %i is in future (%u > %u)",
				    i, le32_to_cpu(pc->file.h[i].time), time);
			return false;
		}
		if (peer_hash_entry(pc, &pc->file.h[i]) != &pc->file.h[i]) {
			log_unusual(state->log,
				    "peer_cache entry %i should be %li, address ",
				    i, (long)(peer_hash_entry(pc, &pc->file.h[i])
					     - pc->file.h));
			log_add_struct(state->log, struct protocol_net_address,
				       &pc->file.h[i]);
			return false;
		}
	}
	return true;
}

void init_peer_cache(struct state *state)
{
	struct peer_cache *pc;

	state->peer_cache = pc = tal(state, struct peer_cache);

	pc->fd = open("peer_cache", O_RDWR);
	if (pc->fd < 0) {
		pc->fd = new_peer_cache(state, &pc->file.randbytes);
		memset(pc->file.h, 0, sizeof(pc->file.h));
	} else {
		if (!get_lock(pc->fd))
			fatal(state, "Someone else using peer_cache");

		if (read(pc->fd, &pc->file, sizeof(pc->file))!=sizeof(pc->file)
		    || !check_peer_cache(state, pc)) {
			log_unusual(state->log, "Corrupt peer_cache: removing");
			close(pc->fd);
			unlink("peer_cache");
			pc->fd = new_peer_cache(state, &pc->file.randbytes);
		}
	}
}

struct protocol_net_address *peer_cache_first(struct state *state, int *i)
{
	*i = -1;
	return peer_cache_next(state, i);
}

struct protocol_net_address *peer_cache_next(struct state *state, int *i)
{
	BUILD_ASSERT(sizeof(*i) * CHAR_BIT >= PEER_HASH_BITS);

	for ((*i)++; *i < ARRAY_SIZE(state->peer_cache->file.h); (*i)++) {
		if (!is_zero_addr(&state->peer_cache->file.h[*i]))
			return &state->peer_cache->file.h[*i];
	}
	return NULL;
}

static void update_on_disk(struct state *state,
			   struct peer_cache *pc,
			   const struct protocol_net_address *a)
{
	lseek(pc->fd, (char *)a - (char *)&pc->file, SEEK_SET);
	if (write(pc->fd, a, sizeof(*a)) != sizeof(*a))
		log_unusual(state->log, "Trouble writing peer_cache: %s",
			    strerror(errno));
}

void peer_cache_update_uuid(struct state *state, 
			    const struct protocol_net_address *addr)
{
	struct protocol_net_address *a;

	a = peer_hash_entry(state->peer_cache, addr);

	if (same_address(a, addr)) {
		a->uuid = addr->uuid;
		update_on_disk(state, state->peer_cache, a);
	}
}

void peer_cache_refresh(struct state *state, 
			const struct protocol_net_address *addr)
{
	struct protocol_net_address *a;

	a = peer_hash_entry(state->peer_cache, addr);

	/* It might have been deleted from cache, but it's important. */
	*a = *addr;
	a->time = cpu_to_le32(time(NULL));

	log_debug(state->log, "peer_cache update for ");
	log_add_struct(state->log, struct protocol_net_address, a);

	update_on_disk(state, state->peer_cache, a);
}

void peer_cache_add(struct state *state, 
		    const struct protocol_net_address *addr)
{
	struct protocol_net_address *a;
	u32 timestamp;

	a = peer_hash_entry(state->peer_cache, addr);
	if (same_address(a, addr)) {
		log_debug(state->log, "peer_cache adding repeat for ");
		log_add_struct(state->log, struct protocol_net_address, addr);
		return;
	}

	/* Don't ever replace a very new entry. */
	if (le32_to_cpu(a->time) > time(NULL) - PEER_CACHE_PEER_EXTRA)
		return;

	/* 50% chance of replacing different entry. */
	if (!is_zero_addr(a) && isaac64_next_uint(isaac64, 2)) {
		log_debug(state->log, "peer_cache not replacing ");
		log_add_struct(state->log, struct protocol_net_address, a);
		log_add(state->log, " with ");
		log_add_struct(state->log, struct protocol_net_address, addr);
		return;
	}

	log_debug(state->log, "peer_cache replacing ");
	log_add_struct(state->log, struct protocol_net_address, a);

	/* Don't let it get into the future, and consider it never if
	 * older than 3 hours. */
	timestamp = le32_to_cpu(addr->time);
	if (timestamp > time(NULL))
		timestamp = time(NULL);
	else if (timestamp < time(NULL) - PEER_CACHE_MAXSECS)
		timestamp = 0;
	else
		/* Always age indirect entries by 30 minutes */
		timestamp -= PEER_CACHE_PEER_EXTRA;

	/* Copy and update timestamp */
	*a = *addr;
	a->time = cpu_to_le32(timestamp);

	log_add(state->log, " with ");
	log_add_struct(state->log, struct protocol_net_address, a);

	update_on_disk(state, state->peer_cache, a);
}

void peer_cache_del(struct state *state,
		    const struct protocol_net_address *addr,
		    bool del_on_disk)
{
	struct protocol_net_address *a;

	a = peer_hash_entry(state->peer_cache, addr);
	if (same_address(a, addr)) {
		log_debug(state->log, "peer_cache deleting ");
		log_add_struct(state->log, struct protocol_net_address, addr);
		memset(a, 0, sizeof(*a));
		if (del_on_disk) {
			log_debug(state->log, "peer_cache updating disk");
			update_on_disk(state, state->peer_cache, a);
		}
	} else {
		log_debug(state->log, "peer_cache not deleting ");
		log_add_struct(state->log, struct protocol_net_address, addr);
		log_add(state->log, " already have ");
		log_add_struct(state->log, struct protocol_net_address, a);
	}
}
