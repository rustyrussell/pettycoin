#ifndef PETTYCOIN_STATE_H
#define PETTYCOIN_STATE_H
#include <stdbool.h>
#include <ccan/list/list.h>
#include <ccan/short_types/short_types.h>
#include <ccan/endian/endian.h>
#include <ccan/compiler/compiler.h>
#include "thash.h"
#include "log.h"

/* Our local state. */
struct state {
	/* Are we on testnet? */
	bool test_net;

	/* Developer test mode. */
	bool developer_test;

	/* Port number we're listening on. */
	be16 listen_port;

	/* Array of pointers to lists, one for each block depth. */
	struct list_head **block_depth;

	/* Head of overall longest chain (most work).
	 * We'd like to know about entries in this chain. */
	struct block *longest_chain;

	/* Head of longest chain with all transactions known.
	 * This is where we can mine. */
	struct block *longest_known;

	/* Most work descendent of longest_known.  This is in effect
	 * our preferred chain; the fallback if we can't get details
	 * about longest_chain. */
	struct block *longest_known_descendent;

	/* Block we're working on now. */
	struct pending_block *pending;

	/* All transactions. */
	struct thash thash;

	/* Number of current peers (some may be connecting) */
	size_t num_peers;
	size_t num_peers_connected;
	struct list_head peers;
	u64 random_welcome;

	/* Set if we're allowed to get more. */
	bool refill_peers;

	/* Set if we're looking up more seeds. */
	bool peer_seeding;
	unsigned int peer_seed_count;

	/* Peer cache */
	struct peer_cache *peer_cache;

	/* Generation of new blocks. */
	char *generate;
	struct generator *gen;

	/* log */
	struct log *log;
	/* level at which we print. */
	enum log_level log_level;

	/* blocks.list */
	int blockfd;

};

struct state *new_state(bool test_net);

void NORETURN fatal(struct state *state, const char *fmt, ...);

#endif /* PETTYCOIN_STATE_H */
