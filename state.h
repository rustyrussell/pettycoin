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

	/* Blocks in main chain, in increasing depth order. */
	struct list_head main_chain;

	/* Non-main-chain blocks, unordered. */
	struct list_head off_main;

	/* All transactions in main chain */
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

	/* log */
	struct log *log;
	/* level at which we print. */
	enum log_level log_level;
};

struct state *new_state(bool test_net);

void NORETURN fatal(struct state *state, const char *fmt, ...);

#endif /* PETTYCOIN_STATE_H */
