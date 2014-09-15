#ifndef PETTYCOIN_STATE_H
#define PETTYCOIN_STATE_H
#include "config.h"
#include "inputhash.h"
#include "log.h"
#include "peer.h"
#include "txhash.h"
#include <ccan/bitmap/bitmap.h>
#include <ccan/compiler/compiler.h>
#include <ccan/endian/endian.h>
#include <ccan/list/list.h>
#include <ccan/short_types/short_types.h>
#include <stdbool.h>

/* Our local state. */
struct state {
	/* Are we on testnet? */
	bool test_net;

	/* Developer test mode. */
	bool developer_test;

	/* Port number we're listening on. */
	be16 listen_port;

	/* Array of pointers to lists, one for each block height. */
	struct list_head **block_height;

	/* Heads of overall longest chains (most work).
	 * We'd like to know about entries in these chains. */
	const struct block **longest_chains;

	/* Heads of longest chains with all transactions known.
	 * This is where we can mine (we use the first one, which
	 * will be an ancestor of longest_chains[0] if possible). */
	const struct block **longest_knowns;

	/* A most work descendent of longest_knowns[0].  This is in effect
	 * our preferred chain; the fallback if we can't get details
	 * about longest_chains. */
	const struct block *preferred_chain;

	/* These are our known unknowns. */
	struct list_head todo;

	/* Blocks we don't know the prev for. */
	struct list_head detached_blocks;

	/* Block we're working on now. */
	struct pending_block *pending;

	/* All transactions. */
	struct txhash txhash;

	/* All inputs to transactions. */
	struct inputhash inputhash;

	/* Are we a bootstrap node? */
	bool nopeers_ok;

	/* Number of current peers */
	size_t num_peers;
	struct list_head peers;
	struct protocol_net_uuid uuid;
	BITMAP_DECLARE(peer_map, MAX_PEERS);

	/* Number we are trying to connect to now. */
	size_t num_peers_connecting;
	/* List of connections we're trying to make. */
	struct list_head connecting;

	/* Features we've warned about. */
	u8 upcoming_features;

	/* Set if we're allowed to get more. */
	bool refill_peers;

	/* Set if we're looking up more seeds. */
	bool peer_seeding;
	unsigned int peer_seed_count;

	/* Peer cache */
	struct peer_cache *peer_cache;

	/* Generation of new blocks. */
	char *generator;
	struct generator *gen;
	struct protocol_address *reward_addr;
	bool require_non_gateway_tx_fee;
	bool require_gateway_tx_fee;

	/* log */
	struct log *log;
	/* level at which we print. */
	enum log_level log_level;

	/* blocks.list */
	int blockfd;

	/* Which shards are we interested in. */
	BITMAP_DECLARE(interests, 65536);
};

struct state *new_state(bool test_net);

void NORETURN fatal(struct state *state, const char *fmt, ...);

#endif /* PETTYCOIN_STATE_H */
