#ifndef PETTYCOIN_STATE_H
#define PETTYCOIN_STATE_H
#include <stdbool.h>
#include <ccan/list/list.h>
#include <ccan/short_types/short_types.h>
#include <ccan/endian/endian.h>
#include "thash.h"

/* Our local state. */
struct state {
	/* Are we on testnet? */
	bool test_net;

	/* Port number we're listening on. */
	be16 listen_port;

	/* This is the main chain, in increasing blocknum order. */
	struct list_head blocks;

	/* All transactions in main chain */
	struct thash thash;

	/* Number of current peers (some may be connecting) */
	size_t num_peers;
	size_t num_peers_connected;

	/* Set if we're allowed to get more. */
	bool refill_peers;

	/* Tal array of peers we want to connect to. */
	struct protocol_net_address *peer_addrs;

	/* Peer cache */
	struct peer_cache *peer_cache;
};

struct state *new_state(bool test_net);

#endif /* PETTYCOIN_STATE_H */
