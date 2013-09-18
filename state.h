#ifndef PETTYCOIN_STATE_H
#define PETTYCOIN_STATE_H
#include <stdbool.h>
#include <ccan/list/list.h>
#include "thash.h"

/* Our local state. */
struct state {
	/* Are we on testnet? */
	bool test_net;

	/* This is the main chain, in increasing blocknum order. */
	struct list_head blocks;

	/* All transactions in main chain */
	struct thash thash;
};

struct state *new_state(bool test_net);

#endif /* PETTYCOIN_STATE_H */
