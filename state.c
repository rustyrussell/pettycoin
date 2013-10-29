#include <ccan/tal/tal.h>
#include <ccan/err/err.h>
#include <openssl/bn.h>
#include "state.h"
#include "genesis.h"
#include "protocol_net.h"

struct state *new_state(bool test_net)
{
	struct state *s = tal(NULL, struct state);

	s->test_net = test_net;
	list_head_init(&s->blocks);
	thash_init(&s->thash);
	s->num_peers = 0;
	s->peer_addrs = tal_arr(s, struct protocol_net_address, 0);
	s->refill_peers = true;
	s->peer_cache = NULL;

	/* Set up genesis block */
	BN_init(&genesis.total_work);
	if (!BN_zero(&genesis.total_work))
		errx(1, "Failed to initialize genesis block");
	genesis.peers = &genesis;

	list_add_tail(&s->blocks, &genesis.list);
	return s;
}
