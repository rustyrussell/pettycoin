#include <ccan/tal/tal.h>
#include <ccan/err/err.h>
#include <openssl/bn.h>
#include "state.h"
#include "genesis.h"
#include "protocol_net.h"
#include "pseudorand.h"

struct state *new_state(bool test_net)
{
	struct state *s = tal(NULL, struct state);

	s->test_net = test_net;
	s->developer_test = false;
	list_head_init(&s->blocks);
	thash_init(&s->thash);
	s->num_peers = 0;
	s->num_peers_connected = 0;
	list_head_init(&s->peers);
	s->refill_peers = true;
	s->peer_seeding = false;
	s->peer_cache = NULL;
	s->random_welcome = isaac64_next_uint64(isaac64);
	s->peer_seed_count = 0;
	printf("My welcome is %llu\n", s->random_welcome);

	/* Set up genesis block */
	BN_init(&genesis.total_work);
	if (!BN_zero(&genesis.total_work))
		errx(1, "Failed to initialize genesis block");
	genesis.peers = &genesis;

	list_add_tail(&s->blocks, &genesis.list);
	return s;
}
