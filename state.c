#include "genesis.h"
#include "log.h"
#include "peer.h"
#include "pending.h"
#include "protocol_net.h"
#include "pseudorand.h"
#include "state.h"
#include <ccan/err/err.h>
#include <ccan/tal/tal.h>
#include <openssl/bn.h>
#include <unistd.h>

/* This keeps valgrind happy! */
static void destroy_state(struct state *state)
{
	txhash_clear(&state->txhash);
	inputhash_clear(&state->inputhash);
	BN_free(&genesis.total_work);
}

struct state *new_state(bool test_net)
{
	struct state *s = tal(NULL, struct state);
	unsigned int i;

	s->test_net = test_net;
	s->developer_test = false;
	s->block_height = tal_arr(s, struct list_head *, 1);
	s->block_height[0] = tal(s->block_height, struct list_head);
	list_head_init(s->block_height[0]);
	s->longest_chains = tal_arr(s, const struct block *, 1);
	s->longest_chains[0] = &genesis;
	s->longest_knowns = tal_arr(s, const struct block *, 1);
	s->longest_knowns[0] = &genesis;
	s->preferred_chain = &genesis;
	list_head_init(&s->todo);
	list_head_init(&s->detached_blocks);
	txhash_init(&s->txhash);
	inputhash_init(&s->inputhash);
	s->nopeers_ok = false;
	s->num_peers = 0;
	list_head_init(&s->peers);
	s->num_peers_connecting = 0;
	list_head_init(&s->connecting);
	s->upcoming_features = 0;
	s->refill_peers = true;
	s->peer_seeding = false;
	s->peer_cache = NULL;
	for (i = 0; i < sizeof(s->uuid.bytes); i++)
		s->uuid.bytes[i] = isaac64_next_uint(isaac64, 256);
	bitmap_zero(s->peer_map, MAX_PEERS);
	s->peer_seed_count = 0;
	s->log_level = LOG_INFORM;
	s->log = new_log(s, NULL, "", s->log_level, STATE_LOG_MAX);
	s->generator = "pettycoin-generate";
	s->reward_addr = NULL;
	bitmap_fill(s->interests, 65536); /* Everything */
	s->require_non_gateway_tx_fee = false;
	s->require_gateway_tx_fee = false;

	tal_add_destructor(s, destroy_state);

	/* Set up genesis block */
	BN_init(&genesis.total_work);
	if (!BN_zero(&genesis.total_work))
		errx(1, "Failed to initialize genesis block");

	list_add_tail(s->block_height[0], &genesis.list);
	s->pending = new_pending_block(s);
	return s;
}

void fatal(struct state *state, const char *fmt, ...)
{
	va_list ap;
	struct peer *peer;

	fprintf(stderr, "FATAL dumping logs:\n");

	va_start(ap, fmt);
	logv(state->log, LOG_BROKEN, fmt, ap);
	va_end(ap);

	/* Dump our log, then the peers. */
	log_to_file(STDERR_FILENO, state->log);
	list_for_each(&state->peers, peer, list)
		log_to_file(STDERR_FILENO, peer->log);

	exit(1);
}
