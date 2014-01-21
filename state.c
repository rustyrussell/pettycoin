#include <ccan/tal/tal.h>
#include <ccan/err/err.h>
#include <openssl/bn.h>
#include <unistd.h>
#include "state.h"
#include "genesis.h"
#include "protocol_net.h"
#include "pseudorand.h"
#include "log.h"
#include "peer.h"

/* helper for unit testing, we only want fatal() below.
 * TODO consider moving fatal() to another file.
 * I wonder whether this is a sign that a lot of the code should be in a lib
 * to make integrating into unit testing easier.
 */
#ifndef ONLY_WANT_FATAL

struct state *new_state(bool test_net)
{
	struct state *s = tal(NULL, struct state);

	s->test_net = test_net;
	s->developer_test = false;
	list_head_init(&s->main_chain);
	list_head_init(&s->off_main);
	thash_init(&s->thash);
	s->num_peers = 0;
	s->num_peers_connected = 0;
	list_head_init(&s->peers);
	s->refill_peers = true;
	s->peer_seeding = false;
	s->peer_cache = NULL;
	s->random_welcome = isaac64_next_uint64(isaac64);
	s->peer_seed_count = 0;
	s->log_level = LOG_BROKEN;
	s->log = new_log(s, "", s->log_level, STATE_LOG_MAX);
	s->generate = "pettycoin-generate";
	s->pending = NULL;

	/* Set up genesis block */
	BN_init(&genesis.total_work);
	if (!BN_zero(&genesis.total_work))
		errx(1, "Failed to initialize genesis block");
	genesis.main_chain = true;

	list_add_tail(&s->main_chain, &genesis.list);
	return s;
}

#endif

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
	
