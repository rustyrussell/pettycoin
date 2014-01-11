/* Test we correctly switch to longer chains. */
#include <ccan/asort/asort.h>
#include <time.h>
#include <assert.h>

static time_t fake_time;
static time_t my_time(time_t *p)
{
	if (p)
		*p = fake_time;
	return fake_time;
}

#define main generate_main
#define time my_time
#define restart_generating my_restart_generating

#include "../generate.c"
#include "../generating.c"
#undef restart_generating
#undef main
#undef time
#include "helper_key.h"
#include "helper_gateway_key.h"
#include "../hash_block.c"
#include "../shadouble.c"
#include "../difficulty.c"
#include "../merkle_transactions.c"
#include "../transaction_cmp.c"
#include "../marshall.c"
#include "../hash_transaction.c"
#include "../create_transaction.c"
#include "../check_block.c"
#include "../block.c"
#include "../timestamp.c"
#include "../prev_merkles.c"
#include "../state.c"
#include "../pseudorand.c"
#include "../log.c"
#include "../pending.c"
#include "../blockfile.c"
#include "../packet.c"

/* Here's a genesis block we created earlier */
static struct protocol_block_header genesis_hdr = {
	.version = 1,
	.features_vote = 0,
	.nonce2 = { 0x54, 0x45, 0x53, 0x54, 0x43, 0x4f, 0x44, 0x45, 0x54, 0x45, 0x53, 0x54, 0x45, 0x45  },
	.fees_to = { { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  } }
};
static struct protocol_block_tailer genesis_tlr = {
	.timestamp = CPU_TO_LE32(1378616576),
	.difficulty = CPU_TO_LE32(0x1effffff),
	.nonce1 = CPU_TO_LE32(21216)
};
struct block genesis = {
	.hdr = &genesis_hdr,
	.tailer = &genesis_tlr,
	.main_chain = true,
	.sha = { { 0x79, 0xee, 0xfb, 0x0d, 0x2e, 0x57, 0xe8, 0x2d, 0x0a, 0x5a, 0xb0, 0x6c, 0x96, 0x95, 0x8b, 0x0f, 0x56, 0xed, 0x7f, 0x9f, 0x57, 0xd2, 0x72, 0x98, 0xb6, 0x0d, 0xb7, 0xe4, 0xa7, 0x58, 0x00, 0x00  }}
};

void restart_generating(struct state *state)
{
}

void update_peers_mutual(struct state *state)
{
}

int main(int argc, char *argv[])
{
	struct state *s;
	struct working_block *w;
	unsigned int i, j;
	const struct protocol_double_sha *prev_sha;
	struct block *b[5], *b_alt[3];
	enum protocol_error e;

	pseudorand_init();
	s = new_state(false);
	fake_time = le32_to_cpu(genesis_tlr.timestamp) + 1;
	prev_sha = &genesis.sha;
		
	/* Generate chain of three blocks. */
	for (i = 0; i < 3; i++) {
		w = new_working_block(s, 0x1effffff, NULL, 0, prev_sha,
				      helper_addr(1));
		for (j = 0; !solve_block(w); j++);
		fake_time++;
		e = check_block_header(s, &w->hdr, w->merkles, w->prev_merkles,
				       &w->tailer, &b[i]);
		assert(e == PROTOCOL_ERROR_NONE);
		assert(b[i]);
		block_add(s, b[i]);
		assert(block_in_main(b[i]));
		prev_sha = &b[i]->sha;
	}

	/* Now generate an alternate chain of two blocks, from b[0]. */
	prev_sha = &b[0]->sha;
	for (i = 0; i < 2; i++) {
		w = new_working_block(s, 0x1effffff, NULL, 0, prev_sha,
				      helper_addr(2));
		for (j = 0; !solve_block(w); j++);
		fake_time++;
		e = check_block_header(s, &w->hdr, w->merkles, w->prev_merkles,
				       &w->tailer, &b_alt[i]);
		assert(e == PROTOCOL_ERROR_NONE);
		assert(b_alt[i]);
		block_add(s, b_alt[i]);
		assert(!block_in_main(b_alt[i]));
		prev_sha = &b_alt[i]->sha;
	}

	/* Now make alternate chain overtake first chain. */
	w = new_working_block(s, 0x1effffff, NULL, 0, prev_sha, helper_addr(2));
	for (j = 0; !solve_block(w); j++);
	fake_time++;
	e = check_block_header(s, &w->hdr, w->merkles, w->prev_merkles,
			       &w->tailer, &b_alt[2]);
	assert(e == PROTOCOL_ERROR_NONE);
	assert(b_alt[2]);
	block_add(s, b_alt[2]);

	assert(block_in_main(b_alt[2]));
	assert(block_in_main(b_alt[1]));
	assert(block_in_main(b_alt[0]));
	assert(block_in_main(b[0]));
	assert(!block_in_main(b[1]));
	assert(!block_in_main(b[2]));

	/* Now make first chain overtake again. */
	prev_sha = &b[2]->sha;
	w = new_working_block(s, 0x1effffff, NULL, 0, prev_sha, helper_addr(1));
	for (j = 0; !solve_block(w); j++);
	fake_time++;
	e = check_block_header(s, &w->hdr, w->merkles, w->prev_merkles,
			       &w->tailer, &b[3]);
	assert(e == PROTOCOL_ERROR_NONE);
	assert(b[3]);
	block_add(s, b[3]);
	assert(!block_in_main(b[3]));

	prev_sha = &b[3]->sha;
	w = new_working_block(s, 0x1effffff, NULL, 0, prev_sha, helper_addr(1));
	for (j = 0; !solve_block(w); j++);
	fake_time++;
	e = check_block_header(s, &w->hdr, w->merkles, w->prev_merkles,
			       &w->tailer, &b[4]);
	assert(e == PROTOCOL_ERROR_NONE);
	assert(b[4]);
	block_add(s, b[4]);

	assert(!block_in_main(b_alt[2]));
	assert(!block_in_main(b_alt[1]));
	assert(!block_in_main(b_alt[0]));
	assert(block_in_main(b[0]));
	assert(block_in_main(b[1]));
	assert(block_in_main(b[2]));
	assert(block_in_main(b[3]));
	assert(block_in_main(b[4]));

	tal_free(s);
	return 0;
}
