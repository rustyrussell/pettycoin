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

#include "../generate.c"
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
static struct block genesis = {
	.hdr = &genesis_hdr,
	.tailer = &genesis_tlr,
	.main_chain = true,
	.sha = { { 0x79, 0xee, 0xfb, 0x0d, 0x2e, 0x57, 0xe8, 0x2d, 0x0a, 0x5a, 0xb0, 0x6c, 0x96, 0x95, 0x8b, 0x0f, 0x56, 0xed, 0x7f, 0x9f, 0x57, 0xd2, 0x72, 0x98, 0xb6, 0x0d, 0xb7, 0xe4, 0xa7, 0x58, 0x00, 0x00  }}
};

int main(int argc, char *argv[])
{
	struct state *s = tal(NULL, struct state);
	struct working_block *w;
	unsigned int i;
	union protocol_transaction *t;
	struct protocol_gateway_payment payment;
	struct block *b, *b2;
	struct transaction_batch *batch;
	u8 *prev_merkles;
	enum protocol_error e;

	/* Sew our genesis block into state. */
	list_head_init(&s->main_chain);
	list_add(&s->main_chain, &genesis.list);

	/* Other minimal setup for state. */
	list_head_init(&s->off_main);
	list_head_init(&s->peers);

	/* Generate a new block, with a transaction in it. */
	fake_time = le32_to_cpu(genesis_tlr.timestamp) + 1;

	/* Now create a block after that, with a gateway transaction in it. */
	w = new_working_block(s, 0x1effffff, NULL, 0, &genesis.sha, helper_addr(1));

	payment.send_amount = cpu_to_le32(1000);
	payment.output_addr = *helper_addr(0);
	t = create_gateway_transaction(s, helper_gateway_public_key(),
				       1, &payment, helper_gateway_key());
	assert(add_transaction(w, t));
	for (i = 0; !solve_block(w); i++);

	e = check_block_header(s, &w->hdr, w->merkles, w->prev_merkles,
			       &w->tailer, &b);
	assert(e == PROTOCOL_ERROR_NONE);
	assert(b);

	/* This is a NOOP, so should succeed. */
	assert(check_block_prev_merkles(s, b));

	/* Put the single transaction into a batch. */
	batch = talz(s, struct transaction_batch);
	batch->trans_start = 0;
	batch->count = 1;
	batch->t[0] = t;

	/* This is the only batch, so it should be full. */
	assert(batch_full(b, batch));

	/* A single transaction is always in order.. */
	assert(check_batch_valid(s, b, batch));

	/* And it should match the merkle hash. */
	assert(put_batch_in_block(s, b, batch));

	/* Should require a single prev_merkle for next block. */
	assert(num_prev_merkles(b) == 1);
	prev_merkles = make_prev_merkles(s, s, b, helper_addr(1));

	/* Solve third block. */
	fake_time++;
	w = new_working_block(s, 0x1effffff, prev_merkles, num_prev_merkles(b),
			      &b->sha, helper_addr(1));
	for (i = 0; !solve_block(w); i++);

	e = check_block_header(s, &w->hdr, w->merkles, w->prev_merkles,
			       &w->tailer, &b2);
	assert(e == PROTOCOL_ERROR_NONE);
	assert(b2);

	/* This should be correct. */
	assert(check_block_prev_merkles(s, b2));

	tal_free(s);
	return 0;
}
