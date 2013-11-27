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
#include "../minimal_log.c"

int main(int argc, char *argv[])
{
	struct state *s = tal(NULL, struct state);
	struct working_block *w, *w2;
	struct protocol_double_sha prev = { .sha = { 0 } };
	unsigned int i;
	struct protocol_double_sha hash, hash2;
	union protocol_transaction *t;
	struct protocol_gateway_payment payment;
	struct update update;

	/* This creates a new genesis block. */
	fake_time = 1378605752;
	w = new_working_block(s, 0x1effffff, NULL, 0, &prev, helper_addr(0));

	for (i = 0; !solve_block(w); i++);
	assert(i == 104624);

	hash_block(&w->hdr, w->merkles, w->prev_merkles, &w->tailer, &hash);
	assert(beats_target(&hash, 0x1effffff));

	assert(w->hdr.version == current_version());
	assert(w->hdr.features_vote == 0);
	assert(memcmp(w->hdr.nonce2, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
		      sizeof(w->hdr.nonce2)) == 0);
	assert(memcmp(&w->hdr.prev_block, &prev, sizeof(prev)) == 0);
	assert(w->hdr.num_transactions == 0);
	assert(w->hdr.num_prev_merkles == 0);
	assert(memcmp(&w->hdr.fees_to, helper_addr(0), sizeof(w->hdr.fees_to))
	       == 0);

	assert(le32_to_cpu(w->tailer.timestamp) == fake_time);
	assert(le32_to_cpu(w->tailer.difficulty) == 0x1effffff);
	assert(le32_to_cpu(w->tailer.nonce1) == i);

	/* Now create a block after that, with a gateway transaction in it. */
	fake_time++;
	w2 = new_working_block(s, 0x1effffff, NULL, 0, &hash, helper_addr(1));

	payment.send_amount = cpu_to_le32(1000);
	payment.output_addr = *helper_addr(0);
	t = create_gateway_transaction(s, helper_gateway_public_key(),
				       1, 0, &payment, helper_gateway_key());
	update.trans_idx = 0;
	update.features = 0;
	update.cookie = t;
	hash_transaction(t, NULL, 0, &update.hash);
	assert(add_transaction(w2, &update));

	for (i = 0; !solve_block(w2); i++);
	assert(i == 15024);

	hash_block(&w2->hdr, w2->merkles, w2->prev_merkles, &w2->tailer,
		   &hash2);
	assert(beats_target(&hash2, 0x1effffff));

	assert(w2->hdr.version == current_version());
	assert(w2->hdr.features_vote == 0);
	assert(memcmp(w2->hdr.nonce2, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
		      sizeof(w2->hdr.nonce2)) == 0);
	assert(memcmp(&w2->hdr.prev_block, &hash, sizeof(hash)) == 0);
	assert(le32_to_cpu(w2->hdr.num_transactions) == 1);
	assert(le32_to_cpu(w2->hdr.num_prev_merkles) == 0);
	assert(memcmp(&w2->hdr.fees_to, helper_addr(1), sizeof(w2->hdr.fees_to))
	       == 0);

	assert(le32_to_cpu(w2->tailer.timestamp) == fake_time);
	assert(le32_to_cpu(w2->tailer.difficulty) == 0x1effffff);
	assert(le32_to_cpu(w2->tailer.nonce1) == i);

	tal_free(s);
	return 0;
}
