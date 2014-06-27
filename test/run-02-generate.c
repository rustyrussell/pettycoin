#include <ccan/asort/asort.h>
#include <time.h>
#include <assert.h>

/* Override time(NULL) in timestamp.c and generate.c */
static time_t fake_time;
static time_t my_time(time_t *p)
{
	if (p)
		*p = fake_time;
	return fake_time;
}
#define time my_time

/* Override main in generate.c */
#define main generate_main
#include "../timestamp.c"
#include "../generate.c"
#undef main
#undef time

#include "helper_key.h"
#include "helper_gateway_key.h"
#include "../hash_block.c"
#include "../shadouble.c"
#include "../difficulty.c"
#include "../merkle_recurse.c"
#include "../merkle_hashes.c"
#include "../tx_cmp.c"
#include "../marshal.c"
#include "../hash_tx.c"
#include "../create_tx.c"
#include "../signature.c"
#include "../shard.c"
#include "../minimal_log.c"

int main(int argc, char *argv[])
{
	struct state *s = tal(NULL, struct state);
	struct working_block *w, *w2;
	struct protocol_double_sha prev = { .sha = { 0 } };
	unsigned int i;
	struct protocol_double_sha hash, hash2;
	union protocol_tx *t;
	struct protocol_gateway_payment payment;
	struct update update;

	/* This creates a new genesis block. */
	fake_time = 1403486777;
	w = new_working_block(s, 0x1ffffff0, NULL, 0, 0,
			      PROTOCOL_INITIAL_SHARD_ORDER,
			      &prev, helper_addr(0));

	for (i = 0; !solve_block(w); i++);
	assert(i == 87);

	hash_block(&w->hdr, w->shard_nums, w->merkles, w->prev_merkles,
		   &w->tailer, &hash);
	assert(beats_target(&hash, 0x1ffffff0));

	assert(w->hdr.version == current_version());
	assert(w->hdr.features_vote == 0);
	assert(memcmp(w->hdr.nonce2, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
		      sizeof(w->hdr.nonce2)) == 0);
	assert(memcmp(&w->hdr.prev_block, &prev, sizeof(prev)) == 0);
	assert(w->hdr.shard_order == PROTOCOL_INITIAL_SHARD_ORDER);
	assert(w->hdr.num_prev_merkles == 0);
	assert(memcmp(&w->hdr.fees_to, helper_addr(0), sizeof(w->hdr.fees_to))
	       == 0);

	assert(le32_to_cpu(w->tailer.timestamp) == fake_time);
	assert(le32_to_cpu(w->tailer.difficulty) == 0x1ffffff0);
	assert(le32_to_cpu(w->tailer.nonce1) == i);
	for (i = 0; i < (1 << w->hdr.shard_order); i++)
		assert(w->shard_nums[i] == 0);

	/* Now create a block after that, with a gateway tx in it. */
	fake_time++;
	w2 = new_working_block(s, 0x1ffffff0, NULL, 0, 1,
			       w->hdr.shard_order, &hash, helper_addr(1));

	payment.send_amount = cpu_to_le32(1000);
	payment.output_addr = *helper_addr(0);
	t = create_gateway_tx(s, helper_gateway_public_key(),
				       1, &payment, helper_gateway_key(s));
	update.shard = shard_of_tx(t, w->hdr.shard_order);
	update.txoff = 0;
	update.features = 0;
	update.cookie = t;
	hash_tx(t, &update.hash);
	assert(add_tx(w2, &update));

	/* Since tx contains randomness, we don't know how long this
	 * will take */
	for (i = 0; !solve_block(w2); i++);

	hash_block(&w2->hdr, w2->shard_nums, w2->merkles, w2->prev_merkles,
		   &w2->tailer, &hash2);
	assert(beats_target(&hash2, 0x1ffffff0));

	assert(w2->hdr.version == current_version());
	assert(w2->hdr.features_vote == 0);
	assert(memcmp(w2->hdr.nonce2, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
		      sizeof(w2->hdr.nonce2)) == 0);
	assert(memcmp(&w2->hdr.prev_block, &hash, sizeof(hash)) == 0);
	assert(w2->hdr.shard_order == PROTOCOL_INITIAL_SHARD_ORDER);
	assert(le32_to_cpu(w2->hdr.num_prev_merkles) == 0);
	assert(memcmp(&w2->hdr.fees_to, helper_addr(1), sizeof(w2->hdr.fees_to))
	       == 0);

	assert(le32_to_cpu(w2->tailer.timestamp) == fake_time);
	assert(le32_to_cpu(w2->tailer.difficulty) == 0x1ffffff0);
	assert(le32_to_cpu(w2->tailer.nonce1) == i);
	for (i = 0; i < (1 << w2->hdr.shard_order); i++) {
		if (i == update.shard)
			assert(w2->shard_nums[i] == 1);
		else
			assert(w2->shard_nums[i] == 0);
	}

	tal_free(s);
	return 0;
}
