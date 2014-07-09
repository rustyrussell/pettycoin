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

#include "../timestamp.c"
#include "../generate.c"
#undef main
#undef time
#include "helper_key.h"
#include "helper_gateway_key.h"
#include "../hash_block.c"
#include "../shadouble.c"
#include "../difficulty.c"
#include "../merkle_txs.c"
#include "../merkle_recurse.c"
#include "../merkle_hashes.c"
#include "../tx_cmp.c"
#include "../marshal.c"
#include "../hash_tx.c"
#include "../create_tx.c"
#include "../check_block.c"
#include "../block.c"
#include "../block_shard.c"
#include "../prev_txhashes.c"
#include "../minimal_log.c"
#include "../signature.c"
#include "../txhash.c"
#include "../shard.c"
#include "../chain.c"
#include "../check_tx.c"
#include "../features.c"
#include "../packet.c"
#include "../gateways.c"
#include "../state.c"
#include "../pseudorand.c"
#include "../create_refs.c"
#include "../tx.c"
#include "../proof.c"
#include "easy_genesis.c"

void restart_generating(struct state *state)
{
}

void wake_peers(struct state *state)
{
}

void broadcast_to_peers(struct state *state, const struct protocol_net_hdr *pkt,
			const struct peer *exclude)
{
}

void steal_pending_txs(struct state *state,
				const struct block *old,
				const struct block *new)
{
}

void todo_add_get_shard(struct state *state,
			const struct protocol_double_sha *block,
			u16 shardnum)
{
}

void todo_add_get_txmap(struct state *state,
			const struct protocol_double_sha *block,
			u16 shardnum)
{
}

void todo_forget_about_block(struct state *state,
			     const struct protocol_double_sha *block)
{
}


struct log *new_log(const tal_t *ctx,
		    const struct log *parent,
		    const char *prefix,
		    enum log_level printlevel, size_t max_mem)
{
	return NULL;
}

struct pending_block *new_pending_block(struct state *state)
{
	return NULL;
}

void logv(struct log *log, enum log_level level, const char *fmt, va_list ap)
{
}

void log_to_file(int fd, const struct log *log)
{
}


int main(int argc, char *argv[])
{
	struct state *s;
	struct working_block *w;
	unsigned int i;
	union protocol_tx *t;
	struct protocol_gateway_payment payment;
	struct block *b, *prev;
	struct block_shard *shard;
	u8 *prev_txhashes;
	enum protocol_ecode e;
	struct gen_update update;
	struct protocol_input_ref *refs;
	struct protocol_proof proof;
	struct protocol_double_sha sha;

	/* We need enough of state to use the real init function here. */
	pseudorand_init();
	s = new_state(true);

	fake_time = le32_to_cpu(genesis_tlr.timestamp) + 1;

	/* Create a block with a gateway tx in it. */
	prev_txhashes = make_prev_txhashes(s, &genesis, helper_addr(1));
	w = new_working_block(s, 0x1ffffff0,
			      prev_txhashes, tal_count(prev_txhashes),
			      le32_to_cpu(genesis.hdr->depth) + 1,
			      next_shard_order(&genesis),
			      &genesis.sha, helper_addr(1));

	payment.send_amount = cpu_to_le32(1000);
	payment.output_addr = *helper_addr(0);
	t = create_gateway_tx(s, helper_gateway_public_key(),
				       1, &payment, helper_gateway_key(s));
	/* Gateway txs have empty refs, so this gives 0-len array. */
	refs = create_refs(s, &genesis, t);

	update.shard = shard_of_tx(t, next_shard_order(&genesis));
	update.txoff = 0;
	update.features = 0;
	update.unused = 0;
	hash_tx_and_refs(t, refs, &update.hashes);
	assert(add_tx(w, &update));
	for (i = 0; !solve_block(w); i++);

	e = check_block_header(s, &w->hdr, w->shard_nums, w->merkles,
			       w->prev_txhashes, &w->tailer, &prev, &sha);
	assert(e == PROTOCOL_ECODE_NONE);
	assert(prev == &genesis);

	/* This is a NOOP, so should succeed. */
	assert(check_block_prev_txhashes(s->log, prev,
					 &w->hdr, w->prev_txhashes));

	b = block_add(s, prev, &sha,
		      &w->hdr, w->shard_nums, w->merkles,
		      w->prev_txhashes, &w->tailer);

	/* Put the single tx into a shard. */
	shard = new_block_shard(s, update.shard, 1);
	b->shard[shard->shardnum] = shard;
	put_tx_in_shard(s, b, shard, 0, txptr_with_ref(shard, t, refs));

	/* This should all be correct. */
	check_block_shard(s, b, shard);
	assert(block_all_known(b, NULL));

	/* Create proof for this transaction. */
	create_proof(&proof, shard, 0);

	/* Check it proves correctly. */
	assert(check_proof(&proof, b, update.shard, 0, t, refs));

	tal_free(s);
	return 0;
}
