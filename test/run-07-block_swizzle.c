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

#include "../generate.c"
#include "../timestamp.c"
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
#include "../complain.c"
#include "../block.c"
#include "../prev_merkles.c"
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
#include "../block_shard.c"
#include "../tal_packet_proof.c"
#include "easy_genesis.c"

void restart_generating(struct state *state)
{
}

void wake_peers(struct state *state)
{
}

void broadcast_to_peers(struct state *state, const struct protocol_net_hdr *pkt)
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

void todo_forget_about_block(struct state *state,
			     const struct protocol_double_sha *block)
{
}

void create_proof(struct protocol_proof *proof,
		  const struct block *block, u16 shardnum, u8 txoff)
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
	u8 *prev_merkles;
	unsigned int i, j;
	struct block *b[5], *b_alt[3], *prev;
	enum protocol_ecode e;

	pseudorand_init();
	s = new_state(true);
	fake_time = le32_to_cpu(genesis_tlr.timestamp) + 1;
	prev = &genesis;
		
	/* Generate chain of three blocks. */
	for (i = 0; i < 3; i++) {
		prev_merkles = make_prev_merkles(s, prev, helper_addr(1));
		w = new_working_block(s, 0x1ffffff0,
				      prev_merkles, tal_count(prev_merkles),
				      le32_to_cpu(prev->hdr->depth) + 1,
				      next_shard_order(prev),
				      &prev->sha, helper_addr(1));
		for (j = 0; !solve_block(w); j++);
		fake_time++;
		e = check_block_header(s, &w->hdr, w->shard_nums, w->merkles,
				       w->prev_merkles, &w->tailer, &b[i],
				       NULL);
		assert(e == PROTOCOL_ECODE_NONE);
		assert(b[i]);
		block_add(s, b[i]);
		assert(tal_count(s->longest_chains) == 1);
		assert(s->longest_chains[0] == b[i]);
		assert(tal_count(s->longest_knowns) == 1);
		assert(s->longest_knowns[0] == b[i]);
		assert(s->preferred_chain == b[i]);
		prev = b[i];
	}

	/* Now generate an alternate chain of two blocks, from b[0]. */
	prev = b[0];
	for (i = 0; i < 2; i++) {
		prev_merkles = make_prev_merkles(s, prev, helper_addr(2));
		w = new_working_block(s, 0x1ffffff0,
				      prev_merkles, tal_count(prev_merkles),
				      le32_to_cpu(prev->hdr->depth) + 1,
				      next_shard_order(prev),
				      &prev->sha, helper_addr(2));
		for (j = 0; !solve_block(w); j++);
		fake_time++;
		e = check_block_header(s, &w->hdr, w->shard_nums, w->merkles,
				       w->prev_merkles, &w->tailer, &b_alt[i],
				       NULL);
		assert(e == PROTOCOL_ECODE_NONE);
		assert(b_alt[i]);
		block_add(s, b_alt[i]);
		if (i == 0) {
			assert(tal_count(s->longest_chains) == 1);
			assert(tal_count(s->longest_knowns) == 1);
		} else {
			/* Second block brings us equal. */
			assert(tal_count(s->longest_chains) == 2);
			assert(tal_count(s->longest_knowns) == 2);
			assert(s->longest_chains[1] == b_alt[1]);
			assert(s->longest_knowns[1] == b_alt[1]);
		}
		assert(s->longest_chains[0] == b[2]);
		assert(s->longest_knowns[0] == b[2]);
		assert(s->preferred_chain == b[2]);
		prev = b_alt[i];
	}

	/* Now make alternate chain overtake first chain. */
	prev_merkles = make_prev_merkles(s, prev, helper_addr(2));
	w = new_working_block(s, 0x1ffffff0,
			      prev_merkles, tal_count(prev_merkles),
			      le32_to_cpu(prev->hdr->depth) + 1,
			      next_shard_order(prev),
			      &prev->sha, helper_addr(2));
	for (j = 0; !solve_block(w); j++);
	fake_time++;
	e = check_block_header(s, &w->hdr, w->shard_nums, w->merkles,
			       w->prev_merkles, &w->tailer, &b_alt[2], NULL);
	assert(e == PROTOCOL_ECODE_NONE);
	assert(b_alt[2]);
	block_add(s, b_alt[2]);

	assert(tal_count(s->longest_chains) == 1);
	assert(s->longest_chains[0] == b_alt[2]);
	assert(tal_count(s->longest_knowns) == 1);
	assert(s->longest_knowns[0] == b_alt[2]);
	assert(s->preferred_chain == b_alt[2]);

	/* Now make first chain equal again. */
	prev = b[2];
	prev_merkles = make_prev_merkles(s, prev, helper_addr(1));
	w = new_working_block(s, 0x1ffffff0,
			      prev_merkles, tal_count(prev_merkles),
			      le32_to_cpu(prev->hdr->depth) + 1,
			      next_shard_order(prev),
			      &prev->sha, helper_addr(1));
	for (j = 0; !solve_block(w); j++);
	fake_time++;
	e = check_block_header(s, &w->hdr, w->shard_nums, w->merkles,
			       w->prev_merkles, &w->tailer, &b[3],
			       NULL);
	assert(e == PROTOCOL_ECODE_NONE);
	assert(b[3]);
	block_add(s, b[3]);

	assert(tal_count(s->longest_chains) == 2);
	assert(tal_count(s->longest_knowns) == 2);
	assert(s->longest_chains[0] == b_alt[2]);
	assert(s->longest_knowns[0] == b_alt[2]);
	assert(s->longest_chains[1] == b[3]);
	assert(s->longest_knowns[1] == b[3]);
	assert(s->preferred_chain == b_alt[2]);

	/* Now overtake. */
	prev = b[3];
	prev_merkles = make_prev_merkles(s, prev, helper_addr(1));
	w = new_working_block(s, 0x1ffffff0,
			      prev_merkles, tal_count(prev_merkles),
			      le32_to_cpu(prev->hdr->depth) + 1,
			      next_shard_order(prev),
			      &prev->sha, helper_addr(1));
	for (j = 0; !solve_block(w); j++);
	fake_time++;
	e = check_block_header(s, &w->hdr, w->shard_nums, w->merkles,
			       w->prev_merkles, &w->tailer, &b[4],
			       NULL);
	assert(e == PROTOCOL_ECODE_NONE);
	assert(b[4]);
	block_add(s, b[4]);

	assert(tal_count(s->longest_chains) == 1);
	assert(s->longest_chains[0] == b[4]);
	assert(tal_count(s->longest_knowns) == 1);
	assert(s->longest_knowns[0] == b[4]);
	assert(s->preferred_chain == b[4]);

	tal_free(s);
	return 0;
}
