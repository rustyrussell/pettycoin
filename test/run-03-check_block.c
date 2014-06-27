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
#include "../tx_cmp.c"
#include "../marshal.c"
#include "../hash_tx.c"
#include "../create_tx.c"
#include "../check_block.c"
#include "../block.c"
#include "../complain.c"
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

/* Here's a genesis block we created earlier */
static struct protocol_block_header genesis_hdr = {
	.version = 1,
	.features_vote = 0,
	.shard_order = 2,
	.nonce2 = { 0x53, 0x6f, 0x6d, 0x65, 0x20, 0x4e, 0x59, 0x54, 0x20, 0x48, 0x65, 0x61, 0x67  },
	.fees_to = { { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  } }
};
static const struct protocol_block_tailer genesis_tlr = {
	.timestamp = CPU_TO_LE32(1403483533),
	.difficulty = CPU_TO_LE32(0x1ffffff0),
	.nonce1 = CPU_TO_LE32(4823)
};
static const u8 genesis_shardnums[] = {
0, 0, 0, 0
};
static const struct protocol_double_sha genesis_merkles[] = {
{ { 0x6d, 0x07, 0x57, 0x1d, 0xee, 0x2e, 0x35, 0xe1, 0x37, 0x8b, 0xc4, 0x3a, 0x8e, 0x13, 0x88, 0xd2, 0xfe, 0xf6, 0xb3, 0x02, 0x1c, 0xc9, 0x92, 0x4b, 0x88, 0x5d, 0x53, 0xb2, 0xce, 0x39, 0x0e, 0xa8  }} ,
{ { 0x6d, 0x07, 0x57, 0x1d, 0xee, 0x2e, 0x35, 0xe1, 0x37, 0x8b, 0xc4, 0x3a, 0x8e, 0x13, 0x88, 0xd2, 0xfe, 0xf6, 0xb3, 0x02, 0x1c, 0xc9, 0x92, 0x4b, 0x88, 0x5d, 0x53, 0xb2, 0xce, 0x39, 0x0e, 0xa8  }} ,
{ { 0x6d, 0x07, 0x57, 0x1d, 0xee, 0x2e, 0x35, 0xe1, 0x37, 0x8b, 0xc4, 0x3a, 0x8e, 0x13, 0x88, 0xd2, 0xfe, 0xf6, 0xb3, 0x02, 0x1c, 0xc9, 0x92, 0x4b, 0x88, 0x5d, 0x53, 0xb2, 0xce, 0x39, 0x0e, 0xa8  }} ,
{ { 0x6d, 0x07, 0x57, 0x1d, 0xee, 0x2e, 0x35, 0xe1, 0x37, 0x8b, 0xc4, 0x3a, 0x8e, 0x13, 0x88, 0xd2, 0xfe, 0xf6, 0xb3, 0x02, 0x1c, 0xc9, 0x92, 0x4b, 0x88, 0x5d, 0x53, 0xb2, 0xce, 0x39, 0x0e, 0xa8  }} ,
};
static struct tx_shard genesis_shard0 = {
	.shardnum = 0
};
static struct tx_shard genesis_shard1 = {
	.shardnum = 1
};
static struct tx_shard genesis_shard2 = {
	.shardnum = 2
};
static struct tx_shard genesis_shard3 = {
	.shardnum = 3
};
static struct tx_shard *genesis_shards[] = {
	&genesis_shard0, &genesis_shard1, &genesis_shard2, &genesis_shard3
};
struct block genesis = {
	.hdr = &genesis_hdr,
	.shard_nums = genesis_shardnums,
	.merkles = genesis_merkles,
	.tailer = &genesis_tlr,
	.shard = genesis_shards,
	.sha = { { 0xb4, 0xdb, 0xfc, 0xcc, 0x63, 0x2c, 0xe2, 0xd5, 0xa7, 0xb0, 0xae, 0xd6, 0x5c, 0x12, 0x5f, 0x2a, 0x43, 0xed, 0x02, 0xbc, 0xf4, 0xa2, 0x0f, 0x77, 0x46, 0x75, 0xcf, 0x80, 0x7c, 0x8b, 0x82, 0xc6  }}
};

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
	unsigned int i;
	union protocol_tx *t;
	struct protocol_gateway_payment payment;
	struct block *b, *b2;
	struct tx_shard *shard;
	u8 *prev_merkles;
	enum protocol_ecode e;
	struct update update;
	struct protocol_input_ref *refs;

	/* We need enough of state to use the real init function here. */
	pseudorand_init();
	s = new_state(true);

	fake_time = le32_to_cpu(genesis_tlr.timestamp) + 1;

	/* Create a block after that, with a gateway tx in it. */
	prev_merkles = make_prev_merkles(s, &genesis, helper_addr(1));

	/* We should need 1 prev_merkle per shard per block. */
	assert(num_prev_merkles(&genesis) == (1 << genesis.hdr->shard_order));
	assert(tal_count(prev_merkles) == num_prev_merkles(&genesis));

	w = new_working_block(s, 0x1ffffff0,
			      prev_merkles, tal_count(prev_merkles),
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
	update.cookie = t;
	hash_tx_for_block(t, NULL, 0, refs, num_inputs(t), &update.hash);
	assert(add_tx(w, &update));
	for (i = 0; !solve_block(w); i++);

	e = check_block_header(s, &w->hdr, w->shard_nums, w->merkles,
			       w->prev_merkles, &w->tailer, &b, NULL);
	assert(e == PROTOCOL_ECODE_NONE);
	assert(b);
	block_add(s, b);

	/* This is a NOOP, so should succeed. */
	assert(check_block_prev_merkles(s, b));

	/* Put the single tx into the shard. */
	shard = new_shard(s, update.shard, 1);
	shard->txcount = 1;
	shard->u[0].txp = txptr_with_ref(shard, t, refs);

	/* This should all be correct. */
	assert(shard_validate_txs(s, NULL, b, shard, NULL, NULL, NULL)
	       == PROTOCOL_ECODE_NONE);
	assert(check_tx_order(s, b, shard, NULL, NULL));
	assert(shard_belongs_in_block(b, shard));

	force_shard_into_block(s, b, shard);

	/* Should require a prev_merkle per shard for each of 2 prev blocks. */
	assert(num_prev_merkles(b) == (2 << genesis.hdr->shard_order));
	prev_merkles = make_prev_merkles(s, b, helper_addr(1));
	assert(tal_count(prev_merkles) == num_prev_merkles(b));

	/* Solve third block. */
	fake_time++;
	w = new_working_block(s, 0x1ffffff0, prev_merkles, num_prev_merkles(b),
			      le32_to_cpu(b->hdr->depth) + 1,
			      next_shard_order(b),
			      &b->sha, helper_addr(1));
	for (i = 0; !solve_block(w); i++);

	e = check_block_header(s, &w->hdr, w->shard_nums, w->merkles,
			       w->prev_merkles, &w->tailer, &b2, NULL);
	assert(e == PROTOCOL_ECODE_NONE);
	assert(b2);

	/* This should be correct. */
	assert(check_block_prev_merkles(s, b2));

	tal_free(s);
	return 0;
}
