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
#include "../block.c"
#include "../block_shard.c"
#include "../prev_txhashes.c"
#include "../minimal_log.c"
#include "../signature.c"
#include "../txhash.c"
#include "../inputhash.c"
#include "../shard.c"
#include "../chain.c"
#include "../check_tx.c"
#include "../features.c"
#include "../tal_packet.c"
#include "../gateways.c"
#include "../state.c"
#include "../pseudorand.c"
#include "../create_refs.c"
#include "../tx.c"
#include "../proof.c"
#include "easy_genesis.c"

/* AUTOGENERATED MOCKS START */
/* Generated stub for check_tx_refs */
enum ref_ecode check_tx_refs(struct state *state,
			     const struct block *block,
			     const union protocol_tx *tx,
			     const struct protocol_input_ref *refs,
			     unsigned int *bad_ref,
			     struct block **block_referred_to) { fprintf(stderr, "check_tx_refs called!\n"); abort(); }
/* Generated stub for complain_bad_amount */
void complain_bad_amount(struct state *state,
			 struct block *block,
			 const struct protocol_proof *proof,
			 const union protocol_tx *tx,
			 const struct protocol_input_ref *refs,
			 const union protocol_tx *intx[]) { fprintf(stderr, "complain_bad_amount called!\n"); abort(); }
/* Generated stub for complain_bad_input */
void complain_bad_input(struct state *state,
			struct block *block,
			const struct protocol_proof *proof,
			const union protocol_tx *tx,
			const struct protocol_input_ref *refs,
			unsigned int bad_input,
			const union protocol_tx *intx) { fprintf(stderr, "complain_bad_input called!\n"); abort(); }
/* Generated stub for complain_bad_input_ref */
void complain_bad_input_ref(struct state *state,
			    struct block *block,
			    const struct protocol_proof *proof,
			    const union protocol_tx *tx,
			    const struct protocol_input_ref *refs,
			    unsigned int bad_refnum,
			    const struct block *block_referred_to) { fprintf(stderr, "complain_bad_input_ref called!\n"); abort(); }
/* Generated stub for complain_doublespend */
void complain_doublespend(struct state *state,
			  struct block *block1,
			  u32 input1,
			  const struct protocol_proof *proof1,
			  const union protocol_tx *tx1,
			  const struct protocol_input_ref *refs1,
			  struct block *block2,
			  u32 input2,
			  const struct protocol_proof *proof2,
			  const union protocol_tx *tx2,
			  const struct protocol_input_ref *refs2) { fprintf(stderr, "complain_doublespend called!\n"); abort(); }
/* Generated stub for log_to_file */
void log_to_file(int fd, const struct log *log) { fprintf(stderr, "log_to_file called!\n"); abort(); }
/* Generated stub for logv */
void logv(struct log *log, enum log_level level, const char *fmt, va_list ap) { fprintf(stderr, "logv called!\n"); abort(); }
/* Generated stub for steal_pending_txs */
void steal_pending_txs(struct state *state,
		       const struct block *old,
		       const struct block *new) { fprintf(stderr, "steal_pending_txs called!\n"); abort(); }
/* Generated stub for todo_add_get_tx */
void todo_add_get_tx(struct state *state,
		     const struct protocol_double_sha *tx) { fprintf(stderr, "todo_add_get_tx called!\n"); abort(); }
/* Generated stub for todo_add_get_tx_in_block */
void todo_add_get_tx_in_block(struct state *state,
			      const struct protocol_double_sha *block,
			      u16 shardnum, u8 txoff) { fprintf(stderr, "todo_add_get_tx_in_block called!\n"); abort(); }
/* Generated stub for todo_forget_about_block */
void todo_forget_about_block(struct state *state,
			     const struct protocol_double_sha *block) { fprintf(stderr, "todo_forget_about_block called!\n"); abort(); }
/* Generated stub for wake_peers */
void wake_peers(struct state *state) { fprintf(stderr, "wake_peers called!\n"); abort(); }
/* AUTOGENERATED MOCKS END */

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

void todo_add_get_shard(struct state *state,
			const struct protocol_double_sha *block,
			u16 shardnum)
{
}

int main(int argc, char *argv[])
{
	struct state *s;
	struct working_block *w;
	unsigned int i;
	union protocol_tx *t;
	struct protocol_gateway_payment payment;
	struct block *prev, *b;
	struct block_shard *shard;
	u8 *prev_txhashes;
	enum protocol_ecode e;
	struct gen_update update;
	struct protocol_input_ref *refs;
	struct protocol_double_sha sha;

	/* We need enough of state to use the real init function here. */
	pseudorand_init();
	s = new_state(true);
	check_chains(s);

	fake_time = le32_to_cpu(genesis_tlr.timestamp) + 1;

	/* Create a block after that, with a gateway tx in it. */
	prev_txhashes = make_prev_txhashes(s, &genesis, helper_addr(1));

	/* We should need 1 prev_merkle per shard per block. */
	assert(num_prev_txhashes(&genesis) == (1 << genesis.hdr->shard_order));
	assert(tal_count(prev_txhashes) == num_prev_txhashes(&genesis));

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

	/* Put the single tx into the shard. */
	shard = new_block_shard(s, update.shard, 1);
	shard->txcount = 1;
	shard->u[0].txp = txptr_with_ref(shard, t, refs);

	/* This should all be correct. */
	check_block_shard(s, b, shard);
	b->shard[shard->shardnum] = shard;

	/* Should require a prev_merkle per shard for each of 2 prev blocks. */
	assert(num_prev_txhashes(b) == (2 << genesis.hdr->shard_order));
	prev_txhashes = make_prev_txhashes(s, b, helper_addr(1));
	assert(tal_count(prev_txhashes) == num_prev_txhashes(b));

	/* Solve third block. */
	fake_time++;
	w = new_working_block(s, 0x1ffffff0, prev_txhashes, num_prev_txhashes(b),
			      le32_to_cpu(b->hdr->depth) + 1,
			      next_shard_order(b),
			      &b->sha, helper_addr(1));
	for (i = 0; !solve_block(w); i++);

	e = check_block_header(s, &w->hdr, w->shard_nums, w->merkles,
			       w->prev_txhashes, &w->tailer, &prev, &sha);
	assert(e == PROTOCOL_ECODE_NONE);
	assert(prev == b);

	/* This should be correct. */
	assert(check_block_prev_txhashes(s->log, b, &w->hdr, w->prev_txhashes));

	tal_free(s);
	return 0;
}
