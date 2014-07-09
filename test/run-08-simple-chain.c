#include "../chain.c"
#include "../state.c"
#include "../block.c"
#include "../pseudorand.c"
#include "../minimal_log.c"
#include "../difficulty.c"
#include "../block_shard.c"
#include "easy_genesis.c"
#include <ccan/strmap/strmap.h>
#include <ccan/tal/str/str.h>

/* Generated stub for marshal_tx_len */
size_t marshal_tx_len(const union protocol_tx *tx) { abort(); }
/* Generated stub for check_block */
void check_block(struct state *state, const struct block *block) { abort(); }
/* Generated stub for todo_add_get_shard */
void todo_add_get_shard(struct state *state,
			const struct protocol_double_sha *block,
			u16 shardnum) { abort(); }
/* Generated stub for todo_add_get_txmap */
void todo_add_get_txmap(struct state *state,
			const struct protocol_double_sha *block,
			u16 shardnum) { abort(); }
/* Generated stub for steal_pending_txs */
void steal_pending_txs(struct state *state,
		       const struct block *old,
		       const struct block *new) { abort(); }
/* Generated stub for restart_generating */
void restart_generating(struct state *state) { abort(); }
/* Generated stub for todo_forget_about_block */
void todo_forget_about_block(struct state *state,
			     const struct protocol_double_sha *block) { abort(); }
/* Generated stub for wake_peers */
void wake_peers(struct state *state) { abort(); }
/* Generated stub for logv */
void logv(struct log *log, enum log_level level, const char *fmt, va_list ap) { abort(); }
/* Generated stub for log_to_file */
void log_to_file(int fd, const struct log *log) { abort(); }
/* Generated stub for pending_features */
u8 pending_features(const struct block *block) { abort(); }
/* Generated stub for hash_tx_and_refs */
void hash_tx_and_refs(const union protocol_tx *tx,
		      const struct protocol_input_ref *refs,
		      struct protocol_txrefhash *txrefhash) { abort(); }
/* Generated stub for check_tx */
enum protocol_ecode check_tx(struct state *state, const union protocol_tx *tx,
			     const struct block *inside_block) { abort(); }
/* Generated stub for check_tx_inputs */
enum input_ecode check_tx_inputs(struct state *state,
				 const union protocol_tx *tx,
				 unsigned int *bad_input_num) { abort(); }
/* Generated stub for check_proof */
bool check_proof(const struct protocol_proof *proof,
		 const struct block *b,
		 const union protocol_tx *tx,
		 const struct protocol_input_ref *refs) { abort(); }
/* Generated stub for merkle_txs */
void merkle_txs(const struct block_shard *shard,
		struct protocol_double_sha *merkle) { abort(); }
/* Generated stub for inputhash_hashfn */
size_t inputhash_hashfn(const struct inputhash_key *key) { abort(); }
/* Generated stub for inputhash_keyof */
const struct inputhash_key *inputhash_keyof(const struct inputhash_elem *elem) { abort(); }
struct log *new_log(const tal_t *ctx,
		    const struct log *parent, const char *prefix,
		    enum log_level printlevel, size_t max_mem)
{
	return NULL;
}

struct pending_block *new_pending_block(struct state *state)
{
	return NULL;
}

struct strmap_block {
	STRMAP_MEMBERS(struct block *);
};
static struct strmap_block blockmap;

static struct block *add_next_block(struct state *state,
				    struct block *prev, const char *name,
				    unsigned int num_txs)
{
	struct block *b;
	struct protocol_block_header *hdr;
	struct protocol_block_tailer *tailer;
	u8 *shard_nums;
	struct protocol_double_sha dummy = { { 0 } };

	hdr = tal(state, struct protocol_block_header);
	hdr->shard_order = PROTOCOL_INITIAL_SHARD_ORDER;
	hdr->depth = cpu_to_le32(le32_to_cpu(prev->hdr->depth) + 1);

	tailer = tal(state, struct protocol_block_tailer);
	tailer->difficulty = prev->tailer->difficulty;

	shard_nums = tal_arrz(state, u8, 1 << hdr->shard_order);
	shard_nums[0] = num_txs;

	b = new_block(state, &prev->total_work, &dummy, hdr, shard_nums, NULL,
		      NULL, tailer);
	b->prev = prev;
	b->complaint = NULL;
	/* Empty node list so list_del doesn't fail. */
	b->list.prev = b->list.next = &b->list;
	list_add_tail(&prev->children, &b->sibling);

	strmap_add(&blockmap, name, b);
	return b;
}

static void create_chain(struct state *state, struct block *base,
			 const char *prefix, unsigned int num)
{
	unsigned int i;

	for (i = 0; i < num; i++) {
		char *name = tal_fmt(state, "%s-%u", prefix, i);
		base = add_next_block(state, base, name, 0);
	}
}

int main(void)
{
	struct state *state;
	const struct block **bests;

	strmap_init(&blockmap);

	pseudorand_init();
	state = new_state(true);

	/* genesis -> block1-0 ... block1-10. */
	create_chain(state, &genesis, "block1", 10);

	/* Simple step_towards test. */
	assert(step_towards(&genesis, strmap_get(&blockmap, "block1-5"))
	       == strmap_get(&blockmap, "block1-0"));

	assert(step_towards(strmap_get(&blockmap, "block1-5"), &genesis)
	       == NULL);

	/* block1-5 -> block2-0 ... block2-9. */
	create_chain(state, strmap_get(&blockmap, "block1-5"), "block2", 10);

	/* step_towards working over a fork. */
	assert(step_towards(strmap_get(&blockmap, "block1-9"),
			    strmap_get(&blockmap, "block2-9"))
	       == strmap_get(&blockmap, "block2-0"));

	assert(step_towards(strmap_get(&blockmap, "block2-9"),
			    strmap_get(&blockmap, "block1-9"))
	       == strmap_get(&blockmap, "block1-6"));

	/* step_towards goes to destination. */
	assert(step_towards(strmap_get(&blockmap, "block2-9"),
			    strmap_get(&blockmap, "block1-6"))
	       == strmap_get(&blockmap, "block1-6"));

	/* Test find_longest_descendents */
	bests = tal_arr(state, const struct block *, 1);
	bests[0] = &genesis;
	find_longest_descendents(&genesis, &bests);
	assert(tal_count(bests) == 1);
	assert(bests[0] == strmap_get(&blockmap, "block2-9"));

	/* Extend it by one */
	add_next_block(state, bests[0], tal_strdup(state, "block2-10"), 0);
	find_longest_descendents(&genesis, &bests);
	assert(tal_count(bests) == 1);
	assert(bests[0] == strmap_get(&blockmap, "block2-10"));

	/* Now create another one. */
	bests[0] = &genesis;
	add_next_block(state, strmap_get(&blockmap, "block2-9"),
		       tal_strdup(state, "block2-10b"), 0);
	find_longest_descendents(&genesis, &bests);
	assert(tal_count(bests) == 2);
	assert(bests[0] == strmap_get(&blockmap, "block2-10")
	       && bests[1] == strmap_get(&blockmap, "block2-10b"));

	strmap_clear(&blockmap);
	tal_free(state);
	return 0;
}
