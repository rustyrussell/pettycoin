/* Helpers for navigating the block chain(s) */
#ifndef PETTYCOIN_CHAIN_H
#define PETTYCOIN_CHAIN_H
#include "config.h"
#include "block.h"
#include <ccan/short_types/short_types.h>
#include <stdbool.h>

struct block;
struct state;

/* Is a in the chain before b (or == b)? */
static inline bool block_preceeds(const struct block *a, const struct block *b)
{
	if (a == b)
		return true;

	if (le32_to_cpu(a->hdr->depth) >= le32_to_cpu(b->hdr->depth))
		return false;

	return block_preceeds(a, b->prev);
}

/* Follow ->prev count times. */
static inline struct block *block_ancestor(const struct block *a,
					   unsigned int count)
{
	struct block *b;

	/* FIXME: Slow!  Optimize if both on main chain! */
	for (b = cast_const(struct block *, a); count && b; count--)
		b = b->prev;

	return b;
}

/* Find common ancestor of curr and target, then first descendent
 * towards target.  NULL if curr == target (or a descendent). */
struct block *step_towards(const struct block *curr, const struct block *target);

/* We've added a new block; update state->longest_chains, state->longest_knowns,
   state->longest_known_descendents as required. */
void update_block_ptrs_new_block(struct state *state, struct block *block);

/* We've added a new shard; update state->longest_chains, state->longest_knowns,
   state->longest_known_descendents as required. */
void update_block_ptrs_new_shard(struct state *state, struct block *block,
				 u16 shardnum);

/* We've invalidated a block. */
void update_block_ptrs_invalidated(struct state *state, const struct block *block);

/* Debugging check */
void check_chains(struct state *state);
#endif /* PETTYCOIN_CHAIN_H */
