/* Helpers for navigating the block chain(s) */
#ifndef PETTYCOIN_CHAIN_H
#define PETTYCOIN_CHAIN_H
#include <stdbool.h>

struct block;
struct state;

/* Is a in the chain before b (or == b)? */
bool block_preceeds(const struct block *a, const struct block *b);

/* Follow ->prev count times. */
struct block *block_ancestor(const struct block *a, unsigned int count);

/* Find common ancestor of curr and target, then first descendent
 * towards target.  NULL if curr == target (or a descendent). */
struct block *step_towards(const struct block *curr, const struct block *target);

/* We've added a new block; update state->longest_chains, state->longest_knowns,
   state->longest_known_descendents as required. */
void update_block_ptrs_new_block(struct state *state, struct block *block);

/* We've added a new batch; update state->longest_chains, state->longest_knowns,
   state->longest_known_descendents as required. */
void update_block_ptrs_new_batch(struct state *state, struct block *block,
				 unsigned int blocknum);

/* We've invalidated a block. */
void update_block_ptrs_invalidated(struct state *state, const struct block *block);

/* Debugging check */
void check_chains(const struct state *state);
#endif /* PETTYCOIN_CHAIN_H */
