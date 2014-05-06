/* Helpers for navigating the block chain(s) */
#ifndef PETTYCOIN_CHAIN_H
#define PETTYCOIN_CHAIN_H
#include <stdbool.h>
#include "protocol.h"

struct block;

/* Is a in the chain before b (or == b)? */
bool block_preceeds(const struct block *a, const struct block *b);

/* Follow ->prev count times. */
struct block *block_ancestor(const struct block *a, unsigned int count);

/* Find common ancestor of curr and target, then first descendent
 * towards target.  NULL if curr == target (or a descendent). */
struct block *step_towards(const struct block *curr, const struct block *target);

#endif /* PETTYCOIN_CHAIN_H */
