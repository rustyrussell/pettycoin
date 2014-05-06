#include "chain.h"
#include "block.h"
#include <ccan/cast/cast.h>

bool block_preceeds(const struct block *a, const struct block *b)
{
	if (a == b)
		return true;

	if (a->blocknum >= b->blocknum)
		return false;

	return block_preceeds(a, b->prev);
}

struct block *step_towards(const struct block *curr, const struct block *target)
{
	const struct block *prev_target;

	/* Move back towards target. */
	while (curr->blocknum > target->blocknum)
		curr = curr->prev;

	/* Already past it, or equal to it */
	if (curr == target)
		return NULL;

	/* Move target back towards curr. */
	while (target->blocknum > curr->blocknum) {
		prev_target = target;
		target = target->prev;
	}

	/* Now move both back until they're at the common ancestor. */
	while (curr != target) {
		prev_target = target;
		target = target->prev;
		curr = curr->prev;
	}

	/* This is one step towards the target. */
	return cast_const(struct block *, prev_target);
}

/* Follow ->prev count times. */
struct block *block_ancestor(const struct block *a, unsigned int count)
{
	struct block *b;

	/* FIXME: Slow!  Optimize if both on main chain! */
	for (b = cast_const(struct block *, a); b->blocknum != count; b = b->prev);
	return b;
}

