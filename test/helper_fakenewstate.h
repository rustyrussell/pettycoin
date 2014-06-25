#ifndef HELPER_FAKENEWSTATE_H
#define HELPER_FAKENEWSTATE_H
#include <ccan/tal/tal.h>
#include "../state.h"
#include "../protocol.h"

static inline struct state *fake_new_state(void)
{
	struct state *s = tal(NULL, struct state);

	/* longest_knowns is required in check_trans_from_gateway */
	s->longest_knowns = tal_arr(s, const struct block *, 1);

	return s;
}
#endif
