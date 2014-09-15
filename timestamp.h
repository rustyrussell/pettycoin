#ifndef PETTYCOIN_TIMESTAMP_H
#define PETTYCOIN_TIMESTAMP_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/time/time.h>
#include <stdbool.h>

struct state;
struct block;

bool check_timestamp(struct state *state, u32 timestamp,
		     const struct block *prev);

/* FIXME: Consensus time? */
static inline u32 current_time(void)
{
	return time_now().ts.tv_sec;
}
#endif /* PETTYCOIN_TIMESTAMP_H */
