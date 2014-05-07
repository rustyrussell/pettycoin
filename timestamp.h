#ifndef PETTYCOIN_TIMESTAMP_H
#define PETTYCOIN_TIMESTAMP_H
#include <stdbool.h>
#include <ccan/short_types/short_types.h>

struct state;
struct block;

bool check_timestamp(struct state *state, u32 timestamp,
		     const struct block *prev);

u32 current_time(void);

#endif /* PETTYCOIN_TIMESTAMP_H */
