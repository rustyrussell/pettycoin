#ifndef PETTYCOIN_GENERATING_H
#define PETTYCOIN_GENERATING_H
#include "config.h"
#include <ccan/short_types/short_types.h>

struct state;
struct block;
void start_generating(struct state *state);
void restart_generating(struct state *state);

/* We use u32 so we can assert() if they don't fit in u16/u8 respectively */
void tell_generator_new_pending(struct state *state, u32 shard, u32 txoff);
#endif
