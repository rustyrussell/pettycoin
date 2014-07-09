#ifndef PETTYCOIN_BLOCKFILE_H
#define PETTYCOIN_BLOCKFILE_H
#include "config.h"
#include <ccan/short_types/short_types.h>

struct state;
struct block;
void load_blocks(struct state *state);

void save_block(struct state *state, struct block *new);

/* We only save transactions within a saved block. */
void save_tx(struct state *state, struct block *block, u16 shard, u8 txoff);

#endif /* PETTYCOIN_BLOCKFILE_H */
