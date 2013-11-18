#ifndef PETTYCOIN_LOAD_BLOCKS_H
#define PETTYCOIN_LOAD_BLOCKS_H

struct state;
void load_blocks(struct state *state);
void save_block(struct state *state, struct block *new);

#endif /* PETTYCOIN_LOAD_BLOCKS_H */
