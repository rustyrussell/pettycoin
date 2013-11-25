#ifndef PETTYCOIN_BLOCKFILE_H
#define PETTYCOIN_BLOCKFILE_H

struct state;
void load_blocks(struct state *state);
void save_block(struct state *state, struct block *new);

#endif /* PETTYCOIN_BLOCKFILE_H */
