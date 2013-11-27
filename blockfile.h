#ifndef PETTYCOIN_BLOCKFILE_H
#define PETTYCOIN_BLOCKFILE_H

struct state;
void load_blocks(struct state *state);
void save_block(struct state *state, struct block *new);

/* We only save transactions within a saved block. */
void save_transaction(struct state *state, struct block *b, u32 i);

#endif /* PETTYCOIN_BLOCKFILE_H */
