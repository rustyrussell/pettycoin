#ifndef PETTYCOIN_BLOCKFILE_H
#define PETTYCOIN_BLOCKFILE_H

struct state;
void load_blocks(struct state *state);
void save_block(struct state *state, struct block *new);

/* We only save transactions within a saved block. */
void save_shard(struct state *state, struct block *block, u16 shardnum);

#endif /* PETTYCOIN_BLOCKFILE_H */