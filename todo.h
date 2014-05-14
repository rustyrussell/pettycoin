#ifndef PETTYCOIN_TODO_H
#define PETTYCOIN_TODO_H
#include <ccan/list/list.h>
#include <ccan/bitmap/bitmap.h>
#include "peer.h"

/* Things we need to find out about from peers. */
struct todo {
	/* Linked from state->todo */
	struct list_node list;

	/* We want to know about this block and batchnum */
	const struct block *block;
	unsigned int batchnum;

	/* Who have we asked? */
	BITMAP_DECLARE(peers_asked, MAX_PEERS);

	/* FIXME: timeout! */
};

void add_block_batch_todo(struct state *state,
			  const struct block *block, unsigned int batchnum);

struct todo *get_todo(struct state *state, const struct peer *from);

void remove_block_batch_todo(struct state *state,
			     const struct block *block, unsigned int batchnum);
#endif /* PETTYCOIN_TODO_H */
