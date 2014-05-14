#include "todo.h"
#include "state.h"
#include <ccan/tal/tal.h>

/* FIXME: Slow! */
static struct todo *find_todo(struct state *state,
			      const struct block *block, unsigned int batchnum)
{
	struct todo *i;

	list_for_each(&state->todo, i, list) {
		if (i->block == block && i->batchnum == batchnum)
			return i;
	}
	return NULL;
}

void add_block_batch_todo(struct state *state,
			  const struct block *block, unsigned int batchnum)
{
	struct todo *todo;

	/* Don't add duplicates. */
	todo = find_todo(state, block, batchnum);
	if (todo)
		return;

	todo = tal(state, struct todo);

	todo->block = block;
	todo->batchnum = batchnum;
	bitmap_zero(todo->peers_asked, MAX_PEERS);

	list_add_tail(&state->todo, &todo->list);

	/* In case a peer is waiting for something to do. */
	wake_peers(state);
}

struct todo *get_todo(struct state *state, const struct peer *from)
{
	struct todo *i;

	list_for_each(&state->todo, i, list) {
		if (!bitmap_test_bit(i->peers_asked, from->peer_num)) {
			bitmap_set_bit(i->peers_asked, from->peer_num);
			/* FIXME: Maybe don't ask if they don't know about block? */
			return i;
		}
	}
	return NULL;
}

void remove_block_batch_todo(struct state *state,
			     const struct block *block, unsigned int batchnum)
{
	struct todo *todo = find_todo(state, block, batchnum);

	if (todo) {
		list_del_from(&state->todo, &todo->list);
		tal_free(todo);
	}
}
