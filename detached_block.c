#include "block.h"
#include "detached_block.h"
#include "protocol_net.h"
#include "recv_block.h"
#include "state.h"
#include <ccan/list/list.h>

/* Blocks which are not fully linked in. */
struct detached_block {
	/* Off state->detached_blocks */
	struct list_node list;
	struct protocol_block_id sha;

	const struct protocol_block_header *hdr;
	const struct protocol_pkt_block *pkt;	
};


/* We got a new block: seek detached blocks which need it (may recurse!) */
void seek_detached_blocks(struct state *state, const struct block *block)
{
	struct detached_block *bd;

again:
	list_for_each(&state->detached_blocks, bd, list) {
		if (structeq(&bd->hdr->prevs[0], &block->sha)) {
			list_del_from(&state->detached_blocks, &bd->list);

			log_debug(state->log, "Reinjecting detatched block");
			/* Inject it through normal path. */
			recv_block_reinject(state, bd->pkt);
			tal_free(bd);

			/* Since that may recurse, we can't trust list. */
			goto again;
		}
	}
}

bool have_detached_block(const struct state *state, 
			 const struct protocol_block_id *sha)
{
	struct detached_block *bd;

	list_for_each(&state->detached_blocks, bd, list) {
		if (structeq(&bd->sha, sha))
			return true;
	}
	return false;
}

void add_detached_block(struct state *state,
			const struct protocol_block_id *sha,
			const struct protocol_block_header *hdr,
			const struct protocol_pkt_block *pkt)
{
	struct detached_block *bd;

	/* Add it to list of detached blocks. */
	bd = tal(state, struct detached_block);
	bd->sha = *sha;
	bd->hdr = hdr;
	bd->pkt = tal_steal(bd, pkt);
	list_add(&state->detached_blocks, &bd->list);
}
