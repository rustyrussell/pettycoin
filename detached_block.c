#include "block.h"
#include "detached_block.h"
#include "jsonrpc.h"
#include "protocol_net.h"
#include "recv_block.h"
#include "state.h"
#include <ccan/list/list.h>

/* Blocks which are not fully linked in. */
struct detached_block {
	/* Off state->detached_blocks */
	struct list_node list;
	struct protocol_block_id sha;

	struct block_info bi;
	const tal_t *pkt_ctx;	
};


/* We got a new block: seek detached blocks which need it (may recurse!) */
void seek_detached_blocks(struct state *state, const struct block *block)
{
	struct detached_block *bd;

again:
	list_for_each(&state->detached_blocks, bd, list) {
		if (structeq(block_prev(&bd->bi, 0), &block->sha)) {
			list_del_from(&state->detached_blocks, &bd->list);

			log_debug(state->log, "Reinjecting detatched block");
			/* Inject it through normal path. */
			recv_block_reinject(state, bd->pkt_ctx,
					    &bd->bi);
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
			const tal_t *pkt_ctx,
			const struct protocol_block_id *sha,
			const struct block_info *bi)
{
	struct detached_block *bd;

	/* Add it to list of detached blocks. */
	bd = tal(state, struct detached_block);
	bd->sha = *sha;
	bd->bi = *bi;
	bd->pkt_ctx = tal_steal(bd, pkt_ctx);
	list_add(&state->detached_blocks, &bd->list);
}

static char *json_detachedblocks(struct json_connection *jcon,
				 const jsmntok_t *params,
				 struct json_result *response)
{
	struct detached_block *bd;

	json_array_start(response, NULL);
	list_for_each(&jcon->state->detached_blocks, bd, list) {
		json_object_start(response, NULL);
		json_add_num(response, "height",
			     le32_to_cpu(bd->bi.hdr->height));
		json_add_double_sha(response, "sha", &bd->sha.sha);
		json_add_double_sha(response, "prev",
				    &block_prev(&bd->bi, 0)->sha);
		json_object_end(response);
	}
	json_array_end(response);
	return NULL;
}

const struct json_command detachedblocks_command = {
	"dev-detachedblocks",
	json_detachedblocks,
	"Get all detached blocks",
	"Returns height, sha and prev for each detached block"
};
