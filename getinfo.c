#include "block.h"
#include "jsonrpc.h"
#include "pending.h"
#include "state.h"
#include "todo.h"

static void json_add_block(char **response, const char *fieldname,
			   const struct block *block)
{
	json_object_start(response, fieldname);
	json_add_double_sha(response, "sha", &block->sha);
	json_add_num(response, "height", le32_to_cpu(block->hdr->height));
	json_object_end(response);
}

static char *json_getinfo(struct json_connection *jcon,
			  const jsmntok_t *params,
			  char **response)
{
	size_t i, num_todo, num_peer_todo, num_peers;
	struct todo_request *todo;
	struct peer *peer;

	json_object_start(response, NULL);
	if (jcon->state->test_net)
		json_add_bool(response, "test_net", true);
	json_array_start(response, "longest");
	for (i = 0; i < tal_count(jcon->state->longest_chains); i++)
		json_add_block(response, NULL, jcon->state->longest_chains[i]);
	json_array_end(response);

	json_array_start(response, "longest_knowns");
	for (i = 0; i < tal_count(jcon->state->longest_knowns); i++)
		json_add_block(response, NULL, jcon->state->longest_knowns[i]);
	json_array_end(response);

	json_add_block(response, "preferred_chain",
		       jcon->state->preferred_chain);

	num_todo = 0;
	list_for_each(&jcon->state->todo, todo, list)
		num_todo++;
	json_add_num(response, "num_todos", num_todo);

	num_peers = num_peer_todo = 0;
	list_for_each(&jcon->state->peers, peer, list) {
		struct todo_pkt *todo_pkt;
		num_peers++;
		list_for_each(&peer->todo, todo_pkt, list)
			num_peer_todo++;
	}
	json_add_num(response, "connections", num_peers);
	json_add_num(response, "num_peer_todos", num_peer_todo);

	json_add_num(response, "num_pending",
		     num_pending_known(jcon->state)
		     + jcon->state->pending->num_unknown);
	json_object_end(response);

	return NULL;
}

const struct json_command getinfo_command = {
	"getinfo",
	json_getinfo,
	"get miscellaneous information",
	"Return test_net, longest[], longest_knowns[], preferred_chain, num_todos, num_pending"
};
