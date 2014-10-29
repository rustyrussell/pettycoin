#include "jsonrpc.h"
#include "pkt_names.h"
#include "protocol_net.h"
#include "state.h"
#include "todo.h"
#include <ccan/io/io.h>
#include <ccan/structeq/structeq.h>
#include <ccan/tal/tal.h>

/* Gets pointer to blk (and maybe batchnum) depending on todo type */
static void get_todo_ptrs(struct state *state,
			  struct todo_request *todo,
			  struct protocol_double_sha **sha,
			  le16 **shardnum,
			  u8 **txoff)
{
	switch (cpu_to_le32(todo->pkt.hdr.type)) {
	case PROTOCOL_PKT_GET_BLOCK:
		*sha = &todo->pkt.get_block.block.sha;
		*shardnum = NULL;
		*txoff = NULL;
		break;
	case PROTOCOL_PKT_GET_SHARD:
		*sha = &todo->pkt.get_shard.block.sha;
		*shardnum = &todo->pkt.get_shard.shard;
		*txoff = NULL;
		break;
	case PROTOCOL_PKT_GET_TXMAP:
		*sha = &todo->pkt.get_txmap.block.sha;
		*shardnum = &todo->pkt.get_txmap.shard;
		*txoff = NULL;
		break;
	case PROTOCOL_PKT_GET_CHILDREN:
		*sha = &todo->pkt.get_children.block.sha;
		*shardnum = NULL;
		*txoff = NULL;
		break;
	case PROTOCOL_PKT_GET_TX_IN_BLOCK:
		*sha = &todo->pkt.get_tx_in_block.pos.block.sha;
		*shardnum = &todo->pkt.get_tx_in_block.pos.shard;
		*txoff = &todo->pkt.get_tx_in_block.pos.txoff;
		break;
	case PROTOCOL_PKT_GET_TX:
		*sha = &todo->pkt.get_tx.tx.sha;
		*shardnum = NULL;
		*txoff = NULL;
		break;
	default:
		log_broken(state->log, "Unknown todo type ");
		log_add_enum(state->log, enum protocol_pkt_type,
			     cpu_to_le32(todo->pkt.hdr.type));
		abort();
	}
}

static void zero_unused(struct state *state, struct todo_request *todo)
{
	switch (cpu_to_le32(todo->pkt.hdr.type)) {
	case PROTOCOL_PKT_GET_BLOCK:
		break;
	case PROTOCOL_PKT_GET_SHARD:
		todo->pkt.get_shard.unused = cpu_to_le16(0);
		break;
	case PROTOCOL_PKT_GET_TXMAP:
		break;
	case PROTOCOL_PKT_GET_CHILDREN:
		break;
	case PROTOCOL_PKT_GET_TX_IN_BLOCK:
		todo->pkt.get_tx_in_block.pos.unused = 0;
		break;
	case PROTOCOL_PKT_GET_TX:
		break;
	default:
		log_broken(state->log, "Unknown todo type ");
		log_add_enum(state->log, enum protocol_pkt_type,
			     cpu_to_le32(todo->pkt.hdr.type));
		abort();
	}
}


/* FIXME: Slow! */
/*
 * FIXME: Move found todos to the end of the queue?
 * FIXME: Penalize peers who make us ask too many bad questions? 
 */
static struct todo_request *find_todo(struct state *state,
				      enum protocol_pkt_type type,
				      const struct protocol_double_sha *sha,
				      u16 shardnum, u8 txoff)
{
	struct todo_request *i;

	list_for_each(&state->todo, i, list) {
		struct protocol_double_sha *i_sha;
		le16 *i_shardnum;
		u8 *i_txoff;

		if (i->pkt.hdr.type != cpu_to_le32(type))
			continue;

		get_todo_ptrs(state, i, &i_sha, &i_shardnum, &i_txoff);
		if (!structeq(i_sha, sha))
			continue;
		if (i_shardnum && le16_to_cpu(*i_shardnum) != shardnum)
			continue;
		if (i_txoff && le16_to_cpu(*i_txoff) != txoff)
			continue;
		return i;
	}
	return NULL;
}

#define new_todo_request(state, type, structtype, blocksha, shardnum, txoff) \
	new_todo_request_((state), (type), sizeof(structtype),		\
			  (blocksha), (shardnum), (txoff))

static void new_todo_request_(struct state *state,
			      enum protocol_pkt_type type,
			      size_t pktlen,
			      const struct protocol_double_sha *sha,
			      u16 shardnum, u8 txoff)
{
	struct todo_request *t;
	struct protocol_double_sha *t_sha;
	le16 *t_shardnum;
	u8 *t_txoff;

	/* We don't insert duplicates. */
	if (find_todo(state, type, sha, shardnum, txoff))
		return;

	t = tal(state, struct todo_request);

	bitmap_zero(t->peers_asked, MAX_PEERS);
	bitmap_zero(t->peers_failed, MAX_PEERS);
	t->pkt.hdr.type = cpu_to_le32(type);
	t->pkt.hdr.len = cpu_to_le32(pktlen);
	
	get_todo_ptrs(state, t, &t_sha, &t_shardnum, &t_txoff);
	*t_sha = *sha;
	if (t_shardnum)
		*t_shardnum = cpu_to_le16(shardnum);
	if (t_txoff)
		*t_txoff = txoff;

	/* Make sure unused fields are zero.  We don't use talz because
	 * we want valgrind to tell us if we don't initialize some fields. */
	zero_unused(state, t);
	list_add_tail(&state->todo, &t->list);

	/* In case a peer is waiting for something to do. */
	wake_peers(state);
}

void todo_add_get_children(struct state *state,
			   const struct protocol_block_id *block)
{
	new_todo_request(state, PROTOCOL_PKT_GET_CHILDREN,
			 struct protocol_pkt_get_children,
			 &block->sha, 0, 0);
}

void todo_add_get_block(struct state *state,
			const struct protocol_block_id *block)
{
	new_todo_request(state, PROTOCOL_PKT_GET_BLOCK,
			 struct protocol_pkt_get_block,
			 &block->sha, 0, 0);
}

void todo_add_get_shard(struct state *state,
			const struct protocol_block_id *block,
			u16 shardnum)
{
	new_todo_request(state, PROTOCOL_PKT_GET_SHARD,
			 struct protocol_pkt_get_shard,
			 &block->sha, shardnum, 0);
}

void todo_add_get_txmap(struct state *state,
			const struct protocol_block_id *block,
			u16 shardnum)
{
	new_todo_request(state, PROTOCOL_PKT_GET_TXMAP,
			 struct protocol_pkt_get_txmap,
			 &block->sha, shardnum, 0);
}

void todo_add_get_tx_in_block(struct state *state,
			      const struct protocol_block_id *block,
			      u16 shardnum, u8 txoff)
{
	new_todo_request(state, PROTOCOL_PKT_GET_TX_IN_BLOCK,
			 struct protocol_pkt_get_tx_in_block,
			 &block->sha, shardnum, txoff);
}

void todo_add_get_tx(struct state *state,
		     const struct protocol_tx_id *tx)
{
	new_todo_request(state, PROTOCOL_PKT_GET_TX,
			 struct protocol_pkt_get_tx,
			 &tx->sha, 0, 0);
}

void todo_for_peer(struct peer *peer, void *pkt)
{
	struct todo_pkt *t = tal(peer, struct todo_pkt);

	t->pkt = tal_steal(t, pkt);
	list_add_tail(&peer->todo, &t->list);

	/* In case it's idle. */
	io_wake(peer);
}

static struct peer *find_peer(struct state *state, unsigned int i)
{
	struct peer *peer;

	list_for_each(&state->peers, peer, list) {
		if (peer->peer_num == i)
			return peer;
	}
	return NULL;
}

/* If a later peer gets the same number, don't get confused! */
void remove_peer_from_todo(struct state *state, struct peer *peer)
{
	struct todo_request *i;

	list_for_each(&state->todo, i, list) {
		bitmap_clear_bit(i->peers_asked, peer->peer_num);
		bitmap_clear_bit(i->peers_failed, peer->peer_num);
	}
}

static void request_done(struct peer *peer)
{
	assert(peer->requests_outstanding);
	peer->requests_outstanding--;

	/* They wait for no more requests when syncing, and also may
	 * be waiting because they were at MAX_REQUESTS. */
	io_wake(peer);
}		

static void delete_todo(struct state *state, struct todo_request *todo)
{
	unsigned int i;

	list_del_from(&state->todo, &todo->list);

	for (i = 0; i < MAX_PEERS; i++) {
		if (bitmap_test_bit(todo->peers_asked, i)
		    && !bitmap_test_bit(todo->peers_failed, i))
			request_done(find_peer(state, i));
	}

	tal_free(todo);
}

static void finish_todo(struct peer *peer,
			enum protocol_pkt_type type,
			const struct protocol_double_sha *sha,
			u16 shardnum, u8 txoff,
			bool success)
{
	struct todo_request *todo;
	const char *status;

	todo = find_todo(peer->state, type, sha, shardnum, txoff);
	if (!todo) {
		/* Someone else may have answered */
		log_debug(peer->log, "Didn't find request, ignoring.");
		return;
	}

	if (bitmap_test_bit(todo->peers_asked, peer->peer_num)) {
		if (bitmap_test_bit(todo->peers_failed, peer->peer_num))
			/* Possible if we time out. */
			status = "already failed";
		else
			status = NULL;
	} else
		status = "unsolicited";

	if (status) {
		log_unusual(peer->log,
			    "Peer replied with %s to %s request ",
			    success ? "success" : "unsuccess", status);
		log_add_enum(peer->log, enum protocol_pkt_type, type);
		log_add(peer->log, " sha ");
		log_add_struct(peer->log, struct protocol_double_sha, sha);
		log_add(peer->log, ":%u(%u)", shardnum, txoff);
	}

	if (success)
		delete_todo(peer->state, todo);
	else if (!status) {
		bitmap_set_bit(todo->peers_failed, peer->peer_num);
		request_done(peer);
	}
}

void todo_done_get_children(struct peer *peer,
			    const struct protocol_block_id *block,
			    bool success)
{
	finish_todo(peer, PROTOCOL_PKT_GET_CHILDREN, &block->sha, 0, 0,
		    success);
}

void todo_done_get_block(struct peer *peer, 
			 const struct protocol_block_id *block,
			 bool success)
{
	finish_todo(peer, PROTOCOL_PKT_GET_BLOCK, &block->sha, 0, 0, success);
}

void todo_done_get_shard(struct peer *peer,
			 const struct protocol_block_id *block,
			 u16 shardnum, bool success)
{
	finish_todo(peer, PROTOCOL_PKT_GET_SHARD, &block->sha, shardnum, 0,
		    success);
}

void todo_done_get_txmap(struct peer *peer,
			 const struct protocol_block_id *block,
			 u16 shardnum, bool success)
{
	finish_todo(peer, PROTOCOL_PKT_GET_TXMAP, &block->sha, shardnum, 0,
		    success);
}

void todo_done_get_tx_in_block(struct peer *peer,
			       const struct protocol_block_id *block,
			       u16 shardnum, u8 txoff, bool success)
{
	finish_todo(peer, PROTOCOL_PKT_GET_TX_IN_BLOCK,
		    &block->sha, shardnum, txoff, success);
}

void todo_done_get_tx(struct peer *peer,
		      const struct protocol_tx_id *tx, bool success)
{
	finish_todo(peer, PROTOCOL_PKT_GET_TX, &tx->sha, 0, 0, success);
}

void todo_forget_about_block(struct state *state,
			     const struct protocol_block_id *block)
{
	struct todo_request *i, *next;

	list_for_each_safe(&state->todo, i, next, list) {
		struct protocol_double_sha *i_sha;
		le16 *i_shardnum;
		u8 *i_txoff;

		get_todo_ptrs(state, i, &i_sha, &i_shardnum, &i_txoff);
		if (!structeq(i_sha, &block->sha))
			continue;

		list_del_from(&state->todo, &i->list);
		tal_free(i);
	}
}

/* Increments peer->requests_outstanding if return non-NULL. */
void *get_todo_pkt(struct state *state, struct peer *peer)
{
	struct todo_pkt *p;
	struct todo_request *r;

	/* First look for packets to send specifically to this peer. */
	p = list_pop(&peer->todo, struct todo_pkt, list);
	if (p) {
		void *ret = tal_steal(peer, p->pkt);
		tal_free(p);
		return ret;
	}

	if (peer->requests_outstanding >= MAX_REQUESTS)
		return NULL;

	/* Now look for generic questions we want answered. */
	list_for_each(&state->todo, r, list) {
		/* FIXME: Limit number of peers we ask simultaneously! */
		if (!bitmap_test_bit(r->peers_asked, peer->peer_num)) {
			bitmap_set_bit(r->peers_asked, peer->peer_num);
			peer->requests_outstanding++;
			/* Give them their own copy. */
			return tal_dup(peer, char, (char *)&r->pkt,
				       le32_to_cpu(r->pkt.hdr.len), 0);
		}
	}
	return NULL;
}

static char *json_listtodo(struct json_connection *jcon,
			   const jsmntok_t *params,
			   struct json_result *response)
{
	struct todo_request *todo;
	struct peer *peer;

	json_object_start(response, NULL);
	json_array_start(response, "todo");
	list_for_each(&jcon->state->todo, todo, list) {
		unsigned int i;
		struct protocol_double_sha *sha;
		le16 *shardnum;
		u8 *txoff;
		
		get_todo_ptrs(jcon->state, todo, &sha, &shardnum, &txoff);
		json_object_start(response, NULL);
		json_add_string(response, "type",
				pkt_name(cpu_to_le32(todo->pkt.hdr.type)));
		if (sha)
			json_add_double_sha(response, "sha", sha);
		if (shardnum)
			json_add_num(response, "shard", le16_to_cpu(*shardnum));
		if (txoff)
			json_add_num(response, "txoff", *txoff);

		json_array_start(response, "peers_asked");
		for (i = 0; i < MAX_PEERS; i++)
			if (bitmap_test_bit(todo->peers_asked, i))
				json_add_num(response, NULL, i);
		json_array_end(response);

		json_array_start(response, "peers_failed");
		for (i = 0; i < MAX_PEERS; i++)
			if (bitmap_test_bit(todo->peers_failed, i))
				json_add_num(response, NULL, i);
		json_array_end(response);
		json_object_end(response);
	}
	json_array_end(response);

	json_array_start(response, "for_peers");
	list_for_each(&jcon->state->peers, peer, list) {
		struct todo_pkt *todo_pkt;

		list_for_each(&peer->todo, todo_pkt, list) {
			struct protocol_net_hdr *hdr;

			hdr = (struct protocol_net_hdr *)todo_pkt->pkt;
			json_object_start(response, NULL);
			json_add_num(response, "peer_num", peer->peer_num);
			json_array_start(response, "pkts");
		
			json_add_string(response, "type",
					pkt_name(cpu_to_le32(hdr->type)));
			json_object_end(response);
		}
	}
	json_array_end(response);
	json_object_end(response);
	return NULL;
}

const struct json_command listtodo_command = {
	"dev-listtodo",
	json_listtodo,
	"List all outstanding TODO requests",
	""
};
