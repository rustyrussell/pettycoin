#include <ccan/structeq/structeq.h>
#include "todo.h"
#include "state.h"
#include "protocol_net.h"
#include <ccan/tal/tal.h>
#include <ccan/io/io.h>

/* Gets pointer to blk (and maybe batchnum) depending on todo type */
static void get_todo_ptrs(struct state *state,
			  struct todo_request *todo,
			  struct protocol_double_sha **blk,
			  le16 **shardnum,
			  u8 **txoff)
{
	switch (cpu_to_le32(todo->pkt.hdr.type)) {
	case PROTOCOL_PKT_GET_BLOCK:
		*blk = &todo->pkt.get_block.block;
		*shardnum = NULL;
		*txoff = NULL;
		break;
	case PROTOCOL_PKT_GET_SHARD:
		*blk = &todo->pkt.get_shard.block;
		*shardnum = &todo->pkt.get_shard.shard;
		*txoff = NULL;
		break;
	case PROTOCOL_PKT_GET_CHILDREN:
		*blk = &todo->pkt.get_children.block;
		*shardnum = NULL;
		*txoff = NULL;
		break;
	case PROTOCOL_PKT_GET_TX_IN_BLOCK:
		*blk = &todo->pkt.get_tx_in_block.block;
		*shardnum = &todo->pkt.get_tx_in_block.shard;
		*txoff = &todo->pkt.get_tx_in_block.txoff;
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
				      const struct protocol_double_sha *blk,
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
		if (!structeq(i_sha, blk))
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
	((structtype *)new_todo_request_((state), (type), sizeof(structtype), \
					 (blocksha), (shardnum), (txoff)))

static void *new_todo_request_(struct state *state,
			       enum protocol_pkt_type type,
			       size_t pktlen,
			       const struct protocol_double_sha *blk,
			       u16 shardnum, u8 txoff)
{
	struct todo_request *t;
	struct protocol_double_sha *t_sha;
	le16 *t_shardnum;
	u8 *t_txoff;

	/* We don't insert duplicates. */
	if (find_todo(state, type, blk, shardnum, txoff))
		return NULL;

	t = tal(state, struct todo_request);

	bitmap_zero(t->peers_asked, MAX_PEERS);
	bitmap_zero(t->peers_failed, MAX_PEERS);
	t->pkt.hdr.type = cpu_to_le32(type);
	t->pkt.hdr.len = cpu_to_le32(pktlen);
	
	get_todo_ptrs(state, t, &t_sha, &t_shardnum, &t_txoff);
	*t_sha = *blk;
	if (t_shardnum)
		*t_shardnum = cpu_to_le16(shardnum);
	if (t_txoff)
		*t_txoff = txoff;

	list_add_tail(&state->todo, &t->list);

	/* In case a peer is waiting for something to do. */
	wake_peers(state);

	return &t->pkt;
}

void todo_add_get_children(struct state *state,
			   const struct protocol_double_sha *block)
{
	new_todo_request(state, PROTOCOL_PKT_GET_CHILDREN,
			 struct protocol_pkt_get_children,
			 block, 0, 0);
}

void todo_add_get_block(struct state *state,
			const struct protocol_double_sha *block)
{
	new_todo_request(state, PROTOCOL_PKT_GET_BLOCK,
			 struct protocol_pkt_get_block,
			 block, 0, 0);
}

void todo_add_get_shard(struct state *state,
			const struct protocol_double_sha *block,
			u16 shardnum)
{
	new_todo_request(state, PROTOCOL_PKT_GET_SHARD,
			 struct protocol_pkt_get_shard,
			 block, shardnum, 0);
}


void todo_add_get_tx_in_block(struct state *state,
			      const struct protocol_double_sha *block,
			      u16 shardnum, u8 txoff)
{
	new_todo_request(state, PROTOCOL_PKT_GET_TX_IN_BLOCK,
			 struct protocol_pkt_get_tx_in_block,
			 block, shardnum, txoff);
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

static void delete_todo(struct state *state, struct todo_request *todo)
{
	unsigned int i;

	list_del_from(&state->todo, &todo->list);

	for (i = 0; i < MAX_PEERS; i++) {
		if (bitmap_test_bit(todo->peers_asked, i)
		    && !bitmap_test_bit(todo->peers_failed, i))
			find_peer(state, i)->requests_outstanding--;
	}

	tal_free(todo);
}

static void finish_todo(struct peer *peer,
			enum protocol_pkt_type type,
			const struct protocol_double_sha *blk,
			u16 shardnum, u8 txoff,
			bool success)
{
	struct todo_request *todo;
	const char *status;

	log_debug(peer->log, "Peer replied with %s ",
		  success ? "success" : "unsuccess");
	log_add_enum(peer->log, enum protocol_pkt_type, type);
	log_add(peer->log, " block ");
	log_add_struct(peer->log, struct protocol_double_sha, blk);
	log_add(peer->log, ":%u", shardnum);

	todo = find_todo(peer->state, type, blk, shardnum, txoff);
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
		log_add(peer->log, " block ");
		log_add_struct(peer->log, struct protocol_double_sha, blk);
		log_add(peer->log, ":%u(%u)", shardnum, txoff);
	}

	if (success)
		delete_todo(peer->state, todo);
	else if (!status) {
		bitmap_set_bit(todo->peers_failed, peer->peer_num);
		assert(peer->requests_outstanding);
		peer->requests_outstanding--;
	}
}

void todo_done_get_children(struct peer *peer,
			    const struct protocol_double_sha *block,
			    bool success)
{
	finish_todo(peer, PROTOCOL_PKT_GET_CHILDREN, block, 0, 0, success);
}

void todo_done_get_block(struct peer *peer, 
			 const struct protocol_double_sha *block,
			 bool success)
{
	finish_todo(peer, PROTOCOL_PKT_GET_BLOCK, block, 0, 0, success);
}

void todo_done_get_shard(struct peer *peer,
			 const struct protocol_double_sha *block,
			 u16 shardnum, bool success)
{
	finish_todo(peer, PROTOCOL_PKT_GET_SHARD, block, shardnum, 0, success);
}

void todo_done_get_tx_in_block(struct peer *peer,
			       const struct protocol_double_sha *block,
			       u16 shardnum, u8 txoff, bool success)
{
	finish_todo(peer, PROTOCOL_PKT_GET_TX_IN_BLOCK,
		    block, shardnum, txoff, success);
}

void todo_forget_about_block(struct state *state,
			     const struct protocol_double_sha *block)
{
	struct todo_request *i, *next;

	list_for_each_safe(&state->todo, i, next, list) {
		struct protocol_double_sha *i_sha;
		le16 *i_shardnum;
		u8 *i_txoff;

		get_todo_ptrs(state, i, &i_sha, &i_shardnum, &i_txoff);
		if (!structeq(i_sha, block))
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
