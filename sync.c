#include "block.h"
#include "chain.h"
#include "difficulty.h"
#include "shadouble.h"
#include "state.h"
#include "sync.h"
#include "tal_packet.h"
#include "timestamp.h"
#include "todo.h"
#include <openssl/bn.h>

/* Count children, ignoring except. */
static u32 num_children(const struct block *block,
			const struct block *except,
			unsigned int height)
{
	const struct block *c;
	u32 num = 0;

	if (height == 100)
		return PROTOCOL_PKT_CHILDREN_SOME;

	list_for_each(&block->children, c, sibling) {
		u32 children;
		if (c == except)
			continue;
		num++;
		children = num_children(c, except, height + 1);
		if (children == PROTOCOL_PKT_CHILDREN_SOME)
			return PROTOCOL_PKT_CHILDREN_SOME;
		num += children;
	}
	return num;
}

static struct protocol_pkt_sync *sync_pkt(struct peer *peer,
					  const struct block *horizon,
					  const struct block *mutual)
{
	struct protocol_pkt_sync *pkt;
	const struct block *b, *prev = NULL;
	struct protocol_net_syncblock s;

	pkt = tal_packet(peer, struct protocol_pkt_sync, PROTOCOL_PKT_SYNC);

	for (b = mutual; !block_preceeds(b, horizon); prev = b, b = b->prev) {
		s.children = cpu_to_le32(num_children(b, prev, 0));
		s.block = b->sha;
		tal_packet_append(&pkt, &s, sizeof(s));
	}

	/* We always include at least 1 syncblock. */
	s.children = cpu_to_le32(num_children(b, prev, 0));
	s.block = b->sha;
	tal_packet_append(&pkt, &s, sizeof(s));

	return pkt;
}

void *sync_or_horizon_pkt(struct peer *peer, const struct block *mutual)
{
	/* FIXME: Peers don't handle horizon packets yet. */
	return sync_pkt(peer, genesis_block(peer->state), mutual);
}

enum protocol_ecode recv_sync_pkt(struct peer *peer,
				  const struct protocol_pkt_sync *sync)
{
	u32 len, num;
	int i;
	struct protocol_net_syncblock *s;
	const struct block *prev = NULL, *b;

	len = le32_to_cpu(sync->len) - sizeof(struct protocol_net_hdr);
	num = len / sizeof(struct protocol_net_syncblock);
	if (len % sizeof(struct protocol_net_syncblock) || num == 0)
		return PROTOCOL_ECODE_INVALID_LEN;

	s = (void *)(sync + 1);

	for (i = num - 1; i < num; i--) {
		b = block_find_any(peer->state, &s[i].block);
		if (!b)
			return PROTOCOL_ECODE_UNKNOWN_BLOCK;

		/* This means we ask if they're way ahead. */
		if (num_children(b, prev, 0) < le32_to_cpu(s[i].children))
			todo_add_get_children(peer->state, &b->sha);
	}

	return PROTOCOL_ECODE_NONE;
}

enum protocol_ecode recv_horizon_pkt(struct peer *peer,
				     const struct protocol_pkt_horizon *horiz)
{
	/* FIXME: Implement horizon! */
	return PROTOCOL_ECODE_UNKNOWN_COMMAND; /* AKA: I suck */
}

enum protocol_ecode
recv_get_children(struct peer *peer,
		  const struct protocol_pkt_get_children *pkt,
		  void **reply)
{
	struct block *b, *i;
	struct protocol_pkt_children *r;

	if (le32_to_cpu(pkt->len) != sizeof(*pkt))
		return PROTOCOL_ECODE_INVALID_LEN;

	*reply = r = tal_packet(peer, struct protocol_pkt_children,
				PROTOCOL_PKT_CHILDREN);
	r->block = pkt->block;

	/* If we don't know it, that's OK. */
	b = block_find_any(peer->state, &pkt->block);
	if (!b) {
		log_debug(peer->log, "unknown get_children block ");
		log_add_struct(peer->log, struct protocol_double_sha,
			       &pkt->block);
		r->err = cpu_to_le32(PROTOCOL_ECODE_UNKNOWN_BLOCK);
		return PROTOCOL_ECODE_NONE;
	}
	r->err = cpu_to_le32(PROTOCOL_ECODE_NONE);

	log_debug(peer->log, "Creating children block for ");
	log_add_struct(peer->log, struct protocol_double_sha,
			       &pkt->block);
	list_for_each(&b->children, i, sibling) {
		struct protocol_net_syncblock s;

		s.block = i->sha;
		s.children = cpu_to_le32(num_children(i, NULL, 0));
		tal_packet_append(&r, &s, sizeof(s));
		*reply = r;

		log_debug(peer->log, "Adding %u children ",
			  le32_to_cpu(s.children));
		log_add_struct(peer->log, struct protocol_double_sha,
			       &s.block);
		assert(block_find_any(peer->state, &s.block));
	}

	return PROTOCOL_ECODE_NONE;
}

enum protocol_ecode
recv_get_block(struct peer *peer,
	       const struct protocol_pkt_get_block *pkt,
	       void **reply)
{
	struct block *b;
	struct protocol_pkt_block *r;

	if (le32_to_cpu(pkt->len) != sizeof(*pkt))
		return PROTOCOL_ECODE_INVALID_LEN;

	r = tal_packet(peer, struct protocol_pkt_block, PROTOCOL_PKT_BLOCK);

	b = block_find_any(peer->state, &pkt->block);
	if (b) {
		r->err = le32_to_cpu(PROTOCOL_ECODE_NONE);
		tal_packet_append_block(&r, b);
	} else {
		/* If we don't know it, that's OK. */
		log_debug(peer->log, "unknown get_block block ");
		log_add_struct(peer->log, struct protocol_double_sha,
			       &pkt->block);
		r->err = le32_to_cpu(PROTOCOL_ECODE_UNKNOWN_BLOCK);
		tal_packet_append_sha(&r, &pkt->block);
	}

	*reply = r;
	return PROTOCOL_ECODE_NONE;
}

enum protocol_ecode recv_children(struct peer *peer,
				  const struct protocol_pkt_children *pkt)
{
	u32 len, num, i;
	const struct block *parent;
	struct protocol_net_syncblock *s;

	if (le32_to_cpu(pkt->len) < sizeof(*pkt))
		return PROTOCOL_ECODE_INVALID_LEN;

	parent = block_find_any(peer->state, &pkt->block);
	if (!parent)
		return PROTOCOL_ECODE_UNKNOWN_BLOCK;

	if (le32_to_cpu(pkt->err) != PROTOCOL_ECODE_NONE) {
		if (le32_to_cpu(pkt->len) != sizeof(*pkt))
			return PROTOCOL_ECODE_INVALID_LEN;
		if (le32_to_cpu(pkt->err) != PROTOCOL_ECODE_UNKNOWN_BLOCK)
			return PROTOCOL_ECODE_UNKNOWN_COMMAND;
		/* They don't know the block.  OK. */
		todo_done_get_children(peer, &pkt->block, false);
		return PROTOCOL_ECODE_NONE;
	}

	len = le32_to_cpu(pkt->len) - sizeof(*pkt);
	num = len / sizeof(struct protocol_net_syncblock);
	if (len % sizeof(struct protocol_net_syncblock))
		return PROTOCOL_ECODE_INVALID_LEN;

	log_debug(peer->log, "Gave us %u children for ", num);
	log_add_struct(peer->log, struct protocol_double_sha, &parent->sha);

	s = (void *)(pkt + 1);
	for (i = 0; i < num; i++) {
		const struct block *b;

		b = block_find_any(peer->state, &s[i].block);
		if (!b) {
			/* We'd better find out about this one... */
			log_debug(peer->log, "Asking about unknown block ");
			log_add_struct(peer->log, struct protocol_double_sha,
				       &s[i].block);
			todo_add_get_block(peer->state, &s[i].block);
		} else {
			/* If they have more children than us, ask deeper. */
			if (num_children(b, NULL, 0)
			    < le32_to_cpu(s[i].children)) {
				log_debug(peer->log, "Getting more kids for ");
				log_add_struct(peer->log, struct protocol_double_sha,
					       &s[i].block);
				
				todo_add_get_children(peer->state, &s[i].block);
			}
		}
	}

	/* FIXME: If we expected more children, mark this as false? */
	todo_done_get_children(peer, &pkt->block, true);

	return PROTOCOL_ECODE_NONE;
}
			


