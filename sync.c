#include "sync.h"
#include "block.h"
#include "chain.h"
#include "difficulty.h"
#include "packet.h"
#include "shadouble.h"
#include "state.h"
#include "timestamp.h"
#include "todo.h"
#include <openssl/bn.h>

/* Count children, ignoring except. */
static u32 num_children(const struct block *block,
			const struct block *except,
			unsigned int depth)
{
	const struct block *c;
	u32 num = 0;

	if (depth == 100)
		return PROTOCOL_PKT_CHILDREN_SOME;

	list_for_each(&block->children, c, sibling) {
		u32 children;
		if (c == except)
			continue;
		num++;
		children = num_children(c, except, depth + 1);
		if (children == PROTOCOL_PKT_CHILDREN_SOME)
			return PROTOCOL_PKT_CHILDREN_SOME;
		num += children;
	}
	return num;
}

/*
 * We step back more than one if we are better than target.  This
 * allows effective compression while being as difficult to generate
 * as the full chain (not my idea: from Gregory Maxwell, I just
 * adapted it for here).
 */
static u32 num_steps(const struct block *b, BN_CTX *bn_ctx)
{
	BIGNUM target, ratio, *val;
	unsigned long steps = 1;

	if (!decode_difficulty(le32_to_cpu(b->tailer->difficulty), &target))
		goto out; 

	val = BN_bin2bn(b->sha.sha, sizeof(b->sha.sha), NULL);
	if (!val)
		goto free_target;

	BN_init(&ratio);
	if (!BN_div(&ratio, NULL, &target, val, bn_ctx))
		goto free_ratio;

	/* Returns 0xffffffffL if ratio is too big, which is fine. */
	steps = BN_get_word(&ratio);
	/* Block value must be <= target. */
	assert(steps > 0);

	/* This is possible on 64 bit systems */
	if (steps > (u32)steps)
		steps = 0xFFFFFFFF;

free_ratio:
	BN_free(&ratio);
	BN_free(val);
free_target:
	BN_free(&target);
out:
	return steps;
}

static const struct block *step_back(const struct block *b,
				     const struct block *last,
				     BN_CTX *bn_ctx)
{
	u32 i, steps = num_steps(b, bn_ctx);

	for (i = 0; i < steps; i++) {
		if (b == last)
			break;
		b = b->prev;
	}
	return b;
}

/* Go 1 day below horizon. */
#define CLOSE_TO_HORIZON (24 * 60 * 60)

/* FIXME: Slow! */
static const struct block *find_horizon(const struct state *state)
{
	const struct block *b = state->preferred_chain, *horizon;
	unsigned int num_over_horizon = 0;

	/* 11 in a row beyond horizon makes this fairly certain. */
	while (b != genesis_block(state)) {
		if (le32_to_cpu(b->tailer->timestamp)
		    + TX_HORIZON_SECS + CLOSE_TO_HORIZON
		    < current_time()) {
			if (!horizon)
				horizon = b;
			num_over_horizon++;
			if (num_over_horizon == 11)
				return horizon;
		} else {
			num_over_horizon = 0;
			horizon = NULL;
		}
		b = b->prev;
	}
	return genesis_block(state);
}

/* FIXME: Cache (most) of this... */
static struct protocol_pkt_horizon *horizon_pkt(struct peer *peer,
						const struct block *horizon,
						const struct block *mutual)
{
	struct protocol_pkt_horizon *pkt;
	const struct block *b;
	BN_CTX *bn_ctx;

	/* Speeds up BN operations. */
	bn_ctx = BN_CTX_new();

	pkt = tal_packet(peer, struct protocol_pkt_horizon,
			 PROTOCOL_PKT_HORIZON);

	for (b = horizon;
	     !block_preceeds(b, mutual);
	     b = step_back(b, mutual, bn_ctx))
		tal_packet_append_block(&pkt, b);

	/* Append final one, to make sure we reach what they know. */
	tal_packet_append_block(&pkt, b);

	BN_CTX_free(bn_ctx);
	return pkt;
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
	const struct block *horizon = find_horizon(peer->state);

	/* If they're below horizon, get them to horizon. */
	if (le32_to_cpu(mutual->hdr->depth) < le32_to_cpu(horizon->hdr->depth))
		return horizon_pkt(peer, horizon, mutual);

	/* Otherwise tell them num children of blocks since horizon */
	return sync_pkt(peer, horizon, mutual);
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

	if (le32_to_cpu(pkt->len) != sizeof(*pkt))
		return PROTOCOL_ECODE_INVALID_LEN;

	b = block_find_any(peer->state, &pkt->block);
	if (b) {
		struct protocol_pkt_block *r;
		r = tal_packet(peer, struct protocol_pkt_block,
					PROTOCOL_PKT_BLOCK);
		tal_packet_append_block(&r, b);
		*reply = r;
	} else {
		/* If we don't know it, that's OK. */
		struct protocol_pkt_unknown_block *r;
		log_debug(peer->log, "unknown get_block block ");
		log_add_struct(peer->log, struct protocol_double_sha,
			       &pkt->block);
		r = tal_packet(peer, struct protocol_pkt_unknown_block,
					PROTOCOL_PKT_UNKNOWN_BLOCK);
		r->block = pkt->block;
		*reply = r;
	}

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
	}

	len = le32_to_cpu(pkt->len) - sizeof(*pkt);
	num = len / sizeof(struct protocol_net_syncblock);
	if (len % sizeof(struct protocol_net_syncblock))
		return PROTOCOL_ECODE_INVALID_LEN;

	s = (void *)(pkt + 1);
	for (i = 0; i < num; i++) {
		const struct block *b = block_find_any(peer->state, &s->block);
		if (!b) {
			/* We'd better find out about this one... */
			todo_add_get_block(peer->state, &s->block);
		} else {
			/* If they have more children than us, ask deeper. */
			if (num_children(b, NULL, 0)
			    < le32_to_cpu(s[i].children))
				todo_add_get_children(peer->state, &b->sha);
		}
	}

	/* FIXME: If we expected more children, mark this as false? */
	todo_done_get_children(peer, &pkt->block, true);

	return PROTOCOL_ECODE_NONE;
}
			


