#include "block.h"
#include "chain.h"
#include "difficulty.h"
#include "shadouble.h"
#include "state.h"
#include "sync.h"
#include "tal_packet.h"
#include "timestamp.h"
#include "todo.h"
#include <ccan/asort/asort.h>
#include <openssl/bn.h>

static int hash_cmp(const struct block *const *a,
		    const struct block *const *b, void *null)
{
	return memcmp(&(*a)->sha, &(*b)->sha, sizeof((*a)->sha));
}

static void hash_children(const struct block *block,
			  struct protocol_double_sha *sha)
{
	const struct block *c;
	const struct block **kids;
	SHA256_CTX ctx;
	size_t i;

	/* Hash children in fixed order: order by id. */
	kids = tal_arr(NULL, const struct block *, 0);
	list_for_each(&block->children, c, sibling) {
		size_t count = tal_count(kids);
		tal_resize(&kids, count+1);
		kids[count] = c;
	}
	asort(kids, tal_count(kids), hash_cmp, NULL);

	SHA256_Init(&ctx);
	for (i = 0; i < tal_count(kids); i++) {
		struct protocol_double_sha child_sha;

		hash_children(kids[i], &child_sha);
		SHA256_Update(&ctx, &child_sha, sizeof(child_sha));
	}
	SHA256_Update(&ctx, &block->sha, sizeof(block->sha));
	SHA256_Double_Final(&ctx, sha);
	tal_free(kids);
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
		log_add_struct(peer->log, struct protocol_block_id,
			       &pkt->block);
		r->err = cpu_to_le32(PROTOCOL_ECODE_UNKNOWN_BLOCK);
		return PROTOCOL_ECODE_NONE;
	}
	r->err = cpu_to_le32(PROTOCOL_ECODE_NONE);

	log_debug(peer->log, "Creating children block for ");
	log_add_struct(peer->log, struct protocol_block_id, &pkt->block);
	list_for_each(&b->children, i, sibling) {
		struct protocol_net_childblock cb;

		cb.block = i->sha;
		/* We assume main chain is long, so don't hash children. */
		if (block_preceeds(i, peer->state->preferred_chain))
			memset(&cb.descendents, 0, sizeof(cb.descendents));
		else
			hash_children(i, &cb.descendents);
		tal_packet_append(&r, &cb, sizeof(cb));
		*reply = r;

		log_debug(peer->log, "Adding children for ");
		log_add_struct(peer->log, struct protocol_block_id, &cb.block);
		assert(block_find_any(peer->state, &cb.block));
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
		tal_packet_append_block(&r, &b->bi);
	} else {
		/* If we don't know it, that's OK. */
		log_debug(peer->log, "unknown get_block block ");
		log_add_struct(peer->log, struct protocol_block_id,
			       &pkt->block);
		r->err = le32_to_cpu(PROTOCOL_ECODE_UNKNOWN_BLOCK);
		tal_packet_append_block_id(&r, &pkt->block);
	}

	*reply = r;
	return PROTOCOL_ECODE_NONE;
}

enum protocol_ecode recv_children(struct peer *peer,
				  const struct protocol_pkt_children *pkt)
{
	u32 len, num, i;
	const struct block *parent;
	struct protocol_net_childblock *cb;

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
	num = len / sizeof(struct protocol_net_childblock);
	if (len % sizeof(struct protocol_net_childblock))
		return PROTOCOL_ECODE_INVALID_LEN;

	log_debug(peer->log, "Gave us %u children for ", num);
	log_add_struct(peer->log, struct protocol_block_id, &parent->sha);

	cb = (void *)(pkt + 1);
	for (i = 0; i < num; i++) {
		const struct block *b;

		b = block_find_any(peer->state, &cb[i].block);
		if (!b) {
			/* We'd better find out about this one... */
			log_debug(peer->log, "Asking about unknown block ");
			log_add_struct(peer->log, struct protocol_block_id,
				       &cb[i].block);
			todo_add_get_block(peer->state, &cb[i].block);
		} else {
			struct protocol_double_sha children_sha;

			/* If on our main chain, we'll find out about
			 * it anyway */
			if (block_preceeds(b, peer->state->preferred_chain))
				continue;

			/* If we disagree about descendents, dig down */
			hash_children(b, &children_sha);
			if (!structeq(&children_sha, &cb[i].descendents)) {
				log_debug(peer->log, "Getting more kids for ");
				log_add_struct(peer->log,
					       struct protocol_block_id,
					       &cb[i].block);
				
				todo_add_get_children(peer->state,
						      &cb[i].block);
			}
		}
	}

	/* FIXME: If we expected more children, mark this as false? */
	todo_done_get_children(peer, &pkt->block, true);

	return PROTOCOL_ECODE_NONE;
}
			


