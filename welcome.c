#include "block.h"
#include "shard.h"
#include "state.h"
#include "tal_packet.h"
#include "version.h"
#include "welcome.h"
#include <ccan/structeq/structeq.h>

static void add_welcome_blocks(const struct state *state,
			       struct protocol_pkt_welcome **w)
{
	const struct block *b, *last;
	unsigned int n, step;

	/* We tell them about the best chain we know which we can offer
	 * information.  If that's not the same as longest_chain, that's
	 * because we can't get the transactions from that. */
	last = b = state->preferred_chain;

	tal_packet_append_sha(w, &b->sha);

	for (n = 1; b; n++) {
		unsigned int i;

		if (n < 10)
			step = 1;
		else
			step *= 2;

		for (i = 0; i < step; i++) {
			b = b->prev;
			if (!b)
				goto out;
		}

		tal_packet_append_sha(w, &b->sha);
		last = b;
	}

out:
	/* Always include the genesis block. */
	b = genesis_block(state);
	if (last != b) {
		tal_packet_append_sha(w, &b->sha);
		n++;
	}

	(*w)->num_blocks = cpu_to_le16(n);
}

static void add_interests(const struct state *state,
			  struct protocol_pkt_welcome **w,
			  u8 shard_order)
{
	size_t i, maplen = ((1 << shard_order) + 31) / 32 * 4;
	u8 *map = tal_arrz(*w, u8, maplen);

	for (i = 0; i < (1 << shard_order); i++)
		if (interested_in_shard(state, i, shard_order))
			map[i / 8] |= (1 << (i % 8));

	(*w)->shard_order = shard_order;
	tal_packet_append(w, map, maplen);
	tal_free(map);
}

struct protocol_pkt_welcome *make_welcome(const tal_t *ctx,
					  const struct state *state,
					  const struct protocol_net_address *a)
{
	struct protocol_pkt_welcome *w;

	w = tal_packet(ctx, struct protocol_pkt_welcome,
		       PROTOCOL_PKT_WELCOME);
	w->version = cpu_to_le32(current_version());
	memcpy(w->moniker, "ICBINB! " VERSION "                        ", 32);
	w->random = state->random_welcome;
	w->you = *a;
	w->listen_port = state->listen_port;
	w->unused = 0;
	add_interests(state, &w, state->preferred_chain->hdr->shard_order);
	add_welcome_blocks(state, &w);

	return w;
}

static size_t popcount(const u8 *bits, size_t num_bits)
{
	size_t n = 0, i;

	for (i = 0; i < num_bits; i++)
		if (bits[i/CHAR_BIT] & (1 << (i % CHAR_BIT)))
			n++;
	return n;
}

enum protocol_ecode check_welcome(const struct state *state,
				  const struct protocol_pkt_welcome *w,
				  const struct protocol_double_sha **blocks)
{
	size_t len = le32_to_cpu(w->len), interest_len;
	const u8 *interest;
	const struct block *genesis = genesis_block(state);

	if (len < sizeof(*w))
		return PROTOCOL_ECODE_INVALID_LEN;
	if (w->type != cpu_to_le32(PROTOCOL_PKT_WELCOME))
		return PROTOCOL_ECODE_UNKNOWN_COMMAND;
	if (w->version != cpu_to_le32(current_version()))
		return PROTOCOL_ECODE_HIGH_VERSION;

	len -= sizeof(*w);

	/* Check number of shards and shard interest bitmap */
	if (w->shard_order < PROTOCOL_INITIAL_SHARD_ORDER)
		return PROTOCOL_ECODE_BAD_SHARD_ORDER;
	/* Must be reasonable. */
	if (w->shard_order > PROTOCOL_MAX_SHARD_ORDER)
		return PROTOCOL_ECODE_BAD_SHARD_ORDER;

	/* Interest map follows base welcome struct. */
	interest = (u8 *)(w + 1);
	interest_len = (((size_t)1 << w->shard_order) + 31) / 32 * 4;
	if (len < interest_len)
		return PROTOCOL_ECODE_INVALID_LEN;
	if (popcount(interest, (size_t)1 << w->shard_order) < 2)
		return PROTOCOL_ECODE_NO_INTEREST;

	len -= interest_len;

	/* Blocks follow interest map. */
	(*blocks) = (struct protocol_double_sha *)(interest + interest_len);

	/* At least one block. */
	if (le16_to_cpu(w->num_blocks) < 1)
		return PROTOCOL_ECODE_INVALID_LEN;
	if (len != le16_to_cpu(w->num_blocks) * sizeof((*blocks)[0]))
		return PROTOCOL_ECODE_INVALID_LEN;

	/* We must agree on genesis block. */
	if (!structeq(&(*blocks)[le16_to_cpu(w->num_blocks)-1], &genesis->sha))
		return PROTOCOL_ECODE_WRONG_GENESIS;

	return PROTOCOL_ECODE_NONE;
}
