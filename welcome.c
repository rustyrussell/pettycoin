#include "block.h"
#include "shard.h"
#include "state.h"
#include "tal_packet.h"
#include "version.h"
#include "welcome.h"
#include <ccan/structeq/structeq.h>

struct protocol_pkt_welcome *make_welcome(const tal_t *ctx,
					  const struct state *state,
					  const struct protocol_net_address *a)
{
	struct protocol_pkt_welcome *w;

	w = tal_packet(ctx, struct protocol_pkt_welcome,
		       PROTOCOL_PKT_WELCOME);
	w->version = cpu_to_le32(current_version());
	memset(w->moniker, 0, sizeof(w->moniker));
	strncpy(w->moniker, "ICBINB! " VERSION, sizeof(w->moniker));
	w->uuid = state->uuid;
	w->you = *a;
	w->listen_port = cpu_to_le16(state->listen_port);
	memcpy(w->interests, state->interests, sizeof(w->interests));

	/* This is the best block we can tell them about. */
	if (state->longest_knowns[0] != genesis_block(state))
		tal_packet_append_block(&w, state->longest_knowns[0]);
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

enum protocol_ecode check_welcome(const struct peer *peer,
				  const struct protocol_pkt_welcome *w,
				  const struct protocol_block_header **block_hdr,
				  size_t *block_len)
{
	size_t len = le32_to_cpu(w->len);

	if (len < sizeof(*w))
		return PROTOCOL_ECODE_INVALID_LEN;
	if (w->type != cpu_to_le32(PROTOCOL_PKT_WELCOME))
		return PROTOCOL_ECODE_UNKNOWN_COMMAND;
	if (w->version != cpu_to_le32(current_version()))
		return PROTOCOL_ECODE_HIGH_VERSION;
	/* This is too lenient, but future-proof. */
	if (popcount(w->interests, 65536) < 2)
		return PROTOCOL_ECODE_NO_INTEREST;

	len -= sizeof(*w);
	*block_hdr = (const struct protocol_block_header *)(w + 1);
	*block_len = len;

	return PROTOCOL_ECODE_NONE;
}
