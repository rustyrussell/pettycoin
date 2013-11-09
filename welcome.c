#include "welcome.h"
#include "state.h"
#include "version.h"

struct protocol_req_welcome *make_welcome(const tal_t *ctx,
					  const struct state *state,
					  const struct protocol_net_address *a)
{
	struct protocol_req_welcome *w = tal(ctx, struct protocol_req_welcome);
	w->len = cpu_to_le32(sizeof(*w) - sizeof(w->len));
	w->type = cpu_to_le32(PROTOCOL_REQ_WELCOME);
	w->version = cpu_to_le32(current_version());
	memcpy(w->moniker, "Can't believe it's not bitcoin!", 32);
	w->random = state->random_welcome;
	w->you = *a;
	w->listen_port = state->listen_port;
	memset(w->interests, 0xFF, sizeof(w->interests));
	return w;
}

static size_t popcount(const u8 *bits, size_t num)
{
	size_t n = 0, i;

	for (i = 0; i < num * CHAR_BIT; i++)
		if (bits[i/CHAR_BIT] & (1 << (i % CHAR_BIT)))
			n++;
	return n;
}

enum protocol_error check_welcome(const struct protocol_req_welcome *w)
{
	if (le32_to_cpu(w->len) < (sizeof(*w) - sizeof(w->len)))
		return PROTOCOL_INVALID_LEN;
	if (w->type != cpu_to_le32(PROTOCOL_REQ_WELCOME))
		return PROTOCOL_UNKNOWN_COMMAND;
	if (w->version != cpu_to_le32(current_version()))
		return PROTOCOL_ERROR_HIGH_VERSION;
	if (popcount(w->interests, sizeof(w->interests)) < 2)
		return PROTOCOL_ERROR_NO_INTEREST;

	return PROTOCOL_ERROR_NONE;
}
