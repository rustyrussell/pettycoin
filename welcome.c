#include "welcome.h"
#include "protocol_net.h"
#include "state.h"
#include "version.h"

struct protocol_req_welcome *make_welcome(const tal_t *ctx,
					  const struct state *state,
					  const struct protocol_net_address *a)
{
	struct protocol_req_welcome *w = tal(ctx, struct protocol_req_welcome);
	w->len = cpu_to_le32(sizeof(*w) - sizeof(w->len));
	w->type = cpu_to_le32(PROTOCOL_REQ_WELCOME);
	w->version = current_version();
	memcpy(w->moniker, "Can't believe it's not bitcoin!", 32);
	w->random = state->random_welcome;
	w->you = *a;
	w->listen_port = state->listen_port;
	memset(w->interests, 0xFF, sizeof(w->interests));
	return w;
}
