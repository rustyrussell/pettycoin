#include "gateways.h"
#include "state.h"
#include <assert.h>

bool accept_gateway(const struct state *state,
		    const struct protocol_pubkey *key)
{
	/* Everyone can be a gateway on testnet! */
	assert(state->test_net);
	return true;
}
