#include "../create_tx.c"
#include "../check_tx.c"
#include "../shadouble.c"
#include "../signature.c"
#include "../txhash.c"
#include "../minimal_log.c"
#include "../marshall.c"
#include "../proof.c"
#include "../shard.c"
#include "../merkle_txs.c"
#include "../hash_tx.c"
#include "../tx.c"
#include <assert.h>
#include "helper_gateway_key.h"
#include "helper_key.h"
#include "helper_fakenewstate.h"

bool accept_gateway(const struct state *state,
		    const struct protocol_pubkey *key)
{
	return (memcmp(key, helper_gateway_public_key(), sizeof(*key)) == 0);
}

int main(int argc, char *argv[])
{
	union protocol_tx *t;
	struct state *s = fake_new_state();
	struct protocol_gateway_payment *payment;
	struct protocol_gateway_payment *out;

	/* Single payment. */
	payment = tal_arr(s, struct protocol_gateway_payment, 1);
	payment[0].send_amount = cpu_to_le32(1000);
	payment[0].output_addr = *helper_addr(0);
	t = create_gateway_tx(s, helper_gateway_public_key(),
				       1, payment, helper_gateway_key());
	assert(t);
	out = get_gateway_outputs(&t->gateway);
	assert(t->gateway.version == current_version());
	assert(version_ok(t->gateway.version));
	assert(t->gateway.features == 0);
	assert(memcmp(&t->gateway.gateway_key, helper_gateway_public_key(),
		      sizeof(t->gateway.gateway_key)) == 0);
	assert(le16_to_cpu(t->gateway.num_outputs) == 1);
	assert(le16_to_cpu(t->gateway.unused) == 0);
	assert(le32_to_cpu(out[0].send_amount) == 1000);
	assert(memcmp(&out[0].output_addr, helper_addr(0),
		      sizeof(out[0].output_addr)) == 0);

	assert(check_tx(s, t, NULL, NULL, NULL, NULL) == PROTOCOL_ECODE_NONE);

	/* Two payments (must be same shard!) */
	payment = tal_arr(s, struct protocol_gateway_payment, 2);
	payment[0].send_amount = cpu_to_le32(1000);
	payment[0].output_addr = *helper_addr(0);
	payment[1].send_amount = cpu_to_le32(2000);
	payment[1].output_addr = *helper_addr(1);
	t = create_gateway_tx(s, helper_gateway_public_key(),
				       2, payment, helper_gateway_key());
	assert(t);
	out = get_gateway_outputs(&t->gateway);
	assert(t->gateway.version == current_version());
	assert(version_ok(t->gateway.version));
	assert(t->gateway.features == 0);
	assert(le16_to_cpu(t->gateway.unused) == 0);
	assert(memcmp(&t->gateway.gateway_key, helper_gateway_public_key(),
		      sizeof(t->gateway.gateway_key)) == 0);
	assert(le16_to_cpu(t->gateway.num_outputs) == 2);
	assert(le32_to_cpu(out[0].send_amount) == 1000);
	assert(memcmp(&out[0].output_addr, helper_addr(0),
		      sizeof(out[0].output_addr)) == 0);
	assert(le32_to_cpu(out[1].send_amount) == 2000);
	assert(memcmp(&out[1].output_addr, helper_addr(1),
		      sizeof(out[1].output_addr)) == 0);

	assert(check_tx(s, t, NULL, NULL, NULL, NULL)
	       == PROTOCOL_ECODE_NONE);

	/* Now try changing it. */
	t->gateway.version++;
	assert(check_tx(s, t, NULL, NULL, NULL, NULL)
	       == PROTOCOL_ECODE_TX_HIGH_VERSION);
	t->gateway.version--;

	t->gateway.features++;
	assert(check_tx(s, t, NULL, NULL, NULL, NULL)
	       == PROTOCOL_ECODE_TX_BAD_SIG);
	t->gateway.features--;

	t->gateway.type++;
	assert(check_tx(s, t, NULL, NULL, NULL, NULL)
	       == PROTOCOL_ECODE_TX_UNKNOWN);
	t->gateway.type--;

	t->gateway.num_outputs = cpu_to_le16(le16_to_cpu(t->gateway.num_outputs)
					     - 1);
	assert(check_tx(s, t, NULL, NULL, NULL, NULL)
	       == PROTOCOL_ECODE_TX_BAD_SIG);
	t->gateway.num_outputs = cpu_to_le16(le16_to_cpu(t->gateway.num_outputs)
					     + 1);

	out[0].send_amount ^= cpu_to_le32(1);
	assert(check_tx(s, t, NULL, NULL, NULL, NULL)
	       == PROTOCOL_ECODE_TX_BAD_SIG);
	out[0].send_amount ^= cpu_to_le32(1);

	out[0].output_addr.addr[0]++;
	assert(check_tx(s, t, NULL, NULL, NULL, NULL)
	       == PROTOCOL_ECODE_TX_BAD_SIG);
	out[0].output_addr.addr[0]--;

	out[1].send_amount ^= cpu_to_le32(1);
	assert(check_tx(s, t, NULL, NULL, NULL, NULL)
	       == PROTOCOL_ECODE_TX_BAD_SIG);
	out[1].send_amount ^= cpu_to_le32(1);

	out[1].output_addr.addr[0]++;
	assert(check_tx(s, t, NULL, NULL, NULL, NULL)
	       == PROTOCOL_ECODE_TX_BAD_SIG);
	out[1].output_addr.addr[0]--;

	/* We restored it ok? */
	assert(check_tx(s, t, NULL, NULL, NULL, NULL)
	       == PROTOCOL_ECODE_NONE);

	/* Try signing it with non-gateway key. */
	t = create_gateway_tx(s, helper_public_key(0),
				       2, payment,
				       helper_private_key(0));
	assert(check_tx(s, t, NULL, NULL, NULL, NULL)
	       == PROTOCOL_ECODE_TX_BAD_GATEWAY);

	tal_free(s);
	return 0;
}
