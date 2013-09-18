#include "../create_transaction.c"
#include "../check_transaction.c"
#include "../shadouble.c"
#include "../hash_transaction.c"
#include <assert.h>
#include "helper_gateway_key.h"
#include "helper_key.h"

struct block *block_find(struct block *start, const u8 lower_sha[4])
{
	abort();
}

bool accept_gateway(const struct state *state,
		    const struct protocol_pubkey *key)
{
	return (memcmp(key, helper_gateway_public_key(), sizeof(*key)) == 0);
}

int main(int argc, char *argv[])
{
	union protocol_transaction *t;
	struct state *s = tal(NULL, struct state);
	struct protocol_gateway_payment *payment;
	union protocol_transaction **trans;

	/* Single payment. */
	payment = tal_arr(s, struct protocol_gateway_payment, 1);
	payment[0].send_amount = cpu_to_le32(1000);
	payment[0].output_addr = *helper_addr(0);
	t = create_gateway_transaction(s, helper_gateway_public_key(),
				       1, payment, helper_gateway_key());
	assert(t);
	assert(t->gateway.version == current_version());
	assert(version_ok(t->gateway.version));
	assert(t->gateway.features == 0);
	assert(memcmp(&t->gateway.gateway_key, helper_gateway_public_key(),
		      sizeof(t->gateway.gateway_key)) == 0);
	assert(le32_to_cpu(t->gateway.num_outputs) == 1);
	assert(le32_to_cpu(t->gateway.output[0].send_amount) == 1000);
	assert(memcmp(&t->gateway.output[0].output_addr,
		      helper_addr(0),
		      sizeof(t->gateway.output[0].output_addr)) == 0);

	trans = tal_arr(s, union protocol_transaction *, 1);
	trans[0] = t;
	assert(check_transaction(s, trans, NULL));

	/* Two payments. */
	payment = tal_arr(s, struct protocol_gateway_payment, 2);
	payment[0].send_amount = cpu_to_le32(1000);
	payment[0].output_addr = *helper_addr(0);
	payment[1].send_amount = cpu_to_le32(2000);
	payment[1].output_addr = *helper_addr(1);
	t = create_gateway_transaction(s, helper_gateway_public_key(),
				       2, payment, helper_gateway_key());
	assert(t);
	assert(t->gateway.version == current_version());
	assert(version_ok(t->gateway.version));
	assert(t->gateway.features == 0);
	assert(memcmp(&t->gateway.gateway_key, helper_gateway_public_key(),
		      sizeof(t->gateway.gateway_key)) == 0);
	assert(le32_to_cpu(t->gateway.num_outputs) == 2);
	assert(le32_to_cpu(t->gateway.output[0].send_amount) == 1000);
	assert(memcmp(&t->gateway.output[0].output_addr,
		      helper_addr(0),
		      sizeof(t->gateway.output[0].output_addr)) == 0);
	assert(le32_to_cpu(t->gateway.output[1].send_amount) == 2000);
	assert(memcmp(&t->gateway.output[1].output_addr,
		      helper_addr(1),
		      sizeof(t->gateway.output[1].output_addr)) == 0);

	trans = tal_arr(s, union protocol_transaction *, 1);
	trans[0] = t;
	assert(check_transaction(s, trans, NULL));

	/* Now try changing it. */
	t->gateway.version++;
	assert(!check_transaction(s, trans, NULL));
	t->gateway.version--;

	t->gateway.features++;
	assert(!check_transaction(s, trans, NULL));
	t->gateway.features--;

	t->gateway.type++;
	assert(!check_transaction(s, trans, NULL));
	t->gateway.type--;

	t->gateway.num_outputs = cpu_to_le32(le32_to_cpu(t->gateway.num_outputs)
					     - 1);
	assert(!check_transaction(s, trans, NULL));
	t->gateway.num_outputs = cpu_to_le32(le32_to_cpu(t->gateway.num_outputs)
					     + 1);

	t->gateway.output[0].send_amount ^= cpu_to_le32(1);
	assert(!check_transaction(s, trans, NULL));
	t->gateway.output[0].send_amount ^= cpu_to_le32(1);

	t->gateway.output[0].output_addr.addr[0]++;
	assert(!check_transaction(s, trans, NULL));
	t->gateway.output[0].output_addr.addr[0]--;

	t->gateway.output[1].send_amount ^= cpu_to_le32(1);
	assert(!check_transaction(s, trans, NULL));
	t->gateway.output[1].send_amount ^= cpu_to_le32(1);

	t->gateway.output[1].output_addr.addr[0]++;
	assert(!check_transaction(s, trans, NULL));
	t->gateway.output[1].output_addr.addr[0]--;

	/* We restored it ok? */
	assert(check_transaction(s, trans, NULL));

	/* Try signing it with non-gateway key. */
	trans[0] = create_gateway_transaction(s, helper_public_key(0),
					      2, payment,
					      helper_private_key(0));
	assert(!check_transaction(s, trans, NULL));

	tal_free(s);
	return 0;
}
