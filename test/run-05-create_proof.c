#include "../timestamp.c"
#include "../proof.c"
#include "../check_transaction.c"
#include "../merkle_transactions.c"
#include "../block.c"
#include "../hash_transaction.c"
#include "../shadouble.c"
#include "../create_transaction.c"
#include "../hash_block.c"
#include "../prev_merkles.c"
#include "../check_block.c"
#include "../difficulty.c"
#include "../transaction_cmp.c"
#include "../state.c"
#include "../pseudorand.c"
#include "../marshall.c"
#include "../log.c"
#include <ccan/tal/tal.h>
#include <ccan/list/list.h>
#include "trans_named.c"

/* Here's a genesis block we created earlier */
static struct protocol_block_header genesis_hdr = {
	.version = 1,
	.features_vote = 0,
	.nonce2 = { 0x54, 0x45, 0x53, 0x54, 0x43, 0x4f, 0x44, 0x45, 0x54, 0x45, 0x53, 0x54, 0x45, 0x45  },
	.fees_to = { { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  } }
};
static struct protocol_block_tailer genesis_tlr = {
	.timestamp = CPU_TO_LE32(1378616576),
	.difficulty = CPU_TO_LE32(0x1effffff),
	.nonce1 = CPU_TO_LE32(21216)
};
struct block genesis = {
	.hdr = &genesis_hdr,
	.tailer = &genesis_tlr,
	.sha = { { 0x79, 0xee, 0xfb, 0x0d, 0x2e, 0x57, 0xe8, 0x2d, 0x0a, 0x5a, 0xb0, 0x6c, 0x96, 0x95, 0x8b, 0x0f, 0x56, 0xed, 0x7f, 0x9f, 0x57, 0xd2, 0x72, 0x98, 0xb6, 0x0d, 0xb7, 0xe4, 0xa7, 0x58, 0x00, 0x00  }}
};

void restart_generating(struct state *state)
{
}

void update_peers_mutual(struct state *state)
{
}

bool accept_gateway(const struct state *state,
		    const struct protocol_pubkey *key)
{
	return (memcmp(key, helper_gateway_public_key(), sizeof(*key)) == 0);
}

int main(int argc, char *argv[])
{
	struct state *s;
	struct block *b[5];
	struct protocol_proof *proof;
	union protocol_transaction *t, **transarr;

	pseudorand_init();
	s = new_state(true);

	/* Gateway payment to addresses 0, 1 and 2 */
	named_gateway(s, "gateway1", 1000, 0, 1, 2, -1);

	b[0] = block_with_names(s);

	/* Now address 0 pays 500 to address 3. */
	t = named_trans(s, "0to3", 0, 3, 500, "gateway1-0", NULL);

	proof = create_proof(s, t, &transarr);
	assert(tal_count(transarr) == 2);
	assert(tal_count(proof) == 1);

	assert(check_transaction_proof(s, transarr, proof));

	/* Now address 1 pays 500 to address 3. */
	t = named_trans(s, "1to3", 1, 3, 500, "gateway1-1", NULL);

	proof = create_proof(s, t, &transarr);
	assert(tal_count(transarr) == 2);
	assert(tal_count(proof) == 1);

	assert(check_transaction_proof(s, transarr, proof));

	/* Both go into block. */
	b[1] = block_with_names(s);

	/* Now address 3 uses both of those to pay 2. */
	t = named_trans(s, "3to2", 3, 2, 750, "0to3", "1to3", NULL);

	proof = create_proof(s, t, &transarr);
	/* This doubles up on the gateway transaction, but that's unusual. */
	assert(tal_count(transarr) == 5);
	assert(tal_count(proof) == 4);

	assert(check_transaction_proof(s, transarr, proof));

	b[2] = block_with_names(s);

	/* Now address 2 uses that to pay 4. */
	t = named_trans(s, "3to4", 2, 4, 375, "3to2", NULL);

	proof = create_proof(s, t, &transarr);
	assert(tal_count(transarr) == 6);
	assert(tal_count(proof) == 5);

	assert(check_transaction_proof(s, transarr, proof));

	tal_free(s);
	return 0;
}
