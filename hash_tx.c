#include "hash_tx.h"
#include "marshal.h"
#include "merkle_recurse.h"
#include "protocol.h"
#include "shadouble.h"
#include "tx.h"
#include <assert.h>

void hash_refs(const struct protocol_input_ref *refs,
	       size_t num_refs,
	       struct protocol_double_sha *sha)
{
	SHA256_CTX shactx;

	/* Get double sha of references (may be 0 for non-normal trans) */
	SHA256_Init(&shactx);
	SHA256_Update(&shactx, refs, sizeof(refs[0]) * num_refs);
	SHA256_Double_Final(&shactx, sha);
}

void hash_tx_and_refs(const union protocol_tx *tx,
		      const struct protocol_input_ref *refs,
		      struct protocol_txrefhash *txrefhash)
{
	hash_tx(tx, &txrefhash->txhash);
	hash_refs(refs, num_inputs(tx), &txrefhash->refhash);
}
 
void hash_tx(const union protocol_tx *tx,
	     struct protocol_double_sha *sha)
{
	SHA256_CTX shactx;

	SHA256_Init(&shactx);
	SHA256_Update(&shactx, tx, marshal_tx_len(tx));
	SHA256_Double_Final(&shactx, sha);
}
