#include "hash_tx.h"
#include "marshal.h"
#include "protocol.h"
#include "shadouble.h"
#include "merkle_recurse.h"
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
		      struct protocol_net_txrefhash *txrefhash)
{
	hash_tx(tx, &txrefhash->txhash);
	hash_refs(refs, num_inputs(tx), &txrefhash->refhash);
}
 
/*
 * Inside a block, the hash is combined with the input
 * back-references.  To demonstrate our knowledge of previous blocks,
 * we prepend the reward address to the tx before hashing (into
 * "prev_merkles").  This function can do both.
 */
void hash_tx_for_block(const union protocol_tx *tx,
		       const void *hash_prefix,
		       size_t hash_prefix_len,
		       const struct protocol_input_ref *refs,
		       size_t num_refs,
		       struct protocol_double_sha *sha)
{
	SHA256_CTX shactx;
	struct protocol_double_sha txsha, refsha;

	/* Get double sha of transaction (prefix is for prev_merkle calc). */
	SHA256_Init(&shactx);
	/* Note: if hash_prefix_len == 0, this is exactly hash_tx() */
	SHA256_Update(&shactx, hash_prefix, hash_prefix_len);
	SHA256_Update(&shactx, tx, marshal_tx_len(tx));
	SHA256_Double_Final(&shactx, &txsha);

	/* Get double sha of references (may be 0 for non-normal trans) */
	hash_refs(refs, num_refs, &refsha);

	/* Get SHA of the two, together. */
	merkle_two_hashes(&txsha, &refsha, sha);
}

void hash_tx(const union protocol_tx *tx,
	     struct protocol_double_sha *sha)
{
	SHA256_CTX shactx;

	SHA256_Init(&shactx);
	SHA256_Update(&shactx, tx, marshal_tx_len(tx));
	SHA256_Double_Final(&shactx, sha);
}
