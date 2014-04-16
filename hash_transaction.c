#include "hash_transaction.h"
#include "marshall.h"
#include "protocol.h"
#include "shadouble.h"

void hash_transaction(const union protocol_transaction *t,
			     const void *hash_prefix,
			     size_t hash_prefix_len,
			     struct protocol_double_sha *sha)
{
	SHA256_CTX shactx;

	/* Get double sha of transaction. */
	SHA256_Init(&shactx);
	SHA256_Update(&shactx, hash_prefix, hash_prefix_len);
	SHA256_Update(&shactx, t, marshall_transaction_len(t));
	SHA256_Double_Final(&shactx, sha);
}

