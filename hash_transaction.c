#include "hash_transaction.h"
#include "overflows.h"
#include "protocol.h"
#include "shadouble.h"
#include <assert.h>
#include <stdlib.h>

void hash_transaction(const union protocol_transaction *t,
			     const void *hash_prefix,
			     size_t hash_prefix_len,
			     struct protocol_double_sha *sha)
{
	const void *data1, *data2;
	size_t len1, len2;
	SHA256_CTX shactx;

	switch (t->hdr.type) {
	case TRANSACTION_NORMAL:
		data1 = t;
		len1 = offsetof(struct protocol_transaction_normal, signature);

		assert(!mul_overflows(sizeof(t->normal.input[0]),
				      le32_to_cpu(t->normal.num_inputs)));
		data2 = &t->normal.input[0];
		len2 = sizeof(t->normal.input[0])
			* le32_to_cpu(t->normal.num_inputs);
		break;
	case TRANSACTION_FROM_GATEWAY:
		data1 = t;
		len1 = offsetof(struct protocol_transaction_gateway, signature);

		assert(!mul_overflows(sizeof(t->gateway.output[0]),
				      le16_to_cpu(t->gateway.num_outputs)));
		data2 = &t->gateway.output[0];
		len2 = sizeof(t->gateway.output[0])
			* le16_to_cpu(t->gateway.num_outputs);
		break;
	default:
		abort();
	}

	/* Get double sha of transaction. */
	SHA256_Init(&shactx);
	SHA256_Update(&shactx, hash_prefix, hash_prefix_len);
	SHA256_Update(&shactx, data1, len1);
	SHA256_Update(&shactx, data2, len2);
	SHA256_Double_Final(&shactx, sha);
}

