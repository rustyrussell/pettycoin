#include "merkle_transactions.h"
#include "shadouble.h"
#include "hash_transaction.h"
#include "protocol.h"
#include <assert.h>
#include <string.h>

void merkle_transactions(const void *prefix, size_t prefix_len,
			 union protocol_transaction **t,
			 size_t num_trans,
			 struct protocol_double_sha *merkle)
{
	/* Always a power of 2. */
	assert((num_trans & (num_trans-1)) == 0);
	assert(num_trans != 0);

	if (num_trans == 1) {
		if (t[0] == NULL)
			memset(merkle, 0, sizeof(*merkle));
		else
			hash_transaction(t[0], prefix, prefix_len, merkle);
	} else {
		SHA256_CTX shactx;
		struct protocol_double_sha sub[2];

		num_trans /= 2;
		merkle_transactions(prefix, prefix_len, t, num_trans, sub);
		merkle_transactions(prefix, prefix_len, t + num_trans,
				    num_trans, sub+1);
		
		SHA256_Init(&shactx);
		SHA256_Update(&shactx, sub, sizeof(sub));
		SHA256_Double_Final(&shactx, merkle);
	}
}
