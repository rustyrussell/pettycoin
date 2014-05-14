#include "hash_block.h"
#include "block.h"
#include "shadouble.h"
#include <stdio.h>

void hash_block(const struct protocol_block_header *hdr,
		const struct protocol_double_sha *merkles,
		const u8 *prev_merkles,
		const struct protocol_block_tailer *tailer,
		struct protocol_double_sha *sha)
{
	SHA256_CTX shactx;
	struct protocol_double_sha hash_of_prev, hash_of_merkles;

	/* First hash the prev_merkles. */
	SHA256_Init(&shactx);
	SHA256_Update(&shactx, prev_merkles,
		      le32_to_cpu(hdr->num_prev_merkles)
		      * sizeof(prev_merkles[0]));
	SHA256_Double_Final(&shactx, &hash_of_prev);

	/* Now hash the merkles of this block's transactions. */
	SHA256_Init(&shactx);
	SHA256_Update(&shactx, merkles,
		      num_batches(le32_to_cpu(hdr->num_transactions))
		      * sizeof(merkles[0]));
	SHA256_Double_Final(&shactx, &hash_of_merkles);

	/* Now hash them all together. */
	SHA256_Init(&shactx);
	SHA256_Update(&shactx, &hash_of_prev, sizeof(hash_of_prev));
	SHA256_Update(&shactx, &hash_of_merkles, sizeof(hash_of_merkles));
	SHA256_Update(&shactx, hdr, sizeof(*hdr));
	SHA256_Update(&shactx, tailer, sizeof(*tailer));
	SHA256_Double_Final(&shactx, sha);
}

