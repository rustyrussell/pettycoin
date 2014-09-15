#include "block.h"
#include "chain.h"
#include "check_block.h"
#include "merkle_txs.h"
#include "prev_txhashes.h"
#include "protocol.h"
#include "shadouble.h"
#include "shard.h"
#include <ccan/array_size/array_size.h>

size_t num_prev_txhashes(const struct block *prev_block)
{
	size_t num = 0;
	unsigned int i;
	const struct block *b;

	for_each_prev_txhash(i, b, prev_block)
		num += num_shards(b->bi.hdr);

	return num;
}

/* Hash has block reward address prepended, so you can prove you know
 * all the transactions. */
u8 prev_txhash(const struct protocol_address *addr,
	       const struct block *block, u16 shard)
{
	SHA256_CTX shactx;
	struct protocol_double_sha sha;
	unsigned int i; 

	SHA256_Init(&shactx);
	SHA256_Update(&shactx, addr, sizeof(*addr));

	for (i = 0; i < block->bi.num_txs[shard]; i++) {
		const union protocol_tx *tx;
		const struct protocol_input_ref *refs;

		tx = block_get_tx(block, shard, i);
		refs = block_get_refs(block, shard, i);

		SHA256_Update(&shactx, tx, marshal_tx_len(tx));
		SHA256_Update(&shactx, refs, marshal_input_ref_len(tx));
	}
	SHA256_Double_Final(&shactx, &sha);

	/* We only use top byte. */
	return sha.sha[0];
}

u8 *make_prev_txhashes(const tal_t *ctx, const struct block *prev_block,
		      const struct protocol_address *my_addr)
{
	const struct block *b;
	unsigned int i;
	size_t len;
	u8 *m, *p;

	len = num_prev_txhashes(prev_block);
	p = m = tal_arr(ctx, u8, len);

	for_each_prev_txhash(i, b, prev_block) {
		unsigned int j;

		for (j = 0; j < num_shards(b->bi.hdr); j++) {
			/* We need to know everything in shard to check
			 * previous txhash. */
			if (!shard_all_known(b->shard[j]))
				return tal_free(m);

			*p = prev_txhash(my_addr, b, j);
			p++;
		}
	}
	assert(p == m + len);

	return m;
}
