#include <ccan/array_size/array_size.h>
#include "merkle_transactions.h"
#include "prev_merkles.h"
#include "protocol.h"
#include "block.h"
#include "check_block.h"

size_t num_prev_merkles(const struct block *prev)
{
	size_t num = 0;
	unsigned int i;

	for (i = 0;
	     i < PETTYCOIN_PREV_BLOCK_MERKLES && prev;
	     i++, prev = prev->prev) {
		num += (1 << prev->hdr->shard_order);
	}

	return num;
}

u8 *make_prev_merkles(const tal_t *ctx, const struct block *prev,
		      const struct protocol_address *my_addr)
{
	unsigned int i;
	size_t len;
	u8 *m, *p;

	len = num_prev_merkles(prev);
	p = m = tal_arr(ctx, u8, len);

	for (i = 0;
	     i < PETTYCOIN_PREV_BLOCK_MERKLES && prev;
	     i++, prev = prev->prev) {
		unsigned int j;

		for (j = 0; j < (1 << prev->hdr->shard_order); j++) {
			struct protocol_double_sha merkle;

			/* We need to know everything in shard to check
			 * previous merkle. */
			if (!shard_all_known(prev, j))
				return tal_free(m);

			/* Merkle has block reward address prepended, so you
			 * can prove you know all the transactions. */
			merkle_transactions(my_addr, sizeof(*my_addr),
					    prev->shard[j]->txp_or_hash,
					    prev->shard[j]->u,
					    0, prev->shard_nums[j],
					    &merkle);

			/* We only save one byte. */
			*p = merkle.sha[0];
			p++;
		}
	}
	assert(p == m + len);

	return m;
}
