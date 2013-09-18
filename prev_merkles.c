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
		num += num_merkles(le32_to_cpu(prev->hdr->num_transactions));
	}

	return num;
}

u8 *make_prev_merkles(const tal_t *ctx,
		      struct state *state, const struct block *prev,
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
		u32 prev_trans = le32_to_cpu(prev->hdr->num_transactions);

		for (j = 0; j < num_merkles(prev_trans); j++) {
			struct protocol_double_sha merkle;

			/* We need to know everything in batch to check
			 * previous merkle. */
			if (!batch_full(prev, prev->batch[j]))
				return tal_free(m);

			/* Merkle has block reward address prepended, so you
			 * can prove you know all the transactions. */
			merkle_transactions(my_addr, sizeof(*my_addr),
					    prev->batch[j]->t,
					    ARRAY_SIZE(prev->batch[j]->t),
					    &merkle);

			/* We only save one byte. */
			*p = merkle.sha[0];
			p++;
		}
	}
	assert(p == m + len);

	return m;
}
