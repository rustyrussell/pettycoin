#include "txhash.h"
#include "block.h"

static struct txhash_elem *txhash_i(struct htable *ht,
				    const struct protocol_double_sha *sha,
				    struct txhash_elem *te,
				    struct txhash_iter *i,
				    size_t h)
{
	while (te) {
		if (txhash_eq(te, sha))
			break;
		te = htable_nextval(ht, &i->i, h);
	}
	return te;
}

struct txhash_elem *txhash_firstval(struct txhash *txhash,
				    const struct protocol_double_sha *sha,
				    struct txhash_iter *i)
{
	size_t h = txhash_hashfn(sha);

	return txhash_i(&txhash->raw, sha,
			htable_firstval(&txhash->raw, &i->i, h),
			i, h);
}

struct txhash_elem *txhash_nextval(struct txhash *txhash,
				   const struct protocol_double_sha *sha,
				   struct txhash_iter *i)
{
	size_t h = txhash_hashfn(sha);

	return txhash_i(&txhash->raw, sha,
			htable_nextval(&txhash->raw, &i->i, h),
			i, h);
}

/* Get the actual transaction, we don't care about which block it's in */
union protocol_tx *txhash_gettx(struct txhash *txhash,
				const struct protocol_double_sha *sha)
{
	struct txhash_iter i;
	struct txhash_elem *te = txhash_firstval(txhash, sha, &i);
	union protocol_tx *tx;

	if (!te)
		return NULL;

	/* Can't be in hash if it doesn't exist. */
	tx = block_get_tx(te->block, te->shardnum, te->txoff);
	assert(tx);
	return tx;
}
