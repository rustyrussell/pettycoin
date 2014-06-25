#include "thash.h"
#include "block.h"

static struct thash_elem *thash_i(struct htable *ht,
				  const struct protocol_double_sha *sha,
				  struct thash_elem *te,
				  struct thash_iter *i,
				  size_t h)
{
	while (te) {
		if (thash_eq(te, sha))
			break;
		te = htable_nextval(ht, &i->i, h);
	}
	return te;
}

struct thash_elem *thash_firstval(struct thash *thash,
				 const struct protocol_double_sha *sha,
				 struct thash_iter *i)
{
	size_t h = thash_hashfn(sha);

	return thash_i(&thash->raw, sha, htable_firstval(&thash->raw, &i->i, h),
		       i, h);
}

struct thash_elem *thash_nextval(struct thash *thash,
				 const struct protocol_double_sha *sha,
				 struct thash_iter *i)
{
	size_t h = thash_hashfn(sha);

	return thash_i(&thash->raw, sha, htable_nextval(&thash->raw, &i->i, h),
		       i, h);
}

/* Get the actual transaction, we don't care about which block it's in */
union protocol_transaction *thash_gettrans(struct thash *thash,
					   const struct protocol_double_sha *sha)
{
	struct thash_iter i;
	struct thash_elem *te = thash_firstval(thash, sha, &i);
	union protocol_transaction *t;

	if (!te)
		return NULL;

	/* Can't be in hash if it doesn't exist. */
	t = block_get_tx(te->block, te->shardnum, te->txoff);
	assert(t);
	return t;
}
