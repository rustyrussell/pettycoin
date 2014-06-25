#ifndef PETTYCOIN_THASH_H
#define PETTYCOIN_THASH_H
#include <ccan/htable/htable_type.h>
#include <string.h>
#include <limits.h>
#include "protocol.h"
#include "hash_transaction.h"

struct thash_elem {
	struct protocol_double_sha sha;
	struct block *block;
	u16 shardnum;
	u8 txoff; /* Within shard. */
};

static inline const struct protocol_double_sha *
thash_keyof(const struct thash_elem *elem)
{
	return &elem->sha;
}

static inline size_t thash_hashfn(const struct protocol_double_sha *sha)
{
	/* We use at least 64 bits, to avoid hashchain bombing. */
	u64 hval;
	unsigned int i;

	memcpy(&hval, sha->sha, sizeof(hval));
	for (i = sizeof(size_t); i < sizeof(hval); i += sizeof(size_t))
		hval ^= (hval >> (i * CHAR_BIT));

	return hval;
}

static inline bool thash_eq(const struct thash_elem *elem,
			    const struct protocol_double_sha *sha)
{
	return memcmp(sha, &elem->sha, sizeof(elem->sha)) == 0;
}

HTABLE_DEFINE_TYPE(struct thash_elem,
		   thash_keyof, thash_hashfn, thash_eq, thash);

/* Since a transaction can appear in multiple blocks (different chains)... */
struct thash_elem *thash_firstval(struct thash *thash,
				  const struct protocol_double_sha *sha,
				  struct thash_iter *i);
struct thash_elem *thash_nextval(struct thash *thash,
				 const struct protocol_double_sha *sha,
				 struct thash_iter *i);

/* Get the actual transaction, we don't care about which block it's in */
union protocol_transaction *thash_gettrans(struct thash *thash,
					   const struct protocol_double_sha *);
#endif /* PETTYCOIN_THASH_H */
