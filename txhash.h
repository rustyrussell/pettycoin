#ifndef PETTYCOIN_TXHASH_H
#define PETTYCOIN_TXHASH_H
#include "config.h"
#include "hash_tx.h"
#include "protocol.h"
#include <ccan/htable/htable_type.h>
#include <ccan/tal/tal.h>
#include <limits.h>
#include <string.h>

struct txhash_elem {
	struct protocol_double_sha sha;
	struct block *block;
	u16 shardnum;
	u8 txoff; /* Within shard. */
};

static inline const struct protocol_double_sha *
txhash_keyof(const struct txhash_elem *elem)
{
	return &elem->sha;
}

static inline size_t txhash_hashfn(const struct protocol_double_sha *sha)
{
	/* We use at least 64 bits, to avoid hashchain bombing. */
	u64 hval;
	unsigned int i;

	memcpy(&hval, sha->sha, sizeof(hval));
	for (i = sizeof(size_t); i < sizeof(hval); i += sizeof(size_t))
		hval ^= (hval >> (i * CHAR_BIT));

	return hval;
}

static inline bool txhash_eq(const struct txhash_elem *elem,
			    const struct protocol_double_sha *sha)
{
	return memcmp(sha, &elem->sha, sizeof(elem->sha)) == 0;
}

HTABLE_DEFINE_TYPE(struct txhash_elem,
		   txhash_keyof, txhash_hashfn, txhash_eq, txhash);

/* Since a transaction can appear in multiple blocks (different chains)... */
struct txhash_elem *txhash_firstval(struct txhash *txhash,
				    const struct protocol_double_sha *sha,
				    struct txhash_iter *i);
struct txhash_elem *txhash_nextval(struct txhash *txhash,
				   const struct protocol_double_sha *sha,
				   struct txhash_iter *i);

/* Get the actual transaction, we don't care about which block it's in */
union protocol_tx *txhash_gettx(struct txhash *txhash,
				const struct protocol_double_sha *);

void txhash_add_tx(struct txhash *txhash,
		   const tal_t *ctx,
		   struct block *block,
		   u16 shard,
		   u8 txoff,
		   const struct protocol_double_sha *sha);

void txhash_del_tx(struct txhash *txhash,
		   struct block *block,
		   u16 shard,
		   u8 txoff,
		   const struct protocol_double_sha *sha);

#endif /* PETTYCOIN_TXHASH_H */
