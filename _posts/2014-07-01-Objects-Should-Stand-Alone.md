---
layout: post
commentIssueId: 9
---

In pettycoin, blocks contain shards, and shards contain
transactions.  These are represented by `struct block`, `struct block_shard`
and then the transactions (or hashes, or NULL).

But I chose early on to save some space in `struct block_shard` like so:

	/* Only transactions we've proven are in block go in here! */
	struct block_shard {
		/* Which shard is this? */
		u16 shardnum;
		/* How many transactions do we have?  Faster than counting NULLs */
		u8 txcount;
		/* How many transaction hashes do we have? */
		u8 hashcount;
	
		/* If we don't know all hashes, we store array of proofs here. */
		struct protocol_proof **proof;
	
		/* Bits to discriminate the union: 0 = txp, 1 == hash */
		BITMAP_DECLARE(txp_or_hash, 255);
	
		union txp_or_hash u[ /* block->shard_nums[shardnum] */ ];
	};

There are referred to by an array of pointers in `struct block`:

	struct block {
		...
		const u8 *shard_nums;
		...
		/* Transactions: may not be fully populated. */
		struct block_shard **shard;
	};

These are allocated lazily, so all of block->shard[] will be NULL to
start with.  This means we tend to hand around block + shardnum rather
than a shard, so we can allocate on demand.  We also can't tell by
looking at a shard whether all transactions are known or not: the
`struct block` contains the size of the shard.

So some places took a block and a shard, some took a block and a shard
number, and the result was confusion (and at least on bug).  I decided
that shards would always be fully populated in a block, and they would
have a `size` field, so they were independent objects.  The result
was quite a nice cleanup.
