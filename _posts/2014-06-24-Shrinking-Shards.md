---
layout: post
commentIssueId: 4
---
I entered today intending to shrink this structure:

	/* Only transactions we've proven are in block go in here! */
	struct transaction_shard {
		/* Which shard is this? */
		unsigned int shardnum;
		/* How many transactions do we have?  Faster than counting NULLs */
		unsigned int count;
		/* FIXME: Size dynamically based on block->shard_nums[shard]. */
		const union protocol_transaction *t[256];
		const struct protocol_input_ref *refs[256];
	};

This in-memory structure represents all transactions within one shard
of a block (remember, a block currently divides transactions into 4
shards).  Space matters: 100,000 transactions per second is
8,640,000,000 per day, and since each shard can only hold 255
transactions, that means at least 33,882,352 shards.  And we have a
horizon of 30 days before transactions expire, so we're over a
billion shards.

As you can tell from the `FIXME` there was one obvious place to change,
and that was the fixed array.  But having two dynamic arrays is kind
of a pain, so first I ensured the the refs alwasy follows the transaction
in memory (easy, since that's how they come off the wire), so we can
derive refs[i] from t[i].

But I didn't want to write a function which took an arbitrary
transaction pointer and assumed that refs followed it: too easy to get
wrong.  So instead, I introduced a type to represent "pointer to
transaction which has a ref following":

	struct txptr_with_ref {
		union protocol_transaction *tx;
	};

	/* Only transactions we've proven are in block go in here! */
	struct transaction_shard {
		/* Which shard is this? */
		unsigned int shardnum;
		/* How many transactions do we have?  Faster than counting NULLs */
		unsigned int count;
		/* FIXME: Size dynamically based on block->shard_nums[shard]. */
		struct txptr_with_ref txp[256];
	};

And created the following helper to extract the ref, given a `txptr_with_ref`:

	static inline const struct protocol_input_ref *
	  refs_for(struct txptr_with_ref t)
	{
		char *p;
	
		p = (char *)t.tx + marshall_transaction_len(t.tx);
		return (struct protocol_input_ref *)p;
	}

Now, handing around a struct by copy is a bit weird, but gcc tends to
handle it OK these days.  This provided a nice type safety net.

Finally, I made it dynamic (and shrunk the other fields to their
actual sizes, too, which will help on 32-bit):

	/* Only transactions we've proven are in block go in here! */
	struct transaction_shard {
		/* Which shard is this? */
		u16 shardnum;
		/* How many transactions do we have?  Faster than counting NULLs */
		u8 count;
		/* Pointers to the actual transactions followed by refs */
		struct txptr_with_ref txp[ /* block->shard_nums[shard] */ ];
	};

Then, once I'd shrunk the structure, it was time to add more stuff
(which is what drew my attention to it in the first place).  Then I
realized I wanted to tweak the wire protocol again: hopefully the
successful completion of that project will be the subject of
tomorrow's post.
