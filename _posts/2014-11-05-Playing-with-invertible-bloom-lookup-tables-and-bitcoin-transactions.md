---
layout: post
commentIssueId: 38
---

Gavin Andresen of bitcoin fame posted
[a github gist](https://gist.github.com/gavinandresen/e20c3b5a1d4b97f79ac2)
a while ago, about using IBLTs to send block transaction summaries across
the bitcoin network.

## About IBLT ##

([Skip if you're familiar with IBLTs](#Using-IBLTs))

The IBLT structure is fairly simple: create a counting bloom filter,
and attach to each bucket the contents of the thing you're filtering
(xoring in each time).  If the IBLT is fairly empty, you'll find
buckets which only have 1 thing in them, and thus recover the things
which were put in (this is the "invertible" part).  When you remove
those, you might find more buckets now have 1 thing in them, etc.  The
[paper](http://arxiv.org/pdf/1101.2245.pdf) is worth reading, but this
should give you the idea.

Here's a simplified example.  Consider the following buckets:

    count: 1
	id:    0xf00
	index: 0
	frag:  Feed Me 

    count: 1
	id:    0xf00
	index: 1
	frag:  Seymore!

    count: 2
    id:    0xf0f
	index: 0
	frag:  0x70x170x100xB0x90x1B0x10x53

	count: 1
	id:	   0x00f
	index: 0
	frag:  I love

Here each "transaction" has 2 parts (index 0 and index 1), we can see
both parts of id 0xf00 exposed in the first two buckets.  The result
is "Feed Me Seymore!".  Now we've recovered that, we remove it, and it
turns out that fragment 1 is also in that third bucket, so we subtract
1 from the counter and XOR out the other values, giving:

    count: 0
	id:    0
	index: 0
	frag:  

    count: 0
	id:    0
	index: 0
	frag:  

    count: 1
    id:    0x00f
	index: 1
	frag:  Triffids

	count: 1
	id:	   0x00f
	index: 0
	frag:  I love

Now we can extract id 0x00f, which is "I love Triffids".

### Subtracting IBLTs ###

The clever bit comes by realizing that if I create an IBLT with
everything in my set, and you create an IBLT with everything in your
set, it's trivial to subtract my IBLT from your IBLT and get an IBLT
of the set differences.  Which is great, because all bloom filters
become useless when they clog up, but if our sets are very similar,
the subtraction result gives a nice sparse IBLT.  And
[here's the paper](http://conferences.sigcomm.org/sigcomm/2011/papers/sigcomm/p218.pdf).

<a name="Using-IBLTs"></a>

## Using IBLTs for Bitcoin ##

Gavin suggested some ways to adapt an IBLT to the blockchain problem:

1. Set a size of 1M for the whole thing.
2. Make each IBLT bucket look like this

		struct entry {
		  u32 count;
		  struct keySum {
				  u8 id[6];
				  u16 index;
				  u8 frag[8];
		  } key;
		}

  This gives 52428 buckets for a 1MB table.

3. Generate a 48-bit id for each transaction and fragment it into
   64-bits at a time, with index incremented for each fragment.  This
   means the average transaction (263 bytes) uses about 32 of these.

## Testing It ##

For my experiment, I used 4 hash functions for each bloom entry, and
just make the 48-bit id the first 48 bits of the SHA.  I used a simple
shell script to pull out the last 10000 bitcoin transactions.

### Recovering Transactions ###

Let's first look at how many transactions we can put in such table and
pull them out again.  This reflects the simple case where the miner
has N transactions we don't have (and we have none they don't have).
For each transaction, we just have to find a standalone copy of each
fragment; since each fragment is in 4 separate places, removing a
transaction as we find it may leave other fragments exposed so we can
make more progress.

The result turns out to be a cliff: with 300 transactions we can
extract all the transactions 100% of the time, with 320 it's down to
0% (this is only 10 runs though).  We only care about full recovery,
because if we can't get one transaction, we fall back to getting the
whole block:

![Graph of recovery success](https://rustyrussell.github.io/pettycoin/images/recovery-stats-simple.svg "Graph of recovery success")

### Eliminating not-present Transactions ###

Now, reality is a bit more complex.  We will have some transactions
which are *not* in the block (I'll call these "our" transactions), as
well as missing some which are ("their" transactions).  Indeed, if the
network is working perfectly, we should have all the transactions in
the block, and also any which have reached us while the block was
being relayed to us, so we expect "our" transactions to dominate.

And it turns out that it's much easier to detect transactions which
aren't in the block than those that are; we only need to find a single
standalone fragment with count -1, and we can be fairly confident that
it means we've found one of our transactions and should remove the
whole thing.  Finding a single exposed fragment for a transaction like
this is far more likely than finding all fragments of a transaction
exposed, and indeed our cliff for these is far higher, around 3300:

![Graph of removal success](https://rustyrussell.github.io/pettycoin/images/removal-stats-simple.svg "Graph of removal success")

Finally, here's a heat map of interaction between the two, as the
number of "their" transactions we need to recover and the number of
"our" transactions we should remove varies.  Blue is 100% recovered
(ie. always success) red is 0% (ie. never):

![Recovery success with variable ours/theirs](https://rustyrussell.github.io/pettycoin/images/heatmap-8byte.svg "Recovery success with variable ours/theirs")

## Testing Some Variants ##

There are three obvious things to try:
1. Increase the size of the slice in each IBLT bucket.
2. Reduce the size of the IBLT from 1M.
3. Add a hashSum field to each bucket as suggested by the paper.

### Larger slices ###

Increasing the data per bucket from 8 to 64 bytes seems like a no-brainer:
instead of 50% overhead for IBLT data, we're down to 12%.  Obviously we
have fewer buckets, but it seems like a net win:

![Recovery success with 64 byte slices](https://rustyrussell.github.io/pettycoin/images/heatmap-64byte.svg "Recovery success with 64 byte slices")

If we make the buckets *too* large (eg. 256 bytes), we lose as expected,
as most space is wasted:

![Recovery success with 256 byte slices](https://rustyrussell.github.io/pettycoin/images/heatmap-256byte.svg "Recovery success with 256 byte slices")

### Smaller IBLTs ###

As expected it's not linear: doubling gives us less than double the
number of transactions we can recover.  But conversely, if we shrink
down to 1/33 the size, we can still recover 30 transactions (this map
uses the 64 byte slices from above):

![Recovery success with 64 byte slices, 30k map](https://rustyrussell.github.io/pettycoin/images/heatmap-64-byte-30k.svg "Recovery success with 64 byte slices, 30k map")

### A Byte of HashSum ###

This is suggested in the original paper to provide more resilience
against false positives, but I only saw this once, even with the very
limited checking my program does that a transaction is well-formed.
(I found it because my code initially didn't handle it, and got stuck
on one run).

Once we check the 48-bit id field, which is based on a cryptographic
hash of the transaction, we're already extremely robust without an
additional hashSum.

## Results and Suggestions ##

8 bytes per slice is too small, larger sizes should be explored.

1M is vast overkill for the current network; as well as making block
propagation slower than the current scheme, it's unnecessary for now.
30k is probably more than enough for current blocks.

Nodes may want to include discarded doublespend transactions in their
IBLT since it's cheaper to include a transaction for consideration
than to extract one which we didn't consider.

## Flaws and Future Work ##

Obviously my code could use optimization.

Also, my selection of transactions was "the first N", which means it's
of limited accuracy.  For example, transaction 613 is a huge 50k
transaction, so if it's marginal the failure rate jumps there.  A more
serious analysis would try to create standard profiles of
transactions.

More intelligent recovery algorithms are possible, which might help in
edge cases.  We could look at transaction arrival time, and try
removing very recent transactions.  We could also do some limited
transaction reconstruction (though the bulkiest parts of the
transaction are the signatures, which can't be guessed).

[Feedback](mailto:rusty@rustcorp.com.au) welcome, as always.
