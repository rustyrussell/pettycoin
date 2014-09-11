---
layout: post
commentIssueId: 9
---
Bitcoin has a very simple structure: the header is merely 80 bytes:

	u32 version;
	u8 prev_hash[32];
	u8 merkle_hash[32];
	u32 timestamp;
	u32 target;
	u32 nonce;

These 80 bytes hash to a very low number, which proves the block has
done the work required.

Transactions are merkled together in a binary tree; the first
transaction pays the mining reward.  This makes it theoretically quite
easy to trim as transactions are used up.  We merkle together transactions
the same way for pettycoin, though trimming is less important since
we have a horizon beyond which all transactions are irrelevant anyway.

The pettycoin header (post-alpha02) is a bit different:

	u8 version;
	u8 features_vote;
	u8 shard_order;
	u8 merkle_pos;

	le32 num_prev_txhashes;
	le32 coinbase_proof_size;
	le32 coinbase_len;

	le32 target;
	le32 height;

	struct protocol_address fees_to;
	struct protocol_double_sha merkle;

The `version`, `features_vote` and `shard_order` roughly hold the same
role as `version` in bitcoin.  Features are voted on, and we can see
when they are approved: a fixed number of blocks after a majority
votes for a feature, the version number will increment, allowing us to
update the protocol without hardforking.

`num_prev_txhashes` is here for convenience: you can determine this
number by knowing the number of shards in all previous blocks, but
it's easier to parse the block if it's self-contained.  The two
coinbase fields and `merkle_pos` support merged mining with bitcoin,
as detailed below.

`target` is the same a bitcoin, and `height` is explicitly placed in
the block rather than being a coinbase convention (a-la
[BIP-34](https://en.bitcoin.it/wiki/BIP_0034)).

`fees_to` replaces the coinbase; it's here because we plan to fold
back rewards from future years to a random selection of early miners,
so we'll need to keep it long past the horizon anyway.

`merkle` is the merkle hash of the contents, but also the previous
blocks' hashes.  You'll note there's no `prev_hash` field: unlike
bitcoin we want to keep more than one previous block (we keep 31).  So
merkle is the merkle tree hash of the transaction summary (node 0),
block N-1 (node 1), block N-2 (node 2), block N-4 (node 3)&hellip;
block N-2147483648 (node 31).  We only need to keep node 0 (which
itself contains the merkle hashes of the transactions for each shard)
until the block is safely below the horizon.  And we'll only need to
keep one of the previous block IDs (plus 5 double-SHA hashes to prove
it's correct), once we start supporting [skip lists for really old
blocks](https://rustyrussell.github.io/pettycoin/2014/08/28/Multiple-prevs.html).

The result looks like this on the wire:

	pettycoin-header [76 bytes]
	previous block hashes [up to 31 * 32 bytes = 992 bytes]
	txcount for each shard [1 byte per shard]
	merkles of txs for each shard [32 bytes per shard]
	txhashes for previous 10 blocks [1 byte per shard * 10]

Once the block is past the horizon, we only need to remember the
header (76 bytes), one of the previous blocks hashes (32 bytes), and
the merkle proof of that (160 bytes).  That 160 bytes is the cost
of being able to skip back: in return for doubling our size we gain
at least a factor of 10 by skipping, so it's worth it.

Merge Mining With Bitcoin
----

But that's not the only change, because alpha02 also supports merged
mining with bitcoin: in fact, it's the only mode we'll support (though you
can fake up a bitcoin block if you don't want to mine bitcoin).

To do that is
[more complex](https://en.bitcoin.it/wiki/Merged_mining_specification):
the hash of the pettycoin block is included in a merkle tree into the
bitcoin coinbase transaction, which is included in a merkle tree into
the bitcoin block header, which is what actually has the
difficult-to-generate hash value.

Thus you need to know the following:
1. How many chains were merge mined?  This is encoded in the coinbase
   input scriptsig.
2. What is the merkle path for pettycoin?  We store this in `merkle_pos` in the
   pettycoin header.
3. What hashes are needed to prove the pettycoin block was mined?
   This is log2(num mergemined chains).
3. What is the coinbase length contents?  We store this in `coinbase_len` in the
   pettycoin header too.
4. How many transactions were in the bitcoin block?  We store this in
   `coinbase_proof_size` in the pettycoin header.
5. The merkle hashes to get from the coinbase hash to the bitcoin
   `merkle_hash` field (log2(num_transactions), or
   `coinbase_proof_size`).
6. The bitcoin header itself.

The coinbase size varies: the first merge-mined block was 135 bytes,
looking now I see 157 bytes at block 320143.  Say 150 bytes average.
You don't need a merkle path if you're only merge-mining pettycoin,
but there are at least 8 chains you could be mining, so say 3 hashes
at 32 bytes each = 96 bytes.  The number of bitcoin transactions is
clearly growing: at 80,000 per day now, which is 333 per block.  It's
easily going to be 1024 per block, requiring 10 x 32 byte hashes
to prove the coinbase was included in the bitcoin header.

The result is a cost of 150 + 96 + 320 + 80 = 646 bytes per block to
support merged mining.  And that has to be kept around forever (modulo
blockchain skipping), as it's the only way to demonstrate that the
pettycoin block was in the bitcoin proof of work.  This is why I
wasn't too aggressive on reducing the 260 bytes in the pettycoin
header.

At 10 second intervals and 1k block size, you can see why a short
horizon is desirable: it's 260MB for each month of block headers,
before we even store any transactions.
