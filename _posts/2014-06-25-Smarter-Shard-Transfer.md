---
layout: post
commentIssueId: 5
---
Late yesterday I realized that one of my grand plans was not going to work.
This morning I fixed it.

When we transmit a block, we only include the merkle hash which
summarizes the transactions for each shard.  A node can then send
`PROTOCOL_PKT_GET_SHARD`, and get the hashes for each transaction in
that shard in a `PROTOCOL_PKT_SHARD` packet.  The idea was that it
should know most of them already, so why re-send them?

Except we didn't actually send the transaction hash, we sent the hash
of the *transaction plus its input references*.  Whereas each node
keeps a mapping of transaction hashes for other reasons, a back reference
is relative to a particular block:

	struct protocol_input_ref {
		/* Follow ->prev this many times. */
		le32 blocks_ago;
		le16 shard;
		/* Offset within that shard. */
		u8 txoff;
		u8 unused;
	};

That means once you have the hashes from `PROTOCOL_PKT_SHARD` you
need to calculate these input references for each transaction you
think might match, so you can hash it with the transaction and
compare.  I hated that code even before I wrote it, and it didn't get
better when it was finished at the end of yesterday.

Fortunately, we already hashed these input refs with the transaction
in two stages: first, hash the transaction, then hash the references,
then finally hash those two hashes.   *That* is the hash which gets
merkled together into the block header.

So the solution is to have `PROTOCOL_PKT_SHARD` send hash pairs.  Each
one is the transaction hash, followed by the hash of the input
references.  This means it's easy to look up each transaction hash to
see if you know about it, then calculate the input reference to make
sure it matches.  The code is much nicer, too; it only took me the
morning to complete it.

Tomorrow, I want to write some more unit tests and vastly simplify the
dumb mining program.  Now the updated protocol has forced me to handle
only knowing the hashes, we can take advantage of that and have the
generator simply feed us the hashes: the code I wrote this morning
already knows how to look those up.
