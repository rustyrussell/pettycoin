---
layout: post
commentIssueId: 36
---
There's an
[interesting post on scaling](https://blog.ethereum.org/2014/10/21/scalability-part-2-hypercubes/)
by Vitalik Buterin over at the Ethereum blog.  I always read these posts with
excitement and a little trepidation, as I wonder if they'll come up with
some scaling trick I missed for pettycoin...

After several false starts, I rejected the idea of having multiple
blockchains and special inter-shard messages, and this post provides a
nice overview of the problems.  In particular, the problem where a
miner on one shard refuses to release the details of their block;
others watching that block can complain, but by definition they're in
the minority.  Vitalik suggests randomly querying your peers, but that
leaves you open to a Sybil attack, where the bad miner creates fake
peers who talk to everyone, and then discloses enough of the unknown
transactions to placate the majority.

The key weakness of the sketch, however, is that Vitalik asserts that
most transactions will be shard-local.  That might be true of
Ethereum, but it's not true of a bitcoin-like payment network.  Even
if we allow that those dealing with large numbers of transactions will
sit on numerous shards, you still have most transactions crossing
multiple boundaries.  That means everyone wants to be neighbors, and
if you're successful in discouraging them all you've done is increase
messages until the point where scalability gains from sharding are
defeated by the increase in transactions simply relaying messages for
other nodes.

In the end, pettycoin regretfully returned to a "miners must know all"
model, but nodes can prove any mistakes they find.  In particular, to
address the data unavailabilty attack, miners must "prove" they know
all the transactions in various previous blocks by hashing them with
their own reward address.  This is a slightly-ungainly[1] compromise,
since we have 1 byte of hash for each shard in the previous
(power-of-two-spaced) 10 blocks, and if a miner gets it wrong you need
to send all the transactions in the incorrect shard to produce a
proof.

[1] ungainly: an irregular adjective.  My solution was "ungainly", your
solution was "ugly", their solution was "a horrible hack" :)
