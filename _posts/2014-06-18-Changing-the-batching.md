---
layout: post
---

The point of pettycoin is that you don't need to know all transactions
in a block to be useful: you can publish a compact standalone proof of
anything which could possibly be malformed about a block, which the code
calls a "complaint".

The original code had a hard-coded 4096 shards: the lower 12 bits of a
pettycoin address indicated which shard it belonged to.  Thus most
transactions would be in two shards: one for the inputs, and one for
the output.  Moreover, transactions within a block are sorted by the
shard of the input(s) (which must be the same), so all spending from
one shard is bunched together, and spending to a shard is scattered.

This sorting has two advantages:
1. It makes it easy to grab half of the transactions you care about
   all at once.
2. In future it should allow efficient guessing of what transactions
   are in a block.  This would significantly speed network
   propogation, disadvantaging propogation of blocks which contain
   transactions never seen by the network before (we send just the
   block header, but you have to know every transaction if you want to
   mine the next block).

So the [first change](https://github.com/rustyrussell/pettycoin/commit/27ba5baef938b500b95e22b579b058039b0df873) was to make the number of shards variable: it
starts at 4, but future feature votes can double it.  This means it's
efficient to put per-shard information into the header, which leads to
the second change.

My original code batched transactions into groups of 256, and merkled
each separately.  These merkle hashes were published in the header:
this is needed because for some complaints we need to send the entire
batch, so 256 is a compromise.

The new code batches by shard of the inputs, and the header explicitly
contains how many transactions are in each shard.  This is an 8 bit
number, so to service more transactions we'll need to increase the
number of shards.  For the moment, it's pretty compact, as well as
allowing nodes to know explicitly what transaction range they should
ask for, for any shard.  We still need to ask our peers for a map of
transactions coming into our shard(s) during startup, and have them
flow through the network during normal running.

This code got half-finished today, but so far I like it: the concept
of batches is entirely eliminated, and the code is no more complex.
