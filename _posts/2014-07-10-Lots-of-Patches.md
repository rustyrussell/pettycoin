---
layout: post
commentIssueId: 12
---

It seems that I'm closing out the early, furious development phase
this week.  The project now has 285 commits, and 152 of those have
been since I've been on sabbatical: 78 in the last two weeks.

So yesterday I decided to sit back for a moment and assess priorities
to get to an alpha release.  Then I found a bug, which lead to some
more coding.  But this afternoon I finally wrote my TODO list, and it
looks like this:

### Implementation: ###

These I think I need to do before a release:

* [Have static genesis](https://github.com/rustyrussell/pettycoin/commit/a170f12c00a3d53efd6fe9b0fae75f40f2cd71aa)
* [Save to disk / restore from disk](https://github.com/rustyrussell/pettycoin/commit/0f7fbd7a011b1afbbf45237f65d5ecc1ef8ed116)
* Re-check prev_txhashes when we complete a shard.
* Real reward address in generating.c
* JSON RPC API

These can wait:

* Remember bad txs
* Use filtering of peers.
* Timeout for slow-syncing peers.
* Timeout old unknown txs.
* Generate complaints for bad tx packets.
* Consider putting txs with unresolved refs into block.
* disable NAGLE if we can use TCP_CORK
* make pending_block->pend a dynamic array of shards.
* keep around blocks we don't know.
* try to guess shards before we ask for them.
* move todos to end of the queue when used once
* penalize peers who make us fail too many todos
* limit simultaneous peers to ask todos
* timeout todos
* off test network.
* Implement partial knowledge.

### Protocol: ###

Before release:

* Payment to gateway.
* Fees
* Reward collection.
* peer location broadcast
* Spread out prev_txhashes

Sometime later:

* Complaint for tx in wrong shard.
* Piggyback packets
* Respect filtering of peers.
* voting mechanism to bump shard order.
* implement receipt of protocol_pkt_horizon.
* multiple gateways
* faster block times
* merge mining
* network time consensus
* Foldback of future rewards.

### Testing: ###

I can do these any time, and should:

* sparse
* unit tests
* replay tests
* fuzz testing.

### Cleanups: ###

Most of these are FIXMEs in the code:

* Use push/pull functions instead of marshal.
* Generate push/pull functions
* Generate log helper functions.
* Save log on abort()
* Save recent packets in log.
* ffz in ccan/bitmap
* idle hook in ccan/io

### Performance: ###

I know these will bite eventually, but they're not problems right now:

* Hash table for blocks
* Faster block_ancestor

### Infrastructure: ###

These are required to have a pettycoin network:

* Write gateway bot.
    * Deploy gateway bot.
* Peer location bootstrap server.
* Permanent nodes

And these are nice to have:

* Website
* Mailing list
* White paper

So far, I have done the first two, and am working my way down the list!
