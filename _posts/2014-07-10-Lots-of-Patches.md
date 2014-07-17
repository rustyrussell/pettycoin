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
looks like this: [EDIT: I'm updating this on the fly, with pointers
to the appropriate commit]

### Implementation: ###

These I think I need to do before a release:

* [<del>Have static genesis</del>](https://github.com/rustyrussell/pettycoin/commit/a170f12c00a3d53efd6fe9b0fae75f40f2cd71aa)
* [<del>Save to disk / restore from disk</del>](https://github.com/rustyrussell/pettycoin/commit/0f7fbd7a011b1afbbf45237f65d5ecc1ef8ed116)
* [<del>Re-check prev_txhashes when we complete a shard.</del>](https://github.com/rustyrussell/pettycoin/commit/0ec909cc65c11be52dd9e4ce3903619cca37c669)
* [<del>Real reward address in generating.c</del>](https://github.com/rustyrussell/pettycoin/commit/1fb70d009dd2aea29d46733feff88b3655bccfae)
* JSON RPC API
* [<del>configuration file</del>](https://github.com/rustyrussell/pettycoin/commit/9aa521aaa5206fc160ed8065394e0d89705e94f9)

These can wait:

* Roll in CCAN
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
* Generate complaints prev_txhashes being wrong

### Protocol: ###

Before release:

* [<del>Payment to gateway.</del>](https://github.com/rustyrussell/pettycoin/commit/c0fcb928be0ba33b865b488750184b48be295688)
* [<del>Fees</del>](https://github.com/rustyrussell/pettycoin/commit/881e3158f93314eefecd6448d69d736f6f522c76)
* [<del>Reward collection.</del>](https://github.com/rustyrussell/pettycoin/commit/cf0c7eec54352b48a56bd6df6d4c8c962ae25984)
* [<del>peer location broadcast</del>](https://github.com/rustyrussell/pettycoin/commit/87e32c86f9a0d366d428aff15957949585a18d3f)
* [<del>Spread out prev_txhashes</del>](https://github.com/rustyrussell/pettycoin/commit/c84d0818abccc46f4e1d09979688ccd41366f168)

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

I am crossing these off as I complete them...
