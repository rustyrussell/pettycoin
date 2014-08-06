# TODO list for pettycoind development #

## Implementation ##

### pettycoin binary ###

Before Alpha02:

* [<del>keep around blocks we don't know.</del>](https://github.com/rustyrussell/pettycoin/commit/e37c62e40d2346d2e8ede158fba344355b4aad01#diff-d41d8cd98f00b204e9800998ecf8427e)
* Watching of addresses
    * This would be useful for a more efficient gateway, or decent wallet.
* Generate complaints about prev_txhashes being wrong
    * If someone managed to sneak this into the network presently, there'd
	  be no way for nodes to report it.
* disable NAGLE.
 
Maybe:

* relicense ccan/opt
  * It's currently GPLv2, which makes pettycoin binaries GPLv2.
* Remember bad txs
* Use filtering of peers.
* Timeout for slow-syncing peers.
* Timeout old unknown txs.
* Generate complaints for bad tx packets.
* Consider putting txs with unresolved refs into block.
* make pending_block->pend a dynamic array of shards.
* try to guess shards before we ask for them.
* move todos to end of the queue when used once
* penalize peers who make us fail too many todos
* limit simultaneous peers to ask todos
* timeout todos
* off test network.
* Implement not-watching-all-shards.

### pettycoin-gateway binary ###

Before Alpha02:

* Return pettycoin TO_GATEWAY transactions to bitcoin network.

### dumbwallet binary ###

Before Alpha02:

* Don't display confusing total after outgoing transaction.
    * We currently display the confirmed total, and the unconfirmed.  If
	  the unconfirmed TX is *from* this account, we should deduct from the
	  confirmed amount immediately.

## Protocol: ##

Before Alpha02:

* Include power of 2 previous blocks in prev
    * Would allow SPV-style block skips which would enable foldover reward on ancient blocks.
* Complaint for tx in wrong shard.
    * If someone managed to sneak this into the network presently, there'd
	  be no way for nodes to report it.
* Fix fee calculation
    * It's currently 3/1024 of the total, it should be 0.3% of the non-change
	  amount.
* Multiple gateways
    * Requires a mechanism to create new gateways.
* Simplify welcome message to have 64k bits always.
    * 8k simply isn't that much, and it's simpler.
* Merge mining
    * Means larger blocks, but we'll want this eventually.
* Network time consensus
    * This is what bitcoin does, we should too.

Maybe:

* Piggyback packets
* Respect filtering of peers.
* voting mechanism to bump shard order.
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

* White paper
