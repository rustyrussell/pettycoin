---
layout: post
commentIssueId: 10
---
Pettycoin relies on partial knowledge, but until today the code assumed
we needed to know transaction in every shard in every block.

Today I implemented the sending and receiving of
`protocol_pkt_get_txmap` and `protocol_pkt_txmap` packets.  When a
node discovers a block, it asks for the entire contents of every shard
it is interested in using `protocol_pkt_get_shard` packets.  But as
transactions can cross shards, it will also be interested in some
transactions which are not in its own shard: this is where
`protocol_pkt_get_txmap` comes in.  The `protocol_pkt_txmap` returned
is a bitmap of whatever transactions you're interested in in that
shard of transactions: you then ask for them individually using
`protocol_pkt_get_tx_in_block` which provides the transaction and
proof that it's at that position in the block.

I also implemented the receipt and checking of every kind of complaint
packet: these prove a problem with a block, and need to be checked
carefully to make sure they really do prove it. There are five kinds:

* `protocol_pkt_complain_tx_misorder`

	This proves that two transactions in a shard are in the wrong
    order.  We insist that they always be ordered, mainly because it
    should speed transmission of blocks by allowing nodes to guess the
    contents.

* `protocol_pkt_complain_tx_invalid`

	This proves that a transaction in a block is invalid.  There's no
    code which generates such complaints today, since there's no way
    to send an invalid transaction, but in future we could use this
    for a buggy miner who produced invalid transactions.

* `protocol_pkt_complain_tx_bad_input`

	This proves that a transaction in a block has a bad input
    (eg. trying to spend someone else's transaction) by providing the
	transaction and the input it tried to use.

* `protocol_pkt_complain_tx_bad_amount`

	This proves that a transaction in a block doesn't add up by
	providing the transaction and all the inputs it tried to use.

* `protocol_pkt_complain_bad_input_ref`

	This proves that a transaction in a block has a bad input
    reference.  Input references are inserted by the miner after each
    transaction, and show where each input for that transaction should
    be (blocks ago, shard number and transaction offset in the shard).
    This proves that the transaction referred to by the reference
    isn't the one the transaction wanted.

There are only two parts of the network protocol now missing.  First
is dealing with skiplist of blocks before the horizon
(`protocol_pkt_horizon`) and the second is broadcast of double spends
and complaining about them if they're inside a block.

But first, I took some time to write some more unit tests: I'm way
behind, still.
