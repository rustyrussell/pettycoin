---
layout: post
title: Pettycoin Revisited Part III: Miner Rewards
commentIssueId: 41
---

> This is the third in a series analyzing the pettycoin implementation
> against Gregory Maxwell's
> [writeup on scaling](https://en.bitcoin.it/wiki/User:Gmaxwell/features#Proofs).
> The first two talked about
> [UTXO commitments vs backrefs](http://rustyrussell.github.io/pettycoin/2014/11/29/Pettycoin-Revisted-Part-I:-UTXO-Commitments.html)
> and the second talked about [Propogation servers vs prev_txhashes](http://rustyrussell.github.io/pettycoin/2014/12/04/Pettycoin-Revisited-Part-II:-Proof-of-Propogation.html).

In bitcoin, miners take any difference between the amounts input in a
transaction, and the amount output; this is called the transaction
fee.  When designing a system where nodes don't know every
transaction, how do you verify that the miner has claimed the correct fee?

## Pettycoin Solution ##

Every 2016 blocks, the hash of that block is used to select a random
transaction in each of the previous 2016 blocks.  The fee on this
random transaction is multiplied by the number of transactions, giving
the mining reward.

While miners will fight to get a block which gives them a good reward,
this should cancel out as a block which gives one a good reward is
likely not to do so for the others.

## Gregory Maxwell's Solution ##

This solution involves hashing the fee amount in with the transaction
to form the merkle tree; you prefix the transaction with the fee total
and hash that, and also sum the totals for the two sub-nodes.

This lets you audit any transaction to ensure it's been summed
correctly.  On the downside, it adds some bytes (say, 4) to each proof
in the merkle hash (usually 32 bytes).  This can replace the normal
merkle hash, but that makes it unlike bitcoin and you might need both
depending on how flexible sidechains are (assuming you want to be a
sidechain).

## Summary ##

The fee hashing is a better alternative: this way a miner knows what
the reward for a block is.  The alternative means that you might not
get any reward if you include a transaction without a fee; though
equally, you might get a huge one, psychology tells us that humans
fear loss more than hope for gain.
