---
layout: post
title: Pettycoin Revisited Part VI: Fees and Horizons
commentIssueId: 42
---
> This is the sixth in a series analyzing the pettycoin implementation
> against Gregory Maxwell's
> [writeup on scaling](https://en.bitcoin.it/wiki/User:Gmaxwell/features#Proofs).
> The first talked about
> [UTXO commitments vs backrefs](http://rustyrussell.github.io/pettycoin/2014/11/29/Pettycoin-Revisted-Part-I:-UTXO-Commitments.html),
> the second talked about [Propogation servers vs prev_txhashes](http://rustyrussell.github.io/pettycoin/2014/12/04/Pettycoin-Revisited-Part-II:-Proof-of-Propogation.html),
> the third talked about [Hashed Fees vs Random Extrapolation](http://rustyrussell.github.io/pettycoin/2014/12/04/Pettycoin-Revisited-Part-III:-Miner-Rewards.html),
> the fourth talked about [Simplified Transactions vs Normal Bitcoin Transactions](http://rustyrussell.github.io/pettycoin/2014/12/05/Pettycoin-Revisited-Part-IV:-Simplified-Transactions.html),
> and the fifth discussed [Fast blocks vs Bitcoin blocks](http://rustyrussell.github.io/pettycoin/2014/12/10/Pettycoin-Revisited-Part-V:-Fast-Blocks.html).

Mining fees must be sufficient to support the network, otherwise it
will eventually fail.  There's a tension between users who want the
lowest fees possible, and miners who want the highest fees possible.
And while the miner of a particular block collects the fees, the
incremental cost of remembering the transaction is carried by the
entire network.

## Bitcoin Solution ##

Bitcoin is supposed to use an open market fee structure; miners choose
what to accept based on fees, and so transactions offer a fee
sufficient to have miners include the transaction in their block.

In practice, the default formula used is very simple: there are a
number of "first-in-first-served" free transaction slots in each
block, then a fixed fee is required per kb of transaction.  This fixed
fee has dropped several times as the bitcoin price increases.

It's not particularly important, as miners view transactions fees as a
tiny cherry on top: the block rewards are driving mining at the
moment.  This will eventually change, so efforts are underway to have
the reference bitcoin client guestimate appropriate fees which are
likely to have a transaction included.  How well this will work in
practice is uncertain: miners have short-term incentive to include
transactions no matter how small the fee, but a longer-term incentive
to reject tiny fees.  This is especially true if clients autodetect
appropriate fee levels.

### What Level of Fee Should Happen? ###

As a first approximation, the cost of running the bitcoin network
should be equal to the value of bitcoins currently produced.  Let's
assume that we want the network to continue at the current spending
level when the block reward next halves; transaction fees will have
to make up the difference, at around $4000 per block.

The bitcoin price is a huge unknown, so we'll try to make our other
guesses extremely conservative.  Let the bitcoin transaction rate will
increase to a massive 100 transactions per second, that's 60,000
transactions each paying around 6c each.

## Pettycoin Solution ##

If bitcoin won't let you reasonably send 1c, what would?  A sidechain
specifically designed for this, with properties that ensured it
wouldn't compete with bitcoin.  That way, miners could pick up the
(too-small) fees, without entering a race to the bottom on the bitcoin
network.

Of course, the sidechain would have to be cheap to run, too, so the
additional cost of merge mining it was worth the small fees involved.

This was the core design of pettycoin:

1. A 1-month horizon, after which coins are returned to the bitcoin
   network.
2. Simplified, less-powerful transaction types.
3. Fees based on percentage, rather than absolute values.

The horizon ensures that pettycoin is not a store of value, but only a
transfer network, and puts an approximate upper limit on how much data
needs to be stored.

Simplified transactions
[were a bad idea](http://rustyrussell.github.io/pettycoin/2014/12/05/Pettycoin-Revisited-Part-IV:-Simplified-Transactions.html)
as they don't save much, and it's hard to tell which parts of the
bitcoin scripts will be useful in future.

The percentage-based fee (0.3% currently) makes for a simple penalty
if transactions get large enough that it would be cheaper to do them
on the bitcoin network.  (You could also flag a transaction as zero-fee,
with the idea that miners may or may not accept them).

This scheme required simplified transactions, which can distinguish a
payment from change.  Using percentage of the total transferred would
encourage users to split their outputs so future transactions would
not need to transfer as much, leading to a larger UTXO size.

The simplest solution I can think of would be to ignore the
largest output, and sum the rest as the fee basis.

This could still be gamed for some cases, of course, but is fairly
simple in the common case.  There's no reason to restrict number of
inputs, as consuming many inputs would reduce the UTXO size and help
the network overall.

## Summary ##

This core idea of a complementary network for sub-cent transactions
has promise, but has a significant bootstrap problem.  If there are
still free bitcoin transactions, it provides no value.  If there are
no more free bitcoin transactions, then you need to pay the
transaction fee to get money on and off the sidechain, in order to
save money later (and you only have a limited time to do it).

It would take a compelling use case to drive adoption, which could
be artificial: eg. a subsidised SatoshiDice-style service on the
microtransaction network.
