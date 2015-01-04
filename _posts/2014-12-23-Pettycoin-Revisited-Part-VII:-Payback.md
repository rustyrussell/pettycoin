---
layout: post
title: Pettycoin Revisited Part VII: Payback
commentIssueId: 42
---
> This is the seventh in a series analyzing the pettycoin implementation
> against Gregory Maxwell's
> [writeup on scaling](https://en.bitcoin.it/wiki/User:Gmaxwell/features#Proofs).
> The first talked about
> [UTXO commitments vs backrefs](http://rustyrussell.github.io/pettycoin/2014/11/29/Pettycoin-Revisted-Part-I:-UTXO-Commitments.html),
> the second talked about [Propogation servers vs prev_txhashes](http://rustyrussell.github.io/pettycoin/2014/12/04/Pettycoin-Revisited-Part-II:-Proof-of-Propogation.html),
> the third talked about [Hashed Fees vs Random Extrapolation](http://rustyrussell.github.io/pettycoin/2014/12/04/Pettycoin-Revisited-Part-III:-Miner-Rewards.html),
> the fourth talked about [Simplified Transactions vs Normal Bitcoin Transactions](http://rustyrussell.github.io/pettycoin/2014/12/05/Pettycoin-Revisited-Part-IV:-Simplified-Transactions.html),
> the fifth discussed [Fast blocks vs Bitcoin blocks](http://rustyrussell.github.io/pettycoin/2014/12/10/Pettycoin-Revisited-Part-V:-Fast-Blocks.html).
> and the sixth [Fees and Horizons for A Microtransaction Sidechain](http://rustyrussell.github.io/pettycoin/2014/12/11/Pettycoin-Revisited-Part-VI:-Fees-and-Horizons.html).

Lacking the ability to mint coins, rewarding miners for a sidechain is
difficult.  Relying on fees in the initial stages is not possible, and
using fees provides a disincentive for actually *using* the network.

## Pettycoin Solution ##

To solve this problem, pettycoin allows transactions to flag themselves
as feeless, with the understanding that miners may not include such
transactions.  It also mines the future to pay for the present: 25%
of the fees from block N+(X-years) would get paid to block N.  The
actual number of years was to be selected by an on-blockchain election
conducted at the 1 year mark.

The problem with this is that it requires the retention of all old
block headers, even before the horizon (otherwise we could use compact
SPV proofs for those headers).  A further lottery process could select
an agreed subset, however.

## Alternate Solution ##

A similar idea was suggested in the
[sidechains whitepaper](http://www.blockstream.com/sidechains.pdf),
via a different mechanism: that old miners would have the right to
mine a block with lower difficulty in the future.  In some ways this
is nicer, since the easy miner could provide proof of their old block
using a compact SPV proof.  Also, if the ability to mine an easy block
is part of the UTXO set, UTXO commitments can provide protection
against double-spends.

This introduces the issue that some party could flood the chain with
easy blocks; perhaps instead each block would only be (say) 25% easier
than normal, rather than ridiculously easy.  The miner could then
sell the use of their private key.

## Summary ##

Weak blocks make checking significantly more complex, but I'd have to
implement it to really know how bad it was.  It fits fairly nicely
into the bitcoin model of inputs and outputs, however.
