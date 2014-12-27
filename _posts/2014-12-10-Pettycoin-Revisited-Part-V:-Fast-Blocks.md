---
layout: post
title: Pettycoin Revisited Part V: Fast Blocks
commentIssueId: 42
---
> This is the fifth in a series analyzing the pettycoin implementation
> against Gregory Maxwell's
> [writeup on scaling](https://en.bitcoin.it/wiki/User:Gmaxwell/features#Proofs).
> The first talked about
> [UTXO commitments vs backrefs](http://rustyrussell.github.io/pettycoin/2014/11/29/Pettycoin-Revisted-Part-I:-UTXO-Commitments.html),
> the second talked about [Propogation servers vs prev_txhashes](http://rustyrussell.github.io/pettycoin/2014/12/04/Pettycoin-Revisited-Part-II:-Proof-of-Propogation.html),
> the third talked about [Hashed Fees vs Random Extrapolation](http://rustyrussell.github.io/pettycoin/2014/12/04/Pettycoin-Revisited-Part-III:-Miner-Rewards.html), and
> the fourth talked about [Simplified Transactions vs Normal Bitcoin Transactions](http://rustyrussell.github.io/pettycoin/2014/12/05/Pettycoin-Revisited-Part-IV:-Simplified-Transactions.html)

Bitcoin uses an average of 10 minutes between blocks, whereas
pettycoin uses 10 seconds.  I chose 10 seconds by standing in front of
an automated checkout at the supermarket and counting how long until I
got annoyed: it was about 5 seconds, which is the average wait time if
blocks were exactly 10 seconds apart.

## Pettycoin Solution ##

Pettycoin's network protocol always handed block headers, then had
separate queries to fill in the contents (a natural consequence of
designing a system where nodes only needed partial knowledge).  It had
a canonical transaction ordering to help with transaction guessing,
but didn't have anything as sophisticated as
[Invertible Bloom Lookup Tables](https://gist.github.com/gavinandresen/e20c3b5a1d4b97f79ac2).

Since 10 seconds is getting close to the network latency, pettycoin
was designed to use [GHOST](https://eprint.iacr.org/2013/881.pdf) to
limit divergence.  Since it never left the test net, the practicality
of this approach was never tested (and indeed, never implemented
fully).

By itself, 10 second block times don't provide a good experience, however:
15% of the time you'll be waiting over 20 seconds for the next block, due
to the long tail of block times.

Hence my
[proposal to limit variance](http://rustyrussell.github.io/pettycoin/2014/10/30/More-Regular-Block-Times.html),
which was never deployed, and which made Gregory Maxwell nervous.  The
proposal feels a little dirty, leaning more on the real-time network
behaviour (in particular, the delay since the previous received block)
to accept a block.  Bitcoin only relies on this for refusing blocks
more than 2 hours in the future, which is an uncommon case.

The costs of having 10x faster block times are 10x larger headers.
For bitcoin, the header is 80 bytes, and 80 bytes every 10 seconds is
still very cheap.  But merge mining raises the header to the `bitcoin
header` + `coinbase` + log2(`number-of-mergemined-chains`) *
`hashsize` + `pettycoin header`.  Which is more like 80 + 100 + 8 *
32 + 80 = 516 bytes, though if previous block hashes are merkled in,
you require some additional hashes, making the minimal block size
around 600 bytes.

For pettycoin, this is somewhat mitigated by the 1 month horizon,
but that's still 155 MB of data for just the headers; a bit more
since we need to keep recent alternate forks for GHOST.

## Summary ##

I think there's merit in a sidechain which offers faster confirmation,
reducing the requirement for zeroconf tricks.  While such a chain is
more divergent, that doesn't matter if they all agree on the
transaction(s) we care about.

This would be an interesting experiment in itself, and if I were doing
pettycoin again, I'd separate this from the microtransaction
sidechain.
