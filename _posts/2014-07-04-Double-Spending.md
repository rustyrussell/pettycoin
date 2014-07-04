---
layout: post
commentIssueId: 11
---

Preventing double spending is the _raison d'etre_ for the blockchain,
so it's a little weird that I implemented it so late.  Yet it's fairly
trivial, and the initial implementation (sans testing!) only took a
day.  Obviously it's illegal for two transactions which spend the same
output to appear in the same chain of blocks (disallowing the same
transaction appearing twice is a corollary of this rule).  So I
maintain a hash of inputs requested by each transaction, and
implemented the complaint packet to show when this happens, as well as
a polite notification when someone sends you a transaction which
clashes with a known one.

The bitcoin reference client treats double spends by ignoring them:
the first spend to reach a node is the one it uses.  I chose a slight
variant, and forget both when we see a clash.  That provides a mild
incentive for miners to do the same, because if they include a
transaction no one knows about in a block there's an extra round-trip
to propogate the block.  With short block times (as I'm thinking for
pettycoin), propogation delay is a significant factor in mining
success.  The result should be that it is harder to double spend.

While implementing this, I realized that when discovering a new
transaction within a block, I need to check for double spends both
ways: both earlier and later in the chain.  This is one subtle
consequence of not knowing everything.

Another consequence: the approach of only tracking unspent outputs is
not quite sufficient with pettycoin.  With bitcoin, if you can do this
because if you can't find the input for a transaction, you drop it: it
doesn't matter whether it's already spent, or doesn't exist at all.
With pettycoin, not knowing an input doesn't invalidate the
transaction, since we don't expect to know everything.  But *someone*
must spot the double-spend so they can spread the word to the rest of
the network, so we need to keep at least some proportion of spent
transactions.  My current implementation keeps them all, which is fine
for the moment...
