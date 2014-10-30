---
layout: post
commentIssueId: 37
---
One problem with bitcoin blocks is the irregular timing between them.
If you're waiting for inclusion in a block to make double-spending
more difficult, the formula you need to know is is 1-e^(-(T/600)):
this says the probability that a block has been found at time T
seconds.  At T=600 (ie. 10 minutes) it's 63%: in fact most blocks are
found in under 7 minutes, but there's a long tail.  14% of the time
you're still waiting after 20 minutes, and 5% of the time you're
waiting over 30 minutes with no confirmation, and 1% are over 46
minutes.

10 minutes is a long time already so this doesn't usually hurt
bitcoin, but for shorter block times (for pettycoin, substitute
minutes below for seconds) it can undermine the aim of making payment
usable for casual purchases.

One obvious idea to trim this tail is to allow weaker blocks if some
time has passed, say, twice the target block time (which should happen
14% of the time).  But this doesn't quite have the desired effect,
because miners will store such lower-target blocks when they find
them, whereas normal blocks enter the blockchain immediately.

Imagine block 100 is produced at midday.  Miner Jill finds an easy
block 101 at 12:05 and sends it out.  At 12:20, no normal block has
been found, so nodes accept Jill's block.  But this means that
transactions broadcast at 12:06 are still waiting, so the fast block
time doesn't help them.

I hacked up a quick simulator, and simulating 1000 blocks demonstrates
this: the 99-of-transactions% case withdrops to around 30 minutes
(from 46 minutes), but we can do better.  We could simply allow easy
blocks after 10 minutes rather than twenty, but there's another way.

There's usually more than one easy block found before the 20 minute
mark (we'd expect 4).  Among those, we actually want the last one, not
the first, since it will include the most transactions.  But naively
accepting the last or the one with most transactions would mean
everyone would keep trying to mine a replacement for the last easy
block, instead of mining on top of that for the next block.

Fortunately, we know what transactions were pending at the 20 minute
mark (at least for us; there are delays across the network).  We can
use this to judge easy blocks: pick the one most similar to these
"expected" transactions.

Unfortunately this opens the door to miners gaming the system.  Jill
creates a heap of her own self-to-self transactions, and includes them
in the block she's solving.  If she solves it, publish the block like
normal.  If she gets an easy solution, she would wait until just
before the 20 minute mark and she knows her easy block has a chance.
Then she publishes all those self-to-self transactions; any other
miner won't have included those transactions, and her block will look
really good by our heuristic.

Thus I suggest judging an easy block by summing the transaction fees
of transactions which match our "expected" ones.  There's now a real
risk for a miner publishing self-to-self transactions with fees, since
another miner may include these transactions in their own competing
block, and gain the fees.

Such an algorithm means that 1% case is around 22 minutes; it's pretty
close to the aim of ensuring 20 minute upper limit on transaction
processing.

Side note: the technique used to adjust difficulty every 2016 would
have to be changed a little.  The simplest way is to adjust difficulty
after each 2016-blocks-worth of work, counting easy blocks as 1/4.
This might be up to 3/4 of a block out, but that's acceptable error.
