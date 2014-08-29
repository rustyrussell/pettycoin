---
layout: post
commentIssueId: 29
---

When I looked at the goals for Alpha02, I realized I'd be breaking the
protocol, so I decided I wanted to do all the breakage at once.  The
first change is to include more than one "prev" reference in each block.

Blocks currently look like this:

    +-------+----------+
	| Stuff | PrevHash |...
	+-------+----------+

This is very much modelled on the bitcoin protocol; each block builds
on the previous one.  But it's been suggested for bitcoin SPV clients
(Simplified Payment Verification, ie. clients without full knowledge)
that you can skip some blocks but still show that you've done all the
work.

The idea is simple: each block's hash has to be below the target
value.  But since blocks are found by trial and error, some blocks
will be _way_ under the target.  The statistics are simple: half the
blocks will be twice as "hard" as they need to be, one quarter four
times as hard, etc.

So, if we let a block which is four times as hard point back 4 blocks
(not just 1), we can drop the three intermediate blocks, for some
space savings.  Of course, we don't know how "hard" a block is until
we've found it, so every block needs to include every back pointer up
to some limit.

    +-------+-----------+-----------+-----------+-----------+
	| Stuff | PrevHash1 | PrevHash2 | PrevHash4 | Prevhash8 |...
	+-------+-----------+-----------+-----------+-----------+

It's just as much work to fake such a "skippy" chain as it is to fake
the entire chain with single back pointers, so no security is lost.

This is great for pettycoin: we have a _horizon_ past which we don't
care about the block contents, just that they lead to the current
blocks we do care about.  This reduces the amount of storage we need
in future, though not by as much as we'd hope (roughly a factor of 10
over keeping every header).

There are some extra tricks we can do; the simplest is to use a merkle
tree to hash the prevhash fields together so when we know which one we
need we can throw away the others (and keep log2(numPrevHash)).  We
can also choose which blocks we keep, aiming to reach the shortest
path, rather than simply stepping backwards greedily.  In fact, we
could even step *forwards* if it allows us to then skip backwards
further.  Dijkstra's algorithm would be of use here, though I haven't
measured how much difference it makes in practice.

The naive back skip list has a fascinating property, in that it
quickly converges on the same blocks.  If there's a limit to how far
you can skip back, this implies that everyone will agree on the
skiplist for really old blocks.

This may also turn out to be a boon: I always planned that the
protocol would fold back rewards from blocks in the far future
(eg. 3-5 years) to those in the past.  But this would mean that we
can't discard blocks below the horizon for at least that long.  Yet
it's just as fair if we call agree on which blocks remain in the
skippy chain, and pile the rewards on to those, rather than every
block.
