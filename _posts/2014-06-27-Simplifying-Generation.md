---
layout: post
commentIssueId: 7
---

Pettycoin has a simple "mining" program called `generate`.  The main
program feeds it transaction positions and hashes on stdin, and it
outputs a block (if it finds one) on stdout.

There's a race here: the generate program might find a block before it
processes the new transaction(s) we just sent.  It handled this
through an ugly system where pettycoin would feed it a cookie
(actually a pointer to a pending transaction) which gets returned with
the solution.  However, if a pending transaction was invalidated, it
would presumably get freed and thus `generate` would hand us a stale
pointer.

This doesn't happen at the moment since we insist on complete
knowledge of all transactions on a chain to start generating.  But in
general it could, and fixing it would be ugly.

However, the new network protocol already has a packet to say "here's
a block header" and "here are the hashes of all transactions and input
refrences in a shard".  All I had to do is change `generate` to send
those packets, and wire them in.  Much code removed.

While moving some code around, I noticed a stupid bug in my "divide
difficulty by 4" routine.  This is used to solve the problem that we
see a new block, but don't recognize the previous block hash.  If the
block took a significant amount of work to generate, we should try
to find it.  Otherwise it may be random spam, so ignore it.

So I wrote a difficulty test case, which not only allowed me to fix
that bug, but turned up an unrelated in block_ancestor, which went
back to then count'th block, not back count blocks as it advertised.

Testing is good.  Next week, I will write a test a day, while trying
to push forward and complete the handling of every packet in the
protocol.
