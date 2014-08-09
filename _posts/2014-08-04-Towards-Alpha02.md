---
layout: post
commentIssueId: 24
---
Lots of bugfixing on alpha01: nothing like having two servers running for
a week to shake things loose!

I spent a few days rewriting
[ccan/io](http://ccodearchive.net/info/io.html) and am fairly happy
with the results.  Both nodes are now running with the new I/O
library.

Except one of the nodes is down pending a restart.  They lost touch
with each other around block 1888, and went their separate ways (an
I/O bug which is now squished).  Getting them to try to resync after
a 6000 block fork is finding some nice bugs!

In particular, once restarted, I saw thousands of
PROTOCOL_ECODE_PRIV_UNKNOWN_PREV in the log, in response to
PROTOCOL_PKT_BLOCK messages.  The first problem was with syncing:

* We sync bitcoin style: we send our most recent 10 block hashes, then
  back by powers of 2.  With each one we send a count of children (if
  there are more than 100 children, we send "lots").
* The mutual block was so far in the past that we end up getting the
  genesis block as our mutual block.  Normally we'd expect to have
  fewer children than the other peer, so we iterate forwards
  enumerating the children of each.
* Unfortunately, this doesn't work: we have lots of children, so do
  they.  So we thought everything was OK, and marked syncing finished.
  Obviously, this is wrong.

Now, once a block was generated, we sent it to the other peer:

* We check the block, it looks OK, but we don't know the previous block
  (header->prev_block), so we drop the block and ask about that one.
* That one is also unknown, so we repeat (about 6000 times).
* Meanwhile another block gets generated, we start asking about that
  one too.  Since we limit ourselves to 4 requests at once, after
  we've had four new blocks come in, this starts limiting the rate at
  which we reach the known block.  And so we never reach it.

The second one already has a FIXME on it: we should remember valid
blocks which don't have a known block.  It still takes a while to
sync, but we will.  I wrote that code today.

The former sync problem made me think about a major protocol change
I've been pondering which will involve rewriting the sync code anyway.

And it'd be nice to do this before -alpha02.  There's no better time to
break the protocol than before there are any users: there's a method
for the network to negotiate protocol changes, but I'd prefer not to
support both old and new protocols until we have to.
