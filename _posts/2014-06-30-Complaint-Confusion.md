---
layout: post
commentIssueId: 8
---

One key idea of pettycoin is that of _complaint_ packets, which allow
one node to prove that there is a problem with a block in a compact
form, and not requiring any other knowledge by the recipient.  For
example, consider if you put a transaction in a block which tries to
use one my transactions as an input.  To show that the block is invalid,
I only need send my transaction, your transaction, and proof that
your transaction is in that block.

Naturally, the code which implemented this was as-yet untested.  When
I started reading it to implement `PROTOCOL_PKT_TX_IN_BLOCK` packets,
I discovered a nasty but buried bug.  By policy, we never put a
known-bad transaction into a block.  But the "create_proof()" routine
called in the complaint generation tried to use the block contents to
prove the bad transaction (which isn't in there).

The call chain obscured this, however, calling `create_proof` within
`tal_packet_append_proof` which was called from
`invalidate_block_bad_input`.  My fix was to make
`tal_packet_append_proof` dumber, and have the caller pass in the
proof.  Sometimes more explicit is good: hard-to-misuse is more
important than easy-to-use.

This also exposed that when we receive a transaction with the proof
it's in the a block, we have to keep the proof around in case we want
to complain about it later.  That's part of today's coding.
