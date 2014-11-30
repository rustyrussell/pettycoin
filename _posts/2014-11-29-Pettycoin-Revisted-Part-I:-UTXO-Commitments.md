---
layout: post
commentIssueId: 39
---
Since blockstream released their fascinating [sidechains paper](http://www.blockstream.com/sidechains.pdf)
I've been discussing related ideas with Gregory Maxwell.  Sidechains
are a method of automating the 1:1 bitcoin pegging (which pettycoin
uses); it will require a soft-fork of the bitcoin protocol, which is
why I never persued such a direction.  The interest in side-chains
suggests it's a medium-term possibility, however.

More interesting to pettycoin directly is
[this writeup](https://en.bitcoin.it/wiki/User:Gmaxwell/features#Proofs)
on how to change bitcoin to allow partial knowledge.  Much of this
(particularly the idea of transmitting proofs of incorrect behavior)
pettycoin already does; the proof of spending a non-existing input,
however, uses a completely different approach which is worth spelling
out here.

## The Problem ##

In bitcoin, every node knows everything, so it's easy to spot a
transaction which says "this transfers 100 bitcoins from <made up
transaction>".  Without that full knowledge, however, you can't be
sure the transaction is really made up, and you can't prove it
compactly to someone who doesn't know every transaction: "you can't
prove a negative".

## Pettycoin's Solution ##

The miner inserts an index for each input into the block alongside the
transaction: this says where the input transaction is.  This
"input_refs" array is hashed into the merkle hash tree (it's every
second leaf node).

You can prove a miner made up an input transaction by presenting the
transaction, the input refs (both with proof that they're in the
block), and the transaction where the input ref said it would be (with proof).
You still need to detect double-spends in the traditional way, though.

## The UTXO Committment Solution ##

This is a bit more complicated, but it does more.  The scheme has
several parts, the first of which is UTXO Committments; a seemingly
standard part of bitcoin-wizard lore which has several variants
(Andrew Miller provided a wealth of links:
[Andrew Miller's proposal and implementation](https://bitcointalk.org/index.php?topic=101734.0),
[Alan Reiner's proposal](https://bitcointalk.org/index.php?topic=88208.0),
[Mark Friedenbach worked on one](https://bitcointalk.org/index.php?topic=204283.0)
and
[Peter Todd has an implementation](https://github.com/petertodd/python-merbinnertree)).

### Background: UTXO Commitments in A Nutshell ###

The important part of bitcoin is the Unspent Transaction Outputs
(UTXO): stuff which can still be used.  As you go through the blocks,
you naturally have to track these, so you know whether a new
transaction is spending only valid, unspent outputs.

The twist is that you formalize this structure into a UTXO tree; the
specific species of tree doesn't really matter for the idea.  This
tree maps "transaction id, output number" to "version, height,
coinbase flag, scriptpubkey, value" (ie. everything you need to know
about a transaction output to use it).

This tree then gets merkled together so you can describe the state of
the tree with a single hash: this hash gets published in the block (and
if it's wrong, the block is invalid and rejected by the other miners).
You can also compactly prove any part of the tree using a merkle proof,
thus proving that a particular transaction is valid (hey, see, here
are the unspent outputs in the last block, with proofs!).

The original motivation for this was to make light-weight clients more
secure; without this, someone can prove to me that their transaction's
inputs are valid, but they can't prove they're not already spent.

### Using UTXO Commitments for Proving Non-Existent Inputs ###

In this model, every transaction in the block is accompanied by a
proof that the inputs are in the UTXO tree; depending on how the UTXO
tree is implemented, this may be sufficient to determine the new UTXO
tree hash after the input is consumed (if not, proof of extra UTXO
tree nodes is required).  Similarly, you can provide the proof of the
locations in the UTXO tree sufficient to determine the UTXO tree hash
after the outputs are inserted.

This way, you can verify the inputs are correct and unspent for any
random transaction.  You can also verify that the UTXO tree is
correct: if it's not, some transaction must have updated it
incorrectly and that can be proven.

## Partial-Knowledge Mining? ##

The UTXO commitment scheme opens the door to "assisted transactions"
where you supply a transaction along with UTXO proofs that all its
inputs are unspent as of the last block.  A recipient which knows
only the block headers<sup>[1](#footnote-1)</sup> can confidently accept this as an
unconfirmed transaction.

In fact, a miner can actually mine this without any extra checks:
opening the door to partial-knowledge mining, which is a bar I decided
was too high for pettycoin.

## Summary ##

The UTXO solution is more complete: it provides both proof that the
inputs exist, *and* that they're unspent.  This definitely wins.

Corollaries of this include (1) Gregory Maxwell is smarter than I am,
and (2) if you can get the attention of the right bitcoin wizards,
your own sidechain project will be greatly improved :)

<a name="footnote-1">[1]</a> Bitcoin is unlikely to add the UTXO hash to the
80-byte header.  Instead, it would become a compulsory part of the
coinbase, is the order of 100 bytes long, and you need
log2(num-transactions) 32 byte hashes to attach it to the header.  But
that's still well under 1k per 10 minutes for a light-weight node.
