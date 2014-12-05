---
layout: post
commentIssueId: 40
---

One key problem with any system where you only need to know part of
the blocks to contribute, is that you need to be sure that the
information is available: that *someone* can tell you anything you need.

A miner who can hide a corrupt transaction in the blockchain can do a
great deal of damage.  If they convince other miners to build on top,
they can out-compete them by revealing the flawed transaction once the
other miners have wasted their time.  Or they can include a
transaction, then re-use the same inputs causing a follow-on miner to
create a corrupt block; after confirmation time, they reveal it as a
double-spend.

## Pettycoin's Solution ##

The miner has to know the contents of the last 1024 blocks, and
demonstrates this knowledge by publishing an alternate hash (which
incorporates its own payout address) for each shard of transactions:
for block N-1, N-2, N-4, ... N-1024.  It includes one byte of these
hashes in the block header, which costs 40 bytes for the initial
shardsize of 4.

The disadvantage: to prove that this byte is wrong, you need to
publish all the transactions in the particular shard, which is quite
large.  This is somewhat helped by the
255-transaction-per-shard-per-block limit.

## Gregory Maxwell's Server Solution ##

In IRC, Gregory Maxwell (@gmaxwell) suggested:

> [...] every block includes a host which promises to serve you the
> data... if you're unable to get it elsewhere, you go get it from
> there. If that host gets dos attacked, well too bad for them.

He suggested using a rateless erasure code to create a server which
cannot hide a malformed transaction, and I've been working on
simulating such a thing.

We assume the transaction data (transactions, plus proofs) has been
batched into N regular elements of (say) 64 bytes.

### Simple Fountain Codes ###

A simple LT fountain code just XORs some random number of elements
together and returns that.  The "random number" is biassed to produce
1 often enough to get decoding started, and from there you can work
your way to decoding the pairs, then triples, etc.

A fountain code allows you to recover the entire data set with a few
percent more fountain codes than the data set size; clearly, we don't
want to send so much data with each query, otherwise we'd send the
entire set.

## Example Using Simple Fountain Codes ##

The client supplies two numbers: an offset, and a seed for a PRNG.
The server sends back the element at that offset, then uses the PRNG
to determine another (say) 16 XORed elements.  After a number of queries,
all elements can be recovered.

## A Server Which Is Hiding Something ##

Of course, a server hiding something will simply refuse to respond to
any transaction which reveals the flawed element.  If it responds to
less than 50% of the queries, it can be assumed that the majority
the miners will regard the block as invalid, and their attack won't succeed.

Unfortunately, using simple fountain codes makes such cheating easy:
any request which wouldn't XOR in the flawed transaction can be safely
served without revealing it, so we need to design our protocol so that
every response includes more than 50% of the elements.

## Modified Fountain Codes ##

Each request has log(N) responses; the first is the element at the
given offset.  Then two elements at psuedo-random offsets are XORed
for the second response, four for the third, etc.

I wrote a server simulator which tracks what has been sent out,
refuses to respond if doing so would reveal the randomly-chosen
invalid response.  With N=10,000 it starts failing to respond before
5000 queries, as expected.

## A Lying Server ##

A server might actually include an invalid element, rather than lie.
If the invalid element were the first response, that would be
immediately obvious, so it be unable to respond in 1/N cases.
Similarly for any case where other responses would reveal (by
elimination) the inconsistency.  A server would work best by lying in
the last response, where half of the N elements are combined together.

Unfortunately, the PRNG makes it difficult to probe for such
inconsistencies.  You would identify it eventually, but to send that
set of queries to other nodes would be a very large data transfer.
The PRNG also makes it difficult to reason about finding
inconsistencies.

## A Non-PRNG Response ##

Do we need the PRNG in this case?  It seems not, as long as each
response covers over half the elements, and the client chooses the
offset.  Assuming a response is still a sequence of XORed exponential
numbers of elements, we just need to decide the algorithm used to
select which elements are XORed.  Ideally, we want a pattern where
it's easy to generate overlapping responses to test for
inconsistencies.

After playing with numerous sequences, an increasing distance sequence
turned out to be a nice tradeoff, with offset increasing by 1 every
time, eg. here are the XOR patterns for the first 4 responses for a
query:

`1`

&nbsp;`22`

&nbsp;&nbsp;`33 3  3`

&nbsp;&nbsp;&nbsp;`44 4  4   4    4     4`

&hellip;

This is Position(n) = (offset + 1 + (n - 1) * n / 2) % N.

It's fairly easy to generate sequences of queries which can be
combined together to verify each other.  In fact, any sequence of
length N can be verified by one request which gets half the length,
and then single requests for the others for (N/2)+1 query responses.
Compare response 3 with response 4; a query at offset+1 will have
response 3 overlap the first four elements of response 4 above.

## A Better Non-PRNG Response ##

If we include a "series offset" parameter (so) in the request, we can could
directly request two parts of any response.

Position(n) = (offset + 1 + (n+so - 1) * (n+so) / 2) % N.

Eg, with so=4:

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`1   1    1    1`

Given the correct offset parameter, this could be made to align with
the second half of response 4.

## Bringing It All Together ##

Rather than rely on good behavior or random nodes doing audits, we
should have miners include server responses which cover a random
transaction in their coinbase: these would be chosen by H(prev-block |
coinbase-outputs), so it would be different for each miner.  There
should be one of these for the previous block (a quick audit), and
another for some older block (to allow propogation of any proofs there
are problems).

The server can be outsourced by the miner, but would need to sign the
responses (otherwise you can't complain if it lies to you).  A miner
wouldn't need to query the server if it knew enough to generate the
response itself, but it should probably do so anyway, asynchronously,
to keep the system honest.

## Summary ##

The Maxwell proposal is very different from current bitcoin.  It would
remove miners from having to know everything about the block they are
mining (of course, someone would have to supply them with the UTXO
proofs in that case).  It still remains to be shown that there isn't a
technique whereby over half the network can be mislead, using a
combination of lying and omission.

Still, this is the only solution I am aware of which doesn't require
full miner knowledge, and that's definite progress.
