---
layout: post
---
When I started thinking about pettycoin my head was full of
proof-of-work, and similar protocol issues.  When I started
implementing pettycoin I quickly got bogged down in the minutia of
networking between pettycoin nodes.  So I decided to implement the
most familiar thing: a command-response protocol.

But a peer-to-peer network isn't like an FTP server.  Getting your
node bootstrapped is a little like querying servers, but once running
it's much more free-flowing as blocks and transactions pass around.
And spray-and-pray only gets you so far.  Thus, I turned my attention
to what it should look like.

When I first used bitcoin, IRC servers were used for peer
communication.  This is actually quite clever, but suffers from the
problems of any external infrastructure.  Nowdays bitcoin still uses
quite naive methods, for example it broadcasts blocks complete with
all transactions, and to bootstrap you ask a single node for
everything.

The protocol I've implemented is a serious rewrite, split for no
good reason over two commits ([1](https://github.com/rustyrussell/pettycoin/commit/8cbde5d7095cb764cf8e8486856964475434496d) and [2](https://github.com/rustyrussell/pettycoin/commit/eb59df41052db94650a131477181a211896d7be5)).
It works as follows to get the block headers:

* The welcome packet includes the 10 last blocks you know, then powers of 2
  back to the genesis block.  A-la bitcoin.  This makes it easy to figure
  out a "mutual" block known by both nodes.
* The response is either a horizon packet (if your blocks are older
  than the 1 month horizon), or a sync packet if you are more recent.
* The horizon packet contains a subset of blocks from below the
  horizon to the genesis block.  Since a node doesn't need the details of
  every block, it uses a similar algorithm to that proposed for
  [compact SPV proofs](http://sourceforge.net/p/bitcoin/mailman/message/32111357/)
  which provides proof that sufficient work was done to reach the
  horizon, without caring about the details.
* The sync packet contains details on every block directly joining
  some point below the horizon to the mutual block, with a count of
  children off in side chains for each one.  This allows the node to
  query the children of any blocks which have a higher number of
  children than expected.
* The node then asks about children recursively, until it has synced
  the tree.

To get the actual contents of the blocks, we currently just ask for
every batch of transactions for every block.  The protocol is supposed
to be more nuanced, but I've decided to change it, which is the
subject of the next post.

Meanwhile, things seem to work again: two nodes talk to each other and
generate blocks without forking, and a third node joining later gets
up to speed.
