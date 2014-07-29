Using the dumbwallet 
====================

We provide a very simple "dumbwallet" program for testing.  It only
has a single key, and doesn't handle any complex cases.

Setting up the dumbwallet
-------------------------

Run `dumbwallet setup` and it will generate your private key and
place it in `dumbwallet.dat`.  You can also use a bitcoin test
network private key, like so (note the P- prefix used to convert
a bitcoin key to a pettycoin key):

    $ KEY=`bitcoind -testnet dumppriv <address>`
	$ ./dumbwallet setup P-$KEY

Using up the dumbwallet
-----------------------

It has two commands: "balance" and "send".  Balance shows the confirmed and
unconfirmed amounts (it's wrong if you have outgoing transactions though,
since they're not deducted from the confirmed balance).

Good luck!<br>
Rusty Russell.
