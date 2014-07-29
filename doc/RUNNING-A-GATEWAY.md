Running a Pettycoin Gateway
===========================

On the test network, anyone can run a pettycoin gateway.  It listens
to the bitcoin (test) network for network sends, and injects funds
into the pettycoin network.

There is currently one running at address
mnwYn3mP11dWvJUbyraBqYBkx8TgWSLgVn on the bitcoin test network, if you
don't want to run your own.

**It does not yet return funds to the bitcoin network!**

Daemons You Need To Be Running
------------------------------

To operate a gateway, you will need to also run the following:

* bitcoind, with configurtion like so (it will also insist you set an
  rpcpassword when you first try to run it).

    testnet=1
    server=1
    gen=0
    txindex=1

* pettycoin, with no particular config.

pettycoin-gateway Setup
------------------------------

Make sure bitcoind, pettycoin-tx and pettycoin-query are in the
path (as pettycoin-gateway will invoke them).

First run `pettycoin-gateway --setup`:

    rusty@Petty1:~/src/pettycoin$ pettycoin-gateway --setup
    Gateway address is muQY1RFhzu2exJj4wihqfotzDDztS1ieZv

This will create the following files in ~/.pettycoin:

<dl>
<dt> `gateway-address`
<dd> The public address of the gateway (also printed by --setup above).
<dt> `gateway-privkey`
<dd> The private key of the gateway (needed to sign pettycoin gateway
     transactions).
<dt> `gateway-txs`

<dd> The bitcoin transaction IDs the gateway already injected into the
	pettycoin network, so it doesn't inject twice.
</dl>

It will also create a bitcoin account called "gateway" with a single
address in it (the same as listed above) to receive funds.

Running pettycoin-gateway
-------------------------

Now you can run pettycoin-gateway!  It exits on any kind of error,
with no decent diagnostics.  But if you run it again it should be
safe, as it only records injected transactions into gateway-tx after
they've been injected into the pettycoin network.

Good luck!<br>
Rusty Russell.
