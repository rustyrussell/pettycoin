[![Build Status](https://travis-ci.org/rustyrussell/pettycoin.svg?branch=master)](https://travis-ci.org/rustyrussell/pettycoin)

This is an unstable, developer experiment, running on its test
network!  Follow along the fun here:
http://rustyrussell.github.io/pettycoin/

To build:
--------
1. Install the openssl development headers and valgrind, eg:
    `apt-get install build-essential git libssl-dev valgrind`.
2. `./configure && make && make check`

Things you can do:
--------
* Run the pettycoin daemon `./pettycoin`:

    * This will create a `~/.pettycoin/` directory where you can place
      your config (which are simply commandline options without the
      --, like `log-level=debug` and `port=8323`).
    * The CPU miner won't run unless you set `--reward-address`; eg.
      `P-mhA9ozMTVWrSnUX2kB8QjEq9FBen8k3euW`.
    * Try `--help`.

* Interact with the running pettycoin using `./pettycoin-query`:

    * `help` is a useful command.
    * You can inject a raw transaction with `sendrawtransaction`.

* Create a transaction with `./pettycoin-tx`.

* **COMING SOON** Run a gateway.

* **COMING SOON** Create and monitor a simple test wallet.

You can see some examples by looking at [test/standalone/simple_inject.sh](https://github.com/rustyrussell/pettycoin/blob/master/test/standalone/simple_inject.sh).

Getting Help
--------

You can reach the developers on IRC (#pettycoin on Freenode), on the
[development mailing list](https://lists.ozlabs.org/listinfo/pettycoin-dev),
and of course, via pull requests and the [Github bug tracker](https://github.com/rustyrussell/pettycoin/issues).

Good luck!<br>
Rusty Russell.
