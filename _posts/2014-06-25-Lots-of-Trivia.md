---
layout: post
commentIssueId: 6
---
It started with some minor cleanups: the error PROTOCOL_INVALID_LEN
should be called PROTOCOL_ERROR_INVALID_LEN to match the other errors.
That became changing `PROTOCOL_ERROR` to `PROTOCOL_ECODE` [everywhere](https://github.com/rustyrussell/pettycoin/commit/ee1f7d36b45b4556031789e722a16cbafc768bba).

Then I noticed that the other constants which are part of the protocol
should also be have the [PROTOCOL_ prefix](https://github.com/rustyrussell/pettycoin/commit/629caf43f15b3be435da0e8e4c676cc874af6203).

And I've switched from transaction, to trans, and finally ended up at
"tx" as the abbreviation for transaction in the code.  So let's
[use tx everywhere](https://github.com/rustyrussell/pettycoin/commit/4b8e36b5b6fbd42a40bed1919352df5780820450).

[Three](https://github.com/rustyrussell/pettycoin/commit/27bd085e5d807b508fef426b39c451127f7d7b8d)
[dead code](https://github.com/rustyrussell/pettycoin/commit/38a2a727cfca5877590aa05dccc3bd330fa6d971)
[removal](https://github.com/rustyrussell/pettycoin/commit/35c0817c5898deb5829e96ca237ae71c2bb53c65)
patches, and one patch to remove an [unused struct field](https://github.com/rustyrussell/pettycoin/commit/4f69068cb660dab7b99fe8dee6667b6cfce957e8).

Two [minor](https://github.com/rustyrussell/pettycoin/commit/b7e7fc44876caaa7cd001371d41608ebd54c7cca) code [moves](https://github.com/rustyrussell/pettycoin/commit/6b35cb3e787a8356da6d9306eb7a86a58b0c9244).

I wrote a new `structeq` ccan module, and [used it](https://github.com/rustyrussell/pettycoin/commit/b04dc9f43102f28d338684fc7703530c0b0a69c9).

I did write [one new unit test](https://github.com/rustyrussell/pettycoin/commit/3ab36757a64bff4e1bacd80bf1b87b5fdff30c74), and added a valgrind suppressions file for openssl so I could [reenable valgrind leak detection](https://github.com/rustyrussell/pettycoin/commit/665f5dca9b0a416a5e4f7848fdc9d6d26b91c271).

Finally, this evening, since I wanted to get all the trivia out of the
way at once, I
[renamed marshall to marshal](https://github.com/rustyrussell/pettycoin/commit/5a5da5b030741c13bb7117e0cf1409bab0398db1).
