---
layout: post
commentIssueId: 13
---

One big item on my
[todo list](http://rustyrussell.github.io/pettycoin/2014/07/10/Lots-of-Patches.html)
was JSON-RPC.  This is what bitcoind uses, so it makes sense for
pettycoin to do the same.  You can see the bitcoin
[JSON API here](http://en.bitcoin.it/wiki/Original_Bitcoin_client/API_Calls_list).

Unfortunately, the bitcoin one is a bit of an organic mess.  For
example, JSON only has doubles, so they decided to represent amounts
in bitcoin, not satoshi, leading to
[a source of problems](http://en.bitcoin.it/wiki/Proper_Money_Handling_%28JSON-RPC%29).
It also conflates the different tasks of bitcoind: it's a wallet, as
well as a way for wallets to interact with the bitcoin network.

So my API is quite different, and I wrote a specific tool
"pettycoin-query" which interacts with the daemon via a UNIX domain
socket (which has fewer worries that using RPC over SSL).

The [jsmn library](http://zserge.bitbucket.org/jsmn.html) is just 200
lines of C, and minimally sufficient: it took me a while to realize
that the jsmntok_t "size" member is the number of children in the
array or object, each of which could contain multiple tokens!

So I wrote wrappers to handle the things I needed
[EDIT: including more the next week, refs fixed].  You can see the
results here, in particular:

* [json_get_member()](https://github.com/rustyrussell/pettycoin/blob/96146a5ed128a6cc5d96031ed18af1b4d85a24e8/json.c#L56) &emdash; To get a particular member of a json object, or NULL.
* [json_get_arr()](https://github.com/rustyrussell/pettycoin/blob/96146a5ed128a6cc5d96031ed18af1b4d85a24e8/json.c#L71) &emdash; To get a particular element of a json array, or NULL.
* [json_next()](https://github.com/rustyrussell/pettycoin/blob/96146a5ed128a6cc5d96031ed18af1b4d85a24e8/json.c#L45) &emdash; To get the next JSON element at the same level.

There's also a
[json_delve()](https://github.com/rustyrussell/pettycoin/blob/96146a5ed128a6cc5d96031ed18af1b4d85a24e8/json.c#L89)
which takes a guide string like ".somemember[6]" and returns NULL if
'somemember' doesn't exist, or isn't an array, or doesn't have 7
elements.  It's much less C-ish than the other two.
