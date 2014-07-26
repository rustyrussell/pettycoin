---
layout: post
commentIssueId: 14
---

Although last week was school holidays, I slowly scratched off items
on the TODO list.  This week was more polishing: a
[web page](http://pettycoin.org) with
[FAQ](http://pettycoin.org/faq.html) and
[code of conduct](http://pettycoin.org/conduct.html), and a
[mailing list](http://lists.ozlabs.org/listinfo/pettycoin-dev).

Thanks to the suggestion of [Tim Ansell](http://blog.mithis.net/)
pettycoin also has an IRC channel and uses
[Travis](https://travis-ci.org/rustyrussell/pettycoin) (which I'd
never heard of before) for CI.

[Joel Stanley](http://jms.id.au/wiki) tried to build the source but
failed for lack of CCAN; this seems like an unnecessary hurdle so I
[merged in CCAN](https://github.com/rustyrussell/pettycoin/commit/540815756a31bed281a71ad65ad46d416085f50d).

I'm working now on the bitcoin&lt;-&gt;pettycoin gateway, and writing
a simple wallet.  Then add some instructions, get a few people to test
them and I'll tag and announce alpha-01!
