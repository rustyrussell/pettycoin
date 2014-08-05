---
layout: post
commentIssueId: 16
---

Joel ran up pettycoin, and indeed, there were bugs.  Most importantly,
it got very upset with not being able to find 16 peers (`--seeding`
fixes that).

Other fixes since then:
* check_chain debug calls drastically reduced: after 1700 blocks I
  noticed pettycoin chew up CPU and become unresponsive for ten
  seconds at a time.
* JSON-RPC fd issues fixed

The JSON-RPC issue convinced me it's time to rewrite ccan/io.  I have
the beginnings of a plan...
