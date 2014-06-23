---
layout: post
commentIssueId: 3
---

Since I spent the end of last week changing the structure of blocks,
it was time to blow the cobwebs off the unit tests.  I stopped
maintaining those when I realized just how much the project was in
flux: I didn't want to spend a good portion of my time refactoring
test code.

The tests now build, but they're still seriously insufficient.  I
wrote one new one which addressed a bug I was seeing with marshalling
and unmarshalling blocks, threw out one obsolete one, and hacked the
others into shape.  I cherry-picked two more commits by Andrew
McDonnell from the
[pull request](https://github.com/rustyrussell/pettycoin/pull/1) from
back in January, but mostly I rewrote things myself.  From now on,
I'll be maintaining and enhancing the test suite along with the code
itself.

I found time to fix a
[longstanding annoyance in ccan/tal/str](https://github.com/rustyrussell/ccan/commit/c8e75cdce11b3ad7db6c1fff580c587395b59965)
as well (which I knew about, but it bit me anyway while writing
tests).  And this evening I tried to follow the instructions to
[add comments to this github blog](http://ivanzuzak.info/2011/02/18/github-hosted-comments-for-github-hosted-blogs.html)
and it works.  If you can fix me CSS (maybe even make the gravatars
more like the large github comments), I'll owe you a beer...
