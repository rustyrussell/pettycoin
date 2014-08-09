---
layout: post
commentIssueId: 26
---

A user (wow, I have a user!) reported several bugs, but the coolest
was that `dumbwallet` would freeze talking to `pettycoin`.  Indeed,
strace revealed that *after a successful poll()* write() on a socket
was taking 90 seconds!  You can see the gory details in the
[ccan commit](https://github.com/rustyrussell/ccan/commit/897626152d12d7fd13a8feb36989eb5c8c1f3485).
Without `O_NONBLOCK` it doesn't do the complete write, but it doesn't
return without blocking either.  I didn't expect `O_NONBLOCK` to make
a difference on a ready socket.

I couldn't find anything in Google, so I'm placing it here to remedy
that.

Side note: the reason I didn't find it sooner is that
[until recently](https://github.com/rustyrussell/ccan/commit/12e924346b342c61219a3fdc57eb6b00a27f1cd1)
io_connect() code was making the socket async to do asynchronous
connect(), then by typo, calling `fcntl(fd, F_SETFD,...)` instead of
`F_SETFL` which didn't restore blocking.
