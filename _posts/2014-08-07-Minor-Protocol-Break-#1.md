---
layout: post
commentIssueId: 25
---
I realized I was out by a factor of 10 on horizons: instead of 30 days,
it was 300 days (120 hours instead of 12 hours for the test network).

I fixed it, then decided 12 hours was too short for the test network
anyway, and made it 3 days.  Technically a protocol break, but in practice
we're tiny and I can just ask anyone forking to upgrade :)
