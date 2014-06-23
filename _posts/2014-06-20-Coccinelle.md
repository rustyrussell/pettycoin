---
layout: post
commentIssueId: 2
---
I recently moved the depth into the header, so I decided to use spatch
to help with the grunt work.  I've used it once before, and a little
googling lead me to this:

	@ rule1 @
	struct block *b;
	@@
		
	- b->blocknum
	+ le32_to_cpu(b->hdr->depth)

This missed two cases, however: `te->block->blocknum` was not
replaced.  I fiddled a bit, then
[posted to the mailing list](http://thread.gmane.org/gmane.comp.version-control.coccinelle/3790)
in confusion, and rapidly received a response: by default, spatch only
parses direct headers, so didn't know the type of `te` here.  Using
the `--recursive-includes` option to spatch fixed that perfectly.
