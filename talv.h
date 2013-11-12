#ifndef PETTYCOIN_TALV_H
#define PETTYCOIN_TALV_H

/* Tal for variable-length arrays. */
#define TALV_LABEL(type, lastelem)		\
	stringify(type) " " stringify(lastelem)
#define talv(ctx, type, lastelem)					\
	((type *)tal_alloc_((ctx), offsetof(type, lastelem),		\
			    false, TALV_LABEL(type, lastelem)))

/* Cast to union, making sure we're the right type. */
#define to_union(utype, member, ptr) \
	((utype *)((void)(sizeof(&((utype *)NULL)->member == (ptr))), (ptr)))

#endif
