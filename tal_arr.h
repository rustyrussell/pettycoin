/* Helpers for handling tal'ed arrays of pointers. */
#ifndef PETTYCOIN_TAL_ARR_H
#define PETTYCOIN_TAL_ARR_H
#include "config.h"
#include <assert.h>
#include <ccan/tal/tal.h>

#define tal_arr_append(pptr, p)					\
	tal_arr_append_((void ***)(pptr) + 0*sizeof(**(pptr)==(p)), (p))

static inline void tal_arr_append_(tal_t ***ctxp, const void *p)
{
	size_t num = tal_count(*ctxp);
	tal_resize(ctxp, num + 1);
	(*ctxp)[num] = (void *)p;
}

#define tal_arr_add(pptr, pos, p)					\
	tal_arr_add_((void ***)(pptr) + 0*sizeof(**(pptr)==(p)), (pos), (p))

static inline void tal_arr_add_(tal_t ***ctxp, size_t pos, void *p)
{
	size_t num = tal_count(*ctxp);
	assert(pos <= num);
	tal_resize(ctxp, num + 1);
	memmove(&(*ctxp)[pos + 1], &(*ctxp)[pos], (num - pos) * sizeof(void *));
	(*ctxp)[pos] = (void *)p;
}

#define tal_arr_del(pptr, pos)					\
	tal_arr_del_((void ***)pptr, (pos))

static inline void tal_arr_del_(tal_t ***ctxp, size_t pos)
{
	size_t num = tal_count(*ctxp);
	assert(pos < num);
	memmove(&(*ctxp)[pos], &(*ctxp)[pos + 1],
		(num - pos - 1) * sizeof(void *));
	tal_resize(ctxp, num - 1);
}

#endif /* PETTYCOIN_TAL_ARR_H */
