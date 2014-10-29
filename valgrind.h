#ifndef PETTYCOIN_VALGRIND_H
#define PETTYCOIN_VALGRIND_H
#include "config.h"

#ifdef VALGRIND_HEADERS
#include <valgrind/memcheck.h>
#elif !defined(VALGRIND_CHECK_MEM_IS_DEFINED)
#define VALGRIND_CHECK_MEM_IS_DEFINED(p, len)
#endif

static inline void *check_mem(const void *data, size_t len)
{
	VALGRIND_CHECK_MEM_IS_DEFINED(data, len);
	return (void *)data;
}
#endif /* PETTYCOIN_VALGRIND_H */
