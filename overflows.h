#ifndef PETTYCOIN_OVERFLOWS_H
#define PETTYCOIN_OVERFLOWS_H
#include <stddef.h>
#include <stdbool.h>

static inline bool mul_overflows(size_t a, size_t b)
{
	if (!b)
		return false;
	return a * b / b != a;
}

static inline bool add_overflows(size_t a, size_t b)
{
	return a + b < b;
}
#endif /* PETTYCOIN_OVERFLOWS_H */
