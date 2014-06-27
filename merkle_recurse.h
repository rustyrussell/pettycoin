#ifndef PETTYCOIN_MERKLE_RECURSE_H
#define PETTYCOIN_MERKLE_RECURSE_H
#include <stddef.h>

struct protocol_double_sha;

void merkle_recurse(size_t off, size_t max_off, size_t num,
		    void (*fn)(size_t n, void *data,
			       struct protocol_double_sha *merkle),
		    void *data,
		    struct protocol_double_sha *merkle);

#endif /* PETTYCOIN_MERKLE_RECURSE_H */


