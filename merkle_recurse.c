#include "merkle_recurse.h"
#include "shadouble.h"
#include "protocol.h"
#include <assert.h>
#include <string.h>

void merkle_recurse(size_t off, size_t max_off, size_t num,
		    void (*fn)(size_t, void *, struct protocol_double_sha *),
		    void *data,
		    struct protocol_double_sha *merkle)
{
	/* Always a power of 2. */
	assert((num & (num-1)) == 0);
	assert(num != 0);

	if (num == 1) {
		if (off >= max_off)
			memset(merkle, 0, sizeof(*merkle));
		else
			fn(off, data, merkle);
	} else {
		SHA256_CTX shactx;
		struct protocol_double_sha sub[2];

		num /= 2;
		merkle_recurse(off, max_off, num, fn, data, sub);
		merkle_recurse(off + num, max_off, num, fn, data, sub+1);
		
		SHA256_Init(&shactx);
		SHA256_Update(&shactx, sub, sizeof(sub));
		SHA256_Double_Final(&shactx, merkle);
	}
}
