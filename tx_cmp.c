#include "addr.h"
#include "marshal.h"
#include "protocol.h"
#include "tx.h"
#include "tx_cmp.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

/* Returns < 0 if a before b, > 0 if a after b, 0 if equal. */
int tx_cmp(const union protocol_tx *a,
		    const union protocol_tx *b)
{
	const struct protocol_address *addra, *addrb;
	struct protocol_address tmpa, tmpb;
	int ret;
	size_t lena, lenb;

	/* We order by upper bits of output. */
	switch (tx_type(a)) {
	case TX_NORMAL:
		pubkey_to_addr(&a->normal.input_key, &tmpa);
		addra = &tmpa;
		goto known1;
	case TX_FROM_GATEWAY:
		addra = &get_gateway_outputs(&a->gateway)[0].output_addr;
		goto known1;
	}
	abort();

known1:
	switch (tx_type(b)) {
	case TX_NORMAL:
		pubkey_to_addr(&b->normal.input_key, &tmpb);
		addrb = &tmpb;
		goto known2;
	case TX_FROM_GATEWAY:
		addrb = &get_gateway_outputs(&b->gateway)[0].output_addr;
		goto known2;
	}
	abort();

known2:
	ret = memcmp(addra, addrb, sizeof(*addra));
	if (ret)
		return ret;

	/* We need some (arbitrary but deterministic) secondary order */
	lena = marshal_tx_len(a);
	lenb = marshal_tx_len(b);

	if (lena < lenb) {
		ret = memcmp(a, b, lena);
		if (ret == 0)
			/* Shortest wins. */
			ret = -1;
	} else if (lenb < lena) {
		ret = memcmp(a, b, lenb);
		if (ret == 0)
			/* Shortest wins. */
			ret = 1;
	} else {
		ret = memcmp(a, b, lenb);
	}

	return ret;
}

