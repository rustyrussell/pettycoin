#include "transaction_cmp.h"
#include "protocol.h"
#include <string.h>
#include <stdlib.h>

static u64 get_amount(const union protocol_transaction *t)
{
	switch (t->hdr.type) {
	case TRANSACTION_NORMAL:
		/* For fraud detection purposes, what matters is more the
		 * amount of money involved rather than the amount moved, eg.
		 * a duplicate is worse with a larger change_amount. */
		return (u64)le32_to_cpu(t->normal.send_amount)
			+ le32_to_cpu(t->normal.change_amount);
	case TRANSACTION_FROM_GATEWAY: {
		u32 i;
		u64 total = 0;

		for (i = 0; i < le16_to_cpu(t->gateway.num_outputs); i++)
			total += le32_to_cpu(t->gateway.output[i].send_amount);
		return total;
	}
	default:
		abort();
	}
}

/* Returns < 0 if a before b, > 0 if a after b, 0 if equal.  Both
 * transactions must be valid, as this assumes we don't have to
 * compare input or output arrays. */
int transaction_cmp(const union protocol_transaction *a,
		    const union protocol_transaction *b)
{
	u64 amount_a, amount_b;

	amount_a = get_amount(a);
	amount_b = get_amount(b);

	if (amount_a < amount_b)
		return -1;
	else if (amount_a > amount_b)
		return 1;

	if (a->hdr.type < b->hdr.type)
		return -1;
	else if (a->hdr.type > b->hdr.type)
		return 1;

	switch (a->hdr.type) {
	case TRANSACTION_NORMAL:
		return memcmp(&a->normal, &b->normal, sizeof(a->normal));
	case TRANSACTION_FROM_GATEWAY:
		return memcmp(&a->gateway, &b->gateway, sizeof(a->gateway));
	default:
		abort();
	}
}

