#ifndef PETTYCOIN_PKT_NAMES_H
#define PETTYCOIN_PKT_NAMES_H
#include "config.h"
#include "protocol_net.h"
#include <stdlib.h>

struct pkt_names {
	enum protocol_pkt_type type;
	const char *name;
};

extern struct pkt_names pkt_names[];

static inline const char *pkt_name(enum protocol_pkt_type type)
{
	unsigned int i;

	for (i = 0; pkt_names[i].name; i++)
		if (pkt_names[i].type == type)
			return pkt_names[i].name;

	return NULL;
}
#endif /* PETTYCOIN_PKT_NAMES_H */
