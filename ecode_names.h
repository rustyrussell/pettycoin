#ifndef PETTYCOIN_ECODE_NAMES_H
#define PETTYCOIN_ECODE_NAMES_H
#include "config.h"
#include "protocol_ecode.h"
#include <stdlib.h>

struct ecode_names {
	enum protocol_ecode ecode;
	const char *name;
};

extern struct ecode_names ecode_names[];

static inline const char *ecode_name(enum protocol_ecode ecode)
{
	unsigned int i;

	for (i = 0; ecode_names[i].name; i++)
		if (ecode_names[i].ecode == ecode)
			return ecode_names[i].name;

	return NULL;
}
#endif /* PETTYCOIN_ECODE_NAMES_H */
