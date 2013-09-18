#ifndef PETTYCOIN_VERSION_H
#define PETTYCOIN_VERSION_H
#include <ccan/short_types/short_types.h>
#include <stdbool.h>

static inline u8 current_version(void)
{
	return 1;
}

static inline bool version_ok(u8 version)
{
	return version == current_version();
}
#endif /* PETTYCOIN_VERSION_H */
