#ifndef PETTYCOIN_PSEUDORAND_H
#define PETTYCOIN_PSEUDORAND_H
#include "config.h"
#include <ccan/isaac/isaac64.h>

extern struct isaac64_ctx *isaac64;

void pseudorand_init(void);
#endif /* PETTYCOIN_PSEUDORAND_H */
