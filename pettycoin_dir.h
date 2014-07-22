#ifndef PETTYCOIN_PETTYCOIN_DIR_H
#define PETTYCOIN_PETTYCOIN_DIR_H
#include "config.h"
#include <ccan/tal/tal.h>

void pettycoin_dir_register_opts(const tal_t *ctx,
				 char **pettycoin_dir, char **rpc_filename);

#endif /* PETTYCOIN_PETTYCOIN_DIR_H */
