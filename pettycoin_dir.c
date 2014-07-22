#include "pettycoin_dir.h"
#include <ccan/opt/opt.h>
#include <ccan/tal/path/path.h>

static char *default_pettycoin_dir(const tal_t *ctx)
{
	char *path;
	const char *env = getenv("HOME");
	if (!env)
		return ".";

	path = path_join(ctx, env, ".pettycoin");
	return path;
}

void pettycoin_dir_register_opts(const tal_t *ctx,
				 char **pettycoin_dir, char **rpc_filename)
{
	*pettycoin_dir = default_pettycoin_dir(ctx);
	*rpc_filename = "pettycoin-rpc";

	opt_register_early_arg("--pettycoin-dir", opt_set_charp, opt_show_charp,
			       pettycoin_dir,
			       "working directory: all other files are relative to this");

	opt_register_arg("--rpc-file", opt_set_charp, opt_show_charp,
			 rpc_filename,
			 "Set JSON-RPC socket (or /dev/tty)");
}
