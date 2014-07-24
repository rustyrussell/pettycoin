#include "base58.h"
#include "blockfile.h"
#include "generating.h"
#include "jsonrpc.h"
#include "log.h"
#include "netaddr.h"
#include "peer.h"
#include "peer_cache.h"
#include "pettycoin_dir.h"
#include "protocol.h"
#include "protocol_net.h"
#include "pseudorand.h"
#include "state.h"
#include "welcome.h"
#include <ccan/err/err.h>
#include <ccan/io/io.h>
#include <ccan/net/net.h>
#include <ccan/noerr/noerr.h>
#include <ccan/opt/opt.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/str/str.h>
#include <ccan/tal/tal.h>
#include <errno.h>
#include <netdb.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

/* Tal wrappers for opt and io. */
static void *opt_allocfn(size_t size)
{
	return tal_alloc_(NULL, size, false, TAL_LABEL("opt_allocfn", ""));
}

static void *io_allocfn(size_t size)
{
	return tal_alloc_(NULL, size, false, TAL_LABEL("io_allocfn", ""));
}

static void *tal_reallocfn(void *ptr, size_t size)
{
	if (!ptr)
		return opt_allocfn(size);
	tal_resize_(&ptr, 1, size, false);
	return ptr;
}

static void tal_freefn(void *ptr)
{
	tal_free(ptr);
}

static void incoming(int fd, struct state *state)
{
	new_peer(state, fd, NULL);
}

static int make_listen_fd(struct state *state, int domain, void *addr, socklen_t len)
{
	int fd = socket(domain, SOCK_STREAM, 0);
	if (fd < 0) {
		log_debug(state->log, "Failed to create %u socket: %s",
			  domain, strerror(errno));
		return -1;
	}

	if (!addr || bind(fd, addr, len) == 0) {
		if (listen(fd, 5) == 0)
			return fd;
		log_unusual(state->log, "Failed to listen on %u socket: %s",
			    domain, strerror(errno));
	} else
		log_debug(state->log, "Failed to bind on %u socket: %s",
			  domain, strerror(errno));

	close_noerr(fd);
	return -1;
}

static void make_listeners(struct state *state, unsigned int portnum)
{
	struct sockaddr_in addr;
	struct sockaddr_in6 addr6;
	socklen_t len;
	int fd1, fd2;

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(portnum);

	addr6.sin6_family = AF_INET6;
	addr6.sin6_addr = in6addr_any;
	addr6.sin6_port = htons(portnum);

	/* IPv6, since on Linux that (usually) binds to IPv4 too. */
	fd1 = make_listen_fd(state, AF_INET6, portnum ? &addr6 : NULL,
			     sizeof(addr6));
	if (fd1 >= 0) {
		struct sockaddr_in6 in6;

		len = sizeof(in6);
		if (getsockname(fd1, (void *)&in6, &len) != 0) {
			log_unusual(state->log, "Failed get IPv6 sockname: %s",
				    strerror(errno));
			close_noerr(fd1);
		} else {
			addr.sin_port = in6.sin6_port;
			state->listen_port = ntohs(addr.sin_port);
			log_info(state->log, "Creating IPv6 listener on port %u",
				 state->listen_port);
			io_new_listener(fd1, incoming, state);
		}
	}

	/* Just in case, aim for the same port... */
	fd2 = make_listen_fd(state, AF_INET,
			     addr.sin_port ? &addr : NULL, sizeof(addr));
	if (fd2 >= 0) {
		len = sizeof(addr);
		if (getsockname(fd2, (void *)&addr, &len) != 0) {
			log_unusual(state->log, "Failed get IPv4 sockname: %s",
				    strerror(errno));
			close_noerr(fd2);
		} else {
			state->listen_port = ntohs(addr.sin_port);
			log_info(state->log, "Creating IPv4 listener on port %u",
				 state->listen_port);
			io_new_listener(fd2, incoming, state);
		}
	}

	if (fd1 < 0 && fd2 < 0)
		fatal(state, "Could not bind to a network address");

	if (state->developer_test) {
		int fd;
		struct protocol_net_address a = 
			{ 0, { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff,
			       0x7f, 0, 0, 1 }, 0, 0 };

		a.time = cpu_to_le32(time(NULL));
		a.port = cpu_to_le16(state->listen_port);
		a.uuid = state->uuid;

		fd = open("addresses", O_CREAT|O_WRONLY|O_APPEND, 0600);
		if (fd < 0)
			err(1, "Opening addresses");
		write(fd, &a, sizeof(a));
		close(fd);
	}
}

static char *add_connect(const char *arg, struct state *state)
{
	const char *node, *service, *colon;

	colon = strchr(arg, ':');
	if (!colon)
		return tal_strdup(NULL, "node addresses must be <addr>:<port>");

	node = tal_strndup(NULL, arg, colon - arg);
	service = colon + 1;

	/* Do lookup async. */
	if (!new_peer_by_addr(state, node, service))
		return tal_fmt(NULL, "error looking up %s:%s: %s",
			       node, service, strerror(errno));

	log_info(state->log, "--connect to %s:%s disables refill", node, service);

	/* Specifying --connect implies use only them. */
	state->refill_peers = false;
	return NULL;
}

static char *arg_log_level(const char *arg, enum log_level *log_level)
{
	if (streq(arg, "debug"))
		*log_level = LOG_DBG;
	else if (streq(arg, "info"))
		*log_level = LOG_INFORM;
	else if (streq(arg, "unusual"))
		*log_level = LOG_UNUSUAL;
	else if (streq(arg, "broken"))
		*log_level = LOG_BROKEN;
	else
		return tal_fmt(NULL, "unknown log level");
	return NULL;
}

/* FIXME: make this nicer! */
static void config_log_stderr_exit(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

	/* This is the format we expect: mangle it to remove '--'. */
	if (streq(fmt, "%s: %.*s: %s")) {
		const char *argv0 = va_arg(ap, const char *);
		unsigned int len = va_arg(ap, unsigned int);
		const char *arg = va_arg(ap, const char *);
		const char *problem = va_arg(ap, const char *);

		fprintf(stderr, "%s line %s: %.*s: %s",
			argv0, arg+strlen(arg)+1, len-2, arg+2, problem);
	} else {
		vfprintf(stderr, fmt, ap);
	}
	fprintf(stderr, "\n");
	va_end(ap);
	exit(1);
}

/* We turn the config file into cmdline arguments. */
static void parse_from_config(const tal_t *ctx)
{
	char *contents, **lines;
	char **argv;
	int i, argc;

	contents = grab_file(ctx, "config");
	/* Doesn't have to exist. */
	if (!contents) {
		if (errno != ENOENT)
			err(1, "Opening and reading config");
		return;
	}

	lines = tal_strsplit(contents, contents, "\r\n", STR_NO_EMPTY);

	/* We have to keep argv around, since opt will point into it */
	argv = tal_arr(ctx, char *, argc = 1);
	argv[0] = "pettycoin config file";

	for (i = 0; i < tal_count(lines) - 1; i++) {
		if (strstarts(lines[i], "#"))
			continue;
		/* Only valid forms are "foo" and "foo=bar" */
		tal_resize(&argv, argc+1);
		/* Stash line number after nul. */
		argv[argc++] = tal_fmt(argv, "--%s%c%u", lines[i], 0, i+1);
	}
	tal_resize(&argv, argc+1);
	argv[argc] = NULL;

	opt_parse(&argc, argv, config_log_stderr_exit);
	tal_free(contents);
}

static char *set_reward_address(const char *arg, struct state *state)
{
	bool test_net;

	/* In case they set multiple times. */
	state->reward_addr = tal_free(state->reward_addr);

	/* Unset. */
	if (streq(arg, "")) {
		return NULL;
	}
	state->reward_addr = tal(state, struct protocol_address);

	if (!pettycoin_from_base58(&test_net, state->reward_addr, arg, strlen(arg)))
		return strdup("Could not parse address");
	if (test_net && !state->test_net)
		return strdup("Reward address is on testnet");
	if (!test_net && state->test_net)
		return strdup("Reward address is on not testnet");

	return NULL;
}

int main(int argc, char *argv[])
{
	char *pettycoin_dir, *rpc_filename;
	struct state *state;
	char *log_prefix = "";
	unsigned int portnum = 0;

	pseudorand_init();
	state = new_state(true);

	err_set_progname(argv[0]);
	opt_set_alloc(opt_allocfn, tal_reallocfn, tal_freefn);
	io_set_alloc(io_allocfn, tal_reallocfn, tal_freefn);

	pettycoin_dir_register_opts(state, &pettycoin_dir, &rpc_filename);

	opt_register_noarg("--help|-h", opt_usage_and_exit, "",
			   "Show this message");
	opt_register_noarg("--version|-V", opt_version_and_exit, VERSION,
			   "Display version and exit");

	opt_register_arg("--log-level", arg_log_level, NULL,
			 &state->log_level,
			 "log level (debug, info, unusual, broken)");
	opt_register_arg("--log-prefix", opt_set_charp, opt_show_charp,
			 &log_prefix, "log prefix");
	opt_register_arg("--connect", add_connect, NULL, state,
			 "Node to connect to (can be specified multiple times)");
	opt_register_arg("--port", opt_set_uintval, NULL, &portnum,
			 "Port to bind to (otherwise, dynamic port is used)");

	/* Generation options. */
	opt_register_arg("--generator", opt_set_charp, opt_show_charp,
			 &state->generator, "Binary to try to generate a block");
	opt_register_arg("--reward-address", set_reward_address, NULL,
			 state, "Address to send block fee rewards");
	opt_register_noarg("--require-fees", opt_set_bool,
			 &state->require_non_gateway_tx_fee,
			 "Never mine normal transactions without a fee");
	opt_register_noarg("--require-gateway-fees", opt_set_bool,
			 &state->require_gateway_tx_fee,
			 "Never mine gateway transactions without a fee");

	opt_register_noarg("--developer-test",
			   opt_set_bool, &state->developer_test,
			   "Developer test mode: connects to localhost");

	/* Parse --pettycoin-dir first. */
	opt_early_parse(argc, argv, opt_log_stderr_exit);

	/* Move to pettycoin dir, to save ourselves the hassle of path manip. */
	if (chdir(pettycoin_dir) != 0) {
		log_unusual(state->log, "Creating pettycoin dir %s"
			    " (because chdir gave %s)",
			    pettycoin_dir, strerror(errno));
		if (mkdir(pettycoin_dir, 0700) != 0)
			fatal(state, "Could not make directory %s: %s",
			      pettycoin_dir, strerror(errno));
		if (chdir(pettycoin_dir) != 0)
			fatal(state, "Could not change directory %s: %s",
			      pettycoin_dir, strerror(errno));
	}
	/* Now look for config file */
	parse_from_config(state);

	/* These arguments don't make any sense in config file. */
	opt_register_noarg("-h|--help", opt_usage_and_exit,
			   "\nPettycoin client program.", "Show this usage");
	opt_register_noarg("-V|--version", opt_version_and_exit,
			   VERSION, "Show version and exit");

	/* Finally parse cmdline (they override config) */
	opt_parse(&argc, argv, opt_log_stderr_exit);
	if (argc != 1)
		errx(1, "no arguments accepted");

	set_log_level(state->log, state->log_level);
	set_log_prefix(state->log, log_prefix);

	/* Start up. */
	load_blocks(state);
	init_peer_cache(state);
	make_listeners(state, portnum);
	fill_peers(state);
	start_generating(state);
	setup_jsonrpc(state, rpc_filename);

	io_loop();

	tal_free(state);
	return 0;
}
