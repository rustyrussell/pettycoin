#include <ccan/io/io.h>
#include <ccan/net/net.h>
#include <ccan/opt/opt.h>
#include <ccan/tal/tal.h>
#include <ccan/tal/str/str.h>
#include <ccan/tal/path/path.h>
#include <ccan/err/err.h>
#include <ccan/noerr/noerr.h>
#include <ccan/io/io.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <netdb.h>
#include <errno.h>
#include "protocol.h"
#include "protocol_net.h"
#include "welcome.h"
#include "peer.h"
#include "log.h"
#include "peer_cache.h"
#include "state.h"
#include "netaddr.h"
#include "pseudorand.h"

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

static void make_listeners(struct state *state)
{
	struct sockaddr_in addr;
	socklen_t len;
	int fd1, fd2;

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = 0;

	/* IPv6, since on Linux that (usually) binds to IPv4 too. */
	fd1 = make_listen_fd(state, AF_INET6, NULL, 0);
	if (fd1 >= 0) {
		struct sockaddr_in6 in6;

		len = sizeof(in6);
		if (getsockname(fd1, (void *)&in6, &len) != 0) {
			log_unusual(state->log, "Failed get IPv6 sockname: %s",
				    strerror(errno));
			close_noerr(fd1);
		} else {
			state->listen_port = addr.sin_port = in6.sin6_port;
			log_info(state->log, "Creating IPv6 listener on port %u",
				 be16_to_cpu(state->listen_port));
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
			state->listen_port = addr.sin_port;
			log_info(state->log, "Creating IPv4 listener on port %u",
				 be16_to_cpu(state->listen_port));
			io_new_listener(fd2, incoming, state);
		}
	}

	if (fd1 < 0 && fd2 < 0)
		fatal(state, "Could not bind to a network address");

	if (state->developer_test) {
		int fd;
		struct protocol_net_address a
			= { { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff,
			      0x7f, 0, 0, 1 } };

		a.port = state->listen_port;

		fd = open("../../addresses", O_WRONLY|O_APPEND, 0600);
		if (fd < 0)
			err(1, "Opening ../../addresses");
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

static char *set_log_level(const char *arg, enum log_level *log_level)
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

static char *make_pettycoin_dir(struct state *state)
{
	char *path;
	const char *env = getenv("HOME");
	if (!env)
		errx(1, "$HOME is not set");

	path = path_join(state, env, ".pettycoin");
	log_debug(state->log, "Pettycoin home dir is '%s'", path);
	return path;
}

int main(int argc, char *argv[])
{
	char *pettycoin_dir;
	struct state *state;

	pseudorand_init();
	state = new_state(true);

	err_set_progname(argv[0]);
	opt_set_alloc(opt_allocfn, tal_reallocfn, tal_freefn);
	io_set_alloc(io_allocfn, tal_reallocfn, tal_freefn);

	opt_register_early_arg("--log-level", set_log_level, NULL,
			       &state->log_level,
			       "log level (debug, info, unusual, broken)");
	opt_register_arg("--connect", add_connect, NULL, state,
			 "Node to connect to (can be specified multiple times)");
	opt_register_noarg("--developer-test",
			   opt_set_bool, &state->developer_test,
			   "Developer test mode: connects to localhost");
	opt_register_noarg("-h|--help", opt_usage_and_exit,
			   "\nPettycoin client program.", "Show this usage");
	opt_register_noarg("-V|--version", opt_version_and_exit,
			   VERSION, "Show version and exit");

	/* Parse --log-level first. */
	opt_early_parse(argc, argv, opt_log_stderr_exit);

	pettycoin_dir = make_pettycoin_dir(state);
	opt_parse(&argc, argv, opt_log_stderr_exit);
	if (argc != 1)
		errx(1, "no arguments accepted");

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

	init_peer_cache(state);
	make_listeners(state);
	fill_peers(state);

	io_loop();

	tal_free(state);
	return 0;
}
