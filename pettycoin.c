#include <ccan/io/io.h>
#include <ccan/net/net.h>
#include <ccan/opt/opt.h>
#include <ccan/tal/tal.h>
#include <ccan/tal/str/str.h>
#include <ccan/err/err.h>
#include <ccan/noerr/noerr.h>
#include <ccan/io/io.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include "protocol.h"
#include "protocol_net.h"
#include "welcome.h"
#include "peer.h"
#include "state.h"
#include "netaddr.h"

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

static int make_listen_fd(int domain, void *addr, socklen_t len)
{
	int fd = socket(domain, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;

	if (!addr || bind(fd, addr, len) == 0) {
		if (listen(fd, 5) == 0)
			return fd;
	}

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
	fd1 = make_listen_fd(AF_INET6, NULL, 0);
	if (fd1 >= 0) {
		struct sockaddr_in6 in6;

		len = sizeof(in6);
		if (getsockname(fd1, (void *)&in6, &len) != 0)
			close_noerr(fd1);
		else {
			state->listen_port = addr.sin_port = in6.sin6_port;
			io_new_listener(fd1, incoming, state);
		}
	}

	/* Just in case, aim for the same port... */
	fd2 = make_listen_fd(AF_INET,
			     addr.sin_port ? &addr : NULL, sizeof(addr));
	if (fd2 >= 0) {
		len = sizeof(addr);
		if (getsockname(fd2, (void *)&addr, &len) != 0)
			close_noerr(fd2);
		else {
			state->listen_port = addr.sin_port;
			io_new_listener(fd2, incoming, state);
		}
	}

	if (fd1 < 0 && fd2 < 0)
		err(1, "Could not bind to a network address");
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

	/* Specifying --connect implies use only them. */
	state->refill_peers = false;
	return NULL;
}

int main(int argc, char *argv[])
{
	struct state *state = new_state(true);

	err_set_progname(argv[0]);
	opt_set_alloc(opt_allocfn, tal_reallocfn, tal_freefn);
	io_set_alloc(io_allocfn, tal_reallocfn, tal_freefn);

	opt_register_arg("--connect", add_connect, NULL, state,
			 "Node to connect to (can be specified multiple times)");
	opt_register_noarg("-h|--help", opt_usage_and_exit,
			   "\nPettycoin client program.", "Show this usage");
	opt_register_noarg("-V|--version", opt_version_and_exit,
			   VERSION, "Show version and exit");

	opt_parse(&argc, argv, opt_log_stderr_exit);
	if (argc != 1)
		errx(1, "no arguments accepted");

	fill_peers(state);
	make_listeners(state);

	io_loop();

	tal_free(state);
	return 0;
}
