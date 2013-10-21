#include "dns.h"
#include "protocol_net.h"
#include "netaddr.h"
#include "packet.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <assert.h>
#include <ccan/tal/tal.h>
#include <ccan/err/err.h>

/* Async dns helper. */
struct dns_info {
	struct state *state;
	struct io_plan (*init)(struct io_conn *, struct state *);
	void *pkt;
	size_t num_addresses;
	struct protocol_net_address *addresses;
};

static void lookup_and_write(int fd, const char *name, const char *port)
{
	struct addrinfo *addr, *i;
	struct protocol_net_address *addresses;
	le32 len;

	if (getaddrinfo(name, port, NULL, &addr) != 0)
		return;

	addresses = tal_arr(NULL, struct protocol_net_address, 0);
	for (i = addr; i; i = i->ai_next) {
		struct protocol_net_address a;
		size_t n;

		if (!addrinfo_to_netaddr(&a, i))
			continue;
		n = tal_count(addresses);
		tal_resize(&addresses, n + 1);
		addresses[n] = a;
	}

	len = cpu_to_le32(tal_count(addresses) * sizeof(addresses[0]));
	if (!len)
		return;
	if (write(fd, &len, sizeof(len)) != sizeof(len))
		return;
	write(fd, addresses, len);
	tal_free(addresses);
}

static struct io_plan connected(struct io_conn *conn, struct dns_info *d)
{
	/* No longer need to try more connections. */
	io_set_finish(conn, NULL, NULL);
	return d->init(conn, d->state);
}

static void try_connect_one(struct dns_info *d);

/* If this connection failed, try connecting to another address. */
static void connect_failed(struct io_conn *conn, struct dns_info *d)
{
	try_connect_one(d);
}

static void try_connect_one(struct dns_info *d)
{
	int fd;

	while (d->num_addresses) {
		struct addrinfo *a = mk_addrinfo(d, &d->addresses[0]);

		/* Consume that address. */
		d->addresses++;
		d->num_addresses--;

		fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
		if (fd >= 0) {
			struct io_conn *c;
			c = io_new_conn(fd, io_connect(fd, a, connected, d));
			io_set_finish(c, connect_failed, d);
			/* That new connection owns d */
			tal_steal(c, d);
			break;
		}
	}
}

static struct io_plan start_connecting(struct io_conn *conn, struct dns_info *d)
{
	le32 *len = d->pkt;

	/* Take ownership of packet, so it's freed with d. */
	tal_steal(d, d->pkt);
	d->num_addresses = le32_to_cpu(*len) / sizeof(d->addresses[0]);
	/* Addresses are after header. */
	d->addresses = (void *)(len + 1);

	assert(d->num_addresses);
	try_connect_one(d);
	return io_close();
}

bool dns_resolve_and_connect(struct state *state,
			     const char *name, const char *port,
			     struct io_plan (*init)(struct io_conn *,
						    struct state *))
{
	int pfds[2];
	struct dns_info *d = tal(NULL, struct dns_info);
	struct io_conn *conn;

	d->state = state;
	d->init = init;

	/* First fork child to get addresses. */
	if (pipe(pfds) != 0) {
		warn("Creating pipes");
		return false;
	}

	switch (fork()) {
	case -1:
		warn("Forking for dns lookup");
		return false;
	case 0:
		close(pfds[0]);
		lookup_and_write(pfds[1], name, port);
		exit(0);
	}

	close(pfds[1]);
	conn = io_new_conn(pfds[0],
			   io_read_packet(&d->pkt, start_connecting, d));
	tal_steal(conn, d);
	return true;
}
