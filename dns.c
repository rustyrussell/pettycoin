#include "dns.h"
#include "netaddr.h"
#include "packet_io.h"
#include "protocol_net.h"
#include <assert.h>
#include <ccan/err/err.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/tal/tal.h>
#include <netdb.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>

/* Async dns helper. */
struct dns_info {
	struct state *state;
	struct io_plan *(*init)(struct io_conn *, struct state *,
				struct protocol_net_address *);
	void *pkt;
	size_t num_addresses;
	struct protocol_net_address *addresses;
};

static void lookup_and_write(int fd, const char *name, const char *port)
{
	struct addrinfo *addr, *i;
	struct protocol_net_address *addresses;
	struct protocol_net_hdr hdr;
	size_t num;

	if (getaddrinfo(name, port, NULL, &addr) != 0)
		return;

	num = 0;
	for (i = addr; i; i = i->ai_next)
		num++;

	addresses = tal_arr(NULL, struct protocol_net_address, num);
	num = 0;
	for (i = addr; i; i = i->ai_next) {
		if (!addrinfo_to_netaddr(&addresses[num], i))
			continue;
		num++;
	}

	if (!num) {
		tal_free(addresses);
		return;
	}

	hdr.len = cpu_to_le32(num * sizeof(addresses[0]) + sizeof(hdr));
	hdr.type = 0;

	if (write_all(fd, &hdr, sizeof(hdr)))
		write_all(fd, addresses, num * sizeof(addresses[0]));
	tal_free(addresses);
}

static struct io_plan *connected(struct io_conn *conn, struct dns_info *d)
{
	/* No longer need to try more connections. */
	io_set_finish(conn, NULL, NULL);
	return d->init(conn, d->state, &d->addresses[0]);
}

static void try_connect_one(struct dns_info *d);

/* If this connection failed, try connecting to another address. */
static void connect_failed(struct io_conn *conn, struct dns_info *d)
{
	try_connect_one(d);
}

static struct io_plan *init_conn(struct io_conn *conn, struct dns_info *d)
{
	struct addrinfo *a = mk_addrinfo(d, &d->addresses[0]);

	io_set_finish(conn, connect_failed, d);

	/* That new connection owns d */
	tal_steal(conn, d);
	return io_connect(conn, a, connected, d);
}

static void try_connect_one(struct dns_info *d)
{
	int fd;

	while (d->num_addresses) {
		struct addrinfo *a = mk_addrinfo(d, &d->addresses[0]);

		fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
		if (fd >= 0) {
			io_new_conn(d->state, fd, init_conn, d);
			break;
		}
		/* Consume that address. */
		d->addresses++;
		d->num_addresses--;
	}
}

static struct io_plan *start_connecting(struct io_conn *conn,
					struct dns_info *d)
{
	le32 *len = d->pkt;

	/* Take ownership of packet, so it's freed with d. */
	tal_steal(d, d->pkt);
	d->num_addresses = le32_to_cpu(*len) / sizeof(d->addresses[0]);
	/* Addresses are after len & type. */
	d->addresses = (void *)(len + 2);

	assert(d->num_addresses);
	try_connect_one(d);
	return io_close(conn);
}

static struct io_plan *init_dns_conn(struct io_conn *conn, struct dns_info *d)
{
	return io_read_packet(conn, &d->pkt, start_connecting, d);
}

tal_t *dns_resolve_and_connect(struct state *state,
			       const char *name, const char *port,
			       struct io_plan *(*init)(struct io_conn *,
						       struct state *,
						       struct protocol_net_address *))
{
	int pfds[2];
	struct dns_info *d = tal(NULL, struct dns_info);
	struct io_conn *conn;

	d->state = state;
	d->init = init;

	/* First fork child to get addresses. */
	if (pipe(pfds) != 0) {
		warn("Creating pipes");
		return NULL;
	}

	fflush(stdout);
	switch (fork()) {
	case -1:
		warn("Forking for dns lookup");
		return NULL;
	case 0:
		close(pfds[0]);
		lookup_and_write(pfds[1], name, port);
		exit(0);
	}

	close(pfds[1]);
	conn = io_new_conn(state, pfds[0], init_dns_conn, d);
	tal_steal(conn, d);
	return d;
}
