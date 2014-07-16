#include "netaddr.h"
#include "protocol_net.h"
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>

static bool is_ipv4(const struct protocol_net_address *addr)
{
	unsigned int i;

	/* IPv4-mapped IPv6 address: First 80 bits 0, next 16 bits 1 */ 
	for (i = 0; i < 10; i++)
		if (addr->addr[i])
			return false;

	for (; i < 12; i++)
		if (addr->addr[i] != 0xFF)
			return false;

	return true;
}

/* Linux supports connecting to IPv4 addresses via IPv6 interface, so
 * this is unnecessary.  But portable. */
struct addrinfo *mk_addrinfo(const tal_t *ctx,
			     const struct protocol_net_address *netaddr)
{
	struct addrinfo *a = tal(ctx, struct addrinfo);
	
	a->ai_flags = 0;
	a->ai_canonname = NULL;
	a->ai_next = NULL;

	if (is_ipv4(netaddr)) {
		struct sockaddr_in *in = tal(a, struct sockaddr_in);

		a->ai_family = in->sin_family = AF_INET;
		a->ai_addrlen = sizeof(*in);
		a->ai_socktype = SOCK_STREAM;
		a->ai_protocol = IPPROTO_TCP;
		memcpy(&in->sin_addr, netaddr->addr + 12, 4);
		in->sin_port = htons(le16_to_cpu(netaddr->port));
		a->ai_addr = (void *)in;
	} else {
		struct sockaddr_in6 *in6 = talz(a, struct sockaddr_in6);

		a->ai_family = in6->sin6_family = AF_INET6;
		a->ai_addrlen = sizeof(*in6);
		a->ai_socktype = SOCK_STREAM;
		a->ai_protocol = IPPROTO_TCP;
		memcpy(&in6->sin6_addr, netaddr->addr, 16);
		in6->sin6_port = htons(le16_to_cpu(netaddr->port));
		a->ai_addr = (void *)in6;
	}
	return a;
}

static void ipv4_netaddr(struct protocol_net_address *netaddr,
			 const struct sockaddr_in *in)
{
	/* IPv4-mapped IPv6 address: First 80 bits 0, next 16 bits 1 */ 
	memset(netaddr->addr, 0, 10);
	memset(netaddr->addr + 10, 0xff, 2);
	memcpy(netaddr->addr + 12, &in->sin_addr, 4);
	netaddr->port = cpu_to_le16(ntohs(in->sin_port));
}

static void ipv6_netaddr(struct protocol_net_address *netaddr,
			 const struct sockaddr_in6 *in6)
{
	memcpy(netaddr->addr, &in6->sin6_addr, 16);
	netaddr->port = cpu_to_le16(ntohs(in6->sin6_port));
}

bool addrinfo_to_netaddr(struct protocol_net_address *netaddr,
			 const struct addrinfo *a)
{
	if (a->ai_protocol != IPPROTO_TCP)
		return false;

	if (a->ai_family == AF_INET) {
		ipv4_netaddr(netaddr, (void *)a->ai_addr);
		return true;
	} else if (a->ai_family == AF_INET6) {
		ipv6_netaddr(netaddr, (void *)a->ai_addr);
		return true;
	} else
		return false;
}

int socket_for_addr(const struct protocol_net_address *addr)
{
	if (is_ipv4(addr))
		return socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	else
		return socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
}

bool get_fd_addr(int fd, struct protocol_net_address *addr)
{
	union {
		struct sockaddr sa;
		struct sockaddr_in in;
		struct sockaddr_in6 in6;
	} u;
	socklen_t len = sizeof(len);

	if (getsockname(fd, &u.sa, &len) != 0)
		return false;

	if (u.sa.sa_family == AF_INET) {
		ipv4_netaddr(addr, &u.in);
		return true;
	} else if (u.sa.sa_family == AF_INET6) {
		ipv6_netaddr(addr, &u.in6);
		return true;
	}

	errno = EINVAL;
	return false;
}
