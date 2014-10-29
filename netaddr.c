#include "netaddr.h"
#include "protocol_net.h"
#include <arpa/inet.h>
#include <assert.h>
#include <ccan/tal/str/str.h>
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

	netaddr->time = cpu_to_le32(0);
	netaddr->unused = cpu_to_le16(0);
	memset(&netaddr->uuid, 0, sizeof(netaddr->uuid));

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

union some_sockaddr {
	struct sockaddr sa;
	struct sockaddr_in in;
	struct sockaddr_in6 in6;
};

static bool get_addr(const union some_sockaddr *u,
		     struct protocol_net_address *addr,
		     socklen_t len)
{
	if (len > sizeof(*u))
		return false;

	addr->time = cpu_to_le32(0);
	addr->unused = cpu_to_le16(0);
	memset(&addr->uuid, 0, sizeof(addr->uuid));
	if (u->sa.sa_family == AF_INET) {
		assert(len == sizeof(u->in));
		ipv4_netaddr(addr, &u->in);
		return true;
	} else if (u->sa.sa_family == AF_INET6) {
		assert(len == sizeof(u->in6));
		ipv6_netaddr(addr, &u->in6);
		return true;
	}

	errno = EINVAL;
	return false;
}

bool get_peer_addr(int fd, struct protocol_net_address *addr)
{
	union some_sockaddr u;
	socklen_t len = sizeof(u);

	if (getpeername(fd, &u.sa, &len) != 0)
		return false;

	return get_addr(&u, addr, len);
}

bool get_local_addr(int fd, struct protocol_net_address *addr)
{
	union some_sockaddr u;
	socklen_t len = sizeof(u);

	if (getsockname(fd, &u.sa, &len) != 0)
		return false;

	return get_addr(&u, addr, len);
}

char *netaddr_string(const tal_t *ctx, const struct protocol_net_address *addr)
{
	char str[INET6_ADDRSTRLEN+1];

	if (inet_ntop(AF_INET6, addr->addr, str, sizeof(str)) == NULL)
		strcpy(str, "UNCONVERTABLE-IPV6");
	return tal_fmt(ctx, "%s:%u", str, le16_to_cpu(addr->port));
}
