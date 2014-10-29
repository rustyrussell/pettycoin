#ifndef PETTYCOIN_NETADDR_H
#define PETTYCOIN_NETADDR_H
#include "config.h"
#include <ccan/tal/tal.h>

struct protocol_net_address;
struct addrinfo *mk_addrinfo(const tal_t *ctx,
			     const struct protocol_net_address *netaddr);

bool addrinfo_to_netaddr(struct protocol_net_address *netaddr,
			 const struct addrinfo *a);

int socket_for_addr(const struct protocol_net_address *addr);
bool get_peer_addr(int fd, struct protocol_net_address *addr);
bool get_local_addr(int fd, struct protocol_net_address *addr);
#endif /* PETTYCOIN_NETADDR_H */
