#include "../protocol_net.h"
#include "../netaddr.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ccan/net/net.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/err/err.h>
#include <unistd.h>
#include <stdio.h>

/* Spits out the protocol_net_addr(s) on stdout! */
int main(int argc, char *argv[])
{
	int i;

	err_set_progname(argv[0]);

	if (argc == 1 || argc % 2 != 1)
		errx(1, "Usage: %s <addr> <port> [<addr> <port>...]", argv[0]);

	for (i = 1; i < argc; i += 2) {
		struct addrinfo *a = net_client_lookup(argv[i], argv[i+1],
						       AF_UNSPEC, SOCK_STREAM);
		if (!a)
			err(1, "Failed to lookup '%s' port '%s'",
			    argv[i], argv[i+1]);

		while (a) {
			struct protocol_net_address netaddr;
			if (!addrinfo_to_netaddr(&netaddr, a))
				err(1, "Invalid address");

			/* As long as they're distinct, it's OK. */
			memcpy(&netaddr.uuid, &i, sizeof(i));

			fprintf(stderr, "Writing out %s address for %s\n",
				a->ai_family == AF_INET ? "IPv4" : "IPv6",
				argv[i]);

			if (!write_all(STDOUT_FILENO, &netaddr,
				       sizeof(netaddr)))
				err(1, "Writing out netaddr");
			a = a->ai_next;
		}
	}
	return 0;
}
