#include "packet.h"
#include "protocol_net.h"
#include <ccan/tal/tal.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <poll.h>

static int do_read_packet(int fd, struct io_plan *plan)
{
	char *len_start, *len_end;
	char **pkt = plan->u1.vp;
	int ret;
	u32 max;

	/* We store len in the second union */
	len_start = plan->u2.c;
	len_end = len_start + sizeof(le32);

	/* Now we have the actual plan, we can point into it to store len. */
	if (*pkt == NULL)
		*pkt = len_start;

	/* Still reading len? */
	if (*pkt >= len_start && *pkt < len_end) {
		ret = read(fd, *pkt, len_end - *pkt);
		if (ret <= 0)
			return -1;
		*pkt += ret;
		return 0;
	}

	/* Just finished reading len?  Allocate. */
	if (*pkt == len_end) {
		le32 len;

		memcpy(&len, len_start, sizeof(le32));

		if (le32_to_cpu(len) > PROTOCOL_MAX_PACKET_LEN) {
			errno = ENOSPC;
			return -1;
		}
		*pkt = tal_arr(NULL, char, sizeof(le32) + le32_to_cpu(len));
		*(le32 *)*pkt = len;

		/* Store offset in plan.u2.s */
		plan->u2.s = sizeof(le32);
	}

	/* Read length from packet header. */
	max = sizeof(le32) + le32_to_cpu(*(le32 *)*pkt);

	ret = read(fd, *pkt + plan->u2.s, max - plan->u2.s);
	if (ret <= 0)
		return -1;

	plan->u2.s += ret;
	return (plan->u2.s == max);
}

struct io_plan io_read_packet_(void *ppkt,
			       struct io_plan (*cb)(struct io_conn *, void *),
			       void *arg)
{
	struct io_plan plan;

	assert(cb);
	/* We'll start pointing into a scratch buffer, until we have len. */
	plan.u1.vp = ppkt;
	*(void **)ppkt = NULL;
	plan.io = do_read_packet;
	plan.next = cb;
	plan.next_arg = arg;
	plan.pollflag = POLLIN;

	return plan;
}

struct io_plan io_write_packet_(const void *pkt,
				struct io_plan (*cb)(struct io_conn *, void *),
				void *arg)
{
	le32 len;

	/* Packet header contains 32-bit little-endian length of the rest */
	memcpy(&len, pkt, sizeof(len));
	assert(le32_to_cpu(len) <= PROTOCOL_MAX_PACKET_LEN);

	return io_write(pkt, sizeof(len) + le32_to_cpu(len), cb, arg);
}
