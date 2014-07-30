#include "log.h"
#include "packet_io.h"
#include "peer.h"
#include "protocol_net.h"
#include <assert.h>
#include <ccan/tal/tal.h>
#include <errno.h>
#include <poll.h>
#include <string.h>

static int read_packet_part(int fd, struct io_plan *plan,
			    void (*log)(const void *buf, int len, void *arg))
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
		log(*pkt, ret, plan->next_arg);
		if (ret <= 0)
			return -1;
		*pkt += ret;
		return 0;
	}

	/* Just finished reading len?  Allocate. */
	if (*pkt == len_end) {
		le32 len;

		memcpy(&len, len_start, sizeof(le32));

		/* Too big for protocol. */ 
		if (le32_to_cpu(len) > PROTOCOL_MAX_PACKET_LEN) {
			errno = ENOSPC;
			return -1;
		}
		if (le32_to_cpu(len) < sizeof(struct protocol_net_hdr)) {
			errno = EINVAL;
			return -1;
		}

		*pkt = tal_arr(NULL, char, le32_to_cpu(len));
		*(le32 *)*pkt = len;

		/* Store offset in plan.u2.s */
		plan->u2.s = sizeof(le32);
	}

	/* Read length from packet header. */
	max = le32_to_cpu(*(le32 *)*pkt);

	ret = read(fd, *pkt + plan->u2.s, max - plan->u2.s);
	log(*pkt + plan->u2.s, ret, plan->next_arg);
	if (ret <= 0)
		return -1;

	plan->u2.s += ret;
	return (plan->u2.s == max);
}

static void nolog(const void *buf, int len, void *arg)
{
}

static int do_read_packet(int fd, struct io_plan *plan)
{
	return read_packet_part(fd, plan, nolog);
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

static void log_one_read(const void *buf, int len, void *arg)
{
	struct peer *peer = arg;
	log_io(peer->log, true, buf, len < 0 ? 0 : len);
}

static int do_read_peer_packet(int fd, struct io_plan *plan)
{
	return read_packet_part(fd, plan, log_one_read);
}

struct io_plan peer_read_packet_(void *ppkt,
				 struct io_plan (*cb)(struct io_conn *,
						      struct peer *),
				 struct peer *peer)
{
	struct io_plan plan;

	assert(cb);
	/* We'll start pointing into a scratch buffer, until we have len. */
	plan.u1.vp = ppkt;
	*(void **)ppkt = NULL;
	plan.io = do_read_peer_packet;
	plan.next = (void *)cb;
	plan.next_arg = peer;
	plan.pollflag = POLLIN;

	return plan;
}

/* Frees pkt on next write! */
struct io_plan peer_write_packet(struct peer *peer, const void *pkt,
				 struct io_plan (*next)(struct io_conn *,
							struct peer *))
{
	le32 len;

	tal_free(peer->outgoing);
	peer->outgoing = pkt;

	/* Packet header contains 32-bit little-endian length */
	memcpy(&len, pkt, sizeof(len));
	assert(le32_to_cpu(len) >= sizeof(struct protocol_net_hdr));
	assert(le32_to_cpu(len) <= PROTOCOL_MAX_PACKET_LEN);

	log_io(peer->log, false, pkt, le32_to_cpu(len));
	return io_write(pkt, le32_to_cpu(len), next, peer);
}

