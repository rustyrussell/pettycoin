#include "log.h"
#include "packet_io.h"
#include "peer.h"
#include "protocol_net.h"
#include <assert.h>
#include <ccan/io/io_plan.h>
#include <ccan/tal/tal.h>
#include <errno.h>
#include <poll.h>
#include <string.h>

static struct log **fd_to_log;

void add_log_for_fd(int fd, struct log *log)
{
	if (!fd_to_log)
		fd_to_log = tal_arrz(NULL, struct log *, fd + 1);
	else if (tal_count(fd_to_log) <= fd)
		tal_resizez(&fd_to_log, fd + 1);

	assert(log);
	assert(fd_to_log[fd] == NULL);
	fd_to_log[fd] = log;
}

void del_log_for_fd(int fd, struct log *log)
{
	assert(fd_to_log[fd] == log);
	fd_to_log[fd] = NULL;
}

static struct log *get_log_for_fd(int fd)
{
	if (!fd_to_log)
		return NULL;
	if (fd >= tal_count(fd_to_log))
		return NULL;
	return fd_to_log[fd];
}

static int do_read_packet(int fd, struct io_plan_arg *arg)
{
	char *len_start, *len_end;
	char **pkt = arg->u1.vp;
	int ret;
	u32 max;
	struct log *log = get_log_for_fd(fd);

	/* We store len in the second union */
	len_start = arg->u2.c;
	len_end = len_start + sizeof(le32);

	/* Now we have the actual arg, we can point into it to store len. */
	if (*pkt == NULL)
		*pkt = len_start;

	/* Still reading len? */
	if (*pkt >= len_start && *pkt < len_end) {
		ret = read(fd, *pkt, len_end - *pkt);
		if (log)
			log_io(log, true, *pkt, ret < 0 ? 0 : ret);
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

		/* Store offset in arg.u2.s */
		arg->u2.s = sizeof(le32);
	}

	/* Read length from packet header. */
	max = le32_to_cpu(*(le32 *)*pkt);

	ret = read(fd, *pkt + arg->u2.s, max - arg->u2.s);
	if (log)
		log_io(log, true, *pkt + arg->u2.s, ret < 0 ? 0 : ret);
	if (ret <= 0)
		return -1;

	arg->u2.s += ret;
	return (arg->u2.s == max);
}

struct io_plan *io_read_packet_(struct io_conn *conn,
				void *ppkt,
				struct io_plan *(*cb)(struct io_conn *, void *),
				void *cb_arg)
{
	struct io_plan_arg *arg = io_plan_arg(conn, IO_IN);

	/* We'll start pointing into a scratch buffer, until we have len. */
	arg->u1.vp = ppkt;
	*(void **)ppkt = NULL;

	return io_set_plan(conn, IO_IN, do_read_packet, cb, cb_arg);
}

struct io_plan *peer_read_packet(struct peer *peer,
				  struct io_plan *(*cb)(struct io_conn *,
							struct peer *))
{
	assert(get_log_for_fd(io_conn_fd(peer->conn)));

	return io_read_packet(peer->conn, &peer->incoming, cb, peer);
}

/* Frees pkt on next write! */
struct io_plan *peer_write_packet(struct peer *peer, const void *pkt,
				  struct io_plan *(*next)(struct io_conn *,
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
	return io_write(peer->conn, pkt, le32_to_cpu(len), next, peer);
}

