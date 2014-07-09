#ifndef PETTYCOIN_PACKET_IO_H
#define PETTYCOIN_PACKET_IO_H
#include "config.h"
#include <ccan/io/io.h>

/* All packets are "le32 len, type" then len-8 bytes. */
struct peer;

/* Takes any pointer to pointer, fills it in. */
#define io_read_packet(ppkt, cb, arg)					\
	((void)sizeof(**(ppkt)),					\
	 io_read_packet_(ppkt,						\
			 typesafe_cb_preargs(struct io_plan, void *,	\
					     (cb), (arg),		\
					     struct io_conn *),		\
			 (arg)))

struct io_plan io_read_packet_(void *ppkt,
			       struct io_plan (*cb)(struct io_conn *, void *),
			       void *arg);

#define io_write_packet(peer, pkt, next)				\
	io_write_packet_((peer), (pkt),					\
			 typesafe_cb_preargs(struct io_plan, void *,	\
					     (next), (peer),		\
					     struct io_conn *))

/* Frees pkt on next write! */
struct io_plan io_write_packet_(struct peer *peer, const void *pkt,
				struct io_plan (*next)(struct io_conn *,
						       void *));
#endif
