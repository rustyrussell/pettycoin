#ifndef PETTYCOIN_PACKET_H
#define PETTYCOIN_PACKET_H
#include <ccan/io/io.h>

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

#define io_write_packet(pkt, cb, arg)					\
	io_write_packet_(pkt,						\
			 typesafe_cb_preargs(struct io_plan, void *,	\
					     (cb), (arg),		\
					     struct io_conn *),		\
			 (arg))

struct io_plan io_write_packet_(const void *pkt,
			       struct io_plan (*cb)(struct io_conn *, void *),
			       void *arg);

#endif
