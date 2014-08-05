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

/* Peer-specific functions (also log I/O) */
#define peer_read_packet(ppkt, cb, peer)				\
	((void)sizeof(**(ppkt)),					\
	 peer_read_packet_((ppkt), (cb), (peer)))

struct io_plan peer_read_packet_(void *ppkt,
				 struct io_plan (*cb)(struct io_conn *,
						      struct peer *),
				 struct peer *peer);

/* Frees pkt on next write! */
struct io_plan peer_write_packet(struct peer *peer, const void *pkt,
				 struct io_plan (*next)(struct io_conn *,
							struct peer *));

struct log;
void add_log_for_fd(int fd, struct log *log);
void del_log_for_fd(int fd, struct log *log);

#endif
