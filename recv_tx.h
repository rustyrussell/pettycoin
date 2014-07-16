#ifndef PETTYCOIN_RECV_TX_H
#define PETTYCOIN_RECV_TX_H
#include "config.h"

struct peer;
struct protocol_pkt_tx_in_block;
struct state;

enum protocol_ecode recv_tx_from_peer(struct peer *peer,
				const struct protocol_pkt_tx_in_block *pkt);

enum protocol_ecode recv_tx_from_blockfile(struct state *state,
				const struct protocol_pkt_tx_in_block *pkt);

#endif /* PETTYCOIN_RECV_TX_H */
