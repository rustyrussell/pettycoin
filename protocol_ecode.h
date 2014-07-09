#ifndef PETTYCOIN_PROTOCOL_ECODE_H
#define PETTYCOIN_PROTOCOL_ECODE_H

enum protocol_ecode {
	PROTOCOL_ECODE_NONE, /* happy camper. */
	/* General errors: */
	PROTOCOL_ECODE_UNKNOWN_COMMAND,
	PROTOCOL_ECODE_INVALID_LEN,
	PROTOCOL_ECODE_SHOULD_BE_WAITING,
	/* You filled in an error field in a packet with something unexpected */
	PROTOCOL_ECODE_UNKNOWN_ERRCODE,

	/* protocol_pkt_welcome: */
	PROTOCOL_ECODE_HIGH_VERSION, /* version is unknown. */
	PROTOCOL_ECODE_LOW_VERSION, /* version is old. */
	PROTOCOL_ECODE_NO_INTEREST, /* not enough interest bits. */
	PROTOCOL_ECODE_WRONG_GENESIS, /* your inital block is wrong. */

	/* protocol_pkt_welcome or protocol_pkt_block */
	PROTOCOL_ECODE_BAD_SHARD_ORDER, /* shard_order is wrong. */

	/* protocol_pkt_sync: */
	PROTOCOL_ECODE_NO_MUTUAL, /* I didn't know any of your blocks. */

	/* protocol_set_filter: */
	PROTOCOL_ECODE_FILTER_INVALID, /* 0 filter bits or bad offset */

	/* protocol_pkt_block
	   protocol_pkt_get_tx_in_block
	   protocol_pkt_get_shard
	   protocol_pkt_get_txmap
	   protocol_pkt_get_syncblock
	*/
	PROTOCOL_ECODE_UNKNOWN_BLOCK,

	/* protocol_pkt_get_shard */
	PROTOCOL_ECODE_UNKNOWN_SHARD,

	/* protocol_pkt_get_tx / protocol_pkt_get_tx_in_block */
	PROTOCOL_ECODE_UNKNOWN_TX,

	/* protocol_pkt_get_tx_in_block */
	PROTOCOL_ECODE_BAD_TXOFF,

	/* protocol_pkt_get_shard / protocol_pkt_shard */
	PROTOCOL_ECODE_BAD_SHARDNUM,

	/* protocol_pkt_block */
	PROTOCOL_ECODE_BLOCK_HIGH_VERSION, /* block version unknown. */
	PROTOCOL_ECODE_BLOCK_LOW_VERSION, /* block version is old. */
	PROTOCOL_ECODE_BAD_TIMESTAMP, /* Too far in future or past. */
	PROTOCOL_ECODE_BAD_PREV_TXHASHES, /* Wrong number of prev_txhashes. */
	PROTOCOL_ECODE_BAD_DIFFICULTY, /* Wrong difficulty calculation. */
	PROTOCOL_ECODE_INSUFFICIENT_WORK, /* Didn't meet difficulty. */
	PROTOCOL_ECODE_BAD_DEPTH, /* Wasn't prev + 1. */

	/* protocol_pkt_tx / protocol_pkt_tx_in_block */
	PROTOCOL_ECODE_TX_HIGH_VERSION, /* transaction version unknown */
	PROTOCOL_ECODE_TX_LOW_VERSION, /* transaction version old */
	PROTOCOL_ECODE_TX_UNKNOWN, /* unknown transaction type */
	PROTOCOL_ECODE_TX_BAD_GATEWAY, /* unknown gateway */
	PROTOCOL_ECODE_TX_CROSS_SHARDS, /* to different shards. */
	PROTOCOL_ECODE_TX_TOO_LARGE, /* too many satoshi in one transaction. */
	PROTOCOL_ECODE_TX_BAD_SIG, /* invalid signature */
	PROTOCOL_ECODE_TX_TOO_MANY_INPUTS, /* > TX_MAX_INPUTS. */

	/* protocol_pkt_tx_in_block */
	PROTOCOL_ECODE_BAD_PROOF, /* your proof was bad. */
	PROTOCOL_ECODE_REF_BAD_BLOCKS_AGO, /* ref->blocks_ago too long ago */
	PROTOCOL_ECODE_REF_BAD_SHARD, /* ref->shard too large. */
	PROTOCOL_ECODE_REF_BAD_TXOFF, /* ref->txoff too large. */

	/* protocol_pkt_shard */
	PROTOCOL_ECODE_BAD_MERKLE,

	/* >= this is invalid. */
	PROTOCOL_ECODE_MAX,

	/* Internal error codes. */
	PROTOCOL_ECODE_PRIV_UNKNOWN_PREV, /* I don't know previous block. */
};

#endif /* PETTYCOIN_PROTOCOL_ECODE_H */
