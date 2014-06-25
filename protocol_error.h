#ifndef PETTYCOIN_PROTOCOL_ERROR_H
#define PETTYCOIN_PROTOCOL_ERROR_H

enum protocol_error {
	PROTOCOL_ERROR_NONE, /* happy camper. */
	/* General errors: */
	PROTOCOL_ERROR_UNKNOWN_COMMAND,
	/* FIXME: Rename to PROTOCOL_ERROR_INVALID_LEN */
	PROTOCOL_INVALID_LEN,
	PROTOCOL_ERROR_SHOULD_BE_WAITING,
	/* You filled in an error field in a packet with something unexpected */
	PROTOCOL_ERROR_UNKNOWN_ERRCODE,

	/* protocol_pkt_welcome: */
	PROTOCOL_ERROR_HIGH_VERSION, /* version is unknown. */
	PROTOCOL_ERROR_LOW_VERSION, /* version is old. */
	PROTOCOL_ERROR_NO_INTEREST, /* not enough interest bits. */
	PROTOCOL_ERROR_WRONG_GENESIS, /* your inital block is wrong. */

	/* protocol_pkt_welcome or protocol_pkt_block */
	PROTOCOL_ERROR_BAD_SHARD_ORDER, /* shard_order is wrong. */

	/* protocol_pkt_sync: */
	PROTOCOL_ERROR_NO_MUTUAL, /* I didn't know any of your blocks. */

	/* protocol_set_filter: */
	PROTOCOL_ERROR_FILTER_INVALID, /* 0 filter bits or bad offset */

	/* protocol_pkt_block
	   protocol_pkt_get_tx_in_block
	   protocol_pkt_get_shard
	   protocol_pkt_get_txmap
	   protocol_pkt_get_syncblock
	*/
	PROTOCOL_ERROR_UNKNOWN_BLOCK,

	/* protocol_pkt_get_shard */
	PROTOCOL_ERROR_UNKNOWN_SHARD,

	/* protocol_pkt_get_tx / protocol_pkt_get_tx_in_block */
	PROTOCOL_ERROR_UNKNOWN_TX,

	/* protocol_pkt_get_tx_in_block */
	PROTOCOL_ERROR_BAD_TXPOS,

	/* protocol_pkt_get_shard / protocol_pkt_shard */
	PROTOCOL_ERROR_BAD_SHARDNUM,

	/* protocol_pkt_block */
	PROTOCOL_ERROR_BLOCK_HIGH_VERSION, /* block version unknown. */
	PROTOCOL_ERROR_BLOCK_LOW_VERSION, /* block version is old. */
	PROTOCOL_ERROR_BAD_TIMESTAMP, /* Too far in future or past. */
	PROTOCOL_ERROR_BAD_PREV_MERKLES, /* Wrong number of prev_merkles. */
	PROTOCOL_ERROR_BAD_DIFFICULTY, /* Wrong difficulty calculation. */
	PROTOCOL_ERROR_INSUFFICIENT_WORK, /* Didn't meet difficulty. */
	PROTOCOL_ERROR_BAD_DEPTH, /* Wasn't prev + 1. */

	/* protocol_pkt_tx / protocol_pkt_tx_in_block */
	PROTOCOL_ERROR_TRANS_HIGH_VERSION, /* transaction version unknown */
	PROTOCOL_ERROR_TRANS_LOW_VERSION, /* transaction version old */
	PROTOCOL_ERROR_TRANS_UNKNOWN, /* unknown transaction type */
	PROTOCOL_ERROR_TRANS_BAD_GATEWAY, /* unknown gateway */
	PROTOCOL_ERROR_TRANS_CROSS_SHARDS, /* to different shards. */
	PROTOCOL_ERROR_TOO_LARGE, /* too many satoshi in one transaction. */
	PROTOCOL_ERROR_TRANS_BAD_SIG, /* invalid signature */
	PROTOCOL_ERROR_TOO_MANY_INPUTS, /* > TRANSACTION_MAX_INPUTS. */

	/* protocol_pkt_tx_in_block */
	PROTOCOL_ERROR_BLOCK_BAD_TX_SHARD, /* TX was in wrong shard in block */

	/* protocol_pkt_shard */
	PROTOCOL_ERROR_BAD_MERKLE,

	/* >= this is invalid. */
	PROTOCOL_ERROR_MAX,

	/* Internal error codes. */
	PROTOCOL_ERROR_PRIV_UNKNOWN_PREV, /* I don't know previous block. */
	PROTOCOL_ERROR_PRIV_TRANS_BAD_INPUT, /* an input is bad. */
	PROTOCOL_ERROR_PRIV_TRANS_BAD_AMOUNTS, /* total inputs != outputs  */
	/* These two only occur within a block: */
	PROTOCOL_ERROR_PRIV_BLOCK_BAD_INPUT_REF, /* input_ref is bad */
	PROTOCOL_ERROR_PRIV_BLOCK_BAD_INPUT_REF_TRANS, /* input_ref points to bad trans */
};

#endif /* PETTYCOIN_PROTOCOL_ERROR_H */
