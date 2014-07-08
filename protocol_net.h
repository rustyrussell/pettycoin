#ifndef PETTYCOIN_PROTOCOL_NET_H
#define PETTYCOIN_PROTOCOL_NET_H
#include "protocol.h"
#include "protocol_ecode.h"

#define PROTOCOL_MAX_PACKET_LEN (4 * 1024 * 1024)

/* Every packet starts with these two. */
struct protocol_net_hdr {
	le32 len; /* size including header */
	le32 type; /* PROTOCOL_PKT_* */
};

struct protocol_net_address {
	u8 addr[16];
	be16 port;
}  __attribute__((aligned(2)));

enum protocol_pkt_type {
	/* Invalid. */
	PROTOCOL_PKT_NONE,
	/* Something went wrong, go away. */
	PROTOCOL_PKT_ERR,
	/* Hi, my version is, and my hobbies are... */
	PROTOCOL_PKT_WELCOME,
	/* EITHER: These blocks should get you up to the horizon. */
	PROTOCOL_PKT_HORIZON,
	/* OR: Here's a rough topology of the blocks we both know. */
	PROTOCOL_PKT_SYNC,
	/* Please tell me about this block's children. */
	PROTOCOL_PKT_GET_CHILDREN,
	/* Here's info about this block's children (response to above). */
	PROTOCOL_PKT_CHILDREN,
	/* Please tell me about this block */
	PROTOCOL_PKT_GET_BLOCK,
	/* Response to the above */
	PROTOCOL_PKT_UNKNOWN_BLOCK,
	/* Here's a block (may be response to GET_BLOCK, or spontaneous) */
	PROTOCOL_PKT_BLOCK,
	/* Please tell me about this shard */
	PROTOCOL_PKT_GET_SHARD,
	/* Here's a shard (response to above) */
	PROTOCOL_PKT_SHARD,
	/* Please give me a TX. */
	PROTOCOL_PKT_GET_TX,
	/* Here's a transaction. */
	PROTOCOL_PKT_TX,
	/* Please give me the TX (w/refs) in this block. */
	PROTOCOL_PKT_GET_TX_IN_BLOCK,
	/* Here's a transaction (w/refs) in a block. */
	PROTOCOL_PKT_TX_IN_BLOCK,
	/* Please tell me what transactions I should know about. */
	PROTOCOL_PKT_GET_TXMAP,
	/* Which transactions you should know about (response to above) */
	PROTOCOL_PKT_TXMAP,

	/* Start sending me transactions and new blocks, filtered like this. */
	PROTOCOL_PKT_SET_FILTER,

	/* Various complaints about a TX. */
	PROTOCOL_PKT_TX_BAD_INPUT,
	PROTOCOL_PKT_TX_BAD_AMOUNT,

	/* Various complaints about a block. */
	PROTOCOL_PKT_BLOCK_TX_MISORDER,
	PROTOCOL_PKT_BLOCK_TX_INVALID,
	PROTOCOL_PKT_BLOCK_TX_BAD_INPUT,
	PROTOCOL_PKT_BLOCK_BAD_INPUT_REF,
	PROTOCOL_PKT_BLOCK_TX_BAD_AMOUNT,

	/* This is used to pad a packet. */
	PROTOCOL_PKT_PIGGYBACK,

	/* >= this is invalid. */
	PROTOCOL_PKT_MAX,

	/* Used for saving to disk. */
	PROTOCOL_PKT_PRIV_FULLSHARD,
};

struct protocol_pkt_welcome {
	le32 len; /* sizeof(struct protocol_pkt_welcome) */
	le32 type; /* PROTOCOL_PKT_WELCOME */
	le32 version; /* Protocol version, currently 1. */
	/* Freeform software version. */
	char moniker[28];
	/* Self-detection */
	le64 random;
	/* Address we see you at. */
	struct protocol_net_address you;
	/* Port you can connect to us at (if != 0) */
	be16 listen_port;
	/* How many block hashes at end. */
	le16 num_blocks;
	/* Our shard_order. */
	u8 shard_order;
	/* Pad to 32 bits */
	u8 unused;
	/* Followed by:
	   What addresses we're interested in (based on lower bits)
	     u8 interests[(num_shards + 31) / 32 * 4];
	   Blocks we know about: 10, then power of 2 back.
	     struct protocol_double_sha block[num_blocks];
	*/
};

/* If you're behind the horizon, this gets you there quickly. */
struct protocol_pkt_horizon {
	le32 len; /* sizeof(struct protocol_pkt_horizon) ... */
	le32 type; /* PROTOCOL_PKT_HORIZON */

	/* marshaled blocks, backwards from horizon to mutual, skipping. */
};

struct protocol_net_syncblock {
	/* Hash of block. */
	struct protocol_double_sha block;
	/* How many children up to the next block */
	le32 children;
};

/* If you're beyond horizon, you get summary of blocks (backwards). */
struct protocol_pkt_sync {
	le32 len; /* sizeof(struct protocol_pkt_sync) ... */
	le32 type; /* PROTOCOL_PKT_SYNC */

	/* struct protocol_net_syncblock [] */
};

/* Tell me about the direct children of this block. */
struct protocol_pkt_get_children {
	le32 len; /* sizeof(struct protocol_pkt_get_children) */
	le32 type; /* PROTOCOL_PKT_GET_CHILDREN */

	struct protocol_double_sha block;
};

/* I'm too lazy to count children, but it's more than 0 */
#define PROTOCOL_PKT_CHILDREN_SOME	0xffffffff

/* Here are the direct children of this block. */
struct protocol_pkt_children {
	le32 len; /* sizeof(struct protocol_pkt_children) ... */
	le32 type; /* PROTOCOL_PKT_CHILDREN */

	struct protocol_double_sha block;
	le32 err; /* PROTOCOL_ECODE_NONE or PROTOCOL_ERROR_UNKNOWN_BLOCK */
	/* struct protocol_net_syncblock [] */
};

/* Once we set filter, we get told about transactions. */
struct protocol_pkt_set_filter {
	le32 len; /* sizeof(struct protocol_pkt_set_filter) */
	le32 type; /* PROTOCOL_PKT_SET_FILTER */

	/* We divide into 64 groups, this it a bitmap of which to send */
	le64 filter;
	/* For transactions, this says which byte of hash to filter (0-19). */
	le64 offset;
};

struct protocol_pkt_block {
	le32 len; /* sizeof(struct protocol_pkt_block) + ... */
	le32 type; /* PROTOCOL_PKT_BLOCK */

	/* Marshaled block */
};

/* This block contains an invalid transaction. */
struct protocol_pkt_block_tx_invalid {
	le32 len; /* sizeof(struct protocol_req_block_tx_invalid) */
	le32 type; /* PROTOCOL_REQ_BLOCK_TX_INVALID */

	/* What is wrong with it, one of:
	 *  PROTOCOL_ECODE_TX_HIGH_VERSION
	 *  PROTOCOL_ECODE_TX_LOW_VERSION
	 *  PROTOCOL_ECODE_TX_UNKNOWN
	 *  PROTOCOL_ECODE_TX_BAD_GATEWAY
	 *  PROTOCOL_ECODE_TX_CROSS_SHARDS
	 *  PROTOCOL_ECODE_TX_TOO_LARGE
	 *  PROTOCOL_ECODE_TX_BAD_SIG
	 *  PROTOCOL_ECODE_TX_TOO_MANY_INPUTS
	 *  PROTOCOL_ECODE_SHARD_BAD_INPUT_REF
	 */
	le32 error;

	/*
	  struct protocol_trans_with_proof proof;
	*/
};

/* This block contains an transaction with an invalid input,
 * ie PROTOCOL_ECODE_PRIV_BLOCK_BAD_INPUT_REF. */
struct protocol_pkt_block_tx_bad_input {
	le32 len; /* sizeof(struct protocol_req_block_tx_bad_input) */
	le32 type; /* PROTOCOL_REQ_BLOCK_TX_BAD_INPUT */

	/* Input I am referring to. */
	le32 inputnum;

	/*
	  struct protocol_tx_with_proof proof;
	  union protocol_tx input;
	*/
};

/* This block contains an input ref with an invalid input (wrong trans!)
 * ie PROTOCOL_ECODE_PRIV_BLOCK_BAD_INPUT_REF_TX. */
struct protocol_pkt_block_bad_input_ref {
	le32 len; /* sizeof(struct protocol_pkt_block_bad_input_ref) */
	le32 type; /* PROTOCOL_PKT_BLOCK_BAD_INPUT_REF */

	/* Input of transaction I am referring to. */
	le32 inputnum;

	/*
	  struct protocol_tx_with_proof tx;
	  struct protocol_tx_with_proof input;
	*/
};

/* This block contains an transaction with an invalid total,
 * ie PROTOCOL_ECODE_TRANS_BAD_AMOUNTS. */
struct protocol_pkt_block_tx_bad_amount {
	le32 len; /* sizeof(struct protocol_req_block_tx_bad_amount) */
	le32 type; /* PROTOCOL_REQ_BLOCK_TX_BAD_AMOUNT */

	/*
	  struct protocol_trans_with_proof proof;
	  The inputs:
	     union protocol_tx input[t->normal.num_inputs];
	*/
};

struct protocol_net_txrefhash {
	struct protocol_double_sha txhash;
	struct protocol_double_sha refhash;
};

struct protocol_pkt_shard {
	le32 len; /* sizeof(struct protocol_pkt_shard) */
	le32 type; /* PROTOCOL_PKT_SHARD */

	struct protocol_double_sha block;
	le16 shard;
	le16 err; /* May be PROTOCOL_ECODE_UNKNOWN_BLOCK or
		     PROTOCOL_ECODE_UNKNOWN_SHARD */

	/* Only if !err:
	   struct protocol_net_txrefhash hash[block->shard_nums[shard]];
	*/
};

struct protocol_pkt_tx_in_block {
	le32 len; /* sizeof(struct protocol_pkt_tx_in_block) + ... */
	le32 type; /* PROTOCOL_PKT_TX_IN_BLOCK */

	le32 err; /* PROTOCOL_ECODE_UNKNOWN_BLOCK,
		   * PROTOCOL_ECODE_UNKNOWN_TX,
		   * or PROTOCOL_ECODE_NONE */

	/* struct protocol_tx_with_proof, or if ecode, just
	 * struct protocol_position. */
};

/* This block contains out-of-order transaction. */
struct protocol_pkt_block_tx_misorder {
	le32 len; /* sizeof(struct protocol_pkt_block_tx_misorder) */
	le32 type; /* PROTOCOL_PKT_BLOCK_TX_MISORDER */

	/* These must refer to the same block!
	  struct protocol_trans_with_proof proof1;
	  struct protocol_trans_with_proof proof2;
	*/
};

struct protocol_pkt_tx {
	le32 len; /* sizeof(struct protocol_pkt_tx) + ... */
	le32 type; /* PROTOCOL_PKT_TX */

	/* marshaled transaction */
};

/* When we've discovered a tx input is bad. */
struct protocol_pkt_tx_bad_input {
	le32 len; /* sizeof(struct protocol_pkt_tx_bad_input) */
	le32 type; /* PROTOCOL_PKT_TX_BAD_INPUT */

	/* The input we're complaining about. */
	le32 inputnum;

	/* The transaction whose input was bad:
	     union protocol_tx trans ...; 
	   The bad input:
	     union protocol_tx input ...;
	*/
};

/* When we've discovered tx inputs don't add up. */
struct protocol_pkt_tx_bad_amount {
	le32 len; /* sizeof(struct protocol_pkt_tx_bad_amount) */
	le32 type; /* PROTOCOL_PKT_TX_BAD_AMOUNT */


	/* The transaction whose input was bad:
	     union protocol_tx trans ...; 
	  The inputs:
	     union protocol_tx input[t->normal.num_inputs];
	*/
};

/* Ask for a specific block (reply will be PROTOCOL_PKT_BLOCK). */
struct protocol_pkt_get_block {
	le32 len; /* sizeof(struct protocol_pkt_get_block) */
	le32 type; /* PROTOCOL_PKT_GET_BLOCK */

	struct protocol_double_sha block;
};

struct protocol_pkt_unknown_block {
	le32 len; /* sizeof(struct protocol_pkt_unknown_block) */
	le32 type; /* PROTOCOL_PKT_UNKNOWN_BLOCK */

	struct protocol_double_sha block;
};


/* Ask for a specific transaction (reply will be PROTOCOL_PKT_TX). */
struct protocol_pkt_get_tx {
	le32 len; /* sizeof(struct protocol_pkt_tx) */
	le32 type; /* PROTOCOL_PKT_GET_TX */

	struct protocol_double_sha tx;
};

/* Ask for a specific block pos (reply will be PROTOCOL_PKT_TX_IN_BLOCK). */
struct protocol_pkt_get_tx_in_block {
	le32 len; /* sizeof(struct protocol_pkt_get_tx_in_block) */
	le32 type; /* PROTOCOL_PKT_GET_TX_IN_BLOCK */

	struct protocol_position pos;
};

/* Ask for a specific shard (reply will be PROTOCOL_PKT_SHARD). */
struct protocol_pkt_get_shard {
	le32 len; /* sizeof(struct protocol_pkt_get_shard) */
	le32 type; /* PROTOCOL_PKT_GET_SHARD */

	struct protocol_double_sha block;
	le16 shard;
	le16 unused;
};

/* For syncing: what transactions should we know about? */
struct protocol_pkt_get_txmap {
	le32 len; /* sizeof(struct protocol_pkt_get_txmap) */
	le32 type; /* PROTOCOL_PKT_GET_TXMAP */

	le16 shard;
	le16 unused;
};

/* For syncing: what transactions should we know about. */
struct protocol_pkt_txmap {
	le32 len; /* sizeof(struct protocol_pkt_get_txmap) */
	le32 type; /* PROTOCOL_PKT_GET_TXMAP */

	struct protocol_double_sha block;
	le16 shard;
	le16 unused;

	/* Each set bit is a TX you want:
	   u8 txmap[(block->shard_nums[shard] + 31) / 32 * 4];
	*/
};

/* Followed by struct protocol_double_sha of block. */
#define PROTOCOL_PKT_PIGGYBACK_NEWBLOCK 1
/* Followed by struct protocol_double_sha of block then le16 shard number. */
#define PROTOCOL_PKT_PIGGYBACK_NEWSHARD 2
/* Followed by struct protocol_double_sha of tx, block then le16 shard
 * and u8 txoff. */
#define PROTOCOL_PKT_PIGGYBACK_TX_IN_BLOCK 3
/* Followed by struct protocol_double_sha of tx. */
#define PROTOCOL_PKT_PIGGYBACK_TX 4

/* This is used to pad packet: information we don't get due to filter. */
struct protocol_pkt_piggyback {
	le32 len; /* sizeof(struct protocol_pkt_piggyback) + ... */
	le32 type; /* PROTOCOL_PKT_PIGGYBACK */

	/* Followed by a series of PROTOCOL_PKT_PIGGYBACK*... */
};

/* Can be a response to any protocol_req_* */
struct protocol_pkt_err {
	le32 len; /* sizeof(struct protocol_pkt_err) */
	le32 type; /* PROTOCOL_PKT_ERR */
	le32 error; /* enum protocol_ecode */
};
#endif /* PETTYCOIN_PROTOCOL_NET_H */
