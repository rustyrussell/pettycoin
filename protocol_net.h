/*
 * This file defines the requirements of the pettycoin network
 * protocol.  It is licensed under CC0, to allow anyone to create
 * interoperable programs with minimal hassle.  See
 * CC0-for-protocol-headers.
 *
 * Author: Rusty Russell <rusty@rustcorp.com.au>
 */
#ifndef PETTYCOIN_PROTOCOL_NET_H
#define PETTYCOIN_PROTOCOL_NET_H
#include "config.h"
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
	/* Here's a pair of hashes in a block (with proof). */
	PROTOCOL_PKT_HASHES_IN_BLOCK,
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
	PROTOCOL_PKT_TX_DOUBLESPEND,

	/* Various complaints about a block. */
	PROTOCOL_PKT_COMPLAIN_TX_MISORDER,
	PROTOCOL_PKT_COMPLAIN_TX_INVALID,
	PROTOCOL_PKT_COMPLAIN_TX_BAD_INPUT,
	PROTOCOL_PKT_COMPLAIN_DOUBLESPEND,
	PROTOCOL_PKT_COMPLAIN_BAD_INPUT_REF,
	PROTOCOL_PKT_COMPLAIN_TX_BAD_AMOUNT,

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
	le32 err; /* PROTOCOL_ECODE_NONE or PROTOCOL_ECODE_UNKNOWN_BLOCK */
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

	le32 err; /* PROTOCOL_ECODE_NONE or PROTOCOL_ECODE_UNKNOWN_BLOCK */

	/* If PROTOCOL_ECODE_NONE: Marshaled block
	 * If PROTOCOL_ECODE_UNKNOWN_BLOCK: SHA of block. */
};

struct protocol_pkt_shard {
	le32 len; /* sizeof(struct protocol_pkt_shard) */
	le32 type; /* PROTOCOL_PKT_SHARD */

	struct protocol_double_sha block;
	le16 shard;
	le16 err; /* May be PROTOCOL_ECODE_UNKNOWN_BLOCK or
		     PROTOCOL_ECODE_UNKNOWN_SHARD */

	/* Only if !err:
	   struct protocol_txrefhash hash[block->shard_nums[shard]];
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

struct protocol_pkt_tx {
	le32 len; /* sizeof(struct protocol_pkt_tx) + ... */
	le32 type; /* PROTOCOL_PKT_TX */

	le32 err; /* PROTOCOL_ECODE_NONE or PROTOCOL_ECODE_UNKNOWN_TX */

	/* if PROTOCOL_ECODE_NONE: marshaled transaction
	 * if PROTOCOL_ECODE_UNKNOWN_TX: double sha of transaction.
	 */
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

/* When we've discovered a tx input was spent by another tx. */
struct protocol_pkt_tx_doublespend {
	le32 len; /* sizeof(struct protocol_pkt_tx_bad_input) */
	le32 type; /* PROTOCOL_PKT_TX_BAD_INPUT */

	/* The inputs we're complaining about. */
	le32 input1, input2;

	/* The transactions which use the same input:
	     union protocol_tx t1 ...; 
	     union protocol_tx t2 ...;
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

struct protocol_pkt_hashes_in_block {
	le32 len; /* sizeof(struct protocol_pkt_hashes_in_block) */
	le32 type; /* PROTOCOL_PKT_HASHES_IN_BLOCK */

	struct protocol_hashes_with_proof hproof;
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


/* Ask for a specific transaction (reply will be PROTOCOL_PKT_TX
 * or PROTOCOL_PKT_TX_IN_BLOCK). */
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

/* What transactions should we know about outside our normal shards? */
struct protocol_pkt_get_txmap {
	le32 len; /* sizeof(struct protocol_pkt_get_txmap) */
	le32 type; /* PROTOCOL_PKT_GET_TXMAP */

	struct protocol_double_sha block;
	le16 shard;
	le16 unused;
};

/* What transactions should we know about outside normal shards. */
struct protocol_pkt_txmap {
	le32 len; /* sizeof(struct protocol_pkt_get_txmap) */
	le32 type; /* PROTOCOL_PKT_GET_TXMAP */

	struct protocol_double_sha block;
	le16 shard;

	le16 err; /* PROTOCOL_ECODE_NONE, or PROTOCOL_ECODE_UNKNOWN_BLOCK */

	/* If err == PROTOCOL_ECODE_NONE, each set bit is a TX you want:
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

/* This block contains an invalid transaction. */
struct protocol_pkt_complain_tx_invalid {
	le32 len; /* sizeof(struct protocol_pkt_complain_tx_invalid) + ... */
	le32 type; /* PROTOCOL_PKT_COMPLAIN_TX_INVALID */

	/* What is wrong with it, one of:
	 *  PROTOCOL_ECODE_INVALID_LEN
	 *  PROTOCOL_ECODE_TX_HIGH_VERSION
	 *  PROTOCOL_ECODE_TX_LOW_VERSION
	 *  PROTOCOL_ECODE_TX_TYPE_UNKNOWN
	 *  PROTOCOL_ECODE_TX_BAD_GATEWAY
	 *  PROTOCOL_ECODE_TX_CROSS_SHARDS
	 *  PROTOCOL_ECODE_TX_TOO_LARGE
	 *  PROTOCOL_ECODE_TX_BAD_SIG
	 *  PROTOCOL_ECODE_TX_TOO_MANY_INPUTS
	 */
	le32 error;

	/* It may not be unmarshallable (PROTOCOL_ECODE_TX_HIGH_VERSION
	 * or PROTOCOL_ECODE_TX_TYPE_UNKNOWN), so explicitly say how big */
	le32 txlen;

	/*
	  struct protocol_tx_with_proof proof;
	*/
};

/* This block contains an transaction with an invalid input. */
struct protocol_pkt_complain_tx_bad_input {
	le32 len; /* sizeof(struct protocol_pkt_complain_tx_bad_input) + ...*/
	le32 type; /* PROTOCOL_PKT_COMPLAIN_TX_BAD_INPUT */

	/* Input I am referring to. */
	le32 inputnum;

	/*
	  struct protocol_tx_with_proof proof;
	  union protocol_tx input;
	*/
};

/* This block contains an input ref with an invalid input (wrong trans!) */
struct protocol_pkt_complain_bad_input_ref {
	le32 len; /* sizeof(struct protocol_pkt_complain_bad_input_ref) + ... */
	le32 type; /* PROTOCOL_PKT_COMPLAIN_BAD_INPUT_REF */

	/* Input of transaction I am referring to. */
	le32 inputnum;

	/*
	  struct protocol_tx_with_proof tx;
	  struct protocol_tx_with_proof input;
	  FIXME: Only need the proof of input hash, not actual tx.
	*/
};

/* This block contains an transaction with an invalid total. */
struct protocol_pkt_complain_tx_bad_amount {
	le32 len; /* sizeof(struct protocol_pkt_complain_tx_bad_amount) + ... */
	le32 type; /* PROTOCOL_PKT_COMPLAIN_TX_BAD_AMOUNT */

	/*
	  struct protocol_tx_with_proof proof;
	  The inputs:
	     union protocol_tx input[t->normal.num_inputs];
	*/
};

/*
 * These blocks contains two transactions which spend the same input.
 * The earlier block is invalid.
 */
struct protocol_pkt_complain_doublespend {
	le32 len; /* sizeof(struct protocol_pkt_complain_doublespend) + ... */
	le32 type; /* PROTOCOL_PKT_COMPLAIN_DOUBLESPEND */

	/* The two inputs which conflict. */
	le32 input1, input2;

	/*
	  struct protocol_trans_with_proof proof1;
	  struct protocol_trans_with_proof proof2;
	*/
};


/* This block contains out-of-order transaction. */
struct protocol_pkt_complain_tx_misorder {
	le32 len; /* sizeof(struct protocol_pkt_complain_tx_misorder) */
	le32 type; /* PROTOCOL_PKT_COMPLAIN_TX_MISORDER */

	/* These must refer to the same block!
	  struct protocol_tx_with_proof proof1;
	  struct protocol_tx_with_proof proof2;
	*/
};

/* Can be a response to any protocol_pkt_* */
struct protocol_pkt_err {
	le32 len; /* sizeof(struct protocol_pkt_err) */
	le32 type; /* PROTOCOL_PKT_ERR */
	le32 error; /* enum protocol_ecode */
};
#endif /* PETTYCOIN_PROTOCOL_NET_H */
