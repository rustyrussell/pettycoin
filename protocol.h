#ifndef PETTYCOIN_PROTOCOL_H
#define PETTYCOIN_PROTOCOL_H
#include <ccan/short_types/short_types.h>
#include <ccan/endian/endian.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>

/* How many transactions get merkled together */
#define PETTYCOIN_BATCH_ORDER		8

/* How many previous blocks do we record a merkle for? */
#define PETTYCOIN_PREV_BLOCK_MERKLES	10

/* How many shards for initial blocks == 1 << PROTOCOL_INITIAL_SHARD_ORDER */
#define PROTOCOL_INITIAL_SHARD_ORDER 2

/* Sanity checking, assume < 1 million shards. */
#define PROTOCOL_MAX_SHARD_ORDER 16

/* Maximum inputs in a single transaction. */
#define TRANSACTION_MAX_INPUTS 4

/* How long (seconds) until transactions are obsolete (30 days) */
#define TRANSACTION_HORIZON_SECS	(60 * 60 * 24 * 30)

/* How long between blocks (seconds) */
#define BLOCK_TARGET_TIME	600

/* How many blocks form a difficulty set (1 fortnight, a-la bitcoin) */
#define DIFFICULTY_UPDATE_BLOCKS	2016

/* How many blocks to join together to count features >= 75%. */
#define FEATURE_VOTE_BLOCKS	2016

/* How many blocks after feature vote to increment version number. */
#define FEATURE_CONFIRM_DELAY	2016

struct protocol_double_sha {
	u8 sha[SHA256_DIGEST_LENGTH /* 32 */ ];
};

/* An ECDSA compressed public key.  33 chars long, even on ARM. */
struct protocol_pubkey {
	u8 key[33];
} __attribute__((aligned(1)));

/* An address is the RIPEMD160 of the SHA of the 33-byte public key. */
struct protocol_address {
	u8 addr[RIPEMD160_DIGEST_LENGTH]; /* 20 */
};

/* ECDSA of double SHA256. */
struct protocol_signature {
	u8 r[32];
	u8 s[32];
};

/*
 * Chain is an series of blocks.
 *
 * Designed to be compatible with bitcoin mining hardware (at least,
 * the USB block adapters), which have a SHA midstate and the last 12 bytes
 * of the bitcoin block header (timestamp, difficulty, nonce).
 */
struct protocol_block_header {
	u8 version;
	u8 features_vote;
	u8 nonce2[14];
	struct protocol_double_sha prev_block;
	le32 num_transactions;
	le32 num_prev_merkles;
	le32 depth;
	struct protocol_address fees_to;
};

/* header is followed by array of double_shas which are the merkles of
 * each transaction + input_refs:
 *	num_merkles = (hdr->num_transactions + (1<<PETTYCOIN_BATCH_ORDER)-1)
 *			>> PETTYCOIN_BATCH_ORDER;
 *	struct protocol_double_sha merkle[num_merkles];
 *
 * Then the previous blocks's merkles hashed with fees_to, for each of
 * the PETTYCOIN_PREV_BLOCK_SIGN blocks:
 *	u8 prev_merkles[hdr->num_prev_merkles]
 *
 * Finally, the tailer:
 */
struct protocol_block_tailer {
	le32 timestamp;
	le32 difficulty;
	le32 nonce1;
};

/* This is how we hash the block:
 * Doesn't change:
 *	struct protocol_double_sha hash_of_prev_merkles;
 * Changes on transaction add:
 *	struct protocol_double_sha hash_of_merkles;
 * Changes on nonce2 increment:
 *	struct protocol_block_header hdr;
 * Changes on every nonce1 change:
 *	struct protocol_block_tailer tailer;
 */

enum protocol_transaction_type {
	/* Normal transfer. */
	TRANSACTION_NORMAL = 0,
	/* Gateway injecting funds from bitcoin network. */
	TRANSACTION_FROM_GATEWAY = 1,
	/* Doublespend penalty transaction? */
	/* Fee collection transaction? */
};

/* For use in the union */
struct protocol_transaction_hdr {
	u8 version;
	u8 type; /* == TRANSACTION_NORMAL || TRANSACTION_FROM_GATEWAY */
	u8 features;
};

/* Which input are we spending? */
struct protocol_input {
	/* This identifies the transaction. */
	struct protocol_double_sha input;
	/* This identifies the output.
	 * For normal transactions, 0 == send_amount, 1 = change */
	le16 output;
	le16 unused;
};

/* Core of a transaction */
struct protocol_transaction_normal {
	u8 version;
	u8 type; /* == TRANSACTION_NORMAL */
	u8 features;
	/* return_amount goes back to this key. */
	struct protocol_pubkey input_key;
	/* send_amount goes to this address. */
	struct protocol_address output_addr;
	/* Amount to output_addr. */
	le32 send_amount;
	/* Amount to return to input_key. */
	le32 change_amount;
	/* Number of inputs to spend (<= TRANSACTION_MAX_INPUTS) */
	le32 num_inputs;
	/* ECDSA of double SHA256 of above, and inputs[] below. */
	struct protocol_signature signature;
	/* The inputs */
	struct protocol_input input[ /* num_inputs */ ];
};

/* Inside a block, a normal transaction is followed by num_inputs of these: */
struct protocol_input_ref {
	le32 blocks_ago;
	le32 txnum;
};

/* From a gateway into the pettycoin network. */
struct protocol_gateway_payment {
	/* How much? */
	le32 send_amount;
	/* To where? */
	struct protocol_address output_addr;
};

struct protocol_transaction_gateway {
	u8 version;
	u8 type; /* == TRANSACTION_FROM_GATEWAY */
	u8 features;
	/* Key of the gateway crediting the funds. */
	struct protocol_pubkey gateway_key;
	/* Reward potential for this transaction. */
	le32 reward;
	/* Number of outputs we're sending. */
	le16 num_outputs;
	le16 unused;
	/* ECDSA of double SHA256 of above, and outputs[] below. */
	struct protocol_signature signature;
	struct protocol_gateway_payment output[ /* num_outputs */ ];
};

union protocol_transaction {
	struct protocol_transaction_hdr hdr;
	struct protocol_transaction_normal normal;
	struct protocol_transaction_gateway gateway;
};

/* Merkle proof, used to show tx (+ refs) is in a block. */
struct protocol_proof {
	struct protocol_double_sha merkle[PETTYCOIN_BATCH_ORDER];
};

/* Proof that a transaction (with inputs refs) was in a block. */
struct protocol_trans_with_proof {
	/* The block it's in. */
	struct protocol_double_sha block;
	/* Transaction number within the block. */
	le32 tnum;
	/* This is the tree of double shas which proves it. */
	struct protocol_proof proof;

	/* union protocol_transaction trans;
	   struct protocol_input_ref ref[num_inputs(trans)];
	*/
};

/* An amount, not a psuedonym! */
#define MAX_SATOSHI 0x7FFFFFFF
#endif /* PETTYCOIN_PROTOCOL_H */
