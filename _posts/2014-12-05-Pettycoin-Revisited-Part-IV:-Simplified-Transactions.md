---
layout: post
title: Pettycoin Revisited Part IV: Simplified Transactions
commentIssueId: 42
---
> This is the fourth in a series analyzing the pettycoin implementation
> against Gregory Maxwell's
> [writeup on scaling](https://en.bitcoin.it/wiki/User:Gmaxwell/features#Proofs).
> The first talked about
> [UTXO commitments vs backrefs](http://rustyrussell.github.io/pettycoin/2014/11/29/Pettycoin-Revisted-Part-I:-UTXO-Commitments.html),
> the second talked about [Propogation servers vs prev_txhashes](http://rustyrussell.github.io/pettycoin/2014/12/04/Pettycoin-Revisited-Part-II:-Proof-of-Propogation.html),
> and the third talked about [Hashed Fees vs Random Extrapolation](http://rustyrussell.github.io/pettycoin/2014/12/04/Pettycoin-Revisited-Part-III:-Miner-Rewards.html).

Each transaction has inputs and outputs.  An input is fully consumed
when used, so you need at least two outputs (one for change).
Obviously, you need more than one input if you want to combine funds to pay
someone.

## Pettycoin Solution ##

Pettycoin allows up to 4 inputs from a single address, which also
implies where the change output goes.  This is makes for a compact
representation:

	/* Which input are we spending? */
	struct protocol_input {
		/* This identifies the transaction. */
		struct protocol_tx_id input;
		/* This identifies the output.
		 * For normal transactions, 0 == send_amount, 1 = change */
		u16 output;
		u16 unused;
	};

	struct protocol_tx_normal {
		u8 version;
		u8 type; /* == TX_NORMAL */
		u8 features;
		/* change_amount goes back to this key. */
		struct protocol_pubkey input_key;
		/* send_amount goes to this address. */
		struct protocol_address output_addr;
		/* Amount to output_addr. */
		u32 send_amount;
		/* Amount to return to input_key. */
		u32 change_amount;
		/* Number of inputs to spend (<= PROTOCOL_TX_MAX_INPUTS) */
		u32 num_inputs;
		/* ECDSA of double SHA256 of above, and input[num_inputs] below. */
		struct protocol_signature signature;
		
		/* The inputs. */
		struct protocol_input input /* [s->num_inputs] */;
	};

The size of a 2-input transaction is 3 + 33 + 32 + 4 + 4 + 4 + 64 +
36*2 = 216 bytes.

This makes it easy to determine fees (since pettycoin uses a 0.3% fee)
as you can tell how much was change and how much was transferred.  It
also (with a canonical signature check) makes transactions non-malleable.

However, it has real disadvantages:

1. Privacy.  By forcing address use in this way, transactions are not
   private.  And you can't use a scheme like CoinJoin because there
   are no multiple different inputs.  Just because amounts are small
   doesn't *necessarily* imply they're non-sensitive.
2. The [sidechains](http://blockstream.com/sidechains.pdf) proposal
   will require sidechain transactions to be of some canonical
   (bitcoin-like!) form, so we'd have to change anyway.
3. The atomic-swap proposal which makes sidechains effective requires
   locktime, which is not present in this simplified transaction format.
4. If you want to be a sidechain, you have to understand bitcoin transactions
   (or, at least a subset) so you can spot transfers coming into the network.

## Bitcoin's Solution ##

Bitcoin's transactions are fully scriptable, though there are standard
forms for the scripts which are generally used.

	struct bitcoin_transaction {
		u32 version;
		varint_t input_count;
		struct bitcoin_transaction_input *input;
		varint_t output_count;
		struct bitcoin_transaction_output *output;
		u32 lock_time;
	};

	struct bitcoin_transaction_output {
		u64 amount;
		varint_t script_length;
		u8 *script;
	};

	struct bitcoin_transaction_input {
		u8 hash[32];
		u32 index; /* output number referred to by above */
		varint_t script_length;
		u8 *script;
		u32 sequence_number;
	};

A [typical output script](https://en.bitcoin.it/wiki/Script) is
`OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG` (25
bytes), and a
[typical output scriptsig](https://en.bitcoin.it/wiki/Script) is
`<sig> <pubkey>` (106 bytes), and a `varint` is 1-9 bytes (typically 1
byte here).  So a typical input would be 32 + 4 + 1 + 106 + 4 = 147
bytes, and the typical output 8 + 1 + 106 = 115 bytes.  With 10 bytes
for the transaction parts, that's 534 bytes.

There are several bad things about the bitcoin approach:

1. The scripting has enough non-uniformity, corner cases and
   weirdness that best practice is to use the reference
   implementation to interpret scripts.
2. [Transaction malleability](https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki) is a real problem, with different encodings possible for
   signatures, scripts and elsewhere.
3. As opcodes and patterns are
   "[reinterpreted](https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki)"
   for soft-forking upgrades, this problem gets worse.
4. Signatures are DER encoded (70/71 instead of 64 bytes) for no good
   reason, and keys can be either uncompressed (64) or compressed (33)
   bytes.  Pettycoin uses binary encoding for signatures and only
   compressed keys.

## Summary ##

The benefits of bitcoin transactions become very apparent if you have
to handle them anyway for sidechains.  And there's a middle ground
possible: use a strict subset of bitcoin scripting, with some limits
on transactions.  It would have required pettycoin to use a different
approach for fees (0.1% of total transferred might make sense, with
limits on numbers of inputs and outputs).

The factor-of-two reduction in size isn't worthwhile, given the
privacy implications.  And cleaning up the protocol slightly is nice,
but again, not worth the gratuitous incompatibility since we'd have to
handle both.
