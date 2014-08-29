/* Terribly dumb wallet for testing. */
#include "addr.h"
#include "base58.h"
#include "create_tx.h"
#include "hex.h"
#include "json.h"
#include "marshal.h"
#include "pettycoin_dir.h"
#include <assert.h>
#include <ccan/err/err.h>
#include <ccan/opt/opt.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/str/str.h>
#include <ccan/structeq/structeq.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/str/str.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/obj_mac.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

/* Tal wrappers for opt. */
static void *opt_allocfn(size_t size)
{
	return tal_alloc_(NULL, size, false, TAL_LABEL("opt_allocfn", ""));
}

static void *tal_reallocfn(void *ptr, size_t size)
{
	if (!ptr)
		return opt_allocfn(size);
	tal_resize_(&ptr, 1, size, false);
	return ptr;
}

static void tal_freefn(void *ptr)
{
	tal_free(ptr);
}

static void create_wallet(const char *privkey)
{
	char *keystr;
	EC_KEY *priv;
	struct protocol_pubkey pubkey;
	struct protocol_address addr;
	unsigned char *p;
	int len, fd;

	if (privkey) {
		bool test_net;

		/* Check privkey decodes OK. */
		priv = key_from_base58(privkey, strlen(privkey),
				       &test_net, &pubkey);
		if (!priv)
			errx(1, "Invalid key '%s' (did you miss 'P-' ?)",
			     privkey);
		if (!test_net)
			errx(1, "Key '%s' is not for test net", privkey);

		/* We *always* used compressed form keys. */
		EC_KEY_set_conv_form(priv, POINT_CONVERSION_COMPRESSED);
	} else {
		priv = EC_KEY_new_by_curve_name(NID_secp256k1);
		if (!priv)
			errx(1, "OpenSSL in use misses support for secp256k1");
		if (EC_KEY_generate_key(priv) != 1)
			errx(1, "Could not generate key");
	}
	keystr = key_to_base58(NULL, true, priv, false);

	p = pubkey.key;
	len = i2o_ECPublicKey(priv, &p);
	assert(len == sizeof(pubkey));
	pubkey_to_addr(&pubkey, &addr);

	fd = open("dumbwallet.key", O_WRONLY|O_CREAT|O_EXCL, 0400);
	if (fd < 0)
		err(1, "creating dumbwallet.key");

	if (!write_all(fd, keystr, strlen(keystr)))
		err(1, "writing dumbwallet.key");
	fsync(fd);
	if (close(fd) != 0)
		err(1, "closing dumbwallet.key");

	printf("%s private key: your address is %s\n (or %s)\n",
	       privkey ? "Recorded" : "Create new", 
	       pettycoin_to_base58(keystr, true, &addr, false),
	       pettycoin_to_base58(keystr, true, &addr, true));

	exit(0);
}

struct utxo {
	struct protocol_tx_id txid;
	unsigned int confirms;
	unsigned int outnum;
	unsigned int amount;
};

static void add_utxo(struct utxo **utxos,
		     const char *resp,
		     const jsmntok_t *txid,
		     const jsmntok_t *confirms,
		     unsigned int outnum,
		     const jsmntok_t *amount)
{
	struct utxo *u;
	size_t num_utxo;
	unsigned int amt;

	if (!json_tok_number(resp, amount, &amt))
		errx(1, "Invalid amount (%.*s)",
		     json_tok_len(amount),
		     json_tok_contents(resp, amount));

	/* This can happen if there's no change. */
	if (amt == 0)
		return;

	num_utxo = tal_count(*utxos);
	tal_resize(utxos, num_utxo + 1);
	u = &(*utxos)[num_utxo];

	if (!from_hex(resp + txid->start, txid->end - txid->start,
		      &u->txid, sizeof(u->txid)))
		errx(1, "Invalid txid %.*s",
		     json_tok_len(txid),
		     json_tok_contents(resp, txid));
	u->outnum = outnum;
	u->amount = amt;
	if (!json_tok_number(resp, confirms, &u->confirms))
		errx(1, "Invalid confirmations (%.*s)",
		     json_tok_len(confirms),
		     json_tok_contents(resp, confirms));
}

static char *read_reply(const tal_t *ctx, int fd, jsmntok_t **toks)
{
	size_t off;
	int i;
	const jsmntok_t *error;
	char *resp = tal_arr(ctx, char, 100);
	
	off = 0;
	while ((i = read(fd, resp + off, tal_count(resp) - 1 - off)) > 0) {
		bool valid;
		off += i;
		if (off == tal_count(resp) - 1)
			tal_resize(&resp, tal_count(resp) * 2);

		*toks = json_parse_input(resp, off, &valid);
		if (*toks)
			break;
		if (!valid)
			errx(1, "Malformed response '%.*s'", (int)off, resp);
	}
	resp[off] = '\0';
	if (i < 0)
		err(1, "reading response");

	error = json_get_member(resp, *toks, "error");
	if (!error)
		errx(1, "Missing 'error' in response '%s'", resp);

	if (!json_tok_is_null(resp, error))
		errx(1, "listtransactions gave error %.*s",
		       json_tok_len(error),
		       json_tok_contents(resp, error));
	return resp;
}

static bool our_addr(const char *resp, const jsmntok_t *addrtok,
		     const struct protocol_address *addr)
{
	struct protocol_address a;
	bool test_net;

	if (!pettycoin_from_base58(&test_net, &a, resp + addrtok->start,
				   addrtok->end - addrtok->start))
		errx(1, "Expected address, not %.*s",
		     json_tok_len(addrtok),
		     json_tok_contents(resp, addrtok));

	if (!test_net)
		return false;

	return structeq(addr, &a);
}

static bool our_key(const char *resp, const jsmntok_t *keytok,
		    const struct protocol_pubkey *pubkey)
{
	struct protocol_pubkey k;

	if (!from_hex(resp + keytok->start, keytok->end - keytok->start,
		      &k, sizeof(k)))
		errx(1, "Expected pubkey, not %.*s",
		     json_tok_len(keytok),
		     json_tok_contents(resp, keytok));

	return structeq(pubkey, &k);
}

static struct utxo *get_utxo(const tal_t *ctx, int fd,
			     const struct protocol_pubkey *pubkey,
			     const struct protocol_address *addr)
{
	char *addrstr, *cmd, *resp;
	jsmntok_t *toks;
	const jsmntok_t *result, *tx, *end;
	struct utxo *utxos;

	addrstr = pettycoin_to_base58(ctx, true, addr, false);
	cmd = tal_fmt(ctx,
		      "{ \"method\" : \"listtransactions\", \"id\" : \"1\", \"params\" : [ \"%s\", 0 ] }",
		      addrstr);

	if (!write_all(fd, cmd, strlen(cmd)))
		err(1, "Writing command");

	resp = read_reply(ctx, fd, &toks);

	result = json_get_member(resp, toks, "result");
	if (!result)
		errx(1, "Missing 'result' in response '%s'", resp);

	if (result->type != JSMN_ARRAY)
		err(1, "Expected array result, not %.*s",
		       json_tok_len(result),
		       json_tok_contents(resp, result));

	utxos = tal_arr(ctx, struct utxo, 0);
	end = json_next(result);

	for (tx = result + 1; tx < end; tx = json_next(tx)) {
		const jsmntok_t *txid, *type, *confirms;

		txid = json_get_member(resp, tx, "txid");
		confirms = json_get_member(resp, tx, "confirmations");
		type = json_get_member(resp, tx, "type");

		if (!txid || !confirms || !type)
			errx(1, "Invalid tx returned %.*s",
			     json_tok_len(tx),
			     json_tok_contents(resp, tx));

		if (json_tok_streq(resp, type, "TX_NORMAL")) {
			const jsmntok_t *outaddr, *inpkey;

			/* Is this a payment to us? */
			outaddr = json_get_member(resp, tx, "output_addr");
			if (our_addr(resp, outaddr, addr))
				add_utxo(&utxos, resp,
					 txid, confirms, 0,
					 json_get_member(resp, tx,
							 "send_amount"));

			/* Is this a payment from us? */
			inpkey = json_get_member(resp, tx, "input_key");
			if (our_key(resp, inpkey, pubkey))
				add_utxo(&utxos, resp,
					 txid, confirms, 1,
					 json_get_member(resp, tx,
							 "change_amount"));
		} else if (json_tok_streq(resp, type, "TX_FROM_GATEWAY")) {
			const jsmntok_t *outputs, *out_end, *out, *outaddr;
			unsigned outnum;

			outputs = json_get_member(resp, tx, "vout");
			out_end = json_next(outputs);

			for (out = outputs + 1, outnum = 0;
			     out < out_end;
			     out = json_next(out), outnum++) {
				/* Is this a payment to us? */
				outaddr = json_get_member(resp, out,
							  "output_addr");
				if (our_addr(resp, outaddr, addr))
					add_utxo(&utxos, resp,
						 txid, confirms, outnum,
						 json_get_member(resp, out,
								 "send_amount"));
			}
		}
		/* FIXME: Other types. */
	}

	return utxos;
}

static void get_balance(const tal_t *ctx, int fd, 
			const struct protocol_pubkey *pubkey,
			const struct protocol_address *addr)
{
	struct utxo *utxos = get_utxo(ctx, fd, pubkey, addr);
	unsigned int i;
	unsigned int confirmed = 0, unconfirmed = 0;

	/* FIXME: This is wrong if we have unconfirmed expenditures! */
	for (i = 0; i < tal_count(utxos); i++) {
		if (utxos[i].confirms < 3)
			unconfirmed += utxos[i].amount;
		else
			confirmed += utxos[i].amount;
	}

	printf("%u.%02u bits", confirmed / 100, confirmed % 100);
	if (unconfirmed)
		printf(" (%u.%02u bits unconfirmed)",
		       unconfirmed / 100, unconfirmed % 100);
	printf("\n");
}

/* Amount is in bits (100 satoshi). */
static u32 get_amount(const char *amountstr)
{
	unsigned long amt;
	char *end;

	amt = strtol(amountstr, &end, 10);
	if (amt == ULONG_MAX && errno == ERANGE)
		err(1, "Invalid amount '%s'", amountstr);

	/* Catch huge overflows */
	if (amt >= PROTOCOL_MAX_SATOSHI / 100) 
		errx(1, "Amount '%s' too large", amountstr);

	amt *= 100;

	if (*end == '.') {
		unsigned long cents = strtol(end + 1, &end, 10);
		if (*end || cents > 100)
			errx(1, "Invalid amount '%s'", amountstr);

		amt += cents;
	} else if (*end != '\0')
		errx(1, "Invalid amount '%s'", amountstr);

	return amt;
}

static void send_normal(const tal_t *ctx, int fd, EC_KEY *key,
			const struct protocol_pubkey *pubkey,
			const struct protocol_address *addr,
			const char *destaddrstr, const char *amountstr)
{
	struct utxo *utxos;
	unsigned int i, num_in;
	int remaining, amount;
	struct utxo *in[PROTOCOL_TX_MAX_INPUTS];
	struct protocol_input inputs[PROTOCOL_TX_MAX_INPUTS];
	struct protocol_address destaddr;
	union protocol_tx *tx;
	const char *txstring, *cmd;
	bool test_net;
	jsmntok_t *toks;

	if (!pettycoin_from_base58(&test_net, &destaddr, destaddrstr,
				   strlen(destaddrstr)))
		errx(1, "Could not convert '%s' to address", destaddrstr);

	if (!test_net)
		errx(1, "'%s' is not a testnet address", destaddrstr);

	utxos = get_utxo(ctx, fd, pubkey, addr);
	/* Use the earliest ones which give us sufficient funds. */
	num_in = 0;
	remaining = amount = get_amount(amountstr);
	for (i = 0; i < tal_count(utxos) && remaining > 0; i++) {
		if (num_in == PROTOCOL_TX_MAX_INPUTS) {
			unsigned int n;

			/* Kick out a smaller one. */
			for (n = 0; n < PROTOCOL_TX_MAX_INPUTS; n++) {
				if (utxos[i].amount > in[n]->amount) {
					remaining += in[n]->amount;
					in[n] = &utxos[i];
					remaining -= in[n]->amount;
					break;
				}
			}
			/* FIXME: Needs two transactions. */
			if (n == PROTOCOL_TX_MAX_INPUTS)
				err(1, "Can't gather than many funds");
		} else {
			in[num_in++] = &utxos[i];
			remaining -= utxos[i].amount;
		}
	}

	/* Now turn those unspent tx outs into inputs. */
	for (i = 0; i < num_in; i++) {
		inputs[i].input = in[i]->txid;
		inputs[i].output = cpu_to_le16(in[i]->outnum);
		inputs[i].unused = cpu_to_le16(0);
	}

	/* FIXME: pay fee. */
	tx = create_normal_tx(ctx, &destaddr, amount, -remaining,
			      num_in, false, inputs, key);
	if (!tx)
		errx(1, "Could not create transaction");

	txstring = to_hex(ctx, tx, marshal_tx_len(tx));
	cmd = tal_fmt(ctx,
		      "{ \"method\" : \"sendrawtransaction\", \"id\" : \"1\", \"params\" : [ %s ] }",
		      txstring);

	if (!write_all(fd, cmd, strlen(cmd)))
		err(1, "Writing command");

	read_reply(ctx, fd, &toks);
}

static int rpc_fd(const char *rpc_filename)
{
	int fd;
	struct sockaddr_un addr;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (strlen(rpc_filename) + 1 > sizeof(addr.sun_path))
		errx(1, "rpc filename '%s' too long", rpc_filename);
	strcpy(addr.sun_path, rpc_filename);
	addr.sun_family = AF_UNIX;

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
		err(1, "Connecting to '%s'", rpc_filename);
	return fd;
}

int main(int argc, char *argv[])
{
	char *pettycoin_dir, *rpc_filename, *method;
	char *keystr;
	EC_KEY *key;
	struct protocol_pubkey pubkey;
	struct protocol_address addr;
	bool test_net;
	int fd;
	const tal_t *ctx = tal(NULL, char);

	err_set_progname(argv[0]);

	opt_set_alloc(opt_allocfn, tal_reallocfn, tal_freefn);
	pettycoin_dir_register_opts(ctx, &pettycoin_dir, &rpc_filename);

	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "setup [<privkey>] | balance | send <amount> <to>", "Show this message");
	opt_register_noarg("--version|-V", opt_version_and_exit, VERSION,
			   "Display version and exit");

	opt_early_parse(argc, argv, opt_log_stderr_exit);
	opt_parse(&argc, argv, opt_log_stderr_exit);

	method = argv[1];
	if (!method)
		errx(1, "Need at least one argument\n%s",
		     opt_usage(argv[0], NULL));

	if (chdir(pettycoin_dir) != 0)
		err(1, "Moving into '%s'", pettycoin_dir);

	keystr = grab_file(NULL, "dumbwallet.key");
	if (!keystr) {
		if (errno != ENOENT)
			err(1, "Reading dumbwallet.key");

		if (!streq(method, "setup"))
			errx(1, "Run setup first");

		create_wallet(argv[2]);
	}

	key = key_from_base58(keystr, strlen(keystr), &test_net, &pubkey);
	if (!key)
		errx(1, "Could not decode private key");

	if (!test_net)
		errx(1, "Private key was not for test net");

	pubkey_to_addr(&pubkey, &addr);

	fd = rpc_fd(rpc_filename);

	if (streq(argv[1], "balance"))
		get_balance(ctx, fd, &pubkey, &addr);
	else if (streq(argv[1], "send")) {
		if (argc != 4)
			errx(1, "Usage: send <addr> <amount>");
		send_normal(ctx, fd, key, &pubkey, &addr, argv[2], argv[3]);
	} else if (streq(argv[1], "setup")) {
		errx(1, "Setup already done: dumbwallet.key exists");
	} else
		errx(1, "Unknown command '%s'", argv[1]);

	tal_free(ctx);
	return 0;
}
