PETTYCOIN_OBJS := block.o check_block.o check_tx.o difficulty.o shadouble.o timestamp.o gateways.o hash_tx.o pettycoin.o merkle_txs.o merkle_recurse.o tx_cmp.o genesis.o marshal.o hash_block.o prev_txhashes.o state.o tal_packet.o dns.o netaddr.o peer.o peer_cache.o pseudorand.o welcome.o log.o generating.o blockfile.o pending.o log_helper.o txhash.o signature.o proof.o chain.o features.o todo.o base58.o sync.o create_refs.o shard.o packet_io.o tx.o complain.o block_shard.o recv_block.o input_refs.o peer_wants.o inputhash.o tx_in_hashes.o merkle_hashes.o recv_tx.o reward.o recv_complain.o json.o jsonrpc.o getinfo.o ecode_names.o
GENERATE_OBJS := generate.o merkle_hashes.o merkle_recurse.o hash_tx.o tx_cmp.o shadouble.o marshal.o minimal_log.o timestamp.o tal_packet.o
MKGENESIS_OBJS := mkgenesis.o shadouble.o hash_block.o merkle_hashes.o merkle_recurse.o minimal_log.o
SIZES_OBJS := sizes.o
MKPRIV_OBJS := mkpriv.o
INJECT_OBJS := inject.o base58.o create_tx.o marshal.o netaddr.o hash_tx.o minimal_log.o shadouble.o signature.o hash_block.o merkle_recurse.o
PETTYCOIN_QUERY_OBJS := pettycoin_query.o json.o base58.o

BINS := generate mkgenesis pettycoin sizes mkpriv inject pettycoin_query
CCAN_OBJS := ccan-asort.o ccan-breakpoint.o ccan-tal.o ccan-tal-path.o ccan-tal-str.o ccan-take.o ccan-list.o ccan-str.o ccan-opt-helpers.o ccan-opt.o ccan-opt-parse.o ccan-opt-usage.o ccan-read_write_all.o ccan-htable.o ccan-io-io.o ccan-io-poll.o ccan-timer.o ccan-time.o ccan-noerr.o ccan-hash.o ccan-isaac64.o ccan-net.o ccan-err.o ccan-tal-grab_file.o
CCANDIR=../ccan/
VERSION:=$(shell git describe --dirty --always 2>/dev/null || echo Unknown)
#CFLAGS = -O3 -flto -ggdb -I $(CCANDIR) -Wall -DVERSION=\"$(VERSION)\"
CFLAGS = -ggdb -I $(CCANDIR) -Wall -Wmissing-prototypes -DVERSION=\"$(VERSION)\"
LDFLAGS = -O3 -flto
LDLIBS := -lcrypto -lrt

# We set this low for convenient testing.
TEST_GENESIS_DIFFICULTY=0x1effffff
TEST_GENESIS_TIMESTAMP=1404886369
TEST_GENESIS_NONCE=MarcusArabellAlex

all: $(BINS)

mkpriv: $(MKPRIV_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(MKPRIV_OBJS) $(LDLIBS)

inject: $(INJECT_OBJS) $(CCAN_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(INJECT_OBJS) $(CCAN_OBJS) $(LDLIBS)

generate: $(GENERATE_OBJS) $(CCAN_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(GENERATE_OBJS) $(CCAN_OBJS) $(LDLIBS)

mkgenesis: $(MKGENESIS_OBJS) $(CCAN_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(MKGENESIS_OBJS) $(CCAN_OBJS) $(LDLIBS)

pettycoin: $(PETTYCOIN_OBJS) $(CCAN_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(PETTYCOIN_OBJS) $(CCAN_OBJS) $(LDLIBS)

pettycoin_query: $(PETTYCOIN_QUERY_OBJS) $(CCAN_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(PETTYCOIN_QUERY_OBJS) $(CCAN_OBJS) $(LDLIBS)

sizes: $(SIZES_OBJS) $(CCAN_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SIZES_OBJS) $(CCAN_OBJS) $(LDLIBS)

genesis.c: mkgenesis
	./mkgenesis $(TEST_GENESIS_DIFFICULTY) $(TEST_GENESIS_TIMESTAMP) $(TEST_GENESIS_NONCE) > $@.tmp; STATUS=$$?; if [ $$STATUS = 0 ]; then mv $@.tmp $@; else rm -f $@.tmp; exit $$STATUS; fi

check: check-include-order
	$(MAKE) -C test check

ecode_names.c: protocol_ecode.h Makefile
	(echo '#include "ecode_names.h"'; echo 'struct ecode_names ecode_names[] = {'; sed -n 's/^\t\(PROTOCOL_ECODE_[A-Z_]*\)/\t{ \1, "\1" }/p' < $<; echo ' { 0, NULL } };') > $@

check-include-order:
	@for f in *.c; do if [ "$$(grep '^#include' < $$f)" != "$$(grep '^#include' < $$f | LANG=C sort)" ]; then echo "$$f:1: includes out of order"; exit 1; fi; done
	@for f in $$(grep -l '^#include' *.h); do if [ "$$(grep '^#include' < $$f | head -n1)" != '#include "config.h"' ]; then echo "$$f:1: doesn't include config.h first"; exit 1; fi; done
	@for f in $$(grep -l '^#include' *.h); do if [ "$$(grep '^#include' < $$f | tail -n +2)" != "$$(grep '^#include' < $$f | tail -n +2 | LANG=C sort)" ]; then echo "$$f:1: includes out of order"; fi; done

clean:
	$(RM) $(BINS) *.o
	$(MAKE) -C test clean

TAGS:
	etags *.[ch]

distclean: clean
	$(RM) genesis.c ecode_names.c

ccan-asort.o: $(CCANDIR)/ccan/asort/asort.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-breakpoint.o: $(CCANDIR)/ccan/breakpoint/breakpoint.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-tal.o: $(CCANDIR)/ccan/tal/tal.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-tal-path.o: $(CCANDIR)/ccan/tal/path/path.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-tal-str.o: $(CCANDIR)/ccan/tal/str/str.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-tal-grab_file.o: $(CCANDIR)/ccan/tal/grab_file/grab_file.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-take.o: $(CCANDIR)/ccan/take/take.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-list.o: $(CCANDIR)/ccan/list/list.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-read_write_all.o: $(CCANDIR)/ccan/read_write_all/read_write_all.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-str.o: $(CCANDIR)/ccan/str/str.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-opt.o: $(CCANDIR)/ccan/opt/opt.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-opt-helpers.o: $(CCANDIR)/ccan/opt/helpers.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-opt-parse.o: $(CCANDIR)/ccan/opt/parse.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-opt-usage.o: $(CCANDIR)/ccan/opt/usage.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-io-io.o: $(CCANDIR)/ccan/io/io.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-io-poll.o: $(CCANDIR)/ccan/io/poll.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-htable.o: $(CCANDIR)/ccan/htable/htable.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-time.o: $(CCANDIR)/ccan/time/time.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-timer.o: $(CCANDIR)/ccan/timer/timer.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-noerr.o: $(CCANDIR)/ccan/noerr/noerr.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-hash.o: $(CCANDIR)/ccan/hash/hash.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-isaac64.o: $(CCANDIR)/ccan/isaac/isaac64.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-net.o: $(CCANDIR)/ccan/net/net.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-err.o: $(CCANDIR)/ccan/err/err.c
	$(CC) $(CFLAGS) -c -o $@ $<

-include *.d
