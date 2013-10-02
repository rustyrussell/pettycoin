PETTYCOIN_OBJS := block.o check_block.o check_transaction.o difficulty.o shadouble.o timestamp.o gateways.o hash_transaction.o pettycoin.o merkle_transactions.o create_transaction.o transaction_cmp.o genesis.o marshall.o hash_block.o prev_merkles.o create_proof.o state.o
GENERATE_OBJS := generate.o merkle_transactions.o hash_transaction.o transaction_cmp.o shadouble.o difficulty.o marshall.o
MKGENESIS_OBJS := mkgenesis.o shadouble.o marshall.o hash_block.o
SIZES_OBJS := sizes.o
CCAN_OBJS := ccan-asort.o ccan-breakpoint.o ccan-tal.o ccan-tal-path.o ccan-tal-str.o ccan-take.o ccan-list.o ccan-str.o ccan-opt-helpers.o ccan-opt.o ccan-opt-parse.o ccan-opt-usage.o ccan-read_write_all.o ccan-htable.o
CCANDIR=../ccan/
VERSION:=$(shell git describe --dirty --always 2>/dev/null || echo Unknown)
#CFLAGS = -O3 -flto -ggdb -I $(CCANDIR) -Wall -DVERSION=\"$(VERSION)\"
CFLAGS = -ggdb -I $(CCANDIR) -Wall -Wmissing-prototypes -DVERSION=\"$(VERSION)\"
LDFLAGS = -O3 -flto
LDLIBS := -lcrypto

# We set this low for convenient testing.
INITIAL_DIFFICULTY=0x1effffff

all: generate mkgenesis pettycoin sizes

generate: $(GENERATE_OBJS) $(CCAN_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(GENERATE_OBJS) $(CCAN_OBJS) $(LDLIBS)

mkgenesis: $(MKGENESIS_OBJS) $(CCAN_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(MKGENESIS_OBJS) $(CCAN_OBJS) $(LDLIBS)

pettycoin: $(PETTYCOIN_OBJS) $(CCAN_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(PETTYCOIN_OBJS) $(CCAN_OBJS) $(LDLIBS)

sizes: $(SIZES_OBJS) $(CCAN_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SIZES_OBJS) $(CCAN_OBJS) $(LDLIBS)

genesis.c: mkgenesis generate
	./mkgenesis 4 $(INITIAL_DIFFICULTY) "Some NYT Head" > $@

check:
	$(MAKE) -C test check

clean:
	$(RM) pettycoin generate mkgenesis sizes *.o
	$(MAKE) -C test clean

TAGS:
	etags *.[ch]

distclean: clean

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
ccan-htable.o: $(CCANDIR)/ccan/htable/htable.c
	$(CC) $(CFLAGS) -c -o $@ $<

