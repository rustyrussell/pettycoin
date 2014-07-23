LDLIBS := -lcrypto -lrt
CCAN_OBJS := ccan-read_write_all.o ccan-net.o ccan-err.o ccan-tal.o ccan-noerr.o ccan-take.o ccan-list.o ccan-io-io.o ccan-io-poll.o ccan-timer.o ccan-time.o
CCANDIR=../../ccan/
CFLAGS = -ggdb -I $(CCANDIR) -Wall -Wmissing-prototypes -DVERSION=\"$(VERSION)\" -fstack-protector
BINS = mkaddr serve_addresses

default: $(BINS)

mkaddr: mkaddr.o ../netaddr.o $(CCAN_OBJS)
serve_addresses: serve_addresses.o $(CCAN_OBJS)

clean:
	$(RM) $(BINS) *.o

ccan-read_write_all.o: $(CCANDIR)/ccan/read_write_all/read_write_all.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-net.o: $(CCANDIR)/ccan/net/net.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-err.o: $(CCANDIR)/ccan/err/err.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-tal.o: $(CCANDIR)/ccan/tal/tal.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-noerr.o: $(CCANDIR)/ccan/noerr/noerr.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-take.o: $(CCANDIR)/ccan/take/take.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-list.o: $(CCANDIR)/ccan/list/list.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-io-io.o: $(CCANDIR)/ccan/io/io.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-io-poll.o: $(CCANDIR)/ccan/io/poll.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-timer.o: $(CCANDIR)/ccan/timer/timer.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-time.o: $(CCANDIR)/ccan/time/time.c
	$(CC) $(CFLAGS) -c -o $@ $<
