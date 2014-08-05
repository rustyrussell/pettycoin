LDLIBS := -lcrypto -lrt
CCAN_OBJS := ccan-read_write_all.o ccan-net.o ccan-err.o ccan-tal.o ccan-noerr.o ccan-take.o ccan-list.o
CCANDIR=../../ccan/
CFLAGS = -ggdb -O3 -I $(CCANDIR) -Wall -Wmissing-prototypes -DVERSION=\"$(VERSION)\" -fstack-protector
BINS = make-peer-packet spv-blocks

default: $(BINS)

make-peer-packet: make-peer-packet.o ../netaddr.o ../tal_packet.o ../marshal.o ../minimal_log.o $(CCAN_OBJS)

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
