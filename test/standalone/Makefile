BINS := serve_addresses
CCANDIR := ../../../ccan/
CFLAGS := -MMD -ggdb -I $(CCANDIR) -Wall
LDLIBS := -lcrypto
CCAN_OBJS := ccan-io-io.o ccan-io-poll.o ccan-read_write_all.o ccan-io-io.o ccan-io-poll.o ccan-timer.o ccan-time.o ccan-list.o

default: $(BINS)
$(BINS:=.o) : %.o : %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(BINS) : $(CCAN_OBJS)

ccan-read_write_all.o: $(CCANDIR)/ccan/read_write_all/read_write_all.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-io-io.o: $(CCANDIR)/ccan/io/io.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-io-poll.o: $(CCANDIR)/ccan/io/poll.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-timer.o: $(CCANDIR)/ccan/timer/timer.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-time.o: $(CCANDIR)/ccan/time/time.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-list.o: $(CCANDIR)/ccan/list/list.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(BINS) *.o
