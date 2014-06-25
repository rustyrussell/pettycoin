SOURCES := $(wildcard run-*.c)
HELPERS := $(wildcard helper*.c)
BINS := $(SOURCES:.c=)
CCANDIR := ../../ccan/
CFLAGS := -MMD -ggdb -I $(CCANDIR) -Wall -DFASTCHECK
LDLIBS := -lcrypto -lrt
CCAN_OBJS := ccan-noerr.o ccan-tal.o ccan-take.o ccan-list.o ccan-read_write_all.o ccan-htable.o ccan-isaac64.o ccan-tal-str.o ccan-str.o ccan-time.o
HELPER_OBJS := $(HELPERS:.c=.o)

# Can't use --leack-check, as openssl leaks?
VALGRIND=valgrind -q --error-exitcode=99 # --track-origins=yes --leak-check=full --show-reachable=yes

check: $(BINS)
	set -e; for b in $(BINS); do printf "[TEST] %-48s" $$b ; $(VALGRIND) ./$$b; echo OK ; done

bins: $(BINS)

$(BINS:=.o) : %.o : %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(BINS) : $(HELPER_OBJS) $(CCAN_OBJS)

ccan-noerr.o: $(CCANDIR)/ccan/noerr/noerr.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-tal.o: $(CCANDIR)/ccan/tal/tal.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-take.o: $(CCANDIR)/ccan/take/take.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-list.o: $(CCANDIR)/ccan/list/list.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-read_write_all.o: $(CCANDIR)/ccan/read_write_all/read_write_all.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-htable.o: $(CCANDIR)/ccan/htable/htable.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-str.o: $(CCANDIR)/ccan/str/str.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-tal-str.o: $(CCANDIR)/ccan/tal/str/str.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-isaac64.o: $(CCANDIR)/ccan/isaac/isaac64.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-time.o: $(CCANDIR)/ccan/time/time.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(BINS) *.o *.d

.PHONY:
	bins

-include *.d
