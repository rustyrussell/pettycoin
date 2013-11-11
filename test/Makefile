SOURCES := $(wildcard run-*.c)
HELPERS := $(wildcard helper*.c)
BINS := $(SOURCES:.c=)
CCANDIR := ../../ccan/
CFLAGS := -MMD -ggdb -I $(CCANDIR) -Wall -DFASTCHECK
LDLIBS := -lcrypto
CCAN_OBJS := ccan-noerr.o ccan-tal.o ccan-take.o ccan-list.o ccan-read_write_all.o ccan-htable.o ccan-isaac64.o
HELPER_OBJS := $(HELPERS:.c=.o)

# Can't use --leack-check, as openssl leaks?
VALGRIND=valgrind -q --error-exitcode=99 # --leak-check=full --show-reachable=yes 

check: $(BINS)
	set -e; for b in $(BINS); do $(VALGRIND) ./$$b; done

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
ccan-isaac64.o: $(CCANDIR)/ccan/isaac/isaac64.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(BINS) *.o
