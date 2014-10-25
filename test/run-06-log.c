#include <ccan/tal/tal.h>
#include <ccan/tal/str/str.h>
#include <ccan/time/time.h>
#include <ccan/isaac/isaac64.h>
#include <ccan/err/err.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
static struct timeabs my_time;

/* Prune everything! */
#define isaac64_next_uint(isaac64, n) ((n) - 1)
#define time_now() my_time
#include "../log.c"
#include "../log_helper.c"
#include "../ecode_names.c"
#include "../base58.c"
#include "../marshal.c"
#include "../pkt_names.c"
#include "../shadouble.c"

/* AUTOGENERATED MOCKS START */
/* Generated stub for hash_tx */
void hash_tx(const union protocol_tx *tx, struct protocol_tx_id *txid)
{ fprintf(stderr, "hash_tx called!\n"); abort(); }
/* Generated stub for to_hex */
char *to_hex(const tal_t *ctx, const void *buf, size_t bufsize)
{ fprintf(stderr, "to_hex called!\n"); abort(); }
/* Generated stub for to_hex_direct */
size_t to_hex_direct(char *dest, size_t destlen,
		     const void *buf, size_t bufsize)
{ fprintf(stderr, "to_hex_direct called!\n"); abort(); }
/* AUTOGENERATED MOCKS END */

static char *read_from(const tal_t *ctx, int fd)
{
	size_t max = 128, done = 0;
	int r;
	char *p = tal_arr(ctx, char, max);

	while ((r = read(fd, p + done, max - done)) > 0) {
		done += r;
		if (done == max)
			tal_resize(&p, max *= 2);
	}
	tal_resize(&p, done + 1);
	p[done] = '\0';

	return p;
}

int main(void)
{
	struct protocol_double_sha dsha;
	struct protocol_net_address netaddr;
	int fds[2];
	char *p, *mem1, *mem2, *mem3;
	int status;
	size_t maxmem = sizeof(struct log_entry) * 4 + 25 + 25 + 28 + 161;
	void *ctx = tal(NULL, char);
	struct log_record *lr;
	struct log *log;

	my_time.ts.tv_sec = 1384064855;
	my_time.ts.tv_nsec = 500;

	lr = new_log_record(ctx, maxmem, LOG_BROKEN+1);
	log = new_log(ctx, lr, "PREFIX:");
	assert(tal_parent(log) == ctx);

	log_debug(log, "This is a debug %s!", "message");
	my_time.ts.tv_nsec++;
	log_info(log, "This is an info %s!", "message");
	my_time.ts.tv_nsec++;
	log_unusual(log, "This is an unusual %s!", "message");
	my_time.ts.tv_nsec++;
	log_broken(log, "This is a broken %s!", "message");
	my_time.ts.tv_nsec++;

	log_add(log, "the sha is ");
	memset(&dsha, 0xFF, sizeof(dsha));
	log_add_struct(log, struct protocol_double_sha, &dsha);

	log_add(log, " and the address is: ");
	memset(netaddr.addr, 0, 10);
	memset(netaddr.addr + 10, 0xFF, 2);
	netaddr.addr[12] = 127;
	netaddr.addr[13] = 0;
	netaddr.addr[14] = 0;
	netaddr.addr[15] = 1;
	netaddr.port = cpu_to_le16(65000);
	netaddr.time = time_now().ts.tv_sec - 10;
	log_add_struct(log, struct protocol_net_address, &netaddr);

	/* Make child write log, be sure it's correct. */
	pipe(fds);
	switch (fork()) {
	case -1:
		err(1, "forking");
	case 0:
		close(fds[0]);
		setenv("TZ", "UTC", 1);
		log_to_file(fds[1], lr);
		tal_free(ctx);
		exit(0);
	}

	close(fds[1]);
	p = read_from(ctx, fds[0]);
	/* Shouldn't contain any NUL chars */
	assert(strlen(p) + 1 == tal_count(p));

	assert(tal_strreg(p, p,
			  "([0-9])* bytes, Sun Nov 10 06:27:35 2013\n"
			  "\\+0\\.000000000 PREFIX:DEBUG: This is a debug message!\n"
			  "\\+0\\.000000001 PREFIX:INFO: This is an info message!\n"
			  "\\+0\\.000000002 PREFIX:UNUSUAL: This is an unusual message!\n"
			  "\\+0\\.000000003 PREFIX:BROKEN: This is a broken message!the sha is ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff and the address is: ::ffff:127\\.0\\.0\\.1:65000 \\(10 seconds old\\)\n\n", &mem1));
	assert(atoi(mem1) < maxmem);
	tal_free(p);

	wait(&status);
	assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);

	/* This cleans us out! */
	log_debug(log, "Overflow!");
	
	/* Make child write log, be sure it's correct. */
	pipe(fds);
	switch (fork()) {
	case -1:
		err(1, "forking");
	case 0:
		close(fds[0]);
		setenv("TZ", "UTC", 1);
		log_to_file(fds[1], lr);
		tal_free(ctx);
		exit(0);
	}

	close(fds[1]);

	p = read_from(ctx, fds[0]);
	/* Shouldn't contain any NUL chars */
	assert(strlen(p) + 1 == tal_count(p));

	assert(tal_strreg(p, p,
			  "([0-9]*) bytes, Sun Nov 10 06:27:35 2013\n"
			  "\\.\\.\\. 4 skipped\\.\\.\\.\n"
			  "\\+0.000000004 PREFIX:DEBUG: Overflow!\n"
			  "\\+0.000000004 PREFIX:DEBUG: Log pruned 4 entries \\(mem ([0-9]*) -> ([0-9]*)\\)\n\n", &mem1, &mem2, &mem3));
	assert(atoi(mem1) < maxmem);
	assert(atoi(mem2) >= maxmem);
	assert(atoi(mem3) < maxmem);
	tal_free(ctx);
	wait(&status);
	assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	return 0;
}
