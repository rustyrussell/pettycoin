#define THIS_TEST_MODULE "log"
#include <ccan/time/time.h>
#include <ccan/isaac/isaac64.h>
#include <ccan/err/err.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
static struct timespec my_time;

/* Prune everything! */
#define isaac64_next_uint(isaac64, n) ((n) - 1)
#define time_now(x) my_time
#include "../log.c"

int main(void)
{
	struct protocol_double_sha dsha;
	struct protocol_net_address netaddr;
	int fds[2];

	const char expect1_template[] = "PREFIX %zu bytes, Sun Nov 10 16:57:35 2013\n"
		"+0.000000500 DEBUG: This is a debug message!\n"
		"+0.000000501 INFO: This is an info message!\n"
		"+0.000000502 UNUSUAL: This is an unusual message!\n"
		"+0.000000503 BROKEN: This is a broken message!the sha is ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff and the address is: ::ffff:127.0.0.1:65000\n\n";
	char expect1[sizeof(expect1_template)+1]; /* given %zu + 1 character - i.e. should be safe to assume sizeof <= 9999 */
	const char expect2_template[] = "PREFIX %zu bytes, Sun Nov 10 16:57:35 2013\n"
		"... 4 skipped...\n"
		"+0.000000504 DEBUG: Overflow!\n"
		"+0.000000504 DEBUG: Log pruned 4 entries (mem %zu -> %zu)\n\n";
	char expect2[sizeof(expect2_template)+1];
	char *p;
	int status;
	size_t expectBytes;
	struct log *log = NULL;

	log_test_start();

	/* 25 - length of text after DEBUG: incl \n */
	/* 25 - length of text after INFO: incl \n */
	/* 28 - length of text after UNUSUAL: incl \n */
	/* 144 - length of text after BROKEN: incl \n */
	/* sizeof(struct log_entry) varies E 32,64-bit */
	/* memory use is { sizeof(log_entry) + length(string) + 1} x N */
	/* TODO: improve how the above string is generated so we dont need these hard-coded magic numbers here */
	expectBytes = sizeof(struct log_entry) * 4 + 25 + 25 + 28 + 144;
	snprintf( expect1, sizeof(expect1), expect1_template, expectBytes);
	/* 10 - length of text after DEBUG: overflow \n */
	/* 37 - length of text after DEBUG: pruned \n */
	/* Interestingly, the pruning mechanism is not a hard cap... we can exceed the max size passed to new_log(), the pruning happens after the next entry is added to the tail... */
	snprintf( expect2, sizeof(expect2), expect2_template, sizeof(struct log_entry) * 2 + 10 + 37, expectBytes + sizeof(struct log_entry) + 10,  sizeof(struct log_entry) + 10); 

	log = new_log(NULL, "PREFIX", LOG_BROKEN+1, expectBytes);

	log_test( "basic logging operations...\n");

	my_time.tv_sec = 1384064855;
	my_time.tv_nsec = 500;

	log_debug(log, "This is a debug %s!", "message");
	my_time.tv_nsec++;
	log_info(log, "This is an info %s!", "message");
	my_time.tv_nsec++;
	log_unusual(log, "This is an unusual %s!", "message");
	my_time.tv_nsec++;
	log_broken(log, "This is a broken %s!", "message");
	my_time.tv_nsec++;

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
	netaddr.port = cpu_to_be16(65000);
	log_add_struct(log, struct protocol_net_address, &netaddr);

	log_test( "forking write...\n");

	/* Make child write log, be sure it's correct. */
	pipe(fds);
	switch (fork()) {
	case -1:
		err(1, "forking");
	case 0:
		close(fds[0]);
		log_to_file(fds[1], log);
		exit(0);
	}

	close(fds[1]);

	log_test( "forking read...\n");


	p = malloc(strlen(expect1) + 1);
	if (!read_all(fds[0], p, strlen(expect1)))
		err(1, "Reading log dump from child");
	if (read(fds[0], p, 1) != 0)
		errx(1, "Extra in log dump from child");
	close(fds[0]);

	p[strlen(expect1)] = '\0';
	/* When the next assertion would fail, we really need to print some extra info... */
	if (!streq(expect1, p)) {
		fprintf(stderr, "We expected something different from the following:\n'%s'\n", p);
		assert(streq(expect1, p));
	}
	wait(&status);
	assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);

	log_test( "overflow...\n");

	/* This cleans us out! */
	log_debug(log, "Overflow!");
	
	/* Make child write log, be sure it's correct. */
	pipe(fds);
	switch (fork()) {
	case -1:
		err(1, "forking");
	case 0:
		close(fds[0]);
		log_to_file(fds[1], log);
		exit(0);
	}

	close(fds[1]);

	if (!read_all(fds[0], p, strlen(expect2)))
		err(1, "Reading log dump from child");
	if (read(fds[0], p, 1) != 0)
		errx(1, "Extra in log dump from child");
	close(fds[0]);

	p[strlen(expect2)] = '\0';
	if (!streq(expect2, p)) {
		fprintf(stderr, "We expected something different from the following:\n'%s'\n", p);
		assert(streq(expect2, p));
	}
	wait(&status);
	assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);

	log_test( "finish...\n");

	free(p);
	log_test_finish();
	return 0;
}
