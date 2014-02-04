#include "log.h"
#include "pseudorand.h"
#include "protocol.h"
#include "protocol_net.h"
#include "hash_transaction.h"
#include <ccan/list/list.h>
#include <ccan/time/time.h>
#include <ccan/tal/str/str.h>
#include <ccan/read_write_all/read_write_all.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <openssl/bn.h>

struct log_entry {
	struct list_node list;
	struct timespec time;
	enum log_level level;
	unsigned int skipped;
	char *log;
};

struct log {
	size_t mem_used;
	size_t max_mem;
	const char *prefix;
	enum log_level print;

	struct list_head log;
};

static void prune_log(struct log *log)
{
	struct log_entry *i, *next, *tail;
	size_t skipped = 0, old_mem = log->mem_used, deleted = 0;

	/* Never delete the last one. */
	tail = list_tail(&log->log, struct log_entry, list);

	list_for_each_safe(&log->log, i, next, list) {
		/* 50% chance of deleting debug, 25% inform, 12.5% unusual. */
		if (i == tail || !isaac64_next_uint(isaac64, 2 << i->level)) {
			i->skipped += skipped;
			skipped = 0;
			continue;
		}

		list_del_from(&log->log, &i->list);
		log->mem_used -= sizeof(*i) + strlen(i->log) + 1;
		tal_free(i);
		skipped++;
		deleted++;
	}

	assert(!skipped);
	log_debug(log, "Log pruned %zu entries (mem %zu -> %zu)",
		  deleted, old_mem, log->mem_used);
}

struct log *new_log(const tal_t *ctx,
		    const struct log *parent,
		    const char *prefix,
		    enum log_level printlevel, size_t max_mem)
{
	struct log *log = tal(ctx, struct log);
	log->mem_used = 0;
	log->max_mem = max_mem;
	if (parent)
		log->prefix = tal_fmt(log, "%s:%s", parent->prefix, prefix);
	else
		log->prefix = tal_strdup(log, prefix);
	log->print = printlevel;
	list_head_init(&log->log);

	return log;
}

void set_log_level(struct log *log, enum log_level level)
{
	log->print = level;
}

void set_log_prefix(struct log *log, const char *prefix)
{
	log->prefix = prefix;
}

static void add_entry(struct log *log, struct log_entry *l)
{
	log->mem_used += sizeof(*l) + strlen(l->log) + 1;
	list_add_tail(&log->log, &l->list);

	if (log->mem_used > log->max_mem)
		prune_log(log);
}

void logv(struct log *log, enum log_level level, const char *fmt, va_list ap)
{
	struct log_entry *l = tal(log, struct log_entry);

	l->time = time_now();
	l->level = level;
	l->skipped = 0;
	l->log = tal_vfmt(l, fmt, ap);

	if (level >= log->print)
		printf("%s %s\n", log->prefix, l->log);

	add_entry(log, l);
}

static void do_log_add(struct log *log, const char *fmt, va_list ap)
{
	struct log_entry *l = list_tail(&log->log, struct log_entry, list);
	size_t oldlen = strlen(l->log);

	/* Remove from list, so it doesn't get pruned. */
	log->mem_used -= sizeof(*l) + oldlen + 1;
	list_del_from(&log->log, &l->list);

	tal_append_vfmt(&l->log, fmt, ap);
	add_entry(log, l);

	if (l->level >= log->print)
		printf("%s \t%s\n", log->prefix, l->log + oldlen);
}

void log_(struct log *log, enum log_level level, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	logv(log, level, fmt, ap);
	va_end(ap);
}

void log_add(struct log *log, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	do_log_add(log, fmt, ap);
	va_end(ap);
}

void log_add_struct_(struct log *log, const char *structname, const void *ptr)
{
	if (streq(structname, "struct protocol_double_sha")) {
		const struct protocol_double_sha *s = ptr;
		log_add(log,
			"%02x%02x%02x%02x%02x%02x%02x%02x"
			"%02x%02x%02x%02x%02x%02x%02x%02x"
			"%02x%02x%02x%02x%02x%02x%02x%02x"
			"%02x%02x%02x%02x%02x%02x%02x%02x",
			s->sha[0], s->sha[1], s->sha[2], s->sha[3],
			s->sha[4], s->sha[5], s->sha[6], s->sha[7],
			s->sha[8], s->sha[9], s->sha[10], s->sha[11],
			s->sha[12], s->sha[13], s->sha[14], s->sha[15],
			s->sha[16], s->sha[17], s->sha[18], s->sha[19],
			s->sha[20], s->sha[21], s->sha[22], s->sha[23],
			s->sha[24], s->sha[25], s->sha[26], s->sha[27],
			s->sha[28], s->sha[29], s->sha[30], s->sha[31]);
	} else if (streq(structname, "struct protocol_net_address")) {
		const struct protocol_net_address *addr = ptr;
		char str[INET6_ADDRSTRLEN];

		if (inet_ntop(AF_INET6, addr->addr, str, sizeof(str)) == NULL)
			log_add(log, "Unconvertable IPv6 (%s)",
				strerror(errno));
		else
			log_add(log, "%s", str);
		log_add(log, ":%u", be16_to_cpu(addr->port));
	} else if (streq(structname, "union protocol_transaction")) {
		const union protocol_transaction *t = ptr;
		struct protocol_double_sha sha;

		hash_transaction(t, NULL, 0, &sha);
		switch (t->hdr.type) {
		case TRANSACTION_NORMAL:
			log_add(log, "NORMAL %u inputs => %u (%u change) ",
				le32_to_cpu(t->normal.num_inputs),
				le32_to_cpu(t->normal.send_amount),
				le32_to_cpu(t->normal.change_amount));
			break;
		case TRANSACTION_FROM_GATEWAY:
			log_add(log, "GATEWAY %u outputs ",
				le32_to_cpu(t->gateway.num_outputs));
			break;
		default:
			log_add(log, "UNKNOWN(%u) ", t->hdr.type);
			break;
		}
		log_add_struct(log, struct protocol_double_sha, &sha);
	} else if (streq(structname, "BIGNUM")) {
		char *str = BN_bn2hex(ptr);
		log_add(log, "%s", str);
		OPENSSL_free(str);
	} else
		abort();
}

void log_to_file(int fd, const struct log *log)
{
	const struct log_entry *i;
	char buf[100];
	struct timespec prev;
	time_t start;
	const char *prefix;

	write_all(fd, log->prefix, strlen(log->prefix));

	i = list_top(&log->log, const struct log_entry, list);
	if (!i) {
		write_all(fd, "0 bytes:\n\n", strlen("0 bytes:\n\n"));
		return;
	}

	/* ctime only does seconds, so start log from 0ns past the second. */
	prev = i->time;
	prev.tv_nsec = 0;
	start = prev.tv_sec;
	sprintf(buf, " %zu bytes, %s", log->mem_used, ctime(&start));
	write_all(fd, buf, strlen(buf));

	/* ctime includes \n... WTF? */
	prefix = "";

	list_for_each(&log->log, i, list) {
		struct timespec diff;

		if (i->skipped) {
			sprintf(buf, "%s... %u skipped...", prefix, i->skipped);
			write_all(fd, buf, strlen(buf));
			prefix = "\n";
		}
		diff = time_sub(i->time, prev);
		sprintf(buf, "%s+%lu.%09u %s: ",
			prefix,
			(unsigned long)diff.tv_sec, (unsigned)diff.tv_nsec,
			i->level == LOG_DBG ? "DEBUG"
			: i->level == LOG_INFORM ? "INFO"
			: i->level == LOG_UNUSUAL ? "UNUSUAL"
			: i->level == LOG_BROKEN ? "BROKEN"
			: "**INVALID**");
		write_all(fd, buf, strlen(buf));
		write_all(fd, i->log, strlen(i->log));
		prefix = "\n";
	}
	write_all(fd, "\n\n", strlen("\n\n"));
}			
