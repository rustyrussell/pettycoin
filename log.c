#include "hex.h"
#include "log.h"
#include "pseudorand.h"
#include <ccan/list/list.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/tal/str/str.h>
#include <ccan/time/time.h>
#include <errno.h>
#include <stdio.h>

struct log_entry {
	struct list_node list;
	struct timeabs time;
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

void log_io(struct log *log, bool in, const void *data, size_t len)
{
	int save_errno = errno;
	struct log_entry *l = tal(log, struct log_entry);

	l->time = time_now();
	l->level = LOG_IO;
	l->skipped = 0;
	l->log = tal_arr(l, char, 1 + len);
	l->log[0] = in;
	memcpy(l->log + 1, data, len);

	if (LOG_IO >= log->print) {
		char *hex = to_hex(l, data, len);
		printf("%s[%s] %s\n", log->prefix, in ? "IN" : "OUT", hex);
		tal_free(hex);
	}
	add_entry(log, l);
	errno = save_errno;
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


void log_to_file(int fd, const struct log *log)
{
	const struct log_entry *i;
	char buf[100];
	struct timeabs prev;
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
	prev.ts.tv_nsec = 0;
	start = prev.ts.tv_sec;
	sprintf(buf, " %zu bytes, %s", log->mem_used, ctime(&start));
	write_all(fd, buf, strlen(buf));

	/* ctime includes \n... WTF? */
	prefix = "";

	list_for_each(&log->log, i, list) {
		struct timerel diff;

		if (i->skipped) {
			sprintf(buf, "%s... %u skipped...", prefix, i->skipped);
			write_all(fd, buf, strlen(buf));
			prefix = "\n";
		}
		diff = time_between(i->time, prev);

		sprintf(buf, "%s+%lu.%09u %s: ",
			prefix,
			(unsigned long)diff.ts.tv_sec,
			(unsigned)diff.ts.tv_nsec,
			i->level == LOG_IO ? (i->log[0] ? "IO-IN" : "IO-OUT")
			: i->level == LOG_DBG ? "DEBUG"
			: i->level == LOG_INFORM ? "INFO"
			: i->level == LOG_UNUSUAL ? "UNUSUAL"
			: i->level == LOG_BROKEN ? "BROKEN"
			: "**INVALID**");

		write_all(fd, buf, strlen(buf));
		if (i->level == LOG_IO) {
			size_t off, used, len = tal_count(i->log)-1;

			/* No allocations, may be in signal handler. */
			for (off = 0; off < len; off += used) {
				used = to_hex_direct(buf, sizeof(buf),
						     i->log + 1 + off,
						     len - off);
				write_all(fd, buf, strlen(buf));
			}
		} else {
			write_all(fd, i->log, strlen(i->log));
		}
		prefix = "\n";
	}
	write_all(fd, "\n\n", strlen("\n\n"));
}
