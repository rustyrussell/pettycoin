#ifndef PETTYCOIN_LOG_H
#define PETTYCOIN_LOG_H
#include <ccan/tal/tal.h>
#include <stdarg.h>

/* 1MB logging per peer. */
#define PEER_LOG_MAX 1048576

/* 16 MB logging for core. */
#define STATE_LOG_MAX 16777216

/* 16 MB logging for generator(s). */
#define GEN_LOG_MAX 16777216

enum log_level {
	/* Gory details which are mainly good for debugging. */
	LOG_DBG,
	/* Information about what's going in. */
	LOG_INFORM,
	/* That's strange... */
	LOG_UNUSUAL,
	/* That's really bad, we're broken. */
	LOG_BROKEN
};

struct log *new_log(const tal_t *ctx, const char *prefix,
		    enum log_level printlevel, size_t max_mem);

#define log_debug(log, ...) log_((log), LOG_DBG, __VA_ARGS__)
#define log_info(log, ...) log_((log), LOG_INFORM, __VA_ARGS__)
#define log_unusual(log, ...) log_((log), LOG_UNUSUAL, __VA_ARGS__)
#define log_broken(log, ...) log_((log), LOG_BROKEN, __VA_ARGS__)

void log_(struct log *log, enum log_level level, const char *fmt, ...)
	PRINTF_FMT(3,4);
void log_add(struct log *log, const char *fmt, ...) PRINTF_FMT(2,3);
void logv(struct log *log, enum log_level level, const char *fmt, va_list ap);

#define log_add_struct(log, structtype, ptr)				\
	log_add_struct_((log), stringify(structtype),			\
		((void)sizeof((ptr) == (structtype *)NULL), (ptr)))

void log_add_struct_(struct log *log, const char *structname, const void *ptr);

void set_log_level(struct log *log, enum log_level level);
void log_to_file(int fd, const struct log *log);
#endif /* PETTYCOIN_LOG_H */
