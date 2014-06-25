/* Just enough standalone logging for utils and testing. */
#include "log.h"
#include <stdio.h>

static enum log_level last_level = LOG_DBG;

/* Just log errors to stderr. */
void log_(struct log *log, enum log_level level, const char *fmt, ...)
{
	va_list ap;

	if (last_level != LOG_DBG)
		fprintf(last_level == LOG_INFORM ? stdout : stderr, "\n");
	last_level = level;

	if (level == LOG_DBG)
		return;

	va_start(ap, fmt);
	vfprintf(level == LOG_INFORM ? stdout : stderr, fmt, ap);
	va_end(ap);
}

void log_add(struct log *log, const char *fmt, ...)
{
	va_list ap;

	if (last_level == LOG_DBG)
		return;

	va_start(ap, fmt);
	vfprintf(last_level == LOG_INFORM ? stdout : stderr, fmt, ap);
	va_end(ap);
}

void log_add_struct_(struct log *log, const char *structname, const void *ptr)
{
	log_add(log, "%s", structname);
}

void log_add_enum_(struct log *log, const char *enumname, unsigned int val)
{
	log_add(log, "%s(%u) ", enumname, val);
}
	
