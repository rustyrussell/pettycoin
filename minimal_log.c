#include "log.h"
#include <stdio.h>

/* Just log errors to stderr. */
void log_(struct log *log, enum log_level level, const char *fmt, ...)
{
	va_list ap;

	if (level == LOG_DBG)
		return;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}
