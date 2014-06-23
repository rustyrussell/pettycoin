#include <ccan/asort/asort.h>
#include <ccan/array_size/array_size.h>
#include <time.h>
#include "timestamp.h"
#include "state.h"
#include "block.h"

/* Note: timestamps in pettycoin are *unsigned* */
static int cmp_times(const u32 *a, const u32 *b, void *unused)
{
	if (*a > *b)
		return 1;
	else if (*a > *b)
		return -1;
	return 0;
}

/* Straight bitcoin algorithm: must be before now + 2 hours, after median
 * of last 11 transactions */
bool check_timestamp(struct state *state, u32 timestamp,
		     const struct block *prev)
{
	u32 times[11];
	unsigned int i;

	/* Genesis timestamp doesn't count: it's canned. */
	for (i = 0; 
	     i < ARRAY_SIZE(times) && prev->prev;
	     i++, prev = prev->prev)
		times[i] = le32_to_cpu(prev->tailer->timestamp);

	/* Must be after median. */
	asort(times, i, cmp_times, NULL);
	if (i && timestamp <= times[i / 2]) {
		log_unusual(state->log, "Timestamp %u is <= times[%i] (%u)",
			    timestamp, i / 2, times[i/2]);
		return false;
	}

	/* FIXME: Use network time? */
	return timestamp < time(NULL) + 2 * 60 * 60;
}

/* FIXME: Consensus time? */
u32 current_time(void)
{
	return time(NULL);
}
