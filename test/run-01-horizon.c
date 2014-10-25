#include "../horizon.c"

static u32 now;

static le32 days_and_seconds_ago(unsigned days, int secs)
{
	return cpu_to_le32(now - (days * 24 * 3600 + secs));
}

int main(void)
{
	struct block_info bi;
	struct protocol_block_tailer tlr;
	struct state state;

	bi.tailer = &tlr;

	now = current_time();

	/* Test network: 3 day horizon. */
	state.test_net = true;

	/* 3 days and two seconds old. */
	tlr.timestamp = days_and_seconds_ago(3, 2);
	/* It's (just) over the horizon */
	assert(block_expired_by(block_expiry(&state, &bi), now));
	/* And it's more than one second past horizon. */
	assert(block_expired_by(block_expiry(&state, &bi), now-1));
	/* And it's definitely more than 1 second second before horizon. */
	assert(block_expired_by(block_expiry(&state, &bi), now+1));

	/* 3 days and one second old. */
	tlr.timestamp = days_and_seconds_ago(3, 1);
	/* It's (just) over the horizon */
	assert(block_expired_by(block_expiry(&state, &bi), now));
	/* But not more than one second past horizon. */
	assert(!block_expired_by(block_expiry(&state, &bi), now-1));
	/* And it's definitely more than 1 second second before horizon. */
	assert(block_expired_by(block_expiry(&state, &bi), now+1));

	/* 3 days minus two seconds old. */
	tlr.timestamp = days_and_seconds_ago(3, -2);
	/* It's not over the horizon */
	assert(!block_expired_by(block_expiry(&state, &bi), now));
	/* And not more than one second past horizon. */
	assert(!block_expired_by(block_expiry(&state, &bi), now-1));
	/* And not within 1 second second before horizon. */
	assert(!block_expired_by(block_expiry(&state, &bi), now+1));

	/* 3 days minus one second old. */
	tlr.timestamp = days_and_seconds_ago(3, -1);
	/* It's not over the horizon */
	assert(!block_expired_by(block_expiry(&state, &bi), now));
	/* And not more than one second past horizon. */
	assert(!block_expired_by(block_expiry(&state, &bi), now-1));
	/* And (just) within 1 second second before horizon. */
	assert(!block_expired_by(block_expiry(&state, &bi), now+1));

	/* Exactly 3 days ago. */
	tlr.timestamp = days_and_seconds_ago(3, 0);
	/* It's just not over the horizon */
	assert(!block_expired_by(block_expiry(&state, &bi), now));
	/* And not more than one second past horizon. */
	assert(!block_expired_by(block_expiry(&state, &bi), now-1));
	/* It is within 1 second second before horizon. */
	assert(block_expired_by(block_expiry(&state, &bi), now+1));

	/* Normal network: 30 day horizon. */
	state.test_net = false;

	/* 30 days and two seconds old. */
	tlr.timestamp = days_and_seconds_ago(30, 2);
	/* It's (just) over the horizon */
	assert(block_expired_by(block_expiry(&state, &bi), now));
	/* And it's more than one second past horizon. */
	assert(block_expired_by(block_expiry(&state, &bi), now-1));
	/* And it's definitely more than 1 second second before horizon. */
	assert(block_expired_by(block_expiry(&state, &bi), now+1));

	/* 30 days and one second old. */
	tlr.timestamp = days_and_seconds_ago(30, 1);
	/* It's (just) over the horizon */
	assert(block_expired_by(block_expiry(&state, &bi), now));
	/* But not more than one second past horizon. */
	assert(!block_expired_by(block_expiry(&state, &bi), now-1));
	/* And it's definitely more than 1 second second before horizon. */
	assert(block_expired_by(block_expiry(&state, &bi), now+1));

	/* 30 days minus two seconds old. */
	tlr.timestamp = days_and_seconds_ago(30, -2);
	/* It's not over the horizon */
	assert(!block_expired_by(block_expiry(&state, &bi), now));
	/* And not more than one second past horizon. */
	assert(!block_expired_by(block_expiry(&state, &bi), now-1));
	/* And not within 1 second second before horizon. */
	assert(!block_expired_by(block_expiry(&state, &bi), now+1));

	/* 30 days minus one second old. */
	tlr.timestamp = days_and_seconds_ago(30, -1);
	/* It's not over the horizon */
	assert(!block_expired_by(block_expiry(&state, &bi), now));
	/* And not more than one second past horizon. */
	assert(!block_expired_by(block_expiry(&state, &bi), now-1));
	/* And (just) within 1 second second before horizon. */
	assert(!block_expired_by(block_expiry(&state, &bi), now+1));

	/* Exactly 30 days ago. */
	tlr.timestamp = days_and_seconds_ago(30, 0);
	/* It's just not over the horizon */
	assert(!block_expired_by(block_expiry(&state, &bi), now));
	/* And not more than one second past horizon. */
	assert(!block_expired_by(block_expiry(&state, &bi), now-1));
	/* It is within 1 second second before horizon. */
	assert(block_expired_by(block_expiry(&state, &bi), now+1));

	return 0;
}
