#! /bin/sh

set -em

rm -rf test-01-dir
mkdir test-01-dir test-01-dir/p1 test-01-dir/p2

# Unpack their blockfiles.
xzcat test-01-blockfile1.xz > test-01-dir/p1/blockfile
xzcat test-01-blockfile2.xz > test-01-dir/p2/blockfile

# Make sure they find each other.
touch test-01-dir/addresses
ln -sf ../addresses test-01-dir/p1/addresses
ln -sf ../addresses test-01-dir/p2/addresses

# Core dumps please!
ulimit -c unlimited

# P1 generates
../../pettycoin --seeding --developer-test --pettycoin-dir=test-01-dir/p1 --generator=../../../../pettycoin-generate --reward-address=P-mhA9ozMTVWrSnUX2kB8QjEq9FBen8k3euW  > test-01-dir/p1.log 2>&1 &

# P2 syncs
../../pettycoin --seeding --developer-test --pettycoin-dir=test-01-dir/p2 > test-01-dir/p2.log 2>&1 &

# They should sync within 5 minutes.
END=$(( $(date +%s) + 300 ))

# Wait for startup
while [ $(date +%s) -lt $END ]; do
    if ../../pettycoin-query --pettycoin-dir=test-01-dir/p1 help >/dev/null 2>&1 && ../../pettycoin-query --pettycoin-dir=test-01-dir/p2 help >/dev/null 2>&1; then
	break;
    fi
    sleep 5
done

while [ $(date +%s) -lt $END ]; do
    DEPTH1=`../../pettycoin-query --pettycoin-dir=test-01-dir/p1 getinfo | sed -n 's/.*"height" : \([0-9]\+\) .*num_todos.*/\1/p'`
    DEPTH2=`../../pettycoin-query --pettycoin-dir=test-01-dir/p2 getinfo | sed -n 's/.*"height" : \([0-9]\+\) .*num_todos.*/\1/p'`
    if [ "$DEPTH1" = "$DEPTH2" ]; then
	../../pettycoin-query --pettycoin-dir=test-01-dir/p1 stop
	../../pettycoin-query --pettycoin-dir=test-01-dir/p2 stop
	exit 0
    fi
    sleep 5
done
echo Timeout >&2
../../pettycoin-query --pettycoin-dir=test-01-dir/p1 stop
../../pettycoin-query --pettycoin-dir=test-01-dir/p2 stop
exit 1
