#! /bin/sh

set -em

rm -rf test-01-dir
mkdir test-01-dir test-01-dir/p1 test-01-dir/p2

NEWBLOCK=100100000800000000000000010002dcf2b3ff756f4c39c16a417e69138d79ce03488dda58e4f53cf640b3a99b91de4e8561afa441badda92600000028000000521f00001201212a5b494784a924f2e0249bf4c268af1d0e000000006d07571dee2e35e1378bc43a8e1388d2fef6b3021cc9924b885d53b2ce390ea86d07571dee2e35e1378bc43a8e1388d2fef6b3021cc9924b885d53b2ce390ea86d07571dee2e35e1378bc43a8e1388d2fef6b3021cc9924b885d53b2ce390ea86d07571dee2e35e1378bc43a8e1388d2fef6b3021cc9924b885d53b2ce390ea83e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e449ee153c4ff3b1d7a7f0901

# Unpack their blockfiles.
xzcat test-01-blockfile1.xz > test-01-dir/p1/blockfile
xzcat test-01-blockfile2.xz > test-01-dir/p2/blockfile

# Make sure they find each other.
touch test-01-dir/addresses
ln -sf ../addresses test-01-dir/p1/addresses
ln -sf ../addresses test-01-dir/p2/addresses

# Core dumps please!
ulimit -c unlimited

../../pettycoin --seeding --developer-test --pettycoin-dir=test-01-dir/p1 > test-01-dir/p1.log 2>&1 &
../../pettycoin --seeding --developer-test --pettycoin-dir=test-01-dir/p2 > test-01-dir/p2.log 2>&1 &

# They should complete within 1 minute.
END=$(( $(date +%s) + 60 ))

# Wait for startup
while [ $(date +%s) -lt $END ]; do
    if ../../pettycoin-query --pettycoin-dir=test-01-dir/p1 help >/dev/null 2>&1 && ../../pettycoin-query --pettycoin-dir=test-01-dir/p2 help >/dev/null 2>&1; then
	break;
    fi
    sleep 5
done

# Give P1 new block, will trigger P2 to ask.
../../pettycoin-query --pettycoin-dir=test-01-dir/p1 submitblock $NEWBLOCK

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
