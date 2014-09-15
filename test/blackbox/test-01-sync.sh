#! /bin/sh

set -em

# FIXME: broken due to protocol change!
exit 0

mkdir $SCRATCHDIR/p1 $SCRATCHDIR/p2

NEWBLOCK=010002dcf2b3ff756f4c39c16a417e69138d79ce03488dda58e4f53cf640b3a99b91de4e8561afa441badda92600000028000000521f00001201212a5b494784a924f2e0249bf4c268af1d0e000000006d07571dee2e35e1378bc43a8e1388d2fef6b3021cc9924b885d53b2ce390ea86d07571dee2e35e1378bc43a8e1388d2fef6b3021cc9924b885d53b2ce390ea86d07571dee2e35e1378bc43a8e1388d2fef6b3021cc9924b885d53b2ce390ea86d07571dee2e35e1378bc43a8e1388d2fef6b3021cc9924b885d53b2ce390ea83e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e449ee153c4ff3b1d7a7f0901

# Unpack their blockfiles.
xzcat test/blackbox/test-01-blockfile1.xz > $SCRATCHDIR/p1/blockfile
xzcat test/blackbox/test-01-blockfile2.xz > $SCRATCHDIR/p2/blockfile

# Make sure they find each other.
touch $SCRATCHDIR/addresses
ln -sf ../addresses $SCRATCHDIR/p1/addresses
ln -sf ../addresses $SCRATCHDIR/p2/addresses

$RUNPREFIX/pettycoin --seeding --developer-test --pettycoin-dir=$SCRATCHDIR/p1 > $SCRATCHDIR/p1.log 2>&1 &
$RUNPREFIX/pettycoin --seeding --developer-test --pettycoin-dir=$SCRATCHDIR/p2 > $SCRATCHDIR/p2.log 2>&1 &

# They should complete within 1 minute.
END=$(( $(date +%s) + 60 ))

# Wait for startup
while [ $(date +%s) -lt $END ]; do
    if $RUNPREFIX/pettycoin-query --pettycoin-dir=$SCRATCHDIR/p1 help >/dev/null 2>&1 && $RUNPREFIX/pettycoin-query --pettycoin-dir=$SCRATCHDIR/p2 help >/dev/null 2>&1; then
	break;
    fi
    sleep 5
done

# FIXME: This doesn't go to P2, which is still syncing!
## Give P1 new block, will trigger P2 to ask.
#$RUNPREFIX/pettycoin-query --pettycoin-dir=$SCRATCHDIR/p1 submitblock $NEWBLOCK

while [ $(date +%s) -lt $END ]; do
    DEPTH1=`$RUNPREFIX/pettycoin-query --pettycoin-dir=$SCRATCHDIR/p1 getinfo | sed -n 's/.*"height" : \([0-9]\+\) .*num_todos.*/\1/p'`
    DEPTH2=`$RUNPREFIX/pettycoin-query --pettycoin-dir=$SCRATCHDIR/p2 getinfo | sed -n 's/.*"height" : \([0-9]\+\) .*num_todos.*/\1/p'`
    if [ "$DEPTH1" = "$DEPTH2" ]; then
	$RUNPREFIX/pettycoin-query --pettycoin-dir=$SCRATCHDIR/p1 stop
	$RUNPREFIX/pettycoin-query --pettycoin-dir=$SCRATCHDIR/p2 stop
	exit 0
    fi
    sleep 5
done
echo Timeout >&2
$RUNPREFIX/pettycoin-query --pettycoin-dir=$SCRATCHDIR/p1 stop
$RUNPREFIX/pettycoin-query --pettycoin-dir=$SCRATCHDIR/p2 stop
exit 1
