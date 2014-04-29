#! /bin/sh

set -e

if [ $# -ne 1 ]; then
    echo "Usage: run_local.sh <num-instances>" >&2
    exit 1
fi

trap "killall serve_addresses; killall pettycoin" EXIT

rm -rf home-* addresses

touch addresses
./serve_addresses &

# Only debug for first one.
flags="--log-level=debug"
#flags="--log-level=info"

for i in `seq 2 $1`; do
    mkdir home-$i
    HOME=home-$i ../../pettycoin --developer-test --generate=../../../../generate --log-prefix="$i:" $flags &
done
trap "" EXIT

i=1
mkdir home-$i
#HOME=home-$i valgrind --db-attach=yes --child-silent-after-fork=yes ../../pettycoin --developer-test --generate=../../../../generate --log-prefix="$i:" $flags
HOME=home-$i gdb --args ../../pettycoin --developer-test --generate=../../../../generate --log-prefix="$i:" $flags
#HOME=home-$i strace -f -o /tmp/out ../../pettycoin --developer-test --generate=../../../../generate $flags
