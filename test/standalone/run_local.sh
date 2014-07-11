#! /bin/sh

set -e

if [ $# -ne 1 ]; then
    echo "Usage: run_local.sh <num-instances>" >&2
    exit 1
fi

setup_dir()
{
    mkdir $1
    ln -s ../addresses $1/addresses 
    cat > $1/config <<EOF
# Generated config file
developer-test
generator=../../../generate
log-prefix=$i:
log-level=info
# This is test/helper_addr(0).
reward-address=P-mhA9ozMTVWrSnUX2kB8QjEq9FBen8k3euW
EOF
}

trap "killall serve_addresses; killall pettycoin" EXIT


rm -rf pettycoin-* addresses

touch addresses
./serve_addresses &

for i in `seq 2 $1`; do
    setup_dir pettycoin-$i
    ../../pettycoin --pettycoin-dir=pettycoin-$i &
done
trap "" EXIT

i=1
setup_dir pettycoin-$i
#HOME=home-$i valgrind --db-attach=yes --child-silent-after-fork=yes ../../pettycoin --developer-test --generate=../../../../generate --log-prefix="$i:" $flags
gdb --args ../../pettycoin --pettycoin-dir=pettycoin-$i --log-level=debug
#HOME=home-$i strace -f -o /tmp/out ../../pettycoin --developer-test --generate=../../../../generate $flags
