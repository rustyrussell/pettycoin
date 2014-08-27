#! /bin/sh

set -e

CCANDIR=${1:-../ccan}
NEW_VERSION=${2:-$(git --git-dir=$CCANDIR/.git describe --always)}
OLD_VERSION=$(grep '^CCAN version: ' ccan/README | cut -d: -f2)

if [ $NEW_VERSION = $OLD_VERSION ]; then
    echo Already at $OLD_VERSION
    exit 0
fi

# Make sure we have a clean tree.
UNCLEAN=$(git status --porcelain | grep -v '^??' || true)
if [ -n "$UNCLEAN" ]; then
    echo "Dirty tree" >&2
    exit 1
fi

MODULES=$(cd ccan; ls -d ccan/* | grep -v ccan/Makefile)
(cd $CCANDIR && git diff $OLD_VERSION $NEW_VERSION $MODULES licenses/ tools/configurator) > ccan/diff
(cd ccan && patch -p1 < diff)
diffstat ccan/diff
rm ccan/diff
grep -v '^CCAN version: ' ccan/README > ccan/README.new
echo "CCAN version: $NEW_VERSION" >> ccan/README.new
mv ccan/README.new ccan/README

echo "Updated to $NEW_VERSION"
