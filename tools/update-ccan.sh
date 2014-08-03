#! /bin/sh

set -e

CCANDIR=${1:-../ccan}
NEW_VERSION=$(git --git-dir=$CCANDIR/.git describe --always)
OLD_VERSION=$(grep '^CCAN version: ' ccan/README | cut -d: -f2)

# Make sure we have a clean tree.
if git status --porcelain | grep -v '^\?\?'; then
    echo "Dirty tree" >&2
    exit 1
fi

(cd $CCANDIR && git diff $OLD_VERSION $NEW_VERSION ccan/ licenses/ tools/configurator) > ccan/diff
(cd ccan && patch -p1 < diff)
rm ccan/diff
grep -v '^CCAN version: ' ccan/README > ccan/README.new
echo "CCAN version: $NEW_VERSION" >> ccan/README.new
mv ccan/README.new ccan/README

echo "Updated to $NEW_VERSION"
