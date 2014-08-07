#! /bin/sh

set -e

OUT=`$RUNPREFIX/dumbwallet --pettycoin-dir=$SCRATCHDIR setup P-cNkMqSEm5FsNGTPcKUaUjoVA8adAm9tezdAjsAeGfxtxjhps76M8`
# Should give correct address.
echo "$OUT" | grep P-mxEP2midj7DRBW4yCxBBSs2MWcMsQfqQVw > /dev/null

