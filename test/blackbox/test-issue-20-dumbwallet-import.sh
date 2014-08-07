#! /bin/sh

set -e

OUT=`../../dumbwallet --pettycoin-dir=$1 setup P-cNkMqSEm5FsNGTPcKUaUjoVA8adAm9tezdAjsAeGfxtxjhps76M8`
# Should give correct address.
echo "$OUT" | grep P-mxEP2midj7DRBW4yCxBBSs2MWcMsQfqQVw > /dev/null

