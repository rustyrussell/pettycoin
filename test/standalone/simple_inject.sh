#! /bin/sh

set -e

DIR=${1:-pettycoin-1}

GATEADDR=muzRJJzenB7uKzokx21W2QGobfDEZfiH1u
GATEPRIVKEY=cRhETWFwVpi7q8Vjs7KqvYYGZC5htvT3ddnd9hJk5znSohTBHRkT
ADDR2=mopv7T2T7szaYdJNxm7jAF8x16dbMfGerN
ADDR3=mu1LMYYHAWDvRRRdT4or3vqHYZyQ7YNpEu
PRIVKEY2=cVxWbCJ11bcQCsz98fkUzozzhkrwd44QZ8ajLe8ZY6FwtsBfy92X
PRIVKEY3=cPfA1cE78BtzTaNGEfQN5H89bgmyV1BzVz8ppMo3tcVjK21WsagM

# Gateway injects 100 satoshi to ADDR2.
TX=`../../pettycoin-tx from-gateway P-$GATEPRIVKEY P-$ADDR2 100`
../../pettycoin-query --pettycoin-dir=$DIR sendrawtransaction $TX

# ADDR2 pays half to ADDR3 (no fee)
TX2=`../../pettycoin-tx --no-fee tx P-$PRIVKEY2 P-$ADDR3 50 50 raw:$TX`
#TX2=`../../inject tx $PRIVKEY2 localhost $PORT P-$ADDR3 50 49 $TX`
../../pettycoin-query --pettycoin-dir=$DIR sendrawtransaction $TX2

# ADDR3 sends half back to gateway (minus fee)
TX3=`../../pettycoin-tx to-gateway P-$PRIVKEY3 P-$GATEADDR 25 24 raw:$TX2`
../../pettycoin-query --pettycoin-dir=$DIR sendrawtransaction $TX3
