#! /bin/sh

# Read request.
while read LINE; do
    LINE=$(echo "$LINE" | tr -d '\015')
    if [ x"$LINE" = x ]; then
	break
    fi
done

# Whatever they said, give canned answer.
echo 'HTTP/1.1 200 OK'
echo 'Content-Type: text/html'
echo
echo '<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">'
echo '<html><head>'
echo '<title>Pettycoin Gateway Status Page</title>'
echo '</head><body>'
echo '<h1>Pettycoin Gateway Status Page</h1>'

if pidof pettycoin-gateway >/dev/null; then
    echo '<p>Gateway is active</p>'
else
    echo '<p>Gateway is <b>DOWN</b></p>'
fi

if [ -r /home/pettycoin/gateway-info.html ]; then
    cat /home/pettycoin/gateway-info.html
fi

LOG=`ls /home/pettycoin/pettycoin-gateway.log* | tail -n1`
echo "<p>Log $LOG</p> <pre>"
cat $LOG
echo '</pre></body>'

