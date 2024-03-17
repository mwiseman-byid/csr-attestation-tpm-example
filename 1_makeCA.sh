# /bin/bash
. ./dirs.sh

openssl genrsa -out $cadir/rootCAKey.pem 2048
openssl req -x509 -config ./openssl-CA.conf -new -nodes -key $cadir/rootCAKey.pem -days 3650 -out $cadir/rootCACert.pem
