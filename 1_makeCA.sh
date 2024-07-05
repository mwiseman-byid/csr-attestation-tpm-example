# /bin/bash
. ./dirs.sh

echo -e "\n   *** Creating CA/ACA"
openssl req -new -nodes -x509 -config ./openssl-CA.conf -keyout $cadir/rootCAKey.pem -out $cadir/rootCACert.pem 
