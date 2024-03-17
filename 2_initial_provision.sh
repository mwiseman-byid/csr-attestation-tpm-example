# /bin/bash
. ./dirs.sh
set -e

# This will make the EK persistent
echo -e "Creating EK"
tpm2_createek -c $cdir/ek.ctx -u $cdir/ek.pub
# 
# the AK will not be persistent in the TPM but TSS will load it from the ek.ctx file
echo -e "\nCreating AK"
tpm2_createak -C $cdir/ek.ctx -G rsa -c $cdir/ak.ctx -u $cdir/ak.pub -r $cdir/ak.priv
#
#tpm2_create -g sha256 -G rsa:rsassa -u certify.pub -r certify.priv \
# the Primary Storage Key (SRK) will not be persistent in the TPM but TSS will load it from the primary.ctx file
echo -e "\nCreating Primary Storage Key (SRK)"
tpm2_createprimary -C o -c $cdir/primaryStorage.ctx
#
# Key AK PEM formatted public key
echo -e "\nRead the AK public key in PEM format"
tpm2_readpublic -c $cdir/ak.ctx -f pem -o $cdir/ak.pem
#
# Create an AK Certificate
echo -e "\nCreate an AK Certificate"
#openssl req -key $cdir/ak.pem -new -out $cdir/ak.pem
openssl req -new -noenc -config ./openssl-AK.conf -keyout $cdir/ak-fake.key -out $cdir/ak-fake.csr

openssl x509 -req -CA $cadir/rootCACert.pem -CAkey $cadir/rootCAKey.pem -force_pubkey $cdir/ak.pem -in $cdir/ak-fake.csr -out $cdir/ak.cert
rm $cdir/ak-fake.*
