# /bin/bash
. ./dirs.sh
set -e
#
# Filenames
# key1.pub            : key1 public key information     : TPM2B_PUBLIC structure
# key1-pub.pem        : key1 public key                 : PEM format
# key1.priv           : key1 private key                : TPM2B_PRIVATE structure
# key1.tpmTPublic     : key1 public key information     : TPMT_PUBLIC structure
# key1.tpmSAttest     : key1 attestation structure      : TPMS_ATTEST structure
# key1.tpmSAttest.sig : signature over key1.tpmSAttest
# key1-csr.pem        : key1's csr (the final result)   : PEM format
#
# Input: The previous script "transmitted" the key1-csr.pem file by copying it
#
# Get the root CA Cert
cp $cadir/rootCACert.pem $vdir

#tar cvf $cdir/attestation_statement.tar -C $cdir key1.attest key1-attest.sig key1.pub ak.cert
# These should come from parsing the transmitted key1-csr.pem. That work is not done. Copy these for now.
# To manually verify the tpm information was put into the csr follow the instructions at the end of this script.
cp $cdir/ak.cert $vdir
cp $cdir/key1-pub.pem $vdir
cp $cdir/key1.tpmTPublic $vdir
cp $cdir/key1.tpmSAttest $vdir 
cp $cdir/key1.tpmSAttest.sig $vdir 

# Verify ak Certificate
echo -e "\n   *** Verify AK Certificate ***"
openssl verify -CAfile $vdir/rootCACert.pem $vdir/ak.cert
echo -e "\n      *** Result: AK Certificate is trusted *****"
#
# Extract the AK public key. Will be used to verify key1.tpmSAttest.
openssl x509 -in $vdir/ak.cert -pubkey -out $vdir/ak.pem

# Verify TPM2_Certify Attestation
echo -e "\n   *** Verify TPM's attestation of key1 (TPMS_ATTEST) ***"
openssl dgst -verify $vdir/ak.pem -keyform pem -sha256 -signature $vdir/key1.tpmSAttest.sig $vdir/key1.tpmSAttest
echo -e "\n      *** Result: key1.tpmSAttest is trusted ***"
echo -e "\n   *** Extract the verified key1's name so it can be compared with the TPMT_PUBLIC object."
# key1.tpmSAttest is The Verifier will now reivew the information in the key1 TPMS_ATTEST structure against  ***"
#
# Parse output from trusted key1.tpmSAttest to get key1's name
tpm2_print -t TPMS_ATTEST $vdir/key1.tpmSAttest > $vdir/key1.tpmSAttest.out
# Hack: Extract name from tpm2_print output using awk
awk '/^ *name: /{print $NF}' $vdir/key1.tpmSAttest.out > $vdir/key1.tpmSAttest.name
# 
# Obtain an unverified key1 TPMT_PUBLIC object. This can be done by either reading if from the csr (it is OPTIONAL) or by having a
# local copy that was kept. In this example, it is obtained from the csr. 
#
# Calculate local key1's name as attested by the AK.
# Note: key1 name = hashalg | hash(TPMT_PUBLIC).
#
openssl dgst -sha256 $vdir/key1.tpmTPublic | sed 's/.*= //' > $vdir/key1.local-name.hash
# Prepend name hashalg to be name
# Hack: Hard coding sha256 for now. Should read this from key1.pub output
printf "000b" > $vdir/key1.name.hashalg
cat $vdir/key1.name.hashalg $vdir/key1.local-name.hash > $vdir/key1.local-name

# Compare name from attest and locally calculated name
diff -s $vdir/key1.tpmSAttest.name $vdir/key1.local-name
# Attention and key's Public data is now trusted.
# Printing Informational messages
echo -e "\n\n    ***** All information about key1 is trusted *****"
echo -e "\n         *** key1 TPMS_ATTEST information ***"
tpm2_print -t TPMS_ATTEST $vdir/key1.tpmSAttest

echo -e "\n         *** key1 TPMT_PUBLIC information ***"
tpm2_print -t TPMT_PUBLIC $vdir/key1.tpmTPublic 

echo -e "\n\n    ***** Verifier examines of key1.tpmTPublic to confirm it matches policy *****"
echo -e "\n   *** Verify key1 public key from csr matches the certified key1 TPMT_PUBLIC object ***"
openssl rsa -inform PEM -pubin -in $vdir/key1-pub.pem -noout -modulus -out $vdir/key1-pub-fromcsr.modulus.raw
awk -F= '/^Modulus=/{print $NF}' $vdir/key1-pub-fromcsr.modulus.raw > $vdir/key1-pub-fromcsr.modulus
tpm2_print -t TPMT_PUBLIC $vdir/key1.tpmTPublic > $vdir/key1.tpmTPublic.out
awk '/^ *rsa: /{print $NF}' $vdir/key1.tpmTPublic.out > $vdir/key1-pub-fromtpmt_public.modulus
set +e
diff -q -s -i $vdir/key1-pub-fromcsr.modulus $vdir/key1-pub-fromtpmt_public.modulus 1>/dev/null
RETURN=$?
set -e
if [ $RETURN -eq 0 ]; then
        echo -e "\n       *** Public key does match ***"
else
        echo -e "\n       *** Public key does NOT match ***"
        exit 1
fi

#... Other examination ....
echo -e "\n   *** Issue key1 Certificate ***"
openssl x509 -req -extfile ./openssl-key1-x509.conf -CA $cadir/rootCACert.pem -CAkey $cadir/rootCAKey.pem -in $vdir/key1-csr.pem -out $vdir/key1.crt

# To manually verify the tpm information was put into the csr do the following:
# openssl asn1parse -in verifier/key1-csr.pem
# Locate the TCG oid: 2.23.133.20.1. The three octet strings are from the RFC
# Tcg-csr-tpm-certify :: = SEQUENCE {
#    tpmSAttest OCTET STRING,
#    signature  OCTET STRING,
#    tpmTPublic OCTET STRING OPTIONAL
# }
# From the screen copy each using the mouse and paste to the command line. Echo that to a file:
# echo "...copied text from 1st octet string ..." | xxd -r -p - > test/tpmSAttest.fromcsr
# echo "...copied text from 2nd octet string ..." | xxd -r -p - > test/signature.fromcsr
# echo "...copied text from 3rd octet string ..." | xxd -r -p - > test/tpmTPublic.fromcsr
#
# diff each with the corresponding file in verifier.
