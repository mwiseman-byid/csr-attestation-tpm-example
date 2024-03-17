# /bin/bash
. ./dirs.sh
set -e
# Expanding attestation_statement
echo -e "*** Expanding attestation_statement ***"
tar xvf $acadir/attestation_statement.tar -C $acadir

# Verify ak Certificate
echo -e "\n*** Verify AK Certificate ***"
openssl verify -CAfile $cadir/rootCACert.pem $acadir/ak.cert
echo -e "\n***** Result: AK Certificate is trusted *****"
#
# Extract the AK public key
openssl x509 -in $acadir/ak.cert -pubkey -out $acadir/ak.pem

# Verify TPM2_Cerify Attestation
echo -e "\n*** Verify TPM's attestation key1-attest (TPMS_ATTEST) ***"
openssl dgst -verify $acadir/ak.pem -keyform pem -sha256 -signature $acadir/key1-attest.sig $acadir/key1.attest
echo -e "\n   *** Result: key1.attest is trusted ***"
echo -e "\n   *** Next: Verify key.pub is trusted ***"
#
echo -e "\nParse output from trusted key1.attest to get trusted key1 name"
tpm2_print -t TPMS_ATTEST $acadir/key1.attest > $acadir/key1.attest.out
# Hack: Extract name using awk
awk '/^ *name: /{print $NF}' $acadir/key1.attest.out > $acadir/key1.attest.name
# 
# Calculate local key1's name. This insures key1.pub is same as attested
# to by the TPM.
# Object name = hashalg | hash(TPMT_PUBLIC).
# ak.pub is a TPM2B_PUBLIC structure
# Hack to extract TPMT_PUBLIC from TPM2B_PUBLIC by removing size (1st 2 octets)
dd bs=2 skip=1 if=$acadir/key1.pub of=$acadir/key1.tpmt_public 2> /dev/null
# Hack: Use sed is needed to remove the leading characters added by openssl dgst
openssl dgst -sha256 $acadir/key1.tpmt_public | sed 's/.*= //' > $acadir/key1.local-name-hash
# Prepend name hashalg to be name
# Hack: Hard coding sha256 for now. Should read this from key1.pub output
printf "000b" > $acadir/key1.name.hash
cat $acadir/key1.name.hash $acadir/key1.local-name-hash > $acadir/key1.local-name

# Compare name from attest and locally calculated name
diff -s $acadir/key1.attest.name $acadir/key1.local-name
# Attestion and key's Public data is now trusted. Print them
echo -e "\n\n   *** All information about key1 is trusted ***"
echo -e "\n   *** key1 TPMS_ATTEST information ***"
tpm2_print -t TPMS_ATTEST $acadir/key1.attest 
echo -e "\n   *** key1 TPMT_PUBLIC information ***"
tpm2_print -t TPMT_PUBLIC $acadir/key1.tpmt_public 
