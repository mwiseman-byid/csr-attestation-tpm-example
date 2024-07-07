#!/bin/bash
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
# Wrap the TPM data into an ASN.1 CertificationRequestInfo output to 'out.cri'
python3 create_cri_from_tcg_attest_certify.py $cdir/key1.tpmSAttest $cdir/key1.tpmSAttest.sig $cdir/key1.tpmTPublic $cdir/key1-pub.pem $cdir/ak.cert $cadir/rootCACert.pem
mv out.cri $cdir/out.cri

openssl dgst -sha256 -binary -out $cdir/out-cri.hash $cdir/out.cri


# Sign the CSR with key1. This returns a out-cri.sig
echo -e "\n   *** Getting attestation for key1 ***"
tpm2_sign -c $cdir/key1.ctx -g sha256 -d $cdir/out-cri.hash -f plain -o $cdir/out-cri.sig

python3 attach_sig_to_cri.py $cdir/out.cri $cdir/out-cri.sig
mv out.csr $cdir/key1-csr.der

# Check that the signature was applied correctly
# Note that openssl will return SUCCESS (0) regardless,
# so you have to look at the command-line output
openssl req -noout -verify -inform der -in $cdir/key1-csr.der

# Convert the output file to PEM
openssl req -inform der -in $cdir/key1-csr.der -out $cdir/key1-csr.pem

# Send csr to verifier. This would normally be a network or other transfer from the client to the RA to the Verifier
cp $cdir/key1-csr.pem $vdir

# Create the attestation_statement as a .tar file for now.
#tar cvf $cdir/attestation_statement.tar -C $cdir key1.attest key1-attest.sig key1.pub ak.cert
