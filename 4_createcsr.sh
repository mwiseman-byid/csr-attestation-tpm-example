# /bin/bash
. ./dirs.sh
set -e

# Wrap the TPM data into an ASN.1 CertificationRequestInfo output to 'out.cri'
python3 tpm_wrapper.py $cdir/key1.attest $cdir/key1-attest.sig $cdir/key1.pub $cdir/key1.pem
mv out.cri $cdir/out.cri

openssl dgst -sha256 -binary -out $cdir/out-cri.hash $cdir/out.cri


# Sign the CSR with key1. This returns a out-cri.sig
echo -e "\n*** Getting attestation for key1 ***"
tpm2_sign -c $cdir/key1.ctx -g sha256 -d $cdir/out-cri.hash -f plain -o $cdir/out-cri.sig

openssl req -noout -text -verify -inform der -in out.csr