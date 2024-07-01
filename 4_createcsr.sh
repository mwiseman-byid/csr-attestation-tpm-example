#!/bin/bash
. ./dirs.sh
set -e

# /bin/bash
. ./dirs.sh
set -e

# Create the TPM Endorsement Key (EK).
echo -e "Creating EK"
tpm2_createek -c $cdir/ek.ctx -u $cdir/ek.pub
# 
# Create the Primary Storage Key (SRK). 
echo -e "\nCreating Primary Storage Key (SRK)"
tpm2_createprimary -C o -c $cdir/primaryStorage.ctx
#
# Create the Attestation Key (AK). The AK will be in the Endorsement Hierarchy under the EK.
echo -e "\nCreating the Attestation Key (AK)"
tpm2_createak -C $cdir/ek.ctx -G rsa -c $cdir/ak.ctx -u $cdir/ak.pub -r $cdir/ak.priv
#
# The following simulates the operation of an Attestation Certification Authority (ACA)
# However, the process of generating the AK and its AK Certificate is outside the scope of these example scripts. These scripts
# "assume" the existance of a trusted AK and AK Certificate.

# These scripts use the "openssl x509" command which assumes a propertly formatted and signed CSR. A CSR is required to be signed by
# the Private Key assocated with the Public Key in the CSR. However, a critical property of an AK is that it will sign only TPM
# generated data (i.e., it will not sign the output of an openssl req command). Therefore, the following commands will:
# 1. Extract the AK Public Key in PEM format.
# 2. Generate a CSR for a new "Fake Key" using attributes from "openssel-AK.conf".
# 3. Generate an x.509 Certificate using the Fake Key CSR as input but then substituting the AK's Public Key into the final AK
#    Certificate using the "-force_pubkey" option.
# 
# Another method would have been to create the AK CSR *CertificationRequestInfo* as defined in [PKCS #10: Certification Request
# Syntax Specification RFC 2986](https://datatracker.ietf.org/doc/html/rfc2986) and sending the bitstream to the TPM using the
# tpm2_hash command then signing the result using the AK and returned ticket. This method was not adopted in this version but may be
# investiaged for a further version.

echo -e "\nCreate the PEM format for the AK public key"
tpm2_readpublic -c $cdir/ak.ctx -f pem -o $cdir/ak.pem
#
# Create an AK Certificate
echo -e "\nCreate a csr for an AK Certificate"
#openssl req -key $cdir/ak.pem -new -out $cdir/ak.pem
openssl req -new -noenc -config ./openssl-AK.conf -keyout $cdir/ak-fake.key -out $cdir/ak-fake.csr

openssl x509 -req -CA $cadir/rootCACert.pem -CAkey $cadir/rootCAKey.pem -force_pubkey $cdir/ak.pem -in $cdir/ak-fake.csr -out $cdir/ak.cert
rm $cdir/ak-fake.*

# Wrap the TPM data into an ASN.1 CertificationRequestInfo output to 'out.cri'
python3 create_cri_from_tcg_attest_certify.py $cdir/key1.attest $cdir/key1-attest.sig $cdir/key1.pub $cdir/key1.pem $cdir/ak.cert $cadir/rootCACert.pem
mv out.cri $cdir/out.cri

openssl dgst -sha256 -binary -out $cdir/out-cri.hash $cdir/out.cri


# Sign the CSR with key1. This returns a out-cri.sig
echo -e "\n*** Getting attestation for key1 ***"
tpm2_sign -c $cdir/key1.ctx -g sha256 -d $cdir/out-cri.hash -f plain -o $cdir/out-cri.sig

python3 attach_sig_to_cri.py $cdir/out.cri $cdir/out-cri.sig
mv out.csr $cdir/out.csr

# Check that the signature was applied correctly
# Note that openssl will return SUCCESS (0) regardless,
# so you have to look at the command-line output
openssl req -noout -verify -inform der -in $cdir/out.csr

# Convert the output file to PEM
openssl req -inform der -in $cdir/out.csr -out $cdir/csr.pem

# Send csr to verifier. This would normally be a network or other transfer from the client to the RA to the Verifier
cp $cdir/csr.pem $vdir


