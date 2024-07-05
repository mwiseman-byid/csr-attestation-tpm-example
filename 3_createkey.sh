#!/bin/bash
. ./dirs.sh
set -e

# General notes:

# Create key1 under Storage Hierarchy
#       Compatibility Note:
#       TPM2_Create with option -c will attempt to perform a TPM2_CreateLoaded command
#       TPM2_Create without option -c will just create the key, return the public and private components
#       and return -- without loading the key.
#       TPM2 versions <= 1.16 does not support TPM2_CreateLoaded command. As there are still
#       TPM2 version 1.16 and lower in the field the tpm2_create is used without the -c option.
#               In particular Windows 10 Hyper-V implements TPM2 1.16 (haven't tested Windows 11)
#
# The public data returned by the tpm2_create -u option is a TPM2B_PUBLIC structure.
# A TPM2B_PUBLIC structure is a 16 bit length preceded TPMT_PUBLIC structure 
#
# key1.pub: is a TPM2B_PUBLIC structure
# key1.priv is a TPM2B_PRIVATE structure
#
# Note that a PEM formatted file of key1 could be created and passed but that can be done by the verifier. A PEM version of key1 is
# not part of the TPMS_ATTEST so is not attestable.
echo -e "\n   *** Creating key1 ***"
tpm2_create -C $cdir/primaryStorage.ctx -u $cdir/key1.pub -r $cdir/key1.priv
#
# The key must be loaded to perform the tpm2_certify command (See Compatibility Note above)
echo -e "\n   ***  Loading key1 ***"
tpm2_load -C $cdir/primaryStorage.ctx -c $cdir/key1.ctx -u $cdir/key1.pub -r $cdir/key1.priv
#
# Attest to key1. This returns a key1.attest is a TPM2B_ATTEST structure
echo -e "\n   *** Get attestation for key1 ***"
tpm2_certify -C $cdir/ak.ctx -g sha256 -c $cdir/key1.ctx -o $cdir/key1.attest -f plain -s $cdir/key1-attest.sig
echo "***\nPrint attestation data for key1 (Informational only) ***"
tpm2_print -t TPMS_ATTEST $cdir/key1.attest
#
# Create key1 PEM formatted public key
echo -e "\n   *** Read the key1 public key in PEM format"
tpm2_readpublic -c $cdir/key1.ctx -f pem -o $cdir/key1.pem
# Create the attestation_statement as a .tar file for now.
#tar cvf $cdir/attestation_statement.tar -C $cdir key1.attest key1-attest.sig key1.pub ak.cert
