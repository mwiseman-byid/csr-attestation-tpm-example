# csr-attestation-tpm-example

## Dependencies
This uses the TCG TSS command line utilities from https://github.com/tpm2-software.
This is normally obtained by downloading from your distro. However, there is an issue
with the released files where the command tpm2_print -t TPMS_ATTEST command
was not implemented. I've filed an issue and was fixed but (as of 23-03-08) was
not merged. I have copied the fixed file to my own reposity at
https://github.com/mwiseman-byid/tpm2-tools. This does require building the tpm2-tss
from the main branch.

There is a python sub-component, it requires python3, pip, and venv:

1. Create a virtual environment
    ```shell
    python -m venv venv
    ```
2. Activate the virtual environment
    ```shell
    source venv/bin/activate
    ```
3. Install the dependencies

    ```shell
    pip install -r requirements.txt
    ```

## Description

This example builds the attestation_statement init a .tar file and does not add
the attestation_statment into a csr with the defined new extension. This is
work to do.

As the tpm2_tools man pages don't specifically state the strutures returned, they
described here (only the parameters used in this demo are described):
> tpm2_create
> >-u TPM2B_PUBLIC (key1.pub)
> >
> >-r TPM2B_PRIVATE (key1.priv)
> 
> tpm2_certify
> >-o TPMS_ATTEST (key1.attest)
> > NOTE: While the TPM2 command tpm2_Certify returns TPM2B_ATTEST, this
> > CLI command returns TPMS_ATTEST (removing the first 16 bits of size) as
> > the signature covers only the TPMS_ATTEST.
> >
> >-s PEM Formatted signature over key1.attest (key1-attest.sig)
> > (in PEM format due to "-f plain")
# How this works
1. This starts with the assumption that the AK is already created and the AK Cert
is signed by a CA trusted by the ACA.

2. All TPM keys have a "name". The name is a hash of the TPMT_PUBLIC area which includes
the key's public portion. The TPMT_PUBLIC also contains the key's meta-data such as the
various attributes and policies. The purpose of this demo is to provide the verifier with
proof that the information is from a trusted TPM (as trusted by the AK and AK Cert)

3. The TPM command TPM2_Certify returns a TPMS_ATTEST (wrapped in a TPM2B_ATTEST) structure
of the loaded key to be certified. The TPMS_ATTEST strucuture contains the key's name
(it also contain the key's qualifiedName which is not relevant to this demo). The TPMS_ATTEST
structure is signed by the AK and returned as a signature.

4. As only the key's name is signed by the AK and sent to the verifier, the verify must
reconstruct a temporary name from a TPMT_PUBLIC source then compare the signed one with
the candidate name. If they match, the verify has the TPMT_PUBLIC for the key.

5. The verifier may already have a copy obtained by various means. One method is by having
the client send it which is why those two parameters are optional.

