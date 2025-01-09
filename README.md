csr-attestation-tpm-example
===========================

# Dependencies
## Distro
These scripts were developed and testing using Ubuntu 22 (as updated on 2024-06-24). Other Linux distros are likely to work but were
not tested.

## tpm2-tools
### Background
These scripts use the TCG TSS command line utilities [tpm2-tools](https://github.com/tpm2-software/tpm2-tools). This package is
normally obtained by installing from your distro using 'apt' in the case of Ubuntu. However, there is an issue with the tpm2_print
command in tpm2-tools prior the tpm2-tools version 5.7. Ubuntu 22 tpm2-tools repo is based on tpm2-tools prior to version 5.7.

> Specifically: The tpm2_print -t TPMS_ATTEST option was not implemented

There are three components to the TSS (TPM software stack):
1. tpm2-tools

    This is the cli used by the scripts
2. tpm2-tss

    This is the set of libraries used by tpm2-tools to create TPM commands and parse TPM responses. These are automatically
    installed when installing tpm2-tools as this package is a dependency of tpm2-tools.
3. tpm2-abrmd
    > This is the Access Broker / Resource Manager daemon. While this daemon is not required, it is recommended.
    > This relieves the application from managing the keys as the TPM typically has limited key slots.
    >
    > The scripts do no key management. As TPM's have a limited number of key slots, the manangement of 
    > keys in these scripts rely on the Access Broker / Resource Manager (tpm2-abrmd).

    > The TPM driver /dev/tpm0 and /dev/tpmrm0 are installed as root owner and group. When tpm2-abrmd installs
    > the TPM driver is changed to the 'tss' group. In order to send commands to the TPM, regardless of whether
    > that is done directly to the TPM's driver or through the tpm2-abrmd the application must be a member of the
    > 'tss' group.  
### Installing the required tpm2-tools
> While not needed, you may have the distro's tpm2-tss and tpm2-tools installed. The installed libraries and commands below
> will take priority over the distro's packages. Running 'sudo make uninstall' on the modules below will restore the use of the
> distro's packages.
1. Install the distro's tpm2-abrmd.
> There is no dependency on this being updated from the tpm2-software repo.
1. Clone [tpm2-tss](https://github.com/tpm2-software/tpm2-tss)
> Cannot just use the distro's provided tpm2-tss as its not compatible with the new tpm2-tools. 
2. Clone [tpm2-tools](https://github.com/tpm2-software/tpm2-tools)
3. Build and install in this order (tpm2-tools depends on installed libraries):

    a. tpm2-tss 
    > *You must execute ldconfig* (as root) to load the new tpm2-tss libraries.

    b. tpm2-tools

## python
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
4. Install pyasn1-alt-modules

    The python script uses a fork of the pyans1-modules. The forked module is at:

    [pyasn1-alt-modules](https://github.com/russhousley/pyasn1-alt-modules.git)

    This will need to be built and installed.

# CAVEAT: DON'T RUN THIS ON BARE METAL!

As a note to newbie TPM developers, running this code on your bare-metal TPM
runs the risk of causing you to lose TPM assets such as keys or even causing
your operating system to fail to boot. While most of the scripts simply add
keys, there is a "clear" option that clears the TPM. It is strongly recommended
that this development be done within a guest OS that gets a virtualized TPM from
the hypervisor or if you must use a bare-metal development machine, do so
starting with the TPM clear and with no dependencies on TPM assets other than
those created by these scripts.

# Description
This example ultimately creates an output file `csr.pem` which is a request to
certify `key1` stored within the local TPM and contains the `id-aa-evidence`
extension containing a TcgTpmCertify evidence bundle.

If the scripts in this repo are executed in order, then they perform (roughly):

1. Create a local OpenSSL CA to act as a new owner for the TPM's attestation key.

2. Create a new EK and AK within the TPM. Create a certificate for the AK under the local OpenSSL CA.

3. Create an application key `key1` within the TPM.

4. Create a CSR for `key1` containing an `id-aa-evidence` attribute according to draft-ietf-lamps-csr-attestation.

5. Use the TPM to perform self-checks and verify the Attestation data.

As the tpm2_tools man pages don't specifically state the structures returned, they
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
1. The precursor to this would be an Attestation Certification Authority (ACA) verifies the trustworthiness of the TPM by examining
   the TPM's Endorsement Key Certificate (EK Cert). An Attestation Key (AK) is created within the TPM. Then using a TPM defined
   protocol the ACA issues an AK Certificate. As this protocol is out of scope for this example, this example will simply create an
   AK Cert using openssl and Python script.

    > The only property of the AK Cert necessary for this example is the presence of the TCG defined OID (2.23.133.8.3:
    > tcg-kp-AIKCertificate) indicating that the certificate is an AK Certificate. This is the only TCG defined property put into
    > this example's AK Certificate.

    > As the role of the CA and the ACA are combined, this example will simply use a single folder "ca".

2. All TPM keys have a "name". The name is a hash of the TPMT_PUBLIC area which includes the key's public portion. The TPMT_PUBLIC
   also contains the key's meta-data such as the various attributes and policies. The purpose of this demo is to provide the
   verifier with proof that the information is from a trusted TPM (as trusted by the AK and AK Cert)

3. The TPM command TPM2_Certify returns a TPMS_ATTEST (wrapped in a TPM2B_ATTEST) structure of the loaded key to be certified. The
   TPMS_ATTEST strucuture contains the key's name (it also contain the key's qualifiedName which is not relevant to this demo). The
   TPMS_ATTEST structure is signed by the AK and returned as a signature.

4. As only the key's name is signed by the AK and sent to the verifier, the verify must reconstruct a temporary name from a
   TPMT_PUBLIC source then compare the signed one with the candidate name. If they match, the verify has the TPMT_PUBLIC for the
   key.

5. The verifier may already have a copy obtained by various means. One method is by having the client send it which is why those two
   parameters are optional.

END
