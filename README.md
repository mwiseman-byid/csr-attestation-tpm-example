# csr-attestation-tpm-example
This uses the TCG TSS command line utilities from https://github.com/tpm2-software.
This is normally obtained by downloading from your distro. However, there is an issue
with the released files where the command tpm2_print -t TPMS_ATTEST command
was not implemented. I've filed an issue and was fixed but (as of 23-03-08) was
not merged. I have copied the fixed file to my own reposity at
https://github.com/mwiseman-byid/tpm2-tools. This does require building the tpm2-tss
from the main branch.

This example builds the attestation_statement init a .tar file and does not add
the attestation_statment into a csr with the defined new extension. This is
work to do.
