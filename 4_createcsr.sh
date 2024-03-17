# /bin/bash
. ./dirs.sh
set -e

python3 tpm_wrapper.py $cdir/key1.attest $cdir/key1-attest.sig $cdir/key1.pub $cdir/key1.pem

