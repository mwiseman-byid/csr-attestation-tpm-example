from pyasn1.type import univ, namedtype
import argparse
from pyasn1.codec.der.encoder import encode


TPM_S_ATTEST = 'tpmSAttest'
TPM_S_ATTEST_ARG = TPM_S_ATTEST.lower()

SIGNATURE = 'signature'
SIGNATURE_ARG = SIGNATURE.lower()

TPM_T_PUBLIC = 'tpmTPublic'
TPM_T_PUBLIC_ARG = TPM_T_PUBLIC.lower()


class TcgAttestCertify(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(TPM_S_ATTEST, univ.OctetString()),
        namedtype.NamedType(SIGNATURE, univ.OctetString()),
        namedtype.OptionalNamedType(TPM_T_PUBLIC, univ.OctetString()),
    )


parser = argparse.ArgumentParser()
parser.add_argument('-p', f'--{TPM_T_PUBLIC_ARG}', required=False, type=argparse.FileType('rb'))
parser.add_argument(TPM_S_ATTEST_ARG, type=argparse.FileType('rb'))
parser.add_argument(SIGNATURE_ARG, type=argparse.FileType('rb'))

args = parser.parse_args()
args_vars = vars(args)

certify_ext = TcgAttestCertify()
certify_ext[TPM_S_ATTEST] = args_vars[TPM_S_ATTEST_ARG].read()
certify_ext[SIGNATURE] = args_vars[SIGNATURE_ARG].read()
if args_vars[TPM_T_PUBLIC_ARG]:
    certify_ext[TPM_T_PUBLIC] = args_vars[TPM_T_PUBLIC_ARG].read()

print(certify_ext)

der = encode(certify_ext)

print(':'.join("{:02x}".format(b) for b in der))
