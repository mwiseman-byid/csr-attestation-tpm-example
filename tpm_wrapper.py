import sys

from cryptography import x509
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.primitives import asymmetric, serialization, hashes
from pyasn1.type import univ, namedtype
import argparse
from pyasn1_alt_modules import rfc2986, rfc5280
from pyasn1.codec.der.decoder import decode
from pyasn1.codec.der.encoder import encode


# RFC 9500 section 2.1
_RSA_DUMMY_KEY = serialization.load_pem_private_key("""
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAsPnoGUOnrpiSqt4XynxA+HRP7S+BSObI6qJ7fQAVSPtRkqso
tWxQYLEYzNEx5ZSHTGypibVsJylvCfuToDTfMul8b/CZjP2Ob0LdpYrNH6l5hvFE
89FU1nZQF15oVLOpUgA7wGiHuEVawrGfey92UE68mOyUVXGweJIVDdxqdMoPvNNU
l86BU02vlBiESxOuox+dWmuVV7vfYZ79Toh/LUK43YvJh+rhv4nKuF7iHjVjBd9s
B6iDjj70HFldzOQ9r8SRI+9NirupPTkF5AKNe6kUhKJ1luB7S27ZkvB3tSTT3P59
3VVJvnzOjaA1z6Cz+4+eRvcysqhrRgFlwI9TEwIDAQABAoIBAEEYiyDP29vCzx/+
dS3LqnI5BjUuJhXUnc6AWX/PCgVAO+8A+gZRgvct7PtZb0sM6P9ZcLrweomlGezI
FrL0/6xQaa8bBr/ve/a8155OgcjFo6fZEw3Dz7ra5fbSiPmu4/b/kvrg+Br1l77J
aun6uUAs1f5B9wW+vbR7tzbT/mxaUeDiBzKpe15GwcvbJtdIVMa2YErtRjc1/5B2
BGVXyvlJv0SIlcIEMsHgnAFOp1ZgQ08aDzvilLq8XVMOahAhP1O2A3X8hKdXPyrx
IVWE9bS9ptTo+eF6eNl+d7htpKGEZHUxinoQpWEBTv+iOoHsVunkEJ3vjLP3lyI/
fY0NQ1ECgYEA3RBXAjgvIys2gfU3keImF8e/TprLge1I2vbWmV2j6rZCg5r/AS0u
pii5CvJ5/T5vfJPNgPBy8B/yRDs+6PJO1GmnlhOkG9JAIPkv0RBZvR0PMBtbp6nT
Y3yo1lwamBVBfY6rc0sLTzosZh2aGoLzrHNMQFMGaauORzBFpY5lU50CgYEAzPHl
u5DI6Xgep1vr8QvCUuEesCOgJg8Yh1UqVoY/SmQh6MYAv1I9bLGwrb3WW/7kqIoD
fj0aQV5buVZI2loMomtU9KY5SFIsPV+JuUpy7/+VE01ZQM5FdY8wiYCQiVZYju9X
Wz5LxMNoz+gT7pwlLCsC4N+R8aoBk404aF1gum8CgYAJ7VTq7Zj4TFV7Soa/T1eE
k9y8a+kdoYk3BASpCHJ29M5R2KEA7YV9wrBklHTz8VzSTFTbKHEQ5W5csAhoL5Fo
qoHzFFi3Qx7MHESQb9qHyolHEMNx6QdsHUn7rlEnaTTyrXh3ifQtD6C0yTmFXUIS
CW9wKApOrnyKJ9nI0HcuZQKBgQCMtoV6e9VGX4AEfpuHvAAnMYQFgeBiYTkBKltQ
XwozhH63uMMomUmtSG87Sz1TmrXadjAhy8gsG6I0pWaN7QgBuFnzQ/HOkwTm+qKw
AsrZt4zeXNwsH7QXHEJCFnCmqw9QzEoZTrNtHJHpNboBuVnYcoueZEJrP8OnUG3r
UjmopwKBgAqB2KYYMUqAOvYcBnEfLDmyZv9BTVNHbR2lKkMYqv5LlvDaBxVfilE0
2riO4p6BaAdvzXjKeRrGNEKoHNBpOSfYCOM16NjL8hIZB1CaV3WbT5oY+jp7Mzd5
7d56RZOE+ERK2uz/7JX9VSsM/LbH9pJibd4e8mikDS9ntciqOH/3
-----END RSA PRIVATE KEY-----
""".encode(), password=None)


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
parser.add_argument(TPM_S_ATTEST_ARG, type=argparse.FileType('rb'))
parser.add_argument(SIGNATURE_ARG, type=argparse.FileType('rb'))
parser.add_argument(TPM_T_PUBLIC_ARG, type=argparse.FileType('rb'))
parser.add_argument('publickeyfilepem', type=argparse.FileType('rb'))

args = parser.parse_args()
args_vars = vars(args)

certify_attr = TcgAttestCertify()
certify_attr[TPM_S_ATTEST] = args_vars[TPM_S_ATTEST_ARG].read()
certify_attr[SIGNATURE] = args_vars[SIGNATURE_ARG].read()
certify_attr[TPM_T_PUBLIC] = args_vars[TPM_T_PUBLIC_ARG].read()

certify_attr_der = encode(certify_attr)

csr_builder = x509.CertificateSigningRequestBuilder()
csr_builder = csr_builder.subject_name(x509.Name(
    [
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'AU'),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, 'QLD'),
        x509.NameAttribute(NameOID.LOCALITY_NAME, 'Brisbane'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'ietf-csr-test'),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, 'mwiseman-key1'),
        x509.NameAttribute(NameOID.COMMON_NAME, 'mwiseman-key1-test')
    ]
))

csr = csr_builder.sign(_RSA_DUMMY_KEY, hashes.SHA256())
cri_der = csr.tbs_certrequest_bytes

cri_pyasn1, _ = decode(cri_der, rfc2986.CertificationRequestInfo())

attr = rfc2986.Attribute()
attr['type'] = univ.ObjectIdentifier('2.23.133.9999.1')
attr['values'].append(certify_attr)

cri_pyasn1['attributes'].append(attr)

pubkey = serialization.load_pem_public_key(args.publickeyfilepem.read())
pubkey_der = pubkey.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

spki, _ = decode(pubkey_der, rfc5280.SubjectPublicKeyInfo())
cri_pyasn1['subjectPKInfo']['subjectPublicKey'] = spki['subjectPublicKey']

with open('out.csr', 'wb') as f:
    f.write(encode(cri_pyasn1))
