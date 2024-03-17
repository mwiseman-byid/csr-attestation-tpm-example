from pyasn1.type import univ
from pyasn1_alt_modules import rfc2986, rfc4055

from pyasn1.codec.der.decoder import decode
from pyasn1.codec.der.encoder import encode
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('cri', type=argparse.FileType('rb'))
parser.add_argument('signature', type=argparse.FileType('rb'))

args = parser.parse_args()

cri, _ = decode(args.cri.read(), asn1Spec=rfc2986.CertificationRequestInfo())
sig = args.signature.read()

csr = rfc2986.CertificationRequest()
csr['certificationRequestInfo'] = cri

csr['signatureAlgorithm']['algorithm'] = rfc4055.sha256WithRSAEncryption
csr['signature'] = univ.BitString(hexValue=sig.hex())

with open('out.csr', 'wb') as f:
    f.write(encode(csr))
